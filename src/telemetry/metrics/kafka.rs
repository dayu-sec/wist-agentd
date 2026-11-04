//! Kafka broker 指标采集（V1：元数据面）。
//!
//! 设计见 `wist-design/doc/design/telemetry/kafka-broker-metrics-spec.md`。
//!
//! ## 为什么自己实现协议
//!
//! 目标场景明确不依赖 Prometheus / exporter。引入 `rdkafka` 会带进 C 依赖（musl 静态发布
//! 还要 vendored），而我们只需要只读的元数据面 —— 手写「请求头 + Metadata v1」比接一个
//! C 库更小、更可控，也让「不依赖第三方」这条在构建层面成立。
//!
//! ## 边界（V1 明确不做）
//!
//! - 只支持 `PLAINTEXT`；SASL / TLS 留给 V1.1（需要额外的握手与证书栈）；
//! - 只做 `Metadata`（拓扑 / ISR / 离线分区）；`DescribeLogDirs`、消费者组 lag 留给后续；
//! - **不伪造失败**：连不上的 broker 不出样本（缺序列 = 不可达），不补 `0`。
//!
//! ## 线程模型
//!
//! 采集在**独立线程**里周期跑，`collect_outcome()` 只读最近一次快照 —— 网络超时
//! 不会拖住 3s 的主循环。

use std::io::{self, Read, Write};
use std::net::{TcpStream, ToSocketAddrs};
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use wist_contracts::discovery::StringKeyValue;

use super::runtime::{MetricsCollectionOutcome, MetricsCollectionTargetSample};

/// 采集域：与 `wist_metrics::spec` 里 `kafka_broker_metrics` 对应。
pub const COLLECTION_KIND: &str = "kafka_broker_metrics";

/// Kafka Metadata 的 API key（`Metadata`）。
const API_KEY_METADATA: i16 = 3;
/// 用 v1：0.10 起就有，字段刚好够（brokers / controller / partitions / ISR）。
const API_VERSION_METADATA: i16 = 1;
/// `DescribeLogDirs` 的 API key。
const API_KEY_DESCRIBE_LOG_DIRS: i16 = 35;
/// v0 从 0.11 起就有；它只给分区 `size`（不给磁盘总量，总量由主机文件系统指标回答）。
const API_VERSION_DESCRIBE_LOG_DIRS: i16 = 0;

/// 探测配置（来自 `[kafka]` 段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaProbeConfig {
    pub bootstrap_servers: Vec<String>,
    pub client_id: String,
    pub timeout: Duration,
    pub interval: Duration,
}

impl KafkaProbeConfig {
    pub fn new(
        bootstrap_servers: Vec<String>,
        client_id: String,
        timeout_ms: u64,
        interval_ms: u64,
    ) -> Self {
        Self {
            bootstrap_servers,
            client_id,
            timeout: Duration::from_millis(timeout_ms),
            interval: Duration::from_millis(interval_ms),
        }
    }
}

/// 一次探测的产物（与具体线程解耦，便于测试）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub targets: Vec<MetricsCollectionTargetSample>,
    pub attempted: usize,
    pub failed: usize,
    pub last_error: Option<String>,
}

#[derive(Debug, Default)]
struct ProbeState {
    latest: Option<ProbeResult>,
}

static CONFIG: OnceLock<KafkaProbeConfig> = OnceLock::new();
static STATE: OnceLock<Mutex<ProbeState>> = OnceLock::new();

fn state() -> &'static Mutex<ProbeState> {
    STATE.get_or_init(|| Mutex::new(ProbeState::default()))
}

/// 由守护进程在启动时调用一次。未启用时**不启动线程**，`collect_outcome` 恒为 `None`。
pub fn init(config: KafkaProbeConfig) {
    if CONFIG.set(config.clone()).is_err() {
        return; // 重复初始化：保留第一次的配置
    }
    std::thread::Builder::new()
        .name("kafka-probe".to_string())
        .spawn(move || {
            loop {
                let result = probe_once(&config);
                if let Ok(mut guard) = state().lock() {
                    guard.latest = Some(result);
                }
                std::thread::sleep(config.interval);
            }
        })
        .ok();
}

/// 把最近一次探测结果转成采集结果。未启用 → `None`（快照里不出现这个域）。
pub fn collect_outcome() -> Option<MetricsCollectionOutcome> {
    CONFIG.get()?;
    let guard = state().lock().ok()?;
    let latest = guard.latest.clone();

    let Some(result) = latest else {
        // 首轮还没跑完：如实说「还没数据」，不谎报成功也不报失败。
        return Some(MetricsCollectionOutcome {
            collection_kind: COLLECTION_KIND.to_string(),
            status: "pending".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            dropped_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        });
    };

    let succeeded = result
        .targets
        .iter()
        .filter(|target| target.status != "failed")
        .count();
    Some(MetricsCollectionOutcome {
        collection_kind: COLLECTION_KIND.to_string(),
        status: if result.failed == 0 && succeeded > 0 {
            "succeeded".to_string()
        } else if succeeded == 0 {
            "failed".to_string()
        } else {
            "partial".to_string()
        },
        attempted_targets: result.attempted,
        succeeded_targets: succeeded,
        failed_targets: result.failed,
        dropped_targets: 0,
        last_error: result.last_error.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
        sample_targets: result.targets,
    })
}

/// 依次尝试 bootstrap 节点，第一个成功的回答即为本轮结果。
fn probe_once(config: &KafkaProbeConfig) -> ProbeResult {
    let mut last_error = None;
    for addr in &config.bootstrap_servers {
        match fetch_metadata(addr, &config.client_id, config.timeout) {
            Ok(metadata) => {
                // 容量面：逐个 broker 连一次 `DescribeLogDirs`。
                // 单个 broker 拿不到就少一条容量读数（缺序列），不影响其余指标。
                let mut sizes = std::collections::BTreeMap::new();
                for broker in &metadata.brokers {
                    let broker_addr = format!("{}:{}", broker.host, broker.port);
                    if let Ok(bytes) =
                        fetch_log_dir_total(&broker_addr, &config.client_id, config.timeout)
                    {
                        sizes.insert(broker.node_id, bytes);
                    }
                }
                return build_targets(&metadata, &sizes, config.bootstrap_servers.len());
            }
            Err(err) => last_error = Some(format!("{addr}: {err}")),
        }
    }
    ProbeResult {
        targets: Vec::new(),
        attempted: config.bootstrap_servers.len(),
        failed: config.bootstrap_servers.len(),
        last_error: last_error.or_else(|| Some("no bootstrap server configured".to_string())),
    }
}

/// 把一次元数据回答翻译成指标目标。
///
/// 每个 broker 一个 `sample_target`：`resource_ref` 即实例身份
/// （`kafka:<cluster>:<broker_id>`），因此不需要额外的 `broker_id` label。
pub fn build_targets(
    metadata: &Metadata,
    log_dir_sizes: &std::collections::BTreeMap<i32, i64>,
    attempted: usize,
) -> ProbeResult {
    let mut targets = Vec::with_capacity(metadata.brokers.len() + 1);

    for broker in &metadata.brokers {
        let led: Vec<&PartitionInfo> = metadata
            .partitions
            .iter()
            .filter(|partition| partition.leader == broker.node_id)
            .collect();
        let under_replicated = metadata
            .partitions
            .iter()
            .filter(|partition| {
                partition.replicas.contains(&broker.node_id)
                    && partition.isr.len() < partition.replicas.len()
            })
            .count();

        let mut facts = vec![
            fact("kafka.broker.up", "1"),
            fact(
                "kafka.broker.is_controller",
                if metadata.controller_id == broker.node_id {
                    "1"
                } else {
                    "0"
                },
            ),
            fact("kafka.partition.count", &led.len().to_string()),
            fact(
                "kafka.partition.under_replicated",
                &under_replicated.to_string(),
            ),
        ];
        // 拿不到容量的 broker 不发这条 —— 不补 0（0 会被当成"磁盘空"）。
        if let Some(bytes) = log_dir_sizes.get(&broker.node_id) {
            facts.push(fact("kafka.log_dir.size_bytes", &bytes.to_string()));
        }
        targets.push(target(
            &format!("kafka:{}:{}", metadata.cluster_key, broker.node_id),
            facts,
        ));
    }

    // 离线分区是集群级的：没有 leader，归到某个 broker 会重复计数。
    let offline = metadata
        .partitions
        .iter()
        .filter(|partition| partition.leader < 0)
        .count();
    targets.push(target(
        &format!("kafka:{}", metadata.cluster_key),
        vec![fact("kafka.partition.offline", &offline.to_string())],
    ));

    ProbeResult {
        targets,
        attempted,
        failed: 0,
        last_error: None,
    }
}

fn fact(key: &str, value: &str) -> StringKeyValue {
    StringKeyValue::new(key, value.to_string())
}

fn target(resource_ref: &str, runtime_facts: Vec<StringKeyValue>) -> MetricsCollectionTargetSample {
    MetricsCollectionTargetSample {
        candidate_id: resource_ref.to_string(),
        target_ref: resource_ref.to_string(),
        status: "succeeded".to_string(),
        last_error: None,
        resource_ref: resource_ref.to_string(),
        execution_hints: Vec::new(),
        runtime_facts,
        labeled_facts: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// 协议层：只实现 Metadata v1
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Broker {
    pub node_id: i32,
    pub host: String,
    pub port: i32,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PartitionInfo {
    pub leader: i32,
    pub replicas: Vec<i32>,
    pub isr: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// 集群标识：优先用 broker 列表的稳定摘要（Metadata v1 不返回 cluster_id）。
    pub cluster_key: String,
    pub brokers: Vec<Broker>,
    pub controller_id: i32,
    pub partitions: Vec<PartitionInfo>,
}

/// 发一次 Metadata 请求并解析。
pub fn fetch_metadata(addr: &str, client_id: &str, timeout: Duration) -> io::Result<Metadata> {
    let payload = encode_metadata_request(11, client_id);
    let response = round_trip(addr, timeout, &payload)?;
    // 响应头：correlation_id（v1 没有 tagged fields）。
    let mut reader = Reader::new(&response);
    let correlation_id = reader.i32()?;
    if correlation_id != 11 {
        return Err(invalid(format!(
            "unexpected correlation id {correlation_id}"
        )));
    }
    parse_metadata_v1(&mut reader)
}

/// 拉一个 broker 的 log dir 合计大小（字节）。
pub fn fetch_log_dir_total(addr: &str, client_id: &str, timeout: Duration) -> io::Result<i64> {
    let payload = encode_describe_log_dirs_request(12, client_id);
    let response = round_trip(addr, timeout, &payload)?;
    let mut reader = Reader::new(&response);
    let correlation_id = reader.i32()?;
    if correlation_id != 12 {
        return Err(invalid(format!(
            "unexpected correlation id {correlation_id}"
        )));
    }
    let partitions = parse_describe_log_dirs_v0(&mut reader)?;
    Ok(partitions.into_iter().map(|(_, size)| size).sum())
}

/// `DescribeLogDirs` v0 请求：`topics = null`（= 全部）。
pub fn encode_describe_log_dirs_request(correlation_id: i32, client_id: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_DESCRIBE_LOG_DIRS.to_be_bytes());
    body.extend_from_slice(&API_VERSION_DESCRIBE_LOG_DIRS.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    body.extend_from_slice(&(-1i32).to_be_bytes());

    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// 解析 `DescribeLogDirs` v0 响应体，返回 `(partition_index, size_bytes)`。
///
/// v0 没有 `throttle_time_ms`，也没有 `total_bytes` —— 磁盘总量由主机文件系统指标回答，
/// 这里不编造分母。
pub fn parse_describe_log_dirs_v0(reader: &mut Reader<'_>) -> io::Result<Vec<(i32, i64)>> {
    let dirs = reader.array_len()?;
    let mut out = Vec::new();
    for _ in 0..dirs {
        let error_code = reader.i16()?;
        let _log_dir = reader.string()?;
        let topics = reader.array_len()?;
        for _ in 0..topics {
            let _topic = reader.string()?;
            let partitions = reader.array_len()?;
            for _ in 0..partitions {
                let partition_index = reader.i32()?;
                let size = reader.i64()?;
                let _offset_lag = reader.i64()?;
                let is_future = reader.boolean()?;
                // 未来副本不是本地已有数据，算进去会让容量虚高。
                if error_code == 0 && !is_future {
                    out.push((partition_index, size));
                }
            }
        }
    }
    Ok(out)
}

fn round_trip(addr: &str, timeout: Duration, payload: &[u8]) -> io::Result<Vec<u8>> {
    let mut last: io::Result<Vec<u8>> = Err(invalid(format!("cannot resolve {addr}")));
    for resolved in addr.to_socket_addrs()? {
        let attempt = (|| -> io::Result<Vec<u8>> {
            let mut stream = TcpStream::connect_timeout(&resolved, timeout)?;
            stream.set_read_timeout(Some(timeout))?;
            stream.set_write_timeout(Some(timeout))?;
            stream.write_all(payload)?;
            stream.flush()?;

            let mut size = [0u8; 4];
            stream.read_exact(&mut size)?;
            let len = i32::from_be_bytes(size);
            if !(0..=64 * 1024 * 1024).contains(&len) {
                return Err(invalid(format!("invalid response size {len}")));
            }
            let mut body = vec![0u8; len as usize];
            stream.read_exact(&mut body)?;
            Ok(body)
        })();
        match attempt {
            Ok(body) => return Ok(body),
            Err(err) => last = Err(err),
        }
    }
    last
}

fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `Metadata` v1 请求：`topics = null`（= 全部 topic）。
pub fn encode_metadata_request(correlation_id: i32, client_id: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_METADATA.to_be_bytes());
    body.extend_from_slice(&API_VERSION_METADATA.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    // client_id：nullable string
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    // topics：nullable array，-1 = 全部
    body.extend_from_slice(&(-1i32).to_be_bytes());

    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// 解析 Metadata v1 响应体（已去掉 correlation_id）。
pub fn parse_metadata_v1(reader: &mut Reader<'_>) -> io::Result<Metadata> {
    let brokers_len = reader.array_len()?;
    let mut brokers = Vec::with_capacity(brokers_len);
    for _ in 0..brokers_len {
        let node_id = reader.i32()?;
        let host = reader.string()?;
        let port = reader.i32()?;
        brokers.push(Broker {
            node_id,
            host,
            port,
        });
    }
    let controller_id = reader.i32()?;

    let topics_len = reader.array_len()?;
    let mut partitions = Vec::new();
    for _ in 0..topics_len {
        let _error_code = reader.i16()?;
        let _name = reader.string()?;
        let _is_internal = reader.boolean()?;
        let partitions_len = reader.array_len()?;
        for _ in 0..partitions_len {
            let _partition_error = reader.i16()?;
            let _partition_index = reader.i32()?;
            let leader = reader.i32()?;
            let replicas = reader.i32_array()?;
            let isr = reader.i32_array()?;
            partitions.push(PartitionInfo {
                leader,
                replicas,
                isr,
            });
        }
    }

    if brokers.is_empty() {
        return Err(invalid("metadata response has no brokers".to_string()));
    }
    let cluster_key = cluster_key(&brokers);
    Ok(Metadata {
        cluster_key,
        brokers,
        controller_id,
        partitions,
    })
}

/// Metadata v1 不返回 `cluster_id`，用 broker 端点集合的稳定摘要当集群键。
///
/// 为什么不用第一个 broker 的地址：换一个 bootstrap 节点就会变，`instance` 会跟着变，
/// 历史序列就断开了。
fn cluster_key(brokers: &[Broker]) -> String {
    let mut parts: Vec<String> = brokers
        .iter()
        .map(|broker| format!("{}:{}", broker.host, broker.port))
        .collect();
    parts.sort();
    let joined = parts.join(",");
    // 稳定的 64 位摘要（FNV-1a）：不引哈希依赖，也够避免把整串地址塞进 instance。
    let mut hash: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in joined.as_bytes() {
        hash ^= u64::from(*byte);
        hash = hash.wrapping_mul(0x100_0000_01b3);
    }
    format!("{hash:016x}")
}

/// 大端只读游标，所有读取都做边界检查（对端畸形数据不能 panic）。
pub struct Reader<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn take(&mut self, len: usize) -> io::Result<&'a [u8]> {
        let end = self
            .pos
            .checked_add(len)
            .ok_or_else(|| invalid("length overflow".to_string()))?;
        if end > self.buf.len() {
            return Err(invalid(format!(
                "truncated response: need {len} bytes at {}",
                self.pos
            )));
        }
        let slice = &self.buf[self.pos..end];
        self.pos = end;
        Ok(slice)
    }

    pub fn i16(&mut self) -> io::Result<i16> {
        let bytes = self.take(2)?;
        Ok(i16::from_be_bytes([bytes[0], bytes[1]]))
    }

    pub fn i32(&mut self) -> io::Result<i32> {
        let bytes = self.take(4)?;
        Ok(i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]))
    }

    pub fn i64(&mut self) -> io::Result<i64> {
        let bytes = self.take(8)?;
        Ok(i64::from_be_bytes([
            bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6], bytes[7],
        ]))
    }

    pub fn boolean(&mut self) -> io::Result<bool> {
        Ok(self.take(1)?[0] != 0)
    }

    pub fn string(&mut self) -> io::Result<String> {
        let len = self.i16()?;
        if len < 0 {
            return Ok(String::new());
        }
        let bytes = self.take(len as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|err| invalid(format!("bad utf8: {err}")))
    }

    /// 数组长度；`-1`（null）按空处理 —— 元数据面里 null 与空集的语义都是「没有」。
    pub fn array_len(&mut self) -> io::Result<usize> {
        let len = self.i32()?;
        if len < 0 {
            return Ok(0);
        }
        // 上限防御：畸形长度不该让我们尝试分配几个 GB。
        if len > 1_000_000 {
            return Err(invalid(format!("array too large: {len}")));
        }
        Ok(len as usize)
    }

    pub fn i32_array(&mut self) -> io::Result<Vec<i32>> {
        let len = self.array_len()?;
        let mut out = Vec::with_capacity(len);
        for _ in 0..len {
            out.push(self.i32()?);
        }
        Ok(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn broker(node_id: i32, host: &str, port: i32) -> Broker {
        Broker {
            node_id,
            host: host.to_string(),
            port,
        }
    }

    fn metadata() -> Metadata {
        Metadata {
            cluster_key: "abc".to_string(),
            brokers: vec![broker(1, "10.0.0.1", 9092), broker(2, "10.0.0.2", 9092)],
            controller_id: 2,
            partitions: vec![
                PartitionInfo {
                    leader: 1,
                    replicas: vec![1, 2],
                    isr: vec![1, 2],
                },
                PartitionInfo {
                    leader: 1,
                    replicas: vec![1, 2],
                    isr: vec![1],
                },
                PartitionInfo {
                    leader: -1,
                    replicas: vec![1, 2],
                    isr: vec![],
                },
            ],
        }
    }

    #[test]
    fn encode_request_has_a_size_prefix_and_null_topic_list() {
        let bytes = encode_metadata_request(11, "wist-agentd");
        let declared = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(
            declared as usize,
            bytes.len() - 4,
            "size 前缀必须等于剩余长度"
        );
        assert_eq!(
            i16::from_be_bytes([bytes[4], bytes[5]]),
            API_KEY_METADATA,
            "api key"
        );
        assert_eq!(
            i16::from_be_bytes([bytes[6], bytes[7]]),
            API_VERSION_METADATA,
            "api version"
        );
        // 最后四个字节是 topics=null
        assert_eq!(&bytes[bytes.len() - 4..], &(-1i32).to_be_bytes());
    }

    #[test]
    fn parses_a_metadata_response() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_be_bytes()); // brokers
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i16.to_be_bytes());
        buf.extend_from_slice(b"10.0");
        buf.extend_from_slice(&9092i32.to_be_bytes());
        buf.extend_from_slice(&2i32.to_be_bytes());
        buf.extend_from_slice(&4i16.to_be_bytes());
        buf.extend_from_slice(b"10.1");
        buf.extend_from_slice(&9093i32.to_be_bytes());
        buf.extend_from_slice(&2i32.to_be_bytes()); // controller
        buf.extend_from_slice(&1i32.to_be_bytes()); // topics
        buf.extend_from_slice(&0i16.to_be_bytes()); // topic error
        buf.extend_from_slice(&1i16.to_be_bytes());
        buf.extend_from_slice(b"t");
        buf.push(0); // is_internal
        buf.extend_from_slice(&1i32.to_be_bytes()); // partitions
        buf.extend_from_slice(&0i16.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes()); // leader
        buf.extend_from_slice(&1i32.to_be_bytes()); // replicas len
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i32.to_be_bytes()); // isr len
        buf.extend_from_slice(&1i32.to_be_bytes());

        let mut reader = Reader::new(&buf);
        let parsed = parse_metadata_v1(&mut reader).expect("parse");
        assert_eq!(parsed.brokers.len(), 2);
        assert_eq!(parsed.controller_id, 2);
        assert_eq!(parsed.partitions.len(), 1);
        assert_eq!(parsed.partitions[0].leader, 1);
        assert_eq!(parsed.partitions[0].isr, vec![1]);
    }

    #[test]
    fn truncated_response_is_an_error_not_a_panic() {
        let buf = vec![0u8; 3];
        let mut reader = Reader::new(&buf);
        assert!(parse_metadata_v1(&mut reader).is_err());
    }

    #[test]
    fn cluster_key_is_order_independent_and_stable() {
        let a = cluster_key(&[broker(1, "a", 9092), broker(2, "b", 9092)]);
        let b = cluster_key(&[broker(2, "b", 9092), broker(1, "a", 9092)]);
        assert_eq!(a, b, "broker 顺序不同不能换一个集群键");
        assert_eq!(a.len(), 16);
    }

    #[test]
    fn build_targets_emits_one_target_per_broker_plus_cluster() {
        let result = build_targets(&metadata(), &std::collections::BTreeMap::new(), 2);
        assert_eq!(result.targets.len(), 3, "2 broker + 1 集群级");
        let first = &result.targets[0];
        assert_eq!(first.resource_ref, "kafka:abc:1");
        let facts: Vec<(&str, &str)> = first
            .runtime_facts
            .iter()
            .map(|fact| (fact.key.as_str(), fact.value.as_str()))
            .collect();
        assert!(facts.contains(&("kafka.broker.up", "1")));
        assert!(
            facts.contains(&("kafka.broker.is_controller", "0")),
            "broker 1 不是 controller"
        );
        assert!(
            facts.contains(&("kafka.partition.count", "2")),
            "broker 1 是 2 个分区的 leader"
        );
        assert!(
            facts.contains(&("kafka.partition.under_replicated", "2")),
            "broker 1 参与两个副本不足的分区（其中一个还是离线分区）"
        );

        let second = &result.targets[1];
        let is_controller = second
            .runtime_facts
            .iter()
            .find(|fact| fact.key == "kafka.broker.is_controller")
            .expect("controller fact");
        assert_eq!(is_controller.value, "1");

        let cluster = &result.targets[2];
        assert_eq!(cluster.resource_ref, "kafka:abc");
        let offline = cluster
            .runtime_facts
            .iter()
            .find(|fact| fact.key == "kafka.partition.offline")
            .expect("offline fact");
        assert_eq!(offline.value, "1");
    }

    #[test]
    fn log_dir_sizes_are_only_emitted_when_known() {
        let mut sizes = std::collections::BTreeMap::new();
        sizes.insert(2, 1_048_576i64);
        let result = build_targets(&metadata(), &sizes, 2);

        let broker1 = &result.targets[0];
        assert!(
            !broker1
                .runtime_facts
                .iter()
                .any(|fact| fact.key == "kafka.log_dir.size_bytes"),
            "拿不到容量的 broker 不能补 0（0 会被读成磁盘空）"
        );

        let broker2 = &result.targets[1];
        let size = broker2
            .runtime_facts
            .iter()
            .find(|fact| fact.key == "kafka.log_dir.size_bytes")
            .expect("有容量就要发");
        assert_eq!(size.value, "1048576");
    }

    #[test]
    fn parses_describe_log_dirs_v0_and_skips_future_replicas() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_be_bytes()); // log_dirs
        buf.extend_from_slice(&0i16.to_be_bytes()); // error_code
        buf.extend_from_slice(&5i16.to_be_bytes());
        buf.extend_from_slice(b"/data");
        buf.extend_from_slice(&1i32.to_be_bytes()); // topics
        buf.extend_from_slice(&1i16.to_be_bytes());
        buf.extend_from_slice(b"t");
        buf.extend_from_slice(&2i32.to_be_bytes()); // partitions
        // 分区 0：真实数据
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1_000i64.to_be_bytes());
        buf.extend_from_slice(&0i64.to_be_bytes());
        buf.push(0);
        // 分区 1：未来副本（不计数）
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&7_000i64.to_be_bytes());
        buf.extend_from_slice(&0i64.to_be_bytes());
        buf.push(1);

        let mut reader = Reader::new(&buf);
        let partitions = parse_describe_log_dirs_v0(&mut reader).expect("parse");
        assert_eq!(partitions, vec![(0, 1_000)], "未来副本不算本地容量");
    }

    #[test]
    fn every_emitted_fact_is_registered_in_the_metric_spec() {
        // 与 runtime 的「覆盖完整性」同一条纪律：新增 fact 忘了在 wist-metrics 注册，
        // 上游会静默丢掉整条序列，而现场只表现为「这个指标没数据」。
        let mut sizes = std::collections::BTreeMap::new();
        sizes.insert(1, 4_096i64);
        let result = build_targets(&metadata(), &sizes, 1);
        for target in &result.targets {
            for fact in &target.runtime_facts {
                let spec = wist_metrics::spec::find_metric_spec(COLLECTION_KIND, &fact.key);
                assert!(spec.is_some(), "fact `{}` 没有指标声明", fact.key);
                let spec = spec.expect("checked");
                assert!(
                    spec.name.starts_with("kafka_"),
                    "`{}` 必须落在 kafka 命名空间",
                    spec.name
                );
            }
        }
    }

    #[test]
    fn unreachable_bootstrap_reports_failure_without_fake_samples() {
        // 127.0.0.1:1 基本必然拒绝连接；即使偶然成功（端口被占），也只要求不 panic。
        let config = KafkaProbeConfig::new(
            vec!["127.0.0.1:1".to_string()],
            "wist-agentd-test".to_string(),
            200,
            1_000,
        );
        let result = probe_once(&config);
        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 1);
        assert!(result.targets.is_empty(), "连不上就不要造样本");
        assert!(result.last_error.is_some());
    }
}
