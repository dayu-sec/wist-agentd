//! Kafka broker 实例**自探**：只发现，不上报、不下发采集任务。
//!
//! ## 为什么是"自探"而不是"配一下"
//!
//! 让运维为一台台机器写 `bootstrap_servers` / `security_protocol` 是不现实的（也没人做）。
//! agentd 以 root 跑在 broker 机器上，**进程本身就是证据** —— 与
//! [`super::log_source`] 定位数据库日志目录同一条路子。
//!
//! 结果**只在本机使用**：采集时选端点/协议（由采集面授权驱动），`doctor` 里给人看。
//! 不上报网关、不新增任何 Kafka 专属接口。
//!
//! ## 证据层（从强到弱）
//!
//! 1. `server.properties`：`listeners` / `advertised.listeners` /
//!    `listener.security.protocol.map` / `sasl.enabled.mechanisms`；
//! 2. 容器环境变量（Bitnami 镜像的 `KAFKA_CFG_*`）；
//! 3. 该进程的监听端口（协议 `unknown`，只能证明"这里有个监听"）。
//!
//! ## 红线（与密码纪律一致）
//!
//! **只读白名单键**：`ssl.keystore.password` / `sasl.jaas.config` / 任何 `*.password`
//! 一律不读、不报、不进日志。产出里只有协议名、端口与机制名。
//!
//! ## 端点可达性
//!
//! 每个端点假设都实测一次：TCP 能连 +（PLAINTEXT 时）能完成 `ApiVersions` 握手。
//! 不实测就选端点等于把"猜地址"的活留给采集期 —— 连不上也是白搭。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::Serialize;
use wist_contracts::discovery::DiscoverySnapshot;

/// 一次解析最多看多少个进程（Kafka 机器上进程很多，不必全扫）。
const MAX_INSPECTED_PROCESSES: usize = 8;
/// 单个集群最多保留多少条端点假设。
const MAX_ENDPOINTS_PER_CLUSTER: usize = 6;
/// `cmdline` / `environ` 的读取上限。
///
/// **不能是 4 KiB**：Java broker 的 cmdline 里 classpath 就常有 6–30 KiB，
/// `kafka.Kafka` 与 `server.properties` 都在**末尾**。截断后 argv 里看不到主类，
/// 真 broker 会被判成「不是 Kafka」（现场表现：进程在、自探一个都没有）。
/// `KAFKA_CFG_*` 也可能很长（Bitnami 把整份配置放环境变量）。
const MAX_PROC_BYTES: usize = 64 * 1024;
/// 配置文件读取上限：`server.properties` 一般几 KB。
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
/// 单次 TCP / 握手探测的超时。
///
/// 它会在采集启动前跑一次：一个 Kafka 机器最多 6 个端点，
/// 每端点只连一次 ⇒ 最坏 ~1.8s，且只有在**真的发现 broker** 时才会花这笔时间。
const PROBE_TIMEOUT: Duration = Duration::from_millis(300);

/// 一条 Kafka 集群候选（自探产物；只在进程内使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KafkaClusterEntry {
    /// 进程身份（审计用）：优先端口，pid 重启不换身份。
    pub source_ref: String,
    /// `node.id` / `broker.id`（**不是**权威 cluster id；权威值要首轮 `Metadata` 才知道）。
    #[serde(skip_serializing_if = "Option::is_none")]
    pub broker_id: Option<i32>,
    /// 监听器（名字 / 协议 / 端口）。
    pub listeners: Vec<KafkaListenerEntry>,
    /// 启用的 SASL 机制（空 = 这些监听器不要求 SASL）。
    pub mechanisms: Vec<String>,
    /// 端点假设 + 实测结果，按"最可能可用"排序。
    pub endpoints: Vec<KafkaEndpointEntry>,
    /// 证据层：`server_properties` / `container_env` / `listening_port`。
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KafkaListenerEntry {
    pub name: String,
    /// `PLAINTEXT` / `SSL` / `SASL_PLAINTEXT` / `SASL_SSL` / `unknown`。
    pub protocol: String,
    pub port: u16,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct KafkaEndpointEntry {
    pub addr: String,
    /// 这条地址是怎么来的：`advertised` / `listener` / `loopback` / `listening_port`。
    pub source: String,
    /// 该端点所属监听器的安全协议（`PLAINTEXT` / `SSL` / `SASL_PLAINTEXT` / `SASL_SSL` /
    /// `unknown`）。采集时按它决定 TLS / SASL。
    pub protocol: String,
    /// TCP 能连上。
    pub reachable: bool,
    /// 不带凭据完成了 Kafka 握手（只有 PLAINTEXT 监听器才可能为 true）——
    /// 它同时证明了「这确实是 Kafka，不是随便一个监听端口」。
    pub kafka_api: bool,
}

/// 一次探测的结果。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct ProbeOutcome {
    pub tcp: bool,
    pub kafka_api: bool,
}

/// 端点探测能力。抽成 trait 的唯一目的是**可测**：单测不该真的去连 socket。
pub trait Reachability {
    fn probe(&self, addr: &str, protocol: &str) -> ProbeOutcome;
}

/// 生产实现：TCP +（PLAINTEXT 时）`ApiVersions` 握手。
pub struct TcpReachability;

impl Reachability for TcpReachability {
    fn probe(&self, addr: &str, protocol: &str) -> ProbeOutcome {
        // 明文监听器：直接用 `ApiVersions` 握手当可达性判据 —— 它同时证明了
        // 「TCP 通」与「这确实是 Kafka」，比先连一次 TCP 再连一次省一半连接。
        if protocol == "PLAINTEXT" {
            let ok = kafka_api_reachable(addr);
            return ProbeOutcome {
                tcp: ok,
                kafka_api: ok,
            };
        }
        // TLS / SASL 监听器没有凭据时做不了完整握手 —— 只证明"能连上"。
        // 这里**不**去猜凭据，也不降级成明文重试（降级是安全事件）。
        ProbeOutcome {
            tcp: tcp_reachable(addr),
            kafka_api: false,
        }
    }
}

fn tcp_reachable(addr: &str) -> bool {
    let Ok(addrs) = addr.to_socket_addrs() else {
        return false;
    };
    for socket in addrs.take(2) {
        if TcpStream::connect_timeout(&socket, PROBE_TIMEOUT).is_ok() {
            return true;
        }
    }
    false
}

/// 用探针自己的 `connect()` 发一次 `ApiVersions`（Kafka 允许未认证连接发它）。
///
/// 复用 `kafka_auth` 而不是在这里再手写一份报文：版本协商的边界处理（半包、错误码）
/// 已经在那边有测试钉住了。
fn kafka_api_reachable(addr: &str) -> bool {
    use crate::telemetry::metrics::kafka_auth::{self, SecurityConfig};

    let security = SecurityConfig {
        protocol: "PLAINTEXT",
        mechanism: "auto",
        username: None,
        password_file: None,
        tls_ca_file: None,
    };
    kafka_auth::connect(addr, &security, PROBE_TIMEOUT)
        .map(|_| true)
        .unwrap_or(false)
}

/// 从发现快照算出 Kafka 集群候选。**纯计算 + 受限读取**，失败一律跳过。
pub fn resolve_from_snapshot(snapshot: &DiscoverySnapshot) -> Vec<KafkaClusterEntry> {
    resolve(snapshot, &RealProc, &TcpReachability)
}

/// 现场诊断用：立即跑一次进程 + 端点发现再解析（不读缓存、不写盘）。
pub fn resolve_live() -> Vec<KafkaClusterEntry> {
    use crate::discovery::DiscoveryProbe as _;

    let now = std::time::SystemTime::now();
    let stamp = wist_shared::time::now_rfc3339();
    let mut snapshot = DiscoverySnapshot::new(format!("kafka-candidates-live-{stamp}"), 0, stamp);
    for output in [
        crate::discovery::process::ProcessDiscoveryProbe.refresh(now),
        crate::discovery::endpoint::EndpointDiscoveryProbe.refresh(now),
    ]
    .into_iter()
    .flatten()
    {
        snapshot.resources.extend(output.resources);
        snapshot.targets.extend(output.targets);
    }
    resolve_from_snapshot(&snapshot)
}

// ---------------------------------------------------------------------------
// 解析主体
// ---------------------------------------------------------------------------

enum ProcFile {
    Cmdline,
    Environ,
}

/// 读进程证据的能力（生产实现 [`RealProc`]，测试用假实现）。
trait KafkaProc {
    fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String>;
    /// 读一个文件；`path` 已含 `/proc/<pid>/root` 前缀。
    fn read_file(&self, path: &str) -> Option<String>;
}

struct ObservedProcess {
    pid: u32,
    exe: String,
}

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn KafkaProc,
    reach: &dyn Reachability,
) -> Vec<KafkaClusterEntry> {
    let ports = tcp_ports(snapshot);
    let mut out = Vec::new();
    let mut inspected = 0usize;

    for process in processes(snapshot) {
        if inspected >= MAX_INSPECTED_PROCESSES {
            break;
        }
        // 先按可执行名粗筛再读 argv：一台机器上进程上百个，
        // 每个都读 4 KiB 的 cmdline 是白花。不可执行名拿不到（空）时才老实读。
        if !may_be_broker(&process.exe) {
            continue;
        }
        let argv = proc.nul_list(process.pid, ProcFile::Cmdline);
        if !is_broker(&process.exe, &argv) {
            continue;
        }
        inspected += 1;
        let environ = proc.nul_list(process.pid, ProcFile::Environ);
        let source_ref = identity(&ports, process.pid);

        let Some(cluster) = cluster_from_evidence(&process, &argv, &environ, proc, &ports) else {
            continue;
        };
        out.push(finalize(cluster, source_ref, reach));
    }
    out
}

/// 把证据整理成一条候选（**还没探测端点**）。
struct RawCluster {
    broker_id: Option<i32>,
    listeners: Vec<KafkaListenerEntry>,
    mechanisms: Vec<String>,
    endpoints: Vec<(String, String)>, // (addr, source)
    evidence: &'static str,
    detail: String,
    confidence: i64,
}

fn cluster_from_evidence(
    process: &ObservedProcess,
    argv: &[String],
    environ: &[String],
    proc: &dyn KafkaProc,
    ports: &BTreeMap<u32, Vec<(String, u16)>>,
) -> Option<RawCluster> {
    // 1) server.properties（最权威：broker 真正在用的是什么）
    if let Some(path) = config_path(argv).or_else(|| existing_config(process.pid, proc)) {
        let full = rooted(process.pid, &path);
        if let Some(text) = proc.read_file(&full)
            && let Some(cluster) = from_properties(&text)
        {
            return Some(RawCluster {
                evidence: "server_properties",
                confidence: 90,
                detail: format!("Kafka broker 配置来自 {path}"),
                ..cluster
            });
        }
    }

    // 2) 容器环境变量（Bitnami 镜像把配置全放在 `KAFKA_CFG_*`）
    if let Some(cluster) = from_container_env(environ) {
        return Some(RawCluster {
            evidence: "container_env",
            confidence: 80,
            detail: "Kafka broker 配置来自容器环境变量 KAFKA_CFG_*".to_string(),
            ..cluster
        });
    }

    // 3) 兜底：该进程的监听端口（协议未知，至少告诉中心"这里有个 Kafka 进程"）
    let listening = ports.get(&process.pid)?;
    let listeners: Vec<KafkaListenerEntry> = listening
        .iter()
        .map(|(_, port)| KafkaListenerEntry {
            name: String::new(),
            protocol: "unknown".to_string(),
            port: *port,
        })
        .collect();
    let endpoints: Vec<(String, String)> = listening
        .iter()
        .map(|(ip, port)| {
            let host = if is_concrete_host(ip) {
                ip.as_str()
            } else {
                "127.0.0.1"
            };
            (endpoint_addr(host, *port), "loopback".to_string())
        })
        .collect();
    Some(RawCluster {
        broker_id: None,
        listeners,
        mechanisms: Vec::new(),
        endpoints,
        evidence: "listening_port",
        detail: "只看到 Kafka 进程的监听端口（配置文件不可读），协议未知".to_string(),
        confidence: 30,
    })
}

fn finalize(
    cluster: RawCluster,
    source_ref: String,
    reach: &dyn Reachability,
) -> KafkaClusterEntry {
    let mut seen = BTreeSet::new();
    let mut endpoints: Vec<KafkaEndpointEntry> = Vec::new();
    for (addr, source) in cluster.endpoints {
        if !seen.insert(addr.clone()) {
            continue;
        }
        if endpoints.len() >= MAX_ENDPOINTS_PER_CLUSTER {
            break;
        }
        let protocol = protocol_of(&cluster.listeners, &addr);
        let outcome = reach.probe(&addr, protocol);
        endpoints.push(KafkaEndpointEntry {
            addr,
            source,
            protocol: protocol.to_string(),
            reachable: outcome.tcp,
            kafka_api: outcome.kafka_api,
        });
    }
    // 排序：广告地址且握手成功 > 其它握手成功 > 能连 > 连不上（`sort_by_key` 稳定）。
    endpoints.sort_by_key(endpoint_rank);

    KafkaClusterEntry {
        source_ref,
        broker_id: cluster.broker_id,
        listeners: cluster.listeners,
        mechanisms: cluster.mechanisms,
        endpoints,
        evidence: cluster.evidence.to_string(),
        detail: cluster.detail,
        confidence: cluster.confidence,
    }
}

fn endpoint_rank(endpoint: &KafkaEndpointEntry) -> u8 {
    match (
        endpoint.kafka_api,
        endpoint.reachable,
        endpoint.source.as_str(),
    ) {
        (true, _, "advertised") => 0,
        (true, _, _) => 1,
        (false, true, "advertised") => 2,
        (false, true, _) => 3,
        (false, false, _) => 4,
    }
}

// ---------------------------------------------------------------------------
// 进程识别
// ---------------------------------------------------------------------------

fn processes(snapshot: &DiscoverySnapshot) -> Vec<ObservedProcess> {
    snapshot
        .resources
        .iter()
        .filter(|resource| resource.kind == "process")
        .filter_map(|resource| {
            let pid = resource.attributes.get("process.pid")?.parse().ok()?;
            let exe = resource
                .attributes
                .get("process.executable.name")
                .cloned()
                .unwrap_or_default();
            Some(ObservedProcess { pid, exe })
        })
        .collect()
}

/// 读 argv 之前的一道粗筛：只有 java / kafka 进程可能是 broker。
///
/// 可执行名拿不到（空）时返回 true —— 宁可多读一个 cmdline，也不要漏报一个真 broker。
fn may_be_broker(exe: &str) -> bool {
    if exe.is_empty() {
        return true;
    }
    let exe = exe.to_ascii_lowercase();
    exe.contains("java") || exe.contains("kafka")
}

/// 是不是 Kafka **broker**。
///
/// 只看「命令与主类」，**不看 classpath**：Bitnami 等发行版把 zookeeper / connect 的 jar
/// 也塞进 `-cp`，按整串 argv 匹配会把 KRaft broker 误判成 ZooKeeper（现场表现：
/// 「本机没有发现 Kafka broker」，而进程就在那儿）。
fn is_broker(exe: &str, argv: &[String]) -> bool {
    let tokens: Vec<String> = command_tokens(argv)
        .into_iter()
        .map(|token| token.to_ascii_lowercase())
        .collect();

    // 排除项：ZooKeeper / Connect / exporter 的**主类或启动脚本**，不是它们的 jar 名。
    if tokens.iter().any(|token| {
        token.contains("quorumpeermain")
            || token.contains("zookeeper-server-start")
            || token.contains("kafkaconnect")
            || token.contains("connect-distributed")
            || token.contains("connect-standalone")
            || token.contains("connectstandalone")
            || token.contains("connectdistributed")
            || token.contains("kafka-exporter")
    }) {
        return false;
    }

    if tokens
        .iter()
        .any(|token| token == "kafka.kafka" || token.ends_with(".kafka"))
    {
        return true;
    }
    if tokens
        .iter()
        .any(|token| token.contains("kafka-server-start"))
    {
        return true;
    }

    // 拿不到 argv 时的兜底：看可执行名（同样只取 basename，Linux 上是完整路径）。
    let name = std::path::Path::new(exe)
        .file_name()
        .map(|name| name.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    matches!(name.as_str(), "kafka" | "kafka-server")
}

/// 去掉 JVM 选项与 classpath 之后的「真命令」：`-cp <一大串 jar>` / `-Dkey=value`。
fn command_tokens(argv: &[String]) -> Vec<&str> {
    let mut out = Vec::new();
    let mut skip_next = false;
    for token in argv {
        if skip_next {
            skip_next = false;
            continue;
        }
        let token = token.trim();
        if matches!(token, "-cp" | "-classpath" | "--class-path") {
            skip_next = true;
            continue;
        }
        if token.contains(".jar")
            || token.starts_with("-D")
            || token.starts_with("-X")
            || token.starts_with("-javaagent")
        {
            continue;
        }
        out.push(token);
    }
    out
}

/// 配置路径线索：`-Dkafka.config.file=…` 或 `kafka-server-start.sh <path>`。
fn config_path(argv: &[String]) -> Option<String> {
    for token in argv {
        if let Some(value) = token.strip_prefix("-Dkafka.config.file=") {
            let value = value.trim();
            if !value.is_empty() {
                return Some(value.to_string());
            }
        }
    }
    // 只从**位置参数**里找，并且取最后一个：
    // - `-Dlog4j.configuration=file:…/log4j.properties` 也以 `.properties` 结尾，
    //   先命中会让 `from_properties` 去读 log4j 配置 —— 里面一个监听器都没有；
    // - 启动脚本把 broker 配置放在命令末尾（`kafka.Kafka <path>`）。
    argv.iter()
        .rev()
        .find(|token| {
            let token = token.trim();
            !token.starts_with('-') && token.ends_with(".properties")
        })
        .map(|token| token.trim().to_string())
}

/// 发行版默认位置（只有真读到文件才算）。
fn existing_config(pid: u32, proc: &dyn KafkaProc) -> Option<String> {
    for candidate in [
        "/opt/kafka/config/server.properties",
        "/etc/kafka/server.properties",
        "/opt/bitnami/kafka/config/server.properties",
    ] {
        if proc.read_file(&rooted(pid, candidate)).is_some() {
            return Some(candidate.to_string());
        }
    }
    None
}

/// 容器里跑的进程，配置里的路径是**容器视角**；`/proc/<pid>/root` 指向它自己的根。
fn rooted(pid: u32, path: &str) -> String {
    format!("/proc/{pid}/root{path}")
}

// ---------------------------------------------------------------------------
// 证据 → 配置
// ---------------------------------------------------------------------------

/// `server.properties` 里**允许读**的键（白名单，见模块注释的红线）。
const ALLOWED_KEYS: &[&str] = &[
    "listeners",
    "advertised.listeners",
    "listener.security.protocol.map",
    "inter.broker.listener.name",
    "security.inter.broker.protocol",
    "sasl.enabled.mechanisms",
    "sasl.mechanism.inter.broker.protocol",
    "broker.id",
    "node.id",
];

fn from_properties(text: &str) -> Option<RawCluster> {
    let mut props: BTreeMap<&str, String> = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with('!') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if ALLOWED_KEYS.contains(&key) {
            props.insert(key, value.trim().to_string());
        }
    }

    let bound = props
        .get("listeners")
        .map(|raw| parse_listeners(raw))
        .unwrap_or_default();
    let advertised = props
        .get("advertised.listeners")
        .map(|raw| parse_listeners(raw))
        .unwrap_or_default();
    if bound.is_empty() && advertised.is_empty() {
        return None;
    }
    let protocols = props
        .get("listener.security.protocol.map")
        .map(|map| parse_protocol_map(map))
        .unwrap_or_default();

    let mut cluster = build_cluster(
        props.get("node.id").or_else(|| props.get("broker.id")),
        bound,
        advertised,
        &protocols,
        props.get("sasl.enabled.mechanisms"),
        "server_properties",
    );
    cluster.detail = "Kafka broker 配置来自 server.properties".to_string();
    cluster.confidence = 90;
    Some(cluster)
}

fn from_container_env(environ: &[String]) -> Option<RawCluster> {
    let mut values: BTreeMap<&str, String> = BTreeMap::new();
    for entry in environ {
        let Some((key, value)) = entry.split_once('=') else {
            continue;
        };
        let key = key.trim();
        if matches!(
            key,
            "KAFKA_CFG_LISTENERS"
                | "KAFKA_CFG_ADVERTISED_LISTENERS"
                | "KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP"
                | "KAFKA_CFG_SASL_ENABLED_MECHANISMS"
                | "KAFKA_CFG_NODE_ID"
                | "KAFKA_CFG_BROKER_ID"
        ) {
            values.insert(key, value.trim().to_string());
        }
    }
    let bound = values
        .get("KAFKA_CFG_LISTENERS")
        .map(|raw| parse_listeners(raw))
        .unwrap_or_default();
    let advertised = values
        .get("KAFKA_CFG_ADVERTISED_LISTENERS")
        .map(|raw| parse_listeners(raw))
        .unwrap_or_default();
    if bound.is_empty() && advertised.is_empty() {
        return None;
    }
    let protocols = values
        .get("KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP")
        .map(|map| parse_protocol_map(map))
        .unwrap_or_default();
    let mut cluster = build_cluster(
        values
            .get("KAFKA_CFG_NODE_ID")
            .or_else(|| values.get("KAFKA_CFG_BROKER_ID")),
        bound,
        advertised,
        &protocols,
        values.get("KAFKA_CFG_SASL_ENABLED_MECHANISMS"),
        "container_env",
    );
    cluster.detail = "Kafka broker 配置来自容器环境变量 KAFKA_CFG_*".to_string();
    cluster.confidence = 80;
    Some(cluster)
}

struct ParsedListener {
    name: String,
    host: String,
    port: u16,
}

impl std::fmt::Debug for ParsedListener {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ParsedListener")
            .field("name", &self.name)
            .field("host", &self.host)
            .field("port", &self.port)
            .finish()
    }
}

/// 把 bind / advertised 两套监听器**按名字合并**成一份候选。
///
/// 为什么两套都要：`listeners` 是进程真正监听的端口（连它才知道本机该连哪），
/// `advertised.listeners` 是 broker 告诉客户端的地址（K8s / NAT 下两者不同）。
/// 只看其中一套会在这两种环境里直接采不到。
fn build_cluster(
    broker_id: Option<&String>,
    bound: Vec<ParsedListener>,
    advertised: Vec<ParsedListener>,
    protocols: &BTreeMap<String, String>,
    mechanisms: Option<&String>,
    evidence: &'static str,
) -> RawCluster {
    let mut names: Vec<String> = Vec::new();
    for listener in bound.iter().chain(advertised.iter()) {
        if !names.iter().any(|name| name == &listener.name) {
            names.push(listener.name.clone());
        }
    }

    let mut entries = Vec::new();
    let mut endpoints = Vec::new();
    for name in names {
        let listening = bound.iter().find(|listener| listener.name == name);
        let public = advertised.iter().find(|listener| listener.name == name);
        let protocol = protocols
            .get(&name)
            .cloned()
            .or_else(|| known_protocol(&name).then(|| name.clone()))
            .unwrap_or_else(|| "unknown".to_string());
        let port = listening
            .map(|listener| listener.port)
            .or_else(|| public.map(|listener| listener.port))
            .unwrap_or_default();
        entries.push(KafkaListenerEntry {
            name: name.clone(),
            protocol,
            port,
        });

        // 端点假设 ①：broker 自己告诉客户端用的地址
        if let Some(public) = public.filter(|listener| is_concrete_host(&listener.host)) {
            endpoints.push((
                endpoint_addr(&public.host, public.port),
                "advertised".to_string(),
            ));
        }
        // 端点假设 ②：bind 在具体 IP 上时，它本身就是可达地址
        if let Some(listener) = listening.filter(|listener| is_concrete_host(&listener.host)) {
            endpoints.push((
                endpoint_addr(&listener.host, listener.port),
                "listener".to_string(),
            ));
        }
        // 端点假设 ③：本机回环（hostNetwork / hostPort / NodePort 场景）
        if port > 0 {
            endpoints.push((endpoint_addr("127.0.0.1", port), "loopback".to_string()));
        }
    }

    RawCluster {
        broker_id: broker_id.and_then(|raw| raw.trim().parse().ok()),
        listeners: entries,
        mechanisms: mechanisms
            .map(|raw| {
                raw.split(',')
                    .map(|item| item.trim().to_string())
                    .filter(|item| !item.is_empty())
                    .collect()
            })
            .unwrap_or_default(),
        endpoints,
        evidence,
        detail: String::new(),
        confidence: 0,
    }
}

/// `INTERNAL://0.0.0.0:9092,EXTERNAL://:9094` → 结构化监听器。
fn parse_listeners(raw: &str) -> Vec<ParsedListener> {
    let mut out = Vec::new();
    for item in raw.split(',') {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((name, rest)) = item.split_once("://") else {
            continue;
        };
        let Some((host, port)) = rest.rsplit_once(':') else {
            continue;
        };
        let Ok(port) = port.trim().parse::<u16>() else {
            continue;
        };
        if port == 0 {
            continue;
        }
        out.push(ParsedListener {
            name: name.trim().to_string(),
            host: host.trim().to_string(),
            port,
        });
    }
    out
}

/// `INTERNAL:PLAINTEXT,EXTERNAL:SASL_SSL` → map。
fn parse_protocol_map(raw: &str) -> BTreeMap<String, String> {
    let mut map = BTreeMap::new();
    for item in raw.split(',') {
        let Some((name, protocol)) = item.trim().split_once(':') else {
            continue;
        };
        let protocol = protocol.trim().to_ascii_uppercase();
        if known_protocol(&protocol) {
            map.insert(name.trim().to_string(), protocol);
        }
    }
    map
}

fn known_protocol(raw: &str) -> bool {
    matches!(raw, "PLAINTEXT" | "SSL" | "SASL_PLAINTEXT" | "SASL_SSL")
}

fn is_concrete_host(host: &str) -> bool {
    !host.is_empty() && host != "0.0.0.0" && host != "::" && host != "[::]" && host != "*"
}

/// `host:port`（IPv6 字面量补方括号）。
fn endpoint_addr(host: &str, port: u16) -> String {
    let host = host.trim();
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// 这条端点的监听器协议（用于决定能不能做完整握手）。
fn protocol_of<'a>(listeners: &'a [KafkaListenerEntry], addr: &str) -> &'a str {
    let Some(port) = addr
        .rsplit_once(':')
        .and_then(|(_, port)| port.parse::<u16>().ok())
    else {
        return "unknown";
    };
    listeners
        .iter()
        .find(|listener| listener.port == port)
        .map(|listener| listener.protocol.as_str())
        .unwrap_or("unknown")
}

// ---------------------------------------------------------------------------
// 端点身份
// ---------------------------------------------------------------------------

/// 监听端口：`pid → [(bind ip, port)]`（只认 tcp）。
fn tcp_ports(snapshot: &DiscoverySnapshot) -> BTreeMap<u32, Vec<(String, u16)>> {
    let mut ports: BTreeMap<u32, BTreeSet<(String, u16)>> = BTreeMap::new();
    for resource in &snapshot.resources {
        if resource.kind != "service_endpoint" {
            continue;
        }
        let attrs = &resource.attributes;
        if attrs.get("endpoint.protocol").map(String::as_str) != Some("tcp") {
            continue;
        }
        let Some(pid) = attrs.get("process.pid").and_then(|pid| pid.parse().ok()) else {
            continue;
        };
        let Some(port) = attrs
            .get("endpoint.bind.port")
            .and_then(|port| port.parse().ok())
        else {
            continue;
        };
        let ip = attrs.get("endpoint.bind.ip").cloned().unwrap_or_default();
        ports.entry(pid).or_default().insert((ip, port));
    }
    ports
        .into_iter()
        .map(|(pid, set)| (pid, set.into_iter().collect()))
        .collect()
}

/// 身份优先用端口：pid 重启就换，同一实例换个 pid 不该多出一条候选。
fn identity(ports: &BTreeMap<u32, Vec<(String, u16)>>, pid: u32) -> String {
    ports
        .get(&pid)
        .and_then(|list| list.iter().map(|(_, port)| *port).min())
        .map(|port| format!("port:{port}"))
        .unwrap_or_else(|| format!("pid:{pid}"))
}

// ---------------------------------------------------------------------------
// 生产实现
// ---------------------------------------------------------------------------

struct RealProc;

impl KafkaProc for RealProc {
    fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String> {
        use std::io::Read;

        let name = match file {
            ProcFile::Cmdline => "cmdline",
            ProcFile::Environ => "environ",
        };
        let Ok(file) = std::fs::File::open(format!("/proc/{pid}/{name}")) else {
            return Vec::new();
        };
        let mut raw = Vec::new();
        // 先按**字节**封顶：进程的参数/环境可能很大，读满再切会白读。
        if file
            .take(MAX_PROC_BYTES as u64)
            .read_to_end(&mut raw)
            .is_err()
        {
            return Vec::new();
        }
        raw.split(|byte| *byte == 0)
            .map(|segment| String::from_utf8_lossy(segment).trim().to_string())
            .filter(|segment| !segment.is_empty())
            .collect()
    }

    fn read_file(&self, path: &str) -> Option<String> {
        use std::io::Read;
        let file = std::fs::File::open(path).ok()?;
        let mut raw = Vec::new();
        file.take(MAX_EVIDENCE_BYTES + 1)
            .read_to_end(&mut raw)
            .ok()?;
        if raw.len() as u64 > MAX_EVIDENCE_BYTES {
            return None;
        }
        String::from_utf8(raw).ok()
    }
}

#[cfg(test)]
mod tests;
