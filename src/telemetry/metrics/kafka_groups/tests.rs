//! 消费组链路的解析 / 编码单测，以及用假 broker 跑通一条完整链路。

use std::io::{Read, Write};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use super::*;
use crate::telemetry::metrics::kafka::PartitionInfo;

// ---------------------------------------------------------------------------
// 编码 / 解析
// ---------------------------------------------------------------------------

#[test]
fn list_groups_request_is_header_only() {
    let bytes = encode_list_groups_request(31, "wist-agentd", 2);
    let declared = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(declared as usize, bytes.len() - 4);
    assert_eq!(
        i16::from_be_bytes([bytes[4], bytes[5]]),
        API_KEY_LIST_GROUPS
    );
    assert_eq!(i16::from_be_bytes([bytes[6], bytes[7]]), 2);
    // v0-v2 请求体为空：请求刚好到 client_id 结束。
    assert_eq!(bytes.len(), 4 + 10 + "wist-agentd".len());
}

#[test]
fn describe_groups_request_carries_the_group_list() {
    let bytes = encode_describe_groups_request(32, "c", 4, &["orders", "payments"]);
    let declared = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
    assert_eq!(declared as usize, bytes.len() - 4);
    assert_eq!(
        i16::from_be_bytes([bytes[4], bytes[5]]),
        API_KEY_DESCRIBE_GROUPS
    );
    let body = &bytes[4 + 10 + 1..]; // header 之后（client_id 只有 1 字节）
    assert_eq!(i32::from_be_bytes([body[0], body[1], body[2], body[3]]), 2);
    assert_eq!(i16::from_be_bytes([body[4], body[5]]), 6);
    assert_eq!(&body[6..12], b"orders");
    // v3+ 末尾还有 include_authorized_operations：漏掉它真 broker 会直接断开连接
    // （假 broker 的解析器宽松，只有真机跑才能暴露）。
    assert_eq!(
        body[body.len() - 1],
        0,
        "include_authorized_operations = false"
    );

    // v2 没有这个字段。
    let v2 = encode_describe_groups_request(32, "c", 2, &["orders"]);
    let v2_body = &v2[4 + 10 + 1..];
    assert_eq!(v2_body.len(), 4 + 2 + 6, "v2 请求体只有 groups");
}

#[test]
fn offset_fetch_request_asks_for_every_topic() {
    let bytes = encode_offset_fetch_request(33, "c", 5, "orders");
    let body = &bytes[4 + 10 + 1..];
    // group_id + topics = null（-1）。用 null 而不是空数组：空数组 =「一个 topic 都不问」。
    assert_eq!(i16::from_be_bytes([body[0], body[1]]), 6);
    assert_eq!(&body[2..8], b"orders");
    assert_eq!(&body[8..12], &(-1i32).to_be_bytes());
}

#[test]
fn list_offsets_request_groups_by_topic_and_asks_for_the_log_end() {
    let partitions = vec![
        ("orders".to_string(), 1),
        ("orders".to_string(), 0),
        ("payments".to_string(), 3),
    ];
    let bytes = encode_list_offsets_request(34, "c", 5, &partitions);
    let body = &bytes[4 + 10 + 1..];
    assert_eq!(&body[0..4], &(-1i32).to_be_bytes(), "replica_id = -1");
    assert_eq!(body[4], 0, "isolation_level = READ_UNCOMMITTED（v2+ 才有）");
    assert_eq!(i32::from_be_bytes([body[5], body[6], body[7], body[8]]), 2);

    let mut reader = Reader::new(&body[9..]);
    let topic = reader.string().expect("topic");
    assert_eq!(topic, "orders", "topic 按字典序：orders 在 payments 前");
    assert_eq!(
        reader.array_len().expect("partitions"),
        2,
        "同 topic 的分区合并"
    );
    for expected in [0, 1] {
        assert_eq!(reader.i32().expect("index"), expected);
        assert_eq!(reader.i32().expect("current_leader_epoch"), -1); // v4+
        assert_eq!(reader.i64().expect("timestamp"), -1, "-1 = log end offset");
    }
    assert_eq!(reader.string().expect("second topic"), "payments");
}

#[test]
fn list_offsets_request_v1_has_no_isolation_level_or_leader_epoch() {
    let bytes = encode_list_offsets_request(34, "c", 1, &[("orders".to_string(), 0)]);
    let body = &bytes[4 + 10 + 1..];
    assert_eq!(&body[0..4], &(-1i32).to_be_bytes(), "replica_id");
    // v1 紧跟着就是 topics 数量：多一个 isolation_level 字节会让 broker 整体错位。
    assert_eq!(i32::from_be_bytes([body[4], body[5], body[6], body[7]]), 1);
    assert_eq!(i16::from_be_bytes([body[8], body[9]]), 6);
    assert_eq!(&body[10..16], b"orders");
    assert_eq!(
        i32::from_be_bytes([body[16], body[17], body[18], body[19]]),
        1
    );
    assert_eq!(
        i32::from_be_bytes([body[20], body[21], body[22], body[23]]),
        0
    );
    // v1 没有 current_leader_epoch：末尾直接是 timestamp。
    assert_eq!(body.len(), 24 + 8, "分区 = index + timestamp，没有别的");
    assert_eq!(&body[24..32], &(-1i64).to_be_bytes());
}

#[test]
fn parse_list_groups_handles_v0_and_v1_layouts() {
    // v0 没有 throttle_time_ms。
    let mut v0 = Vec::new();
    v0.extend_from_slice(&31i32.to_be_bytes());
    v0.extend_from_slice(&0i16.to_be_bytes());
    v0.extend_from_slice(&1i32.to_be_bytes());
    v0.extend_from_slice(&6i16.to_be_bytes());
    v0.extend_from_slice(b"orders");
    v0.extend_from_slice(&8i16.to_be_bytes());
    v0.extend_from_slice(b"consumer");

    let groups = parse_list_groups(&v0, 31, 0).expect("v0");
    assert_eq!(groups, vec![("orders".to_string(), "consumer".to_string())]);

    // v1 多了 throttle：漏读它会把 0 当成组数量。
    let mut v1 = Vec::new();
    v1.extend_from_slice(&31i32.to_be_bytes());
    v1.extend_from_slice(&0i32.to_be_bytes()); // throttle
    v1.extend_from_slice(&0i16.to_be_bytes());
    v1.extend_from_slice(&1i32.to_be_bytes());
    v1.extend_from_slice(&6i16.to_be_bytes());
    v1.extend_from_slice(b"orders");
    v1.extend_from_slice(&8i16.to_be_bytes());
    v1.extend_from_slice(b"consumer");
    assert_eq!(parse_list_groups(&v1, 31, 1).expect("v1").len(), 1);
}

#[test]
fn parse_list_groups_reports_a_broker_error() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&31i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&30i16.to_be_bytes()); // CLUSTER_AUTHORIZATION_FAILED
    buf.extend_from_slice(&0i32.to_be_bytes());
    let err = parse_list_groups(&buf, 31, 1).expect_err("must fail");
    assert!(err.to_string().contains("30"), "{err}");
}

#[test]
fn parse_describe_groups_reads_state_and_error() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&32i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes()); // throttle
    buf.extend_from_slice(&2i32.to_be_bytes()); // groups
    // 组 1：正常
    buf.extend_from_slice(&0i16.to_be_bytes());
    buf.extend_from_slice(&6i16.to_be_bytes());
    buf.extend_from_slice(b"orders");
    buf.extend_from_slice(&18i16.to_be_bytes());
    buf.extend_from_slice(b"PreparingRebalance");
    // 组 2：不存在
    buf.extend_from_slice(&69i16.to_be_bytes());
    buf.extend_from_slice(&4i16.to_be_bytes());
    buf.extend_from_slice(b"gone");
    buf.extend_from_slice(&4i16.to_be_bytes());
    buf.extend_from_slice(b"Dead");

    let groups = parse_describe_groups(&buf, 32, 4).expect("parse");
    assert_eq!(
        groups[0],
        ("orders".to_string(), "PreparingRebalance".to_string(), 0)
    );
    assert_eq!(groups[1].2, 69, "GROUP_ID_NOT_FOUND 要原样带出来");
}

#[test]
fn parse_offset_fetch_v5_reads_leader_epoch_and_skips_uncommitted() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&33i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes()); // throttle（v3+）
    buf.extend_from_slice(&1i32.to_be_bytes()); // topics
    buf.extend_from_slice(&6i16.to_be_bytes());
    buf.extend_from_slice(b"orders");
    buf.extend_from_slice(&2i32.to_be_bytes()); // partitions
    // 分区 0：有提交位点
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&100i64.to_be_bytes());
    buf.extend_from_slice(&(-1i32).to_be_bytes()); // leader_epoch（v5+）
    buf.extend_from_slice(&(-1i16).to_be_bytes()); // metadata = null
    buf.extend_from_slice(&0i16.to_be_bytes());
    // 分区 1：-1 = 没提交过
    buf.extend_from_slice(&1i32.to_be_bytes());
    buf.extend_from_slice(&(-1i64).to_be_bytes());
    buf.extend_from_slice(&(-1i32).to_be_bytes());
    buf.extend_from_slice(&(-1i16).to_be_bytes());
    buf.extend_from_slice(&0i16.to_be_bytes());
    buf.extend_from_slice(&0i16.to_be_bytes()); // 顶层 error_code

    let (committed, failed) = parse_offset_fetch(&buf, 33, 5).expect("parse");
    assert_eq!(
        committed,
        vec![Committed {
            topic: "orders".to_string(),
            partition: 0,
            offset: 100
        }]
    );
    assert_eq!(failed, 0, "-1 是「没提交过」，不是失败");
}

#[test]
fn parse_offset_fetch_surfaces_the_group_level_error() {
    let mut buf = Vec::new();
    buf.extend_from_slice(&33i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes());
    buf.extend_from_slice(&0i32.to_be_bytes()); // topics 空
    buf.extend_from_slice(&16i16.to_be_bytes()); // NOT_COORDINATOR
    let err = parse_offset_fetch(&buf, 33, 5).expect_err("must fail");
    assert!(err.to_string().contains("16"), "{err}");
}

#[test]
fn parse_list_offsets_v1_and_v4_layouts() {
    // v1：没有 throttle，分区里没有 leader_epoch。
    let mut v1 = Vec::new();
    v1.extend_from_slice(&34i32.to_be_bytes());
    v1.extend_from_slice(&1i32.to_be_bytes());
    v1.extend_from_slice(&6i16.to_be_bytes());
    v1.extend_from_slice(b"orders");
    v1.extend_from_slice(&1i32.to_be_bytes());
    v1.extend_from_slice(&0i32.to_be_bytes());
    v1.extend_from_slice(&0i16.to_be_bytes());
    v1.extend_from_slice(&0i64.to_be_bytes());
    v1.extend_from_slice(&150i64.to_be_bytes());
    assert_eq!(
        parse_list_offsets(&v1, 34, 1).expect("v1"),
        (vec![(("orders".to_string(), 0), 150)], 0)
    );

    // v4：多一个 throttle 和一个 leader_epoch。
    let mut v4 = Vec::new();
    v4.extend_from_slice(&34i32.to_be_bytes());
    v4.extend_from_slice(&0i32.to_be_bytes());
    v4.extend_from_slice(&1i32.to_be_bytes());
    v4.extend_from_slice(&6i16.to_be_bytes());
    v4.extend_from_slice(b"orders");
    v4.extend_from_slice(&1i32.to_be_bytes());
    v4.extend_from_slice(&0i32.to_be_bytes());
    v4.extend_from_slice(&0i16.to_be_bytes());
    v4.extend_from_slice(&0i64.to_be_bytes());
    v4.extend_from_slice(&150i64.to_be_bytes());
    v4.extend_from_slice(&3i32.to_be_bytes());
    assert_eq!(
        parse_list_offsets(&v4, 34, 4).expect("v4"),
        (vec![(("orders".to_string(), 0), 150)], 0)
    );
}

/// 分区级 `error_code` 不能静默丢掉：它是「lag 看起来正常」的来源之一。
#[test]
fn partition_level_errors_are_counted_not_dropped() {
    // OffsetFetch：分区 0 正常，分区 1 无权限。
    let mut fetch = Vec::new();
    fetch.extend_from_slice(&33i32.to_be_bytes());
    fetch.extend_from_slice(&0i32.to_be_bytes());
    fetch.extend_from_slice(&1i32.to_be_bytes());
    fetch.extend_from_slice(&6i16.to_be_bytes());
    fetch.extend_from_slice(b"orders");
    fetch.extend_from_slice(&2i32.to_be_bytes());
    for (partition, offset, error) in [(0i32, 100i64, 0i16), (1, 200, 29)] {
        fetch.extend_from_slice(&partition.to_be_bytes());
        fetch.extend_from_slice(&offset.to_be_bytes());
        fetch.extend_from_slice(&(-1i32).to_be_bytes());
        fetch.extend_from_slice(&(-1i16).to_be_bytes());
        fetch.extend_from_slice(&error.to_be_bytes());
    }
    fetch.extend_from_slice(&0i16.to_be_bytes());
    let (offsets, failed) = parse_offset_fetch(&fetch, 33, 5).expect("parse");
    assert_eq!(offsets.len(), 1);
    assert_eq!(failed, 1, "分区级 error 要计数");

    // ListOffsets：分区 0 正常，分区 1 NOT_LEADER。
    let mut ends = Vec::new();
    ends.extend_from_slice(&34i32.to_be_bytes());
    ends.extend_from_slice(&0i32.to_be_bytes());
    ends.extend_from_slice(&1i32.to_be_bytes());
    ends.extend_from_slice(&6i16.to_be_bytes());
    ends.extend_from_slice(b"orders");
    ends.extend_from_slice(&2i32.to_be_bytes());
    for (partition, error, offset) in [(0i32, 0i16, 150i64), (1, 6, -1)] {
        ends.extend_from_slice(&partition.to_be_bytes());
        ends.extend_from_slice(&error.to_be_bytes());
        ends.extend_from_slice(&0i64.to_be_bytes());
        ends.extend_from_slice(&offset.to_be_bytes());
        ends.extend_from_slice(&(-1i32).to_be_bytes());
    }
    let (offsets, failed) = parse_list_offsets(&ends, 34, 5).expect("parse");
    assert_eq!(offsets, vec![(("orders".to_string(), 0), 150)]);
    assert_eq!(failed, 1, "NOT_LEADER 要计数");
}

#[test]
fn group_state_is_normalized_to_the_documented_values() {
    for (raw, expected) in [
        ("Stable", "stable"),
        ("Empty", "empty"),
        ("Dead", "dead"),
        ("PreparingRebalance", "rebalancing"),
        ("CompletingRebalance", "rebalancing"),
        ("", "unknown"),
        ("SomethingNew", "unknown"),
    ] {
        assert_eq!(group_state(raw), expected, "raw = {raw:?}");
    }
}

#[test]
fn truncated_response_is_an_error_not_a_panic() {
    assert!(parse_list_groups(&[0, 0], 31, 1).is_err());
    assert!(parse_describe_groups(&[0, 0], 32, 4).is_err());
    assert!(parse_offset_fetch(&[0, 0], 33, 5).is_err());
    assert!(parse_list_offsets(&[0, 0], 34, 4).is_err());
}

// ---------------------------------------------------------------------------
// 假 broker：一条完整链路
// ---------------------------------------------------------------------------

/// 假 broker：协商 + 消费组四个 API。每条连接一个线程（`Links` 会缓存连接不关）。
struct FakeKafka {
    port: u16,
    stop: Arc<AtomicBool>,
    accept: Option<std::thread::JoinHandle<()>>,
    workers: Arc<Mutex<Vec<std::thread::JoinHandle<()>>>>,
}

impl FakeKafka {
    fn start<F>(responder: F) -> Self
    where
        F: Fn(i16, i16, i32) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::start_with_port(move |_, api_key, version, correlation| {
            responder(api_key, version, correlation)
        })
    }

    /// 需要把自己的端口写进响应（metadata 的 advertised 地址）时用这个。
    fn start_with_port<F>(responder: F) -> Self
    where
        F: Fn(u16, i16, i16, i32) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        Self::start_with_body(move |port, api_key, version, correlation, _body| {
            responder(port, api_key, version, correlation)
        })
    }

    /// 需要看**请求体**才能回答时用这个（比如按请求里的组名回不同的位点）。
    fn start_with_body<F>(responder: F) -> Self
    where
        F: Fn(u16, i16, i16, i32, &[u8]) -> Option<Vec<u8>> + Send + Sync + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        listener.set_nonblocking(true).expect("nonblocking");
        let port = listener.local_addr().expect("addr").port();
        let stop = Arc::new(AtomicBool::new(false));
        let workers = Arc::new(Mutex::new(Vec::new()));
        let responder = Arc::new(responder);

        let accept = {
            let stop = stop.clone();
            let workers = workers.clone();
            std::thread::spawn(move || {
                while !stop.load(Ordering::Relaxed) {
                    match listener.accept() {
                        Ok((stream, _)) => {
                            let responder = responder.clone();
                            let handle = std::thread::spawn(move || {
                                serve_connection(stream, port, responder.as_ref());
                            });
                            if let Ok(mut guard) = workers.lock() {
                                guard.push(handle);
                            }
                        }
                        Err(err) if err.kind() == std::io::ErrorKind::WouldBlock => {
                            std::thread::sleep(Duration::from_millis(1));
                        }
                        Err(_) => break,
                    }
                }
            })
        };

        Self {
            port,
            stop,
            accept: Some(accept),
            workers,
        }
    }
}

impl Drop for FakeKafka {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(accept) = self.accept.take() {
            let _ = accept.join();
        }
        if let Ok(mut workers) = self.workers.lock() {
            for worker in workers.drain(..) {
                let _ = worker.join();
            }
        }
    }
}

fn serve_connection<F>(mut stream: std::net::TcpStream, port: u16, responder: &F)
where
    F: Fn(u16, i16, i16, i32, &[u8]) -> Option<Vec<u8>>,
{
    // macOS / BSD 上 accept 出来的 socket 会继承监听器的 O_NONBLOCK：
    // 不显式改回阻塞模式，`read_exact` 会立刻返回 WouldBlock（不是超时）。
    stream.set_nonblocking(false).ok();
    stream.set_read_timeout(Some(Duration::from_secs(5))).ok();
    loop {
        let mut size = [0u8; 4];
        if stream.read_exact(&mut size).is_err() {
            return; // 对端关闭 / 超时
        }
        let len = i32::from_be_bytes(size);
        if len < 0 {
            return;
        }
        let mut body = vec![0u8; len as usize];
        if stream.read_exact(&mut body).is_err() {
            return;
        }
        let api_key = i16::from_be_bytes([body[0], body[1]]);
        let version = i16::from_be_bytes([body[2], body[3]]);
        let correlation = i32::from_be_bytes([body[4], body[5], body[6], body[7]]);
        let Some(response) = responder(port, api_key, version, correlation, &body) else {
            continue;
        };
        if stream
            .write_all(&(response.len() as i32).to_be_bytes())
            .and_then(|_| stream.write_all(&response))
            .and_then(|_| stream.flush())
            .is_err()
        {
            return;
        }
    }
}

/// `ApiVersions` v0 响应：`extra` 决定本 broker 声明了哪些能力。
fn api_versions_body(correlation: i32, extra: &[(i16, i16, i16)]) -> Vec<u8> {
    // Metadata 是必需项（没它 `connect()` 直接报错），其余由 `extra` 决定。
    let mut apis = vec![(18, 0, 4), (3, 0, 2)];
    apis.extend_from_slice(extra);
    let mut body = Vec::new();
    body.extend_from_slice(&correlation.to_be_bytes());
    body.extend_from_slice(&0i16.to_be_bytes());
    body.extend_from_slice(&(apis.len() as i32).to_be_bytes());
    for (key, min, max) in apis {
        body.extend_from_slice(&key.to_be_bytes());
        body.extend_from_slice(&min.to_be_bytes());
        body.extend_from_slice(&max.to_be_bytes());
    }
    body
}

const GROUP_APIS: &[(i16, i16, i16)] = &[
    (API_KEY_LIST_GROUPS, 0, 2),
    (API_KEY_DESCRIBE_GROUPS, 0, 4),
    (API_KEY_OFFSET_FETCH, 2, 5),
    (API_KEY_LIST_OFFSETS, 1, 5),
];

fn list_groups_body(correlation: i32, groups: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&correlation.to_be_bytes());
    body.extend_from_slice(&0i32.to_be_bytes()); // throttle（v1+）
    body.extend_from_slice(&0i16.to_be_bytes());
    body.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for (group, protocol) in groups {
        body.extend_from_slice(&(group.len() as i16).to_be_bytes());
        body.extend_from_slice(group.as_bytes());
        body.extend_from_slice(&(protocol.len() as i16).to_be_bytes());
        body.extend_from_slice(protocol.as_bytes());
    }
    body
}

fn describe_groups_body(correlation: i32, groups: &[(&str, &str)]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&correlation.to_be_bytes());
    body.extend_from_slice(&0i32.to_be_bytes());
    body.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for (group, state) in groups {
        body.extend_from_slice(&0i16.to_be_bytes());
        body.extend_from_slice(&(group.len() as i16).to_be_bytes());
        body.extend_from_slice(group.as_bytes());
        body.extend_from_slice(&(state.len() as i16).to_be_bytes());
        body.extend_from_slice(state.as_bytes());
        // 后面的 protocol_type / members 不读；真 broker 会发，夹具停在这里也合法。
    }
    body
}

fn offset_fetch_body(correlation: i32, topic: &str, offsets: &[i64]) -> Vec<u8> {
    let partitions: Vec<(i64, i16)> = offsets.iter().map(|offset| (*offset, 0)).collect();
    offset_fetch_body_with(correlation, &[(topic, partitions.as_slice())])
}

/// 带分区级 error_code 的版本：`(offset, error_code)`。
fn offset_fetch_body_with(correlation: i32, topics: &[(&str, &[(i64, i16)])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&correlation.to_be_bytes());
    body.extend_from_slice(&0i32.to_be_bytes()); // throttle
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for (index, (offset, error)) in partitions.iter().enumerate() {
            body.extend_from_slice(&(index as i32).to_be_bytes());
            body.extend_from_slice(&offset.to_be_bytes());
            body.extend_from_slice(&(-1i32).to_be_bytes()); // leader_epoch（v5+）
            body.extend_from_slice(&(-1i16).to_be_bytes()); // metadata = null
            body.extend_from_slice(&error.to_be_bytes());
        }
    }
    body.extend_from_slice(&0i16.to_be_bytes()); // 顶层 error_code
    body
}

fn list_offsets_body(correlation: i32, topic: &str, ends: &[i64]) -> Vec<u8> {
    let partitions: Vec<(i64, i16)> = ends.iter().map(|end| (*end, 0)).collect();
    list_offsets_body_with(correlation, &[(topic, partitions.as_slice())])
}

/// 带分区级 error_code 的版本：`(log_end_offset, error_code)`。
fn list_offsets_body_with(correlation: i32, topics: &[(&str, &[(i64, i16)])]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&correlation.to_be_bytes());
    body.extend_from_slice(&0i32.to_be_bytes()); // throttle（v2+）
    body.extend_from_slice(&(topics.len() as i32).to_be_bytes());
    for (topic, partitions) in topics {
        body.extend_from_slice(&(topic.len() as i16).to_be_bytes());
        body.extend_from_slice(topic.as_bytes());
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for (index, (end, error)) in partitions.iter().enumerate() {
            body.extend_from_slice(&(index as i32).to_be_bytes());
            body.extend_from_slice(&error.to_be_bytes());
            body.extend_from_slice(&0i64.to_be_bytes()); // timestamp
            body.extend_from_slice(&end.to_be_bytes());
            body.extend_from_slice(&(-1i32).to_be_bytes()); // leader_epoch（v4+）
        }
    }
    body
}

fn metadata_for(port: u16, partitions: &[(&str, i32)]) -> Metadata {
    Metadata {
        cluster_key: "test-cluster1".to_string(),
        cluster_id: Some("test-cluster1".to_string()),
        brokers: vec![Broker {
            node_id: 1,
            host: "127.0.0.1".to_string(),
            port: port as i32,
        }],
        controller_id: 1,
        partitions: partitions
            .iter()
            .map(|(topic, partition)| PartitionInfo {
                topic: topic.to_string(),
                partition: *partition,
                leader: 1,
                replicas: vec![1],
                isr: vec![1],
            })
            .collect(),
    }
}

fn collect_with(metadata: &Metadata, policy: &GroupPolicy) -> GroupCollection {
    collect(
        metadata,
        &SecurityConfig {
            protocol: "PLAINTEXT",
            mechanism: "auto",
            username: None,
            password_file: None,
            tls_ca_file: None,
        },
        Duration::from_millis(500),
        policy,
    )
}

fn fact<'a>(facts: &'a [MetricsLabeledFact], key: &str, group: &str) -> Option<&'a str> {
    facts
        .iter()
        .find(|fact| {
            fact.key == key
                && fact
                    .labels
                    .iter()
                    .any(|label| label.key == "group" && label.value == group)
        })
        .map(|fact| fact.value.as_str())
}

// ---- 请求体里的组名（假 broker 要按组回不同的位点）----

fn request_group(body: &[u8], describe_groups: bool) -> String {
    // 请求头：api_key(2) + version(2) + correlation_id(4) + client_id(i16 长度 + 字节)
    let client_len = i16::from_be_bytes([body[8], body[9]]) as usize;
    let mut at = 10 + client_len;
    if describe_groups {
        at += 4; // groups 数组长度（本探针一次只问一个组）
    }
    let len = i16::from_be_bytes([body[at], body[at + 1]]) as usize;
    at += 2;
    String::from_utf8_lossy(&body[at..at + len]).to_string()
}

/// 一轮里每个分区只问一次 LEO：请求数从 `组数 × leader 数` 降到 `leader 数`。
///
/// 这不是「省一点」：默认 `max_groups=200`、单轮预算 20s，不缓存时大集群会把预算
/// 耗在重复请求上，后面的组整轮没数据（只留一条 warning）。
#[test]
fn one_round_fetches_each_partition_end_offset_once() {
    let list_offsets_calls = Arc::new(AtomicUsize::new(0));
    let counter = list_offsets_calls.clone();
    let broker =
        FakeKafka::start_with_body(
            move |_port, api_key, _version, correlation, body| match api_key {
                18 => Some(api_versions_body(correlation, GROUP_APIS)),
                API_KEY_LIST_GROUPS => Some(list_groups_body(
                    correlation,
                    &[("orders", "consumer"), ("payments", "consumer")],
                )),
                API_KEY_DESCRIBE_GROUPS => {
                    let group = request_group(body, true);
                    Some(describe_groups_body(
                        correlation,
                        &[(group.as_str(), "Stable")],
                    ))
                }
                API_KEY_OFFSET_FETCH => {
                    let group = request_group(body, false);
                    // orders 提交到 100，payments 提交到 50；两者的 LEO 都是 150。
                    let offset = if group == "orders" { 100 } else { 50 };
                    Some(offset_fetch_body(correlation, "orders", &[offset]))
                }
                API_KEY_LIST_OFFSETS => {
                    counter.fetch_add(1, Ordering::Relaxed);
                    Some(list_offsets_body(correlation, "orders", &[150]))
                }
                _ => None,
            },
        );

    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string(), "payments".to_string()],
        ..GroupPolicy::default()
    };
    let collected = collect_with(&metadata, &policy);

    // 缓存不能把两个组算成同一个读数。
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), Some("50"));
    assert_eq!(fact(&collected.facts, FACT_LAG, "payments"), Some("100"));
    assert_eq!(
        list_offsets_calls.load(Ordering::Relaxed),
        1,
        "同一个分区在一轮里只该问一次（两个组共用一个 LEO 快照）"
    );
}

#[test]
fn collects_lag_and_state_through_the_whole_chain() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100, 200])),
        // LEO 150 / 200 → 分区 0 积压 50，分区 1 为 0。
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150, 200])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0), ("orders", 1)]);
    let policy = GroupPolicy {
        // 阈值模式默认会丢掉 50 的小积压，用白名单把它留下来。
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert!(collected.warnings.is_empty(), "{:?}", collected.warnings);
    assert_eq!(collected.dropped_groups, 0);
    assert_eq!(fact(&collected.facts, FACT_STATE, "orders"), Some("stable"));
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), Some("50"));

    let lag = collected
        .facts
        .iter()
        .find(|fact| fact.key == FACT_LAG)
        .expect("lag fact");
    assert!(
        lag.labels
            .iter()
            .any(|label| label.key == "topic" && label.value == "orders"),
        "lag 必须带 topic label（同一个组可能订阅多个 topic）: {lag:?}"
    );
}

#[test]
fn threshold_mode_keeps_groups_that_are_really_behind() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[5_100])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);

    // 默认阈值 1000：5100 > 1000 → 发。
    let collected = collect_with(&metadata, &GroupPolicy::default());
    assert!(collected.warnings.is_empty(), "{:?}", collected.warnings);
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), Some("5000"));
}

#[test]
fn small_lag_is_dropped_in_threshold_mode_but_state_still_reported() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Empty")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);

    let collected = collect_with(&metadata, &GroupPolicy::default());
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), None);
    assert_eq!(
        fact(&collected.facts, FACT_STATE, "orders"),
        Some("empty"),
        "状态不受 lag 阈值影响（否则 rebalance 中的组会隐身）"
    );
}

#[test]
fn non_consumer_groups_are_skipped() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(
            correlation,
            &[("orders", "consumer"), ("connect-cluster", "connect")],
        )),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[100])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);

    let collected = collect_with(&metadata, &GroupPolicy::default());
    assert!(
        collected.facts.iter().all(|fact| !fact
            .labels
            .iter()
            .any(|label| label.value == "connect-cluster")),
        "非 consumer 组不产生 lag / state 序列"
    );
}

#[test]
fn max_groups_truncates_and_reports_dropped_groups() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(
            correlation,
            &[
                ("a-group", "consumer"),
                ("b-group", "consumer"),
                ("c-group", "consumer"),
            ],
        )),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("a-group", "Empty")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[100])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        max_groups: 1,
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(collected.dropped_groups, 2, "截断必须计数，不能静默丢弃");
    let states: Vec<&str> = collected
        .facts
        .iter()
        .filter(|fact| fact.key == FACT_STATE)
        .map(|fact| fact.value.as_str())
        .collect();
    assert_eq!(states, vec!["empty"], "按组名稳定截断，只查第一个组");
}

#[test]
fn a_broker_without_list_offsets_only_loses_the_lag_reading() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(
            correlation,
            &[
                (API_KEY_LIST_GROUPS, 0, 2),
                (API_KEY_DESCRIBE_GROUPS, 0, 4),
                (API_KEY_OFFSET_FETCH, 2, 5),
                // 故意不声明 ListOffsets。
            ],
        )),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(
        fact(&collected.facts, FACT_STATE, "orders"),
        Some("stable"),
        "没有 ListOffsets 不影响组状态"
    );
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), None);
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("ListOffsets")),
        "少了一类读数必须留痕：{:?}",
        collected.warnings
    );
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("lag 会偏低")),
        "拿不到 LEO 要说清楚会偏低：{:?}",
        collected.warnings
    );
}

#[test]
fn describe_group_errors_are_isolated_per_group() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(
            correlation,
            &[("orders", "consumer"), ("broken", "consumer")],
        )),
        // 不管问哪个组都只回 broken：orders 应该报错而不是拿到 broken 的状态。
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("broken", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[100])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);

    let collected = collect_with(&metadata, &GroupPolicy::default());
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("组 orders DescribeGroups 失败")),
        "{:?}",
        collected.warnings
    );
    assert_eq!(fact(&collected.facts, FACT_STATE, "broken"), Some("stable"));
}

#[test]
fn an_unreachable_coordinator_is_reported_not_fatal() {
    // 端口 1 必定拒绝连接；不用「先绑再放」的临时端口（会被并行用例抢到，变成 flaky）。
    let dead_port = 1u16;
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[100])),
        _ => None,
    });
    let mut metadata = metadata_for(broker.port, &[("orders", 0)]);
    metadata.brokers.push(Broker {
        node_id: 2,
        host: "127.0.0.1".to_string(),
        port: dead_port as i32,
    });

    let collected = collect_with(&metadata, &GroupPolicy::default());
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("broker 2")),
        "{:?}",
        collected.warnings
    );
    assert_eq!(
        fact(&collected.facts, FACT_STATE, "orders"),
        Some("stable"),
        "另一个 broker 挂了不能拖垮能连上的那些组"
    );
}

#[test]
fn repeated_collections_produce_identical_fact_order() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body_with(
            correlation,
            &[("orders", &[(100, 0)])],
        )),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body_with(
            correlation,
            &[("orders", &[(150, 0)])],
        )),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let first = collect_with(&metadata, &policy);
    let second = collect_with(&metadata, &policy);
    assert_eq!(
        first.facts, second.facts,
        "同一份输入必须产出同一顺序（否则快照每轮都在抖）"
    );
    let keys: Vec<&str> = first.facts.iter().map(|fact| fact.key.as_str()).collect();
    assert_eq!(
        keys,
        vec![FACT_LAG, FACT_STATE],
        "排序按 fact key：lag 在 state 之前"
    );
}

// ---------------------------------------------------------------------------
// 与探针主循环接上：组读数挂在集群级 target 上
// ---------------------------------------------------------------------------

/// 白名单必须**先于** `max_groups` 生效：大集群里只看几个关键组是白名单的主场景。
#[test]
fn allowlist_survives_max_groups_truncation() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(
            correlation,
            &[
                ("a-group", "consumer"),
                ("b-group", "consumer"),
                ("c-group", "consumer"),
            ],
        )),
        API_KEY_DESCRIBE_GROUPS => {
            Some(describe_groups_body(correlation, &[("c-group", "Stable")]))
        }
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[100])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["c-group".to_string()],
        max_groups: 1,
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(
        fact(&collected.facts, FACT_STATE, "c-group"),
        Some("stable"),
        "白名单里的组不能被 max_groups 截掉：{:?}",
        collected.warnings
    );
    assert_eq!(
        fact(&collected.facts, FACT_STATE, "a-group"),
        None,
        "不在白名单里的组不查"
    );
    assert_eq!(collected.dropped_groups, 0, "先筛后截断，没有丢弃");
}

/// 提交位点超过 LEO（retention 删了尾巴）：按 0，不报负数。
#[test]
fn negative_lag_is_clamped_to_zero() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[500])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), Some("0"));
}

/// 新组（从未提交过位点）：没有 lag 序列，而不是发一个 0（0 = 追上了，语义完全不同）。
#[test]
fn group_without_committed_offsets_has_no_lag_series() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("brand-new", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(
            correlation,
            &[("brand-new", "Stable")],
        )),
        // 所有分区都是 -1（没提交过）。
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[-1])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[1_000])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["brand-new".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(fact(&collected.facts, FACT_LAG, "brand-new"), None);
    assert_eq!(
        fact(&collected.facts, FACT_STATE, "brand-new"),
        Some("stable"),
        "状态照常上送"
    );
    assert!(collected.warnings.is_empty(), "{:?}", collected.warnings);
}

/// 一个组订阅多个 topic：lag 按 topic 拆成多条序列（否则定位不到积压源）。
#[test]
fn multiple_topics_get_separate_lag_series() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body_with(
            correlation,
            &[
                ("orders", &[(100, 0), (200, 0)]),
                ("payments", &[(1_000, 0)]),
            ],
        )),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body_with(
            correlation,
            &[
                ("orders", &[(150, 0), (200, 0)]),
                ("payments", &[(1_400, 0)]),
            ],
        )),
        _ => None,
    });
    let metadata = metadata_for(
        broker.port,
        &[("orders", 0), ("orders", 1), ("payments", 0)],
    );
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    let lags: Vec<(&str, &str)> = collected
        .facts
        .iter()
        .filter(|fact| fact.key == FACT_LAG)
        .map(|fact| (label_of(fact, "topic"), fact.value.as_str()))
        .collect();
    assert_eq!(lags, vec![("orders", "50"), ("payments", "400")]);
}

/// 元数据过期（NOT_LEADER）导致某些分区拿不到 LEO：lag 偏低必须被说出来。
#[test]
fn list_offsets_partition_error_is_surfaced_as_a_warning() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100, 200])),
        // 分区 1 是 NOT_LEADER_OR_FOLLOWER，拿不到 LEO。
        API_KEY_LIST_OFFSETS => Some(list_offsets_body_with(
            correlation,
            &[("orders", &[(150, 0), (-1, 6)])],
        )),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0), ("orders", 1)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(
        fact(&collected.facts, FACT_LAG, "orders"),
        Some("50"),
        "只算拿得到 LEO 的分区"
    );
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("1 个分区拿不到 log end offset")),
        "少算的分区必须留痕：{:?}",
        collected.warnings
    );
}

#[test]
fn many_group_failures_collapse_into_one_line_per_reason() {
    // 200 个组同时没权限 / 协调者都在迁移：一轮该只占两行，不能刷 200 行。
    let mut warnings = GroupWarnings::default();
    for index in 0..50 {
        let group = format!("g-{index:02}");
        warnings.failure(
            "DescribeGroups 失败：error_code 15（组不存在 / 无权限）".to_string(),
            &group,
        );
        warnings.partitions("拿不到 log end offset（lag 会偏低）", &group, 2);
    }

    let lines = warnings.finish();
    assert_eq!(lines.len(), 2, "{lines:?}");
    assert!(
        lines[0].starts_with("50 个组（如 g-00, g-01, g-02…） DescribeGroups 失败"),
        "{:?}",
        lines[0]
    );
    assert!(lines[1].contains("共 100 个分区"), "{:?}", lines[1]);
}

#[test]
fn a_single_group_warning_keeps_the_plain_sentence() {
    // 单组时保持原来的写法：现场按关键字 grep 的历史习惯不变。
    let mut warnings = GroupWarnings::default();
    warnings.failure("DescribeGroups 失败：boom".to_string(), "orders");
    warnings.partitions("拿不到 log end offset（lag 会偏低）", "orders", 3);

    let lines = warnings.finish();
    assert_eq!(lines[0], "组 orders DescribeGroups 失败：boom");
    assert_eq!(
        lines[1],
        "组 orders 有 3 个分区拿不到 log end offset（lag 会偏低）"
    );
}

#[test]
fn many_isolated_group_errors_produce_a_single_warning_line() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(
            correlation,
            &[
                ("g1", "consumer"),
                ("g2", "consumer"),
                ("g3", "consumer"),
                ("g4", "consumer"),
            ],
        )),
        // 不论问哪个组都回别的组名：四个组都报「返回的组不对」。
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("other", "Stable")])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);

    let collected = collect_with(&metadata, &GroupPolicy::default());
    let describe: Vec<&String> = collected
        .warnings
        .iter()
        .filter(|warning| warning.contains("DescribeGroups 失败"))
        .collect();
    assert_eq!(describe.len(), 1, "{:?}", collected.warnings);
    assert!(
        describe[0].starts_with("4 个组（如 g1, g2, g3…）"),
        "{:?}",
        describe[0]
    );
}

/// 提交位点读取失败（分区级 error）同样会让 lag 偏低，也要留痕。
#[test]
fn offset_fetch_partition_error_is_surfaced_as_a_warning() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body_with(
            correlation,
            &[("orders", &[(100, 0), (200, 29)])],
        )),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150, 200])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0), ("orders", 1)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(fact(&collected.facts, FACT_LAG, "orders"), Some("50"));
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("1 个分区位点读取失败")),
        "{:?}",
        collected.warnings
    );
}

// ---------------------------------------------------------------------------
// 与探针主循环接上：组读数挂在集群级 target 上
// ---------------------------------------------------------------------------

/// `Metadata v2` 响应：一个 broker + 一个 topic（两个分区，leader 都是它）。
fn metadata_v2_response(correlation: i32, port: u16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&correlation.to_be_bytes());
    body.extend_from_slice(&1i32.to_be_bytes()); // brokers
    body.extend_from_slice(&1i32.to_be_bytes()); // node_id
    body.extend_from_slice(&9i16.to_be_bytes());
    body.extend_from_slice(b"127.0.0.1");
    body.extend_from_slice(&(port as i32).to_be_bytes());
    body.extend_from_slice(&(-1i16).to_be_bytes()); // rack = null
    body.extend_from_slice(&9i16.to_be_bytes());
    body.extend_from_slice(b"live-test"); // cluster_id
    body.extend_from_slice(&1i32.to_be_bytes()); // controller
    body.extend_from_slice(&1i32.to_be_bytes()); // topics
    body.extend_from_slice(&0i16.to_be_bytes()); // topic error
    body.extend_from_slice(&6i16.to_be_bytes());
    body.extend_from_slice(b"orders");
    body.push(0); // is_internal
    body.extend_from_slice(&2i32.to_be_bytes()); // partitions
    for partition in 0..2i32 {
        body.extend_from_slice(&0i16.to_be_bytes()); // partition error
        body.extend_from_slice(&partition.to_be_bytes());
        body.extend_from_slice(&1i32.to_be_bytes()); // leader
        body.extend_from_slice(&1i32.to_be_bytes()); // replicas len
        body.extend_from_slice(&1i32.to_be_bytes());
        body.extend_from_slice(&1i32.to_be_bytes()); // isr len
        body.extend_from_slice(&1i32.to_be_bytes());
    }
    body
}

/// 探针每轮真就是这么干的：组读数上到集群级 target 的 labeled_facts 上。
#[test]
fn probe_once_attaches_group_facts_to_the_cluster_target() {
    let broker = FakeKafka::start_with_port(|port, api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        3 => Some(metadata_v2_response(correlation, port)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100, 200])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150, 200])),
        _ => None,
    });

    let config = crate::telemetry::metrics::kafka::KafkaProbeConfig::new(
        vec![format!("127.0.0.1:{}", broker.port)],
        "wist-agentd-test".to_string(),
        500,
        1_000,
    )
    .with_groups(
        GroupPolicy {
            allowlist: vec!["orders".to_string()],
            ..GroupPolicy::default()
        },
        0, // 每轮都采（不缓存）
    );
    let result = crate::telemetry::metrics::kafka::probe_once_for_test(&config);

    assert_eq!(result.failed, 0, "{:?}", result.last_error);
    let cluster = result.targets.last().expect("集群级 target");
    assert_eq!(cluster.resource_ref, "kafka:live-test");
    assert!(
        cluster
            .labeled_facts
            .iter()
            .any(|fact| fact.key == FACT_STATE),
        "集群 target 应当带上组状态：{:?}",
        cluster.labeled_facts
    );
    assert!(
        cluster
            .labeled_facts
            .iter()
            .any(|fact| fact.key == FACT_LAG && fact.value == "50"),
        "集群 target 应当带上 lag：{:?}",
        cluster.labeled_facts
    );
}

/// 白名单里的组名拼错 / 还没创建：不能静默（现场只会看到「配了却没数据」）。
#[test]
fn unknown_allowlisted_group_is_reported() {
    let broker = FakeKafka::start(|api_key, _version, correlation| match api_key {
        18 => Some(api_versions_body(correlation, GROUP_APIS)),
        API_KEY_LIST_GROUPS => Some(list_groups_body(correlation, &[("orders", "consumer")])),
        API_KEY_DESCRIBE_GROUPS => Some(describe_groups_body(correlation, &[("orders", "Stable")])),
        API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
        API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150])),
        _ => None,
    });
    let metadata = metadata_for(broker.port, &[("orders", 0)]);
    let policy = GroupPolicy {
        allowlist: vec!["orders".to_string(), "ordres".to_string()],
        ..GroupPolicy::default()
    };

    let collected = collect_with(&metadata, &policy);
    assert_eq!(fact(&collected.facts, FACT_STATE, "orders"), Some("stable"));
    assert!(
        collected
            .warnings
            .iter()
            .any(|warning| warning.contains("ordres")),
        "拼错的白名单组名要报出来：{:?}",
        collected.warnings
    );
}

/// `lag_interval_ms` 的复用语义：间隔内**不去访问集群**，但序列不能断。
#[test]
fn group_readings_are_reused_between_lag_rounds() {
    let list_groups_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = list_groups_calls.clone();
    let broker =
        FakeKafka::start_with_port(move |port, api_key, _version, correlation| match api_key {
            18 => Some(api_versions_body(correlation, GROUP_APIS)),
            3 => Some(metadata_v2_response(correlation, port)),
            API_KEY_LIST_GROUPS => {
                counter.fetch_add(1, Ordering::Relaxed);
                Some(list_groups_body(correlation, &[("orders", "consumer")]))
            }
            API_KEY_DESCRIBE_GROUPS => {
                Some(describe_groups_body(correlation, &[("orders", "Stable")]))
            }
            API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
            API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150])),
            _ => None,
        });

    let config = crate::telemetry::metrics::kafka::KafkaProbeConfig::new(
        vec![format!("127.0.0.1:{}", broker.port)],
        "wist-agentd-test".to_string(),
        500,
        1_000,
    )
    .with_groups(
        GroupPolicy {
            allowlist: vec!["orders".to_string()],
            ..GroupPolicy::default()
        },
        60_000, // 60s 一轮：第二圈应该只用缓存
    );

    let mut cache = crate::telemetry::metrics::kafka::GroupCache::default();
    let first = crate::telemetry::metrics::kafka::probe_once_with_cache(&config, &mut cache);
    let second = crate::telemetry::metrics::kafka::probe_once_with_cache(&config, &mut cache);

    assert_eq!(
        list_groups_calls.load(Ordering::Relaxed),
        1,
        "间隔内不应再访问 broker"
    );
    for result in [&first, &second] {
        let cluster = result.targets.last().expect("集群级 target");
        assert!(
            cluster
                .labeled_facts
                .iter()
                .any(|fact| fact.key == FACT_LAG),
            "两轮都要带上 lag（第二轮用缓存，不能让序列断掉）"
        );
    }
}

/// `lag_interval_ms = 0`：每轮都真去采。
#[test]
fn zero_lag_interval_collects_every_round() {
    let list_groups_calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let counter = list_groups_calls.clone();
    let broker =
        FakeKafka::start_with_port(move |port, api_key, _version, correlation| match api_key {
            18 => Some(api_versions_body(correlation, GROUP_APIS)),
            3 => Some(metadata_v2_response(correlation, port)),
            API_KEY_LIST_GROUPS => {
                counter.fetch_add(1, Ordering::Relaxed);
                Some(list_groups_body(correlation, &[("orders", "consumer")]))
            }
            API_KEY_DESCRIBE_GROUPS => {
                Some(describe_groups_body(correlation, &[("orders", "Stable")]))
            }
            API_KEY_OFFSET_FETCH => Some(offset_fetch_body(correlation, "orders", &[100])),
            API_KEY_LIST_OFFSETS => Some(list_offsets_body(correlation, "orders", &[150])),
            _ => None,
        });

    let config = crate::telemetry::metrics::kafka::KafkaProbeConfig::new(
        vec![format!("127.0.0.1:{}", broker.port)],
        "wist-agentd-test".to_string(),
        500,
        1_000,
    )
    .with_groups(
        GroupPolicy {
            allowlist: vec!["orders".to_string()],
            ..GroupPolicy::default()
        },
        0,
    );

    let mut cache = crate::telemetry::metrics::kafka::GroupCache::default();
    crate::telemetry::metrics::kafka::probe_once_with_cache(&config, &mut cache);
    crate::telemetry::metrics::kafka::probe_once_with_cache(&config, &mut cache);
    assert_eq!(list_groups_calls.load(Ordering::Relaxed), 2);
}
