//! `kafka_source` 的单测：进程识别、证据解析、端点假设与可达性排序。
//!
//! 全部用假 `/proc` + 假探测 —— 不需要一台真 Kafka，也不需要真去连 socket。

use std::cell::RefCell;
use std::collections::BTreeMap;

use super::*;
use wist_contracts::discovery::{DiscoveredResource, DiscoverySnapshot};

// ---------------------------------------------------------------------------
// 夹具
// ---------------------------------------------------------------------------

#[derive(Default)]
struct FakeProc {
    argv: BTreeMap<u32, Vec<String>>,
    environ: BTreeMap<u32, Vec<String>>,
    /// 路径（**已含** `/proc/<pid>/root`）→ 内容。
    files: BTreeMap<String, String>,
    /// 读了哪些进程的 argv（验证粗筛有没有生效）。
    argv_reads: RefCell<Vec<u32>>,
}

impl KafkaProc for FakeProc {
    fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String> {
        match file {
            ProcFile::Cmdline => {
                self.argv_reads.borrow_mut().push(pid);
                self.argv.get(&pid).cloned().unwrap_or_default()
            }
            ProcFile::Environ => self.environ.get(&pid).cloned().unwrap_or_default(),
        }
    }

    fn read_file(&self, path: &str) -> Option<String> {
        self.files.get(path).cloned()
    }
}

/// 假探测：记住被问到的协议，按 `dead` 决定可达性。
#[derive(Default)]
struct FakeReach {
    dead: Vec<String>,
    /// 被问到的 `(addr, protocol)`，用于验证"TLS/SASL 端点不做明文握手"。
    asked: RefCell<Vec<(String, String)>>,
}

impl Reachability for FakeReach {
    fn probe(&self, addr: &str, protocol: &str) -> ProbeOutcome {
        self.asked
            .borrow_mut()
            .push((addr.to_string(), protocol.to_string()));
        if self.dead.iter().any(|dead| dead == addr) {
            return ProbeOutcome::default();
        }
        ProbeOutcome {
            tcp: true,
            // 只有明文监听器才可能在不带凭据的情况下完成 Kafka 握手。
            kafka_api: protocol == "PLAINTEXT",
        }
    }
}

fn args(items: &[&str]) -> Vec<String> {
    items.iter().map(|item| item.to_string()).collect()
}

fn process_resource(pid: u32, exe: &str) -> DiscoveredResource {
    DiscoveredResource {
        resource_id: format!("host:pid:{pid}"),
        kind: "process".to_string(),
        origin_idx: 0,
        attributes: BTreeMap::from([
            ("process.pid".to_string(), pid.to_string()),
            ("process.executable.name".to_string(), exe.to_string()),
        ]),
        discovered_at: "2026-11-05T00:00:00Z".to_string(),
        last_seen_at: "2026-11-05T00:00:00Z".to_string(),
        health: "healthy".to_string(),
        source: "process".to_string(),
    }
}

fn endpoint_resource(pid: u32, ip: &str, port: u16) -> DiscoveredResource {
    DiscoveredResource {
        resource_id: format!("host:endpoint:tcp:{ip}:{port}"),
        kind: "service_endpoint".to_string(),
        origin_idx: 0,
        attributes: BTreeMap::from([
            ("endpoint.protocol".to_string(), "tcp".to_string()),
            ("endpoint.bind.ip".to_string(), ip.to_string()),
            ("endpoint.bind.port".to_string(), port.to_string()),
            ("process.pid".to_string(), pid.to_string()),
        ]),
        discovered_at: "2026-11-05T00:00:00Z".to_string(),
        last_seen_at: "2026-11-05T00:00:00Z".to_string(),
        health: "healthy".to_string(),
        source: "endpoint".to_string(),
    }
}

fn snapshot(resources: Vec<DiscoveredResource>) -> DiscoverySnapshot {
    let mut snapshot = DiscoverySnapshot::new(
        "snap-kafka".to_string(),
        1,
        "2026-11-05T00:00:00Z".to_string(),
    );
    snapshot.resources = resources;
    snapshot
}

const BROKER_PROPS: &str = r#"
# Kafka 3.6 server.properties
broker.id=0
listeners=INTERNAL://0.0.0.0:9092,EXTERNAL://0.0.0.0:30001
advertised.listeners=INTERNAL://kafka-0.kafka-headless.kafka:9092,EXTERNAL://10.168.1.145:30001
listener.security.protocol.map=INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT
sasl.enabled.mechanisms=SCRAM-SHA-512,PLAIN
"#;

fn broker_fixture() -> (FakeProc, Vec<DiscoveredResource>) {
    let mut proc = FakeProc::default();
    proc.argv.insert(
        42,
        args(&[
            "java",
            "-Dkafka.config.file=/opt/kafka/config/server.properties",
            "kafka.Kafka",
            "/opt/kafka/config/server.properties",
        ]),
    );
    proc.files.insert(
        "/proc/42/root/opt/kafka/config/server.properties".to_string(),
        BROKER_PROPS.to_string(),
    );
    // 端点资源决定 `source_ref`（优先用端口做身份，pid 重启不换）。
    (
        proc,
        vec![
            process_resource(42, "java"),
            endpoint_resource(42, "0.0.0.0", 9092),
        ],
    )
}

// ---------------------------------------------------------------------------
// 进程识别
// ---------------------------------------------------------------------------

#[test]
fn detects_a_broker_from_server_properties() {
    let (proc, resources) = broker_fixture();
    let reach = FakeReach::default();
    let clusters = resolve(&snapshot(resources), &proc, &reach);

    assert_eq!(clusters.len(), 1, "{clusters:?}");
    let cluster = &clusters[0];
    assert_eq!(cluster.evidence, "server_properties");
    assert_eq!(cluster.confidence, 90);
    assert_eq!(cluster.broker_id, Some(0));
    assert_eq!(cluster.mechanisms, vec!["SCRAM-SHA-512", "PLAIN"]);
    assert_eq!(
        cluster
            .listeners
            .iter()
            .map(|listener| (
                listener.name.as_str(),
                listener.protocol.as_str(),
                listener.port
            ))
            .collect::<Vec<_>>(),
        vec![
            ("INTERNAL", "PLAINTEXT", 9092),
            ("EXTERNAL", "PLAINTEXT", 30001)
        ]
    );
    // 广告地址排在前面（它是 broker 自己告诉客户端用的地址）。
    assert_eq!(
        cluster.endpoints[0].addr,
        "kafka-0.kafka-headless.kafka:9092"
    );
    assert_eq!(cluster.endpoints[0].source, "advertised");
    assert!(
        cluster
            .endpoints
            .iter()
            .any(|endpoint| endpoint.addr == "10.168.1.145:30001"),
        "{:?}",
        cluster.endpoints
    );
    assert_eq!(cluster.source_ref, "port:9092", "身份用端口，pid 重启不换");
}

#[test]
fn container_env_is_used_when_no_config_file_is_readable() {
    let mut proc = FakeProc::default();
    proc.argv.insert(
        7,
        args(&[
            "java",
            "kafka.Kafka",
            "/opt/bitnami/kafka/config/server.properties",
        ]),
    );
    proc.environ.insert(
        7,
        args(&[
            "KAFKA_CFG_NODE_ID=1",
            "KAFKA_CFG_LISTENERS=CONTROLLER://:9093,INTERNAL://:9092,EXTERNAL://:9094",
            "KAFKA_CFG_ADVERTISED_LISTENERS=INTERNAL://broker-1:9092,EXTERNAL://10.0.0.9:9094",
            "KAFKA_CFG_LISTENER_SECURITY_PROTOCOL_MAP=CONTROLLER:PLAINTEXT,INTERNAL:PLAINTEXT,EXTERNAL:PLAINTEXT",
            "KAFKA_CFG_SASL_ENABLED_MECHANISMS=SCRAM-SHA-512",
        ]),
    );
    let clusters = resolve(
        &snapshot(vec![process_resource(7, "java")]),
        &proc,
        &FakeReach::default(),
    );

    assert_eq!(clusters.len(), 1, "{clusters:?}");
    let cluster = &clusters[0];
    assert_eq!(cluster.evidence, "container_env");
    assert_eq!(cluster.confidence, 80);
    assert_eq!(cluster.broker_id, Some(1));
    assert_eq!(cluster.listeners.len(), 3);
    assert_eq!(cluster.mechanisms, vec!["SCRAM-SHA-512"]);
}

#[test]
fn the_argv_prefilter_skips_unrelated_processes() {
    // 一百个 postgres 进程也不应该去读 cmdline。
    let mut proc = FakeProc::default();
    let mut resources = Vec::new();
    for pid in 100..110 {
        resources.push(process_resource(pid, "postgres"));
        proc.argv.insert(pid, args(&["postgres", "-D", "/data/pg"]));
    }
    let clusters = resolve(&snapshot(resources), &proc, &FakeReach::default());
    assert!(clusters.is_empty());
    assert!(
        proc.argv_reads.borrow().is_empty(),
        "非 java/kafka 进程不该被读 argv：{:?}",
        proc.argv_reads.borrow()
    );
}

#[test]
fn an_empty_executable_name_still_gets_checked() {
    // 可执行名拿不到时宁可多读一次，也不要漏报。
    let mut proc = FakeProc::default();
    proc.argv
        .insert(21, args(&["java", "kafka.Kafka", "/cfg/server.properties"]));
    proc.files.insert(
        "/proc/21/root/cfg/server.properties".to_string(),
        [
            "broker.id=1",
            "listeners=PLAINTEXT://0.0.0.0:9092",
            "listener.security.protocol.map=PLAINTEXT:PLAINTEXT",
        ]
        .join("\n"),
    );
    let clusters = resolve(
        &snapshot(vec![process_resource(21, "")]),
        &proc,
        &FakeReach::default(),
    );
    assert_eq!(clusters.len(), 1);
}

#[test]
fn non_broker_processes_are_ignored() {
    for (exe, argv) in [
        ("postgres", args(&["postgres", "-D", "/data/pg"])),
        (
            "java",
            args(&["java", "org.apache.zookeeper.server.quorum.QuorumPeerMain"]),
        ),
        (
            "kafka-exporter",
            args(&["kafka-exporter", "--kafka.server=127.0.0.1:9092"]),
        ),
        (
            "java",
            args(&["java", "org.apache.kafka.connect.cli.ConnectStandalone"]),
        ),
    ] {
        assert!(
            !is_broker(exe, &argv),
            "{exe} {argv:?} 不是 broker，不能被当成候选"
        );
    }
    assert!(is_broker(
        "java",
        &args(&["java", "kafka.Kafka", "server.properties"])
    ));
    assert!(is_broker(
        "kafka-server-start.sh",
        &args(&[
            "kafka-server-start.sh",
            "/opt/kafka/config/server.properties"
        ])
    ));
}

#[test]
fn a_broker_without_any_evidence_produces_nothing() {
    // 有 kafka.Kafka，但配置文件读不到、环境变量没有、也没监听端口 —— 没有可用信息。
    let mut proc = FakeProc::default();
    proc.argv.insert(
        9,
        args(&["java", "kafka.Kafka", "/nowhere/server.properties"]),
    );
    let clusters = resolve(
        &snapshot(vec![process_resource(9, "java")]),
        &proc,
        &FakeReach::default(),
    );
    assert!(clusters.is_empty(), "{clusters:?}");
}

// ---------------------------------------------------------------------------
// 证据解析
// ---------------------------------------------------------------------------

#[test]
fn properties_are_parsed_from_the_allowlist_only() {
    let mut proc = FakeProc::default();
    proc.argv
        .insert(3, args(&["java", "kafka.Kafka", "/cfg/server.properties"]));
    proc.files.insert(
        "/proc/3/root/cfg/server.properties".to_string(),
        [
            "node.id=2",
            "listeners=PLAINTEXT://0.0.0.0:9092",
            "listener.security.protocol.map=PLAINTEXT:PLAINTEXT",
            "ssl.keystore.password=SUPER-SECRET-KEYSTORE",
            "sasl.jaas.config=required username=\"admin\" password=\"SUPER-SECRET-JAAS\";",
        ]
        .join("\n"),
    );
    let clusters = resolve(
        &snapshot(vec![process_resource(3, "java")]),
        &proc,
        &FakeReach::default(),
    );
    let serialized = serde_json::to_string(&clusters).expect("serialize");
    assert!(
        !serialized.contains("SUPER-SECRET"),
        "密码类键绝不能进候选：{serialized}"
    );
    assert_eq!(clusters[0].broker_id, Some(2));
    // 通配绑定不产生 `0.0.0.0:9092` 这种对中心毫无意义的地址。
    assert!(
        clusters[0]
            .endpoints
            .iter()
            .all(|endpoint| !endpoint.addr.starts_with("0.0.0.0")),
        "{:?}",
        clusters[0].endpoints
    );
    assert!(
        clusters[0]
            .endpoints
            .iter()
            .any(|endpoint| endpoint.addr == "127.0.0.1:9092")
    );
}

#[test]
fn falls_back_to_listening_ports_with_unknown_protocol() {
    let mut proc = FakeProc::default();
    proc.argv.insert(
        5,
        args(&["java", "kafka.Kafka", "/missing/server.properties"]),
    );
    let clusters = resolve(
        &snapshot(vec![
            process_resource(5, "java"),
            endpoint_resource(5, "0.0.0.0", 9092),
            endpoint_resource(5, "0.0.0.0", 9093),
        ]),
        &proc,
        &FakeReach::default(),
    );

    assert_eq!(clusters.len(), 1, "{clusters:?}");
    let cluster = &clusters[0];
    assert_eq!(cluster.evidence, "listening_port");
    assert_eq!(cluster.confidence, 30);
    assert_eq!(cluster.listeners.len(), 2);
    assert!(
        cluster
            .listeners
            .iter()
            .all(|listener| listener.protocol == "unknown")
    );
    assert_eq!(cluster.source_ref, "port:9092", "取最小端口做身份");
    assert!(
        cluster
            .endpoints
            .iter()
            .all(|endpoint| endpoint.addr.starts_with("127.0.0.1:"))
    );
}

#[test]
fn tls_listeners_are_reported_but_never_half_handshaken() {
    // 配置里写明是 SASL_SSL：端点仍然可用，但探测只能证明"能连上"。
    let mut proc = FakeProc::default();
    proc.argv
        .insert(11, args(&["java", "kafka.Kafka", "/cfg/server.properties"]));
    proc.files.insert(
        "/proc/11/root/cfg/server.properties".to_string(),
        [
            "listeners=EXTERNAL://0.0.0.0:9094",
            "advertised.listeners=EXTERNAL://kafka.example.com:9094",
            "listener.security.protocol.map=EXTERNAL:SASL_SSL",
            "sasl.enabled.mechanisms=SCRAM-SHA-512",
        ]
        .join("\n"),
    );
    let reach = FakeReach::default();
    let clusters = resolve(&snapshot(vec![process_resource(11, "java")]), &proc, &reach);

    let cluster = &clusters[0];
    assert_eq!(cluster.listeners[0].protocol, "SASL_SSL");
    assert!(
        cluster.endpoints.iter().all(|endpoint| !endpoint.kafka_api),
        "SASL_SSL 端点不可能在不带凭据时完成握手：{:?}",
        cluster.endpoints
    );
    assert!(
        reach
            .asked
            .borrow()
            .iter()
            .any(|(_, protocol)| protocol == "SASL_SSL"),
        "探测必须知道这个端点的协议"
    );
}

// ---------------------------------------------------------------------------
// 端点
// ---------------------------------------------------------------------------

#[test]
fn unreachable_endpoints_sort_last_but_are_still_reported() {
    let (proc, resources) = broker_fixture();
    let reach = FakeReach {
        // k8s 集群内的 headless DNS 在宿主上往往解析不了 —— 如实标不可达。
        dead: vec!["kafka-0.kafka-headless.kafka:9092".to_string()],
        ..FakeReach::default()
    };
    let clusters = resolve(&snapshot(resources), &proc, &reach);
    let endpoints = &clusters[0].endpoints;

    assert_eq!(endpoints[0].addr, "10.168.1.145:30001", "{endpoints:?}");
    assert!(endpoints[0].reachable);
    let dead = endpoints.last().expect("last");
    assert_eq!(dead.addr, "kafka-0.kafka-headless.kafka:9092");
    assert!(!dead.reachable, "不可达的也要留着（解释为什么没采到）");
}

#[test]
fn endpoints_are_deduped_and_capped() {
    let mut proc = FakeProc::default();
    proc.argv
        .insert(13, args(&["java", "kafka.Kafka", "/cfg/server.properties"]));
    // 四个监听器 → 4 个 bind 地址 + 4 个 loopback；去重后不超过上限。
    proc.files.insert(
        "/proc/13/root/cfg/server.properties".to_string(),
        [
            "listeners=L1://0.0.0.0:9001,L2://0.0.0.0:9002,L3://0.0.0.0:9003,L4://0.0.0.0:9004",
            "listener.security.protocol.map=L1:PLAINTEXT,L2:PLAINTEXT,L3:PLAINTEXT,L4:PLAINTEXT",
        ]
        .join("\n"),
    );
    let clusters = resolve(
        &snapshot(vec![process_resource(13, "java")]),
        &proc,
        &FakeReach::default(),
    );
    let endpoints = &clusters[0].endpoints;
    assert!(endpoints.len() <= MAX_ENDPOINTS_PER_CLUSTER);
    let mut unique: Vec<&str> = endpoints.iter().map(|e| e.addr.as_str()).collect();
    unique.sort_unstable();
    unique.dedup();
    assert_eq!(unique.len(), endpoints.len(), "端点不能重复");
}

#[test]
fn ipv6_listener_addresses_are_bracketed() {
    let mut proc = FakeProc::default();
    proc.argv
        .insert(17, args(&["java", "kafka.Kafka", "/cfg/server.properties"]));
    proc.files.insert(
        "/proc/17/root/cfg/server.properties".to_string(),
        [
            "listeners=INTERNAL://[::1]:9092",
            "advertised.listeners=INTERNAL://[fd00::1]:9092",
            "listener.security.protocol.map=INTERNAL:PLAINTEXT",
        ]
        .join("\n"),
    );
    let clusters = resolve(
        &snapshot(vec![process_resource(17, "java")]),
        &proc,
        &FakeReach::default(),
    );
    assert!(
        clusters[0]
            .endpoints
            .iter()
            .any(|endpoint| endpoint.addr == "[fd00::1]:9092"),
        "{:?}",
        clusters[0].endpoints
    );
}

#[test]
fn an_empty_snapshot_yields_no_candidates() {
    let clusters = resolve(
        &snapshot(Vec::new()),
        &FakeProc::default(),
        &FakeReach::default(),
    );
    assert!(clusters.is_empty());
}

// ---------------------------------------------------------------------------
// 纯函数
// ---------------------------------------------------------------------------

#[test]
fn listener_and_protocol_parsing_is_defensive() {
    let listeners = parse_listeners("PLAINTEXT://:9092, BROKEN, EXTERNAL://host:0");
    assert_eq!(listeners.len(), 1, "{listeners:?}");
    assert_eq!(listeners[0].name, "PLAINTEXT");
    assert_eq!(listeners[0].port, 9092);
    assert!(listeners[0].host.is_empty());

    let map = parse_protocol_map("A:PLAINTEXT,B:sasl_ssl,C:WAT");
    assert_eq!(map.get("A").map(String::as_str), Some("PLAINTEXT"));
    assert_eq!(map.get("B").map(String::as_str), Some("SASL_SSL"));
    assert!(!map.contains_key("C"), "未知协议不能被当成真协议");
}

#[test]
fn config_path_comes_from_the_jvm_flag_or_the_script_argument() {
    assert_eq!(
        config_path(&args(&[
            "java",
            "-Dkafka.config.file=/a/b/c.properties",
            "kafka.Kafka",
            "/x/y.properties"
        ])),
        Some("/a/b/c.properties".to_string()),
        "JVM 参数优先（那是 broker 真正加载的）"
    );
    assert_eq!(
        config_path(&args(&[
            "kafka-server-start.sh",
            "/opt/kafka/config/server.properties"
        ])),
        Some("/opt/kafka/config/server.properties".to_string())
    );
    assert_eq!(config_path(&args(&["java", "kafka.Kafka"])), None);
}

#[test]
fn concrete_hosts_exclude_wildcards() {
    assert!(is_concrete_host("10.0.0.1"));
    assert!(is_concrete_host("kafka-0.kafka-headless"));
    for wildcard in ["", "0.0.0.0", "::", "[::]", "*"] {
        assert!(!is_concrete_host(wildcard), "{wildcard:?}");
    }
}

#[test]
fn endpoint_addresses_handle_ipv6_literals() {
    assert_eq!(endpoint_addr("10.0.0.1", 9092), "10.0.0.1:9092");
    assert_eq!(endpoint_addr("fd00::1", 9092), "[fd00::1]:9092");
    assert_eq!(endpoint_addr("[fd00::1]", 9092), "[fd00::1]:9092");
}

#[test]
fn identity_prefers_the_smallest_port() {
    let ports = BTreeMap::from([(
        42u32,
        vec![
            ("0.0.0.0".to_string(), 9093u16),
            ("0.0.0.0".to_string(), 9092),
        ],
    )]);
    assert_eq!(identity(&ports, 42), "port:9092");
    assert_eq!(identity(&ports, 99), "pid:99");
}
