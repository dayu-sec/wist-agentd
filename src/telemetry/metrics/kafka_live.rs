//! 真 broker 验收（设计文档 §9）：指向**任意一个** broker，默认不跑。
//!
//! 两种用法：
//!
//! - 本地夹具：`dev/kafka-sasl/run.sh`（一个容器、两条 listener、三种机制）；
//! - 已有集群（研发 / 测试环境，甚至现场）：把下面几个环境变量指过去 ——
//!   **不需要发布 agentd，也不需要 Docker**：
//!
//! ```text
//! WIST_KAFKA_LIVE=1
//! WIST_KAFKA_LIVE_BOOTSTRAP=kafka-dev.intra:9093       # host:port
//! WIST_KAFKA_LIVE_PROTOCOL=SASL_SSL                     # PLAINTEXT|SSL|SASL_PLAINTEXT|SASL_SSL
//! WIST_KAFKA_LIVE_MECHANISMS=SCRAM-SHA-512              # 逗号分隔；非 SASL 留空
//! WIST_KAFKA_LIVE_USER=wist-probe                       # SASL 必填
//! WIST_KAFKA_LIVE_PASSWORD=...                          # SASL 必填（只写本机临时文件，0600）
//! WIST_KAFKA_LIVE_CA_FILE=/path/to/ca.pem               # SSL/SASL_SSL 可选；不给走系统根
//! ```
//!
//! ```bash
//! cargo test --lib telemetry::metrics::kafka_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! 验的是「单测 + 假 broker 证明不了」的那一层：我们手写的 `Metadata v1` /
//! `DescribeLogDirs v0` / `SaslHandshake` / `SaslAuthenticate` 报文，真实现能不能接受，
//! 以及 advertised 地址从这台机器到底通不通（探针的第二条连接靠它）。
//!
//! 为什么放在 lib 里而不是 `tests/`：`telemetry` 是 `pub(crate)`，集成测试拿不到
//! `kafka_auth`；而这些用例要的正是**同一份** `connect()` / `fetch_metadata()`。

use std::fs;
use std::path::{Path, PathBuf};
use std::time::Duration;

use super::kafka::{Metadata, fetch_log_dir_totals, fetch_metadata};
use super::kafka_auth::SecurityConfig;
use super::kafka_groups::{self, GroupPolicy};

const TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_ID: &str = "wist-agentd-live";

struct LiveEnv {
    bootstrap: String,
    protocol: String,
    mechanisms: Vec<String>,
    username: Option<String>,
    password_file: Option<PathBuf>,
    ca_file: Option<String>,
}

impl LiveEnv {
    fn sasl(&self) -> bool {
        self.protocol.starts_with("SASL_")
    }

    fn tls(&self) -> bool {
        matches!(self.protocol.as_str(), "SSL" | "SASL_SSL")
    }

    /// 不做机制专项验证时用的机制值：SASL 用列表里的第一个，其余用 `auto`（会被忽略）。
    fn default_mechanism(&self) -> String {
        if self.sasl() {
            self.mechanisms
                .first()
                .cloned()
                .unwrap_or_else(|| "auto".to_string())
        } else {
            "auto".to_string()
        }
    }

    fn config<'a>(&'a self, mechanism: &'a str) -> SecurityConfig<'a> {
        SecurityConfig {
            protocol: &self.protocol,
            mechanism,
            username: self.username.as_deref(),
            password_file: self.password_file.as_deref().and_then(Path::to_str),
            tls_ca_file: self.ca_file.as_deref(),
        }
    }
}

fn var(name: &str) -> Option<String> {
    std::env::var(name).ok().filter(|value| !value.is_empty())
}

/// SASL 的密码只以文件形式交给探针（与生产同一条路径）。
///
/// 测试自己写一份临时文件（0600），用完即删；**不**把密码写进仓库或日志。
fn write_secret(name: &str, secret: &str) -> PathBuf {
    let path = std::env::temp_dir().join(format!("wist-kafka-live-{}-{name}", std::process::id()));
    fs::write(&path, secret).expect("write secret");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let _ = fs::set_permissions(&path, fs::Permissions::from_mode(0o600));
    }
    path
}

/// 没配置就 SKIP（默认 `cargo test` 不会碰这些用例）。
fn live_env() -> Option<LiveEnv> {
    if var("WIST_KAFKA_LIVE").as_deref() != Some("1") {
        eprintln!("SKIP：需要 WIST_KAFKA_LIVE=1 并指向一个真 broker（见 dev/kafka-sasl/README）");
        return None;
    }
    let bootstrap = var("WIST_KAFKA_LIVE_BOOTSTRAP")
        .unwrap_or_else(|| panic!("缺 WIST_KAFKA_LIVE_BOOTSTRAP（host:port）"));
    let protocol = var("WIST_KAFKA_LIVE_PROTOCOL").unwrap_or_else(|| "PLAINTEXT".to_string());
    let mechanisms = var("WIST_KAFKA_LIVE_MECHANISMS")
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|item| !item.is_empty())
                .map(str::to_string)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    let username = var("WIST_KAFKA_LIVE_USER");
    let password_file =
        var("WIST_KAFKA_LIVE_PASSWORD").map(|secret| write_secret("password", &secret));
    let ca_file = var("WIST_KAFKA_LIVE_CA_FILE");

    let sasl = protocol.starts_with("SASL_");
    if sasl {
        assert!(
            username.is_some() && password_file.is_some(),
            "SASL 需要 WIST_KAFKA_LIVE_USER 与 WIST_KAFKA_LIVE_PASSWORD"
        );
        assert!(
            !mechanisms.is_empty(),
            "SASL 需要 WIST_KAFKA_LIVE_MECHANISMS（例如 SCRAM-SHA-512，多个用逗号分隔）"
        );
    }

    Some(LiveEnv {
        bootstrap,
        protocol,
        mechanisms,
        username,
        password_file,
        ca_file,
    })
}

fn fetch(env: &LiveEnv, config: &SecurityConfig<'_>) -> Metadata {
    fetch_metadata(&env.bootstrap, config, CLIENT_ID, TIMEOUT)
        .unwrap_or_else(|err| panic!("{}: {err}", env.bootstrap))
}

/// 配置自检：变量不全时先报环境问题，别让它伪装成协议问题。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn live_env_is_self_consistent() {
    let Some(env) = live_env() else { return };
    if env.tls()
        && let Some(ca) = env.ca_file.as_deref()
    {
        assert!(
            Path::new(ca).is_file(),
            "WIST_KAFKA_LIVE_CA_FILE 不存在：{ca}"
        );
    }
    eprintln!(
        "target={} protocol={} mechanisms={:?} tls_ca={}",
        env.bootstrap,
        env.protocol,
        env.mechanisms,
        env.ca_file.as_deref().unwrap_or("（系统根）")
    );
}

/// 协商出来的版本能不能用：先看一眼，再看报文。
///
/// 真跑时先跑这一条：它会告诉你是哪一档 broker（4.x 的 `DescribeLogDirs` 基线是 v1）、
/// 以及容量面到底能不能用。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn negotiated_versions_are_compatible() {
    let Some(env) = live_env() else { return };
    let mechanism = env.default_mechanism();
    let config = env.config(&mechanism);
    let connection = super::kafka_auth::connect(&env.bootstrap, &config, TIMEOUT)
        .unwrap_or_else(|err| panic!("{}: {err}", env.bootstrap));
    eprintln!(
        "metadata=v{} describe_log_dirs={:?} (broker 声明 {:?}) list_groups={:?} describe_groups={:?} offset_fetch={:?} list_offsets={:?}",
        connection.versions.metadata,
        connection.versions.describe_log_dirs.version,
        connection.versions.describe_log_dirs.range,
        connection.versions.list_groups.version,
        connection.versions.describe_groups.version,
        connection.versions.offset_fetch.version,
        connection.versions.list_offsets.version
    );
    assert!(
        (1..=2).contains(&connection.versions.metadata),
        "协商出来的 Metadata 版本必须在解析器支持范围内"
    );
}

/// `Metadata v1` 真实现能不能被我们的解析器读懂。
///
/// 顺手把 advertised 列表打出来：探针的第二条连接（`DescribeLogDirs`）就是按它去连的，
/// 现场「metadata 有数、容量没数」几乎都是这一步不通。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn metadata_round_trips() {
    let Some(env) = live_env() else { return };
    let mechanism = env.default_mechanism();
    let config = env.config(&mechanism);
    let metadata = fetch(&env, &config);

    let advertised: Vec<String> = metadata
        .brokers
        .iter()
        .map(|broker| format!("{}:{}", broker.host, broker.port))
        .collect();
    eprintln!(
        "advertised={advertised:?} controller_id={} cluster_key={} cluster_id={:?}",
        metadata.controller_id, metadata.cluster_key, metadata.cluster_id
    );

    assert!(!metadata.brokers.is_empty(), "至少要有一个 broker");
    assert!(
        metadata.controller_id >= 0,
        "controller_id={}",
        metadata.controller_id
    );
}

/// `DescribeLogDirs v0` 的字段布局与 advertised 可达性。
///
/// 这条最值钱：v0 顶层漏读 `throttle_time_ms` 的 bug 就是它会在第一次真机跑时
/// 直接暴露（容量被算成 0），而假 broker 永远发现不了。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn log_dir_total_is_readable_for_every_broker() {
    let Some(env) = live_env() else { return };
    let mechanism = env.default_mechanism();
    let config = env.config(&mechanism);
    let metadata = fetch(&env, &config);

    let mut read = 0usize;
    let mut failures = Vec::new();
    for broker in &metadata.brokers {
        let addr = format!("{}:{}", broker.host, broker.port);
        match fetch_log_dir_totals(&addr, &config, CLIENT_ID, TIMEOUT) {
            Ok(totals) => {
                assert!(
                    totals.size_bytes >= 0,
                    "broker {}: 容量为负 {}",
                    broker.node_id,
                    totals.size_bytes
                );
                eprintln!(
                    "broker {} ({addr}) log_dir_size_bytes={} log_dir_usable_bytes={:?}",
                    broker.node_id, totals.size_bytes, totals.usable_bytes
                );
                read += 1;
            }
            Err(err) => failures.push(format!("broker {} ({addr}): {err}", broker.node_id)),
        }
    }

    assert!(
        failures.is_empty(),
        "以下 broker 的容量读数失败（advertised 不通 / 权限不足 / 版本布局对不上）：\n{}",
        failures.join("\n")
    );
    assert!(read > 0, "一个 broker 的容量都没读到");
}

/// 「现在到底能采到哪些 kafka 指标」：按探针一轮真实做的事跑一遍，
/// 把要上送的 fact 逐条打出来。这是回答「能力够不够」最直接的一手证据。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn probe_targets_cover_the_expected_facts() {
    let Some(env) = live_env() else { return };
    let mechanism = env.default_mechanism();
    let config = env.config(&mechanism);
    let metadata = fetch(&env, &config);

    // 与 `probe_once` 一样：每个 broker 连一次 DescribeLogDirs。
    let mut totals = std::collections::BTreeMap::new();
    for broker in &metadata.brokers {
        let addr = format!("{}:{}", broker.host, broker.port);
        if let Ok(read) = fetch_log_dir_totals(&addr, &config, CLIENT_ID, TIMEOUT) {
            totals.insert(broker.node_id, read);
        }
    }
    let result = super::kafka::build_targets(&metadata, &totals);

    for target in &result.targets {
        let facts: Vec<String> = target
            .runtime_facts
            .iter()
            .map(|fact| format!("{}={}", fact.key, fact.value))
            .collect();
        eprintln!("{}  {}", target.resource_ref, facts.join(" "));
    }

    assert_eq!(
        result.targets.len(),
        metadata.brokers.len() + 1,
        "每个 broker 一条 + 集群级一条"
    );
    let cluster = result.targets.last().expect("集群级 target");
    assert!(
        cluster
            .runtime_facts
            .iter()
            .any(|fact| fact.key == "kafka.partition.offline"),
        "集群级至少要带离线分区数"
    );
}

/// 配置里列出的每个机制都要能认证；SASL 下再跑一遍 `auto`（生产默认值）。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn configured_mechanisms_authenticate() {
    let Some(env) = live_env() else { return };
    let mechanisms: Vec<String> = if env.sasl() {
        env.mechanisms.clone()
    } else {
        vec!["auto".to_string()]
    };

    for mechanism in &mechanisms {
        let config = env.config(mechanism);
        let metadata = fetch(&env, &config);
        assert!(!metadata.brokers.is_empty(), "{mechanism}: 没有 broker");
        eprintln!(
            "mechanism {mechanism}: ok ({} brokers)",
            metadata.brokers.len()
        );
    }

    if env.sasl() {
        let config = env.config("auto");
        fetch(&env, &config);
        eprintln!("mechanism auto: ok");
    }
}

/// 消费组链路：`ListGroups → DescribeGroups → OffsetFetch → ListOffsets`。
///
/// 默认把**所有**组都打出来（阈值 -1），受 `WIST_KAFKA_LIVE_MAX_GROUPS`（默认 200）约束；
/// 想只看特定组就设 `WIST_KAFKA_LIVE_GROUP=orders`。
///
/// 只读：全程不 produce / 不 consume，不建组也不提交位点。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn consumer_group_lag_and_state_are_readable() {
    let Some(env) = live_env() else { return };
    let mechanism = env.default_mechanism();
    let config = env.config(&mechanism);
    let metadata = fetch(&env, &config);

    let allowlist: Vec<String> = var("WIST_KAFKA_LIVE_GROUP").into_iter().collect();
    let max_groups = var("WIST_KAFKA_LIVE_MAX_GROUPS")
        .and_then(|raw| raw.parse::<usize>().ok())
        .unwrap_or(200);
    let policy = GroupPolicy {
        allowlist,
        max_groups,
        // -1：lag 永远 >= 0，等于「不按阈值过滤」，用于把现场真实组全打出来。
        lag_threshold: -1,
    };

    let collected = kafka_groups::collect(&metadata, &config, TIMEOUT, &policy);
    for warning in &collected.warnings {
        eprintln!("warning: {warning}");
    }
    for fact in &collected.facts {
        let labels: Vec<String> = fact
            .labels
            .iter()
            .map(|label| format!("{}=\"{}\"", label.key, label.value))
            .collect();
        eprintln!("{}{{{}}}={}", fact.key, labels.join(","), fact.value);
    }
    if collected.dropped_groups > 0 {
        eprintln!(
            "dropped_groups={} （超出 max_groups={max_groups}）",
            collected.dropped_groups
        );
    }
    if collected.facts.is_empty() {
        // 空集群（真的一个组都没有）不应算失败；有 warnings 才是问题。
        assert!(
            collected.warnings.is_empty(),
            "消费组一条读数都没拿到，且有 warnings：{:#?}",
            collected.warnings
        );
        eprintln!("集群里没有 consumer group（ListGroups 返回空）");
    }
}

/// 自探的端点探测（`discovery::kafka_source::TcpReachability`）在真集群上也能用。
///
/// 这条验的是**候选上报时的那次探测**，与采集探针本身的路径不同：
/// 它只做 TCP + `ApiVersions`（不带凭据），用来证明「这个地址确实是 Kafka」。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn self_discovery_probe_reaches_the_real_broker() {
    use crate::discovery::kafka_source::{Reachability, TcpReachability};

    let Some(env) = live_env() else { return };
    // 自探假设 broker 与 agent 同机（`PROBE_TIMEOUT = 300ms`）；这里跑在远端/网关后面，
    // 偶尔一次超时就重试 —— 重试的是**测试环境**的时延，不是产品逻辑。
    let mut outcome = TcpReachability.probe(&env.bootstrap, "PLAINTEXT");
    for _ in 0..2 {
        if outcome.kafka_api {
            break;
        }
        outcome = TcpReachability.probe(&env.bootstrap, "PLAINTEXT");
    }
    assert!(outcome.tcp, "{} 连不上", env.bootstrap);
    assert!(
        outcome.kafka_api,
        "PLAINTEXT 监听器应该能完成 ApiVersions 握手（自探靠它证明这是 Kafka）"
    );
}

/// §9 第 3 条：认证失败时日志里搜不到密码。
#[test]
#[ignore = "需要指向一个真 broker（见 dev/kafka-sasl/README）"]
fn wrong_password_is_rejected_without_leaking_it() {
    let Some(env) = live_env() else { return };
    if !env.sasl() {
        return;
    }
    let password_file = env.password_file.as_ref().expect("SASL 必有密码文件");
    let secret = fs::read_to_string(password_file).expect("read password");
    let secret = secret.trim().to_string();
    let wrong = write_secret("wrong-password", &format!("{secret}-not-the-one"));

    for mechanism in &env.mechanisms {
        let config = SecurityConfig {
            protocol: &env.protocol,
            mechanism,
            username: env.username.as_deref(),
            password_file: wrong.to_str(),
            tls_ca_file: env.ca_file.as_deref(),
        };
        let err = fetch_metadata(&env.bootstrap, &config, CLIENT_ID, TIMEOUT)
            .expect_err("错密码必须失败");
        let message = err.to_string();
        assert!(
            message.contains("SASL") || message.contains("认证"),
            "{mechanism}: 要能看出是认证问题：{message}"
        );
        assert!(
            !message.contains(&secret),
            "{mechanism}: 错误里不能出现密码：{message}"
        );
    }

    let _ = fs::remove_file(&wrong);
}
