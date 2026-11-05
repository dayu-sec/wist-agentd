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
//! ## 边界（当前）
//!
//! - 传输层只有「请求头 + 单次请求」：`Metadata`、`DescribeLogDirs`，以及消费组四件套
//!   （`ListGroups` / `DescribeGroups` / `OffsetFetch` / `ListOffsets`，见 `kafka_groups.rs`）；
//!   TLS / SASL 握手在 `kafka_auth.rs`（`PLAINTEXT` / `SSL` / `SASL_PLAINTEXT` / `SASL_SSL`），
//!   协议版本由每次建连的 `ApiVersions` 协商决定；
//! - **不伪造失败**：连不上的 broker 不出样本（缺序列 = 不可达），不补 `0`。
//!
//! ## 节奏
//!
//! 拓扑 / 容量面跟 `interval`（默认 30s）；消费组 lag 是成本主项，跟 `lag_interval_ms`
//! （默认 60s，规范 §6 建议 60–300s）。两轮之间沿用上一轮的组读数，不让序列忽有忽无。
//!
//! ## 线程模型
//!
//! 采集在**独立线程**里周期跑，`collect_outcome()` 只读最近一次快照 —— 网络超时
//! 不会拖住 3s 的主循环。

use std::collections::BTreeMap;
use std::io;
use std::sync::{Mutex, OnceLock};
use std::time::Duration;

use wist_contracts::discovery::StringKeyValue;

use super::kafka_auth::{self, OwnedSecurityConfig, SecurityConfig};
use super::kafka_groups::{self, GroupPolicy};
use super::runtime::{MetricsCollectionOutcome, MetricsCollectionTargetSample};

/// 采集域：与 `wist_metrics::spec` 里 `kafka_broker_metrics` 对应。
pub const COLLECTION_KIND: &str = "kafka_broker_metrics";

/// `Metadata` 的 API key。
///
/// 具体发哪个版本由 `ApiVersions` 协商结果决定（本探针能解 v1/v2），
/// 这里不再写死版本号。
const API_KEY_METADATA: i16 = 3;
/// `DescribeLogDirs` 的 API key（协商结果 v0-v4；v4 才带可用空间）。
const API_KEY_DESCRIBE_LOG_DIRS: i16 = 35;

/// 探测配置（来自 `[kafka]` 段）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaProbeConfig {
    pub bootstrap_servers: Vec<String>,
    pub client_id: String,
    pub timeout: Duration,
    pub interval: Duration,
    /// 消费组 lag / 状态的限流口径（§5 基数上限）。
    pub groups: GroupPolicy,
    /// 消费组采集周期：lag 是成本主项，不必跟着拓扑面（30s）跑。
    pub group_interval: Duration,
    /// 容量面（逐 broker 的 `DescribeLogDirs`）的整体预算。
    ///
    /// 单个 broker 失败只影响它自己，但**不可达 broker 数 × 单次超时**是串行叠加的：
    /// 一个 30 broker 的集群里有几台网络不通，一轮就能拖上百秒，把同一轮的
    /// lag 面一起饿死。超预算就少采尾部 broker 的容量（P1），拓扑 / ISR / lag 照旧。
    pub capacity_budget: Duration,
    /// 传输与认证参数；默认 `PLAINTEXT`（`with_security` 才会改）。
    pub security: OwnedSecurityConfig,
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
            // 默认值：查全部组（白名单空）但按阈值过滤，单轮上限 200 个组。
            // 大集群用 `lag_group_allowlist` 或调小 `max_groups` 限流。
            groups: GroupPolicy::default(),
            group_interval: Duration::from_millis(GROUP_INTERVAL_DEFAULT_MS),
            capacity_budget: Duration::from_millis(CAPACITY_BUDGET_DEFAULT_MS),
            security: OwnedSecurityConfig::default(),
        }
    }

    /// 装上 `[kafka]` 里的 TLS / SASL 参数（`PLAINTEXT` 时保持默认即可）。
    pub fn with_security(mut self, security: OwnedSecurityConfig) -> Self {
        self.security = security;
        self
    }

    /// 装上消费组采集的上限与周期。
    pub fn with_groups(mut self, groups: GroupPolicy, group_interval_ms: u64) -> Self {
        self.groups = groups;
        self.group_interval = Duration::from_millis(group_interval_ms);
        self
    }
}

/// 消费组采集的默认周期：60s（规范 §6 建议 60–300s，lag 是成本主项）。
const GROUP_INTERVAL_DEFAULT_MS: u64 = 60_000;

/// 容量面的默认总预算（10s）。
///
/// 比单次超时（默认 5s）大，但远小于「broker 数 × 超时」的最坏值：正常情况下
/// 一台 broker 一次 `DescribeLogDirs` 是毫秒级的，碰到超预算说明有一批 broker
/// 网络不通，这时少采几个容量读数比拖垮整轮更合理。
const CAPACITY_BUDGET_DEFAULT_MS: u64 = 10_000;

/// 一次探测的产物（与具体线程解耦，便于测试）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub targets: Vec<MetricsCollectionTargetSample>,
    pub attempted: usize,
    pub failed: usize,
    pub last_error: Option<String>,
    /// 不影响本轮成败、但**确实造成了样本缺失**的原因
    /// （例如某个 broker 的 `DescribeLogDirs` 失败：该 broker 只是少了容量读数）。
    ///
    /// 单独立项是因为这类缺失在上面的汇总里看不见：没有它，现场只能看到
    /// 「`kafka_log_dir.size_bytes` 没有数据」而猜不出是哪个 broker、哪个 API。
    pub warnings: Vec<String>,
}

/// 一个集群的运行时状态。
struct ClusterRuntime {
    config: KafkaProbeConfig,
    /// 下一轮该采的时刻。
    next_at: std::time::Instant,
    /// 消费组面自己的缓存（周期比拓扑面慢）。
    groups: GroupCache,
    /// warnings 的日志闸门（内容变了才打）。
    log_gate: ProbeLogState,
    latest: Option<ProbeResult>,
}

/// 一次待执行的自探扫描。
///
/// 自探要读 `/proc` 并做有界 TCP 探测（每端点 ≤300ms），不能在 3s 主循环里跑：
/// 主循环只把请求丢进来，真正的解析 + 探测在探测线程上做。
struct PendingScan {
    /// 投递时的代号；期间撤过授权/又投递了新扫描就对不上，结果直接丢弃。
    epoch: u64,
    snapshot: Option<wist_contracts::discovery::DiscoverySnapshot>,
    settings: KafkaTargetSettings,
}

/// 探测运行时。
///
/// 一个进程一份（见 [`runtime`]）；测试可以自己造一份，不碰全局状态。
#[derive(Default)]
struct ProbeRuntime {
    /// key = bootstrap 列表的稳定串（目前就是自探出来的那一个端点地址）。
    clusters: BTreeMap<String, ClusterRuntime>,
    worker_started: bool,
    /// 上一次 reconcile 后生效的集群集合（变化才打日志）。
    log_signature: String,
    /// 待执行的自探扫描（**最新覆盖旧的**）。
    pending_scan: Option<PendingScan>,
    /// 自探代次：每次投递 / 撤授权 +1，用来丢弃晚到的扫描结果。
    scan_epoch: u64,
    /// 已授权但本机没有可达端点：只打一条，端点回来时复位。
    no_endpoint_logged: bool,
}

impl ProbeRuntime {
    /// 把采集面授权 + 自探结果**对账**成当前要采的集群集合。
    ///
    /// - 新出现的集群：立即采第一轮；
    /// - 已有的集群：换配置（协议/周期变了），保留调度与上一轮结果；
    /// - 不在列表里的：停止采集（**撤授权就是传空列表**），结果从快照里消失。
    ///
    /// 幂等：同一份输入重复调用不会多起线程、不会重置调度。
    /// 返回 `true` 表示调用方该把探测线程拉起来。
    fn reconcile(&mut self, configs: Vec<KafkaProbeConfig>) -> bool {
        let desired: BTreeMap<String, KafkaProbeConfig> = configs
            .into_iter()
            .map(|config| (probe_key(&config), config))
            .collect();

        let removed: Vec<String> = self
            .clusters
            .keys()
            .filter(|key| !desired.contains_key(*key))
            .cloned()
            .collect();
        for key in removed {
            self.clusters.remove(&key);
        }
        for (key, config) in desired {
            match self.clusters.get_mut(&key) {
                Some(runtime) => runtime.config = config,
                None => {
                    self.clusters.insert(
                        key,
                        ClusterRuntime {
                            config,
                            next_at: std::time::Instant::now(),
                            groups: GroupCache::default(),
                            log_gate: ProbeLogState::default(),
                            latest: None,
                        },
                    );
                }
            }
        }

        // 只在集合真的变了时打一行：采集线程每 tick 都会调 reconcile。
        let signature = self.clusters.keys().cloned().collect::<Vec<_>>().join(",");
        if signature != self.log_signature {
            if signature.is_empty() {
                log::info!("event=KafkaProbeRevoked detail=\"no kafka collection grant\"");
            } else {
                log::info!("event=KafkaProbeEnabled endpoints=\"{signature}\"");
            }
            self.log_signature = signature;
        }

        let should_start = !self.clusters.is_empty() && !self.worker_started;
        if should_start {
            self.worker_started = true;
        }
        should_start
    }

    /// 投递一次自探扫描（不在这里做探测）。
    ///
    /// 返回 `true` 表示调用方该把探测线程拉起来 —— **即使当前要采的集群为空**：
    /// 首次授权时还没有任何集群，不拉线程就没人执行扫描。
    fn request_scan(
        &mut self,
        snapshot: Option<wist_contracts::discovery::DiscoverySnapshot>,
        settings: KafkaTargetSettings,
    ) -> bool {
        self.scan_epoch = self.scan_epoch.wrapping_add(1);
        self.pending_scan = Some(PendingScan {
            epoch: self.scan_epoch,
            snapshot,
            settings,
        });
        !std::mem::replace(&mut self.worker_started, true)
    }

    /// 取走待执行的扫描（最新覆盖旧的）。
    fn take_scan(&mut self) -> Option<PendingScan> {
        self.pending_scan.take()
    }

    /// 把扫描结果落到运行态。
    ///
    /// 代号对不上（期间撤过授权 / 又投递了新扫描）就 **丢弃**：否则撤授权后晚一步
    /// 回来的扫描会把集群加回去，而主循环不会再调一次撤授权（它只在状态切换时调）。
    fn finish_scan(&mut self, epoch: u64, targets: Vec<KafkaProbeConfig>) {
        if epoch != self.scan_epoch {
            return;
        }
        if targets.is_empty() {
            if !self.no_endpoint_logged {
                log::info!(
                    "event=KafkaProbeNoEndpoint detail=\"已授权，但本机没有可达的 Kafka 端点（非 broker 节点，或端点不可达）\""
                );
                self.no_endpoint_logged = true;
            }
        } else {
            self.no_endpoint_logged = false;
        }
        self.reconcile(targets);
    }

    /// 撤授权：停采，并作废待执行 / 在途的扫描。
    fn revoke(&mut self) {
        self.scan_epoch = self.scan_epoch.wrapping_add(1);
        self.pending_scan = None;
        self.no_endpoint_logged = false;
        self.reconcile(Vec::new());
    }

    /// 取一个到期的集群（已排好下一轮时间）。
    fn take_due(&mut self) -> Option<DueJob> {
        let now = std::time::Instant::now();
        let key = self
            .clusters
            .iter()
            .find(|(_, runtime)| runtime.next_at <= now)
            .map(|(key, _)| key.clone())?;
        let runtime = self.clusters.get_mut(&key)?;
        runtime.next_at = now + runtime.config.interval;
        Some(DueJob {
            key,
            config: runtime.config.clone(),
            groups: std::mem::take(&mut runtime.groups),
            log_gate: std::mem::take(&mut runtime.log_gate),
        })
    }

    /// 把一轮结果放回去；集群在探测期间被撤销就丢掉（不写回）。
    fn finish(&mut self, mut job: DueJob, result: ProbeResult) {
        if job.log_gate.warnings_changed(&result) {
            for warning in &result.warnings {
                log::warn!(
                    "event=KafkaProbeWarning endpoint=\"{}\" detail=\"{warning}\"",
                    job.key
                );
            }
        }
        let Some(runtime) = self.clusters.get_mut(&job.key) else {
            return;
        };
        runtime.groups = job.groups;
        runtime.log_gate = job.log_gate;
        runtime.latest = Some(result);
    }

    /// 把各集群最近一轮结果合并成一条采集结果。没有授权 → `None`。
    fn collect_outcome(&self) -> Option<MetricsCollectionOutcome> {
        if self.clusters.is_empty() {
            return None;
        }

        let mut targets = Vec::new();
        let mut attempted = 0usize;
        let mut failed = 0usize;
        let mut last_error: Option<String> = None;
        let mut any_result = false;
        for runtime in self.clusters.values() {
            let Some(result) = runtime.latest.as_ref() else {
                continue;
            };
            any_result = true;
            attempted += result.attempted;
            failed += result.failed;
            if last_error.is_none() {
                last_error = result.last_error.clone();
            }
            targets.extend(result.targets.iter().cloned());
        }

        // 同一台机器可能跑多个 broker（每个进程一条候选），而每轮 Metadata 都会返回
        // **整个集群**的 broker 列表 —— 不按 `resource_ref` 去重会给同一个 broker
        // 产出重复序列（同 instance 同指标，写侧就重复了）。
        let mut seen = std::collections::BTreeSet::new();
        targets.retain(|target| seen.insert(target.resource_ref.clone()));

        if !any_result {
            // 授权到了但首轮还没跑完：如实说「还没数据」。
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
        }

        let succeeded = targets
            .iter()
            .filter(|target| target.status != "failed")
            .count();
        Some(MetricsCollectionOutcome {
            collection_kind: COLLECTION_KIND.to_string(),
            status: if failed == 0 && succeeded > 0 {
                "succeeded".to_string()
            } else if succeeded == 0 {
                "failed".to_string()
            } else {
                "partial".to_string()
            },
            attempted_targets: attempted,
            succeeded_targets: succeeded,
            failed_targets: failed,
            dropped_targets: 0,
            last_error,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: targets,
        })
    }
}

static RUNTIME: OnceLock<Mutex<ProbeRuntime>> = OnceLock::new();

fn runtime() -> &'static Mutex<ProbeRuntime> {
    RUNTIME.get_or_init(|| Mutex::new(ProbeRuntime::default()))
}

/// 投递一次自探扫描（**不等结果**）：主循环只决定何时探，探测在探测线程上做。
///
/// 端点/协议只来自自探，所以调用方还必须把采集面授权的存在性考虑进来：
/// 没授权时调 [`revoke`]，而不是投递空扫描。
pub fn request_scan(
    snapshot: Option<wist_contracts::discovery::DiscoverySnapshot>,
    settings: KafkaTargetSettings,
) {
    let Ok(mut guard) = runtime().lock() else {
        return;
    };
    let start = guard.request_scan(snapshot, settings);
    drop(guard);
    if start {
        spawn_worker();
    }
}

/// 撤授权：停采（下个 tick 内序列消失），并作废待执行 / 在途的自探扫描。
pub fn revoke() {
    if let Ok(mut guard) = runtime().lock() {
        guard.revoke();
    }
}

/// 集群的稳定键：bootstrap 列表拼起来。
fn probe_key(config: &KafkaProbeConfig) -> String {
    config.bootstrap_servers.join(",")
}

struct DueJob {
    key: String,
    config: KafkaProbeConfig,
    groups: GroupCache,
    log_gate: ProbeLogState,
}

/// 探测线程：做自探扫描与到期的采集轮次，绝不阻塞主循环。
fn spawn_worker() {
    let spawned = std::thread::Builder::new()
        .name("kafka-probe".to_string())
        .spawn(|| {
            loop {
                // 自探扫描排在前面：新挂上的集群立刻采到。
                let scan = runtime()
                    .lock()
                    .ok()
                    .and_then(|mut guard| guard.take_scan());
                if let Some(scan) = scan {
                    // 读 /proc + 有界 TCP 探测都在这里做（最多几秒），主循环不等。
                    let targets = targets_from_discovery(scan.snapshot.as_ref(), &scan.settings);
                    if let Ok(mut guard) = runtime().lock() {
                        guard.finish_scan(scan.epoch, targets);
                    }
                    continue;
                }
                let job = runtime().lock().ok().and_then(|mut guard| guard.take_due());
                let Some(mut job) = job else {
                    // 没有到期的：慢轮询（成本可忽略）。
                    std::thread::sleep(Duration::from_millis(500));
                    continue;
                };
                let result = probe_once(&job.config, &mut job.groups);
                if let Ok(mut guard) = runtime().lock() {
                    guard.finish(job, result);
                }
            }
        });
    if let Err(err) = spawned {
        log::warn!("event=KafkaProbeThreadFailed detail=\"{err}\"");
    }
}

/// 探测线程的日志闸门。
///
/// **只打 warnings**：域级成败已经由指标运行时统一打（`MetricsCollectionFailed` /
/// `MetricsCollectionRecovered`），这里再打一遍只会让同一个故障出现两行。
/// warnings（某个 broker 的容量读数缺失）是运行时看不到的细节，才需要单独说。
/// 探测默认 30s 一轮，相同的 warnings 不重复打。
#[derive(Default)]
struct ProbeLogState {
    warnings: Option<String>,
}

impl ProbeLogState {
    /// 内容变了（包括从“有”变成“没有”）就返回 true。
    fn warnings_changed(&mut self, result: &ProbeResult) -> bool {
        let joined = result.warnings.join(" | ");
        if self.warnings.as_deref() == Some(joined.as_str()) {
            return false;
        }
        self.warnings = Some(joined);
        true
    }
}

/// 把各集群最近一轮结果合并成一条采集结果。没有授权 → `None`（快照里不出现这个域）。
pub fn collect_outcome() -> Option<MetricsCollectionOutcome> {
    runtime().lock().ok()?.collect_outcome()
}

/// 上一轮消费组采集的产物。
///
/// 拓扑面 30s 一轮，lag 60s 一轮：两轮之间**接着用上一轮的组读数**，不对已有序列
/// 发发停停（断点会让趋势图出现空洞，比稍微陈旧更糟）。
#[derive(Default)]
pub(super) struct GroupCache {
    last: Option<std::time::Instant>,
    /// 这些 facts 属于哪个集群：换了集群就丢掉（否则会把 A 集群的组挂到 B 上）。
    cluster_key: Option<String>,
    facts: Vec<super::runtime::MetricsLabeledFact>,
}

/// 自探端点 → 采集配置时的约定。
///
/// 这里是**唯一**还留在机器上的东西：SASL 密码文件（Secret 挂到固定路径）。
/// 用户名不是秘密，固定约定；机制用 `auto`（由 broker 的 `SaslHandshake` 选）。
pub const KAFKA_PROBE_USERNAME: &str = "wist-probe";
/// 凭据目录（Secret 挂载点）。`probe` 放密码，`ca.pem` 可选（私有 CA）。
pub const KAFKA_SECRET_DIR: &str = "/etc/wist-agentd/secrets/kafka";

/// 把自探结果翻译成采集配置（每个集群一条）。
///
/// - 端点：取自探里**第一个可达**的（已按「广告地址 + 握手成功」排过序）；
/// - 协议：监听器的安全协议；`unknown` 按 `PLAINTEXT` 试（最保守，失败了会在 warning 里说）；
/// - 凭据：SASL 用 `secrets/kafka/probe`，TLS 用 `secrets/kafka/ca.pem`（存在才给）。
///
/// 没有快照 / 没有可达端点 → 空列表（调用方据此停采，而不是猜地址）。
pub fn targets_from_discovery(
    snapshot: Option<&wist_contracts::discovery::DiscoverySnapshot>,
    settings: &KafkaTargetSettings,
) -> Vec<KafkaProbeConfig> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    targets_from_clusters(
        crate::discovery::kafka_source::resolve_from_snapshot(snapshot),
        settings,
    )
}

/// 纯映射部分（与发现解耦，单测不需要真 `/proc`）。
pub fn targets_from_clusters(
    clusters: Vec<crate::discovery::kafka_source::KafkaClusterEntry>,
    settings: &KafkaTargetSettings,
) -> Vec<KafkaProbeConfig> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for cluster in clusters {
        let Some(endpoint) = cluster.endpoints.iter().find(|endpoint| endpoint.reachable) else {
            log::debug!(
                "event=KafkaClusterUnreachable source_ref={} endpoints={:?}",
                cluster.source_ref,
                cluster
                    .endpoints
                    .iter()
                    .map(|e| &e.addr)
                    .collect::<Vec<_>>()
            );
            continue;
        };
        if !seen.insert(endpoint.addr.clone()) {
            continue;
        }
        let protocol = match endpoint.protocol.as_str() {
            "PLAINTEXT" | "SSL" | "SASL_PLAINTEXT" | "SASL_SSL" => endpoint.protocol.as_str(),
            // 读取不到协议（只看得到监听端口）：按明文试，失败会在本轮 warning 里说明。
            _ => "PLAINTEXT",
        };
        let sasl = protocol.contains("SASL");
        let tls = matches!(protocol, "SSL" | "SASL_SSL");
        let ca_path = format!("{KAFKA_SECRET_DIR}/ca.pem");
        let config = KafkaProbeConfig::new(
            vec![endpoint.addr.clone()],
            settings.client_id.clone(),
            settings.timeout.as_millis() as u64,
            settings.interval.as_millis() as u64,
        )
        .with_groups(
            settings.groups.clone(),
            settings.group_interval.as_millis() as u64,
        )
        .with_security(OwnedSecurityConfig {
            protocol: protocol.to_string(),
            mechanism: "auto".to_string(),
            username: sasl.then(|| KAFKA_PROBE_USERNAME.to_string()),
            password_file: sasl.then(|| format!("{KAFKA_SECRET_DIR}/probe")),
            tls_ca_file: tls
                .then(|| ca_path.clone())
                .filter(|path| std::path::Path::new(path).is_file()),
        });
        out.push(config);
    }
    out
}

/// `targets_from_discovery` 的调优参数（来自工作授权的周期 + `[kafka]` 的几个旋钮）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct KafkaTargetSettings {
    pub client_id: String,
    pub timeout: Duration,
    pub interval: Duration,
    pub group_interval: Duration,
    pub groups: GroupPolicy,
}

/// 依次尝试 bootstrap 节点，第一个成功的回答即为本轮结果。
fn probe_once(config: &KafkaProbeConfig, groups: &mut GroupCache) -> ProbeResult {
    probe_with_budget(config, groups, config.capacity_budget)
}

/// `probe_once` 的实现，预算可注入（测试用 0 验「不把整轮拖死」）。
fn probe_with_budget(
    config: &KafkaProbeConfig,
    groups: &mut GroupCache,
    capacity_budget: Duration,
) -> ProbeResult {
    let security = config.security.borrowed();
    let mut last_error = None;
    for addr in &config.bootstrap_servers {
        match fetch_metadata(addr, &security, &config.client_id, config.timeout) {
            Ok(metadata) => {
                let mut warnings = Vec::new();

                // 消费组面**先跑**：lag 是 P0，容量面（P1）再慢也不应该把它饿死。
                // 换集群（bootstrap 指到了另一个集群）就作废旧读数。
                if groups.cluster_key.as_deref() != Some(metadata.cluster_key.as_str()) {
                    groups.cluster_key = Some(metadata.cluster_key.clone());
                    groups.last = None;
                    groups.facts.clear();
                }
                let due = match groups.last {
                    None => true,
                    Some(last) => last.elapsed() >= config.group_interval,
                };
                if due {
                    let collected =
                        kafka_groups::collect(&metadata, &security, config.timeout, &config.groups);
                    groups.last = Some(std::time::Instant::now());
                    groups.facts = collected.facts;
                    warnings.extend(collected.warnings);
                    if collected.dropped_groups > 0 {
                        warnings.push(format!(
                            "消费组数超过 max_groups={}，本轮丢弃 {} 个（按组名稳定截断）",
                            config.groups.max_groups, collected.dropped_groups
                        ));
                    }
                }

                // 容量面：逐个 broker 连一次 `DescribeLogDirs`。
                // 单个 broker 拿不到就少一条容量读数（缺序列），不影响其余指标；
                // 但**必须留一条可定位的记录**（哪个 broker、哪个 API、什么原因）。
                // 整轮用量封顶：超时就少采尾部 broker 的容量，而不是拖死探测线程。
                let started = std::time::Instant::now();
                let mut log_dirs = BTreeMap::new();
                for (index, broker) in metadata.brokers.iter().enumerate() {
                    if started.elapsed() >= capacity_budget {
                        warnings.push(format!(
                            "容量面超过预算 {}ms：后 {} 个 broker 本轮不采（拓扑与 lag 不受影响）",
                            capacity_budget.as_millis(),
                            metadata.brokers.len() - index
                        ));
                        break;
                    }
                    let broker_addr = format!("{}:{}", broker.host, broker.port);
                    match fetch_log_dir_totals(
                        &broker_addr,
                        &security,
                        &config.client_id,
                        config.timeout,
                    ) {
                        Ok(totals) => {
                            // 目录级 error_code 以前只看不用：一个掉线的卷会让合计
                            // **静默偏低**。这是容量告警的反方向错误，必须留痕。
                            if totals.failed_dirs > 0 {
                                warnings.push(format!(
                                    "broker {} ({broker_addr}) 有 {} 个 log dir 返回错误码（容量读数偏低）",
                                    broker.node_id, totals.failed_dirs
                                ));
                            }
                            log_dirs.insert(broker.node_id, totals);
                        }
                        Err(err) => warnings.push(format!(
                            "broker {} ({broker_addr}) DescribeLogDirs 失败：{err}",
                            broker.node_id
                        )),
                    }
                }

                let mut result = build_targets(&metadata, &log_dirs);
                result.warnings = warnings;
                // 组读数挂在集群级 target 上（身份是 `kafka:<cluster>`，组名与 topic 只做 label）。
                let cluster_ref = format!("kafka:{}", metadata.cluster_key);
                if let Some(cluster) = result
                    .targets
                    .iter_mut()
                    .find(|target| target.resource_ref == cluster_ref)
                {
                    cluster.labeled_facts = groups.facts.clone();
                }
                return result;
            }
            Err(err) => last_error = Some(format!("{addr}: {err}")),
        }
    }
    ProbeResult {
        targets: Vec::new(),
        attempted: config.bootstrap_servers.len(),
        failed: config.bootstrap_servers.len(),
        last_error: last_error.or_else(|| Some("no bootstrap server configured".to_string())),
        warnings: Vec::new(),
    }
}

/// 测试用：跑一轮完整探测（含消费组），不需要起真 broker。
#[cfg(test)]
pub(super) fn probe_once_for_test(config: &KafkaProbeConfig) -> ProbeResult {
    probe_once(config, &mut GroupCache::default())
}

/// 测试用：指定容量面预算（`0` = 一个 broker 的容量都不采）。
#[cfg(test)]
pub(super) fn probe_once_with_budget(config: &KafkaProbeConfig, budget: Duration) -> ProbeResult {
    probe_with_budget(config, &mut GroupCache::default(), budget)
}

/// 测试用：带缓存跑一轮（验证 `lag_interval_ms` 的复用语义）。
#[cfg(test)]
pub(super) fn probe_once_with_cache(
    config: &KafkaProbeConfig,
    cache: &mut GroupCache,
) -> ProbeResult {
    probe_once(config, cache)
}

/// 把一次元数据回答翻译成指标目标。
///
/// 每个 broker 一个 `sample_target`：`resource_ref` 即实例身份
/// （`kafka:<cluster>:<broker_id>`），因此不需要额外的 `broker_id` label。
///
/// `attempted` 用**目标数**（broker + 1 个集群级），不用 bootstrap 地址数：
/// 后者与 `succeeded_targets` 不同口径，会让 3 个 broker 的集群报出
/// "attempted=1 / succeeded=4"（self-observability 里自相矛盾）。
pub fn build_targets(
    metadata: &Metadata,
    log_dir_totals: &BTreeMap<i32, LogDirTotals>,
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
        if let Some(totals) = log_dir_totals.get(&broker.node_id) {
            facts.push(fact(
                "kafka.log_dir.size_bytes",
                &totals.size_bytes.to_string(),
            ));
            // 可用空间只有 `DescribeLogDirs v4` 才有；更老的 broker 就少这一条（不伪造）。
            if let Some(usable) = totals.usable_bytes {
                facts.push(fact("kafka.log_dir.usable_bytes", &usable.to_string()));
            }
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
        attempted: targets.len(),
        targets,
        failed: 0,
        last_error: None,
        warnings: Vec::new(),
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
    /// topic 名：消费组 lag 要把「提交位点」对到「分区 leader」上，必须有它。
    pub topic: String,
    pub partition: i32,
    pub leader: i32,
    pub replicas: Vec<i32>,
    pub isr: Vec<i32>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Metadata {
    /// 集群标识：优先用 broker 回的 `cluster_id`（Metadata v2+），拿不到才退到端点摘要。
    pub cluster_key: String,
    /// Metadata v2+ 的 `cluster_id`（更老的 broker 为 `None`）。
    pub cluster_id: Option<String>,
    pub brokers: Vec<Broker>,
    pub controller_id: i32,
    pub partitions: Vec<PartitionInfo>,
}

/// 发一次 Metadata 请求并解析。
pub fn fetch_metadata(
    addr: &str,
    security: &SecurityConfig<'_>,
    client_id: &str,
    timeout: Duration,
) -> io::Result<Metadata> {
    let mut connection = kafka_auth::connect(addr, security, timeout)?;
    let version = connection.versions.metadata;
    let payload = encode_metadata_request(11, client_id, version);
    let response = kafka_auth::exchange(&mut *connection.stream, &payload)?;
    // 响应头：correlation_id（v1/v2 没有任何 tagged fields）。
    let mut reader = Reader::new(&response);
    let correlation_id = reader.i32()?;
    if correlation_id != 11 {
        return Err(invalid(format!(
            "unexpected correlation id {correlation_id}"
        )));
    }
    parse_metadata_response(&mut reader, version)
}

/// 一个 broker 的容量读数：已用总量 + （v4 才有的）可用总量 + 目录级错误数。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct LogDirTotals {
    pub size_bytes: i64,
    /// 各 log dir 所在卷的可用空间之和；broker 不支持 `DescribeLogDirs v4` 时为 `None`。
    ///
    /// 仍然是「Kafka 侧只说自己的卷」，不是整块盘的分母（主机文件系统指标仍是权威口径）。
    pub usable_bytes: Option<i64>,
    /// 返回非 0 `error_code` 的目录数（盘掉线 / 目录不可读）。
    ///
    /// 这种目录不贡献容量，但**必须让上层能报警**：否则一个掉线的卷只会让
    /// `kafka_log_dir_size_bytes` 静默变小，而「容量告警」恰好是最经不起反向误差的一项。
    pub failed_dirs: usize,
}

/// 拉一个 broker 的 log dir 合计（已用 + 可用）。
pub fn fetch_log_dir_totals(
    addr: &str,
    security: &SecurityConfig<'_>,
    client_id: &str,
    timeout: Duration,
) -> io::Result<LogDirTotals> {
    let mut connection = kafka_auth::connect(addr, security, timeout)?;
    let Some(version) = connection.versions.describe_log_dirs.version else {
        return Err(invalid(
            connection
                .versions
                .describe_log_dirs
                .unavailable_reason("DescribeLogDirs"),
        ));
    };
    let payload = encode_describe_log_dirs_request(12, client_id, version);
    let response = kafka_auth::exchange(&mut *connection.stream, &payload)?;
    parse_describe_log_dirs(&response, 12, version)
}

/// `DescribeLogDirs` 请求：`topics = null`（= 全部）。
///
/// v2 起是 flexible 版本：请求头多一组 tagged fields，`topics` 用 compact 编码。
pub fn encode_describe_log_dirs_request(
    correlation_id: i32,
    client_id: &str,
    version: i16,
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_DESCRIBE_LOG_DIRS.to_be_bytes());
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    if version >= 2 {
        body.push(0); // 请求头 tagged fields（空）
        body.push(0); // topics = null（compact nullable array）
        body.push(0); // 请求体 tagged fields（空）
    } else {
        body.extend_from_slice(&(-1i32).to_be_bytes());
    }

    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// 解析 `DescribeLogDirs` 响应（含 correlation_id），版本 v0-v4。
///
/// 字段顺序以 Kafka 3.9 的 `DescribeLogDirsResponse.json` 为准：
/// 响应头（flexible=v2+ 有 tagged fields）→ throttle →（v3+ 顶层 error_code）→ results。
/// 每个 result 里 v4 才追加 `total_bytes` / `usable_bytes`。
pub fn parse_describe_log_dirs(
    response: &[u8],
    correlation_id: i32,
    version: i16,
) -> io::Result<LogDirTotals> {
    let flexible = version >= 2;
    let mut reader = Reader::new(response);
    let got = reader.i32()?;
    if got != correlation_id {
        return Err(invalid(format!("unexpected correlation id {got}")));
    }
    if flexible {
        reader.skip_tagged_fields()?;
    }
    let _throttle_time_ms = reader.i32()?;
    if version >= 3 {
        let error_code = reader.i16()?;
        if error_code != 0 {
            return Err(invalid(format!(
                "DescribeLogDirs 顶层 error_code {error_code}（权限不足或状态异常）"
            )));
        }
    }

    let dirs = array_len(&mut reader, flexible)?;
    let mut size_bytes = 0i64;
    let mut usable_bytes: Option<i64> = None;
    let mut failed_dirs = 0usize;
    let mut last_dir_error: Option<i16> = None;
    for _ in 0..dirs {
        let error_code = reader.i16()?;
        let _log_dir = string(&mut reader, flexible)?;
        let topics = array_len(&mut reader, flexible)?;
        for _ in 0..topics {
            let _topic = string(&mut reader, flexible)?;
            let partitions = array_len(&mut reader, flexible)?;
            for _ in 0..partitions {
                let _partition_index = reader.i32()?;
                let partition_size = reader.i64()?;
                let _offset_lag = reader.i64()?;
                let is_future = reader.boolean()?;
                if flexible {
                    reader.skip_tagged_fields()?;
                }
                // 未来副本不是本地已有数据，算进去会让容量虚高。
                if error_code == 0 && !is_future {
                    size_bytes += partition_size;
                }
            }
            if flexible {
                reader.skip_tagged_fields()?;
            }
        }
        // 目录级错误：这个目录读不出来（盘掉线 / 权限）—— 不贡献容量，但要计数。
        if error_code != 0 {
            failed_dirs += 1;
            last_dir_error = Some(error_code);
        }
        if version >= 4 {
            let _total_bytes = reader.i64()?;
            let dir_usable = reader.i64()?;
            // 兼容 -1（未知）：只要有一个目录给了就上报合计。
            if error_code == 0 && dir_usable >= 0 {
                *usable_bytes.get_or_insert(0) += dir_usable;
            }
        }
        if flexible {
            reader.skip_tagged_fields()?;
        }
    }
    if flexible {
        reader.skip_tagged_fields()?;
    }

    if dirs == 0 {
        return Err(invalid(
            "DescribeLogDirs 返回 0 个日志目录（字段布局与 broker 版本对不上？）".to_string(),
        ));
    }
    // 全部目录都读不出来时**不能**发一个 0：0 会被读成「磁盘空」，
    // 而这里的事实是「一点都没读到」。两者在容量告警上的方向完全相反。
    if failed_dirs == dirs {
        return Err(invalid(format!(
            "DescribeLogDirs 的 {dirs} 个日志目录全部返回错误码（最后一个 {}）",
            last_dir_error.unwrap_or(0)
        )));
    }
    Ok(LogDirTotals {
        size_bytes,
        usable_bytes,
        failed_dirs,
    })
}

/// 读数组长度：flexible 用 compact 编码。
fn array_len(reader: &mut Reader<'_>, flexible: bool) -> io::Result<usize> {
    if flexible {
        reader.compact_array_len()
    } else {
        reader.array_len()
    }
}

/// 读字符串：flexible 用 compact 编码。
fn string(reader: &mut Reader<'_>, flexible: bool) -> io::Result<String> {
    if flexible {
        reader.compact_string()
    } else {
        reader.string()
    }
}

pub(super) fn invalid(message: String) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

/// `Metadata` 请求：`topics = null`（= 全部 topic）。
///
/// v1–v3 的请求体只有 `topics`；v4 起多一个 `allow_auto_topic_creation`。
/// 本探针只发 v1/v2（协商上限就卡在那里），所以不需要那个字段。
pub fn encode_metadata_request(correlation_id: i32, client_id: &str, version: i16) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_METADATA.to_be_bytes());
    body.extend_from_slice(&version.to_be_bytes());
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

/// 解析 Metadata 响应体（已去掉 correlation_id），`version` ∈ {1, 2}。
///
/// 字段顺序以 Kafka 3.9/4.0 的 `MetadataResponse.json` 为准：
/// brokers（v1 起带 nullable 的 rack）→（v2 起 `cluster_id`）→ controller_id → topics。
pub fn parse_metadata_response(reader: &mut Reader<'_>, version: i16) -> io::Result<Metadata> {
    if !(1..=2).contains(&version) {
        return Err(invalid(format!(
            "不支持的 Metadata 版本 v{version}（本探针只解析 v1-v2）"
        )));
    }
    let brokers_len = reader.array_len()?;
    let mut brokers = Vec::with_capacity(brokers_len);
    for _ in 0..brokers_len {
        let node_id = reader.i32()?;
        let host = reader.string()?;
        let port = reader.i32()?;
        // Metadata v1 起每个 broker 带机架（nullable string）。不读它，后面的
        // `controller_id` / topics 全部错位 —— 真 broker 上直接解析失败或读出垃圾。
        let _rack = reader.string()?;
        brokers.push(Broker {
            node_id,
            host,
            port,
        });
    }
    let cluster_id = if version >= 2 {
        let raw = reader.string()?;
        if raw.is_empty() { None } else { Some(raw) }
    } else {
        None
    };
    let controller_id = reader.i32()?;

    let topics_len = reader.array_len()?;
    let mut partitions = Vec::new();
    for _ in 0..topics_len {
        let _error_code = reader.i16()?;
        let name = reader.string()?;
        let _is_internal = reader.boolean()?;
        let partitions_len = reader.array_len()?;
        for _ in 0..partitions_len {
            let _partition_error = reader.i16()?;
            let partition = reader.i32()?;
            let leader = reader.i32()?;
            let replicas = reader.i32_array()?;
            let isr = reader.i32_array()?;
            partitions.push(PartitionInfo {
                topic: name.clone(),
                partition,
                leader,
                replicas,
                isr,
            });
        }
    }

    if brokers.is_empty() {
        return Err(invalid("metadata response has no brokers".to_string()));
    }
    // 有 `cluster_id` 就用它（全局稳定，换 bootstrap 节点/换 IP 都不变）；
    // 老 broker 没这个字段才退回端点摘要。
    let cluster_key = cluster_id.clone().unwrap_or_else(|| cluster_key(&brokers));
    Ok(Metadata {
        cluster_key,
        cluster_id,
        brokers,
        controller_id,
        partitions,
    })
}

/// Metadata v1 不返回 `cluster_id`，用 broker 端点集合的稳定摘要当集群键。
///
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

    /// Kafka 的 `bytes`：int32 长度 + 原始字节；`-1`（null）按空处理。
    /// SASL 的 auth_bytes 就是它，**不能**当 UTF-8 解。
    pub fn bytes(&mut self) -> io::Result<Vec<u8>> {
        let len = self.i32()?;
        if len < 0 {
            return Ok(Vec::new());
        }
        Ok(self.take(len as usize)?.to_vec())
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

    /// Kafka flexible 版本的 unsigned varint（LEB128，最多 5 字节）。
    pub fn uvarint(&mut self) -> io::Result<u32> {
        let mut value = 0u32;
        for shift in [0u32, 7, 14, 21, 28] {
            let byte = self.take(1)?[0];
            value |= u32::from(byte & 0x7f) << shift;
            if byte & 0x80 == 0 {
                return Ok(value);
            }
        }
        Err(invalid("varint 超过 5 字节".to_string()))
    }

    /// compact 数组长度：`uvarint - 1`，`0` 表示 null。
    pub fn compact_array_len(&mut self) -> io::Result<usize> {
        let raw = self.uvarint()?;
        if raw == 0 {
            return Ok(0);
        }
        let len = (raw - 1) as usize;
        if len > 1_000_000 {
            return Err(invalid(format!("array too large: {len}")));
        }
        Ok(len)
    }

    /// compact 字符串：长度也是 `uvarint - 1`。
    pub fn compact_string(&mut self) -> io::Result<String> {
        let raw = self.uvarint()?;
        if raw == 0 {
            return Ok(String::new());
        }
        let bytes = self.take((raw - 1) as usize)?;
        String::from_utf8(bytes.to_vec()).map_err(|err| invalid(format!("bad utf8: {err}")))
    }

    /// 跳过 tagged fields（flexible 版本里每个结构末尾都有一组）。
    pub fn skip_tagged_fields(&mut self) -> io::Result<()> {
        let count = self.uvarint()?;
        for _ in 0..count {
            let _tag = self.uvarint()?;
            let size = self.uvarint()?;
            let _ = self.take(size as usize)?;
        }
        Ok(())
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
    use std::io::{Read, Write};

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
            cluster_id: None,
            brokers: vec![broker(1, "10.0.0.1", 9092), broker(2, "10.0.0.2", 9092)],
            controller_id: 2,
            partitions: vec![
                PartitionInfo {
                    topic: "t".to_string(),
                    partition: 0,
                    leader: 1,
                    replicas: vec![1, 2],
                    isr: vec![1, 2],
                },
                PartitionInfo {
                    topic: "t".to_string(),
                    partition: 1,
                    leader: 1,
                    replicas: vec![1, 2],
                    isr: vec![1],
                },
                PartitionInfo {
                    topic: "t".to_string(),
                    partition: 2,
                    leader: -1,
                    replicas: vec![1, 2],
                    isr: vec![],
                },
            ],
        }
    }

    /// 这些用例只验元数据 / 容量面，把消费组采集关掉（`max_groups = 0`）。
    fn probe_config(port: u16, timeout_ms: u64) -> KafkaProbeConfig {
        KafkaProbeConfig::new(
            vec![format!("127.0.0.1:{port}")],
            "wist-agentd-test".to_string(),
            timeout_ms,
            1_000,
        )
        .with_groups(
            GroupPolicy {
                max_groups: 0,
                ..GroupPolicy::default()
            },
            60_000,
        )
    }

    #[test]
    fn encode_request_has_a_size_prefix_and_null_topic_list() {
        for version in [1, 2] {
            let bytes = encode_metadata_request(11, "wist-agentd", version);
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
                version,
                "api version 必须是协商出来的那个"
            );
            // v1/v2 的请求体一样；最后四个字节是 topics=null
            assert_eq!(&bytes[bytes.len() - 4..], &(-1i32).to_be_bytes());
        }
    }

    /// v2 多一个 `cluster_id`：有它就该拿它做 `instance` 的集群段（换 IP 不断档）。
    #[test]
    fn metadata_v2_uses_the_broker_cluster_id() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_be_bytes()); // brokers
        buf.extend_from_slice(&1i32.to_be_bytes()); // node_id
        buf.extend_from_slice(&8i16.to_be_bytes());
        buf.extend_from_slice(b"10.0.0.1");
        buf.extend_from_slice(&9092i32.to_be_bytes());
        buf.extend_from_slice(&(-1i16).to_be_bytes()); // rack = null
        buf.extend_from_slice(&13i16.to_be_bytes()); // cluster_id
        buf.extend_from_slice(b"real-cluster1");
        buf.extend_from_slice(&1i32.to_be_bytes()); // controller
        buf.extend_from_slice(&0i32.to_be_bytes()); // topics

        let mut reader = Reader::new(&buf);
        let parsed = parse_metadata_response(&mut reader, 2).expect("parse v2");
        assert_eq!(parsed.cluster_id.as_deref(), Some("real-cluster1"));
        assert_eq!(parsed.cluster_key, "real-cluster1");
        assert_eq!(parsed.brokers.len(), 1);
    }

    /// v1 没有 `cluster_id`：退回端点摘要，绝不能用空串当集群键。
    #[test]
    fn metadata_v1_falls_back_to_the_endpoint_digest() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&2i32.to_be_bytes());
        buf.extend_from_slice(&4i16.to_be_bytes());
        buf.extend_from_slice(b"10.0");
        buf.extend_from_slice(&9093i32.to_be_bytes());
        buf.extend_from_slice(&(-1i16).to_be_bytes());
        buf.extend_from_slice(&2i32.to_be_bytes()); // controller
        buf.extend_from_slice(&0i32.to_be_bytes()); // topics

        let mut reader = Reader::new(&buf);
        let parsed = parse_metadata_response(&mut reader, 1).expect("parse v1");
        assert_eq!(parsed.cluster_id, None);
        assert_eq!(parsed.cluster_key, cluster_key(&parsed.brokers));
        assert_eq!(parsed.cluster_key.len(), 16, "64 位摘要");
    }

    #[test]
    fn parses_a_metadata_response() {
        // 按 Kafka 3.9 的 `MetadataResponse.json` 的 v1 布局拼：
        // brokers[{node_id, host, port, rack(nullable)}] / controller_id /
        // topics[{error_code, name, is_internal, partitions[...]}]
        let mut buf = Vec::new();
        buf.extend_from_slice(&2i32.to_be_bytes()); // brokers
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&4i16.to_be_bytes());
        buf.extend_from_slice(b"10.0");
        buf.extend_from_slice(&9092i32.to_be_bytes());
        buf.extend_from_slice(&(-1i16).to_be_bytes()); // rack = null
        buf.extend_from_slice(&2i32.to_be_bytes());
        buf.extend_from_slice(&4i16.to_be_bytes());
        buf.extend_from_slice(b"10.1");
        buf.extend_from_slice(&9093i32.to_be_bytes());
        buf.extend_from_slice(&4i16.to_be_bytes()); // rack = "az-1"
        buf.extend_from_slice(b"az-1");
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
        let parsed = parse_metadata_response(&mut reader, 1).expect("parse");
        assert_eq!(parsed.brokers.len(), 2);
        assert_eq!(
            parsed.brokers[1].host, "10.1",
            "机架字段不能吃掉下一台的 host"
        );
        assert_eq!(parsed.controller_id, 2);
        assert_eq!(parsed.partitions.len(), 1);
        assert_eq!(parsed.partitions[0].leader, 1);
        assert_eq!(parsed.partitions[0].isr, vec![1]);
    }

    #[test]
    fn truncated_response_is_an_error_not_a_panic() {
        let buf = vec![0u8; 3];
        let mut reader = Reader::new(&buf);
        assert!(parse_metadata_response(&mut reader, 1).is_err());
    }

    #[test]
    fn reader_bytes_handles_null_and_binary_payloads() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(-1i32).to_be_bytes());
        buf.extend_from_slice(&3i32.to_be_bytes());
        buf.extend_from_slice(&[0x00, 0xff, 0x01]);

        let mut reader = Reader::new(&buf);
        assert_eq!(reader.bytes().expect("null"), Vec::<u8>::new());
        assert_eq!(
            reader.bytes().expect("binary"),
            vec![0x00, 0xff, 0x01],
            "auth_bytes 不能当字符串解"
        );
    }

    /// 读一条请求，返回 `(api_key, api_version, correlation_id)`。
    fn read_request(stream: &mut std::net::TcpStream) -> (i16, i16, i32) {
        let mut size = [0u8; 4];
        stream.read_exact(&mut size).expect("size prefix");
        let mut body = vec![0u8; i32::from_be_bytes(size) as usize];
        stream.read_exact(&mut body).expect("request body");
        (
            i16::from_be_bytes([body[0], body[1]]),
            i16::from_be_bytes([body[2], body[3]]),
            i32::from_be_bytes([body[4], body[5], body[6], body[7]]),
        )
    }

    fn write_response(stream: &mut std::net::TcpStream, body: &[u8]) {
        stream
            .write_all(&(body.len() as i32).to_be_bytes())
            .expect("frame size");
        stream.write_all(body).expect("frame body");
        stream.flush().expect("flush");
    }

    /// `ApiVersions` v0 响应：Metadata v0-v2、DescribeLogDirs v0-v1，以及 SASL 两条。
    fn api_versions_body(correlation_id: i32) -> Vec<u8> {
        let apis: [(i16, i16, i16); 5] = [
            (18, 0, 4),
            (API_KEY_METADATA, 0, 2),
            (API_KEY_DESCRIBE_LOG_DIRS, 0, 1),
            (17, 0, 1),
            (36, 0, 2),
        ];
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes()); // error_code
        body.extend_from_slice(&(apis.len() as i32).to_be_bytes());
        for (api_key, min, max) in apis {
            body.extend_from_slice(&api_key.to_be_bytes());
            body.extend_from_slice(&min.to_be_bytes());
            body.extend_from_slice(&max.to_be_bytes());
        }
        body
    }

    /// `Metadata` v2 响应：brokers（带 rack）/ cluster_id / controller / topics。
    fn metadata_v2_body(correlation_id: i32, brokers: &[(i32, &str, i32)]) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&(brokers.len() as i32).to_be_bytes());
        for (node_id, host, port) in brokers {
            body.extend_from_slice(&node_id.to_be_bytes());
            body.extend_from_slice(&(host.len() as i16).to_be_bytes());
            body.extend_from_slice(host.as_bytes());
            body.extend_from_slice(&port.to_be_bytes());
            body.extend_from_slice(&(-1i16).to_be_bytes()); // rack = null
        }
        body.extend_from_slice(&13i16.to_be_bytes()); // cluster_id
        body.extend_from_slice(b"test-cluster1");
        body.extend_from_slice(&brokers[0].0.to_be_bytes()); // controller
        body.extend_from_slice(&0i32.to_be_bytes()); // topics
        body
    }

    fn describe_log_dirs_body(correlation_id: i32, size: i64, dir_error: i16) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&0i32.to_be_bytes()); // throttle_time_ms
        body.extend_from_slice(&1i32.to_be_bytes()); // log_dirs
        body.extend_from_slice(&dir_error.to_be_bytes()); // error_code（目录级）
        body.extend_from_slice(&5i16.to_be_bytes());
        body.extend_from_slice(b"/data");
        body.extend_from_slice(&1i32.to_be_bytes()); // topics
        body.extend_from_slice(&1i16.to_be_bytes());
        body.extend_from_slice(b"t");
        body.extend_from_slice(&1i32.to_be_bytes()); // partitions
        body.extend_from_slice(&0i32.to_be_bytes());
        body.extend_from_slice(&size.to_be_bytes());
        body.extend_from_slice(&0i64.to_be_bytes());
        body.push(0);
        body
    }

    /// 起一个假 broker：第一条连接答「协商 + Metadata」，`capacity` 有值时
    /// 再伺候第二条连接答「协商 + DescribeLogDirs」（`(已用字节, 目录 error_code)`）。
    ///
    /// 线程干完就退出、监听器随之关闭 —— 没伺候的那条连接会被拒，
    /// 正好用来验「容量缺失只影响那一条读数」。
    fn spawn_kafka<F>(
        brokers: F,
        capacity: Option<(i64, i16)>,
    ) -> (u16, std::thread::JoinHandle<()>)
    where
        F: FnOnce(u16) -> Vec<(i32, String, i32)> + Send + 'static,
    {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let handle = std::thread::spawn(move || {
            // 第一条连接：metadata
            let (mut stream, _) = listener.accept().expect("accept");
            let (api_key, version, correlation_id) = read_request(&mut stream);
            assert_eq!(api_key, 18, "第一条必须是 ApiVersions");
            assert_eq!(version, 0);
            write_response(&mut stream, &api_versions_body(correlation_id));
            let (api_key, version, correlation_id) = read_request(&mut stream);
            assert_eq!(api_key, API_KEY_METADATA, "然后才是 Metadata");
            assert_eq!(version, 2, "协商后应选双方都支持的最高版 v2");
            let advertised_owned = brokers(port);
            let advertised: Vec<(i32, &str, i32)> = advertised_owned
                .iter()
                .map(|(id, host, port)| (*id, host.as_str(), *port))
                .collect();
            write_response(&mut stream, &metadata_v2_body(correlation_id, &advertised));

            // 第二条连接（可选）：DescribeLogDirs
            let Some((size, dir_error)) = capacity else {
                return;
            };
            let (mut stream, _) = listener.accept().expect("accept");
            let (api_key, _, correlation_id) = read_request(&mut stream);
            assert_eq!(api_key, 18);
            write_response(&mut stream, &api_versions_body(correlation_id));
            let (api_key, version, correlation_id) = read_request(&mut stream);
            assert_eq!(api_key, API_KEY_DESCRIBE_LOG_DIRS);
            assert_eq!(version, 1, "协商后应选 v1（v0 在 4.0 已移除）");
            write_response(
                &mut stream,
                &describe_log_dirs_body(correlation_id, size, dir_error),
            );
        });
        (port, handle)
    }

    /// 探针每轮真就是这么干的：metadata 一次 + 每个 broker 一次 DescribeLogDirs。
    #[test]
    fn probe_once_reads_capacity_when_the_broker_answers() {
        let (port, server) = spawn_kafka(
            |port| vec![(7, "127.0.0.1".to_string(), port as i32)],
            Some((1_048_576, 0)),
        );
        let config = probe_config(port, 500);
        let result = probe_once(&config, &mut GroupCache::default());
        server.join().expect("broker thread");

        assert_eq!(result.failed, 0, "{:?}", result.last_error);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        let size = result.targets[0]
            .runtime_facts
            .iter()
            .find(|fact| fact.key == "kafka.log_dir.size_bytes")
            .expect("应当带上容量读数");
        assert_eq!(size.value, "1048576");
    }

    /// 容量面有自己的总预算：不可达 broker 数 × 单次超时是串行叠加的，
    /// 不封顶就会把同一轮的 lag 面一起饿死。预算为 0 时一个都不采，但要留 warning。
    #[test]
    fn capacity_face_respects_its_budget_instead_of_stalling_the_round() {
        let (port, server) =
            spawn_kafka(|port| vec![(7, "127.0.0.1".to_string(), port as i32)], None);
        let config = probe_config(port, 200);
        let result = probe_once_with_budget(&config, Duration::ZERO);
        server.join().expect("broker thread");

        assert!(
            result.targets.iter().all(|target| !target
                .runtime_facts
                .iter()
                .any(|fact| fact.key == "kafka.log_dir.size_bytes")),
            "超预算就不采容量，不是发 0"
        );
        let warning = result
            .warnings
            .iter()
            .find(|warning| warning.contains("容量面超过预算"))
            .unwrap_or_else(|| panic!("缺超预算的 warning：{:?}", result.warnings));
        assert!(warning.contains("后 1 个 broker"), "{warning}");
        assert!(
            result.targets.len() >= 2,
            "拓扑面不受容量面预算影响：{:?}",
            result.targets.len()
        );
    }

    /// 目录级 `error_code` 以前只看不用：一个掉线的卷会让合计**静默偏低**，
    /// 而容量告警恰好是最经不起反向误差的一项。全部目录都读不到时更不能发 0。
    #[test]
    fn a_failed_log_dir_is_reported_and_never_reported_as_zero() {
        let (port, server) = spawn_kafka(
            |port| vec![(7, "127.0.0.1".to_string(), port as i32)],
            Some((4_096, 2)),
        );
        let config = probe_config(port, 500);
        let result = probe_once(&config, &mut GroupCache::default());
        server.join().expect("broker thread");

        assert!(
            !result.targets[0]
                .runtime_facts
                .iter()
                .any(|fact| fact.key == "kafka.log_dir.size_bytes"),
            "全部日志目录都读不到时不能发 0（0 会被读成磁盘空）"
        );
        let warning = result
            .warnings
            .iter()
            .find(|warning| warning.contains("DescribeLogDirs"))
            .unwrap_or_else(|| panic!("缺 DescribeLogDirs 的 warning：{:?}", result.warnings));
        assert!(warning.contains("错误码"), "{warning}");
        assert!(warning.contains("broker 7"), "{warning}");
    }

    /// 部分目录失败：能读到的目录照常合计，同时把失败目录数报上去（不假装完整）。
    #[test]
    fn a_partially_readable_broker_reports_its_dir_errors() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&12i32.to_be_bytes()); // correlation_id
        buf.extend_from_slice(&0i32.to_be_bytes()); // throttle_time_ms
        buf.extend_from_slice(&2i32.to_be_bytes()); // 2 个 log dir
        // 目录 1：正常，一个非 future 分区 1_000 字节
        buf.extend_from_slice(&0i16.to_be_bytes());
        buf.extend_from_slice(&5i16.to_be_bytes());
        buf.extend_from_slice(b"/data");
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&1i16.to_be_bytes());
        buf.extend_from_slice(b"t");
        buf.extend_from_slice(&1i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&1_000i64.to_be_bytes());
        buf.extend_from_slice(&0i64.to_be_bytes());
        buf.push(0);
        // 目录 2：盘掉线（error_code 58 = LOG_DIR_NOT_FOUND）
        buf.extend_from_slice(&58i16.to_be_bytes());
        buf.extend_from_slice(&8i16.to_be_bytes());
        buf.extend_from_slice(b"/data-02");
        buf.extend_from_slice(&0i32.to_be_bytes()); // 没有 topic

        let totals = parse_describe_log_dirs(&buf, 12, 1).expect("parse");
        assert_eq!(totals.size_bytes, 1_000, "只算读得到的目录");
        assert_eq!(
            totals.failed_dirs, 1,
            "失败目录必须计数（否则合计静默偏低）"
        );
        assert_eq!(totals.usable_bytes, None);
    }

    #[test]
    fn probe_once_goes_through_the_security_layer() {
        let (port, server) =
            spawn_kafka(|port| vec![(7, "127.0.0.1".to_string(), port as i32)], None);
        let config = probe_config(port, 200);
        let result = probe_once(&config, &mut GroupCache::default());
        server.join().expect("broker thread");

        assert_eq!(
            result.attempted,
            result.targets.len(),
            "attempted 与 succeeded 同口径（目标数），不是 bootstrap 地址数"
        );
        assert_eq!(result.failed, 0, "{:?}", result.last_error);
        assert_eq!(result.targets.len(), 2, "1 broker + 1 集群级");
        assert!(
            result.targets[0]
                .resource_ref
                .starts_with("kafka:test-cluster1:"),
            "instance 应当用 broker 回的 cluster_id：{}",
            result.targets[0].resource_ref
        );
        assert!(result.targets[0].resource_ref.ends_with(":7"));
        assert!(
            !result.targets[0]
                .runtime_facts
                .iter()
                .any(|fact| fact.key == "kafka.log_dir.size_bytes"),
            "拿不到容量就不发这条"
        );
        // 容量缺失必须留痕（哪个 broker、哪个 API、什么原因），否则现场只能看到
        // 「kafka.log_dir.size_bytes 没有数据」而定位不了。
        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
        let warning = &result.warnings[0];
        assert!(warning.contains("broker 7"), "{warning}");
        assert!(warning.contains("DescribeLogDirs"), "{warning}");
        assert!(warning.contains(&format!("127.0.0.1:{port}")), "{warning}");
    }

    /// §12-2：一个 broker 抽不到容量，不影响其余 broker 的指标，但要留一条 warning。
    #[test]
    fn an_unreachable_broker_only_loses_its_capacity_reading() {
        // 端口 1 不需要 root 权限建 listener，连接必定被拒；
        // 不用「先绑再放」的临时端口 —— 并行的其它用例可能刚好抢到它（macOS 上就是既有的 flaky）。
        let dead_port = 1i32;

        let (live_port, server) = spawn_kafka(
            move |live_port| {
                vec![
                    (7, "127.0.0.1".to_string(), live_port as i32),
                    (8, "127.0.0.1".to_string(), dead_port),
                ]
            },
            Some((2_048, 0)),
        );
        let config = probe_config(live_port, 200);
        let result = probe_once(&config, &mut GroupCache::default());
        server.join().expect("broker thread");

        assert_eq!(result.failed, 0, "一个 broker 少条读数不等于整轮失败");
        assert_eq!(result.targets.len(), 3, "2 broker + 1 集群级");
        assert_eq!(result.warnings.len(), 1, "{:?}", result.warnings);
        assert!(
            result.warnings[0].contains("broker 8"),
            "{:?}",
            result.warnings
        );
        assert!(
            result.warnings[0].contains(&format!("127.0.0.1:{dead_port}")),
            "{:?}",
            result.warnings
        );
    }

    /// 已经死透、从 metadata 里消失的 broker：它的序列直接消失，不是发 0。
    #[test]
    fn a_broker_missing_from_metadata_simply_has_no_samples() {
        let (port, server) =
            spawn_kafka(|port| vec![(7, "127.0.0.1".to_string(), port as i32)], None);
        let config = probe_config(port, 200);
        let result = probe_once(&config, &mut GroupCache::default());
        server.join().expect("broker thread");

        assert_eq!(result.targets.len(), 2, "只剩这一个 broker + 集群级");
        assert!(
            result
                .targets
                .iter()
                .all(|target| target.resource_ref.ends_with(":7")
                    || target.resource_ref == "kafka:test-cluster1"),
            "不能给已经不存在的 broker 造样本"
        );
    }

    /// 协商到 v1 时同一套解析器也要能用：v1 与 v0 布局相同，只是限流时机变了。
    #[test]
    fn describe_log_dirs_v1_is_accepted_by_the_same_parser() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&12i32.to_be_bytes()); // correlation_id
        buf.extend_from_slice(&0i32.to_be_bytes()); // throttle
        buf.extend_from_slice(&1i32.to_be_bytes()); // log_dirs
        buf.extend_from_slice(&0i16.to_be_bytes());
        buf.extend_from_slice(&5i16.to_be_bytes());
        buf.extend_from_slice(b"/data");
        buf.extend_from_slice(&0i32.to_be_bytes()); // topics

        let totals = parse_describe_log_dirs(&buf, 12, 1).expect("parse");
        assert_eq!(totals.size_bytes, 0, "有目录但没分区 = 真的空");
        assert_eq!(totals.usable_bytes, None, "v1 没有可用空间字段");
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
        let result = build_targets(&metadata(), &BTreeMap::new());
        assert_eq!(result.targets.len(), 3, "2 broker + 1 集群级");
        assert_eq!(
            result.attempted,
            result.targets.len(),
            "attempted 与 succeeded 必须同口径（目标数），否则会出现 succeeded > attempted"
        );
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
        let mut totals = BTreeMap::new();
        totals.insert(
            2,
            LogDirTotals {
                size_bytes: 1_048_576,
                usable_bytes: None,
                failed_dirs: 0,
            },
        );
        let result = build_targets(&metadata(), &totals);

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
        assert!(
            !broker2
                .runtime_facts
                .iter()
                .any(|fact| fact.key == "kafka.log_dir.usable_bytes"),
            "v4 之前没有可用空间，不能伪造"
        );
    }

    /// `DescribeLogDirs v4` 给了可用空间：已用与可用都要发。
    #[test]
    fn usable_bytes_is_emitted_when_the_broker_answers_v4() {
        let mut totals = BTreeMap::new();
        totals.insert(
            1,
            LogDirTotals {
                size_bytes: 1_000,
                usable_bytes: Some(9_000),
                failed_dirs: 0,
            },
        );
        let result = build_targets(&metadata(), &totals);
        let facts: Vec<(&str, &str)> = result.targets[0]
            .runtime_facts
            .iter()
            .map(|fact| (fact.key.as_str(), fact.value.as_str()))
            .collect();
        assert!(facts.contains(&("kafka.log_dir.size_bytes", "1000")));
        assert!(facts.contains(&("kafka.log_dir.usable_bytes", "9000")));
    }

    #[test]
    fn parses_describe_log_dirs_v0_and_skips_future_replicas() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&12i32.to_be_bytes()); // correlation_id
        // v0 顶层先有 throttle_time_ms（`0+`）—— 漏读它会把 0 当成目录数量。
        buf.extend_from_slice(&0i32.to_be_bytes()); // throttle_time_ms
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

        let totals = parse_describe_log_dirs(&buf, 12, 0).expect("parse");
        assert_eq!(totals.size_bytes, 1_000, "未来副本不算本地容量");
        assert_eq!(totals.usable_bytes, None);
    }

    /// 0 个日志目录 = 字段布局对不上，**不能**当成 0 字节容量上报。
    #[test]
    fn zero_log_dirs_is_an_error_not_a_zero_byte_reading() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&12i32.to_be_bytes());
        buf.extend_from_slice(&0i32.to_be_bytes()); // throttle_time_ms
        buf.extend_from_slice(&0i32.to_be_bytes()); // log_dirs = 0

        let err = parse_describe_log_dirs(&buf, 12, 1).expect_err("必须是错误");
        assert!(err.to_string().contains("0 个日志目录"), "{err}");
    }

    /// `DescribeLogDirs v2+` 是 flexible：请求头 / 数组 / 字符串都换了编码。
    ///
    /// 夹具逐字节拼，确保「请求头 tagged fields + compact nullable topics + 请求体 tagged fields」
    /// 这三步都写对 —— 少一步真 broker 会直接断开连接。
    #[test]
    fn flexible_describe_log_dirs_request_uses_compact_encoding() {
        let bytes = encode_describe_log_dirs_request(12, "wist-agentd", 4);
        let declared = i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]]);
        assert_eq!(declared as usize, bytes.len() - 4);
        assert_eq!(
            i16::from_be_bytes([bytes[4], bytes[5]]),
            API_KEY_DESCRIBE_LOG_DIRS
        );
        assert_eq!(i16::from_be_bytes([bytes[6], bytes[7]]), 4);
        // client_id 在 v2+ 里**不是** compact 字符串，尾已是头 tagged fields(0) + topics=null(0) + body tagged(0)。
        assert_eq!(&bytes[bytes.len() - 3..], &[0, 0, 0]);
        let client_len = i16::from_be_bytes([bytes[12], bytes[13]]) as usize;
        assert_eq!(client_len, "wist-agentd".len());
    }

    /// 拼一个 v4（flexible）响应：一个 log dir、一个 topic、两个分区（其中一个 future）。
    fn describe_log_dirs_v4_body(correlation_id: i32, total: i64, usable: i64) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&correlation_id.to_be_bytes());
        buf.push(0); // 响应头 tagged fields
        buf.extend_from_slice(&0i32.to_be_bytes()); // throttle
        buf.extend_from_slice(&0i16.to_be_bytes()); // 顶层 error_code（v3+）
        buf.push(2); // results: compact array len = 1 + 1
        buf.extend_from_slice(&0i16.to_be_bytes()); // result error_code
        buf.push(6); // log_dir "/data" → len+1
        buf.extend_from_slice(b"/data");
        buf.push(2); // topics: 1
        buf.push(2); // topic "t"
        buf.extend_from_slice(b"t");
        buf.push(3); // partitions: 2
        for (index, size, future) in [(0i32, 1_000i64, 0u8), (1, 7_000, 1)] {
            buf.extend_from_slice(&index.to_be_bytes());
            buf.extend_from_slice(&size.to_be_bytes());
            buf.extend_from_slice(&0i64.to_be_bytes()); // offset_lag
            buf.push(future);
            buf.push(0); // partition tagged fields
        }
        buf.push(0); // topic tagged fields
        buf.extend_from_slice(&total.to_be_bytes());
        buf.extend_from_slice(&usable.to_be_bytes());
        buf.push(0); // result tagged fields
        buf.push(0); // 响应体 tagged fields
        buf
    }

    #[test]
    fn parses_describe_log_dirs_v4_with_usable_bytes() {
        let buf = describe_log_dirs_v4_body(12, 40_960, 61_440);
        let totals = parse_describe_log_dirs(&buf, 12, 4).expect("parse v4");
        assert_eq!(totals.size_bytes, 1_000, "future 副本不算");
        assert_eq!(totals.usable_bytes, Some(61_440));
    }

    #[test]
    fn usable_bytes_is_absent_before_v4() {
        // v2 是 flexible，但没有 total/usable。
        let mut buf = Vec::new();
        buf.extend_from_slice(&12i32.to_be_bytes());
        buf.push(0); // 响应头 tagged fields
        buf.extend_from_slice(&0i32.to_be_bytes()); // throttle
        buf.push(2); // results
        buf.extend_from_slice(&0i16.to_be_bytes());
        buf.push(6);
        buf.extend_from_slice(b"/data");
        buf.push(1); // topics = 0（compact 空集 = uvarint 1）
        buf.push(0); // result tagged fields
        buf.push(0); // 响应体 tagged fields

        let totals = parse_describe_log_dirs(&buf, 12, 2).expect("parse v2");
        assert_eq!(totals.size_bytes, 0);
        assert_eq!(totals.usable_bytes, None);
    }

    /// 顶层 error_code（v3+）不为 0 时不能说「0 字节」：那是权限问题，不是磁盘空。
    #[test]
    fn v3_top_level_error_is_reported() {
        let mut buf = Vec::new();
        buf.extend_from_slice(&12i32.to_be_bytes());
        buf.push(0);
        buf.extend_from_slice(&0i32.to_be_bytes());
        buf.extend_from_slice(&29i16.to_be_bytes()); // TOPIC_AUTHORIZATION_FAILED 类
        buf.push(1); // results = 0
        buf.push(0);

        let err = parse_describe_log_dirs(&buf, 12, 3).expect_err("必须报错");
        assert!(err.to_string().contains("29"), "{err}");
    }

    #[test]
    fn every_emitted_fact_is_registered_in_the_metric_spec() {
        // 与 runtime 的「覆盖完整性」同一条纪律：新增 fact 忘了在 wist-metrics 注册，
        // 上游会静默丢掉整条序列，而现场只表现为「这个指标没数据」。
        let mut totals = BTreeMap::new();
        totals.insert(
            1,
            LogDirTotals {
                size_bytes: 4_096,
                usable_bytes: Some(1_024),
                failed_dirs: 0,
            },
        );
        let result = build_targets(&metadata(), &totals);
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

    /// 消费组事实也必须都已注册（否则 lag / state 会静默丢序列）。
    #[test]
    fn consumer_group_facts_are_registered_in_the_metric_spec() {
        for key in [
            super::super::kafka_groups::FACT_LAG,
            super::super::kafka_groups::FACT_STATE,
        ] {
            let spec = wist_metrics::spec::find_metric_spec(COLLECTION_KIND, key)
                .unwrap_or_else(|| panic!("fact `{key}` 没有指标声明"));
            assert!(
                spec.name.starts_with("kafka_consumergroup_"),
                "{}",
                spec.name
            );
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
        let result = probe_once(&config, &mut GroupCache::default());
        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 1);
        assert!(result.targets.is_empty(), "连不上就不要造样本");
        assert!(result.last_error.is_some());
        assert!(
            result.warnings.is_empty(),
            "整轮失败只算一次，不要和 warnings 重复打：{:?}",
            result.warnings
        );
    }

    /// 探测线程的日志闸门：warnings 没变就不重复打（30s 一轮，否则一天几千行）。
    #[test]
    fn probe_warning_gate_only_fires_on_change() {
        let mut gate = ProbeLogState::default();
        let warning = "broker 7 (127.0.0.1:9092) DescribeLogDirs 失败：refused".to_string();

        let degraded = ProbeResult {
            targets: Vec::new(),
            attempted: 1,
            failed: 0,
            last_error: None,
            warnings: vec![warning.clone()],
        };
        assert!(gate.warnings_changed(&degraded), "第一次就要打");
        assert!(!gate.warnings_changed(&degraded), "同一句话不重复");

        let healthy = ProbeResult {
            warnings: Vec::new(),
            ..degraded.clone()
        };
        assert!(gate.warnings_changed(&healthy), "恢复要清闸门");
        assert!(
            gate.warnings_changed(&degraded),
            "恢复之后再坏，得能再打一次"
        );
    }

    // -----------------------------------------------------------------------
    // reconcile：授权启停 + 多集群合并
    // -----------------------------------------------------------------------

    fn cluster_config(addr: &str) -> KafkaProbeConfig {
        KafkaProbeConfig::new(
            vec![addr.to_string()],
            "wist-agentd-test".to_string(),
            200,
            1_000,
        )
    }

    fn probe_result(attempted: usize, failed: usize, resource: &str) -> ProbeResult {
        let mut result = ProbeResult {
            targets: Vec::new(),
            attempted,
            failed,
            last_error: None,
            warnings: Vec::new(),
        };
        if failed == 0 {
            result.targets = vec![target(resource, vec![fact("kafka.broker.up", "1")])];
        } else {
            result.last_error = Some("metadata failed".to_string());
        }
        result
    }

    #[test]
    fn reconcile_is_idempotent_and_revocation_removes_the_domain() {
        let mut runtime = ProbeRuntime::default();
        assert!(
            runtime.collect_outcome().is_none(),
            "没有授权 = 快照里不出现这个域"
        );

        let config = cluster_config("127.0.0.1:9092");
        assert!(runtime.reconcile(vec![config.clone()]), "首次要拉起线程");
        assert!(!runtime.reconcile(vec![config.clone()]), "幂等，不重复起");
        assert_eq!(
            runtime.collect_outcome().expect("授权后域出现").status,
            "pending",
            "首轮还没跑完：如实说 pending"
        );

        // 到期的只会被取一次（下一次要等一个间隔）。
        assert!(runtime.take_due().is_some());
        assert!(runtime.take_due().is_none());

        assert!(!runtime.reconcile(Vec::new()));
        assert!(
            runtime.collect_outcome().is_none(),
            "撤授权后域与序列一起消失"
        );
    }

    #[test]
    fn collect_outcome_merges_clusters() {
        let mut runtime = ProbeRuntime::default();
        runtime.reconcile(vec![cluster_config("a:9092"), cluster_config("b:9092")]);

        // 第一个集群成功，第二个整轮失败。
        let first = runtime.take_due().expect("a 到期");
        runtime.finish(first, probe_result(1, 0, "kafka:cluster-a:0"));
        let second = runtime.take_due().expect("b 到期");
        runtime.finish(second, probe_result(1, 1, "kafka:cluster-b:0"));

        let merged = runtime.collect_outcome().expect("合并结果");
        assert_eq!(merged.status, "partial");
        assert_eq!(merged.attempted_targets, 2);
        assert_eq!(merged.failed_targets, 1);
        assert_eq!(merged.succeeded_targets, 1);
        assert_eq!(merged.sample_targets.len(), 1);
        assert_eq!(merged.sample_targets[0].resource_ref, "kafka:cluster-a:0");
    }

    #[test]
    fn duplicate_targets_across_clusters_are_collapsed() {
        // 同一台机器跑两个 broker 进程 → 两条候选 → 两轮 Metadata 都返回整个集群。
        let mut runtime = ProbeRuntime::default();
        runtime.reconcile(vec![cluster_config("a:9092"), cluster_config("b:9092")]);
        let first = runtime.take_due().expect("a 到期");
        runtime.finish(first, probe_result(1, 0, "kafka:c:0"));
        let second = runtime.take_due().expect("b 到期");
        runtime.finish(second, probe_result(1, 0, "kafka:c:0"));

        let merged = runtime.collect_outcome().expect("merged");
        assert_eq!(
            merged.sample_targets.len(),
            1,
            "同一个 broker 不能出两条序列：{:?}",
            merged
                .sample_targets
                .iter()
                .map(|t| &t.resource_ref)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_finished_probe_for_a_revoked_cluster_is_dropped() {
        let mut runtime = ProbeRuntime::default();
        runtime.reconcile(vec![cluster_config("a:9092")]);
        let job = runtime.take_due().expect("到期");
        // 探测过程中授权被撤销。
        runtime.reconcile(Vec::new());
        runtime.finish(job, probe_result(1, 0, "kafka:x:0"));
        assert!(runtime.collect_outcome().is_none());
    }

    // -----------------------------------------------------------------------
    // 自探扫描：主循环只投递，探测线程执行
    // -----------------------------------------------------------------------

    #[test]
    fn a_scan_is_queued_and_starts_the_worker_even_without_clusters() {
        let mut runtime = ProbeRuntime::default();
        // 首次授权时还没有任何集群：不拉线程就没人执行扫描。
        assert!(
            runtime.request_scan(None, target_settings()),
            "没有集群也要拉探测线程"
        );
        assert!(
            !runtime.request_scan(None, target_settings()),
            "线程不重复起"
        );

        let scan = runtime.take_scan().expect("有待执行的扫描");
        assert!(scan.snapshot.is_none());
        assert!(runtime.take_scan().is_none(), "取走即空");
    }

    /// 授权了、但本机没有可达端点：只打一次；端点回来时闸门复位。
    #[test]
    fn an_empty_scan_reports_no_endpoint_once_and_recovers() {
        let mut runtime = ProbeRuntime::default();
        let epoch = runtime.scan_epoch;

        runtime.finish_scan(epoch, Vec::new());
        assert!(runtime.no_endpoint_logged);
        runtime.finish_scan(epoch, Vec::new());
        assert!(runtime.no_endpoint_logged, "同一状态不重复说");

        runtime.finish_scan(epoch, vec![cluster_config("a:9092")]);
        assert!(!runtime.no_endpoint_logged, "端点回来要复位");
        assert_eq!(runtime.clusters.len(), 1);
    }

    /// 晚到的扫描结果不能把已撤销的授权“复活”。
    #[test]
    fn a_scan_result_that_arrives_after_revocation_is_dropped() {
        let mut runtime = ProbeRuntime::default();
        runtime.request_scan(None, target_settings());
        let scan = runtime.take_scan().expect("scan");

        runtime.revoke();
        runtime.finish_scan(scan.epoch, vec![cluster_config("a:9092")]);

        assert!(
            runtime.clusters.is_empty(),
            "撤授权后晚一步回来的扫描不能把集群加回去"
        );
        assert!(runtime.collect_outcome().is_none());
    }

    /// 新扫描会作废旧扫描（代号 +1）：只有最后一次的结果算数。
    #[test]
    fn only_the_latest_scan_result_is_applied() {
        let mut runtime = ProbeRuntime::default();
        runtime.request_scan(None, target_settings());
        let first = runtime.take_scan().expect("first");
        runtime.request_scan(None, target_settings());
        let second = runtime.take_scan().expect("second");
        assert!(second.epoch > first.epoch);

        runtime.finish_scan(first.epoch, vec![cluster_config("a:9092")]);
        assert!(runtime.clusters.is_empty(), "旧扫描要丢弃");

        runtime.finish_scan(second.epoch, vec![cluster_config("b:9092")]);
        assert_eq!(runtime.clusters.len(), 1, "最新扫描生效");
        assert!(runtime.clusters.contains_key("b:9092"));
    }

    // -----------------------------------------------------------------------
    // 自探 → 采集配置
    // -----------------------------------------------------------------------

    fn target_settings() -> KafkaTargetSettings {
        KafkaTargetSettings {
            client_id: "wist-agentd-test".to_string(),
            timeout: Duration::from_millis(500),
            interval: Duration::from_secs(30),
            group_interval: Duration::from_secs(60),
            groups: GroupPolicy::default(),
        }
    }

    fn discovered(
        endpoints: &[(&str, &str, &str, bool)],
    ) -> crate::discovery::kafka_source::KafkaClusterEntry {
        use crate::discovery::kafka_source::{KafkaClusterEntry, KafkaEndpointEntry};

        KafkaClusterEntry {
            source_ref: "port:9092".to_string(),
            broker_id: Some(0),
            listeners: Vec::new(),
            mechanisms: Vec::new(),
            endpoints: endpoints
                .iter()
                .map(|(addr, source, protocol, reachable)| KafkaEndpointEntry {
                    addr: (*addr).to_string(),
                    source: (*source).to_string(),
                    protocol: (*protocol).to_string(),
                    reachable: *reachable,
                    kafka_api: *reachable && *protocol == "PLAINTEXT",
                })
                .collect(),
            evidence: "server_properties".to_string(),
            detail: String::new(),
            confidence: 90,
        }
    }

    #[test]
    fn targets_take_the_first_reachable_endpoint() {
        let configs = targets_from_clusters(
            vec![discovered(&[
                ("10.9.9.9:9092", "advertised", "PLAINTEXT", false),
                ("127.0.0.1:9092", "loopback", "PLAINTEXT", true),
            ])],
            &target_settings(),
        );
        assert_eq!(configs.len(), 1);
        assert_eq!(configs[0].bootstrap_servers, vec!["127.0.0.1:9092"]);
        assert_eq!(configs[0].security.protocol, "PLAINTEXT");
        assert_eq!(configs[0].security.username, None);
        assert_eq!(configs[0].security.password_file, None);
        assert_eq!(configs[0].interval, Duration::from_secs(30));
        assert_eq!(configs[0].timeout, Duration::from_millis(500));
        assert_eq!(configs[0].group_interval, Duration::from_secs(60));
    }

    #[test]
    fn sasl_endpoints_get_the_conventional_credentials() {
        let configs = targets_from_clusters(
            vec![discovered(&[(
                "10.0.0.1:9094",
                "advertised",
                "SASL_SSL",
                true,
            )])],
            &target_settings(),
        );
        let security = &configs[0].security;
        assert_eq!(security.protocol, "SASL_SSL");
        assert_eq!(security.mechanism, "auto");
        assert_eq!(security.username.as_deref(), Some(KAFKA_PROBE_USERNAME));
        assert_eq!(
            security.password_file.as_deref(),
            Some("/etc/wist-agentd/secrets/kafka/probe")
        );
    }

    #[test]
    fn unknown_protocol_falls_back_to_plaintext() {
        let configs = targets_from_clusters(
            vec![discovered(&[(
                "127.0.0.1:9092",
                "loopback",
                "unknown",
                true,
            )])],
            &target_settings(),
        );
        assert_eq!(configs[0].security.protocol, "PLAINTEXT");
        assert_eq!(configs[0].security.username, None);
    }

    #[test]
    fn unreachable_and_duplicate_endpoints_are_skipped() {
        let configs = targets_from_clusters(
            vec![
                discovered(&[("10.0.0.1:9092", "advertised", "PLAINTEXT", false)]),
                discovered(&[("10.0.0.2:9092", "advertised", "PLAINTEXT", true)]),
                discovered(&[("10.0.0.2:9092", "loopback", "PLAINTEXT", true)]),
            ],
            &target_settings(),
        );
        assert_eq!(configs.len(), 1, "不可达的集群不出配置，重复端点只留一条");
        assert_eq!(configs[0].bootstrap_servers, vec!["10.0.0.2:9092"]);
    }
}
