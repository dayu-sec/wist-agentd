//! 采集调度器：一条专属线程管所有采集目标。
//!
//! 为什么单独一条线程：采集里有网络（Kafka，将来还有数据库），而主循环是 3s 节奏的
//! 控制面 —— 采集的等待不能算到它头上。主循环只做两件事：投递目标集合、读最近快照。
//!
//! 线程自带一个 `current_thread` tokio runtime：现在两个采集器都是同步实现（直接跑在
//! 这条线程上，不占主循环）；P1 起 async 采集器（MySQL / Doris）会在这个 runtime 上
//! 并发跑，届时同步采集器改走 `spawn_blocking`（见设计文档 §6.4）。
//!
//! 设计见 `docs/design/metrics-collection-runtime.md`。

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use super::collection::{self, Collector, CollectorOutput, ProbeResult, WarningGate};
use super::kafka::{self, GroupCache, KafkaProbeConfig, KafkaTargetSettings};
use super::runtime::MetricsCollectionOutcome;
use super::target_view::{MetricsTargetView, MetricsTargetViewEntry};

/// 主机三域一轮的周期。它们原来跟 3s tick 跑，这里保持同一量级。
const HOST_ROUND_INTERVAL: Duration = Duration::from_secs(3);

/// 没有到期工作时的空转间隔（拿一次锁 + 扫几个目标，成本可忽略）。
const IDLE_POLL: Duration = Duration::from_millis(100);

/// 线程 panic 后的重启退避（避免坏状态下的忙循环）。
const RESTART_BACKOFF: Duration = Duration::from_secs(1);

#[derive(Default)]
struct HostState {
    /// 最近一次投递的目标视图（来自发现策略）。
    view: Option<MetricsTargetView>,
    /// 产出当前 `outcomes` 的那批目标。**不含 `generated_at`**：它每 tick 都变，
    /// 拿整体比较会让「目标集合变没变」永远为真。
    used: Option<Vec<MetricsTargetViewEntry>>,
    outcomes: Vec<MetricsCollectionOutcome>,
    next_at: Option<Instant>,
}

struct KafkaState {
    config: KafkaProbeConfig,
    next_at: Instant,
    /// 消费组面自己的缓存（周期比拓扑面慢）。
    groups: GroupCache,
    /// warnings 的日志闸门（内容变了才打）。
    gate: WarningGate,
    latest: Option<ProbeResult>,
}

/// 一次待执行的自探扫描。
///
/// 自探要读 `/proc` 并做有界 TCP 探测（每端点 ≤300ms），不能在 3s 主循环里跑：
/// 主循环只把请求丢进来，真正的解析 + 探测在这条线程上做。
struct PendingScan {
    /// 投递时的代号；期间撤过授权 / 又投递了新扫描就对不上，结果直接丢弃。
    epoch: u64,
    snapshot: Option<wist_contracts::discovery::DiscoverySnapshot>,
    settings: KafkaTargetSettings,
}

/// 调度器状态。一个进程一份（见 [`scheduler`]）；测试可以自己造一份。
#[derive(Default)]
struct Scheduler {
    host: HostState,
    /// key = bootstrap 列表的稳定串（目前就是自探出来的那一个端点地址）。
    kafka: BTreeMap<String, KafkaState>,
    pending_scan: Option<PendingScan>,
    /// 自探代次：每次投递 / 撤授权 +1，用来丢弃晚到的扫描结果。
    scan_epoch: u64,
    /// 已授权但本机没有可达端点：只打一条，端点回来时复位。
    no_endpoint_logged: bool,
    /// 上一次对账后生效的集群集合（变化才打日志）。
    log_signature: String,
    /// 采集线程是否已经拉起（由**调用方**维护，线程自己不碰）。
    worker_started: bool,
}

impl Scheduler {
    // -----------------------------------------------------------------------
    // 投递入口
    // -----------------------------------------------------------------------

    /// 投递最新目标视图；返回 `true` 表示调用方该把线程拉起来。
    fn apply_host_view(&mut self, view: &MetricsTargetView) -> bool {
        self.host.view = Some(view.clone());
        // 目标集合变了就立刻排一轮（`generated_at` 变化不算）。
        if self.host.used.as_deref() != Some(view.targets.as_slice()) {
            self.host.next_at = Some(Instant::now());
        }
        self.start_worker()
    }

    /// 投递一次自探扫描（不在这里做探测）。
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
        self.start_worker()
    }

    /// 撤授权：停采、作废待执行 / 在途的扫描。
    fn revoke(&mut self) {
        self.scan_epoch = self.scan_epoch.wrapping_add(1);
        self.pending_scan = None;
        self.no_endpoint_logged = false;
        self.reconcile(Vec::new());
    }

    fn start_worker(&mut self) -> bool {
        !std::mem::replace(&mut self.worker_started, true)
    }

    // -----------------------------------------------------------------------
    // 主机三域
    // -----------------------------------------------------------------------

    fn host_due(&self) -> bool {
        match (&self.host.view, self.host.next_at) {
            (Some(_), Some(at)) => at <= Instant::now(),
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// 取一轮主机采集（排好下一轮时间；返回用于回填校验的目标集合）。
    fn take_host_round(&mut self) -> Option<(MetricsTargetView, Vec<MetricsTargetViewEntry>)> {
        let view = self.host.view.clone()?;
        let used = view.targets.clone();
        self.host.next_at = Some(Instant::now() + HOST_ROUND_INTERVAL);
        Some((view, used))
    }

    /// 回填一轮主机结果。
    ///
    /// 采集期间目标集合被换掉就丢弃本轮（并立刻重排）：否则会把旧目标的数据
    /// 挂到新目标上，那是比晚一拍更糟的错误。
    fn finish_host_round(
        &mut self,
        used: Vec<MetricsTargetViewEntry>,
        outcomes: Vec<MetricsCollectionOutcome>,
    ) {
        let unchanged = self
            .host
            .view
            .as_ref()
            .map(|view| view.targets == used)
            .unwrap_or(false);
        if unchanged {
            self.host.used = Some(used);
            self.host.outcomes = outcomes;
        } else {
            self.host.next_at = Some(Instant::now());
        }
    }

    /// 保证读到的 outcomes 与**传入的**目标集合对得上。
    ///
    /// 为什么带参数而不是只看自己存的 view：主循环每个 tick 投递一份新视图，
    /// 两份视图之间可能夹着采集线程的一轮（甚至测试里的并发调用）。用**调用方**这份
    /// 目标做比较，才能保证「这次返回的结果一定对应这份目标」。
    ///
    /// `target_view` 里 `generated_at` 每 tick 都变、目标集合平时不变，所以这里通常
    /// 什么都不做。目标集合真的变了时先同步补一轮（主机侧读 `/proc`，毫秒级）。
    fn ensure_host_for(&mut self, view: &MetricsTargetView) {
        if self.host.used.as_deref() == Some(view.targets.as_slice()) {
            return;
        }
        let outcomes = Collector::Host { view }.collect().into_domains();
        self.host.outcomes = outcomes;
        self.host.used = Some(view.targets.clone());
        self.host.next_at = Some(Instant::now() + HOST_ROUND_INTERVAL);
    }

    // -----------------------------------------------------------------------
    // Kafka
    // -----------------------------------------------------------------------

    /// 把采集面授权 + 自探结果**对账**成当前要采的集群集合。
    ///
    /// - 新出现的集群：立即采第一轮；
    /// - 已有的集群：换配置（协议/周期变了），保留调度与上一轮结果；
    /// - 不在列表里的：停止采集（撤授权就是传空列表），结果从快照里消失。
    fn reconcile(&mut self, configs: Vec<KafkaProbeConfig>) {
        let desired: BTreeMap<String, KafkaProbeConfig> = configs
            .into_iter()
            .map(|config| (probe_key(&config), config))
            .collect();

        let removed: Vec<String> = self
            .kafka
            .keys()
            .filter(|key| !desired.contains_key(*key))
            .cloned()
            .collect();
        for key in removed {
            self.kafka.remove(&key);
        }
        for (key, config) in desired {
            match self.kafka.get_mut(&key) {
                Some(state) => state.config = config,
                None => {
                    self.kafka.insert(
                        key,
                        KafkaState {
                            config,
                            next_at: Instant::now(),
                            groups: GroupCache::default(),
                            gate: WarningGate::default(),
                            latest: None,
                        },
                    );
                }
            }
        }

        let signature = self.kafka.keys().cloned().collect::<Vec<_>>().join(",");
        if signature != self.log_signature {
            if signature.is_empty() {
                log::info!("event=KafkaProbeRevoked detail=\"no kafka collection grant\"");
            } else {
                log::info!("event=KafkaProbeEnabled endpoints=\"{signature}\"");
            }
            self.log_signature = signature;
        }
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

    fn take_scan(&mut self) -> Option<PendingScan> {
        self.pending_scan.take()
    }

    /// 取一个到期的集群（已排好下一轮时间）。
    fn take_due(&mut self) -> Option<DueJob> {
        let now = Instant::now();
        let key = self
            .kafka
            .iter()
            .find(|(_, state)| state.next_at <= now)
            .map(|(key, _)| key.clone())?;
        let state = self.kafka.get_mut(&key)?;
        state.next_at = now + state.config.interval;
        Some(DueJob {
            key,
            config: state.config.clone(),
            groups: std::mem::take(&mut state.groups),
            gate: std::mem::take(&mut state.gate),
        })
    }

    /// 把一轮结果放回去；集群在探测期间被撤销就丢掉（不写回）。
    fn finish(&mut self, mut job: DueJob, result: ProbeResult) {
        if job.gate.changed(&result.warnings) {
            for warning in &result.warnings {
                log::warn!(
                    "event=KafkaProbeWarning endpoint=\"{}\" detail=\"{warning}\"",
                    job.key
                );
            }
        }
        let Some(state) = self.kafka.get_mut(&job.key) else {
            return;
        };
        state.groups = job.groups;
        state.gate = job.gate;
        state.latest = Some(result);
    }

    fn kafka_outcome(&self) -> Option<MetricsCollectionOutcome> {
        collection::kafka_outcome(
            !self.kafka.is_empty(),
            self.kafka
                .values()
                .filter_map(|state| state.latest.as_ref()),
        )
    }

    /// 快照读取：主机三域 + Kafka。没有授权时 Kafka 不出现。
    fn collect_all_for(&mut self, view: &MetricsTargetView) -> Vec<MetricsCollectionOutcome> {
        self.ensure_host_for(view);
        let mut outcomes = self.host.outcomes.clone();
        if let Some(kafka) = self.kafka_outcome() {
            outcomes.push(kafka);
        }
        outcomes
    }
}

struct DueJob {
    key: String,
    config: KafkaProbeConfig,
    groups: GroupCache,
    gate: WarningGate,
}

/// 集群的稳定键：bootstrap 列表拼起来。
fn probe_key(config: &KafkaProbeConfig) -> String {
    config.bootstrap_servers.join(",")
}

// ---------------------------------------------------------------------------
// 进程级入口
// ---------------------------------------------------------------------------

static SCHEDULER: OnceLock<Mutex<Scheduler>> = OnceLock::new();

/// 拿锁；线程 panic 导致中毒时继续用（采集状态坏一格可以，主循环不能因此停摆）。
fn scheduler() -> MutexGuard<'static, Scheduler> {
    SCHEDULER
        .get_or_init(|| Mutex::new(Scheduler::default()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// 投递最新目标视图（发现策略每次刷新后调）。幂等、非阻塞。
pub fn apply_host_view(view: &MetricsTargetView) {
    let start = scheduler().apply_host_view(view);
    if start {
        spawn_worker();
    }
}

/// 投递一次自探扫描（**不等结果**）：主循环只决定何时探。
pub fn request_scan(
    snapshot: Option<wist_contracts::discovery::DiscoverySnapshot>,
    settings: KafkaTargetSettings,
) {
    let start = scheduler().request_scan(snapshot, settings);
    if start {
        spawn_worker();
    }
}

/// 撤授权：停采（下个 tick 内序列消失），并作废待执行 / 在途的自探扫描。
pub fn revoke() {
    scheduler().revoke();
}

/// 最近一次完成的采集结果：主机三域 + Kafka（没有授权就没有 Kafka）。
///
/// 主机部分会对照**传入的**目标视图：目标集合变了就先同步补一轮（毫秒级）。
pub fn collect_all(view: &MetricsTargetView) -> Vec<MetricsCollectionOutcome> {
    scheduler().collect_all_for(view)
}

// ---------------------------------------------------------------------------
// 线程与调度循环
// ---------------------------------------------------------------------------

/// 拉起采集线程（只在第一次投递时调；线程 panic 会在内部自愈）。
fn spawn_worker() {
    let spawned = std::thread::Builder::new()
        .name("collector".to_string())
        .spawn(|| {
            loop {
                let outcome = std::panic::catch_unwind(AssertUnwindSafe(run_forever));
                match outcome {
                    // `run_forever` 是死循环，正常不会返回；返回即视为「该收工了」。
                    Ok(()) => return,
                    Err(_) => {
                        log::error!(
                            "event=CollectorThreadRestarted detail=\"采集线程 panic，已重新拉起\""
                        );
                        std::thread::sleep(RESTART_BACKOFF);
                    }
                }
            }
        });
    if let Err(err) = spawned {
        log::warn!("event=CollectorThreadFailed detail=\"{err}\"");
    }
}

fn run_forever() {
    loop {
        let runtime = match tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
        {
            Ok(runtime) => runtime,
            Err(err) => {
                log::warn!("event=CollectorRuntimeFailed detail=\"{err}\"");
                std::thread::sleep(RESTART_BACKOFF);
                continue;
            }
        };
        // `block_on` 里的调度循环不会返回；真要返回了，重新建一个继续跑。
        runtime.block_on(async {
            loop {
                if !step() {
                    tokio::time::sleep(IDLE_POLL).await;
                }
            }
        });
    }
}

/// 做一件到期的工作；没有就返回 `false`（调用方睡一会）。
///
/// 优先级：自探（新目标要尽快可用）→ 主机三域（每 3s）→ Kafka（按各自周期）。
/// 一次只做一件：同一域的采集天然串行，不会出现两轮同时打同一个 broker / 同一份 `/proc`。
fn step() -> bool {
    let scan = scheduler().take_scan();
    if let Some(scan) = scan {
        let targets = kafka::targets_from_discovery(scan.snapshot.as_ref(), &scan.settings);
        scheduler().finish_scan(scan.epoch, targets);
        return true;
    }

    let host_round = {
        let mut guard = scheduler();
        if guard.host_due() {
            guard.take_host_round()
        } else {
            None
        }
    };
    if let Some((view, used)) = host_round {
        let outcomes = Collector::Host { view: &view }.collect().into_domains();
        scheduler().finish_host_round(used, outcomes);
        return true;
    }

    let job = scheduler().take_due();
    if let Some(mut job) = job {
        let result = match (Collector::Kafka {
            config: &job.config,
            groups: &mut job.groups,
        })
        .collect()
        {
            CollectorOutput::Targets(result) => result,
            // 分派写错时只丢这一轮（采集线程不能因此死掉）。
            CollectorOutput::Domains(_) => {
                log::error!(
                    "event=CollectorOutputMismatch domain={}",
                    kafka::COLLECTION_KIND
                );
                return true;
            }
        };
        scheduler().finish(job, result);
        return true;
    }

    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::metrics::runtime::MetricsCollectionTargetSample;
    use wist_contracts::discovery::StringKeyValue;

    fn cluster_config(addr: &str) -> KafkaProbeConfig {
        KafkaProbeConfig::new(
            vec![addr.to_string()],
            "wist-agentd-test".to_string(),
            200,
            1_000,
        )
    }

    fn target_settings() -> KafkaTargetSettings {
        KafkaTargetSettings {
            client_id: "wist-agentd-test".to_string(),
            timeout: Duration::from_millis(500),
            interval: Duration::from_secs(30),
            group_interval: Duration::from_secs(60),
            groups: super::super::kafka_groups::GroupPolicy::default(),
        }
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
            result.targets = vec![MetricsCollectionTargetSample {
                candidate_id: resource.to_string(),
                target_ref: resource.to_string(),
                status: "succeeded".to_string(),
                last_error: None,
                resource_ref: resource.to_string(),
                execution_hints: Vec::new(),
                runtime_facts: vec![StringKeyValue::new("kafka.broker.up", "1")],
                labeled_facts: Vec::new(),
            }];
        } else {
            result.last_error = Some("metadata failed".to_string());
        }
        result
    }

    #[test]
    fn reconcile_is_idempotent_and_revocation_removes_the_domain() {
        let mut runtime = Scheduler::default();
        let config = cluster_config("a:9092");

        runtime.reconcile(vec![config.clone()]);
        runtime.reconcile(vec![config.clone()]);
        assert_eq!(runtime.kafka.len(), 1, "幂等，不会多出集群");

        runtime.revoke();
        assert!(runtime.kafka.is_empty(), "撤授权要停采");
        assert!(runtime.kafka_outcome().is_none(), "域从快照里消失");
    }

    #[test]
    fn collect_all_merges_host_and_kafka_domains() {
        let mut runtime = Scheduler::default();
        runtime.reconcile(vec![cluster_config("a:9092")]);

        let first = runtime.take_due().expect("a 到期");
        runtime.finish(first, probe_result(1, 0, "kafka:cluster-a:0"));

        let outcomes = runtime.collect_all_for(&empty_view());
        let kafka = outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == kafka::COLLECTION_KIND)
            .expect("Kafka 域");
        assert_eq!(kafka.status, "succeeded");
        assert_eq!(kafka.attempted_targets, 1);
        assert_eq!(kafka.succeeded_targets, 1);
    }

    #[test]
    fn duplicate_targets_across_clusters_are_collapsed() {
        let mut runtime = Scheduler::default();
        runtime.reconcile(vec![cluster_config("a:9092"), cluster_config("b:9092")]);

        // 两个集群的 Metadata 都会给出同一台 broker（同一 resource_ref）。
        for _ in 0..2 {
            let job = runtime.take_due().expect("到期");
            runtime.finish(job, probe_result(1, 0, "kafka:same:0"));
        }

        let outcome = runtime.kafka_outcome().expect("域存在");
        assert_eq!(
            outcome.sample_targets.len(),
            1,
            "同一个 broker 不能出两条序列：{:?}",
            outcome
                .sample_targets
                .iter()
                .map(|target| &target.resource_ref)
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn a_finished_probe_for_a_revoked_cluster_is_dropped() {
        let mut runtime = Scheduler::default();
        runtime.reconcile(vec![cluster_config("a:9092")]);
        let job = runtime.take_due().expect("到期");
        // 探测过程中授权被撤销。
        runtime.revoke();
        runtime.finish(job, probe_result(1, 0, "kafka:x:0"));
        assert!(runtime.kafka_outcome().is_none());
    }

    #[test]
    fn a_scan_is_queued_and_starts_the_worker_even_without_clusters() {
        let mut runtime = Scheduler::default();
        assert!(
            runtime.request_scan(None, target_settings()),
            "没有集群也要拉采集线程"
        );
        assert!(
            !runtime.request_scan(None, target_settings()),
            "线程不重复起"
        );

        let scan = runtime.take_scan().expect("有待执行的扫描");
        assert!(scan.snapshot.is_none());
        assert!(runtime.take_scan().is_none(), "取走即空");
    }

    #[test]
    fn an_empty_scan_reports_no_endpoint_once_and_recovers() {
        let mut runtime = Scheduler::default();
        let epoch = runtime.scan_epoch;

        runtime.finish_scan(epoch, Vec::new());
        assert!(runtime.no_endpoint_logged);
        runtime.finish_scan(epoch, Vec::new());
        assert!(runtime.no_endpoint_logged, "同一状态不重复说");

        runtime.finish_scan(epoch, vec![cluster_config("a:9092")]);
        assert!(!runtime.no_endpoint_logged, "端点回来要复位");
        assert_eq!(runtime.kafka.len(), 1);
    }

    #[test]
    fn a_scan_result_that_arrives_after_revocation_is_dropped() {
        let mut runtime = Scheduler::default();
        runtime.request_scan(None, target_settings());
        let scan = runtime.take_scan().expect("scan");

        runtime.revoke();
        runtime.finish_scan(scan.epoch, vec![cluster_config("a:9092")]);

        assert!(
            runtime.kafka.is_empty(),
            "撤授权后晚一步回来的扫描不能把集群加回去"
        );
        assert!(runtime.kafka_outcome().is_none());
    }

    #[test]
    fn only_the_latest_scan_result_is_applied() {
        let mut runtime = Scheduler::default();
        runtime.request_scan(None, target_settings());
        let first = runtime.take_scan().expect("first");
        runtime.request_scan(None, target_settings());
        let second = runtime.take_scan().expect("second");
        assert!(second.epoch > first.epoch);

        runtime.finish_scan(first.epoch, vec![cluster_config("a:9092")]);
        assert!(runtime.kafka.is_empty(), "旧扫描要丢弃");

        runtime.finish_scan(second.epoch, vec![cluster_config("b:9092")]);
        assert_eq!(runtime.kafka.len(), 1, "最新扫描生效");
        assert!(runtime.kafka.contains_key("b:9092"));
    }

    fn empty_view() -> MetricsTargetView {
        MetricsTargetView {
            generated_at: "2026-11-05T00:00:00Z".to_string(),
            targets: Vec::new(),
        }
    }
}
