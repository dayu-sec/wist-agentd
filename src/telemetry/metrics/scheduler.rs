//! 采集调度器：一条专属线程管所有采集目标。
//!
//! 为什么单独一条线程：采集里有网络（Kafka，将来还有数据库），而主循环是 3s 节奏的
//! 控制面 —— 采集的等待不能算到它头上。主循环只做两件事：投递目标集合、读最近快照。
//!
//! ## 执行模型
//!
//! 线程自带一个 `current_thread` tokio runtime，调度循环用 `JoinSet` 并发跑采集作业，
//! 全局并发上限由 `Semaphore` 控制。每个作业都是 `async`（`collection::Collector`）：
//!
//! - 同步实现（主机三域、Kafka）在作业里走 `spawn_blocking`，不霸住执行器；
//! - P1 的 async 采集器（MySQL / Doris）直接在 future 里跑。
//!
//! 阻塞作业**不可取消**：预算到了只是看门狗（`CollectorTargetStalled`）报出来，
//! 在飞标记一直保留到作业真正返回，不会给一个还卡着的目标重复排轮次。
//!
//! 设计见 `docs/design/metrics-collection-runtime.md`。

use std::collections::BTreeMap;
use std::panic::AssertUnwindSafe;
use std::sync::{Arc, Mutex, MutexGuard, OnceLock};
use std::time::{Duration, Instant};

use tokio::sync::Semaphore;
use tokio::task::JoinSet;

use super::collection::{Collector, CollectorOutput, ProbeResult, WarningGate};
use super::kafka::{self, GroupCache, KafkaProbeConfig, KafkaTargetSettings};
use super::runtime::MetricsCollectionOutcome;
use super::target_view::{MetricsTargetView, MetricsTargetViewEntry};

/// 主机三域一轮的周期。它们原来跟 3s tick 跑，这里保持同一量级。
const HOST_ROUND_INTERVAL: Duration = Duration::from_secs(3);

/// 主机一轮的看门狗阈值（读 `/proc`，正常是毫秒级）。
const HOST_ROUND_BUDGET: Duration = Duration::from_secs(30);

/// Kafka 一轮的看门狗阈值：比内部预算（容量 10s + 消费组 20s）宽裕一档。
const KAFKA_ROUND_BUDGET: Duration = Duration::from_secs(60);

/// 同时在跑的采集作业上限（一个目标一轮算一个）。
///
/// 现在只有「主机三域 + 每个集群」这么几个目标，上限只是防将来域变多时把
/// blocking 池打满；异步采集器接进来后它同时是它们的并发闸门。
const MAX_CONCURRENT_ROUNDS: usize = 8;

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
    inflight: bool,
    started_at: Option<Instant>,
    stalled_logged: bool,
}

struct KafkaState {
    config: KafkaProbeConfig,
    next_at: Instant,
    /// 消费组面自己的缓存（周期比拓扑面慢）。采集时跟着作业走，回来交还。
    groups: GroupCache,
    /// warnings 的日志闸门（内容变了才打）。
    gate: WarningGate,
    latest: Option<ProbeResult>,
    inflight: bool,
    started_at: Option<Instant>,
    stalled_logged: bool,
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
    scan_inflight: bool,
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
    // 作业起停（调度循环调用）
    // -----------------------------------------------------------------------

    fn host_can_start(&self) -> bool {
        !self.host.inflight && self.host.view.is_some() && self.host_due()
    }

    fn host_due(&self) -> bool {
        match (&self.host.view, self.host.next_at) {
            (Some(_), Some(at)) => at <= Instant::now(),
            (Some(_), None) => true,
            (None, _) => false,
        }
    }

    /// 取一轮主机采集作业（排好下一轮时间、置在飞标记）。
    fn begin_host_round(&mut self) -> Option<Collector> {
        let view = self.host.view.clone()?;
        self.host.next_at = Some(Instant::now() + HOST_ROUND_INTERVAL);
        self.host.inflight = true;
        self.host.started_at = Some(Instant::now());
        self.host.stalled_logged = false;
        Some(Collector::Host(view))
    }

    fn scan_can_start(&self) -> bool {
        !self.scan_inflight && self.pending_scan.is_some()
    }

    fn begin_scan(&mut self) -> Option<PendingScan> {
        let scan = self.pending_scan.take()?;
        self.scan_inflight = true;
        Some(scan)
    }

    /// 取一个到期的 Kafka 集群（排好下一轮时间、置在飞标记、把组缓存交给作业）。
    fn begin_next_due_kafka(&mut self) -> Option<(String, Collector)> {
        let now = Instant::now();
        let key = self
            .kafka
            .iter()
            .find(|(_, state)| !state.inflight && state.next_at <= now)
            .map(|(key, _)| key.clone())?;
        let state = self.kafka.get_mut(&key)?;
        state.next_at = now + state.config.interval;
        state.inflight = true;
        state.started_at = Some(now);
        state.stalled_logged = false;
        let groups = std::mem::take(&mut state.groups);
        let config = state.config.clone();
        Some((
            key,
            Collector::Kafka {
                config: Box::new(config),
                groups,
            },
        ))
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
        self.host.inflight = false;
        self.host.started_at = None;
        self.host.stalled_logged = false;
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
            // 目标已经换了：让下一轮马上跑（不要在旧结果上多等一个周期）。
            self.host.next_at = Some(Instant::now());
        }
    }

    fn finish_kafka(&mut self, key: &str, result: ProbeResult, groups: GroupCache) {
        let Some(state) = self.kafka.get_mut(key) else {
            // 集群在采集期间被撤销：结果直接丢弃。
            return;
        };
        state.inflight = false;
        state.started_at = None;
        state.stalled_logged = false;
        state.groups = groups;
        if state.gate.changed(&result.warnings) {
            for warning in &result.warnings {
                log::warn!("event=KafkaProbeWarning endpoint=\"{key}\" detail=\"{warning}\"");
            }
        }
        state.latest = Some(result);
    }

    /// 作业异常（JoinError）：清掉所有在飞标记，下一轮重新排。
    ///
    /// 宁可多采一轮，也不要让一个目标因为一次意外永远不再被调度。
    fn clear_inflight(&mut self) {
        self.host.inflight = false;
        self.host.started_at = None;
        self.scan_inflight = false;
        for state in self.kafka.values_mut() {
            state.inflight = false;
            state.started_at = None;
        }
    }

    /// 看门狗：作业超过预算只报一次，不终止它（阻塞调用本来也停不下来）。
    fn log_stalled(&mut self) {
        let now = Instant::now();
        if self.host.inflight
            && !self.host.stalled_logged
            && self
                .host
                .started_at
                .is_some_and(|at| now.duration_since(at) > HOST_ROUND_BUDGET)
        {
            self.host.stalled_logged = true;
            log::warn!(
                "event=CollectorTargetStalled domain=host_metrics budget_ms={}",
                HOST_ROUND_BUDGET.as_millis()
            );
        }
        for (key, state) in self.kafka.iter_mut() {
            if state.inflight
                && !state.stalled_logged
                && state
                    .started_at
                    .is_some_and(|at| now.duration_since(at) > KAFKA_ROUND_BUDGET)
            {
                state.stalled_logged = true;
                log::warn!(
                    "event=CollectorTargetStalled domain={} target=\"{key}\" budget_ms={}",
                    kafka::COLLECTION_KIND,
                    KAFKA_ROUND_BUDGET.as_millis()
                );
            }
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
        let outcomes = super::collection::host_outcomes(view);
        self.host.outcomes = outcomes;
        self.host.used = Some(view.targets.clone());
        self.host.next_at = Some(Instant::now() + HOST_ROUND_INTERVAL);
    }

    // -----------------------------------------------------------------------
    // Kafka 对账
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
                            inflight: false,
                            started_at: None,
                            stalled_logged: false,
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
    fn finish_scan(&mut self, epoch: u64, targets: Option<Vec<KafkaProbeConfig>>) {
        self.scan_inflight = false;
        let Some(targets) = targets else {
            // 扫描作业异常（panic / JoinError）：留一行，别把「没扫到」当成「没有端点」。
            log::warn!("event=KafkaDiscoveryScanFailed detail=\"扫描作业异常，本轮不更新端点\"");
            return;
        };
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

    fn kafka_outcome(&self) -> Option<MetricsCollectionOutcome> {
        super::collection::kafka_outcome(
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

/// 集群的稳定键：bootstrap 列表拼起来。
fn probe_key(config: &KafkaProbeConfig) -> String {
    config.bootstrap_servers.join(",")
}

/// 采集作业的产物（由 `JoinSet` 送回调度循环）。
enum JobOutcome {
    Scan {
        epoch: u64,
        targets: Option<Vec<KafkaProbeConfig>>,
    },
    /// `key` 为 `None` 表示主机轮次。
    Collected {
        key: Option<String>,
        output: CollectorOutput,
    },
}

impl Scheduler {
    /// 把一个完成的作业落到状态里。
    fn apply(&mut self, outcome: JobOutcome) {
        match outcome {
            JobOutcome::Scan { epoch, targets } => self.finish_scan(epoch, targets),
            JobOutcome::Collected { key: None, output } => match output {
                CollectorOutput::Host { used, outcomes } => self.finish_host_round(used, outcomes),
                CollectorOutput::Kafka { .. } => {
                    log::error!("event=CollectorOutputMismatch domain=host_metrics");
                    self.clear_inflight();
                }
            },
            JobOutcome::Collected {
                key: Some(key),
                output,
            } => match output {
                CollectorOutput::Kafka { result, groups } => {
                    self.finish_kafka(&key, result, groups)
                }
                CollectorOutput::Host { .. } => {
                    log::error!(
                        "event=CollectorOutputMismatch domain={}",
                        kafka::COLLECTION_KIND
                    );
                    self.clear_inflight();
                }
            },
        }
    }
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
        runtime.block_on(supervise());
    }
}

/// 调度循环：收结果 → 起作业 → 等一个完成或超时空转。
async fn supervise() {
    let permits = Arc::new(Semaphore::new(MAX_CONCURRENT_ROUNDS));
    let mut jobs: JoinSet<JobOutcome> = JoinSet::new();

    loop {
        while let Some(joined) = jobs.try_join_next() {
            handle_join(joined);
        }
        scheduler().log_stalled();

        start_due(&mut jobs, &permits);
        if jobs.is_empty() {
            // 没有在飞的：慢轮询，成本可忽略。
            tokio::time::sleep(IDLE_POLL).await;
        } else {
            tokio::select! {
                joined = jobs.join_next() => {
                    if let Some(joined) = joined {
                        handle_join(joined);
                    }
                }
                _ = tokio::time::sleep(IDLE_POLL) => {}
            }
        }
    }
}

fn handle_join(joined: Result<JobOutcome, tokio::task::JoinError>) {
    match joined {
        Ok(outcome) => scheduler().apply(outcome),
        Err(err) => {
            log::warn!("event=CollectorJobFailed detail=\"{err}\"");
            // 作业在返回结果前就没了（async 代码 panic）：清标记，下一轮重新排。
            scheduler().clear_inflight();
        }
    }
}

/// 起所有能起的作业；返回是否起了至少一个。
fn start_due(jobs: &mut JoinSet<JobOutcome>, permits: &Arc<Semaphore>) -> bool {
    let mut started = false;

    // 自探最优先：新挂上的集群要尽快可用。
    if scheduler().scan_can_start()
        && let Ok(permit) = permits.clone().try_acquire_owned()
        && let Some(scan) = scheduler().begin_scan()
    {
        let epoch = scan.epoch;
        jobs.spawn(async move {
            let _permit = permit;
            let targets = tokio::task::spawn_blocking(move || {
                kafka::targets_from_discovery(scan.snapshot.as_ref(), &scan.settings)
            })
            .await
            .ok();
            JobOutcome::Scan { epoch, targets }
        });
        started = true;
    }

    // 主机三域。
    if scheduler().host_can_start()
        && let Ok(permit) = permits.clone().try_acquire_owned()
        && let Some(collector) = scheduler().begin_host_round()
    {
        jobs.spawn(async move {
            let _permit = permit;
            JobOutcome::Collected {
                key: None,
                output: collector.collect().await,
            }
        });
        started = true;
    }

    // Kafka：按各自周期，能起几个起几个（受总并发闸门约束）。
    loop {
        let Ok(permit) = permits.clone().try_acquire_owned() else {
            break;
        };
        let Some((key, collector)) = scheduler().begin_next_due_kafka() else {
            break;
        };
        jobs.spawn(async move {
            let _permit = permit;
            JobOutcome::Collected {
                key: Some(key),
                output: collector.collect().await,
            }
        });
        started = true;
    }

    started
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
            groups: crate::telemetry::metrics::kafka_groups::GroupPolicy::default(),
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

    fn empty_view() -> MetricsTargetView {
        MetricsTargetView {
            generated_at: "2026-11-05T00:00:00Z".to_string(),
            targets: Vec::new(),
        }
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

        let (key, _collector) = runtime.begin_next_due_kafka().expect("a 到期");
        runtime.finish_kafka(
            &key,
            probe_result(1, 0, "kafka:cluster-a:0"),
            GroupCache::default(),
        );

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
            let (key, _) = runtime.begin_next_due_kafka().expect("到期");
            runtime.finish_kafka(
                &key,
                probe_result(1, 0, "kafka:same:0"),
                GroupCache::default(),
            );
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
        let (key, _) = runtime.begin_next_due_kafka().expect("到期");
        // 探测过程中授权被撤销。
        runtime.revoke();
        runtime.finish_kafka(&key, probe_result(1, 0, "kafka:x:0"), GroupCache::default());
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

        let scan = runtime.begin_scan().expect("有可执行的扫描");
        assert!(scan.snapshot.is_none());
        assert!(runtime.begin_scan().is_none(), "在飞时不能重复起");
    }

    #[test]
    fn an_empty_scan_reports_no_endpoint_once_and_recovers() {
        let mut runtime = Scheduler::default();
        let epoch = runtime.scan_epoch;

        runtime.finish_scan(epoch, Some(Vec::new()));
        assert!(runtime.no_endpoint_logged);
        runtime.finish_scan(epoch, Some(Vec::new()));
        assert!(runtime.no_endpoint_logged, "同一状态不重复说");

        runtime.finish_scan(epoch, Some(vec![cluster_config("a:9092")]));
        assert!(!runtime.no_endpoint_logged, "端点回来要复位");
        assert_eq!(runtime.kafka.len(), 1);
    }

    #[test]
    fn a_scan_result_that_arrives_after_revocation_is_dropped() {
        let mut runtime = Scheduler::default();
        runtime.request_scan(None, target_settings());
        let scan = runtime.begin_scan().expect("scan");

        runtime.revoke();
        runtime.finish_scan(scan.epoch, Some(vec![cluster_config("a:9092")]));

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
        let first = runtime.begin_scan().expect("first");
        runtime.request_scan(None, target_settings());
        let second = runtime.begin_scan().expect("second");
        assert!(second.epoch > first.epoch);

        runtime.finish_scan(first.epoch, Some(vec![cluster_config("a:9092")]));
        assert!(runtime.kafka.is_empty(), "旧扫描要丢弃");

        runtime.finish_scan(second.epoch, Some(vec![cluster_config("b:9092")]));
        assert_eq!(runtime.kafka.len(), 1, "最新扫描生效");
        assert!(runtime.kafka.contains_key("b:9092"));
    }

    #[test]
    fn a_scan_job_failure_does_not_look_like_no_endpoint() {
        let mut runtime = Scheduler::default();
        runtime.finish_scan(runtime.scan_epoch, None);
        assert!(!runtime.no_endpoint_logged, "异常不是「没有端点」");
        assert!(!runtime.scan_inflight);
    }

    #[test]
    fn a_stalled_round_keeps_the_target_in_flight() {
        // 阻塞作业不可取消：超预算只报一次，标记保留到作业真正返回。
        let mut runtime = Scheduler::default();
        runtime.reconcile(vec![cluster_config("a:9092")]);
        let (_key, _) = runtime.begin_next_due_kafka().expect("到期");
        runtime
            .kafka
            .values_mut()
            .for_each(|state| state.started_at = Some(Instant::now() - KAFKA_ROUND_BUDGET * 2));

        runtime.log_stalled();
        assert!(
            runtime.kafka.values().all(|state| state.stalled_logged),
            "超预算要留痕"
        );
        assert!(
            runtime.begin_next_due_kafka().is_none(),
            "在飞时不能给同一个目标再排一轮"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_host_collector_runs_as_a_job() {
        let view = empty_view();
        let output = Collector::Host(view).collect().await;
        let CollectorOutput::Host { used, outcomes } = output else {
            panic!("主机分支必须返回 Host 产物");
        };
        assert!(used.is_empty());
        assert_eq!(outcomes.len(), 3, "host / process / container 各一条");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn the_kafka_collector_hands_the_group_cache_back() {
        let config = KafkaProbeConfig::new(
            vec!["127.0.0.1:1".to_string()],
            "wist-agentd-test".to_string(),
            50,
            1_000,
        );
        let output = Collector::Kafka {
            config: Box::new(config),
            groups: GroupCache::default(),
        }
        .collect()
        .await;
        let CollectorOutput::Kafka { result, .. } = output else {
            panic!("Kafka 分支必须返回 Kafka 产物");
        };
        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 1, "连不上就是整轮失败");
        assert!(result.targets.is_empty(), "连不上不造样本");
    }
}
