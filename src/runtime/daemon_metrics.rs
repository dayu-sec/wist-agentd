use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::path::Path;
use std::sync::{LazyLock, Mutex};

use wist_contracts::telemetry_record::DataFrame;
use wist_shared::fs::read_json;
use wist_shared::time::now_rfc3339;

use crate::self_observability::MetricsHealthSnapshot;
use crate::state_store::log_seq_state;
use crate::telemetry::metrics::{
    runtime::{self, MetricsRuntimeSnapshot},
    samples,
    target_view::{self, MetricsTargetView},
};
use crate::telemetry::warp_parse::TelemetryRecordSink;

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub(super) struct MetricsTick {
    pub(super) snapshot: Option<MetricsRuntimeSnapshot>,
    pub(super) failures: Vec<MetricsFailure>,
    pub(super) target_view_loaded: bool,
    pub(super) used_cached_snapshot: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum MetricsFailureKind {
    TargetViewLoad,
    RuntimeSnapshotLoad,
    RuntimeSnapshotStore,
    /// 采集域 / 目标没采上来（数据面）。
    ///
    /// 不进 `MetricsTick::failures`：它不影响「这一拍走没走通」，也不该把一台空闲机器
    /// 翻成 `Active`（broker 长期不可达是稳态，不是“有活干”）。
    Collection,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub(super) struct MetricsFailure {
    pub(super) kind: MetricsFailureKind,
    /// tick 级：落盘阶段名；采集级：固定 `collect`。
    pub(super) phase: String,
    /// 采集级：采集域（`kafka_broker_metrics` / `host_metrics` …）；tick 级为 `-`。
    pub(super) collection: String,
    /// 采集级：目标标识（`kafka:<cluster>:<broker>` 等）；域级失败为 `-`。
    pub(super) target: String,
    /// 采集级：`failed` / `partial`；tick 级为空。
    pub(super) status: String,
    pub(super) path: String,
    pub(super) detail: String,
}

impl MetricsTick {
    pub(super) fn is_active(&self) -> bool {
        !self.failures.is_empty()
    }

    pub(super) fn health_snapshot(&self) -> MetricsHealthSnapshot {
        let (
            total_targets,
            host_targets,
            process_targets,
            container_targets,
            attempted_targets,
            succeeded_targets,
            failed_targets,
            updated_at,
        ) = match &self.snapshot {
            Some(snapshot) => (
                snapshot.total_targets,
                snapshot.host_targets,
                snapshot.process_targets,
                snapshot.container_targets,
                snapshot
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.attempted_targets)
                    .sum(),
                snapshot
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.succeeded_targets)
                    .sum(),
                snapshot
                    .outcomes
                    .iter()
                    .map(|outcome| outcome.failed_targets)
                    .sum(),
                Some(snapshot.generated_at.clone()),
            ),
            None => (0, 0, 0, 0, 0, 0, 0, None),
        };

        MetricsHealthSnapshot {
            target_view_loaded: self.target_view_loaded,
            used_cached_snapshot: self.used_cached_snapshot,
            total_targets,
            host_targets,
            process_targets,
            container_targets,
            attempted_targets,
            succeeded_targets,
            failed_targets,
            failure_count: self.failures.len(),
            last_error: self
                .failures
                .last()
                .map(|failure| format!("{}: {}", failure.phase, failure.detail)),
            updated_at,
        }
    }
}

/// 把指标运行时快照规范化成样本并拍平成 VM JSON lines 逐帧上送。无样本时跳过（避免空帧占用 uplink）。
///
/// 指标帧与日志帧共用同一个 agent 级全局 `seq`（`next_seq`）：取号递增、先持久化高水位再发送，
/// 保证跨重启不回退、且与日志帧在 `(agent, seq)` 去重键上不撞号。
pub(super) async fn write_metrics_uplink(
    sink: &mut TelemetryRecordSink,
    agent_id: &str,
    snapshot: &MetricsRuntimeSnapshot,
    selection: &std::collections::BTreeMap<String, String>,
    next_seq: &mut u64,
    global_seq_path: &Path,
) -> io::Result<()> {
    let samples = samples::build_samples_snapshot(snapshot);
    let lines = samples::build_vm_metric_lines_with(&samples, agent_id, selection);
    if lines.is_empty() {
        return Ok(());
    }
    let observed_at = now_rfc3339();
    // 先从全局计数器取号（与日志同源），再统一持久化高水位、最后发送。
    let mut frames = Vec::with_capacity(lines.len());
    for line in &lines {
        let seq = *next_seq;
        *next_seq += 1;
        frames.push((DataFrame::new(agent_id, observed_at.clone(), seq), line));
    }
    // 前移一位持久化：崩溃只会浪费号，绝不回退撞号。
    log_seq_state::store_async(global_seq_path, *next_seq).await?;
    for (envelope, line) in frames {
        sink.write_metrics(&envelope, line).await?;
    }
    Ok(())
}

pub(super) fn process_metrics_tick(state_dir: &Path) -> MetricsTick {
    let target_view_path = target_view::path_for(state_dir);
    let runtime_snapshot_path = runtime::path_for(state_dir);

    match read_json::<MetricsTargetView>(&target_view_path) {
        Ok(view) => {
            let snapshot = runtime::build_runtime_snapshot_from_view(&view);
            let mut failures = Vec::new();
            if let Err(err) = runtime::store(&runtime_snapshot_path, &snapshot) {
                failures.push(metrics_failure(
                    MetricsFailureKind::RuntimeSnapshotStore,
                    "runtime_snapshot_store",
                    &runtime_snapshot_path,
                    err,
                ));
            }
            MetricsTick {
                snapshot: Some(snapshot),
                failures,
                target_view_loaded: true,
                used_cached_snapshot: false,
            }
        }
        Err(err) => {
            let mut failures = vec![metrics_failure(
                MetricsFailureKind::TargetViewLoad,
                "target_view_load",
                &target_view_path,
                err,
            )];
            let cached_snapshot =
                load_cached_runtime_snapshot(&runtime_snapshot_path, &mut failures);

            MetricsTick {
                snapshot: cached_snapshot.clone(),
                failures,
                target_view_loaded: false,
                used_cached_snapshot: cached_snapshot.is_some(),
            }
        }
    }
}

pub(super) fn emit_metrics_tick(tick: &MetricsTick) {
    // 采集失败的明细无关稳态收敛：先按「变化才打 / 恢复也打」处理，
    // 不能被下面那句汇总行的闸门吞掉。
    emit_collection_failures(tick.snapshot.as_ref());

    let health = tick.health_snapshot();
    // 指标快照同样逐 tick 产生，走稳态收敛（内容变化立即打印，否则补心跳）。
    if !crate::runtime::steady_log::should_emit_metrics(
        &crate::self_observability::metrics_signature(&health),
    ) {
        return;
    }
    log::info!(
        "event=MetricsRuntimeUpdated target_view_loaded={} used_cached_snapshot={} total_targets={} host_targets={} process_targets={} container_targets={} attempted_targets={} succeeded_targets={} failed_targets={} failures={} updated_at={}",
        health.target_view_loaded,
        health.used_cached_snapshot,
        health.total_targets,
        health.host_targets,
        health.process_targets,
        health.container_targets,
        health.attempted_targets,
        health.succeeded_targets,
        health.failed_targets,
        health.failure_count,
        health.updated_at.as_deref().unwrap_or("-"),
    );
}

pub(super) fn emit_metrics_failures(failures: &[MetricsFailure]) {
    for failure in failures {
        emit_metrics_failure(failure);
    }
}

pub(super) fn emit_metrics_failure(failure: &MetricsFailure) {
    if failure.kind == MetricsFailureKind::Collection {
        // 采集失败：现场要的是「哪个域 / 哪个目标 / 为什么」。整域没上来算 error，
        // 部分目标失败算 warn（其余目标仍在上报）。
        let event = if failure.status == "failed" {
            "MetricsCollectionFailed"
        } else {
            "MetricsCollectionPartial"
        };
        let line = format!(
            "event={event} collection={} target={} status={} error=\"{}\"",
            failure.collection, failure.target, failure.status, failure.detail
        );
        if failure.status == "failed" {
            log::error!("{line}");
        } else {
            log::warn!("{line}");
        }
        return;
    }
    log::error!(
        "event=MetricsRuntimeFailed kind={:?} phase={} path={} error={}",
        failure.kind,
        failure.phase,
        failure.path,
        failure.detail
    );
}

/// 把一次快照里「没采上来的东西」摊平成失败项（纯函数，便于测试）。
///
/// 优先给**目标级**明细（带上 `last_error`）；没目标明细时才退到域级一行，
/// 至少把采集域、状态和计数说清楚，而不是现场只能看到汇总行里的 `failed_targets=2`。
fn collection_failures(snapshot: &MetricsRuntimeSnapshot) -> Vec<MetricsFailure> {
    let mut failures = Vec::new();
    for outcome in &snapshot.outcomes {
        let failing: Vec<&_> = outcome
            .sample_targets
            .iter()
            .filter(|sample| sample.status == "failed")
            .collect();
        if !failing.is_empty() {
            for sample in failing {
                let target = if sample.resource_ref.is_empty() {
                    sample.candidate_id.clone()
                } else {
                    sample.resource_ref.clone()
                };
                failures.push(MetricsFailure {
                    kind: MetricsFailureKind::Collection,
                    phase: "collect".to_string(),
                    collection: outcome.collection_kind.clone(),
                    target,
                    status: sample.status.clone(),
                    path: "-".to_string(),
                    detail: sample
                        .last_error
                        .clone()
                        .unwrap_or_else(|| "目标采集失败，但没有给 last_error".to_string()),
                });
            }
            continue;
        }

        let failed =
            outcome.status == "failed" || outcome.status == "partial" || outcome.failed_targets > 0;
        if !failed {
            continue;
        }
        failures.push(MetricsFailure {
            kind: MetricsFailureKind::Collection,
            phase: "collect".to_string(),
            collection: outcome.collection_kind.clone(),
            target: "-".to_string(),
            status: outcome.status.clone(),
            path: "-".to_string(),
            detail: outcome.last_error.clone().unwrap_or_else(|| {
                format!(
                    "status={} attempted={} failed={}，采集器没有给 last_error",
                    outcome.status, outcome.attempted_targets, outcome.failed_targets
                )
            }),
        });
    }
    failures
}

/// 已经打过的采集失败（签名 → 失败项）。
///
/// 只在主循环里被访问（单线程拍），与 `steady_log` 的全局闸门同一取向。
static EMITTED_COLLECTION_FAILURES: LazyLock<Mutex<BTreeMap<String, MetricsFailure>>> =
    LazyLock::new(|| Mutex::new(BTreeMap::new()));

/// 只打「新出现的」失败；已经好了的补一行“恢复”。
///
/// 持久性故障（broker 挂了一整天）不能每 3s 刷一行：2.88 万行/天会把日志和诊断包
/// 一起没掉，现场反而看不到别的东西。
fn emit_collection_failures(snapshot: Option<&MetricsRuntimeSnapshot>) {
    let current: BTreeMap<String, MetricsFailure> = snapshot
        .map(collection_failures)
        .unwrap_or_default()
        .into_iter()
        .map(|failure| (failure_signature(&failure), failure))
        .collect();

    let mut emitted = EMITTED_COLLECTION_FAILURES
        .lock()
        .unwrap_or_else(|err| err.into_inner());

    for (signature, failure) in &current {
        if !emitted.contains_key(signature) {
            emit_metrics_failure(failure);
        }
    }
    for (signature, failure) in emitted.iter() {
        if !current.contains_key(signature) {
            // 恢复也是状态迁移：不只在汇总行里“少一个数”，要能搜到“什么时候回来的”。
            log::info!(
                "event=MetricsCollectionRecovered collection={} target={}",
                failure.collection,
                failure.target
            );
        }
    }
    *emitted = current;
}

pub(super) fn failure_signatures(failures: &[MetricsFailure]) -> BTreeSet<String> {
    failures.iter().map(failure_signature).collect()
}

pub(super) fn filter_new_failures<'a>(
    failures: &'a [MetricsFailure],
    previous: &BTreeSet<String>,
) -> Vec<&'a MetricsFailure> {
    failures
        .iter()
        .filter(|failure| !previous.contains(&failure_signature(failure)))
        .collect()
}

fn failure_signature(failure: &MetricsFailure) -> String {
    format!(
        "{:?}|{}|{}|{}|{}|{}|{}",
        failure.kind,
        failure.phase,
        failure.collection,
        failure.target,
        failure.status,
        failure.path,
        failure.detail
    )
}

fn load_cached_runtime_snapshot(
    path: &Path,
    failures: &mut Vec<MetricsFailure>,
) -> Option<MetricsRuntimeSnapshot> {
    if !path.exists() {
        return None;
    }

    match read_json(path) {
        Ok(snapshot) => Some(snapshot),
        Err(err) => {
            failures.push(metrics_failure(
                MetricsFailureKind::RuntimeSnapshotLoad,
                "runtime_snapshot_load",
                path,
                err,
            ));
            None
        }
    }
}

fn metrics_failure(
    kind: MetricsFailureKind,
    phase: &str,
    path: &Path,
    err: io::Error,
) -> MetricsFailure {
    MetricsFailure {
        kind,
        phase: phase.to_string(),
        collection: "-".to_string(),
        target: "-".to_string(),
        status: String::new(),
        path: path.display().to_string(),
        detail: err.to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use wist_contracts::discovery::StringKeyValue;
    use wist_shared::fs::read_json;

    use super::{
        MetricsFailure, MetricsFailureKind, collection_failures, failure_signature,
        process_metrics_tick, write_metrics_uplink,
    };
    use crate::telemetry::metrics::runtime::{
        MetricsCollectionOutcome, MetricsCollectionTargetSample, MetricsRuntimeSnapshot,
        path_for as runtime_path_for,
    };
    use crate::telemetry::metrics::target_view::{
        MetricsTargetView, MetricsTargetViewEntry, path_for as target_view_path_for, store,
    };
    use crate::telemetry::warp_parse::{TcpFraming, TcpRecordSink, TelemetryRecordSink};

    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("warp-insight-daemon-metrics-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn sample(
        resource_ref: &str,
        status: &str,
        last_error: Option<&str>,
    ) -> MetricsCollectionTargetSample {
        MetricsCollectionTargetSample {
            candidate_id: resource_ref.to_string(),
            target_ref: resource_ref.to_string(),
            status: status.to_string(),
            last_error: last_error.map(str::to_string),
            resource_ref: resource_ref.to_string(),
            execution_hints: Vec::new(),
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
        }
    }

    fn outcome(
        collection_kind: &str,
        status: &str,
        attempted: usize,
        failed: usize,
        last_error: Option<&str>,
        sample_targets: Vec<MetricsCollectionTargetSample>,
    ) -> MetricsCollectionOutcome {
        MetricsCollectionOutcome {
            collection_kind: collection_kind.to_string(),
            status: status.to_string(),
            attempted_targets: attempted,
            succeeded_targets: attempted.saturating_sub(failed),
            failed_targets: failed,
            dropped_targets: 0,
            last_error: last_error.map(str::to_string),
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets,
        }
    }

    fn snapshot(outcomes: Vec<MetricsCollectionOutcome>) -> MetricsRuntimeSnapshot {
        MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: outcomes.iter().map(|o| o.attempted_targets).sum(),
            host_targets: 0,
            process_targets: 0,
            container_targets: 0,
            outcomes,
        }
    }

    /// 现场看不到「是谁、为什么」是这次要解决的问题：先把它钉住。
    #[test]
    fn collection_failures_name_the_target_and_the_reason() {
        let tick = snapshot(vec![outcome(
            "process_metrics",
            "partial",
            2,
            1,
            Some("pid 42 gone"),
            vec![
                sample("proc:42", "failed", Some("/proc/42 不存在")),
                sample("proc:43", "succeeded", None),
            ],
        )]);

        let failures = collection_failures(&tick);
        assert_eq!(failures.len(), 1, "只报失败的那个目标；成功的不要噪音");
        let failure = &failures[0];
        assert_eq!(failure.kind, MetricsFailureKind::Collection);
        assert_eq!(failure.collection, "process_metrics");
        assert_eq!(failure.target, "proc:42");
        assert_eq!(failure.status, "failed");
        assert_eq!(failure.detail, "/proc/42 不存在");
    }

    /// kafka 探针就是这个形状：整轮不通时 `targets` 为空，只有域级 `last_error`。
    #[test]
    fn collection_failures_fall_back_to_the_domain_when_targets_are_absent() {
        let tick = snapshot(vec![outcome(
            "kafka_broker_metrics",
            "failed",
            1,
            1,
            Some("127.0.0.1:9092: Connection refused (os error 61)"),
            Vec::new(),
        )]);

        let failures = collection_failures(&tick);
        assert_eq!(failures.len(), 1);
        assert_eq!(failures[0].target, "-", "域级失败不编造目标");
        assert_eq!(failures[0].collection, "kafka_broker_metrics");
        assert_eq!(failures[0].status, "failed");
        assert!(
            failures[0].detail.contains("127.0.0.1:9092"),
            "原因里要带地址：{}",
            failures[0].detail
        );
    }

    /// 采集器没给 `last_error` 时也不能静默：至少把计数说清楚。
    #[test]
    fn collection_failures_never_hide_a_failure_without_a_reason() {
        let tick = snapshot(vec![outcome(
            "host_metrics",
            "failed",
            1,
            1,
            None,
            Vec::new(),
        )]);

        let failures = collection_failures(&tick);
        assert_eq!(failures.len(), 1);
        let detail = &failures[0].detail;
        assert!(
            detail.contains("attempted=1") && detail.contains("failed=1"),
            "没有 last_error 也要能看出发生了什么：{detail}"
        );
    }

    /// 正常采集（含 `idle`）一律不出失败项：这条闸门决定了日志噪音量。
    #[test]
    fn successful_and_idle_outcomes_produce_no_failures() {
        let tick = snapshot(vec![
            outcome(
                "process_metrics",
                "succeeded",
                2,
                0,
                None,
                vec![
                    sample("proc:1", "succeeded", None),
                    sample("proc:2", "succeeded", None),
                ],
            ),
            outcome("container_metrics", "idle", 0, 0, None, Vec::new()),
        ]);
        assert!(collection_failures(&tick).is_empty());
    }

    /// 「变化才打」靠签名：目标或原因一变就必须是新的签名，否则现场看不到第二次故障。
    #[test]
    fn collection_failure_signature_covers_target_and_reason() {
        let base = MetricsFailure {
            kind: MetricsFailureKind::Collection,
            phase: "collect".to_string(),
            collection: "process_metrics".to_string(),
            target: "proc:42".to_string(),
            status: "failed".to_string(),
            path: "-".to_string(),
            detail: "boom".to_string(),
        };
        let other_target = MetricsFailure {
            target: "proc:43".to_string(),
            ..base.clone()
        };
        let other_reason = MetricsFailure {
            detail: "boom again".to_string(),
            ..base.clone()
        };

        assert_ne!(failure_signature(&base), failure_signature(&other_target));
        assert_ne!(failure_signature(&base), failure_signature(&other_reason));
        assert_eq!(failure_signature(&base), failure_signature(&base.clone()));
    }

    #[test]
    fn process_metrics_tick_builds_and_stores_runtime_snapshot_from_target_view() {
        let state_dir = temp_dir("build");
        let view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![
                MetricsTargetViewEntry {
                    candidate_id: "host-1".to_string(),
                    collection_kind: "host_metrics".to_string(),
                    target_ref: "host-1:host".to_string(),
                    resource_ref: "host-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("host.name", "host-a")],
                },
                MetricsTargetViewEntry {
                    candidate_id: "proc-1".to_string(),
                    collection_kind: "process_metrics".to_string(),
                    target_ref: "proc-1".to_string(),
                    resource_ref: "proc-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("process.pid", "42")],
                },
            ],
        };
        store(&target_view_path_for(&state_dir), &view).expect("store target view");

        let tick = process_metrics_tick(&state_dir);
        let stored: MetricsRuntimeSnapshot =
            read_json(&runtime_path_for(&state_dir)).expect("load runtime snapshot");

        assert!(tick.target_view_loaded);
        assert!(!tick.used_cached_snapshot);
        assert!(tick.failures.is_empty());
        assert_eq!(tick.snapshot, Some(stored.clone()));
        assert_eq!(stored.total_targets, 2);
        assert_eq!(stored.host_targets, 1);
        assert_eq!(stored.process_targets, 1);
        assert_eq!(stored.container_targets, 0);
    }

    #[test]
    fn process_metrics_tick_uses_cached_runtime_snapshot_when_target_view_is_missing() {
        let state_dir = temp_dir("cached");
        let cached = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 3,
            host_targets: 1,
            process_targets: 1,
            container_targets: 1,
            outcomes: vec![
                crate::telemetry::metrics::runtime::MetricsCollectionOutcome {
                    collection_kind: "host_metrics".to_string(),
                    status: "succeeded".to_string(),
                    attempted_targets: 1,
                    succeeded_targets: 1,
                    failed_targets: 0,
                    dropped_targets: 0,
                    last_error: None,
                    runtime_facts: vec![StringKeyValue::new("host.loadavg.1m", "0.10")],
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
                crate::telemetry::metrics::runtime::MetricsCollectionOutcome {
                    collection_kind: "process_metrics".to_string(),
                    status: "succeeded".to_string(),
                    attempted_targets: 1,
                    succeeded_targets: 1,
                    failed_targets: 0,
                    dropped_targets: 0,
                    last_error: None,
                    runtime_facts: vec![StringKeyValue::new("process.pid", "42")],
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
                crate::telemetry::metrics::runtime::MetricsCollectionOutcome {
                    collection_kind: "container_metrics".to_string(),
                    status: "succeeded".to_string(),
                    attempted_targets: 1,
                    succeeded_targets: 1,
                    failed_targets: 0,
                    dropped_targets: 0,
                    last_error: None,
                    runtime_facts: vec![StringKeyValue::new("container.runtime", "containerd")],
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
            ],
        };
        crate::telemetry::metrics::runtime::store(&runtime_path_for(&state_dir), &cached)
            .expect("store cached runtime snapshot");

        let tick = process_metrics_tick(&state_dir);

        assert!(!tick.target_view_loaded);
        assert!(tick.used_cached_snapshot);
        assert_eq!(tick.snapshot, Some(cached));
        assert_eq!(tick.failures.len(), 1);
        assert_eq!(tick.failures[0].phase, "target_view_load");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_metrics_uplink_sends_metrics_frame() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut body = Vec::new();
            let mut buf = vec![0u8; 2048];
            loop {
                let n = socket.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            String::from_utf8_lossy(&body).into_owned()
        });
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));

        let snapshot = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 1,
            host_targets: 1,
            process_targets: 0,
            container_targets: 0,
            outcomes: vec![MetricsCollectionOutcome {
                collection_kind: "host_metrics".to_string(),
                status: "succeeded".to_string(),
                attempted_targets: 1,
                succeeded_targets: 1,
                failed_targets: 0,
                dropped_targets: 0,
                last_error: None,
                runtime_facts: vec![StringKeyValue::new("host.loadavg.1m", "0.25")],
                labeled_facts: Vec::new(),
                sample_targets: vec![MetricsCollectionTargetSample {
                    candidate_id: "host-1".to_string(),
                    target_ref: "host-1:host".to_string(),
                    status: "succeeded".to_string(),
                    last_error: None,
                    resource_ref: "host-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("host.name", "host-a")],
                    runtime_facts: vec![StringKeyValue::new("host.loadavg.1m", "0.25")],
                    labeled_facts: Vec::new(),
                }],
            }],
        };

        let state_dir = temp_dir("metrics-uplink");
        let global_seq_path = crate::state_store::log_seq_state::path_for(&state_dir);
        let mut next_seq = 0u64;
        write_metrics_uplink(
            &mut sink,
            "agent-001",
            &snapshot,
            &Default::default(),
            &mut next_seq,
            &global_seq_path,
        )
        .await
        .expect("write metrics uplink");
        drop(sink);

        let body = server.await.expect("join");
        assert!(body.contains(" METRICS: "), "frame: {body}");
        assert!(body.contains("\"agent\":\"agent-001\""), "frame: {body}");
        assert!(
            body.contains("system_load_average_1m"),
            "normalized sample: {body}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_metrics_uplink_draws_from_global_seq_and_persists() {
        let listener = match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => listener,
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => return,
            Err(err) => panic!("bind listener: {err}"),
        };
        let port = listener.local_addr().expect("listener addr").port();
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut body = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = socket.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            String::from_utf8_lossy(&body).into_owned()
        });
        let state_dir = temp_dir("metrics-seq");
        let global_seq_path = crate::state_store::log_seq_state::path_for(&state_dir);
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));

        // 两个数值样本 → 两帧，seq 应从传入的全局计数器 5 开始递增。
        let snapshot = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 1,
            host_targets: 1,
            process_targets: 0,
            container_targets: 0,
            outcomes: vec![MetricsCollectionOutcome {
                collection_kind: "host_metrics".to_string(),
                status: "succeeded".to_string(),
                attempted_targets: 1,
                succeeded_targets: 1,
                failed_targets: 0,
                dropped_targets: 0,
                last_error: None,
                runtime_facts: vec![],
                labeled_facts: Vec::new(),
                sample_targets: vec![MetricsCollectionTargetSample {
                    candidate_id: "host-1".to_string(),
                    target_ref: "host-1:host".to_string(),
                    status: "succeeded".to_string(),
                    last_error: None,
                    resource_ref: "host-1".to_string(),
                    execution_hints: vec![],
                    runtime_facts: vec![
                        StringKeyValue::new("host.loadavg.1m", "0.25"),
                        StringKeyValue::new("host.uptime.seconds", "3600"),
                    ],
                    labeled_facts: Vec::new(),
                }],
            }],
        };

        let mut next_seq = 5u64;
        write_metrics_uplink(
            &mut sink,
            "agent-001",
            &snapshot,
            &Default::default(),
            &mut next_seq,
            &global_seq_path,
        )
        .await
        .expect("write metrics uplink");
        drop(sink);

        // 取号递增 + 高水位持久化到独立全局 seq 文件。
        // 帧数 = 两个数值样本 + 采集记账 + 若干自观测行（后者取决于本机平台）。
        let persisted = crate::state_store::log_seq_state::load_or_default_async(&global_seq_path)
            .await
            .expect("load global seq");
        assert!(next_seq > 5, "uplink must have drawn seq numbers");
        assert_eq!(persisted, next_seq);

        // 帧信封 seq 来自全局计数器（从 5 开始连续递增），而非 batch_seq。
        let body = server.await.expect("join");
        let seqs: Vec<u64> = body
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let (envelope, _) = line.split_once(" METRICS: ").expect("METRICS marker");
                let parsed: serde_json::Value = serde_json::from_str(envelope).expect("envelope");
                parsed["seq"].as_u64().expect("seq")
            })
            .collect();
        assert_eq!(seqs.len() as u64 + 5, next_seq);
        let expected: Vec<u64> = (5..5 + seqs.len() as u64).collect();
        assert_eq!(seqs, expected);
    }
}
