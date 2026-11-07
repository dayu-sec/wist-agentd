//! 指标运行时：把目标视图变成一批 `MetricsCollectionOutcome`。
//!
//! 采集按域拆在 [`host`] / [`process`] / [`container`]；本模块只负责
//! 共享类型、provider 注册、批次记账与快照持久化。

mod container;
mod host;
mod process;

use super::scheduler;

use std::io;
use std::path::Path;
use std::sync::OnceLock;

use serde::{Deserialize, Serialize};
use wist_contracts::discovery::StringKeyValue;
use wist_shared::fs::write_json_atomic;
use wist_shared::time::now_rfc3339;

// `investigate disk` 与指标采集共用同一套文件系统过滤/去重规则。
pub(crate) use host::local_filesystems;

pub use wist_metrics::provider::{
    MetricProvider, MetricsCollectionOutcome, MetricsCollectionTargetSample, MetricsLabeledFact,
};

#[cfg(test)]
use super::target_view::path_for as target_view_path_for;
use super::target_view::{MetricsTargetView, MetricsTargetViewEntry};

/// 控制面（平台）endpoint：`system_host_info` 的 `host_ip` 用它选「到平台的源地址」。
///
/// 为什么是进程级配置而不是参数：`MetricProvider` 是 `wist-metrics` 里的 trait，签名不带
/// 采集上下文，为它改 trait 会牵动一个独立发版的 crate。与 `kafka` 探针同一个做法
/// （`kafka::init` 也是启动时写一次配置）。由 `run_forever_async` 写入；控制面地址变了
/// 本来就要求重启。
static PLATFORM_ENDPOINT: OnceLock<String> = OnceLock::new();

/// 由 daemon 启动时调用一次；`None` / 空串 = 未配置（选 IP 时按默认路由兜底）。
pub fn init_platform_endpoint(endpoint: Option<String>) {
    if let Some(endpoint) = endpoint.filter(|value| !value.trim().is_empty()) {
        let _ = PLATFORM_ENDPOINT.set(endpoint);
    }
}

/// 供 `host_ip` 选源地址用；未初始化时返回 `None`。
pub(crate) fn platform_endpoint() -> Option<&'static str> {
    PLATFORM_ENDPOINT.get().map(String::as_str)
}
#[cfg(test)]
use wist_shared::fs::read_json;

#[cfg(test)]
use host::*;
#[cfg(test)]
use process::*;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[serde(deny_unknown_fields)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct MetricsRuntimeSnapshot {
    pub generated_at: String,
    pub total_targets: usize,
    pub host_targets: usize,
    pub process_targets: usize,
    pub container_targets: usize,
    #[serde(default)]
    pub outcomes: Vec<MetricsCollectionOutcome>,
}

#[cfg(test)]
pub fn build_runtime_snapshot(state_dir: &Path) -> io::Result<MetricsRuntimeSnapshot> {
    let view: MetricsTargetView = read_json(&target_view_path_for(state_dir))?;
    Ok(build_runtime_snapshot_from_view(&view))
}

/// 构建快照（**同步**采一轮主机三域，不碰 Kafka）。
///
/// 测试与离线工具用这一个；守护进程走 [`build_runtime_snapshot_live`]。
#[cfg(test)]
pub fn build_runtime_snapshot_from_view(view: &MetricsTargetView) -> MetricsRuntimeSnapshot {
    let outcomes = super::collection::host_outcomes(view);
    build_snapshot(view, outcomes)
}

/// 守护进程的路：主机三域与 Kafka 都读**调度器最近一次完成的结果**。
///
/// 采集不在主循环里发生（见 `scheduler.rs`）；目标集合变了时调度器会同步补一轮主机采集，
/// 所以这里不会读到上一份目标的数据。
pub fn build_runtime_snapshot_live(view: &MetricsTargetView) -> MetricsRuntimeSnapshot {
    scheduler::apply_host_view(view);
    let outcomes = scheduler::collect_all(view);
    build_snapshot(view, outcomes)
}

fn build_snapshot(
    view: &MetricsTargetView,
    outcomes: Vec<MetricsCollectionOutcome>,
) -> MetricsRuntimeSnapshot {
    let mut host_targets = 0;
    let mut process_targets = 0;
    let mut container_targets = 0;

    for target in &view.targets {
        match target.collection_kind.as_str() {
            "host_metrics" => host_targets += 1,
            "process_metrics" => process_targets += 1,
            "container_metrics" => container_targets += 1,
            _ => {}
        }
    }

    MetricsRuntimeSnapshot {
        generated_at: now_rfc3339(),
        total_targets: host_targets + process_targets + container_targets,
        host_targets,
        process_targets,
        container_targets,
        outcomes,
    }
}

pub fn path_for(state_dir: &Path) -> std::path::PathBuf {
    state_dir
        .join("telemetry")
        .join("metrics_runtime_snapshot.json")
}

pub fn store(path: &Path, snapshot: &MetricsRuntimeSnapshot) -> io::Result<()> {
    write_json_atomic(path, snapshot)
}

fn build_host_outcome(
    attempted_targets: usize,
    mut sample_targets: Vec<MetricsCollectionTargetSample>,
) -> MetricsCollectionOutcome {
    if attempted_targets == 0 {
        return MetricsCollectionOutcome {
            collection_kind: "host_metrics".to_string(),
            status: "idle".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            dropped_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets,
        };
    }

    let collected = host::collect_host_runtime_facts(&sample_targets);
    let runtime_facts = collected.facts;
    let labeled_facts = collected.labeled_facts;
    if runtime_facts.is_empty() && labeled_facts.is_empty() {
        for sample in &mut sample_targets {
            sample.status = "failed".to_string();
            sample.last_error = Some("host metrics probe produced no runtime facts".to_string());
        }
        MetricsCollectionOutcome {
            collection_kind: "host_metrics".to_string(),
            status: "failed".to_string(),
            attempted_targets,
            succeeded_targets: 0,
            failed_targets: attempted_targets,
            dropped_targets: 0,
            last_error: Some("host metrics probe produced no runtime facts".to_string()),
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets,
        }
    } else {
        // 主机级指标每批只上送一次：只挂到第一个目标上，避免按目标复制出重复序列。
        for (index, sample) in sample_targets.iter_mut().enumerate() {
            sample.status = "succeeded".to_string();
            if index == 0 {
                sample.runtime_facts = runtime_facts.clone();
                sample.labeled_facts = labeled_facts.clone();
            }
        }
        let dropped_targets = attempted_targets.saturating_sub(sample_targets.len());
        MetricsCollectionOutcome {
            collection_kind: "host_metrics".to_string(),
            status: "succeeded".to_string(),
            attempted_targets,
            succeeded_targets: attempted_targets,
            failed_targets: 0,
            dropped_targets,
            last_error: None,
            runtime_facts,
            labeled_facts,
            sample_targets,
        }
    }
}

fn build_process_outcome(targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
    if targets.is_empty() {
        return MetricsCollectionOutcome {
            collection_kind: "process_metrics".to_string(),
            status: "idle".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            dropped_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        };
    }

    let mut succeeded_targets = 0usize;
    let mut failed_targets = 0usize;
    let mut dropped_targets = 0usize;
    let mut sample_targets = Vec::new();
    let mut last_error = None;

    for target in &targets {
        let probed = process::probe_process_target(target);
        if probed.status == "succeeded" {
            succeeded_targets += 1;
        } else {
            failed_targets += 1;
            if last_error.is_none() {
                last_error = probed.last_error.clone();
            }
        }
        if sample_targets.len() < SAMPLE_LIMIT {
            sample_targets.push(probed);
        } else {
            dropped_targets += 1;
        }
    }

    let status = if failed_targets == 0 {
        "succeeded"
    } else if succeeded_targets == 0 {
        "failed"
    } else {
        "partial"
    };

    MetricsCollectionOutcome {
        collection_kind: "process_metrics".to_string(),
        status: status.to_string(),
        attempted_targets: targets.len(),
        succeeded_targets,
        failed_targets,
        dropped_targets,
        last_error,
        runtime_facts: vec![
            StringKeyValue::new("process.probe.mode", process::process_probe_mode()),
            StringKeyValue::new("process.probe.success_count", succeeded_targets.to_string()),
            StringKeyValue::new("process.probe.failed_count", failed_targets.to_string()),
        ],
        labeled_facts: Vec::new(),
        sample_targets,
    }
}

fn build_container_outcome(targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
    if targets.is_empty() {
        return MetricsCollectionOutcome {
            collection_kind: "container_metrics".to_string(),
            status: "idle".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            dropped_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        };
    }

    let mut succeeded_targets = 0usize;
    let mut failed_targets = 0usize;
    let mut dropped_targets = 0usize;
    let mut sample_targets = Vec::new();
    let mut last_error = None;

    for target in &targets {
        let probed = container::probe_container_target(target);
        if probed.status == "failed" {
            failed_targets += 1;
            if last_error.is_none() {
                last_error = probed.last_error.clone();
            }
        } else {
            succeeded_targets += 1;
        }
        if sample_targets.len() < SAMPLE_LIMIT {
            sample_targets.push(probed);
        } else {
            dropped_targets += 1;
        }
    }

    let status = if failed_targets == 0 {
        "succeeded"
    } else if succeeded_targets == 0 {
        "failed"
    } else {
        "partial"
    };

    MetricsCollectionOutcome {
        collection_kind: "container_metrics".to_string(),
        status: status.to_string(),
        attempted_targets: targets.len(),
        succeeded_targets,
        failed_targets,
        dropped_targets,
        last_error,
        runtime_facts: vec![
            StringKeyValue::new("container.probe.mode", container::container_probe_mode()),
            StringKeyValue::new(
                "container.probe.success_count",
                succeeded_targets.to_string(),
            ),
            StringKeyValue::new("container.probe.failed_count", failed_targets.to_string()),
        ],
        labeled_facts: Vec::new(),
        sample_targets,
    }
}

/// 编译期注册的 provider 列表；新增一类指标 = 加一个 provider 并在这里登记。
pub(crate) fn providers() -> &'static [&'static dyn MetricProvider] {
    &[
        &HostMetricsProvider,
        &ProcessMetricsProvider,
        &ContainerMetricsProvider,
    ]
}

pub struct HostMetricsProvider;
pub struct ProcessMetricsProvider;
pub struct ContainerMetricsProvider;

impl MetricProvider for HostMetricsProvider {
    fn collection_kind(&self) -> &'static str {
        "host_metrics"
    }

    fn collect(&self, targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
        let mut sample_targets = Vec::new();
        for target in &targets {
            maybe_push_sample(&mut sample_targets, target);
        }
        build_host_outcome(targets.len(), sample_targets)
    }
}

impl MetricProvider for ProcessMetricsProvider {
    fn collection_kind(&self) -> &'static str {
        "process_metrics"
    }

    fn collect(&self, targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
        build_process_outcome(targets)
    }
}

impl MetricProvider for ContainerMetricsProvider {
    fn collection_kind(&self) -> &'static str {
        "container_metrics"
    }

    fn collect(&self, targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
        build_container_outcome(targets)
    }
}

pub(super) fn push_fact_if_absent(facts: &mut Vec<StringKeyValue>, candidate: StringKeyValue) {
    if facts.iter().any(|fact| fact.key == candidate.key) {
        return;
    }
    facts.push(candidate);
}

/// 每类采集每个批次最多保留的目标样本数；超出部分计入 `dropped_targets`。
const SAMPLE_LIMIT: usize = 3;

fn maybe_push_sample(
    samples: &mut Vec<MetricsCollectionTargetSample>,
    target: &MetricsTargetViewEntry,
) {
    if samples.len() >= SAMPLE_LIMIT {
        return;
    }

    samples.push(MetricsCollectionTargetSample {
        candidate_id: target.candidate_id.clone(),
        target_ref: target.target_ref.clone(),
        status: "pending".to_string(),
        last_error: None,
        resource_ref: target.resource_ref.clone(),
        execution_hints: target.execution_hints.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
    });
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{
        MetricsCollectionOutcome, MetricsCollectionTargetSample, MetricsRuntimeSnapshot,
        build_runtime_snapshot, path_for, store,
    };
    use crate::telemetry::metrics::target_view::{MetricsTargetView, MetricsTargetViewEntry};
    use wist_contracts::discovery::StringKeyValue;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("warp-insight-metrics-runtime-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn build_runtime_snapshot_counts_batch_a_targets() {
        let state_dir = temp_dir("counts");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![
                MetricsTargetViewEntry {
                    candidate_id: "host-1".to_string(),
                    collection_kind: "host_metrics".to_string(),
                    target_ref: "host-1:host".to_string(),
                    resource_ref: "host-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("host.name", "local-host")],
                },
                MetricsTargetViewEntry {
                    candidate_id: "proc-1".to_string(),
                    collection_kind: "process_metrics".to_string(),
                    target_ref: "proc-1".to_string(),
                    resource_ref: "proc-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("process.pid", "42")],
                },
                MetricsTargetViewEntry {
                    candidate_id: "container-1".to_string(),
                    collection_kind: "container_metrics".to_string(),
                    target_ref: "container-1".to_string(),
                    resource_ref: "container-1".to_string(),
                    execution_hints: vec![
                        StringKeyValue::new("container.runtime", "containerd"),
                        StringKeyValue::new("pid", std::process::id().to_string()),
                    ],
                },
            ],
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");

        assert!(
            snapshot.generated_at.ends_with('Z'),
            "collection time should be RFC3339"
        );
        assert_eq!(snapshot.total_targets, 3);
        assert_eq!(snapshot.host_targets, 1);
        assert_eq!(snapshot.process_targets, 1);
        assert_eq!(snapshot.container_targets, 1);

        let host_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "host_metrics")
            .expect("host outcome");
        assert_eq!(host_outcome.status, "succeeded");
        assert_eq!(host_outcome.attempted_targets, 1);
        assert_eq!(host_outcome.succeeded_targets, 1);
        assert_eq!(host_outcome.failed_targets, 0);
        assert!(host_outcome.last_error.is_none());
        assert!(!host_outcome.runtime_facts.is_empty());
        assert_eq!(host_outcome.sample_targets.len(), 1);

        let process_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "process_metrics")
            .expect("process outcome");
        assert!(matches!(
            process_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(process_outcome.attempted_targets, 1);
        assert_eq!(
            process_outcome.succeeded_targets + process_outcome.failed_targets,
            1
        );
        assert!(!process_outcome.runtime_facts.is_empty());
        assert_eq!(process_outcome.sample_targets.len(), 1);
        assert_eq!(
            process_outcome.sample_targets[0].status,
            if process_outcome.succeeded_targets == 1 {
                "succeeded"
            } else {
                "failed"
            }
        );

        let container_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "container_metrics")
            .expect("container outcome");
        assert!(matches!(
            container_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(container_outcome.attempted_targets, 1);
        assert_eq!(
            container_outcome.succeeded_targets + container_outcome.failed_targets,
            1
        );
        assert!(!container_outcome.runtime_facts.is_empty());
        assert_eq!(container_outcome.sample_targets.len(), 1);
    }

    #[test]
    fn store_runtime_snapshot_round_trip() {
        let state_dir = temp_dir("store");
        let snapshot = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 0,
            host_targets: 0,
            process_targets: 0,
            container_targets: 0,
            outcomes: vec![
                super::MetricsCollectionOutcome {
                    collection_kind: "host_metrics".to_string(),
                    status: "idle".to_string(),
                    attempted_targets: 0,
                    succeeded_targets: 0,
                    failed_targets: 0,
                    dropped_targets: 0,
                    last_error: None,
                    runtime_facts: Vec::new(),
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
                super::MetricsCollectionOutcome {
                    collection_kind: "process_metrics".to_string(),
                    status: "idle".to_string(),
                    attempted_targets: 0,
                    succeeded_targets: 0,
                    failed_targets: 0,
                    dropped_targets: 0,
                    last_error: None,
                    runtime_facts: Vec::new(),
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
                super::MetricsCollectionOutcome {
                    collection_kind: "container_metrics".to_string(),
                    status: "idle".to_string(),
                    attempted_targets: 0,
                    succeeded_targets: 0,
                    failed_targets: 0,
                    dropped_targets: 0,
                    last_error: None,
                    runtime_facts: Vec::new(),
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
            ],
        };
        let snapshot_path = path_for(&state_dir);

        store(&snapshot_path, &snapshot).expect("store runtime snapshot");
        let loaded: MetricsRuntimeSnapshot =
            wist_shared::fs::read_json(&snapshot_path).expect("load runtime snapshot");

        assert_eq!(loaded, snapshot);
    }

    #[test]
    fn build_runtime_snapshot_limits_samples_per_collection_kind() {
        let state_dir = temp_dir("sample-limit");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: (0..5)
                .map(|idx| MetricsTargetViewEntry {
                    candidate_id: format!("proc-{idx}"),
                    collection_kind: "process_metrics".to_string(),
                    target_ref: format!("proc-{idx}"),
                    resource_ref: format!("proc-{idx}"),
                    execution_hints: vec![StringKeyValue::new("process.pid", idx.to_string())],
                })
                .collect(),
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");
        let process_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "process_metrics")
            .expect("process outcome");

        assert_eq!(process_outcome.attempted_targets, 5);
        assert_eq!(
            process_outcome.succeeded_targets + process_outcome.failed_targets,
            5
        );
        assert!(matches!(
            process_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(process_outcome.sample_targets.len(), 3);
        assert_eq!(
            process_outcome.dropped_targets, 2,
            "targets beyond the sample cap must be accounted, not silently dropped"
        );
        assert_eq!(
            process_outcome.sample_targets.len() + process_outcome.dropped_targets,
            process_outcome.attempted_targets
        );
    }

    #[test]
    fn build_runtime_snapshot_marks_process_target_failed_when_pid_hint_missing() {
        let state_dir = temp_dir("process-missing-pid");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![MetricsTargetViewEntry {
                candidate_id: "proc-1".to_string(),
                collection_kind: "process_metrics".to_string(),
                target_ref: "proc-1".to_string(),
                resource_ref: "proc-1".to_string(),
                execution_hints: vec![StringKeyValue::new("process.identity", "demo")],
            }],
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");
        let process_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "process_metrics")
            .expect("process outcome");

        assert_eq!(process_outcome.status, "failed");
        assert_eq!(process_outcome.attempted_targets, 1);
        assert_eq!(process_outcome.succeeded_targets, 0);
        assert_eq!(process_outcome.failed_targets, 1);
        assert!(
            process_outcome
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("process.pid"))
        );
        assert_eq!(process_outcome.sample_targets.len(), 1);
        assert_eq!(process_outcome.sample_targets[0].status, "failed");
    }

    #[test]
    fn build_runtime_snapshot_marks_container_target_failed_when_hints_missing() {
        let state_dir = temp_dir("container-missing-hints");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![MetricsTargetViewEntry {
                candidate_id: "container-1".to_string(),
                collection_kind: "container_metrics".to_string(),
                target_ref: "container-1".to_string(),
                resource_ref: "container-1".to_string(),
                execution_hints: Vec::new(),
            }],
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");
        let container_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "container_metrics")
            .expect("container outcome");

        assert_eq!(container_outcome.status, "failed");
        assert_eq!(container_outcome.attempted_targets, 1);
        assert_eq!(container_outcome.succeeded_targets, 0);
        assert_eq!(container_outcome.failed_targets, 1);
        assert!(
            container_outcome
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("no runtime facts"))
        );
        assert_eq!(container_outcome.sample_targets.len(), 1);
        assert_eq!(container_outcome.sample_targets[0].status, "failed");
    }

    #[test]
    fn provider_registry_covers_batch_a_kinds() {
        let kinds: Vec<&str> = super::providers()
            .iter()
            .map(|provider| provider.collection_kind())
            .collect();
        assert_eq!(
            kinds,
            vec!["host_metrics", "process_metrics", "container_metrics"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_host_runtime_facts_are_collected() {
        let collected = super::collect_host_runtime_facts(&[]);
        let facts = collected.facts;
        let fact_value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        for key in ["host.loadavg.1m", "host.loadavg.5m", "host.loadavg.15m"] {
            let value = fact_value(key).unwrap_or_else(|| panic!("missing fact {key}"));
            assert!(
                value.parse::<f64>().is_ok(),
                "{key} should parse as f64, got {value:?}"
            );
        }

        let uptime = fact_value("host.uptime.seconds").expect("host.uptime.seconds");
        let uptime: f64 = uptime.parse().expect("uptime should parse as f64");
        assert!(uptime >= 0.0, "uptime should be non-negative, got {uptime}");

        let total = fact_value("host.memory.total_bytes").expect("host.memory.total_bytes");
        let total: i64 = total.parse().expect("total should parse as i64");
        assert!(total > 0, "total memory should be positive, got {total}");

        let available =
            fact_value("host.memory.available_bytes").expect("host.memory.available_bytes");
        let available: i64 = available.parse().expect("available should parse as i64");
        assert!(
            available > 0,
            "available memory should be positive, got {available}"
        );

        // 磁盘 I/O：平台拿不到时不发；发了就必须是整盘、数值可解析。
        let disk_io: Vec<_> = collected
            .labeled_facts
            .iter()
            .filter(|fact| fact.key == "host.disk.read_bytes")
            .collect();
        for fact in disk_io {
            assert!(fact.value.parse::<u64>().is_ok(), "{}", fact.value);
            assert!(
                fact.labels
                    .iter()
                    .any(|label| label.key == "device" && !label.value.is_empty()),
                "disk io fact must carry a device label"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_whole_disk_strips_volume_suffixes() {
        // APFS 卷名是 `diskNsM`（可嵌套）；I/O 统计只在整盘上有一份。
        assert_eq!(super::macos_whole_disk("/dev/disk3s1s1"), "disk3");
        assert_eq!(super::macos_whole_disk("/dev/disk0s2"), "disk0");
        assert_eq!(super::macos_whole_disk("disk3"), "disk3");
        assert_eq!(super::macos_whole_disk("/dev/disk10"), "disk10");
        assert_eq!(super::macos_whole_disk("/dev/disk3"), "disk3");
    }

    #[cfg(unix)]
    #[test]
    fn host_disk_runtime_facts_are_collected() {
        let facts = super::collect_host_runtime_facts(&[]).facts;
        let fact_value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        let usage =
            fact_value("host.disk.system.usage_ratio").expect("host.disk.system.usage_ratio");
        let usage: f64 = usage.parse().expect("usage should parse as f64");
        assert!(
            (0.0..=1.0).contains(&usage),
            "usage should be 0..=1, got {usage}"
        );

        let total =
            fact_value("host.disk.system.total_bytes").expect("host.disk.system.total_bytes");
        let total: i64 = total.parse().expect("total should parse as i64");
        assert!(total > 0, "total disk should be positive, got {total}");

        let available = fact_value("host.disk.system.available_bytes")
            .expect("host.disk.system.available_bytes");
        let available: i64 = available.parse().expect("available should parse as i64");
        assert!(
            available >= 0,
            "available disk should be non-negative, got {available}"
        );
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn host_info_fact_carries_machine_identity() {
        let collected = super::collect_host_runtime_facts(&[]);
        let info = collected
            .labeled_facts
            .iter()
            .find(|fact| fact.key == "host.info")
            .expect("host.info");

        assert_eq!(info.value, "1", "info 指标的值恒为 1");
        let label = |key: &str| {
            info.labels
                .iter()
                .find(|label| label.key == key)
                .map(|label| label.value.as_str())
        };
        assert!(!label("host_name").unwrap_or_default().is_empty());
        assert_eq!(label("os"), Some(std::env::consts::OS));
        assert_eq!(label("arch"), Some(std::env::consts::ARCH));

        // `host_ip` 可缺（机器没有可用 IPv4），但一旦有值，必须是可解析的非回环 IPv4。
        if let Some(ip) = label("host_ip") {
            let parsed: std::net::Ipv4Addr = ip.parse().expect("host_ip must be an IPv4 address");
            assert!(!parsed.is_loopback(), "host_ip 不得是回环地址: {ip}");
        }
    }

    /// 端到端：真实采集 → 样本 → VM 行。`system_host_info` 必须真的带上身份 label，
    /// 且这些 label **不得**跑到测量序列上。
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn real_host_facts_become_a_single_host_info_vm_line() {
        use crate::telemetry::metrics::samples::{
            build_samples_snapshot, build_vm_metric_lines_with,
        };

        let collected = super::collect_host_runtime_facts(&[]);
        let target = MetricsCollectionTargetSample {
            candidate_id: "host-1:host:host_metrics".to_string(),
            target_ref: "host-1:host".to_string(),
            status: "succeeded".to_string(),
            last_error: None,
            resource_ref: "host-1".to_string(),
            execution_hints: Vec::new(),
            runtime_facts: collected.facts,
            labeled_facts: collected.labeled_facts,
        };
        let runtime = MetricsRuntimeSnapshot {
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
                runtime_facts: Vec::new(),
                labeled_facts: Vec::new(),
                sample_targets: vec![target],
            }],
        };

        let snapshot = build_samples_snapshot(&runtime);
        let lines = build_vm_metric_lines_with(&snapshot, "agent-1", &Default::default());

        let info_lines: Vec<_> = lines
            .iter()
            .filter(|line| line.metric.name == "system_host_info")
            .collect();
        assert_eq!(info_lines.len(), 1, "每批只能有一条 info 序列");
        let info = info_lines[0];
        assert_eq!(info.metric.instance, "host-1");
        assert!(
            !info
                .metric
                .host_name
                .as_deref()
                .unwrap_or_default()
                .is_empty()
        );
        assert_eq!(info.metric.os.as_deref(), Some(std::env::consts::OS));
        assert_eq!(info.metric.arch.as_deref(), Some(std::env::consts::ARCH));
        if let Some(host_ip) = info.metric.host_ip.as_deref() {
            let parsed: std::net::Ipv4Addr = host_ip.parse().expect("host_ip must be IPv4");
            assert!(!parsed.is_loopback());
        }

        // 身份 label 只能出现在 info 序列上：漏到测量序列就是序列身份漂移。
        for line in &lines {
            if line.metric.name == "system_host_info" {
                continue;
            }
            assert!(
                line.metric.host_name.is_none(),
                "{} 带了 host_name",
                line.metric.name
            );
            assert!(
                line.metric.host_ip.is_none(),
                "{} 带了 host_ip",
                line.metric.name
            );
            assert!(line.metric.os.is_none(), "{} 带了 os", line.metric.name);
            assert!(line.metric.arch.is_none(), "{} 带了 arch", line.metric.name);
            assert!(
                line.metric.kernel.is_none(),
                "{} 带了 kernel",
                line.metric.name
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn host_filesystem_runtime_facts_carry_mount_labels() {
        let collected = super::collect_host_runtime_facts(&[]);
        let usage = collected
            .labeled_facts
            .iter()
            .find(|fact| fact.key == "host.filesystem.usage_ratio")
            .expect("host.filesystem.usage_ratio");
        let mountpoint = usage
            .labels
            .iter()
            .find(|label| label.key == "mountpoint")
            .expect("mountpoint label");
        let fstype = usage
            .labels
            .iter()
            .find(|label| label.key == "fstype")
            .expect("fstype label");
        assert!(!mountpoint.value.is_empty());
        assert!(!fstype.value.is_empty());
        let usage: f64 = usage.value.parse().expect("usage should parse as f64");
        assert!(
            (0.0..=1.0).contains(&usage),
            "usage should be 0..=1, got {usage}"
        );

        #[cfg(target_os = "linux")]
        assert!(
            collected
                .labeled_facts
                .iter()
                .any(|fact| fact.key == "host.filesystem.usage_ratio"
                    && fact
                        .labels
                        .iter()
                        .any(|label| label.key == "mountpoint" && label.value == "/")),
            "root filesystem should be collected on Linux"
        );
    }

    #[test]
    fn host_provider_carries_labeled_facts_to_outcome_and_sample_targets() {
        use super::MetricProvider;

        let target = MetricsTargetViewEntry {
            candidate_id: "host-1:host:host_metrics".to_string(),
            collection_kind: "host_metrics".to_string(),
            target_ref: "host-1:host".to_string(),
            resource_ref: "host-1".to_string(),
            execution_hints: vec![StringKeyValue::new("host.name", "host-a")],
        };

        let outcome = super::HostMetricsProvider.collect(vec![&target]);

        assert_eq!(outcome.status, "succeeded");
        assert!(
            outcome
                .labeled_facts
                .iter()
                .any(|fact| fact.key == "host.filesystem.usage_ratio"),
            "outcome should carry filesystem facts"
        );
        assert_eq!(outcome.sample_targets.len(), 1);
        assert_eq!(
            outcome.sample_targets[0].labeled_facts,
            outcome.labeled_facts
        );
    }

    /// 采集侧产出的 fact 必须能落到注册表，或在 ignore 表里明确登记。
    /// 这条测试是 §7.5「覆盖完整性」的可执行版本：新增 fact 忘了加注册表会在这里失败。
    #[test]
    fn every_emitted_fact_is_registered_or_explicitly_ignored() {
        use super::MetricProvider;
        use crate::telemetry::metrics::spec::find_metric_spec;

        const IGNORED: &[&str] = &[
            // 身份信息：进 instance，不进指标
            "process.identity",
            "discovery.identity_strength",
            "discovery.identity_status",
            "process.executable.name",
            // 容器/编排身份：属发现域
            "container.runtime",
            "container.runtime.namespace",
            "cgroup.path",
            "k8s.namespace.name",
            "k8s.pod.uid",
            "k8s.pod.name",
            "k8s.container.name",
        ];

        let registered =
            |kind: &str, key: &str| find_metric_spec(kind, key).is_some() || IGNORED.contains(&key);

        let host = super::collect_host_runtime_facts(&[]);
        let host_keys = host
            .facts
            .iter()
            .map(|fact| fact.key.as_str())
            .chain(host.labeled_facts.iter().map(|fact| fact.key.as_str()));
        for key in host_keys {
            assert!(
                registered("host_metrics", key),
                "host fact `{key}` is neither registered nor ignored"
            );
        }

        let pid = std::process::id().to_string();
        let process_entry = MetricsTargetViewEntry {
            candidate_id: "proc:metrics".to_string(),
            collection_kind: "process_metrics".to_string(),
            target_ref: "host-1:pid".to_string(),
            resource_ref: "host-1:pid".to_string(),
            execution_hints: vec![StringKeyValue::new("process.pid", pid.clone())],
        };
        let container_entry = MetricsTargetViewEntry {
            candidate_id: "ctr:metrics".to_string(),
            collection_kind: "container_metrics".to_string(),
            target_ref: "container-1".to_string(),
            resource_ref: "container-1".to_string(),
            execution_hints: vec![
                StringKeyValue::new("container.runtime", "docker"),
                StringKeyValue::new("pid", pid),
            ],
        };

        for (kind, outcome) in [
            (
                "process_metrics",
                super::ProcessMetricsProvider.collect(vec![&process_entry]),
            ),
            (
                "container_metrics",
                super::ContainerMetricsProvider.collect(vec![&container_entry]),
            ),
        ] {
            for target in &outcome.sample_targets {
                let keys = target
                    .runtime_facts
                    .iter()
                    .map(|fact| fact.key.as_str())
                    .chain(target.labeled_facts.iter().map(|fact| fact.key.as_str()));
                for key in keys {
                    assert!(
                        registered(kind, key),
                        "{kind} fact `{key}` is neither registered nor ignored"
                    );
                }
            }
        }
    }

    /// 旧名已下线：事实与样本里都不允许再出现 `legacy.*` 或点分名字。
    #[test]
    fn no_legacy_facts_or_names_are_emitted() {
        use super::MetricProvider;

        let target = MetricsTargetViewEntry {
            candidate_id: "host-1:metrics".to_string(),
            collection_kind: "host_metrics".to_string(),
            target_ref: "host-1:host".to_string(),
            resource_ref: "host-1".to_string(),
            execution_hints: Vec::new(),
        };
        let outcome = super::HostMetricsProvider.collect(vec![&target]);

        let fact_keys: Vec<&str> = outcome
            .sample_targets
            .iter()
            .flat_map(|target| target.runtime_facts.iter().map(|fact| fact.key.as_str()))
            .chain(
                outcome
                    .sample_targets
                    .iter()
                    .flat_map(|target| target.labeled_facts.iter().map(|fact| fact.key.as_str())),
            )
            .collect();
        assert!(!fact_keys.is_empty());
        assert!(
            fact_keys.iter().all(|key| !key.starts_with("legacy.")),
            "legacy fact emitted: {fact_keys:?}"
        );

        let runtime = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 1,
            host_targets: 1,
            process_targets: 0,
            container_targets: 0,
            outcomes: vec![outcome],
        };
        let samples = crate::telemetry::metrics::samples::build_samples_snapshot(&runtime);
        let names: Vec<&str> = samples
            .groups
            .iter()
            .flat_map(|group| group.samples.iter())
            .map(|sample| sample.name.as_str())
            .collect();
        assert!(names.contains(&"system_load_average_1m"));
        assert!(
            names.iter().all(|name| !name.contains('.')),
            "legacy name emitted: {names:?}"
        );
    }

    /// 主机级指标每批只挂到一个目标上：多个 host 目标不得复制出重复序列。
    #[test]
    fn host_facts_are_attached_to_the_first_target_only() {
        use super::MetricProvider;

        let target = |id: &str| MetricsTargetViewEntry {
            candidate_id: format!("{id}:metrics"),
            collection_kind: "host_metrics".to_string(),
            target_ref: format!("{id}:host"),
            resource_ref: id.to_string(),
            execution_hints: Vec::new(),
        };
        let (first, second) = (target("host-1"), target("host-2"));

        let outcome = super::HostMetricsProvider.collect(vec![&first, &second]);

        assert_eq!(outcome.sample_targets.len(), 2);
        assert!(!outcome.sample_targets[0].runtime_facts.is_empty());
        assert!(
            outcome.sample_targets[1].runtime_facts.is_empty()
                && outcome.sample_targets[1].labeled_facts.is_empty(),
            "second host target must not duplicate host-level facts"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn is_partition_is_false_for_unknown_devices() {
        assert!(!super::is_partition("definitely-not-a-block-device"));
    }

    #[test]
    fn disk_capacity_facts_derive_usage_from_total_and_available() {
        let mut facts = Vec::new();
        super::push_disk_capacity_facts(&mut facts, "data", 4096, 1024);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        assert_eq!(value("host.disk.data.usage_ratio"), Some("0.75"));
        assert_eq!(value("host.disk.data.total_bytes"), Some("4096"));
        assert_eq!(value("host.disk.data.available_bytes"), Some("1024"));
    }

    #[test]
    fn linux_data_mounts_exclude_system_and_virtual_filesystems() {
        let is_data = super::is_linux_data_mount_point;

        assert!(is_data("/data", "ext4", 100));
        assert!(is_data("/home", "xfs", 100));
        assert!(is_data("/var/lib/docker", "ext4", 100));

        assert!(!is_data("/", "ext4", 100));
        assert!(!is_data("/boot", "ext4", 100));
        assert!(!is_data("/boot/efi", "vfat", 100));
        assert!(!is_data("/run/media/u/disk", "ext4", 100));
        assert!(!is_data("/sys/fs/cgroup", "cgroup2", 100));
        assert!(!is_data("/proc", "proc", 100));
        assert!(!is_data("/data", "overlay", 100));
        assert!(!is_data("/data", "fuse.sshfs", 100));
        assert!(!is_data("/data", "nfs", 100));
        assert!(!is_data("/data", "ceph", 100));
        assert!(!is_data("/data", "tmpfs", 100));
        assert!(!is_data("/data", "ext4", 0));
    }

    #[test]
    fn linux_filesystem_mount_filter_excludes_virtual_and_network_mounts() {
        let include = super::is_linux_filesystem_mount_point;

        assert!(include("/", "ext4", 100));
        assert!(include("/data", "xfs", 100));
        assert!(include("/var/lib/docker", "ext4", 100));
        assert!(include("/data", "zfs", 100));

        assert!(!include("/boot", "ext4", 100));
        assert!(!include("/boot/efi", "vfat", 100));
        assert!(!include("/run", "tmpfs", 100));
        assert!(!include("/run/media/u/disk", "ext4", 100));
        assert!(!include("/sys/fs/cgroup", "cgroup2", 100));
        assert!(!include("/proc", "proc", 100));
        assert!(!include("/dev/shm", "tmpfs", 100));
        assert!(!include("/data", "overlay", 100));
        assert!(!include("/data", "squashfs", 100));
        assert!(!include("/data", "fuse.sshfs", 100));
        assert!(!include("/data", "nfs4", 100));
        assert!(!include("/data", "ceph", 100));
        assert!(!include("/data", "lustre", 100));
        assert!(!include("/data", "virtiofs", 100));
        assert!(!include("/data", "ext4", 0));
    }

    #[test]
    fn macos_filesystem_mount_filter_keeps_data_and_local_volumes() {
        let include = super::is_macos_filesystem_mount_point;

        assert!(include("/", "apfs", 100));
        assert!(include("/System/Volumes/Data", "apfs", 100));
        assert!(include("/Volumes/Backup", "apfs", 100));
        assert!(include("/Volumes/USB", "exfat", 100));
        assert!(include("/Volumes/Installer", "hfs", 100));

        assert!(!include("/System/Volumes/Preboot", "apfs", 100));
        assert!(!include("/System/Volumes/VM", "apfs", 100));
        assert!(!include("/Volumes/net", "smbfs", 100));
        assert!(!include("/Volumes/net", "nfs", 100));
        assert!(!include("/Volumes/net", "webdav", 100));
        assert!(!include("/Volumes/net", "afpfs", 100));
        assert!(!include("/private/var/vm", "apfs", 100));
        assert!(!include("/Volumes/Backup", "apfs", 0));
    }

    #[test]
    fn filesystem_facts_use_bytes_and_mountpoint_labels() {
        let facts = super::filesystem_facts("/var", "xfs", 4096, 1024);
        assert!(facts.len() >= 3);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        assert_eq!(value("host.filesystem.usage_ratio"), Some("0.75"));
        assert_eq!(value("host.filesystem.total_bytes"), Some("4096"));
        assert_eq!(value("host.filesystem.available_bytes"), Some("1024"));
        for fact in &facts {
            assert!(
                fact.labels
                    .iter()
                    .any(|label| label.key == "mountpoint" && label.value == "/var")
            );
            assert!(
                fact.labels
                    .iter()
                    .any(|label| label.key == "fstype" && label.value == "xfs")
            );
        }
    }

    #[test]
    fn filesystem_dedupe_key_groups_bind_mounts_by_device() {
        assert_eq!(
            super::filesystem_dedupe_key("/dev/sda1", "/data"),
            super::filesystem_dedupe_key("/dev/sda1", "/mnt/data")
        );
        assert_ne!(
            super::filesystem_dedupe_key("", "/data"),
            super::filesystem_dedupe_key("", "/mnt/data")
        );
        assert_eq!(
            super::filesystem_dedupe_key("", "/data"),
            "mount:/data".to_string()
        );
    }

    #[test]
    fn ps_cputime_parses_seconds_minutes_and_hours() {
        assert_eq!(super::parse_ps_cputime("0:00.42"), Some(0.42));
        assert_eq!(super::parse_ps_cputime("1:02.00"), Some(62.0));
        assert_eq!(super::parse_ps_cputime("2:03:04.50"), Some(7384.5));
        assert_eq!(super::parse_ps_cputime("n/a"), None);
    }

    #[test]
    fn process_state_characters_map_to_the_closed_set() {
        assert_eq!(super::process_state_label('R'), "running");
        assert_eq!(super::process_state_label('D'), "disk_sleep");
        assert_eq!(super::process_state_label('Z'), "zombie");
        assert_eq!(super::process_state_label('?'), "unknown");
    }

    #[test]
    fn memory_usage_ratio_is_derived_and_guards_zero_total() {
        assert_eq!(super::memory_usage_ratio(0, 0), None);
        assert_eq!(super::memory_usage_ratio(1000, 250), Some(0.75));
        // available 超出 total 时夹取，不产生负使用率。
        assert_eq!(super::memory_usage_ratio(1000, 4000), Some(0.0));
    }

    #[test]
    fn disk_capacity_facts_clamp_available_to_total() {
        let mut facts = Vec::new();
        super::push_disk_capacity_facts(&mut facts, "system", 100, 400);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };
        assert_eq!(value("host.disk.system.available_bytes"), Some("100"));
        assert_eq!(value("host.disk.system.usage_ratio"), Some("0"));
    }

    #[test]
    fn diskstats_parser_maps_fields_and_skips_virtual_devices() {
        let text = "   8       0 sda 100 0 2000 30 50 0 1000 20 0 40 60 0 0 0 0\n\
                   8       1 sda1 10 0 100 3 5 0 50 2 0 4 6 0 0 0 0\n\
                   7       0 loop0 1 0 8 0 0 0 0 0 0 0 0 0 0 0 0\n";
        let stats = super::parse_diskstats(text);
        assert_eq!(stats.len(), 2, "loop devices are skipped");
        let sda = &stats[0];
        assert_eq!(sda.device, "sda");
        assert_eq!(sda.reads, 100);
        assert_eq!(sda.read_bytes, 2000 * 512);
        assert_eq!(sda.writes, 50);
        assert_eq!(sda.written_bytes, 1000 * 512);
        assert!((sda.io_seconds - 0.04).abs() < 1e-9);
        assert_eq!(stats[1].device, "sda1");
    }

    #[test]
    fn diskstats_parser_ignores_short_lines() {
        assert!(super::parse_diskstats("8 0 sda 1 2 3\n").is_empty());
    }

    #[test]
    fn filesystem_facts_skip_empty_fstype_label() {
        let facts = super::filesystem_facts("/data", "", 100, 50);
        assert!(
            facts
                .iter()
                .all(|fact| fact.labels.iter().all(|label| label.key != "fstype"))
        );
    }

    #[test]
    fn filesystem_facts_clamp_available_to_total() {
        let facts = super::filesystem_facts("/", "ext4", 100, 200);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        assert_eq!(value("host.filesystem.usage_ratio"), Some("0"));
        assert_eq!(value("host.filesystem.available_bytes"), Some("100"));
    }
}
