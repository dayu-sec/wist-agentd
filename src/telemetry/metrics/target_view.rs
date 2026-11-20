//! Read-only metrics target view built from planner candidates.

use std::io;
use std::path::Path;

use crate::fs_async::write_json_atomic_async;
use serde::{Deserialize, Serialize};
use wist_contracts::discovery::CollectionCandidate;

use crate::state_store::planner_candidates;

pub use wist_metrics::target::MetricsTargetViewEntry;

/// 逐进程指标是否采集。
///
/// **`false` = 默认停采**，理由：
///   * `CollectionSourceKind` 里没有进程类来源 —— 没有任何工作能授权它；
///   * 网关与本仓前端都还没有消费 `process_*` 序列的查询/看板；
///   * 它以前能采，纯粹是 `planner_bridge` 把发现快照里的 process targets 顺带转成了
///     采集候选（950 个目标/轮，`SAMPLE_LIMIT=3` 只报 3 条随机样本，其余记 dropped）。
///
/// 重新打开的时机：P2-c 给进程域加上「按授权选目标」后，把它打开并把上限
/// （`CapabilityLimits.max_metrics_targets`）按授权数下发。
/// 进程发现本身不受影响：它是用途推断与资产清单的输入，由发现策略管（`[discovery] process_enabled`）。
pub(crate) const PROCESS_METRICS_COLLECTION_ENABLED: bool = false;

/// 这一版要读的候选文件。顺序固定（host → process → container），
/// 进程那一格按开关取舍。
fn candidate_paths(state_dir: &Path, include_process: bool) -> Vec<std::path::PathBuf> {
    let mut paths = vec![planner_candidates::host_metrics_path_for(state_dir)];
    if include_process {
        paths.push(planner_candidates::process_metrics_path_for(state_dir));
    }
    paths.push(planner_candidates::container_metrics_path_for(state_dir));
    paths
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsTargetView {
    pub generated_at: String,
    #[serde(default)]
    pub targets: Vec<MetricsTargetViewEntry>,
}

#[cfg(test)]
pub fn build_metrics_target_view(
    state_dir: &Path,
    generated_at: &str,
) -> io::Result<MetricsTargetView> {
    build_metrics_target_view_with(state_dir, generated_at, PROCESS_METRICS_COLLECTION_ENABLED)
}

#[cfg(test)]
pub fn build_metrics_target_view_with(
    state_dir: &Path,
    generated_at: &str,
    include_process: bool,
) -> io::Result<MetricsTargetView> {
    let mut targets = Vec::new();

    for path in candidate_paths(state_dir, include_process) {
        let candidates = planner_candidates::load_or_default(&path)?;
        targets.extend(candidates.into_iter().map(map_candidate));
    }

    Ok(MetricsTargetView {
        generated_at: generated_at.to_string(),
        targets,
    })
}

pub fn path_for(state_dir: &Path) -> std::path::PathBuf {
    state_dir.join("telemetry").join("metrics_target_view.json")
}

#[cfg(test)]
pub fn store(path: &Path, view: &MetricsTargetView) -> io::Result<()> {
    wist_shared::fs::write_json_atomic(path, view)
}

pub async fn build_metrics_target_view_async(
    state_dir: &Path,
    generated_at: &str,
) -> io::Result<MetricsTargetView> {
    let mut targets = Vec::new();

    for path in candidate_paths(state_dir, PROCESS_METRICS_COLLECTION_ENABLED) {
        let candidates = planner_candidates::load_or_default_async(&path).await?;
        targets.extend(candidates.into_iter().map(map_candidate));
    }

    Ok(MetricsTargetView {
        generated_at: generated_at.to_string(),
        targets,
    })
}

pub async fn store_async(path: &Path, view: &MetricsTargetView) -> io::Result<()> {
    write_json_atomic_async(path, view).await
}

fn map_candidate(candidate: CollectionCandidate) -> MetricsTargetViewEntry {
    MetricsTargetViewEntry {
        candidate_id: candidate.candidate_id,
        collection_kind: candidate.collection_kind,
        target_ref: candidate.target_ref,
        resource_ref: candidate.resource_ref,
        execution_hints: candidate.execution_hints,
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use wist_contracts::discovery::{CollectionCandidate, StringKeyValue};
    use wist_shared::fs::read_json;

    use super::{build_metrics_target_view, build_metrics_target_view_with, path_for, store};
    use crate::state_store::planner_candidates;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("warp-insight-metrics-target-view-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn build_metrics_target_view_collects_batch_a_candidates() {
        let state_dir = temp_dir("view");
        planner_candidates::store(
            &planner_candidates::host_metrics_path_for(&state_dir),
            &[CollectionCandidate {
                candidate_id: "host-1:host:host_metrics".to_string(),
                target_ref: "host-1:host".to_string(),
                collection_kind: "host_metrics".to_string(),
                resource_ref: "host-1".to_string(),
                execution_hints: vec![StringKeyValue::new("host.name", "host-a")],
                generated_at: "2026-04-19T00:00:00Z".to_string(),
            }],
        )
        .expect("store host candidates");
        planner_candidates::store(
            &planner_candidates::process_metrics_path_for(&state_dir),
            &[CollectionCandidate {
                candidate_id: "proc-1:process_metrics".to_string(),
                target_ref: "proc-1".to_string(),
                collection_kind: "process_metrics".to_string(),
                resource_ref: "proc-1".to_string(),
                execution_hints: vec![StringKeyValue::new("process.pid", "42")],
                generated_at: "2026-04-19T00:00:00Z".to_string(),
            }],
        )
        .expect("store process candidates");

        let view = build_metrics_target_view_with(&state_dir, "2026-04-19T00:00:00Z", true)
            .expect("build metrics target view");

        assert_eq!(view.targets.len(), 2);
        assert!(
            view.targets
                .iter()
                .any(|target| target.collection_kind == "host_metrics")
        );
        assert!(
            view.targets
                .iter()
                .any(|target| target.collection_kind == "process_metrics")
        );
        assert!(view.targets.iter().any(|target| {
            target.collection_kind == "process_metrics"
                && target
                    .execution_hints
                    .iter()
                    .any(|hint| hint.key == "process.pid")
        }));
    }

    /// 逐进程指标默认停采：进程候选文件存在也不读（否则旧文件会继续被采）。
    #[test]
    fn process_candidates_are_ignored_while_collection_is_disabled() {
        let state_dir = temp_dir("process-disabled");
        planner_candidates::store(
            &planner_candidates::process_metrics_path_for(&state_dir),
            &[CollectionCandidate {
                candidate_id: "proc-1:process_metrics".to_string(),
                target_ref: "proc-1".to_string(),
                collection_kind: "process_metrics".to_string(),
                resource_ref: "proc-1".to_string(),
                execution_hints: vec![StringKeyValue::new("process.pid", "42")],
                generated_at: "2026-04-19T00:00:00Z".to_string(),
            }],
        )
        .expect("store process candidates");

        let view = build_metrics_target_view(&state_dir, "2026-04-19T00:00:00Z")
            .expect("build metrics target view");

        assert!(
            view.targets
                .iter()
                .all(|target| target.collection_kind != "process_metrics"),
            "停采期间不得把进程目标交给采集器"
        );
    }

    #[test]
    fn store_metrics_target_view_round_trip() {
        let state_dir = temp_dir("store");
        let view = build_metrics_target_view(&state_dir, "2026-04-19T00:00:00Z")
            .expect("empty target view");
        let view_path = path_for(&state_dir);

        store(&view_path, &view).expect("store target view");
        let loaded: super::MetricsTargetView = read_json(&view_path).expect("load target view");

        assert_eq!(loaded, view);
    }
}
