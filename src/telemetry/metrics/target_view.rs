//! Read-only metrics target view built from planner candidates.

use std::io;
use std::path::Path;

use crate::fs_async::write_json_atomic_async;
use serde::{Deserialize, Serialize};
use wist_contracts::discovery::CollectionCandidate;

use crate::state_store::planner_candidates;

pub use wist_metrics::target::MetricsTargetViewEntry;

/// 逐进程指标的候选要不要采，由**授权**决定（`KeyProcessMetrics` 来源 + 签名），
/// 不再是编译期开关：
///
/// * 没授权 → 守护进程连候选文件都不生成（磁盘上不会留一份“看起来还在采”的旧数据）；
/// * 授权了 → `key_process::select_key_process_candidates` 按签名从发现快照里选代表进程。
///
/// 进程发现本身不受影响：它是用途推断与资产清单的输入，由发现策略管。
///
/// 这一版读的候选文件。顺序固定（host → process → container）。
/// 文件不存在时 `load_or_default` 返回空 —— 所以“没授权”自然是零个目标。
fn candidate_paths(state_dir: &Path) -> Vec<std::path::PathBuf> {
    vec![
        planner_candidates::host_metrics_path_for(state_dir),
        planner_candidates::process_metrics_path_for(state_dir),
        planner_candidates::container_metrics_path_for(state_dir),
    ]
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MetricsTargetView {
    pub generated_at: String,
    #[serde(default)]
    pub targets: Vec<MetricsTargetViewEntry>,
    /// 关键进程指标的**选目标结论**：授权了但一条签名都没命中时写原因（`None` = 正常或未授权）。
    ///
    /// 为什么要跨文件传：选目标发生在**发现拍**（要读 `/proc/<pid>/cmdline`），而采集记账在
    /// **指标 tick** —— 两者之间只有这个视图文件。不带下来就只剩一行日志，
    /// 管理面的「采集结果」看不到“授权了为什么没数据”。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process_selection_error: Option<String>,
}

#[cfg(test)]
pub fn build_metrics_target_view(
    state_dir: &Path,
    generated_at: &str,
) -> io::Result<MetricsTargetView> {
    let mut targets = Vec::new();

    for path in candidate_paths(state_dir) {
        let candidates = planner_candidates::load_or_default(&path)?;
        targets.extend(candidates.into_iter().map(map_candidate));
    }

    Ok(MetricsTargetView {
        generated_at: generated_at.to_string(),
        targets,
        // 纯构建器不知道选择结论；由发现拍在落盘前填。
        process_selection_error: None,
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

    for path in candidate_paths(state_dir) {
        let candidates = planner_candidates::load_or_default_async(&path).await?;
        targets.extend(candidates.into_iter().map(map_candidate));
    }

    Ok(MetricsTargetView {
        generated_at: generated_at.to_string(),
        targets,
        // 纯构建器不知道选择结论；由发现拍在落盘前填。
        process_selection_error: None,
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

    use super::{build_metrics_target_view, path_for, store};
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

        let view = build_metrics_target_view(&state_dir, "2026-04-19T00:00:00Z")
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

    /// 进程候选文件**就是授权的落地结果**：没授权时它不存在 → 零个目标；
    /// 授权了才由 `key_process::select_key_process_candidates` 写进来。
    ///
    /// 这条钉住“不要在读取侧再偷偷关一次”—— 关的职责在写入侧（没授权就不生成文件），
    /// 两边都关会让“文件在、却不采”变成没人能解释的态。
    #[test]
    fn process_targets_come_only_from_the_candidate_file() {
        let state_dir = temp_dir("process-candidates-are-the-source");

        let empty = build_metrics_target_view(&state_dir, "2026-04-19T00:00:00Z")
            .expect("build empty view");
        assert!(
            empty
                .targets
                .iter()
                .all(|target| target.collection_kind != "process_metrics"),
            "没有候选文件就不该有进程目标"
        );

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
        assert_eq!(
            view.targets
                .iter()
                .filter(|target| target.collection_kind == "process_metrics")
                .count(),
            1
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
