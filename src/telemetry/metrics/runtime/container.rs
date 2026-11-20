//! 容器域采集：复用进程探测，再按容器身份收敛标签。

use wist_contracts::discovery::StringKeyValue;

use super::process::{facts_from_row, missing_row_error};
use super::push_fact_if_absent;
use super::{MetricsCollectionTargetSample, MetricsTargetViewEntry};
use crate::sys_proc::ProcSnapshot;

pub(super) fn probe_container_target(
    target: &MetricsTargetViewEntry,
    table: &ProcSnapshot,
) -> MetricsCollectionTargetSample {
    let mut sample = MetricsCollectionTargetSample {
        candidate_id: target.candidate_id.clone(),
        target_ref: target.target_ref.clone(),
        status: "failed".to_string(),
        last_error: None,
        resource_ref: target.resource_ref.clone(),
        execution_hints: target.execution_hints.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
    };

    let mut facts = Vec::new();
    for hint in &sample.execution_hints {
        if matches!(
            hint.key.as_str(),
            "container.runtime"
                | "container.runtime.namespace"
                | "cgroup.path"
                | "k8s.namespace.name"
                | "k8s.pod.uid"
                | "k8s.pod.name"
                | "k8s.container.name"
        ) {
            push_fact_if_absent(&mut facts, hint.clone());
        }
    }

    let mut process_probe_error = None;
    if let Some(pid) = sample
        .execution_hints
        .iter()
        .find(|hint| hint.key == "pid")
        .and_then(|hint| hint.value.parse::<u32>().ok())
    {
        match table.get(pid) {
            Some(row) => {
                push_fact_if_absent(
                    &mut facts,
                    StringKeyValue::new("container.pid", pid.to_string()),
                );
                for fact in facts_from_row(row, &[]) {
                    // pid 在容器域由 `container.pid` 表达；`process.pid` 在此域没有登记，直接丢弃。
                    if fact.key == "process.pid" {
                        continue;
                    }
                    push_fact_if_absent(&mut facts, fact);
                }
            }
            // 进程已退出 / 整表取数失败：两种情况都要说出来，别混成「采到了空的」。
            None => process_probe_error = Some(missing_row_error(pid, table)),
        }
    }

    if facts.is_empty() {
        sample.last_error = process_probe_error
            .or_else(|| Some("container metrics probe produced no runtime facts".to_string()));
        return sample;
    }

    sample.status = if process_probe_error.is_some() {
        "partial".to_string()
    } else {
        "succeeded".to_string()
    };
    sample.last_error = process_probe_error;
    sample.runtime_facts = facts;
    sample
}

pub(super) fn container_probe_mode() -> &'static str {
    "discovery_hints"
}
