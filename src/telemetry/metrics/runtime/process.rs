//! 进程域采集：从**一轮进程表**里取 facts，不再按目标逐个取数。
//!
//! 取数在 [`crate::sys_proc::snapshot`]（macOS 一次 `ps -axo`，Linux 一次 `/proc`
//! 遍历）；这里只查表、只做纯映射，所以能在 Linux CI 上单测。
//!
//! 历史：macOS 曾经每个目标一次 `ps -p <pid>`，900 个进程的机器上一轮 900 次
//! fork（实测约 1.4s CPU / 20% 一个核），见 `sys_proc` 的模块注释。

use wist_contracts::discovery::StringKeyValue;

use super::push_fact_if_absent;
use super::{MetricsCollectionTargetSample, MetricsTargetViewEntry};
use crate::sys_proc::{ProcRow, ProcSnapshot};

/// 从表里取一个目标的采集结果。
pub(super) fn probe_from_table(
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

    let Some(pid) = target_pid(target) else {
        sample.last_error = Some("process.pid execution hint missing".to_string());
        return sample;
    };

    let Some(row) = table.get(pid) else {
        sample.last_error = Some(missing_row_error(pid, table));
        return sample;
    };

    sample.status = "succeeded".to_string();
    sample.runtime_facts = facts_from_row(row, &sample.execution_hints);
    sample
}

/// 目标声明的 pid（`process.pid` 执行提示）。
pub(super) fn target_pid(target: &MetricsTargetViewEntry) -> Option<u32> {
    target
        .execution_hints
        .iter()
        .find(|hint| hint.key == "process.pid")
        .and_then(|hint| hint.value.parse::<u32>().ok())
}

/// 「表里没有这个 pid」的说明：整表取数失败和进程已退出要分开讲，
/// 否则一次 `ps` 失败会被 900 个目标重复报成「进程消失」。
pub(super) fn missing_row_error(pid: u32, table: &ProcSnapshot) -> String {
    match table.error() {
        Some(err) => format!("process table unavailable: {err}"),
        None => format!("process {pid} not found in snapshot"),
    }
}

/// 一行进程表 → 该目标的运行时 facts。
pub(super) fn facts_from_row(
    row: &ProcRow,
    execution_hints: &[StringKeyValue],
) -> Vec<StringKeyValue> {
    let mut facts = Vec::new();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("process.pid", row.pid.to_string()),
    );
    // 身份类 hint 由发现侧给出，采集侧只转接（保持既有口径）。
    for hint in execution_hints {
        if matches!(
            hint.key.as_str(),
            "process.identity" | "discovery.identity_strength" | "discovery.identity_status"
        ) {
            push_fact_if_absent(&mut facts, hint.clone());
        }
    }
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("process.state", process_state_label(row.state)),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("process.memory.rss_bytes", row.rss_bytes.to_string()),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("process.cpu.seconds", format!("{:.3}", row.cpu_seconds)),
    );
    // 拿不到可执行名（受限的 `/proc`、内核线程）时不发这条 fact：
    // 不编空串，也不拿 pid 充数。两端口径一致：macOS 取 `ps comm`，Linux 取 `/proc/<pid>/exe`。
    if let Some(comm) = row.comm.as_ref() {
        push_fact_if_absent(
            &mut facts,
            StringKeyValue::new("process.executable.name", comm.clone()),
        );
    }
    facts
}

/// 状态字符 → 规范闭集取值（未识别的一律 `unknown`）。
pub(super) fn process_state_label(state: char) -> &'static str {
    match state {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk_sleep",
        'T' | 't' => "stopped",
        'Z' => "zombie",
        'X' | 'x' => "dead",
        'I' => "idle",
        _ => "unknown",
    }
}

pub(super) fn process_probe_mode() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "procfs"
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        "ps"
    }
    #[cfg(not(unix))]
    {
        "unsupported"
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sys_proc::ProcRow;

    fn target(pid: u32) -> MetricsTargetViewEntry {
        MetricsTargetViewEntry {
            candidate_id: format!("host-1:pid:{pid}:process_metrics"),
            collection_kind: "process_metrics".to_string(),
            target_ref: format!("host-1:pid:{pid}:process"),
            resource_ref: format!("host-1:pid:{pid}"),
            execution_hints: vec![StringKeyValue::new("process.pid", pid.to_string())],
        }
    }

    fn row(pid: u32) -> ProcRow {
        ProcRow {
            pid,
            state: 'S',
            rss_bytes: 2048,
            cpu_seconds: 1.5,
            start_token: Some("ps_lstart:Mon Nov 16 15:45:11 2026".to_string()),
            comm: Some("/usr/local/bin/demo".to_string()),
        }
    }

    fn fact<'a>(facts: &'a [StringKeyValue], key: &str) -> Option<&'a str> {
        facts
            .iter()
            .find(|fact| fact.key == key)
            .map(|fact| fact.value.as_str())
    }

    #[test]
    fn probe_takes_every_fact_from_the_table_row() {
        let table = ProcSnapshot::from_rows(vec![row(42)]);
        let sample = probe_from_table(&target(42), &table);

        assert_eq!(sample.status, "succeeded");
        assert_eq!(fact(&sample.runtime_facts, "process.pid"), Some("42"));
        assert_eq!(
            fact(&sample.runtime_facts, "process.state"),
            Some("sleeping")
        );
        assert_eq!(
            fact(&sample.runtime_facts, "process.memory.rss_bytes"),
            Some("2048")
        );
        assert_eq!(
            fact(&sample.runtime_facts, "process.cpu.seconds"),
            Some("1.500")
        );
        assert_eq!(
            fact(&sample.runtime_facts, "process.executable.name"),
            Some("/usr/local/bin/demo")
        );
    }

    #[test]
    fn probe_reports_missing_pid_hint_and_missing_row_separately() {
        let table = ProcSnapshot::from_rows(vec![row(42)]);
        let mut no_pid = target(1);
        no_pid.execution_hints.clear();

        let sample = probe_from_table(&no_pid, &table);
        assert_eq!(sample.status, "failed");
        assert_eq!(
            sample.last_error.as_deref(),
            Some("process.pid execution hint missing")
        );

        // 进程已退出：报「表里没有」，不是「采到了空的」。
        let gone = probe_from_table(&target(99), &table);
        assert_eq!(gone.status, "failed");
        assert!(
            gone.last_error
                .as_deref()
                .unwrap_or_default()
                .contains("not found in snapshot")
        );
    }

    #[test]
    fn rows_without_comm_omit_the_executable_name_fact() {
        // 拿不到可执行名时宁可少一条 fact，也不发一个空值。
        let mut row = row(42);
        row.comm = None;
        let table = ProcSnapshot::from_rows(vec![row]);
        let sample = probe_from_table(&target(42), &table);

        assert_eq!(sample.status, "succeeded");
        assert_eq!(fact(&sample.runtime_facts, "process.executable.name"), None);
    }
}
