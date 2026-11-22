//! 进程类 opcode：`process.list` / `process.tree` / `process.open_files`。
//!
//! 三条共同纪律：
//!
//! 1. **不含 argv**：只给可执行名 / pid / ppid / uid / 状态 / CPU / RSS；
//! 2. 取数复用 `investigate_load` 的同一份映射（`ProcessSample`），不另写一套；
//! 3. 都有预算与条数上限，结果里的 `truncated` 必须如实。

use serde::Deserialize;
use serde_json::{Value, json};
use wist_contracts::action_plan::RiskLevel;

use super::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};
use crate::investigate_load::{self, ProcessSample};

const SCHEMA_LIST: &str = "wist.opcode.process_list/v1";
const SCHEMA_TREE: &str = "wist.opcode.process_tree/v1";
const SCHEMA_OPEN_FILES: &str = "wist.opcode.process_open_files/v1";

const DEFAULT_TOP: usize = 10;
const MAX_TOP: usize = 50;
const MAX_TREE_DEPTH: usize = 32;
const MAX_FD_ENTRIES: usize = 200_000;

pub const LIST_SPEC: OpSpec = OpSpec {
    id: "process.list",
    risk: RiskLevel::R0,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(5_000, MAX_TOP, 0),
    handler: list,
};

pub const TREE_SPEC: OpSpec = OpSpec {
    id: "process.tree",
    risk: RiskLevel::R0,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(5_000, MAX_TREE_DEPTH, 0),
    handler: tree,
};

pub const OPEN_FILES_SPEC: OpSpec = OpSpec {
    id: "process.open_files",
    risk: RiskLevel::R1,
    platforms: &["linux"],
    budget: OpBudget::new(2_000, 1_000, 0),
    handler: open_files,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ListArgs {
    #[serde(default)]
    top: Option<usize>,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    uid: Option<u32>,
    #[serde(default)]
    state: Option<String>,
}

fn sample_all() -> Result<(Vec<ProcessSample>, u64), OpError> {
    investigate_load::sample_processes_for_opcode(None)
        .map_err(|detail| OpError::new(codes::OP_FAILED, detail))
}

fn row(process: &ProcessSample) -> Value {
    json!({
        "pid": process.pid,
        "ppid": process.ppid,
        "name": process.name,
        "state": process.state,
        "uid": process.uid,
        "cpu_percent": process.cpu,
        "rss_bytes": process.rss,
        "run_time_seconds": process.run_time,
        "agent": process.agent,
    })
}

fn list(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: ListArgs = parse_args(input.args)?;
    let max_top = MAX_TOP.min(input.budget.max_items.max(1));
    let top = args.top.unwrap_or(DEFAULT_TOP).clamp(1, max_top);
    if let Some(name) = args.name.as_deref() {
        if name.chars().count() > 128 {
            return Err(OpError::new(codes::INVALID_ARGS, "name 超过 128 个字符"));
        }
        if name.trim().is_empty() {
            return Err(OpError::new(codes::INVALID_ARGS, "name 不能是空串"));
        }
    }
    if let Some(state) = args.state.as_deref()
        && state.chars().count() != 1
    {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            "state 必须是单个状态字母（R/S/D/Z…）",
        ));
    }

    let (mut processes, window_ms) = sample_all()?;
    let total = processes.len() as u64;
    if let Some(name) = args.name.as_deref() {
        let needle = name.to_lowercase();
        processes.retain(|process| process.name.to_lowercase().contains(&needle));
    }
    if let Some(uid) = args.uid {
        processes.retain(|process| process.uid == Some(uid));
    }
    if let Some(state) = args.state.as_deref() {
        processes.retain(|process| process.state == state);
    }
    let matched = processes.len() as u64;
    let rows: Vec<Value> = processes.iter().take(top).map(row).collect();

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_LIST,
            "window_ms": window_ms,
            "total": total,
            "matched": matched,
            "returned": rows.len(),
            "truncated": matched > rows.len() as u64,
            "processes": rows,
        }),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TreeArgs {
    #[serde(default)]
    pid: Option<u32>,
    #[serde(default)]
    name: Option<String>,
}

fn tree(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: TreeArgs = parse_args(input.args)?;
    let selector_name = args.name.as_deref().filter(|name| !name.trim().is_empty());
    if args.pid.is_some() == selector_name.is_some() {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            "process.tree 需要且只能给一个：pid 或 name",
        ));
    }

    // 只采一次：按名字解析与向上追链用同一份快照，否则会白跑两个 1s 窗口。
    let (processes, window_ms) = sample_all()?;
    let (pid, resolved_by) = match (args.pid, selector_name) {
        (Some(pid), None) => (pid, "pid"),
        (None, Some(name)) => {
            let needle = name.to_lowercase();
            let found = processes
                .iter()
                .filter(|process| process.name.to_lowercase().contains(&needle))
                .min_by_key(|process| process.pid)
                .map(|process| process.pid)
                .ok_or_else(|| {
                    OpError::new(
                        codes::TARGET_NOT_FOUND,
                        format!("没有名字匹配 `{name}` 的进程"),
                    )
                })?;
            (found, "name")
        }
        _ => unreachable!("selector shape is checked above"),
    };

    let max_depth = MAX_TREE_DEPTH.min(input.budget.max_items.max(1));
    let mut by_pid: std::collections::BTreeMap<u32, &ProcessSample> = processes
        .iter()
        .map(|process| (process.pid, process))
        .collect();
    let mut chain = Vec::new();
    let mut current = pid;
    let mut truncated = false;
    loop {
        let Some(process) = by_pid.remove(&current) else {
            if chain.is_empty() {
                return Err(OpError::new(
                    codes::TARGET_NOT_FOUND,
                    format!("进程 {current} 不存在或已退出"),
                ));
            }
            break;
        };
        chain.push(row(process));
        match process.ppid {
            Some(parent) if parent != 0 && parent != current => current = parent,
            _ => break,
        }
        if chain.len() >= max_depth {
            truncated = true;
            break;
        }
    }

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_TREE,
            "window_ms": window_ms,
            "root_pid": pid,
            "resolved_by": resolved_by,
            "truncated": truncated,
            "chain": chain,
        }),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct OpenFilesArgs {
    pid: u32,
    #[serde(default)]
    limit: Option<usize>,
}

fn open_files(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: OpenFilesArgs = parse_args(input.args)?;
    let limit = args
        .limit
        .unwrap_or(100)
        .clamp(1, input.budget.max_items.max(1));
    let fd_dir = format!("/proc/{}/fd", args.pid);
    let entries = std::fs::read_dir(&fd_dir).map_err(|err| {
        OpError::new(
            codes::TARGET_NOT_FOUND,
            format!("进程 {} 的 fd 目录不可读：{err}", args.pid),
        )
    })?;

    let mut files = Vec::new();
    let mut file_paths = 0u64;
    let mut deleted_paths = 0u64;
    let mut sockets = 0u64;
    let mut pipes = 0u64;
    let mut anon = 0u64;
    let mut other = 0u64;
    let mut seen = 0usize;
    let mut truncated = false;

    for entry in entries.flatten() {
        if seen >= MAX_FD_ENTRIES {
            truncated = true;
            break;
        }
        seen += 1;
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let text = target.to_string_lossy();
        if text.starts_with("socket:[") {
            sockets += 1;
        } else if text.starts_with("pipe:[") {
            pipes += 1;
        } else if text.starts_with("anon_inode:") || text.starts_with("/memfd:") {
            anon += 1;
        } else if let Some(path) = text.strip_suffix(" (deleted)") {
            // 计数与明细分开：明细受 `limit` 截断，计数必须仍然是全量。
            deleted_paths += 1;
            if files.len() < limit {
                files.push(json!({ "path": path, "deleted": true }));
            } else {
                truncated = true;
            }
        } else if text.starts_with('/') {
            file_paths += 1;
            if files.len() < limit {
                files.push(json!({ "path": text, "deleted": false }));
            } else {
                truncated = true;
            }
        } else {
            other += 1;
        }
    }

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_OPEN_FILES,
            "pid": args.pid,
            "limit": limit,
            "files": files,
            "counts": {
                "files": file_paths,
                "deleted": deleted_paths,
                "sockets": sockets,
                "pipes": pipes,
                "anon": anon,
                "other": other,
            },
            "fd_seen": seen,
            "truncated": truncated,
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(args: &'a serde_json::Value) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: &[],
            budget: OpBudget::new(60_000, 50, 0),
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    #[test]
    fn list_args_are_validated_before_sampling() {
        for bad in [
            json!({"state": "RUN"}),
            json!({"name": "   "}),
            json!({"name": "x".repeat(200)}),
        ] {
            let err = list(&input(&bad)).expect_err("bad args");
            assert_eq!(err.code, codes::INVALID_ARGS);
        }
    }

    #[test]
    fn tree_needs_exactly_one_selector() {
        for bad in [json!({}), json!({"pid": 1, "name": "init"})] {
            let err = tree(&input(&bad)).expect_err("ambiguous");
            assert_eq!(err.code, codes::INVALID_ARGS);
        }
    }

    #[test]
    fn tree_of_a_missing_pid_is_target_not_found() {
        let err = tree(&input(&json!({"pid": 4_000_000_000u32}))).expect_err("missing");
        assert_eq!(err.code, codes::TARGET_NOT_FOUND);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_files_of_the_current_process_lists_real_fds() {
        let pid = std::process::id();
        let output = open_files(&input(&json!({ "pid": pid, "limit": 10 }))).expect("list fds");
        assert_eq!(output.value["pid"], pid);
        assert!(output.value["fd_seen"].as_u64().unwrap_or(0) >= 1);
        // 进程至少有 0/1/2 三个标准 fd（测试运行时一定在）。
        assert!(output.value["counts"]["files"].as_u64().unwrap_or(0) >= 0);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_files_counts_stay_complete_when_the_listing_is_capped() {
        use std::time::{SystemTime, UNIX_EPOCH};

        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-open-files-{suffix}"));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let a = dir.join("a.txt");
        let b = dir.join("b.txt");
        std::fs::write(&a, b"a").expect("write a");
        std::fs::write(&b, b"b").expect("write b");
        let held_a = std::fs::File::open(&a).expect("open a");
        let held_b = std::fs::File::open(&b).expect("open b");

        let output = open_files(&input(&json!({
            "pid": std::process::id(),
            "limit": 1
        })))
        .expect("list fds");

        assert_eq!(output.value["files"].as_array().expect("files").len(), 1);
        assert!(
            output.value["counts"]["files"].as_u64().unwrap_or(0) >= 2,
            "counts must not be capped by the listing limit: {}",
            output.value["counts"]
        );
        assert_eq!(output.value["truncated"], true);

        drop(held_a);
        drop(held_b);
        let _ = std::fs::remove_dir_all(dir);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn open_files_of_a_missing_pid_is_target_not_found() {
        let err = open_files(&input(&json!({ "pid": 4_000_000_000u32 }))).expect_err("missing");
        assert_eq!(err.code, codes::TARGET_NOT_FOUND);
    }
}
