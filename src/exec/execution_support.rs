//! Shared execution-state helpers.
//!
//! 这里只回答一个问题：**同一 `action_id` + `plan_digest` 是否已经有执行**。
//! 三个落盘位置（`running/`、`reporting/`、`history/`）的差别只有「用哪个 store 读」
//! 和「是否跳过上报信封文件」，所以目录扫描骨架、坏文件跳过、身份比对都收敛在
//! [`scan_state_dir`] / [`scan_state_dir_async`] 里，各 store 只保留自己的读取方式。

use std::fs;
use std::future::Future;
use std::io;
use std::path::{Path, PathBuf};

use wist_contracts::action_result::ActionResult;
use wist_shared::paths::REPORT_ENVELOPE_SUFFIX;

use crate::state_store::execution_queue::{self, ExecutionQueueItem};
use crate::state_store::{history, reporting, running};

pub fn final_state_name(result: &ActionResult) -> &'static str {
    result.final_status.as_state_name()
}

pub fn find_duplicate_execution(
    state_dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    let queue_path = execution_queue::path_for(state_dir);
    let queue = execution_queue::load_or_default(&queue_path)?;
    if let Some(execution_id) = queued_duplicate_execution(&queue, action_id, plan_digest) {
        return Ok(Some(execution_id));
    }

    if let Some(execution_id) =
        find_duplicate_running_execution(&state_dir.join("running"), action_id, plan_digest)?
    {
        return Ok(Some(execution_id));
    }

    if let Some(execution_id) =
        find_duplicate_reporting_execution(&state_dir.join("reporting"), action_id, plan_digest)?
    {
        return Ok(Some(execution_id));
    }

    find_duplicate_history_execution(&state_dir.join("history"), action_id, plan_digest)
}

pub fn lookup_queued_execution(
    state_dir: &Path,
    execution_id: &str,
) -> io::Result<Option<ExecutionQueueItem>> {
    let queue_path = execution_queue::path_for(state_dir);
    if !queue_path.exists() {
        return Ok(None);
    }

    let queue = execution_queue::load_or_default(&queue_path)?;
    Ok(queue
        .items
        .into_iter()
        .find(|item| item.execution_id == execution_id))
}

/// `running/<execution_id>.json` 里找同一动作 + 同一计划摘要的执行。
fn find_duplicate_running_execution(
    dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    scan_state_dir(dir, false, |path| {
        let state = running::load(path).ok()?;
        same_plan_target(
            Some(&state.action_id),
            Some(&state.plan_digest),
            action_id,
            plan_digest,
        )
        .then_some(state.execution_id)
    })
}

/// `reporting/<execution_id>.json` 里找同一动作 + 同一计划摘要的执行；
/// 上报信封旁文件（`*.report.json`）不是状态记录，必须跳过。
fn find_duplicate_reporting_execution(
    dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    scan_state_dir(dir, true, |path| {
        let state = reporting::load(path).ok()?;
        same_plan_target(
            Some(&state.action_id),
            Some(&state.plan_digest),
            action_id,
            plan_digest,
        )
        .then_some(state.execution_id)
    })
}

/// `history/<execution_id>.json` 里找同一动作 + 同一计划摘要的执行；
/// 历史记录的这两个字段可缺省，缺省即不命中。
fn find_duplicate_history_execution(
    dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    scan_state_dir(dir, false, |path| {
        let record = history::load(path).ok()?;
        let action = record.action_id.as_deref();
        same_plan_target(
            action,
            record.plan_digest.as_deref(),
            action_id,
            plan_digest,
        )
        .then_some(record.execution_id)
    })
}

pub async fn find_duplicate_execution_async(
    state_dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    let queue_path = execution_queue::path_for(state_dir);
    let queue = execution_queue::load_or_default_async(&queue_path).await?;
    if let Some(execution_id) = queued_duplicate_execution(&queue, action_id, plan_digest) {
        return Ok(Some(execution_id));
    }

    if let Some(execution_id) =
        find_duplicate_running_execution_async(&state_dir.join("running"), action_id, plan_digest)
            .await?
    {
        return Ok(Some(execution_id));
    }

    if let Some(execution_id) = find_duplicate_reporting_execution_async(
        &state_dir.join("reporting"),
        action_id,
        plan_digest,
    )
    .await?
    {
        return Ok(Some(execution_id));
    }

    find_duplicate_history_execution_async(&state_dir.join("history"), action_id, plan_digest).await
}

pub async fn lookup_queued_execution_async(
    state_dir: &Path,
    execution_id: &str,
) -> io::Result<Option<ExecutionQueueItem>> {
    let queue_path = execution_queue::path_for(state_dir);
    if !path_exists_async(&queue_path).await? {
        return Ok(None);
    }

    let queue = execution_queue::load_or_default_async(&queue_path).await?;
    Ok(queue
        .items
        .into_iter()
        .find(|item| item.execution_id == execution_id))
}

async fn find_duplicate_running_execution_async(
    dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    scan_state_dir_async(dir, false, |path| async move {
        let state = running::load_async(&path).await.ok()?;
        same_plan_target(
            Some(&state.action_id),
            Some(&state.plan_digest),
            action_id,
            plan_digest,
        )
        .then_some(state.execution_id)
    })
    .await
}

async fn find_duplicate_reporting_execution_async(
    dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    scan_state_dir_async(dir, true, |path| async move {
        let state = reporting::load_async(&path).await.ok()?;
        same_plan_target(
            Some(&state.action_id),
            Some(&state.plan_digest),
            action_id,
            plan_digest,
        )
        .then_some(state.execution_id)
    })
    .await
}

async fn find_duplicate_history_execution_async(
    dir: &Path,
    action_id: &str,
    plan_digest: &str,
) -> io::Result<Option<String>> {
    scan_state_dir_async(dir, false, |path| async move {
        let record = history::load_async(&path).await.ok()?;
        let action = record.action_id.as_deref();
        same_plan_target(
            action,
            record.plan_digest.as_deref(),
            action_id,
            plan_digest,
        )
        .then_some(record.execution_id)
    })
    .await
}

/// 队列里已排队的同一动作 + 同一计划摘要（队列项的两个字段都是必填）。
fn queued_duplicate_execution(
    queue: &execution_queue::ExecutionQueueState,
    action_id: &str,
    plan_digest: &str,
) -> Option<String> {
    queue
        .items
        .iter()
        .find(|item| item.action_id == action_id && item.plan_digest == plan_digest)
        .map(|item| item.execution_id.clone())
}

/// 逐条扫描状态目录，`probe` 返回 `Some` 即短路返回。
///
/// 判定口径与拆分前保持一致：只读 `*.json`；`skip_report_envelopes` 时跳过
/// `*.report.json` 上报信封；单个文件读取/解析失败视为「不命中」，
/// 只有目录本身读不了才向上抛错。
fn scan_state_dir<F>(
    dir: &Path,
    skip_report_envelopes: bool,
    mut probe: F,
) -> io::Result<Option<String>>
where
    F: FnMut(&Path) -> Option<String>,
{
    if !dir.exists() {
        return Ok(None);
    }

    for entry in fs::read_dir(dir)? {
        let path = entry?.path();
        if !is_candidate_state_file(&path, skip_report_envelopes) {
            continue;
        }
        if let Some(execution_id) = probe(&path) {
            return Ok(Some(execution_id));
        }
    }

    Ok(None)
}

/// [`scan_state_dir`] 的异步版本；`probe` 拿到文件路径后自己决定怎么读。
///
/// 这里 `probe` 拿的是 **owned `PathBuf`**（同步版是 `&Path`）：它返回的 future 不能借用
/// 循环体内的 `path`（那个引用活不到 `await` 之后），所以把所有权交出去。
async fn scan_state_dir_async<F, Fut>(
    dir: &Path,
    skip_report_envelopes: bool,
    mut probe: F,
) -> io::Result<Option<String>>
where
    F: FnMut(PathBuf) -> Fut,
    Fut: Future<Output = Option<String>>,
{
    if !path_exists_async(dir).await? {
        return Ok(None);
    }

    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        let path = entry.path();
        if !is_candidate_state_file(&path, skip_report_envelopes) {
            continue;
        }
        if let Some(execution_id) = probe(path).await {
            return Ok(Some(execution_id));
        }
    }

    Ok(None)
}

fn is_candidate_state_file(path: &Path, skip_report_envelopes: bool) -> bool {
    is_json_state_file(path) && !(skip_report_envelopes && is_report_envelope_file(path))
}

fn is_json_state_file(path: &Path) -> bool {
    path.extension().and_then(|ext| ext.to_str()) == Some("json")
}

fn is_report_envelope_file(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.ends_with(REPORT_ENVELOPE_SUFFIX))
}

/// 「同一动作 + 同一计划摘要」的判定口径（`actual` 的字段可缺省，缺省即不命中）。
fn same_plan_target(
    actual_action_id: Option<&str>,
    actual_plan_digest: Option<&str>,
    action_id: &str,
    plan_digest: &str,
) -> bool {
    actual_action_id == Some(action_id) && actual_plan_digest == Some(plan_digest)
}

/// `Ok(true)` 表示存在；不存在（含父目录不存在）返回 `Ok(false)`；其它错误照常上抛。
async fn path_exists_async(path: &Path) -> io::Result<bool> {
    match tokio::fs::metadata(path).await {
        Ok(_) => Ok(true),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
#[path = "execution_support_tests.rs"]
mod tests;
