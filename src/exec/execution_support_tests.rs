use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use wist_shared::paths::REPORT_ENVELOPE_SUFFIX;

use super::{
    find_duplicate_execution, find_duplicate_execution_async, is_candidate_state_file,
    lookup_queued_execution, lookup_queued_execution_async, same_plan_target,
};
use crate::state_store::execution_queue::{self, ExecutionQueueItem};
use crate::state_store::{history, reporting, running};

const ACTION_ID: &str = "act-1";
const PLAN_DIGEST: &str = "digest-1";

fn temp_state_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("duration")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-agentd-execution-support-{name}-{suffix}"));
    fs::create_dir_all(&dir).expect("create temp state dir");
    dir
}

fn queued_item(execution_id: &str) -> ExecutionQueueItem {
    ExecutionQueueItem::builder(
        execution_id.to_string(),
        ACTION_ID.to_string(),
        PLAN_DIGEST.to_string(),
        "req-1".to_string(),
        "2026-01-01T00:00:00Z".to_string(),
    )
    .build()
}

fn store_queue(state_dir: &Path, item: ExecutionQueueItem) {
    let mut queue = execution_queue::ExecutionQueueState::new();
    queue.enqueue(item);
    execution_queue::store(&execution_queue::path_for(state_dir), &queue).expect("store queue");
}

fn store_running(state_dir: &Path, execution_id: &str, action_id: &str, plan_digest: &str) {
    let state = running::RunningExecutionState::builder(
        execution_id.to_string(),
        action_id.to_string(),
        "running".to_string(),
        "/tmp/workdir".to_string(),
    )
    .plan_digest(plan_digest.to_string())
    .request_id("req-1".to_string())
    .build();
    let path = running::path_for(state_dir, execution_id);
    fs::create_dir_all(path.parent().expect("running dir")).expect("create running dir");
    running::store(&path, &state).expect("store running state");
}

fn reporting_state(
    execution_id: &str,
    action_id: &str,
    plan_digest: &str,
) -> reporting::ReportingState {
    reporting::ReportingState::new(
        execution_id.to_string(),
        action_id.to_string(),
        plan_digest.to_string(),
        "req-1".to_string(),
        "succeeded".to_string(),
        "/tmp/result.json".to_string(),
        None,
        None,
        None,
        0,
        None,
        None,
    )
}

fn store_reporting(state_dir: &Path, execution_id: &str, action_id: &str, plan_digest: &str) {
    let path = reporting::path_for(state_dir, execution_id);
    fs::create_dir_all(path.parent().expect("reporting dir")).expect("create reporting dir");
    reporting::store(
        &path,
        &reporting_state(execution_id, action_id, plan_digest),
    )
    .expect("store reporting state");
}

/// 上报信封旁文件：文件名以 `.report.json` 结尾，内容与状态记录同形 —— 扫描时必须跳过。
fn store_report_envelope(state_dir: &Path, execution_id: &str, action_id: &str, plan_digest: &str) {
    let dir = state_dir.join("reporting");
    fs::create_dir_all(&dir).expect("create reporting dir");
    let path = dir.join(format!("{execution_id}{REPORT_ENVELOPE_SUFFIX}"));
    reporting::store(
        &path,
        &reporting_state(execution_id, action_id, plan_digest),
    )
    .expect("store report envelope");
}

fn store_history(
    state_dir: &Path,
    execution_id: &str,
    action_id: Option<&str>,
    plan_digest: Option<&str>,
) {
    let record = history::ExecutionHistoryRecord::quarantined(
        execution_id.to_string(),
        action_id.map(str::to_string),
        plan_digest.map(str::to_string),
        None,
        "detail".to_string(),
    );
    let path = history::path_for(state_dir, execution_id);
    fs::create_dir_all(path.parent().expect("history dir")).expect("create history dir");
    history::store(&path, &record).expect("store history record");
}

fn store_file(state_dir: &Path, name: &str, contents: &str) {
    let dir = state_dir.join("running");
    fs::create_dir_all(&dir).expect("create running dir");
    fs::write(dir.join(name), contents).expect("write fixture file");
}

#[test]
fn find_duplicate_execution_prefers_the_queue_over_later_stores() {
    let state_dir = temp_state_dir("queue-precedence");
    store_queue(&state_dir, queued_item("exec-queued"));
    store_running(&state_dir, "exec-running", ACTION_ID, PLAN_DIGEST);

    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-queued".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn find_duplicate_execution_matches_running_state_identity() {
    let state_dir = temp_state_dir("running-identity");
    store_running(&state_dir, "exec-other-digest", ACTION_ID, "digest-other");

    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        None
    );

    store_running(&state_dir, "exec-running", ACTION_ID, PLAN_DIGEST);
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-running".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn find_duplicate_execution_skips_report_envelope_files() {
    let state_dir = temp_state_dir("reporting-envelope");
    store_report_envelope(&state_dir, "exec-envelope", ACTION_ID, PLAN_DIGEST);

    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        None
    );

    // 真正的上报状态记录仍然命中：信封文件不参与判定。
    store_reporting(&state_dir, "exec-reporting", ACTION_ID, PLAN_DIGEST);
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-reporting".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn find_duplicate_execution_requires_full_identity_in_history() {
    let state_dir = temp_state_dir("history-identity");
    store_history(&state_dir, "exec-partial", Some(ACTION_ID), None);

    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        None
    );

    store_history(
        &state_dir,
        "exec-history",
        Some(ACTION_ID),
        Some(PLAN_DIGEST),
    );
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-history".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn find_duplicate_execution_ignores_unreadable_state_files() {
    let state_dir = temp_state_dir("unreadable");
    store_file(&state_dir, "broken.json", "{not json}");
    store_file(&state_dir, "notes.txt", "ignored");

    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        None
    );

    store_running(&state_dir, "exec-running", ACTION_ID, PLAN_DIGEST);
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-running".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn find_duplicate_execution_reports_none_for_missing_state_dir() {
    let state_dir = temp_state_dir("missing-parent").join("absent");

    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        None
    );

    let _ = fs::remove_dir_all(state_dir.parent().expect("parent"));
}

#[test]
fn find_duplicate_execution_prefers_running_over_reporting_over_history() {
    let state_dir = temp_state_dir("store-precedence");
    store_history(
        &state_dir,
        "exec-history",
        Some(ACTION_ID),
        Some(PLAN_DIGEST),
    );
    store_reporting(&state_dir, "exec-reporting", ACTION_ID, PLAN_DIGEST);
    store_running(&state_dir, "exec-running", ACTION_ID, PLAN_DIGEST);

    // 三层都存在时先报 running（能重接的那个状态）。
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-running".to_string())
    );

    fs::remove_file(running::path_for(&state_dir, "exec-running")).expect("remove running");
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-reporting".to_string())
    );

    fs::remove_file(reporting::path_for(&state_dir, "exec-reporting")).expect("remove reporting");
    assert_eq!(
        find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("scan state"),
        Some("exec-history".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn find_duplicate_execution_async_agrees_with_the_sync_scan() {
    let state_dir = temp_state_dir("async-parity");
    store_queue(&state_dir, queued_item("exec-queued"));
    store_running(&state_dir, "exec-running", ACTION_ID, PLAN_DIGEST);
    store_reporting(&state_dir, "exec-reporting", ACTION_ID, PLAN_DIGEST);
    store_report_envelope(&state_dir, "exec-envelope", ACTION_ID, PLAN_DIGEST);

    let sync = find_duplicate_execution(&state_dir, ACTION_ID, PLAN_DIGEST).expect("sync scan");
    let asynchronous = find_duplicate_execution_async(&state_dir, ACTION_ID, PLAN_DIGEST)
        .await
        .expect("async scan");

    assert_eq!(sync, asynchronous);
    assert_eq!(sync, Some("exec-queued".to_string()));

    let _ = fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn find_duplicate_execution_async_skips_report_envelope_files() {
    let state_dir = temp_state_dir("async-envelope");
    store_report_envelope(&state_dir, "exec-envelope", ACTION_ID, PLAN_DIGEST);

    assert_eq!(
        find_duplicate_execution_async(&state_dir, ACTION_ID, PLAN_DIGEST)
            .await
            .expect("async scan"),
        None
    );

    store_reporting(&state_dir, "exec-reporting", ACTION_ID, PLAN_DIGEST);
    assert_eq!(
        find_duplicate_execution_async(&state_dir, ACTION_ID, PLAN_DIGEST)
            .await
            .expect("async scan"),
        Some("exec-reporting".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn find_duplicate_execution_async_requires_full_identity_in_history() {
    let state_dir = temp_state_dir("async-history");
    // 与同步版同一个偏门形状：`action_id` 有、`plan_digest` 缺 —— 缺一半也不算命中。
    store_history(&state_dir, "exec-partial", Some(ACTION_ID), None);
    store_history(
        &state_dir,
        "exec-history",
        Some(ACTION_ID),
        Some(PLAN_DIGEST),
    );

    assert_eq!(
        find_duplicate_execution_async(&state_dir, ACTION_ID, PLAN_DIGEST)
            .await
            .expect("async scan"),
        Some("exec-history".to_string())
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn lookup_queued_execution_reports_none_without_a_queue_file() {
    let state_dir = temp_state_dir("lookup-missing-queue");

    assert!(
        lookup_queued_execution(&state_dir, "exec-queued")
            .expect("sync lookup")
            .is_none()
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[tokio::test]
async fn lookup_queued_execution_finds_the_same_item_sync_and_async() {
    let state_dir = temp_state_dir("lookup-queue");
    store_queue(&state_dir, queued_item("exec-queued"));

    let sync = lookup_queued_execution(&state_dir, "exec-queued")
        .expect("sync lookup")
        .expect("queued item");
    let asynchronous = lookup_queued_execution_async(&state_dir, "exec-queued")
        .await
        .expect("async lookup")
        .expect("queued item");

    assert_eq!(sync, asynchronous);
    assert_eq!(sync.action_id, ACTION_ID);
    assert!(
        lookup_queued_execution_async(&state_dir, "exec-absent")
            .await
            .expect("async lookup")
            .is_none()
    );

    let _ = fs::remove_dir_all(&state_dir);
}

#[test]
fn candidate_state_files_exclude_report_envelopes_only_when_asked() {
    let state = Path::new("exec-1.json");
    let envelope = Path::new("exec-1.report.json");
    let other = Path::new("exec-1.txt");

    assert!(is_candidate_state_file(state, false));
    assert!(is_candidate_state_file(state, true));
    assert!(is_candidate_state_file(envelope, false));
    assert!(!is_candidate_state_file(envelope, true));
    assert!(!is_candidate_state_file(other, false));
}

#[test]
fn same_plan_target_requires_both_identity_fields() {
    assert!(same_plan_target(
        Some(ACTION_ID),
        Some(PLAN_DIGEST),
        ACTION_ID,
        PLAN_DIGEST
    ));
    assert!(!same_plan_target(
        Some(ACTION_ID),
        None,
        ACTION_ID,
        PLAN_DIGEST
    ));
    assert!(!same_plan_target(None, None, ACTION_ID, PLAN_DIGEST));
    assert!(!same_plan_target(
        Some(ACTION_ID),
        Some("digest-other"),
        ACTION_ID,
        PLAN_DIGEST
    ));
}
