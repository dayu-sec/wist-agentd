use std::fs;

use super::{
    FileInputProcessor, block_on, config, log_checkpoints, read_json, read_output_records, temp_dir,
};
use crate::telemetry::logs::files::LogFileHandles;
use crate::telemetry::warp_parse::FileRecordSink;

/// 跨 tick 共用一份句柄表时，**rename 轮转**仍然正确：旧文件的尾巴要排空、新文件要接上。
///
/// 为什么单拎一条：旧的轮转用例每次都新建处理器（= 每批重开文件），拿不到“句柄还指着
/// 上一个 inode”的情形；而那正是持句柄后最需要用 `stat` 识别出来的事。
#[test]
fn a_shared_handle_set_drains_the_old_tail_across_a_rotation() {
    let root = temp_dir("rotate-shared-handles");
    let source_path = root.join("app.log");
    let rotated_path = root.join("app.log.1");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "first\n").expect("write first log");

    let mut handles = LogFileHandles::new();
    let mut next_seq = 0;
    let mut first = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    block_on(first.process_once_with_handles_async(&mut next_seq, &mut handles))
        .expect("first process");
    assert_eq!(handles.open_count(), 1);

    fs::rename(&source_path, &rotated_path).expect("rotate file");
    fs::write(&rotated_path, "first\nold-tail\n").expect("append old tail");
    fs::write(&source_path, "second\n").expect("write new active log");
    let mut second = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    let outcome = block_on(second.process_once_with_handles_async(&mut next_seq, &mut handles))
        .expect("second process");
    let records = read_output_records(&output_path);

    assert!(outcome.rotated);
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.as_str())
            .collect::<Vec<_>>(),
        vec!["first\n", "old-tail\n", "second\n"],
        "旧文件的尾巴不能因为句柄换了而丢"
    );
    assert_eq!(
        handles.open_count(),
        3,
        "轮转：新文件 1 次 + 被排空的旧文件 1 次（不是每批都重开）"
    );
}

/// 跨 tick 共用句柄表时，**copytruncate** 仍然靠 checkpoint 探针识别（探针从同一句柄读）。
#[test]
fn a_shared_handle_set_detects_copytruncate_through_the_handle_probe() {
    let root = temp_dir("copytruncate-shared-handles");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    let prefix = "1234567890abcdef1234567890abcdef";
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, format!("{prefix}\nold-tail\n")).expect("write log");

    let mut handles = LogFileHandles::new();
    let mut next_seq = 0;
    let mut first = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    let first_outcome =
        block_on(first.process_once_with_handles_async(&mut next_seq, &mut handles))
            .expect("first process");
    assert_eq!(first_outcome.records_processed, 2);

    // copytruncate：同一个 inode 被截断后重写（前缀相同、总长度更大）。
    fs::write(&source_path, format!("{prefix}\nnew-tail\nmore\n")).expect("rewrite log");
    let mut second = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    let second_outcome =
        block_on(second.process_once_with_handles_async(&mut next_seq, &mut handles))
            .expect("second process");
    let records = read_output_records(&output_path);

    assert!(second_outcome.truncated, "探针变了 = 被截断过，要从 0 重读");
    assert_eq!(second_outcome.records_processed, 3);
    assert_eq!(records.len(), 5);
    assert_eq!(records[2].body, format!("{prefix}\n"));
    assert_eq!(records[3].body, "new-tail\n");
    assert_eq!(records[4].body, "more\n");
    assert_eq!(
        handles.open_count(),
        1,
        "探针必须从持有句柄读：为了一次比对再 open 一次，就是把审计反馈环又接回去"
    );
}

#[test]
fn copytruncate_with_same_prefix_restarts_from_zero_when_checkpoint_probe_changes() {
    let root = temp_dir("copytruncate-same-prefix");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    let prefix = "1234567890abcdef1234567890abcdef";
    let original = format!("{prefix}\nold-tail\n");
    let rewritten = format!("{prefix}\nnew-tail\nmore\n");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, &original).expect("write log");

    let mut first = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    let first_outcome = first.process_once().expect("first process");
    assert_eq!(first_outcome.records_processed, 2);

    fs::write(&source_path, &rewritten).expect("rewrite log");
    let mut second = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    let second_outcome = second.process_once().expect("second process");
    let records = read_output_records(&output_path);

    assert!(second_outcome.truncated);
    assert_eq!(second_outcome.records_processed, 3);
    assert_eq!(records.len(), 5);
    assert_eq!(records[2].body, format!("{prefix}\n"));
    assert_eq!(records[3].body, "new-tail\n");
    assert_eq!(records[4].body, "more\n");
}

#[test]
fn rotate_keeps_draining_old_file_tail_and_tracks_new_file_separately() {
    let root = temp_dir("rotate");
    let source_path = root.join("app.log");
    let rotated_path = root.join("app.log.1");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "first\n").expect("write first log");

    let mut first = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    first.process_once().expect("first process");

    fs::rename(&source_path, &rotated_path).expect("rotate file");
    fs::write(&rotated_path, "first\nold-tail\n").expect("append old tail");
    fs::write(&source_path, "second\n").expect("write new active log");
    let mut second = FileInputProcessor::new(
        config(&root, &source_path),
        FileRecordSink::new(output_path.clone()),
    );
    let outcome = second.process_once().expect("second process");
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read checkpoint");
    let records = read_output_records(&output_path);
    let source_path_string = source_path.display().to_string();
    let rotated_path_string = rotated_path.display().to_string();
    let active = state
        .files
        .iter()
        .find(|entry| entry.path == source_path_string)
        .expect("active checkpoint");
    let rotated = state
        .files
        .iter()
        .find(|entry| entry.path == rotated_path_string)
        .expect("rotated checkpoint");

    assert!(outcome.rotated);
    assert!(!outcome.truncated);
    assert_eq!(outcome.records_processed, 2);
    assert_eq!(records.len(), 3);
    assert_eq!(records[0].body, "first\n");
    assert_eq!(records[1].body, "old-tail\n");
    assert_eq!(records[2].body, "second\n");
    assert_eq!(state.files.len(), 2);
    assert_eq!(active.checkpoint_offset, "second\n".len() as u64);
    assert_eq!(rotated.checkpoint_offset, "first\nold-tail\n".len() as u64);
    assert_eq!(
        active.rotated_from_path.as_deref(),
        Some(source_path_string.as_str())
    );
    assert!(!active.file_id.contains("path:"));
    assert!(!rotated.file_id.contains("path:"));
    assert_ne!(active.file_id, rotated.file_id);
}
