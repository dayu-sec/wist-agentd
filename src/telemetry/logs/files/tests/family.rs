use std::collections::BTreeSet;
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

use super::super::prune_family_state;
use super::{config, log_checkpoints, read_json, read_output_records, temp_dir};
use crate::state_store::log_checkpoint_state::{
    LogCheckpointState, PendingMultilineState, TrackedFileCheckpoint,
};
use crate::telemetry::logs::files::file_reader::ReadLimits;
use crate::telemetry::logs::files::file_watcher::StartupPosition;
use crate::telemetry::logs::files::{FileFamilyProcessor, FileInputConfig};
use crate::telemetry::logs::multiline::MultilineMode;
use crate::telemetry::warp_parse::FileRecordSink;
use wist_shared::fs::write_json_atomic;
use wist_shared::records::{self, Record};

fn family_config(root: &Path, pattern: &Path) -> FileInputConfig {
    let mut cfg = config(root, pattern);
    // 测试里每轮都要重新扫目录；生产默认 15s（见 DEFAULT_RESCAN_INTERVAL_MS）。
    cfg.rescan_interval_ms = 0;
    cfg
}

fn output_path(root: &Path) -> PathBuf {
    let log_dir = root.join("log");
    fs::create_dir_all(&log_dir).expect("create log dir");
    log_dir.join("records.ndjson")
}

fn checkpoint_path(root: &Path) -> PathBuf {
    log_checkpoints::path_for(&root.join("state"), "input-app")
}

fn read_state(root: &Path) -> LogCheckpointState {
    read_json(&checkpoint_path(root)).expect("read checkpoint")
}

#[test]
fn processes_all_matched_files_with_per_file_checkpoints() {
    let root = temp_dir("family-all");
    fs::create_dir_all(root.join("state")).expect("create state");
    let a = root.join("a.log");
    let b = root.join("b.log");
    fs::write(&a, "a1\na2\n").expect("write a");
    fs::write(&b, "b1\n").expect("write b");
    fs::write(root.join("ignore.txt"), "x\n").expect("write ignore");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut processor = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = processor.process_once().expect("process");

    let records = read_output_records(&output);
    let state = read_state(&root);
    let mut sources: Vec<&str> = records
        .iter()
        .map(|record| record.source_path.as_str())
        .collect();
    sources.sort();
    sources.dedup();

    assert_eq!(outcome.records_processed, 3);
    assert_eq!(records.len(), 3);
    assert_eq!(
        sources,
        vec![a.display().to_string(), b.display().to_string()]
    );
    assert_eq!(state.files.len(), 2);
    assert_eq!(
        state
            .files
            .iter()
            .find(|entry| entry.path == a.display().to_string())
            .expect("a checkpoint")
            .checkpoint_offset,
        "a1\na2\n".len() as u64
    );
    assert_eq!(
        state
            .files
            .iter()
            .find(|entry| entry.path == b.display().to_string())
            .expect("b checkpoint")
            .checkpoint_offset,
        "b1\n".len() as u64
    );
}

#[test]
fn first_scan_tail_skips_existing_content_then_reads_new_lines() {
    let root = temp_dir("family-first-tail");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("a.log");
    fs::write(&file, "old\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Tail;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    let first_outcome = first.process_once().expect("first");
    assert_eq!(first_outcome.records_processed, 0);
    assert_eq!(
        read_state(&root).files[0].checkpoint_offset,
        "old\n".len() as u64
    );

    fs::write(&file, "old\nnew\n").expect("append");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let second_outcome = second.process_once().expect("second");
    let records = read_output_records(&output);
    assert_eq!(second_outcome.records_processed, 1);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "new\n");
}

#[test]
fn a_file_discovered_after_the_first_scan_is_read_from_head() {
    // D10：重启 / 运行中新出现的文件从 head 读，停机期间的日志不能整段丢。
    let root = temp_dir("family-new-head");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::write(root.join("a.log"), "a-old\n").expect("write a");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Tail;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    first.process_once().expect("first");
    assert_eq!(read_state(&root).files.len(), 1);

    // 模拟“停机期间新建的文件”：它没有 checkpoint，但 input 已经跑过。
    fs::write(root.join("b.log"), "b-existing\n").expect("write b");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    let records = read_output_records(&output);
    assert_eq!(outcome.records_processed, 1);
    assert_eq!(records.last().expect("record").body, "b-existing\n");
}

#[cfg(unix)]
#[test]
fn symlink_rotation_drains_real_tail_and_follows_new_file() {
    let root = temp_dir("family-symlink-rotate");
    fs::create_dir_all(root.join("state")).expect("create state");
    let pods = root.join("pods");
    let containers = root.join("containers");
    fs::create_dir_all(&pods).expect("create pods");
    fs::create_dir_all(&containers).expect("create containers");
    let real = pods.join("0.log");
    let rotated = pods.join("0.log.1");
    fs::write(&real, "first\n").expect("write real");
    let link = containers.join("app.log");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &containers.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    first.process_once().expect("first");

    // 真实路径要落盘：轮转发生在 pods/，不是 containers/。
    let state = read_state(&root);
    let entry = state
        .files
        .iter()
        .find(|entry| entry.path == link.display().to_string())
        .expect("symlink checkpoint");
    // `real_path` 是 **canonicalize 之后**的路径：macOS 上 `/var` 是 `/private/var` 的软链，
    // 断言必须比真实路径，不能比 `temp_dir()` 拼出来的字面量。
    assert_eq!(
        entry.real_path,
        fs::canonicalize(&real)
            .expect("canonicalize real")
            .display()
            .to_string()
    );

    // kubelet 风格的轮转：真实文件改名，symlink 仍指向原路径（现在指向新文件）。
    fs::rename(&real, &rotated).expect("rotate real");
    fs::write(&rotated, "first\nold-tail\n").expect("append old tail");
    fs::write(&real, "second\n").expect("write new active");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");

    let records = read_output_records(&output);
    assert!(outcome.rotated);
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.as_str())
            .collect::<Vec<_>>(),
        vec!["first\n", "old-tail\n", "second\n"]
    );
    // 旧文件读完即释放；活动文件仍按 symlink 路径记账。
    let state = read_state(&root);
    let active = state
        .files
        .iter()
        .find(|entry| entry.path == link.display().to_string())
        .expect("active checkpoint");
    assert_eq!(active.checkpoint_offset, "second\n".len() as u64);
}

#[test]
fn per_file_multiline_pending_does_not_cross_files() {
    let root = temp_dir("family-multiline");
    fs::create_dir_all(root.join("state")).expect("create state");
    let a = root.join("a.log");
    let b = root.join("b.log");
    fs::write(&a, "a1\n  a-cont\n").expect("write a");
    fs::write(&b, "b1\n  b-cont\n").expect("write b");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    first.process_once().expect("first");

    // 两个文件各自挂着一个未封口块，不能共用一份。
    let state = read_state(&root);
    assert_eq!(state.files.len(), 2);
    assert!(
        state
            .files
            .iter()
            .all(|entry| entry.pending_multiline.is_some())
    );

    // 各追加一条非缩进行：两个块分别封口，不能粘成一条。
    fs::write(&a, "a1\n  a-cont\na-next\n").expect("append a");
    fs::write(&b, "b1\n  b-cont\nb-next\n").expect("append b");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    let records = read_output_records(&output);
    let mut bodies: Vec<&str> = records.iter().map(|record| record.body.as_str()).collect();
    bodies.sort();

    assert_eq!(outcome.records_processed, 2);
    assert_eq!(bodies, vec!["a1\n  a-cont\n", "b1\n  b-cont\n"]);
}

#[test]
fn max_new_files_caps_discovery_per_tick() {
    let root = temp_dir("family-max-new");
    fs::create_dir_all(root.join("state")).expect("create state");
    for index in 0..5 {
        fs::write(root.join(format!("{index}.log")), "x\n").expect("write");
    }
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.max_new_files = 2;
    cfg.max_files = 10;

    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 2);
    assert_eq!(read_state(&root).files.len(), 2);

    let mut second = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 2);
    assert_eq!(read_state(&root).files.len(), 4);

    let mut third = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(third.process_once().expect("third").records_processed, 1);
    assert_eq!(read_state(&root).files.len(), 5);
}

#[test]
fn max_files_keeps_tracked_files_and_refuses_new_ones() {
    let root = temp_dir("family-max-files");
    fs::create_dir_all(root.join("state")).expect("create state");
    for index in 0..3 {
        fs::write(root.join(format!("{index}.log")), "x\n").expect("write");
    }
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.max_files = 2;
    cfg.max_new_files = 10;

    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    let first_outcome = first.process_once().expect("first");
    assert_eq!(first_outcome.records_processed, 2);
    // 触顶要如实报出来：拒绝了多少、当前跟踪多少、上限多少。
    let capacity = first_outcome.capacity.as_ref().expect("capacity report");
    assert_eq!(capacity.max_files, 2);
    assert_eq!(capacity.tracked, 2);
    assert_eq!(capacity.refused, 1);

    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let second_outcome = second.process_once().expect("second");
    assert_eq!(second_outcome.records_processed, 0);
    assert_eq!(
        second_outcome
            .capacity
            .as_ref()
            .expect("still over the cap")
            .refused,
        1
    );
    assert_eq!(read_state(&root).files.len(), 2);
}

#[test]
fn no_match_is_not_an_error() {
    let root = temp_dir("family-no-match");
    fs::create_dir_all(root.join("state")).expect("create state");
    let output = output_path(&root);

    let cfg = family_config(&root, &root.join("*.log"));
    let mut processor = FileFamilyProcessor::new(cfg, FileRecordSink::new(output));
    let outcome = processor.process_once().expect("must not fail");
    assert_eq!(outcome.records_processed, 0);
    assert!(read_state(&root).files.is_empty());
}

#[test]
fn a_directory_target_reads_direct_files() {
    let root = temp_dir("family-dir");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("nested")).expect("create nested");
    fs::write(root.join("a.log"), "a\n").expect("write a");
    fs::write(root.join("nested").join("b.log"), "b\n").expect("write b");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root);
    cfg.startup_position = StartupPosition::Head;
    let mut processor = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = processor.process_once().expect("process");

    assert_eq!(outcome.records_processed, 1);
    assert_eq!(read_output_records(&output)[0].body, "a\n");
}

#[test]
fn a_deleted_tracked_file_is_skipped_not_failed() {
    let root = temp_dir("family-deleted");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("a.log");
    fs::write(&file, "a\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    first.process_once().expect("first");

    fs::remove_file(&file).expect("remove");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output));
    let outcome = second.process_once().expect("deleted file must not fail");
    assert_eq!(outcome.records_processed, 0);
}

#[test]
fn exclude_globs_keep_matching_files_out_of_the_family() {
    let root = temp_dir("family-exclude");
    fs::create_dir_all(root.join("state")).expect("create state");
    let a = root.join("a.log");
    let b = root.join("b.log");
    let skipped = root.join("skip-1.log");
    fs::write(&a, "a\n").expect("write a");
    fs::write(&b, "b\n").expect("write b");
    fs::write(&skipped, "skipped\n").expect("write skipped");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.exclude_globs = vec![format!("{}/skip-*.log", root.display())];

    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    let outcome = first.process_once().expect("first");
    assert_eq!(outcome.records_processed, 2);

    let state = read_state(&root);
    let mut tracked: Vec<&str> = state
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    tracked.sort();
    assert_eq!(
        tracked,
        vec![a.display().to_string(), b.display().to_string()]
    );

    // 被排除的文件不仅本轮不读，也不会在后续轮次里“补”回来。
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 0);
    let bodies: Vec<String> = read_output_records(&output)
        .into_iter()
        .map(|record| record.body)
        .collect();
    assert!(!bodies.iter().any(|body| body == "skipped\n"), "{bodies:?}");
}

#[test]
fn an_input_level_pending_block_is_migrated_onto_its_file() {
    // 旧状态（单文件 input）把未封口块存在 input 级；文件族接管后要把它接到对应文件，
    // 否则那条块会在第一次 `commit_family_state` 里被清掉。
    let root = temp_dir("family-migrate-pending");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("a.log");
    fs::write(&file, "a1\n  a-cont\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 0);

    // 把逐文件的块搬回 input 级，模拟旧版 checkpoint 的存储形式。
    let mut state = read_state(&root);
    let pending = state
        .files
        .iter_mut()
        .find(|entry| entry.path == file.display().to_string())
        .expect("file checkpoint")
        .pending_multiline
        .take()
        .expect("pending block");
    state.pending_multiline = Some(pending);
    write_json_atomic(&checkpoint_path(&root), &state).expect("write legacy state");

    fs::write(&file, "a1\n  a-cont\na-next\n").expect("append");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    let records = read_output_records(&output);

    assert_eq!(outcome.records_processed, 1);
    assert_eq!(records[0].body, "a1\n  a-cont\n");
    // 迁移后 input 级不再持有块；新的未封口块挂回文件。
    let state = read_state(&root);
    assert!(state.pending_multiline.is_none());
    assert!(
        state
            .files
            .iter()
            .find(|entry| entry.path == file.display().to_string())
            .expect("file checkpoint")
            .pending_multiline
            .is_some()
    );
}

#[test]
fn the_read_budget_is_shared_across_files_in_one_tick() {
    // 本轮预算耗尽时，后面的文件一轮不读、也**不能**留下 offset=0 的 checkpoint，
    // 否则那些文件的内容会被当成“已读过”永久跳过。
    let root = temp_dir("family-budget");
    fs::create_dir_all(root.join("state")).expect("create state");
    for index in 0..3 {
        fs::write(root.join(format!("{index}.log")), "x\n").expect("write");
    }
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.read_limits = ReadLimits::new(1_048_576, 4_194_304, 2);

    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 2);
    let state = read_state(&root);
    assert_eq!(state.files.len(), 2);
    assert!(
        !state
            .files
            .iter()
            .any(|entry| entry.path == root.join("2.log").display().to_string()),
        "预算耗尽的文件不得留下 checkpoint"
    );

    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 1);
    let state = read_state(&root);
    assert_eq!(state.files.len(), 3);
    assert_eq!(
        state
            .files
            .iter()
            .find(|entry| entry.path == root.join("2.log").display().to_string())
            .expect("2.log checkpoint")
            .checkpoint_offset,
        "x\n".len() as u64
    );
}

#[test]
fn a_file_appearing_after_an_empty_first_scan_is_read_from_head() {
    // 首次扫描时目录还是空的（新装的机器、容器目录还没建）：那不是「首装 tail」的场景，
    // 之后出现的文件属于 D10 的「运行中/重启后新文件」，要从 head 读。
    let root = temp_dir("family-empty-first-scan");
    fs::create_dir_all(root.join("state")).expect("create state");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Tail;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 0);

    fs::write(root.join("a.log"), "existing\n").expect("write");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 1);
    assert_eq!(read_output_records(&output)[0].body, "existing\n");
}

#[test]
fn an_idle_tick_does_not_rewrite_the_checkpoint_file() {
    // 未被扫描、也没有新行的 tick 不应该重写状态盘：
    // 512 个文件的全量状态每 3s 重写一次是数 GB/天的写放大。
    let root = temp_dir("family-idle-no-rewrite");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::write(root.join("a.log"), "a1\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    // 不让第 2/3 个 tick 重扫：只有「扫描」本身才会改状态。
    cfg.rescan_interval_ms = 60_000;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 1);
    let after_first = fs::read(checkpoint_path(&root)).expect("read checkpoint");

    let mut second = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 0);
    let after_second = fs::read(checkpoint_path(&root)).expect("read checkpoint");
    assert_eq!(after_first, after_second, "空闲 tick 不应重写 checkpoint");

    // 真的追加了内容才写。
    fs::write(root.join("a.log"), "a1\na2\n").expect("append");
    let mut third = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(third.process_once().expect("third").records_processed, 1);
    let after_third = fs::read(checkpoint_path(&root)).expect("read checkpoint");
    assert_ne!(after_second, after_third, "有进展就要落盘");
}

#[test]
fn a_rotation_while_stopped_is_drained_on_the_next_start() {
    // 停机期间发生轮转：checkpoint 指着旧 inode。重启后必须先按真实路径把旧文件尾巴读完。
    let root = temp_dir("family-rotation-while-stopped");
    fs::create_dir_all(root.join("state")).expect("create state");
    let active = root.join("app.log");
    let rotated = root.join("app.log.1");
    fs::write(&active, "first\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("app.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 1);

    // 停机期间：改名 + 新主文件（文件名不匹配 glob，只有 app.log 在跟踪集里）。
    fs::rename(&active, &rotated).expect("rotate");
    fs::write(&rotated, "first\nold-tail\n").expect("write old tail");
    fs::write(&active, "second\n").expect("write new active");

    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    assert!(outcome.rotated);
    let bodies: Vec<String> = read_output_records(&output)
        .into_iter()
        .map(|record| record.body)
        .collect();
    assert_eq!(bodies, vec!["first\n", "old-tail\n", "second\n"]);
}

#[test]
fn a_truncated_file_flushes_its_pending_block_before_reading_from_zero() {
    // copytruncate：文件被截断后同一个 inode 从头写。旧块要先封口，再从 0 读新内容。
    // 前 32 字节保持不变（= 指纹相同），尾部变化靠 checkpoint probe 判定为「截断」。
    const PREFIX: &str = "0123456789abcdef0123456789abcde\n"; // 32 字节
    let root = temp_dir("family-truncate");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("a.log");
    fs::write(&file, format!("{PREFIX}  cont\n")).expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 0);

    fs::write(&file, format!("{PREFIX}  cont2\n")).expect("truncate and rewrite");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    assert!(outcome.truncated, "{outcome:?}");
    // 旧块封口交出去；新内容成为新的未封口块。
    let records = read_output_records(&output);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, format!("{PREFIX}  cont\n"));
    let state = read_state(&root);
    assert_eq!(state.files.len(), 1);
    assert_eq!(
        state.files[0]
            .pending_multiline
            .as_ref()
            .expect("new pending")
            .record
            .body,
        format!("{PREFIX}  cont2\n")
    );
}

#[test]
fn an_orphan_input_level_pending_block_is_flushed_not_dropped() {
    // 旧状态里 input 级块指向的文件条目已经不在（被清过）：不能只是把它丢掉，
    // 否则那段日志会随着本轮 `commit_family_state` 的清理无声消失。
    let root = temp_dir("family-orphan-pending");
    fs::create_dir_all(root.join("state")).expect("create state");
    let output = output_path(&root);

    let mut state = LogCheckpointState::new("input-app".to_string(), "2026-04-13T00:00:00Z".into());
    state.pending_multiline = Some(PendingMultilineState {
        source_path: root.join("gone.log").display().to_string(),
        last_updated_at: "2026-04-13T00:00:00Z".to_string(),
        record: Record {
            body: "orphan\n".to_string(),
            start_offset: 0,
            end_offset: 7,
            lines: 1,
            completion: records::Completion::Boundary,
        },
    });
    write_json_atomic(&checkpoint_path(&root), &state).expect("write legacy state");

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut processor = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = processor.process_once().expect("process");

    assert_eq!(outcome.records_processed, 1);
    let records = read_output_records(&output);
    assert_eq!(records[0].body, "orphan\n");
    assert_eq!(
        records[0].source_path,
        root.join("gone.log").display().to_string()
    );
    let state = read_state(&root);
    assert!(state.pending_multiline.is_none());
}

#[cfg(unix)]
#[test]
fn one_unreadable_file_does_not_block_the_rest_of_the_family() {
    // 一个 000 权限的文件读不了，不能把同目录其它文件一起卡住：
    // 本轮读写得到的那些照常交付 + 提交 checkpoint，错误在最后报上去。
    let root = temp_dir("family-unreadable");
    fs::create_dir_all(root.join("state")).expect("create state");
    let blocked = root.join("a.log");
    let readable = root.join("b.log");
    fs::write(&blocked, "blocked\n").expect("write blocked");
    fs::write(&readable, "readable\n").expect("write readable");
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o000)).expect("chmod 000");
    if fs::read(&blocked).is_ok() {
        // 以 root 等特权运行时 0o000 仍可读，跳过该用例。
        fs::set_permissions(&blocked, fs::Permissions::from_mode(0o644)).ok();
        return;
    }
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    let err = first.process_once().expect_err("unreadable file must fail");
    assert_eq!(err.kind(), std::io::ErrorKind::PermissionDenied);

    // 可读的那个已经交付并提交了 checkpoint。
    let records = read_output_records(&output);
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.as_str())
            .collect::<Vec<_>>(),
        vec!["readable\n"]
    );
    let state = read_state(&root);
    let tracked: Vec<&str> = state
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(tracked, vec![readable.display().to_string()]);

    // 修好权限后，两个文件都能读，且可读的那个不会重放。
    fs::set_permissions(&blocked, fs::Permissions::from_mode(0o644)).expect("chmod 644");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 1);
    assert_eq!(read_output_records(&output).len(), 2);
}

#[cfg(unix)]
#[test]
fn a_symlink_alias_of_a_collected_file_is_not_read_twice() {
    // 目录里同时有真实文件与指向它的 symlink：两者是**同一批字节**，
    // 各读一遍就是同一批行上送两次。按真实路径去重，保留先遇到的那条。
    let root = temp_dir("family-alias");
    fs::create_dir_all(root.join("state")).expect("create state");
    let real = root.join("a.log");
    let alias = root.join("b.log");
    fs::write(&real, "only-once\n").expect("write real");
    std::os::unix::fs::symlink(&real, &alias).expect("symlink");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 1);

    let state = read_state(&root);
    assert_eq!(state.files.len(), 1, "{:?}", state.files);

    // 后续轮次也不应该把别名补进来。
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 0);
    assert_eq!(read_output_records(&output).len(), 1);
}

#[test]
fn a_deleted_file_flushes_its_pending_block_instead_of_keeping_it_forever() {
    // 文件被删、也找不到轮转目标时，手里那条未封口块要按到期封口交出去；
    // 留着不清的话，`prune_family_state` 会因为「有 pending 就保留」而把它当成一个
    // 既不封口也不会过期的死块。
    let root = temp_dir("family-deleted-pending");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("a.log");
    fs::write(&file, "a1\n  a-cont\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 0);
    assert!(
        read_state(&root).files[0].pending_multiline.is_some(),
        "首轮应留下未封口块"
    );

    fs::remove_file(&file).expect("remove");
    let mut second = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 1);
    assert_eq!(read_output_records(&output)[0].body, "a1\n  a-cont\n");

    // 块已封口、pending 清空 → 条目不再被「有 pending 就保留」钉住。
    let state = read_state(&root);
    assert!(state.files.is_empty(), "{:?}", state.files);
}

#[test]
fn a_rotation_without_a_target_does_not_drop_the_pending_block() {
    // 文件被替换（inode 变了）但旧文件已被删/压缩搬走：旧块不能丢。
    let root = temp_dir("family-rotate-gone");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("a.log");
    fs::write(&file, "a1\n  a-cont\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 0);

    // 删掉原文件再新建同名文件（inode 不同 = 轮转），旧文件无处可寻。
    fs::remove_file(&file).expect("remove");
    fs::write(&file, "b1\na-next\n").expect("write new");
    let mut second = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    let records = read_output_records(&output);
    assert!(outcome.rotated);
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.as_str())
            .collect::<Vec<_>>(),
        vec!["a1\n  a-cont\n", "b1\n"]
    );
    let state = read_state(&root);
    let entry = state
        .files
        .iter()
        .find(|entry| entry.path == file.display().to_string())
        .expect("新文件的 checkpoint");
    assert_eq!(
        entry
            .pending_multiline
            .as_ref()
            .expect("新文件的未封口块")
            .record
            .body,
        "a-next\n"
    );
}

#[cfg(unix)]
#[test]
fn a_rotation_drain_that_eats_the_budget_does_not_skip_the_new_file() {
    // 排空旧文件吃满预算时，新文件必须留下 offset=0 的 checkpoint；
    // 否则下一轮它没有 checkpoint，会被当成新文件从 head 读，轮转后写入的内容全丢。
    let root = temp_dir("family-budget-rotate");
    fs::create_dir_all(root.join("state")).expect("create state");
    let pods = root.join("pods");
    let containers = root.join("containers");
    fs::create_dir_all(&pods).expect("create pods");
    fs::create_dir_all(&containers).expect("create containers");
    let real = pods.join("0.log");
    let rotated = pods.join("0.log.1");
    fs::write(&real, "first\n").expect("write real");
    let link = containers.join("app.log");
    std::os::unix::fs::symlink(&real, &link).expect("symlink");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &containers.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.read_limits = ReadLimits::new(1_048_576, 4_194_304, 2);

    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 1);

    fs::rename(&real, &rotated).expect("rotate real");
    fs::write(&rotated, "first\nold-1\nold-2\n").expect("append old tail");
    fs::write(&real, "second\n").expect("write new active");

    // 旧文件尾巴 2 行恰好用完整轮预算。
    let mut second = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(second.process_once().expect("second").records_processed, 2);
    let active = read_state(&root)
        .files
        .into_iter()
        .find(|entry| entry.path == link.display().to_string())
        .expect("新文件要留下起点 checkpoint");
    assert_eq!(active.checkpoint_offset, 0);

    let mut third = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(third.process_once().expect("third").records_processed, 1);
    let records = read_output_records(&output);
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.as_str())
            .collect::<Vec<_>>(),
        vec!["first\n", "old-1\n", "old-2\n", "second\n"]
    );
}

fn tracked(
    path: &str,
    checkpoint_offset: u64,
    last_size: Option<u64>,
    pending: bool,
    last_commit_point_at: Option<&str>,
) -> TrackedFileCheckpoint {
    TrackedFileCheckpoint {
        file_id: path.to_string(),
        path: path.to_string(),
        device_id: None,
        inode: None,
        fingerprint: None,
        checkpoint_offset,
        checkpoint_probe: None,
        last_size,
        last_read_at: None,
        last_commit_point_at: last_commit_point_at.map(str::to_string),
        rotated_from_path: None,
        real_path: String::new(),
        pending_multiline: pending.then(|| PendingMultilineState {
            source_path: path.to_string(),
            last_updated_at: "2026-04-13T00:00:00Z".to_string(),
            record: Record {
                body: "line\n".to_string(),
                start_offset: 0,
                end_offset: 5,
                lines: 1,
                completion: records::Completion::Boundary,
            },
        }),
    }
}

#[test]
fn prune_keeps_unmatched_entries_only_when_they_still_matter() {
    let now = "2026-04-13T00:00:00Z";
    let stale = "2026-03-01T00:00:00Z";
    let mut state = LogCheckpointState::new("input-app".to_string(), now.to_string());
    state.files = vec![
        // 仍匹配：无论读没读完、新不新，一律保留。
        tracked("/var/log/matched.log", 10, Some(10), false, Some(stale)),
        // 不匹配但还有未封口块：块在等空闲封口，不能丢。
        tracked("/var/log/pending.log", 10, Some(10), true, Some(stale)),
        // 不匹配、已读完、无块：立即释放。
        tracked("/var/log/read-fully.log", 10, Some(10), false, Some(now)),
        // 不匹配、没读完、最近还在读：留着等尾巴（轮转 / 延迟写入）。
        tracked("/var/log/unfinished.log", 3, Some(10), false, Some(now)),
        // 不匹配、没读完、但已经 7 天没动：过期。
        tracked("/var/log/abandoned.log", 3, Some(10), false, Some(stale)),
    ];
    let matched: BTreeSet<String> = ["/var/log/matched.log".to_string()].into_iter().collect();

    prune_family_state(&mut state, &matched, &BTreeSet::new(), now);

    let mut kept: Vec<&str> = state
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    kept.sort();
    assert_eq!(
        kept,
        vec![
            "/var/log/matched.log",
            "/var/log/pending.log",
            "/var/log/unfinished.log",
        ]
    );
}

#[test]
fn prune_drops_a_deselected_entry_immediately() {
    // 策展人取消了选择（filters / exclude_globs / target 变了）：**没读完也停**。
    // 与“轮转/删除”不同 —— 那些旧名字已不在枚举结果里，不属于 deselected，仍照旧排空。
    let now = "2026-04-13T00:00:00Z";
    let mut state = LogCheckpointState::new("input-app".to_string(), now.to_string());
    state.files = vec![
        tracked(
            "/var/log/containers/web-1_prod_nginx-a1.log",
            3,
            Some(10),
            false,
            Some(now),
        ),
        // 未封口块也挡不住取消选择（否则那个块永远等不到下一轮）。
        tracked(
            "/var/log/containers/dbg-1_prod_dbg-b1.log",
            3,
            Some(10),
            true,
            Some(now),
        ),
        // 仅轮转离场（不在 deselected 里）：仍旧保留着排空尾巴。
        tracked("/var/log/rotated-away.log", 3, Some(10), false, Some(now)),
    ];
    let matched: BTreeSet<String> = BTreeSet::new();
    let deselected: BTreeSet<String> = [
        "/var/log/containers/web-1_prod_nginx-a1.log".to_string(),
        "/var/log/containers/dbg-1_prod_dbg-b1.log".to_string(),
    ]
    .into_iter()
    .collect();

    prune_family_state(&mut state, &matched, &deselected, now);

    let kept: Vec<&str> = state
        .files
        .iter()
        .map(|entry| entry.path.as_str())
        .collect();
    assert_eq!(kept, vec!["/var/log/rotated-away.log"]);
}

#[test]
fn tightening_filters_stops_reading_an_already_tracked_growing_file() {
    // 容器日志一直在增长：靠“排空到 EOF”永远排不完。
    // 把某个 pod 从 filters 里剔掉之后，必须**当轮**就停（而不是继续往里进）。
    let root = temp_dir("family-filter-drop");
    fs::create_dir_all(root.join("state")).expect("create state");
    let kept = root.join("web-1_prod_nginx-a1.log");
    let dropped = root.join("debug-1_prod_debug-b1.log");
    fs::write(&kept, "k1\n").expect("write kept");
    fs::write(&dropped, "d1\n").expect("write dropped");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    // 第一轮：没有过滤器 → 两个都进跟踪集。
    let mut first = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 2);
    assert_eq!(read_state(&root).files.len(), 2);

    // 第二轮：策展人收紧 filters，同时被剔的那个文件**又长了**。
    cfg.filters = wist_contracts::work::ContainerFilters {
        namespace_in: vec!["prod".to_string()],
        pod_not_in: vec!["debug-1".to_string()],
        ..Default::default()
    };
    fs::write(&dropped, "d1\nd2\n").expect("append dropped");
    let mut second = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    let outcome = second.process_once().expect("second");
    assert_eq!(outcome.records_processed, 0, "取消选择后不该再读它");
    let bodies: Vec<String> = read_output_records(&output)
        .into_iter()
        .map(|record| record.body)
        .collect();
    assert!(!bodies.iter().any(|body| body == "d2\n"), "{bodies:?}");

    // checkpoint 也要放掉：否则状态里永远挂着一条没人读的文件。
    let tracked: Vec<String> = read_state(&root)
        .files
        .iter()
        .map(|entry| entry.path.clone())
        .collect();
    assert_eq!(tracked, vec![kept.display().to_string()]);
}

#[test]
fn a_deselected_file_that_comes_back_is_read_from_head_like_a_new_file() {
    // 已知取舍（与 W1 对“曾排除的文件”同一语义）：取消选择会释放 checkpoint，
    // 之后再选上时它就是一个“新文件” —— 从 head 读。这条测试把这个取舍钉住，
    // 以免以后有人以为“重新选上能续读”而踩到重复数据。
    let root = temp_dir("family-filter-return");
    fs::create_dir_all(root.join("state")).expect("create state");
    let file = root.join("dbg-1_prod_dbg-b1.log");
    fs::write(&file, "d1\n").expect("write");
    let output = output_path(&root);

    let mut cfg = family_config(&root, &root.join("*.log"));
    cfg.startup_position = StartupPosition::Head;
    cfg.filters = wist_contracts::work::ContainerFilters {
        namespace_in: vec!["prod".to_string()],
        pod_not_in: vec!["dbg-1".to_string()],
        ..Default::default()
    };
    let mut excluded = FileFamilyProcessor::new(cfg.clone(), FileRecordSink::new(output.clone()));
    assert_eq!(
        excluded.process_once().expect("excluded").records_processed,
        0
    );

    // 再选上：按新文件从 head 读（重新产出一条 d1）。
    cfg.filters = Default::default();
    let mut included = FileFamilyProcessor::new(cfg, FileRecordSink::new(output.clone()));
    assert_eq!(
        included.process_once().expect("included").records_processed,
        1
    );
}
