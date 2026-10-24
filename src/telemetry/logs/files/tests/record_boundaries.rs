use std::fs;

use super::{
    FileInputProcessor, config, log_checkpoints, read_json, read_output_records, temp_dir,
    write_json_atomic,
};
use crate::state_store::log_checkpoint_state::LogCheckpointState;
use crate::telemetry::logs::files::file_reader::ReadLimits;
use crate::telemetry::logs::multiline::MultilineMode;
use crate::telemetry::warp_parse::FileRecordSink;

/// MySQL slow log：`# Time:` 起块，下一条 `# Time:` 或空闲超时封口。
#[test]
fn slow_log_blocks_start_at_the_time_header() {
    let root = temp_dir("slow-log");
    let source_path = root.join("slow.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(
        &source_path,
        "# Time: 2026-10-24T01:02:03Z\n\
         # User@Host: app[app] @ localhost []\n\
         SELECT 1;\n\
         # Time: 2026-10-24T01:02:04Z\n\
         SELECT 2;\n",
    )
    .expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::MysqlSlow;
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));

    let outcome = processor.process_once().expect("process");
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let state: LogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");

    assert_eq!(outcome.records_processed, 1);
    let records = read_output_records(&output_path);
    assert_eq!(records.len(), 1);
    assert_eq!(
        records[0].body,
        "# Time: 2026-10-24T01:02:03Z\n\
         # User@Host: app[app] @ localhost []\n\
         SELECT 1;\n"
    );
    // 最后一块还没等到下一条 `# Time:`：留在 checkpoint 里等下一轮 / 空闲封口。
    assert_eq!(
        state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("# Time: 2026-10-24T01:02:04Z\nSELECT 2;\n")
    );
}

/// csvlog 的某列会把换行写进引号里：**引号外**的换行才是记录边界。
#[test]
fn csv_keeps_quoted_newlines_inside_one_record() {
    let root = temp_dir("postgres-csv");
    let source_path = root.join("postgresql.csv");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "1,\"a\nb\",x\n2,\"y\",z\n").expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::PostgresCsv;
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));

    let outcome = processor.process_once().expect("process");
    assert_eq!(outcome.records_processed, 2);
    let records = read_output_records(&output_path);
    assert_eq!(
        records.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
        vec!["1,\"a\nb\",x\n", "2,\"y\",z\n"]
    );
}

/// 半个引号块跨读批：引号状态从 pending 正文**重算**，不另存一份会漂的状态。
#[test]
fn csv_resumes_an_unfinished_quoted_record_across_ticks() {
    let root = temp_dir("postgres-csv-cross-tick");
    let source_path = root.join("postgresql.csv");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "1,\"a\n").expect("write partial");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::PostgresCsv;

    let mut first = FileInputProcessor::new(cfg.clone(), FileRecordSink::new(output_path.clone()));
    let first_outcome = first.process_once().expect("first process");
    assert_eq!(first_outcome.records_processed, 0);
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let first_state: LogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");
    assert_eq!(
        first_state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("1,\"a\n")
    );

    fs::write(&source_path, "1,\"a\nb\",x\n").expect("finish record");
    let mut second = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let second_outcome = second.process_once().expect("second process");
    assert_eq!(second_outcome.records_processed, 1);
    let records = read_output_records(&output_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "1,\"a\nb\",x\n");
}

/// 读取器截断的长行不带换行：不能让它把下一行粘进来（两行都不完整）。
#[test]
fn csv_does_not_glue_a_truncated_line_to_the_next_row() {
    let root = temp_dir("postgres-csv-truncated");
    let source_path = root.join("postgresql.csv");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(
        &source_path,
        "1,\"THIS_FIELD_IS_FAR_TOO_LONG_TO_FIT\",x\n2,\"y\",z\n",
    )
    .expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::PostgresCsv;
    // 16 字节：第一行会被读取器截断（其余字节被跳过，提交的文本没有换行）。
    cfg.read_limits = ReadLimits::new(16, 4_194_304, 4096);
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));

    let outcome = processor.process_once().expect("process");
    assert_eq!(outcome.truncated_lines, 1);
    assert_eq!(outcome.withheld.records, 1, "截断行不下发");
    assert_eq!(outcome.records_processed, 1);
    let records = read_output_records(&output_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "2,\"y\",z\n");
}

/// 噪音行：整条命中即丢；**不消耗 seq**（取号不上报会让接收端报假的数据丢失）。
#[test]
fn noise_needles_drop_whole_records_without_taking_a_seq() {
    let root = temp_dir("noise-drop");
    let source_path = root.join("auth.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(
        &source_path,
        "pam_unix(cron:session): session opened for user root\n\
         Accepted publickey for deploy from 10.0.0.1 port 22 ssh2\n",
    )
    .expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.drop_if_contains = vec!["pam_unix(cron:session)".to_string()];
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));

    let outcome = processor.process_once().expect("process");
    assert_eq!(outcome.records_processed, 1);
    assert_eq!(outcome.dropped_noise, 1);
    let records = read_output_records(&output_path);
    assert_eq!(records.len(), 1);
    assert!(
        records[0].body.starts_with("Accepted publickey"),
        "{}",
        records[0].body
    );
    assert_eq!(records[0].seq, 0, "被丢的那条不占号");
}

/// csvlog 的记录边界是**确定的**：短空闲（<60s）**不**封口 —— 否则写得慢的大字段会被切碎。
#[test]
fn csv_does_not_flush_a_quoted_record_after_a_short_idle() {
    let root = temp_dir("postgres-csv-idle");
    let source_path = root.join("postgresql.csv");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "1,\"a\n").expect("write partial");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::PostgresCsv;

    let mut first = FileInputProcessor::new(cfg.clone(), FileRecordSink::new(output_path.clone()));
    first.process_once().expect("first process");

    // 立刻再跑一轮：pending 才“几毫秒没更新”，远没到 60s 的恢复阈值。
    let mut second = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let outcome = second.process_once().expect("second process");
    assert_eq!(outcome.records_processed, 0);
    assert_eq!(outcome.withheld.records, 0);
    assert!(!output_path.exists() || read_output_records(&output_path).is_empty());
}

/// 写到一半的 csv 记录（引号奇偶永久失衡）不能无限吸收后续行：
/// 长空闲后按 `Oversized` 封口（闸门挡下、不下发）并清掉 pending，下一行重新起头。
#[test]
fn csv_drops_a_torn_record_after_the_long_idle_bound() {
    let root = temp_dir("postgres-csv-torn");
    let source_path = root.join("postgresql.csv");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "1,\"a\n").expect("write torn record");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::PostgresCsv;

    let mut first = FileInputProcessor::new(cfg.clone(), FileRecordSink::new(output_path.clone()));
    first.process_once().expect("first process");
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let mut state: LogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");
    state
        .pending_multiline
        .as_mut()
        .expect("pending")
        .last_updated_at = "2000-01-01T00:00:00Z".to_string();
    write_json_atomic(&checkpoint_path, &state).expect("age pending");

    let mut second = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let outcome = second.process_once().expect("second process");
    assert_eq!(outcome.records_processed, 0, "残缺记录不下发");
    assert_eq!(outcome.withheld.records, 1, "按 Oversized 被闸门挡下");
    assert!(!output_path.exists() || read_output_records(&output_path).is_empty());
    let state: LogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");
    assert!(state.pending_multiline.is_none(), "恢复后不再粘住后续行");
}

/// 未封口块到期封口时也走同一套噪音过滤（否则“丢掉的块”会在下一轮冒出来）。
#[test]
fn noise_needles_apply_to_a_pending_block_on_flush() {
    let root = temp_dir("noise-drop-pending");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "ERROR first\n  noise frame\n").expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    cfg.drop_if_contains = vec!["noise frame".to_string()];

    let mut first = FileInputProcessor::new(cfg.clone(), FileRecordSink::new(output_path.clone()));
    first.process_once().expect("first process");
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let mut state: LogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");
    state
        .pending_multiline
        .as_mut()
        .expect("pending")
        .last_updated_at = "2000-01-01T00:00:00Z".to_string();
    write_json_atomic(&checkpoint_path, &state).expect("age pending");

    let mut second = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let outcome = second.process_once().expect("second process");
    assert_eq!(outcome.records_processed, 0);
    assert_eq!(outcome.dropped_noise, 1, "整块命中就整块丢");
    assert!(!output_path.exists() || read_output_records(&output_path).is_empty());
}
