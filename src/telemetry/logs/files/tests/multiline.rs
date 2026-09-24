use std::fs;

use super::{
    FileInputProcessor, StartupPosition, config, log_checkpoints, read_json, read_output_records,
    temp_dir, write_json_atomic,
};
use crate::telemetry::logs::multiline::MultilineMode;
use crate::telemetry::warp_parse::FileRecordSink;

#[test]
fn indented_multiline_merges_stack_frames() {
    let root = temp_dir("multiline");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "ERROR first\n  frame1\nINFO next\n").expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));

    let outcome = processor.process_once().expect("process");
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read checkpoint");

    assert_eq!(outcome.records_processed, 1);
    let records = read_output_records(&output_path);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "ERROR first\n  frame1\n");
    assert_eq!(
        state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("INFO next\n")
    );
}

#[test]
fn multiline_state_survives_across_ticks_and_flushes_on_idle() {
    let root = temp_dir("multiline-cross-tick");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "ERROR first\n").expect("write log");
    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::IndentedContinuation;

    let mut first = FileInputProcessor::new(cfg.clone(), FileRecordSink::new(output_path.clone()));
    let first_outcome = first.process_once().expect("first process");
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let first_state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read first checkpoint");

    assert_eq!(first_outcome.records_processed, 0);
    assert_eq!(
        first_state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("ERROR first\n")
    );

    fs::write(&source_path, "ERROR first\n  frame1\nINFO next\n").expect("append log");
    let mut second = FileInputProcessor::new(cfg.clone(), FileRecordSink::new(output_path.clone()));
    let second_outcome = second.process_once().expect("second process");
    let second_state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read second checkpoint");
    let second_records = read_output_records(&output_path);

    assert_eq!(second_outcome.records_processed, 1);
    assert_eq!(second_records.len(), 1);
    assert_eq!(second_records[0].body, "ERROR first\n  frame1\n");
    assert_eq!(
        second_state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("INFO next\n")
    );

    let mut third = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let third_outcome = third.process_once().expect("third process");
    let third_state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read third checkpoint");
    let third_records = read_output_records(&output_path);

    assert_eq!(third_outcome.records_processed, 0);
    assert_eq!(third_records.len(), 1);
    assert_eq!(
        third_state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("INFO next\n")
    );

    let mut aged_state = third_state.clone();
    aged_state
        .pending_multiline
        .as_mut()
        .expect("pending")
        .last_updated_at = "2000-01-01T00:00:00Z".to_string();
    write_json_atomic(&checkpoint_path, &aged_state).expect("age pending multiline");

    let mut flush_cfg = config(&root, &source_path);
    flush_cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut fourth = FileInputProcessor::new(flush_cfg, FileRecordSink::new(output_path.clone()));
    let fourth_outcome = fourth.process_once().expect("fourth process");
    let fourth_state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read fourth checkpoint");
    let fourth_records = read_output_records(&output_path);

    assert_eq!(fourth_outcome.records_processed, 1);
    assert!(fourth_state.pending_multiline.is_none());
    assert_eq!(fourth_records.len(), 2);
    assert_eq!(fourth_records[1].body, "INFO next\n");
}

#[test]
fn an_unreadable_checkpoint_does_not_stop_collection() {
    // 读不动的 checkpoint 不该让采集停：当没有，按 startup_position 重新定位。
    //
    // 为什么值得钉住：读不动的 checkpoint 若当成错误往上抛，这个输入会**每 tick 都失败**
    // （而 daemon 的失败去重让它只打印一次）—— 表现成"这个文件永远不进数据"的静默停摆。
    // 换 schema 时尤其容易踩到。
    let root = temp_dir("unreadable-checkpoint");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "ERROR first\n  frame1\n").expect("write log");

    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    fs::create_dir_all(checkpoint_path.parent().expect("parent")).expect("create state dir");
    // 一份读不动的 checkpoint（例如换了结构之后留下的旧形状）。
    fs::write(
        &checkpoint_path,
        r#"{"schema_version":"v1","input_id":"input-app","updated_at":"t","files":[],"pending_multiline":{"source_path":"/x","body":"old shape","start_offset":0,"end_offset":9,"last_updated_at":"t"}}"#,
    )
    .expect("write unreadable checkpoint");

    let mut cfg = config(&root, &source_path);
    cfg.startup_position = StartupPosition::Head;
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let outcome = processor
        .process_once()
        .expect("读不动也要能继续采，不是往上抛错");

    // 当没有 checkpoint + head ⇒ 从头重读：两行归成一条，但它**还没封口**
    // （`indented` 读法下，一条记录要等下一个边界信号 —— 那是它的本意，不是 bug）。
    assert_eq!(outcome.records_processed, 0);
    // 真正的证据在这里：checkpoint 被重写成能读的形状，而且里面那条只能来自"从头读"。
    let state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("checkpoint 应被重写成可读的形状");
    assert_eq!(state.input_id, "input-app");
    assert_eq!(
        state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("ERROR first\n  frame1\n")
    );
}

#[test]
fn a_block_that_never_ends_is_withheld_instead_of_forwarded_half_way() {
    // 方案 A：内容不全的记录**不转发**（也不取号）—— 发出去它长得像完整记录，会骗过下游解析。
    // 这个用例把一个 `max_lines` 都压满的病态块（锚之后永远只有缩进行）走一遍。
    let root = temp_dir("withheld-oversized");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");

    let limit = crate::telemetry::logs::multiline::MAX_RECORD_LINES;
    let mut content = String::from("ERROR first\n");
    for index in 0..=limit + 1 {
        content.push_str(&format!("  frame {index}\n"));
    }
    // 再给一个锚：否则最后那条会一直悬着不封口（那是设计行为），用例就看不出放行结果。
    content.push_str("INFO next\nINFO last\n");
    fs::write(&source_path, &content).expect("write log");

    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let outcome = processor.process_once().expect("process");

    // 块被挡下（一条），而且**说得出是哪条上限**：
    assert_eq!(outcome.withheld.records, 1, "{outcome:?}");
    assert!(outcome.withheld.bytes > 0);
    let summary = outcome.withheld.detail();
    assert!(summary.contains("truncated:record_limit"), "{summary}");

    // 放行的只有锚之后那条：被挡下的没转发，也没在它前面/后面造出多余的记录。
    let records = read_output_records(&output_path);
    assert_eq!(records.len(), 1, "{outcome:?}");
    assert_eq!(records[0].body, "INFO next\n");
    // 关键不变量：被挡下的**不占号** —— 否则接收端会看到一个洞，而按协议 §6
    // 未上报的洞等于真丢失 → 凭空报一次数据丢失。
    assert_eq!(records[0].seq, 0, "被挡下的那条不该占 seq");
    // 块之后的那条锚仍按正常“等下一个边界”走：最后一条悬着。
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read checkpoint");
    assert_eq!(
        state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("INFO last\n")
    );
    // checkpoint 照常前进：这个文件不会被反复重读。
    assert_eq!(
        state.files[0].checkpoint_offset,
        content.len() as u64,
        "chunk 读完就该推进到文件末"
    );
}

#[test]
fn the_record_limit_belongs_to_folding_not_to_line_counts() {
    // 一行一条时**根本没有在攒什么东西**，所以累积上限与它无关：
    // 再长的文件也不该被挡下。这条边界很容易未来被“统一上限”改坏。
    let root = temp_dir("withheld-none-mode");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");

    let lines = crate::telemetry::logs::multiline::MAX_RECORD_LINES * 2;
    let mut content = String::new();
    for index in 0..lines {
        content.push_str(&format!("  line {index}\n"));
    }
    fs::write(&source_path, &content).expect("write log");

    let mut cfg = config(&root, &source_path);
    cfg.multiline_mode = MultilineMode::None;
    let mut processor = FileInputProcessor::new(cfg, FileRecordSink::new(output_path.clone()));
    let outcome = processor.process_once().expect("process");

    assert!(outcome.withheld.is_empty(), "{outcome:?}");
    // 全部当记录产出（内存预算小的那部分进 spool，也算产出）。
    assert_eq!(outcome.records_processed, lines, "{outcome:?}");
}

#[test]
fn rotate_keeps_pending_multiline_bound_to_old_file_until_tail_is_drained() {
    let root = temp_dir("rotate-multiline");
    let source_path = root.join("app.log");
    let rotated_path = root.join("app.log.1");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "ERROR first\n").expect("write first log");

    let mut initial_cfg = config(&root, &source_path);
    initial_cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileInputProcessor::new(
        initial_cfg.clone(),
        FileRecordSink::new(output_path.clone()),
    );
    let first_outcome = first.process_once().expect("first process");
    assert_eq!(first_outcome.records_processed, 0);

    fs::rename(&source_path, &rotated_path).expect("rotate file");
    fs::write(&rotated_path, "ERROR first\n  frame1\n").expect("append old tail");
    fs::write(&source_path, "INFO next\n").expect("write new active log");

    let mut second = FileInputProcessor::new(initial_cfg, FileRecordSink::new(output_path.clone()));
    let second_outcome = second.process_once().expect("second process");
    let records = read_output_records(&output_path);

    assert!(second_outcome.rotated);
    assert_eq!(second_outcome.records_processed, 1);
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "ERROR first\n  frame1\n");

    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read checkpoint");
    assert_eq!(
        state
            .pending_multiline
            .as_ref()
            .map(|pending| pending.record.body.as_str()),
        Some("INFO next\n")
    );
}

#[test]
fn switching_a_source_to_single_line_reads_the_leftover_record_out_first() {
    // 读法从 `indented` 改成 `none`：手里那条未封口的记录**不能被丢掉** ——
    // 否则改一下目录，那条日志就无声地没了。
    let root = temp_dir("multiline-mode-switch");
    let source_path = root.join("app.log");
    let output_path = root.join("log").join("records.ndjson");
    fs::create_dir_all(root.join("state")).expect("create state");
    fs::create_dir_all(root.join("log")).expect("create log");
    fs::write(&source_path, "ERROR first\n").expect("write log");

    let mut folded_cfg = config(&root, &source_path);
    folded_cfg.multiline_mode = MultilineMode::IndentedContinuation;
    let mut first = FileInputProcessor::new(folded_cfg, FileRecordSink::new(output_path.clone()));
    assert_eq!(first.process_once().expect("first").records_processed, 0);

    fs::write(&source_path, "ERROR first\n  frame1\nINFO next\n").expect("append log");
    let mut single_line_cfg = config(&root, &source_path);
    single_line_cfg.multiline_mode = MultilineMode::None;
    let mut second =
        FileInputProcessor::new(single_line_cfg, FileRecordSink::new(output_path.clone()));
    let second_outcome = second.process_once().expect("second process");

    let records = read_output_records(&output_path);
    // 遗留的那条先冲出来，之后才是逐行的：
    assert_eq!(second_outcome.records_processed, 3);
    assert_eq!(
        records
            .iter()
            .map(|record| record.body.as_str())
            .collect::<Vec<_>>(),
        vec!["ERROR first\n", "  frame1\n", "INFO next\n"]
    );
    let checkpoint_path = log_checkpoints::path_for(&root.join("state"), "input-app");
    let state: crate::state_store::log_checkpoint_state::LogCheckpointState =
        read_json(&checkpoint_path).expect("read checkpoint");
    assert!(state.pending_multiline.is_none(), "一行一条不留未封口状态");
}
