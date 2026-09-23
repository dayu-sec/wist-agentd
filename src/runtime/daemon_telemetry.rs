use std::io;
use std::path::PathBuf;

use wist_contracts::agent_config::{AgentConfig, LogFileInputSection};
use wist_shared::time::now_rfc3339;

use crate::control::work::AppliedWorkGrant;
use crate::telemetry::logs::files::{FileInputProcessor, ProcessOutcome};
use crate::telemetry::warp_parse::{RecordSink, TelemetryRecordSink};

#[path = "daemon_telemetry_support.rs"]
mod support;

use support::{
    build_file_input_config, build_record_sink, invalid_output_failure, missing_input_failure,
    processing_failure, replay_spool_only, spool_paused_reason,
};

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub(super) struct TelemetryTick {
    pub(super) outcomes: Vec<ProcessOutcome>,
    pub(super) failures: Vec<TelemetryFailure>,
    /// 本 tick 处于暂停（spool 超限）的输入，作为“当前状态事实”供 daemon 跨 tick 差值。
    pub(super) notifications: Vec<TelemetryWorkState>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) enum TelemetryFailureKind {
    MissingInput,
    ProcessingFailed,
    InvalidOutput,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub(super) struct TelemetryFailure {
    pub(super) kind: TelemetryFailureKind,
    pub(super) input_id: String,
    pub(super) path: String,
    pub(super) detail: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum WorkState {
    Paused,
    Resumed,
}

/// 工作状态通知（非告警、非失败）。`Paused` 由采集 tick 产生，`Resumed` 由 daemon 跨 tick 差值合成。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct TelemetryWorkState {
    pub(super) input_id: String,
    pub(super) state: WorkState,
    pub(super) reason: String,
    pub(super) at: String,
}

impl TelemetryTick {
    pub(super) fn is_active(&self) -> bool {
        !self.failures.is_empty()
            || self.outcomes.iter().any(|outcome| {
                outcome.records_processed > 0
                    || outcome.replayed_spool > 0
                    || outcome.spooled > 0
                    || outcome.paused
            })
    }
}

/// 构建共享的遥测上送 sink（日志与指标共用同一连接）。
pub(super) fn build_telemetry_sink(config: &AgentConfig) -> io::Result<TelemetryRecordSink> {
    build_record_sink(config)
}

/// 当 sink 无法构建（非法输出配置）时，为每个输入生成一条 `InvalidOutput` 失败。
pub(super) fn invalid_output_tick(
    config: &AgentConfig,
    work: &AppliedWorkGrant,
    detail: String,
) -> TelemetryTick {
    let from_config = config
        .telemetry
        .logs
        .file_inputs
        .iter()
        .map(|input| invalid_output_failure(input, detail.clone()));
    let from_work = work
        .log_inputs()
        .into_iter()
        .map(|entry| invalid_output_failure(&entry.input, detail.clone()));
    let failures = from_config.chain(from_work).collect();
    TelemetryTick {
        outcomes: Vec::new(),
        failures,
        notifications: Vec::new(),
    }
}

/// 按本轮要采的输入清单跑一遍。
///
/// 两类输入**并存**，各有各的道理：
///   * 配置里的 `file_inputs`：本机运维的逃生舱（临时盯一个文件不需要惊动网关）；
///   * 工作折算出来的：平台派活（`Control.Agent.Work`），任务 id 带 `work-` 前缀。
///
/// 两者同名冲突是不可能的（前缀不同），但同一路径被两边同时盯着是可能的 —— 那会让
/// 同一行日志上送两次。这是有意留的：去重会掩盖“人手工加了一条本该由网关派的任务”，
/// 而那正是需要被看见的事。
pub(super) async fn process_telemetry_inputs(
    config: &AgentConfig,
    work: &AppliedWorkGrant,
    sink: &mut TelemetryRecordSink,
    next_seq: &mut u64,
) -> TelemetryTick {
    let mut outcomes = Vec::new();
    let mut failures = Vec::new();
    let mut notifications = Vec::new();

    for input in &config.telemetry.logs.file_inputs {
        process_telemetry_input(
            config,
            input,
            sink,
            &mut outcomes,
            &mut failures,
            &mut notifications,
            next_seq,
        )
        .await;
    }
    for entry in work.log_inputs() {
        process_telemetry_input(
            config,
            &entry.input,
            sink,
            &mut outcomes,
            &mut failures,
            &mut notifications,
            next_seq,
        )
        .await;
    }

    TelemetryTick {
        outcomes,
        failures,
        notifications,
    }
}

async fn process_telemetry_input<S: RecordSink>(
    config: &AgentConfig,
    input: &LogFileInputSection,
    sink: &mut S,
    outcomes: &mut Vec<ProcessOutcome>,
    failures: &mut Vec<TelemetryFailure>,
    notifications: &mut Vec<TelemetryWorkState>,
    next_seq: &mut u64,
) {
    let source_path = PathBuf::from(&input.path);
    if !source_path.exists() {
        failures.push(missing_input_failure(input));
        match replay_spool_only(config, input, sink).await {
            Ok(Some(outcome)) => outcomes.push(outcome),
            Ok(None) => {}
            Err(err) => failures.push(processing_failure(
                input,
                format!("failed to replay spool: {err}"),
            )),
        }
        return;
    }

    match process_input_with_sink(config, input, source_path, sink, next_seq).await {
        Ok(outcome) => {
            if outcome.paused {
                notifications.push(TelemetryWorkState {
                    input_id: input.input_id.clone(),
                    state: WorkState::Paused,
                    reason: spool_paused_reason(outcome.spool_bytes),
                    at: now_rfc3339(),
                });
            }
            outcomes.push(outcome);
        }
        Err(err) => failures.push(processing_failure(input, err.to_string())),
    }
}

async fn process_input_with_sink<S: RecordSink>(
    config: &AgentConfig,
    input: &LogFileInputSection,
    source_path: PathBuf,
    sink: &mut S,
    next_seq: &mut u64,
) -> io::Result<ProcessOutcome> {
    let mut processor =
        FileInputProcessor::new(build_file_input_config(config, input, source_path), sink);
    processor.process_once_async(next_seq).await
}
