use std::io;
use std::path::PathBuf;

use wist_contracts::agent_config::{AgentConfig, LogFileInputSection};
use wist_shared::time::now_rfc3339;

use crate::control::work::AppliedWorkGrant;
use crate::telemetry::logs::files::{FileInputProcessor, ProcessOutcome};
use crate::telemetry::warp_parse::{RecordSink, TcpFraming, TelemetryRecordSink};

#[path = "daemon_telemetry_support.rs"]
mod support;

use support::{
    build_file_input_config, build_record_sink, invalid_output_failure, missing_input_failure,
    processing_failure, replay_spool_only, spool_paused_reason, withheld_failure,
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
    /// 有记录因**内容不全**被挡下不转发（边界判据在这个文件上没起作用）。
    /// 不是"采集失败"，但必须说出来 —— 否则一条永不结束的块会静默消失。
    RecordWithheld,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub(super) struct TelemetryFailure {
    pub(super) kind: TelemetryFailureKind,
    pub(super) input_id: String,
    pub(super) path: String,
    /// 问题的**身份** —— 去重按它（`kind|input_id|path|detail`）。
    ///
    /// 所以它必须是**稳定**的：同一个问题反复出现就应该是同一行字。
    pub(super) detail: String,
    /// 这个问题的**量**（会变，如"本次挡下几条"）。
    ///
    /// **不参与去重**：重复报的是"问题还在"，不是"它又大了一点"。
    /// 把会变的东西放进 `detail` 会让每个 tick 都成新签名、每 tick 打印一次。
    pub(super) magnitude: Option<String>,
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

/// 分帧**必须**升到 `len` 时返回是谁要求的（`input_id`）；`None` = 照配置即可。
///
/// 抽成纯函数是为了能直接测这个判定：它错了会让日志静默丢进 miss（续行没有信封、
/// 匹配不上任何规则），而端到端测试很难稳定复现“恰好掉在 miss 里”。
///
/// 只看 tcp + `line`：file sink 逐条 JSON 编码，换行天然安全；`len` 对单行同样合法。
pub(super) fn len_framing_required<'a>(
    config: &AgentConfig,
    mut inputs: impl Iterator<Item = &'a LogFileInputSection>,
) -> Option<&'a str> {
    if config.telemetry.logs.output.kind != "tcp"
        || config.telemetry.logs.output.tcp.framing == "len"
    {
        return None;
    }
    inputs
        .find(|input| input.multiline_mode != "none")
        .map(|input| input.input_id.as_str())
}

/// 构建共享的遥测上送 sink（日志与指标共用同一连接）。
///
/// 分帧**不照抄配置**：`line` 只适用于不含换行的记录（协议 §3）。一旦有输入声明的读法
/// 是 `indented`，折叠出来的正文就可能含换行 —— 此时若还用 `line`，接收端会把续行当成
/// 独立行；那些行没有信封、匹配不上任何规则，**静默掉进 miss**（实测复现过）。
///
/// 所以这里不靠人去配对配置，而是按本轮真要采什么定：有这种输入就升到 `len` 并说清是谁要求的。
pub(super) fn build_telemetry_sink(
    config: &AgentConfig,
    work: &AppliedWorkGrant,
) -> io::Result<TelemetryRecordSink> {
    let from_work = work.log_inputs();
    let required = len_framing_required(
        config,
        from_work
            .iter()
            .map(|entry| &entry.input)
            .chain(config.telemetry.logs.file_inputs.iter()),
    );
    let Some(input_id) = required else {
        return build_record_sink(config, None);
    };
    eprintln!(
        "event=UplinkFramingEscalated from=line to=len input_id={input_id} reason=\"该输入声明多行读法，折叠出的正文可能含换行（协议 §3：line 只用于单行）\""
    );
    build_record_sink(config, Some(TcpFraming::Len))
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
            // 被挡下的记录走 failure 通道，是为了蹭 daemon 已有的**按签名去重**：
            // 一个持续存在的病态块只报一次，恢复正常后自动清掉。
            // （量放 `magnitude`：它会变，不能进签名，否则每 tick 都算新问题。）
            if let Some(failure) = withheld_failure(input, &outcome.withheld) {
                failures.push(failure);
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

#[cfg(test)]
mod tests {
    use super::len_framing_required;
    use wist_contracts::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, LogFileInputSection,
        PathsSection,
    };

    fn config(kind: &str, framing: &str) -> AgentConfig {
        let mut config = AgentConfig::new(
            AgentSection::default(),
            ControlPlaneSection::default(),
            PathsSection::default(),
            ExecutionSection::default(),
        );
        config.telemetry.logs.output.kind = kind.to_string();
        config.telemetry.logs.output.tcp.framing = framing.to_string();
        config
    }

    fn input(id: &str, multiline: &str) -> LogFileInputSection {
        LogFileInputSection {
            input_id: id.to_string(),
            path: "/var/log/app.log".to_string(),
            startup_position: "tail".to_string(),
            multiline_mode: multiline.to_string(),
        }
    }

    fn required(config: &AgentConfig, inputs: &[LogFileInputSection]) -> Option<String> {
        len_framing_required(config, inputs.iter()).map(str::to_string)
    }

    #[test]
    fn a_folding_input_forces_length_framing_on_a_line_uplink() {
        // `line` 分帧靠 `\n` 切帧；折叠出的正文自带换行 → 续行会被当成独立行、掉进 miss。
        // 所以只要有一个输入要归并，就必须升到 `len`，而且要报出是谁要求的。
        let config = config("tcp", "line");
        assert_eq!(
            required(&config, &[input("a", "none"), input("b", "indented")]),
            Some("b".to_string())
        );
    }

    #[test]
    fn all_single_line_inputs_leave_the_configured_framing_alone() {
        let config = config("tcp", "line");
        assert_eq!(required(&config, &[input("a", "none")]), None);
    }

    #[test]
    fn an_explicit_length_uplink_needs_no_escalation() {
        // 配置已经写了 `len`：对单行同样合法，不必（也不该）再报一次升级。
        let config = config("tcp", "len");
        assert_eq!(required(&config, &[input("a", "indented")]), None);
    }

    #[test]
    fn a_file_uplink_needs_no_escalation() {
        // file sink 逐条 JSON 编码，换行天然安全 —— 没有“被切开”这回事。
        let config = config("file", "line");
        assert_eq!(required(&config, &[input("a", "indented")]), None);
    }
}
