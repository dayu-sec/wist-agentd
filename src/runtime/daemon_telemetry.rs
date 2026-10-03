use std::io;
use std::path::{Path, PathBuf};

use wist_contracts::agent_config::{AgentConfig, LogFileInputSection, LogsOutputSection};
use wist_shared::time::now_rfc3339;

use crate::control::work::AppliedWorkGrant;
use crate::state_store::log_seq_state;
use crate::telemetry::exporters;
use crate::telemetry::logs::InputOrigin;
use crate::telemetry::logs::files::{FileInputProcessor, ProcessOutcome};
use crate::telemetry::warp_parse::{
    RecordSink, TcpFraming, TelemetryRecordSink, uplink_write_detail,
};

#[path = "daemon_telemetry_support.rs"]
mod support;

use support::{
    build_file_input_config, build_record_sink, invalid_output_failure, missing_input_failure,
    processing_failure, replay_spool_only, spool_paused_reason, unsupported_target, uplink_failure,
    withheld_failure,
};

// 生效输出解析要给主循环用（它在短路前算），所以在同一层再导出一次；
// `pub(crate)` 也让 `doctor` 复用同一套判定（工具说一套、进程做一套是没有意义的）。
pub(crate) use support::effective_output;

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
    /// **出口写失败**：记录已安全进 spool 等重发，但「写出口」这一步没成功。
    ///
    /// 单列一类是因为它与「读文件失败」的处置完全不同：输入没问题，是出口（数据面目标）
    /// 连不上 / 写了就断，或本地输出盘坏。身份串是**固定**的，目标与原因在 `magnitude`
    /// （见 `uplink_failure`）—— 否则同一次故障会因为「退避 / 拒绝」两种形态交替重报。
    OutputWriteFailed,
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
    /// 完全静默的一轮：没有产出、没有失败、没有通知。
    ///
    /// 用于生效输出被关闸（`enabled = false`）时：不是「采集失败」，而是「本就不该产出」——
    /// 既要零产出，也要零告警（把正常待命报成失败正是旧实现的毛病）。
    pub(super) fn silent() -> Self {
        Self {
            outcomes: Vec::new(),
            failures: Vec::new(),
            notifications: Vec::new(),
        }
    }

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

/// 出口健康的**跨 tick 记忆**：只用来在「失败 → 恢复」时补一行。
///
/// 为什么需要：失败本身每 tick 现算（失败面与 `is_active` 都对），但**恢复**没有任何一轮的失败面
/// 能表达 —— 没有它，运维看到 `output write failed …` 之后就无法知道「什么时候可以放下」。
///
/// 它**不臆造健康**：只有真的发出去了（直发或回放成功）才宣告恢复；源文件安静且无积压时
/// 既不尝试、也不宣告 —— 「没试就不知道」是诚实的，不是遗漏。
#[derive(Debug, Default)]
pub(super) struct UplinkHealth {
    failing: bool,
}

impl UplinkHealth {
    /// 最近的出口写失败是否**尚未恢复**。
    ///
    /// 只读，且刻意不参与任何迁移：状态上报（每 3s）会读它，但**不能**因为上报本身
    /// 就改变健康记忆 —— 唯一的状态迁移点仍是 `note_tick`（由真正的产出轮驱动）。
    pub(super) fn is_failing(&self) -> bool {
        self.failing
    }

    /// 记一轮的产出情况，返回**该打的一行**（只有恢复时才有）。
    pub(super) fn note_tick(&mut self, failed: bool, sent_something: bool) -> Option<&'static str> {
        if failed {
            self.failing = true;
            return None;
        }
        if self.failing && sent_something {
            self.failing = false;
            return Some("event=UplinkRecovered detail=\"出口写失败已恢复\"");
        }
        None
    }
}

/// 分帧**必须**升到 `len` 时返回是谁要求的（`input_id`）；`None` = 照配置即可。
///
/// 抽成纯函数是为了能直接测这个判定：它错了会让日志静默丢进 miss（续行没有信封、
/// 匹配不上任何规则），而端到端测试很难稳定复现“恰好掉在 miss 里”。
///
/// 只看 `tcp` + `line`：file sink 逐条 JSON 编码，换行天然安全；`len` 对单行同样合法。
/// 注意这里看的是**生效输出**（grant 合流后），不是原始本机配置 —— grant 可能把本机
/// `file` 覆盖成 tcp，此时分帧升级的判定必须跟着走。
pub(super) fn len_framing_required<'a>(
    output: &LogsOutputSection,
    mut inputs: impl Iterator<Item = &'a LogFileInputSection>,
) -> Option<&'a str> {
    if output.kind != "tcp" || output.tcp.framing == "len" {
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
/// 分帧取的是**生效输出**（`[telemetry.logs.output]` 与 grant 合流后的结论，见
/// [`effective_output`]），因此 grant 把本机 `file` 覆盖成 tcp 时也照样升级。
pub(super) fn build_telemetry_sink(
    config: &AgentConfig,
    work: &AppliedWorkGrant,
    output: &LogsOutputSection,
) -> io::Result<TelemetryRecordSink> {
    let from_work = work.log_inputs();
    let required = len_framing_required(
        output,
        from_work
            .iter()
            .map(|entry| &entry.input)
            .chain(config.telemetry.logs.file_inputs.iter()),
    );
    let Some(input_id) = required else {
        return build_record_sink(output, None);
    };
    eprintln!(
        "event=UplinkFramingEscalated from=line to=len input_id={input_id} reason=\"该输入声明多行读法，折叠出的正文可能含换行（协议 §3：line 只用于单行）\""
    );
    build_record_sink(output, Some(TcpFraming::Len))
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
///   * 配置里的 `file_inputs`：本机运维的逃生舱（临时盯一个文件不需要惊动网关）——
///     它**不来自任何采集面**，帧里就不带 `family`/`unit`；
///   * 工作折算出来的：平台派活（`Control.Agent.Work`），任务 id 带 `work-` 前缀，
///     并把**面 + 目录单元**带进帧 —— 这就是「这条来自哪个面」的依据。
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
    // 三个收集器装在一个结构里穿过去：它们本来就是「本 tick 的结果」，分散成三个参数
    // 只会让每个调用点重复三遍（也正好越过 clippy 的参数上限）。
    let mut tick = TelemetryTick {
        outcomes: Vec::new(),
        failures: Vec::new(),
        notifications: Vec::new(),
    };

    for input in &config.telemetry.logs.file_inputs {
        process_telemetry_input(
            config,
            input,
            &InputOrigin::default(),
            sink,
            &mut tick,
            next_seq,
        )
        .await;
    }
    for entry in work.log_inputs() {
        process_telemetry_input(
            config,
            &entry.input,
            &InputOrigin::new(entry.family.clone(), entry.unit_id.clone()),
            sink,
            &mut tick,
            next_seq,
        )
        .await;
    }

    tick
}

/// 跑一轮**到点**的导出器（`Exporter` 来源），把输出当记录上送。
///
/// 与 [`process_telemetry_inputs`] 平行，但导出器不是「读一个文件」而是「**周期跑一条固定命令**」：
///   * 周期是导出器属性（`crate::telemetry::exporters`），到点才跑；上次运行时刻落本地状态；
///   * 跑**无论成败都推进下次时间**（失败不每 tick 重试，避免刷屏）；
///   * 失败/写失败都如实打到自观测（`agentd.err`），不静默。
#[allow(clippy::too_many_arguments)]
pub(super) async fn process_exporters(
    work: &AppliedWorkGrant,
    state_dir: &Path,
    agent_id: &str,
    global_seq_path: &Path,
    sink: &mut TelemetryRecordSink,
    next_seq: &mut u64,
) {
    let runs = work.exporter_runs();
    let mut state = exporters::load_state(state_dir);
    let mut changed = false;
    // 剪掉不在本次授权里的缺件记录（面撤了，记录不该留着误导）。
    let before = state.missing.len();
    state
        .missing
        .retain(|id, _| runs.iter().any(|run| run.exporter_id == *id));
    if state.missing.len() != before {
        changed = true;
    }
    if runs.is_empty() {
        if changed {
            exporters::save_state(state_dir, &state);
        }
        return;
    }

    let now = exporters::now_ms();
    let mut ran_any = false;
    for run in runs {
        let Some(def) = exporters::def(&run.exporter_id) else {
            continue;
        };
        let argv = match exporters::argv_for(&run.exporter_id, run.arg.as_deref()) {
            Ok(argv) => argv,
            Err(err) => {
                eprintln!("wist-agentd exporter {} failed: {err}", run.exporter_id);
                continue;
            }
        };
        // **跑前预检**：工具不在就别 spawn —— 缺件是部署缺口（如忘装 smartmontools），
        // 不是「运行错误」。如实记进状态（`diagnose` 会展示），工具装上即自动恢复。
        let tool = exporters::tool_path(&argv).unwrap_or_default().to_string();
        if !exporters::tool_present(&tool) {
            let newly = state.missing.get(&run.exporter_id) != Some(&tool);
            state.missing.insert(run.exporter_id.clone(), tool.clone());
            if newly {
                changed = true;
                eprintln!(
                    "wist-agentd exporter {} tool missing: {tool} \
                     （对应面今天采不到；装上后自动恢复）",
                    run.exporter_id
                );
            }
            // 不推进周期：工具一装上，下一个 tick 就能跑。
            continue;
        }
        if state.missing.remove(&run.exporter_id).is_some() {
            changed = true;
            eprintln!(
                "wist-agentd exporter {} tool available again: {tool}",
                run.exporter_id
            );
        }
        if !exporters::is_due(
            def.period_secs,
            state.last_run_ms.get(&run.input_id).copied(),
            now,
        ) {
            continue;
        }
        // 先记「已尝试」：失败也推进下次时间（否则一个坏导出器每 tick 重试）。
        state.last_run_ms.insert(run.input_id.clone(), now);
        changed = true;
        ran_any = true;
        match exporters::run_argv(&argv, def.timeout_secs).await {
            Ok(output) => {
                let records = exporters::records_from_output(
                    agent_id,
                    &run.input_id,
                    &run.target,
                    &run.family,
                    &run.unit_id,
                    &output,
                    next_seq,
                );
                if !records.is_empty()
                    && let Err(err) = sink.write_records(&records).await
                {
                    eprintln!(
                        "wist-agentd exporter {} uplink failed: {err}",
                        run.exporter_id
                    );
                }
                eprintln!(
                    "event=ExporterRun exporter={} unit={} records={}",
                    run.exporter_id,
                    run.unit_id,
                    records.len()
                );
            }
            Err(err) => eprintln!("wist-agentd exporter {} failed: {err}", run.exporter_id),
        }
    }
    if changed {
        exporters::save_state(state_dir, &state);
    }
    if ran_any && let Err(err) = log_seq_state::store_async(global_seq_path, *next_seq).await {
        eprintln!("wist-agentd exporter seq persist failed: {err}");
    }
}

async fn process_telemetry_input<S: RecordSink>(
    config: &AgentConfig,
    input: &LogFileInputSection,
    origin: &InputOrigin,
    sink: &mut S,
    tick: &mut TelemetryTick,
    next_seq: &mut u64,
) {
    // 目标形态先过一道：通配 / `~` / 相对路径今天采不了，要报成“形态不支持”，
    // 而不是拖到下面报“路径不存在”（那会把运维引去查权限）。
    if let Some(failure) = unsupported_target(input) {
        tick.failures.push(failure);
        return;
    }

    let source_path = PathBuf::from(&input.path);
    if !source_path.exists() {
        tick.failures.push(missing_input_failure(input));
        match replay_spool_only(config, input, sink).await {
            Ok(Some(outcome)) => tick.outcomes.push(outcome),
            Ok(None) => {}
            Err(err) => tick.failures.push(processing_failure(
                input,
                format!("failed to replay spool: {err}"),
            )),
        }
        return;
    }

    match process_input_with_sink(config, input, origin, source_path, sink, next_seq).await {
        Ok(outcome) => {
            if outcome.paused {
                tick.notifications.push(TelemetryWorkState {
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
                tick.failures.push(failure);
            }
            // 出口写失败：记录已安全进 spool，但**写出口**没成。必须说出来 ——
            // 旧行为里第一次失败是完全静默的（只有下一轮的回放失败才会报），
            // 而目标现在由控制面下发 —— 填错必须当场看得见，不能等 spool 涨到上限才 `pause`。
            if let Some(detail) = outcome.sink_error.as_deref() {
                tick.failures
                    .push(uplink_failure(input, detail, Some(outcome.spooled)));
            }
            tick.outcomes.push(outcome);
        }
        Err(err) => match uplink_write_detail(&err) {
            // 回放阶段的出口失败也要归到出口失败类（而不是含混的「处理失败」）：
            // 靠 `UplinkWriteError` 标记分辨（`warp_parse`），不靠错误文本。
            Some(detail) => tick.failures.push(uplink_failure(input, detail, None)),
            None => tick
                .failures
                .push(processing_failure(input, err.to_string())),
        },
    }
}

async fn process_input_with_sink<S: RecordSink>(
    config: &AgentConfig,
    input: &LogFileInputSection,
    origin: &InputOrigin,
    source_path: PathBuf,
    sink: &mut S,
    next_seq: &mut u64,
) -> io::Result<ProcessOutcome> {
    let mut processor = FileInputProcessor::new(
        build_file_input_config(config, input, source_path, origin),
        sink,
    );
    processor.process_once_async(next_seq).await
}

#[cfg(test)]
mod tests {
    use super::{UplinkHealth, len_framing_required};

    #[test]
    fn uplink_health_reports_recovery_once_and_only_after_a_real_send() {
        let mut health = UplinkHealth::default();

        // 安静且没失败：不宣告任何事（“没试就不知道”）。
        assert!(health.note_tick(false, false).is_none());
        // 真的发出去过、也没失败：同样不宣告。
        assert!(health.note_tick(false, true).is_none());

        // 失败 → 只有**真的发出去了**才算恢复。
        assert!(health.note_tick(true, false).is_none());
        assert!(
            health.note_tick(false, false).is_none(),
            "没试就不算恢复（不能臆造健康）"
        );
        let recovery = health.note_tick(false, true).expect("recovery line");
        assert!(recovery.contains("UplinkRecovered"), "{recovery}");
        // 只报一次。
        assert!(health.note_tick(false, true).is_none());

        // 再次失败 → 恢复 → 再报一次（跳动的出口不该静默）。
        assert!(health.note_tick(true, true).is_none());
        assert!(health.note_tick(false, true).is_some());
    }
    use wist_contracts::agent_config::{
        LogFileInputSection, LogsOutputSection, LogsTcpOutputSection,
    };

    fn output(kind: &str, framing: &str) -> LogsOutputSection {
        LogsOutputSection {
            kind: kind.to_string(),
            tcp: LogsTcpOutputSection {
                framing: framing.to_string(),
                ..Default::default()
            },
            ..Default::default()
        }
    }

    fn input(id: &str, multiline: &str) -> LogFileInputSection {
        LogFileInputSection {
            input_id: id.to_string(),
            path: "/var/log/app.log".to_string(),
            startup_position: "tail".to_string(),
            multiline_mode: multiline.to_string(),
        }
    }

    fn required(output: &LogsOutputSection, inputs: &[LogFileInputSection]) -> Option<String> {
        len_framing_required(output, inputs.iter()).map(str::to_string)
    }

    #[test]
    fn a_folding_input_forces_length_framing_on_a_line_uplink() {
        // `line` 分帧靠 `\n` 切帧；折叠出的正文自带换行 → 续行会被当成独立行、掉进 miss。
        // 所以只要有一个输入要归并，就必须升到 `len`，而且要报出是谁要求的。
        let output = output("tcp", "line");
        assert_eq!(
            required(&output, &[input("a", "none"), input("b", "indented")]),
            Some("b".to_string())
        );
    }

    #[test]
    fn all_single_line_inputs_leave_the_configured_framing_alone() {
        let output = output("tcp", "line");
        assert_eq!(required(&output, &[input("a", "none")]), None);
    }

    #[test]
    fn an_explicit_length_uplink_needs_no_escalation() {
        // 配置已经写了 `len`：对单行同样合法，不必（也不该）再报一次升级。
        let output = output("tcp", "len");
        assert_eq!(required(&output, &[input("a", "indented")]), None);
    }

    #[test]
    fn a_file_uplink_needs_no_escalation() {
        // file sink 逐条 JSON 编码，换行天然安全 —— 没有“被切开”这回事。
        let output = output("file", "line");
        assert_eq!(required(&output, &[input("a", "indented")]), None);
    }
}
