use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::agent_config::{
    AgentConfig, LogFileInputSection, LogsOutputSection, LogsSection,
};
use wist_shared::time::now_rfc3339;

use crate::control::work::{AppliedWorkGrant, WorkExporterRun};
use crate::state_store::log_seq_state;
use crate::telemetry::exporters;
use crate::telemetry::logs::InputOrigin;
use crate::telemetry::logs::files::file::FamilyCapacity;
use crate::telemetry::logs::files::{
    FileFamilyProcessor, FileInputProcessor, ProcessOutcome, is_family_target,
};
use crate::telemetry::logs::gate::Withheld;
use crate::telemetry::warp_parse::{
    RecordSink, SinkIdentity, TcpFraming, TelemetryRecordSink, uplink_write_detail,
};

#[path = "daemon_telemetry_support.rs"]
mod support;

use support::{
    build_file_input_config, capacity_failure, headless_lines_failure, invalid_output_failure,
    missing_input_failure, noise_dropped_failure, processing_failure, replay_spool_only,
    selection_filtered_failure, spool_paused_reason, truncated_failure, unsupported_target,
    uplink_failure, withheld_failure,
};

// 生效输出解析要给主循环用（它在短路前算），所以在同一层再导出一次；
// `pub(crate)` 也让 `doctor` 复用同一套判定（工具说一套、进程做一套是没有意义的）。
pub(crate) use support::effective_output;
/// 调查（`telemetry-health`）复用同一条 spool 路径：两处各写一份迟早会漂。
pub(crate) use support::spool_path_for_id;

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
    /// 单行超过 `max_line_bytes` 被截断提交。
    ///
    /// 为什么它必须可见：对纯文本只是“少了一点尾巴”，对 **JSON Lines**（如 Suricata 的
    /// `eve.json`）产出的是一条永远解析不了的记录。没有这一行，“下游为什么有坏 JSON”
    /// 就只能猜。量与去重口径同 `NoiseDropped`（量在 `magnitude`）。
    TruncatedLine,
    /// 文件族触顶（`max_files`）：新文件不再纳入跟踪（**没采全**，不是"没匹配"）。
    CapacityExceeded,
    /// 按 `drop_if_contains` 丢掉噪音行：**配置的正常结果，不是故障**。
    ///
    /// 为什么走这条通道（并打 `info` 而不是 `error`）：它需要“同一问题只报一次”的去重，
    /// 否则每分钟一条的 `pam_unix(cron:session)` 会让自观测也变成噪音。
    NoiseDropped,
    /// 多行读法下因「没有头」被丢掉的行：既可能是落在一条记录的中间（启动 / 轮转的正常代价），
    /// 也可能是**这个格式根本不在起始行表里**（那就是这个容器一条数据都采不到）。
    ///
    /// 为什么它必须可见：以前这个数只活在界定器里，从不进自观测 ——
    /// “这个容器的日志怎么一条都没有”只能靠猜。
    HeadlessLinesDropped,
    /// 选源过滤器真的把现存文件剔掉了：**配置的正常结果，不是故障**。
    ///
    /// 与 `NoiseDropped` 同档（进 failure 通道只为蹭签名去重，打 `info`）。
    /// 它要回答两个问题：“过滤真的生效了吗”与“其中多少条是因为容器身份读不到才作的判定”
    /// —— 后者说明 `config.v2.json` 读不出来（权限 / 非 json-file 驱动 / 容器创建中），
    /// 那时排除式是静默 no-op、包含式会一条不收。
    SelectionFiltered,
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
        // 噪音行丢弃是**配置的正常结果**，不算“这台机器在干活”：
        // 一个持续丢 cron 噪音的空闲机器不该因此永远显示 `Active`。
        self.failures.iter().any(|failure| {
            failure.kind != TelemetryFailureKind::NoiseDropped
                && failure.kind != TelemetryFailureKind::SelectionFiltered
        }) || self.outcomes.iter().any(|outcome| {
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
        .find(|input| {
            // 读法词表与折叠器同源：新增长读法（`mysql_slow` / `postgres_csv`）自动升级分帧。
            crate::telemetry::logs::multiline::MultilineMode::parse(&input.multiline_mode)
                .is_some_and(|mode| mode.folds_records())
        })
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
    work: &AppliedWorkGrant,
    output: &LogsOutputSection,
) -> io::Result<TelemetryRecordSink> {
    let (identity, escalated) = resolve_sink_identity(work, output)?;
    log_framing_escalation(escalated.as_deref());
    Ok(identity.sink())
}

/// 跨 tick 复用的 sink 槽位。
///
/// **为什么必须复用**：`TcpRecordSink` 的连接、退避截止点与当前退避时长全在实例上。
/// 以前每轮 tick 都重新构造，于是：
///   * 健康链路每 3 秒重连一次（对端看到“连接抖动”，本机多一次 TCP 握手）；
///   * 断网时的指数退避（`1s..30s`）**跨不过 tick** —— 每拍都从 0 重来，
///     5 秒连接超时把 3 秒的节奏拉成 8 秒。
///
/// 重建条件只有一个：身份变了（本机配置与 grant 合流后的 `kind` / 目标 / 分帧）。
/// 目标换了还留着旧连接是错的；同一目标上的退避与连接则应该活到下一轮。
#[derive(Default)]
pub(super) struct TelemetrySinkSlot {
    identity: Option<SinkIdentity>,
    sink: Option<TelemetryRecordSink>,
}

impl TelemetrySinkSlot {
    /// 取本轮可用的 sink：身份没变就复用上一轮的实例（连接 + 退避状态都在）。
    pub(super) fn get_or_build(
        &mut self,
        work: &AppliedWorkGrant,
        output: &LogsOutputSection,
    ) -> io::Result<&mut TelemetryRecordSink> {
        let (identity, escalated) = resolve_sink_identity(work, output)?;
        if self.identity.as_ref() != Some(&identity) {
            // 只在分帧真的刚升上来的那一拍报一次；单纯换目标（例如网关改下发地址）
            // 不算“升级”，别把同一句话重复说。
            let already_len = matches!(
                self.identity.as_ref(),
                Some(SinkIdentity::Tcp {
                    framing: TcpFraming::Len,
                    ..
                })
            );
            if !already_len {
                log_framing_escalation(escalated.as_deref());
            }
            // 上一帧已经写完（写失败会交给后台收尾，见 `finish_in_background`），
            // 所以这里直接丢弃旧实例是干净的。
            self.identity = Some(identity);
            self.sink = None;
        }
        if self.sink.is_none() {
            self.sink = Some(self.identity.as_ref().expect("identity set above").sink());
        }
        Ok(self.sink.as_mut().expect("just built"))
    }
}

/// 算出本轮的 sink 身份，以及「是哪个输入把分帧升到 `len`」（仅用于日志）。
fn resolve_sink_identity(
    work: &AppliedWorkGrant,
    output: &LogsOutputSection,
) -> io::Result<(SinkIdentity, Option<String>)> {
    let from_work = work.log_inputs();
    let required = len_framing_required(output, from_work.iter().map(|entry| &entry.input));
    let identity = SinkIdentity::resolve(output, required.map(|_| TcpFraming::Len))?;
    Ok((identity, required.map(str::to_string)))
}

fn log_framing_escalation(input_id: Option<&str>) {
    let Some(input_id) = input_id else {
        return;
    };
    log::info!(
        "event=UplinkFramingEscalated from=line to=len input_id={input_id} reason=\"该输入声明多行读法，折叠出的正文可能含换行（协议 §3：line 只用于单行）\""
    );
}

/// 当 sink 无法构建（非法输出配置）时，为每个输入生成一条 `InvalidOutput` 失败。
pub(super) fn invalid_output_tick(work: &AppliedWorkGrant, detail: String) -> TelemetryTick {
    let failures = work
        .log_inputs()
        .into_iter()
        .map(|entry| invalid_output_failure(&entry.input, detail.clone()))
        .collect();
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
    // 追平预算**一轮 tick 一份**：它是“采集段总共能占多久”，不是每条输入的。
    let budget = CatchupBudget::new(&config.telemetry.logs);

    // **只跑网关派活折算出来的采集任务**。
    //
    // 本机 `[[telemetry.logs.file_inputs]]` 已废弃（0.18.5）：规模化部署里路径由网关按
    // “采集面 + 平台单元”下发，这 5 个面已经覆盖了原来本机手写的那几条（install.log /
    // launchd.log / wifi.log …），本机再配一遍只会制造“配了、也以为在采、其实没人管”的错觉。
    // 字段保留只为让旧 toml 还能启动（值被忽略）。
    for entry in work.log_inputs() {
        process_telemetry_input(
            config,
            &entry.input,
            &InputOrigin::new(entry.family.clone(), entry.unit_id.clone()),
            sink,
            &mut tick,
            next_seq,
            &budget,
        )
        .await;
    }

    tick
}

/// 一次导出器运行的失败（本轮没采成 / 没送达）。
///
/// 单独一条而不并进 [`TelemetryFailure`]：导出器按运行而不是按文件句柄计，
/// 且 `input_id` 带 `-exporter` 后缀、不落在工作视图的 `tasks` 里。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct ExporterFailure {
    pub(super) work_id: String,
    pub(super) input_id: String,
    pub(super) exporter_id: String,
    pub(super) detail: String,
}

/// 一轮导出器运行的结果。
///
/// 同时给成功项：失败要跨 tick 记忆到下一次**成功**，否则一个 60s 周期的导出器失败后，
/// 中间 59 秒的 tick 都会显示「正常」—— 那是假健康。
#[derive(Debug, Default)]
pub(super) struct ExporterReport {
    pub(super) failures: Vec<ExporterFailure>,
    /// 本轮真跑成功（含「跑成功但窗口里没条目」）的 `input_id`。
    pub(super) succeeded: Vec<String>,
}

/// 跑一轮**到点**的导出器（`Exporter` 来源），把输出当记录上送。
///
/// 与 [`process_telemetry_inputs`] 平行，但导出器不是「读一个文件」而是「**周期跑一条固定命令**」：
///   * 周期是导出器属性（`crate::telemetry::exporters`），到点才跑；上次运行时刻落本地状态；
///   * 调度上**无论成败都推进下次时间**（失败不每 tick 重试，避免刷屏）；
///   * 但**有状态导出器的游标只在数据交出去之后才推进**：上送失败时下一轮重读同一段
///     （至少一次），宁可重复也不把没送达的一段永久跳过；
///   * 失败/写失败都如实打到自观测（`agentd.err`），不静默；
///   * 同时交还本轮失败/成功项，供采集健康汇总（`ExporterReport`）。
#[allow(clippy::too_many_arguments)]
pub(super) async fn process_exporters(
    work: &AppliedWorkGrant,
    state_dir: &Path,
    agent_id: &str,
    global_seq_path: &Path,
    sink: &mut TelemetryRecordSink,
    next_seq: &mut u64,
) -> ExporterReport {
    let runs = work.exporter_runs();
    let mut state = exporters::load_state(state_dir);
    let mut report = ExporterReport::default();
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
        return report;
    }

    let now = exporters::now_ms();
    let mut ran_any = false;
    for run in runs {
        let Some(def) = exporters::def(&run.exporter_id) else {
            continue;
        };
        // 有状态导出器（内核日志）用上次落盘的游标续读；无状态的一律 `None`。
        // 游标的键是**运行标识**（与 `last_run_ms` 同一把钥匙）：两个单元盯同一个导出器时
        // 各读各的位置，最差重复，不会让其中一边静默收不到。
        let cursor = if exporters::uses_cursor(&run.exporter_id) {
            exporters::load_cursor(state_dir, &run.input_id)
        } else {
            None
        };
        let argv = match exporters::argv_for_run(
            &run.exporter_id,
            run.arg.as_deref(),
            cursor.as_deref(),
        ) {
            Ok(argv) => argv,
            Err(err) => {
                log::error!("wist-agentd exporter {} failed: {err}", run.exporter_id);
                report.failures.push(ExporterFailure {
                    work_id: run.work_id,
                    input_id: run.input_id,
                    exporter_id: run.exporter_id,
                    detail: err.to_string(),
                });
                continue;
            }
        };
        // **跑前预检**：工具不在就别 spawn —— 缺件是部署缺口（如忘装 smartmontools），
        // 不是「运行错误」。如实记进状态（`diagnose` 会展示），工具装上即自动恢复。
        let tool = exporters::tool_path(&argv).unwrap_or_default().to_string();
        if !exporters::tool_present(&tool) {
            let newly = state.missing.get(&run.exporter_id) != Some(&tool);
            state.missing.insert(run.exporter_id.clone(), tool.clone());
            report.failures.push(ExporterFailure {
                work_id: run.work_id.clone(),
                input_id: run.input_id.clone(),
                exporter_id: run.exporter_id.clone(),
                detail: format!("工具缺失：{tool}（装上后自动恢复）"),
            });
            if newly {
                changed = true;
                log::warn!(
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
            log::info!(
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
        match exporters::run_with_cursor_fallback(
            &run.exporter_id,
            run.arg.as_deref(),
            cursor.as_deref(),
            def.timeout_secs,
        )
        .await
        {
            Ok((output, fell_back)) => {
                if fell_back {
                    // 这条自观测就是“采集没有静默退回文件 / 没有卡死”的证据（见 D6）。
                    log::warn!(
                        "event=ExporterCursorFallback exporter={} action=\"游标已失效（可能被 journal vacuum 清掉）；已回退 --since {} 重读\"",
                        run.exporter_id,
                        exporters::KERNEL_INITIAL_SINCE
                    );
                }
                // 一行一条 JSON = 一条记录（body 原样）。
                let records = exporters::records_from_output(
                    agent_id,
                    &run.input_id,
                    &run.target,
                    exporters::emits_journald_json(&run.exporter_id),
                    &run.family,
                    &run.unit_id,
                    &output,
                    next_seq,
                );
                // 游标只在**这一段真的交出去**之后才推进：上送失败还推进，等于把这一段
                // 永久丢掉（journal 不会因为你没发成功就回滚）。宁可下一轮重读一次。
                let mut delivered = true;
                if !records.is_empty()
                    && let Err(err) = sink.write_records(&records).await
                {
                    delivered = false;
                    log::error!(
                        "wist-agentd exporter {} uplink failed: {err}",
                        run.exporter_id
                    );
                    report.failures.push(ExporterFailure {
                        work_id: run.work_id.clone(),
                        input_id: run.input_id.clone(),
                        exporter_id: run.exporter_id.clone(),
                        detail: format!("上送失败：{err}"),
                    });
                }
                if delivered {
                    // 真跑成功（含「窗口里没条目」）：清掉跨 tick 的失败记忆。
                    report.succeeded.push(run.input_id.clone());
                    persist_cursor(state_dir, &run, &output, fell_back);
                } else {
                    log::warn!(
                        "event=ExporterCursorHeld exporter={} note=\"本轮上送失败，游标不推进；下一轮重读同一段（至少一次）\"",
                        run.exporter_id
                    );
                }
                log::info!(
                    "event=ExporterRun exporter={} unit={} records={}",
                    run.exporter_id,
                    run.unit_id,
                    records.len()
                );
            }
            Err(err) => {
                // 带游标却超时 → 游标指向旧位置，journalctl 静默重读整份 journal（实测），
                // 留它只会每轮超时。清掉，下一轮走有界的 `--since`。
                let reset = exporters::should_reset_cursor(cursor.as_deref(), &err);
                if reset {
                    if let Err(clear_err) = exporters::clear_cursor(state_dir, &run.input_id) {
                        log::error!(
                            "wist-agentd exporter {} cursor clear failed: {clear_err}",
                            run.exporter_id
                        );
                    }
                    log::warn!(
                        "event=ExporterCursorReset exporter={} reason=timeout action=\"游标可能指向已不存在的旧位置（重读整份 journal 超时）；已清游标，下一轮从 --since 重读\"",
                        run.exporter_id
                    );
                }
                log::error!("wist-agentd exporter {} failed: {err}", run.exporter_id)
            }
        }
    }
    if changed {
        exporters::save_state(state_dir, &state);
    }
    if ran_any && let Err(err) = log_seq_state::store_async(global_seq_path, *next_seq).await {
        log::error!("wist-agentd exporter seq persist failed: {err}");
    }
    report
}

/// 把本轮取到的游标落盘；取不到就如实说，不静默丢下一段。
///
/// 四种情形分开处理，因为「没游标」的原因决定了下一轮会不会重复读：
///   * 有新游标 → 原子落盘；
///   * 窗口里**真没条目**（输出为空）→ 什么都不做（内核安静是常态，不该每 60s 告警一次）；
///   * 回退过、且窗口里没条目 → 旧游标已证明是死的，**清掉**（否则每轮都失败一次再回退一次）；
///   * 有内容但取不到游标 → 保留旧游标并告警（宁可下一轮重复读一段，也不假装读到了）。
fn persist_cursor(state_dir: &Path, run: &WorkExporterRun, output: &str, fell_back: bool) {
    let exporter_id = run.exporter_id.as_str();
    let run_id = run.input_id.as_str();
    if !exporters::uses_cursor(exporter_id) {
        return;
    }
    match exporters::cursor_from_output(output) {
        Some(next) => {
            if let Err(err) = exporters::save_cursor(state_dir, run_id, &next) {
                log::error!("wist-agentd exporter {exporter_id} cursor persist failed: {err}");
            }
        }
        // 输出为空 = 这段时间没有新条目（正常）；但若刚回退过，说明旧游标确实是死的。
        None if output.trim().is_empty() => {
            if fell_back {
                if let Err(err) = exporters::clear_cursor(state_dir, run_id) {
                    log::error!("wist-agentd exporter {exporter_id} cursor clear failed: {err}");
                }
                log::warn!(
                    "event=ExporterCursorDropped exporter={exporter_id} \
                     note=\"回退后仍没有新游标；已清掉旧游标，下一轮从 --since 重新开始\""
                );
            }
        }
        None => log::warn!(
            "event=ExporterCursorMissing exporter={exporter_id} \
             note=\"本轮输出里没有 __CURSOR（journalctl 输出格式变了？）；保留旧游标，下一轮可能重复读同一段\""
        ),
    }
}

/// 一轮 tick 里「采集段」还能占多久。
///
/// 为什么需要它：`max_lines_per_tick` / `max_read_bytes_per_tick` 只是**一批**的上限，
/// 而主循环 3s 一拍 —— 只读一批的话，单输入上限就是 `4096 行 / 3s ≈ 1365 行/秒`。
/// 一条 IDS 的 `eve.json`（万级 EPS）会把 checkpoint 永远甩在文件尾后面，
/// spool 涨满后 `pause`：数据“采了”，但一直在滞后。
///
/// 两层时限：
///   * `slice`：**单条输入**的让位粒度（默认 400ms）—— 一个疯长的输入不能把后面的输饿死；
///   * `deadline`：**整轮 tick** 的总预算（默认 1800ms = 3s 拍的 60%）—— 采集排在
///     发现 / 指标之后，不能把一拍吃干净。
///
/// 任一为 `0` = 关闭追平，回到「每 tick 一批」的旧行为（逃生口）。
struct CatchupBudget {
    slice: Option<Duration>,
    deadline: Option<Instant>,
}

impl CatchupBudget {
    fn new(logs: &LogsSection) -> Self {
        if logs.catchup_slice_ms == 0 || logs.catchup_budget_ms == 0 {
            return Self {
                slice: None,
                deadline: None,
            };
        }
        let slice = Duration::from_millis(logs.catchup_slice_ms);
        let total = Duration::from_millis(logs.catchup_budget_ms);
        Self {
            slice: Some(slice),
            // 全局预算是**硬上限**：哪怕配置把片写得比它长，也不越过它 ——
            // 否则“采集段最多占一拍 60%”就只是一句口号。
            deadline: Some(Instant::now() + total),
        }
    }

    /// 本条输入的截止时刻（`None` = 追平已关闭，只跑一批）。
    fn slice_deadline(&self) -> Option<Instant> {
        let slice = self.slice?;
        let slice_end = Instant::now() + slice;
        Some(match self.deadline {
            Some(global) if global < slice_end => global,
            _ => slice_end,
        })
    }

    fn exhausted(&self) -> bool {
        self.deadline.is_some_and(|end| Instant::now() >= end)
    }
}

/// **一条输入**在一轮 tick 里的报告汇总。
///
/// 为什么要汇总：追平会让同一条输入在一拍里跑多批。若每批都往 `tick.failures` 里推一条，
/// 同一个问题在一拍里会被打 N 次（`filter_new_failures` 只跟**上一拍**的签名比，
/// 不处理同一拍内的重复）—— 那正好把「按签名去重」毁了。所以量在这里累加，拍末只报一次。
#[derive(Default)]
struct InputTickReports {
    /// 泵停时的 spool 字节数（只记第一次：暂停就跳出了，本来也只会有一批）。
    paused_spool_bytes: Option<u64>,
    withheld: Withheld,
    dropped_noise: usize,
    headless_lines: usize,
    truncated_lines: usize,
    selection_filtered: usize,
    identity_unknown: usize,
    spooled: usize,
    sink_error: Option<String>,
    capacity: Option<FamilyCapacity>,
}

impl InputTickReports {
    fn observe(&mut self, outcome: &ProcessOutcome) {
        if outcome.paused && self.paused_spool_bytes.is_none() {
            self.paused_spool_bytes = Some(outcome.spool_bytes);
        }
        self.withheld.records += outcome.withheld.records;
        self.withheld.bytes += outcome.withheld.bytes;
        self.dropped_noise += outcome.dropped_noise;
        self.headless_lines += outcome.headless_lines;
        self.truncated_lines += outcome.truncated_lines;
        self.selection_filtered += outcome.selection_filtered;
        self.identity_unknown += outcome.identity_unknown;
        self.spooled += outcome.spooled;
        if outcome.capacity.is_some() {
            self.capacity = outcome.capacity.clone();
        }
        if let Some(detail) = outcome.sink_error.as_deref() {
            self.sink_error = Some(detail.to_string());
        }
    }

    /// 能不能再追一批：追平靠**读到了行**判断（`records_processed` 会被多行折叠 / 噪音丢弃
    /// 变成 0，`checkpoint_offset` 在未封口块下不前进）。
    fn made_progress(outcome: &ProcessOutcome) -> bool {
        outcome.read_lines > 0 && !outcome.paused && outcome.sink_error.is_none()
    }
}

async fn process_telemetry_input<S: RecordSink>(
    config: &AgentConfig,
    input: &LogFileInputSection,
    origin: &InputOrigin,
    sink: &mut S,
    tick: &mut TelemetryTick,
    next_seq: &mut u64,
    budget: &CatchupBudget,
) {
    // 目标形态先过一道：`**` / `~` / 相对路径采不了，要报成“形态不支持”，
    // 而不是拖到下面报“路径不存在”（那会把运维引去查权限）。
    if let Some(failure) = unsupported_target(input) {
        tick.failures.push(failure);
        return;
    }

    let source_path = PathBuf::from(&input.path);
    let family_target = is_family_target(&input.path);
    if !family_target && !source_path.exists() {
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

    let mut reports = InputTickReports::default();
    loop {
        let slice_end = budget.slice_deadline();
        let outcome = match process_input_with_sink(
            config,
            input,
            origin,
            source_path.clone(),
            sink,
            next_seq,
        )
        .await
        {
            Ok(outcome) => outcome,
            Err(err) => {
                match uplink_write_detail(&err) {
                    // 回放阶段的出口失败也要归到出口失败类（而不是含混的「处理失败」）：
                    // 靠 `UplinkWriteError` 标记分辨（`warp_parse`），不靠错误文本。
                    Some(detail) => tick.failures.push(uplink_failure(input, detail, None)),
                    None => tick
                        .failures
                        .push(processing_failure(input, err.to_string())),
                }
                break;
            }
        };
        reports.observe(&outcome);
        let again = InputTickReports::made_progress(&outcome) && slice_end.is_some();
        // 每批的 outcome 都留下：`is_active` / “本轮发过东西吗”本来就是“任一批”的语义。
        tick.outcomes.push(outcome);
        if !again {
            break;
        }
        if slice_end.is_some_and(|end| Instant::now() >= end) || budget.exhausted() {
            break;
        }
    }

    // 拍末一次性上报（顺序与旧行为一致：先工作状态，再失败）。
    if let Some(spool_bytes) = reports.paused_spool_bytes {
        tick.notifications.push(TelemetryWorkState {
            input_id: input.input_id.clone(),
            state: WorkState::Paused,
            reason: spool_paused_reason(spool_bytes),
            at: now_rfc3339(),
        });
    }
    if let Some(failure) = withheld_failure(input, &reports.withheld) {
        tick.failures.push(failure);
    }
    // 触顶：不说出来，「为什么这台机器的某个容器没数据」就只能靠猜。
    if let Some(capacity) = reports.capacity.as_ref() {
        tick.failures.push(capacity_failure(input, capacity));
    }
    // 噪音行丢弃：配置的正常结果，但**必须可对账** ——
    // 否则“这个面怎么少了一半”只能靠猜。走 failure 通道蹭它的按签名去重。
    if reports.dropped_noise > 0 {
        tick.failures
            .push(noise_dropped_failure(input, reports.dropped_noise));
    }
    // “没有头”被丢掉的行：多行读法下这就是“这个容器怎么一条都没有”的答案。
    // 与噪音丢弃分开报：一个是配置主动剔除，一个是读法没认出这个格式。
    if let Some(failure) = headless_lines_failure(input, reports.headless_lines) {
        tick.failures.push(failure);
    }
    // 超长行被截断：对纯文本是“丢一点尾巴”，对 **JSON Lines 就是产出一条永远解析不了的
    // 记录**。必须让它可见，否则“下游为什么有坏 JSON”查不到源头。
    if reports.truncated_lines > 0 {
        tick.failures
            .push(truncated_failure(input, reports.truncated_lines));
    }
    // 选源过滤：同样要能对账。与噪音丢弃分开报 ——
    // “剔了几个文件”与“丢了几行记录”是两种量，混在一起就都看不准。
    if reports.selection_filtered > 0 || reports.identity_unknown > 0 {
        tick.failures.push(selection_filtered_failure(
            input,
            reports.selection_filtered,
            reports.identity_unknown,
        ));
    }
    // 出口写失败：记录已安全进 spool，但**写出口**没成。必须说出来 ——
    // 旧行为里第一次失败是完全静默的（只有下一轮的回放失败才会报），
    // 而目标现在由控制面下发 —— 填错必须当场看得见，不能等 spool 涨到上限才 `pause`。
    if let Some(detail) = reports.sink_error.as_deref() {
        tick.failures
            .push(uplink_failure(input, detail, Some(reports.spooled)));
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
    let config = build_file_input_config(config, input, source_path, origin);
    if is_family_target(&input.path) {
        let mut processor = FileFamilyProcessor::new(config, sink);
        processor.process_once_async(next_seq).await
    } else {
        let mut processor = FileInputProcessor::new(config, sink);
        processor.process_once_async(next_seq).await
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{
        CatchupBudget, InputTickReports, TelemetrySinkSlot, UplinkHealth, len_framing_required,
    };
    use crate::config::agent_config::LogsSection;
    use crate::control::work::AppliedWorkGrant;
    use crate::telemetry::logs::files::file::{FamilyCapacity, ProcessOutcome, ProcessOutcomeKind};
    use crate::telemetry::logs::gate::Withheld;
    use wist_contracts::telemetry_record::DataFrame;

    /// 一个“本批读了 N 行”的来源批次；其余字段默认空，用例按需覆盖。
    fn outcome(read_lines: usize) -> ProcessOutcome {
        ProcessOutcome {
            kind: ProcessOutcomeKind::SourceBatch,
            records_processed: read_lines,
            emitted_directly: 0,
            spooled: 0,
            sink_error: None,
            checkpoint_offset: 0,
            replayed_spool: 0,
            truncated: false,
            truncated_lines: 0,
            read_lines,
            withheld: Withheld::default(),
            dropped_noise: 0,
            headless_lines: 0,
            selection_filtered: 0,
            identity_unknown: 0,
            rotated: false,
            paused: false,
            spool_bytes: 0,
            capacity: None,
        }
    }

    /// 追平会把同一条输入的失败/计数拆到多批上；聚合必须“加起来只报一次”。
    #[test]
    fn input_tick_reports_aggregate_across_batches() {
        let mut reports = InputTickReports::default();

        let mut first = outcome(10);
        first.withheld = Withheld {
            records: 2,
            bytes: 100,
        };
        first.dropped_noise = 1;
        first.headless_lines = 4;
        first.truncated_lines = 3;
        first.spooled = 5;
        first.selection_filtered = 2;
        first.identity_unknown = 1;
        first.paused = true;
        first.spool_bytes = 1234;
        first.capacity = Some(FamilyCapacity {
            tracked: 512,
            max_files: 512,
            refused: 4,
        });
        reports.observe(&first);

        let mut second = outcome(7);
        second.withheld = Withheld {
            records: 1,
            bytes: 50,
        };
        second.dropped_noise = 2;
        second.headless_lines = 6;
        second.truncated_lines = 4;
        second.spooled = 6;
        second.selection_filtered = 1;
        second.identity_unknown = 2;
        // 第二批又报了一次暂停：只记第一次（暂停后本来就会跳出，这里只是钉住汇总口径）。
        second.paused = true;
        second.spool_bytes = 9999;
        // 触顶与出口失败都取“最后一次看到的”，量由各自签名去重后只报一行。
        second.capacity = Some(FamilyCapacity {
            tracked: 512,
            max_files: 512,
            refused: 1,
        });
        second.sink_error = Some("tcp 10.0.0.1:9000 refused".to_string());
        reports.observe(&second);

        assert_eq!(reports.withheld.records, 3);
        assert_eq!(reports.withheld.bytes, 150);
        assert_eq!(reports.dropped_noise, 3);
        assert_eq!(reports.headless_lines, 10, "无头行跨批累加");
        assert_eq!(reports.truncated_lines, 7, "截断数是跨批累加的");
        assert_eq!(reports.spooled, 11);
        assert_eq!(reports.selection_filtered, 3);
        assert_eq!(reports.identity_unknown, 3);
        assert_eq!(reports.paused_spool_bytes, Some(1234), "暂停只记第一次");
        assert_eq!(
            reports.capacity.as_ref().map(|capacity| capacity.refused),
            Some(1),
            "触顶取最后一次"
        );
        assert_eq!(
            reports.sink_error.as_deref(),
            Some("tcp 10.0.0.1:9000 refused"),
            "出口失败取最后一次（目标/原因会变）"
        );
    }

    /// 追平的唯一进度判据是「本批读到了行」。
    ///
    /// 用 `records_processed` 会漏：噪音全丢 / 多行未封口时它可以是 0；
    /// 用 `checkpoint_offset` 也会漏：未封口块下它不前进。
    #[test]
    fn made_progress_means_lines_were_read_and_nothing_is_stuck() {
        assert!(InputTickReports::made_progress(&outcome(1)));
        assert!(
            !InputTickReports::made_progress(&outcome(0)),
            "已追平就不再循环"
        );

        let mut paused = outcome(10);
        paused.paused = true;
        assert!(
            !InputTickReports::made_progress(&paused),
            "spool 暂停时继续读只会把积压堆高"
        );

        let mut failed = outcome(10);
        failed.sink_error = Some("refused".to_string());
        assert!(
            !InputTickReports::made_progress(&failed),
            "出口写失败时继续读只会把 spool 堆得更高"
        );
    }

    #[test]
    fn catchup_can_be_disabled_by_either_zero() {
        let logs = LogsSection {
            catchup_slice_ms: 0,
            ..Default::default()
        };
        let budget = CatchupBudget::new(&logs);
        assert!(
            budget.slice_deadline().is_none(),
            "slice=0 必须回到「每 tick 一批」"
        );
        assert!(!budget.exhausted(), "关闭追平时不应报预算耗尽");

        let logs = LogsSection {
            catchup_budget_ms: 0,
            ..Default::default()
        };
        assert!(CatchupBudget::new(&logs).slice_deadline().is_none());
    }

    #[test]
    fn catchup_slice_never_exceeds_the_tick_budget() {
        let logs = LogsSection {
            catchup_slice_ms: 5_000,
            catchup_budget_ms: 1_000,
            ..Default::default()
        };
        let budget = CatchupBudget::new(&logs);
        let deadline = budget.slice_deadline().expect("追平开启时必须给截止时间");
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            remaining <= Duration::from_millis(1_000),
            "单个片不能越过整轮预算（实际剩余 {remaining:?}）"
        );
    }

    #[test]
    fn tick_budget_is_a_hard_cap_even_when_the_slice_is_longer() {
        // 配置把片写得比预算长时不放大预算：采集段不能因此吃掉整拍。
        let logs = LogsSection {
            catchup_slice_ms: 400,
            catchup_budget_ms: 10,
            ..Default::default()
        };
        let budget = CatchupBudget::new(&logs);
        let deadline = budget.slice_deadline().expect("追平开启时必须有截止时间");
        let remaining = deadline.saturating_duration_since(Instant::now());
        assert!(
            remaining <= Duration::from_millis(10),
            "整轮预算是硬上限（实际剩余 {remaining:?}）"
        );
    }

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
    use crate::config::agent_config::{
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
            exclude_globs: Vec::new(),
            filters: Default::default(),
            drop_if_contains: Vec::new(),
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
        // 新读法同样归并（CRI 容器日志的多行正文）：不升 `len` 就会把续行打散。
        assert_eq!(
            required(&output, &[input("a", "none"), input("b", "container_cri")]),
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

    // ------------------------------------------------------------------
    // 跨 tick 复用（P0）：连接与退避状态必须活过一拍
    // ------------------------------------------------------------------

    fn tcp_output(port: u16) -> LogsOutputSection {
        LogsOutputSection {
            kind: "tcp".to_string(),
            tcp: LogsTcpOutputSection {
                addr: "127.0.0.1".to_string(),
                port,
                framing: "line".to_string(),
            },
            ..Default::default()
        }
    }

    /// 数一数字节流里出现了几次某个帧标记。
    fn marker_count(bytes: &[u8], marker: &[u8]) -> usize {
        bytes
            .windows(marker.len())
            .filter(|window| *window == marker)
            .count()
    }

    /// 同一目标上的两拍必须共用**一条**连接。
    ///
    /// 这是 `TcpRecordSink` 的连接与指数退避能活过一拍的前提：每拍重连既是对端的连接抖动，
    /// 也会让 `1s..30s` 的退避跨不过 tick（断网时 3s 节奏被 5s 连接超时拉成 8s）。
    #[tokio::test(flavor = "current_thread")]
    async fn the_sink_slot_reuses_one_connection_across_ticks() {
        use tokio::io::AsyncReadExt;

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let port = listener.local_addr().expect("addr").port();
        // 只 accept 一次：第二拍若重连，就会在 backlog 里另起一条连接，这里只能看到一条。
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut seen = Vec::new();
            let mut buf = [0u8; 1024];
            loop {
                let read = socket.read(&mut buf).await.expect("read");
                if read == 0 {
                    break;
                }
                seen.extend_from_slice(&buf[..read]);
            }
            seen
        });

        let output = tcp_output(port);
        let grant = AppliedWorkGrant::default();
        let mut slot = TelemetrySinkSlot::default();
        for seq in [1u64, 2] {
            let sink = slot.get_or_build(&grant, &output).expect("sink");
            sink.write_fact(
                &DataFrame::new("agent-1", "2026-11-08T00:00:00Z", seq),
                b"{}",
            )
            .await
            .expect("write fact");
        }
        // 丢掉槽位 → 连接关闭 → server 读到 EOF 收尾。
        drop(slot);

        let seen = server.await.expect("server task");
        assert_eq!(
            marker_count(&seen, b" OBSFACT:"),
            2,
            "两拍的两帧必须落在同一条连接上"
        );
    }

    /// 复用的真正目的：**指数退避必须活过一拍**。
    ///
    /// 以前 sink 每 tick 重建，`next_attempt_at` / `backoff` 跟着实例一起丢——
    /// 断网时每拍都从 0 重来，5 秒连接超时把 3 秒节奏拉成 8 秒。
    /// 本用例不验“连接被复用”（那是另一个用例），验的是**退避状态没被扔**：
    /// 第二拍必须直接按退避失败，而不是再发起一次连接。
    #[tokio::test(flavor = "current_thread")]
    async fn the_sink_slot_keeps_the_backoff_window_across_ticks() {
        // 拿一个确定没人监听的端口：bind 成功后立刻释放。
        let port = {
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            listener.local_addr().expect("addr").port()
        };
        let output = tcp_output(port);
        let grant = AppliedWorkGrant::default();
        let mut slot = TelemetrySinkSlot::default();

        // 第一拍：真的去连，被拒 → 进退避。
        let first = slot
            .get_or_build(&grant, &output)
            .expect("第一拍要能构造 sink")
            .write_fact(&DataFrame::new("agent-1", "2026-11-08T00:00:00Z", 1), b"{}")
            .await
            .expect_err("没人监听，必须失败");
        assert!(
            !first.to_string().contains("backoff"),
            "第一次是**真连接失败**，不是退避: {first}"
        );

        // 第二拍（同一目标）：**不得再连一次**，直接按退避失败。
        let second = slot
            .get_or_build(&grant, &output)
            .expect("第二拍要能取回同一份 sink")
            .write_fact(&DataFrame::new("agent-1", "2026-11-08T00:00:00Z", 2), b"{}")
            .await
            .expect_err("退避窗口内必须失败");
        assert!(
            second.to_string().contains("tcp uplink in backoff"),
            "退避状态必须活过一拍（否则每拍重连，退避等于没有）: {second}"
        );
    }

    /// 目标变了必须重建：留着指向旧地址的连接是错的（那是上一份授权的出口）。
    #[tokio::test(flavor = "current_thread")]
    async fn the_sink_slot_rebuilds_when_the_target_changes() {
        use tokio::io::AsyncReadExt;

        let first = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind first");
        let second = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind second");
        let first_port = first.local_addr().expect("addr").port();
        let second_port = second.local_addr().expect("addr").port();
        let reader = |listener: tokio::net::TcpListener| {
            tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let mut seen = Vec::new();
                let mut buf = [0u8; 1024];
                loop {
                    let read = socket.read(&mut buf).await.expect("read");
                    if read == 0 {
                        break;
                    }
                    seen.extend_from_slice(&buf[..read]);
                }
                seen
            })
        };
        let first_server = reader(first);
        let second_server = reader(second);

        let grant = AppliedWorkGrant::default();
        let mut slot = TelemetrySinkSlot::default();
        for (port, seq) in [(first_port, 1u64), (second_port, 2)] {
            let sink = slot.get_or_build(&grant, &tcp_output(port)).expect("sink");
            sink.write_fact(
                &DataFrame::new("agent-1", "2026-11-08T00:00:00Z", seq),
                b"{}",
            )
            .await
            .expect("write fact");
        }
        drop(slot);

        let to_first = first_server.await.expect("first server");
        let to_second = second_server.await.expect("second server");
        assert_eq!(marker_count(&to_first, b" OBSFACT:"), 1);
        assert_eq!(
            marker_count(&to_second, b" OBSFACT:"),
            1,
            "换了目标就必须新建连接，而不是继续往旧地址写"
        );
    }
}
