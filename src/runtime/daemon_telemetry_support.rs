use std::io;
use std::path::{Path, PathBuf};

use crate::config::agent_config::{AgentConfig, LogFileInputSection, LogsOutputSection};
use wist_api::uplink::AgentUplinkGrant;

use crate::telemetry::logs::InputOrigin;
use crate::telemetry::logs::files::file_reader::ReadLimits;
use crate::telemetry::logs::files::file_watcher::StartupPosition;
use crate::telemetry::logs::files::{
    DEFAULT_MAX_FILES_PER_INPUT, DEFAULT_MAX_NEW_FILES_PER_TICK, DEFAULT_RESCAN_INTERVAL_MS,
    FileInputConfig, ProcessOutcome,
};
use crate::telemetry::logs::gate::Withheld;
use crate::telemetry::logs::multiline::MultilineMode;
use crate::telemetry::spool;
use crate::telemetry::warp_parse::{RecordSink, TcpFraming, TelemetryRecordSink};

use super::{TelemetryFailure, TelemetryFailureKind};

pub(super) const SPOOL_REPLAY_BATCH_SIZE: usize = 128;

/// 本轮该用哪个输出 —— 本机 `[telemetry.logs.output]` 与控制面 grant 合流后的结论。
///
/// 返回的是一份**覆盖后的 `LogsOutputSection`**，用它表达三态：
///   * `enabled = false` → **完全静默**（不读源、不写、不上送）；
///   * `enabled = true` + `kind = "file"` / `"tcp"` → 照常产出到本地文件 / 数据面 TCP。
///
/// 用「覆盖后的配置段」而不是另造一个枚举：下游的 sink 构建、分帧升级、kind 校验（未知
/// kind → `InvalidOutput`）全都按 `LogsOutputSection` 工作，覆盖后原地复用，行为与从前一致。
///
/// 生效规则（控制面 grant 优先于本机配置，严格按契约语义）：
///   1. 未下发（`None`：未入网 / 旧网关 404 / 网络失败 / 解析失败）→ 用本机配置；
///   2. 下发 `enabled = false` → 静默；
///   3. 下发 `enabled = true` 且带 `host`/`port` → **强制** `tcp(host, port)`，覆盖本机 `kind`
///      （本机即使是 `file` 也改成 tcp，`enabled` 也随之上开）；
///   4. 下发 `enabled = true` 但没给目标 → 沿用本机 `kind`（本机 `enabled = false` 则仍静默）。
///
/// 注意 `kind` 与 `enabled` 正交：grant 只改「写到哪」（`kind`/目标），不改「怎么分帧」
/// （`tcp.framing` 仍是本机的事实，由下游 `build_telemetry_sink` 按本轮输入决定要不要升 `len`）。
pub fn effective_output(
    config: &AgentConfig,
    grant: Option<&AgentUplinkGrant>,
) -> LogsOutputSection {
    let mut output = config.telemetry.logs.output.clone();

    if let Some(grant) = grant {
        if !grant.enabled {
            // 控制面明确关掉：总闸归零，与 kind 无关。
            output.enabled = false;
            return output;
        }
        if let Some((host, port)) = grant.target() {
            // 强制 tcp：覆盖本机 kind（本机 file 也改 tcp）与目标；enabled 随之上开。
            output.enabled = true;
            output.kind = "tcp".to_string();
            output.tcp.addr = host.to_string();
            output.tcp.port = port;
            return output;
        }
        // enabled 但没给目标：沿用本机 kind，继续往下按本机总闸判定。
    }

    // 本机总闸：与 kind 正交，false 即静默。
    if !output.enabled {
        return output;
    }
    output
}

pub(super) fn build_record_sink(
    output: &LogsOutputSection,
    framing: Option<TcpFraming>,
) -> io::Result<TelemetryRecordSink> {
    TelemetryRecordSink::from_logs_output(output, framing)
}

pub(super) async fn replay_spool_only<S: RecordSink>(
    config: &AgentConfig,
    input: &LogFileInputSection,
    sink: &mut S,
) -> io::Result<Option<ProcessOutcome>> {
    let spool_path = spool_path_for(config, input);
    if !spool::has_records_async(&spool_path).await? {
        return Ok(None);
    }

    let replayed = spool::replay_records_async(&spool_path, sink, SPOOL_REPLAY_BATCH_SIZE).await?;
    Ok(Some(ProcessOutcome::spool_replay_only(replayed)))
}

pub(super) fn build_file_input_config(
    config: &AgentConfig,
    input: &LogFileInputSection,
    source_path: PathBuf,
    origin: &InputOrigin,
) -> FileInputConfig {
    FileInputConfig {
        agent_id: config
            .agent
            .agent_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        input_id: input.input_id.clone(),
        origin: origin.clone(),
        source_path,
        exclude_globs: input.exclude_globs.clone(),
        filters: input.filters.clone(),
        max_files: DEFAULT_MAX_FILES_PER_INPUT,
        max_new_files: DEFAULT_MAX_NEW_FILES_PER_TICK,
        rescan_interval_ms: DEFAULT_RESCAN_INTERVAL_MS,
        state_dir: PathBuf::from(&config.paths.state_dir),
        spool_path: spool_path_for(config, input),
        startup_position: startup_position_for(input),
        multiline_mode: multiline_mode_for(input),
        in_memory_budget_bytes: config.telemetry.logs.in_memory_buffer_bytes as usize,
        read_limits: ReadLimits::new(
            config.telemetry.logs.max_line_bytes as usize,
            config.telemetry.logs.max_read_bytes_per_tick as usize,
            config.telemetry.logs.max_lines_per_tick as usize,
        ),
        spool_max_bytes: config.telemetry.logs.spool_max_bytes,
    }
}

pub(super) fn invalid_output_failure(
    input: &LogFileInputSection,
    detail: String,
) -> TelemetryFailure {
    TelemetryFailure {
        kind: TelemetryFailureKind::InvalidOutput,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail,
        magnitude: None,
    }
}

pub(super) fn missing_input_failure(input: &LogFileInputSection) -> TelemetryFailure {
    TelemetryFailure {
        kind: TelemetryFailureKind::MissingInput,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail: "source path does not exist".to_string(),
        magnitude: None,
    }
}

/// 这份输入的**目标形态**采集端今天能不能处理；不能就返回该报的失败。
///
/// 为什么单独一条（不复用 [`missing_input_failure`]）：
///   那个说的是“路径不存在”（去查权限/拼写），这个是“这种目标形态还没实现”
///   （去改成显式绝对路径 / 单层 glob）——两句话把人引向不同的下一步。
pub(super) fn unsupported_target(input: &LogFileInputSection) -> Option<TelemetryFailure> {
    let target = input.path.as_str();
    let shape_ok = target.starts_with('/')
        && !target.contains('~')
        // `**` 没实现：先扫固定前缀目录、`*` 不跨目录。放在这里拒，是为了报「形态不支持」
        // 而不是让文件族处理器每轮抛一次 InvalidInput（那会被当成目录不可读）。
        && !target.contains("**");
    if shape_ok {
        return None;
    }
    Some(TelemetryFailure {
        kind: TelemetryFailureKind::MissingInput,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail: "target must be an absolute path without `**` \
                 (single-level globs are supported; `~`, relative paths and recursive globs are not)"
            .to_string(),
        magnitude: None,
    })
}

pub(super) fn processing_failure(input: &LogFileInputSection, detail: String) -> TelemetryFailure {
    TelemetryFailure {
        kind: TelemetryFailureKind::ProcessingFailed,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail,
        magnitude: None,
    }
}

/// 记录已进 spool（等重发），但**写出口**这一步失败了。
///
/// **身份必须稳定**：同一次出口故障在一次 tick 里可能以两种形态被看到 —— 先行上送的指标
/// 把连接打进退避后，日志侧看到 `tcp uplink in backoff`；而没有指标的 tick 真的去连，看到
/// `Connection refused`。把这种易变的原文放进 `detail`，两者就成了**两个签名**、交替重报
/// （实测退化成每 tick 一行）。所以：
///   * `detail` 用**固定**身份串（同一次出口故障永远同一行）；
///   * 目标与底层原因（含 `host:port`）放 `magnitude` —— 会变、不参与签名，但照常打出来。
///
/// `spooled` 为 `None` = 本次不是「直发失败入 spool」，而是回放阶段失败（记录本就在 spool 里）。
pub(super) fn uplink_failure(
    input: &LogFileInputSection,
    raw_detail: &str,
    spooled: Option<usize>,
) -> TelemetryFailure {
    let magnitude = match spooled {
        Some(spooled) => format!("records={spooled} cause={raw_detail}"),
        None => format!("cause={raw_detail}"),
    };
    TelemetryFailure {
        kind: TelemetryFailureKind::OutputWriteFailed,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail: "output write failed; records buffered to spool".to_string(),
        magnitude: Some(magnitude),
    }
}

/// 有记录因**内容不全**被挡下。什么都没挡下就返回 `None`。
///
/// 身份用 `Withheld::detail`（稳定，参与去重），量用 `Withheld::magnitude`（会变，不参与）。
pub(super) fn withheld_failure(
    input: &LogFileInputSection,
    withheld: &Withheld,
) -> Option<TelemetryFailure> {
    if withheld.is_empty() {
        return None;
    }
    Some(TelemetryFailure {
        kind: TelemetryFailureKind::RecordWithheld,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail: withheld.detail(),
        magnitude: Some(withheld.magnitude()),
    })
}

/// 文件族触顶（`max_files`）：**没采全**，不是"没匹配"。
///
/// `detail` 必须稳定（去重按 `kind|input_id|path|detail`）：同一次触顶反复出现应当是同一行字；
/// 会变的量（拒绝了多少、当前跟踪多少）放 `magnitude`。
pub(super) fn capacity_failure(
    input: &LogFileInputSection,
    capacity: &crate::telemetry::logs::files::file::FamilyCapacity,
) -> TelemetryFailure {
    TelemetryFailure {
        kind: TelemetryFailureKind::CapacityExceeded,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail: format!(
            "file family reached max_files={} ; new files are not tracked              (raise the limit or narrow the pattern)",
            capacity.max_files
        ),
        magnitude: Some(format!(
            "refused={} tracked={}",
            capacity.refused, capacity.tracked
        )),
    }
}

pub(super) fn spool_paused_reason(spool_bytes: u64) -> String {
    format!("spool over limit ({spool_bytes} bytes); source read paused")
}

fn spool_path_for(config: &AgentConfig, input: &LogFileInputSection) -> PathBuf {
    Path::new(&config.telemetry.logs.spool_dir).join(format!("{}.ndjson", input.input_id))
}

fn multiline_mode_for(input: &LogFileInputSection) -> MultilineMode {
    match input.multiline_mode.as_str() {
        "indented" => MultilineMode::IndentedContinuation,
        _ => MultilineMode::None,
    }
}

/// 启动位：`tail`（默认，只采新增）| `head`（从文件头读一遍）。
///
/// 认不出的值一律按 `tail`：默认方向必须落在「不会把历史灌进去」那一侧。
fn startup_position_for(input: &LogFileInputSection) -> StartupPosition {
    match input.startup_position.as_str() {
        "head" => StartupPosition::Head,
        _ => StartupPosition::Tail,
    }
}

#[cfg(test)]
mod tests {
    use super::{
        InputOrigin, TelemetryFailureKind, Withheld, build_file_input_config, capacity_failure,
        effective_output, startup_position_for, unsupported_target, uplink_failure,
        withheld_failure,
    };
    use crate::config::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, LogFileInputSection,
        PathsSection,
    };
    use crate::telemetry::logs::files::file_watcher::StartupPosition;
    use std::path::PathBuf;
    use wist_api::uplink::AgentUplinkGrant;

    fn config_with_agent(agent_id: Option<&str>) -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: agent_id.map(str::to_string),
                environment_id: None,
                instance_name: None,
            },
            ControlPlaneSection::default(),
            PathsSection::default(),
            ExecutionSection::default(),
        )
    }

    fn input() -> LogFileInputSection {
        LogFileInputSection {
            input_id: "app".to_string(),
            path: "/var/log/app.log".to_string(),
            startup_position: "head".to_string(),
            multiline_mode: "none".to_string(),
            exclude_globs: Vec::new(),
            filters: Default::default(),
        }
    }

    #[test]
    fn startup_position_defaults_to_tail_and_a_typo_never_becomes_head() {
        // 默认方向必须落在“不会把历史灌进去”那一侧。
        // （本地配置里写错的值其实已在 `wist-validate` 被拒（`invalid_log_startup_position`）；
        // 这里是第二道：万一校验被绕过，也不能默默变成 head。）
        let cases = [
            ("tail", StartupPosition::Tail),
            ("", StartupPosition::Tail),
            ("head", StartupPosition::Head),
            ("typo", StartupPosition::Tail),
        ];
        for (raw, expected) in cases {
            let mut entry = input();
            entry.startup_position = raw.to_string();
            assert_eq!(startup_position_for(&entry), expected, "raw {raw:?}");
        }
    }

    #[test]
    fn a_relative_or_tilde_target_is_reported_as_such() {
        // `~` 不展开、相对路径依赖 cwd、`**` 未实现：必须报成“形态不支持”，
        // 而不是拖到下面报“路径不存在”或让文件族处理器每轮抛一次 IO 错误。
        for target in [
            "~/Library/Logs/Homebrew/*",
            "relative/app.log",
            "/var/log/**/*.log",
        ] {
            let mut entry = input();
            entry.path = target.to_string();
            let failure = unsupported_target(&entry).expect("must be rejected as unsupported");
            assert_eq!(failure.path, target);
            assert!(failure.detail.contains("absolute path"), "{failure:?}");
        }

        // 显式绝对路径、单层 glob、目录都放行：存在性 / 匹配由后面的处理器管。
        for target in [
            "/var/log/install.log",
            "/var/log/containers/*.log",
            "/var/log/postgresql",
        ] {
            let mut ok = input();
            ok.path = target.to_string();
            assert!(unsupported_target(&ok).is_none(), "{target}");
        }
    }

    #[test]
    fn a_capacity_report_becomes_a_stable_failure() {
        // `detail` 稳定（去重按它），会变的量放 `magnitude`。
        use crate::telemetry::logs::files::file::FamilyCapacity;
        let mut entry = input();
        entry.path = "/var/log/containers/*.log".to_string();
        let capacity = FamilyCapacity {
            tracked: 512,
            max_files: 512,
            refused: 37,
        };
        let failure = capacity_failure(&entry, &capacity);
        assert!(failure.detail.contains("max_files=512"), "{failure:?}");
        assert_eq!(failure.magnitude.as_deref(), Some("refused=37 tracked=512"));
        let again = capacity_failure(
            &entry,
            &FamilyCapacity {
                tracked: 512,
                max_files: 512,
                refused: 5,
            },
        );
        assert_eq!(failure.detail, again.detail, "签名不含量");
    }

    #[test]
    fn uses_configured_agent_id() {
        let config = build_file_input_config(
            &config_with_agent(Some("agent-x")),
            &input(),
            PathBuf::from("/var/log/app.log"),
            &InputOrigin::default(),
        );
        assert_eq!(config.agent_id, "agent-x");
    }

    #[test]
    fn falls_back_to_unknown_agent_id_when_not_configured() {
        let config = build_file_input_config(
            &config_with_agent(None),
            &input(),
            PathBuf::from("/var/log/app.log"),
            &InputOrigin::default(),
        );
        assert_eq!(config.agent_id, "unknown");
    }

    #[test]
    fn the_declared_read_mode_becomes_the_fold_mode() {
        // 授权工作里声明的读法（或配置里的 file_inputs）读到这里就变成本轮真用的归并模式。
        // 默认必须是一行一条：它错成 `indented` 会把独立记录粘成一条（无声的内容损坏）。
        let mut input = input();
        assert_eq!(
            build_file_input_config(
                &config_with_agent(Some("a")),
                &input,
                PathBuf::from("/var/log/app.log"),
                &InputOrigin::default(),
            )
            .multiline_mode,
            crate::telemetry::logs::multiline::MultilineMode::None
        );

        input.multiline_mode = "indented".to_string();
        assert_eq!(
            build_file_input_config(
                &config_with_agent(Some("a")),
                &input,
                PathBuf::from("/var/log/app.log"),
                &InputOrigin::default(),
            )
            .multiline_mode,
            crate::telemetry::logs::multiline::MultilineMode::IndentedContinuation
        );
    }

    #[test]
    fn a_problem_that_only_grows_is_not_reported_again() {
        // 去重签名是 `kind|input_id|path|detail`，所以**量不能进 `detail`**：
        // 一个持续存在的病态块每 tick 的量都在变，进了 `detail` 就每 tick 算一个新问题 ——
        // 那正好毁掉"走 failure 通道蹭去重"这个选择。量交给 `magnitude`。
        use crate::runtime::daemon::runtime_state_support::{
            failure_signatures, filter_new_failures,
        };

        let input = input();
        let first = withheld_failure(
            &input,
            &Withheld {
                records: 1,
                bytes: 11_890,
            },
        )
        .expect("failure");
        let later = withheld_failure(
            &input,
            &Withheld {
                records: 1,
                bytes: 4_194_304,
            },
        )
        .expect("failure");

        let seen = failure_signatures(std::slice::from_ref(&first));
        assert!(
            filter_new_failures(std::slice::from_ref(&later), &seen).is_empty(),
            "同一个问题只是变大了，不该算新签名：{seen:?}"
        );
        // 但量确实被记下来了（只是不参与去重）。
        assert_ne!(first.magnitude, later.magnitude);
        assert!(
            later
                .magnitude
                .as_deref()
                .expect("magnitude")
                .contains("bytes=4194304")
        );
    }

    #[test]
    fn an_output_write_failure_keeps_a_stable_identity_and_puts_the_target_in_the_magnitude() {
        // 同一次出口故障在一次 tick 里可能以两种形态出现：指标先失败把连接打进退避，
        // 日志侧看到 `tcp uplink in backoff`；没有指标的 tick 真的去连，看到 `Connection refused`。
        // 两者**必须同一签名**，否则交替重报（实测退化成每 tick 一行）。
        let input = input();
        let in_backoff = uplink_failure(&input, "10.0.1.9:9000: tcp uplink in backoff", Some(3));
        let refused = uplink_failure(
            &input,
            "10.0.1.9:9000: Connection refused (os error 61)",
            Some(5),
        );

        use crate::runtime::daemon::runtime_state_support::{
            failure_signatures, filter_new_failures,
        };
        let seen = failure_signatures(std::slice::from_ref(&in_backoff));
        assert!(
            filter_new_failures(std::slice::from_ref(&refused), &seen).is_empty(),
            "同一目标、只是错误形态不同，必须是同一签名"
        );
        assert_eq!(in_backoff.detail, refused.detail, "身份串必须是固定的");

        // 目标与底层原因仍要看得见（走 magnitude）。
        assert_eq!(in_backoff.kind, TelemetryFailureKind::OutputWriteFailed);
        let magnitude = in_backoff.magnitude.as_deref().expect("magnitude");
        assert!(magnitude.contains("10.0.1.9:9000"), "{magnitude}");
        assert!(magnitude.contains("backoff"), "{magnitude}");
        assert!(magnitude.contains("records=3"), "{magnitude}");

        // 回放阶段（本轮没有入 spool 的量）也要能报，并同样保持同一身份。
        let replayed = uplink_failure(&input, "10.0.1.9:9000: tcp connect timed out", None);
        assert_eq!(replayed.detail, in_backoff.detail);
        let magnitude = replayed.magnitude.as_deref().expect("magnitude");
        assert!(magnitude.contains("timed out"), "{magnitude}");
        assert!(
            !magnitude.contains("records="),
            "回放轮没有本轮入 spool 的量：{magnitude}"
        );
    }

    #[test]
    fn nothing_withheld_means_no_failure_at_all() {
        // 什么都没挡下就不该造一条 failure：空 failure 会被当成"这个输入有问题"而进健康快照。
        assert!(withheld_failure(&input(), &Withheld::default()).is_none());
    }

    // ── 生效输出（本机配置 ⊕ 控制面 grant）────────────────────────

    fn config_with_output(kind: &str, enabled: bool) -> AgentConfig {
        let mut config = config_with_agent(Some("agent-x"));
        config.telemetry.logs.output.kind = kind.to_string();
        config.telemetry.logs.output.enabled = enabled;
        config.telemetry.logs.output.tcp.addr = "127.0.0.1".to_string();
        config.telemetry.logs.output.tcp.port = 9000;
        config
    }

    fn grant_enabled(host: &str, port: u16) -> AgentUplinkGrant {
        AgentUplinkGrant::enabled_at(host.to_string(), port, "2026-09-26T00:00:00Z".to_string())
    }

    fn standby() -> AgentUplinkGrant {
        AgentUplinkGrant::standby("2026-09-26T00:00:00Z".to_string())
    }

    #[test]
    fn without_a_grant_the_local_config_decides() {
        // 未下发（未入网 / 旧网关 404 / 网络失败）→ 用本机配置，一字不改。
        let config = config_with_output("file", true);
        let resolved = effective_output(&config, None);
        assert!(resolved.enabled);
        assert_eq!(resolved.kind, "file");
        assert_eq!(resolved.file.path, config.telemetry.logs.output.file.path);
    }

    #[test]
    fn a_standby_grant_silences_the_output() {
        // 控制面明确关掉：不管本机 kind 是什么，总闸归零。
        let config = config_with_output("tcp", true);
        let resolved = effective_output(&config, Some(&standby()));
        assert!(!resolved.enabled);
    }

    #[test]
    fn an_enabled_grant_with_a_target_forces_tcp_over_the_local_kind() {
        // 本机 kind = file，grant 给了目标 → 强制 tcp(host, port)，覆盖本机 kind。
        let config = config_with_output("file", true);
        let resolved = effective_output(&config, Some(&grant_enabled("dp.example", 9100)));
        assert!(resolved.enabled);
        assert_eq!(resolved.kind, "tcp");
        assert_eq!(resolved.tcp.addr, "dp.example");
        assert_eq!(resolved.tcp.port, 9100);
    }

    #[test]
    fn an_enabled_grant_with_a_target_also_overrides_a_locally_disabled_gate() {
        // grant 优先于本机总闸：本机 enabled=false 也挡不住控制面的 enabled=true + 目标。
        let config = config_with_output("file", false);
        let resolved = effective_output(&config, Some(&grant_enabled("dp.example", 9100)));
        assert!(resolved.enabled);
        assert_eq!(resolved.kind, "tcp");
    }

    #[test]
    fn an_enabled_grant_without_a_target_follows_the_local_kind() {
        // enabled 但没给目标：沿用本机 kind（本机 file 就仍是 file）。
        let config = config_with_output("file", true);
        let mut grant = grant_enabled("ignored.example", 1);
        grant.host = None;
        grant.port = None;
        grant.enabled = true;
        let resolved = effective_output(&config, Some(&grant));
        assert!(resolved.enabled);
        assert_eq!(resolved.kind, "file");
    }

    #[test]
    fn a_locally_disabled_gate_silences_the_output_without_a_grant() {
        // 本机总闸：与 kind 正交，false 即静默。
        let config = config_with_output("tcp", false);
        let resolved = effective_output(&config, None);
        assert!(!resolved.enabled);
    }

    #[test]
    fn an_enabled_grant_without_a_target_respects_a_locally_disabled_gate() {
        // 契约 §3 第 4 行括号里的子句：`enabled = true` 但没给目标 → 沿用本机 kind；
        // 而**本机总闸关着**时仍是静默 —— grant 的 `enabled` 只表示「控制面允许」，
        // 没有目标就不构成一次有效的目标覆盖，不该把本机总闸撬开。
        let config = config_with_output("file", false);
        let mut grant = grant_enabled("ignored.example", 1);
        grant.host = None;
        grant.port = None;
        let resolved = effective_output(&config, Some(&grant));
        assert!(!resolved.enabled, "没有目标时不得攤开本机总闸");
    }
}
