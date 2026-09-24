use std::io;
use std::path::{Path, PathBuf};

use wist_contracts::agent_config::{AgentConfig, LogFileInputSection};

use crate::telemetry::logs::files::file_reader::ReadLimits;
use crate::telemetry::logs::files::file_watcher::StartupPosition;
use crate::telemetry::logs::files::{FileInputConfig, ProcessOutcome};
use crate::telemetry::logs::gate::Withheld;
use crate::telemetry::logs::multiline::MultilineMode;
use crate::telemetry::spool;
use crate::telemetry::warp_parse::{RecordSink, TcpFraming, TelemetryRecordSink};

use super::{TelemetryFailure, TelemetryFailureKind};

pub(super) const SPOOL_REPLAY_BATCH_SIZE: usize = 128;

pub(super) fn build_record_sink(
    config: &AgentConfig,
    framing: Option<TcpFraming>,
) -> io::Result<TelemetryRecordSink> {
    TelemetryRecordSink::from_logs_output(&config.telemetry.logs.output, framing)
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
) -> FileInputConfig {
    FileInputConfig {
        agent_id: config
            .agent
            .agent_id
            .clone()
            .unwrap_or_else(|| "unknown".to_string()),
        input_id: input.input_id.clone(),
        source_path,
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

pub(super) fn processing_failure(input: &LogFileInputSection, detail: String) -> TelemetryFailure {
    TelemetryFailure {
        kind: TelemetryFailureKind::ProcessingFailed,
        input_id: input.input_id.clone(),
        path: input.path.clone(),
        detail,
        magnitude: None,
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

fn startup_position_for(input: &LogFileInputSection) -> StartupPosition {
    match input.startup_position.as_str() {
        "tail" => StartupPosition::Tail,
        _ => StartupPosition::Head,
    }
}

#[cfg(test)]
mod tests {
    use super::{Withheld, build_file_input_config, withheld_failure};
    use std::path::PathBuf;
    use wist_contracts::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, LogFileInputSection,
        PathsSection,
    };

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
        }
    }

    #[test]
    fn uses_configured_agent_id() {
        let config = build_file_input_config(
            &config_with_agent(Some("agent-x")),
            &input(),
            PathBuf::from("/var/log/app.log"),
        );
        assert_eq!(config.agent_id, "agent-x");
    }

    #[test]
    fn falls_back_to_unknown_agent_id_when_not_configured() {
        let config = build_file_input_config(
            &config_with_agent(None),
            &input(),
            PathBuf::from("/var/log/app.log"),
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
                PathBuf::from("/var/log/app.log")
            )
            .multiline_mode,
            crate::telemetry::logs::multiline::MultilineMode::None
        );

        input.multiline_mode = "indented".to_string();
        assert_eq!(
            build_file_input_config(
                &config_with_agent(Some("a")),
                &input,
                PathBuf::from("/var/log/app.log")
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
    fn nothing_withheld_means_no_failure_at_all() {
        // 什么都没挡下就不该造一条 failure：空 failure 会被当成"这个输入有问题"而进健康快照。
        assert!(withheld_failure(&input(), &Withheld::default()).is_none());
    }
}
