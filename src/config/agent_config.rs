//! `AgentConfig` contract types.

use serde::{Deserialize, Serialize};

use wist_contracts::SCHEMA_VERSION_V1;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct AgentConfig {
    pub schema_version: String,
    #[serde(default)]
    pub agent: AgentSection,
    #[serde(default)]
    pub control_plane: ControlPlaneSection,
    #[serde(default)]
    pub paths: PathsSection,
    #[serde(default)]
    pub execution: ExecutionSection,
    #[serde(default)]
    pub telemetry: TelemetrySection,
    #[serde(default)]
    pub discovery: DiscoverySection,
    /// 本进程**运行日志**的 `[log]` 段（与 `telemetry.logs` 的“被采集日志”不同）。
    ///
    /// 直接内嵌共享 crate 的单类型 [`wist_log::LogSection`]（同名同义，单一事实来源），
    /// 在 daemon 启动早期交给 `wist_log::init`。
    #[serde(default)]
    pub log: wist_log::LogSection,
}

impl AgentConfig {
    pub fn new(
        agent: AgentSection,
        control_plane: ControlPlaneSection,
        paths: PathsSection,
        execution: ExecutionSection,
    ) -> Self {
        Self {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            agent,
            control_plane,
            paths,
            execution,
            telemetry: TelemetrySection::default(),
            discovery: DiscoverySection::default(),
            log: wist_log::LogSection::default(),
        }
    }

    pub fn with_telemetry(mut self, telemetry: TelemetrySection) -> Self {
        self.telemetry = telemetry;
        self
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct DiscoverySection {
    #[serde(default = "default_discovery_host_enabled")]
    pub host_enabled: bool,
    #[serde(default = "default_discovery_network_enabled")]
    pub network_enabled: bool,
    #[serde(default = "default_discovery_endpoint_enabled")]
    pub endpoint_enabled: bool,
    #[serde(default)]
    pub process_enabled: bool,
    #[serde(default)]
    pub container_enabled: bool,
}

impl Default for DiscoverySection {
    fn default() -> Self {
        Self {
            host_enabled: default_discovery_host_enabled(),
            network_enabled: default_discovery_network_enabled(),
            endpoint_enabled: default_discovery_endpoint_enabled(),
            process_enabled: true,
            container_enabled: false,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct AgentSection {
    #[serde(default)]
    pub agent_id: Option<String>,
    #[serde(default)]
    pub environment_id: Option<String>,
    #[serde(default)]
    pub instance_name: Option<String>,
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct ControlPlaneSection {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub enrollment_token: Option<String>,
    #[serde(default)]
    pub credential_request: Option<String>,
    #[serde(default)]
    pub credential_id: Option<String>,
    #[serde(default)]
    pub credential_expires_at: Option<String>,
    #[serde(default)]
    pub tls_mode: Option<String>,
    #[serde(default)]
    pub trust_bundle: Option<String>,
    #[serde(default)]
    pub auth_mode: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct PathsSection {
    #[serde(default = "default_root_dir")]
    pub root_dir: String,
    #[serde(default = "default_run_dir")]
    pub run_dir: String,
    #[serde(default = "default_state_dir")]
    pub state_dir: String,
    #[serde(default = "default_log_dir")]
    pub log_dir: String,
}

impl Default for PathsSection {
    fn default() -> Self {
        Self {
            root_dir: default_root_dir(),
            run_dir: default_run_dir(),
            state_dir: default_state_dir(),
            log_dir: default_log_dir(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct ExecutionSection {
    #[serde(default = "default_max_running_actions")]
    pub max_running_actions: u32,
    #[serde(default = "default_cancel_grace_ms")]
    pub cancel_grace_ms: u64,
    #[serde(default = "default_stdout_limit_bytes")]
    pub default_stdout_limit_bytes: u64,
    #[serde(default = "default_stderr_limit_bytes")]
    pub default_stderr_limit_bytes: u64,
}

impl Default for ExecutionSection {
    fn default() -> Self {
        Self {
            max_running_actions: default_max_running_actions(),
            cancel_grace_ms: default_cancel_grace_ms(),
            default_stdout_limit_bytes: default_stdout_limit_bytes(),
            default_stderr_limit_bytes: default_stderr_limit_bytes(),
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct TelemetrySection {
    #[serde(default)]
    pub logs: LogsSection,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct LogsSection {
    #[serde(default)]
    pub file_inputs: Vec<LogFileInputSection>,
    /// 采集任务清单外置文件（可选）：路径相对本配置文件解析。
    /// 设置后不能再同时写内联 `[[telemetry.logs.file_inputs]]`（二选一）。
    #[serde(default)]
    pub file_inputs_file: Option<String>,
    #[serde(default = "default_logs_buffer_bytes")]
    pub in_memory_buffer_bytes: u64,
    /// 单行最大字节数：超过则截断提交（并计数），避免无换行大文件拖垮内存。
    #[serde(default = "default_max_line_bytes")]
    pub max_line_bytes: u64,
    /// 单次 tick 最多读取的字节数（大文件回放分块）。
    #[serde(default = "default_max_read_bytes_per_tick")]
    pub max_read_bytes_per_tick: u64,
    /// 单次 tick 最多读取的行数（大文件回放分块）。
    #[serde(default = "default_max_lines_per_tick")]
    pub max_lines_per_tick: u64,
    /// 落盘待发队列（spool）上限（字节）。
    #[serde(default = "default_spool_max_bytes")]
    pub spool_max_bytes: u64,
    /// spool 超限行为：当前仅 `pause`（默认，暂停采集+告警，保完整）。
    /// `drop_oldest` 留待后续按 input 优先级丢弃落地（校验层暂不接收）。
    #[serde(default = "default_spool_over_limit")]
    pub spool_over_limit: String,
    #[serde(default = "default_logs_spool_dir")]
    pub spool_dir: String,
    #[serde(default)]
    pub output: LogsOutputSection,
}

impl Default for LogsSection {
    fn default() -> Self {
        Self {
            file_inputs: Vec::new(),
            file_inputs_file: None,
            in_memory_buffer_bytes: default_logs_buffer_bytes(),
            max_line_bytes: default_max_line_bytes(),
            max_read_bytes_per_tick: default_max_read_bytes_per_tick(),
            max_lines_per_tick: default_max_lines_per_tick(),
            spool_max_bytes: default_spool_max_bytes(),
            spool_over_limit: default_spool_over_limit(),
            spool_dir: default_logs_spool_dir(),
            output: LogsOutputSection::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct LogsOutputSection {
    /// 采集输出总闸：`false` = **不产出主机内容**（不写本地文件、不上送日志/指标帧）。
    ///
    /// 与 `kind` **正交**，不要混用：
    ///   * `kind` 回答「写到哪」（`file` / `tcp`）；
    ///   * `enabled` 回答「要不要写」。
    ///
    /// **但事实摘要不受这个闸门管**：待命期仍会上报（它是让平台能推断「这台机器是什么」的
    /// 最小元数据 —— 进程列表 / 监听端口 / os / arch；没有它，新装机器在网关侧一片空白，
    /// 连「该派什么活」都定不下来）。详见 `doc/design/telemetry/agent-uplink-authorization.md`。
    ///
    /// 之所以要拆开：此前用 `kind = "file"` 表达「待命」，于是待命态下事实帧走 file
    /// 分支返回 `Err`，让默认配置持续打印 `fact summary uplink failed` —— 把正常状态
    /// 报成了故障。待命是一种开关状态，不该由「写到哪」来表达。
    ///
    /// 默认 `true`：本地配置不写这个键时行为与从前一致（dev / standalone 不受影响）。
    /// 「待命」由签发方（网关初始配置）显式写 `enabled = false` 表达。
    #[serde(default = "default_logs_output_enabled")]
    pub enabled: bool,
    #[serde(default = "default_logs_output_kind")]
    pub kind: String,
    #[serde(default)]
    pub file: LogsFileOutputSection,
    #[serde(default)]
    pub tcp: LogsTcpOutputSection,
}

impl Default for LogsOutputSection {
    fn default() -> Self {
        Self {
            enabled: default_logs_output_enabled(),
            kind: default_logs_output_kind(),
            file: LogsFileOutputSection::default(),
            tcp: LogsTcpOutputSection::default(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct LogsFileOutputSection {
    #[serde(default = "default_logs_output_file")]
    pub path: String,
}

impl Default for LogsFileOutputSection {
    fn default() -> Self {
        Self {
            path: default_logs_output_file(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct LogsTcpOutputSection {
    #[serde(default = "default_logs_output_tcp_addr")]
    pub addr: String,
    #[serde(default = "default_logs_output_tcp_port")]
    pub port: u16,
    #[serde(default = "default_logs_output_tcp_framing")]
    pub framing: String,
}

impl Default for LogsTcpOutputSection {
    fn default() -> Self {
        Self {
            addr: default_logs_output_tcp_addr(),
            port: default_logs_output_tcp_port(),
            framing: default_logs_output_tcp_framing(),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
#[serde(deny_unknown_fields)]
pub struct LogFileInputSection {
    pub input_id: String,
    /// 采集目标：显式绝对路径、目录，或文件族 glob（绝对路径，`*` 不跨目录，不支持 `**`）。
    pub path: String,
    /// 首次读到这个文件时从哪里开始：`tail`（默认，只采新增）| `head`（从文件头读一遍）。
    #[serde(default = "default_startup_position")]
    pub startup_position: String,
    #[serde(default = "default_multiline_mode")]
    pub multiline_mode: String,
    /// 从文件族匹配集里剔掉的**绝对路径** glob（默认空，只对 glob / 目录目标有意义）。
    ///
    /// 容器日志的选源就是一条 glob + 若干排除项：`/var/log/containers/*.log` 里同时有
    /// init / sidecar / 平台自身的容器，不该只能靠把业务名写进 pattern 来避开。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub exclude_globs: Vec<String>,
}

/// 外置采集任务清单文件的顶层结构（`[telemetry.logs] file_inputs_file` 指向的文件）。
/// 内容为 `[[file_inputs]]` 数组；字段语义与内联 `[[telemetry.logs.file_inputs]]` 一致。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct LogFileInputsFile {
    pub file_inputs: Vec<LogFileInputSection>,
}

fn default_logs_buffer_bytes() -> u64 {
    1_048_576
}

/// 1 MiB：超过此长度的单行截断提交（见 log-file-input-spec §7.3）。
fn default_max_line_bytes() -> u64 {
    1_048_576
}

/// 4 MiB / tick：大文件回放分块读取。
fn default_max_read_bytes_per_tick() -> u64 {
    4_194_304
}

/// 4096 行 / tick：大文件回放分块读取。
fn default_max_lines_per_tick() -> u64 {
    4096
}

/// 256 MiB：落盘待发队列上限（见 log-file-input-spec §7.5）。
fn default_spool_max_bytes() -> u64 {
    268_435_456
}

fn default_spool_over_limit() -> String {
    "pause".to_string()
}

fn default_root_dir() -> String {
    ".".to_string()
}

fn default_run_dir() -> String {
    "run".to_string()
}

fn default_state_dir() -> String {
    "state".to_string()
}

fn default_log_dir() -> String {
    "log".to_string()
}

fn default_max_running_actions() -> u32 {
    1
}

fn default_cancel_grace_ms() -> u64 {
    5_000
}

fn default_stdout_limit_bytes() -> u64 {
    1_048_576
}

fn default_stderr_limit_bytes() -> u64 {
    1_048_576
}

fn default_logs_spool_dir() -> String {
    "state/spool/logs".to_string()
}

fn default_logs_output_file() -> String {
    "log/wist-records.ndjson".to_string()
}

/// 采集输出默认**开**：不写这个键的既有本地配置行为不变。
fn default_logs_output_enabled() -> bool {
    true
}

fn default_logs_output_kind() -> String {
    "file".to_string()
}

fn default_logs_output_tcp_addr() -> String {
    "127.0.0.1".to_string()
}

fn default_logs_output_tcp_port() -> u16 {
    9000
}

fn default_logs_output_tcp_framing() -> String {
    "line".to_string()
}

fn default_multiline_mode() -> String {
    "none".to_string()
}

/// 本地配置（`[[telemetry.logs.file_inputs]]`）里 `startup_position` 不写时的默认值：**`tail`**（只采新增）。
///
/// 与授权派活同口径（agentd 折算工作时写死 `tail`，见 `AppliedWorkGrant::log_inputs`）：
/// 默认**不重放历史** —— 从文件头读会把几百 MB 的存量日志在启动瞬间灌进数据面，
/// 而“想看历史”是运维的一次性动作，应当显式写 `startup_position = "head"`。
///
/// 同类工具也是这个方向：Fluent Bit 的 `read_from_head` 默认为 false。
fn default_startup_position() -> String {
    "tail".to_string()
}

fn default_discovery_host_enabled() -> bool {
    true
}

fn default_discovery_network_enabled() -> bool {
    true
}

fn default_discovery_endpoint_enabled() -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_file_input_without_startup_position_starts_from_the_tail() {
        // 契约默认值：不写 = **tail**（只采新增）。它决定了「运维本地加一条输入，
        // 第一次跑会不会把整个历史文件灌进数据面」，所以在这里钉住。
        let input: LogFileInputSection =
            serde_json::from_str(r#"{"input_id":"app","path":"/var/log/app.log"}"#)
                .expect("decode");
        assert_eq!(input.startup_position, "tail");
        assert_eq!(input.multiline_mode, "none");
    }

    #[test]
    fn logs_output_rejects_unknown_keys() {
        // 「旧 agentd 读不了含 enabled 的新初始配置」这个部署风险（见设计文档 §10）的**前提**
        // 就在这里：本结构是 deny_unknown_fields，所以任何一端多写一个键，另一端（旧版）
        // 会硬失败而不是忽略。钉住它 —— 免得有人把它改成宽松解析，以为「这样就兼容旧版了」
        // （实际后果是旧版忽略 enabled、拿着 kind="tcp" 直接外发）。
        assert!(serde_json::from_str::<LogsOutputSection>(r#"{"enabled":true,"nope":1}"#).is_err());
    }

    #[test]
    fn an_output_section_without_enabled_is_on() {
        // 向后兼容钉在这里：老配置没有 `enabled` 键时必须仍然产出。
        // 若默认值被改成 false，所有既有 dev / standalone 安装会在升级后静默停采。
        let output: LogsOutputSection = serde_json::from_str(r#"{"kind":"tcp"}"#).expect("decode");
        assert!(output.enabled);
        assert!(LogsOutputSection::default().enabled);
    }

    #[test]
    fn an_explicit_disabled_output_is_respected() {
        // 待命由签发方显式写出来，显式值不能被默认值盖掉。
        let output: LogsOutputSection =
            serde_json::from_str(r#"{"enabled":false,"kind":"tcp"}"#).expect("decode");
        assert!(!output.enabled);
        assert_eq!(output.kind, "tcp");
    }

    #[test]
    fn an_explicit_startup_position_still_wins() {
        // 要看历史得自己写出来 —— 显式值不能被默认值盖掉。
        let input: LogFileInputSection = serde_json::from_str(
            r#"{"input_id":"app","path":"/var/log/app.log","startup_position":"head"}"#,
        )
        .expect("decode");
        assert_eq!(input.startup_position, "head");
    }

    #[test]
    fn a_discovery_section_omitted_whole_defaults_process_on_but_an_inline_omission_defaults_it_off()
     {
        // 这是**有意**的、也是文档写明的两套默认（见 wist-agentd
        // docs/design/agent-config-schema.md §8）：
        //   * 整段 `[discovery]` 不写 → DiscoverySection::default() → process = true；
        //   * 写了 `[discovery]` 但段内省略 process_enabled → serde 逐字段默认 → false。
        // 极易在重构默认值时被「顺手统一」掉，所以在这里钉死两侧。
        assert!(DiscoverySection::default().process_enabled);
        assert!(DiscoverySection::default().host_enabled);

        let inline: DiscoverySection = serde_json::from_str("{}").expect("decode");
        assert!(
            !inline.process_enabled,
            "段内省略 process_enabled 必须是 false"
        );
        assert!(inline.host_enabled, "段内省略 host_enabled 仍是 true");

        // 整段缺省：走 Default，process 为 true。
        let whole_missing: AgentConfig =
            serde_json::from_str(r#"{"schema_version":"v1"}"#).expect("decode");
        assert!(whole_missing.discovery.process_enabled);

        // 段存在但为空：走 serde 逐字段默认，process 为 false。
        let empty_section: AgentConfig =
            serde_json::from_str(r#"{"schema_version":"v1","discovery":{}}"#).expect("decode");
        assert!(!empty_section.discovery.process_enabled);
    }

    #[test]
    fn agent_config_rejects_unknown_fields() {
        // 合同是两侧共用的字节：多出来的键必须硬失败。
        assert!(
            serde_json::from_str::<AgentConfig>(r#"{"schema_version":"v1","nope":1}"#).is_err()
        );
    }

    #[test]
    fn agent_config_new_fills_the_version_and_default_sections() {
        let config = AgentConfig::new(
            AgentSection::default(),
            ControlPlaneSection::default(),
            PathsSection::default(),
            ExecutionSection::default(),
        );
        assert_eq!(config.schema_version, SCHEMA_VERSION_V1);
        assert_eq!(config.telemetry, TelemetrySection::default());
        assert_eq!(config.discovery, DiscoverySection::default());
        assert_eq!(config.log, wist_log::LogSection::default());
    }

    #[test]
    fn a_log_section_omitted_whole_defaults_to_stderr_text() {
        // 运行日志段整段不写 = 写 stderr / text / info，交给 journald 或容器 runtime。
        let config: AgentConfig =
            serde_json::from_str(r#"{"schema_version":"v1"}"#).expect("decode");
        assert_eq!(config.log.format, wist_log::LogFormat::Text);
        assert!(config.log.file.is_none());
        assert!(config.log.level.is_none());
    }

    #[test]
    fn a_log_section_decodes_every_documented_field() {
        let config: AgentConfig = serde_json::from_str(
            r#"{"schema_version":"v1","log":{"level":"wist_agentd=debug","format":"json",
               "file":"/var/log/agentd.log","max_bytes":1048576,"keep_files":3,
               "max_age_seconds":86400}}"#,
        )
        .expect("decode");
        let log = &config.log;
        assert_eq!(log.level.as_deref(), Some("wist_agentd=debug"));
        assert_eq!(log.format, wist_log::LogFormat::Json);
        assert_eq!(
            log.file.as_deref(),
            Some(std::path::Path::new("/var/log/agentd.log"))
        );
        assert_eq!(log.max_bytes, Some(1_048_576));
        assert_eq!(log.keep_files, Some(3));
        // 旧名 `max_age_seconds` 仍映射到 `max_seconds`。
        assert_eq!(log.max_seconds, Some(86_400));
    }

    #[test]
    fn a_log_section_rejects_an_unknown_format() {
        // 格式是枚举：拼错（如 `xml`）在反序列化时就硬失败，不静默回落到 text。
        assert!(
            serde_json::from_str::<AgentConfig>(
                r#"{"schema_version":"v1","log":{"format":"xml"}}"#
            )
            .is_err()
        );
    }
}
