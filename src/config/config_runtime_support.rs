use std::env;
use std::path::{Component, Path, PathBuf};

use orion_error::conversion::ToStructError;
use wist_contracts::agent_config::AgentConfig;

use crate::config_runtime::{
    ConfigError, ConfigReason, SYSTEM_CONFIG_DIR, SYSTEM_DATA_ROOT, SYSTEM_LOG_DIR,
};

/// 采集输出（file sink，属于数据）在数据根目录下的子目录。
const COLLECTED_OUTPUT_SUBDIR: &str = "data";
/// 采集输出默认文件名。
const COLLECTED_OUTPUT_FILE: &str = "wist-records.ndjson";

pub(super) fn default_file_config_text() -> String {
    r#"schema_version = "v1"

[telemetry.logs]
in_memory_buffer_bytes = 1048576
spool_dir = "state/spool/logs"

[telemetry.logs.output]
kind = "file"

# 采集输出（file sink）路径：不写则按“它是数据”处理，跟数据根目录走 ——
#   系统级部署（配置在 /etc/wist-agentd）→ /var/lib/wist-agentd/data/wist-records.ndjson
#   开发机 / --user 安装　　→ <配置目录>/data/wist-records.ndjson
# 需要指定就显式声明（相对路径相对本配置文件所在目录，绝对路径原样使用）：
# [telemetry.logs.output.file]
# path = "/var/lib/wist-agentd/data/wist-records.ndjson"

[discovery]
# 默认保留 host + network + endpoint + process discovery，便于本地 metrics / action target 建模。
# container 属于更高基数发现，只有启用对应场景时再显式打开。
host_enabled = true
network_enabled = true
endpoint_enabled = true
process_enabled = true
container_enabled = false

# 可选：
# [agent]
# # 为空时会自动生成实例名；如需显式指定可取消注释。
# # instance_name = "monitoring-host-01"
#
# 可选：
# [control_plane]
# # 管理端端点（非秘密，可由 CM 下发）。注册是一次性动作：成功后 daemon 把正式 agent_id
# # 与凭据写入 state，无需把 token 写进本文件。
# enabled = true
# endpoint = "https://10.0.1.1"
# tls_mode = "https"
# trust_bundle = ""
#
# 注册 token（一次性）不写配置，装的时候传一次就行（不落盘）：
#   sudo wist-agentd service install --system --enrollment-token <token>
# 已装好但还没注册，也可以单独补注册：
#   sudo wist-agentd enroll --token <token>            # 或： echo <token> | sudo wist-agentd enroll --token-stdin
#
# 可选：
# [paths]
# # 数据/日志目录默认值随**配置目录**而定（只填充未声明的键，显式声明优先）：
# #   配置在 /etc/wist-agentd（系统级部署）→ 数据（run/state/spool + 采集输出 data/）落 /var/lib/wist-agentd，
# #                                         日志落 /var/log/wist-agentd
# #   其它位置（开发机 / --user 安装）→ 数据与日志就放在配置目录下
# # 解析规则：相对路径相对本配置文件所在目录，绝对路径原样使用。
# # root_dir = "/var/lib/wist-agentd"   # run/state/spool 的基准
# # run_dir = "run"
# # state_dir = "state"
# # log_dir = "/var/log/wist-agentd"
#
# 采集任务与运行设定的稳定度不同：可以把 [[telemetry.logs.file_inputs]] 清单移到独立文件，
# 在 [telemetry.logs] 内用 file_inputs_file 引用（路径相对本配置文件，与内联二选一）：
# file_inputs_file = "tasks/apps.toml"
#   tasks/apps.toml 内容示例：
#   [[file_inputs]]
#   input_id = "monitoring-app"
#   path = "/var/log/monitoring/app.log"
#   startup_position = "tail"
#   multiline_mode = "none"
#
# 示例：把某个监控系统日志文件送到本地 warp-parse record 输出文件。
# 取消注释后，把 path 改成你的真实日志路径。
#
# [[telemetry.logs.file_inputs]]
# input_id = "monitoring-app"
# path = "/var/log/monitoring/app.log"
# startup_position = "head"
# multiline_mode = "none"
#
# macOS P0 采集清单（示例，按需取消注释）：只支持“可追加的单个文本文件”。
# 需要 root/Full Disk Access 才能读的路径，agent 用户态读取失败会被跳过/进本地缓冲重试，
# 生产请用 root helper 采集；新增文件（.ips）与统一日志/audit 需 Phase 2 source。
# 注：install.log / launchd.log 体量大，默认 tail（只收新增行）；需要首次回放历史时改 head。
#
# [[telemetry.logs.file_inputs]]
# input_id = "macos_install_log"
# path = "/var/log/install.log"
# startup_position = "tail"
# multiline_mode = "none"
#
# [[telemetry.logs.file_inputs]]
# input_id = "macos_launchd"
# path = "/var/log/com.apple.xpc.launchd/launchd.log"
# startup_position = "tail"
# multiline_mode = "none"
#
# [[telemetry.logs.file_inputs]]
# input_id = "macos_shutdown_monitor"
# path = "/var/log/shutdown_monitor.log"
# startup_position = "tail"
# multiline_mode = "none"
#
# [[telemetry.logs.file_inputs]]
# input_id = "macos_fsck"
# path = "/var/log/fsck_apfs.log"
# startup_position = "head"
# multiline_mode = "none"
#
# [[telemetry.logs.file_inputs]]
# input_id = "macos_wifi"
# path = "/var/log/wifi.log"
# startup_position = "tail"
# multiline_mode = "none"
#
# 示例：把日志通过 TCP 发到本机数据面的 tcp_src。
# [telemetry.logs.output]
# kind = "tcp"
#
# [telemetry.logs.output.tcp]
# addr = "127.0.0.1"
# port = 9000
# framing = "line"
"#
    .to_string()
}

pub(super) fn expand_env_contract(mut config: AgentConfig) -> Result<AgentConfig, ConfigError> {
    config.agent.agent_id = expand_optional(config.agent.agent_id)?;
    config.agent.environment_id = expand_optional(config.agent.environment_id)?;
    config.agent.instance_name = expand_optional(config.agent.instance_name)?;
    config.control_plane.endpoint = expand_optional(config.control_plane.endpoint)?;
    config.control_plane.enrollment_token = expand_optional(config.control_plane.enrollment_token)?;
    config.control_plane.credential_request =
        expand_optional(config.control_plane.credential_request)?;
    config.control_plane.credential_id = expand_optional(config.control_plane.credential_id)?;
    config.control_plane.bearer_token = expand_optional(config.control_plane.bearer_token)?;
    config.control_plane.credential_expires_at =
        expand_optional(config.control_plane.credential_expires_at)?;
    config.control_plane.tls_mode = expand_optional(config.control_plane.tls_mode)?;
    config.control_plane.trust_bundle = expand_optional(config.control_plane.trust_bundle)?;
    config.control_plane.auth_mode = expand_optional(config.control_plane.auth_mode)?;
    config.paths.root_dir = expand_string(config.paths.root_dir)?;
    config.paths.run_dir = expand_string(config.paths.run_dir)?;
    config.paths.state_dir = expand_string(config.paths.state_dir)?;
    config.paths.log_dir = expand_string(config.paths.log_dir)?;
    config.telemetry.logs.spool_dir = expand_string(config.telemetry.logs.spool_dir)?;
    config.telemetry.logs.output.kind = expand_string(config.telemetry.logs.output.kind)?;
    config.telemetry.logs.output.file.path = expand_string(config.telemetry.logs.output.file.path)?;
    config.telemetry.logs.output.tcp.addr = expand_string(config.telemetry.logs.output.tcp.addr)?;
    config.telemetry.logs.output.tcp.framing =
        expand_string(config.telemetry.logs.output.tcp.framing)?;
    for input in &mut config.telemetry.logs.file_inputs {
        input.input_id = expand_string(std::mem::take(&mut input.input_id))?;
        input.path = expand_string(std::mem::take(&mut input.path))?;
        input.startup_position = expand_string(std::mem::take(&mut input.startup_position))?;
        input.multiline_mode = expand_string(std::mem::take(&mut input.multiline_mode))?;
    }
    Ok(config)
}

/// `[paths]` 中未显式声明时的默认目录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct DefaultPaths {
    pub(super) root_dir: String,
    pub(super) run_dir: String,
    pub(super) state_dir: String,
    pub(super) log_dir: String,
}

/// 数据默认落点由**配置目录**决定：
///
/// - 配置在 `/etc/wist-agentd`（系统级部署）→ 配置与数据分离：
///   `run/state/spool` 落 `/var/lib/wist-agentd`，日志（含采集输出）落 `/var/log/wist-agentd`；
/// - 其它位置（开发机 / `--user` 安装）→ 数据就放在配置目录下（`run` / `state` / `log`）。
///
/// `run/state` 保持相对 `root_dir`，`log_dir` 在系统级下是绝对的 `/var/log/wist-agentd`。
pub(super) fn default_paths_for(config_dir: &Path) -> DefaultPaths {
    if is_system_config_dir(config_dir) {
        DefaultPaths {
            root_dir: SYSTEM_DATA_ROOT.to_string(),
            run_dir: "run".to_string(),
            state_dir: "state".to_string(),
            log_dir: SYSTEM_LOG_DIR.to_string(),
        }
    } else {
        DefaultPaths {
            root_dir: ".".to_string(),
            run_dir: "run".to_string(),
            state_dir: "state".to_string(),
            log_dir: "log".to_string(),
        }
    }
}

/// 配置目录是否落在系统级配置目录（`/etc/wist-agentd` 及其子目录）下。
pub(super) fn is_system_config_dir(config_dir: &Path) -> bool {
    let absolute = if config_dir.is_absolute() {
        config_dir.to_path_buf()
    } else {
        std::env::current_dir()
            .map(|cwd| cwd.join(config_dir))
            .unwrap_or_else(|_| config_dir.to_path_buf())
    };
    absolute.starts_with(SYSTEM_CONFIG_DIR)
}

/// 把 `[paths]`（和采集输出路径）中**未显式声明**的键填成平台默认值。
///
/// 只填未声明的键：显式写 `root_dir = "."` 仍按原意解析，不会被静默改写。
/// 采集输出（`[telemetry.logs.output.file].path`）未声明时按“它是数据”处理：
/// 系统级 → `/var/lib/wist-agentd/data/wist-records.ndjson`；开发机 → `<配置目录>/data/wist-records.ndjson`。
pub(super) fn apply_path_defaults(config: &mut AgentConfig, config_path: &Path, raw: &toml::Value) {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let system = is_system_config_dir(config_dir);
    let defaults = default_paths_for(config_dir);
    let declared = raw.get("paths");
    let declared_key = |key: &str| declared.and_then(|paths| paths.get(key)).is_some();

    if !declared_key("root_dir") {
        config.paths.root_dir = defaults.root_dir;
    }
    if !declared_key("run_dir") {
        config.paths.run_dir = defaults.run_dir;
    }
    if !declared_key("state_dir") {
        config.paths.state_dir = defaults.state_dir;
    }
    if !declared_key("log_dir") {
        config.paths.log_dir = defaults.log_dir;
    }

    let output_declared = raw
        .get("telemetry")
        .and_then(|telemetry| telemetry.get("logs"))
        .and_then(|logs| logs.get("output"))
        .and_then(|output| output.get("file"))
        .and_then(|file| file.get("path"))
        .is_some();
    if !output_declared {
        config.telemetry.logs.output.file.path = collected_output_default(system);
    }
}

/// 采集输出（file sink）未显式声明时的默认路径：它是**数据**，跟数据根目录走 ——
/// 系统级 `/var/lib/wist-agentd/data/wist-records.ndjson`，
/// 开发机 / `--user` `<配置目录>/data/wist-records.ndjson`。
fn collected_output_default(system: bool) -> String {
    let relative = format!("{COLLECTED_OUTPUT_SUBDIR}/{COLLECTED_OUTPUT_FILE}");
    if system {
        Path::new(SYSTEM_DATA_ROOT)
            .join(&relative)
            .display()
            .to_string()
    } else {
        relative
    }
}

pub(super) fn resolve_paths(mut config: AgentConfig, config_path: &Path) -> AgentConfig {
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let root_dir = absolutize(config_dir, &config.paths.root_dir);

    config.paths.root_dir = root_dir.display().to_string();
    config.paths.run_dir = absolutize(&root_dir, &config.paths.run_dir)
        .display()
        .to_string();
    config.paths.state_dir = absolutize(&root_dir, &config.paths.state_dir)
        .display()
        .to_string();
    config.paths.log_dir = absolutize(&root_dir, &config.paths.log_dir)
        .display()
        .to_string();
    config.telemetry.logs.spool_dir = absolutize(&root_dir, &config.telemetry.logs.spool_dir)
        .display()
        .to_string();
    config.telemetry.logs.output.file.path =
        absolutize(&root_dir, &config.telemetry.logs.output.file.path)
            .display()
            .to_string();
    config.telemetry.logs.file_inputs = config
        .telemetry
        .logs
        .file_inputs
        .into_iter()
        .map(|mut input| {
            input.path = absolutize(&root_dir, &input.path).display().to_string();
            input
        })
        .collect();
    config
}

pub(super) fn absolutize(base: &Path, raw: &str) -> PathBuf {
    let path = Path::new(raw);
    let joined = if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    };
    normalize_path(joined)
}

fn normalize_path(path: PathBuf) -> PathBuf {
    let mut normalized = PathBuf::new();
    for component in path.components() {
        match component {
            Component::CurDir => {}
            Component::ParentDir => {
                normalized.pop();
            }
            other => normalized.push(other.as_os_str()),
        }
    }
    normalized
}

fn expand_optional(value: Option<String>) -> Result<Option<String>, ConfigError> {
    value.map(expand_string).transpose()
}

pub(super) fn expand_string(value: String) -> Result<String, ConfigError> {
    let mut out = String::with_capacity(value.len());
    let mut cursor = 0usize;
    while let Some(start) = value[cursor..].find("${") {
        let start = cursor + start;
        out.push_str(&value[cursor..start]);
        let rest = &value[start + 2..];
        let Some(end_rel) = rest.find('}') else {
            out.push_str(&value[start..]);
            return Ok(out);
        };
        let end = start + 2 + end_rel;
        let name = &value[start + 2..end];
        let expanded =
            env::var(name).map_err(|_| ConfigReason::MissingEnvVar.to_err().with_detail(name))?;
        out.push_str(&expanded);
        cursor = end + 1;
    }
    out.push_str(&value[cursor..]);
    Ok(out)
}
