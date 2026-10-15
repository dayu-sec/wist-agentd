//! 常驻服务集成：把 `wist-agentd` 交给 OS 服务管理器长期托管。
//!
//! 两种落地形态：
//! - Linux：systemd unit（`Restart=always`，日志进 journald）。
//! - macOS：launchd plist（`KeepAlive`，日志进 `/var/log/wist-agentd`）。
//!
//! 设计前提：agentd 自身**只前台运行**（不 fork / 不 double-fork daemonize），
//! 开机自启、崩溃拉起、退出后重启全部由服务管理器负责；重复实例由 state 目录下的
//! flock（[`crate::single_instance`]）兜底——服务管理器重启期间若前任未退出，新进程
//! 会以 `AlreadyRunning` 快速失败，再由 `Restart` / `KeepAlive` 重试。
//!
//! 本模块只做三件事：渲染服务定义、落盘/删除定义文件、给出服务管理器的操作命令。
//! 真正的 `systemctl` / `launchctl` 调用由 CLI 层执行，便于单测只覆盖可确定的部分。

use std::fs;
use std::path::{Path, PathBuf};

use orion_error::{conversion::ToStructError, prelude::*};
use wist_shared::fs::write_bytes_atomic;

use crate::error::{AgentdReason, AgentdResult};

pub mod launchd;
pub mod systemd;

/// 服务实例名（systemd unit 名 / 进程显示名）。
pub const SERVICE_NAME: &str = "wist-agentd";
/// macOS launchd label（反向域名，全机唯一）。
pub const LAUNCHD_LABEL: &str = "com.dayu-sec.wist-agentd";
/// 可选的环境变量文件（systemd `EnvironmentFile`），只放长期环境变量；
/// 一次性注册 token 走命令行（`service install --enrollment-token` / `enroll --token`），不落盘。
pub const ENV_FILE_NAME: &str = "agentd.env";
/// 与 `wist-agentd` 同目录发布、由守护进程拉起的执行器。
pub const EXEC_BIN_NAME: &str = "wist-exec";

/// 服务管理器形态（由编译目标决定；渲染函数显式接收，便于测试两个平台）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ServicePlatform {
    Systemd,
    Launchd,
}

impl ServicePlatform {
    /// 当前目标平台使用的服务管理器；非 Linux / macOS 返回 `None`。
    pub fn current() -> Option<ServicePlatform> {
        if cfg!(target_os = "linux") {
            Some(ServicePlatform::Systemd)
        } else if cfg!(target_os = "macos") {
            Some(ServicePlatform::Launchd)
        } else {
            None
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            ServicePlatform::Systemd => "systemd",
            ServicePlatform::Launchd => "launchd",
        }
    }
}

/// 服务定义与日志的落盘位置（系统级）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceLayout {
    pub platform: ServicePlatform,
    /// service 定义文件（`*.service` / `*.plist`）。
    pub definition_path: PathBuf,
    /// launchd 标准输出/错误目录；systemd 走 journald，故为 `None`。
    pub log_dir: Option<PathBuf>,
}

impl ServiceLayout {
    /// 按平台解析标准安装位置（系统级）。
    pub fn resolve(platform: ServicePlatform) -> AgentdResult<Self> {
        let (definition_path, log_dir) = match platform {
            ServicePlatform::Systemd => (systemd::unit_path()?, None),
            ServicePlatform::Launchd => (launchd::plist_path()?, Some(launchd::log_dir()?)),
        };
        Ok(Self {
            platform,
            definition_path,
            log_dir,
        })
    }

    /// 使用显式路径构造（测试 / 非标准布局）。
    pub fn for_paths(
        platform: ServicePlatform,
        definition_path: PathBuf,
        log_dir: Option<PathBuf>,
    ) -> Self {
        Self {
            platform,
            definition_path,
            log_dir,
        }
    }
}

/// 一条服务定义（渲染 systemd unit 或 launchd plist 所需的全部信息）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceSpec {
    /// 已安装的 `wist-agentd` 绝对路径。
    pub bin: PathBuf,
    /// 绝对配置目录（必须绝对：服务启动时的工作目录不确定）。
    pub config_dir: PathBuf,
}

impl ServiceSpec {
    pub fn new(bin: PathBuf, config_dir: PathBuf) -> Self {
        Self { bin, config_dir }
    }

    /// 与 `wist-agentd` 同目录的执行器路径。
    pub fn exec_bin(&self) -> PathBuf {
        self.bin.with_file_name(EXEC_BIN_NAME)
    }

    /// 可选环境变量文件路径（systemd 会读取；macOS 仅作文档提示）。
    pub fn env_file(&self) -> PathBuf {
        self.config_dir.join(ENV_FILE_NAME)
    }

    /// launchd 的 domain target（系统级固定为 `system`）。
    pub fn launchd_domain(&self) -> String {
        "system".to_string()
    }

    /// launchd 运维 target（`<domain>/<label>`）。
    pub fn launchd_target(&self) -> String {
        format!("{}/{}", self.launchd_domain(), LAUNCHD_LABEL)
    }
}

/// 渲染服务定义文本。
pub fn render(layout: &ServiceLayout, spec: &ServiceSpec) -> String {
    match layout.platform {
        ServicePlatform::Systemd => systemd::unit_text(spec),
        ServicePlatform::Launchd => launchd::plist_text(spec, layout.log_dir.as_deref()),
    }
}

/// 默认配置目录（系统级：`/etc/wist-agentd`）。
pub fn default_config_dir() -> PathBuf {
    PathBuf::from(crate::config_runtime::SYSTEM_CONFIG_DIR)
}

/// 当前可执行文件（规范化后的绝对路径），作为 `--bin` 的默认值。
pub fn default_bin() -> AgentdResult<PathBuf> {
    let exe = std::env::current_exe().source_err(
        AgentdReason::ServicePathUnresolved,
        "resolve current executable for service install",
    )?;
    Ok(fs::canonicalize(&exe).unwrap_or(exe))
}

/// 安装结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InstallReport {
    pub platform: ServicePlatform,
    pub definition_path: PathBuf,
    pub overwritten: bool,
    pub bin_present: bool,
    pub exec_bin_present: bool,
    pub log_dir: Option<PathBuf>,
}

/// 落盘服务定义（不做任何服务管理器调用）。
pub fn install(
    layout: &ServiceLayout,
    spec: &ServiceSpec,
    force: bool,
) -> AgentdResult<InstallReport> {
    reject_unrepresentable_path(spec)?;

    let definition_path = layout.definition_path.clone();
    let existed = definition_path.exists();
    if existed && !force {
        return Err(AgentdReason::ServiceAlreadyInstalled
            .to_err()
            .with_detail(format!(
                "service definition already exists: {} (pass --force to overwrite)",
                definition_path.display()
            )));
    }

    let parent = definition_path.parent().ok_or_else(|| {
        AgentdReason::ServicePathUnresolved
            .to_err()
            .with_detail(format!(
                "no parent directory for {}",
                definition_path.display()
            ))
    })?;
    fs::create_dir_all(parent).source_err(
        AgentdReason::system_error(),
        format!("create service definition dir {}", parent.display()),
    )?;

    // 原子写：写中途失败不会留下半截的服务定义。
    // 注意 `write_bytes_atomic` 会自己补一个结尾换行，因此先去掉渲染文本的尾换行，
    // 保证落盘内容与 `render()` 逐字节一致（`install_writes_definition_and_is_guarded_by_force` 盯着这一点）。
    let text = render(layout, spec);
    let body = text.strip_suffix('\n').unwrap_or(&text);
    write_bytes_atomic(&definition_path, body.as_bytes()).source_err(
        AgentdReason::system_error(),
        format!("write service definition {}", definition_path.display()),
    )?;

    if let Some(log_dir) = layout.log_dir.as_ref() {
        fs::create_dir_all(log_dir).source_err(
            AgentdReason::system_error(),
            format!("create service log dir {}", log_dir.display()),
        )?;
    }

    Ok(InstallReport {
        platform: layout.platform,
        definition_path,
        overwritten: existed,
        bin_present: spec.bin.is_file(),
        exec_bin_present: spec.exec_bin().is_file(),
        log_dir: layout.log_dir.clone(),
    })
}

/// 删除服务定义（不做任何服务管理器调用），返回是否真的删掉了文件。
pub fn remove(layout: &ServiceLayout) -> AgentdResult<bool> {
    let definition_path = &layout.definition_path;
    match fs::remove_file(definition_path) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(AgentdReason::system_error().to_err().with_detail(format!(
            "remove service definition {}: {err}",
            definition_path.display()
        ))),
    }
}

/// 服务定义是**行/XML 结构**：含换行的路径无法安全表达（会被当成下一条指令），直接拒绝。
fn reject_unrepresentable_path(spec: &ServiceSpec) -> AgentdResult<()> {
    for (label, value) in [
        ("binary", spec.bin.display().to_string()),
        ("config dir", spec.config_dir.display().to_string()),
    ] {
        if value.contains('\n') || value.contains('\r') {
            return Err(AgentdReason::ServicePathUnresolved.to_err().with_detail(
                format!("{label} contains a newline and cannot be written into a service definition: {value:?}"),
            ));
        }
    }
    Ok(())
}

/// 服务管理器**拆除是异步的**（launchd 的 bootout 返回后进程仍可能在退出中），
/// 紧随其后的加载可能拿到瞬时错误，因此留一小段重试窗口。
pub const ACTIVATE_RETRIES: u32 = 5;
pub const ACTIVATE_RETRY_DELAY: std::time::Duration = std::time::Duration::from_millis(300);

/// 一条服务管理器命令。`ignore_failure` 用于幂等前置步骤（如先 bootout 再 bootstrap）。
/// `retries` 是失败后**额外**重试的次数（0 = 不重试）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCommand {
    pub program: String,
    pub args: Vec<String>,
    pub ignore_failure: bool,
    pub retries: u32,
}

impl ServiceCommand {
    fn new(program: &str, args: Vec<String>, ignore_failure: bool) -> Self {
        Self {
            program: program.to_string(),
            args,
            ignore_failure,
            retries: 0,
        }
    }

    /// 标记为「可重试」：只在失败时生效（成功立刻返回，不引入额外等待）。
    fn retryable(mut self, retries: u32) -> Self {
        self.retries = retries;
        self
    }

    /// 可直接粘到终端复现的命令行。
    pub fn display_line(&self) -> String {
        let mut parts = Vec::with_capacity(self.args.len() + 1);
        parts.push(shell_quote(&self.program));
        parts.extend(self.args.iter().map(|arg| shell_quote(arg)));
        parts.join(" ")
    }
}

/// 让服务管理器加载并启动服务（幂等）。
pub fn activate_commands(
    layout: &ServiceLayout,
    spec: &ServiceSpec,
) -> AgentdResult<Vec<ServiceCommand>> {
    match layout.platform {
        ServicePlatform::Systemd => {
            // 必须是 `restart` 而不是 `enable --now`：`--now` 在**已 active** 的 unit 上
            // 等同于 start，是 no-op。这样 `service install --force`（换二进制 / 改定义）
            // 在 Linux 上会留着旧进程跑旧二进制。restart 在「首次安装（未启动）」时
            // 也会把服务拉起来，因此两种情形都正确。
            Ok(vec![
                ServiceCommand::new("systemctl", vec!["daemon-reload".to_string()], false),
                ServiceCommand::new(
                    "systemctl",
                    vec!["enable".to_string(), SERVICE_NAME.to_string()],
                    false,
                ),
                ServiceCommand::new(
                    "systemctl",
                    vec!["restart".to_string(), SERVICE_NAME.to_string()],
                    false,
                )
                .retryable(ACTIVATE_RETRIES),
            ])
        }
        ServicePlatform::Launchd => {
            let domain = spec.launchd_domain();
            Ok(vec![
                // 已加载时 bootstrap 会失败，先无脑 bootout 一次（失败可忽略）。
                ServiceCommand::new(
                    "launchctl",
                    vec!["bootout".to_string(), spec.launchd_target()],
                    true,
                ),
                // bootout 返回 ≠ 旧进程已退出；紧随其后的 bootstrap 可能拿到
                // `Bootstrap failed: 5: Input/output error`，因此这里允许重试。
                ServiceCommand::new(
                    "launchctl",
                    vec![
                        "bootstrap".to_string(),
                        domain,
                        layout.definition_path.display().to_string(),
                    ],
                    false,
                )
                .retryable(ACTIVATE_RETRIES),
                ServiceCommand::new(
                    "launchctl",
                    vec!["enable".to_string(), spec.launchd_target()],
                    false,
                ),
            ])
        }
    }
}

/// 停止并取消托管（卸载前调用，幂等）。
pub fn deactivate_commands(platform: ServicePlatform, spec: &ServiceSpec) -> Vec<ServiceCommand> {
    match platform {
        ServicePlatform::Systemd => vec![
            ServiceCommand::new(
                "systemctl",
                vec![
                    "disable".to_string(),
                    "--now".to_string(),
                    SERVICE_NAME.to_string(),
                ],
                true,
            ),
            ServiceCommand::new("systemctl", vec!["daemon-reload".to_string()], false),
        ],
        ServicePlatform::Launchd => vec![ServiceCommand::new(
            "launchctl",
            vec!["bootout".to_string(), spec.launchd_target()],
            true,
        )],
    }
}

/// 运维检查命令（只打印，不执行）。
pub fn inspect_commands(platform: ServicePlatform, spec: &ServiceSpec) -> Vec<ServiceCommand> {
    match platform {
        ServicePlatform::Systemd => vec![
            ServiceCommand::new(
                "systemctl",
                vec!["status".to_string(), SERVICE_NAME.to_string()],
                false,
            ),
            ServiceCommand::new(
                "journalctl",
                vec!["-u".to_string(), SERVICE_NAME.to_string(), "-f".to_string()],
                false,
            ),
        ],
        ServicePlatform::Launchd => vec![ServiceCommand::new(
            "launchctl",
            vec!["print".to_string(), spec.launchd_target()],
            false,
        )],
    }
}

/// 服务状态自检结果（只读：不创建目录、不触发注册）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceStatus {
    pub platform: ServicePlatform,
    pub definition_path: PathBuf,
    pub definition_present: bool,
    pub bin: PathBuf,
    pub bin_present: bool,
    pub exec_bin: PathBuf,
    pub exec_bin_present: bool,
    pub config_path: PathBuf,
    pub config_present: bool,
    /// 配置读不到时的原因（首行），供运维定位“为什么落点都是 `-`”。
    pub config_error: Option<String>,
    /// 配置解析出的数据落点（配置读不到时为 `None`）。
    pub root_dir: Option<PathBuf>,
    pub run_dir: Option<PathBuf>,
    pub state_dir: Option<PathBuf>,
    pub log_dir: Option<PathBuf>,
    /// 单实例锁是否已被持有（即已有 agentd 在跑）；`None` 表示无法判定。
    pub running: Option<bool>,
    pub log_hint: String,
}

/// 采集服务状态。
pub fn status(layout: &ServiceLayout, spec: &ServiceSpec) -> AgentdResult<ServiceStatus> {
    let config_path = crate::config_runtime::resolve_config_path(&spec.config_dir);
    let config_present = config_path.is_file();
    // 配置能解析出就展示真实落点（含 /etc → /var/lib 的推导），否则把原因一并带回给运维。
    // 用 display_chain 的**全部**信息（首行只是 reason 名，真正的细节在缩进行里），压成一行便于 `key=value` 输出。
    let loaded = if config_present {
        crate::config_runtime::load_from_path(&config_path)
            .map_err(|err| one_line(&err.display_chain()))
    } else {
        Err("config file not found".to_string())
    };
    let (paths, config_error) = match loaded {
        Ok(config) => (Some(config), None),
        Err(reason) => (None, config_present.then_some(reason)),
    };
    let state_dir = paths
        .as_ref()
        .map(|config| PathBuf::from(&config.paths.state_dir));
    let running = state_dir
        .as_deref()
        .map(crate::single_instance::is_held)
        .transpose()
        .source_err(
            AgentdReason::system_error(),
            "probe single-instance lock for service status",
        )?;

    Ok(ServiceStatus {
        platform: layout.platform,
        definition_present: layout.definition_path.is_file(),
        definition_path: layout.definition_path.clone(),
        bin_present: spec.bin.is_file(),
        bin: spec.bin.clone(),
        exec_bin_present: spec.exec_bin().is_file(),
        exec_bin: spec.exec_bin(),
        config_present,
        config_path,
        config_error,
        root_dir: paths
            .as_ref()
            .map(|config| PathBuf::from(&config.paths.root_dir)),
        run_dir: paths
            .as_ref()
            .map(|config| PathBuf::from(&config.paths.run_dir)),
        log_dir: paths
            .as_ref()
            .map(|config| PathBuf::from(&config.paths.log_dir)),
        state_dir,
        running,
        log_hint: log_hint(layout)?,
    })
}

/// 日志查看提示（systemd 走 journald，launchd 走落盘文件）。
pub fn log_hint(layout: &ServiceLayout) -> AgentdResult<String> {
    match layout.platform {
        ServicePlatform::Systemd => Ok(format!("journalctl -u {SERVICE_NAME} -f")),
        ServicePlatform::Launchd => {
            let log_dir = layout
                .log_dir
                .clone()
                .ok_or_else(|| AgentdReason::ServicePathUnresolved.to_err())?;
            Ok(format!(
                "tail -f {}",
                log_dir.join(launchd::STDERR_FILE).display()
            ))
        }
    }
}

/// 执行一条服务管理器命令，返回是否成功（含 stdout / stderr 供 CLI 回显）。
pub fn run(command: &ServiceCommand) -> AgentdResult<ServiceCommandOutcome> {
    let output = std::process::Command::new(&command.program)
        .args(&command.args)
        .output()
        .map_err(|err| {
            AgentdReason::ServiceCommandFailed
                .to_err()
                .with_detail(format!("run `{}`: {err}", command.display_line()))
        })?;

    Ok(ServiceCommandOutcome {
        command: command.clone(),
        success: output.status.success(),
        stdout: String::from_utf8_lossy(&output.stdout).trim().to_string(),
        stderr: String::from_utf8_lossy(&output.stderr).trim().to_string(),
    })
}

/// 按 `command.retries` 重试执行：成功立刻返回，失败才等待后重试，
/// 最终返回**最后一次**的结果（交回调用方报错）。
pub fn run_with_retries(command: &ServiceCommand) -> AgentdResult<ServiceCommandOutcome> {
    let mut attempt = 0;
    loop {
        let outcome = run(command)?;
        if outcome.success || attempt >= command.retries {
            return Ok(outcome);
        }
        attempt += 1;
        std::thread::sleep(ACTIVATE_RETRY_DELAY);
    }
}

/// 一条命令的执行结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ServiceCommandOutcome {
    pub command: ServiceCommand,
    pub success: bool,
    pub stdout: String,
    pub stderr: String,
}

/// 把多行错误链压成一行（`service status` 的 `key=value` 输出用）。
fn one_line(text: &str) -> String {
    text.lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" / ")
}

fn shell_quote(value: &str) -> String {
    if !value.is_empty()
        && value.chars().all(|ch| {
            ch.is_ascii_alphanumeric() || matches!(ch, '/' | '.' | '-' | '_' | '=' | ':' | '@')
        })
    {
        value.to_string()
    } else {
        format!("'{}'", value.replace('\'', "'\\''"))
    }
}

/// 只读探测某个路径是否存在（供状态输出使用）。
pub fn path_state(path: &Path) -> String {
    if path.is_file() {
        format!("{} (present)", path.display())
    } else {
        format!("{} (missing)", path.display())
    }
}

#[cfg(test)]
#[path = "tests.rs"]
mod tests;
