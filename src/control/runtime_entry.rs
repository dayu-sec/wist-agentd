use std::ffi::OsString;
use std::io;
use std::path::{Path, PathBuf};

use orion_error::{conversion::ToStructError, prelude::*};

use crate::config_runtime::SYSTEM_CONFIG_DIR;
use crate::daemon;
use crate::enrollment::is_registered_agent_id;
use crate::error::{AgentdReason, AgentdResult};
use crate::self_observability;
use crate::service::{
    self, ServiceCommand, ServiceCommandOutcome, ServiceLayout, ServicePlatform, ServiceScope,
    ServiceSpec,
};
use crate::state_store;

const CONFIG_DIR: &str = "wist-agentd";

pub(crate) async fn run() -> AgentdResult<()> {
    let root =
        std::env::current_dir().source_err(AgentdReason::system_error(), "resolve current dir")?;
    run_from_args_async(root, std::env::args_os().skip(1)).await
}

#[derive(Debug, Clone, PartialEq, Eq)]
enum Command {
    Help,
    Version,
    Run,
    InitConfig { stdout_only: bool },
    Service(ServiceRequest),
    Enroll(EnrollRequest),
}

/// `service` 子命令的动作。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ServiceAction {
    Print,
    Install,
    Uninstall,
    Status,
}

const SERVICE_ACTIONS: &str = "print | install | uninstall | status";

/// `service` 子命令的参数。
#[derive(Debug, Clone, PartialEq, Eq)]
struct ServiceRequest {
    action: ServiceAction,
    scope: ServiceScope,
    /// 仅 `print` 可用：为目标平台渲染定义（例如在 macOS 上为 Linux 生成 unit）。
    platform: Option<ServicePlatform>,
    bin: Option<PathBuf>,
    force: bool,
    activate: bool,
    /// 仅 `install` 可用：安装前用这个一次性 token 完成注册（不落盘）。
    enrollment_token: Option<String>,
}

/// `enroll` 子命令的参数（用一次性 token 注册，token 不落盘）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct EnrollRequest {
    /// `Some` = `--token <value>`；`None` + `stdin` = `--token-stdin`；都没有则走配置/环境变量。
    token: Option<String>,
    token_stdin: bool,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct ParsedArgs {
    command: Command,
    config_dir: Option<PathBuf>,
}

async fn run_from_args_async<I, S>(root: PathBuf, args: I) -> AgentdResult<()>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let parsed = parse_command(args).map_err(|err| {
        AgentdReason::InvalidArgs
            .to_err()
            .with_detail(err.to_string())
    })?;
    match parsed.command {
        Command::Help => {
            print!("{}", usage_message());
            Ok(())
        }
        Command::Version => {
            println!("wist-agentd {}", env!("CARGO_PKG_VERSION"));
            Ok(())
        }
        Command::Run => run_daemon(root, parsed.config_dir.as_deref()).await,
        Command::Service(request) => run_service(root, parsed.config_dir.as_deref(), request).await,
        Command::Enroll(request) => run_enroll(root, parsed.config_dir.as_deref(), request).await,
        Command::InitConfig { stdout_only: true } => {
            print!("{}", crate::config_runtime::default_config_template());
            Ok(())
        }
        Command::InitConfig { stdout_only: false } => {
            let config_root = match parsed.config_dir.as_deref() {
                Some(path) => resolve_config_dir_arg(&root, path),
                None => default_config_root(),
            };
            let ensured = crate::config_runtime::ensure_default_config(&config_root).conv_err()?;
            let data_root = crate::config_runtime::system_data_root_for(&config_root);
            println!(
                "{}",
                init_config_message(&ensured.path, ensured.created, data_root.as_deref())
            );
            Ok(())
        }
    }
}

#[cfg(test)]
fn run_from_args<I, S>(root: PathBuf, args: I) -> AgentdResult<()>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .source_err(AgentdReason::system_error(), "build tokio runtime")?
        .block_on(run_from_args_async(root, args))
}

fn parse_command<I, S>(args: I) -> io::Result<ParsedArgs>
where
    I: IntoIterator<Item = S>,
    S: Into<OsString>,
{
    let args: Vec<OsString> = args.into_iter().map(Into::into).collect();
    let mut command = Command::Run;
    let mut command_explicit = false;
    let mut config_dir = None;
    let mut index = 0usize;

    while index < args.len() {
        let arg = &args[index];
        if arg == "help" || arg == "--help" || arg == "-h" {
            if command_explicit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "help cannot be combined with another command",
                ));
            }
            command = Command::Help;
            command_explicit = true;
            index += 1;
            continue;
        }
        if arg == "version" || arg == "--version" || arg == "-V" {
            if command_explicit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "version cannot be combined with another command",
                ));
            }
            command = Command::Version;
            command_explicit = true;
            index += 1;
            continue;
        }
        if arg == "service" {
            if command_explicit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "multiple commands are not supported",
                ));
            }
            let (request, sub_config_dir, next) = parse_service_request(&args, index + 1)?;
            merge_config_dir(&mut config_dir, sub_config_dir)?;
            command = Command::Service(request);
            command_explicit = true;
            index = next;
            continue;
        }
        if arg == "enroll" {
            if command_explicit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "multiple commands are not supported",
                ));
            }
            let (request, sub_config_dir, next) = parse_enroll_request(&args, index + 1)?;
            merge_config_dir(&mut config_dir, sub_config_dir)?;
            command = Command::Enroll(request);
            command_explicit = true;
            index = next;
            continue;
        }
        if arg == "--config-dir" {
            let value = config_dir_value(&args, index + 1)?;
            config_dir = Some(PathBuf::from(value));
            index += 2;
            continue;
        }
        if arg == "--stdout" {
            match command {
                Command::InitConfig { .. } => {
                    command = Command::InitConfig { stdout_only: true };
                    index += 1;
                    continue;
                }
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        "--stdout is only supported with init-config",
                    ));
                }
            }
        }
        if arg == "init-config" {
            if command_explicit {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "multiple commands are not supported",
                ));
            }
            command = Command::InitConfig { stdout_only: false };
            command_explicit = true;
            index += 1;
            continue;
        }

        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "unknown argument or command: {} (supported: help | version | init-config [--stdout] | service <print|install|uninstall|status> | --config-dir <path>)",
                PathBuf::from(arg).display()
            ),
        ));
    }

    Ok(ParsedArgs {
        command,
        config_dir,
    })
}

fn config_dir_value(args: &[OsString], value_index: usize) -> io::Result<&OsString> {
    option_value(args, value_index, "--config-dir")
}

/// 取 `flag` 后面的取值；缺失或看起来像另一个选项时报错。
fn option_value<'a>(
    args: &'a [OsString],
    value_index: usize,
    flag: &str,
) -> io::Result<&'a OsString> {
    let Some(value) = args.get(value_index) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        ));
    };
    if looks_like_option(value) {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing value for {flag}"),
        ));
    }
    Ok(value)
}

fn looks_like_option(value: &OsString) -> bool {
    value.to_str().is_some_and(|text| {
        matches!(
            text,
            "--help"
                | "-h"
                | "--version"
                | "-V"
                | "--stdout"
                | "--config-dir"
                | "--bin"
                | "--for"
                | "--token"
                | "--token-stdin"
                | "--enrollment-token"
                | "--system"
                | "--user"
                | "--force"
                | "--no-activate"
        )
    })
}

/// 解析 `service <action> [--system|--user] [--bin <path>] [--force] [--no-activate] [--enrollment-token <t>]`。
///
/// 返回 `(请求, 本段解析到的 --config-dir, 下一个待扫描下标)`：子命令参数与全局参数可以**任意顺序**混用
/// （`--config-dir` 在子解析器里一并吃掉，否则 `service install --config-dir X --force` 会把 `--force`
/// 丢回主循环并报“unknown argument”）。
fn parse_service_request(
    args: &[OsString],
    action_index: usize,
) -> io::Result<(ServiceRequest, Option<PathBuf>, usize)> {
    let Some(action) = args.get(action_index) else {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("missing service action (supported: {SERVICE_ACTIONS})"),
        ));
    };
    let action = match action.to_str() {
        Some("print") => ServiceAction::Print,
        Some("install") => ServiceAction::Install,
        Some("uninstall") => ServiceAction::Uninstall,
        Some("status") => ServiceAction::Status,
        _ => {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "unknown service action: {} (supported: {SERVICE_ACTIONS})",
                    PathBuf::from(action).display()
                ),
            ));
        }
    };

    let mut request = ServiceRequest {
        action,
        // 常驻 Agent 需要读 /var/log 等受限路径，默认系统级；开发机可用 --user。
        scope: ServiceScope::System,
        platform: None,
        bin: None,
        force: false,
        activate: true,
        enrollment_token: None,
    };
    let mut index = action_index + 1;
    let mut config_dir = None;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--config-dir" {
            let value = option_value(args, index + 1, "--config-dir")?;
            set_config_dir(&mut config_dir, PathBuf::from(value))?;
            index += 2;
            continue;
        }
        if arg == "--system" {
            request.scope = ServiceScope::System;
            index += 1;
            continue;
        }
        if arg == "--user" {
            request.scope = ServiceScope::User;
            index += 1;
            continue;
        }
        if arg == "--force" {
            require_install_action(action, "--force")?;
            request.force = true;
            index += 1;
            continue;
        }
        if arg == "--no-activate" {
            require_install_action(action, "--no-activate")?;
            request.activate = false;
            index += 1;
            continue;
        }
        if arg == "--for" {
            if action != ServiceAction::Print {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "--for is only supported with `service print`",
                ));
            }
            let value = option_value(args, index + 1, "--for")?;
            request.platform = Some(match value.to_str() {
                Some("systemd") | Some("linux") => ServicePlatform::Systemd,
                Some("launchd") | Some("macos") => ServicePlatform::Launchd,
                _ => {
                    return Err(io::Error::new(
                        io::ErrorKind::InvalidInput,
                        format!(
                            "unknown platform for --for: {} (supported: systemd | launchd)",
                            PathBuf::from(value).display()
                        ),
                    ));
                }
            });
            index += 2;
            continue;
        }
        if arg == "--bin" {
            let value = option_value(args, index + 1, "--bin")?;
            request.bin = Some(PathBuf::from(value));
            index += 2;
            continue;
        }
        if arg == "--enrollment-token" {
            require_install_action(action, "--enrollment-token")?;
            let value = option_value(args, index + 1, "--enrollment-token")?;
            request.enrollment_token = Some(os_string_to_token(value)?);
            index += 2;
            continue;
        }
        break;
    }

    Ok((request, config_dir, index))
}

/// 解析 `enroll [--token <T> | --token-stdin] [--config-dir <path>]`。
fn parse_enroll_request(
    args: &[OsString],
    start_index: usize,
) -> io::Result<(EnrollRequest, Option<PathBuf>, usize)> {
    let mut request = EnrollRequest {
        token: None,
        token_stdin: false,
    };
    let mut config_dir = None;
    let mut index = start_index;
    while index < args.len() {
        let arg = &args[index];
        if arg == "--config-dir" {
            let value = option_value(args, index + 1, "--config-dir")?;
            set_config_dir(&mut config_dir, PathBuf::from(value))?;
            index += 2;
            continue;
        }
        if arg == "--token" {
            let value = option_value(args, index + 1, "--token")?;
            request.token = Some(os_string_to_token(value)?);
            index += 2;
            continue;
        }
        if arg == "--token-stdin" {
            request.token_stdin = true;
            index += 1;
            continue;
        }
        break;
    }

    if request.token.is_some() && request.token_stdin {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "--token and --token-stdin are mutually exclusive",
        ));
    }
    Ok((request, config_dir, index))
}

/// 写入 `--config-dir` 槽：重复且取值不一致时报错（重复且相同视为幂等）。
fn set_config_dir(slot: &mut Option<PathBuf>, path: PathBuf) -> io::Result<()> {
    if let Some(existing) = slot.as_ref()
        && *existing != path
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!(
                "conflicting --config-dir: {} vs {}",
                existing.display(),
                path.display()
            ),
        ));
    }
    *slot = Some(path);
    Ok(())
}

/// 把子解析器里的 `--config-dir` 合入全局槽。
fn merge_config_dir(slot: &mut Option<PathBuf>, value: Option<PathBuf>) -> io::Result<()> {
    match value {
        Some(path) => set_config_dir(slot, path),
        None => Ok(()),
    }
}

/// token 不接受非 UTF-8 值，且去首尾空白（避免 shell 换行混进凭据）。
fn os_string_to_token(value: &OsString) -> io::Result<String> {
    value
        .to_str()
        .map(|text| text.trim().to_string())
        .filter(|text| !text.is_empty())
        .ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "enrollment token must be non-empty UTF-8",
            )
        })
}

fn require_install_action(action: ServiceAction, flag: &str) -> io::Result<()> {
    if action == ServiceAction::Install {
        return Ok(());
    }
    Err(io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("{flag} is only supported with `service install`"),
    ))
}

async fn run_daemon(root: PathBuf, config_dir: Option<&Path>) -> AgentdResult<()> {
    let config_root = match config_dir {
        Some(path) => resolve_config_dir_arg(&root, path),
        None => default_config_root(),
    };
    let mut config = crate::config_runtime::load_or_init_async(&config_root)
        .await
        .conv_err()?;
    let root_dir = PathBuf::from(&config.paths.root_dir);
    let run_dir = PathBuf::from(&config.paths.run_dir);
    let state_dir = PathBuf::from(&config.paths.state_dir);
    let log_dir = PathBuf::from(&config.paths.log_dir);

    // 单实例锁：同一数据 home 下只允许一个 agentd 进程。
    // 覆盖 start.sh / --foreground / 直接运行二进制等所有入口。
    let _instance_lock = crate::single_instance::acquire(&state_dir)?;

    crate::bootstrap::initialize_async(&root_dir, &run_dir, &state_dir, &log_dir)
        .await
        .source_err(
            AgentdReason::system_error(),
            "initialize runtime directories",
        )?;
    let config_path = crate::config_runtime::resolve_config_path(&config_root);
    crate::enrollment::ensure_enrolled_with_config_path(&mut config, &state_dir, &config_path)
        .await
        .conv_err()?;
    initialize_runtime_state_async(&state_dir, &config)
        .await
        .source_err(AgentdReason::system_error(), "initialize runtime state")?;
    self_observability::register();
    eprintln!(
        "wist-agentd {} starting: config={} mode={} run_dir={} state_dir={} log_dir={}",
        env!("CARGO_PKG_VERSION"),
        config_path.display(),
        if config.control_plane.enabled {
            "managed"
        } else {
            "standalone"
        },
        run_dir.display(),
        state_dir.display(),
        log_dir.display(),
    );
    let exec_bin =
        resolve_exec_bin().source_err(AgentdReason::ExecBinUnavailable, "resolve wist-exec")?;
    let loop_ctx = daemon::DaemonLoop {
        config: &config,
        exec_bin: &exec_bin,
    };

    if std::env::var("WIST_AGENTD_RUN_ONCE").ok().as_deref() == Some("1") {
        let snapshot = daemon::run_once_async(&loop_ctx).await?;
        self_observability::emit(&snapshot);
        return Ok(());
    }

    daemon::run_forever_async(loop_ctx).await?;
    Ok(())
}

/// 执行 `enroll` 子命令：用一次性 token 注册，token 不落盘。
async fn run_enroll(
    root: PathBuf,
    config_dir: Option<&Path>,
    request: EnrollRequest,
) -> AgentdResult<()> {
    let config_root = match config_dir {
        Some(path) => resolve_config_dir_arg(&root, path),
        None => default_config_root(),
    };
    let token = if request.token_stdin {
        Some(read_token_from_stdin()?)
    } else {
        request.token
    };

    let decision = match token {
        Some(token) => crate::enrollment::enroll_with_token(&config_root, token)
            .await
            .conv_err()?,
        // 未给 token：等价于守护进程启动时的注册（用配置/环境变量里的 token）。
        None => crate::enrollment::enroll_from_config(&config_root)
            .await
            .conv_err()?,
    };
    let decision = reject_disabled(&config_root, decision)?;
    report_enrollment(&config_root, decision);
    Ok(())
}

/// 用一次性 token 注册；`Disabled` 视为错误（运维明确要求注册）。
async fn enroll_with_token_at(
    config_root: &Path,
    token: String,
) -> AgentdResult<crate::enrollment::EnrollmentDecision> {
    let decision = crate::enrollment::enroll_with_token(config_root, token)
        .await
        .conv_err()?;
    reject_disabled(config_root, decision)
}

/// `enroll` 的明确语义：配置里关掉了控制面就不能算“注册成功”。
fn reject_disabled(
    config_root: &Path,
    decision: crate::enrollment::EnrollmentDecision,
) -> AgentdResult<crate::enrollment::EnrollmentDecision> {
    match decision {
        crate::enrollment::EnrollmentDecision::Disabled => {
            Err(AgentdReason::Enrollment.to_err().with_detail(format!(
                "control_plane.enabled is false in {}/agentd.toml; enable it (with endpoint) before enrolling",
                config_root.display()
            )))
        }
        other => Ok(other),
    }
}

/// 从 stdin 读一次性 token（避免 token 出现在 argv / shell history）。
fn read_token_from_stdin() -> AgentdResult<String> {
    let mut buffer = String::new();
    std::io::Read::read_to_string(&mut std::io::stdin(), &mut buffer).source_err(
        AgentdReason::system_error(),
        "read enrollment token from stdin",
    )?;
    let token = buffer.trim().to_string();
    if token.is_empty() {
        return Err(AgentdReason::InvalidArgs
            .to_err()
            .with_detail("--token-stdin received an empty token"));
    }
    Ok(token)
}

/// 打印注册结果：只说结果与凭据落点，不吐任何秘密。
fn report_enrollment(config_root: &Path, decision: crate::enrollment::EnrollmentDecision) {
    use crate::enrollment::EnrollmentDecision;

    let label = match decision {
        EnrollmentDecision::Enrolled => "enrolled",
        EnrollmentDecision::ExistingStateIdentity => {
            "already enrolled (state identity, no request sent)"
        }
        EnrollmentDecision::ExistingConfigIdentity => {
            "already enrolled (config identity, no request sent)"
        }
        EnrollmentDecision::Disabled => "enrollment disabled",
    };
    println!("{label}");

    let config_path = crate::config_runtime::resolve_config_path(config_root);
    if let Ok(config) = crate::config_runtime::load_from_path(&config_path) {
        println!(
            "agent_id={}",
            config.agent.agent_id.as_deref().unwrap_or("-")
        );
        println!(
            "credential_file={}",
            crate::state_store::agent_runtime::path_for(Path::new(&config.paths.state_dir))
                .display()
        );
    }
    println!("token_persisted=false");
}

/// 执行 `service` 子命令：解析安装位置 →（可选）先注册 → 落盘定义 → 交给服务管理器加载。
async fn run_service(
    root: PathBuf,
    config_dir: Option<&Path>,
    request: ServiceRequest,
) -> AgentdResult<()> {
    let platform = match request.platform {
        Some(platform) => platform,
        None => ServicePlatform::current().ok_or_else(|| {
            AgentdReason::ServicePathUnresolved.to_err().with_detail(
                "service management is supported on Linux (systemd) and macOS (launchd) only",
            )
        })?,
    };
    let config_dir = match config_dir {
        Some(path) => resolve_config_dir_arg(&root, path),
        None => service::default_config_dir(request.scope)?,
    };
    let bin = match request.bin.as_ref() {
        Some(path) => path.clone(),
        None => service::default_bin()?,
    };
    let spec = ServiceSpec::new(request.scope, bin, config_dir);
    let layout = ServiceLayout::resolve(platform, request.scope)?;

    match request.action {
        ServiceAction::Print => {
            print!("{}", service::render(&layout, &spec));
            Ok(())
        }
        ServiceAction::Install => run_service_install(&layout, &spec, &request).await,
        ServiceAction::Uninstall => run_service_uninstall(&layout, &spec, platform),
        ServiceAction::Status => run_service_status(&layout, &spec),
    }
}

async fn run_service_install(
    layout: &ServiceLayout,
    spec: &ServiceSpec,
    request: &ServiceRequest,
) -> AgentdResult<()> {
    // 先注册再装服务：token 无效/控制面不可达时，不会留下一个启动即报错的半成品服务。
    if let Some(token) = request.enrollment_token.as_ref() {
        let decision = enroll_with_token_at(&spec.config_dir, token.clone()).await?;
        report_enrollment(&spec.config_dir, decision);
    }

    let report = service::install(layout, spec, request.force)?;
    println!(
        "service definition written: {}",
        report.definition_path.display()
    );
    if report.overwritten {
        println!("previous definition overwritten (--force)");
    }
    if !report.bin_present {
        eprintln!(
            "warning: wist-agentd binary not found: {} (install it before starting the service)",
            spec.bin.display()
        );
    }
    if !report.exec_bin_present {
        eprintln!(
            "warning: wist-exec not found next to wist-agentd: {} (the daemon resolves it as a sibling binary; set WARP_INSIGHT_EXEC_BIN or place it there)",
            spec.exec_bin().display()
        );
    }
    if let Some(log_dir) = report.log_dir.as_ref() {
        println!("launchd logs: {}", log_dir.display());
    }
    if !spec.config_dir.is_dir() {
        eprintln!(
            "warning: config dir {} does not exist; the daemon writes the default agentd.toml on first start (run `wist-agentd init-config --config-dir {}` to create and review it before starting)",
            spec.config_dir.display(),
            spec.config_dir.display()
        );
    }

    let activate = service::activate_commands(layout, spec)?;
    if request.activate {
        run_service_commands(&activate)?;
        println!("service activated ({})", layout.platform.as_str());
    } else {
        println!("definition only (--no-activate); activate manually:");
        for command in &activate {
            println!("  {}", command.display_line());
        }
    }
    println!("logs: {}", service::log_hint(layout, spec)?);
    for command in service::inspect_commands(layout.platform, spec) {
        println!("check: {}", command.display_line());
    }
    Ok(())
}

fn run_service_uninstall(
    layout: &ServiceLayout,
    spec: &ServiceSpec,
    platform: ServicePlatform,
) -> AgentdResult<()> {
    // 先停再删：避免留下无人托管的孤儿进程（停止失败的兜底由启动时的 flock 承担）。
    run_service_commands(&service::deactivate_commands(platform, spec))?;
    let removed = service::remove(layout)?;
    println!(
        "service definition {}: {}",
        layout.definition_path.display(),
        if removed { "removed" } else { "not present" }
    );
    Ok(())
}

fn run_service_status(layout: &ServiceLayout, spec: &ServiceSpec) -> AgentdResult<()> {
    let status = service::status(layout, spec)?;
    println!("platform={}", status.platform.as_str());
    println!("scope={}", status.scope.as_str());
    println!("definition={}", status.definition_path.display());
    println!("definition_present={}", status.definition_present);
    println!("bin={}", service::path_state(&status.bin));
    println!("exec_bin={}", service::path_state(&status.exec_bin));
    println!("config={}", service::path_state(&status.config_path));
    if let Some(reason) = status.config_error.as_ref() {
        println!("config_error={reason}");
    }
    for (key, path) in [
        ("root_dir", status.root_dir.as_ref()),
        ("run_dir", status.run_dir.as_ref()),
        ("state_dir", status.state_dir.as_ref()),
        ("log_dir", status.log_dir.as_ref()),
    ] {
        match path {
            Some(path) => println!("{key}={}", path.display()),
            None => println!("{key}=-"),
        }
    }
    match status.running {
        Some(true) => println!("running=true"),
        Some(false) => println!("running=false"),
        None => println!("running=unknown (no readable config)"),
    }
    println!("logs={}", status.log_hint);
    for command in service::inspect_commands(status.platform, spec) {
        println!("check={}", command.display_line());
    }
    Ok(())
}

/// 顺序执行服务管理器命令；`ignore_failure` 的失败只忽略，其余汇总报错。
fn run_service_commands(commands: &[ServiceCommand]) -> AgentdResult<()> {
    let mut failures = Vec::new();
    for command in commands {
        // 服务管理器拆除是异步的（尤其 launchd），瞬时失败靠有界重试吃掉。
        let outcome = service::run_with_retries(command)?;
        if outcome.success || command.ignore_failure {
            continue;
        }
        failures.push(format!(
            "`{}` failed: {}",
            command.display_line(),
            failure_detail(&outcome)
        ));
    }
    if failures.is_empty() {
        return Ok(());
    }
    Err(AgentdReason::ServiceCommandFailed
        .to_err()
        .with_detail(failures.join("; ")))
}

fn failure_detail(outcome: &ServiceCommandOutcome) -> String {
    let text = if outcome.stderr.is_empty() {
        outcome.stdout.as_str()
    } else {
        outcome.stderr.as_str()
    };
    text.lines().next().unwrap_or("no output").to_string()
}

fn init_config_message(path: &Path, created: bool, data_root: Option<&Path>) -> String {
    let config_dir = path
        .parent()
        .map(|value| value.display().to_string())
        .unwrap_or_else(|| CONFIG_DIR.to_string());
    let data_note = match data_root {
        Some(data_root) => format!(
            "\nconfig dir {} is the system location: data (run/state/spool + collected output data/) defaults to {}, logs to {} (declare [paths] to override)",
            config_dir,
            data_root.display(),
            crate::config_runtime::SYSTEM_LOG_DIR
        ),
        None => String::new(),
    };
    if created {
        format!(
            "initialized config directory {} and wrote config file {}{}",
            config_dir,
            path.display(),
            data_note
        )
    } else {
        format!(
            "config file already exists at {} (config directory: {}){}",
            path.display(),
            config_dir,
            data_note
        )
    }
}

fn usage_message() -> &'static str {
    concat!(
        "Usage:\n",
        "  wist-agentd [--config-dir <path>]\n",
        "  wist-agentd help\n",
        "  wist-agentd version\n",
        "  wist-agentd init-config [--stdout] [--config-dir <path>]\n",
        "  wist-agentd service <print|install|uninstall|status> [--system|--user] [--bin <path>] [--force] [--no-activate] [--config-dir <path>]\n",
        "  wist-agentd service print --for <systemd|launchd>   (render for another platform)\n",
        "  wist-agentd enroll [--token <token> | --token-stdin] [--config-dir <path>]\n",
        "\n",
        "Commands:\n",
        "  help                 Show this help message.\n",
        "  version              Print the daemon version.\n",
        "  init-config          Initialize config directory wist-agentd/ and write agentd.toml.\n",
        "  init-config --stdout Print the default config template to stdout.\n",
        "  service print        Print the systemd unit / launchd plist without touching the system.\n",
        "  service install      Write the service definition and (unless --no-activate) load and start it.\n",
        "  service uninstall    Stop the service and remove its definition.\n",
        "  service status       Show definition / binary / config / lock / log status.\n",
        "  enroll               Enroll with a one-time token; the token is never written to disk.\n",
        "\n",
        "Service options (Linux uses systemd, macOS uses launchd):\n",
        "  --system             Install for the whole host (default; /etc paths, root-owned).\n",
        "  --user               Install for the current user (systemd --user / launchd LaunchAgent).\n",
        "  --bin <path>         Installed path of the wist-agentd binary (default: current executable).\n",
        "  --for <platform>     Only with `service print`: render systemd or launchd output.\n",
        "  --force              Overwrite an existing service definition.\n",
        "  --no-activate        Only write the definition; print the commands to load it yourself.\n",
        "  --enrollment-token <token>  Only with `service install`: enroll first (token not persisted).\n",
        "\n",
        "Enroll options:\n",
        "  --token <token>      One-time enrollment token (visible in argv/ps for the run).\n",
        "  --token-stdin        Read the token from stdin instead (recommended on shared hosts).\n",
        "\n",
        "Options:\n",
        "  --config-dir <path>  Use the specified config directory. Relative paths are resolved from the current working directory.\n",
        "                       Default: /etc/wist-agentd.\n",
    )
}

/// 显式 `--config-dir` 的解析：绝对路径原样使用，相对路径相对当前工作目录。
fn resolve_config_dir_arg(root: &Path, path: &Path) -> PathBuf {
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        root.join(path)
    }
}

/// 命令行入口使用的默认配置目录：系统默认位置（要么给 `--config-dir`，要么就是它）。
fn default_config_root() -> PathBuf {
    PathBuf::from(SYSTEM_CONFIG_DIR)
}

async fn initialize_runtime_state_async(
    state_dir: &Path,
    config: &wist_contracts::agent_config::AgentConfig,
) -> io::Result<()> {
    let runtime_path = state_store::agent_runtime::path_for(state_dir);
    let mut runtime_state =
        state_store::agent_runtime::load_or_default_async(&runtime_path).await?;
    sync_runtime_identity(&mut runtime_state, config)?;
    state_store::agent_runtime::store_async(&runtime_path, &runtime_state).await?;

    let queue_path = state_store::execution_queue::path_for(state_dir);
    let queue_state = state_store::execution_queue::load_or_default_async(&queue_path).await?;
    state_store::execution_queue::store_async(&queue_path, &queue_state).await?;
    Ok(())
}

fn resolve_exec_bin() -> io::Result<PathBuf> {
    let env_override = std::env::var_os("WARP_INSIGHT_EXEC_BIN").map(PathBuf::from);
    let path_env = std::env::var_os("PATH");
    let current_exe = std::env::current_exe()?;
    resolve_exec_bin_from(&current_exe, env_override.as_deref(), path_env.as_deref())
}

fn resolve_exec_bin_from(
    current_exe: &Path,
    env_override: Option<&Path>,
    path_env: Option<&std::ffi::OsStr>,
) -> io::Result<PathBuf> {
    if let Some(path) = env_override {
        return validate_exec_bin(path.to_path_buf(), "WARP_INSIGHT_EXEC_BIN");
    }

    let sibling = current_exe.with_file_name("wist-exec");
    if sibling.exists() {
        return validate_exec_bin(sibling, "current executable sibling");
    }

    if let Some(path_env) = path_env {
        for dir in std::env::split_paths(path_env) {
            let candidate = dir.join("wist-exec");
            if candidate.exists() {
                return validate_exec_bin(candidate, "PATH");
            }
        }
    }

    validate_exec_bin(sibling, "current executable sibling")
}

fn validate_exec_bin(path: PathBuf, origin: &str) -> io::Result<PathBuf> {
    let metadata = std::fs::metadata(&path).map_err(|err| {
        io::Error::new(
            err.kind(),
            format!(
                "wist-exec was not found via {origin}: {} ({err})",
                path.display()
            ),
        )
    })?;
    if !metadata.is_file() {
        return Err(io::Error::other(format!(
            "wist-exec path is not a file: {}",
            path.display()
        )));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;

        if metadata.permissions().mode() & 0o111 == 0 {
            return Err(io::Error::new(
                io::ErrorKind::PermissionDenied,
                format!("wist-exec is not executable: {}", path.display()),
            ));
        }
    }
    Ok(path)
}

fn sync_runtime_identity(
    runtime_state: &mut wist_contracts::agent_state::AgentRuntimeState,
    config: &wist_contracts::agent_config::AgentConfig,
) -> io::Result<()> {
    if let Some(agent_id) = config
        .agent
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        // Never silently rebind an already-enrolled identity to a different
        // config id while keeping its credentials — that would let state carry
        // a cross-agent credential. Fail loudly and ask the operator to resolve.
        if is_registered_agent_id(&runtime_state.agent_id) && runtime_state.agent_id != agent_id {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                format!(
                    "config agent.agent_id ({agent_id}) conflicts with enrolled runtime identity {}; remove agent.agent_id or clear the agent state to re-enroll",
                    runtime_state.agent_id
                ),
            ));
        }
        runtime_state.agent_id = agent_id.to_string();
    }
    if let Some(instance_id) = config
        .agent
        .instance_name
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
    {
        runtime_state.instance_id = instance_id.to_string();
    }
    Ok(())
}

#[cfg(test)]
#[path = "runtime_entry_tests.rs"]
mod tests;
