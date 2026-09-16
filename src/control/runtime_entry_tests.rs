use super::{
    init_config_message, parse_command, resolve_config_dir_arg, resolve_exec_bin_from,
    run_from_args, sync_runtime_identity, usage_message,
};
use std::fs;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};
use wist_contracts::agent_config::{
    AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
};
use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("duration")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-agentd-lib-{name}-{suffix}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn block_on<F: std::future::Future>(future: F) -> F::Output {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("build tokio runtime")
        .block_on(future)
}

#[test]
fn resolve_exec_bin_uses_env_override_when_present() {
    let root = temp_dir("override");
    let current_exe = root.join("bin").join("wist-agentd");
    let override_path = root.join("custom").join("wist-exec");
    fs::create_dir_all(current_exe.parent().expect("current_exe parent"))
        .expect("create current_exe parent");
    fs::create_dir_all(override_path.parent().expect("override parent"))
        .expect("create override parent");
    fs::write(&override_path, b"#!/bin/sh\n").expect("write override");
    #[cfg(unix)]
    {
        let mut perms = fs::metadata(&override_path)
            .expect("override metadata")
            .permissions();
        perms.set_mode(0o755);
        fs::set_permissions(&override_path, perms).expect("set override permissions");
    }

    let resolved = resolve_exec_bin_from(&current_exe, Some(Path::new(&override_path)), None)
        .expect("resolve");

    assert_eq!(resolved, override_path);
}

#[cfg(unix)]
#[test]
fn resolve_exec_bin_uses_path_when_sibling_is_missing() {
    let root = temp_dir("path-fallback");
    let current_exe = root.join("bin").join("wist-agentd");
    let path_dir = root.join("path-bin");
    let path_exec = path_dir.join("wist-exec");
    fs::create_dir_all(current_exe.parent().expect("current_exe parent"))
        .expect("create current_exe parent");
    fs::create_dir_all(&path_dir).expect("create path dir");
    fs::write(&path_exec, b"#!/bin/sh\n").expect("write path exec");
    let mut perms = fs::metadata(&path_exec)
        .expect("path exec metadata")
        .permissions();
    perms.set_mode(0o755);
    fs::set_permissions(&path_exec, perms).expect("set path exec permissions");

    let path_env = std::ffi::OsString::from(path_dir.display().to_string());
    let resolved = resolve_exec_bin_from(&current_exe, None, Some(path_env.as_os_str()))
        .expect("resolve via path");

    assert_eq!(resolved, path_exec);
}

#[cfg(unix)]
#[test]
fn resolve_exec_bin_prefers_sibling_before_path() {
    let root = temp_dir("sibling-before-path");
    let current_exe = root.join("bin").join("wist-agentd");
    let sibling = root.join("bin").join("wist-exec");
    let path_dir = root.join("path-bin");
    let path_exec = path_dir.join("wist-exec");
    fs::create_dir_all(current_exe.parent().expect("current_exe parent"))
        .expect("create current_exe parent");
    fs::create_dir_all(&path_dir).expect("create path dir");
    fs::write(&sibling, b"#!/bin/sh\n").expect("write sibling");
    fs::write(&path_exec, b"#!/bin/sh\n").expect("write path exec");
    for path in [&sibling, &path_exec] {
        let mut perms = fs::metadata(path).expect("exec metadata").permissions();
        perms.set_mode(0o755);
        fs::set_permissions(path, perms).expect("set exec permissions");
    }

    let path_env = std::ffi::OsString::from(path_dir.display().to_string());
    let resolved = resolve_exec_bin_from(&current_exe, None, Some(path_env.as_os_str()))
        .expect("resolve sibling before path");

    assert_eq!(resolved, sibling);
}

#[test]
fn parse_command_defaults_to_run() {
    assert_eq!(
        parse_command(Vec::<&str>::new()).expect("parse"),
        super::ParsedArgs {
            command: super::Command::Run,
            config_dir: None,
        }
    );
}

#[test]
fn parse_command_accepts_help_variants() {
    assert_eq!(
        parse_command(["help"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::Help,
            config_dir: None,
        }
    );
    assert_eq!(
        parse_command(["--help"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::Help,
            config_dir: None,
        }
    );
    assert_eq!(
        parse_command(["-h"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::Help,
            config_dir: None,
        }
    );
}

#[test]
fn parse_command_accepts_init_config() {
    assert_eq!(
        parse_command(["init-config"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::InitConfig { stdout_only: false },
            config_dir: None,
        }
    );
}

#[test]
fn parse_command_accepts_init_config_stdout() {
    assert_eq!(
        parse_command(["init-config", "--stdout"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::InitConfig { stdout_only: true },
            config_dir: None,
        }
    );
}

#[test]
fn parse_command_accepts_global_config_dir() {
    assert_eq!(
        parse_command(["--config-dir", "conf", "init-config"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::InitConfig { stdout_only: false },
            config_dir: Some(PathBuf::from("conf")),
        }
    );
}

#[test]
fn parse_command_accepts_init_config_stdout_after_config_dir() {
    assert_eq!(
        parse_command(["init-config", "--config-dir", "conf", "--stdout"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::InitConfig { stdout_only: true },
            config_dir: Some(PathBuf::from("conf")),
        }
    );
}

#[test]
fn parse_command_rejects_unknown_command() {
    let err = parse_command(["bad-command"]).expect_err("unknown command");
    assert!(err.to_string().contains("unknown argument or command"));
    assert!(err.to_string().contains("--config-dir"));
}

#[test]
fn parse_command_rejects_missing_config_dir_value() {
    let err = parse_command(["--config-dir"]).expect_err("missing config dir");
    assert!(err.to_string().contains("missing value for --config-dir"));
}

#[test]
fn parse_command_rejects_config_dir_followed_by_option() {
    let err =
        parse_command(["init-config", "--config-dir", "--stdout"]).expect_err("invalid config dir");
    assert!(err.to_string().contains("missing value for --config-dir"));
}

#[test]
fn parse_command_rejects_stdout_without_init_config() {
    let err = parse_command(["--stdout"]).expect_err("stdout without init-config");
    assert!(
        err.to_string()
            .contains("--stdout is only supported with init-config")
    );
}

#[test]
fn run_from_args_init_config_creates_config_without_exec_bin() {
    let root = temp_dir("cli-init-config");

    run_from_args(root.clone(), ["init-config", "--config-dir", "wist-agentd"])
        .expect("init config command");

    assert!(root.join("wist-agentd").join("agentd.toml").exists());
}

#[test]
fn run_from_args_init_config_honors_custom_config_dir() {
    let root = temp_dir("cli-init-config-custom-dir");

    run_from_args(root.clone(), ["init-config", "--config-dir", "conf"])
        .expect("init config with custom dir");

    assert!(root.join("conf").join("agentd.toml").exists());
}

#[test]
fn init_config_message_mentions_config_directory_when_created() {
    let path = Path::new("/tmp/project/wist-agentd/agentd.toml");

    let message = init_config_message(path, true, None);

    assert!(message.contains("initialized config directory"));
    assert!(message.contains("/tmp/project/wist-agentd"));
    assert!(message.contains("/tmp/project/wist-agentd/agentd.toml"));
    assert!(!message.contains("run/state/log/spool default to"));
}

#[test]
fn init_config_message_explains_data_separation_for_system_config_dir() {
    let path = Path::new("/etc/wist-agentd/agentd.toml");

    let message = init_config_message(path, true, Some(Path::new("/var/lib/wist-agentd")));

    assert!(message.contains(
        "data (run/state/spool + collected output data/) defaults to /var/lib/wist-agentd"
    ));
    assert!(message.contains("logs to /var/log/wist-agentd"));
    assert!(message.contains("declare [paths] to override"));
}

#[test]
fn usage_message_lists_supported_commands() {
    let message = usage_message();

    assert!(message.contains("wist-agentd init-config [--stdout]"));
    assert!(message.contains("wist-agentd help"));
    assert!(message.contains("wist-agentd version"));
    assert!(message.contains("wist-agentd service <print|install|uninstall|status>"));
    assert!(message.contains("Show this help message"));
    assert!(message.contains("--config-dir <path>"));
}

#[test]
fn parse_command_accepts_version_variants() {
    for arg in ["version", "--version", "-V"] {
        assert_eq!(
            parse_command([arg]).expect("parse"),
            super::ParsedArgs {
                command: super::Command::Version,
                config_dir: None,
            }
        );
    }
}

#[test]
fn parse_command_accepts_service_action_and_defaults_to_system_scope() {
    let parsed = parse_command(["service", "print"]).expect("parse");
    assert_eq!(parsed.config_dir, None);
    assert_eq!(
        parsed.command,
        super::Command::Service(super::ServiceRequest {
            action: super::ServiceAction::Print,
            scope: super::ServiceScope::System,
            platform: None,
            bin: None,
            force: false,
            activate: true,
            enrollment_token: None,
        })
    );
}

#[test]
fn parse_command_accepts_service_install_flags() {
    let parsed = parse_command([
        "service",
        "install",
        "--user",
        "--bin",
        "/opt/wist/bin/wist-agentd",
        "--force",
        "--no-activate",
        "--config-dir",
        "/etc/wist-agentd",
    ])
    .expect("parse");

    assert_eq!(parsed.config_dir, Some(PathBuf::from("/etc/wist-agentd")));
    assert_eq!(
        parsed.command,
        super::Command::Service(super::ServiceRequest {
            action: super::ServiceAction::Install,
            scope: super::ServiceScope::User,
            platform: None,
            bin: Some(PathBuf::from("/opt/wist/bin/wist-agentd")),
            force: true,
            activate: false,
            enrollment_token: None,
        })
    );
}

#[test]
fn parse_command_rejects_invalid_service_arguments() {
    let err = parse_command(["service"]).expect_err("missing action");
    assert!(err.to_string().contains("missing service action"));

    let err = parse_command(["service", "restart"]).expect_err("unknown action");
    assert!(err.to_string().contains("unknown service action"));

    let err = parse_command(["service", "status", "--force"]).expect_err("flag misuse");
    assert!(
        err.to_string()
            .contains("--force is only supported with `service install`")
    );

    let err = parse_command(["service", "install", "--bin", "--force"]).expect_err("no value");
    assert!(err.to_string().contains("missing value for --bin"));
}

#[test]
fn parse_command_accepts_service_flags_after_config_dir() {
    // 真正的调用顺序（脚本/文档里）：子命令参数跟在 --config-dir 后面也必须能解析。
    let parsed = parse_command([
        "service",
        "install",
        "--bin",
        "/usr/local/bin/wist-agentd",
        "--config-dir",
        "/etc/wist-agentd",
        "--force",
        "--enrollment-token",
        "tok-7",
    ])
    .expect("parse");

    assert_eq!(parsed.config_dir, Some(PathBuf::from("/etc/wist-agentd")));
    assert_eq!(
        parsed.command,
        super::Command::Service(super::ServiceRequest {
            action: super::ServiceAction::Install,
            scope: super::ServiceScope::System,
            platform: None,
            bin: Some(PathBuf::from("/usr/local/bin/wist-agentd")),
            force: true,
            activate: true,
            enrollment_token: Some("tok-7".to_string()),
        })
    );
}

#[test]
fn parse_command_accepts_enroll_flags_after_config_dir() {
    let parsed =
        parse_command(["enroll", "--config-dir", "conf", "--token", "tok-1"]).expect("parse");
    assert_eq!(parsed.config_dir, Some(PathBuf::from("conf")));
    assert_eq!(
        parsed.command,
        super::Command::Enroll(super::EnrollRequest {
            token: Some("tok-1".to_string()),
            token_stdin: false,
        })
    );
}

#[test]
fn parse_command_rejects_conflicting_config_dir_values() {
    let err = parse_command(["service", "print", "--config-dir", "a", "--config-dir", "b"])
        .expect_err("conflicting config dir");

    assert!(
        err.to_string().contains("conflicting --config-dir"),
        "{err}"
    );
}

#[test]
fn parse_command_accepts_cross_platform_render_target() {
    let parsed = parse_command(["service", "print", "--for", "launchd"]).expect("parse");
    assert_eq!(
        parsed.command,
        super::Command::Service(super::ServiceRequest {
            action: super::ServiceAction::Print,
            scope: super::ServiceScope::System,
            platform: Some(super::ServicePlatform::Launchd),
            bin: None,
            force: false,
            activate: true,
            enrollment_token: None,
        })
    );

    let err = parse_command(["service", "status", "--for", "systemd"]).expect_err("flag misuse");
    assert!(
        err.to_string()
            .contains("--for is only supported with `service print`")
    );

    let err = parse_command(["service", "print", "--for", "windows"]).expect_err("bad target");
    assert!(err.to_string().contains("unknown platform for --for"));
}

#[test]
fn parse_command_accepts_enroll_with_token_forms() {
    let parsed = parse_command(["enroll", "--token", "tok-1"]).expect("parse");
    assert_eq!(
        parsed.command,
        super::Command::Enroll(super::EnrollRequest {
            token: Some("tok-1".to_string()),
            token_stdin: false,
        })
    );

    let parsed = parse_command([
        "enroll",
        "--token-stdin",
        "--config-dir",
        "/etc/wist-agentd",
    ])
    .expect("parse");
    assert_eq!(parsed.config_dir, Some(PathBuf::from("/etc/wist-agentd")));
    assert_eq!(
        parsed.command,
        super::Command::Enroll(super::EnrollRequest {
            token: None,
            token_stdin: true,
        })
    );

    // 不给 token = 用配置/环境变量里的（等价于守护进程启动时的注册）。
    assert_eq!(
        parse_command(["enroll"]).expect("parse"),
        super::ParsedArgs {
            command: super::Command::Enroll(super::EnrollRequest {
                token: None,
                token_stdin: false,
            }),
            config_dir: None,
        }
    );
}

#[test]
fn parse_command_rejects_bad_enroll_arguments() {
    let err = parse_command(["enroll", "--token"]).expect_err("missing token value");
    assert!(err.to_string().contains("missing value for --token"));

    let err = parse_command(["enroll", "--token", "a", "--token-stdin"]).expect_err("both forms");
    assert!(err.to_string().contains("mutually exclusive"));

    let err = parse_command(["enroll", "--token", "   "]).expect_err("blank token");
    assert!(err.to_string().contains("non-empty UTF-8"));
}

#[test]
fn parse_command_accepts_service_install_enrollment_token() {
    let parsed = parse_command([
        "service",
        "install",
        "--enrollment-token",
        "tok-9",
        "--no-activate",
    ])
    .expect("parse");

    assert_eq!(
        parsed.command,
        super::Command::Service(super::ServiceRequest {
            action: super::ServiceAction::Install,
            scope: super::ServiceScope::System,
            platform: None,
            bin: None,
            force: false,
            activate: false,
            enrollment_token: Some("tok-9".to_string()),
        })
    );

    let err = parse_command(["service", "status", "--enrollment-token", "tok-9"])
        .expect_err("flag misuse");
    assert!(
        err.to_string()
            .contains("--enrollment-token is only supported with `service install`")
    );
}

#[test]
fn run_service_install_does_not_write_a_definition_when_enrollment_fails() {
    let root = temp_dir("cli-install-enroll-fail");
    // 配置目录里没有 agentd.toml → 注册失败 → 不应留下服务定义。
    let spec = crate::service::ServiceSpec::new(
        super::ServiceScope::System,
        root.join("bin/wist-agentd"),
        root.join("missing-conf"),
    );
    let layout = crate::service::ServiceLayout::for_paths(
        crate::service::ServicePlatform::Systemd,
        super::ServiceScope::System,
        root.join("wist-agentd.service"),
        None,
    );
    let request = super::ServiceRequest {
        action: super::ServiceAction::Install,
        scope: super::ServiceScope::System,
        platform: None,
        bin: Some(spec.bin.clone()),
        force: false,
        activate: false,
        enrollment_token: Some("tok-x".to_string()),
    };

    let result = block_on(super::run_service_install(&layout, &spec, &request));

    assert!(result.is_err(), "enrollment failure must abort the install");
    assert!(!layout.definition_path.exists());
}

#[test]
fn parse_command_rejects_token_flags_outside_enroll() {
    let err = parse_command(["init-config", "--token", "tok"]).expect_err("unknown argument");
    assert!(err.to_string().contains("unknown argument or command"));

    let err = parse_command(["service", "print", "--token", "tok"]).expect_err("unknown argument");
    assert!(err.to_string().contains("unknown argument or command"));

    let err =
        parse_command(["service", "install", "--enrollment-token", "  "]).expect_err("blank token");
    assert!(err.to_string().contains("non-empty UTF-8"));
}

#[test]
fn run_service_print_renders_without_side_effects() {
    let root = temp_dir("cli-service-print");
    let config_dir = root.join("etc/wist-agentd");
    let definition = crate::service::ServiceLayout::resolve(
        crate::service::ServicePlatform::current().expect("linux or macos"),
        super::ServiceScope::System,
    )
    .expect("layout")
    .definition_path;

    let result = block_on(super::run_service(
        root.clone(),
        Some(&config_dir),
        super::ServiceRequest {
            action: super::ServiceAction::Print,
            scope: super::ServiceScope::System,
            platform: None,
            bin: Some(PathBuf::from("/usr/local/bin/wist-agentd")),
            force: false,
            activate: false,
            enrollment_token: None,
        },
    ));

    assert!(result.is_ok());
    // print 只输出定义，既不改动真实定义文件，也不创建配置目录。
    assert!(definition.is_absolute());
    assert!(!config_dir.exists());
}

#[test]
fn init_config_message_mentions_existing_config_file_and_directory() {
    let path = Path::new("/tmp/project/wist-agentd/agentd.toml");

    let message = init_config_message(path, false, None);

    assert!(message.contains("config file already exists"));
    assert!(message.contains("/tmp/project/wist-agentd"));
    assert!(message.contains("/tmp/project/wist-agentd/agentd.toml"));
}

#[test]
fn run_from_args_init_config_stdout_does_not_create_config_file() {
    let root = temp_dir("cli-init-config-stdout");

    run_from_args(root.clone(), ["init-config", "--stdout"]).expect("init config stdout");

    assert!(!root.join("wist-agentd").join("agentd.toml").exists());
}

#[test]
fn default_config_root_is_the_system_dir() {
    assert_eq!(
        super::default_config_root(),
        PathBuf::from(crate::config_runtime::SYSTEM_CONFIG_DIR)
    );
}

#[test]
fn resolve_config_dir_arg_uses_relative_override_from_root() {
    let root = temp_dir("requested-config-root-relative");

    assert_eq!(
        resolve_config_dir_arg(&root, Path::new("conf")),
        root.join("conf")
    );
}

#[test]
fn resolve_config_dir_arg_preserves_absolute_override() {
    let root = temp_dir("requested-config-root-absolute");
    let absolute = root.join("external-conf");

    assert_eq!(resolve_config_dir_arg(&root, &absolute), absolute);
}

#[test]
fn resolve_exec_bin_rejects_missing_candidate() {
    let root = temp_dir("missing");
    let current_exe = root.join("bin").join("wist-agentd");
    fs::create_dir_all(current_exe.parent().expect("current_exe parent"))
        .expect("create current_exe parent");

    let err =
        resolve_exec_bin_from(&current_exe, None, None).expect_err("missing exec should fail");
    assert!(err.to_string().contains("wist-exec was not found"));
}

#[cfg(unix)]
#[test]
fn resolve_exec_bin_rejects_non_executable_file() {
    let root = temp_dir("not-executable");
    let current_exe = root.join("bin").join("wist-agentd");
    let candidate = root.join("bin").join("wist-exec");
    fs::create_dir_all(current_exe.parent().expect("current_exe parent"))
        .expect("create current_exe parent");
    fs::write(&candidate, b"#!/bin/sh\n").expect("write candidate");
    let mut perms = fs::metadata(&candidate)
        .expect("candidate metadata")
        .permissions();
    perms.set_mode(0o644);
    fs::set_permissions(&candidate, perms).expect("set candidate permissions");

    let err = resolve_exec_bin_from(&current_exe, None, None)
        .expect_err("non executable candidate should fail");

    assert!(err.to_string().contains("not executable"));
}

#[test]
fn sync_runtime_identity_prefers_config_identity_when_present() {
    let mut runtime = AgentRuntimeState::new(
        "local-agent".to_string(),
        "local-instance".to_string(),
        "0.1.0".to_string(),
        RuntimeMode::Normal,
        "2026-04-12T10:00:00Z".to_string(),
    );
    let config = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-from-config".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-from-config".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            bearer_token: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: ".".to_string(),
            run_dir: "run".to_string(),
            state_dir: "state".to_string(),
            log_dir: "log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1,
            default_stderr_limit_bytes: 1,
        },
    );

    sync_runtime_identity(&mut runtime, &config).expect("sync identity");

    assert_eq!(runtime.agent_id, "agent-from-config");
    assert_eq!(runtime.instance_id, "instance-from-config");
}

#[test]
fn sync_runtime_identity_rejects_config_agent_id_conflicting_with_enrolled_identity() {
    let mut runtime = AgentRuntimeState::new(
        "agent-a".to_string(),
        "instance-a".to_string(),
        "0.1.0".to_string(),
        RuntimeMode::Normal,
        "2026-04-12T10:00:00Z".to_string(),
    );
    let config = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-b".to_string()),
            environment_id: None,
            instance_name: Some("instance-from-config".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            bearer_token: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: ".".to_string(),
            run_dir: "run".to_string(),
            state_dir: "state".to_string(),
            log_dir: "log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1,
            default_stderr_limit_bytes: 1,
        },
    );

    let err = sync_runtime_identity(&mut runtime, &config).expect_err("conflict rejected");

    assert!(err.to_string().contains("conflicts"));
    assert_eq!(runtime.agent_id, "agent-a");
}
