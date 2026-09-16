use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use super::*;

fn temp_dir(name: &str) -> PathBuf {
    let suffix = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("duration")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-agentd-service-{name}-{suffix}"));
    fs::create_dir_all(&dir).expect("create temp dir");
    dir
}

fn spec_in(root: &Path) -> ServiceSpec {
    ServiceSpec::new(
        ServiceScope::System,
        root.join("bin").join("wist-agentd"),
        root.join("etc").join("wist-agentd"),
    )
}

fn layout_in(root: &Path, platform: ServicePlatform) -> ServiceLayout {
    let definition_path = match platform {
        ServicePlatform::Systemd => root.join("wist-agentd.service"),
        ServicePlatform::Launchd => root.join("com.dayu-sec.wist-agentd.plist"),
    };
    let log_dir = match platform {
        ServicePlatform::Systemd => None,
        ServicePlatform::Launchd => Some(root.join("logs")),
    };
    ServiceLayout::for_paths(platform, ServiceScope::System, definition_path, log_dir)
}

#[test]
fn system_scope_paths_follow_platform_conventions() {
    assert_eq!(
        default_config_dir(ServiceScope::System).expect("system config dir"),
        PathBuf::from("/etc/wist-agentd")
    );
    assert_eq!(
        ServiceLayout::resolve(ServicePlatform::Systemd, ServiceScope::System)
            .expect("systemd system layout")
            .definition_path,
        PathBuf::from("/etc/systemd/system/wist-agentd.service")
    );
    assert_eq!(
        ServiceLayout::resolve(ServicePlatform::Launchd, ServiceScope::System)
            .expect("launchd system layout")
            .definition_path,
        PathBuf::from("/Library/LaunchDaemons/com.dayu-sec.wist-agentd.plist")
    );
}

#[test]
fn systemd_unit_runs_in_foreground_and_restarts_always() {
    let root = temp_dir("unit");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Systemd);

    let text = render(&layout, &spec);

    assert!(text.contains("[Unit]"));
    assert!(text.contains("[Install]"));
    assert!(text.contains("Type=simple"));
    assert!(text.contains(&format!(
        "ExecStart={} --config-dir {}",
        spec.bin.display(),
        spec.config_dir.display()
    )));
    assert!(text.contains("Restart=always"));
    assert!(text.contains("RestartSec=5"));
    // 前导 `-` 表示环境变量文件可缺失。
    assert!(text.contains(&format!("EnvironmentFile=-{}", spec.env_file().display())));
    assert!(text.contains("WantedBy=multi-user.target"));
}

#[test]
fn systemd_user_scope_targets_default_target_with_user_flag() {
    let root = temp_dir("unit-user");
    let spec = ServiceSpec::new(
        ServiceScope::User,
        root.join("bin/wist-agentd"),
        root.join("conf"),
    );
    let layout = ServiceLayout::for_paths(
        ServicePlatform::Systemd,
        ServiceScope::User,
        root.join("wist-agentd.service"),
        None,
    );

    let text = render(&layout, &spec);

    assert!(text.contains("WantedBy=default.target"));
    assert_eq!(spec.systemctl_scope_args(), vec!["--user".to_string()]);
}

#[test]
fn launchd_plist_keeps_alive_and_logs_to_files() {
    let root = temp_dir("plist");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Launchd);
    let log_dir = layout.log_dir.clone().expect("log dir");

    let text = render(&layout, &spec);

    assert!(text.contains("<key>Label</key>"));
    assert!(text.contains(LAUNCHD_LABEL));
    assert!(text.contains("<key>KeepAlive</key>"));
    assert!(text.contains("<true/>"));
    assert!(text.contains(&format!("<string>{}</string>", spec.bin.display())));
    assert!(text.contains("--config-dir"));
    assert!(text.contains(&format!("<string>{}</string>", spec.config_dir.display())));
    assert!(text.contains(&format!(
        "<string>{}</string>",
        log_dir.join("agentd.err").display()
    )));
}

#[test]
fn install_writes_definition_and_is_guarded_by_force() {
    let root = temp_dir("install");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Systemd);

    let report = install(&layout, &spec, false).expect("first install");
    assert!(!report.overwritten);
    assert_eq!(report.platform, ServicePlatform::Systemd);
    assert!(!report.exec_bin_present);
    let written = fs::read_to_string(&layout.definition_path).expect("read definition");
    assert_eq!(written, render(&layout, &spec));

    let err = install(&layout, &spec, false).expect_err("second install without force");
    assert_eq!(err.reason(), &AgentdReason::ServiceAlreadyInstalled);

    let report = install(&layout, &spec, true).expect("forced install");
    assert!(report.overwritten);
}

#[test]
fn install_creates_launchd_log_dir_and_reports_exec_sibling() {
    let root = temp_dir("install-launchd");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Launchd);
    let log_dir = layout.log_dir.clone().expect("log dir");

    let report = install(&layout, &spec, false).expect("install");
    assert!(log_dir.is_dir());
    assert!(!report.exec_bin_present);
    assert_eq!(report.log_dir.as_deref(), Some(log_dir.as_path()));

    fs::create_dir_all(spec.bin.parent().expect("bin parent")).expect("create bin dir");
    fs::write(&spec.bin, b"#!/bin/sh\n").expect("write bin");
    fs::write(spec.exec_bin(), b"#!/bin/sh\n").expect("write exec");
    let report = install(&layout, &spec, true).expect("reinstall");
    assert!(report.bin_present);
    assert!(report.exec_bin_present);
}

#[test]
fn remove_reports_whether_a_definition_existed() {
    let root = temp_dir("remove");
    let layout = layout_in(&root, ServicePlatform::Systemd);

    assert!(!remove(&layout).expect("remove missing"));
    install(&layout, &spec_in(&root), false).expect("install");
    assert!(remove(&layout).expect("remove existing"));
    assert!(!layout.definition_path.exists());
}

#[test]
fn install_rejects_paths_that_cannot_be_represented_in_a_definition() {
    let root = temp_dir("install-newline");
    let layout = layout_in(&root, ServicePlatform::Systemd);
    let spec = ServiceSpec::new(
        ServiceScope::System,
        PathBuf::from("/opt/wist\nbin/wist-agentd"),
        root.join("conf"),
    );

    let err = install(&layout, &spec, false).expect_err("newline path must be rejected");

    assert_eq!(err.reason(), &AgentdReason::ServicePathUnresolved);
    assert!(!layout.definition_path.exists());
}

#[test]
fn install_quotes_paths_with_specials_in_the_rendered_unit() {
    let root = temp_dir("install-quoted");
    let layout = layout_in(&root, ServicePlatform::Systemd);
    let spec = ServiceSpec::new(
        ServiceScope::System,
        PathBuf::from("/opt/my app/wist-agentd"),
        PathBuf::from("/etc/my 100%/wist-agentd"),
    );

    install(&layout, &spec, false).expect("install");

    let written = fs::read_to_string(&layout.definition_path).expect("read definition");
    assert!(written.contains(
        "ExecStart=\"/opt/my app/wist-agentd\" --config-dir \"/etc/my 100%%/wist-agentd\""
    ));
}

#[test]
fn activate_commands_are_idempotent_per_platform() {
    let root = temp_dir("activate");
    let spec = spec_in(&root);

    let systemd = activate_commands(&layout_in(&root, ServicePlatform::Systemd), &spec)
        .expect("systemd activate");
    assert_eq!(
        systemd.iter().map(|c| c.display_line()).collect::<Vec<_>>(),
        vec![
            "systemctl daemon-reload",
            "systemctl enable wist-agentd",
            "systemctl restart wist-agentd",
        ]
    );

    let launchd =
        activate_commands(&layout_in(&root, ServicePlatform::Launchd), &spec).expect("launchd");
    assert_eq!(launchd.len(), 3);
    assert_eq!(launchd[0].program, "launchctl");
    assert_eq!(launchd[0].args[0], "bootout");
    assert!(launchd[0].ignore_failure);
    assert_eq!(
        launchd[1].args,
        vec![
            "bootstrap".to_string(),
            "system".to_string(),
            root.join("com.dayu-sec.wist-agentd.plist")
                .display()
                .to_string()
        ]
    );
    assert_eq!(
        launchd[2].args,
        vec!["enable".to_string(), format!("system/{LAUNCHD_LABEL}")]
    );
}

/// `enable --now` 在**已 active** 的 unit 上等价于 start（no-op），于是
/// `service install --force`（升级二进制 / 改配置）会让旧进程继续跑旧定义。
/// 因此 systemd 分支必须用 `restart`；launchd 分支靠 bootout+bootstrap 天然重建进程。
#[test]
fn systemd_activation_restarts_so_reinstall_takes_effect() {
    let root = temp_dir("activate-restart");
    let spec = spec_in(&root);

    for platform in [ServicePlatform::Systemd, ServicePlatform::Launchd] {
        let commands = activate_commands(&layout_in(&root, platform), &spec).expect("activate");
        let lines = commands
            .iter()
            .map(|c| c.display_line())
            .collect::<Vec<_>>();
        let restarts = lines
            .iter()
            .any(|line| line.contains(" restart ") || line.contains("bootstrap"));
        assert!(restarts, "{platform:?} 的激活命令不会重建进程: {lines:?}");
        assert!(
            !lines.iter().any(|line| line.contains("enable --now")),
            "{platform:?} 用了 enable --now，已 active 的 unit 上不会重启: {lines:?}"
        );
    }
}

/// 拆除是异步的：只有“紧随 bootout / 需要进程重建”的那一步允许重试，
/// 幂等前置步骤不需要。
#[test]
fn only_the_process_restart_step_is_retryable() {
    let root = temp_dir("activate-retry");
    let spec = spec_in(&root);

    let systemd = activate_commands(&layout_in(&root, ServicePlatform::Systemd), &spec)
        .expect("systemd activate");
    assert_eq!(systemd[0].retries, 0, "daemon-reload 不需要重试");
    assert_eq!(systemd[1].retries, 0, "enable 不需要重试");
    assert_eq!(systemd[2].retries, ACTIVATE_RETRIES);

    let launchd =
        activate_commands(&layout_in(&root, ServicePlatform::Launchd), &spec).expect("launchd");
    assert_eq!(launchd[0].retries, 0, "bootout 是 best-effort，不重试");
    assert_eq!(
        launchd[1].retries, ACTIVATE_RETRIES,
        "bootstrap 要吃掉瞬时错误"
    );
    assert_eq!(launchd[2].retries, 0, "enable 不需要重试");

    // 卸载/只读路径不该引入重试。
    for command in deactivate_commands(ServicePlatform::Systemd, &spec)
        .into_iter()
        .chain(deactivate_commands(ServicePlatform::Launchd, &spec))
        .chain(inspect_commands(ServicePlatform::Systemd, &spec))
    {
        assert_eq!(command.retries, 0, "{:?}", command.display_line());
    }
}

#[cfg(unix)]
#[test]
fn run_with_retries_retries_until_success() {
    let root = temp_dir("retry-ok");
    let counter = root.join("attempts");
    let script = write_attempt_counter_script(&root, 2);

    let command = ServiceCommand::new(
        "sh",
        vec![script.display().to_string(), counter.display().to_string()],
        false,
    )
    .retryable(2);
    let outcome = run_with_retries(&command).expect("run");

    assert!(outcome.success, "第 3 次应成功");
    assert_eq!(attempts(&counter), 3);
}

#[cfg(unix)]
#[test]
fn run_with_retries_gives_up_and_reports_the_last_failure() {
    let root = temp_dir("retry-fail");
    let counter = root.join("attempts");
    let script = write_attempt_counter_script(&root, 99);

    let command = ServiceCommand::new(
        "sh",
        vec![script.display().to_string(), counter.display().to_string()],
        false,
    )
    .retryable(2);
    let outcome = run_with_retries(&command).expect("run");

    assert!(!outcome.success, "一直失败就该报失败");
    assert_eq!(attempts(&counter), 3, "重试次数必须有界（1 + retries）");
}

#[cfg(unix)]
#[test]
fn run_with_retries_does_not_retry_a_success() {
    let root = temp_dir("retry-once");
    let counter = root.join("attempts");
    let script = write_attempt_counter_script(&root, 0);

    let command = ServiceCommand::new(
        "sh",
        vec![script.display().to_string(), counter.display().to_string()],
        false,
    )
    .retryable(ACTIVATE_RETRIES);
    let outcome = run_with_retries(&command).expect("run");

    assert!(outcome.success);
    assert_eq!(attempts(&counter), 1, "成功不得重复执行");
}

/// 每次运行都往计数器文件追加一行；成功所需次数由 `succeed_from` 决定。
#[cfg(unix)]
fn write_attempt_counter_script(root: &Path, succeed_from: u32) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;

    let script = root.join("flaky.sh");
    fs::write(
        &script,
        format!(
            "#!/bin/sh\nn=$(cat \"$1\" 2>/dev/null | wc -l | tr -d ' ')\necho x >>\"$1\"\nif [ \"$n\" -lt {succeed_from} ]; then echo 'transient failure' >&2; exit 1; fi\nexit 0\n"
        ),
    )
    .expect("write flaky script");
    fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).expect("chmod flaky script");
    script
}

#[cfg(unix)]
fn attempts(counter: &Path) -> usize {
    fs::read_to_string(counter)
        .expect("read attempts")
        .lines()
        .count()
}

#[test]
fn deactivate_and_inspect_commands_match_scope() {
    let root = temp_dir("deactivate");
    let user_spec = ServiceSpec::new(
        ServiceScope::User,
        root.join("bin/wist-agentd"),
        root.join("conf"),
    );

    let systemd = deactivate_commands(ServicePlatform::Systemd, &user_spec);
    assert_eq!(
        systemd[0].display_line(),
        "systemctl --user disable --now wist-agentd"
    );
    assert!(systemd[0].ignore_failure);

    let inspect = inspect_commands(ServicePlatform::Systemd, &user_spec);
    assert_eq!(
        inspect[0].display_line(),
        "systemctl --user status wist-agentd"
    );
    assert_eq!(
        inspect[1].display_line(),
        "journalctl --user -u wist-agentd -f"
    );

    let launchd = deactivate_commands(ServicePlatform::Launchd, &user_spec);
    assert_eq!(launchd[0].args[0], "bootout");
    assert!(launchd[0].args[1].starts_with("gui/"));
}

#[test]
fn log_hint_points_at_journal_or_log_file() {
    let root = temp_dir("log-hint");
    let spec = spec_in(&root);

    assert_eq!(
        log_hint(&layout_in(&root, ServicePlatform::Systemd), &spec).expect("systemd hint"),
        "journalctl -u wist-agentd -f"
    );
    let launchd = log_hint(&layout_in(&root, ServicePlatform::Launchd), &spec).expect("launchd");
    assert_eq!(
        launchd,
        format!("tail -f {}", root.join("logs/agentd.err").display())
    );
}

#[test]
fn status_reads_config_state_dir_and_detects_running_lock() {
    let root = temp_dir("status");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Systemd);

    let before = status(&layout, &spec).expect("status without config");
    assert!(!before.definition_present);
    assert!(!before.config_present);
    assert!(before.state_dir.is_none());
    assert!(before.root_dir.is_none());
    assert!(before.run_dir.is_none());
    assert!(before.log_dir.is_none());
    assert!(before.running.is_none());

    fs::create_dir_all(&spec.config_dir).expect("create config dir");
    let config = format!(
        "{}[paths]\nroot_dir = \".\"\nstate_dir = \"state\"\n",
        crate::config_runtime::default_config_template()
    );
    fs::write(spec.config_dir.join("agentd.toml"), config).expect("write config");

    let with_config = status(&layout, &spec).expect("status with config");
    assert!(with_config.config_present);
    let state_dir = with_config.state_dir.clone().expect("state dir");
    assert_eq!(state_dir, spec.config_dir.join("state"));
    // 配置不在 /etc 下：数据就地放在配置目录（run/state/log 三项与 root 一致）。
    assert_eq!(
        with_config.root_dir.as_deref(),
        Some(spec.config_dir.as_path())
    );
    assert_eq!(
        with_config.run_dir.as_deref(),
        Some(spec.config_dir.join("run").as_path())
    );
    assert_eq!(
        with_config.log_dir.as_deref(),
        Some(spec.config_dir.join("log").as_path())
    );
    assert_eq!(with_config.running, Some(false));

    let _lock = crate::single_instance::acquire(&state_dir).expect("acquire lock");
    let while_running = status(&layout, &spec).expect("status while running");
    assert_eq!(while_running.running, Some(true));
}

#[test]
fn status_reports_config_load_failure_reason() {
    let root = temp_dir("status-config-error");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Systemd);
    fs::create_dir_all(&spec.config_dir).expect("create config dir");
    // `${...}` 指向未设置的变量：配置存在但载入失败——落点无法给出，原因必须可见。
    fs::write(
        spec.config_dir.join("agentd.toml"),
        "schema_version = \"v1\"\n[agent]\ninstance_name = \"${WIST_TEST_MISSING_VAR}\"\n",
    )
    .expect("write config");

    let status = status(&layout, &spec).expect("status");

    assert!(status.config_present);
    assert!(status.root_dir.is_none());
    assert!(status.running.is_none());
    let reason = status.config_error.expect("config error surfaced");
    assert!(reason.contains("WIST_TEST_MISSING_VAR"), "{reason}");
    // 压成一行，避免 `key=value` 输出被多行错误链打断。
    assert!(!reason.contains('\n'));
}

#[test]
fn command_display_line_quotes_paths_with_spaces() {
    let command = ServiceCommand::new(
        "launchctl",
        vec!["bootstrap".to_string(), "/tmp/a b".to_string()],
        false,
    );
    assert_eq!(command.display_line(), "launchctl bootstrap '/tmp/a b'");
}

#[test]
fn current_platform_is_supported_on_linux_and_macos() {
    if cfg!(any(target_os = "linux", target_os = "macos")) {
        assert!(ServicePlatform::current().is_some());
    }
}
