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
        root.join("bin").join("wist-agentd"),
        root.join("etc").join("wist-agentd"),
    )
}

fn layout_in(root: &Path, platform: ServicePlatform) -> ServiceLayout {
    let definition_path = match platform {
        ServicePlatform::Systemd => root.join("wist-agentd.service"),
        ServicePlatform::Upstart => root.join("wist-agentd.conf"),
        ServicePlatform::Launchd => root.join("com.dayu-sec.wist-agentd.plist"),
    };
    let log_dir = match platform {
        ServicePlatform::Systemd => None,
        ServicePlatform::Upstart | ServicePlatform::Launchd => Some(root.join("logs")),
    };
    ServiceLayout::for_paths(platform, definition_path, log_dir)
}

#[test]
fn system_paths_follow_platform_conventions() {
    assert_eq!(default_config_dir(), PathBuf::from("/etc/wist-agentd"));
    assert_eq!(
        ServiceLayout::resolve(ServicePlatform::Systemd)
            .expect("systemd system layout")
            .definition_path,
        PathBuf::from("/etc/systemd/system/wist-agentd.service")
    );
    assert_eq!(
        ServiceLayout::resolve(ServicePlatform::Upstart)
            .expect("upstart system layout")
            .definition_path,
        PathBuf::from("/etc/init/wist-agentd.conf")
    );
    assert_eq!(
        ServiceLayout::resolve(ServicePlatform::Launchd)
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

/// 把渲染出的 unit 按 `[section]` 切分，返回该节的有效指令行（跳过注释与空行）。
///
/// 为什么不用全文 `contains`：systemd 对「放错节的键」只报一条 `Unknown key` 警告然后忽略，
/// 于是「配了但没生效」——例如把 `StartLimitIntervalSec` 写进 `[Service]`，全文包含断言照样绿。
fn section_lines<'a>(text: &'a str, section: &str) -> Vec<&'a str> {
    let mut current = String::new();
    let mut lines = Vec::new();
    for line in text.lines() {
        let trimmed = line.trim();
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.strip_suffix(']'))
        {
            current = name.to_string();
            continue;
        }
        if current == section && !trimmed.is_empty() && !trimmed.starts_with('#') {
            lines.push(trimmed);
        }
    }
    lines
}

/// 回归：`StartLimitBurst` + `Restart=always` 会在外部故障（磁盘满 / 网络未就绪）反复失败后
/// 把 unit 永久标成 `failed`，故障解除也不会自己回来。应改为关闭 start limit + 指数退避。
#[test]
fn systemd_unit_backs_off_instead_of_giving_up() {
    let root = temp_dir("unit-backoff");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Systemd);

    let text = render(&layout, &spec);

    // `StartLimit*` 只在 `[Unit]` 生效（写进 `[Service]` 会被 systemd 当未知键忽略）——按节断言。
    let unit = section_lines(&text, "Unit");
    assert!(
        unit.contains(&"StartLimitIntervalSec=0"),
        "[Unit] 缺少 StartLimitIntervalSec=0：\n{text}"
    );
    assert_eq!(
        unit.iter()
            .filter(|line| line.starts_with("StartLimit"))
            .count(),
        1,
        "只能有一条 start limit 设置：\n{text}"
    );
    assert!(
        !text.contains("StartLimitBurst"),
        "任何 start limit 都意味着「失败 N 次即放弃拉起」"
    );

    // 退避三项必须在 `[Service]`。
    let service = section_lines(&text, "Service");
    for expected in [
        "Restart=always",
        "RestartSec=5",
        "RestartSteps=5",
        "RestartMaxDelaySec=60",
    ] {
        assert!(
            service.contains(&expected),
            "[Service] 缺少 {expected}：\n{text}"
        );
    }
    assert!(
        !service.iter().any(|line| line.starts_with("StartLimit")),
        "StartLimit* 写在 [Service] 里不会生效：\n{text}"
    );
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
fn upstart_job_respawns_without_giving_up_and_logs_to_files() {
    let root = temp_dir("upstart-job");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Upstart);
    let log_dir = layout.log_dir.clone().expect("log dir");

    let text = render(&layout, &spec);

    assert!(text.contains("start on runlevel [2345]"));
    assert!(text.contains("stop on runlevel [!2345]"));
    // 崩溃即重拉，且**不因为反复失败而永久放弃**（对齐 systemd 的 StartLimitIntervalSec=0）。
    assert!(text.contains("respawn\n"));
    assert!(text.contains("respawn limit unlimited"));
    // upstart 没有指数退避：固定 5s 间隔压住重启风暴。
    assert!(text.contains("post-stop exec sleep 5"));
    // `exec` 让 job 主进程就是 agentd，stdout/stderr 显式落盘（不再刷 /dev/console）。
    assert!(text.contains("console none"));
    assert!(text.contains(&format!(
        "exec {} --config-dir {} >> {} 2>> {}",
        spec.bin.display(),
        spec.config_dir.display(),
        log_dir.join("agentd.out").display(),
        log_dir.join("agentd.err").display()
    )));
    // `agentd.env` 等价物：只按 KEY=VALUE 读（**不** `.` 执行），文件可缺失。
    assert!(
        text.contains(&format!("if [ -f {} ]; then", spec.env_file().display())),
        "{text}"
    );
    assert!(text.contains("while IFS= read -r line"));
    assert!(!text.contains("then . "), "{text}");
    // RHEL 6 的 upstart 0.6.5 不认这两个 stanza（会丢掉整份 job）：不能渲染。
    assert!(!text.contains("kill signal"));
    assert!(!text.contains("kill timeout"));
}

#[test]
fn upstart_job_path_derives_from_the_service_name() {
    // 定义文件名与 `initctl <verb> <job>` 里的 job 名必须是同一个字符串：
    // 写成两份常量时，改名会出现「装了但 initctl 不认识」的半成品。
    let path = ServiceLayout::resolve(ServicePlatform::Upstart)
        .expect("upstart layout")
        .definition_path;
    assert_eq!(
        path.file_name().and_then(|name| name.to_str()),
        Some(&*format!("{SERVICE_NAME}.conf"))
    );
}

#[test]
fn install_creates_upstart_log_dir_and_reports_exec_sibling() {
    let root = temp_dir("install-upstart");
    let spec = spec_in(&root);
    let layout = layout_in(&root, ServicePlatform::Upstart);
    let log_dir = layout.log_dir.clone().expect("log dir");

    // upstart 的 stdout/stderr 重定向目标必须在**拉起 job 之前**就存在，
    // 否则 `>>` 直接失败、job 起不来。这与 launchd 的 plist 日志目录是同一个要求。
    let report = install(&layout, &spec, false).expect("install");
    assert!(log_dir.is_dir());
    assert_eq!(report.log_dir.as_deref(), Some(log_dir.as_path()));
    assert_eq!(report.platform, ServicePlatform::Upstart);
    assert!(!report.exec_bin_present);

    fs::create_dir_all(spec.bin.parent().expect("bin parent")).expect("create bin dir");
    fs::write(&spec.bin, b"#!/bin/sh\n").expect("write bin");
    fs::write(spec.exec_bin(), b"#!/bin/sh\n").expect("write exec");
    let report = install(&layout, &spec, true).expect("reinstall");
    assert!(report.bin_present);
    assert!(report.exec_bin_present);
}

#[test]
fn install_rejects_newline_paths_for_upstart_too() {
    // 换行会往 `script` 里插一整条新命令（root 身份执行）——落盘前必须拒绝。
    let root = temp_dir("install-newline-upstart");
    let layout = layout_in(&root, ServicePlatform::Upstart);
    let spec = ServiceSpec::new(PathBuf::from("/opt/wist\n/tmp/evil.sh"), root.join("conf"));

    let err = install(&layout, &spec, false).expect_err("newline path must be rejected");

    assert_eq!(err.reason(), &AgentdReason::ServicePathUnresolved);
    assert!(!layout.definition_path.exists());
}

/// 把渲染出的 `script ... end script` 块取出来（job 文件里唯一可执行的片段）。
#[cfg(unix)]
fn upstart_script_block(text: &str) -> String {
    let start = text.find("script\n").expect("script stanza");
    let body = &text[start + "script\n".len()..];
    let end = body.find("\nend script").expect("end script");
    body[..end].to_string()
}

/// 行为测试：`agentd.env` 是**数据**语义，不是 shell。
///
/// 用真 `sh` 跑渲染出来的 script 块，把一个“只会打环境变量”的假 agentd 当 exec 目标：
/// 1. `KEY=VALUE` 与去引号生效；
/// 2. 值里的 `$(...)` **不会**被执行（与 systemd `EnvironmentFile` 同语义）；
/// 3. 路径带空白也能被正确引用（否则 `exec` 会被拆成两条命令）。
#[cfg(unix)]
#[test]
fn upstart_script_loads_env_file_as_data_not_code() {
    use std::os::unix::fs::PermissionsExt;
    use std::process::Command;

    let root = temp_dir("upstart-env");
    let layout = layout_in(&root, ServicePlatform::Upstart);
    let log_dir = layout.log_dir.clone().expect("log dir");
    fs::create_dir_all(&log_dir).expect("create log dir");

    // 路径里带空白：同时验证 shell_quote。
    let spec = ServiceSpec::new(
        root.join("bin dir").join("wist-agentd"),
        root.join("etc dir").join("wist-agentd"),
    );
    fs::create_dir_all(spec.bin.parent().expect("bin parent")).expect("create bin dir");
    fs::create_dir_all(&spec.config_dir).expect("create config dir");
    fs::write(
        &spec.bin,
        "#!/bin/sh\nprintf '%s' \"$WIST_TEST_VAR|$WIST_TEST_EVIL\"\n",
    )
    .expect("write fake bin");
    fs::set_permissions(&spec.bin, fs::Permissions::from_mode(0o755)).expect("chmod fake bin");

    let marker = root.join("pwned");
    fs::write(
        spec.env_file(),
        format!(
            // `=novalue`（空键）必须被跳过：`export "=novalue"` 在 `sh -e` 下会中止整个 job。
            "# 注释行\n\nWIST_TEST_VAR=\"quoted value\"\nWIST_TEST_EVIL=$(touch {})\nno_equals_line\n=novalue\n",
            marker.display()
        ),
    )
    .expect("write env file");

    let rendered = render(&layout, &spec);
    assert!(
        !rendered.contains("then . "),
        "agentd.env 不得被 `.` 执行（shell 语义）:\n{rendered}"
    );

    let output = Command::new("sh")
        .arg("-c")
        .arg(upstart_script_block(&rendered))
        .output()
        .expect("run rendered script block");
    assert!(
        output.status.success(),
        "script 块执行失败：{}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );

    // exec 把假 agentd 的 stdout 重定向进了 <log_dir>/agentd.out。
    let written = fs::read_to_string(log_dir.join("agentd.out")).expect("read agentd.out");
    assert_eq!(
        written,
        format!("quoted value|$(touch {})", marker.display()),
        "env 文件应被当成数据读取（去一层引号、不执行命令）"
    );
    assert!(
        !marker.exists(),
        "agentd.env 里的命令被执行了: {}",
        marker.display()
    );
}

#[test]
fn program_in_paths_looks_only_at_the_given_path_variable() {
    let root = temp_dir("path-lookup");
    let bin_dir = root.join("sbin");
    fs::create_dir_all(&bin_dir).expect("create bin dir");
    fs::write(bin_dir.join("initctl"), b"#!/bin/sh\n").expect("write initctl");
    let path_var = std::ffi::OsString::from(bin_dir.display().to_string());

    assert!(program_in_paths(Some(path_var.as_os_str()), "initctl"));
    assert!(!program_in_paths(Some(path_var.as_os_str()), "systemctl"));
    assert!(!program_in_paths(None, "initctl"));
}

/// 平台判据是"systemd 在不在跑"，不是"装没装 systemctl"。
///
/// 这条直接决定升级走到哪：判成 systemd 就会用 `systemctl restart` 重启 agentd，
/// 在 PID 1 是 upstart 的 CentOS 6 / RHEL 6 上必失败（升级回滚），而 `initctl` 一次都没试。
#[test]
fn systemd_running_only_looks_at_the_runtime_marker() {
    let root = temp_dir("systemd-marker");
    let marker = root.join("systemd").join("system");
    assert!(!systemd_running_at(&marker), "没建目录就是不在跑");
    fs::create_dir_all(&marker).expect("create marker");
    assert!(systemd_running_at(&marker));
    let _ = fs::remove_dir_all(root);
}

/// 平台选择的四种组合（回归：曾在「装了 systemctl 但 PID 1 是 upstart」的
/// CentOS 6 / RHEL 6 上判成 systemd，于是升级最后一步跑 `systemctl restart`
/// 必失败、整次升级回滚，而真正在管它的 `initctl` 一次都没试）。
#[test]
fn platform_needs_a_running_systemd_not_an_installed_systemctl() {
    use ServicePlatform::{Systemd, Upstart};

    // systemd 真在跑：不管 upstart 组件在不在，都是 systemd 在管。
    assert_eq!(linux_platform_from(true, true), Systemd);
    assert_eq!(linux_platform_from(true, false), Systemd);

    // systemd 没在跑（PID 1 是 upstart，哪怕装了 systemctl 组件）：必须是 upstart。
    assert_eq!(linux_platform_from(false, true), Upstart);

    // 两者都没有（精简容器）：仍写 systemd unit，交给运维 / CM（`--no-activate`）。
    assert_eq!(linux_platform_from(false, false), Systemd);
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
        PathBuf::from("/opt/my app/wist-agentd"),
        PathBuf::from("/etc/my 100%/wist-agentd"),
    );

    install(&layout, &spec, false).expect("install");

    let written = fs::read_to_string(&layout.definition_path).expect("read definition");
    assert!(written.contains(
        "ExecStart=\"/opt/my app/wist-agentd\" --config-dir \"/etc/my 100%%/wist-agentd\""
    ));
}

/// upstart 的 `script` 块会交给 `sh` 执行：路径里的空白/分号不转义就会把一条命令拆成两条。
#[test]
fn upstart_job_shell_quotes_paths_with_specials() {
    let root = temp_dir("upstart-quoted");
    let layout = layout_in(&root, ServicePlatform::Upstart);
    let spec = ServiceSpec::new(
        PathBuf::from("/opt/my app/wist-agentd"),
        PathBuf::from("/etc/my;rm -rf /wist-agentd"),
    );

    install(&layout, &spec, false).expect("install");

    let written = fs::read_to_string(&layout.definition_path).expect("read definition");
    assert!(
        written.contains(
            "exec '/opt/my app/wist-agentd' --config-dir '/etc/my;rm -rf /wist-agentd' >>"
        ),
        "{written}"
    );
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

    let upstart = activate_commands(&layout_in(&root, ServicePlatform::Upstart), &spec)
        .expect("upstart activate");
    assert_eq!(
        upstart.iter().map(|c| c.display_line()).collect::<Vec<_>>(),
        vec![
            "initctl reload-configuration",
            "initctl stop wist-agentd",
            "initctl start wist-agentd",
        ]
    );
    assert!(
        upstart[1].ignore_failure,
        "没跑过时 initctl stop 返回非零，必须忽略"
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
/// 因此 systemd 分支必须用 `restart`；upstart 用 stop + start（只 start 在已跑时是 no-op）；
/// launchd 分支靠 bootout+bootstrap 天然重建进程。
#[test]
fn activation_restarts_so_reinstall_takes_effect() {
    let root = temp_dir("activate-restart");
    let spec = spec_in(&root);

    for platform in [
        ServicePlatform::Systemd,
        ServicePlatform::Upstart,
        ServicePlatform::Launchd,
    ] {
        let lines = activate_commands(&layout_in(&root, platform), &spec)
            .expect("activate")
            .iter()
            .map(|c| c.display_line())
            .collect::<Vec<_>>();
        let restarts = lines
            .iter()
            .any(|line| line.contains(" restart ") || line.contains("bootstrap"))
            || (lines.iter().any(|line| line == "initctl stop wist-agentd")
                && lines.iter().any(|line| line == "initctl start wist-agentd"));
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

    let upstart = activate_commands(&layout_in(&root, ServicePlatform::Upstart), &spec)
        .expect("upstart activate");
    assert_eq!(upstart[0].retries, 0, "reload-configuration 不需要重试");
    assert_eq!(upstart[1].retries, 0, "stop 是 best-effort，不重试");
    assert_eq!(
        upstart[2].retries, ACTIVATE_RETRIES,
        "start 要吃掉 post-stop 窗口后的瞬时错误"
    );

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
        .chain(deactivate_commands(ServicePlatform::Upstart, &spec))
        .chain(deactivate_commands(ServicePlatform::Launchd, &spec))
        .chain(inspect_commands(
            &layout_in(&root, ServicePlatform::Systemd),
            &spec,
        ))
        .chain(inspect_commands(
            &layout_in(&root, ServicePlatform::Upstart),
            &spec,
        ))
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
fn deactivate_and_inspect_commands_target_the_system_domain() {
    let root = temp_dir("deactivate");
    let spec = spec_in(&root);

    let systemd = deactivate_commands(ServicePlatform::Systemd, &spec);
    assert_eq!(
        systemd[0].display_line(),
        "systemctl disable --now wist-agentd"
    );
    assert!(systemd[0].ignore_failure);

    let inspect = inspect_commands(&layout_in(&root, ServicePlatform::Systemd), &spec);
    assert_eq!(inspect[0].display_line(), "systemctl status wist-agentd");
    assert_eq!(inspect[1].display_line(), "journalctl -u wist-agentd -f");

    let upstart = deactivate_commands(ServicePlatform::Upstart, &spec);
    assert_eq!(upstart[0].display_line(), "initctl stop wist-agentd");
    assert!(upstart[0].ignore_failure);

    // 检查命令里的日志路径必须跟着 layout 走（与 `log_hint` 同一事实来源）。
    let inspect = inspect_commands(&layout_in(&root, ServicePlatform::Upstart), &spec);
    assert_eq!(inspect[0].display_line(), "initctl status wist-agentd");
    assert_eq!(
        inspect[1].display_line(),
        format!("tail -f {}", root.join("logs/agentd.err").display())
    );

    let launchd = deactivate_commands(ServicePlatform::Launchd, &spec);
    assert_eq!(launchd[0].args[0], "bootout");
    assert_eq!(launchd[0].args[1], format!("system/{LAUNCHD_LABEL}"));
}

#[test]
fn log_hint_points_at_journal_or_log_file() {
    let root = temp_dir("log-hint");

    assert_eq!(
        log_hint(&layout_in(&root, ServicePlatform::Systemd)).expect("systemd hint"),
        "journalctl -u wist-agentd -f"
    );
    let launchd = log_hint(&layout_in(&root, ServicePlatform::Launchd)).expect("launchd");
    assert_eq!(
        launchd,
        format!("tail -f {}", root.join("logs/agentd.err").display())
    );

    let upstart = log_hint(&layout_in(&root, ServicePlatform::Upstart)).expect("upstart");
    assert_eq!(
        upstart,
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
