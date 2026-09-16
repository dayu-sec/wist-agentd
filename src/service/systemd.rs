//! systemd unit 渲染（Linux 常驻托管）。
//!
//! 关键取舍：
//! - `Type=simple` + 前台进程：agentd 不做 double-fork，PID 1 直接跟踪主进程。
//! - `Restart=always`：常驻进程正常/异常退出都拉起；`systemctl stop` 不会触发重启。
//! - `EnvironmentFile=-...`（前导 `-` 表示文件可缺失）：只放长期环境变量；
//!   一次性注册 token 走命令行（`service install --enrollment-token` / `enroll --token`），不落盘。
//! - `KillMode=control-group`（systemd 默认）：stop 时连 `wist-exec` 子进程一起收走，
//!   未完成的执行由下次启动的 crash recovery 重新排队。
//! - `NoNewPrivileges=true`：只禁止提权，不降权；agent 仍需 root 读受限日志路径。

use std::path::PathBuf;

use crate::error::AgentdResult;
use crate::service::{SERVICE_NAME, ServiceScope, ServiceSpec, home_dir};

const SYSTEM_UNIT_DIR: &str = "/etc/systemd/system";
const USER_UNIT_DIR: &str = ".config/systemd/user";
const UNIT_FILE_NAME: &str = "wist-agentd.service";

/// unit 文件落盘路径。
pub fn unit_path(scope: ServiceScope) -> AgentdResult<PathBuf> {
    match scope {
        ServiceScope::System => Ok(PathBuf::from(SYSTEM_UNIT_DIR).join(UNIT_FILE_NAME)),
        ServiceScope::User => Ok(home_dir()?.join(USER_UNIT_DIR).join(UNIT_FILE_NAME)),
    }
}

/// 渲染 unit 文本。
///
/// 所有写进 unit 的路径都经过 [`systemd_arg`] 处理：含空格/引号/`%`/`$` 的路径会被引号包裹并转义，
/// 避免路径里的空白把一条指令拆成两条，或 `%`/`$` 被 systemd 当成 specifier / 变量展开。
pub fn unit_text(spec: &ServiceSpec) -> String {
    let wanted_by = match spec.scope {
        ServiceScope::System => "multi-user.target",
        ServiceScope::User => "default.target",
    };
    let mut text = String::new();
    text.push_str("[Unit]\n");
    text.push_str("Description=wist agent daemon (edge controller)\n");
    text.push_str("Documentation=https://github.com/dayu-sec/wist-agentd\n");
    text.push_str("After=network-online.target\n");
    text.push_str("Wants=network-online.target\n");
    // 单实例锁冲突（前任未退出）会快速失败，这里限流避免重启风暴刷满 journal。
    text.push_str("StartLimitIntervalSec=60\n");
    text.push_str("StartLimitBurst=10\n");
    text.push('\n');
    text.push_str("[Service]\n");
    text.push_str("Type=simple\n");
    text.push_str(&format!(
        "ExecStart={} --config-dir {}\n",
        systemd_arg(&spec.bin.display().to_string()),
        systemd_arg(&spec.config_dir.display().to_string())
    ));
    text.push_str(&format!(
        "EnvironmentFile=-{}\n",
        systemd_arg(&spec.env_file().display().to_string())
    ));
    text.push_str("Restart=always\n");
    text.push_str("RestartSec=5\n");
    text.push_str("KillSignal=SIGTERM\n");
    text.push_str("KillMode=control-group\n");
    text.push_str("TimeoutStopSec=30\n");
    text.push_str(&format!("SyslogIdentifier={SERVICE_NAME}\n"));
    text.push_str("StandardOutput=journal\n");
    text.push_str("StandardError=journal\n");
    text.push_str("LimitNOFILE=65536\n");
    text.push_str("NoNewPrivileges=true\n");
    text.push('\n');
    text.push_str("[Install]\n");
    text.push_str(&format!("WantedBy={wanted_by}\n"));
    text
}

/// 把一个路径写成 systemd 指令参数：普通路径原样输出（可读），需要时加引号并转义。
///
/// systemd 的规则：双引号内 `\\` `\"` 需转义，`%` 是 specifier 前缀（写成 `%%`），
/// `$` 会做变量展开（写成 `$$`）。
pub(super) fn systemd_arg(value: &str) -> String {
    let plain = value.chars().all(|ch| {
        ch.is_ascii_alphanumeric()
            || matches!(ch, '/' | '.' | '-' | '_' | ':' | '@' | '+' | '=' | ',')
    });
    if plain {
        return value.to_string();
    }
    let mut quoted = String::with_capacity(value.len() + 2);
    quoted.push('"');
    for ch in value.chars() {
        match ch {
            '\\' => quoted.push_str("\\\\"),
            '"' => quoted.push_str("\\\""),
            '%' => quoted.push_str("%%"),
            '$' => quoted.push_str("$$"),
            other => quoted.push(other),
        }
    }
    quoted.push('"');
    quoted
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn unit_path_uses_system_dir_for_system_scope() {
        assert_eq!(
            unit_path(ServiceScope::System).expect("unit path"),
            PathBuf::from("/etc/systemd/system/wist-agentd.service")
        );
    }

    #[test]
    fn systemd_arg_leaves_ordinary_paths_untouched() {
        assert_eq!(
            systemd_arg("/usr/local/bin/wist-agentd"),
            "/usr/local/bin/wist-agentd"
        );
        assert_eq!(systemd_arg("/etc/wist-agentd"), "/etc/wist-agentd");
    }

    #[test]
    fn systemd_arg_quotes_and_escapes_special_characters() {
        assert_eq!(systemd_arg("/opt/my app/bin"), "\"/opt/my app/bin\"");
        assert_eq!(systemd_arg("/a%i/bin"), "\"/a%%i/bin\"");
        assert_eq!(systemd_arg("/a$HOME/bin"), "\"/a$$HOME/bin\"");
        assert_eq!(systemd_arg("/a\"b"), "\"/a\\\"b\"");
        assert_eq!(systemd_arg("/a\\b"), "\"/a\\\\b\"");
    }
}
