//! launchd plist 渲染（macOS 常驻托管）。
//!
//! 关键取舍：
//! - `RunAtLoad` + `KeepAlive`：加载即启动，退出（正常或崩溃）都拉起；`launchctl bootout`
//!   才是真正的停止手段。
//! - `ThrottleInterval=10`：launchd 的最小重启间隔，避免启动即失败时形成重启风暴。
//! - 标准输出/错误：系统级落 `/var/log/wist-agentd/`（与 agent 日志目录一致），
//!   用户级落 `~/Library/Logs/wist-agentd/`（用户写不了 `/var/log`），
//!   需要配合 newsyslog / logrotate 轮转（见 `docs/agentd-install-and-usage.md`）。
//! - `WorkingDirectory` 落在稳定目录，`--config-dir` 始终用绝对路径。
//! - LaunchDaemon 的环境变量极简，故显式补 `PATH`。macOS 侧**不做** `EnvironmentFile` 等价物：
//!   一次性 enrollment token 走命令行（`service install --enrollment-token` / `enroll --token`），不落盘；
//!   Linux 侧若需要长期环境变量，用 systemd 的 `EnvironmentFile=-<config>/agentd.env`。

use std::path::{Path, PathBuf};

use crate::config_runtime::SYSTEM_LOG_DIR;
use crate::error::AgentdResult;
use crate::service::{LAUNCHD_LABEL, ServiceScope, ServiceSpec, home_dir};

const SYSTEM_PLIST_DIR: &str = "/Library/LaunchDaemons";
const USER_PLIST_DIR: &str = "Library/LaunchAgents";
const PLIST_FILE_NAME: &str = "com.dayu-sec.wist-agentd.plist";
const USER_LOG_DIR: &str = "Library/Logs/wist-agentd";

/// 标准输出落盘文件名。
pub const STDOUT_FILE: &str = "agentd.out";
/// 标准错误落盘文件名（agentd 的运维输出都走 stderr）。
pub const STDERR_FILE: &str = "agentd.err";

/// plist 落盘路径。
pub fn plist_path(scope: ServiceScope) -> AgentdResult<PathBuf> {
    match scope {
        ServiceScope::System => Ok(PathBuf::from(SYSTEM_PLIST_DIR).join(PLIST_FILE_NAME)),
        ServiceScope::User => Ok(home_dir()?.join(USER_PLIST_DIR).join(PLIST_FILE_NAME)),
    }
}

/// launchd 标准输出/错误目录：系统级跟随 agent 日志目录（`/var/log/wist-agentd`），
/// 用户级放 `~/Library/Logs/wist-agentd`（用户写不了 `/var/log`）。
pub fn log_dir(scope: ServiceScope) -> AgentdResult<PathBuf> {
    match scope {
        ServiceScope::System => Ok(PathBuf::from(SYSTEM_LOG_DIR)),
        ServiceScope::User => Ok(home_dir()?.join(USER_LOG_DIR)),
    }
}

/// 渲染 plist 文本。`log_dir_override` 为 `None` 时回退到作用域默认日志目录。
pub fn plist_text(spec: &ServiceSpec, log_dir_override: Option<&Path>) -> String {
    let working_dir = match spec.scope {
        ServiceScope::System => PathBuf::from("/"),
        ServiceScope::User => home_dir().unwrap_or_else(|_| PathBuf::from("/")),
    };
    // 目录不存在时 launchd 无法启动作业；渲染阶段取不到 HOME 就退化为 `/tmp`。
    let log_dir = match log_dir_override {
        Some(dir) => dir.to_path_buf(),
        None => log_dir(spec.scope).unwrap_or_else(|_| PathBuf::from("/tmp")),
    };

    let mut text = String::new();
    text.push_str("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n");
    text.push_str("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n");
    text.push_str("<plist version=\"1.0\">\n<dict>\n");
    text.push_str(&kv_string("Label", LAUNCHD_LABEL));
    text.push_str("  <key>ProgramArguments</key>\n  <array>\n");
    text.push_str(&format!(
        "    <string>{}</string>\n",
        escape_xml(&spec.bin.display().to_string())
    ));
    text.push_str("    <string>--config-dir</string>\n");
    text.push_str(&format!(
        "    <string>{}</string>\n",
        escape_xml(&spec.config_dir.display().to_string())
    ));
    text.push_str("  </array>\n");
    text.push_str("  <key>RunAtLoad</key>\n  <true/>\n");
    text.push_str("  <key>KeepAlive</key>\n  <true/>\n");
    text.push_str("  <key>ThrottleInterval</key>\n  <integer>10</integer>\n");
    text.push_str("  <key>ExitTimeOut</key>\n  <integer>30</integer>\n");
    text.push_str("  <key>ProcessType</key>\n  <string>Background</string>\n");
    text.push_str(&kv_string(
        "WorkingDirectory",
        &working_dir.display().to_string(),
    ));
    text.push_str(&kv_string(
        "StandardOutPath",
        &log_dir.join(STDOUT_FILE).display().to_string(),
    ));
    text.push_str(&kv_string(
        "StandardErrorPath",
        &log_dir.join(STDERR_FILE).display().to_string(),
    ));
    text.push_str("  <key>EnvironmentVariables</key>\n  <dict>\n");
    text.push_str("    <key>PATH</key>\n");
    text.push_str("    <string>/usr/local/bin:/usr/bin:/bin:/usr/sbin:/sbin</string>\n");
    text.push_str("  </dict>\n");
    text.push_str("</dict>\n</plist>\n");
    text
}

fn kv_string(key: &str, value: &str) -> String {
    format!(
        "  <key>{}</key>\n  <string>{}</string>\n",
        escape_xml(key),
        escape_xml(value)
    )
}

fn escape_xml(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&apos;"),
            other => out.push(other),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn plist_escapes_xml_special_characters() {
        assert_eq!(escape_xml("a&b<c\"d"), "a&amp;b&lt;c&quot;d");
    }

    #[test]
    fn plist_path_uses_launch_daemons_for_system_scope() {
        assert_eq!(
            plist_path(ServiceScope::System).expect("plist path"),
            PathBuf::from("/Library/LaunchDaemons/com.dayu-sec.wist-agentd.plist")
        );
    }
}
