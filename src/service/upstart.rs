//! Upstart job 渲染（RHEL / CentOS 6 等「有 upstart、没有 systemd」的 Linux）。
//!
//! 关键取舍：
//! - 定义文件落在 `/etc/init/<job>.conf`：upstart 只在**启动**和
//!   `initctl reload-configuration` 时读取，新写的 job 不 reload 就是 `Unknown job`
//!   （现场实测：`initctl start` 不会自己重读目录）。
//! - `respawn` + `respawn limit unlimited`：与 systemd 的 `Restart=always` +
//!   `StartLimitIntervalSec=0` 同义 —— 崩溃/退出后**无限重拉**，不因“重启风暴”永久放弃
//!   （外部故障：磁盘满 / 网络未就绪，解除后必须能自己回来）。
//! - `post-stop exec sleep 5`：upstart 没有指数退避，用固定 5s 间隔压住重启风暴。
//!   代价是 `stop` 也要等这 5s（`service uninstall` / `--force` 重装会慢 5 秒）；
//!   换来的是 `initctl stop` 返回后紧跟的 `initctl start` 不会撞上 post-stop 的窗口。
//! - `script` + `exec`：agentd 不做 double-fork，`exec` 让 job 的主进程就是 agentd 本身，
//!   upstart 的 PID 与信号跟踪才准；stdout/stderr 显式落 `<log_dir>/{agentd.out,agentd.err}`
//!   （upstart 0.6.5 没有 launchd `StandardErrorPath` 的等价物，也不再往 `/dev/console` 刷）。
//! - **不渲染 `kill signal` / `kill timeout`**：RHEL 6 自带的 upstart 0.6.5 不认这两个
//!   stanza，整份 job 会被丢弃（现场日志：`/etc/init/wist-agentd.conf:11: Unknown stanza`
//!   → `initctl: Unknown job`）。用 upstart 默认（SIGTERM，超时后 SIGKILL）。
//! - `agentd.env` 等价物：在 `script` 里**按 `KEY=VALUE` 解析**（不执行文件内容），
//!   与 systemd 的 `EnvironmentFile=-...` 同为数据语义；文件缺失时不报错。

use std::path::{Path, PathBuf};

use crate::config_runtime::SYSTEM_LOG_DIR;
use crate::error::AgentdResult;
use crate::service::{SERVICE_NAME, ServiceSpec, shell_quote};

const SYSTEM_INIT_DIR: &str = "/etc/init";

/// 标准输出落盘文件名（与 launchd 同名，运维习惯一致）。
pub const STDOUT_FILE: &str = "agentd.out";
/// 标准错误落盘文件名（agentd 的运维输出都走 stderr）。
pub const STDERR_FILE: &str = "agentd.err";

/// job 定义落盘路径（系统级）。
///
/// 文件名由 [`SERVICE_NAME`] 推导，而不是再写一份常量：`initctl status <job>`、
/// `respawn` 里的实例名、定义文件名必须是同一个字符串，否则改名时会出现
/// 「装了但 `initctl` 不认识」的半成品。
pub fn job_path() -> AgentdResult<PathBuf> {
    Ok(PathBuf::from(SYSTEM_INIT_DIR).join(format!("{SERVICE_NAME}.conf")))
}

/// 标准输出/错误目录：跟随 agent 日志目录（`/var/log/wist-agentd`）。
pub fn log_dir() -> AgentdResult<PathBuf> {
    Ok(PathBuf::from(SYSTEM_LOG_DIR))
}

/// 标准错误文件路径（默认日志目录下；`inspect` / 日志提示在拿不到 layout 时的回退）。
pub fn stderr_path() -> PathBuf {
    PathBuf::from(SYSTEM_LOG_DIR).join(STDERR_FILE)
}

/// 渲染 job 文本。`log_dir_override` 为 `None` 时回退到默认日志目录。
///
/// 所有写进 `script` 的路径都经 [`shell_quote`] 处理：它们会被 `sh` 当命令/重定向目标解析，
/// 含空白或 `;` 的路径不转义就会把一条命令拆成两条。
pub fn job_text(spec: &ServiceSpec, log_dir_override: Option<&Path>) -> String {
    let log_dir = match log_dir_override {
        Some(dir) => dir.to_path_buf(),
        None => log_dir().unwrap_or_else(|_| PathBuf::from("/tmp")),
    };
    let stdout = log_dir.join(STDOUT_FILE);
    let stderr = log_dir.join(STDERR_FILE);
    let env = shell_quote(&spec.env_file().display().to_string());

    let mut text = String::new();
    text.push_str(
        "# wist-agentd — Upstart job（RHEL / CentOS 6 等「有 upstart、没有 systemd」的 Linux）。\n\
         # 由 `wist-agentd service install` 生成；手改后执行 `initctl reload-configuration`。\n",
    );
    text.push_str("description \"wist agent daemon (edge controller)\"\n");
    text.push_str("author \"dayu-sec\"\n");
    text.push('\n');
    // 与其它服务管理器一致：跟着多用户运行级起停，不自建 target。
    text.push_str("start on runlevel [2345]\n");
    text.push_str("stop on runlevel [!2345]\n");
    text.push('\n');
    text.push_str(
        "# 崩溃/退出即重拉，且不因反复失败永久放弃（= systemd Restart=always +\n\
         # StartLimitIntervalSec=0）。upstart 没有指数退避，固定 5s 间隔压住重启风暴。\n\
         respawn\n\
         respawn limit unlimited\n\
         post-stop exec sleep 5\n",
    );
    text.push('\n');
    text.push_str("# stdout/stderr 在下面显式重定向，不再往 /dev/console 刷。\n");
    text.push_str("console none\n");
    text.push('\n');
    text.push_str("script\n");
    text.push_str(&ENV_LOADER.replace("{env}", &env));
    text.push_str(&format!(
        "  exec {} --config-dir {} >> {} 2>> {}\n",
        shell_quote(&spec.bin.display().to_string()),
        shell_quote(&spec.config_dir.display().to_string()),
        shell_quote(&stdout.display().to_string()),
        shell_quote(&stderr.display().to_string())
    ));
    text.push_str("end script\n");
    text
}

/// `agentd.env` 的 upstart 等价物：**只按 `KEY=VALUE` 读取并导出，不执行文件内容**。
///
/// 为什么不用 `. agentd.env`：那是 shell 语义，文件里一行 `FOO=$(curl … | sh)` 就会在 root 下
/// 执行；而 systemd 的 `EnvironmentFile` 是**数据**语义（只解析键值）。同一条契约不能在两个
/// 平台上语义不同，所以这里自己解析：空行 / `#` 注释 / 没有 `=` 的行跳过，
/// 值外层的一对引号去掉（与 systemd 的简单情形一致）。
///
/// 不支持 systemd 的进阶语法（多行续行、`\` 转义）：这类配置改写到 `agentd.toml` 或
/// 由 CM 直接注入环境变量。
const ENV_LOADER: &str = r#"  if [ -f {env} ]; then
    while IFS= read -r line || [ -n "$line" ]; do
      case "$line" in ''|'#'*) continue ;; ?*=*) ;; *) continue ;; esac
      key=${line%%=*}; value=${line#*=}
      case "$value" in
        \"*\") value=${value#\"}; value=${value%\"} ;;
        \'*\') value=${value#\'}; value=${value%\'} ;;
      esac
      export "$key=$value"
    done < {env}
  fi
"#;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn job_path_uses_etc_init() {
        assert_eq!(
            job_path().expect("job path"),
            PathBuf::from("/etc/init/wist-agentd.conf")
        );
    }

    #[test]
    fn stderr_path_follows_the_agent_log_dir() {
        assert_eq!(
            stderr_path(),
            PathBuf::from("/var/log/wist-agentd/agentd.err")
        );
    }
}
