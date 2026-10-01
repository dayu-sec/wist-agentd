//! 凭据**终态**的落盘：`state/auth_terminal.json`。
//!
//! 为什么需要它：终态（`TERMINAL_AUTH_CODES`）只按「网关明确拒了」判定，判定之后 agentd
//! **停掉常规上报**（状态 / 工作 / 上送 / 续期都不再发）—— 而那个标志原先只在内存里
//! （进程故意不退出，避免 launchd/systemd 的 KeepAlive 把它变成重启风暴）。于是形成两个盲区：
//!
//!   1. **不自愈**：网关侧后来恢复了（补上拒绝名单、换回库…），这台机器不知道，静默到底；
//!   2. **外部不可见**：`diagnose` 是新进程、没有这个标志，于是它一路报 OK，页面上只剩「离线」。
//!
//! 落盘把「我什么时候因为哪个 code 进了终态、重试了多少次」变成**跨重启保留**且
//! **能被外部读到**的事实；自愈则由守护进程的低频重试负责 —— 那正是本模块之外的常规上报
//! 之外**唯一**还会发出去的控制面请求（成功即 `clear_async`）。
//!
//! 与 `fact_report` 同一取舍：**故意放在 `state_dir` 根下**，不放 `reporting/` —— 那里的内容
//! 会被健康计数当成「待送报告积压」逐个数。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_async::read_json_async;

/// 认出来的路径：状态上报（`run_forever_async` 的常规上报）。
pub const SOURCE_STATUS_REPORT: &str = "status_report";
/// 认出来的路径：续期（`renew_credential_if_due` 判出被吊销）。
pub const SOURCE_RENEWAL: &str = "renewal";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthTerminal {
    /// 网关给的稳定 code（见 `control::enrollment::TERMINAL_AUTH_CODES`）。
    pub code: String,
    /// 哪条路径认出来的（[`SOURCE_STATUS_REPORT`] / [`SOURCE_RENEWAL`]）。
    pub source: String,
    /// 进入终态的时刻（RFC3339）。**跨重启保留** —— 重启后 `diagnose` 与
    /// `event=AuthTerminalRestored` 靠它说清「从什么时候起」。
    ///
    /// 换终态 code 时**跟着改**（见 `daemon::retry_terminal_probe`）：它说的是「**这个** code
    /// 从哪时起」。重试的节奏由内存里的 `Instant` 控制，不读这个字段。
    pub detected_at: String,
    /// 低频重试的次数（每次尝试前 +1）。为什么值得落盘：`diagnose` 要能回答
    /// 「它到底在试、还是根本没在试」——只看 `since` 分不出这两种。
    #[serde(default)]
    pub attempts: i64,
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("auth_terminal.json")
}

/// 读取终态台账；文件不存在（几乎总是：没有进过终态）返回 `None`。
pub async fn load_async(path: &Path) -> io::Result<Option<AuthTerminal>> {
    match read_json_async(path).await {
        Ok(state) => Ok(Some(state)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn store_async(path: &Path, state: &AuthTerminal) -> io::Result<()> {
    crate::fs_async::write_json_atomic_async(path, state).await
}

/// 清除台账（自愈成功时）。**文件已经不在也算成功** —— 调用方要的是「清干净了」，
/// 不是「我删掉了一个确实存在的文件」。
pub async fn clear_async(path: &Path) -> io::Result<()> {
    match tokio::fs::remove_file(path).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;

    fn unique_dir(name: &str) -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-agentd-auth-terminal-{name}-{nanos}"));
        std::fs::create_dir_all(&dir).expect("create dir");
        dir
    }

    fn sample() -> AuthTerminal {
        AuthTerminal {
            code: "certificate_mismatch".to_string(),
            source: SOURCE_STATUS_REPORT.to_string(),
            detected_at: "2026-09-30T13:02:23Z".to_string(),
            attempts: 3,
        }
    }

    #[tokio::test]
    async fn a_missing_ledger_is_absence_not_an_error() {
        // 「没进过终态」是正常态：读它必须是 `None`，不是 Err —— 否则每次 diagnose 都报故障。
        let dir = unique_dir("missing");
        let loaded = load_async(&path_for(&dir)).await.expect("load");
        assert_eq!(loaded, None);
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn the_ledger_round_trips_and_survives_a_restart() {
        let dir = unique_dir("round-trip");
        let path = path_for(&dir);
        store_async(&path, &sample()).await.expect("store");
        // 换一个「进程」去读：跨重启保留是这块落盘存在的全部理由。
        assert_eq!(load_async(&path).await.expect("load"), Some(sample()));
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn clearing_is_idempotent() {
        let dir = unique_dir("clear");
        let path = path_for(&dir);
        store_async(&path, &sample()).await.expect("store");
        clear_async(&path).await.expect("clear");
        assert_eq!(load_async(&path).await.expect("load"), None);
        // 再清一次：自愈路径可能重复到达，不能因此报错。
        clear_async(&path).await.expect("clear twice");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }

    #[tokio::test]
    async fn an_older_ledger_without_attempts_still_loads() {
        // 字段是后加的：老文件缺 `attempts` 要读成 0，而不是让整个台账读不出来
        // （读不出来 = 看不见终态，正是这块落盘要消灭的盲区）。
        let dir = unique_dir("older");
        let path = path_for(&dir);
        std::fs::write(
            &path,
            r#"{"code":"certificate_revoked","source":"renewal","detected_at":"t"}"#,
        )
        .expect("write");
        let loaded = load_async(&path).await.expect("load").expect("some");
        assert_eq!(loaded.attempts, 0);
        assert_eq!(loaded.code, "certificate_revoked");
        let _ = tokio::fs::remove_dir_all(&dir).await;
    }
}
