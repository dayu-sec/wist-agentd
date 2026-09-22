//! 事实上报的「上次送出的内容摘要」（`state/reporting/fact_summary_digest.json`）。
//!
//! 为什么需要它：事实上送按**内容变化**触发，不是按 discovery 的 revision
//! （后者每轮 refresh 无条件 +1）。所以 agentd 必须记住上次送出去的摘要，
//! 否则每轮都会重发一份全量。
//!
//! 为什么落盘而不是只放内存：重启后内容通常没变，没必要再送一遍。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_async::{read_json_async, write_json_atomic_async};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSummaryDigestState {
    /// 上次成功上送的内容摘要。
    #[serde(default)]
    pub content_digest: String,
    /// 上次成功上送的时刻（RFC3339，给人看）。
    #[serde(default)]
    pub reported_at: String,
    /// 同一时刻的毫秒时间戳（给最小间隔判定用，免去解析 RFC3339）。
    #[serde(default)]
    pub reported_at_ms: i64,
    /// 上次**发起尝试**的毫秒时间戳（不管成没成）。
    ///
    /// 节流必须按「上次尝试」而不是「上次成功」：网关宕机时 `reported_at_ms` 不更新，
    /// 若用它当节流键就形同无节流，每 tick 都重发。`#[serde(default)]` 兼容老文件
    /// （缺字段时读成 0，即「没有历史尝试」，首次放行）。
    #[serde(default)]
    pub last_attempt_at_ms: i64,
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("reporting").join("fact_summary_digest.json")
}

/// 读取上次送出的摘要；文件不存在（首次运行）返回 `None`。
pub async fn load_async(path: &Path) -> io::Result<Option<FactSummaryDigestState>> {
    match read_json_async(path).await {
        Ok(state) => Ok(Some(state)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn store_async(path: &Path, state: &FactSummaryDigestState) -> io::Result<()> {
    write_json_atomic_async(path, state).await
}
