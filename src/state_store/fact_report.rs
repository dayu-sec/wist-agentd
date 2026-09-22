//! 事实上报的**节流**状态（`state/reporting/fact_report.json`）。
//!
//! 为什么需要它：agentd 按探针周期采到快照就上报，但主循环 tick 比这密得多。
//! 没有下限就会每 tick 都发一份全量摘要 —— 那是流量，不是信息。
//!
//! 为什么不记「上次送出的摘要」了：判重归网关（网关自己重算内容摘要）。
//! agentd 侧若也拿摘要拦一道，一旦本地算法或状态文件退化，就会**永远不再上报**，
//! 而且没有任何一层能发现是漏报还是真没变。宁可多发一次，不可静默停报。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_async::{read_json_async, write_json_atomic_async};

#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactReportState {
    /// 上次**发起尝试**的毫秒时间戳（不管成没成）。
    ///
    /// 节流必须按「上次尝试」而不是「上次成功」：网关宕机时后者不更新，
    /// 若用它当节流键就形同无节流，每 tick 都重发。`#[serde(default)]` 兼容老文件
    /// （缺字段时读成 0，即「没有历史尝试」，首次放行）。
    ///
    /// 老文件里携带的 `content_digest` / `reported_at*` 字段现已不用，
    /// 反序列化时被忽略（没有 `deny_unknown_fields`），下次写入即被抹掉。
    #[serde(default)]
    pub last_attempt_at_ms: i64,
}

/// 节流状态文件：**故意放在 `state_dir` 根下，不在 `reporting/` 里**。
///
/// 因为 `reporting/` 的内容会被健康计数当作「待送报告积压」逐个数
/// （`count_reporting_entries_async`），而这是一串**时间戳**，不是待送报告 —— 放在那里
/// 会让 `reporting_count` 永远多 1。原先放在 `reporting/` 里，只是因为在控制面直报模式下
/// 「没配端点就早退」把这个问题遮住了；改走数据面后就显形了。
pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("fact_report.json")
}

/// 读取节流状态；文件不存在（首次运行）返回 `None`。
pub async fn load_async(path: &Path) -> io::Result<Option<FactReportState>> {
    match read_json_async(path).await {
        Ok(state) => Ok(Some(state)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn store_async(path: &Path, state: &FactReportState) -> io::Result<()> {
    write_json_atomic_async(path, state).await
}
