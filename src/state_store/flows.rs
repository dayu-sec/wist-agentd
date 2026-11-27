//! 主机流记录的**运行态快照**（`state/flows/status.json`）。
//!
//! 为什么落盘：`agentd diagnose` 是**另一个进程**，它得能回答「这台机器的流采集现在怎么样」。
//!
//! 为什么不是状态报文：agentd → 网关的 v1 报文是 `deny_unknown_fields` 的（加字段 =
//! 旧读取方整份拒收，见 `wist-contracts` 里的同类注释），而流记录自观测是新能力，
//! 不值得为它开一个新端点。一份几行的 JSON 同时满足两个消费者：`diagnose` 直接读，
//! 现场也能 `cat`。
//!
//! 写入节流在调用方（`FlowRuntime`）：稳态每 30s 一次，失败面变化时立刻写 ——
//! 这条路径不能变成「每 3s 一次 fsync」。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};

use crate::fs_async::write_json_atomic_async;

/// 快照格式版本。改字段语义要升它（`diagnose` 只读自己这版）。
pub(crate) const SCHEMA_VERSION: &str = "agentd.flow_status/v1";

/// 自观测计数器（累计值，随进程生命周期；重启归零 —— 它们是「这次运行表现如何」）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowCounters {
    /// 累计上送成功的窗口记录数。
    #[serde(default)]
    pub windows_sent: u64,
    /// 到达批量上限（剩下的桶留到下一拍）的拍数。
    #[serde(default)]
    pub flush_capped: u64,
    /// 落在已 flush 窗口、只能计丢的包数（迟到，不补发）。
    #[serde(default)]
    pub late_dropped: u64,
    /// 带 `truncated=true` 的窗口记录数（聚合表淘汰过）。
    #[serde(default)]
    pub truncated_windows: u64,
    /// 因观测上下文丢失（网卡在窗口结束前消失）丢弃的记录数。
    #[serde(default)]
    pub lost_records: u64,
    /// 采集器起不来的次数（内核太老 / 缺 CAP / qdisc 冲突 / 对象加载失败）。
    #[serde(default)]
    pub load_failures: u64,
    /// 被观测网卡集合变化的次数（切窗重挂）。
    #[serde(default)]
    pub interface_changes: u64,
    /// 墙钟跳变次数（按旧锚点归窗 + `partial=clock_changed`）。
    #[serde(default)]
    pub clock_jumps: u64,
    /// 上送失败的批数（至多一次：本批丢弃，不重发）。
    #[serde(default)]
    pub uplink_failures: u64,
}

/// 一份运行态快照。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FlowStatus {
    pub schema_version: String,
    /// 这份快照是什么时候写的（本机时钟，RFC 3339）。
    pub updated_at: String,
    /// 采集器当前是否在跑。
    pub collecting: bool,
    /// 走哪条 attach 路径：`tcx`（≥6.6，内核自动摘）| `netlink`（<6.6，需自己清残留）。
    pub attach_path: String,
    /// 运行内核版本。
    pub kernel: String,
    /// 正在观测的网卡。
    #[serde(default)]
    pub ifaces: Vec<String>,
    #[serde(default)]
    pub counters: FlowCounters,
    /// 最近一次失败的一句话（没有失败就没有这个键）。
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
}

pub(crate) fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("flows").join("status.json")
}

/// 读快照；文件不存在 = 从未运行过（`Ok(None)`，不是错误）。
pub(crate) fn load(path: &Path) -> io::Result<Option<FlowStatus>> {
    match std::fs::read(path) {
        Ok(bytes) => {
            let status: FlowStatus = serde_json::from_slice(&bytes).map_err(|err| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    format!("{}: {err}", path.display()),
                )
            })?;
            Ok(Some(status))
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub(crate) async fn store_async(path: &Path, status: &FlowStatus) -> io::Result<()> {
    write_json_atomic_async(path, status).await
}

#[cfg(test)]
mod tests {
    use super::*;

    fn status() -> FlowStatus {
        FlowStatus {
            schema_version: SCHEMA_VERSION.to_string(),
            updated_at: "2026-11-27T00:00:00Z".to_string(),
            collecting: true,
            attach_path: "tcx".to_string(),
            kernel: "6.8.0-138-generic".to_string(),
            ifaces: vec!["eth0".to_string()],
            counters: FlowCounters {
                windows_sent: 42,
                late_dropped: 3,
                ..Default::default()
            },
            last_error: None,
        }
    }

    #[test]
    fn a_missing_file_is_not_an_error() {
        let dir = std::env::temp_dir().join(format!("wist-flow-status-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("dir");
        assert!(load(&path_for(&dir)).expect("load").is_none());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test(flavor = "current_thread")]
    async fn status_roundtrips_and_keeps_counters() {
        let dir = std::env::temp_dir().join(format!(
            "wist-flow-status-rt-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = path_for(&dir);
        store_async(&path, &status()).await.expect("store");
        let loaded = load(&path).expect("load").expect("present");
        assert_eq!(loaded, status());
        assert_eq!(loaded.counters.windows_sent, 42);
        // `last_error` 为空时不写这个键（cat / 下游不用区分 null 与缺失）。
        let text = std::fs::read_to_string(&path).expect("read");
        assert!(!text.contains("last_error"), "{text}");
        std::fs::remove_dir_all(&dir).ok();
    }
}
