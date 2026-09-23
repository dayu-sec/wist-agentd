//! 网关授权工作的**本地留痕**（`state/work/grant.json`）。
//!
//! 记三件事，各有各的用处：
//!   1. 网关**原样发来的快照**（`grant`）—— debug 的第一手材料：「它到底发了我什么」，
//!      不必回到网关翻库、也不必等下一次拉取；
//!   2. **折算结论**（日志采集任务清单、指标周期）—— 「我据此在做什么」；
//!   3. **已回报的版本**（`acked`）—— 重启后不用把每个版本再点头一遍。
//!
//! ## 为什么值得落盘
//!
//! · **debug**：出问题时本机就能看到期望状态与折算结果，两边对不上时一眼能定位是哪一层；
//! · **断网/重启后能继续干活**：进程活着时网关联不上本来就会保留上次应用的工作，
//!   但重启后内存清空 —— 没有这份留痕就变成「没授权 → 不采集、不上指标」。
//!   用了留痕则是「按最后已知期望继续干」，代价见 `refresh_work_grant` 的取舍说明
//!   （断网期间撤回会晚一步生效）；
//! · **不重复确认**：确认记忆全在内存时，每次重启都会把当前的版本再回报一遍。
//!   这不是错误（网关侧是覆盖式写入），但是没必要的流量与噪声；
//! · **任务式工作（一次性工作）将来要记进度与断点**，也需要一个本地落点。
//!
//! 注意：它**不能**治病「重启后页面显示未确认」这类现象 —— 页面的确认读的是**网关**
//! 那份回执，agentd 重启不会把网关库里那一行抹掉。这份留痕解决的是本机失忆，不是两边不一致。
//!
//! ## 这不是「期望状态的第二份真相」
//!
//! 连上网关后一律以网关为准：快照是幂等的期望状态，拉一次就回到期望。
//! 本地这份只是**最后已知**的那一份，永远不参与「谁更新」的比较。

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wist_contracts::work::WorkGrant;

use crate::fs_async::{read_json_async, write_json_atomic_async};

/// 落盘格式版本：将来改结构时用它判断「这份能不能读」。
pub const SCHEMA_VERSION_V1: &str = "v1";

/// 一条从工作折算出来的日志采集任务的**留痕投影**。
///
/// 为什么不直接把 `LogFileInputSection` 存进去：那个结构是**运行期配置**（还有
/// `startup_position` / `multiline_mode` 等与本次留痕无关的字段），而这里要回答的
/// 是「网关派了什么、我折算成了哪个任务、它盯的是哪个文件」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkLogInputRecord {
    pub work_id: String,
    pub family: String,
    pub unit_id: String,
    /// 采集任务 id（`work-<面>-<单元>`）：它同时是 checkpoint 与 spool 的目录名。
    pub input_id: String,
    pub path: String,
}

/// `state/work/grant.json` 的内容。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct WorkGrantRecord {
    pub schema_version: String,
    /// 网关的授权序号（Agent 据此判断快照有没有变）。
    pub sequence: i64,
    /// 这份快照是什么时候收到的（本机时钟）。
    pub received_at: String,
    /// 本机把它应用（折算 + 确认）完的时间。
    pub applied_at: String,
    /// 折算出的日志采集任务。
    #[serde(default)]
    pub log_inputs: Vec<WorkLogInputRecord>,
    /// 指标上送周期（秒）；`None` = 不上送。
    #[serde(default)]
    pub metrics_interval_seconds: Option<i64>,
    /// 已回报给网关的版本：`work_id → plan_version`。
    #[serde(default)]
    pub acked: BTreeMap<String, i64>,
    /// 收到但**未执行**的一次性工作 id（agentd 侧尚未实现执行）。
    #[serde(default)]
    pub unexecutable_one_shot: Vec<String>,
    /// 网关原样发来的授权快照。
    pub grant: WorkGrant,
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("work").join("grant.json")
}

/// 读取留痕；文件不存在（首次运行）返回 `None`。
///
/// 读不动（坏 JSON、权限问题）返回 `Err`：调用方**记一行日志后继续**（fail-open），
/// 而不是让 agentd 起不来 —— 一份留痕不该有让采集停下的权力。
pub async fn load_async(path: &Path) -> io::Result<Option<WorkGrantRecord>> {
    match read_json_async(path).await {
        Ok(record) => Ok(Some(record)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn store_async(path: &Path, record: &WorkGrantRecord) -> io::Result<()> {
    write_json_atomic_async(path, record).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::work::{StandingWork, WorkSpec, WorkSpecSource, WorkSpecUnit};

    fn grant() -> WorkGrant {
        let spec = WorkSpec {
            units: vec![WorkSpecUnit {
                unit_id: "mac-host-metrics".to_string(),
                capability: "collect_metrics".to_string(),
                rule_ref: "agent_uplink".to_string(),
                requires_privilege: "none".to_string(),
                sources: vec![WorkSpecSource {
                    kind: "MetricInterval".to_string(),
                    target: "15s".to_string(),
                }],
            }],
        };
        WorkGrant {
            agent_id: "agent-001".to_string(),
            standing: vec![StandingWork {
                work_id: "work-a".to_string(),
                agent_id: "agent-001".to_string(),
                family: "HostMetrics".to_string(),
                spec: spec.encode().expect("encode spec"),
                catalog_version: 1,
                proposal_id: None,
                plan_version: 2,
                effective_from: "2026-09-23T00:00:00Z".to_string(),
                status: "active".to_string(),
                updated_by: "admin".to_string(),
                updated_at: "2026-09-23T00:00:00Z".to_string(),
            }],
            one_shot: Vec::new(),
            sequence: 4,
            granted_at: "2026-09-23T00:00:00Z".to_string(),
        }
    }

    fn record() -> WorkGrantRecord {
        WorkGrantRecord {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            sequence: 4,
            received_at: "2026-09-23T00:00:01Z".to_string(),
            applied_at: "2026-09-23T00:00:01Z".to_string(),
            log_inputs: vec![WorkLogInputRecord {
                work_id: "work-b".to_string(),
                family: "CrashPanic".to_string(),
                unit_id: "mac-crash-panic".to_string(),
                input_id: "work-CrashPanic-mac-crash-panic".to_string(),
                path: "/Library/Logs/DiagnosticReports/*.ips".to_string(),
            }],
            metrics_interval_seconds: Some(15),
            acked: BTreeMap::from([("work-a".to_string(), 2)]),
            unexecutable_one_shot: vec!["work-upgrade".to_string()],
            grant: grant(),
        }
    }

    #[tokio::test]
    async fn round_trips_through_the_state_file() {
        let dir = std::env::temp_dir().join(format!(
            "wist-agentd-work-grant-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = path_for(&dir);
        // 首次运行：没有文件不是错误。
        assert!(load_async(&path).await.expect("load missing").is_none());

        store_async(&path, &record()).await.expect("store");
        let loaded = load_async(&path).await.expect("load").expect("record");
        assert_eq!(loaded, record());
        // 目录是自动建的（不掉进「父目录不存在」的坑）。
        assert!(path.exists());
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_broken_file_is_an_error_the_caller_can_log_and_ignore() {
        let dir = std::env::temp_dir().join(format!(
            "wist-agentd-work-grant-broken-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = path_for(&dir);
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, "{ not json").expect("write");
        let err = load_async(&path).await.expect_err("bad json must error");
        // 具体错误类型不锁（`fs_async` 把 serde 错包装成 `io::Error::other`）；
        // 要锁的是**它确实报错、而不是静默当成重没收到过**：
        // 「文件坏了」与「首次运行」必须分得开，否则调试时会以为网关没发。
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(&dir).ok();
    }
}
