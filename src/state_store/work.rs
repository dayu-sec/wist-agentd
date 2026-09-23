//! agentd 的**工作内容视图**（`state/work.json`）。
//!
//! 记的是**本机在做什么工作**，不是网关那份授权快照的抄本 —— 谁授权了什么、期望哪一版，
//! 是**网关的事实**（网关库里有），本机再抄一份只会诱使人拿它当第二份真相。
//!
//! 这里回答的是四个问题，debug 时按顺序看就是一条线：
//!   1. 我手里有哪些工作、什么状态（`standing[]` / `one_shot[]`）；
//!   2. 每份工作**具体在采什么**（`units[]`：单元 + 采集来源 + 规则标识 + 需什么权限）；
//!   3. 它在本机跑成了哪些**采集任务**（`tasks[]`：任务 id + 盯的路径 + 起读位置），
//!      任务 id 同时也是 `state/logs/file_inputs/<input_id>/` 与 spool 的目录名；
//!   4. 汇总形态（`metrics_interval_seconds`）与**做到哪一步**（`one_shot[].execution`）。
//!
//! 只留最小溯源（`gateway_sequence`）：它把这份本机视图与网关那一版期望对上号，
//! 但**不是**授权副本 —— 想知道网关当时发了什么，答案在网关。
//!
//! ## 为什么值得落盘
//!
//! · **debug**：「这台机器到底在采什么」一眼可见，不必反解授权快照、也不必回网关翻库；
//! · **断网/重启后能继续干活**：进程活着时网关联不上会保留上次应用的工作，但重启后内存
//!   清空 —— 没有这份文件就变成「没授权 → 不采集、不上指标」；有了它是「按最后已知的
//!   工作继续干」。代价：**断网期间撤回会晚一步生效**；
//! · **不重复确认**：确认过的版本一并记下，重启后不把每个版本再点头一遍；
//! · **任务式工作（一次性工作）要记进度与断点**，`one_shot[]` 就是它的落点
//!   （现在只有一个 `execution: "unexecuted"`）。
//!
//! ## 名字为什么是 `work.json`
//!
//! · 模型的话：「工作」（Work）就是网关授权、Agent 执行的那件事 —— `StandingWork` /
//!   `OneShotWork` / `WorkGrant` 共用一个词根；
//! · 本仓的目录约定（`docs/design/agentd-state-and-boundaries.md` §4）：**单例状态扁平放
//!   `state/` 根下**（`agent_runtime.json` / `execution_queue.json`），「一个实体多实例」
//!   才用目录。这份只有「这台 agent 的工作视图」这一份，所以扁平；
//! · 刻意**不**叫 `work_state.json`：本仓「work state」已被占用（`AgentWorkState { Paused,
//!   Resumed }` / `TelemetryWorkState` 指的是采集暂停/继续），撞语义会害到读代码的人。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wist_contracts::work::WorkSpecUnit;

use crate::fs_async::{read_json_async, write_json_atomic_async};

/// 落盘格式版本：将来改结构时用它判断「这份能不能读」。
pub const SCHEMA_VERSION_V1: &str = "v1";

/// 从一份工作折算出来的**本地采集任务**（日志类）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkTaskRecord {
    /// 任务 id：同时是 `state/logs/file_inputs/<input_id>/` 与 spool 文件名。
    pub input_id: String,
    /// 盯的文件（通配）。
    pub path: String,
    /// `head` | `tail`：起读位置。授权采集一律 `tail`（不重放历史）。
    pub startup_position: String,
}

/// 一份**常驻工作**在本机的样子。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct StandingWorkRecord {
    pub work_id: String,
    /// 采集面（`CollectionFamily`）。
    pub family: String,
    /// `active` | `paused`（被撤回/被取代的不在这里 —— 那不是"我手里的工作"）。
    pub status: String,
    /// 网关的期望版本。
    pub plan_version: i64,
    /// 我回报过的版本；`None` = 还没回报（网关那边看到的就是漂移）。
    pub acknowledged_version: Option<i64>,
    pub effective_from: String,
    /// **工作内容**：这份工作包含哪些采集单元、各自怎么采。
    pub units: Vec<WorkSpecUnit>,
    /// 折算成的本地采集任务（指标类工作没有任务，只看 `metrics_interval_seconds`）。
    #[serde(default)]
    pub tasks: Vec<WorkTaskRecord>,
}

/// 一件**一次性工作**在本机的样子。
///
/// 两个状态轴分开记，不要混：`status` 是**网关侧**的派发状态
/// （dispatched / accepted / …），`execution` 是**本机执行状态** ——
/// 现在一律 `unexecuted`（agentd 尚未实现一次性工作的执行）。
/// 将来接上执行后，这里会长出 `current_step` / `completed_steps` / `attempt` 这些断点字段。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct OneShotWorkRecord {
    pub work_id: String,
    /// 动作面：upgrade / snapshot / exec / …。
    pub action: String,
    pub spec: String,
    pub status: String,
    /// `unexecuted`（本机尚未执行）。
    pub execution: String,
    pub scheduled_at: String,
    pub deadline_at: String,
    pub timeout_seconds: i64,
}

/// `state/work.json` 的内容。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkRecord {
    pub schema_version: String,
    /// 这份视图是什么时候算出来的（本机时钟）。
    pub recorded_at: String,
    /// 溯源：本视图对应网关的授权序号。**不是授权副本** ——
    /// 它只用来把本机视图与网关那一版期望对上号。
    pub gateway_sequence: i64,
    /// 手里生效或暂停的常驻工作。
    #[serde(default)]
    pub standing: Vec<StandingWorkRecord>,
    /// 手里未了结的一次性工作。
    #[serde(default)]
    pub one_shot: Vec<OneShotWorkRecord>,
    /// 汇总：指标上送周期（秒）；`None` = 不上送。
    #[serde(default)]
    pub metrics_interval_seconds: Option<i64>,
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("work.json")
}

/// 读取工作视图；文件不存在（首次运行）返回 `None`。
///
/// 读不动（坏 JSON、权限问题）返回 `Err`：调用方**记一行日志后继续**（fail-open），
/// 而不是让 agentd 起不来 —— 一份工作视图不该有让采集停下的权力。
pub async fn load_async(path: &Path) -> io::Result<Option<WorkRecord>> {
    match read_json_async(path).await {
        Ok(record) => Ok(Some(record)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

pub async fn store_async(path: &Path, record: &WorkRecord) -> io::Result<()> {
    write_json_atomic_async(path, record).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::work::WorkSpecSource;

    fn record() -> WorkRecord {
        WorkRecord {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            recorded_at: "2026-09-23T08:00:00Z".to_string(),
            gateway_sequence: 5,
            standing: vec![StandingWorkRecord {
                work_id: "work-crash".to_string(),
                family: "CrashPanic".to_string(),
                status: "active".to_string(),
                plan_version: 2,
                acknowledged_version: Some(2),
                effective_from: "2026-09-23T07:00:00Z".to_string(),
                units: vec![WorkSpecUnit {
                    unit_id: "mac-crash-panic".to_string(),
                    capability: "collect_logs".to_string(),
                    rule_ref: "mac-drafts/crash-panic".to_string(),
                    requires_privilege: "fda".to_string(),
                    sources: vec![WorkSpecSource {
                        kind: "FileGlob".to_string(),
                        target: "/Library/Logs/DiagnosticReports/*.ips".to_string(),
                    }],
                }],
                tasks: vec![WorkTaskRecord {
                    input_id: "work-CrashPanic-mac-crash-panic".to_string(),
                    path: "/Library/Logs/DiagnosticReports/*.ips".to_string(),
                    startup_position: "tail".to_string(),
                }],
            }],
            one_shot: vec![OneShotWorkRecord {
                work_id: "work-upgrade".to_string(),
                action: "upgrade".to_string(),
                spec: "0.1.4".to_string(),
                status: "dispatched".to_string(),
                execution: "unexecuted".to_string(),
                scheduled_at: "2026-09-23T08:00:00Z".to_string(),
                deadline_at: "2026-09-24T08:00:00Z".to_string(),
                timeout_seconds: 600,
            }],
            metrics_interval_seconds: Some(15),
        }
    }

    fn temp_path(name: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!(
            "wist-agentd-work-{name}-{}",
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let path = path_for(&dir);
        (dir, path)
    }

    #[tokio::test]
    async fn round_trips_through_the_state_file() {
        let (dir, path) = temp_path("round-trip");
        // 首次运行：没有文件不是错误。
        assert!(load_async(&path).await.expect("load missing").is_none());

        store_async(&path, &record()).await.expect("store");
        let loaded = load_async(&path).await.expect("load").expect("record");
        assert_eq!(loaded, record());
        // 扁平落在 state/ 根下（本仓约定：单例状态不用目录）。
        assert_eq!(path, dir.join("work.json"));
        std::fs::remove_dir_all(&dir).ok();
    }

    #[tokio::test]
    async fn a_broken_file_is_an_error_the_caller_can_log_and_ignore() {
        let (dir, path) = temp_path("broken");
        std::fs::create_dir_all(path.parent().expect("parent")).expect("mkdir");
        std::fs::write(&path, "{ not json").expect("write");
        let err = load_async(&path).await.expect_err("bad json must error");
        // 具体错误类型不锁（`fs_async` 把 serde 错包装成 `io::Error::other`）；
        // 要锁的是**它确实报错、而不是静默当成重没收到过**：
        // 「文件坏了」与「首次运行」必须分得开，否则调试时会以为本机没有工作。
        assert_ne!(err.kind(), io::ErrorKind::NotFound);
        std::fs::remove_dir_all(&dir).ok();
    }
}
