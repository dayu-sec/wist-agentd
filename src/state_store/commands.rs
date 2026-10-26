//! 一次性命令的本机台账与本地入口。
//!
//! 两条来源共用同一份台账与同一条执行路径：
//!   * **网关下发**：状态上报回执里的 `AgentStatusAck.commands`；
//!   * **本机入口**：`wist-agentd refresh-facts` 写的 `AgentCommand`。
//!
//! 台账（`state/command_history.json`）记录最近处理过的命令与结果：网关没收到结果会重发
//! 同一条 `command_id`，agentd 见到它已在台账里就只补结果、不再执行（重启后同样生效）。
//! 这与「期望状态快照」是两种东西：命令有明确的 id、执行一次、结果回传。

use std::io;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wist_api::status::AgentCommand;

use crate::fs_async::{read_json_async, write_json_atomic_async};

/// 台账最多保留多少条。命令是低频动作，64 条足够覆盖「网关离线一阵子后重连」的重发窗口。
pub const HISTORY_LIMIT: usize = 64;

const REQUEST_FILE: &str = "command.request.json";
const HISTORY_FILE: &str = "command_history.json";

/// 一条已处理命令的结果。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandRecord {
    pub command_id: String,
    pub kind: String,
    /// 见 `wist_api::status::command_outcome`。
    pub outcome: String,
    #[serde(default)]
    pub detail: String,
    pub completed_at_ms: i64,
}

/// 本机命令台账（最近 [`HISTORY_LIMIT`] 条，按完成顺序）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandHistory {
    #[serde(default)]
    pub entries: Vec<CommandRecord>,
}

impl CommandHistory {
    pub fn find(&self, command_id: &str) -> Option<&CommandRecord> {
        self.entries
            .iter()
            .rev()
            .find(|entry| entry.command_id == command_id)
    }

    /// 记录一条结果；同一 `command_id` 覆盖旧记录，超出上限时丢最旧的。
    pub fn record(&mut self, record: CommandRecord) {
        self.entries
            .retain(|entry| entry.command_id != record.command_id);
        self.entries.push(record);
        if self.entries.len() > HISTORY_LIMIT {
            let drop = self.entries.len() - HISTORY_LIMIT;
            self.entries.drain(..drop);
        }
    }
}

pub fn request_path(state_dir: &Path) -> PathBuf {
    state_dir.join(REQUEST_FILE)
}

pub fn history_path(state_dir: &Path) -> PathBuf {
    state_dir.join(HISTORY_FILE)
}

/// 本机请求文件的投递结果。
///
/// 请求文件是**单槽**的：守护进程按 tick 把它取走。若已有一条还没被取走，
/// 再投一条就会把它覆盖 —— 那条命令的 `command_id` 从此不会被台账记到，
/// 正在等它的调用者会白等到超时。所以保留先到的那条，把它的 id 交回去。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SubmitOutcome {
    /// 新请求已落盘。
    Queued,
    /// 已有一条待拾取的请求：没覆盖，返回正在排队的那条。
    AlreadyPending(AgentCommand),
}

/// 写一条**本机**命令（原子写；会按需创建 state 目录）。
///
/// 已有一条未被拾取的请求时**不覆盖**，见 [`SubmitOutcome`]。
pub async fn submit_request_async(
    state_dir: &Path,
    command: &AgentCommand,
) -> io::Result<SubmitOutcome> {
    // 读不出来（含坏 JSON）不挡路：守护进程那边也是「读不出来就丢掉」，
    // 这里直接覆盖重写 —— 真正的 IO 问题会由下面的写入报出来。
    if let Ok(Some(pending)) = read_request_async(state_dir).await {
        return Ok(SubmitOutcome::AlreadyPending(pending));
    }
    write_json_atomic_async(&request_path(state_dir), command).await?;
    Ok(SubmitOutcome::Queued)
}

/// 读本机命令；不存在返回 `None`。坏 JSON 交给调用方删掉并留日志。
pub async fn read_request_async(state_dir: &Path) -> io::Result<Option<AgentCommand>> {
    match read_json_async(&request_path(state_dir)).await {
        Ok(command) => Ok(Some(command)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// 处理前先把请求删掉（不存在不算错）。
pub async fn remove_request_async(state_dir: &Path) -> io::Result<()> {
    match tokio::fs::remove_file(request_path(state_dir)).await {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
    }
}

/// 读台账；文件不存在 = 空台账。
pub async fn load_history_async(state_dir: &Path) -> io::Result<CommandHistory> {
    match read_json_async(&history_path(state_dir)).await {
        Ok(history) => Ok(history),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(CommandHistory::default()),
        Err(err) => Err(err),
    }
}

pub async fn store_history_async(state_dir: &Path, history: &CommandHistory) -> io::Result<()> {
    write_json_atomic_async(&history_path(state_dir), history).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_api::status::{command_kind, command_outcome};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-agentd-commands-{name}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn record(id: &str, outcome: &str) -> CommandRecord {
        CommandRecord {
            command_id: id.to_string(),
            kind: command_kind::REFRESH_FACTS.to_string(),
            outcome: outcome.to_string(),
            detail: String::new(),
            completed_at_ms: 1,
        }
    }

    #[tokio::test]
    async fn request_roundtrip_and_idempotent_remove() {
        let dir = temp_dir("request");
        assert!(read_request_async(&dir).await.expect("read").is_none());

        let command = AgentCommand {
            command_id: "local-1".to_string(),
            requested_at_ms: 10,
            kind: command_kind::REFRESH_FACTS.to_string(),
            params: String::new(),
        };
        assert_eq!(
            submit_request_async(&dir, &command).await.expect("submit"),
            SubmitOutcome::Queued
        );
        assert!(request_path(&dir).exists());
        assert_eq!(read_request_async(&dir).await.expect("read"), Some(command));

        remove_request_async(&dir).await.expect("remove");
        assert!(read_request_async(&dir).await.expect("read").is_none());
        remove_request_async(&dir).await.expect("idempotent remove");
    }

    #[tokio::test]
    async fn an_unclaimed_request_is_not_overwritten_by_a_second_one() {
        let dir = temp_dir("request-slot");
        let first = AgentCommand {
            command_id: "local-first".to_string(),
            requested_at_ms: 10,
            kind: command_kind::REFRESH_FACTS.to_string(),
            params: String::new(),
        };
        let second = AgentCommand {
            command_id: "local-second".to_string(),
            requested_at_ms: 20,
            ..first.clone()
        };
        submit_request_async(&dir, &first).await.expect("submit");
        // 覆盖会丢掉第一条的 id，正在等它的调用者将永远等不到台账结果。
        assert_eq!(
            submit_request_async(&dir, &second).await.expect("submit"),
            SubmitOutcome::AlreadyPending(first.clone())
        );
        assert_eq!(read_request_async(&dir).await.expect("read"), Some(first));
    }

    #[tokio::test]
    async fn history_finds_by_id_replaces_and_caps() {
        let dir = temp_dir("history");
        assert_eq!(
            load_history_async(&dir).await.expect("load"),
            CommandHistory::default()
        );

        let mut history = CommandHistory::default();
        history.record(record("c-1", command_outcome::SUCCEEDED));
        history.record(record("c-2", command_outcome::FAILED));
        // 同一个 id 覆盖旧记录，不产生两条。
        history.record(record("c-1", command_outcome::THROTTLED));
        assert_eq!(history.entries.len(), 2);
        assert_eq!(
            history.find("c-1").map(|entry| entry.outcome.as_str()),
            Some(command_outcome::THROTTLED)
        );

        for index in 0..(HISTORY_LIMIT + 10) {
            history.record(record(
                &format!("c-many-{index}"),
                command_outcome::SUCCEEDED,
            ));
        }
        assert_eq!(history.entries.len(), HISTORY_LIMIT);

        store_history_async(&dir, &history).await.expect("store");
        assert_eq!(load_history_async(&dir).await.expect("load"), history);
    }
}
