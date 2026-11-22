//! 把**执行结果**送回控制面：`POST /api/v1/agent/action-results`。
//!
//! 为什么需要这个模块：调度器把结果写成了本地信封（`state/reporting/<execution>.report.json`），
//! 但**从来没有人把它发出去** —— 网关那边有收货端点、有测试，agentd 这一侧的发送线一直没接。
//! 表现是：命令 ack `accepted`（已取走）、本地执行完成、结果落盘，然后……页面永远等不到；
//! 命令在网关上停在 `claimed`，`outcome` 为空。
//!
//! 设计取舍：
//!
//! * **以磁盘为队列**：发送只依赖 `state/reporting/*.report.json`。daemon 重启、网关宕机、
//!   网络抖动都不会丢结果 —— 下一拍继续发。为此发送成功后**同时**删掉信封与状态文件
//!   （`remove_local_report_artifacts_async`），删不掉最多重发一次（网关按
//!   `(agent_id, action_id)` 幂等）。
//! * **一次失败就停**：末尾按文件名排序，遇到第一个失败就结束本拍，避免网关不可达时
//!   每 3 秒刷一屏日志、也避免把队列里几十条一次打过去。

use std::path::Path;

use wist_api::action_result::ReportActionResult;
use wist_shared::fs::read_json;
use wist_shared::paths::REPORT_ENVELOPE_SUFFIX;

use crate::config::agent_config::AgentConfig;
use crate::control::enrollment::enrollment_http_client;

/// 从报告文件名里取出 `execution_id`（`exec_abc.report.json` → `exec_abc`）。
///
/// 不是 `.report.json` 的文件一律跳过：同一个目录里还有 `exec_abc.json`（上报状态），
/// 它不是待发内容。
pub(crate) fn execution_id_from_envelope(name: &str) -> Option<&str> {
    name.strip_suffix(REPORT_ENVELOPE_SUFFIX)
        .filter(|id| !id.is_empty())
}

/// 把积压的执行结果上报给网关（best-effort，失败留到下一拍）。
pub(crate) async fn send_pending_action_reports(config: &AgentConfig, state_dir: &Path) {
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return;
    };
    if config
        .agent
        .agent_id
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return;
    }
    let dir = state_dir.join("reporting");
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        // 还没有任何执行结果：这是常态，不是错误。
        Err(_) => return,
    };

    let mut pending: Vec<(String, std::path::PathBuf)> = Vec::new();
    while let Ok(Some(entry)) = entries.next_entry().await {
        let file_name = entry.file_name();
        let Some(name) = file_name.to_str() else {
            continue;
        };
        if let Some(execution_id) = execution_id_from_envelope(name) {
            pending.push((execution_id.to_string(), entry.path()));
        }
    }
    if pending.is_empty() {
        return;
    }
    // 稳定顺序：先来的先发（`exec_` 前缀带时间戳，字典序≈时间序）。
    pending.sort_by(|left, right| left.0.cmp(&right.0));

    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            log::warn!("event=ActionResultClientFailed detail=\"{err}\"");
            return;
        }
    };
    let url = format!(
        "{}/api/v1/agent/action-results",
        endpoint.trim_end_matches('/')
    );

    for (execution_id, path) in pending {
        let envelope: ReportActionResult = match read_json(&path) {
            Ok(envelope) => envelope,
            Err(err) => {
                // 读不出来说明文件坏了（或正被写）：留着没意义，也没有更安全的选择。
                log::warn!(
                    "event=ActionResultEnvelopeUnreadable execution_id={execution_id} detail=\"{err}\""
                );
                continue;
            }
        };
        match client.post(&url).json(&envelope).send().await {
            Ok(response) if response.status().is_success() => {
                log::info!(
                    "event=ActionResultReported execution_id={} action_id={} status={}",
                    execution_id,
                    envelope.action_id,
                    envelope.final_status.as_state_name()
                );
                if let Err(err) =
                    crate::reporting::reporting_pipeline::remove_local_report_artifacts_async(
                        state_dir,
                        &execution_id,
                    )
                    .await
                {
                    // 删不掉只会导致网关收到重复报告（按 action_id 幂等），不影响正确性。
                    log::warn!(
                        "event=ActionResultCleanupFailed execution_id={execution_id} detail=\"{err}\""
                    );
                }
            }
            Ok(response) => {
                log::warn!(
                    "event=ActionResultRejected execution_id={} status={}",
                    execution_id,
                    response.status()
                );
                // 4xx 多半是报文/身份问题，重试也没用；但 5xx / 429 值得下一拍再来。
                if response.status().is_client_error() {
                    continue;
                }
                break;
            }
            Err(err) => {
                log::warn!(
                    "event=ActionResultPostFailed execution_id={execution_id} detail=\"{err}\""
                );
                // 网关不可达：本拍收手，别把后面几十条一起撞上去。
                break;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::execution_id_from_envelope;

    #[test]
    fn envelope_name_maps_to_execution_id() {
        assert_eq!(
            execution_id_from_envelope("exec_1700000000_ab.report.json"),
            Some("exec_1700000000_ab")
        );
        // 同目录的「上报状态」文件不是待发内容。
        assert_eq!(execution_id_from_envelope("exec_1700000000_ab.json"), None);
        assert_eq!(execution_id_from_envelope(".report.json"), None);
        assert_eq!(execution_id_from_envelope("notes.txt"), None);
    }
}
