//! 日志源候选的**上报**（agentd → 网关）。
//!
//! 与采集预检同一姿态：**尽力而为**。解析本身不做任何写操作，送不出去只进日志 ——
//! 一条辅助信息不该把发现 tick 变成故障。
//!
//! ## 什么时候发
//!
//! 跟**事实摘要**同拍：摘要真的发出去了（`FactSendOutcome::Reported`）才跟着发。
//! 理由：
//!
//! * 解析用的进程证据就来自这一拍算出来的发现快照，两者天然同源；
//! * 摘要已经有 5 分钟节流（手动刷新会强制绕过），日志源跟着它走，不必另造一套节流；
//! * 一台机器不会每 3 秒发一次 HTTP。
//!
//! ## 旧网关怎么办
//!
//! 旧网关没有这个端点，会回 404 —— 那就是「对方还不支持」，静默跳过（与
//! `agent/uplink:poll` 同构）。报成失败只会让现场多一条无意义告警。

use serde::{Deserialize, Serialize};
use wist_contracts::API_VERSION_V1;
use wist_contracts::discovery::DiscoverySnapshot;
use wist_shared::time::now_rfc3339;

use crate::config::agent_config::AgentConfig;
use crate::control::enrollment::enrollment_http_client;
use crate::discovery::log_source::{LogSourceEntry, resolve_from_snapshot};

/// 与网关约定的 `kind`（网关侧同名常量在 `api/agent_log_sources.rs`）。
const REPORT_KIND: &str = "log_sources";

/// 回传给网关的报文。字段与网关 `AgentLogSourceReport` 逐字对齐。
#[derive(Debug, Serialize)]
struct LogSourceReport<'a> {
    api_version: &'a str,
    kind: &'a str,
    agent_id: &'a str,
    instance_id: &'a str,
    observed_at: String,
    sources: &'a [LogSourceEntry],
}

/// 网关回执：逐条校验的结果。
#[derive(Debug, Deserialize)]
struct LogSourceReportAck {
    accepted: usize,
    rejected: usize,
}

/// 解析并上报；返回网关**接受**的条数。
///
/// 返回 `Ok(0)` 的几种情况都是**正常**的，不要当故障：
/// * 本机把 `[discovery] source_resolve` 关了；
/// * 这一拍没有发现快照 / 快照里没有进程（探针没开）；
/// * 旧网关回 404；
/// * 一个候选都没有（没有在跑的服务，或它不在 v1 的服务词表里）。
pub(crate) async fn report_log_sources(
    config: &AgentConfig,
    snapshot: Option<&DiscoverySnapshot>,
    instance_id: &str,
) -> Result<usize, String> {
    if !config.discovery.source_resolve {
        return Ok(0);
    }
    let Some(snapshot) = snapshot else {
        return Ok(0);
    };
    // 快照里连进程都没有：说明进程探针没开 / 这一拍没跑成。
    // 此时**不能**发空列表 —— 那会把网关里上一轮的候选全清掉（看起来像「服务没了」）。
    if !snapshot
        .resources
        .iter()
        .any(|resource| resource.kind == "process")
    {
        return Ok(0);
    }

    // L3 的搜索范围：控制面下发、落 `state/`。这里是 5 分钟级路径，一次几 KB 的读
    // 可以忽略；好处是「守护进程写下的就是这里用的」（不会出现内存与磁盘两套口径）。
    let policy = crate::control::source_search_policy::load_async(std::path::Path::new(
        &config.paths.state_dir,
    ))
    .await;
    let sources = resolve_from_snapshot(snapshot, &policy);
    // 一行 debug：现场问的第一个问题往往是「我明明配了 `-D`，为什么没上报」。
    log::debug!("event=LogSourcesResolved sources={}", sources.len());
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return Err("no control_plane.endpoint configured".to_string());
    };
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return Err("not enrolled (agent.agent_id is empty)".to_string());
    };
    let client = enrollment_http_client(config).map_err(|err| err.to_string())?;
    let report = LogSourceReport {
        api_version: API_VERSION_V1,
        kind: REPORT_KIND,
        agent_id,
        instance_id,
        observed_at: now_rfc3339(),
        sources: &sources,
    };
    let url = format!(
        "{}/api/v1/agent/log-sources",
        endpoint.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .json(&report)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    // 旧网关：这个端点还不存在。静默跳过 —— 不是故障。
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        log::debug!("log source uplink: gateway has no {url} (old gateway), skipping");
        return Ok(0);
    }
    if !response.status().is_success() {
        return Err(format!(
            "HTTP {} from {url}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }
    let ack: LogSourceReportAck = response
        .json()
        .await
        .map_err(|err| format!("invalid log source ack: {err}"))?;
    if ack.rejected > 0 {
        // 逐条丢弃是网关的**正常**行为（一条坏候选不该拖垮整份报告），
        // 但要留一行，否则「我明明报了它却没生效」无从查起。
        log::warn!(
            "event=LogSourceReportedPartially accepted={} rejected={}",
            ack.accepted,
            ack.rejected
        );
    }
    Ok(ack.accepted)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::discovery::log_source::rules;

    fn entry(evidence: &str, dir: &str) -> LogSourceEntry {
        LogSourceEntry {
            service: "postgresql".to_string(),
            source_ref: "port:5432".to_string(),
            dir: dir.to_string(),
            evidence: evidence.to_string(),
            detail: "-D /data/pg".to_string(),
            confidence: 90,
        }
    }

    fn keys(value: &serde_json::Value) -> Vec<String> {
        let mut keys: Vec<String> = value.as_object().expect("object").keys().cloned().collect();
        keys.sort();
        keys
    }

    /// 两侧不共享类型（各自在 seam 一侧定义），字段名只能靠测试钉住：
    /// 网关是 `deny_unknown_fields`，多一个字段、少一个字段都是**整份报告**解析失败。
    #[test]
    fn entry_field_names_are_pinned_to_the_gateway_contract() {
        let value = serde_json::to_value(entry("cmdline_datadir", "/data/pg/log")).unwrap();
        assert_eq!(
            keys(&value),
            [
                "confidence",
                "detail",
                "dir",
                "evidence",
                "service",
                "source_ref"
            ]
        );
    }

    #[test]
    fn report_envelope_is_pinned_to_the_gateway_contract() {
        let sources = vec![entry("cmdline_datadir", "/data/pg/log")];
        let report = LogSourceReport {
            api_version: API_VERSION_V1,
            kind: REPORT_KIND,
            agent_id: "agent-a",
            instance_id: "instance-a",
            observed_at: now_rfc3339(),
            sources: &sources,
        };
        let value = serde_json::to_value(&report).unwrap();
        assert_eq!(
            keys(&value),
            [
                "agent_id",
                "api_version",
                "instance_id",
                "kind",
                "observed_at",
                "sources"
            ]
        );
        // `kind` 拼错会让网关回 400（它按字面值比对）。
        assert_eq!(value["kind"], "log_sources");
        assert_eq!(value["api_version"], "v1");
    }

    /// 本端产出的 `evidence` 必须是网关词表的子集 —— 拼写漂移会让候选被逐条丢弃，
    /// 而现场只看到“日志目录找不到”。两边各持一份**同样的字面清单**，谁改漏了谁红。
    #[test]
    fn evidence_values_are_pinned_to_the_gateway_vocabulary() {
        for evidence in rules::EVIDENCE_VALUES {
            let value = serde_json::to_value(entry(evidence, "/data/pg/log")).unwrap();
            assert_eq!(value["evidence"], *evidence);
        }
        // 占位行的形状：`dir` 必须为空（网关按这个判自相矛盾）。
        assert!(entry("unresolved", "").dir.is_empty());
    }
}
