//! 采集预检（collection preflight）的 **agentd 侧**：网关让机器自己探一次路径。
//!
//! ## 为什么是 agentd 来做，而不是人跑 CLI
//!
//! agentd 以 root 跑在客户主机上，CLI 能看到的它都看得到。远程维护时让人 SSH 到
//! 客户机器上执行命令，成本极高 —— 所以方向反过来：网关入队一条命令，agent 在下一个
//! 状态上报（≤3s）里认领，本机探完**直接回传结论的原料**。
//!
//! ## 为什么复用 `refresh_facts` 这个 kind
//!
//! 已经装在现场的旧 agentd 只认识 `refresh_facts`。新开一个 kind 会让它们回
//! `unsupported` —— 等于「想看一眼结论先得升级」，而客户的机器不该为这个升级。
//!
//! 复用之后：**旧 agentd** 忽略 `params`，做整轮重采（路径照样探、事实照样重报，
//! 结论依然出得来，只是少了 `unreadable` 这层证据）；**新 agentd** 认出
//! `{"scope":"paths","paths":[…]}`，只探这几条路径并回传，省掉一次全量采集。
//!
//! ## 三态，不是两态
//!
//! 探针必须把「确认不存在」与「探不了（权限 / IO）」分开报：
//! 前者是可用的事实（这台机器确实没有），后者是「不知道」。
//! `Path::exists()` 会把两者压成同一个 `false` —— 那是现场最误导人的一种假象。
//! 所以这里用 [`crate::reporting::fact_summary::probe_paths`]，它的三态与事实上报同源。

use serde::Serialize;

use crate::config::agent_config::AgentConfig;
use crate::control::enrollment::enrollment_http_client;
use crate::reporting::fact_summary::{PathProbeReport, UnreadablePath, probe_paths};
use wist_contracts::API_VERSION_V1;
use wist_shared::time::now_rfc3339;

/// 与网关约定的 `kind`。网关侧同一个常量在 `api/preflight.rs`。
const PREFLIGHT_KIND: &str = "collection_preflight";

/// 单次最多探多少条路径（与网关的上限一致）。
const MAX_PROBE_PATHS: usize = 512;

/// 命令参数里认出「这是一次只探路径的请求」。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeRequest {
    pub paths: Vec<String>,
}

/// 解析 `refresh_facts` 的 `params`；不是路径探测请求就返回 `None`。
///
/// 宽容解析是刻意的：`params` 是网关写的，但版本会对不上（旧网关发空串、
/// 将来的网关可能带别的字段）。认不出就退回「整轮重采」，而不是报错。
pub(crate) fn parse_probe_request(params: &str) -> Option<ProbeRequest> {
    let params = params.trim();
    if params.is_empty() {
        return None;
    }
    let value: serde_json::Value = serde_json::from_str(params).ok()?;
    if value.get("scope").and_then(|scope| scope.as_str()) != Some("paths") {
        return None;
    }
    let paths: Vec<String> = value
        .get("paths")?
        .as_array()?
        .iter()
        .filter_map(|item| item.as_str())
        .map(|path| path.trim().to_string())
        // 只认绝对路径：相对路径的结果取决于进程 cwd，同一台机器换一种启动方式就翻面。
        .filter(|path| path.starts_with('/'))
        .take(MAX_PROBE_PATHS)
        .collect();
    if paths.is_empty() {
        return None;
    }
    Some(ProbeRequest { paths })
}

/// 回传给网关的报文（与 `wist-gateway` 的 `AgentPreflightReport` 对得上）。
#[derive(Debug, Serialize)]
struct PreflightReport<'a> {
    api_version: &'a str,
    kind: &'a str,
    agent_id: &'a str,
    instance_id: &'a str,
    observed_at: String,
    probed_paths: &'a [String],
    present_paths: &'a [String],
    unreadable_paths: &'a [UnreadablePath],
}

/// 探一次并回传。返回 `(outcome, detail)`，与其它一次性命令同一口径。
///
/// `outcome` 只用 `succeeded` / `failed`：这一步既不是「重采」也不是「上报事实」，
/// 混用 `no_uplink` 之类的语义会让人以为采集链路断了。
pub(crate) async fn report_path_probe(
    config: &AgentConfig,
    paths: &[String],
) -> (&'static str, String) {
    let probe = probe_paths(paths);
    match post_report(config, &probe).await {
        Ok(()) => (
            wist_api::status::command_outcome::SUCCEEDED,
            summarize(&probe),
        ),
        Err(detail) => (
            wist_api::status::command_outcome::FAILED,
            format!("{}；回传失败：{detail}", summarize(&probe)),
        ),
    }
}

fn summarize(probe: &PathProbeReport) -> String {
    let mut detail = format!(
        "probed={} present={}",
        probe.probed.len(),
        probe.present.len()
    );
    if !probe.unreadable.is_empty() {
        detail.push_str(&format!(" unreadable={}", probe.unreadable.len()));
    }
    detail
}

async fn post_report(config: &AgentConfig, probe: &PathProbeReport) -> Result<(), String> {
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return Err("no control_plane.endpoint configured".to_string());
    };
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return Err("not enrolled (agent.agent_id is empty)".to_string());
    };
    let client = enrollment_http_client(config).map_err(|err| err.to_string())?;
    let report = PreflightReport {
        api_version: API_VERSION_V1,
        kind: PREFLIGHT_KIND,
        agent_id,
        instance_id: config.agent.instance_name.as_deref().unwrap_or_default(),
        observed_at: now_rfc3339(),
        probed_paths: &probe.probed,
        present_paths: &probe.present,
        unreadable_paths: &probe.unreadable,
    };
    let url = format!(
        "{}/api/v1/agent/collection-preflight",
        endpoint.trim_end_matches('/')
    );
    let response = client
        .post(&url)
        .json(&report)
        .send()
        .await
        .map_err(|err| err.to_string())?;
    if !response.status().is_success() {
        return Err(format!(
            "HTTP {} from {url}: {}",
            response.status(),
            response.text().await.unwrap_or_default()
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_config::{
        AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };

    fn test_config(endpoint: Option<&str>, agent_id: Option<&str>) -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: agent_id.map(str::to_string),
                environment_id: None,
                instance_name: Some("instance-x".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: endpoint.map(str::to_string),
                enrollment_token: None,
                credential_request: None,
                credential_id: None,
                credential_expires_at: None,
                tls_mode: None,
                trust_bundle: None,
                auth_mode: None,
            },
            PathsSection::default(),
            ExecutionSection::default(),
        )
    }

    #[tokio::test]
    async fn a_report_without_an_endpoint_fails_loudly() {
        // 离线机器：探测本身能做完，但结果送不出去。必须回 `failed` + 原因，
        // 不能“默默成功”（那会让网关一直显示探测中）。
        let config = test_config(None, Some("agent-x"));
        let paths = vec![env!("CARGO_MANIFEST_DIR").to_string()];

        let (outcome, detail) = report_path_probe(&config, &paths).await;

        assert_eq!(outcome, wist_api::status::command_outcome::FAILED);
        assert!(detail.contains("probed=1"), "探测本身做完了：{detail}");
        assert!(detail.contains("回传失败"), "{detail}");
        assert!(detail.contains("no control_plane.endpoint"), "{detail}");
    }

    #[tokio::test]
    async fn a_report_without_an_agent_id_fails_loudly() {
        let config = test_config(Some("https://127.0.0.1:1"), None);
        let paths = vec![env!("CARGO_MANIFEST_DIR").to_string()];

        let (outcome, detail) = report_path_probe(&config, &paths).await;

        assert_eq!(outcome, wist_api::status::command_outcome::FAILED);
        assert!(detail.contains("not enrolled"), "{detail}");
    }

    #[test]
    fn the_report_body_matches_the_gateway_contract() {
        // 字段名/形状是跨仓契约：网关侧 `AgentPreflightReport` 就按这几个名字读。
        let probed = vec!["/var/lib/docker/containers".to_string()];
        let present = probed.clone();
        let unreadable = vec![UnreadablePath {
            path: "/var/log/pods".to_string(),
            error: "permission denied".to_string(),
        }];
        let report = PreflightReport {
            api_version: API_VERSION_V1,
            kind: PREFLIGHT_KIND,
            agent_id: "agent-1",
            instance_id: "node-1",
            observed_at: "2026-10-26T00:00:00Z".to_string(),
            probed_paths: &probed,
            present_paths: &present,
            unreadable_paths: &unreadable,
        };
        let value = serde_json::to_value(&report).expect("serialize");

        assert_eq!(value["api_version"], "v1");
        assert_eq!(value["kind"], "collection_preflight");
        assert_eq!(value["agent_id"], "agent-1");
        assert_eq!(value["probed_paths"][0], "/var/lib/docker/containers");
        assert_eq!(value["unreadable_paths"][0]["path"], "/var/log/pods");
        assert_eq!(value["unreadable_paths"][0]["error"], "permission denied");
    }

    #[test]
    fn parses_a_path_scoped_request() {
        let request =
            parse_probe_request(r#"{"scope":"paths","paths":["/a","/b"]}"#).expect("request");
        assert_eq!(request.paths, vec!["/a".to_string(), "/b".to_string()]);
    }

    #[test]
    fn ignores_requests_that_are_not_path_scoped() {
        assert!(parse_probe_request("").is_none());
        assert!(parse_probe_request("   ").is_none());
        assert!(parse_probe_request("{}").is_none());
        assert!(parse_probe_request(r#"{"scope":"facts"}"#).is_none());
        assert!(parse_probe_request("not json").is_none());
    }

    #[test]
    fn drops_relative_and_empty_path_lists() {
        assert!(parse_probe_request(r#"{"scope":"paths","paths":["relative"]}"#).is_none());
        assert!(parse_probe_request(r#"{"scope":"paths","paths":[]}"#).is_none());
        let request =
            parse_probe_request(r#"{"scope":"paths","paths":["relative","/a"]}"#).expect("request");
        assert_eq!(request.paths, vec!["/a".to_string()]);
    }

    #[test]
    fn caps_the_number_of_paths() {
        let many: Vec<String> = (0..MAX_PROBE_PATHS + 10)
            .map(|index| format!("/p{index}"))
            .collect();
        let params = serde_json::json!({ "scope": "paths", "paths": many }).to_string();
        let request = parse_probe_request(&params).expect("request");
        assert_eq!(request.paths.len(), MAX_PROBE_PATHS);
    }
}
