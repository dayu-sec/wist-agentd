//! 原文快照（DSNAP）上送设置的控制面拉取与应用（agentd 侧）。
//!
//! 与 [`crate::control::uplink`] 同构：网关给的是**期望状态**（这台机器该不该上送原文快照、
//! 多久一帧），这里把它拉下来并在内存里应用。「什么时候拉、拉多密」在主循环里
//! （见 `runtime::daemon::refresh_discovery_snapshot_policy`），本模块只负责
//! 「这一趟拿没拿到」以及「该不该打日志」。
//!
//! ## 为什么另开一条拉取
//!
//! 塞进 `AgentUplinkGrant` / `DiscoveryPoliciesReturned` 会让「新网关 + 旧 agentd」解析失败
//! （那两个契约两侧都 `deny_unknown_fields`）。独立端点对两个方向都安全 ——
//! 旧 agentd 从不调它；新 agentd 遇旧网关得到 404，回落本机配置。
//!
//! ## 优先级
//!
//! 控制面设置 > 本机 `[discovery]`。网关**没有设置**时回 `204`，同样回落本机配置：
//! 本机配置是离线 / 旧网关 / 未入网时唯一的来源，不能被一个空设置永久压掉。
//!
//! ## 一个容易踩的坑
//!
//! 网关**撤销**设置（从有到无）时必须把已应用的 grant 清掉，否则 Agent 会一直沿用
//! 最后一次下发的周期，与本机配置脱节 —— 页面显示「已恢复默认」，机器却还在按旧值跑。

use std::time::Duration;

use crate::config::agent_config::AgentConfig;
use wist_api::discovery_snapshot::{
    APPLIED_SOURCE_CONTROL_PLANE, APPLIED_SOURCE_LOCAL_CONFIG, AppliedDiscoverySnapshot,
    DiscoverySnapshotGrant, POLL_DISCOVERY_SNAPSHOT_KIND, PollDiscoverySnapshot,
};
use wist_shared::time::now_rfc3339;

use crate::control::enrollment::enrollment_http_client;

/// 单次拉取请求的超时（与 `uplink`/`work` 同值：这条路径排在采集之前，必须自己封顶）。
const SNAPSHOT_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// 周期下限，与主循环的夹取同值（`DISCOVERY_SNAPSHOT_MIN_INTERVAL_SECS`）。
pub(crate) const MIN_INTERVAL_SECONDS: u64 = 60;

/// 一次拉取的结果。
///
/// 「没拿到」要分出**预期内**与**异常**：前者静默、后者按签名去重地报一行。
/// 把两者混成一个 `Option`，会让「旧网关没有这个端点」每 30s 刷一行 failed。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotFetch {
    Granted(DiscoverySnapshotGrant),
    /// 预期内：未入网 / 旧网关 404 / 网关没有设置（204）。按「无下发」处理：用本机配置。
    NotDispatched,
    /// 异常（含 401/403）。**保留**上次已应用的设置。
    ///
    /// 与 `uplink` 刻意不同：那里凭据被拒要强制回落待命（那是**数据外发**的授权）；
    /// 这里只是采样周期，强制关掉它并不能减少什么风险，反而会把「凭据问题」放大成
    /// 「这台机器不再上送资产」。
    Failed(String),
}

impl SnapshotFetch {
    /// 只取「拿到了什么」，用于诊断（失败/无下发都当 `None`）。
    pub(crate) fn grant(self) -> Option<DiscoverySnapshotGrant> {
        match self {
            SnapshotFetch::Granted(grant) => Some(grant),
            _ => None,
        }
    }
}

/// 拉取原文快照上送设置。
///
/// `applied` 是当前**实际生效**的值，随请求回传给网关（管理面据此显示「配置 vs 生效」）。
pub(crate) async fn fetch_discovery_snapshot(
    config: &AgentConfig,
    applied: Option<AppliedDiscoverySnapshot>,
) -> SnapshotFetch {
    // 未入网：缺端点 / 身份任一 —— 这是「无下发」，不是故障。
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return SnapshotFetch::NotDispatched;
    };
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return SnapshotFetch::NotDispatched;
    };
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();

    let request = PollDiscoverySnapshot {
        api_version: wist_contracts::API_VERSION_V1.to_string(),
        kind: POLL_DISCOVERY_SNAPSHOT_KIND.to_string(),
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        requested_at: now_rfc3339(),
        applied,
    };
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        // 建不出客户端是本机配置/环境的问题（信任锚、证书），要看得见。
        Err(err) => return SnapshotFetch::Failed(format!("client: {err}")),
    };
    let url = format!(
        "{}/api/v1/agent/discovery-snapshot:poll",
        endpoint.trim_end_matches('/')
    );
    match client
        .post(&url)
        .timeout(SNAPSHOT_REQUEST_TIMEOUT)
        .json(&request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<DiscoverySnapshotGrant>().await {
                Ok(grant) => SnapshotFetch::Granted(grant),
                Err(err) => {
                    SnapshotFetch::Failed(format!("invalid response from {endpoint}: {err}"))
                }
            }
        }
        // 网关**没有设置**（204）：明确「没有意见」，回落本机配置。
        Ok(response) if response.status() == reqwest::StatusCode::NO_CONTENT => {
            SnapshotFetch::NotDispatched
        }
        // 旧网关没有这个端点（404）：同样按「无下发」处理，不刷日志。
        Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND => {
            SnapshotFetch::NotDispatched
        }
        Ok(response) => {
            SnapshotFetch::Failed(format!("http {} from {endpoint}", response.status()))
        }
        Err(err) => SnapshotFetch::Failed(format!("transport: {err}")),
    }
}

/// 该打的一行日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SnapshotEvent {
    Applied(String),
    Failed(String),
}

/// 当前已应用的控制面设置（内存态，跨 tick 活着）。
///
/// **不落盘**：与 uplink 同一取舍 —— 重启后先按本机配置跑，网关可达后 30s 内再应用下发值。
/// 这样「网关撤了设置但机器正好重启」不会让它继续按旧值跑。
#[derive(Debug, Clone, Default)]
pub(crate) struct AppliedSnapshotPolicy {
    grant: Option<DiscoverySnapshotGrant>,
    last_failure: Option<String>,
}

impl AppliedSnapshotPolicy {
    /// 已应用的控制面设置；`None` = 没有（未入网 / 旧网关 / 网关没设置 / 一直失败）。
    pub(crate) fn grant(&self) -> Option<&DiscoverySnapshotGrant> {
        self.grant.as_ref()
    }

    /// 消费一次拉取结果，返回该打的一行日志（`None` = 不必打）。
    ///
    /// 变化判定只看**生效状态**（`enabled` + 周期），不看 `granted_at`：网关每次 poll
    /// 都现算墙钟，把它算进变化会让每个 agent 每 30s 都判为「变了」。
    pub(crate) fn observe(&mut self, outcome: SnapshotFetch) -> Option<SnapshotEvent> {
        match outcome {
            SnapshotFetch::NotDispatched => {
                self.last_failure = None;
                // 从「有下发」变回「无下发」= 网关撤销了设置：必须清掉，
                // 否则会一直沿用旧周期（页面显示已恢复，机器还在按旧值跑）。
                if self.grant.take().is_some() {
                    return Some(SnapshotEvent::Applied(
                        "event=DiscoverySnapshotPolicyCleared source=local_config detail=\"网关已撤销设置，回落本机 [discovery]\"".to_string(),
                    ));
                }
                None
            }
            SnapshotFetch::Failed(signature) => {
                if self.last_failure.as_deref() == Some(signature.as_str()) {
                    return None;
                }
                let line =
                    format!("wist-agentd discovery snapshot policy fetch failed: {signature}");
                self.last_failure = Some(signature);
                Some(SnapshotEvent::Failed(line))
            }
            SnapshotFetch::Granted(grant) => {
                self.last_failure = None;
                let changed = self.grant.as_ref().map(policy_key) != Some(policy_key(&grant));
                self.grant = Some(grant);
                if !changed {
                    return None;
                }
                let applied = self.grant.as_ref().expect("just assigned");
                Some(SnapshotEvent::Applied(format!(
                    "event=DiscoverySnapshotPolicyApplied enabled={} interval_seconds={} source=grant:{}",
                    applied.enabled,
                    applied.interval_seconds.max(MIN_INTERVAL_SECONDS),
                    applied.source
                )))
            }
        }
    }
}

fn policy_key(grant: &DiscoverySnapshotGrant) -> (bool, u64) {
    (
        grant.enabled,
        grant.interval_seconds.max(MIN_INTERVAL_SECONDS),
    )
}

/// 本轮该用的快照上送配置：控制面有下发就按下发，否则按本机 `[discovery]`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct EffectiveSnapshotPolicy {
    pub enabled: bool,
    pub interval_seconds: u64,
    /// `control_plane` / `local_config`（与回传给网关的口径一致）。
    pub source: &'static str,
}

impl EffectiveSnapshotPolicy {
    pub(crate) fn applied(&self) -> AppliedDiscoverySnapshot {
        AppliedDiscoverySnapshot {
            enabled: self.enabled,
            interval_seconds: self.interval_seconds,
            source: self.source.to_string(),
        }
    }
}

pub(crate) fn effective_policy(
    config: &AgentConfig,
    grant: Option<&DiscoverySnapshotGrant>,
) -> EffectiveSnapshotPolicy {
    match grant {
        Some(grant) => EffectiveSnapshotPolicy {
            enabled: grant.enabled,
            interval_seconds: grant.interval_seconds.max(MIN_INTERVAL_SECONDS),
            source: APPLIED_SOURCE_CONTROL_PLANE,
        },
        None => EffectiveSnapshotPolicy {
            enabled: config.discovery.snapshot_uplink_enabled,
            interval_seconds: config
                .discovery
                .snapshot_uplink_interval_seconds
                .max(MIN_INTERVAL_SECONDS),
            source: APPLIED_SOURCE_LOCAL_CONFIG,
        },
    }
}

#[cfg(test)]
mod tests {
    use super::{
        AppliedSnapshotPolicy, EffectiveSnapshotPolicy, MIN_INTERVAL_SECONDS, SnapshotEvent,
        SnapshotFetch, effective_policy,
    };
    use crate::config::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };
    use wist_api::discovery_snapshot::{
        APPLIED_SOURCE_CONTROL_PLANE, APPLIED_SOURCE_LOCAL_CONFIG, DiscoverySnapshotGrant,
        GRANT_SOURCE_AGENT,
    };

    fn config(snapshot_enabled: bool, interval_seconds: u64) -> AgentConfig {
        let mut config = AgentConfig::new(
            AgentSection {
                agent_id: Some("agent-x".to_string()),
                environment_id: None,
                instance_name: Some("instance-x".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: Some("https://gateway.example".to_string()),
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
        );
        config.discovery.snapshot_uplink_enabled = snapshot_enabled;
        config.discovery.snapshot_uplink_interval_seconds = interval_seconds;
        config
    }

    fn grant(enabled: bool, interval_seconds: u64) -> DiscoverySnapshotGrant {
        DiscoverySnapshotGrant {
            enabled,
            interval_seconds,
            source: GRANT_SOURCE_AGENT.to_string(),
            granted_at: "2026-10-26T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn local_config_is_used_until_a_grant_arrives() {
        let config = config(true, 3600);
        let effective = effective_policy(&config, None);
        assert!(effective.enabled);
        assert_eq!(effective.interval_seconds, 3600);
        assert_eq!(effective.source, APPLIED_SOURCE_LOCAL_CONFIG);

        let effective = effective_policy(&config, Some(&grant(false, 300)));
        assert!(!effective.enabled);
        assert_eq!(effective.interval_seconds, 300);
        assert_eq!(effective.source, APPLIED_SOURCE_CONTROL_PLANE);
    }

    #[test]
    fn a_too_short_grant_is_clamped() {
        let effective = effective_policy(&config(true, 3600), Some(&grant(true, 5)));
        assert_eq!(effective.interval_seconds, MIN_INTERVAL_SECONDS);
    }

    #[test]
    fn only_real_changes_are_reported() {
        let mut applied = AppliedSnapshotPolicy::default();
        let first = applied.observe(SnapshotFetch::Granted(grant(true, 3600)));
        assert!(matches!(first, Some(SnapshotEvent::Applied(_))));

        // 同一个生效状态（只有 granted_at 不同）不该再打一行。
        assert!(
            applied
                .observe(SnapshotFetch::Granted(grant(true, 3600)))
                .is_none()
        );

        let changed = applied.observe(SnapshotFetch::Granted(grant(true, 300)));
        assert!(matches!(changed, Some(SnapshotEvent::Applied(_))));
    }

    /// 网关撤销设置（204）时必须**清掉**已应用的 grant，否则机器会一直按旧周期跑。
    #[test]
    fn a_cleared_setting_falls_back_to_local_config() {
        let mut applied = AppliedSnapshotPolicy::default();
        applied.observe(SnapshotFetch::Granted(grant(true, 300)));
        assert!(applied.grant().is_some());

        let cleared = applied.observe(SnapshotFetch::NotDispatched);
        assert!(matches!(cleared, Some(SnapshotEvent::Applied(_))));
        assert!(applied.grant().is_none());
        assert_eq!(
            effective_policy(&config(true, 3600), applied.grant()),
            EffectiveSnapshotPolicy {
                enabled: true,
                interval_seconds: 3600,
                source: APPLIED_SOURCE_LOCAL_CONFIG,
            }
        );

        // 再收一次 204 就没什么可报的了。
        assert!(applied.observe(SnapshotFetch::NotDispatched).is_none());
    }

    #[test]
    fn a_failure_is_reported_once_and_keeps_the_applied_grant() {
        let mut applied = AppliedSnapshotPolicy::default();
        applied.observe(SnapshotFetch::Granted(grant(true, 300)));

        let first = applied.observe(SnapshotFetch::Failed("transport: timeout".to_string()));
        assert!(matches!(first, Some(SnapshotEvent::Failed(_))));
        assert!(applied.grant().is_some(), "失败不得清掉已应用的设置");

        assert!(
            applied
                .observe(SnapshotFetch::Failed("transport: timeout".to_string()))
                .is_none(),
            "同一签名只报一次"
        );
        // 故障形态变了要能再报。
        assert!(
            applied
                .observe(SnapshotFetch::Failed("http 500 from x".to_string()))
                .is_some()
        );
    }
}
