//! 导出器运行参数（二进制**搜索目录** + 周期 / 超时）：从网关拉取、落盘、供应。
//!
//! ## 为什么在网关下发，而不是本机配置
//!
//! 工具装在哪个目录是**纯环境信息**（发行版 / 容器镜像 / Homebrew / 自建前缀）；
//! 写死在 agentd 里意味着每种环境都要发一版 root 守护进程。数据能改「去哪找、多久跑」，
//! **不能改「跑什么」**：`id` 必须是代码里登记的导出器，二进制名与参数都在 `telemetry::exporters`。
//!
//! ## 拿不到怎么办（fail-safe，不是 fail-closed）
//!
//! 内置表（`telemetry::exporters::BIN_DIRS` + 默认周期）已经覆盖常见发行版，所以：
//! 未入网 / 旧网关（404）/ 网络失败 / 响应坏 → **沿用上一份已落盘的策略**；
//! 从未拿到过 → 用内置值。这与 L3 搜索（拿不到就不搜）不同：那是权限面，这是环境参数。
//!
//! ## 本机也要校验
//!
//! 网关装载时已经校验过目录与 ID，这里再守一道（同样的目录白名单 + 已知 ID）：
//! 两端校验不是重复劳动 —— 任一端的回归都不该变成“让 root 守护进程去跑别的东西”。

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wist_contracts::API_VERSION_V1;
use wist_shared::time::now_rfc3339;

use crate::config::agent_config::AgentConfig;
use crate::control::enrollment::enrollment_http_client;
use crate::fs_async::write_json_atomic_async;

/// 与网关约定的 `kind`（网关侧同名常量在 `api/exporter_policy.rs`）。
const POLL_KIND: &str = "exporter_policy";
/// 落盘文件名（在 `paths.state_dir` 下）。
const STATE_FILE: &str = "exporter_policy.json";
/// 拉取超时：与其它 `:poll` 同量级（不能吃掉 3s 的主循环 tick）。
const FETCH_TIMEOUT: Duration = Duration::from_secs(5);
/// 单平台搜索目录上限（与网关同值；超出部分丢弃并告警）。
const MAX_BIN_DIRS: usize = 16;
/// 周期 / 超时的上下界（与网关同值；越界一律按内置值）。
const MIN_PERIOD_SECS: u64 = 10;
const MAX_PERIOD_SECS: u64 = 24 * 3600;
const MIN_TIMEOUT_SECS: u64 = 1;
const MAX_TIMEOUT_SECS: u64 = 300;

/// 允许作为**二进制搜索目录**的系统目录前缀（与网关同一份口径）。
const ALLOWED_BIN_DIR_PREFIXES: &[&str] = &["/usr", "/bin", "/sbin", "/opt", "/snap"];

/// 一份生效的导出器运行参数。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterPolicy {
    /// 来自知识库的哪一版（0 = 空载 / 旧包没有 `exporters.toml`）。
    #[serde(default)]
    pub exporters_version: i64,
    #[serde(default)]
    pub platform: String,
    /// 按优先级排列的搜索目录；空 = 用内置表。
    #[serde(default)]
    pub bin_dirs: Vec<String>,
    /// 逐导出器的周期 / 超时覆盖；空 = 全用内置值。
    #[serde(default)]
    pub exporters: Vec<ExporterOverride>,
    #[serde(default)]
    pub fetched_at: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ExporterOverride {
    pub id: String,
    #[serde(default)]
    pub period_secs: Option<u64>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE)
}

/// 读落盘的那份（坏文件 = 当作没有，不阻塞启动）。
pub fn load(state_dir: &Path) -> Option<ExporterPolicy> {
    let path = path_for(state_dir);
    let text = std::fs::read_to_string(&path).ok()?;
    match serde_json::from_str::<ExporterPolicy>(&text) {
        Ok(policy) => Some(sanitize(policy)),
        Err(err) => {
            log::warn!(
                "event=ExporterPolicyUnreadable path={} detail={err}",
                path.display()
            );
            None
        }
    }
}

/// 拉一次；成功则落盘并返回。`None` = 这一拍没有拿到新策略（沿用落盘那份 / 内置值）。
pub(crate) async fn refresh(config: &AgentConfig, state_dir: &Path) -> Option<ExporterPolicy> {
    let endpoint = config.control_plane.endpoint.as_deref()?;
    let agent_id = config.agent.agent_id.as_deref()?;
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            log::warn!("exporter policy: failed to build client: {err}");
            return None;
        }
    };
    let url = format!(
        "{}/api/v1/agent/exporter-policy:poll",
        endpoint.trim_end_matches('/')
    );
    let request = serde_json::json!({
        "api_version": API_VERSION_V1,
        "kind": POLL_KIND,
        "agent_id": agent_id,
        "instance_id": instance_id,
        // 本机事实：决定用哪一套搜索目录（网关按它选表）。
        "platform": std::env::consts::OS,
        "requested_at": now_rfc3339(),
    });
    let response = match client
        .post(&url)
        .timeout(FETCH_TIMEOUT)
        .json(&request)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => {
            log::warn!("exporter policy: request {url} failed: {err}");
            return None;
        }
    };
    // 旧网关没这个端点：等同“这个部署不下发导出器参数”，静默用内置值。
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        log::debug!("exporter policy: gateway has no {url} (old gateway), skipping");
        return None;
    }
    if !response.status().is_success() {
        log::warn!("exporter policy: HTTP {} from {url}", response.status());
        return None;
    }
    let returned: Returned = match response.json().await {
        Ok(returned) => returned,
        Err(err) => {
            log::warn!("exporter policy: invalid response from {url}: {err}");
            return None;
        }
    };
    if returned.api_version != API_VERSION_V1 || returned.kind != POLL_KIND {
        log::warn!(
            "exporter policy: unexpected response (api_version={:?} kind={:?}) from {url}",
            returned.api_version,
            returned.kind
        );
        return None;
    }
    // 空载（网关没装知识库 / 旧包没有 exporters.toml）：**不是错误**，用内置值。
    if returned.exporters_version <= 0 && returned.bin_dirs.is_empty() {
        log::debug!("exporter policy: gateway has no policy (empty), using built-in table");
        return None;
    }
    // 网关回的时间戳进日志：排查“策略是不是旧的 / 两侧时钟是不是偏了”时第一个要看的东西。
    let returned_at = returned.returned_at.clone();
    let policy = sanitize(ExporterPolicy {
        exporters_version: returned.exporters_version,
        platform: returned.platform,
        bin_dirs: returned.bin_dirs,
        exporters: returned
            .exporters
            .into_iter()
            .map(|row| ExporterOverride {
                id: row.id,
                period_secs: row.period_secs,
                timeout_secs: row.timeout_secs,
            })
            .collect(),
        fetched_at: now_rfc3339(),
    });
    if let Err(err) = write_json_atomic_async(&path_for(state_dir), &policy).await {
        log::warn!("exporter policy: write state failed: {err}");
    }
    log::info!(
        "event=ExporterPolicyApplied version={} platform={} dirs={} overrides={} returned_at={}",
        policy.exporters_version,
        policy.platform,
        policy.bin_dirs.len(),
        policy.exporters.len(),
        returned_at
    );
    Some(policy)
}

/// 本机侧的**最后一道**校验：目录必须是系统目录内的绝对路径、ID 必须是已登记的导出器、
/// 周期 / 超时在界内。任何一条不满足就丢弃该项（不是整份拒用 —— 目录表坏了也该用内置值，
/// 而不是让采集停摆）。
fn sanitize(mut policy: ExporterPolicy) -> ExporterPolicy {
    let before_dirs = policy.bin_dirs.len();
    // 去重不能只靠 `dedup()`：它只去**相邻**重复，而数据里的重复很可能不相邻
    // （`/usr/bin` 在前、`/bin` 中间、`/usr/bin` 又在后）。留着就是每次解析多一次 stat。
    let mut seen_dirs: Vec<String> = Vec::new();
    policy.bin_dirs.retain(|dir| {
        is_safe_bin_dir(dir)
            && if seen_dirs.iter().any(|seen| seen == dir) {
                false
            } else {
                seen_dirs.push(dir.clone());
                true
            }
    });
    if policy.bin_dirs.len() > MAX_BIN_DIRS {
        policy.bin_dirs.truncate(MAX_BIN_DIRS);
    }
    if policy.bin_dirs.len() != before_dirs {
        log::warn!(
            "event=ExporterPolicyDirsDropped kept={} dropped={}",
            policy.bin_dirs.len(),
            before_dirs - policy.bin_dirs.len()
        );
    }

    let before_overrides = policy.exporters.len();
    policy.exporters.retain_mut(|row| {
        if crate::telemetry::exporters::def(&row.id).is_none() {
            log::warn!(
                "event=ExporterPolicyOverrideDropped id={} detail=unknown-exporter",
                row.id
            );
            return false;
        }
        let period_ok = row
            .period_secs
            .is_none_or(|value| (MIN_PERIOD_SECS..=MAX_PERIOD_SECS).contains(&value));
        let timeout_ok = row
            .timeout_secs
            .is_none_or(|value| (MIN_TIMEOUT_SECS..=MAX_TIMEOUT_SECS).contains(&value));
        if !period_ok || !timeout_ok {
            log::warn!(
                "event=ExporterPolicyOverrideDropped id={} detail=out-of-range",
                row.id
            );
            return false;
        }
        true
    });
    if policy.exporters.len() != before_overrides {
        log::warn!(
            "event=ExporterPolicyOverridesDropped kept={} dropped={}",
            policy.exporters.len(),
            before_overrides - policy.exporters.len()
        );
    }
    policy
}

fn is_safe_bin_dir(dir: &str) -> bool {
    dir.starts_with('/')
        && !dir.contains("..")
        && !dir
            .chars()
            .any(|ch| matches!(ch, '*' | '?' | '$' | '`' | ';' | '|' | '&' | '\n' | '\r'))
        && dir.len() > 1
        && !dir.ends_with('/')
        && ALLOWED_BIN_DIR_PREFIXES.iter().any(|root| {
            dir == *root
                || dir
                    .strip_prefix(root)
                    .is_some_and(|rest| rest.starts_with('/'))
        })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Returned {
    api_version: String,
    kind: String,
    #[serde(default)]
    exporters_version: i64,
    #[serde(default)]
    platform: String,
    #[serde(default)]
    bin_dirs: Vec<String>,
    #[serde(default)]
    exporters: Vec<ReturnedOverride>,
    /// 网关回的时间戳（审计用）。**必须在这里显式声明** 或者允许未知字段：
    /// 这个结构是 `deny_unknown_fields` 的，网关只要多一个键，整份响应就会被拒 ——
    /// 那就变成“策略永远不生效且只留一行 warn”，而这条路径没有其它验证手段。
    #[serde(default)]
    returned_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReturnedOverride {
    id: String,
    #[serde(default)]
    period_secs: Option<u64>,
    #[serde(default)]
    timeout_secs: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };

    fn policy(dirs: &[&str], overrides: Vec<ExporterOverride>) -> ExporterPolicy {
        ExporterPolicy {
            exporters_version: 1,
            platform: "linux".to_string(),
            bin_dirs: dirs.iter().map(|dir| (*dir).to_string()).collect(),
            exporters: overrides,
            fetched_at: String::new(),
        }
    }

    /// 只回一次响应的假网关（与 `metrics_labels` 同一套思路）：验的是 agent 侧的契约
    /// （请求形状 / 空载 / 404 / 坏响应），而不是真实网关的集成。
    async fn mock_gateway(status: u16, body: String) -> (String, tokio::task::JoinHandle<String>) {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut buf = vec![0u8; 8192];
            let read = tokio::io::AsyncReadExt::read(&mut socket, &mut buf)
                .await
                .expect("read");
            let request = String::from_utf8_lossy(&buf[..read]).to_string();
            let reason = if status == 200 { "OK" } else { "ERR" };
            let response = format!(
                "HTTP/1.1 {status} {reason}\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                body.len()
            );
            tokio::io::AsyncWriteExt::write_all(&mut socket, response.as_bytes())
                .await
                .expect("write");
            request
        });
        (format!("http://{addr}"), handle)
    }

    fn config_for(endpoint: &str, state_dir: &Path) -> AgentConfig {
        let mut config = AgentConfig::new(
            AgentSection {
                agent_id: Some("agent-1".to_string()),
                environment_id: None,
                instance_name: Some("inst-1".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: Some(endpoint.to_string()),
                tls_mode: Some("http".to_string()),
                ..ControlPlaneSection::default()
            },
            PathsSection {
                state_dir: state_dir.display().to_string(),
                ..PathsSection::default()
            },
            ExecutionSection::default(),
        );
        config.control_plane.credential_id = None;
        config
    }

    async fn state_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-exporter-policy-{name}-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("state dir");
        dir
    }

    /// 正常响应：本机再校验一遍（不安全的目录被丢），并落盘。
    #[tokio::test]
    async fn a_good_response_is_applied_and_persisted() {
        let dir = state_dir("apply").await;
        let body = r#"{"api_version":"v1","kind":"exporter_policy",
            "exporters_version":4,"platform":"linux",
            "bin_dirs":["/usr/bin","/tmp/bin","/bin"],
            "exporters":[{"id":"dmesg","period_secs":120}],
            "returned_at":"2026-11-28T00:00:00Z"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;

        let config = config_for(&endpoint, &dir);
        let policy = refresh(&config, &dir).await.expect("applied");
        assert_eq!(policy.exporters_version, 4);
        assert_eq!(
            policy.bin_dirs,
            vec!["/usr/bin".to_string(), "/bin".to_string()],
            "不安全的目录要在本机这一层就被丢掉"
        );
        assert_eq!(policy.exporters.len(), 1);
        assert_eq!(policy.exporters[0].period_secs, Some(120));
        // 落盘：重启后不必等一次拉取。
        assert_eq!(load(&dir).map(|p| p.exporters_version), Some(4));

        let request = server.await.expect("server");
        assert!(
            request.contains("/api/v1/agent/exporter-policy:poll"),
            "{request}"
        );
        assert!(request.contains("exporter_policy"), "{request}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 空载（网关没装知识库 / 旧包没有 exporters.toml）：200 + 空表 → 不应用、不落盘。
    #[tokio::test]
    async fn an_empty_policy_is_not_applied() {
        let dir = state_dir("empty").await;
        let body = r#"{"api_version":"v1","kind":"exporter_policy",
            "exporters_version":0,"platform":"linux","bin_dirs":[],"exporters":[],
            "returned_at":"2026-11-28T00:00:00Z"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;

        let policy = refresh(&config_for(&endpoint, &dir), &dir).await;
        assert!(policy.is_none(), "空载不是错误，但也不该应用");
        assert!(!path_for(&dir).exists(), "空载不该覆盖掉落盘那份");
        let _ = server.await;
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 旧网关没有这个端点（404）/ 服务端错误 / 响应形状不对：都沿用落盘那份。
    #[tokio::test]
    async fn old_gateways_and_bad_responses_are_ignored() {
        let dir = state_dir("ignored").await;
        // 先有一份落盘的值，才能验“失败不清空”。
        let before = policy(&["/usr/bin"], Vec::new());
        std::fs::write(
            path_for(&dir),
            serde_json::to_vec(&before).expect("serialize"),
        )
        .expect("write");

        for (status, body) in [
            (404u16, String::new()),
            (500, "boom".to_string()),
            (200, "{not json".to_string()),
            (
                200,
                r#"{"api_version":"v1","kind":"something_else",
                    "exporters_version":4,"bin_dirs":["/bin"],"exporters":[]}"#
                    .to_string(),
            ),
        ] {
            let (endpoint, server) = mock_gateway(status, body).await;
            let outcome = refresh(&config_for(&endpoint, &dir), &dir).await;
            assert!(outcome.is_none(), "status={status} 不该被应用");
            let _ = server.await;
            // 落盘那份还在、内容未变。
            assert_eq!(
                load(&dir),
                Some(policy(&["/usr/bin"], Vec::new())),
                "status={status} 不该动落盘那份"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn unsafe_dirs_and_unknown_ids_are_dropped_not_fatal() {
        let cleaned = sanitize(policy(
            &[
                "/usr/bin",
                "/tmp/bin",
                "/bin",
                // 非相邻重复：`dedup()` 去不掉，必须显式去。
                "/usr/bin",
                "relative",
                "/usr/bin/../x",
            ],
            vec![
                ExporterOverride {
                    id: "dmesg".to_string(),
                    period_secs: Some(120),
                    timeout_secs: None,
                },
                ExporterOverride {
                    id: "rm-rf".to_string(),
                    period_secs: Some(120),
                    timeout_secs: None,
                },
                ExporterOverride {
                    id: "smartctl".to_string(),
                    period_secs: Some(1),
                    timeout_secs: None,
                },
            ],
        ));
        assert_eq!(
            cleaned.bin_dirs,
            vec!["/usr/bin".to_string(), "/bin".to_string()]
        );
        assert_eq!(cleaned.exporters.len(), 1);
        assert_eq!(cleaned.exporters[0].id, "dmesg");
    }

    #[test]
    fn the_state_file_round_trips_and_bad_files_are_ignored() {
        let dir = std::env::temp_dir().join(format!(
            "wist-exporter-policy-{}-{}",
            std::process::id(),
            crate::telemetry::exporters::now_ms()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        assert!(load(&dir).is_none());

        let policy = policy(&["/usr/bin"], Vec::new());
        std::fs::write(
            path_for(&dir),
            serde_json::to_vec(&policy).expect("serialize"),
        )
        .expect("write");
        assert_eq!(load(&dir), Some(policy));

        std::fs::write(path_for(&dir), b"{not json").expect("write bad");
        assert!(load(&dir).is_none(), "坏文件当作没有，而不是让启动失败");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
