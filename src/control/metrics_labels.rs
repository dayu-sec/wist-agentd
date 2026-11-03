//! 选择类 label（`env` / `cluster` / `app` / …）：从网关拉取、落盘、供指标贴标使用。
//!
//! ## 为什么 agentd 侧没有配置
//!
//! label 的值分三层，全在控制面（见 `wist-agentd/docs/design/metrics-selection-labels.md`）：
//!
//! ```text
//! 生效值 = 部署默认（网关配置 [agent.metrics_labels]）
//!        ∪ 推断（网关按事实判定；本阶段为空）
//!        ∪ 每 agent 手工覆盖（管理面写入）
//! ```
//!
//! 合并与校验都在网关做完，agentd 只做**复核 + 缓存**。本机配置里的 `[metrics.labels]`
//! 已废弃（仍可解析、不再生效，见 `crate::config`），所以「谁有 root 谁能改标签」这条
//! 旁路没有了。
//!
//! ## 拿不到怎么办
//!
//! 沿用**上一份已落盘的**值（重启后也还在）；连缓存都没有 → 指标不带选择类 label。
//! 为什么保留旧值而不是清空：选择类 label 是**筛选维度**，断网期间清空会让「这台机器的
//! 序列」在时间轴上凭空断成两段，而这台机器什么都没变。
//!
//! ## 为什么整包拒收
//!
//! 逐键丢弃会让一份坏响应悄悄生效一半 —— 序列按一半维度分段，比彻底不生效更难查。
//! 所以只要有一个键/值不合法，整包拒绝并保留旧缓存。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wist_api::metrics_labels::{
    AgentMetricsLabels, PollAgentMetricsLabels, label_source, rules::validate_labels,
};
use wist_shared::time::now_rfc3339;

use crate::config::agent_config::AgentConfig;
use crate::control::enrollment::enrollment_http_client;
use crate::fs_async::write_json_atomic_async;

/// 落盘文件名（在 `paths.state_dir/metrics/` 下）。
const STATE_FILE: &str = "labels.json";

/// 拉取超时。这条路径在主循环里（3s 一拍、5min 节流），必须自己封顶。
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// 一次拉取的结果（用于命令台账逐项记账）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RefreshOutcome {
    /// 拿到了，且与上一份不同（已落盘）。
    Updated,
    /// 拿到了，但与上一份相同（不重写文件）。
    Unchanged,
    /// 没拿到（未入网 / 旧网关 404 / 网络失败 / 响应非法）。缓存原样保留。
    Failed(String),
}

impl RefreshOutcome {
    pub fn as_str(&self) -> &'static str {
        match self {
            RefreshOutcome::Updated => "updated",
            RefreshOutcome::Unchanged => "unchanged",
            RefreshOutcome::Failed(_) => "failed",
        }
    }
}

/// 本地缓存：**网关给的**那份值（不是合并结果 —— 合并只在网关做）。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CachedMetricsLabels {
    /// 网关侧的版本；没有缓存时视为 0。
    #[serde(default)]
    pub revision: u64,
    /// 生效值。
    #[serde(default)]
    pub labels: BTreeMap<String, String>,
    /// 每个键的来源（`default` / `inferred` / `manual`），只用于展示。
    #[serde(default)]
    pub sources: BTreeMap<String, String>,
    /// 最后一次成功拉取的时刻。
    #[serde(default)]
    pub fetched_at: String,
}

impl CachedMetricsLabels {
    pub fn is_empty(&self) -> bool {
        self.labels.is_empty()
    }

    /// 渲染成一行（`show` / 日志用）：`env=prod(default) cluster=kafka(default)`。
    pub fn describe(&self) -> String {
        if self.labels.is_empty() {
            return "（无选择类 label）".to_string();
        }
        let mut parts = Vec::new();
        for (key, value) in &self.labels {
            match self.sources.get(key) {
                Some(source) => parts.push(format!("{key}={value}({source})")),
                None => parts.push(format!("{key}={value}")),
            }
        }
        parts.join(" ")
    }

    /// 打印用多行文本（`metrics-labels show`）。
    pub fn render(&self) -> String {
        if self.labels.is_empty() {
            return "no selection labels (gateway returned an empty set, or nothing fetched yet)\n"
                .to_string();
        }
        let mut out = format!("revision = {}\n", self.revision);
        if !self.fetched_at.is_empty() {
            out.push_str(&format!("fetched_at = {}\n", self.fetched_at));
        }
        for (key, value) in &self.labels {
            let source = self.sources.get(key).map(String::as_str).unwrap_or("-");
            out.push_str(&format!("{key} = {value}    (source: {source})\n"));
        }
        out
    }
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join("metrics").join(STATE_FILE)
}

/// 读缓存。缺失 / 坏 JSON / 值不合法都按「没有缓存」处理并留一行日志 ——
/// 一个坏文件不该让指标带着越界 label 出去，也不该让守护进程起不来。
pub fn load(state_dir: &Path) -> CachedMetricsLabels {
    let path = path_for(state_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return CachedMetricsLabels::default();
        }
        Err(err) => {
            log::warn!("metrics labels: read {} failed: {err}", path.display());
            return CachedMetricsLabels::default();
        }
    };
    parse(&path, &text)
}

fn parse(path: &Path, text: &str) -> CachedMetricsLabels {
    match serde_json::from_str::<CachedMetricsLabels>(text) {
        Ok(cached) => {
            // 文件可能被人手工改过（或来自旧版本）。复核与网关响应同一套规则。
            if let Err(err) = validate_labels(&cached.labels) {
                log::warn!(
                    "event=MetricsLabelsCacheRejected path={} reason={} detail=\"{err}\"",
                    path.display(),
                    err.code()
                );
                return CachedMetricsLabels::default();
            }
            cached
        }
        Err(err) => {
            log::warn!(
                "event=MetricsLabelsCacheUnreadable path={} detail={err}",
                path.display()
            );
            CachedMetricsLabels::default()
        }
    }
}

/// 删除缓存（`metrics-labels clear-cache`）。守护进程内存里的那份要等重启才清，
/// 所以命令文案必须说清这一点。
pub fn clear_cache(state_dir: &Path) -> std::io::Result<bool> {
    match std::fs::remove_file(path_for(state_dir)) {
        Ok(()) => Ok(true),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(err) => Err(err),
    }
}

/// 拉一次；成功则落盘。返回这一拍的结果（`Failed` 不覆盖磁盘）。
pub(crate) async fn refresh(
    config: &AgentConfig,
    state_dir: &Path,
    previous: &CachedMetricsLabels,
) -> RefreshOutcome {
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return RefreshOutcome::Failed("control_plane.endpoint 未配置".to_string());
    };
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return RefreshOutcome::Failed("agent_id 未配置（尚未入网）".to_string());
    };
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => return RefreshOutcome::Failed(format!("build client: {err}")),
    };
    let url = format!(
        "{}/api/v1/agent/metrics-labels:poll",
        endpoint.trim_end_matches('/')
    );
    let request = PollAgentMetricsLabels::new(agent_id, instance_id, &now_rfc3339());
    let response = match client
        .post(&url)
        .timeout(FETCH_TIMEOUT)
        .json(&request)
        .send()
        .await
    {
        Ok(response) => response,
        Err(err) => return RefreshOutcome::Failed(format!("request {url}: {err}")),
    };
    // 旧网关没这个端点：等同「这个部署还没有选择类 label」，静默沿用旧值。
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        log::debug!("metrics labels: gateway has no {url} (old gateway), keeping cache");
        return RefreshOutcome::Unchanged;
    }
    if !response.status().is_success() {
        return RefreshOutcome::Failed(format!("HTTP {} from {url}", response.status()));
    }
    let returned: AgentMetricsLabels = match response.json().await {
        Ok(returned) => returned,
        Err(err) => return RefreshOutcome::Failed(format!("invalid response from {url}: {err}")),
    };
    if returned.agent_id != agent_id {
        return RefreshOutcome::Failed(format!(
            "response is for another agent ({} != {agent_id})",
            returned.agent_id
        ));
    }
    // 规则与网关同一份：这里只复核“我拿到的值能不能贴出去”。
    if let Err(err) = validate_labels(&returned.labels) {
        return RefreshOutcome::Failed(format!("invalid labels ({}): {err}", err.code()));
    }
    let next = CachedMetricsLabels {
        revision: returned.revision,
        labels: returned.labels,
        sources: returned.sources,
        fetched_at: now_rfc3339(),
    };
    if next.labels == previous.labels && next.revision == previous.revision {
        return RefreshOutcome::Unchanged;
    }
    if let Err(err) = write_json_atomic_async(&path_for(state_dir), &next).await {
        // 落盘失败不影响本拍生效（调用方手里已经有这份），但要让现场能查到。
        log::warn!("metrics labels: write state failed: {err}");
    }
    log::info!(
        "event=MetricsLabelsApplied revision={} labels=\"{}\"",
        next.revision,
        next.describe()
    );
    RefreshOutcome::Updated
}

/// 把「拉到的值」写回配置快照，供既有采集/上送路径使用。
///
/// 为什么改 `config.metrics.labels` 而不是给采集链加一个参数：那条链上已有 20+ 处
/// `config.metrics.labels` 的读点，逐个穿参只会让「有的地方用新值、有的地方用旧值」
/// 变成可能。这里改的是**进程内的运行时快照**，配置文件一个字节都不动。
pub(crate) fn apply(config: &mut AgentConfig, labels: &CachedMetricsLabels) {
    config.metrics.labels = labels.labels.clone();
}

/// 来源词表里有没有 `manual`（诊断用：告诉人「这个值是网关那边手工定的」）。
pub fn has_manual(labels: &CachedMetricsLabels) -> bool {
    labels
        .sources
        .values()
        .any(|source| source == label_source::MANUAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };

    /// 一个只回一次响应的假网关：读到请求头 + body 后按给定状态码/正文回。
    ///
    /// 为什么不用真实网关：这条路径要验的是**agent 侧**的契约（请求形状 / 整包拒收 /
    /// 缓存保留），拿一个真实网关会把失败面摊薄成集成问题。
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
            "wist-metrics-labels-{name}-{}-{}",
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

    fn cache(pairs: &[(&str, &str)]) -> CachedMetricsLabels {
        CachedMetricsLabels {
            revision: 3,
            labels: pairs
                .iter()
                .map(|(key, value)| ((*key).to_string(), (*value).to_string()))
                .collect(),
            sources: BTreeMap::new(),
            fetched_at: "2026-11-03T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn describe_renders_every_key_with_its_source() {
        let mut labels = cache(&[("env", "prod"), ("cluster", "kafka-prod")]);
        labels
            .sources
            .insert("env".to_string(), label_source::DEFAULT.to_string());
        labels
            .sources
            .insert("cluster".to_string(), label_source::MANUAL.to_string());
        assert_eq!(
            labels.describe(),
            "cluster=kafka-prod(manual) env=prod(default)"
        );
    }

    #[test]
    fn an_empty_cache_describes_itself_instead_of_printing_nothing() {
        assert!(cache(&[]).describe().contains("无选择类 label"));
        assert!(
            CachedMetricsLabels::default()
                .render()
                .contains("no selection labels")
        );
    }

    #[test]
    fn render_lists_keys_with_sources_for_the_cli() {
        let mut labels = cache(&[("env", "prod")]);
        labels
            .sources
            .insert("env".to_string(), label_source::MANUAL.to_string());
        let text = labels.render();
        assert!(text.contains("revision = 3"));
        assert!(text.contains("env = prod"));
        assert!(text.contains("source: manual"));
    }

    #[test]
    fn a_corrupt_or_invalid_cache_is_treated_as_absent() {
        let path = Path::new("/tmp/whatever.json");
        // 坏 JSON。
        assert_eq!(parse(path, "{not json"), CachedMetricsLabels::default());
        // 合法 JSON 但值越界（大写不在值文法里）：整包丢弃，不带着它贴标。
        let text = r#"{"revision":1,"labels":{"env":"Prod"},"sources":{},"fetched_at":"t"}"#;
        assert_eq!(parse(path, text), CachedMetricsLabels::default());
        // 正常的一份能读回来。
        let text = r#"{"revision":2,"labels":{"env":"prod"},"sources":{"env":"default"},"fetched_at":"t"}"#;
        let parsed = parse(path, text);
        assert_eq!(parsed.revision, 2);
        assert_eq!(parsed.labels.get("env").map(String::as_str), Some("prod"));
    }

    #[test]
    fn has_manual_only_reports_manual_sources() {
        let mut labels = cache(&[("env", "prod")]);
        labels
            .sources
            .insert("env".to_string(), label_source::DEFAULT.to_string());
        assert!(!has_manual(&labels));
        labels
            .sources
            .insert("env".to_string(), label_source::MANUAL.to_string());
        assert!(has_manual(&labels));
    }

    #[test]
    fn apply_overwrites_only_the_runtime_snapshot() {
        let mut config = AgentConfig::new(
            crate::config::agent_config::AgentSection::default(),
            crate::config::agent_config::ControlPlaneSection::default(),
            crate::config::agent_config::PathsSection::default(),
            crate::config::agent_config::ExecutionSection::default(),
        );
        config
            .metrics
            .labels
            .insert("stale".to_string(), "value".to_string());
        apply(&mut config, &cache(&[("env", "prod")]));
        assert_eq!(
            config.metrics.labels,
            BTreeMap::from([("env".to_string(), "prod".to_string())])
        );
    }

    #[tokio::test]
    async fn a_valid_response_is_applied_and_cached() {
        let dir = state_dir("apply").await;
        let body = r#"{"api_version":"v1","kind":"agent_metrics_labels","agent_id":"agent-1",
            "revision":7,"labels":{"env":"prod","cluster":"kafka-prod","app":"kafka"},
            "sources":{"env":"default","cluster":"default","app":"inferred"},
            "updated_at":"2026-11-03T00:00:00Z"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;

        let config = config_for(&endpoint, &dir);
        let outcome = refresh(&config, &dir, &CachedMetricsLabels::default()).await;
        assert_eq!(outcome, RefreshOutcome::Updated);
        assert_eq!(outcome.as_str(), "updated");

        // 请求形状：这是与网关的契约（路径 + 两个身份字段都在请求体里）。
        let request = server.await.expect("server");
        assert!(
            request.starts_with("POST /api/v1/agent/metrics-labels:poll "),
            "{request}"
        );
        assert!(request.contains("\"agent_id\":\"agent-1\""), "{request}");
        assert!(request.contains("\"instance_id\":\"inst-1\""), "{request}");

        // 缓存已落盘，且与响应一致。
        let cached = load(&dir);
        assert_eq!(cached.revision, 7);
        assert_eq!(cached.labels.get("app").map(String::as_str), Some("kafka"));
        assert_eq!(
            cached.sources.get("app").map(String::as_str),
            Some("inferred")
        );
        assert!(!has_manual(&cached), "全是网关默认值，没有人手工覆盖");
    }

    #[tokio::test]
    async fn an_unchanged_response_does_not_rewrite_the_cache() {
        let dir = state_dir("unchanged").await;
        let previous = cache(&[("env", "prod")]);
        let body = r#"{"api_version":"v1","kind":"agent_metrics_labels","agent_id":"agent-1",
            "revision":3,"labels":{"env":"prod"},"sources":{"env":"default"},"updated_at":"t"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;

        let config = config_for(&endpoint, &dir);
        let outcome = refresh(&config, &dir, &previous).await;
        let _ = server.await;
        // revision 与内容都没变 → 不重写文件（避免每 5 分钟一次无意义写盘）。
        assert_eq!(outcome, RefreshOutcome::Unchanged);
        assert!(!path_for(&dir).exists(), "内容没变就不该留下缓存文件");
    }

    #[tokio::test]
    async fn an_illegal_response_is_rejected_as_a_whole_and_the_cache_survives() {
        let dir = state_dir("illegal").await;
        // 一个越界的值就够了：整包拒收，而不是贴一半（半套 label 会让序列按一半维度分段）。
        let body = r#"{"api_version":"v1","kind":"agent_metrics_labels","agent_id":"agent-1",
            "revision":9,"labels":{"env":"Prod"},"sources":{},"updated_at":"t"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;

        let config = config_for(&endpoint, &dir);
        let outcome = refresh(&config, &dir, &cache(&[("env", "prod")])).await;
        let _ = server.await;
        match outcome {
            RefreshOutcome::Failed(detail) => assert!(
                detail.contains("invalid_metric_label_value"),
                "失败原因要带稳定码：{detail}"
            ),
            other => panic!("expected Failed, got {other:?}"),
        }
        assert!(!path_for(&dir).exists(), "非法响应不能落盘");
    }

    #[tokio::test]
    async fn a_response_for_another_agent_is_rejected() {
        // 防串台：网关若回错人（缓存/代理串了），把这台机器标成别人的用途是最坏的结果。
        let dir = state_dir("wrong-agent").await;
        let body = r#"{"api_version":"v1","kind":"agent_metrics_labels","agent_id":"agent-2",
            "revision":1,"labels":{"app":"kafka"},"sources":{},"updated_at":"t"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;
        let config = config_for(&endpoint, &dir);
        let outcome = refresh(&config, &dir, &CachedMetricsLabels::default()).await;
        let _ = server.await;
        assert!(matches!(outcome, RefreshOutcome::Failed(_)), "{outcome:?}");
        assert!(!path_for(&dir).exists());
    }

    #[tokio::test]
    async fn an_old_gateway_without_the_endpoint_counts_as_no_change() {
        // 旧网关没有这个端点：等同「这个部署还没有选择类 label」，
        // 不能算失败（否则每 5 分钟一条告警）。
        let dir = state_dir("old-gateway").await;
        let (endpoint, server) = mock_gateway(404, "{}".to_string()).await;
        let config = config_for(&endpoint, &dir);
        let outcome = refresh(&config, &dir, &CachedMetricsLabels::default()).await;
        let _ = server.await;
        assert_eq!(outcome, RefreshOutcome::Unchanged);
    }

    #[tokio::test]
    async fn an_empty_label_set_is_applied_as_a_real_change() {
        // 网关把值清空（例如运维删掉了部署默认）→ 必须真的把缓存清空，
        // 否则指标会一直带着已经不存在的 label。
        let dir = state_dir("cleared").await;
        let body = r#"{"api_version":"v1","kind":"agent_metrics_labels","agent_id":"agent-1",
            "revision":4,"labels":{},"updated_at":"t"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;
        let config = config_for(&endpoint, &dir);
        let outcome = refresh(&config, &dir, &cache(&[("env", "prod")])).await;
        let _ = server.await;
        assert_eq!(outcome, RefreshOutcome::Updated);
        assert!(load(&dir).labels.is_empty());
    }

    #[tokio::test]
    async fn a_lower_revision_with_different_content_still_wins() {
        // 版本号只是提示：网关库回滚/重建后 revision 会变小，内容才是事实。
        // 只比版本会让这台机器永远停在「更大的那一版」上。
        let dir = state_dir("lower-rev").await;
        let body = r#"{"api_version":"v1","kind":"agent_metrics_labels","agent_id":"agent-1",
            "revision":2,"labels":{"app":"redis"},"sources":{},"updated_at":"t"}"#;
        let (endpoint, server) = mock_gateway(200, body.to_string()).await;
        let config = config_for(&endpoint, &dir);
        let previous = CachedMetricsLabels {
            revision: 9,
            labels: [("app".to_string(), "kafka".to_string())]
                .into_iter()
                .collect(),
            ..CachedMetricsLabels::default()
        };
        let outcome = refresh(&config, &dir, &previous).await;
        let _ = server.await;
        assert_eq!(outcome, RefreshOutcome::Updated);
        assert_eq!(
            load(&dir).labels.get("app").map(String::as_str),
            Some("redis")
        );
    }

    #[tokio::test]
    async fn without_an_endpoint_or_identity_the_fetch_fails_instead_of_panicking() {
        let dir = state_dir("unconfigured").await;
        let mut config = config_for("http://127.0.0.1:1", &dir);
        config.agent.agent_id = None;
        let outcome = refresh(&config, &dir, &CachedMetricsLabels::default()).await;
        assert!(matches!(outcome, RefreshOutcome::Failed(_)), "{outcome:?}");

        let mut config = config_for("http://127.0.0.1:1", &dir);
        config.control_plane.endpoint = None;
        let outcome = refresh(&config, &dir, &CachedMetricsLabels::default()).await;
        assert!(matches!(outcome, RefreshOutcome::Failed(_)), "{outcome:?}");
    }
}
