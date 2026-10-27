//! L3 受限搜索的**生效 roots**：从网关拉取、落盘、供解析使用。
//!
//! ## 为什么 agentd 侧没有配置
//!
//! 搜索等于允许一个 root 进程**枚举**客户机的目录。这件事不该由主机上的一个配置文件
//! 决定（谁有 root 谁能放宽），也不该让运维逐台改。所以口径是：
//!
//! ```text
//! 生效 roots = 知识库 [[units]] search_roots（签名产物，舰队上限）
//!            ∩ [collection] allowed_source_roots（部署侧采集授权）
//! ```
//!
//! 交集由**网关**算好（`api/source_search_policy.rs`），agentd 只应用，不再判定。
//!
//! ## 拿不到怎么办
//!
//! **不搜索**（fail-closed），行为与 L2b 完全一致：
//!
//! * 网关没有这个端点（旧网关，404）→ 静默跳过；
//! * 网关不可达 / 响应坏 → 保留**上一份**已落盘的策略（重启后也还在），只在日志里记一笔。
//!
//! 为什么保留上一份而不是清空：策略是“允许去哪儿找”，不是“数据”；断网期间清空会让
//! 本已定位到的日志突然消失（候选被替换掉），而它并没有变。

use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wist_contracts::API_VERSION_V1;
use wist_shared::time::now_rfc3339;

use crate::config::agent_config::AgentConfig;
use crate::control::enrollment::enrollment_http_client;
use crate::fs_async::write_json_atomic_async;

/// 与网关约定的 `kind`（网关侧同名常量在 `api/source_search_policy.rs`）。
const POLL_KIND: &str = "source_search_policy";

/// 落盘文件名（在 `paths.state_dir` 下）。
const STATE_FILE: &str = "source_search_policy.json";

/// 拉策略的超时。
///
/// 这条路径在**主循环**里（每 3s 一拍、按 5min 节流）—— 必须自己封顶，不能吃掉 tick。
/// 与发现策略表同一取舍（那里也是 5s）。
const FETCH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// 与网关同值的安全阈值（`search` 里也是它，只留一份，避免两处漂移）。
const MAX_ROOTS_PER_SERVICE: usize = crate::discovery::log_source::search::MAX_SEARCH_ROOTS;

/// 一台机器上**实际生效**的搜索范围。
///
/// `services` 为空 = 不搜索 —— 这是缺省状态，也是旧网关下的唯一状态。
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceSearchPolicy {
    /// 这份 roots 来自知识库的哪一版（0 = 网关空载 / 未知）。
    #[serde(default)]
    pub catalog_version: i64,
    /// 服务 → roots（网关已经算好交集，agent 不再判定）。
    #[serde(default)]
    pub services: BTreeMap<String, Vec<String>>,
    /// 最后一次成功拉取的时刻（给人看/审计）。
    #[serde(default)]
    pub fetched_at: String,
}

impl SourceSearchPolicy {
    /// 这个服务的搜索范围；不在策略里 = 空切片（不搜）。
    pub fn roots_for(&self, service: &str) -> &[String] {
        self.services
            .get(service)
            .map(Vec::as_slice)
            .unwrap_or_default()
    }

    /// 这台机器上到底要不要搜索。
    pub fn is_empty(&self) -> bool {
        self.services.is_empty()
    }

    /// 把“服务 → 生效 roots”渲染成一行（日志 / 诊断用）。
    pub fn describe(&self) -> String {
        if self.services.is_empty() {
            return "不搜索".to_string();
        }
        self.services
            .iter()
            .map(|(service, roots)| format!("{service}=[{}]", roots.join(",")))
            .collect::<Vec<_>>()
            .join(" ")
    }
}

pub fn path_for(state_dir: &Path) -> PathBuf {
    state_dir.join(STATE_FILE)
}

/// 读上次落盘的策略。缺失 / 坏 JSON / 越界值都按“不搜索”处理并留一行日志。
pub fn load(state_dir: &Path) -> SourceSearchPolicy {
    let path = path_for(state_dir);
    let text = match std::fs::read_to_string(&path) {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return SourceSearchPolicy::default();
        }
        Err(err) => {
            log::warn!(
                "source search policy: read {} failed: {err}",
                path.display()
            );
            return SourceSearchPolicy::default();
        }
    };
    parse(&path, &text)
}

/// 同上，异步版（上报路径上用，不阻塞运行时工作线程）。
pub async fn load_async(state_dir: &Path) -> SourceSearchPolicy {
    let path = path_for(state_dir);
    let text = match tokio::fs::read_to_string(&path).await {
        Ok(text) => text,
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
            return SourceSearchPolicy::default();
        }
        Err(err) => {
            log::warn!(
                "source search policy: read {} failed: {err}",
                path.display()
            );
            return SourceSearchPolicy::default();
        }
    };
    parse(&path, &text)
}

fn parse(path: &Path, text: &str) -> SourceSearchPolicy {
    match serde_json::from_str::<SourceSearchPolicy>(text) {
        Ok(policy) => sanitize(policy),
        Err(err) => {
            // 坏文件不该让守护进程起不来：当作“还没拉到过”。
            log::warn!(
                "event=SourceSearchPolicyUnreadable path={} detail={err}",
                path.display()
            );
            SourceSearchPolicy::default()
        }
    }
}

/// 拉一次策略；成功则落盘并返回。
///
/// 返回 `None` 的全部含义都是“这一拍没有新策略，沿用上一份”：
/// 未入网、旧网关（404）、网络失败、响应坏。
pub(crate) async fn refresh(config: &AgentConfig, state_dir: &Path) -> Option<SourceSearchPolicy> {
    let endpoint = config.control_plane.endpoint.as_deref()?;
    let agent_id = config.agent.agent_id.as_deref()?;
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            log::warn!("source search policy: failed to build client: {err}");
            return None;
        }
    };
    let url = format!(
        "{}/api/v1/agent/source-search-policy:poll",
        endpoint.trim_end_matches('/')
    );
    let request = serde_json::json!({
        "api_version": API_VERSION_V1,
        "kind": POLL_KIND,
        "agent_id": agent_id,
        "instance_id": instance_id,
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
            log::warn!("source search policy: request {url} failed: {err}");
            return None;
        }
    };
    // 旧网关没这个端点：等同“这个部署不支持 L3”，静默。
    if response.status() == reqwest::StatusCode::NOT_FOUND {
        log::debug!("source search policy: gateway has no {url} (old gateway), skipping");
        return None;
    }
    if !response.status().is_success() {
        log::warn!(
            "source search policy: HTTP {} from {url}",
            response.status()
        );
        return None;
    }
    let returned: Returned = match response.json().await {
        Ok(returned) => returned,
        Err(err) => {
            log::warn!("source search policy: invalid response from {url}: {err}");
            return None;
        }
    };
    // 契约漂移不能静默应用：这两个字段就是“我拿到的是不是我以为的那份”的全部依据。
    if returned.api_version != API_VERSION_V1 || returned.kind != POLL_KIND {
        log::warn!(
            "source search policy: unexpected response (api_version={:?} kind={:?}) from {url}",
            returned.api_version,
            returned.kind
        );
        return None;
    }
    let policy = sanitize(SourceSearchPolicy {
        catalog_version: returned.catalog_version,
        services: returned
            .services
            .into_iter()
            .map(|row| (row.service, row.roots))
            .collect(),
        fetched_at: now_rfc3339(),
    });
    if let Err(err) = write_json_atomic_async(&path_for(state_dir), &policy).await {
        // 落盘失败不影响本拍生效（调用方手里已经有这份了），但要让现场能查到。
        log::warn!("source search policy: write state failed: {err}");
    }
    log::info!(
        "event=SourceSearchPolicyApplied catalog_version={} services={} roots=\"{}\"",
        policy.catalog_version,
        policy.services.len(),
        policy.describe()
    );
    Some(policy)
}

/// 逐项复核网关给的值。
///
/// 网关是权威，但这里是**纵深防御**：一份被篡改/写坏的策略不该让 agentd 去枚举 `/`。
/// 越界条目逐条丢弃（不是整份丢弃 —— 一个坏 root 不该让其它 root 失效）。
fn sanitize(mut policy: SourceSearchPolicy) -> SourceSearchPolicy {
    let mut cleaned = BTreeMap::new();
    for (service, roots) in std::mem::take(&mut policy.services) {
        let mut kept: Vec<String> = Vec::new();
        for root in roots {
            let value = root.trim();
            if value.starts_with('/')
                && value != "/"
                && !value.split('/').any(|segment| segment == "..")
                && !value.contains(['*', '?', '[', '\0'])
            {
                let normalized = value.trim_end_matches('/').to_string();
                if !kept.contains(&normalized) {
                    kept.push(normalized);
                }
            } else {
                log::warn!(
                    "event=SourceSearchRootRejected service={service} root={value:?} reason=invalid"
                );
            }
        }
        if kept.is_empty() {
            continue;
        }
        if kept.len() > MAX_ROOTS_PER_SERVICE {
            log::warn!(
                "event=SourceSearchRootsTruncated service={service} kept={}",
                kept.len()
            );
            kept.truncate(MAX_ROOTS_PER_SERVICE);
        }
        cleaned.insert(service, kept);
    }
    policy.services = cleaned;
    policy
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct Returned {
    #[serde(default)]
    api_version: String,
    #[serde(default)]
    kind: String,
    #[serde(default)]
    catalog_version: i64,
    #[serde(default)]
    services: Vec<ServiceRow>,
    #[serde(default)]
    #[allow(dead_code)]
    returned_at: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ServiceRow {
    service: String,
    #[serde(default)]
    roots: Vec<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(services: &[(&str, &[&str])]) -> SourceSearchPolicy {
        SourceSearchPolicy {
            catalog_version: 15,
            services: services
                .iter()
                .map(|(service, roots)| {
                    (
                        (*service).to_string(),
                        roots.iter().map(|root| (*root).to_string()).collect(),
                    )
                })
                .collect(),
            fetched_at: String::new(),
        }
    }

    #[test]
    fn roots_for_an_unknown_service_is_empty() {
        let policy = policy(&[("postgresql", &["/data"])]);
        assert_eq!(policy.roots_for("postgresql"), ["/data".to_string()]);
        assert!(policy.roots_for("mysql").is_empty());
        assert!(!policy.is_empty());
        assert!(SourceSearchPolicy::default().is_empty());
    }

    #[test]
    fn sanitize_drops_dangerous_roots_but_keeps_the_rest() {
        let cleaned = sanitize(policy(&[(
            "postgresql",
            &["/", "/data/", "relative", "/data/../etc", "/srv", "/data/*"],
        )]));
        assert_eq!(
            cleaned.roots_for("postgresql"),
            ["/data".to_string(), "/srv".to_string()],
            "只留合法目录，且归一为无尾斜杠"
        );
    }

    #[test]
    fn sanitize_removes_a_service_whose_roots_are_all_bad() {
        let cleaned = sanitize(policy(&[("mysql", &["/", "relative"])]));
        assert!(
            cleaned.is_empty(),
            "一个合法 root 都没有 = 这个服务不搜，而不是搜 `/`"
        );
    }

    #[test]
    fn sanitize_caps_the_roots_per_service() {
        let many: Vec<&str> = (0..=MAX_ROOTS_PER_SERVICE).map(|_| "/data").collect();
        // 全是同一个值也不该放过：先归一再去重，剩下的才是真的条数。
        let cleaned = sanitize(policy(&[("redis", &many)]));
        assert_eq!(cleaned.roots_for("redis").len(), 1);
    }

    #[test]
    fn describe_is_human_readable() {
        assert_eq!(SourceSearchPolicy::default().describe(), "不搜索");
        let policy = policy(&[("postgresql", &["/data"]), ("redis", &["/srv"])]);
        assert_eq!(policy.describe(), "postgresql=[/data] redis=[/srv]");
    }

    #[test]
    fn load_missing_file_means_no_search() {
        let dir = std::env::temp_dir().join(format!(
            "wist-ssp-load-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create dir");
        assert!(load(&dir).is_empty());

        // 坏 JSON 同样按“不搜索”处理（不让守护进程起不来）。
        std::fs::write(path_for(&dir), b"{not json").expect("write");
        assert!(load(&dir).is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn a_persisted_policy_validates_against_itself() {
        // 落盘格式与线上响应同一形状：字段名漂移会让重启后读不回来。
        let text = serde_json::to_string(&policy(&[("postgresql", &["/data"])])).expect("encode");
        let keys: Vec<String> = serde_json::from_str::<serde_json::Value>(&text)
            .expect("decode")
            .as_object()
            .expect("object")
            .keys()
            .cloned()
            .collect();
        let mut keys = keys;
        keys.sort();
        assert_eq!(keys, ["catalog_version", "fetched_at", "services"]);
    }
}
