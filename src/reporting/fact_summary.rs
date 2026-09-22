//! 事实**摘要**：把采集到的发现快照机械压缩成「推得动用途」的最小集合。
//!
//! 为什么压缩放在 agentd：压缩是**机械操作**（去重 + 只留推断要用的字段），
//! 不需要知道规则表，所以策展知识不必下放。原文快照照旧走数据面给中心做资产整理。
//!
//! 幂等键是内容摘要，不是 discovery 的 revision（后者每轮 refresh 无条件 +1）。

use std::collections::BTreeSet;

use ring::digest;
use serde::{Deserialize, Serialize};
use wist_contracts::discovery::{DiscoveredResource, DiscoverySnapshot};

/// `DiscoveredResource::kind`：进程（与 `ProcessDiscoveryProbe` 写入的值一致）。
const PROCESS_KIND: &str = "process";
/// `DiscoveredResource::kind`：监听端点（与 `EndpointDiscoveryProbe` 写入的值一致）。
const ENDPOINT_KIND: &str = "service_endpoint";

/// 进程可执行标识的属性名。
///
/// 注意这个属性名与语义并不完全一致：macOS 侧 `ps -axo comm=` 实际给的是**完整路径**，
/// Linux 侧读 `/proc/{pid}/comm` 只有 basename。所以规则表里 `process_path` 类规则
/// 目前只在 macOS 上成立（显式化 `process.executable.path` 记在 B119）。
const PROCESS_EXECUTABLE: &str = "process.executable.name";
/// 监听端口的属性名。
const ENDPOINT_PORT: &str = "endpoint.bind.port";

/// 可上报的事实摘要（对应模型 `Control.AgentFactSummary` 的可上报部分）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSummaryDraft {
    /// 快照 revision：**仅留痕**，不进内容摘要。
    pub revision: i64,
    /// 事实是什么时候观察到（快照生成时间）：**仅留痕**，不进内容摘要。
    pub observed_at: String,
    pub os: String,
    pub arch: String,
    /// 去重前的进程条数（去重会毁掉基数，留一个原始计数备查）。不进内容摘要。
    pub process_count: i64,
    pub process_executables: Vec<String>,
    pub packages: Vec<String>,
    pub listen_ports: Vec<String>,
}

/// 内容摘要的规范化视图。
///
/// **刻意不含** `revision` / `observed_at` / `process_count`：
/// 前两者每轮 refresh 都变，后者随无关进程生灭一直动 —— 放进摘要等于每轮都变，
/// 幂等就失效了。摘要表达的是「内容」，不是「哪一次采的」。
#[derive(Serialize)]
struct DigestView<'a> {
    os: &'a str,
    arch: &'a str,
    process_executables: &'a [String],
    packages: &'a [String],
    listen_ports: &'a [String],
}

/// 从发现快照压出摘要。
///
/// 去重靠 `BTreeSet`：既去掉重复，又给出稳定顺序 —— 同一份事实任何一次采集
/// 都压出同一个内容摘要，这正是幂等键要的性质。
pub fn build_summary(snapshot: &DiscoverySnapshot) -> FactSummaryDraft {
    let mut executables = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut process_count: i64 = 0;

    for resource in &snapshot.resources {
        match resource.kind.as_str() {
            PROCESS_KIND => {
                process_count += 1;
                if let Some(value) = attribute(resource, PROCESS_EXECUTABLE) {
                    executables.insert(value.to_string());
                }
            }
            ENDPOINT_KIND => {
                if let Some(value) = attribute(resource, ENDPOINT_PORT) {
                    ports.insert(value.to_string());
                }
            }
            _ => {}
        }
    }

    FactSummaryDraft {
        revision: i64::try_from(snapshot.revision).unwrap_or(i64::MAX),
        observed_at: snapshot.generated_at.clone(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        process_count,
        process_executables: executables.into_iter().collect(),
        // 包清单还没有探针（backlog B119）：如实留空，
        // 别让「没采」看起来像「没装」。
        packages: Vec::new(),
        listen_ports: ports.into_iter().collect(),
    }
}

fn attribute<'a>(resource: &'a DiscoveredResource, key: &str) -> Option<&'a str> {
    resource
        .attributes
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
}

/// 内容摘要（`sha256:<hex>`）。
///
/// 为什么用 sha256 而不是仓库里那个 `fnv64` 开发占位（`wist_shared::integrity`）：
/// 它是**变更检测的幂等键**，一旦碰撞就会静默跳过上报、摘要停在旧内容上，
/// 这不是该放开发占位的地方。`ring` 本来就在依赖图里（rustls 带进来），无新增构建成本。
pub fn content_digest(summary: &FactSummaryDraft) -> String {
    // 归一化放在**这个函数内部**，而不是只靠 `build_summary` 的 `BTreeSet`：
    // 不变式要由主张它的函数来守 —— 否则谁传一份手工构造/从缓存来的 draft（顺序或重复项不同），
    // 幂等键就静默失真（多发一次，不会丢数据，但“内容没变就不发”就不再成立）。
    let process_executables = normalized(&summary.process_executables);
    let packages = normalized(&summary.packages);
    let listen_ports = normalized(&summary.listen_ports);
    let view = DigestView {
        os: &summary.os,
        arch: &summary.arch,
        process_executables: &process_executables,
        packages: &packages,
        listen_ports: &listen_ports,
    };
    // 对 `&str` / `&[String]` 序列化不可能失败；这里不用 `unwrap_or_default()`：
    // 那会把“序列化失败”变成“空输入的常量摘要”，等于“内容永远没变”，上送会永久停摆。
    let bytes = serde_json::to_vec(&view).expect("digest view serialization is infallible");
    let hash = digest::digest(&digest::SHA256, &bytes);
    let hex: String = hash
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();
    format!("sha256:{hex}")
}

/// 去重 + 定序。
fn normalized(values: &[String]) -> Vec<String> {
    values
        .iter()
        .cloned()
        .collect::<BTreeSet<String>>()
        .into_iter()
        .collect()
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use wist_contracts::discovery::DiscoveredResource;

    use super::*;

    fn snapshot(resources: Vec<DiscoveredResource>) -> DiscoverySnapshot {
        let mut snapshot = DiscoverySnapshot::new(
            "snapshot-1".to_string(),
            7,
            "2026-09-22T00:00:00Z".to_string(),
        );
        snapshot.resources = resources;
        snapshot
    }

    fn resource(kind: &str, attributes: &[(&str, &str)]) -> DiscoveredResource {
        DiscoveredResource {
            resource_id: format!("{kind}-{}", attributes.len()),
            kind: kind.to_string(),
            origin_idx: 0,
            attributes: attributes
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect::<BTreeMap<_, _>>(),
            discovered_at: "2026-09-22T00:00:00Z".to_string(),
            last_seen_at: "2026-09-22T00:00:00Z".to_string(),
            health: "healthy".to_string(),
            source: kind.to_string(),
        }
    }

    fn process(name: &str) -> DiscoveredResource {
        resource(
            "process",
            &[("process.pid", "42"), (PROCESS_EXECUTABLE, name)],
        )
    }

    #[test]
    fn dedups_processes_and_counts_before_dedup() {
        let summary = build_summary(&snapshot(vec![
            process("/opt/homebrew/bin/mise"),
            process("/opt/homebrew/bin/mise"),
            process("/usr/bin/xcodebuild"),
        ]));

        assert_eq!(summary.process_count, 3);
        assert_eq!(
            summary.process_executables,
            vec!["/opt/homebrew/bin/mise", "/usr/bin/xcodebuild"]
        );
    }

    #[test]
    fn collects_listen_ports_and_ignores_unrelated_kinds() {
        let summary = build_summary(&snapshot(vec![
            resource(ENDPOINT_KIND, &[(ENDPOINT_PORT, "5432")]),
            resource(ENDPOINT_KIND, &[(ENDPOINT_PORT, "5432")]),
            resource(ENDPOINT_KIND, &[(ENDPOINT_PORT, "6379")]),
            resource("host", &[("host.name", "demo")]),
            resource("container", &[("container.id", "abc")]),
        ]));

        assert_eq!(summary.listen_ports, vec!["5432", "6379"]);
        assert!(summary.process_executables.is_empty());
        assert_eq!(summary.process_count, 0);
    }

    #[test]
    fn skips_resources_without_the_field() {
        let summary = build_summary(&snapshot(vec![
            resource("process", &[("process.pid", "1")]),
            resource("process", &[(PROCESS_EXECUTABLE, "")]),
            resource(ENDPOINT_KIND, &[("endpoint.protocol", "tcp")]),
        ]));

        // 内核线程等没有可执行名的进程只计入条数，不进推断信号。
        assert_eq!(summary.process_count, 2);
        assert!(summary.process_executables.is_empty());
        assert!(summary.listen_ports.is_empty());
    }

    #[test]
    fn digest_ignores_order_revision_and_process_count() {
        let base = build_summary(&snapshot(vec![process("a"), process("b")]));

        // 顺序、revision、observed_at、条数都不该改变内容摘要。
        let mut reordered = build_summary(&snapshot(vec![process("b"), process("a")]));
        reordered.revision = 999;
        reordered.observed_at = "2030-01-01T00:00:00Z".to_string();
        reordered.process_count = 1;

        assert_eq!(content_digest(&base), content_digest(&reordered));
    }

    #[test]
    fn digest_changes_when_content_changes() {
        let base = build_summary(&snapshot(vec![process("a")]));
        let more = build_summary(&snapshot(vec![process("a"), process("b")]));

        assert_ne!(content_digest(&base), content_digest(&more));
        assert!(content_digest(&base).starts_with("sha256:"));
        assert_eq!(content_digest(&base).len(), "sha256:".len() + 64);
    }

    #[test]
    fn digest_normalizes_order_and_duplicates_within_itself() {
        // 不变式由 content_digest 自己守：手工构造的 draft（乱序/含重复）也必须算出同一摘要。
        let mut base = build_summary(&snapshot(vec![process("a"), process("b")]));
        let canonical = content_digest(&base);

        base.process_executables = vec!["b".to_string(), "a".to_string(), "a".to_string()];
        assert_eq!(content_digest(&base), canonical);

        base.listen_ports = vec!["6379".to_string(), "5432".to_string(), "5432".to_string()];
        let with_ports = content_digest(&base);
        assert_ne!(with_ports, canonical);

        base.listen_ports = vec!["5432".to_string(), "6379".to_string()];
        assert_eq!(content_digest(&base), with_ports);
    }

    #[test]
    fn os_and_arch_come_from_the_host() {
        let summary = build_summary(&snapshot(Vec::new()));
        assert_eq!(summary.os, std::env::consts::OS);
        assert_eq!(summary.arch, std::env::consts::ARCH);
        assert_eq!(summary.revision, 7);
        assert_eq!(summary.observed_at, "2026-09-22T00:00:00Z");
        // 包清单探针还没有，别让「没采」看起来像「没装」。
        assert!(summary.packages.is_empty());
    }
}
