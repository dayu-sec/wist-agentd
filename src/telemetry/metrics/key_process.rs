//! 关键进程指标的选目标：把「匹配签名」变成一组确定性的采集候选。
//!
//! 输入是**发现快照**（进程实体 + 端点端口），没有快照就没有目标 —— 这一点与
//! Kafka / 数据库自探一致：目标只来自本机。
//!
//! 选择规则（与 `docs/design/key-process-metrics.md` 同源）：
//!
//! 1. **命中**：任一签名命中即算采到（或语义）；
//! 2. **分组**：按归属分组 —— `service.unit` → `container.id` → 命中的那条签名；
//! 3. **代表**：同组取 **PID 最小**。worker 在 master 之后 fork，PID 必然更大，
//!    所以“组内 PID 最小”就是控制进程本身；
//! 4. **上限**：按组截断，超出记 `dropped`。
//!
//! `cmdline` 只在这里读一次、读完就丢：它经常带口令（`--password=…`），
//! 不允许进入任何持久化结构（见设计文档 §9.2）。所以本模块的 cmdline 由**闭包注入**，
//! 生产侧传 [`cmdline_text`]，测试传一个固定表。

use std::collections::BTreeMap;

use wist_contracts::discovery::{
    CollectionCandidate, DiscoveredResource, DiscoverySnapshot, StringKeyValue,
};
use wist_contracts::work::{KeyProcessSignature, KeyProcessSignaturePrefix};

/// 关键进程指标的候选上限（未下发上限时的内建值）：量级 = 常见服务数。
pub(crate) const KEY_PROCESS_TARGET_LIMIT: usize = 50;

/// 一条**已拥有**的签名。
///
/// 契约的 [`KeyProcessSignature`] 借用了 `target` 字符串，而授权在这里要跨 tick 存活，
/// 所以转成拥有型。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct OwnedSignature {
    pub(crate) prefix: KeyProcessSignaturePrefix,
    pub(crate) value: String,
}

impl OwnedSignature {
    pub(crate) fn from_borrowed(signature: KeyProcessSignature<'_>) -> Self {
        Self {
            prefix: signature.prefix,
            value: signature.value.to_string(),
        }
    }

    /// `unit:kafka` —— 诊断与日志里用它指认「是哪条签名没命中」。
    pub(crate) fn label(&self) -> String {
        format!("{}:{}", self.prefix.as_str(), self.value)
    }
}

/// 一次选择的结果。
#[derive(Debug, Default)]
pub(crate) struct KeyProcessSelection {
    /// 选中的采集候选（每个组一个代表）。
    pub(crate) candidates: Vec<CollectionCandidate>,
    /// 命中签名的组数（截断前）。
    pub(crate) groups: usize,
    /// 超过上限被裁掉的组数。
    pub(crate) dropped: usize,
    /// 一个都没命中时的原因（直接进日志；`None` = 有命中或有候选）。
    pub(crate) reason: Option<String>,
}

/// 生产侧取命令行：Linux 读 `/proc/<pid>/cmdline`，其余平台没有。
///
/// NUL 分隔换成空格后交给 [`matches_cmdline`] 按空白切 token。
#[cfg(target_os = "linux")]
pub(crate) fn cmdline_text(pid: u32) -> Option<String> {
    let bytes = std::fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    if bytes.is_empty() {
        return None;
    }
    Some(String::from_utf8_lossy(&bytes).replace('\0', " "))
}

/// macOS / 其它平台：v1 不读命令行（`ps -axo command=` 会给，但不在本版范围）。
#[cfg(not(target_os = "linux"))]
pub(crate) fn cmdline_text(_pid: u32) -> Option<String> {
    None
}

/// 选目标。纯函数：所有 I/O 都通过 `cmdline_of` 注入。
pub(crate) fn select_key_process_candidates(
    snapshot: &DiscoverySnapshot,
    signatures: &[OwnedSignature],
    cmdline_of: &dyn Fn(u32) -> Option<String>,
    limit: usize,
) -> KeyProcessSelection {
    if signatures.is_empty() {
        return KeyProcessSelection {
            reason: Some("授权没有携带任何签名".to_string()),
            ..KeyProcessSelection::default()
        };
    }

    let resources = resources_by_id(snapshot);
    let ports = listening_ports_by_pid(snapshot);

    // cmdline 一个 pid 只读一次：多条 cmdline 签名不该重复读同一个进程。
    let mut cmdline_cache: BTreeMap<u32, Option<String>> = BTreeMap::new();
    let mut cmdline_for = |pid: u32| -> Option<String> {
        if let Some(cached) = cmdline_cache.get(&pid) {
            return cached.clone();
        }
        let value = cmdline_of(pid);
        cmdline_cache.insert(pid, value.clone());
        value
    };

    // 组键 → （pid 最小的）命中记录
    let mut best: BTreeMap<String, Hit> = BTreeMap::new();
    for target in &snapshot.targets {
        if target.kind != "process" {
            continue;
        }
        let Some(pid) = target
            .execution_hints
            .get("process.pid")
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let resource = resources.get(target.resource_ref.as_str()).copied();
        let Some(signature) = signatures
            .iter()
            .find(|signature| matches(signature, pid, resource, &ports, &mut cmdline_for))
        else {
            continue;
        };

        let group = group_key(resource, signature);
        let hit = Hit {
            pid,
            group: group.clone(),
            candidate: build_candidate(snapshot, target, resource),
        };
        match best.get(&group) {
            Some(existing) if existing.pid <= pid => {}
            _ => {
                best.insert(group, hit);
            }
        }
    }

    let groups = best.len();
    if groups == 0 {
        return KeyProcessSelection {
            reason: Some(format!(
                "no process matched {}",
                signatures
                    .iter()
                    .map(OwnedSignature::label)
                    .collect::<Vec<_>>()
                    .join("|")
            )),
            ..KeyProcessSelection::default()
        };
    }

    // 组键字典序 → 截断结果是确定的，不依赖遍历顺序。
    let mut hits: Vec<Hit> = best.into_values().collect();
    hits.sort_by(|left, right| left.group.cmp(&right.group));
    let dropped = groups.saturating_sub(limit);
    hits.truncate(limit);

    KeyProcessSelection {
        candidates: hits.into_iter().map(|hit| hit.candidate).collect(),
        groups,
        dropped,
        reason: None,
    }
}

struct Hit {
    pid: u32,
    group: String,
    candidate: CollectionCandidate,
}

fn resources_by_id(snapshot: &DiscoverySnapshot) -> BTreeMap<&str, &DiscoveredResource> {
    snapshot
        .resources
        .iter()
        .map(|resource| (resource.resource_id.as_str(), resource))
        .collect()
}

/// `pid → 监听端口集合`：取自端点探针产出的 `service_endpoint` 资源。
fn listening_ports_by_pid(snapshot: &DiscoverySnapshot) -> BTreeMap<u32, Vec<u16>> {
    let mut ports: BTreeMap<u32, Vec<u16>> = BTreeMap::new();
    for resource in &snapshot.resources {
        if resource.kind != "service_endpoint" {
            continue;
        }
        let Some(pid) = resource
            .attributes
            .get("process.pid")
            .and_then(|value| value.parse::<u32>().ok())
        else {
            continue;
        };
        let Some(port) = resource
            .attributes
            .get("endpoint.bind.port")
            .and_then(|value| value.parse::<u16>().ok())
        else {
            continue;
        };
        ports.entry(pid).or_default().push(port);
    }
    ports
}

fn matches(
    signature: &OwnedSignature,
    pid: u32,
    resource: Option<&DiscoveredResource>,
    ports: &BTreeMap<u32, Vec<u16>>,
    cmdline_for: &mut impl FnMut(u32) -> Option<String>,
) -> bool {
    let attribute = |key: &str| {
        resource
            .and_then(|resource| resource.attributes.get(key))
            .map(String::as_str)
    };
    match signature.prefix {
        // systemd 单元名：大小写不敏感子串（部署者命名的，不需要精确到模板实例）。
        KeyProcessSignaturePrefix::Unit => attribute("service.unit").is_some_and(|unit| {
            unit.to_lowercase()
                .contains(&signature.value.to_lowercase())
        }),
        // 可执行名：按 **basename** 相等（契约层已拒绝带 `/` 的值）。
        KeyProcessSignaturePrefix::Exe => attribute("process.executable.name")
            .map(basename)
            .is_some_and(|name| name.eq_ignore_ascii_case(&signature.value)),
        // 监听端口：该 pid 真的持有这个端口。
        KeyProcessSignaturePrefix::Port => signature
            .value
            .parse::<u16>()
            .ok()
            .is_some_and(|port| ports.get(&pid).is_some_and(|list| list.contains(&port))),
        // 命令行：某个 token **完全相等**（契约层已禁止值里带空白）。
        //
        // 为什么**不做 basename 相等**：argv 里大量 token 是路径（classpath / `-jar` 的路径 /
        // 配置路径），`cmdline:kafka` 会把 `-cp /opt/kafka` 这种“只是引用了这个目录”的进程
        // 也算命中 —— 这正是设计里拒绝子串的那一类误判。要匹配 jar 就写完整 token
        // （`cmdline:/opt/app/app.jar`），路径无关的写在 `unit:` / `exe:` 上。
        KeyProcessSignaturePrefix::Cmdline => cmdline_for(pid).is_some_and(|text| {
            text.split_whitespace()
                .any(|token| token == signature.value)
        }),
    }
}

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

/// 分组键：**归属**优先，其次才是“哪条签名命中的”。
///
/// 为什么不能用“整个命中集合算一组”：两个互不相干的关键进程（`app.jar` 与 `worker.py`）
/// 会被合成一个组，最后只报一个代表 —— 少报且没有解释。
fn group_key(resource: Option<&DiscoveredResource>, signature: &OwnedSignature) -> String {
    if let Some(unit) = resource
        .and_then(|resource| resource.attributes.get("service.unit"))
        .filter(|unit| !unit.is_empty())
    {
        return format!("unit:{unit}");
    }
    if let Some(container) = resource
        .and_then(|resource| resource.attributes.get("container.id"))
        .filter(|container| !container.is_empty())
    {
        return format!("ctr:{container}");
    }
    format!("sig:{}", signature.label())
}

/// 构造采集候选：形状与 `planner_bridge` 的进程候选一致（下游不用区分来源）。
fn build_candidate(
    snapshot: &DiscoverySnapshot,
    target: &wist_contracts::discovery::DiscoveredTarget,
    resource: Option<&DiscoveredResource>,
) -> CollectionCandidate {
    let mut execution_hints = Vec::new();
    for key in [
        "process.pid",
        "process.identity",
        "discovery.identity_strength",
        "discovery.identity_status",
    ] {
        if let Some(value) = target.execution_hints.get(key) {
            execution_hints.push(StringKeyValue::new(key, value.clone()));
        }
    }
    // 分组依据要在下游也能看到（诊断时回答“它为什么算一个代表”）。
    if let Some(unit) = resource.and_then(|resource| resource.attributes.get("service.unit")) {
        execution_hints.push(StringKeyValue::new("service.unit", unit.clone()));
    }
    CollectionCandidate {
        candidate_id: format!("{}:process_metrics", target.target_id),
        target_ref: target.target_id.clone(),
        collection_kind: "process_metrics".to_string(),
        resource_ref: target.resource_ref.clone(),
        execution_hints,
        generated_at: snapshot.generated_at.clone(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::discovery::{DiscoveredTarget, DiscoverySnapshot};

    fn signature(prefix: KeyProcessSignaturePrefix, value: &str) -> OwnedSignature {
        OwnedSignature {
            prefix,
            value: value.to_string(),
        }
    }

    fn snapshot() -> DiscoverySnapshot {
        let mut snapshot =
            DiscoverySnapshot::new("snap-1".to_string(), 1, "2026-11-21T00:00:00Z".to_string());
        snapshot.resources = vec![
            resource(
                "host-1:pid:10",
                &[
                    ("process.pid", "10"),
                    ("process.executable.name", "/usr/bin/nginx"),
                    ("service.unit", "nginx.service"),
                ],
            ),
            resource(
                "host-1:pid:11",
                &[
                    ("process.pid", "11"),
                    ("process.executable.name", "/usr/bin/nginx"),
                    ("service.unit", "nginx.service"),
                ],
            ),
            resource(
                "host-1:pid:20",
                &[
                    ("process.pid", "20"),
                    ("process.executable.name", "/usr/lib/jvm/java"),
                ],
            ),
            resource(
                "host-1:pid:30",
                &[
                    ("process.pid", "30"),
                    ("process.executable.name", "/usr/local/bin/worker"),
                    ("container.id", "3f9a2b"),
                ],
            ),
            resource(
                "host-1:pid:40",
                &[
                    ("process.pid", "40"),
                    ("process.executable.name", "/usr/bin/sshd"),
                    ("service.unit", "ssh.service"),
                ],
            ),
            // 端点：pid 20 监听 9092。
            endpoint("host-1:endpoint:20:9092", "20", "9092"),
        ];
        snapshot.targets = vec![
            target("host-1:pid:10", "host-1:pid:10"),
            target("host-1:pid:11", "host-1:pid:11"),
            target("host-1:pid:20", "host-1:pid:20"),
            target("host-1:pid:30", "host-1:pid:30"),
            target("host-1:pid:40", "host-1:pid:40"),
        ];
        snapshot
    }

    fn resource(id: &str, attributes: &[(&str, &str)]) -> DiscoveredResource {
        DiscoveredResource {
            resource_id: id.to_string(),
            kind: "process".to_string(),
            origin_idx: 0,
            attributes: attributes
                .iter()
                .map(|(key, value)| (key.to_string(), value.to_string()))
                .collect(),
            discovered_at: String::new(),
            last_seen_at: String::new(),
            health: "healthy".to_string(),
            source: "process".to_string(),
        }
    }

    fn endpoint(id: &str, pid: &str, port: &str) -> DiscoveredResource {
        DiscoveredResource {
            resource_id: id.to_string(),
            kind: "service_endpoint".to_string(),
            origin_idx: 0,
            attributes: BTreeMap::from([
                ("process.pid".to_string(), pid.to_string()),
                ("endpoint.bind.port".to_string(), port.to_string()),
            ]),
            discovered_at: String::new(),
            last_seen_at: String::new(),
            health: "healthy".to_string(),
            source: "service_endpoint".to_string(),
        }
    }

    fn target(target_id: &str, resource_ref: &str) -> DiscoveredTarget {
        let pid = resource_ref.rsplit(':').next().unwrap_or("0");
        DiscoveredTarget {
            target_id: target_id.to_string(),
            kind: "process".to_string(),
            origin_idx: 0,
            resource_ref: resource_ref.to_string(),
            execution_hints: BTreeMap::from([("process.pid".to_string(), pid.to_string())]),
            state: "active".to_string(),
        }
    }

    fn no_cmdline(_pid: u32) -> Option<String> {
        None
    }

    /// `unit:` 命中一个组的那批进程，代表取 **PID 最小**（= master）。
    #[test]
    fn a_unit_signature_picks_the_lowest_pid_as_the_representative() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Unit, "nginx")],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(selection.groups, 1);
        assert_eq!(selection.dropped, 0);
        assert_eq!(selection.candidates.len(), 1);
        assert_eq!(
            selection.candidates[0].resource_ref, "host-1:pid:10",
            "PID 最小的那个才是控制进程"
        );
        assert!(selection.reason.is_none());
    }

    /// `unit:` 是**大小写不敏感**的子串匹配（单元名是部署者命名的，不拿大小写卡人）。
    /// 写反了就是“签名看着对、永远不命中”。
    #[test]
    fn unit_matches_case_insensitively_as_a_substring() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Unit, "NGINX")],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(selection.groups, 1);
        assert_eq!(selection.candidates[0].resource_ref, "host-1:pid:10");
    }

    /// `cmdline` 一个进程只读一次：多条 cmdline 签名不该重复读 `/proc/<pid>/cmdline`。
    #[test]
    fn the_command_line_is_read_at_most_once_per_process() {
        let reads = std::cell::RefCell::new(Vec::new());
        let cmdline = |pid: u32| -> Option<String> {
            reads.borrow_mut().push(pid);
            Some("/usr/bin/java -jar app.jar".to_string())
        };
        let selection = select_key_process_candidates(
            &snapshot(),
            &[
                signature(KeyProcessSignaturePrefix::Cmdline, "nope"),
                signature(KeyProcessSignaturePrefix::Cmdline, "app.jar"),
            ],
            &cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(
            selection.groups, 4,
            "夹具里 5 个进程都命中第二条签名，但 pid 10/11 同一个 unit → 4 个组"
        );
        let reads = reads.into_inner();
        let mut unique = reads.clone();
        unique.sort_unstable();
        unique.dedup();
        assert_eq!(
            reads.len(),
            unique.len(),
            "同一个 pid 被读了两次：{reads:?}"
        );
    }

    /// `exe:` 按 basename 相等匹配，`/usr/bin/nginx` 与 `nginx` 是同一个。
    #[test]
    fn exe_matches_on_the_basename_only() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Exe, "nginx")],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(selection.groups, 1);
        assert_eq!(selection.candidates[0].resource_ref, "host-1:pid:10");
    }

    /// `port:` 靠端点探针的「端口 → pid」反查。
    #[test]
    fn port_matches_the_process_that_holds_the_listener() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Port, "9092")],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(selection.groups, 1);
        assert_eq!(selection.candidates[0].resource_ref, "host-1:pid:20");
    }

    /// `cmdline:` 是 token **完全相等或 basename 相等**，不是子串。
    #[test]
    fn cmdline_matches_a_whole_token_only() {
        let cmdline = |pid: u32| -> Option<String> {
            (pid == 20).then(|| "/usr/bin/java -cp /opt/kafka kafka.Kafka".to_string())
        };
        let hit = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Cmdline, "kafka.Kafka")],
            &cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(hit.groups, 1);
        assert_eq!(hit.candidates[0].resource_ref, "host-1:pid:20");

        // `kafka` 只是 `kafka.Kafka` 的前缀：不算命中。
        let miss = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Cmdline, "kafka")],
            &cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(miss.groups, 0);
        assert!(miss.reason.is_some());
    }

    /// `cmdline:` **不做 basename 相等**：argv 里的路径 token 不能把“只是引用了这个目录”
    /// 的进程算进来。（这个取舍写在 `matches` 的注释与设计文档 §5。）
    #[test]
    fn cmdline_does_not_match_by_basename() {
        let cmdline = |pid: u32| -> Option<String> {
            (pid == 20).then(|| "/usr/bin/java -cp /opt/kafka kafka.Kafka".to_string())
        };
        // `/opt/kafka` 的 basename 是 `kafka`，但它不是这个进程的身份。
        let miss = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Cmdline, "kafka")],
            &cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(
            miss.groups, 0,
            "basename 相等不算命中（否则 classpath 会误命中）"
        );
    }

    /// 一个容器内的进程按 `container.id` 成组，不与宿主进程合并。
    #[test]
    fn a_container_process_groups_by_its_container() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Exe, "worker")],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(selection.groups, 1);
        assert_eq!(selection.candidates[0].resource_ref, "host-1:pid:30");
    }

    /// 多条签名是**或**：同一个进程只报一次。
    #[test]
    fn multiple_signatures_are_an_or_and_never_double_report() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[
                signature(KeyProcessSignaturePrefix::Exe, "nginx"),
                signature(KeyProcessSignaturePrefix::Unit, "nginx"),
                signature(KeyProcessSignaturePrefix::Port, "9092"),
            ],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert_eq!(selection.groups, 2, "nginx 一组 + java 一组");
        let refs: Vec<&str> = selection
            .candidates
            .iter()
            .map(|candidate| candidate.resource_ref.as_str())
            .collect();
        assert!(refs.contains(&"host-1:pid:10"));
        assert!(refs.contains(&"host-1:pid:20"));
    }

    /// 超过上限按**组**截断，并且截断是确定的（组键字典序）。
    #[test]
    fn the_cap_truncates_whole_groups_deterministically() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[
                signature(KeyProcessSignaturePrefix::Exe, "nginx"),
                signature(KeyProcessSignaturePrefix::Port, "9092"),
                signature(KeyProcessSignaturePrefix::Exe, "sshd"),
            ],
            &no_cmdline,
            2,
        );
        assert_eq!(selection.groups, 3);
        assert_eq!(selection.dropped, 1);
        assert_eq!(selection.candidates.len(), 2);
    }

    /// 一条都没命中 → 必须给出原因（进日志），不能静默空转。
    #[test]
    fn no_match_reports_the_signatures_it_tried() {
        let selection = select_key_process_candidates(
            &snapshot(),
            &[signature(KeyProcessSignaturePrefix::Unit, "kafka")],
            &no_cmdline,
            KEY_PROCESS_TARGET_LIMIT,
        );
        assert!(selection.candidates.is_empty());
        assert_eq!(selection.groups, 0);
        let reason = selection.reason.expect("reason");
        assert!(reason.contains("no process matched"), "{reason}");
        assert!(reason.contains("unit:kafka"), "{reason}");
    }

    /// 空签名（授权写错）也不能变成“静默采全部”。
    #[test]
    fn an_empty_signature_list_selects_nothing() {
        let selection =
            select_key_process_candidates(&snapshot(), &[], &no_cmdline, KEY_PROCESS_TARGET_LIMIT);
        assert!(selection.candidates.is_empty());
        assert!(selection.reason.is_some());
    }
}
