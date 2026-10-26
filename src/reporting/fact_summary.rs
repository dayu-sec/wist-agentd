//! 事实**摘要**：把采集到的发现快照机械压缩成「推得动用途」的最小集合。
//!
//! 为什么压缩放在 agentd：压缩是**机械操作**（去重 + 只留推断要用的字段），
//! 不需要知道规则表，所以策展知识不必下放。原文快照照旧走数据面给中心做资产整理。
//!
//! 为什么 agentd 不拿内容摘要做判重：那会让 agent 侧算法一退化（比如退化成常量）
//! 就永远不再上报。agentd **无条件周期全量**上送（只按最小间隔节流），
//! 判重归网关 —— 网关从收到的内容自己重算摘要，agent 声明坏了也不影响入库。

use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use wist_contracts::discovery::{DiscoveredResource, DiscoverySnapshot};
use wist_contracts::fact_summary::{EPHEMERAL_PORT_START, FactContent};

/// `DiscoveredResource::kind`：进程（与 `ProcessDiscoveryProbe` 写入的值一致）。
const PROCESS_KIND: &str = "process";
/// `DiscoveredResource::kind`：监听端点（与 `EndpointDiscoveryProbe` 写入的值一致）。
const ENDPOINT_KIND: &str = "service_endpoint";
/// `DiscoveredResource::kind`：主机（与 `HostDiscoveryProbe` 写入的值一致）。
const HOST_KIND: &str = "host";
/// `DiscoveredResource::kind`：网卡地址（与 `NetworkDiscoveryProbe` 写入的值一致）。
const IP_ADDRESS_KIND: &str = "ip_address";

/// 进程可执行标识的属性名。
///
/// 语义是「可执行实体的标识」，两端都是**绝对路径**（Linux 取 `/proc/<pid>/exe`，
/// macOS 取 `ps -axo comm=`）。早先 Linux 侧只给 `comm` 的 basename（15 字符、会截断、
/// 会撞名），`process_path` 类规则因此在 Linux 上不成立。
const PROCESS_EXECUTABLE: &str = "process.executable.name";
/// 监听端点：协议（`tcp` / `udp`）。与 `EndpointDiscoveryProbe` 写入的值一致。
const ENDPOINT_PROTOCOL: &str = "endpoint.protocol";
/// 监听端口的属性名。
const ENDPOINT_PORT: &str = "endpoint.bind.port";
/// 主机标识 / 主机名的属性名（`host` 方向）。
const HOST_ID: &str = "host.id";
const HOST_NAME: &str = "host.name";
/// 网卡地址的属性名（`ip_address` 方向）。cidr 比裸地址更能说明「在哪个网段」。
const ADDR_IFACE: &str = "net.if.name";
const ADDR_CIDR: &str = "net.if.cidr";
const ADDR_IP: &str = "net.if.addr";

/// 可上报的事实摘要（对应模型 `Control.AgentFactSummary` 的可上报部分）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct FactSummaryDraft {
    /// 快照 revision：**仅留痕**，不进内容摘要。
    pub revision: i64,
    /// 事实是什么时候观察到（快照生成时间）：**仅留痕**，不进内容摘要。
    pub observed_at: String,
    pub os: String,
    pub arch: String,
    /// 去重前的**用户态**进程条数（内核线程与僵尸不算 —— 它们没有可执行实体）。
    /// 去重会毁掉基数，留一个原始计数备查。不进内容摘要。
    pub process_count: i64,
    pub process_executables: Vec<String>,
    pub packages: Vec<String>,
    /// 稳定的服务端口，形如 `tcp:5432`（已滤掉内核临时端口区间）。
    pub listen_ports: Vec<String>,
    /// 网关下发、本机实际探测过的路径（白名单）。
    pub probed_paths: Vec<String>,
    /// 其中存在的路径（`probed_paths` 的子集）。
    pub present_paths: Vec<String>,
    // ── 以下三项是**留痕/展示**：不进内容摘要（见 `FactContent`）。──
    // 机器名/IP 会因改名、换网而变，但它们不影响「这台机器是干什么用的」；
    // 放进摘要会让每次换网就触发一次重报与重算。
    /// 主机标识（`host.id`）。
    pub host_id: String,
    /// 主机名（`host.name`）。
    pub host_name: String,
    /// 网卡地址（每块网卡一条，形如 `en0 192.168.1.5/24`）。
    /// 已滤掉链路本地（`fe80::/10`）/ 回环 / IPv4 自分配 —— 展示口径与机器画像一致。
    pub network_addresses: Vec<String>,
}

impl FactSummaryDraft {
    /// 取内容视图（摘要的输入）。
    pub fn content(&self) -> FactContent {
        FactContent::new(
            self.os.clone(),
            self.arch.clone(),
            self.process_executables.clone(),
            self.packages.clone(),
            self.listen_ports.clone(),
            self.probed_paths.clone(),
            self.present_paths.clone(),
        )
    }

    /// 内容摘要（`fact-v3:sha256:<hex>`）。
    ///
    /// 实现只有一份 —— 在 `wist_contracts::fact_summary`，与网关共用。
    /// 这里只做转接：两侧各写一份规范化的话，一边改了另一边不知道，
    /// 就会出现「一边认为变了、另一边永远认为没变」的静默漏报。
    ///
    /// 注意：这个值在 wire 上只是**声明**。真正的判重在网关（它自己重算一遍）。
    pub fn content_digest(&self) -> String {
        self.content().content_digest()
    }
}

/// 从发现快照压出摘要。
///
/// `probe_paths` 是网关随发现策略下发的**路径白名单**（来自采集目录的 `path_exists:` 条件）。
/// 这里逐条探存在性，并把「探测过」与「存在」分开报：前者缺失是「无法判定」，
/// 后者缺失才是「不存在」。全部探完才上报，不按变化增量（摘要本来就是全量的）。
pub fn build_summary(snapshot: &DiscoverySnapshot, probe_paths: &[String]) -> FactSummaryDraft {
    let mut executables = BTreeSet::new();
    let mut ports = BTreeSet::new();
    let mut addresses = BTreeSet::new();
    let mut process_count: i64 = 0;
    let mut host_id = String::new();
    let mut host_name = String::new();

    for resource in &snapshot.resources {
        match resource.kind.as_str() {
            PROCESS_KIND => {
                process_count += 1;
                if let Some(value) = attribute(resource, PROCESS_EXECUTABLE) {
                    executables.insert(value.to_string());
                }
            }
            ENDPOINT_KIND => {
                let Some(port) =
                    attribute(resource, ENDPOINT_PORT).and_then(|value| value.parse::<u16>().ok())
                else {
                    continue;
                };
                // 只按端口区间判：临时区间里的监听是客户端 socket / 端口池 / 端口转发的副产物。
                // **不按回环地址判** —— `127.0.0.1:5432` 这类只绑本地的服务同样是有效判据。
                if port >= EPHEMERAL_PORT_START {
                    continue;
                }
                // 探针总是同时写协议与端口；缺一个说明快照不完整，不猜。
                let Some(protocol) = attribute(resource, ENDPOINT_PROTOCOL) else {
                    continue;
                };
                ports.insert((protocol.to_ascii_lowercase(), port));
            }
            HOST_KIND => {
                if let Some(value) = attribute(resource, HOST_ID) {
                    host_id = value.to_string();
                }
                if let Some(value) = attribute(resource, HOST_NAME) {
                    host_name = value.to_string();
                }
            }
            IP_ADDRESS_KIND => {
                // cidr 优先：它同时说明地址与网段；没有就退回裸地址。
                let Some(address) =
                    attribute(resource, ADDR_CIDR).or_else(|| attribute(resource, ADDR_IP))
                else {
                    continue;
                };
                // 展示口径：滤掉链路本地 / 回环 / 自分配（与机器画像同一判据）。网卡探针会把每张
                // 网卡的 `fe80::` 都列进快照，不滤的话「这台机器在哪」会被十几条噪声淹掉。
                if crate::discovery::network::is_meaningless_address_spec(address) {
                    continue;
                }
                // 带上网卡名，否则多块网卡时一堆地址分不清谁是谁。
                addresses.insert(match attribute(resource, ADDR_IFACE) {
                    Some(iface) => format!("{iface} {address}"),
                    None => address.to_string(),
                });
            }
            _ => {}
        }
    }

    let probe = self::probe_paths(probe_paths);

    FactSummaryDraft {
        // 与契约同一口径：`snapshot.revision` 现为 `Int`（i64），不再需要收窄。
        revision: snapshot.revision,
        observed_at: snapshot.generated_at.clone(),
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        process_count,
        process_executables: executables.into_iter().collect(),
        // 包清单还没有探针（backlog B119）：如实留空，
        // 别让「没采」看起来像「没装」。
        packages: Vec::new(),
        listen_ports: ports
            .into_iter()
            .map(|(protocol, port)| format!("{protocol}:{port}"))
            .collect(),
        probed_paths: probe.probed,
        present_paths: probe.present,
        host_id,
        host_name,
        network_addresses: addresses.into_iter().collect(),
    }
}

/// 一次路径探测的结果。
///
/// 为什么把 `unreadable` 单独拿出来：以前只看「存在 / 不存在」两态，而 `Path::exists()`
/// 把所有错误都压成 `false` —— 「没权限」于是伪装成「没有这个目录」，网关据此报
/// `match_unsatisfied`（确认没有），处置方向（去查采集配置）和真因（去查权限）正好相反。
///
/// `unreadable` 里的路径**不在** `probed` 里：网关的三态求值会因此得到
/// `fact_not_collected`（无法判定），而不是「确认不存在」。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct PathProbeReport {
    pub probed: Vec<String>,
    pub present: Vec<String>,
    pub unreadable: Vec<UnreadablePath>,
}

/// 探不了的一条路径（原始错误照原样带出，供人直接看出是权限还是别的）。
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
pub struct UnreadablePath {
    pub path: String,
    pub error: String,
}

/// 探路径存在性。只接受**绝对路径**：相对路径的结果取决于进程 cwd，
/// 同一台机器换一个启动方式就会翻面，不能当事实。
///
/// 三态：存在 / 确认不存在（`NotFound`）/ 探不了（其余错误）。只有前两者进 `probed`。
pub fn probe_paths(paths: &[String]) -> PathProbeReport {
    let mut report = PathProbeReport::default();
    let mut probed = BTreeSet::new();
    let mut present = BTreeSet::new();
    for path in paths {
        let path = path.trim();
        if path.is_empty() || !path.starts_with('/') {
            continue;
        }
        match std::fs::metadata(path) {
            Ok(_) => {
                probed.insert(path.to_string());
                present.insert(path.to_string());
            }
            // 确认不存在：这是一条**可用的事实**（`path_exists` 为假）。
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {
                probed.insert(path.to_string());
            }
            // 看不到 ≠ 不存在：不记“探过”，让求值落成「无法判定」。
            Err(err) => {
                log::warn!("fact summary: probe path unreadable: {path}: {err}");
                report.unreadable.push(UnreadablePath {
                    path: path.to_string(),
                    error: err.to_string(),
                });
            }
        }
    }
    report.probed = probed.into_iter().collect();
    report.present = present.into_iter().collect();
    report
}

fn attribute<'a>(resource: &'a DiscoveredResource, key: &str) -> Option<&'a str> {
    resource
        .attributes
        .get(key)
        .map(String::as_str)
        .filter(|value| !value.is_empty())
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

    /// 按探针真实写出的形状造端点（绑定地址不参与过滤，但真实快照里有）。
    fn endpoint(protocol: &str, bind_ip: &str, port: &str) -> DiscoveredResource {
        resource(
            ENDPOINT_KIND,
            &[
                (ENDPOINT_PROTOCOL, protocol),
                ("endpoint.bind.ip", bind_ip),
                (ENDPOINT_PORT, port),
            ],
        )
    }

    /// 多数用例不关心路径白名单：统一走空表。
    fn summary(snapshot: &DiscoverySnapshot) -> FactSummaryDraft {
        build_summary(snapshot, &[])
    }

    #[test]
    fn dedups_processes_and_counts_before_dedup() {
        let summary = summary(&snapshot(vec![
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
        let summary = summary(&snapshot(vec![
            endpoint("tcp", "0.0.0.0", "5432"),
            endpoint("tcp", "0.0.0.0", "5432"),
            endpoint("udp", "::", "6379"),
            resource("host", &[("host.name", "demo")]),
            resource("container", &[("container.id", "abc")]),
        ]));

        // 协议参与身份：同一端口在 tcp/udp 上是两件不同的事。
        assert_eq!(summary.listen_ports, vec!["tcp:5432", "udp:6379"]);
        assert!(summary.process_executables.is_empty());
        assert_eq!(summary.process_count, 0);
    }

    #[test]
    fn drops_ephemeral_socket_pool_ports() {
        // 实测噪声的形状：一个 license 进程的临时端口池 + 编辑器的端口转发 —— 全在 ≥ 32768。
        // 判据只看区间：回环上的**服务**端口（本地 postgres / 开发机的 dev server）
        // 同样是「这台机器在跑什么」的信号，不能一刀切掉。
        let summary = summary(&snapshot(vec![
            endpoint("tcp", "0.0.0.0", "5432"),
            endpoint("tcp", "127.0.0.1", "6379"),
            // 编辑器端口转发：回环 + 临时端口。
            endpoint("tcp", "127.0.0.1", "46671"),
            // license 池 / docker 随机发布端口。
            endpoint("tcp", "0.0.0.0", "35432"),
            endpoint("tcp", "::", "33013"),
            // 边界：32768 起算临时端口。
            endpoint("udp", "0.0.0.0", "32768"),
        ]));

        assert_eq!(summary.listen_ports, vec!["tcp:5432", "tcp:6379"]);
    }

    #[test]
    fn keeps_wildcard_service_ports_and_needs_a_protocol() {
        // `0.0.0.0` / `::` 是真实的服务监听（对外可达），就是用途推断要的信号。
        // 但只写端口、没写协议的端点不猜协议：宁可少一条，不要编一个 `tcp`。
        let summary = summary(&snapshot(vec![
            endpoint("tcp", "0.0.0.0", "8080"),
            endpoint("tcp", "::", "443"),
            resource(ENDPOINT_KIND, &[(ENDPOINT_PORT, "6379")]),
        ]));

        assert_eq!(summary.listen_ports, vec!["tcp:443", "tcp:8080"]);
    }

    #[test]
    fn skips_resources_without_the_field() {
        let summary = summary(&snapshot(vec![
            resource("process", &[("process.pid", "1")]),
            resource("process", &[(PROCESS_EXECUTABLE, "")]),
            resource(ENDPOINT_KIND, &[("endpoint.protocol", "tcp")]),
        ]));

        // 没有可执行名的进程只计入条数，不进推断信号（Linux 侧的内核线程已在探针里滤掉，
        // 这里保留的是「资源本身缺字段」的兼容行为）。
        assert_eq!(summary.process_count, 2);
        assert!(summary.process_executables.is_empty());
        assert!(summary.listen_ports.is_empty());
    }

    #[test]
    fn digest_ignores_order_revision_and_process_count() {
        let base = summary(&snapshot(vec![process("a"), process("b")]));

        // 顺序、revision、observed_at、条数都不该改变内容摘要。
        let mut reordered = summary(&snapshot(vec![process("b"), process("a")]));
        reordered.revision = 999;
        reordered.observed_at = "2030-01-01T00:00:00Z".to_string();
        reordered.process_count = 1;
        reordered.host_id = "other".to_string();
        reordered.network_addresses = vec!["en0 10.0.0.1/24".to_string()];

        assert_eq!(base.content_digest(), reordered.content_digest());
    }

    #[test]
    fn digest_changes_when_content_changes() {
        let base = summary(&snapshot(vec![process("a")]));
        let more = summary(&snapshot(vec![process("a"), process("b")]));

        assert_ne!(base.content_digest(), more.content_digest());
        // 版本前缀是契约的一部分：网关用同一实现重算，两侧算法/字段集必须对齐。
        let digest = base.content_digest();
        assert!(digest.starts_with("fact-v3:sha256:"), "{digest}");
        assert_eq!(digest.len(), "fact-v3:sha256:".len() + 64);
    }

    #[test]
    fn probes_configured_paths_and_separates_present_from_probed() {
        let existing = env!("CARGO_MANIFEST_DIR").to_string();
        let missing = format!("{existing}/definitely-not-here-{}", std::process::id());
        let summary = build_summary(
            &snapshot(vec![]),
            &[
                existing.clone(),
                missing.clone(),
                "relative/path".to_string(),
            ],
        );
        // 探测过 = 白名单里的绝对路径（相对路径不探：结果随 cwd 变）。
        assert_eq!(
            summary.probed_paths,
            vec![existing.clone(), missing.clone()]
        );
        // 存在 = 探测过里的子集。
        assert_eq!(summary.present_paths, vec![existing]);
        assert!(
            !summary
                .probed_paths
                .iter()
                .any(|path| path == "relative/path"),
            "相对路径不能当作事实"
        );
    }

    #[cfg(unix)]
    #[test]
    fn unreadable_paths_are_not_reported_as_probed() {
        // 「看不到 ≠ 不存在」：用一条**不可能读到**的路径（父级是设备文件，`ENOTDIR`）。
        // 这类路径既不能报 `match_unsatisfied`（确认没有），因为那会把「查权限」的人
        // 引去改采集配置。
        let existing = env!("CARGO_MANIFEST_DIR").to_string();
        let report = probe_paths(&[existing.clone(), "/dev/null/child".to_string()]);

        assert_eq!(report.probed, vec![existing.clone()]);
        assert_eq!(report.present, vec![existing]);
        assert_eq!(report.unreadable.len(), 1, "{report:?}");
        assert_eq!(report.unreadable[0].path, "/dev/null/child");
        assert!(
            !report.unreadable[0].error.is_empty(),
            "原始错误要带出来，否则人还是不知道是权限还是别的"
        );
    }

    #[test]
    fn digest_matches_the_shared_contract_implementation() {
        // 证明 agentd 报的声明就是网关重算的那把钥匙 —— 两边都调 FactContent。
        let summary = summary(&snapshot(vec![process("a"), process("b")]));
        let expected = FactContent::new(
            summary.os.clone(),
            summary.arch.clone(),
            summary.process_executables.clone(),
            summary.packages.clone(),
            summary.listen_ports.clone(),
            summary.probed_paths.clone(),
            summary.present_paths.clone(),
        )
        .content_digest();
        assert_eq!(summary.content_digest(), expected);
    }

    #[test]
    fn digest_normalizes_order_and_duplicates_within_itself() {
        // 不变式由共享实现自己守：手工构造的 draft（乱序/含重复）也必须算出同一摘要。
        let mut base = summary(&snapshot(vec![process("a"), process("b")]));
        let canonical = base.content_digest();

        base.process_executables = vec!["b".to_string(), "a".to_string(), "a".to_string()];
        assert_eq!(base.content_digest(), canonical);

        base.listen_ports = vec!["6379".to_string(), "5432".to_string(), "5432".to_string()];
        let with_ports = base.content_digest();
        assert_ne!(with_ports, canonical);

        base.listen_ports = vec!["5432".to_string(), "6379".to_string()];
        assert_eq!(base.content_digest(), with_ports);
    }

    #[test]
    fn collects_host_identity_and_network_addresses_for_display() {
        // 这三项只用于展示（页面上“这台机器是谁、在哪”），不进内容摘要。
        let summary = summary(&snapshot(vec![
            resource("host", &[("host.id", "mid-1"), ("host.name", "demo")]),
            resource(
                IP_ADDRESS_KIND,
                &[
                    (ADDR_IFACE, "en0"),
                    (ADDR_CIDR, "192.168.1.5/24"),
                    (ADDR_IP, "192.168.1.5"),
                ],
            ),
            // 同一块网卡多条地址：都收，按串去重定序。
            resource(
                IP_ADDRESS_KIND,
                &[(ADDR_IFACE, "en0"), (ADDR_CIDR, "192.168.1.5/24")],
            ),
            // 没有 cidr 时退回裸地址，且没有网卡名也能用。
            resource(IP_ADDRESS_KIND, &[(ADDR_IP, "10.8.0.2")]),
            // 链路本地噪声：展示口径里滤掉（每张网卡一条，会把「在哪」淹掉）。
            resource(
                IP_ADDRESS_KIND,
                &[(ADDR_IFACE, "en0"), (ADDR_CIDR, "fe80::1/64")],
            ),
        ]));

        assert_eq!(summary.host_id, "mid-1");
        assert_eq!(summary.host_name, "demo");
        assert_eq!(
            summary.network_addresses,
            vec!["10.8.0.2", "en0 192.168.1.5/24"]
        );
    }

    #[test]
    fn drops_link_local_loopback_and_self_assigned_network_addresses() {
        // 展示口径与机器画像一致：噪声地址不进 fact summary（否则中心那边也是十几条 fe80）。
        let summary = summary(&snapshot(vec![
            resource(
                IP_ADDRESS_KIND,
                &[(ADDR_IFACE, "en0"), (ADDR_CIDR, "192.168.3.178/24")],
            ),
            resource(
                IP_ADDRESS_KIND,
                &[
                    (ADDR_IFACE, "en0"),
                    (ADDR_CIDR, "fe80::1857:ec5:fe03:af06/64"),
                ],
            ),
            resource(
                IP_ADDRESS_KIND,
                &[(ADDR_IFACE, "lo0"), (ADDR_CIDR, "127.0.0.1/8")],
            ),
            resource(IP_ADDRESS_KIND, &[(ADDR_IP, "169.254.10.20")]),
        ]));

        assert_eq!(summary.network_addresses, vec!["en0 192.168.3.178/24"]);
    }

    #[test]
    fn host_and_network_changes_do_not_change_the_content_digest() {
        // 关键不变式：改机器名、换网络（DHCP）不该触发重报与重算 ——
        // 摘要回答的是“这台机器是干什么用的”，不是“它叫什么、在哪”。
        let base = summary(&snapshot(vec![process("a")]));
        let mut renamed = summary(&snapshot(vec![process("a")]));
        renamed.host_id = "another-mid".to_string();
        renamed.host_name = "another-name".to_string();
        renamed.network_addresses = vec!["en1 10.0.0.9/24".to_string()];

        assert_eq!(base.content_digest(), renamed.content_digest());
    }

    #[test]
    fn os_and_arch_come_from_the_host() {
        let summary = summary(&snapshot(Vec::new()));
        assert_eq!(summary.os, std::env::consts::OS);
        assert_eq!(summary.arch, std::env::consts::ARCH);
        assert_eq!(summary.revision, 7);
        assert_eq!(summary.observed_at, "2026-09-22T00:00:00Z");
        // 包清单探针还没有，别让「没采」看起来像「没装」。
        assert!(summary.packages.is_empty());
    }
}
