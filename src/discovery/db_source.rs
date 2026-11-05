//! 数据库自探的**公共层**：netns 视角的端口与地址、运行时判据、凭据 key。
//!
//! MySQL / PostgreSQL / Doris 的自探只有两件事不同：**证据**（读哪个配置文件、看哪段 argv）
//! 与**握手**（怎么确认端口上真的是这个库）。其余都对运行时敏感而与数据库无关，
//! 所以放在这里，三个域共用一份：
//!
//! - 端口：`/proc/<pid>/net/tcp`（**该进程 netns** 的表，不是宿主的）；
//! - 地址：先回环（同 netns / compose 发布了端口），再该 netns 的非回环地址
//!   （docker bridge IP / pod IP）；
//! - 身份：host 用端口，容器用 pod / 容器名（一个节点上多个 3306 不会互相覆盖凭据）。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use wist_contracts::discovery::DiscoverySnapshot;

/// 单次 TCP 握手超时（自探在采集启动前跑，一个实例通常只有一两个候选）。
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);
/// 单个 netns 最多试几个地址（回环 + 少量 veth / pod IP）。
pub(crate) const MAX_ADDRS_PER_NETNS: usize = 3;
/// `cmdline` 的读取上限。
pub(crate) const MAX_PROC_BYTES: usize = 4096;
/// 配置文件读取上限（`my.cnf` / `postgresql.conf` 一般几 KB）。
pub(crate) const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;

/// 实例所在的"范围"：决定凭据目录怎么命名。
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum InstanceScope {
    /// 与 agentd 同一个 netns（host 上的 systemd 服务 / 裸二进制）。
    Host,
    /// 独立的 netns（docker / docker-compose / k8s pod）。
    Container,
}

/// 容器身份（从 `container` 探针的资源里 join 出来）。
#[derive(Default, Debug, Clone)]
pub(crate) struct ContainerIdentity {
    pub k8s_namespace: Option<String>,
    pub k8s_pod: Option<String>,
    pub name: Option<String>,
}

/// 进程证据的读取能力（生产实现 [`RealProc`]，测试用假实现）。
pub(crate) trait DbProc {
    fn cmdline(&self, pid: u32) -> Vec<String>;
    /// 读一个文件；`path` 已含 `/proc/<pid>/root` 前缀。
    fn read_file(&self, path: &str) -> Option<String>;
    /// 该进程 **netns** 里的 TCP 监听端口。
    fn listen_ports(&self, pid: u32) -> Vec<u16>;
    /// 该进程 netns 里的**非回环**地址。
    fn net_addrs(&self, pid: u32) -> Vec<String>;
    /// 进程 netns 是否与 agentd 相同。
    fn same_netns(&self, pid: u32) -> bool;
}

/// 一条已观测到的数据库进程。
pub(crate) struct ObservedProcess {
    pub pid: u32,
    pub exe: String,
    /// 进程所属容器（`/proc/<pid>/cgroup` 推出来的 id）。
    pub container_id: Option<String>,
}

pub(crate) fn processes(snapshot: &DiscoverySnapshot) -> Vec<ObservedProcess> {
    snapshot
        .resources
        .iter()
        .filter(|resource| resource.kind == "process")
        .filter_map(|resource| {
            let pid = resource.attributes.get("process.pid")?.parse().ok()?;
            let exe = resource
                .attributes
                .get("process.executable.name")
                .cloned()
                .unwrap_or_default();
            Some(ObservedProcess {
                pid,
                exe,
                container_id: resource.attributes.get("container.id").cloned(),
            })
        })
        .collect()
}

/// `container.id` → 容器身份（k8s 的 namespace/pod 名、docker 的容器名）。
pub(crate) fn container_identities(
    snapshot: &DiscoverySnapshot,
) -> BTreeMap<String, ContainerIdentity> {
    snapshot
        .resources
        .iter()
        .filter(|resource| resource.kind == "container")
        .filter_map(|resource| {
            let attrs = &resource.attributes;
            let id = attrs.get("container.id")?.clone();
            Some((
                id,
                ContainerIdentity {
                    k8s_namespace: attrs.get("k8s.namespace.name").cloned(),
                    k8s_pod: attrs.get("k8s.pod.name").cloned(),
                    name: attrs.get("container.name").cloned(),
                },
            ))
        })
        .collect()
}

/// 候选连接地址：同 netns 只有回环；否则先试回环（compose 常把端口发布到宿主），
/// 再试该 netns 自己的地址（docker bridge / pod IP）。
pub(crate) fn candidate_addrs(
    pid: u32,
    same_netns: bool,
    proc: &dyn DbProc,
    domain: &str,
) -> Vec<String> {
    let mut addrs = vec!["127.0.0.1".to_string()];
    if same_netns {
        return addrs;
    }
    for addr in proc.net_addrs(pid) {
        if addrs.len() >= MAX_ADDRS_PER_NETNS {
            break;
        }
        if addr != "127.0.0.1" && !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
    if addrs.len() == 1 {
        log::debug!(
            "event=DbNetnsAddrUnavailable domain={domain} source_ref=pid:{pid} detail=\"容器网络里没读到非回环地址：只能试宿主回环（compose 发布端口时仍可用）\""
        );
    }
    addrs
}

/// 凭据目录名。
///
/// host 用端口（一个 host 上一个 3306）；容器必须用**名字**：一个节点上多个 pod 都是
/// 3306，用端口会互相覆盖凭据 —— 而名字是运维**投放凭据之前就能知道**的东西。
pub(crate) fn credential_key(
    scope: InstanceScope,
    host: &str,
    port: u16,
    container: Option<&ContainerIdentity>,
) -> String {
    if scope == InstanceScope::Host {
        return format!("port-{port}");
    }
    let Some(container) = container else {
        return sanitize_key(&format!("addr-{host}-{port}"));
    };
    if let (Some(namespace), Some(pod)) = (&container.k8s_namespace, &container.k8s_pod) {
        return sanitize_key(&format!("pod-{namespace}-{pod}"));
    }
    match &container.name {
        Some(name) if !name.is_empty() => sanitize_key(&format!("container-{name}")),
        _ => sanitize_key(&format!("addr-{host}-{port}")),
    }
}

/// 目录名安全化：小写、只留 `[a-z0-9-]`、不重复连字符。
pub(crate) fn sanitize_key(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut last_dash = true;
    for ch in raw.chars() {
        if ch.is_ascii_alphanumeric() {
            out.push(ch.to_ascii_lowercase());
            last_dash = false;
        } else if !last_dash {
            out.push('-');
            last_dash = true;
        }
    }
    out.trim_end_matches('-').to_string()
}

pub(crate) fn rooted(pid: u32, path: &str) -> String {
    format!("/proc/{pid}/root{path}")
}

/// 现场诊断用：进程 + 端点 + 容器探针各跑一次，拼一个临时快照（不读缓存、不写盘）。
pub(crate) fn live_snapshot(tag: &str) -> DiscoverySnapshot {
    use crate::discovery::DiscoveryProbe as _;

    let now = std::time::SystemTime::now();
    let stamp = wist_shared::time::now_rfc3339();
    let mut snapshot = DiscoverySnapshot::new(format!("{tag}-candidates-live-{stamp}"), 0, stamp);
    for output in [
        crate::discovery::process::ProcessDiscoveryProbe.refresh(now),
        crate::discovery::endpoint::EndpointDiscoveryProbe.refresh(now),
        crate::discovery::container::ContainerDiscoveryProbe.refresh(now),
    ]
    .into_iter()
    .flatten()
    {
        snapshot.resources.extend(output.resources);
        snapshot.targets.extend(output.targets);
    }
    snapshot
}

/// 连上 addr，用 `probe` 读一个响应字节判断"是不是这个协议"。
pub(crate) fn tcp_probe(addr: &str, probe: impl Fn(&mut TcpStream) -> bool) -> bool {
    let Ok(mut addrs) = addr.to_socket_addrs() else {
        return false;
    };
    let Some(target) = addrs.next() else {
        return false;
    };
    let Ok(mut stream) = TcpStream::connect_timeout(&target, HANDSHAKE_TIMEOUT) else {
        return false;
    };
    let _ = stream.set_read_timeout(Some(HANDSHAKE_TIMEOUT));
    let _ = stream.set_write_timeout(Some(HANDSHAKE_TIMEOUT));
    probe(&mut stream)
}

// ---------------------------------------------------------------------------
// 生产实现
// ---------------------------------------------------------------------------

pub(crate) struct RealProc;

impl RealProc {
    /// `/proc/<pid>/net/<name>` 的文本（这就是该进程 netns 的视图）。
    fn net_file(pid: u32, name: &str) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/net/{name}")).ok()
    }
}

impl DbProc for RealProc {
    fn cmdline(&self, pid: u32) -> Vec<String> {
        use std::io::Read;

        let Ok(file) = std::fs::File::open(format!("/proc/{pid}/cmdline")) else {
            return Vec::new();
        };
        let mut buf = Vec::new();
        if file
            .take(MAX_PROC_BYTES as u64)
            .read_to_end(&mut buf)
            .is_err()
        {
            return Vec::new();
        }
        buf.split(|byte| *byte == 0)
            .filter(|chunk| !chunk.is_empty())
            .map(|chunk| String::from_utf8_lossy(chunk).to_string())
            .collect()
    }

    fn read_file(&self, path: &str) -> Option<String> {
        use std::io::Read;

        let file = std::fs::File::open(path).ok()?;
        let mut buf = Vec::new();
        file.take(MAX_EVIDENCE_BYTES).read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).to_string())
    }

    fn listen_ports(&self, pid: u32) -> Vec<u16> {
        let mut ports: BTreeSet<u16> = BTreeSet::new();
        for name in ["tcp", "tcp6"] {
            let Some(text) = Self::net_file(pid, name) else {
                continue;
            };
            ports.extend(listen_ports_in_table(&text));
        }
        let owned = owned_socket_ports(pid);
        if !owned.is_empty() {
            ports.retain(|port| owned.contains(port));
        }
        ports.into_iter().collect()
    }

    fn net_addrs(&self, pid: u32) -> Vec<String> {
        Self::net_file(pid, "fib_trie")
            .map(|text| local_addrs_in_fib(&text))
            .unwrap_or_default()
    }

    fn same_netns(&self, pid: u32) -> bool {
        let read = |path: String| std::fs::read_link(path).ok();
        match (
            read(format!("/proc/{pid}/ns/net")),
            read("/proc/self/ns/net".into()),
        ) {
            (Some(a), Some(b)) => a == b,
            // 读不到就保守当成「不同 netns」：多试一个地址而已，不会漏报。
            _ => false,
        }
    }
}

/// `/proc/<pid>/net/tcp{,6}` 里状态为 `0A`（LISTEN）的本地端口。
pub(crate) fn listen_ports_in_table(text: &str) -> Vec<u16> {
    let mut ports = Vec::new();
    for line in text.lines().skip(1) {
        // 列：`sl local_address rem_address st …`（`st=0A` 是 LISTEN）。
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[3] != "0A" {
            continue;
        }
        let Some((_, port)) = fields[1].rsplit_once(':') else {
            continue;
        };
        if let Ok(port) = u16::from_str_radix(port, 16) {
            ports.push(port);
        }
    }
    ports
}

/// 该 pid 自己持有的监听端口（`/proc/<pid>/fd` 的 socket inode → 表里的 inode）。
///
/// 读不到（无权限 / 已退出）时返回空，调用方会退化为「该 netns 的全部监听端口」——
/// 多出来的候选端口会被握手筛掉。
fn owned_socket_ports(pid: u32) -> BTreeSet<u16> {
    let mut inode_ports: BTreeMap<String, u16> = BTreeMap::new();
    for name in ["tcp", "tcp6"] {
        let Ok(text) = std::fs::read_to_string(format!("/proc/{pid}/net/{name}")) else {
            continue;
        };
        for line in text.lines().skip(1) {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 || fields[3] != "0A" {
                continue;
            }
            let Some((_, port)) = fields[1].rsplit_once(':') else {
                continue;
            };
            let (Ok(port), inode) = (u16::from_str_radix(port, 16), fields[9]) else {
                continue;
            };
            inode_ports.insert(inode.to_string(), port);
        }
    }
    if inode_ports.is_empty() {
        return BTreeSet::new();
    }

    let mut out = BTreeSet::new();
    let Ok(entries) = std::fs::read_dir(format!("/proc/{pid}/fd")) else {
        return out;
    };
    for entry in entries.flatten() {
        let Ok(target) = std::fs::read_link(entry.path()) else {
            continue;
        };
        let target = target.to_string_lossy();
        let Some(inode) = target
            .strip_prefix("socket:[")
            .and_then(|rest| rest.strip_suffix(']'))
        else {
            continue;
        };
        if let Some(port) = inode_ports.get(inode) {
            out.insert(*port);
        }
    }
    out
}

/// `/proc/<pid>/net/fib_trie` 里标了 `host LOCAL` 的非回环 IPv4 地址。
///
/// 不引 netlink：fib_trie 是内核导出的本地地址表，读一行文本就够，
/// 也不用 `setns` 或起子进程。
pub(crate) fn local_addrs_in_fib(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut pending: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if let Some(rest) = line.strip_prefix("|-- ") {
            pending = Some(rest.trim().to_string());
            continue;
        }
        let Some(addr) = pending.take() else {
            continue;
        };
        // 紧跟着的那行是分类：`/32 host LOCAL`。
        if line.contains("host LOCAL") && !addr.starts_with("127.") {
            out.push(addr);
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn listen_ports_are_read_from_the_proc_net_table() {
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 3500007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12345 1\n   1: 3500007F:9C40 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12346 1\n   2: 3500007F:0CEA 0100007F:9C40 01 00000000:00000000 00:00000000 00000000   999        0 12347 1\n";
        assert_eq!(listen_ports_in_table(table), vec![3306, 40000]);
    }

    #[test]
    fn fib_trie_yields_non_loopback_local_addresses() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 127.0.0.1\n        /32 host LOCAL\n     |-- 172.17.0.2\n        /32 host LOCAL\n     |-- 172.17.0.0\n        /16 link UNICAST\n";
        assert_eq!(local_addrs_in_fib(trie), vec!["172.17.0.2".to_string()]);
    }

    #[test]
    fn credential_keys_are_runtime_specific() {
        let k8s = ContainerIdentity {
            k8s_namespace: Some("prod".to_string()),
            k8s_pod: Some("mysql-0".to_string()),
            name: Some("mysql".to_string()),
        };
        assert_eq!(
            credential_key(InstanceScope::Host, "127.0.0.1", 3306, Some(&k8s)),
            "port-3306"
        );
        assert_eq!(
            credential_key(InstanceScope::Container, "10.0.0.5", 3306, Some(&k8s)),
            "pod-prod-mysql-0"
        );

        let docker = ContainerIdentity {
            name: Some("compose-mysql-1".to_string()),
            ..Default::default()
        };
        assert_eq!(
            credential_key(InstanceScope::Container, "172.17.0.2", 3306, Some(&docker)),
            "container-compose-mysql-1"
        );
        assert_eq!(
            credential_key(InstanceScope::Container, "172.18.0.7", 3306, None),
            "addr-172-18-0-7-3306"
        );
    }

    #[test]
    fn sanitize_key_makes_a_directory_safe_name() {
        assert_eq!(sanitize_key("pod-prod-mysql-0"), "pod-prod-mysql-0");
        assert_eq!(sanitize_key("pod-Prod_MySQL.0"), "pod-prod-mysql-0");
        assert_eq!(sanitize_key("---"), "");
    }
}
