//! 数据库自探的**公共层**：运行时的端口与地址、证据读能力、凭据 key。
//!
//! MySQL / PostgreSQL / Doris 的自探只有两件事不同：**证据**（读哪个配置文件、看哪段 argv）
//! 与**握手**（怎么确认端口上真的是这个库）。其余都对运行时敏感而与数据库无关，
//! 所以放在这里，三个域共用一份：
//!
//! - 端口：宿主进程按「该进程自己的 netns / 监听表」取（Linux `/proc/<pid>/net/tcp`，
//!   macOS libproc）；容器里的库按**容器发布端口**取（`container_port` 资源，
//!   目前由 macOS 的 Docker 探针产出）；
//! - 地址：先回环（同 netns / compose 发布了端口），再该 netns 的非回环地址
//!   （docker bridge IP / pod IP）；
//! - 身份：host 用端口，容器用 pod / 容器名（一个节点上多个 3306 不会互相覆盖凭据）。

use std::collections::BTreeMap;
// 只有 Linux 实现（`/proc/<pid>/fd` 反查 inode）和测试用到。
#[cfg(target_os = "linux")]
use std::collections::BTreeSet;
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use wist_contracts::discovery::DiscoverySnapshot;

/// 单次 TCP 握手超时（自探在采集启动前跑，一个实例通常只有一两个候选）。
pub(crate) const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);
/// 单个 netns 最多试几个地址（回环 + 少量 veth / pod IP + 绑定地址）。
pub(crate) const MAX_ADDRS_PER_NETNS: usize = 4;
/// `cmdline` 的读取上限。
///
/// **不能是 4 KiB**：Doris FE 是 Java，classpath 常 6–30 KiB，主类（`org.apache.doris.DorisFE`）
/// 与 `fe.conf` 路径都在末尾；截断后 `is_fe` 会把真 FE 判成「不是 FE」。
/// PostgreSQL / MySQL 的 argv 很短，抬高的只是候选进程的读量（多数进程会被 `may_be_server` 先筛掉）。
///
/// 只在 Linux 实现里用到；macOS 的上限是内核的 `KERN_ARGMAX`。
#[cfg(any(target_os = "linux", test))]
pub(crate) const MAX_PROC_BYTES: usize = 64 * 1024;
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
    /// 该进程**监听 socket 实际绑定的**非回环、非通配地址。
    ///
    /// 需要它是因为 `bind-address = 10.0.0.5` 的实例不接回环：
    /// 只试 `127.0.0.1` 会把一台活着的库判成「没有端点」。
    fn bound_addrs(&self, pid: u32) -> Vec<String>;
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
    let mut addrs: Vec<String> = Vec::new();
    if same_netns {
        // 同 netns：先回环，再补「只绑了某张网卡」的实例的绑定地址。
        addrs.push("127.0.0.1".to_string());
        push_unique(&mut addrs, proc.bound_addrs(pid));
        return addrs;
    }

    // 容器：**先试它自己的地址**。
    //
    // 顺序很关键：宿主上可能也跑着一个同端口的实例（比如宿主装了 MySQL，
    // pod 里也有一个 3306）。先试 127.0.0.1 会握手上宿主的库，然后拿 pod 的凭据
    // 去连——结果是「密码错」加「把宿主实例记到 pod 的凭据 key 上」，两个都错得很难查。
    push_unique(&mut addrs, proc.net_addrs(pid));
    addrs.push("127.0.0.1".to_string());
    if addrs.len() == 1 {
        log::debug!(
            "event=DbNetnsAddrUnavailable domain={domain} source_ref=pid:{pid} detail=\"容器网络里没读到非回环地址：只能试宿主回环（compose 发布端口时仍可用）\""
        );
    }
    addrs
}

fn push_unique(addrs: &mut Vec<String>, candidates: Vec<String>) {
    for addr in candidates {
        if addrs.len() >= MAX_ADDRS_PER_NETNS {
            return;
        }
        if addr != "127.0.0.1" && !addrs.contains(&addr) {
            addrs.push(addr);
        }
    }
}

/// 容器发布到宿主的 TCP 端口（目前只有 macOS 的容器探针会产出）。
pub(crate) const CONTAINER_PORT_KIND: &str = "container_port";

/// 一个「容器里的库」候选：宿主看不到它的进程，只能看到发布出来的端口。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ContainerPort {
    pub container_id: String,
    pub container_name: Option<String>,
    pub image: String,
    pub host: String,
    pub port: u16,
}

pub(crate) fn container_ports(snapshot: &DiscoverySnapshot) -> Vec<ContainerPort> {
    snapshot
        .resources
        .iter()
        .filter(|resource| resource.kind == CONTAINER_PORT_KIND)
        .filter(|resource| {
            resource
                .attributes
                .get("endpoint.protocol")
                .is_some_and(|protocol| protocol.eq_ignore_ascii_case("tcp"))
        })
        .filter_map(|resource| {
            let port = resource
                .attributes
                .get("endpoint.bind.port")
                .and_then(|value| value.parse::<u16>().ok())?;
            let ip = resource
                .attributes
                .get("endpoint.bind.ip")
                .map(String::as_str)
                .unwrap_or("");
            Some(ContainerPort {
                container_id: resource
                    .attributes
                    .get("container.id")
                    .cloned()
                    .unwrap_or_default(),
                container_name: resource
                    .attributes
                    .get("container.name")
                    .cloned()
                    .filter(|name| !name.is_empty()),
                image: resource
                    .attributes
                    .get("container.image")
                    .cloned()
                    .unwrap_or_default(),
                host: published_host(ip),
                port,
            })
        })
        .collect()
}

/// 通配/空绑定地址都落到回环：容器发布端口就在本机。
fn published_host(ip: &str) -> String {
    if ip.is_empty() || ip == "0.0.0.0" || ip == "::" {
        "127.0.0.1".to_string()
    } else {
        ip.to_string()
    }
}

/// 容器端点的凭据身份：用**容器名**（与 Linux 容器侧一个口径），
/// 容器重建（IP/发布端口变了）也不会把凭据错拐到别的实例上。
pub(crate) fn container_identity(port: &ContainerPort) -> ContainerIdentity {
    ContainerIdentity {
        name: port.container_name.clone(),
        ..Default::default()
    }
}

/// 一次自探最多接受几个**容器里的库**（预算限的是握手，不是看多少条端口）。
const MAX_CONTAINER_TARGETS: usize = 8;

/// 已确认为某个产品的容器实例。
pub(crate) struct ContainerDbTarget {
    pub source_ref: String,
    pub host: String,
    pub port: u16,
    pub credential_key: String,
    pub image: String,
}

/// 从容器发布端口里挑出**这个产品**的实例。
///
/// `is_product` 只判「这个镜像像不像」，最终仍由 `handshake` 确认协议 —— 与宿主进程
/// 那条路径同一个两段式（`may_be_server` + argv/端口 → 握手），所以不会把 MySQL 的
/// 3306 当成 PostgreSQL。
pub(crate) fn container_targets(
    snapshot: &DiscoverySnapshot,
    mut is_product: impl FnMut(&str) -> bool,
    mut handshake: impl FnMut(&str) -> bool,
) -> Vec<ContainerDbTarget> {
    let mut out = Vec::new();
    for port in container_ports(snapshot) {
        if out.len() >= MAX_CONTAINER_TARGETS {
            break;
        }
        if !is_product(&port.image) {
            continue;
        }
        if !handshake(&format!("{}:{}", port.host, port.port)) {
            continue;
        }
        let identity = container_identity(&port);
        let source_ref = match &port.container_name {
            Some(name) => format!("container:{name}"),
            None => format!("port:{}", port.port),
        };
        out.push(ContainerDbTarget {
            source_ref,
            credential_key: credential_key(
                InstanceScope::Container,
                &port.host,
                port.port,
                Some(&identity),
            ),
            host: port.host,
            port: port.port,
            image: port.image,
        });
    }
    out
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
    let out = out.trim_end_matches('-').to_string();
    // 空 key 会让凭据路径退化成根目录（`secrets/mysql/password`），必须兜住。
    if out.is_empty() {
        "unknown".to_string()
    } else {
        out
    }
}

/// 进程视角的文件路径。
///
/// Linux 走 `/proc/<pid>/root`：容器里运行时读到的是**容器内**的 `/etc/my.cnf`。
/// macOS 没有 netns（容器跑在 Linux VM 里，宿主进程看不到），直接读真实路径。
#[cfg(target_os = "linux")]
pub(crate) fn rooted(pid: u32, path: &str) -> String {
    format!("/proc/{pid}/root{path}")
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn rooted(_pid: u32, path: &str) -> String {
    path.to_string()
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
    #[cfg(target_os = "linux")]
    fn net_file(pid: u32, name: &str) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/net/{name}")).ok()
    }
}

#[cfg(target_os = "linux")]
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

    fn bound_addrs(&self, pid: u32) -> Vec<String> {
        let mut out = Vec::new();
        for name in ["tcp", "tcp6"] {
            let Some(text) = Self::net_file(pid, name) else {
                continue;
            };
            out.extend(bound_addrs_in_table(&text));
        }
        out.sort();
        out.dedup();
        out
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

// ── macOS：libproc + sysctl ─────────────────────────────────────────
/// `/proc/<pid>/net/tcp{,6}` 里状态为 `0A`（LISTEN）的本地端口。
///
/// `test` 也编译：纯解析，在 macOS 开发机上也能跑用例。
#[cfg(any(target_os = "linux", test))]
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

/// `/proc/<pid>/net/tcp` 里 LISTEN 行绑定的**具体** IPv4 地址（跳过通配与回环）。
///
/// 只要 IPv4：IPv6 绑定地址在容器里常见的是 `::`（通配），具体地址基本用不上，
/// 而为它写一套 hex 解析换不来收益。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn bound_addrs_in_table(text: &str) -> Vec<String> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 4 || fields[3] != "0A" {
            continue;
        }
        let Some((addr, _)) = fields[1].split_once(':') else {
            continue;
        };
        // v4 地址是**小端**的 32 位十六进制：0100007F = 127.0.0.1。
        if addr.len() != 8 {
            continue;
        }
        let Ok(raw) = u32::from_str_radix(addr, 16) else {
            continue;
        };
        let bytes = raw.to_le_bytes();
        let ip = format!("{}.{}.{}.{}", bytes[0], bytes[1], bytes[2], bytes[3]);
        if ip.starts_with("127.") || ip == "0.0.0.0" {
            continue;
        }
        out.push(ip);
    }
    out
}

/// 该 pid 自己持有的监听端口（`/proc/<pid>/fd` 的 socket inode → 表里的 inode）。
///
/// 读不到（无权限 / 已退出）时返回空，调用方会退化为「该 netns 的全部监听端口」——
/// 多出来的候选端口会被握手筛掉。
#[cfg(target_os = "linux")]
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
#[cfg(any(target_os = "linux", test))]
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

// ── macOS：libproc + sysctl ───────────────────────────────────────
//
// 与 Linux **同一套语义**（进程 → argv → 配置证据 → 监听端口 → 握手），只换事实来源：
//   · 端口 / 绑定地址：复用端点探针的 libproc 实现（已能按 pid 枚举监听 socket）；
//   · argv：`sysctl(KERN_PROCARGS2)`，不引外部二进制（与 `endpoint_macos.rs` 同一取舍）；
//   · 配置文件：直接读真实路径（`rooted` 在非 Linux 上是恒等）；
//   · netns：macOS 没有，恒为同一个 ⇒ 端点按 `Host` 口径记住，凭据 key 是 `port-<port>`。
//
// 覆盖边界：只能看到**宿主进程**。Docker Desktop 的库在 Linux VM 里，宿主 libproc
// 只能看到 Docker 自己的转发进程，argv 不像数据库 —— 那类现场不属于本路径。

#[cfg(target_os = "macos")]
impl DbProc for RealProc {
    fn cmdline(&self, pid: u32) -> Vec<String> {
        mac_procargs(pid)
    }

    fn read_file(&self, path: &str) -> Option<String> {
        use std::io::Read;

        let file = std::fs::File::open(path).ok()?;
        let mut buf = Vec::new();
        file.take(MAX_EVIDENCE_BYTES).read_to_end(&mut buf).ok()?;
        Some(String::from_utf8_lossy(&buf).to_string())
    }

    fn listen_ports(&self, pid: u32) -> Vec<u16> {
        let mut ports: Vec<u16> = crate::discovery::endpoint::listening_tcp_for_pid(pid)
            .into_iter()
            .map(|(_, port)| port)
            .collect();
        ports.sort_unstable();
        ports.dedup();
        ports
    }

    fn net_addrs(&self, _pid: u32) -> Vec<String> {
        // macOS 没有 netns 视角：容器在 Linux VM 里，宿主的 libproc 看不到它们的地址。
        Vec::new()
    }

    fn bound_addrs(&self, pid: u32) -> Vec<String> {
        bound_addrs_from_listeners(&crate::discovery::endpoint::listening_tcp_for_pid(pid))
    }

    fn same_netns(&self, _pid: u32) -> bool {
        // 没有 netns：所有能看到的进程都与 agentd 同域。
        true
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
impl DbProc for RealProc {
    fn cmdline(&self, _pid: u32) -> Vec<String> {
        Vec::new()
    }

    fn read_file(&self, _path: &str) -> Option<String> {
        None
    }

    fn listen_ports(&self, _pid: u32) -> Vec<u16> {
        Vec::new()
    }

    fn net_addrs(&self, _pid: u32) -> Vec<String> {
        Vec::new()
    }

    fn bound_addrs(&self, _pid: u32) -> Vec<String> {
        Vec::new()
    }

    fn same_netns(&self, _pid: u32) -> bool {
        false
    }
}

/// 监听端点里**具体绑定**的非回环地址。
///
/// 需要它是因为 `bind-address = 10.0.0.5` 的实例不接回环：只试 `127.0.0.1`
/// 会把一台活着的库判成「没有端点」。通配（`0.0.0.0` / `::`）不算具体地址。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn bound_addrs_from_listeners(listeners: &[(String, u16)]) -> Vec<String> {
    let mut out: Vec<String> = listeners
        .iter()
        .map(|(addr, _)| addr.clone())
        .filter(|addr| !addr.starts_with("127.") && addr != "0.0.0.0")
        .filter(|addr| addr != "::" && addr != "::1" && !addr.starts_with("fe80::"))
        .collect();
    out.sort();
    out.dedup();
    out
}

/// `sysctl(KERN_PROCARGS2)` 拿一个进程的 argv。
///
/// 为什么不用 `ps`：长驻探针每多一个外部二进制就多一个「生产机上没装 / PATH 不对」
/// 的故障点；`endpoint_macos.rs` 选 libproc 也是同一个理由。
#[cfg(target_os = "macos")]
fn mac_procargs(pid: u32) -> Vec<String> {
    let Some(arg_max) = arg_max() else {
        return Vec::new();
    };
    let mut buf = vec![0u8; arg_max];
    let mut size = arg_max;
    let mut mib = [CTL_KERN, KERN_PROCARGS2, pid as libc::c_int];
    // SAFETY: `mib`/`buf`/`size` 都是本函数拥有的有效内存；sysctl 只写入 `buf`
    // 的前 `size` 字节，并把实际长度回写到 `size`。
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            buf.as_mut_ptr().cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    if rc != 0 || size < 4 {
        return Vec::new();
    }
    buf.truncate(size);
    parse_procargs2(&buf)
}

#[cfg(target_os = "macos")]
const CTL_KERN: libc::c_int = 1;
#[cfg(target_os = "macos")]
const KERN_ARGMAX: libc::c_int = 8;
/// `sys/sysctl.h`：`KERN_PROCARGS2`（libc 未导出，按头文件取值）。
#[cfg(target_os = "macos")]
const KERN_PROCARGS2: libc::c_int = 49;

/// `KERN_ARGMAX` 只查一次：它是内核常量，与进程无关。
///
/// **只缓存成功**：一次 `sysctl` 失败（极端情况）不该把整台机器的 argv 能力永久打死。
#[cfg(target_os = "macos")]
fn arg_max() -> Option<usize> {
    static ARG_MAX: std::sync::OnceLock<usize> = std::sync::OnceLock::new();
    if let Some(value) = ARG_MAX.get() {
        return Some(*value);
    }
    let value = probe_arg_max()?;
    let _ = ARG_MAX.set(value);
    Some(value)
}

#[cfg(target_os = "macos")]
fn probe_arg_max() -> Option<usize> {
    let mut value: libc::c_int = 0;
    let mut size = std::mem::size_of::<libc::c_int>();
    let mut mib = [CTL_KERN, KERN_ARGMAX];
    // SAFETY: 同上；这里只写一个 `c_int`。
    let rc = unsafe {
        libc::sysctl(
            mib.as_mut_ptr(),
            mib.len() as libc::c_uint,
            (&mut value as *mut libc::c_int).cast::<libc::c_void>(),
            &mut size,
            std::ptr::null_mut(),
            0,
        )
    };
    (rc == 0 && value > 0).then_some(value as usize)
}

/// 解析 `KERN_PROCARGS2` 的缓冲区。
///
/// 布局：`argc: i32`（原生字节序）→ `exec_path\0` → 一段 `\0` 对齐填充 →
/// `argv[0]\0 … argv[argc-1]\0` → 环境变量。
///
/// 缺陷（已知、可接受）：空字符串参数与对齐填充在字节上不可区分，会被当成填充跳过。
/// 对 argv 的用途（找 `--defaults-file` / `-D` / `--port` / Doris 的 classpath）没有影响。
/// 纯函数：偏移和字节序是最容易写错的地方，必须有能跑的用例盯着。
#[cfg(any(target_os = "macos", test))]
pub(crate) fn parse_procargs2(buf: &[u8]) -> Vec<String> {
    if buf.len() < 4 {
        return Vec::new();
    }
    let argc = i32::from_ne_bytes([buf[0], buf[1], buf[2], buf[3]]);
    if argc <= 0 {
        return Vec::new();
    }
    let mut rest = &buf[4..];
    // 跳过 exec_path。
    let Some(nul) = rest.iter().position(|byte| *byte == 0) else {
        return Vec::new();
    };
    rest = &rest[nul + 1..];
    // 跳过对齐填充（连续的 NUL）。
    let start = rest
        .iter()
        .position(|byte| *byte != 0)
        .unwrap_or(rest.len());
    rest = &rest[start..];

    let mut argv = Vec::with_capacity(argc as usize);
    for chunk in rest.split(|byte| *byte == 0) {
        if argv.len() >= argc as usize || chunk.is_empty() {
            break;
        }
        argv.push(String::from_utf8_lossy(chunk).to_string());
    }
    argv
}

/// 测试用：拼一条 `container_port` 资源（容器探针在 macOS 上的产出形状）。
#[cfg(test)]
pub(crate) fn container_port_fixture(
    container_id: &str,
    name: &str,
    image: &str,
    ip: &str,
    host_port: u16,
) -> wist_contracts::discovery::DiscoveredResource {
    wist_contracts::discovery::DiscoveredResource {
        resource_id: format!("{container_id}:port:{host_port}"),
        kind: CONTAINER_PORT_KIND.to_string(),
        origin_idx: 0,
        attributes: BTreeMap::from([
            ("container.id".to_string(), container_id.to_string()),
            ("container.name".to_string(), name.to_string()),
            ("container.image".to_string(), image.to_string()),
            ("endpoint.protocol".to_string(), "tcp".to_string()),
            ("endpoint.bind.ip".to_string(), ip.to_string()),
            ("endpoint.bind.port".to_string(), host_port.to_string()),
        ]),
        discovered_at: "2026-11-08T00:00:00Z".to_string(),
        last_seen_at: "2026-11-08T00:00:00Z".to_string(),
        health: "healthy".to_string(),
        source: "container".to_string(),
    }
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
        assert_eq!(sanitize_key("---"), "unknown", "空 key 会退化成凭据根目录");
        assert_eq!(sanitize_key(""), "unknown");
    }

    #[test]
    fn bound_addrs_skip_wildcard_and_loopback() {
        // 0100007F = 127.0.0.1，00000000 = 0.0.0.0，0A00000A = 10.0.0.10
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 1 1
   1: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 2 1
   2: 0A00000A:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 3 1
   3: 0A00000A:0CEA 0A00000B:1234 01 00000000:00000000 00:00000000 00000000   999        0 4 1
";
        assert_eq!(bound_addrs_in_table(table), vec!["10.0.0.10".to_string()]);
    }

    #[test]
    fn proc_cmdline_cap_leaves_room_for_a_java_classpath() {
        // 这个上限是 PG / MySQL / Doris 共用的。Doris FE 是 Java，classpath 就是几 KiB，
        // 主类在末尾；4 KiB 的封顶会让真 FE 被判成“不是 FE”。
        assert!(
            std::hint::black_box(MAX_PROC_BYTES) >= 32 * 1024,
            "MAX_PROC_BYTES={MAX_PROC_BYTES} 会把 Java FE 的 cmdline 截断到看不到主类"
        );
    }

    // ── macOS：KERN_PROCARGS2 解析（纯函数，Linux CI 也跑） ──────────────

    /// 按内核的布局拼一个 `KERN_PROCARGS2` 缓冲区。
    #[cfg(any(target_os = "macos", test))]
    fn procargs2(exec_path: &str, argv: &[&str], padding: usize) -> Vec<u8> {
        let mut buf = Vec::new();
        buf.extend_from_slice(&(argv.len() as i32).to_ne_bytes());
        buf.extend_from_slice(exec_path.as_bytes());
        buf.push(0);
        buf.extend(std::iter::repeat_n(0u8, padding));
        for arg in argv {
            buf.extend_from_slice(arg.as_bytes());
            buf.push(0);
        }
        buf.extend_from_slice(b"PATH=/usr/bin\0");
        buf
    }

    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn procargs2_skips_exec_path_and_alignment_padding() {
        let buf = procargs2(
            "/opt/homebrew/opt/postgresql@16/bin/postgres",
            &["postgres", "-D", "/opt/homebrew/var/postgresql@16"],
            3,
        );
        assert_eq!(
            parse_procargs2(&buf),
            vec![
                "postgres".to_string(),
                "-D".to_string(),
                "/opt/homebrew/var/postgresql@16".to_string(),
            ],
            "argc 之后要跳过 exec_path 与对齐填充，且不能把环境变量当 argv"
        );
    }

    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn procargs2_rejects_truncated_or_empty_buffers() {
        assert!(parse_procargs2(&[]).is_empty());
        assert!(parse_procargs2(&[0, 0, 0]).is_empty(), "不到 4 字节");
        assert!(parse_procargs2(&0i32.to_ne_bytes()).is_empty(), "argc = 0");
        assert!(
            parse_procargs2(&(-3i32).to_ne_bytes()).is_empty(),
            "argc < 0"
        );
        // 只有 argc + exec_path，没有 NUL 结尾：不动 panic。
        let mut no_nul = 1i32.to_ne_bytes().to_vec();
        no_nul.extend_from_slice(b"/bin/sh");
        assert!(parse_procargs2(&no_nul).is_empty());
    }

    // ── macOS：具体绑定地址的筛选（纯函数） ────────────────────────────

    #[cfg(any(target_os = "macos", test))]
    #[test]
    fn bound_addrs_from_listeners_keep_only_specific_non_loopback() {
        let listeners = vec![
            ("127.0.0.1".to_string(), 5432),
            ("0.0.0.0".to_string(), 5432),
            ("::".to_string(), 5432),
            ("::1".to_string(), 5432),
            ("fe80::1".to_string(), 5432),
            ("10.0.0.5".to_string(), 5432),
            ("10.0.0.5".to_string(), 5433),
        ];
        assert_eq!(
            bound_addrs_from_listeners(&listeners),
            vec!["10.0.0.5".to_string()],
            "回环 / 通配 / 链路本地地址都不算具体绑定"
        );
    }

    // ── 平台事实来源的冒烟用例 ───────────────────────────────────────

    #[cfg(not(target_os = "linux"))]
    #[test]
    fn rooted_is_identity_without_netns() {
        assert_eq!(
            rooted(42, "/opt/homebrew/etc/my.cnf"),
            "/opt/homebrew/etc/my.cnf"
        );
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn rooted_enters_the_process_mount_namespace() {
        assert_eq!(rooted(42, "/etc/my.cnf"), "/proc/42/root/etc/my.cnf");
    }

    /// 真 libproc：自己刚绑的监听口必须被看见。
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_listen_ports_see_our_own_listener() {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).expect("bind loopback");
        let port = listener.local_addr().expect("local_addr").port();
        let ports = RealProc.listen_ports(std::process::id());
        assert!(
            ports.contains(&port),
            "ports={ports:?} 应包含自己刚绑的 {port}"
        );
    }

    /// 真 sysctl：自己的 argv 读得回来（cargo test 的 argv[0] 在 `target/.../deps/` 下）。
    #[cfg(target_os = "macos")]
    #[test]
    fn macos_cmdline_reads_our_own_argv() {
        let argv = RealProc.cmdline(std::process::id());
        assert!(!argv.is_empty(), "KERN_PROCARGS2 读不到自己的 argv");
        assert!(
            argv.iter().any(|arg| arg.contains("deps")),
            "argv={argv:?} 应包含测试二进制路径"
        );
    }

    // ── 容器发布端口（macOS / Docker） ────────────────────────────────

    fn snapshot_with(
        resources: Vec<wist_contracts::discovery::DiscoveredResource>,
    ) -> DiscoverySnapshot {
        let mut snapshot =
            DiscoverySnapshot::new("t".to_string(), 0, "2026-11-08T00:00:00Z".to_string());
        snapshot.resources = resources;
        snapshot
    }

    #[test]
    fn container_ports_normalize_published_binds() {
        let snapshot = snapshot_with(vec![
            container_port_fixture("c1", "pg-probe-test", "postgres:16", "0.0.0.0", 55999),
            container_port_fixture("c2", "mysql", "mysql:8", "::", 33060),
            container_port_fixture("c3", "bound", "postgres", "10.0.0.9", 5432),
        ]);
        let ports = container_ports(&snapshot);
        assert_eq!(ports.len(), 3);
        assert_eq!(ports[0].host, "127.0.0.1", "通配绑定落到回环");
        assert_eq!(ports[1].host, "127.0.0.1", "IPv6 通配也落到回环");
        assert_eq!(ports[2].host, "10.0.0.9", "具体绑定地址保留");
        assert_eq!(ports[0].port, 55999);
        assert_eq!(ports[0].image, "postgres:16");
    }

    #[test]
    fn container_targets_filter_by_image_and_require_the_handshake() {
        let snapshot = snapshot_with(vec![
            container_port_fixture("c1", "pg-probe-test", "postgres:16", "0.0.0.0", 55999),
            container_port_fixture("c2", "mysql", "mysql:8", "0.0.0.0", 33060),
        ]);
        // 只有握手通过的那条算；镜像是 MySQL 的不该被 PG 认领。
        let targets = container_targets(
            &snapshot,
            |image| image.contains("postgres"),
            |addr| addr == "127.0.0.1:55999",
        );
        assert_eq!(targets.len(), 1);
        assert_eq!(targets[0].host, "127.0.0.1");
        assert_eq!(targets[0].port, 55999);
        assert_eq!(targets[0].source_ref, "container:pg-probe-test");
        assert_eq!(
            targets[0].credential_key, "container-pg-probe-test",
            "容器凭据按名字，不随发布端口变"
        );
    }

    #[test]
    fn container_targets_respect_the_per_product_budget() {
        let resources = (0..12)
            .map(|index| {
                container_port_fixture(
                    &format!("c{index}"),
                    &format!("pg-{index}"),
                    "postgres:16",
                    "0.0.0.0",
                    50000 + index as u16,
                )
            })
            .collect();
        let snapshot = snapshot_with(resources);
        let targets = container_targets(&snapshot, |_| true, |_| true);
        assert_eq!(
            targets.len(),
            super::MAX_CONTAINER_TARGETS,
            "预算限的是握手次数"
        );
    }

    #[test]
    fn container_ports_ignore_non_tcp_and_malformed_entries() {
        let mut udp = container_port_fixture("c1", "dns", "coredns", "0.0.0.0", 53);
        udp.attributes
            .insert("endpoint.protocol".to_string(), "udp".to_string());
        let mut no_port = container_port_fixture("c2", "x", "postgres:16", "0.0.0.0", 5432);
        no_port.attributes.remove("endpoint.bind.port");
        // 同样带端口的 `service_endpoint` 不能被当成容器发布端口。
        let mut other_kind = container_port_fixture("c3", "y", "postgres:16", "0.0.0.0", 5433);
        other_kind.kind = "service_endpoint".to_string();

        let snapshot = snapshot_with(vec![udp, no_port, other_kind]);
        assert!(
            container_ports(&snapshot).is_empty(),
            "只认 kind=container_port + tcp + 有端口"
        );
    }

    #[test]
    fn a_nameless_container_falls_back_to_its_address_key() {
        let snapshot = snapshot_with(vec![container_port_fixture(
            "c1",
            "",
            "postgres:16",
            "0.0.0.0",
            55999,
        )]);
        let targets = container_targets(&snapshot, |_| true, |_| true);
        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].source_ref, "port:55999",
            "没名字时审计口径退回端口"
        );
        assert_eq!(
            targets[0].credential_key, "addr-127-0-0-1-55999",
            "没名字时凭据用地址（与 Linux 容器侧同一回退）"
        );
    }

    #[test]
    fn container_targets_skip_ports_whose_image_does_not_match() {
        let snapshot = snapshot_with(vec![container_port_fixture(
            "c1", "cache", "redis:7", "0.0.0.0", 6379,
        )]);
        let targets = container_targets(&snapshot, |image| image.contains("postgres"), |_| true);
        assert!(
            targets.is_empty(),
            "镜像不像就不握手，否则每个容器都会被三个产品各探一次"
        );
    }

    // ── macOS 平台层的其余语义 ──────────────────────────────────────

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_has_no_netns_and_no_container_addresses() {
        let pid = std::process::id();
        assert!(RealProc.same_netns(pid), "macOS 没有 netns，恒为同域");
        assert!(
            RealProc.net_addrs(pid).is_empty(),
            "容器的地址不在宿主视野里"
        );
    }
}
