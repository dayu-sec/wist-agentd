//! MySQL / TiDB 实例**自探**：只发现，不上报、不下发采集任务。
//!
//! 与 [`super::kafka_source`] 同一条路子：agentd 以 root 跑在数据库机器上，
//! **进程本身就是证据**。运维不需要在配置文件里写任何地址 —— 采不采、什么时候采
//! 由采集面授权决定，地址由这里给。
//!
//! ## 三种运行时同一套逻辑
//!
//! 数据目录里 MySQL 可能跑在 **host**、**docker-compose**、**k8s pod** 里。
//! 决定"连哪儿"的不是运行时类型，而是**进程所在的 network namespace**：
//!
//! 1. 端口读 `/proc/<pid>/net/tcp` —— 这是**该进程 netns** 的监听表（不是宿主的），
//!    root 直接读，不需要 `setns`；
//! 2. 地址按候选顺序逐个握手：`127.0.0.1`（同 netns / compose 发布了端口）→
//!    该 netns 里的非回环地址（docker bridge IP / pod IP，从 `/proc/<pid>/net/fib_trie` 取）；
//! 3. 第一个握得通的地址就是端点。
//!
//! 这样 host（同 netns）、compose（发布端口到回环）、k8s（pod IP）都走同一条路。
//! 前提只有一个：agentd 要能看见进程（k8s 需 DaemonSet + `hostPID: true`）。
//!
//! ## 证据层（从强到弱）
//!
//! 1. `--defaults-file` / `/etc/my.cnf` / `/etc/mysql/my.cnf` 的 `[mysqld] port=`；
//! 2. 命令行 `--port=` / `--skip-networking`；
//! 3. netns 里的 TCP 监听端口（只看得到「这里有个监听」）。
//!
//! ## 为什么还要握手
//!
//! 一个 `mysqld` 通常监听两个端口（3306 经典协议、33060 X 协议），容器里还可能有
//! 别的转发。**只认「发 Protocol 10 问候包」的端口**：TCP 能连不等于能用 SQL 采，
//! 把 X 协议端口当 MySQL 采会每轮都失败一次。
//!
//! ## 红线
//!
//! 只读白名单键：`[mysqld]` 段的 `port` / `skip-networking` / `socket`。
//! 任何含 `password` / `user` 的键一律不读、不报、不进日志。

use std::collections::{BTreeMap, BTreeSet};
use std::net::{TcpStream, ToSocketAddrs};
use std::time::Duration;

use serde::Serialize;
use wist_contracts::discovery::DiscoverySnapshot;

/// 一次解析最多看多少个进程（数据库机器上进程很多，不必全扫）。
const MAX_INSPECTED_PROCESSES: usize = 8;
/// 单个进程最多实测几个端口（3306 + 33060 + 少量转发）。
const MAX_PROBE_PORTS_PER_PROCESS: usize = 4;
/// 单个 netns 最多试几个地址（回环 + 少量 veth / pod IP）。
const MAX_ADDRS_PER_NETNS: usize = 3;
/// `cmdline` 的读取上限。
const MAX_PROC_BYTES: usize = 4096;
/// 配置文件读取上限：`my.cnf` 一般几 KB。
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
/// 单次 TCP 握手的超时（与 Kafka 自探同一量级）。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);
/// MySQL 经典协议的问候包第一字节（`protocol_version`）。
const PROTOCOL_10: u8 = 0x0a;

/// 实例所在的"范围"：决定凭据目录怎么命名。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub enum InstanceScope {
    /// 与 agentd 同一个 netns（host 上的 systemd 服务 / 裸二进制）。
    Host,
    /// 独立的 netns（docker / docker-compose / k8s pod）。
    Container,
}

/// 一条 MySQL 实例候选（自探产物；只在进程内使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MysqlInstanceEntry {
    /// 进程身份（审计用）：优先端口，pid 重启不换身份。
    pub source_ref: String,
    /// 连接地址：`127.0.0.1`（同 netns / 发布到回环）或容器 / pod IP。
    pub host: String,
    /// 经典协议端口（已通过握手）。
    pub port: u16,
    /// 凭据目录名（见设计文档 §12.1-5）：
    /// `port-<port>` / `pod-<ns>-<pod>` / `container-<name>` / `addr-<ip>-<port>`。
    pub credential_key: String,
    pub scope: InstanceScope,
    /// 证据层：`config` / `argv` / `listening_port`。
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
}

impl MysqlInstanceEntry {
    /// 指标 `instance`：容器用**凭据 key**（pod / 容器名，重启换 IP 不断档），
    /// host 用 `<ip>:<port>`（本机就是 `127.0.0.1`，与其它域一致）。
    pub fn instance(&self) -> String {
        match self.scope {
            InstanceScope::Host => format!("mysql:{}:{}", self.host, self.port),
            InstanceScope::Container => format!("mysql:{}", self.credential_key),
        }
    }
}

/// 端口探活能力（生产实现 [`TcpHandshake`]，测试用假实现）。
pub trait Handshake {
    fn mysql_greeting(&self, addr: &str) -> bool;
}

/// 生产实现：TCP 连上并读第一个字节。
pub struct TcpHandshake;

impl Handshake for TcpHandshake {
    fn mysql_greeting(&self, addr: &str) -> bool {
        mysql_greeting(addr)
    }
}

/// 从发现快照解析本机 MySQL 候选。
pub fn resolve_from_snapshot(snapshot: &DiscoverySnapshot) -> Vec<MysqlInstanceEntry> {
    resolve(snapshot, &RealProc, &TcpHandshake)
}

/// 现场诊断用：立即跑一次进程 / 端点 / 容器发现再解析（不读缓存、不写盘）。
pub fn resolve_live() -> Vec<MysqlInstanceEntry> {
    use crate::discovery::DiscoveryProbe as _;

    let now = std::time::SystemTime::now();
    let stamp = wist_shared::time::now_rfc3339();
    let mut snapshot = DiscoverySnapshot::new(format!("mysql-candidates-live-{stamp}"), 0, stamp);
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
    resolve_from_snapshot(&snapshot)
}

// ---------------------------------------------------------------------------
// 解析主体
// ---------------------------------------------------------------------------

/// 读进程证据的能力（生产实现 [`RealProc`]，测试用假实现）。
trait MysqlProc {
    fn cmdline(&self, pid: u32) -> Vec<String>;
    /// 读一个文件；`path` 已含 `/proc/<pid>/root` 前缀。
    fn read_file(&self, path: &str) -> Option<String>;
    /// 该进程 **netns** 里的 TCP 监听端口（读 `/proc/<pid>/net/tcp{,6}`）。
    ///
    /// 与宿主 `/proc/net/tcp` 的区别就是容器：pod 里的监听在宿主表里看不到。
    fn listen_ports(&self, pid: u32) -> Vec<u16>;
    /// 该进程 netns 里的**非回环**地址（docker bridge IP / pod IP）。
    fn net_addrs(&self, pid: u32) -> Vec<String>;
    /// 进程 netns 是否与 agentd 相同（同为 `net:[inode]`）。
    fn same_netns(&self, pid: u32) -> bool;
}

struct ObservedProcess {
    pid: u32,
    exe: String,
    /// 进程所属容器（`/proc/<pid>/cgroup` 推出来的 id）。
    container_id: Option<String>,
}

/// 容器身份（从 `container` 探针的资源里 join 出来）。
#[derive(Default)]
struct ContainerIdentity {
    k8s_namespace: Option<String>,
    k8s_pod: Option<String>,
    name: Option<String>,
}

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn MysqlProc,
    handshake: &dyn Handshake,
) -> Vec<MysqlInstanceEntry> {
    let snapshot_ports = tcp_ports(snapshot);
    let containers = container_identities(snapshot);
    let mut by_target: BTreeMap<(String, u16), MysqlInstanceEntry> = BTreeMap::new();
    let mut inspected = 0usize;

    for process in processes(snapshot) {
        if inspected >= MAX_INSPECTED_PROCESSES {
            break;
        }
        // 先按可执行名粗筛再读 argv：一台机器上进程上百个，每个都读 4 KiB 是白花。
        if !may_be_server(&process.exe) {
            continue;
        }
        let argv = proc.cmdline(process.pid);
        if !is_server(&process.exe, &argv) {
            continue;
        }
        inspected += 1;

        let Some(hint) = port_hint(&process, &argv, proc) else {
            // `--skip-networking`：只能走 socket，SQL 采不了。
            log::debug!(
                "event=MysqlNetworkingDisabled source_ref=pid:{} detail=\"进程没开 TCP 监听\"",
                process.pid
            );
            continue;
        };

        let same_netns = proc.same_netns(process.pid);
        let scope = if same_netns {
            InstanceScope::Host
        } else {
            InstanceScope::Container
        };
        let addrs = candidate_addrs(process.pid, same_netns, proc);

        let candidates = match hint.port {
            Some(port) => vec![port],
            None => {
                let mut list = proc.listen_ports(process.pid);
                if list.is_empty() {
                    // 没有 `/proc/<pid>/net`（非 Linux / 无权限）：退回快照里的端点证据。
                    list = snapshot_ports
                        .get(&process.pid)
                        .map(|entries| entries.iter().map(|(_, port)| *port).collect())
                        .unwrap_or_default();
                }
                list.truncate(MAX_PROBE_PORTS_PER_PROCESS);
                list
            }
        };

        for port in candidates {
            let Some(host) = addrs
                .iter()
                .find(|addr| handshake.mysql_greeting(&format!("{addr}:{port}")))
            else {
                log::debug!(
                    "event=MysqlPortNotMysql port={port} candidates={:?} detail=\"候选地址都没握手成功（可能是 X 协议、别的服务，或端口未发布到宿主）\"",
                    addrs
                );
                continue;
            };
            let credential_key = credential_key(
                scope,
                &host.to_string(),
                port,
                process
                    .container_id
                    .as_deref()
                    .and_then(|id| containers.get(id)),
            );
            let entry = MysqlInstanceEntry {
                source_ref: format!("port:{port}"),
                host: host.to_string(),
                port,
                credential_key,
                scope,
                evidence: hint.evidence.to_string(),
                detail: hint.detail.clone(),
                confidence: hint.confidence,
            };
            // 同一个 (地址, 端口) 只留置信度最高的那条。
            match by_target.get(&(entry.host.clone(), port)) {
                Some(existing) if existing.confidence >= entry.confidence => {}
                _ => {
                    by_target.insert((entry.host.clone(), port), entry);
                }
            }
        }
    }

    let mut out: Vec<MysqlInstanceEntry> = by_target.into_values().collect();
    out.sort_by_key(|entry| (entry.host.clone(), entry.port));
    out
}

/// 候选连接地址：同 netns 只有回环；否则先试回环（compose 常把端口发布到宿主），
/// 再试该 netns 自己的地址（docker bridge / pod IP）。
fn candidate_addrs(pid: u32, same_netns: bool, proc: &dyn MysqlProc) -> Vec<String> {
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
            "event=MysqlNetnsAddrUnavailable source_ref=pid:{pid} detail=\"容器网络里没读到非回环地址：只能试宿主回环（compose 发布端口时仍可用）\""
        );
    }
    addrs
}

/// 凭据目录名。
///
/// host 用端口（一个 host 上一个 3306）；容器必须用**名字**：一个节点上多个 pod 都是
/// 3306，用端口会互相覆盖凭据。
fn credential_key(
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
fn sanitize_key(raw: &str) -> String {
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

/// 端口从哪来。
struct PortHint {
    port: Option<u16>,
    evidence: &'static str,
    detail: String,
    confidence: i64,
}

/// 依证据强弱给出端口假设；`None` = 明确不能走 TCP。
fn port_hint(process: &ObservedProcess, argv: &[String], proc: &dyn MysqlProc) -> Option<PortHint> {
    if argv
        .iter()
        .any(|arg| arg == "--skip-networking" || arg == "--skip_networking")
    {
        return None;
    }

    // 1) 配置文件（`--defaults-file` 优先，否则标准路径）。
    //    走 `/proc/<pid>/root` 读：容器里跑的时候，读到的是**容器内**的 my.cnf。
    for path in defaults_files(argv) {
        let full = rooted(process.pid, &path);
        let Some(text) = proc.read_file(&full) else {
            continue;
        };
        let parsed = from_my_cnf(&text);
        if parsed.skip_networking {
            log::debug!(
                "event=MysqlNetworkingDisabled source_ref=pid:{} path=\"{path}\"",
                process.pid
            );
            return None;
        }
        if let Some(port) = parsed.port {
            return Some(PortHint {
                port: Some(port),
                evidence: "config",
                detail: format!("{path} 的 [mysqld] port={port}"),
                confidence: 90,
            });
        }
    }

    // 2) 命令行。
    if let Some(port) = argv_port(argv) {
        return Some(PortHint {
            port: Some(port),
            evidence: "argv",
            detail: format!("命令行 --port={port}"),
            confidence: 80,
        });
    }

    // 3) 只看到监听端口。
    Some(PortHint {
        port: None,
        evidence: "listening_port",
        detail: "只看得到进程 netns 里的 TCP 监听端口".to_string(),
        confidence: 50,
    })
}

/// 候选配置文件（只按路径名找，不递归）。
fn defaults_files(argv: &[String]) -> Vec<String> {
    if let Some(path) = argv
        .iter()
        .find_map(|arg| arg.strip_prefix("--defaults-file="))
    {
        return vec![path.to_string()];
    }
    [
        "/etc/my.cnf",
        "/etc/mysql/my.cnf",
        "/etc/mysql/mysql.conf.d/mysqld.cnf",
        "/etc/mysql/mariadb.conf.d/50-server.cnf",
    ]
    .iter()
    .map(|path| path.to_string())
    .collect()
}

fn argv_port(argv: &[String]) -> Option<u16> {
    argv.iter()
        .find_map(|arg| arg.strip_prefix("--port="))
        .and_then(|value| value.parse().ok())
}

#[derive(Default)]
struct MyCnf {
    port: Option<u16>,
    skip_networking: bool,
}

/// 极简 INI 解析：只看 `[mysqld]` / `[server]` 段的白名单键。
///
/// 不引 INI 依赖：需要的信息就两个键，而完整解析器会把 `!include`、
/// 多值、转义都拉进来 —— 那些对本模块没有意义。
fn from_my_cnf(text: &str) -> MyCnf {
    let mut out = MyCnf::default();
    let mut in_server_section = false;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if line.starts_with('[') {
            let section = line.trim_start_matches('[').trim_end_matches(']').trim();
            in_server_section = matches!(section, "mysqld" | "server" | "mariadb");
            continue;
        }
        if !in_server_section {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            if line.to_ascii_lowercase().replace('_', "-") == "skip-networking" {
                out.skip_networking = true;
            }
            continue;
        };
        let key = key.trim().to_ascii_lowercase().replace('_', "-");
        let value = value.trim();
        match key.as_str() {
            "port" => out.port = value.parse().ok(),
            "skip-networking" => out.skip_networking = true,
            // 其余键（含任何凭据）一律不读。
            _ => {}
        }
    }
    out
}

fn processes(snapshot: &DiscoverySnapshot) -> Vec<ObservedProcess> {
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
fn container_identities(snapshot: &DiscoverySnapshot) -> BTreeMap<String, ContainerIdentity> {
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

/// 读 argv 之前的粗筛。
///
/// 可执行名拿不到（空）时返回 `true` —— 宁可多读一个 cmdline，也不要漏报。
fn may_be_server(exe: &str) -> bool {
    if exe.is_empty() {
        return true;
    }
    let exe = exe.to_ascii_lowercase();
    ["mysqld", "mariadbd", "tidb", "mysql"]
        .iter()
        .any(|needle| exe.contains(needle))
}

/// 是不是**服务端**进程（排除客户端与包装脚本）。
fn is_server(exe: &str, argv: &[String]) -> bool {
    let name = if exe.is_empty() {
        argv.first()
            .map(|arg| {
                std::path::Path::new(arg)
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_default()
            })
            .unwrap_or_default()
    } else {
        exe.to_string()
    };
    let name = name.to_ascii_lowercase();

    // `mysqld_safe` 是包装脚本，真正监听的是它拉起的 `mysqld`，两个都报会重复。
    const CLIENT_OR_WRAPPER: &[&str] = &[
        "mysqld_safe",
        "mysqld_multi",
        "mysqldump",
        "mysqladmin",
        "mysqlrouter",
        "mysqlsh",
        "mysql ",
        "mysql-",
        "mariadb-backup",
        "mariadbd-safe",
    ];
    if CLIENT_OR_WRAPPER
        .iter()
        .any(|needle| name.as_str() == needle.trim() || name.starts_with(needle))
    {
        return false;
    }

    name.contains("mysqld")
        || name.contains("mariadbd")
        || name.contains("tidb-server")
        // `tidb-server` 有时被包装成别的名字，退回看 argv。
        || (name.is_empty()
            && argv
                .iter()
                .any(|arg| arg.contains("mysqld") || arg.contains("tidb-server")))
}

fn tcp_ports(snapshot: &DiscoverySnapshot) -> BTreeMap<u32, Vec<(String, u16)>> {
    let mut ports: BTreeMap<u32, BTreeSet<(String, u16)>> = BTreeMap::new();
    for resource in &snapshot.resources {
        if resource.kind != "service_endpoint" {
            continue;
        }
        let attrs = &resource.attributes;
        if attrs.get("endpoint.protocol").map(String::as_str) != Some("tcp") {
            continue;
        }
        let Some(pid) = attrs.get("process.pid").and_then(|pid| pid.parse().ok()) else {
            continue;
        };
        let Some(port) = attrs
            .get("endpoint.bind.port")
            .and_then(|port| port.parse().ok())
        else {
            continue;
        };
        let ip = attrs.get("endpoint.bind.ip").cloned().unwrap_or_default();
        ports.entry(pid).or_default().insert((ip, port));
    }
    ports
        .into_iter()
        .map(|(pid, set)| (pid, set.into_iter().collect()))
        .collect()
}

fn rooted(pid: u32, path: &str) -> String {
    format!("/proc/{pid}/root{path}")
}

/// TCP 连上并读问候包首字节。
fn mysql_greeting(addr: &str) -> bool {
    use std::io::Read;

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
    let mut first = [0u8; 1];
    matches!(stream.read(&mut first), Ok(1)) && first[0] == PROTOCOL_10
}

// ---------------------------------------------------------------------------
// 生产实现
// ---------------------------------------------------------------------------

struct RealProc;

impl RealProc {
    /// `/proc/<pid>/net/<name>` 的文本（这就是该进程 netns 的视图）。
    fn net_file(pid: u32, name: &str) -> Option<String> {
        std::fs::read_to_string(format!("/proc/{pid}/net/{name}")).ok()
    }
}

impl MysqlProc for RealProc {
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
fn listen_ports_in_table(text: &str) -> Vec<u16> {
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
fn local_addrs_in_fib(text: &str) -> Vec<String> {
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
    use wist_contracts::discovery::DiscoveredResource;

    #[derive(Default)]
    struct FakeProc {
        cmdlines: BTreeMap<u32, Vec<String>>,
        files: BTreeMap<String, String>,
        listen: BTreeMap<u32, Vec<u16>>,
        addrs: BTreeMap<u32, Vec<String>>,
        same_netns: BTreeSet<u32>,
    }

    impl MysqlProc for FakeProc {
        fn cmdline(&self, pid: u32) -> Vec<String> {
            self.cmdlines.get(&pid).cloned().unwrap_or_default()
        }

        fn read_file(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn listen_ports(&self, pid: u32) -> Vec<u16> {
            self.listen.get(&pid).cloned().unwrap_or_default()
        }

        fn net_addrs(&self, pid: u32) -> Vec<String> {
            self.addrs.get(&pid).cloned().unwrap_or_default()
        }

        fn same_netns(&self, pid: u32) -> bool {
            self.same_netns.contains(&pid)
        }
    }

    #[derive(Default)]
    struct FakeHandshake {
        accepting: Vec<String>,
    }

    impl Handshake for FakeHandshake {
        fn mysql_greeting(&self, addr: &str) -> bool {
            self.accepting.iter().any(|item| item == addr)
        }
    }

    fn process(pid: u32, exe: &str) -> DiscoveredResource {
        resource(
            "process",
            vec![
                ("process.pid", pid.to_string()),
                ("process.executable.name", exe.to_string()),
            ],
        )
    }

    fn container_process(pid: u32, exe: &str, container_id: &str) -> DiscoveredResource {
        resource(
            "process",
            vec![
                ("process.pid", pid.to_string()),
                ("process.executable.name", exe.to_string()),
                ("container.id", container_id.to_string()),
            ],
        )
    }

    fn container(id: &str, attrs: Vec<(&str, String)>) -> DiscoveredResource {
        let mut all = vec![("container.id", id.to_string())];
        all.extend(attrs);
        resource("container", all)
    }

    fn listener(pid: u32, port: u16) -> DiscoveredResource {
        resource(
            "service_endpoint",
            vec![
                ("process.pid", pid.to_string()),
                ("endpoint.protocol", "tcp".to_string()),
                ("endpoint.bind.ip", "0.0.0.0".to_string()),
                ("endpoint.bind.port", port.to_string()),
            ],
        )
    }

    fn resource(kind: &str, attrs: Vec<(&str, String)>) -> DiscoveredResource {
        DiscoveredResource {
            resource_id: format!(
                "{kind}:{}",
                attrs
                    .iter()
                    .map(|(key, value)| format!("{key}={value}"))
                    .collect::<Vec<_>>()
                    .join(",")
            ),
            kind: kind.to_string(),
            origin_idx: 0,
            attributes: attrs
                .into_iter()
                .map(|(key, value)| (key.to_string(), value))
                .collect(),
            discovered_at: "2026-11-05T00:00:00Z".to_string(),
            last_seen_at: "2026-11-05T00:00:00Z".to_string(),
            health: "ok".to_string(),
            source: "test".to_string(),
        }
    }

    fn snapshot(resources: Vec<DiscoveredResource>) -> DiscoverySnapshot {
        let mut snapshot =
            DiscoverySnapshot::new("test".to_string(), 1, "2026-11-05T00:00:00Z".to_string());
        snapshot.resources = resources;
        snapshot
    }

    #[test]
    fn a_host_mysqld_is_reached_over_loopback() {
        let snapshot = snapshot(vec![process(42, "mysqld"), listener(42, 3306)]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306]);
        proc.same_netns.insert(42);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "127.0.0.1");
        assert_eq!(found[0].scope, InstanceScope::Host);
        assert_eq!(found[0].credential_key, "port-3306");
        assert_eq!(found[0].instance(), "mysql:127.0.0.1:3306");
        assert_eq!(found[0].evidence, "listening_port");
    }

    #[test]
    fn a_k8s_pod_is_reached_over_its_pod_ip_with_a_pod_credential_key() {
        let snapshot = snapshot(vec![
            container_process(42, "mysqld", "abc123"),
            container(
                "abc123",
                vec![
                    ("k8s.namespace.name", "prod".to_string()),
                    ("k8s.pod.name", "mysql-0".to_string()),
                ],
            ),
            listener(42, 3306),
        ]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306, 33060]);
        proc.addrs.insert(42, vec!["10.244.1.5".to_string()]);
        let handshake = FakeHandshake {
            accepting: vec!["10.244.1.5:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1, "33060 没握手成功，不该进来");
        assert_eq!(found[0].host, "10.244.1.5", "pod 里的监听只能走 pod IP");
        assert_eq!(found[0].scope, InstanceScope::Container);
        assert_eq!(found[0].credential_key, "pod-prod-mysql-0");
        assert_eq!(
            found[0].instance(),
            "mysql:pod-prod-mysql-0",
            "容器身份用名字，重启换 IP 不断档"
        );
    }

    #[test]
    fn a_compose_container_with_a_published_port_uses_loopback() {
        let snapshot = snapshot(vec![
            container_process(42, "mysqld", "def456"),
            container(
                "def456",
                vec![("container.name", "compose-mysql-1".to_string())],
            ),
        ]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306]);
        proc.addrs.insert(42, vec!["172.17.0.2".to_string()]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "127.0.0.1", "发布了端口就走回环");
        assert_eq!(found[0].credential_key, "container-compose-mysql-1");
    }

    #[test]
    fn a_container_without_metadata_falls_back_to_the_address_key() {
        let snapshot = snapshot(vec![container_process(42, "mysqld", "unknown-id")]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306]);
        proc.addrs.insert(42, vec!["172.18.0.7".to_string()]);
        let handshake = FakeHandshake {
            accepting: vec!["172.18.0.7:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].credential_key, "addr-172-18-0-7-3306");
    }

    #[test]
    fn the_x_protocol_port_is_dropped_by_the_handshake() {
        let snapshot = snapshot(vec![process(42, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306, 33060]);
        proc.same_netns.insert(42);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1, "只留握手通过的端口");
        assert_eq!(found[0].port, 3306);
    }

    #[test]
    fn argv_port_wins_over_the_listening_port() {
        let snapshot = snapshot(vec![process(42, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec!["/usr/sbin/mysqld".to_string(), "--port=3307".to_string()],
        );
        proc.same_netns.insert(42);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3307".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence, "argv");
        assert_eq!(found[0].confidence, 80);
    }

    #[test]
    fn a_defaults_file_port_is_the_strongest_evidence() {
        let snapshot = snapshot(vec![process(42, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.cmdlines
            .insert(42, vec!["/usr/sbin/mysqld".to_string()]);
        proc.same_netns.insert(42);
        proc.files.insert(
            "/proc/42/root/etc/my.cnf".to_string(),
            "[mysqld]\nport = 3308\nsocket = /run/mysqld.sock\n".to_string(),
        );
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3308".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 3308);
        assert_eq!(found[0].evidence, "config");
        assert_eq!(found[0].confidence, 90);
    }

    #[test]
    fn skip_networking_means_no_tcp_endpoint() {
        let snapshot = snapshot(vec![process(42, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec![
                "/usr/sbin/mysqld".to_string(),
                "--skip-networking".to_string(),
            ],
        );
        proc.same_netns.insert(42);
        proc.listen.insert(42, vec![3306]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string()],
        };

        assert!(resolve(&snapshot, &proc, &handshake).is_empty());
    }

    #[test]
    fn clients_and_wrappers_are_not_servers() {
        for exe in ["mysqldump", "mysqladmin", "mysqld_safe", "mysql"] {
            assert!(
                !may_be_server(exe) || !is_server(exe, &[]),
                "`{exe}` 不该当成服务端"
            );
        }
        assert!(is_server("mysqld", &[]));
        assert!(is_server("mariadbd", &[]));
        assert!(is_server("tidb-server", &[]));
    }

    #[test]
    fn the_same_address_and_port_are_reported_once() {
        let snapshot = snapshot(vec![process(42, "mysqld"), process(43, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec!["/usr/sbin/mysqld".to_string(), "--port=3306".to_string()],
        );
        proc.same_netns.insert(42);
        proc.same_netns.insert(43);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1, "同一地址+端口只留一条");
        assert_eq!(found[0].evidence, "argv", "留置信度高的那条");
    }

    #[test]
    fn my_cnf_parsing_only_reads_whitelisted_keys() {
        let parsed =
            from_my_cnf("[client]\nport=9999\n[mysqld]\nport=3306\nuser=mysql\npassword=secret\n");
        assert_eq!(parsed.port, Some(3306), "只看 [mysqld] 段");
        assert!(!parsed.skip_networking);
    }

    #[test]
    fn my_cnf_underscore_and_hyphen_are_equivalent() {
        let parsed = from_my_cnf("[mysqld]\nskip_networking\n");
        assert!(parsed.skip_networking);
        let parsed = from_my_cnf("[mysqld]\nskip-networking = 1\n");
        assert!(parsed.skip_networking);
    }

    #[test]
    fn listen_ports_are_read_from_the_proc_net_table() {
        // 真实格式：sl local_address rem_address st ... inode
        let table = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n   0: 3500007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12345 1\n   1: 3500007F:9C40 00000000:0000 0A 00000000:00000000 00:00000000 00000000   999        0 12346 1\n   2: 3500007F:0CEA 0100007F:9C40 01 00000000:00000000 00:00000000 00000000   999        0 12347 1\n";
        let ports = listen_ports_in_table(table);
        assert_eq!(ports, vec![3306, 40000], "只取 LISTEN（0A）");
    }

    #[test]
    fn fib_trie_yields_non_loopback_local_addresses() {
        let trie = "Main:\n  +-- 0.0.0.0/0 3 0 5\n     |-- 127.0.0.1\n        /32 host LOCAL\n     |-- 172.17.0.2\n        /32 host LOCAL\n     |-- 172.17.0.0\n        /16 link UNICAST\n";
        let addrs = local_addrs_in_fib(trie);
        assert_eq!(addrs, vec!["172.17.0.2".to_string()], "回环与网段不算");
    }

    #[test]
    fn sanitize_key_makes_a_directory_safe_name() {
        assert_eq!(sanitize_key("pod-prod-mysql-0"), "pod-prod-mysql-0");
        assert_eq!(sanitize_key("pod-Prod_MySQL.0"), "pod-prod-mysql-0");
        assert_eq!(sanitize_key("---"), "");
    }
}
