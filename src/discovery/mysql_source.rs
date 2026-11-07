//! MySQL / TiDB 实例**自探**：只发现，不上报、不下发采集任务。
//!
//! 与 [`super::kafka_source`] 同一条路子：agentd 以 root 跑在数据库机器上，
//! **进程本身就是证据**。运维不需要在配置文件里写任何地址 —— 采不采、什么时候采
//! 由采集面授权决定，地址由这里给。
//!
//! ## 运行时无关
//!
//! 数据目录里 MySQL 可能跑在 **host**、**docker-compose**、**k8s pod** 里。
//! 端口、地址与身份都由 [`super::db_source`] 按 **netns** 统一处理
//! （`/proc/<pid>/net/tcp` + 回环优先的多候选握手），本模块只管 MySQL 自己的事：
//!
//! - **证据**：`[mysqld] port=` / `--port=` / `--skip-networking`；
//! - **握手**：读问候包首字节必须是 `protocol_version = 10`。
//!
//! 握手这一步是必须的：`mysqld` 通常同时监听 3306（经典协议）与 33060（X 协议），
//! TCP 能连不等于能用 SQL 采 —— 把 X 协议端口当 MySQL 采会每轮失败一次，
//! 而那在指标上看起来和「库挂了」一模一样。
//!
//! ## 红线
//!
//! 只读白名单键：`[mysqld]` 段的 `port` / `skip-networking` / `socket`。
//! 任何含 `password` / `user` 的键一律不读、不报、不进日志。

use std::collections::BTreeMap;

use serde::Serialize;
use wist_contracts::discovery::DiscoverySnapshot;

use super::db_source::{
    DbProc, ObservedProcess, RealProc, candidate_addrs, container_identities, credential_key,
    processes, rooted, tcp_probe,
};

/// MySQL 经典协议的问候包第一字节（`protocol_version`）。
const PROTOCOL_10: u8 = 0x0a;
/// 一次解析最多看多少个进程（数据库机器上进程很多，不必全扫）。
const MAX_INSPECTED_PROCESSES: usize = 8;
/// 单个进程最多实测几个端口（3306 + 33060 + 少量转发）。
const MAX_PROBE_PORTS_PER_PROCESS: usize = 4;

/// 实例所在范围（host / 容器）；由公共层定义，这里重导出便于同域代码引用。
pub use super::db_source::InstanceScope;

/// 一条 MySQL 实例候选（自探产物；只在进程内使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MysqlInstanceEntry {
    /// 进程身份（审计用）：优先端口，pid 重启不换身份。
    pub source_ref: String,
    /// 连接地址：`127.0.0.1`（同 netns / 发布到回环）或容器 / pod IP。
    pub host: String,
    /// 经典协议端口（已通过握手）。
    pub port: u16,
    /// 凭据目录名：`port-<port>` / `pod-<ns>-<pod>` / `container-<name>` / `addr-<ip>-<port>`。
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
        tcp_probe(addr, |stream| {
            use std::io::Read;
            let mut first = [0u8; 1];
            matches!(stream.read(&mut first), Ok(1)) && first[0] == PROTOCOL_10
        })
    }
}

/// 从发现快照解析本机 MySQL 候选。
pub fn resolve_from_snapshot(snapshot: &DiscoverySnapshot) -> Vec<MysqlInstanceEntry> {
    resolve(snapshot, &RealProc, &TcpHandshake)
}

/// 现场诊断用：立即跑一次进程 / 端点 / 容器发现再解析（不读缓存、不写盘）。
pub fn resolve_live() -> Vec<MysqlInstanceEntry> {
    resolve_from_snapshot(&super::db_source::live_snapshot("mysql"))
}

// ---------------------------------------------------------------------------
// 解析主体
// ---------------------------------------------------------------------------

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn DbProc,
    handshake: &dyn Handshake,
) -> Vec<MysqlInstanceEntry> {
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
        let addrs = candidate_addrs(process.pid, same_netns, proc, "mysql");

        // 证据给的端口先试；**再补上实际监听端口**。
        // 配置写的端口和真正监听的可能不一致（改过 my.cnf 没重启），
        // 只认前者会让一台活着的库被判成「端口上不是 MySQL」。
        let mut candidates = Vec::new();
        if let Some(port) = hint.port {
            candidates.push(port);
        }
        for port in proc.listen_ports(process.pid) {
            if candidates.len() >= MAX_PROBE_PORTS_PER_PROCESS {
                break;
            }
            if !candidates.contains(&port) {
                candidates.push(port);
            }
        }

        // 没任何候选端口的进程不占名额：预算限的是握手，不是「看过多少个进程」
        // （`--skip-networking` 的实例不该把名额吃光）。
        if candidates.is_empty() {
            continue;
        }
        inspected += 1;

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
                host,
                port,
                process
                    .container_id
                    .as_deref()
                    .and_then(|id| containers.get(id)),
            );
            let entry = MysqlInstanceEntry {
                source_ref: format!("port:{port}"),
                host: host.clone(),
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

/// 端口从哪来。
struct PortHint {
    port: Option<u16>,
    evidence: &'static str,
    detail: String,
    confidence: i64,
}

/// 依证据强弱给出端口假设；`None` = 明确不能走 TCP。
fn port_hint(process: &ObservedProcess, argv: &[String], proc: &dyn DbProc) -> Option<PortHint> {
    if argv
        .iter()
        .any(|arg| arg == "--skip-networking" || arg == "--skip_networking")
    {
        return None;
    }

    // 1) 配置文件（`--defaults-file` 优先，否则标准路径）。
    //    走 `/proc/<pid>/root` 读：容器里跑的时候，读到的是**容器内**的 my.cnf。
    let mut config_from: Option<(String, u16)> = None;
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
            config_from = Some((path, port));
            break;
        }
    }
    if let Some((path, port)) = config_from {
        return Some(PortHint {
            port: Some(port),
            evidence: "config",
            detail: format!("{path} 的 [mysqld] port={port}"),
            confidence: 90,
        });
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use wist_contracts::discovery::DiscoveredResource;

    #[derive(Default)]
    struct FakeProc {
        cmdlines: BTreeMap<u32, Vec<String>>,
        files: BTreeMap<String, String>,
        listen: BTreeMap<u32, Vec<u16>>,
        bound: BTreeMap<u32, Vec<String>>,
        addrs: BTreeMap<u32, Vec<String>>,
        same_netns: BTreeSet<u32>,
    }

    impl DbProc for FakeProc {
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

        fn bound_addrs(&self, pid: u32) -> Vec<String> {
            self.bound.get(&pid).cloned().unwrap_or_default()
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
        let snapshot = snapshot(vec![process(42, "mysqld")]);
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
    fn a_host_instance_bound_to_a_specific_ip_is_reached_there() {
        // `bind-address = 10.0.0.5` 的实例不接回环：只试 127.0.0.1 会漏报。
        let snapshot = snapshot(vec![process(42, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306]);
        proc.same_netns.insert(42);
        proc.bound.insert(42, vec!["10.0.0.5".to_string()]);
        let handshake = FakeHandshake {
            accepting: vec!["10.0.0.5:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "10.0.0.5");
        assert_eq!(
            found[0].scope,
            InstanceScope::Host,
            "同 netns 仍是 host 语义"
        );
        assert_eq!(found[0].credential_key, "port-3306");
    }

    #[test]
    fn a_container_prefers_its_own_address_over_the_host_loopback() {
        // 宿主上可能也跑着一个 3306：先试回环会连到宿主的库，再拿 pod 的凭据去认，
        // 结果是「密码错」+「把宿主实例记到 pod 的 key 上」。
        let snapshot = snapshot(vec![
            container_process(42, "mysqld", "abc123"),
            container(
                "abc123",
                vec![
                    ("k8s.namespace.name", "prod".to_string()),
                    ("k8s.pod.name", "mysql-0".to_string()),
                ],
            ),
        ]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![3306]);
        proc.addrs.insert(42, vec!["10.244.1.5".to_string()]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string(), "10.244.1.5:3306".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "10.244.1.5", "容器自己的地址优先");
        assert_eq!(found[0].credential_key, "pod-prod-mysql-0");
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
    fn the_actual_listening_port_is_tried_when_the_configured_one_is_stale() {
        // my.cnf 写 3306，但进程实际监听 3307（改过配置没重启）。
        let snapshot = snapshot(vec![process(42, "mysqld")]);
        let mut proc = FakeProc::default();
        proc.cmdlines
            .insert(42, vec!["/usr/sbin/mysqld".to_string()]);
        proc.same_netns.insert(42);
        proc.listen.insert(42, vec![3307]);
        proc.files.insert(
            "/proc/42/root/etc/my.cnf".to_string(),
            "[mysqld]
port = 3306
"
            .to_string(),
        );
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3307".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 3307, "配置过期时要用实际监听端口");
        assert_eq!(found[0].evidence, "config", "证据来源仍是配置文件");
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
    fn socket_only_instances_do_not_consume_the_inspection_budget() {
        // 8 个 `--skip-networking` 的 mysqld 排在前面：它们根本没有 TCP 候选，
        // 不该占名额；否则后面那个真监听 3306 的实例永远轮不到。
        let mut resources = Vec::new();
        let mut proc = FakeProc::default();
        for index in 0..8u32 {
            let pid = 100 + index;
            resources.push(process(pid, "/usr/sbin/mysqld"));
            proc.cmdlines.insert(
                pid,
                vec![
                    "/usr/sbin/mysqld".to_string(),
                    "--skip-networking".to_string(),
                ],
            );
            proc.same_netns.insert(pid);
        }
        resources.push(process(999, "/usr/sbin/mysqld"));
        proc.cmdlines
            .insert(999, vec!["/usr/sbin/mysqld".to_string()]);
        proc.listen.insert(999, vec![3306]);
        proc.same_netns.insert(999);

        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:3306".to_string()],
        };
        let found = resolve(&snapshot(resources), &proc, &handshake);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].port, 3306);
    }
}
