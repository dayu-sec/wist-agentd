//! PostgreSQL 实例**自探**：只发现，不上报、不下发采集任务。
//!
//! 与 [`super::mysql_source`] 同一套：运行时（host / docker-compose / k8s）由
//! [`super::db_source`] 按 netns 处理，本模块只管 PG 自己的证据与握手。
//!
//! - **证据**：`-D <datadir>/postgresql.conf` 的 `port =` / 常见发行版路径 /
//!   命令行 `-p <port>` / 监听端口；
//! - **握手**：发 `SSLRequest`（8 字节），收一个 `S`（支持 TLS）或 `N`（不支持）字节
//!   就说明是 PG。这一步同时排掉 pooler（pgbouncer 按进程名排除）与别的服务。
//!
//! ## 红线
//!
//! `postgresql.conf` 只读 `port` / `listen_addresses` / `ssl`；
//! 认证配置（`pg_hba.conf` / `pg_ident.conf`）与任何 `password` 键一律不读、不报。

use std::collections::BTreeMap;

use serde::Serialize;
use wist_contracts::discovery::DiscoverySnapshot;

use super::db_source::{
    DbProc, InstanceScope, ObservedProcess, RealProc, candidate_addrs, container_identities,
    credential_key, processes, rooted, tcp_probe,
};

/// 一次解析最多看多少个进程。
const MAX_INSPECTED_PROCESSES: usize = 8;
/// 单个进程最多实测几个端口。
const MAX_PROBE_PORTS_PER_PROCESS: usize = 4;

/// 一条 PostgreSQL 实例候选（自探产物；只在进程内使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct PgInstanceEntry {
    pub source_ref: String,
    /// 连接地址：`127.0.0.1` 或容器 / pod IP。
    pub host: String,
    pub port: u16,
    /// 凭据目录名（与 MySQL 同一套规则）。
    pub credential_key: String,
    pub scope: InstanceScope,
    /// 证据层：`config` / `argv` / `listening_port`。
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
}

impl PgInstanceEntry {
    pub fn instance(&self) -> String {
        match self.scope {
            InstanceScope::Host => format!("postgres:{}:{}", self.host, self.port),
            InstanceScope::Container => format!("postgres:{}", self.credential_key),
        }
    }
}

/// 端口探活能力（生产实现 [`TcpHandshake`]，测试用假实现）。
pub trait Handshake {
    fn postgres_greeting(&self, addr: &str) -> bool;
}

pub struct TcpHandshake;

impl Handshake for TcpHandshake {
    fn postgres_greeting(&self, addr: &str) -> bool {
        tcp_probe(addr, |stream| {
            use std::io::{Read, Write};
            // SSLRequest：长度 8 + 魔数 80877103。
            const SSL_REQUEST: [u8; 8] = [0x00, 0x00, 0x00, 0x08, 0x04, 0xd2, 0x16, 0x2f];
            if stream.write_all(&SSL_REQUEST).is_err() {
                return false;
            }
            let mut reply = [0u8; 1];
            if !matches!(stream.read(&mut reply), Ok(1)) {
                return false;
            }
            // 'S' = 走 TLS、'N' = 明文，两种都是 PG。
            matches!(reply[0], b'S' | b'N')
        })
    }
}

pub fn resolve_from_snapshot(snapshot: &DiscoverySnapshot) -> Vec<PgInstanceEntry> {
    resolve(snapshot, &RealProc, &TcpHandshake)
}

/// 现场诊断用：立即跑一次发现再解析（与守护进程同一条路径）。
pub fn resolve_live() -> Vec<PgInstanceEntry> {
    resolve_from_snapshot(&super::db_source::live_snapshot("postgres"))
}

// ---------------------------------------------------------------------------
// 解析主体
// ---------------------------------------------------------------------------

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn DbProc,
    handshake: &dyn Handshake,
) -> Vec<PgInstanceEntry> {
    let containers = container_identities(snapshot);
    let mut by_target: BTreeMap<(String, u16), PgInstanceEntry> = BTreeMap::new();
    let mut inspected = 0usize;

    for process in processes(snapshot) {
        if inspected >= MAX_INSPECTED_PROCESSES {
            break;
        }
        if !may_be_server(&process.exe) {
            continue;
        }
        let argv = proc.cmdline(process.pid);
        if !is_server(&process.exe, &argv) {
            continue;
        }
        inspected += 1;

        let hint = port_hint(&process, &argv, proc);
        let same_netns = proc.same_netns(process.pid);
        let scope = if same_netns {
            InstanceScope::Host
        } else {
            InstanceScope::Container
        };
        let addrs = candidate_addrs(process.pid, same_netns, proc, "postgres");

        // 证据端口先试，再补实际监听端口（配置改了没重启时前者是错的）。
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

        for port in candidates {
            let Some(host) = addrs
                .iter()
                .find(|addr| handshake.postgres_greeting(&format!("{addr}:{port}")))
            else {
                log::debug!(
                    "event=PgPortNotPostgres port={port} candidates={:?} detail=\"候选地址都没握手成功（可能不是 PostgreSQL，或端口未发布到宿主）\"",
                    addrs
                );
                continue;
            };
            let entry = PgInstanceEntry {
                source_ref: format!("port:{port}"),
                host: host.clone(),
                port,
                credential_key: credential_key(
                    scope,
                    host,
                    port,
                    process
                        .container_id
                        .as_deref()
                        .and_then(|id| containers.get(id)),
                ),
                scope,
                evidence: hint.evidence.to_string(),
                detail: hint.detail.clone(),
                confidence: hint.confidence,
            };
            match by_target.get(&(entry.host.clone(), port)) {
                Some(existing) if existing.confidence >= entry.confidence => {}
                _ => {
                    by_target.insert((entry.host.clone(), port), entry);
                }
            }
        }
    }

    let mut out: Vec<PgInstanceEntry> = by_target.into_values().collect();
    out.sort_by_key(|entry| (entry.host.clone(), entry.port));
    out
}

struct PortHint {
    port: Option<u16>,
    evidence: &'static str,
    detail: String,
    confidence: i64,
}

fn port_hint(process: &ObservedProcess, argv: &[String], proc: &dyn DbProc) -> PortHint {
    // 1) 配置文件：`-D` 给的目录优先，其次常见发行版路径。
    for path in config_files(argv) {
        let full = rooted(process.pid, &path);
        let Some(text) = proc.read_file(&full) else {
            continue;
        };
        if let Some(port) = port_from_conf(&text) {
            return PortHint {
                port: Some(port),
                evidence: "config",
                detail: format!("{path} 的 port = {port}"),
                confidence: 90,
            };
        }
    }

    // 2) 命令行：`-p 5432` / `--port=5432` / `-p5432`。
    if let Some(port) = argv_port(argv) {
        return PortHint {
            port: Some(port),
            evidence: "argv",
            detail: format!("命令行端口 {port}"),
            confidence: 80,
        };
    }

    PortHint {
        port: None,
        evidence: "listening_port",
        detail: "只看得到进程 netns 里的 TCP 监听端口".to_string(),
        confidence: 50,
    }
}

/// 候选配置文件：`-D` 指向的目录下的 `postgresql.conf`，再加几个常见位置。
fn config_files(argv: &[String]) -> Vec<String> {
    let mut out = Vec::new();
    if let Some(datadir) = argv_datadir(argv) {
        out.push(format!("{}/postgresql.conf", datadir.trim_end_matches('/')));
    }
    out.push("/etc/postgresql/postgresql.conf".to_string());
    out.push("/var/lib/postgresql/data/postgresql.conf".to_string());
    out.push("/var/lib/pgsql/data/postgresql.conf".to_string());
    out.push("/etc/postgresql/16/main/postgresql.conf".to_string());
    out.push("/etc/postgresql/15/main/postgresql.conf".to_string());
    out
}

fn argv_datadir(argv: &[String]) -> Option<String> {
    for (index, arg) in argv.iter().enumerate() {
        if arg == "-D" {
            return argv.get(index + 1).cloned();
        }
        for prefix in ["-D", "--datadir="] {
            if let Some(value) = arg.strip_prefix(prefix)
                && !value.is_empty()
            {
                return Some(value.to_string());
            }
        }
    }
    None
}

fn argv_port(argv: &[String]) -> Option<u16> {
    for (index, arg) in argv.iter().enumerate() {
        if arg == "-p" || arg == "--port" {
            return argv.get(index + 1).and_then(|value| value.parse().ok());
        }
        for prefix in ["-p", "--port="] {
            if let Some(value) = arg.strip_prefix(prefix)
                && let Ok(port) = value.parse()
            {
                return Some(port);
            }
        }
    }
    None
}

/// `postgresql.conf` 只读 `port`（行首键，注释忽略）。
///
/// 不处理 `include` / `include_if_exists`：标准发行版包里 `port` 都在主文件里，
/// 跟随 include 会把「读一个配置文件」变成「遍历一棵目录树」，收益不值。
fn port_from_conf(text: &str) -> Option<u16> {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        if key.trim().eq_ignore_ascii_case("port") {
            // 去掉行尾注释与引号。
            let value = value
                .split('#')
                .next()
                .unwrap_or("")
                .trim()
                .trim_matches('\'');
            return value.parse().ok();
        }
    }
    None
}

fn may_be_server(exe: &str) -> bool {
    if exe.is_empty() {
        return true;
    }
    let exe = exe.to_ascii_lowercase();
    ["postgres", "postmaster", "pgsql", "pg"]
        .iter()
        .any(|needle| exe.contains(needle))
}

/// 是不是**服务端**进程（排除客户端、备份工具、连接池）。
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

    // 连接池与客户端：它们说 PG 协议但不是数据库本身，
    // 采它们会把「池子的统计」当成「数据库的统计」。
    const NOT_A_SERVER: &[&str] = &[
        "pgbouncer",
        "psql",
        "pg_dump",
        "pg_restore",
        "pg_basebackup",
        "pg_ctl",
        "pg_isready",
        "pg_exporter",
        "postgres_exporter",
        "pg_rewind",
        "pg_upgrade",
    ];
    if NOT_A_SERVER.iter().any(|needle| name.starts_with(needle)) {
        return false;
    }

    // `postgres: writer process` 这类子进程不监听端口，会在候选端口为空时自然退出；
    // 这里不额外排除，免得漏掉改了进程名的 postmaster。
    name.starts_with("postgres") || name.starts_with("postmaster") || name == "pg"
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
        fn postgres_greeting(&self, addr: &str) -> bool {
            self.accepting.iter().any(|item| item == addr)
        }
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

    fn process(pid: u32, exe: &str) -> DiscoveredResource {
        resource(
            "process",
            vec![
                ("process.pid", pid.to_string()),
                ("process.executable.name", exe.to_string()),
            ],
        )
    }

    fn snapshot(resources: Vec<DiscoveredResource>) -> DiscoverySnapshot {
        let mut snapshot =
            DiscoverySnapshot::new("test".to_string(), 1, "2026-11-05T00:00:00Z".to_string());
        snapshot.resources = resources;
        snapshot
    }

    #[test]
    fn a_host_postgres_is_reached_over_loopback() {
        let snapshot = snapshot(vec![process(42, "postgres")]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![5432]);
        proc.same_netns.insert(42);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:5432".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "127.0.0.1");
        assert_eq!(found[0].credential_key, "port-5432");
        assert_eq!(found[0].instance(), "postgres:127.0.0.1:5432");
    }

    #[test]
    fn the_datadir_config_ports_highest_and_provides_the_port() {
        let snapshot = snapshot(vec![process(42, "postgres")]);
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec![
                "/usr/lib/postgresql/16/bin/postgres".to_string(),
                "-D".to_string(),
                "/var/lib/pgsql/data".to_string(),
            ],
        );
        proc.same_netns.insert(42);
        proc.files.insert(
            "/proc/42/root/var/lib/pgsql/data/postgresql.conf".to_string(),
            "# port = 5432\nport = 5433\t\t# custom\n".to_string(),
        );
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:5433".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 5433);
        assert_eq!(found[0].evidence, "config");
        assert_eq!(found[0].confidence, 90);
    }

    #[test]
    fn argv_port_is_used_when_there_is_no_config() {
        let snapshot = snapshot(vec![process(42, "postgres")]);
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec!["postgres".to_string(), "-p".to_string(), "6543".to_string()],
        );
        proc.same_netns.insert(42);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:6543".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 6543);
        assert_eq!(found[0].evidence, "argv");
    }

    #[test]
    fn the_actual_listening_port_is_tried_when_the_config_is_stale() {
        let snapshot = snapshot(vec![process(42, "postgres")]);
        let mut proc = FakeProc::default();
        proc.same_netns.insert(42);
        proc.files.insert(
            "/proc/42/root/var/lib/pgsql/data/postgresql.conf".to_string(),
            "port = 5432\n".to_string(),
        );
        proc.listen.insert(42, vec![6432]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:6432".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 6432);
    }

    #[test]
    fn a_k8s_pod_uses_the_pod_ip_and_the_pod_key() {
        let snapshot = snapshot(vec![
            resource(
                "process",
                vec![
                    ("process.pid", "42".to_string()),
                    ("process.executable.name", "postgres".to_string()),
                    ("container.id", "abc".to_string()),
                ],
            ),
            resource(
                "container",
                vec![
                    ("container.id", "abc".to_string()),
                    ("k8s.namespace.name", "data".to_string()),
                    ("k8s.pod.name", "pg-0".to_string()),
                ],
            ),
        ]);
        let mut proc = FakeProc::default();
        proc.listen.insert(42, vec![5432]);
        proc.addrs.insert(42, vec!["10.244.2.9".to_string()]);
        let handshake = FakeHandshake {
            accepting: vec!["10.244.2.9:5432".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "10.244.2.9");
        assert_eq!(found[0].credential_key, "pod-data-pg-0");
        assert_eq!(found[0].instance(), "postgres:pod-data-pg-0");
    }

    #[test]
    fn a_bouncer_is_not_a_database() {
        assert!(!may_be_server("pgbouncer") || !is_server("pgbouncer", &[]));
        assert!(is_server("postgres", &[]));
        assert!(is_server("postmaster", &[]));
        assert!(!is_server("psql", &[]));
        assert!(!is_server("pg_basebackup", &[]));
    }

    #[test]
    fn the_port_line_ignores_comments_and_quotes() {
        assert_eq!(port_from_conf("port = 5432"), Some(5432));
        assert_eq!(port_from_conf("# port = 5432\nport = 6543"), Some(6543));
        assert_eq!(port_from_conf("port='5555'  # x"), Some(5555));
        assert_eq!(port_from_conf("max_connections = 100"), None);
    }

    #[test]
    fn datadir_is_read_from_both_forms() {
        let argv = vec![
            "postgres".to_string(),
            "-D".to_string(),
            "/data".to_string(),
        ];
        assert_eq!(argv_datadir(&argv).as_deref(), Some("/data"));
        let argv = vec!["postgres".to_string(), "--datadir=/data2".to_string()];
        assert_eq!(argv_datadir(&argv).as_deref(), Some("/data2"));
        let argv = vec!["postgres".to_string(), "-D/data3".to_string()];
        assert_eq!(argv_datadir(&argv).as_deref(), Some("/data3"));
    }
}
