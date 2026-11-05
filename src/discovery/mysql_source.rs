//! MySQL / TiDB 实例**自探**：只发现，不上报、不下发采集任务。
//!
//! 与 [`super::kafka_source`] 同一条路子：agentd 以 root 跑在数据库机器上，
//! **进程本身就是证据**。运维不需要在配置文件里写任何地址 —— 采不采、什么时候采
//! 由采集面授权决定，地址由这里给。
//!
//! ## 证据层（从强到弱）
//!
//! 1. `--defaults-file` / `/etc/my.cnf` / `/etc/mysql/my.cnf` 的 `[mysqld] port=`；
//! 2. 命令行 `--port=` / `--skip-networking`；
//! 3. 该进程的 TCP 监听端口（只看得到「这里有个监听」）。
//!
//! ## 为什么还要握手
//!
//! 一个 `mysqld` 通常监听两个端口（3306 经典协议、33060 X 协议），容器里还可能有
//! 别的转发。**只认「发 Protocol 10 问候包」的端口**：TCP 能连不等于能用 SQL 采，
//! 把 X 协议端口当 MySQL 采会每轮都失败一次。
//!
//! ## 红线
//!
//! 只读白名单键：`[mysqld]` 段里的 `port` / `skip-networking` / `socket`。
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
/// `cmdline` 的读取上限。
const MAX_PROC_BYTES: usize = 4096;
/// 配置文件读取上限：`my.cnf` 一般几 KB。
const MAX_EVIDENCE_BYTES: u64 = 64 * 1024;
/// 单次 TCP 握手的超时（与 Kafka 自探同一量级）。
const HANDSHAKE_TIMEOUT: Duration = Duration::from_millis(300);
/// MySQL 经典协议的问候包第一字节（`protocol_version`）。
const PROTOCOL_10: u8 = 0x0a;

/// 一条 MySQL 实例候选（自探产物；只在进程内使用）。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct MysqlInstanceEntry {
    /// 进程身份（审计用）：优先端口，pid 重启不换身份。
    pub source_ref: String,
    /// 经典协议端口（已通过握手）。
    pub port: u16,
    /// 证据层：`config` / `argv` / `listening_port`。
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
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

/// 现场诊断用：立即跑一次进程 + 端点发现再解析（不读缓存、不写盘）。
pub fn resolve_live() -> Vec<MysqlInstanceEntry> {
    use crate::discovery::DiscoveryProbe as _;

    let now = std::time::SystemTime::now();
    let stamp = wist_shared::time::now_rfc3339();
    let mut snapshot = DiscoverySnapshot::new(format!("mysql-candidates-live-{stamp}"), 0, stamp);
    for output in [
        crate::discovery::process::ProcessDiscoveryProbe.refresh(now),
        crate::discovery::endpoint::EndpointDiscoveryProbe.refresh(now),
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
}

struct ObservedProcess {
    pid: u32,
    exe: String,
}

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn MysqlProc,
    handshake: &dyn Handshake,
) -> Vec<MysqlInstanceEntry> {
    let ports = tcp_ports(snapshot);
    let mut by_port: BTreeMap<u16, MysqlInstanceEntry> = BTreeMap::new();
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

        let candidates = match hint.port {
            Some(port) => vec![port],
            None => {
                let mut list: Vec<u16> = ports
                    .get(&process.pid)
                    .map(|entries| entries.iter().map(|(_, port)| *port).collect())
                    .unwrap_or_default();
                list.truncate(MAX_PROBE_PORTS_PER_PROCESS);
                list
            }
        };

        for port in candidates {
            let addr = format!("127.0.0.1:{port}");
            if !handshake.mysql_greeting(&addr) {
                log::debug!(
                    "event=MysqlPortNotMysql addr=\"{addr}\" detail=\"不是 MySQL 经典协议（可能是 X 协议或别的服务）\""
                );
                continue;
            }
            let entry = MysqlInstanceEntry {
                source_ref: format!("port:{port}"),
                port,
                evidence: hint.evidence.to_string(),
                detail: hint.detail.clone(),
                confidence: hint.confidence,
            };
            // 两个 pid 报同一个端口（容器 + 宿主）时留置信度高的那条。
            match by_port.get(&port) {
                Some(existing) if existing.confidence >= entry.confidence => {}
                _ => {
                    by_port.insert(port, entry);
                }
            }
        }
    }

    let mut out: Vec<MysqlInstanceEntry> = by_port.into_values().collect();
    out.sort_by_key(|entry| entry.port);
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
fn port_hint(process: &ObservedProcess, argv: &[String], proc: &dyn MysqlProc) -> Option<PortHint> {
    if argv
        .iter()
        .any(|arg| arg == "--skip-networking" || arg == "--skip_networking")
    {
        return None;
    }

    // 1) 配置文件（`--defaults-file` 优先，否则标准路径）。
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
        detail: "只看得到进程的 TCP 监听端口".to_string(),
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
            Some(ObservedProcess { pid, exe })
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::discovery::DiscoveredResource;

    #[derive(Default)]
    struct FakeProc {
        cmdlines: BTreeMap<u32, Vec<String>>,
        files: BTreeMap<String, String>,
    }

    impl MysqlProc for FakeProc {
        fn cmdline(&self, pid: u32) -> Vec<String> {
            self.cmdlines.get(&pid).cloned().unwrap_or_default()
        }

        fn read_file(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }
    }

    #[derive(Default)]
    struct FakeHandshake {
        accepting: Vec<u16>,
    }

    impl Handshake for FakeHandshake {
        fn mysql_greeting(&self, addr: &str) -> bool {
            let port: u16 = addr.rsplit(':').next().unwrap().parse().unwrap();
            self.accepting.contains(&port)
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
    fn a_mysqld_with_a_listening_port_is_reported() {
        let snapshot = snapshot(vec![process(42, "mysqld"), listener(42, 3306)]);
        let proc = FakeProc::default();
        let handshake = FakeHandshake {
            accepting: vec![3306],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 3306);
        assert_eq!(found[0].source_ref, "port:3306");
        assert_eq!(found[0].evidence, "listening_port");
    }

    #[test]
    fn the_x_protocol_port_is_dropped_by_the_handshake() {
        // 33060 是 X 协议：TCP 能连，但不是经典协议。
        let snapshot = snapshot(vec![
            process(42, "mysqld"),
            listener(42, 3306),
            listener(42, 33060),
        ]);
        let proc = FakeProc::default();
        let handshake = FakeHandshake {
            accepting: vec![3306],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1, "只留握手通过的端口");
        assert_eq!(found[0].port, 3306);
    }

    #[test]
    fn argv_port_wins_over_the_listening_port() {
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec!["/usr/sbin/mysqld".to_string(), "--port=3307".to_string()],
        );
        let snapshot = snapshot(vec![process(42, "mysqld"), listener(42, 3307)]);
        let handshake = FakeHandshake {
            accepting: vec![3307],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].evidence, "argv");
        assert_eq!(found[0].confidence, 80);
    }

    #[test]
    fn a_defaults_file_port_is_the_strongest_evidence() {
        let mut proc = FakeProc::default();
        proc.cmdlines
            .insert(42, vec!["/usr/sbin/mysqld".to_string()]);
        proc.files.insert(
            "/proc/42/root/etc/my.cnf".to_string(),
            "[mysqld]\nport = 3308\nsocket = /run/mysqld.sock\n".to_string(),
        );
        let snapshot = snapshot(vec![process(42, "mysqld"), listener(42, 3308)]);
        let handshake = FakeHandshake {
            accepting: vec![3308],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 3308);
        assert_eq!(found[0].evidence, "config");
        assert_eq!(found[0].confidence, 90);
    }

    #[test]
    fn skip_networking_means_no_tcp_endpoint() {
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec![
                "/usr/sbin/mysqld".to_string(),
                "--skip-networking".to_string(),
            ],
        );
        let snapshot = snapshot(vec![process(42, "mysqld"), listener(42, 3306)]);
        let handshake = FakeHandshake {
            accepting: vec![3306],
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
    fn the_same_port_from_two_processes_is_reported_once() {
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec!["/usr/sbin/mysqld".to_string(), "--port=3306".to_string()],
        );
        let snapshot = snapshot(vec![
            process(42, "mysqld"),
            process(43, "mysqld"),
            listener(42, 3306),
            listener(43, 3306),
        ]);
        let handshake = FakeHandshake {
            accepting: vec![3306],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1, "同一端口只留一条");
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
}
