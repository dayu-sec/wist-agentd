//! Doris 自探：只发现 **FE**（P0 只从 FE 读集群的 BE 视图）。
//!
//! 为什么只找 FE：`SHOW BACKENDS` 是 FE 的命令；连 BE 拿不到集群视图。
//! 所以 P0 的能力边界是「本机有 FE → 能看到整个集群的 BE 存活 / 容量 / tablet」；
//! 只有 BE 的机器不出指标（会在 `doctor` 与日志里说清楚，不猜、不补 0）。
//!
//! 运行时（host / docker-compose / k8s）由 [`super::db_source`] 按 netns 处理；
//! FE 用 MySQL 协议对外服务，所以指纹与 MySQL 一样：问好包首字节是 `protocol_version 10`。

use std::collections::BTreeMap;

use serde::Serialize;
use wist_contracts::discovery::DiscoverySnapshot;

use super::db_source::{
    DbProc, InstanceScope, RealProc, candidate_addrs, container_identities, container_targets,
    credential_key, processes, tcp_probe,
};

/// FE 的默认查询端口（MySQL 协议）。
const DEFAULT_QUERY_PORT: u16 = 9030;
/// 一次解析最多看多少个进程。
const MAX_INSPECTED_PROCESSES: usize = 8;

/// 一条 Doris FE 候选。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DorisInstanceEntry {
    pub source_ref: String,
    pub host: String,
    pub port: u16,
    pub credential_key: String,
    pub scope: InstanceScope,
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
}

impl DorisInstanceEntry {
    pub fn instance(&self) -> String {
        match self.scope {
            InstanceScope::Host => format!("doris:{}:{}", self.host, self.port),
            InstanceScope::Container => format!("doris:{}", self.credential_key),
        }
    }
}

pub trait Handshake {
    fn mysql_greeting(&self, addr: &str) -> bool;
}

pub struct TcpHandshake;

impl Handshake for TcpHandshake {
    fn mysql_greeting(&self, addr: &str) -> bool {
        tcp_probe(addr, |stream| {
            use std::io::Read;
            let mut first = [0u8; 1];
            matches!(stream.read(&mut first), Ok(1)) && first[0] == 0x0a
        })
    }
}

pub fn resolve_from_snapshot(snapshot: &DiscoverySnapshot) -> Vec<DorisInstanceEntry> {
    resolve(snapshot, &RealProc, &TcpHandshake)
}

pub fn resolve_live() -> Vec<DorisInstanceEntry> {
    resolve_from_snapshot(&super::db_source::live_snapshot("doris"))
}

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn DbProc,
    handshake: &dyn Handshake,
) -> Vec<DorisInstanceEntry> {
    let containers = container_identities(snapshot);
    let mut by_target: BTreeMap<(String, u16), DorisInstanceEntry> = BTreeMap::new();
    let mut inspected = 0usize;

    for process in processes(snapshot) {
        if inspected >= MAX_INSPECTED_PROCESSES {
            break;
        }
        if !may_be_fe(&process.exe) {
            continue;
        }
        let argv = proc.cmdline(process.pid);
        if !is_fe(&process.exe, &argv) {
            continue;
        }
        inspected += 1;

        let same_netns = proc.same_netns(process.pid);
        let scope = if same_netns {
            InstanceScope::Host
        } else {
            InstanceScope::Container
        };
        let addrs = candidate_addrs(process.pid, same_netns, proc, "doris");

        // 端口：优先默认查询口，其次该进程 netns 里所有监听（握手会筛掉 8030 等 HTTP 口）。
        let mut ports = vec![DEFAULT_QUERY_PORT];
        for port in proc.listen_ports(process.pid) {
            if !ports.contains(&port) && ports.len() < 4 {
                ports.push(port);
            }
        }

        for port in ports {
            let Some(host) = addrs
                .iter()
                .find(|addr| handshake.mysql_greeting(&format!("{addr}:{port}")))
            else {
                continue;
            };
            let evidence = if port == DEFAULT_QUERY_PORT {
                "default_port"
            } else {
                "listening_port"
            };
            let entry = DorisInstanceEntry {
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
                evidence: evidence.to_string(),
                detail: format!("FE 的 MySQL 协议端口 {port}"),
                confidence: if port == DEFAULT_QUERY_PORT { 80 } else { 50 },
            };
            by_target.insert((entry.host.clone(), port), entry);
            break;
        }
    }

    // 容器里的 FE：镜像名粗筛 + MySQL 协议握手。
    for target in container_targets(snapshot, may_be_fe, |addr| handshake.mysql_greeting(addr)) {
        let detail = format!(
            "容器镜像 {} 发布到宿主 {}:{}",
            target.image, target.host, target.port
        );
        let entry = DorisInstanceEntry {
            source_ref: target.source_ref,
            host: target.host,
            port: target.port,
            credential_key: target.credential_key,
            scope: InstanceScope::Container,
            evidence: "container_image".to_string(),
            detail,
            confidence: 70,
        };
        match by_target.get(&(entry.host.clone(), entry.port)) {
            Some(existing) if existing.confidence >= entry.confidence => {}
            _ => {
                by_target.insert((entry.host.clone(), entry.port), entry);
            }
        }
    }

    let mut out: Vec<DorisInstanceEntry> = by_target.into_values().collect();
    out.sort_by_key(|entry| (entry.host.clone(), entry.port));
    out
}

fn may_be_fe(exe: &str) -> bool {
    if exe.is_empty() {
        return true;
    }
    let exe = exe.to_ascii_lowercase();
    exe.contains("java") || exe.contains("doris") || exe.contains("palo")
}

/// 是不是 **FE**（排除 BE 与 broker）。
fn is_fe(exe: &str, argv: &[String]) -> bool {
    let joined = argv.join(" ").to_ascii_lowercase();
    let name = exe.to_ascii_lowercase();

    // BE / broker 都不做 `SHOW BACKENDS`。
    if joined.contains("palo_be")
        || joined.contains("doris_be")
        || name.contains("doris_be")
        || name.contains("palo_be")
    {
        return false;
    }

    joined.contains("palofe")
        || joined.contains("doris_fe")
        || joined.contains("dorisfe")
        || name.contains("doris-fe")
        || name.contains("palo-fe")
        // 兜底：只看得到 "doris"，端口握手会筛。
        || name.contains("doris")
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use wist_contracts::discovery::DiscoveredResource;

    #[derive(Default)]
    struct FakeProc {
        cmdlines: BTreeMap<u32, Vec<String>>,
        listen: BTreeMap<u32, Vec<u16>>,
        bound: BTreeMap<u32, Vec<String>>,
        addrs: BTreeMap<u32, Vec<String>>,
        same_netns: BTreeSet<u32>,
    }

    impl DbProc for FakeProc {
        fn cmdline(&self, pid: u32) -> Vec<String> {
            self.cmdlines.get(&pid).cloned().unwrap_or_default()
        }
        fn read_file(&self, _path: &str) -> Option<String> {
            None
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

    fn resource(kind: &str, attrs: Vec<(&str, String)>) -> DiscoveredResource {
        DiscoveredResource {
            resource_id: format!("{kind}:{}", attrs.len()),
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

    /// 容器里的 Doris FE：宿主看不到进程（java 在 VM 里），靠容器发布端口。
    #[test]
    fn a_container_published_port_becomes_a_container_scoped_instance() {
        let snapshot = snapshot(vec![crate::discovery::db_source::container_port_fixture(
            "c1",
            "doris-fe",
            "apache/doris:2.1",
            "0.0.0.0",
            19030,
        )]);
        let proc = FakeProc::default();
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:19030".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].host, "127.0.0.1");
        assert_eq!(found[0].port, 19030);
        assert_eq!(found[0].scope, InstanceScope::Container);
        assert_eq!(found[0].credential_key, "container-doris-fe");
        assert_eq!(found[0].evidence, "container_image");
    }

    #[test]
    fn an_fe_on_the_query_port_is_reported() {
        let snapshot = snapshot(vec![process(42, "java")]);
        let mut proc = FakeProc::default();
        proc.cmdlines.insert(
            42,
            vec!["java".to_string(), "org.apache.doris.PaloFe".to_string()],
        );
        proc.same_netns.insert(42);
        proc.listen.insert(42, vec![9030, 8030]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:9030".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1);
        assert_eq!(found[0].port, 9030);
        assert_eq!(found[0].credential_key, "port-9030");
        assert_eq!(found[0].instance(), "doris:127.0.0.1:9030");
        assert_eq!(found[0].evidence, "default_port");
    }

    #[test]
    fn a_java_fe_with_a_long_classpath_is_still_discovered() {
        // 真实 FE 的 cmdline：classpath 很长，主类在末尾；4 KiB 封顶会把它截掉。
        let snapshot = snapshot(vec![process(42, "/usr/lib/jvm/jdk-17/bin/java")]);
        let mut proc = FakeProc::default();
        let classpath = "/opt/doris/fe/lib/fe-common.jar:/opt/doris/fe/lib/fe-core.jar:/opt/doris/fe/lib/doris-fe.jar";
        proc.cmdlines.insert(
            42,
            vec![
                "/usr/lib/jvm/jdk-17/bin/java".to_string(),
                "-Xmx8g".to_string(),
                "-cp".to_string(),
                classpath.to_string(),
                "org.apache.doris.DorisFE".to_string(),
            ],
        );
        proc.same_netns.insert(42);
        proc.listen.insert(42, vec![9030, 8030]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:9030".to_string()],
        };

        let found = resolve(&snapshot, &proc, &handshake);

        assert_eq!(found.len(), 1, "{found:?}");
        assert_eq!(found[0].port, 9030);
    }

    #[test]
    fn a_backend_is_not_a_frontend() {
        let snapshot = snapshot(vec![process(42, "doris_be")]);
        let mut proc = FakeProc::default();
        proc.cmdlines
            .insert(42, vec!["/opt/doris/be/bin/doris_be".to_string()]);
        proc.same_netns.insert(42);
        proc.listen.insert(42, vec![9050, 8040]);
        let handshake = FakeHandshake {
            accepting: vec!["127.0.0.1:9050".to_string()],
        };

        assert!(
            resolve(&snapshot, &proc, &handshake).is_empty(),
            "BE 上跑不了 SHOW BACKENDS"
        );
    }

    #[test]
    fn the_http_port_is_dropped_by_handshake() {
        // 只发现得到 8030（HTTP）时不报，避免每轮都失败一次。
        let snapshot = snapshot(vec![process(42, "java")]);
        let mut proc = FakeProc::default();
        proc.cmdlines
            .insert(42, vec!["java".to_string(), "PaloFe".to_string()]);
        proc.same_netns.insert(42);
        proc.listen.insert(42, vec![8030]);
        let handshake = FakeHandshake::default();

        assert!(resolve(&snapshot, &proc, &handshake).is_empty());
    }
}
