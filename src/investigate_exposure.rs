//! 暴露面（`wist-agentd investigate exposure`）：**这台机器此刻在等谁连进来**。
//!
//! 只答属性，不答行为：监听 socket 是机器的一种**状态**，一次枚举就是全集；而"它往外连了谁"
//! 是行为，只有连续观测才准，归采集面（且我们已经明确不建这种"有结构性缺口"的采集面）。
//!
//! 这题刻意**不做安全判定**（`EVIDENCE_ONLY_TOPICS`）：`0.0.0.0:8080` 是好是坏，取决于这台
//! 机器该不该有它、以及它前面有没有反代/安全组 —— 主机只看得见绑定地址，看不见可达性。
//! 所以它给证据，判定留给中心的 join：`listeners × software(漏洞) × 拓扑(是否真对外)`。
//!
//! 三条边界：
//!
//! 1. **只读** `/proc/net/tcp{,6}` / `udp{,6}` + `/proc/<pid>/fd`，不 exec `ss`/`netstat`。
//! 2. **只做快照**：没有观察窗口。短连接看不到，这一点必须写在报告的 `limits` 里。
//! 3. **容器 netns 不覆盖**：宿主只看得见自己的 netns；有容器运行时就把这条认知写出来，
//!    否则"没看到 8080"会被读成"容器没开 8080"。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv6Addr;
use std::path::Path;

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{Finding, InvestigateRequest, Row, running_as_root};
use crate::investigate_probe::{Tally, truncate_rows};

/// 扫描 `/proc/<pid>/fd` 的预算：再大就不是"看一眼"了。
const MAX_FDS: usize = 200_000;

#[derive(Debug, Clone, PartialEq, Eq)]
struct Socket {
    proto: String,
    addr: String,
    port: u16,
    uid: u32,
    inode: u64,
}

pub(crate) fn investigate(
    request: &InvestigateRequest,
    _config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    if !cfg!(target_os = "linux") {
        return Err("exposure 调查暂只支持 Linux（macOS 需要 netstat/sysctl 的只读白名单）".into());
    }
    Ok(vec![listeners_finding(request.top)])
}

#[derive(Debug, Clone)]
struct Listener {
    proto: String,
    addr: String,
    port: u16,
    uid: u32,
    pids: BTreeSet<u32>,
    names: BTreeSet<String>,
}

fn listeners_finding(top: usize) -> Finding {
    let mut tally = Tally::default();
    let mut sockets: Vec<Socket> = Vec::new();
    let mut unreadable = 0usize;
    for (path, proto) in [
        ("/proc/net/tcp", "tcp"),
        ("/proc/net/tcp6", "tcp6"),
        ("/proc/net/udp", "udp"),
        ("/proc/net/udp6", "udp6"),
    ] {
        match tally.read(Path::new(path)) {
            Some(text) => sockets.extend(parse_proc_net(&text, proto)),
            None => unreadable += 1,
        }
    }
    if sockets.is_empty() && unreadable == 4 {
        return Finding::new(
            "exposure.listeners",
            Status::Unknown,
            "无法读取套接字表",
            "/proc/net/tcp{,6} 与 udp{,6} 都不可读",
        )
        .coverage(tally.coverage())
        .limit("本机可能是受限容器（/proc/net 被隐藏）");
    }

    let root = running_as_root();
    let (owners, owners_truncated) = if root {
        socket_owners(MAX_FDS)
    } else {
        (BTreeMap::new(), false)
    };

    // 聚合：同一个 (proto, 地址, 端口, uid) 下的多个 socket（SO_REUSEPORT）算一行。
    let mut grouped: BTreeMap<(String, String, u16, u32), Listener> = BTreeMap::new();
    let mut skipped = 0usize;
    for socket in sockets {
        if socket.inode == 0 {
            // 内核内部 socket（如 ICMP），没有可归属的进程。
            skipped += 1;
            continue;
        }
        let key = (
            socket.proto.clone(),
            socket.addr.clone(),
            socket.port,
            socket.uid,
        );
        let entry = grouped.entry(key).or_insert_with(|| Listener {
            proto: socket.proto.clone(),
            addr: socket.addr.clone(),
            port: socket.port,
            uid: socket.uid,
            pids: BTreeSet::new(),
            names: BTreeSet::new(),
        });
        if let Some((pid, name)) = owners.get(&socket.inode) {
            entry.pids.insert(*pid);
            if !name.is_empty() {
                entry.names.insert(name.clone());
            }
        }
    }

    let mut listeners: Vec<Listener> = grouped.into_values().collect();
    // 对外的排前面：`all` → `specific` → `loopback`。
    listeners.sort_by_key(|listener| {
        (
            scope_rank(&listener.addr),
            listener.port,
            listener.proto.clone(),
            listener.addr.clone(),
        )
    });

    let mut public = 0usize;
    let mut rows: Vec<Row> = Vec::new();
    for listener in &listeners {
        let scope = bind_scope(&listener.addr);
        if scope == "all" {
            public += 1;
        }
        let mut note = scope.to_string();
        if !listener.names.is_empty() {
            note.push('；');
            note.push_str(
                &listener
                    .names
                    .iter()
                    .cloned()
                    .collect::<Vec<_>>()
                    .join(", "),
            );
        } else if !root {
            note.push_str("；属主不可见（非 root）");
        }
        rows.push(Row::new(
            format!("{}:{}", listener.addr, listener.port),
            format!("{} / uid {}", listener.proto, listener.uid),
            note,
        ));
    }
    let (rows, omitted) = truncate_rows(rows, top);

    let mut detail = format!(
        "监听套接字 {} 个；绑定全部地址（0.0.0.0 / ::）{} 个",
        listeners.len(),
        public
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    if unreadable > 0 {
        let _ =
            std::fmt::Write::write_fmt(&mut detail, format_args!("；{unreadable} 个来源不可读"));
    }

    let coverage = crate::investigate::Coverage::new(
        tally.checked,
        if root { 0 } else { 1 },
        skipped + tally.skipped + usize::from(owners_truncated),
    );
    let mut finding = Finding::new("exposure.listeners", Status::Ok, "监听端口已列出", detail)
        .rows(rows)
        .coverage(coverage)
        .limit("这是一次快照：生命周期短于一次读取的连接不会出现在报告里")
        .limit("只覆盖 agent 所在 netns；容器里的监听端口不在本报告里");

    if !root {
        finding =
            finding.limit("非 root：端口可见，但属主（pid/进程名）不可见 —— 以 root 重跑才完整");
    }
    if owners_truncated {
        // “预算用完”必须说出来：否则这张表看起来像“所有端口都归好属了”。
        finding = finding.limit(format!(
            "进程表超过扫描预算（{MAX_FDS} 个 fd）：部分端口没有属主"
        ));
    }
    if Path::new("/var/run/docker.sock").exists()
        || Path::new("/run/containerd/containerd.sock").exists()
    {
        finding =
            finding.limit("本机有容器运行时：宿主 netns 之外的端口需要另行检查（container 题）");
    }
    finding.hint("绑定 `0.0.0.0` / `::` 只说明本机在听；是否真的对外取决于反代、安全组与拓扑")
}

/// `/proc/net/tcp{,6}` / `udp{,6}` 的一行：只取本地地址、状态、uid、inode。
///
/// 字段顺序（Linux 稳定）：`sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...`。
fn parse_proc_net(text: &str, proto: &str) -> Vec<Socket> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        // UDP 没有 LISTEN 状态（未连接 socket 显示 07），所以只对 TCP 过滤状态。
        let state = fields[3];
        if proto.starts_with("tcp") && state != "0A" {
            continue;
        }
        let Some((addr, port)) = parse_local(fields[1], proto) else {
            continue;
        };
        let uid = fields[7].parse::<u32>().unwrap_or(0);
        let inode = fields[9].parse::<u64>().unwrap_or(0);
        out.push(Socket {
            proto: proto.to_string(),
            addr,
            port,
            uid,
            inode,
        });
    }
    out
}

fn parse_local(field: &str, proto: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if proto.ends_with("6") {
        decode_v6(addr_hex)?
    } else {
        decode_v4(addr_hex)?
    };
    Some((addr, port))
}

/// `/proc/net/tcp` 的 v4 地址是**小端**的 32 位十六进制（`0100007F` = 127.0.0.1）。
fn decode_v4(hex: &str) -> Option<String> {
    let raw = u32::from_str_radix(hex, 16).ok()?;
    let bytes = raw.to_le_bytes();
    Some(format!(
        "{}.{}.{}.{}",
        bytes[0], bytes[1], bytes[2], bytes[3]
    ))
}

/// v6 是**四组**各自小端的 32 位（共 32 个十六进制字符）。
fn decode_v6(hex: &str) -> Option<String> {
    if hex.len() != 32 {
        return None;
    }
    let mut bytes = [0u8; 16];
    for (index, chunk) in hex.as_bytes().chunks(8).enumerate() {
        let group = u32::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
        bytes[index * 4..index * 4 + 4].copy_from_slice(&group.to_le_bytes());
    }
    Some(Ipv6Addr::from(bytes).to_string())
}

/// `all` = 绑定全部地址；`loopback` = 只有本机；`specific` = 某一个地址。
fn bind_scope(addr: &str) -> &'static str {
    if addr == "0.0.0.0" || addr == "::" {
        "all"
    } else if addr == "::1" || addr.starts_with("127.") {
        "loopback"
    } else {
        "specific"
    }
}

fn scope_rank(addr: &str) -> u8 {
    match bind_scope(addr) {
        "all" => 0,
        "specific" => 1,
        _ => 2,
    }
}

/// socket inode → (pid, 进程名)。非 root 只能看到自己的进程，所以结果天然不完整。
///
/// 返回 `(映射, 是否因预算截断)`：截断必须被调用方报出来 ——
/// “预算用完”与“这些端口真的没有属主”是两件事。
fn socket_owners(budget: usize) -> (BTreeMap<u64, (u32, String)>, bool) {
    let mut map = BTreeMap::new();
    if budget == 0 {
        return (map, true);
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return (map, false);
    };
    let mut budget = budget;
    let mut comm_cache: BTreeMap<u32, String> = BTreeMap::new();
    for entry in entries.flatten() {
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if budget == 0 {
                return (map, true);
            }
            budget -= 1;
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            let Some(target) = target.to_str() else {
                continue;
            };
            let Some(inode) = target
                .strip_prefix("socket:[")
                .and_then(|rest| rest.strip_suffix(']'))
                .and_then(|inode| inode.parse::<u64>().ok())
            else {
                continue;
            };
            // 同一个 pid 的每个 fd 都读一次 comm 是浪费：按 pid 缓存。
            let comm = comm_cache
                .entry(pid)
                .or_insert_with(|| {
                    fs::read_to_string(entry.path().join("comm"))
                        .map(|comm| comm.trim().to_string())
                        .unwrap_or_default()
                })
                .clone();
            map.insert(inode, (pid, comm));
        }
    }
    (map, false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn v4_addresses_are_little_endian() {
        assert_eq!(decode_v4("0100007F").as_deref(), Some("127.0.0.1"));
        assert_eq!(decode_v4("00000000").as_deref(), Some("0.0.0.0"));
        assert_eq!(decode_v4("0101A8C0").as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn v6_addresses_decode_per_32_bit_group() {
        assert_eq!(
            decode_v6("00000000000000000000000001000000").as_deref(),
            Some("::1")
        );
        assert_eq!(
            decode_v6("00000000000000000000000000000000").as_deref(),
            Some("::")
        );
    }

    #[test]
    fn proc_net_parsing_keeps_only_listeners_for_tcp() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1\n\
                    1: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 222 1\n";
        let sockets = parse_proc_net(text, "tcp");
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 8080);
        assert_eq!(sockets[0].addr, "127.0.0.1");
        assert_eq!(sockets[0].inode, 111);
    }

    #[test]
    fn udp_sockets_are_not_filtered_by_state() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                    0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 333 1\n";
        let sockets = parse_proc_net(text, "udp");
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 53);
    }

    #[test]
    fn bind_scope_separates_public_from_local() {
        assert_eq!(bind_scope("0.0.0.0"), "all");
        assert_eq!(bind_scope("::"), "all");
        assert_eq!(bind_scope("127.0.0.1"), "loopback");
        assert_eq!(bind_scope("::1"), "loopback");
        assert_eq!(bind_scope("10.1.2.3"), "specific");
    }

    #[test]
    fn owner_mapping_reports_budget_exhaustion() {
        // 预算为 0 时必须告诉调用方“没扫完”，而不是返回空表让它当成“都没属主”。
        let (owners, exhausted) = socket_owners(0);
        assert!(owners.is_empty());
        assert!(exhausted);
    }
}
