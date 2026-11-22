//! 本机套接字事实：`/proc/net/{tcp,tcp6,udp,udp6}` 与 `/proc/<pid>/fd` 的解析。
//!
//! 调查面（`investigate_exposure`）与执行器（`socket.list`）**共用这一份**：
//! 两边各写一份解析，字段与过滤条件迟早会分叉。这里不做任何判定，
//! 只把内核表变成结构体，过滤条件由调用方给。
//!
//! 只读；不 exec `ss` / `netstat`。

use std::collections::BTreeMap;
use std::fs;
use std::net::Ipv6Addr;
use std::time::Instant;

/// 扫描 `/proc/<pid>/fd` 的预算：再大就不是「看一眼」了。
pub(crate) const MAX_FDS: usize = 200_000;

/// 套接字表的来源（顺序固定）。调用方按这个顺序读，报告里也按这个顺序说明可读性。
pub(crate) const SOURCES: &[(&str, &str)] = &[
    ("/proc/net/tcp", "tcp"),
    ("/proc/net/tcp6", "tcp6"),
    ("/proc/net/udp", "udp"),
    ("/proc/net/udp6", "udp6"),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Socket {
    pub proto: String,
    pub addr: String,
    pub port: u16,
    pub uid: u32,
    pub inode: u64,
    /// 内核状态码（`0A` = LISTEN，`07` = UDP 未连接…）。
    ///
    /// **不在这里过滤**：调查面只要监听项，执行面可能要看全部连接。
    pub state: String,
}

pub(crate) fn family_of(proto: &str) -> &'static str {
    if proto.ends_with('6') { "ipv6" } else { "ipv4" }
}

/// `/proc/net/*` 的状态码 → 可读名。UDP 的 `07` 是「未连接」而不是「已关闭」。
pub(crate) fn state_name(code: &str, proto: &str) -> &'static str {
    match code {
        "01" => "established",
        "02" => "syn_sent",
        "03" => "syn_recv",
        "04" => "fin_wait1",
        "05" => "fin_wait2",
        "06" => "time_wait",
        "07" => {
            if proto.starts_with("udp") {
                "unconnected"
            } else {
                "close"
            }
        }
        "08" => "close_wait",
        "09" => "last_ack",
        "0A" => "listen",
        "0B" => "closing",
        _ => "unknown",
    }
}

/// 是否在等连接：TCP 看 `0A`；UDP 没有 LISTEN，「未连接」（07）就是它的监听态。
pub(crate) fn is_listening(socket: &Socket) -> bool {
    if socket.proto.starts_with("udp") {
        socket.state == "07"
    } else {
        socket.state == "0A"
    }
}

/// `/proc/net/tcp{,6}` / `udp{,6}` 的一行：只取本地地址、状态、uid、inode。
///
/// 字段顺序（Linux 稳定）：`sl local rem st tx:rx tr:tm retrnsmt uid timeout inode ...`。
pub(crate) fn parse_proc_net(text: &str, proto: &str) -> Vec<Socket> {
    let mut out = Vec::new();
    for line in text.lines().skip(1) {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 10 {
            continue;
        }
        let Some((addr, port)) = parse_local(fields[1], proto) else {
            continue;
        };
        out.push(Socket {
            proto: proto.to_string(),
            addr,
            port,
            uid: fields[7].parse::<u32>().unwrap_or(0),
            inode: fields[9].parse::<u64>().unwrap_or(0),
            state: fields[3].to_string(),
        });
    }
    out
}

fn parse_local(field: &str, proto: &str) -> Option<(String, u16)> {
    let (addr_hex, port_hex) = field.split_once(':')?;
    let port = u16::from_str_radix(port_hex, 16).ok()?;
    let addr = if proto.ends_with('6') {
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
pub(crate) fn bind_scope(addr: &str) -> &'static str {
    if addr == "0.0.0.0" || addr == "::" {
        "all"
    } else if addr == "::1" || addr.starts_with("127.") {
        "loopback"
    } else {
        "specific"
    }
}

pub(crate) fn scope_rank(addr: &str) -> u8 {
    match bind_scope(addr) {
        "all" => 0,
        "specific" => 1,
        _ => 2,
    }
}

/// socket inode → (pid, 进程名)。非 root 只能看到自己的进程，所以结果天然不完整。
///
/// 返回 `(映射, 是否没扫完)`：截断必须被调用方报出来 ——
/// 「预算/时间用完」与「这些端口真的没有属主」是两件事。
pub(crate) fn socket_owners(
    budget: usize,
    deadline: Option<Instant>,
) -> (BTreeMap<u64, (u32, String)>, bool) {
    let mut map = BTreeMap::new();
    let out_of_time = || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    // 预算或时间一开始就没了：**什么都没扫**，也必须如实说「没扫完」。
    if budget == 0 || out_of_time() {
        return (map, true);
    }
    let Ok(entries) = fs::read_dir("/proc") else {
        return (map, false);
    };
    let mut budget = budget;
    let mut comm_cache: BTreeMap<u32, String> = BTreeMap::new();
    for entry in entries.flatten() {
        if out_of_time() {
            return (map, true);
        }
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(pid) = name.parse::<u32>() else {
            continue;
        };
        let Ok(fds) = fs::read_dir(entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if budget == 0 || out_of_time() {
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
    fn proc_net_parsing_keeps_every_state_and_the_raw_code() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                    0: 0100007F:1F90 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 111 1\n\
                    1: 0100007F:9C40 0100007F:1F90 01 00000000:00000000 00:00000000 00000000  1000        0 222 1\n";
        let sockets = parse_proc_net(text, "tcp");
        assert_eq!(sockets.len(), 2, "解析层不做过滤");
        assert_eq!(sockets[0].port, 8080);
        assert_eq!(sockets[0].addr, "127.0.0.1");
        assert_eq!(sockets[0].state, "0A");
        assert!(is_listening(&sockets[0]));
        assert_eq!(sockets[1].state, "01");
        assert!(!is_listening(&sockets[1]));
        assert_eq!(sockets[1].uid, 1000);
    }

    #[test]
    fn udp_treats_unconnected_as_its_listening_state() {
        let text = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n\
                    0: 00000000:0035 00000000:0000 07 00000000:00000000 00:00000000 00000000     0        0 333 1\n";
        let sockets = parse_proc_net(text, "udp");
        assert_eq!(sockets.len(), 1);
        assert_eq!(sockets[0].port, 53);
        assert_eq!(state_name(&sockets[0].state, "udp"), "unconnected");
        assert!(is_listening(&sockets[0]));
    }

    #[test]
    fn state_codes_map_to_stable_names() {
        assert_eq!(state_name("0A", "tcp"), "listen");
        assert_eq!(state_name("07", "tcp"), "close");
        assert_eq!(state_name("07", "udp"), "unconnected");
        assert_eq!(state_name("01", "tcp"), "established");
        assert_eq!(state_name("FF", "tcp"), "unknown");
    }

    #[test]
    fn bind_scope_separates_public_from_local() {
        assert_eq!(bind_scope("0.0.0.0"), "all");
        assert_eq!(bind_scope("::"), "all");
        assert_eq!(bind_scope("127.0.0.1"), "loopback");
        assert_eq!(bind_scope("::1"), "loopback");
        assert_eq!(bind_scope("10.1.2.3"), "specific");
        assert_eq!(family_of("tcp6"), "ipv6");
        assert_eq!(family_of("udp"), "ipv4");
    }

    #[test]
    fn owner_mapping_reports_budget_exhaustion() {
        // 预算为 0 时必须告诉调用方「没扫完」，而不是返回空表让它当成「都没属主」。
        let (owners, exhausted) = socket_owners(0, None);
        assert!(owners.is_empty());
        assert!(exhausted);
    }

    #[test]
    fn owner_mapping_reports_an_exhausted_deadline() {
        let past = Instant::now() - std::time::Duration::from_secs(1);
        let (owners, exhausted) = socket_owners(MAX_FDS, Some(past));
        assert!(owners.is_empty());
        assert!(exhausted);
    }
}
