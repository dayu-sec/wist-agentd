//! tc/eBPF 采集器（Linux + 构建期有 clang 时编译）。
//!
//! 只做三件事：加载/挂载、按窗口扫表、把原始累计量还原成 [`FlowKey`] + [`WindowAgg`]。
//! 窗口的**墙钟归属**由调用方用「桶差」换算（见 [`crate::telemetry::flows::window_from_bucket`]）：
//! BPF 侧用 `bpf_ktime_get_ns()` 分桶（单调时钟），用户态把当前桶对齐到 UTC 整分，
//! 其余桶按差值回推 —— 不需要把墙钟写进 BPF。

use crate::telemetry::flows::iface::IfaceSnapshot;
use crate::telemetry::flows::record::{Direction, FLUSH_LAG_WINDOWS, FlowKey, WindowAgg, is_late};
use crate::telemetry::flows::support::{FlowSupport, Unavailable};
use crate::telemetry::flows::{FlushedFlow, WatchedIface};
use aya::maps::{HashMap, MapData, PerCpuArray};
use aya::programs::ProgramError;
use aya::programs::tc::{SchedClassifier, TcAttachType};
use aya::{Ebpf, EbpfError};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// 构建期由 build.rs 编好并嵌入。对齐要求来自 aya（map/程序结构需要 8 字节对齐）。
static FLOW_BPF: &[u8] = aya::include_bytes_aligned!(concat!(env!("OUT_DIR"), "/flow.bpf.o"));

const MIN_KERNEL: (u32, u32) = (5, 4);
const PROG_EGRESS: &str = "flow_egress";
const PROG_INGRESS: &str = "flow_ingress";
const MAP_NAME: &str = "flow_map";
const MAP_DROPS: &str = "drops";

/// BPF map 的键（与 `flow.bpf.c` 的 `struct flow_key` 逐字节一致）。
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RawFlowKey {
    window_id: u64,
    ifindex: u32,
    direction: u8,
    protocol: u8,
    family: u8,
    flags: u8,
    src: [u8; 16],
    dst: [u8; 16],
    src_port: u16,
    dst_port: u16,
    icmp_type: u8,
    icmp_code: u8,
    pad: [u8; 6],
}
// SAFETY: `repr(C, packed)`、字段全是整数数组，没有指针也没有未初始化字节。
unsafe impl aya::Pod for RawFlowKey {}

/// BPF map 的值（与 `flow.bpf.c` 的 `struct flow_val` 逐字节一致）。
#[repr(C, packed)]
#[derive(Debug, Clone, Copy, Default)]
pub(crate) struct RawFlowVal {
    packets: u64,
    bytes: u64,
    wire_bytes: u64,
    skb_count: u64,
    gso_skb_count: u64,
    dropped: u32,
    flags: u32,
}
// SAFETY: 同上。
unsafe impl aya::Pod for RawFlowVal {}

const FLAG_PORT_UNAVAILABLE: u8 = 1;
const FLAG_WIRE_BYTES_MISSING: u32 = 2;

/// 读内核版本（`uname -r` 的前两个数字）。
pub(crate) fn kernel_release() -> Option<String> {
    let mut buf: libc::utsname = unsafe { std::mem::zeroed() };
    if unsafe { libc::uname(&mut buf) } != 0 {
        return None;
    }
    let bytes: Vec<u8> = buf
        .release
        .iter()
        .take_while(|byte| **byte != 0)
        .map(|byte| *byte as u8)
        .collect();
    String::from_utf8(bytes).ok()
}

fn parse_kernel(release: &str) -> Option<(u32, u32)> {
    let mut parts = release.split(|ch: char| !ch.is_ascii_digit());
    let major = parts.find(|p| !p.is_empty())?.parse().ok()?;
    let minor = parts.find(|p| !p.is_empty())?.parse().ok()?;
    Some((major, minor))
}

/// 本机能采吗（只判内核；权限/挂载在 `start` 里才会暴露）。
pub(crate) fn probe() -> FlowSupport {
    let Some(release) = kernel_release() else {
        return FlowSupport::Unavailable(Unavailable::KernelTooOld {
            running: "unknown".to_string(),
            required: "5.4".to_string(),
        });
    };
    match parse_kernel(&release) {
        Some(version) if version >= MIN_KERNEL => FlowSupport::Available,
        _ => FlowSupport::Unavailable(Unavailable::KernelTooOld {
            running: release,
            required: "5.4".to_string(),
        }),
    }
}

/// 已挂载的观测器。`Drop` 时 aya 负责摘掉 filter（不删除宿主已有的 qdisc）。
pub(crate) struct Collector {
    bpf: Ebpf,
    ifaces: Vec<WatchedIface>,
    /// 上次读到的 drops 累计值（per-cpu 计数器本身不清零，只算增量）。
    last_drops: u64,
    /// 已经 flush 到哪个桶（含）。再落进这个桶的包是**迟到**，只能计丢，不能再发一条。
    flushed_through: u64,
    /// 迟到包数（补发会破坏「一个键一个窗口一条记录」，所以只记数）。
    late_dropped: u64,
}

fn attach_error(ifname: &str, err: ProgramError) -> Unavailable {
    let text = err.to_string();
    // EPERM/EACCES 是能力问题，其余（EBUSY/ENOENT/verifier）按运行失败报。
    if text.contains("Operation not permitted") || text.contains("Permission denied") {
        Unavailable::PermissionDenied {
            capability: "CAP_NET_ADMIN/CAP_BPF".to_string(),
        }
    } else {
        Unavailable::QdiscConflict {
            ifname: ifname.to_string(),
            detail: text,
        }
    }
}

impl Collector {
    pub(crate) fn start(ifaces: &[&IfaceSnapshot]) -> Result<Self, Unavailable> {
        let mut bpf = Ebpf::load(FLOW_BPF).map_err(|err: EbpfError| Unavailable::LoadFailed {
            detail: err.to_string(),
        })?;

        // 先各加载一次（挂到多张网卡时复用同一个已加载程序）。
        for name in [PROG_EGRESS, PROG_INGRESS] {
            let program: &mut SchedClassifier = bpf
                .program_mut(name)
                .ok_or_else(|| Unavailable::LoadFailed {
                    detail: format!("program {name} missing from flow.bpf.o"),
                })?
                .try_into()
                .map_err(|err: ProgramError| Unavailable::LoadFailed {
                    detail: err.to_string(),
                })?;
            program
                .load()
                .map_err(|err: ProgramError| Unavailable::LoadFailed {
                    detail: err.to_string(),
                })?;
        }

        for iface in ifaces {
            for (name, attach_type) in [
                (PROG_EGRESS, TcAttachType::Egress),
                (PROG_INGRESS, TcAttachType::Ingress),
            ] {
                let program: &mut SchedClassifier = bpf
                    .program_mut(name)
                    .expect("checked above")
                    .try_into()
                    .map_err(|err: ProgramError| Unavailable::LoadFailed {
                        detail: err.to_string(),
                    })?;
                // aya 会在需要时创建 clsact；失败按「装不上」归类，**不强行删已有 qdisc**。
                let cname = std::ffi::CString::new(iface.name.as_str()).map_err(|_| {
                    Unavailable::QdiscConflict {
                        ifname: iface.name.clone(),
                        detail: "interface name contains a NUL byte".to_string(),
                    }
                })?;
                program
                    .attach(cname.as_c_str(), attach_type)
                    .map_err(|err| attach_error(&iface.name, err))?;
            }
        }

        Ok(Self {
            bpf,
            last_drops: 0,
            flushed_through: 0,
            late_dropped: 0,
            ifaces: ifaces
                .iter()
                .map(|iface| WatchedIface {
                    name: iface.name.clone(),
                    ifindex: iface.ifindex,
                    mac: iface.mac.clone(),
                    addrs: iface.addrs.clone(),
                })
                .collect(),
        })
    }

    pub(crate) fn watched(&self) -> &[WatchedIface] {
        &self.ifaces
    }

    /// 读「表满/更新失败」计数并返回**增量**（per-cpu 计数器只增不清，避免重置语义）。
    fn take_drops(&mut self) -> u64 {
        let Some(map) = self.bpf.map_mut(MAP_DROPS) else {
            return 0;
        };
        let Ok(counter) = PerCpuArray::<_, u64>::try_from(map) else {
            return 0;
        };
        let total: u64 = match counter.get(&0, 0) {
            Ok(values) => values.iter().map(|value| *value).sum(),
            Err(_) => return 0,
        };
        let delta = total.saturating_sub(self.last_drops);
        self.last_drops = total;
        delta
    }

    /// 迟到包数（上一次 flush 之后落进已 flush 窗口的包）。自观测用。
    pub(crate) fn take_late_dropped(&mut self) -> u64 {
        std::mem::take(&mut self.late_dropped)
    }

    /// flush 掉已经结束满 `FLUSH_LAG_WINDOWS` 个窗口的桶。
    pub(crate) fn flush(&mut self, now_bucket: u64) -> Vec<FlushedFlow> {
        let drops = self.take_drops();
        let horizon = now_bucket.saturating_sub(FLUSH_LAG_WINDOWS);
        let Some(map) = self.bpf.map_mut(MAP_NAME) else {
            return Vec::new();
        };
        let Ok(mut hash) = HashMap::<&mut MapData, RawFlowKey, RawFlowVal>::try_from(map) else {
            return Vec::new();
        };

        // 先收集候选（迭代中删除会破坏遍历），再逐条取走。
        let mut candidates: Vec<RawFlowKey> = Vec::new();
        for entry in hash.iter() {
            let Ok((key, _)) = entry else { continue };
            if key.window_id <= horizon {
                candidates.push(key);
            }
        }

        let mut flushed = Vec::with_capacity(candidates.len());
        for key in candidates {
            let Ok(value) = hash.get(&key, 0) else {
                continue;
            };
            let _ = hash.remove(&key);
            // 迟到：这个桶在上一轮已经 flush 过，再发一条就是同一幂等键的第二条记录。
            if is_late(key.window_id, self.flushed_through) {
                self.late_dropped = self.late_dropped.saturating_add(1);
                continue;
            }
            let agg = WindowAgg {
                packets: value.packets,
                bytes: value.bytes,
                wire_bytes: (value.flags & FLAG_WIRE_BYTES_MISSING == 0)
                    .then_some(value.wire_bytes),
                skb_count: value.skb_count,
                gso_skb_count: value.gso_skb_count,
                dropped: value.dropped,
                // 近似：BPF 侧只知道「自上次读取以来有没有失败过」，没有按窗口分桶。
                // 宁可多报一轮（truncated=true），也不要在丢过数据时静默报完整。
                truncated: drops > 0,
            };
            if agg.is_empty() {
                continue;
            }
            let Some(decoded) = decode_key(&key) else {
                continue;
            };
            flushed.push(FlushedFlow {
                ifindex: key.ifindex,
                key: decoded,
                window_bucket: key.window_id,
                agg,
            });
        }
        self.flushed_through = self.flushed_through.max(horizon);
        flushed
    }
    /// 不按窗口过滤地把表里的条目全取出来（只给真机冒烟测试用）。
    #[cfg(test)]
    pub(crate) fn snapshot_all(&mut self) -> Vec<FlushedFlow> {
        let Some(map) = self.bpf.map_mut(MAP_NAME) else {
            return Vec::new();
        };
        let Ok(hash) = HashMap::<&mut MapData, RawFlowKey, RawFlowVal>::try_from(map) else {
            return Vec::new();
        };
        let mut out = Vec::new();
        for entry in hash.iter() {
            let Ok((key, value)) = entry else { continue };
            let Some(decoded) = decode_key(&key) else {
                continue;
            };
            out.push(FlushedFlow {
                ifindex: key.ifindex,
                key: decoded,
                window_bucket: key.window_id,
                agg: WindowAgg {
                    packets: value.packets,
                    bytes: value.bytes,
                    wire_bytes: (value.flags & FLAG_WIRE_BYTES_MISSING == 0)
                        .then_some(value.wire_bytes),
                    skb_count: value.skb_count,
                    gso_skb_count: value.gso_skb_count,
                    dropped: value.dropped,
                    truncated: false,
                },
            });
        }
        out
    }
}

fn decode_key(raw: &RawFlowKey) -> Option<FlowKey> {
    let family = raw.family;
    let src = match family {
        4 => IpAddr::V4(Ipv4Addr::new(
            raw.src[0], raw.src[1], raw.src[2], raw.src[3],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(raw.src)),
        _ => return None,
    };
    let dst = match family {
        4 => IpAddr::V4(Ipv4Addr::new(
            raw.dst[0], raw.dst[1], raw.dst[2], raw.dst[3],
        )),
        6 => IpAddr::V6(Ipv6Addr::from(raw.dst)),
        _ => return None,
    };
    let direction = match raw.direction {
        0 => Direction::In,
        1 => Direction::Out,
        _ => return None,
    };
    let icmp = matches!(raw.protocol, 1 | 58).then_some((raw.icmp_type, raw.icmp_code));
    Some(FlowKey {
        direction,
        protocol: raw.protocol,
        src,
        dst,
        src_port: u16::from_be(raw.src_port),
        dst_port: u16::from_be(raw.dst_port),
        icmp_type: icmp.map(|(kind, _)| kind),
        icmp_code: icmp.map(|(_, code)| code),
        port_unavailable: raw.flags & FLAG_PORT_UNAVAILABLE != 0,
    })
}

// ── 网卡发现（Linux 事实，平台不指定）────────────────────────────────────────

/// 当前接口快照：名字/ifindex/MAC/地址 + 是不是默认路由出口。
///
/// 只读 `/sys`、`/proc/net/route` 与 libc 的 `getifaddrs`：不依赖 `ip` 命令，
/// 也不打开 netlink 长连接（这里只需要"现在是什么样"）。
pub(crate) fn interfaces() -> Vec<IfaceSnapshot> {
    use std::collections::HashMap;

    let mut addrs: HashMap<String, Vec<IpAddr>> = HashMap::new();
    let mut raw: *mut libc::ifaddrs = std::ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut raw) } == 0 {
        let mut cursor = raw;
        while !cursor.is_null() {
            let entry = unsafe { &*cursor };
            if !entry.ifa_addr.is_null() {
                let family = unsafe { (*entry.ifa_addr).sa_family as i32 };
                if family == libc::AF_INET || family == libc::AF_INET6 {
                    let name = unsafe { std::ffi::CStr::from_ptr(entry.ifa_name) }
                        .to_string_lossy()
                        .into_owned();
                    if let Some(ip) = sockaddr_to_ip(entry.ifa_addr) {
                        addrs.entry(name).or_default().push(ip);
                    }
                }
            }
            cursor = entry.ifa_next;
        }
        unsafe { libc::freeifaddrs(raw) };
    }

    let default_egress = default_egress_iface();

    let mut snapshot: Vec<IfaceSnapshot> = Vec::new();
    let mut raw_names: *mut libc::if_nameindex = std::ptr::null_mut();
    raw_names = unsafe { libc::if_nameindex() };
    if raw_names.is_null() {
        return snapshot;
    }
    let mut index = 0usize;
    loop {
        let entry = unsafe { *raw_names.add(index) };
        if entry.if_index == 0 {
            break;
        }
        // SAFETY: `if_nameindex()` 返回的 name 以 NUL 结尾，且在本循环内有效。
        let name = unsafe { std::ffi::CStr::from_ptr(entry.if_name) }
            .to_string_lossy()
            .into_owned();
        let mut iface_addrs = addrs.remove(&name).unwrap_or_default();
        iface_addrs.sort();
        iface_addrs.dedup();
        snapshot.push(IfaceSnapshot {
            mac: read_mac(&name),
            name: name.clone(),
            ifindex: entry.if_index,
            addrs: iface_addrs,
            is_default_egress: default_egress.as_deref() == Some(name.as_str()),
        });
        index += 1;
    }
    unsafe { libc::if_freenameindex(raw_names) };
    snapshot
}

fn sockaddr_to_ip(addr: *const libc::sockaddr) -> Option<IpAddr> {
    let family = unsafe { (*addr).sa_family as i32 };
    match family {
        libc::AF_INET => {
            let sin = unsafe { &*(addr as *const libc::sockaddr_in) };
            Some(IpAddr::V4(std::net::Ipv4Addr::from(u32::from_be(
                sin.sin_addr.s_addr,
            ))))
        }
        libc::AF_INET6 => {
            let sin6 = unsafe { &*(addr as *const libc::sockaddr_in6) };
            Some(IpAddr::V6(std::net::Ipv6Addr::from(sin6.sin6_addr.s6_addr)))
        }
        _ => None,
    }
}

fn read_mac(ifname: &str) -> Option<String> {
    let text = std::fs::read_to_string(format!("/sys/class/net/{ifname}/address")).ok()?;
    let mac = text.trim();
    (!mac.is_empty()).then(|| mac.to_string())
}

/// 默认路由出口（`/proc/net/route` 里 dest=0 且带 RTF_UP 的那条）。
fn default_egress_iface() -> Option<String> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let iface = fields.next()?;
        let dest = fields.next()?;
        let _gateway = fields.next()?;
        let flags = fields.next()?;
        if dest == "00000000" {
            let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
            if flags & 0x1 != 0 {
                return Some(iface.to_string());
            }
        }
    }
    None
}

/// 默认路由的网关（v4），给真机冒烟测试选一个本机确实会经 eth0 走的目的地址。
fn default_gateway_v4() -> Option<std::net::Ipv4Addr> {
    let text = std::fs::read_to_string("/proc/net/route").ok()?;
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let _iface = fields.next()?;
        let dest = fields.next()?;
        let gateway = fields.next()?;
        if dest == "00000000" {
            // /proc/net/route 里的地址是「按小端打印的 32 位值」。
            let raw = u32::from_str_radix(gateway, 16).ok()?;
            return Some(std::net::Ipv4Addr::from(raw.to_be()));
        }
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::flows::iface::{self, select_observed};
    use std::mem::{offset_of, size_of};

    /// C 与 Rust 两边的结构必须逐字节一致：改了任一边而没改另一边，map 会解析出垃圾。
    #[test]
    fn raw_struct_layout_matches_the_bpf_object() {
        assert_eq!(size_of::<RawFlowKey>(), 60, "flow_key 大小");
        assert_eq!(size_of::<RawFlowVal>(), 48, "flow_val 大小");
        assert_eq!(offset_of!(RawFlowKey, window_id), 0);
        assert_eq!(offset_of!(RawFlowKey, ifindex), 8);
        assert_eq!(offset_of!(RawFlowKey, direction), 12);
        assert_eq!(offset_of!(RawFlowKey, protocol), 13);
        assert_eq!(offset_of!(RawFlowKey, family), 14);
        assert_eq!(offset_of!(RawFlowKey, flags), 15);
        assert_eq!(offset_of!(RawFlowKey, src), 16);
        assert_eq!(offset_of!(RawFlowKey, dst), 32);
        assert_eq!(offset_of!(RawFlowKey, src_port), 48);
        assert_eq!(offset_of!(RawFlowKey, dst_port), 50);
        assert_eq!(offset_of!(RawFlowKey, icmp_type), 52);
        assert_eq!(offset_of!(RawFlowKey, pad), 54);
        assert_eq!(offset_of!(RawFlowVal, packets), 0);
        assert_eq!(offset_of!(RawFlowVal, wire_bytes), 16);
        assert_eq!(offset_of!(RawFlowVal, dropped), 40);
        assert_eq!(offset_of!(RawFlowVal, flags), 44);
    }

    fn raw_key(family: u8, direction: u8, protocol: u8, flags: u8) -> RawFlowKey {
        RawFlowKey {
            window_id: 7,
            ifindex: 2,
            direction,
            protocol,
            family,
            flags,
            src: [0; 16],
            dst: [0; 16],
            // 端口在 map 里是网络序：0x1f90 = 8080。
            src_port: 0x1f90u16.to_be(),
            dst_port: 0x01bbu16.to_be(),
            icmp_type: 0,
            icmp_code: 0,
            pad: [0; 6],
        }
    }

    #[test]
    fn decodes_a_v4_tcp_key() {
        let mut raw = raw_key(4, 1, 6, 0);
        raw.src[..4].copy_from_slice(&[10, 118, 0, 14]);
        raw.dst[..4].copy_from_slice(&[88, 214, 25, 121]);
        let key = decode_key(&raw).expect("decode");
        assert_eq!(key.direction, Direction::Out);
        assert_eq!(key.protocol, 6);
        assert_eq!(key.src.to_string(), "10.118.0.14");
        assert_eq!(key.dst.to_string(), "88.214.25.121");
        assert_eq!(key.src_port, 8080, "网络序要转回来");
        assert_eq!(key.dst_port, 443);
        assert!(key.icmp_type.is_none(), "TCP 不该带 icmp 字段");
        assert!(!key.port_unavailable);
    }

    #[test]
    fn decodes_a_v6_icmp_key_and_the_unavailable_flag() {
        let mut raw = raw_key(6, 0, 58, FLAG_PORT_UNAVAILABLE);
        raw.src = [0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1];
        raw.dst = [0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2];
        raw.icmp_type = 128;
        raw.icmp_code = 1;
        let key = decode_key(&raw).expect("decode");
        assert_eq!(key.direction, Direction::In);
        assert_eq!(key.src.to_string(), "2001:db8::1");
        assert_eq!(key.dst.to_string(), "fd00::2");
        assert_eq!(key.icmp_type, Some(128));
        assert_eq!(key.icmp_code, Some(1));
        assert!(key.port_unavailable);
    }

    #[test]
    fn rejects_unknown_family_and_direction() {
        assert!(decode_key(&raw_key(0, 1, 6, 0)).is_none(), "family 0");
        assert!(decode_key(&raw_key(5, 1, 6, 0)).is_none(), "family 5");
        assert!(decode_key(&raw_key(4, 2, 6, 0)).is_none(), "direction 2");
        assert!(decode_key(&raw_key(4, 9, 6, 0)).is_none(), "direction 9");
    }

    #[test]
    fn interface_snapshot_finds_the_default_egress_with_a_routable_addr() {
        // 纯读：任何 Linux 主机都该有默认出口；没有就说明这台机不适合做流采集。
        let snapshot = interfaces();
        let chosen = select_observed(&snapshot);
        assert!(
            !chosen.is_empty(),
            "没有可观测网卡：{:?}",
            snapshot
                .iter()
                .map(|iface| (&iface.name, iface.is_default_egress))
                .collect::<Vec<_>>()
        );
        let iface = chosen[0];
        assert!(iface.addrs.iter().any(|addr| iface::is_flow_addr(*addr)));
        assert!(!iface.name.is_empty() && iface.ifindex > 0);
    }

    /// 真机冒烟（root + tc）：一次挂载里验四件事 ——
    /// 1) UDP 出向的**精确 L3 字节**；2) 不同目的端口不合并；3) 大报文仍按 L3 计；
    /// 4) ICMP echo 进得到 `protocol=1` + `icmp_type=8`。
    #[test]
    #[ignore = "需要 root + tc + 真实流量（在 Linux 真机上跑）"]
    fn counts_real_flows_on_a_live_interface() {
        let snapshot = interfaces();
        let chosen = select_observed(&snapshot);
        let iface = (*chosen.first().expect("默认出口网卡")).clone();
        let ifaces = [iface.clone()];
        let refs: Vec<&IfaceSnapshot> = ifaces.iter().collect();
        let mut collector = Collector::start(&refs).expect("attach tc");

        let gateway = default_gateway_v4().expect("默认网关");
        let local_v4 = iface
            .addrs
            .iter()
            .find_map(|addr| match addr {
                IpAddr::V4(v4) => Some(*v4),
                IpAddr::V6(_) => None,
            })
            .expect("网卡应有一个 v4 地址");

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind");
        let send = |payload: usize, port: u16, count: u64| {
            let body = vec![b'x'; payload];
            for _ in 0..count {
                socket.send_to(&body, (gateway, port)).expect("send");
                std::thread::sleep(std::time::Duration::from_millis(20));
            }
        };
        // 同一个目的地址、三个不同端口；第三个是大报文（1400B payload）。
        send(15, 9, 5);
        send(15, 10, 3);
        send(1400, 11, 2);
        std::thread::sleep(std::time::Duration::from_millis(300));

        let flows = collector.snapshot_all();
        for (port, count, per_packet_l3) in [
            (9u16, 5u64, 20u64 + 8 + 15),
            (10, 3, 20u64 + 8 + 15),
            (11, 2, 20u64 + 8 + 1400),
        ] {
            let flow = flows
                .iter()
                .find(|flow| {
                    flow.ifindex == iface.ifindex
                        && flow.key.direction == Direction::Out
                        && flow.key.protocol == 17
                        && flow.key.dst_port == port
                })
                .unwrap_or_else(|| {
                    panic!(
                        "没数到出向 UDP 到 {}:{port}；已看到 {:?}",
                        gateway,
                        flows
                            .iter()
                            .map(|flow| (
                                flow.key.protocol,
                                flow.key.direction,
                                flow.key.dst_port,
                                flow.agg.packets,
                                flow.agg.bytes
                            ))
                            .collect::<Vec<_>>()
                    )
                });
            assert_eq!(flow.agg.packets, count, "端口 {port} 的报文数");
            assert_eq!(
                flow.agg.bytes,
                per_packet_l3 * count,
                "端口 {port} 的 L3 字节（不含以太头）"
            );
            assert_eq!(flow.key.src, IpAddr::V4(local_v4), "源地址");
            assert_eq!(flow.key.dst, IpAddr::V4(gateway), "目的地址");
            // 本版不读 5.14+ 的 wire_len：口径必须如实说 unavailable。
            assert!(flow.agg.wire_bytes.is_none(), "wire_bytes 应报 unavailable");
        }

        // ICMP echo：走 ping（root 下是 raw socket）。
        // **不要求 ping 成功**：很多 VPC 网关不回 ICMP，但出向 echo request 一定会经过
        // 我们的 hook —— 这正是要验的东西（回包有没有是网络策略的事，不是采集器的事）。
        let status = std::process::Command::new("ping")
            .args(["-c", "3", "-W", "1", "-q", &gateway.to_string()])
            .status()
            .expect("run ping");
        eprintln!("ping {gateway} exit={status}");
        std::thread::sleep(std::time::Duration::from_millis(300));

        let flows = collector.snapshot_all();
        let echo = flows
            .iter()
            .find(|flow| {
                flow.ifindex == iface.ifindex
                    && flow.key.protocol == 1
                    && flow.key.direction == Direction::Out
                    && flow.key.icmp_type == Some(8)
                    && flow.key.dst == IpAddr::V4(gateway)
            })
            .unwrap_or_else(|| {
                panic!(
                    "没数到 ICMP echo；已看到 {:?}",
                    flows
                        .iter()
                        .map(|flow| (
                            flow.key.protocol,
                            flow.key.direction,
                            flow.key.icmp_type,
                            flow.key.dst.to_string()
                        ))
                        .collect::<Vec<_>>()
                )
            });
        assert!(echo.agg.packets >= 1, "至少 1 个 echo request");
        assert!(echo.agg.bytes >= 3 * (20 + 8), "ICMP 至少含 IP + ICMP 头");
    }
}
