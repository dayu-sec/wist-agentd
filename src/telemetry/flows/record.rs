//! `FLOW:` 帧的一条记录：窗口边界、键归一与编码。
//!
//! 口径见设计文档 §6（字段）、§7（窗口与键）、§8（统计）。
//!
//! 三条硬约束：
//! 1. 窗口是**半开区间** `[start, end)`，按到达 hook 的时刻归窗；
//! 2. 只有窗口内**有字节**才产出记录 —— 空闲长连接每窗发一条零记录会爆量；
//! 3. 云侧身份与判决字段**一律不出现**（`instance-id`/`action`/`log-status`/…），
//!    富化与判决是平台的事。

use serde::Serialize;
use std::net::IpAddr;

/// 记录契约版本。改字段语义要升它（不要悄悄改）。
pub(crate) const RECORD_SCHEMA: &str = "wist.host_flow/v1";
/// 观测来源：主机侧 eBPF（下游据此与云侧记录**择一**使用，不相加）。
pub(crate) const SOURCE: &str = "host_ebpf";
/// 覆盖标记：主机视角，看不到到达网卡前就被云侧策略丢弃的流量。
pub(crate) const COVERAGE: &str = "host_partial";
/// 窗口时长（秒），UTC 整分对齐。
pub(crate) const WINDOW_SECONDS: u64 = 60;
/// flush 延迟（按窗口计）：只 flush **结束至少这么多窗**的桶，给迟到包留收敛时间。
pub(crate) const FLUSH_LAG_WINDOWS: u64 = 2;

pub(crate) const PROTO_ICMP: u8 = 1;
pub(crate) const PROTO_TCP: u8 = 6;
pub(crate) const PROTO_UDP: u8 = 17;
pub(crate) const PROTO_ICMPV6: u8 = 58;

/// 这个协议号会不会被采集。其余（GRE/ESP/…）在 BPF 侧就丢掉了，不在这里补。
pub(crate) const fn proto_is_collected(proto: u8) -> bool {
    matches!(proto, PROTO_TCP | PROTO_UDP | PROTO_ICMP | PROTO_ICMPV6)
}

/// ICMP / ICMPv6 没有端口，记录里固定填 `"0"`（与云侧口径对齐，Q2 实测后如需改只改这里）。
pub(crate) const fn proto_has_ports(proto: u8) -> bool {
    matches!(proto, PROTO_TCP | PROTO_UDP)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub(crate) enum Direction {
    /// 进入被观测网卡。
    In,
    /// 离开被观测网卡。
    Out,
}

impl Direction {
    /// 与云侧词表一致（不是 `ingress`/`egress`）。
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::In => "in",
            Self::Out => "out",
        }
    }

    /// hook 标识：记录里保留它，排障时能一眼看出观测点。
    pub(crate) const fn capture(self) -> &'static str {
        match self {
            Self::In => "tc_ingress",
            Self::Out => "tc_egress",
        }
    }
}

/// 窗口开始时刻：UTC 整分对齐。
pub(crate) const fn window_start(now_secs: u64) -> u64 {
    now_secs - now_secs % WINDOW_SECONDS
}

/// 这个窗口现在能不能 flush。
///
/// 只 flush「结束已经过去 `FLUSH_LAG_WINDOWS` 个窗口」的桶：迟到的包通常在同一秒内到达，
/// 留一轮足够收敛；仍落进已 flush 窗口的包由采集层计入 `dropped`（不补发，避免同一幂等键
/// 出现两条记录）。
pub(crate) const fn is_flushable(window: u64, now_secs: u64) -> bool {
    window + WINDOW_SECONDS * FLUSH_LAG_WINDOWS <= now_secs
}

/// 一条记录的观测上下文（同一窗口内所有记录共享）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WindowCtx {
    pub collector_instance_id: String,
    pub host_id: String,
    pub host_name: Option<String>,
    pub kernel: String,
    pub ifname: String,
    pub ifindex: u32,
    pub if_mac: Option<String>,
    /// 窗口开始时该网卡的地址快照（已排序，v4 在前）。
    pub local_addrs: Vec<IpAddr>,
}

/// 窗口内一个键的累计量。BPF 侧只累加，不做判定。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub(crate) struct WindowAgg {
    /// Σ `gso_segs`：估算的 L3 报文数（GSO 超级包按段数还原）。
    pub packets: u64,
    /// Σ `skb->len`：L3 字节，**不含 L2**。
    pub bytes: u64,
    /// Σ `wire_len`：只有 5.14+ 才有；取不到就是 `None`（不估算，不伪造精度）。
    pub wire_bytes: Option<u64>,
    /// 实际观察到的 skb 数（GSO/GRO 诊断用）。
    pub skb_count: u64,
    /// 其中 `gso_segs > 1` 的 skb 数。
    pub gso_skb_count: u64,
    /// 本窗口内因聚合表满被淘汰 / 读取竞态未能计入的事件数。
    pub dropped: u32,
    /// 本窗口是否发生过聚合表上限淘汰。
    pub truncated: bool,
}

impl WindowAgg {
    /// 把一条 BPF map 条目并进窗口累计。
    ///
    /// `wire_bytes` 只要有一条取不到就整体退化成 `None` —— 部分窗口有、部分窗口没有的
    /// 「线缆字节」比没有更误导。
    pub(crate) fn merge(&mut self, other: &WindowAgg) {
        self.packets = self.packets.saturating_add(other.packets);
        self.bytes = self.bytes.saturating_add(other.bytes);
        self.wire_bytes = match (self.wire_bytes, other.wire_bytes) {
            (Some(a), Some(b)) => Some(a.saturating_add(b)),
            _ => None,
        };
        self.skb_count = self.skb_count.saturating_add(other.skb_count);
        self.gso_skb_count = self.gso_skb_count.saturating_add(other.gso_skb_count);
        self.dropped = self.dropped.saturating_add(other.dropped);
        self.truncated |= other.truncated;
    }

    /// 没有字节的桶不产出记录（只可能是探测期残留或全被过滤）。
    pub(crate) const fn is_empty(&self) -> bool {
        self.bytes == 0 && self.packets == 0
    }
}

/// 窗口被截断的原因（`partial=true` 时必须有一句可归因的话）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum PartialReason {
    AgentStart,
    Paused,
    InterfaceChanged,
    Shutdown,
}

impl PartialReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::AgentStart => "agent_start",
            Self::Paused => "paused",
            Self::InterfaceChanged => "interface_changed",
            Self::Shutdown => "shutdown",
        }
    }
}

/// 一条 `FLOW:` 记录。
///
/// 字段与设计文档 §6 一一对应；不出现的键（`null`）一律靠 `skip_serializing_if` 省掉，
/// 避免下游把「没这个字段」读成「值为 null」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub(crate) struct HostFlowRecord {
    pub record_schema: &'static str,
    pub source: &'static str,
    pub coverage: &'static str,
    pub capture: &'static str,
    pub collector_instance_id: String,
    pub host_id: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_name: Option<String>,
    pub kernel: String,
    pub ifname: String,
    pub ifindex: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub if_mac: Option<String>,
    pub local_addrs: Vec<String>,
    pub direction: &'static str,
    pub protocol: String,
    pub srcaddr: String,
    pub dstaddr: String,
    pub srcport: String,
    pub dstport: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_type: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub icmp_code: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_unavailable: Option<bool>,
    pub start: u64,
    pub end: u64,
    pub window_seconds: u32,
    pub packets: u64,
    pub bytes: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub wire_bytes: Option<u64>,
    pub wire_bytes_source: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub skb_count: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gso_skb_count: Option<u64>,
    pub truncated: bool,
    pub dropped: u32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub partial_reason: Option<&'static str>,
}

/// 一个聚合键（BPF map key 的 Rust 侧镜像，**不含** `window_id`）。
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub(crate) struct FlowKey {
    pub direction: Direction,
    pub protocol: u8,
    pub src: IpAddr,
    pub dst: IpAddr,
    pub src_port: u16,
    pub dst_port: u16,
    pub icmp_type: Option<u8>,
    pub icmp_code: Option<u8>,
    pub port_unavailable: bool,
}

impl HostFlowRecord {
    /// 由键 + 累计量 + 上下文构造一条记录。
    ///
    /// `window` 是窗口起点；`partial` 只在窗口被提前截断时给。
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn from_window(
        ctx: &WindowCtx,
        key: &FlowKey,
        window: u64,
        window_seconds: u32,
        agg: &WindowAgg,
        partial: Option<PartialReason>,
    ) -> Self {
        let (srcport, dstport) = if proto_has_ports(key.protocol) && !key.port_unavailable {
            (key.src_port.to_string(), key.dst_port.to_string())
        } else {
            ("0".to_string(), "0".to_string())
        };
        let (icmp_type, icmp_code) = match (key.icmp_type, key.icmp_code) {
            (Some(kind), Some(code)) => (Some(kind.to_string()), Some(code.to_string())),
            _ => (None, None),
        };
        Self {
            record_schema: RECORD_SCHEMA,
            source: SOURCE,
            coverage: COVERAGE,
            capture: key.direction.capture(),
            collector_instance_id: ctx.collector_instance_id.clone(),
            host_id: ctx.host_id.clone(),
            host_name: ctx.host_name.clone(),
            kernel: ctx.kernel.clone(),
            ifname: ctx.ifname.clone(),
            ifindex: ctx.ifindex,
            if_mac: ctx.if_mac.clone(),
            local_addrs: ctx.local_addrs.iter().map(ToString::to_string).collect(),
            direction: key.direction.as_str(),
            protocol: key.protocol.to_string(),
            srcaddr: key.src.to_string(),
            dstaddr: key.dst.to_string(),
            srcport,
            dstport,
            icmp_type,
            icmp_code,
            port_unavailable: key.port_unavailable.then_some(true),
            start: window,
            end: window + u64::from(window_seconds),
            window_seconds,
            packets: agg.packets,
            bytes: agg.bytes,
            wire_bytes: agg.wire_bytes,
            wire_bytes_source: if agg.wire_bytes.is_some() {
                "wire_len"
            } else {
                "unavailable"
            },
            skb_count: Some(agg.skb_count),
            gso_skb_count: Some(agg.gso_skb_count),
            truncated: agg.truncated,
            dropped: agg.dropped,
            partial: partial.map(|_| true),
            partial_reason: partial.map(PartialReason::as_str),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ctx() -> WindowCtx {
        WindowCtx {
            collector_instance_id: "agent-host-1".to_string(),
            host_id: "host-1".to_string(),
            host_name: Some("vm-web-01".to_string()),
            kernel: "5.15.0-91-generic".to_string(),
            ifname: "eth0".to_string(),
            ifindex: 2,
            if_mac: Some("52:54:00:aa:bb:cc".to_string()),
            local_addrs: vec![
                "10.118.0.14".parse().expect("v4"),
                "fd00::14".parse().expect("v6"),
            ],
        }
    }

    fn tcp_key() -> FlowKey {
        FlowKey {
            direction: Direction::Out,
            protocol: PROTO_TCP,
            src: "10.118.0.14".parse().expect("v4"),
            dst: "88.214.25.121".parse().expect("v4"),
            src_port: 50123,
            dst_port: 443,
            icmp_type: None,
            icmp_code: None,
            port_unavailable: false,
        }
    }

    fn agg() -> WindowAgg {
        WindowAgg {
            packets: 13,
            bytes: 1460,
            wire_bytes: None,
            skb_count: 4,
            gso_skb_count: 1,
            dropped: 0,
            truncated: false,
        }
    }

    #[test]
    fn windows_are_utc_minute_aligned_and_half_open() {
        assert_eq!(window_start(0), 0);
        assert_eq!(window_start(59), 0);
        assert_eq!(window_start(60), 60);
        assert_eq!(window_start(1789469802), 1789469760);
        // 窗口结束正好等于 start + 60：下一条记录从这里开始（半开区间）。
        assert_eq!(window_start(1789469820), 1789469820);
    }

    #[test]
    fn only_settled_windows_are_flushed() {
        let now = 1_789_469_820; // 正好是一个窗口起点
        // 上一窗（1789469760）刚结束：还要等一轮，先不 flush。
        assert!(!is_flushable(1_789_469_760, now));
        // 再往前一窗已经过了一个完整窗口的宽限。
        assert!(is_flushable(1_789_469_700, now));
    }

    #[test]
    fn tcp_record_carries_no_icmp_and_no_wire_bytes_when_unavailable() {
        let record =
            HostFlowRecord::from_window(&ctx(), &tcp_key(), 1_789_469_760, 60, &agg(), None);
        let text = serde_json::to_string(&record).expect("serialize");
        assert!(text.contains("\"protocol\":\"6\""));
        assert!(text.contains("\"direction\":\"out\""));
        assert!(text.contains("\"capture\":\"tc_egress\""));
        assert!(text.contains("\"srcport\":\"50123\""));
        assert!(
            !text.contains("icmp_type"),
            "TCP 不该出现 icmp 字段: {text}"
        );
        assert!(!text.contains("wire_bytes\""), "取不到就不出现: {text}");
        assert!(text.contains("\"wire_bytes_source\":\"unavailable\""));
        assert!(
            !text.contains("\"partial\""),
            "正常窗口不带 partial: {text}"
        );
    }

    #[test]
    fn icmp_record_zeroes_ports_and_keeps_type_code() {
        let key = FlowKey {
            direction: Direction::In,
            protocol: PROTO_ICMP,
            src: "88.214.25.121".parse().expect("v4"),
            dst: "10.118.0.14".parse().expect("v4"),
            src_port: 0,
            dst_port: 0,
            icmp_type: Some(8),
            icmp_code: Some(0),
            port_unavailable: false,
        };
        let record = HostFlowRecord::from_window(&ctx(), &key, 1_789_469_760, 60, &agg(), None);
        assert_eq!(record.srcport, "0");
        assert_eq!(record.dstport, "0");
        assert_eq!(record.icmp_type.as_deref(), Some("8"));
        assert_eq!(record.icmp_code.as_deref(), Some("0"));
        assert_eq!(record.direction, "in");
        assert_eq!(record.capture, "tc_ingress");
    }

    #[test]
    fn fragmented_packets_mark_ports_unavailable() {
        let mut key = tcp_key();
        key.port_unavailable = true;
        let record = HostFlowRecord::from_window(&ctx(), &key, 1_789_469_760, 60, &agg(), None);
        assert_eq!(record.srcport, "0");
        assert_eq!(record.dstport, "0");
        assert_eq!(record.port_unavailable, Some(true));
    }

    #[test]
    fn partial_windows_say_why() {
        let record = HostFlowRecord::from_window(
            &ctx(),
            &tcp_key(),
            1_789_469_760,
            30,
            &agg(),
            Some(PartialReason::Paused),
        );
        assert_eq!(record.partial, Some(true));
        assert_eq!(record.partial_reason, Some("paused"));
        assert_eq!(record.end, 1_789_469_790, "短窗按实际秒数结束");
        assert_eq!(record.window_seconds, 30);
    }

    /// 云侧字段一个都不许出现：它们由平台富化（`action` 更不能塞 `observed` 进枚举）。
    #[test]
    fn cloud_side_fields_never_appear() {
        let record =
            HostFlowRecord::from_window(&ctx(), &tcp_key(), 1_789_469_760, 60, &agg(), None);
        let text = serde_json::to_string(&record).expect("serialize");
        for forbidden in [
            "\"action\"",
            "\"instance-id\"",
            "\"vpc-id\"",
            "\"subnet-id\"",
            "\"interface-id\"",
            "\"account-id\"",
            "\"log-status\"",
            "\"needs_enrichment\"",
            "\"version\"",
            "\"cross-region\"",
        ] {
            assert!(
                !text.contains(forbidden),
                "记录里不该出现 {forbidden}：{text}"
            );
        }
    }

    #[test]
    fn merging_keeps_wire_bytes_all_or_nothing() {
        let mut left = agg();
        left.wire_bytes = Some(1500);
        let mut right = agg();
        right.wire_bytes = Some(900);
        left.merge(&right);
        assert_eq!(left.wire_bytes, Some(2400));
        assert_eq!(left.packets, 26);
        assert_eq!(left.bytes, 2920);

        // 一边取不到 → 整体退化为 None（部分窗口有线缆字节比没有更误导）。
        let mut mixed = agg();
        mixed.wire_bytes = Some(100);
        mixed.merge(&agg());
        assert_eq!(mixed.wire_bytes, None);
    }

    #[test]
    fn empty_windows_do_not_produce_records() {
        assert!(WindowAgg::default().is_empty());
        assert!(!agg().is_empty());
    }

    #[test]
    fn only_tcp_udp_icmp_are_collected() {
        for proto in [PROTO_TCP, PROTO_UDP, PROTO_ICMP, PROTO_ICMPV6] {
            assert!(proto_is_collected(proto), "{proto}");
        }
        for proto in [0, 2, 47, 50] {
            assert!(!proto_is_collected(proto), "{proto}");
        }
        assert!(proto_has_ports(PROTO_TCP));
        assert!(proto_has_ports(PROTO_UDP));
        assert!(!proto_has_ports(PROTO_ICMP));
        assert!(!proto_has_ports(PROTO_ICMPV6));
    }
}
