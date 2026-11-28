//! `FLOW:` 帧的一条记录：窗口边界、键归一与编码。
//!
//! 口径见设计文档 §6（字段）、§7（窗口与键）、§8（统计）。
//!
//! 三条硬约束：
//! 1. 窗口是**半开区间** `[start, end)`，按到达 hook 的时刻归窗；
//! 2. 只有窗口内**有字节**才产出记录 —— 空闲长连接每窗发一条零记录会爆量；
//! 3. 云侧身份与判决字段**一律不出现**（`instance-id`/`action`/`log-status`/…），
//!    富化与判决是平台的事。
//!
//! 形状本身**只在契约里定义一份**（`wist-contracts::host_flow`）：数据面与平台按同一份
//! 解析，agentd 这边只负责把它填出来。本地不另存结构体 —— 两份定义迟早会漂。

use std::net::IpAddr;

pub(crate) use wist_contracts::host_flow::HostFlowRecord;
use wist_contracts::host_flow::{
    CAPTURE_TC_EGRESS, CAPTURE_TC_INGRESS, COVERAGE_HOST_PARTIAL, DIRECTION_IN, DIRECTION_OUT,
    RECORD_SCHEMA_V1, SOURCE_HOST_EBPF, WINDOW_SECONDS_DEFAULT, WIRE_BYTES_SOURCE_UNAVAILABLE,
    WIRE_BYTES_SOURCE_WIRE_LEN,
};

/// 窗口时长（秒），UTC 整分对齐（与契约的默认窗口同一个数，不各写一份）。
pub(crate) const WINDOW_SECONDS: u64 = WINDOW_SECONDS_DEFAULT as u64;
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
            Self::In => DIRECTION_IN,
            Self::Out => DIRECTION_OUT,
        }
    }

    /// hook 标识：记录里保留它，排障时能一眼看出观测点。
    pub(crate) const fn capture(self) -> &'static str {
        match self {
            Self::In => CAPTURE_TC_INGRESS,
            Self::Out => CAPTURE_TC_EGRESS,
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

/// 这个窗口是否**已经 flush 过**：之后再落进这个窗口的包就是迟到。
///
/// 迟到包不能补发 —— 同一 `(五元组, 窗口)` 的幂等键只允许出现一条记录，
/// 补发会让下游把同一段流量算两次。采集层把它们计入 `late_dropped`（可见，但不重复）。
pub(crate) const fn is_late(window: u64, flushed_through: u64) -> bool {
    window <= flushed_through
}

/// 一拍最多取多少个窗口去上送。
///
/// 为什么要上限：一个繁忙主机单窗口可能有几万个五元组，一个 tick 里顺序 `await` 几万次写
/// 会把主循环（日志采集 / 心跳 / 命令认领）拖住。超出的桶**留在 BPF 表里**，下一拍照着取 ——
/// 不是丢数据，只是分拍。
pub(crate) const MAX_FLOWS_PER_FLUSH: usize = 4096;

/// 一次 flush 的取桶计划（纯逻辑，跨平台可测）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct TakePlan {
    /// 这一拍取走前多少个（候选已按窗口**升序**排好）。
    pub(crate) taken: usize,
    /// `flushed_through` 该推进到哪个窗口（含）。
    pub(crate) advance_to: u64,
    /// 还有没取走的（这一拍到了批量上限）。
    pub(crate) deferred: bool,
}

/// 决定这一拍取哪些窗口、`flushed_through` 推到哪。
///
/// 两条必须成立的性质：
/// 1. **最老的先走**：批量上限下不能让老窗口一直饿着（LRU 淘汰也会先吃它们）；
/// 2. `flushed_through` **只能推进到真正取走的那一窗**（推迟的桶不能被判成迟到）。
///    只有「horizon 以内的都取完了」才可以推进到 `horizon` —— 那之后再有包落进那些
///    空窗口就是真的迟到，计丢即可。
pub(crate) fn plan_take(windows_ascending: &[u64], horizon: u64, max: usize) -> TakePlan {
    if windows_ascending.is_empty() {
        return TakePlan {
            taken: 0,
            advance_to: horizon,
            deferred: false,
        };
    }
    if max == 0 || windows_ascending.len() <= max {
        return TakePlan {
            taken: windows_ascending.len(),
            advance_to: horizon,
            deferred: false,
        };
    }
    TakePlan {
        taken: max,
        // 取走的最后一个窗口：它才是“已经交出去”的水位。
        advance_to: windows_ascending[max - 1],
        deferred: true,
    }
}

/// 把 BPF 的**单调桶**换算成 UTC 对齐的窗口起点。
///
/// BPF 侧只拿得到 `bpf_ktime_get_ns()`（单调时钟），它分出的桶边界不对齐墙钟。
/// 桶与桶之间永远是 60s，所以「落后几个桶」等价于「往前几个 UTC 整分窗口」。
pub(crate) fn window_from_bucket(now_wall: u64, now_bucket: u64, bucket: u64) -> u64 {
    let behind = now_bucket.saturating_sub(bucket);
    window_start(now_wall.saturating_sub(behind.saturating_mul(WINDOW_SECONDS)))
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
    /// 进程正常退出（SIGTERM/SIGINT）时用：停机收尾会把在途窗口切开发出去。
    ///
    /// 仍然是“窗口不完整”，但原因不同 —— 现场看到 `shutdown` 就知道这次少的那一段
    /// 是**预期内**的停机边界，不是丢数据。
    Shutdown,
    /// 墙钟跳变（NTP 回拨/手动改时间）。
    ///
    /// 窗口归属靠「单调桶差 + 当前墙钟」换算（见 [`window_from_bucket`]）；墙钟一变，
    /// 映射就断了。处理方式：按**旧锚点外推**的时间把这些桶归窗（它们确实是那一刻采的，
    /// 按新墙钟重算会撞幂等键），并标成本原因；下一窗重新锚定。
    ClockChanged,
}

impl PartialReason {
    pub(crate) const fn as_str(self) -> &'static str {
        use wist_contracts::host_flow::{
            PARTIAL_REASON_AGENT_START, PARTIAL_REASON_CLOCK_CHANGED,
            PARTIAL_REASON_INTERFACE_CHANGED, PARTIAL_REASON_PAUSED, PARTIAL_REASON_SHUTDOWN,
        };
        match self {
            Self::AgentStart => PARTIAL_REASON_AGENT_START,
            Self::Paused => PARTIAL_REASON_PAUSED,
            Self::InterfaceChanged => PARTIAL_REASON_INTERFACE_CHANGED,
            Self::Shutdown => PARTIAL_REASON_SHUTDOWN,
            Self::ClockChanged => PARTIAL_REASON_CLOCK_CHANGED,
        }
    }
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

/// 由键 + 累计量 + 上下文构造一条记录（**唯一构造点**）。
///
/// `window` 是窗口起点；`partial` 只在窗口被提前截断时给。
///
/// 为什么是自由函数而不是 `impl HostFlowRecord`：类型定义在 `wist-contracts`，
/// 跨 crate 不能写 inherent impl（E0116）。
#[allow(clippy::too_many_arguments)]
pub(crate) fn record_from_window(
    ctx: &WindowCtx,
    key: &FlowKey,
    window: u64,
    window_seconds: u32,
    agg: &WindowAgg,
    partial: Option<PartialReason>,
) -> HostFlowRecord {
    let (srcport, dstport) = if proto_has_ports(key.protocol) && !key.port_unavailable {
        (key.src_port.to_string(), key.dst_port.to_string())
    } else {
        ("0".to_string(), "0".to_string())
    };
    let (icmp_type, icmp_code) = match (key.icmp_type, key.icmp_code) {
        (Some(kind), Some(code)) => (Some(kind.to_string()), Some(code.to_string())),
        _ => (None, None),
    };
    HostFlowRecord {
        record_schema: RECORD_SCHEMA_V1.to_string(),
        source: SOURCE_HOST_EBPF.to_string(),
        coverage: COVERAGE_HOST_PARTIAL.to_string(),
        capture: key.direction.capture().to_string(),
        collector_instance_id: ctx.collector_instance_id.clone(),
        host_id: ctx.host_id.clone(),
        host_name: ctx.host_name.clone(),
        kernel: ctx.kernel.clone(),
        ifname: ctx.ifname.clone(),
        ifindex: ctx.ifindex,
        if_mac: ctx.if_mac.clone(),
        local_addrs: ctx.local_addrs.iter().map(ToString::to_string).collect(),
        direction: key.direction.as_str().to_string(),
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
            WIRE_BYTES_SOURCE_WIRE_LEN
        } else {
            WIRE_BYTES_SOURCE_UNAVAILABLE
        }
        .to_string(),
        skb_count: Some(agg.skb_count),
        gso_skb_count: Some(agg.gso_skb_count),
        truncated: agg.truncated,
        dropped: agg.dropped,
        partial: partial.map(|_| true),
        partial_reason: partial.map(|reason| reason.as_str().to_string()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::telemetry_record::DataFrame;

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
    fn late_windows_are_recognised_after_flush() {
        // 已经 flush 到 100：100 及更早都算迟到（100 本身上一轮已发过）。
        assert!(is_late(100, 100));
        assert!(is_late(99, 100));
        assert!(!is_late(101, 100));
        // 还没 flush 过任何桶时，桶 0 也算迟到（它是远古数据，绝不能补发）。
        assert!(is_late(0, 0));
    }

    #[test]
    fn bucket_maps_back_to_utc_aligned_windows() {
        let now_wall = 1_789_469_820; // 正好落在 UTC 整分
        let now_bucket = 100;
        assert_eq!(window_from_bucket(now_wall, now_bucket, 100), 1_789_469_820);
        assert_eq!(
            window_from_bucket(now_wall, now_bucket, 98),
            window_start(now_wall) - 120
        );
        // 桶差比实际时间差距大（重启/时钟异常）时不能下溢。
        assert_eq!(window_from_bucket(10, 100, 0), 0);
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
    fn take_plan_keeps_old_windows_first_and_never_skips_advanced_windows() {
        // 没到上限：全取，水位推到 horizon（空老窗口里的迟到包才算真迟到）。
        assert_eq!(
            plan_take(&[10, 20], 30, MAX_FLOWS_PER_FLUSH),
            TakePlan {
                taken: 2,
                advance_to: 30,
                deferred: false
            }
        );
        // 没有候选：仍然要推进到 horizon（否则迟到包会被永久保留在表里）。
        assert_eq!(
            plan_take(&[], 30, MAX_FLOWS_PER_FLUSH),
            TakePlan {
                taken: 0,
                advance_to: 30,
                deferred: false
            }
        );

        // 到上限：只取最老的 N 个，水位只能推到**真取走**的那一窗。
        let plan = plan_take(&[10, 20, 30], 40, 2);
        assert_eq!(plan.taken, 2);
        assert!(plan.deferred);
        assert_eq!(
            plan.advance_to, 20,
            "推迟的 30 不能被推进到水位里，否则下一拍会被当成迟到直接丢掉"
        );

        // `max = 0` = 不限量（停采时的 drain 用），不能退化成“一条都不取”。
        assert_eq!(
            plan_take(&[10, 20], 30, 0),
            TakePlan {
                taken: 2,
                advance_to: 30,
                deferred: false
            }
        );
    }

    #[test]
    fn tcp_record_carries_no_icmp_and_no_wire_bytes_when_unavailable() {
        let record = record_from_window(&ctx(), &tcp_key(), 1_789_469_760, 60, &agg(), None);
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
        let record = record_from_window(&ctx(), &key, 1_789_469_760, 60, &agg(), None);
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
        let record = record_from_window(&ctx(), &key, 1_789_469_760, 60, &agg(), None);
        assert_eq!(record.srcport, "0");
        assert_eq!(record.dstport, "0");
        assert_eq!(record.port_unavailable, Some(true));
    }

    #[test]
    fn partial_windows_say_why() {
        let record = record_from_window(
            &ctx(),
            &tcp_key(),
            1_789_469_760,
            30,
            &agg(),
            Some(PartialReason::Paused),
        );
        assert_eq!(record.partial, Some(true));
        assert_eq!(record.partial_reason.as_deref(), Some("paused"));
        assert_eq!(record.end, 1_789_469_790, "短窗按实际秒数结束");
        assert_eq!(record.window_seconds, 30);
    }

    /// 云侧字段一个都不许出现：它们由平台富化（`action` 更不能塞 `observed` 进枚举）。
    #[test]
    fn cloud_side_fields_never_appear() {
        let record = record_from_window(&ctx(), &tcp_key(), 1_789_469_760, 60, &agg(), None);
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

    /// 规格文档里的示例必须**现在就能解析**。
    ///
    /// 写作动机：文档一旦写成“看起来对但字段名/类型已漂移”，下游照文档实现就会在
    /// 联调时才发现。这里直接吃文档：`include_str!` 把两者绑在一起 —— 改文档就会
    /// 重跑这个测试（改字段而不改文档，也会在契约那侧的 key 集合测试里先红）。
    ///
    /// 同时钉住示例里的**长度前缀**：文档写 `718 {...}` 就必须真的是 718 字节。
    #[test]
    fn the_spec_document_examples_match_the_contract() {
        const SPEC: &str = include_str!("../../../docs/design/host-flow-data-spec.md");

        // 按 info string **精确**取代码块（`json` / `jsonl` / `text` 是三种不同的块）。
        fn blocks(doc: &str, wanted: &str) -> Vec<String> {
            let mut out = Vec::new();
            let mut cur: Option<(String, Vec<&str>)> = None;
            for line in doc.lines() {
                let trimmed = line.trim_start();
                if trimmed.starts_with("```") {
                    match cur.take() {
                        None => {
                            let lang = trimmed.trim_start_matches('`').trim().to_string();
                            cur = Some((lang, Vec::new()));
                        }
                        Some((lang, lines)) => {
                            if lang == wanted {
                                out.push(lines.join("\n"));
                            }
                        }
                    }
                    continue;
                }
                if let Some((_, lines)) = cur.as_mut() {
                    lines.push(line);
                }
            }
            out
        }

        // 1) 完整帧示例（```text 块）：`<len> <信封> FLOW: <正文>`。
        let mut frames = 0usize;
        for block in blocks(SPEC, "text") {
            for line in block.lines() {
                let Some((len_part, frame)) = line.split_once(' ') else {
                    continue;
                };
                let Ok(len) = len_part.parse::<usize>() else {
                    continue;
                };
                let (envelope, body) = frame.split_once(" FLOW: ").expect("FLOW marker");
                assert_eq!(len, frame.len(), "文档写的长度前缀与真实帧字节数不一致");
                let envelope: DataFrame = serde_json::from_str(envelope).expect("envelope");
                let record: HostFlowRecord = serde_json::from_str(body).expect("body");
                assert_eq!(envelope.schema_version, "v1");
                assert_eq!(envelope.agent_id, record.collector_instance_id);
                assert_eq!(record.record_schema, RECORD_SCHEMA_V1);
                frames += 1;
            }
        }
        assert_eq!(frames, 1, "规格里应当恰有一个完整帧示例");

        // 2) 正文示例（```json 块）：必须过 `deny_unknown_fields` 的强类型解析。
        let bodies = blocks(SPEC, "json");
        for text in &bodies {
            let record: HostFlowRecord =
                serde_json::from_str(text.trim()).expect("doc example body");
            assert_eq!(record.record_schema, RECORD_SCHEMA_V1);
            assert_eq!(
                record.end - record.start,
                u64::from(record.window_seconds),
                "示例里的窗口长度必须自洽"
            );
        }
        assert!(
            bodies.len() >= 2,
            "规格至少要有 ICMP 与 partial 两个正文示例"
        );
    }
}
