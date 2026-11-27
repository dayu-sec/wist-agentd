//! 观测哪张网卡：**本机事实**决定，平台不指定接口名。
//!
//! 规则（设计 §7.2）：默认路由出口 ∩ 持有可在网络上路由的地址 ∩ 不是 loopback/容器虚拟口。
//! 首版不观测 vlan 子接口（记在父接口上），bond 记 bond 本身。
//!
//! 这里的函数是**纯判定**，不碰 sysfs/netlink —— 采集层把它看到的接口快照交进来，
//! 这样选择规则可以在 macOS 上被测试覆盖。

use std::collections::BTreeSet;
use std::net::IpAddr;

/// 采集层对一张网卡的观测快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct IfaceSnapshot {
    pub name: String,
    pub ifindex: u32,
    pub mac: Option<String>,
    pub addrs: Vec<IpAddr>,
    /// 默认路由的出口接口（由采集层查路由表得出）。
    pub is_default_egress: bool,
}

/// 容器/本机虚拟接口的名字特征：这些接口的计数与「对外通信」不是一回事。
pub(crate) fn looks_virtual(name: &str) -> bool {
    if name == "lo" {
        return true;
    }
    const PREFIXES: [&str; 10] = [
        "veth", "docker", "br-", "cni", "flannel", "cali", "virbr", "lxc", "podman", "kube",
    ];
    PREFIXES.iter().any(|prefix| name.starts_with(prefix))
}

/// vlan 子接口：`eth0.100` 这种。首版记在父接口上，不单独观测。
pub(crate) fn looks_vlan(name: &str) -> bool {
    match name.rsplit_once('.') {
        Some((parent, vlan)) => {
            !parent.is_empty() && !vlan.is_empty() && vlan.bytes().all(|b| b.is_ascii_digit())
        }
        None => false,
    }
}

/// 这个地址值不值得为「对外通信」而采集。
///
/// 排除：loopback、链路本地、组播、广播、未指定地址。保留：全局单播与 ULA（`fc00::/7`）。
pub(crate) fn is_flow_addr(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            let [a, b, ..] = v4.octets();
            !v4.is_loopback()
                && !v4.is_multicast()
                && !v4.is_broadcast()
                && !v4.is_unspecified()
                && !(a == 169 && b == 254)
        }
        IpAddr::V6(v6) => {
            let segments = v6.segments();
            let is_unspecified = segments == [0, 0, 0, 0, 0, 0, 0, 0];
            let is_loopback = segments == [0, 0, 0, 0, 0, 0, 0, 1];
            let is_multicast = segments[0] & 0xff00 == 0xff00;
            let is_link_local = segments[0] & 0xffc0 == 0xfe80;
            let is_ula = segments[0] & 0xfe00 == 0xfc00;
            let is_global = segments[0] & 0xe000 == 0x2000; // 2000::/3
            !is_unspecified
                && !is_loopback
                && !is_multicast
                && !is_link_local
                && (is_ula || is_global)
        }
    }
}

/// 从默认路由表文本里抽出出口网卡名（v4，`/proc/net/route`）。
///
/// 列：`Iface Destination Gateway Flags RefCnt Use Metric Mask …`；默认路由 = `Destination`
/// 全 0 且带 `RTF_UP`。**全部**取出来（多默认路由/ECMP 时要全观测，见设计 §7.2），
/// 不取第一条。
pub(crate) fn parse_default_routes_v4(text: &str) -> BTreeSet<String> {
    let mut ifaces = BTreeSet::new();
    for line in text.lines().skip(1) {
        let mut fields = line.split_whitespace();
        let (Some(iface), Some(dest), Some(_gateway), Some(flags)) =
            (fields.next(), fields.next(), fields.next(), fields.next())
        else {
            continue;
        };
        if dest != "00000000" {
            continue;
        }
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        if flags & 0x1 != 0 {
            ifaces.insert(iface.to_string());
        }
    }
    ifaces
}

/// 从默认路由表文本里抽出出口网卡名（v6，`/proc/net/ipv6_route`）。
///
/// 列：`dest(32hex) prefix_len(2hex) src(32hex) src_prefix_len(2hex) nexthop(32hex)
/// metric(8hex) refcnt use flags(8hex) ifname`。默认路由 = `dest` 全 0 且 `prefix_len == 00`，
/// 并要求 `RTF_UP`。
///
/// 为什么要读它：**纯 IPv6 主机**的 `/proc/net/route` 是空的 —— 只读 v4 会把那类机器
/// 永远卡在 `source_not_ready`（授权了、没数据）。
pub(crate) fn parse_default_routes_v6(text: &str) -> BTreeSet<String> {
    let mut ifaces = BTreeSet::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let (Some(dest), Some(prefix_len), Some(flags), Some(iface)) =
            (fields.first(), fields.get(1), fields.get(8), fields.get(9))
        else {
            continue;
        };
        if !dest.chars().all(|ch| ch == '0') || *prefix_len != "00" {
            continue;
        }
        let flags = u32::from_str_radix(flags, 16).unwrap_or(0);
        if flags & 0x1 != 0 {
            ifaces.insert(iface.to_string());
        }
    }
    ifaces
}

/// 从快照里选出要观测的网卡（按 `ifindex` 升序，保证输出稳定）。
///
/// 默认出口正常只有一张；如果出现多张（多默认路由/ECMP），全部观测 —— 每条记录带
/// `ifname`/`ifindex`，不做跨接口合并。
pub(crate) fn select_observed(snapshot: &[IfaceSnapshot]) -> Vec<&IfaceSnapshot> {
    let mut chosen: Vec<&IfaceSnapshot> = snapshot
        .iter()
        .filter(|iface| {
            iface.is_default_egress
                && !looks_virtual(&iface.name)
                && !looks_vlan(&iface.name)
                && iface.addrs.iter().copied().any(is_flow_addr)
        })
        .collect();
    chosen.sort_by_key(|iface| iface.ifindex);
    chosen
}

#[cfg(test)]
mod tests {
    use super::*;

    fn iface(name: &str, ifindex: u32, addrs: &[&str], default_egress: bool) -> IfaceSnapshot {
        IfaceSnapshot {
            name: name.to_string(),
            ifindex,
            mac: Some(format!("52:54:00:00:00:{ifindex:02x}")),
            addrs: addrs.iter().map(|a| a.parse().expect("addr")).collect(),
            is_default_egress: default_egress,
        }
    }

    #[test]
    fn virtual_and_vlan_names_are_recognised() {
        for name in [
            "lo",
            "veth123",
            "docker0",
            "br-9a",
            "cni0",
            "cali1",
            "flannel.1",
        ] {
            assert!(looks_virtual(name), "{name}");
        }
        for name in ["eth0", "ens5", "bond0", "eno1"] {
            assert!(!looks_virtual(name), "{name}");
        }
        assert!(looks_vlan("eth0.100"));
        assert!(!looks_vlan("eth0"));
        assert!(!looks_vlan("eth0.bak"));
    }

    #[test]
    fn only_routable_addresses_count() {
        for ok in ["10.118.0.14", "172.16.0.1", "fd00::14", "2001:db8::1"] {
            assert!(is_flow_addr(ok.parse().expect("addr")), "{ok}");
        }
        for bad in [
            "127.0.0.1",
            "169.254.1.1",
            "224.0.0.1",
            "255.255.255.255",
            "0.0.0.0",
            "::1",
            "fe80::1",
            "ff02::1",
            "::",
        ] {
            assert!(!is_flow_addr(bad.parse().expect("addr")), "{bad}");
        }
    }

    #[test]
    fn picks_the_default_egress_with_a_routable_address() {
        let snapshot = vec![
            iface("lo", 1, &["127.0.0.1", "::1"], false),
            iface("eth0", 2, &["10.118.0.14", "fe80::14"], true),
            iface("eth1", 3, &["192.168.9.9"], false),
        ];
        let chosen = select_observed(&snapshot);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].name, "eth0");
    }

    #[test]
    fn excludes_container_interfaces_even_on_the_default_route() {
        let snapshot = vec![
            iface("docker0", 5, &["172.17.0.1"], true),
            iface("eth0", 2, &["10.0.0.5"], true),
        ];
        let chosen = select_observed(&snapshot);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].name, "eth0");
    }

    #[test]
    fn a_nic_with_only_link_local_v6_is_not_observed() {
        let snapshot = vec![iface("eth0", 2, &["fe80::1"], true)];
        assert!(select_observed(&snapshot).is_empty(), "只有 fe80 不采");
    }

    #[test]
    fn bond_is_observed_and_vlan_is_left_to_its_parent() {
        let snapshot = vec![
            iface("bond0", 4, &["10.0.0.5"], true),
            iface("bond0.100", 5, &["10.0.100.5"], true),
        ];
        let chosen = select_observed(&snapshot);
        assert_eq!(chosen.len(), 1);
        assert_eq!(chosen[0].name, "bond0");
    }

    #[test]
    fn multiple_default_egress_ifaces_are_all_kept_in_stable_order() {
        let snapshot = vec![
            iface("eth1", 7, &["10.0.1.5"], true),
            iface("eth0", 2, &["10.0.0.5"], true),
        ];
        let names: Vec<&str> = select_observed(&snapshot)
            .iter()
            .map(|iface| iface.name.as_str())
            .collect();
        assert_eq!(names, vec!["eth0", "eth1"]);
    }

    /// 默认路由解析：**全部**取，不只第一条（ECMP / 双上行都要观测）。
    #[test]
    fn every_default_route_counts_not_just_the_first() {
        let v4 = "Iface\tDestination\tGateway\t\tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n\
                  eth0\t00000000\t0102A8C0\t0003\t0\t0\t100\t00000000\t0\t0\t0\n\
                  eth1\t00000000\t0102A8C0\t0001\t0\t0\t200\t00000000\t0\t0\t0\n\
                  eth2\t0001A8C0\t00000000\t0001\t0\t0\t0\t00FFFFFF\t0\t0\t0\n";
        let ifaces = parse_default_routes_v4(v4);
        assert_eq!(
            ifaces,
            BTreeSet::from(["eth0".to_string(), "eth1".to_string()]),
            "两条默认路由都要留下；非默认的那条不要"
        );
    }

    /// 无 v4 默认路由但有 v6 默认路由的主机：必须能选出网卡。
    #[test]
    fn an_ipv6_only_host_still_has_a_default_route() {
        let v6 = "\
00000000000000000000000000000000 00 00000000000000000000000000000000 00 \
00000000000000000000000000000000 00000400 00000001 00000000 00000003 eth0\n\
fe800000000000000000000000000001 40 00000000000000000000000000000000 00 \
00000000000000000000000000000000 00000400 00000001 00000000 00000003 eth0\n\
20010db8000000000000000000000001 80 00000000000000000000000000000000 00 \
00000000000000000000000000000000 00000400 00000001 00000000 00000003 eth1\n";
        assert_eq!(
            parse_default_routes_v6(v6),
            BTreeSet::from(["eth0".to_string()]),
            "只有一段全 0 且 prefix=00 的那条是默认路由"
        );
        // v4 表为空 → 只靠 v6 也能选出网卡。
        let mut default_egress = parse_default_routes_v4("");
        default_egress.extend(parse_default_routes_v6(v6));
        let snapshot = vec![iface(
            "eth0",
            2,
            &["2001:db8::14"],
            default_egress.contains("eth0"),
        )];
        assert_eq!(select_observed(&snapshot).len(), 1);
    }
}
