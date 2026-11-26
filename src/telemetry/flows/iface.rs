//! 观测哪张网卡：**本机事实**决定，平台不指定接口名。
//!
//! 规则（设计 §7.2）：默认路由出口 ∩ 持有可在网络上路由的地址 ∩ 不是 loopback/容器虚拟口。
//! 首版不观测 vlan 子接口（记在父接口上），bond 记 bond 本身。
//!
//! 这里的函数是**纯判定**，不碰 sysfs/netlink —— 采集层把它看到的接口快照交进来，
//! 这样选择规则可以在 macOS 上被测试覆盖。

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
}
