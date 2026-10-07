//! Host-side network inventory discovery probe.

use std::collections::BTreeMap;
#[cfg(target_os = "linux")]
use std::fs;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr};
#[cfg(unix)]
use std::{ffi::CStr, ptr};

use wist_contracts::discovery::{DiscoveredResource, DiscoveredTarget, DiscoveryOrigin};
use wist_shared::time::now_rfc3339;

use super::host::{default_host_id, default_host_name};
use super::{DiscoveryError, DiscoveryProbe, DiscoverySourceKind, ProbeOutput};

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct NetworkDiscoveryProbe;

impl DiscoveryProbe for NetworkDiscoveryProbe {
    fn name(&self) -> &'static str {
        "network"
    }

    fn source(&self) -> DiscoverySourceKind {
        DiscoverySourceKind::LocalRuntime
    }

    fn refresh_interval(&self) -> std::time::Duration {
        // 这是**内建默认值**：与策展数据 `wist-knowledge/aspect-policies.toml` 里的
        // `default_interval_seconds` 同值，只在拿不到平台下发的策略表（断网 / 网关未配表）时生效。
        // 拿得到表就由表盖过（见 `DiscoveryRuntime` 的到期判定）；改策展值不必改这里。

        std::time::Duration::from_secs(900)
    }

    fn refresh(&self, _now: std::time::SystemTime) -> Result<ProbeOutput, DiscoveryError> {
        let discovered_at = now_rfc3339();
        let host_id = default_host_id();
        let host_name = default_host_name();
        let source = self.source().as_str().to_string();
        let observed_at = discovered_at.clone();
        let origin_id = format!("{}:{}:{}", source, self.name(), observed_at);
        let inventory = discover_network_inventory().map_err(|err| {
            super::probe_failed(
                self.name(),
                self.source(),
                format!("network discovery failed: {err}"),
            )
        })?;

        let mut resources = Vec::new();
        let mut targets = Vec::new();
        for iface in inventory {
            let iface_id = format!("{host_id}:if:{}", iface.name);
            let mut iface_attrs = BTreeMap::from([
                ("host.id".to_string(), host_id.clone()),
                ("host.name".to_string(), host_name.clone()),
                ("net.if.name".to_string(), iface.name.clone()),
            ]);
            if let Some(mac) = &iface.mac {
                iface_attrs.insert("net.if.mac".to_string(), mac.clone());
            }
            if let Some(state) = &iface.state {
                iface_attrs.insert("net.if.state".to_string(), state.clone());
            }

            resources.push(DiscoveredResource {
                resource_id: iface_id.clone(),
                kind: "network_interface".to_string(),
                origin_idx: 0,
                attributes: iface_attrs,
                discovered_at: discovered_at.clone(),
                last_seen_at: discovered_at.clone(),
                health: "healthy".to_string(),
                source: self.name().to_string(),
            });
            targets.push(DiscoveredTarget {
                target_id: format!("{iface_id}:network_interface"),
                kind: "network_interface".to_string(),
                origin_idx: 0,
                resource_ref: iface_id.clone(),
                execution_hints: BTreeMap::from([
                    ("host.id".to_string(), host_id.clone()),
                    ("host.name".to_string(), host_name.clone()),
                    ("net.if.name".to_string(), iface.name.clone()),
                ]),
                state: "active".to_string(),
            });

            for address in iface.addresses {
                let address_id = format!("{}:ip:{}", iface_id, encode_id_segment(&address.ip));
                let cidr = address.cidr();
                let mut attrs = BTreeMap::from([
                    ("host.id".to_string(), host_id.clone()),
                    ("host.name".to_string(), host_name.clone()),
                    ("net.if.name".to_string(), iface.name.clone()),
                    ("net.if.addr".to_string(), address.ip.clone()),
                    ("net.if.prefix".to_string(), address.prefix.to_string()),
                    ("net.if.cidr".to_string(), cidr.clone()),
                    ("network.interface.ref".to_string(), iface_id.clone()),
                ]);
                if let Some(gateway) = &address.gateway_ip {
                    attrs.insert("net.if.gateway".to_string(), gateway.clone());
                }
                if let Some(scope) = &address.scope {
                    attrs.insert("net.if.addr.scope".to_string(), scope.clone());
                }
                if let Some(mac) = &iface.mac {
                    attrs.insert("net.if.mac".to_string(), mac.clone());
                }

                resources.push(DiscoveredResource {
                    resource_id: address_id.clone(),
                    kind: "ip_address".to_string(),
                    origin_idx: 0,
                    attributes: attrs.clone(),
                    discovered_at: discovered_at.clone(),
                    last_seen_at: discovered_at.clone(),
                    health: "healthy".to_string(),
                    source: self.name().to_string(),
                });
                targets.push(DiscoveredTarget {
                    target_id: format!("{address_id}:ip_address"),
                    kind: "ip_address".to_string(),
                    origin_idx: 0,
                    resource_ref: address_id,
                    execution_hints: attrs,
                    state: "active".to_string(),
                });
            }
        }

        Ok(ProbeOutput {
            probe: self.name().to_string(),
            source: self.source(),
            refreshed_at: discovered_at,
            origin: DiscoveryOrigin {
                origin_id,
                probe: self.name().to_string(),
                source,
                observed_at,
            },
            resources,
            targets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Observed", module = "Observed.Entity")]
struct ObservedNetworkInterface {
    name: String,
    mac: Option<String>,
    state: Option<String>,
    addresses: Vec<ObservedIpAddress>,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Observed", module = "Observed.Entity")]
struct ObservedIpAddress {
    ip: String,
    prefix: u8,
    gateway_ip: Option<String>,
    scope: Option<String>,
}

impl ObservedIpAddress {
    fn cidr(&self) -> String {
        format!("{}/{}", self.ip, self.prefix)
    }
}

#[cfg(target_os = "linux")]
fn discover_network_inventory() -> io::Result<Vec<ObservedNetworkInterface>> {
    let gateways = linux_default_gateways()?;
    let mut interfaces = unix_interfaces_from_getifaddrs(&gateways)?;
    for iface in &mut interfaces {
        iface.mac = linux_read_interface_file(&iface.name, "address")
            .filter(|mac| mac != "00:00:00:00:00:00");
        iface.state = linux_read_interface_file(&iface.name, "operstate");
    }
    Ok(interfaces)
}

#[cfg(target_os = "linux")]
fn linux_default_gateways() -> io::Result<BTreeMap<String, String>> {
    fs::read_to_string("/proc/net/route")
        .map(|content| parse_linux_proc_default_gateways(&content))
        .or_else(|err| {
            if err.kind() == io::ErrorKind::NotFound {
                Ok(BTreeMap::new())
            } else {
                Err(err)
            }
        })
}

#[cfg(target_os = "linux")]
fn linux_read_interface_file(iface: &str, file: &str) -> Option<String> {
    fs::read_to_string(format!("/sys/class/net/{iface}/{file}"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_default_gateways(content: &str) -> BTreeMap<String, String> {
    content
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 3 || fields[1] != "00000000" {
                return None;
            }
            let iface = fields[0].to_string();
            let gateway = u32::from_str_radix(fields[2], 16).ok()?;
            let octets = gateway.to_le_bytes();
            Some((iface, Ipv4Addr::from(octets).to_string()))
        })
        .collect()
}

#[cfg(all(unix, not(target_os = "linux")))]
fn discover_network_inventory() -> io::Result<Vec<ObservedNetworkInterface>> {
    unix_interfaces_from_getifaddrs(&BTreeMap::new())
}

/// 本机网卡地址列表（形如 `en0 192.168.1.5/24`），供机器画像 / 状态上报在管理面展示。
///
/// 与发现探针共用同一份枚举（`discover_network_inventory`，已跳过回环）。**只保留有信息量的地址**：
/// 滤掉 IPv6 链路本地（`fe80::/10`，每张网卡都有一条）、回环与 IPv4 自分配（`169.254.0.0/16`）——
/// 一台多网卡主机否则会带上十几条这种噪声，把管理面的「这是哪台机器」淹掉。格式与事实摘要的
/// `network_addresses` 一致（`iface cidr`）；采不到就返回空表 —— 这是展示信息，不该影响上报本身。
#[cfg(unix)]
pub(crate) fn local_ip_addresses() -> Vec<String> {
    let Ok(interfaces) = discover_network_inventory() else {
        return Vec::new();
    };
    project_host_addresses(interfaces)
}

/// 从网卡枚举投影出「这台机器是谁」的 `iface cidr` 列表：滤掉噪声，其余保持枚举顺序。
///
/// 拆成纯函数是为了能用合成 inventory 单测 —— 真实枚举（`discover_network_inventory`）依赖
/// 运行环境的网卡，测不稳定。
fn project_host_addresses(interfaces: Vec<ObservedNetworkInterface>) -> Vec<String> {
    let mut addresses = Vec::new();
    for iface in interfaces {
        for address in iface.addresses {
            if is_meaningless_address(&address.ip) {
                continue;
            }
            addresses.push(format!("{} {}", iface.name, address.cidr()));
        }
    }
    addresses
}

/// 对「这台机器是谁」没有信息量的地址：IPv6 链路本地 / 回环 / 未指定，IPv4 回环 / 自分配（APIPA）/ 未指定。
///
/// 判断靠解析而不是字符串前缀：`fe80::/10` 覆盖 `fe80`–`febf`，只有按位判断才不漏。解析不了的
/// 串（不该出现）不作为噪声，原样保留 —— 展示层宁愿多一条也不要错删。
pub(crate) fn is_meaningless_address(ip: &str) -> bool {
    if let Ok(v6) = ip.parse::<Ipv6Addr>() {
        return v6.is_loopback() || v6.is_unspecified() || v6.is_unicast_link_local();
    }
    if let Ok(v4) = ip.parse::<Ipv4Addr>() {
        return v4.is_loopback() || v4.is_unspecified() || v4.is_link_local();
    }
    false
}

/// 判断一条地址 **spec**（`192.168.1.5/24` 或裸 `10.0.0.2`）是否是展示噪声：
/// 取 `/` 前的地址段再交给 [`is_meaningless_address`]。
///
/// 供不经过 `project_host_addresses` 的展示口径使用（发现快照里的 `net.if.cidr` / `net.if.addr`）。
pub(crate) fn is_meaningless_address_spec(spec: &str) -> bool {
    is_meaningless_address(spec.split('/').next().unwrap_or(spec))
}

#[cfg(not(unix))]
pub(crate) fn local_ip_addresses() -> Vec<String> {
    Vec::new()
}

#[cfg(unix)]
fn unix_interfaces_from_getifaddrs(
    gateways: &BTreeMap<String, String>,
) -> io::Result<Vec<ObservedNetworkInterface>> {
    let mut addrs: *mut libc::ifaddrs = ptr::null_mut();
    if unsafe { libc::getifaddrs(&mut addrs) } != 0 {
        return Err(io::Error::last_os_error());
    }

    let mut interfaces: BTreeMap<String, ObservedNetworkInterface> = BTreeMap::new();
    let result = {
        let mut cursor = addrs;
        while !cursor.is_null() {
            let item = unsafe { &*cursor };
            cursor = item.ifa_next;
            if item.ifa_addr.is_null() {
                continue;
            }
            let flags = item.ifa_flags;
            if flags & (libc::IFF_LOOPBACK as u32) != 0 {
                continue;
            }
            let name = unsafe { CStr::from_ptr(item.ifa_name) }
                .to_string_lossy()
                .to_string();
            let iface =
                interfaces
                    .entry(name.clone())
                    .or_insert_with(|| ObservedNetworkInterface {
                        name: name.clone(),
                        mac: None,
                        state: Some(if flags & (libc::IFF_UP as u32) != 0 {
                            "up".to_string()
                        } else {
                            "down".to_string()
                        }),
                        addresses: Vec::new(),
                    });

            let family = unsafe { (*item.ifa_addr).sa_family as i32 };
            match family {
                libc::AF_INET => {
                    let sockaddr = unsafe { &*(item.ifa_addr as *const libc::sockaddr_in) };
                    let ip = Ipv4Addr::from(u32::from_be(sockaddr.sin_addr.s_addr)).to_string();
                    if ip.starts_with("127.") {
                        continue;
                    }
                    let prefix = if item.ifa_netmask.is_null() {
                        32
                    } else {
                        let netmask = unsafe { &*(item.ifa_netmask as *const libc::sockaddr_in) };
                        u32::from_be(netmask.sin_addr.s_addr).count_ones() as u8
                    };
                    iface.addresses.push(ObservedIpAddress {
                        ip,
                        prefix,
                        gateway_ip: gateways.get(&name).cloned(),
                        scope: None,
                    });
                }
                libc::AF_INET6 => {
                    let sockaddr = unsafe { &*(item.ifa_addr as *const libc::sockaddr_in6) };
                    let ip = Ipv6Addr::from(sockaddr.sin6_addr.s6_addr).to_string();
                    if ip == "::1" {
                        continue;
                    }
                    let prefix = if item.ifa_netmask.is_null() {
                        128
                    } else {
                        let netmask = unsafe { &*(item.ifa_netmask as *const libc::sockaddr_in6) };
                        netmask
                            .sin6_addr
                            .s6_addr
                            .iter()
                            .map(|octet| octet.count_ones())
                            .sum::<u32>() as u8
                    };
                    iface.addresses.push(ObservedIpAddress {
                        scope: ipv6_scope(&ip).map(str::to_string),
                        ip,
                        prefix,
                        gateway_ip: None,
                    });
                }
                _ => {}
            }
        }

        Ok(interfaces
            .into_values()
            .filter(|iface| !iface.addresses.is_empty())
            .collect())
    };
    unsafe { libc::freeifaddrs(addrs) };
    result
}

fn encode_id_segment(value: &str) -> String {
    let mut encoded = String::with_capacity(value.len() * 2);
    for byte in value.as_bytes() {
        encoded.push_str(&format!("{byte:02x}"));
    }
    encoded
}

fn ipv6_scope(ip: &str) -> Option<&'static str> {
    let addr = ip.parse::<Ipv6Addr>().ok()?;
    if addr.is_unicast_link_local() {
        Some("link_local")
    } else if addr.is_unique_local() {
        Some("unique_local")
    } else {
        None
    }
}

#[cfg(not(unix))]
fn discover_network_inventory() -> io::Result<Vec<ObservedNetworkInterface>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::ObservedIpAddress;
    use super::ObservedNetworkInterface;
    #[cfg(target_os = "linux")]
    use super::parse_linux_proc_default_gateways;
    use super::{encode_id_segment, ipv6_scope, is_meaningless_address, project_host_addresses};

    fn iface(name: &str, addresses: &[(&str, u8)]) -> ObservedNetworkInterface {
        ObservedNetworkInterface {
            name: name.to_string(),
            mac: None,
            state: Some("up".to_string()),
            addresses: addresses
                .iter()
                .map(|(ip, prefix)| ObservedIpAddress {
                    ip: (*ip).to_string(),
                    prefix: *prefix,
                    gateway_ip: None,
                    scope: None,
                })
                .collect(),
        }
    }

    /// 端到端投影：用一条真实的 macOS 记录（18 条，其中 12 条是每张网卡一条的链路本地 IPv6）
    /// 验证噪声被滤掉、有信息量的保留。
    #[test]
    fn projects_only_meaningful_host_addresses() {
        let interfaces = vec![
            iface("awdl0", &[("fe80::303b:c4ff:fe6b:406e", 64)]),
            iface(
                "bridge100",
                &[
                    ("192.168.139.3", 23),
                    ("fe80::603e:5fff:fef3:3364", 64),
                    ("fd07:b51a:cc66:0:a617:db5e:ab7:e9f1", 64),
                ],
            ),
            iface(
                "bridge101",
                &[("192.168.117.0", 24), ("fe80::603e:5fff:fef3:3365", 64)],
            ),
            iface(
                "bridge102",
                &[("192.168.107.0", 24), ("fe80::603e:5fff:fef3:3366", 64)],
            ),
            iface(
                "en0",
                &[("fe80::1857:ec5:fe03:af06", 64), ("192.168.3.178", 24)],
            ),
            iface("llw0", &[("fe80::303b:c4ff:fe6b:406e", 64)]),
            iface("utun0", &[("fe80::19c3:bef7:1b4f:f4f5", 64)]),
            iface("utun1", &[("fe80::3de5:8507:afee:5945", 64)]),
            iface(
                "utun100",
                &[
                    ("100.121.111.48", 8),
                    ("fe80::845:a9a4:a00a:8bcd", 64),
                    ("fe80::", 64),
                ],
            ),
            iface("utun2", &[("fe80::4aef:bbdd:5acd:f782", 64)]),
            iface("utun3", &[("fe80::ce81:b1c:bd2c:69e", 64)]),
        ];

        let addresses = project_host_addresses(interfaces);

        // 18 → 6：只留物理/虚拟网卡上的有信息量地址。
        assert_eq!(addresses.len(), 6, "实际：{addresses:?}");
        assert!(
            !addresses.iter().any(|entry| entry.contains("fe80")),
            "不得留链路本地：{addresses:?}"
        );
        // en0 的物理 IPv4、ULA 与 Tailscale CGNAT 都保留；顺序按枚举来。
        assert_eq!(
            addresses,
            vec![
                "bridge100 192.168.139.3/23",
                "bridge100 fd07:b51a:cc66:0:a617:db5e:ab7:e9f1/64",
                "bridge101 192.168.117.0/24",
                "bridge102 192.168.107.0/24",
                "en0 192.168.3.178/24",
                "utun100 100.121.111.48/8",
            ]
        );
    }

    #[test]
    fn classifies_meaningless_addresses() {
        // 噪声：IPv6 链路本地（每张网卡一条）、回环、未指定、IPv4 自分配。
        for noise in [
            "fe80::1",
            "fe80::303b:c4ff:fe6b:406e",
            "febf::1",
            "Fe80::1",
            "::1",
            "::",
            "127.0.0.1",
            "169.254.10.20",
            "0.0.0.0",
        ] {
            assert!(is_meaningless_address(noise), "{noise} 应被判为噪声");
        }
        // 有信息量：私网 / 公网 / ULA（fd00::/8）/ Tailscale CGNAT（100.64.0.0/10）/
        // site-local（fec0::/10，虽废弃但不是链路本地）/ IPv4-mapped。
        for meaningful in [
            "192.168.3.178",
            "10.0.0.5",
            "100.121.111.48",
            "fd07:b51a:cc66:0:a617:db5e:ab7:e9f1",
            "2001:db8::1",
            "fec0::1",
            "::ffff:127.0.0.1",
        ] {
            assert!(
                !is_meaningless_address(meaningful),
                "{meaningful} 不该被滤掉"
            );
        }
        // 解析不了的串（含空串）保留，宁可多一条也不错删 —— 真实枚举不会产生这些。
        assert!(!is_meaningless_address("not-an-ip"));
        assert!(!is_meaningless_address(""));
    }

    #[test]
    fn projects_nothing_when_every_address_is_noise() {
        let interfaces = vec![
            iface("lo0", &[("127.0.0.1", 8), ("::1", 128)]),
            iface("en0", &[("fe80::1", 64), ("169.254.1.2", 16)]),
        ];
        assert!(project_host_addresses(interfaces).is_empty());
    }

    #[test]
    fn address_formats_cidr() {
        let address = ObservedIpAddress {
            ip: "192.168.10.41".to_string(),
            prefix: 24,
            gateway_ip: None,
            scope: None,
        };

        assert_eq!(address.cidr(), "192.168.10.41/24");
    }

    #[test]
    fn address_id_segments_are_encoded() {
        assert_eq!(encode_id_segment("fe80::1"), "666538303a3a31");
    }

    #[test]
    fn classifies_ipv6_address_scope() {
        assert_eq!(ipv6_scope("fe80::1"), Some("link_local"));
        assert_eq!(ipv6_scope("fd00::1"), Some("unique_local"));
        assert_eq!(ipv6_scope("2001:db8::1"), None);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn parses_linux_proc_default_gateways_by_interface() {
        let gateways = parse_linux_proc_default_gateways(
            "Iface\tDestination\tGateway\tFlags\tRefCnt\tUse\tMetric\tMask\n\
             eth0\t00000000\t010AA8C0\t0003\t0\t0\t100\t00000000\n\
             wlan0\t00000000\t0101A8C0\t0003\t0\t0\t200\t00000000\n",
        );

        assert_eq!(
            gateways.get("eth0").map(String::as_str),
            Some("192.168.10.1")
        );
        assert_eq!(
            gateways.get("wlan0").map(String::as_str),
            Some("192.168.1.1")
        );
    }
}
