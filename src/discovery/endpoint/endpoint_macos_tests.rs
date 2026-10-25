//! `endpoint_macos` 的单元测试。
//!
//! 拆成独立文件只是因为这个仓约定单文件 500 行以下。这里放四类用例：
//! 端口字节序、地址族解析、重复 fd 去重、以及真机冒烟。

use super::*;

#[test]
fn port_is_decoded_from_network_byte_order() {
    // 8080 = 0x1F90；macOS 存的是网络字节序，小端机上 `int` 的低 16 位是 0x901F。
    assert_eq!(decode_network_port(8080u16.to_be() as i32), 8080);
    assert_eq!(decode_network_port(22u16.to_be() as i32), 22);
    assert_eq!(decode_network_port(65535u16.to_be() as i32), 65535);
    assert_eq!(decode_network_port(0), 0);
}

#[test]
fn ipv4_address_comes_from_ina_46() {
    let laddr = InAddrUnion {
        ina_46: In4In6Addr {
            i46a_pad32: [0, 0, 0],
            i46a_addr4: [127, 0, 0, 1],
        },
    };
    assert_eq!(
        decode_address(INI_IPV4, &laddr).as_deref(),
        Some("127.0.0.1")
    );

    let laddr = InAddrUnion {
        ina_46: In4In6Addr {
            i46a_pad32: [0, 0, 0],
            i46a_addr4: [0, 0, 0, 0],
        },
    };
    // `0.0.0.0` 是「所有接口」，不是噪声：它恰恰是**对外暴露**的标志。
    assert_eq!(decode_address(INI_IPV4, &laddr).as_deref(), Some("0.0.0.0"));
}

#[test]
fn ipv6_address_comes_from_ina_6() {
    let mut raw = [0u8; 16];
    raw[15] = 1;
    let laddr = InAddrUnion { ina_6: raw };
    assert_eq!(decode_address(INI_IPV6, &laddr).as_deref(), Some("::1"));
}

#[test]
fn unknown_family_is_rejected() {
    let laddr = InAddrUnion { ina_6: [0u8; 16] };
    assert!(decode_address(0, &laddr).is_none());
}

#[test]
fn port_zero_is_not_an_endpoint() {
    let info = InSockInfo {
        insi_fport: 0,
        insi_lport: 0,
        insi_gencnt: 0,
        insi_flags: 0,
        insi_flow: 0,
        insi_vflag: INI_IPV4,
        insi_ip_ttl: 0,
        rfu_1: 0,
        insi_faddr: InAddrUnion { ina_6: [0u8; 16] },
        insi_laddr: InAddrUnion {
            ina_46: In4In6Addr {
                i46a_pad32: [0, 0, 0],
                i46a_addr4: [127, 0, 0, 1],
            },
        },
        insi_v4: InSockInfoV4 { in4_tos: 0 },
        insi_v6: InSockInfoV6 {
            in6_hlim: 0,
            in6_cksum: 0,
            in6_ifindex: 0,
            in6_hops: 0,
        },
    };
    assert!(address_and_port(&info).is_none());
}

/// 同一个 socket 多个 fd 时只算一个暴露面（OrbStack / SO_REUSEPORT 会这样）。
#[test]
fn duplicate_fds_collapse_into_one_listener() {
    let mut listeners = vec![
        RawListener {
            protocol: "tcp",
            local_ip: "0.0.0.0".to_string(),
            local_port: 18429,
            pid: 42,
            fd: 9,
        },
        RawListener {
            protocol: "tcp",
            local_ip: "0.0.0.0".to_string(),
            local_port: 18429,
            pid: 42,
            fd: 17,
        },
        // 不同 pid 绑同一端口（SO_REUSEPORT 的另一个进程）是两个暴露面。
        RawListener {
            protocol: "tcp",
            local_ip: "0.0.0.0".to_string(),
            local_port: 18429,
            pid: 43,
            fd: 4,
        },
    ];
    listeners.sort();
    listeners.dedup_by(|left, right| {
        left.protocol == right.protocol
            && left.local_ip == right.local_ip
            && left.local_port == right.local_port
            && left.pid == right.pid
    });
    assert_eq!(listeners.len(), 2);
}

/// 真机冒烟：只断言结构和取值范围，不断言具体端口 —— 测试机开着什么谁也说不准。
#[test]
fn real_discovery_returns_plausible_listeners() {
    let endpoints = discover_service_endpoints().expect("discovery should not fail");
    for endpoint in &endpoints {
        assert!(matches!(endpoint.protocol.as_str(), "tcp" | "udp"));
        assert!(endpoint.local_port > 0);
        assert!(!endpoint.local_ip.is_empty());
        assert!(endpoint.pid.is_some());
        assert_eq!(endpoint.binding_confidence.as_deref(), Some("single_owner"));
    }
    // 这台机器上至少跑着 sshd / 各类 GUI 服务，正常不会是空的。
    // 若真的空，直接报出来比留一个永远通过的用例好。
    assert!(
        !endpoints.is_empty(),
        "expected at least one listening socket on this machine"
    );
}

/// 探测结果要能拼进快照：中心侧认的是 `kind = service_endpoint` 和那几个 attribute key，
/// 少了任何一个，atlas 那边就静默地一条端口也看不到。
#[test]
fn snapshot_carries_service_endpoint_resources() {
    use crate::discovery::endpoint::EndpointDiscoveryProbe;
    use crate::discovery::runtime::DiscoveryRuntime;

    let mut runtime = DiscoveryRuntime::new(vec![Box::new(EndpointDiscoveryProbe)]);
    let result = runtime.refresh_all();
    assert!(
        result.errors.is_empty(),
        "endpoint probe should not error: {:?}",
        result.errors
    );

    let endpoints: Vec<_> = result
        .refreshed_snapshot
        .resources
        .iter()
        .filter(|resource| resource.kind == "service_endpoint")
        .collect();
    assert!(
        !endpoints.is_empty(),
        "snapshot must carry listener resources"
    );

    let first = endpoints[0];
    // 适配器（以及 atlas 的提取器）就靠这四个 key 干活。
    for key in [
        "endpoint.protocol",
        "endpoint.bind.ip",
        "endpoint.bind.port",
        "process.pid",
    ] {
        assert!(
            first.attributes.contains_key(key),
            "missing attribute {key} on {}",
            first.resource_id
        );
    }
    assert_eq!(
        first
            .attributes
            .get("runtime.binding.confidence")
            .map(String::as_str),
        Some("single_owner")
    );

    // target 也要有，否则运行时无法把端点作为采集对象追踪。
    assert!(
        result
            .refreshed_snapshot
            .targets
            .iter()
            .any(|target| target.kind == "service_endpoint"),
        "snapshot must carry service_endpoint targets"
    );
}

/// 结构体布局的自检：libproc 会按自己的尺寸 copyout，我们的缓冲区不能比它小。
#[test]
fn socket_structs_are_not_smaller_than_libproc_expects() {
    // `PROC_PIDFDSOCKETINFO_SIZE` = sizeof(proc_fileinfo) + sizeof(socket_info)，
    // 后者为 272 + max(union) = 272 + 528（un_sockinfo）= 800。
    assert!(mem::size_of::<SocketFdInfo>() >= 824);
    assert_eq!(mem::size_of::<ProcFileInfo>(), 24);
    assert_eq!(mem::size_of::<InSockInfo>(), 80);
    assert_eq!(mem::size_of::<TcpSockInfo>(), 120);
}
