//! macOS `libproc` implementation for service endpoint discovery.
//!
//! 为什么是 libproc 而不是 `lsof`：
//!
//! - agentd 是长驻探针。每多一个外部二进制就多一个「生产机上没装 / 版本不一致 /
//!   PATH 不对」的故障点，而这几类故障在出事的时候最难看出来。
//! - `lsof` 在非 root 下只能看到**自己的**进程；libproc 的可见性由进程权限决定，
//!   和 Linux 的 `/proc` 语义一致 —— agentd 以 root 跑时两者都能看全。
//! - `proc_pidinfo(PROC_PIDTASKINFO)` 在 `runtime/daemon.rs` 里已经用过了，链路是熟的。
//!
//! 枚举方式是「按进程找 socket」：`proc_listallpids` → 每个 pid 的 `PROC_PIDLISTFDS`
//! → 过滤 `PROX_FDTYPE_SOCKET` → `PROC_PIDFDSOCKETINFO`。这样**归属天然已知**，
//! 不需要 Linux 那套 socket inode 反查，所以 `owner_count` 恒为 1、
//! `binding_confidence` 恒为 `single_owner`。

use std::ffi::c_void;
use std::io;
use std::mem;
use std::net::{Ipv4Addr, Ipv6Addr};

use super::ObservedServiceEndpoint;
use crate::process_control::process_identity;

/// `sys/proc_info.h`: `PROC_PIDFDSOCKETINFO`。libc 只导出了 `PROC_PIDLISTFDS`。
const PROC_PIDFDSOCKETINFO: libc::c_int = 3;

/// `sys/proc_info.h`: `SOCKINFO_IN` / `SOCKINFO_TCP`（`socket_info.soi_kind`）。
const SOCKINFO_IN: i32 = 1;
const SOCKINFO_TCP: i32 = 2;

/// `sys/proc_info.h`: `INI_IPV4` / `INI_IPV6`（`in_sockinfo.insi_vflag`）。
const INI_IPV4: u8 = 0x1;
const INI_IPV6: u8 = 0x2;

/// `sys/proc_info.h`: `TSI_S_LISTEN`。
const TSI_S_LISTEN: i32 = 1;

const IPPROTO_TCP: i32 = 6;
const IPPROTO_UDP: i32 = 17;

/// `PATH_MAX`；`proc_pidpath` 的缓冲区。
const PROC_PIDPATH_MAX: usize = 4096;

// ── libproc 结构体 ─────────────────────────────────────────
//
// libc 只导出 `proc_fdinfo` 和三个函数，其余结构体得自己按
// `sys/proc_info.h` 声明。字段顺序和类型必须逐字对齐 —— 一个偏移错了，
// 读出来的端口就是别的字段的前半截。
//
// `soi_proto` 的真实大小由最大的 union 成员 `un_sockinfo`（528B）决定；
// 这里开 1024B 余量。libproc 只要求 buffersize **不小于**所需大小，
// 超出部分是安全的（内核按自己的尺寸 copyout 并返回该尺寸）。

#[repr(C)]
#[derive(Clone, Copy)]
struct ProcFileInfo {
    fi_openflags: u32,
    fi_status: u32,
    fi_offset: i64,
    fi_type: i32,
    fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VinInfoStat {
    vst_dev: u32,
    vst_mode: u16,
    vst_nlink: u16,
    vst_ino: u64,
    vst_uid: u32,
    vst_gid: u32,
    vst_atime: i64,
    vst_atimensec: i64,
    vst_mtime: i64,
    vst_mtimensec: i64,
    vst_ctime: i64,
    vst_ctimensec: i64,
    vst_birthtime: i64,
    vst_birthtimensec: i64,
    vst_size: i64,
    vst_blocks: i64,
    vst_blksize: i32,
    vst_flags: u32,
    vst_gen: u32,
    vst_rdev: u32,
    vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SockBufInfo {
    sbi_cc: u32,
    sbi_hiwat: u32,
    sbi_mbcnt: u32,
    sbi_mbmax: u32,
    sbi_lowat: u32,
    sbi_flags: i16,
    sbi_timeo: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct In4In6Addr {
    i46a_pad32: [u32; 3],
    i46a_addr4: [u8; 4],
}

#[repr(C)]
#[derive(Clone, Copy)]
union InAddrUnion {
    ina_46: In4In6Addr,
    ina_6: [u8; 16],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfoV4 {
    in4_tos: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfoV6 {
    in6_hlim: u8,
    in6_cksum: i32,
    in6_ifindex: u16,
    in6_hops: i16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct InSockInfo {
    insi_fport: i32,
    insi_lport: i32,
    insi_gencnt: u64,
    insi_flags: u32,
    insi_flow: u32,
    insi_vflag: u8,
    insi_ip_ttl: u8,
    rfu_1: u32,
    insi_faddr: InAddrUnion,
    insi_laddr: InAddrUnion,
    insi_v4: InSockInfoV4,
    insi_v6: InSockInfoV6,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct TcpSockInfo {
    tcpsi_ini: InSockInfo,
    tcpsi_state: i32,
    tcpsi_timer: [i32; 4],
    tcpsi_mss: i32,
    tcpsi_flags: u32,
    rfu_1: u32,
    tcpsi_tp: u64,
}

#[repr(C)]
#[derive(Clone, Copy)]
union SoiProto {
    pri_in: InSockInfo,
    pri_tcp: TcpSockInfo,
    /// 只为把 union 撑到不小于真实的 `un_sockinfo`；不读这一项。
    _reserve: [u8; 1024],
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketInfo {
    soi_stat: VinInfoStat,
    soi_so: u64,
    soi_pcb: u64,
    soi_type: i32,
    soi_protocol: i32,
    soi_family: i32,
    soi_options: i16,
    soi_linger: i16,
    soi_state: i16,
    soi_qlen: i16,
    soi_incqlen: i16,
    soi_qlimit: i16,
    soi_timeo: i16,
    soi_error: u16,
    soi_oobmark: u32,
    soi_rcv: SockBufInfo,
    soi_snd: SockBufInfo,
    soi_kind: i32,
    rfu_1: u32,
    soi_proto: SoiProto,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct SocketFdInfo {
    pfi: ProcFileInfo,
    psi: SocketInfo,
}

// ── 枚举 ──────────────────────────────────────────────────

/// 一个待组装成 `ObservedServiceEndpoint` 的监听项。
///
/// 拆出来是为了让地址/端口的解析成为**纯函数**：FFI 那部分只能在真机上验，
/// 而偏移和字节序恰恰是最容易写错的地方，必须有能跑的用例盯着。
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
struct RawListener {
    protocol: &'static str,
    local_ip: String,
    local_port: u16,
    pid: u32,
    fd: i32,
}

pub(super) fn discover_service_endpoints() -> io::Result<Vec<ObservedServiceEndpoint>> {
    let listeners = discover_listening_sockets()?;
    let mut endpoints = Vec::with_capacity(listeners.len());
    // `lstart` 要起一个 `ps` 子进程，按 pid 去重后才调；一个进程开十个端口只算一次。
    let mut identity_cache: std::collections::BTreeMap<u32, Option<String>> =
        std::collections::BTreeMap::new();
    let mut executable_cache: std::collections::BTreeMap<u32, Option<String>> =
        std::collections::BTreeMap::new();

    for listener in listeners {
        let pid = listener.pid;
        let process_identity = identity_cache
            .entry(pid)
            .or_insert_with(|| process_identity(pid).ok().flatten())
            .clone();
        let process_name = executable_cache
            .entry(pid)
            .or_insert_with(|| executable_path(pid))
            .clone();

        endpoints.push(ObservedServiceEndpoint {
            protocol: listener.protocol.to_string(),
            local_ip: listener.local_ip,
            local_port: listener.local_port,
            // macOS 的 libproc 不暴露 socket inode；`pid:fd` 在一次探测内足够唯一，
            // 而且中心侧只拿它拼 resource_id，不参与业务语义。
            socket_inode: format!("{}:{}", pid, listener.fd),
            pid: Some(pid),
            process_identity,
            process_name,
            cgroup_path: None,
            container_id: None,
            owner_count: Some(1),
            binding_confidence: Some("single_owner".to_string()),
        });
    }

    Ok(endpoints)
}

fn discover_listening_sockets() -> io::Result<Vec<RawListener>> {
    let mut listeners = Vec::new();
    for pid in list_all_pids()? {
        let fds = match list_socket_fds(pid) {
            Ok(fds) => fds,
            // 权限不足 / 进程刚退出：跳过这一个 pid，不让整次探测失败。
            Err(_) => continue,
        };
        for fd in fds {
            let Some(listener) = socket_listener(pid, fd) else {
                continue;
            };
            listeners.push(listener);
        }
    }

    // 同一个 (proto, ip, port, pid) 可能对应多个 fd（SO_REUSEPORT、或者像 OrbStack
    // 这样一次 bind 多个句柄），对资产目录来说它们是同一个暴露面。
    // 去重键**不含 fd** —— 带上 fd 就等于没去重。
    listeners.sort();
    listeners.dedup_by(|left, right| {
        left.protocol == right.protocol
            && left.local_ip == right.local_ip
            && left.local_port == right.local_port
            && left.pid == right.pid
    });
    Ok(listeners)
}

fn list_all_pids() -> io::Result<Vec<u32>> {
    let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
    if count <= 0 {
        return Err(io::Error::last_os_error());
    }
    // 枚举期间会有进程创建/退出，多留一点余量再截断。
    let capacity = count as usize + 32;
    let mut pids = vec![0 as libc::pid_t; capacity];
    let written = unsafe {
        libc::proc_listallpids(
            pids.as_mut_ptr() as *mut c_void,
            (capacity * mem::size_of::<libc::pid_t>()) as libc::c_int,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }
    pids.truncate(written as usize);
    Ok(pids
        .into_iter()
        .filter(|pid| *pid > 0)
        .map(|pid| pid as u32)
        .collect())
}

fn list_socket_fds(pid: u32) -> io::Result<Vec<i32>> {
    let pid = pid as libc::c_int;
    let bytes =
        unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
    if bytes <= 0 {
        return Err(io::Error::last_os_error());
    }

    let fd_size = mem::size_of::<libc::proc_fdinfo>();
    let capacity = bytes as usize / fd_size + 8;
    let mut buffer = vec![0u8; capacity * fd_size];
    let written = unsafe {
        libc::proc_pidinfo(
            pid,
            libc::PROC_PIDLISTFDS,
            0,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as libc::c_int,
        )
    };
    if written <= 0 {
        return Err(io::Error::last_os_error());
    }

    let count = written as usize / fd_size;
    let mut fds = Vec::with_capacity(count);
    for index in 0..count {
        let offset = index * fd_size;
        let info: libc::proc_fdinfo =
            unsafe { std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const _) };
        if info.proc_fdtype as libc::c_int == libc::PROX_FDTYPE_SOCKET {
            fds.push(info.proc_fd);
        }
    }
    Ok(fds)
}

/// 读一个 socket fd 的详情；不是「在监听」就返回 `None`。
fn socket_listener(pid: u32, fd: i32) -> Option<RawListener> {
    let mut info: SocketFdInfo = unsafe { mem::zeroed() };
    let size = mem::size_of::<SocketFdInfo>() as libc::c_int;
    let written = unsafe {
        libc::proc_pidfdinfo(
            pid as libc::c_int,
            fd,
            PROC_PIDFDSOCKETINFO,
            &mut info as *mut SocketFdInfo as *mut c_void,
            size,
        )
    };
    if written <= 0 {
        return None;
    }

    // `soi_kind` 决定 `soi_proto` 怎么解释。
    match info.psi.soi_kind {
        SOCKINFO_TCP => {
            // 只看 LISTEN：ESTABLISHED 的连接不是「谁在对外提供服务」。
            let tcp = unsafe { info.psi.soi_proto.pri_tcp };
            if tcp.tcpsi_state != TSI_S_LISTEN {
                return None;
            }
            let (local_ip, local_port) = address_and_port(&tcp.tcpsi_ini)?;
            Some(RawListener {
                protocol: "tcp",
                local_ip,
                local_port,
                pid,
                fd,
            })
        }
        SOCKINFO_IN => {
            let inet = unsafe { info.psi.soi_proto.pri_in };
            if info.psi.soi_protocol != IPPROTO_UDP && info.psi.soi_protocol != IPPROTO_TCP {
                return None;
            }
            let protocol = if info.psi.soi_protocol == IPPROTO_TCP {
                "tcp"
            } else {
                "udp"
            };
            let (local_ip, local_port) = address_and_port(&inet)?;
            Some(RawListener {
                protocol,
                local_ip,
                local_port,
                pid,
                fd,
            })
        }
        // unix domain / kqueue / 其它：不是网络暴露面。
        _ => None,
    }
}

/// 从 `in_sockinfo` 取本地地址与端口。端口 0 表示还没绑定，直接丢掉。
fn address_and_port(info: &InSockInfo) -> Option<(String, u16)> {
    let port = decode_network_port(info.insi_lport);
    if port == 0 {
        return None;
    }
    let ip = decode_address(info.insi_vflag, &info.insi_laddr)?;
    Some((ip, port))
}

/// macOS 把端口按**网络字节序**塞在 `int` 的低 16 位里。
fn decode_network_port(raw: i32) -> u16 {
    u16::from_be(raw as u16)
}

/// `insi_vflag` 决定 `ina_46` 还是 `ina_6` 有意义。
fn decode_address(vflag: u8, laddr: &InAddrUnion) -> Option<String> {
    if vflag & INI_IPV4 != 0 {
        let addr = unsafe { laddr.ina_46.i46a_addr4 };
        return Some(Ipv4Addr::new(addr[0], addr[1], addr[2], addr[3]).to_string());
    }
    if vflag & INI_IPV6 != 0 {
        let addr = unsafe { laddr.ina_6 };
        return Some(Ipv6Addr::from(addr).to_string());
    }
    None
}

fn executable_path(pid: u32) -> Option<String> {
    let mut buffer = vec![0u8; PROC_PIDPATH_MAX];
    let written = unsafe {
        libc::proc_pidpath(
            pid as libc::c_int,
            buffer.as_mut_ptr() as *mut c_void,
            buffer.len() as u32,
        )
    };
    if written <= 0 {
        return None;
    }
    let path = String::from_utf8_lossy(&buffer[..written as usize])
        .trim_end_matches('\0')
        .to_string();
    (!path.is_empty()).then_some(path)
}

#[cfg(test)]
#[path = "endpoint_macos_tests.rs"]
mod tests;
