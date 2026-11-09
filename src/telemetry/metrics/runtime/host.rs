//! 主机域采集：CPU、负载、内存、磁盘容量、逐挂载点文件系统、块设备 I/O。
//!
//! 只产出 `fact_key`（单位中立），指标名/单位/类型由 `wist-metrics` 注册表决定。

use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
use std::net::{IpAddr, SocketAddr, ToSocketAddrs, UdpSocket};
use std::path::Path;
use std::time::Instant;

use sysinfo::{Disks, System};
use wist_contracts::discovery::StringKeyValue;

use super::super::cpu;
use super::push_fact_if_absent;
use super::{MetricsCollectionTargetSample, MetricsLabeledFact};

pub(super) struct HostRuntimeFacts {
    pub(super) facts: Vec<StringKeyValue>,
    pub(super) labeled_facts: Vec<MetricsLabeledFact>,
}

pub(super) fn collect_host_runtime_facts(
    _sample_targets: &[MetricsCollectionTargetSample],
) -> HostRuntimeFacts {
    let mut facts = Vec::new();
    let mut labeled_facts = Vec::new();

    // CPU：逐核逐 mode 的累计秒（权威源）。
    let cpu_times = cpu::host_cpu_times();
    for time in &cpu_times {
        labeled_facts.push(MetricsLabeledFact {
            key: "host.cpu.seconds".to_string(),
            value: format!("{:.3}", time.seconds),
            labels: vec![
                StringKeyValue::new("cpu", time.cpu.clone()),
                StringKeyValue::new("mode", time.mode),
            ],
        });
    }
    // 整机使用率（0–1）：窗口内 idle 增量 / (经过时间 × 核数)，再取 `1 -`。
    // 首轮 / 计数器回退 / 核数变化时不出值（见 `cpu::CpuUsageWindow`）。
    if let Some(ratio) = cpu::usage_ratio(Instant::now(), &cpu_times) {
        push_fact_if_absent(
            &mut facts,
            StringKeyValue::new("host.cpu.usage_ratio", ratio.to_string()),
        );
    }

    let loadavg = System::load_average();
    for (key, value) in [
        ("host.loadavg.1m", loadavg.one),
        ("host.loadavg.5m", loadavg.five),
        ("host.loadavg.15m", loadavg.fifteen),
    ] {
        push_fact_if_absent(&mut facts, StringKeyValue::new(key, value.to_string()));
    }

    let uptime = System::uptime();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.uptime.seconds", uptime.to_string()),
    );

    let mut system = System::new();
    system.refresh_memory();
    let total_memory = system.total_memory();
    let available_memory = system.available_memory();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.memory.total_bytes", total_memory.to_string()),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.memory.available_bytes", available_memory.to_string()),
    );
    // 总量未知时不发比例：算出 0% 会伪造一个「内存很空」的读数。
    if let Some(ratio) = memory_usage_ratio(total_memory, available_memory) {
        push_fact_if_absent(
            &mut facts,
            StringKeyValue::new("host.memory.usage_ratio", ratio.to_string()),
        );
    }
    // swap 总量为 0 表示未配置交换分区（或平台拿不到）：两者都不发，避免伪造 0。
    let swap_total = system.total_swap();
    if swap_total > 0 {
        push_fact_if_absent(
            &mut facts,
            StringKeyValue::new("host.memory.swap_total_bytes", swap_total.to_string()),
        );
        push_fact_if_absent(
            &mut facts,
            StringKeyValue::new(
                "host.memory.swap_free_bytes",
                system.free_swap().to_string(),
            ),
        );
    }

    let disks = Disks::new_with_refreshed_list();
    collect_host_disk_usage(&disks, &mut facts);
    collect_host_filesystem_usage(&disks, &mut labeled_facts);
    collect_disk_io(&disks, &mut labeled_facts);
    collect_host_info(&mut labeled_facts);

    HostRuntimeFacts {
        facts,
        labeled_facts,
    }
}

/// 主机身份：一条 `system_host_info` 序列（值恒为 1），承载「这是哪台机器」。
///
/// 为什么不把这些字段贴到每条测量序列上：主机名会改、IP 会随 DHCP/迁移变、内核会升级。
/// 平铺会让全部 `system_*` 序列在变化时断成两段；集中在 info 指标上，变化只替换这一条。
fn collect_host_info(labeled_facts: &mut Vec<MetricsLabeledFact>) {
    let mut labels = Vec::new();

    let host_name = crate::discovery::host::default_host_name();
    if !host_name.trim().is_empty() {
        labels.push(StringKeyValue::new("host_name", host_name));
    }
    if let Some(ip) = primary_host_ip() {
        labels.push(StringKeyValue::new("host_ip", ip));
    }
    labels.push(StringKeyValue::new("os", std::env::consts::OS));
    labels.push(StringKeyValue::new("arch", std::env::consts::ARCH));
    if let Some(kernel) = System::kernel_version()
        && !kernel.trim().is_empty()
    {
        labels.push(StringKeyValue::new("kernel", kernel));
    }

    labeled_facts.push(MetricsLabeledFact {
        key: "host.info".to_string(),
        value: "1".to_string(),
        labels,
    });
}

/// 主 IP：优先「到平台的源地址」，其次默认路由口，最后字典序（跳过虚拟网卡）。
///
/// 一台主机天然有多个地址（物理网卡 / 容器网桥 / VPN / 虚拟化），没有一个天然是「唯一」的。
/// 对平台来说唯一有意义的定义是「平台到达这台主机时用的那个源地址」—— 所以先按控制面
/// endpoint 做一次**零报文**的路由探测（UDP connect 不发包，只让内核按路由表选源地址）。
fn primary_host_ip() -> Option<String> {
    choose_primary_host_ip(
        super::platform_endpoint().and_then(platform_source_ip),
        crate::discovery::network::host_addresses(),
    )
}

/// 纯函数：三种来源的优先级（拆出来是为了能用合成数据单测）。
fn choose_primary_host_ip(
    platform_ip: Option<String>,
    addresses: Vec<crate::discovery::network::HostAddress>,
) -> Option<String> {
    // 1) 内核按路由表给出的「去平台」源地址：最贴近「平台眼里的这台机器」。
    if let Some(ip) = platform_ip {
        return Some(ip);
    }

    // 同优先级内保持确定性：按 (接口名, 地址) 排序，不依赖枚举顺序。
    fn first_by_name(items: Vec<&crate::discovery::network::HostAddress>) -> Option<String> {
        let mut items = items;
        items.sort_by(|left, right| {
            left.iface
                .cmp(&right.iface)
                .then_with(|| left.ip.cmp(&right.ip))
        });
        items.first().map(|address| address.ip.clone())
    }

    // 2) 默认路由口（Linux `/proc/net/route` 已经解析出来并挂在地址上）。
    let default_route: Vec<_> = addresses
        .iter()
        .filter(|address| address.default_route)
        .collect();
    if let Some(ip) = first_by_name(default_route) {
        return Some(ip);
    }

    // 3) 兜底：字典序，跳过容器网桥 / veth / VPN / 虚拟化接口。
    let physical: Vec<_> = addresses
        .iter()
        .filter(|address| !crate::discovery::network::is_virtual_interface(&address.iface))
        .collect();
    if let Some(ip) = first_by_name(physical) {
        return Some(ip);
    }

    // 4) 只剩虚拟网卡（例如容器里只有 eth0/veth）：宁可给个地址，也不要空着。
    first_by_name(addresses.iter().collect())
}

/// 控制面 endpoint → 内核按路由表选出的本地源 IPv4（**不发包**）。
///
/// `UdpSocket::connect` 在 UDP 上只设对端、不做握手；取到的 `local_addr` 就是
/// 内核去往该地址时会给包用的源地址。拿不到（没配置 / 解析失败 / 无路由 / 选到回环）→ `None`，
/// 由调用方走默认路由兜底。
fn platform_source_ip(endpoint: &str) -> Option<String> {
    let authority = endpoint_authority(endpoint)?;
    // `host_ip` 的契约是 IPv4：优先 v4；只有 v6 时不给（不写一条 v6 的 host_ip）。
    let target = authority
        .to_socket_addrs()
        .ok()?
        .find(|address| address.is_ipv4())?;
    let socket = UdpSocket::bind(SocketAddr::from(([0, 0, 0, 0], 0))).ok()?;
    socket.connect(target).ok()?;
    match socket.local_addr().ok()?.ip() {
        IpAddr::V4(ip) if !ip.is_loopback() && !ip.is_unspecified() && !ip.is_link_local() => {
            Some(ip.to_string())
        }
        _ => None,
    }
}

/// `https://host:3100/api` → `host:3100`；没写端口时按 scheme 补（`http`→80，其余→443）。
fn endpoint_authority(endpoint: &str) -> Option<String> {
    let endpoint = endpoint.trim();
    if endpoint.is_empty() {
        return None;
    }
    let (scheme, rest) = match endpoint.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => (String::new(), endpoint),
    };
    let authority = rest.split('/').next()?.trim();
    if authority.is_empty() {
        return None;
    }
    // IPv6 字面量必须带端口（`[::1]:443`），原样交给 `to_socket_addrs`。
    if authority.starts_with('[') {
        return Some(authority.to_string());
    }
    let has_port = authority
        .rsplit_once(':')
        .is_some_and(|(_, port)| port.parse::<u16>().is_ok());
    if has_port {
        return Some(authority.to_string());
    }
    Some(format!(
        "{authority}:{}",
        if scheme == "http" { 80 } else { 443 }
    ))
}

pub(super) fn collect_host_disk_usage(disks: &Disks, facts: &mut Vec<StringKeyValue>) {
    if cfg!(target_os = "linux") {
        collect_linux_disk_usage(disks, facts);
    } else {
        collect_primary_disk_usage(disks, facts);
    }
}

/// 非 Linux 平台只报「主盘」：macOS APFS 把用户数据放在 Data 卷（`/` 只是只读系统快照），
/// 所以优先取 Data、回落到 `/`；其它 Unix 取 `/`。
pub(super) fn collect_primary_disk_usage(disks: &Disks, facts: &mut Vec<StringKeyValue>) {
    let mounts: &[&str] = if cfg!(target_os = "macos") {
        &["/System/Volumes/Data", "/"]
    } else {
        &["/"]
    };

    for mount in mounts {
        let Some(disk) = disks
            .list()
            .iter()
            .find(|disk| disk.mount_point() == Path::new(mount))
        else {
            continue;
        };
        push_disk_capacity_facts(facts, "system", disk.total_space(), disk.available_space());
        return;
    }
}

/// Linux 把容量拆成两个角色：
/// - `system`：根文件系统 `/`（系统盘）；
/// - `data`：其余本地块设备挂载点（数据盘）。多块数据盘按容量汇总，
///   同一设备被 bind mount 到多个路径时只算一次。
///
/// 原有的 `host.disk.*` 保持为系统盘，兼容既有网关接口与页面。
pub(super) fn collect_linux_disk_usage(disks: &Disks, facts: &mut Vec<StringKeyValue>) {
    let Some(root) = disks
        .list()
        .iter()
        .find(|disk| disk.mount_point() == Path::new("/"))
    else {
        return;
    };
    let root_total = root.total_space();
    let root_available = root.available_space();
    push_disk_capacity_facts(facts, "system", root_total, root_available);

    let mut seen_devices = HashSet::new();
    // 根文件系统的 bind mount 也是「系统盘」，不能重复计入数据盘。
    let root_device = root.name().to_string_lossy();
    if !root_device.is_empty() {
        seen_devices.insert(root_device.into_owned());
    }
    let mut data_total = 0u64;
    let mut data_available = 0u64;
    let mut data_mounts = 0usize;
    for disk in disks.list() {
        if !is_linux_data_mount(disk) {
            continue;
        }
        // 同一设备可能被 bind mount 到多个路径（如 /data 与 /mnt/data），只算一次。
        let device = disk.name().to_string_lossy();
        let key = if device.is_empty() {
            format!("mount:{}", disk.mount_point().display())
        } else {
            device.into_owned()
        };
        if !seen_devices.insert(key) {
            continue;
        }
        data_total = data_total.saturating_add(disk.total_space());
        data_available = data_available.saturating_add(disk.available_space());
        data_mounts += 1;
    }

    if data_mounts > 0 {
        push_disk_capacity_facts(facts, "data", data_total, data_available);
        push_fact_if_absent(
            facts,
            StringKeyValue::new("host.disk.data.mounts", data_mounts.to_string()),
        );
    }
}

/// 是否计入 Linux「数据盘」。
///
/// `sysinfo::Disks` 已经过滤掉 proc/sys/devtmpfs/tmpfs/NFS 等虚拟或网络挂载；
/// 这里再排除根（系统盘）、引导分区、运行期目录与容器叠加层，避免把系统自身
/// 或临时文件系统误算成数据盘。
pub(super) fn is_linux_data_mount(disk: &sysinfo::Disk) -> bool {
    is_linux_data_mount_point(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
    )
}

pub(super) fn is_linux_data_mount_point(mount: &str, file_system: &str, total_space: u64) -> bool {
    if total_space == 0 || mount == "/" {
        return false;
    }
    if mount == "/boot" || mount.starts_with("/boot/") {
        return false;
    }
    if mount == "/run"
        || mount.starts_with("/run/")
        || mount == "/sys"
        || mount.starts_with("/sys/")
        || mount == "/proc"
        || mount.starts_with("/proc/")
        || mount == "/dev"
        || mount.starts_with("/dev/")
    {
        return false;
    }
    !is_excluded_filesystem(file_system)
}

pub(super) fn push_disk_capacity_facts(
    facts: &mut Vec<StringKeyValue>,
    role: &str,
    total: u64,
    available: u64,
) {
    let available = available.min(total);
    let usage_ratio = if total == 0 {
        0.0
    } else {
        total.saturating_sub(available) as f64 / total as f64
    };
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("host.disk.{role}.usage_ratio"),
            usage_ratio.to_string(),
        ),
    );
    push_fact_if_absent(
        facts,
        StringKeyValue::new(format!("host.disk.{role}.total_bytes"), total.to_string()),
    );
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("host.disk.{role}.available_bytes"),
            available.to_string(),
        ),
    );
}

/// 逐挂载点文件系统容量：同一 fact key 的多条实例用 `mountpoint` / `fstype` 标签区分。
///
/// 与 [`collect_host_disk_usage`] 的 `host.disk.*` 汇总不是重复：汇总是整盘（按 `disk_role`
/// 分 system/data），这里是逐挂载点细粒度容量。
pub(super) fn collect_host_filesystem_usage(disks: &Disks, facts: &mut Vec<MetricsLabeledFact>) {
    for filesystem in local_filesystems(disks) {
        facts.extend(filesystem_facts(
            &filesystem.mount,
            &filesystem.file_system,
            filesystem.total_space,
            filesystem.available_space,
        ));
    }
}

/// 本机一个「真实文件系统」的容量快照。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LocalFilesystem {
    pub mount: String,
    pub device: String,
    pub file_system: String,
    pub total_space: u64,
    pub available_space: u64,
}

/// 本机真实文件系统清单（指标与 `investigate disk` **共用同一套过滤与去重规则**）。
///
/// 顺序是刻意的：**规范挂载点优先**（Linux `/`、macOS 的 Data 卷），其余按系统给出的顺序补齐。
/// 同一设备被 bind mount / btrfs 子卷挂到多处时只保留第一条 —— 逐条上报会把容量重复计数。
pub(crate) fn local_filesystems(disks: &Disks) -> Vec<LocalFilesystem> {
    if !(cfg!(target_os = "linux") || cfg!(target_os = "macos")) {
        return Vec::new();
    }
    let preferred: &[&str] = if cfg!(target_os = "macos") {
        &["/System/Volumes/Data", "/"]
    } else {
        &["/"]
    };

    let mut seen = HashSet::new();
    let mut filesystems = Vec::new();
    for mount in preferred {
        let Some(disk) = disks
            .list()
            .iter()
            .find(|disk| disk.mount_point() == Path::new(mount))
        else {
            continue;
        };
        if !is_local_filesystem_mount(disk) {
            continue;
        }
        let device = disk.name().to_string_lossy().to_string();
        if !seen.insert(filesystem_dedupe_key(&device, mount)) {
            continue;
        }
        filesystems.push(local_filesystem(disk));
    }
    for disk in disks.list() {
        if !is_local_filesystem_mount(disk) {
            continue;
        }
        let device = disk.name().to_string_lossy().to_string();
        let mount = disk.mount_point().to_string_lossy();
        if !seen.insert(filesystem_dedupe_key(&device, &mount)) {
            continue;
        }
        filesystems.push(local_filesystem(disk));
    }
    filesystems
}

pub(super) fn local_filesystem(disk: &sysinfo::Disk) -> LocalFilesystem {
    LocalFilesystem {
        mount: disk.mount_point().to_string_lossy().to_string(),
        device: disk.name().to_string_lossy().to_string(),
        file_system: disk.file_system().to_string_lossy().to_string(),
        total_space: disk.total_space(),
        available_space: disk.available_space(),
    }
}

pub(super) fn is_local_filesystem_mount(disk: &sysinfo::Disk) -> bool {
    if cfg!(target_os = "macos") {
        is_macos_filesystem_mount(disk)
    } else {
        is_linux_filesystem_mount(disk)
    }
}

/// 同一设备（bind mount / btrfs 子卷）只保留第一条；设备名为空时用挂载点兜底。
pub(super) fn filesystem_dedupe_key(device: &str, mount: &str) -> String {
    if device.is_empty() {
        format!("mount:{mount}")
    } else {
        device.to_string()
    }
}

pub(super) fn is_linux_filesystem_mount(disk: &sysinfo::Disk) -> bool {
    is_linux_filesystem_mount_point(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
    )
}

pub(super) fn is_linux_filesystem_mount_point(
    mount: &str,
    file_system: &str,
    total_space: u64,
) -> bool {
    if total_space == 0 {
        return false;
    }
    if mount == "/boot" || mount.starts_with("/boot/") {
        return false;
    }
    if mount == "/run"
        || mount.starts_with("/run/")
        || mount == "/sys"
        || mount.starts_with("/sys/")
        || mount == "/proc"
        || mount.starts_with("/proc/")
        || mount == "/dev"
        || mount.starts_with("/dev/")
    {
        return false;
    }
    !is_excluded_filesystem(file_system)
}

pub(super) fn is_macos_filesystem_mount(disk: &sysinfo::Disk) -> bool {
    is_macos_filesystem_mount_point(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
    )
}

pub(super) fn is_macos_filesystem_mount_point(
    mount: &str,
    file_system: &str,
    total_space: u64,
) -> bool {
    if total_space == 0 {
        return false;
    }
    if mount == "/" || mount == "/System/Volumes/Data" {
        return true;
    }
    // 其它系统辅助卷（Preboot / VM / Update / xarts / iSCPreboot / Hardware）
    // 与 Data 共享 APFS container，逐卷上报会重复计数。
    if mount.starts_with("/System/Volumes/") {
        return false;
    }
    if mount.starts_with("/Volumes/") {
        return !is_excluded_filesystem(file_system) && !file_system.contains("fuse");
    }
    false
}

pub(super) fn is_excluded_filesystem(file_system: &str) -> bool {
    matches!(
        file_system,
        "proc"
            | "sysfs"
            | "devtmpfs"
            | "devpts"
            | "tmpfs"
            | "cgroup"
            | "cgroup2"
            | "pstore"
            | "securityfs"
            | "debugfs"
            | "tracefs"
            | "hugetlbfs"
            | "mqueue"
            | "configfs"
            | "fusectl"
            | "binfmt_misc"
            | "rpc_pipefs"
            | "nsfs"
            | "efivarfs"
            | "ramfs"
            | "rootfs"
            | "overlay"
            | "aufs"
            | "squashfs"
            | "iso9660"
            | "nfs"
            | "nfs4"
            | "cifs"
            | "smb3"
            | "ceph"
            | "glusterfs"
            | "lustre"
            | "beegfs"
            | "gpfs"
            | "orangefs"
            | "pvfs2"
            | "afs"
            | "ncpfs"
            | "coda"
            | "davfs"
            | "shfs"
            | "9p"
            | "virtiofs"
            | "autofs"
            | "devfs"
            | "map"
            | "smbfs"
            | "webdav"
            | "afpfs"
    ) || file_system.starts_with("fuse")
}

pub(super) fn filesystem_facts(
    mount: &str,
    file_system: &str,
    total: u64,
    available: u64,
) -> Vec<MetricsLabeledFact> {
    let available = available.min(total);
    let usage_ratio = if total == 0 {
        0.0
    } else {
        total.saturating_sub(available) as f64 / total as f64
    };
    let mut labels = vec![StringKeyValue::new("mountpoint", mount)];
    if !file_system.is_empty() {
        labels.push(StringKeyValue::new("fstype", file_system));
    }
    let mut facts = vec![
        MetricsLabeledFact {
            key: "host.filesystem.usage_ratio".to_string(),
            value: usage_ratio.to_string(),
            labels: labels.clone(),
        },
        MetricsLabeledFact {
            key: "host.filesystem.total_bytes".to_string(),
            value: total.to_string(),
            labels: labels.clone(),
        },
        MetricsLabeledFact {
            key: "host.filesystem.available_bytes".to_string(),
            value: available.to_string(),
            labels: labels.clone(),
        },
    ];
    if let Some((inodes, inodes_free)) = filesystem_inode_counts(mount) {
        facts.push(MetricsLabeledFact {
            key: "host.filesystem.inodes".to_string(),
            value: inodes.to_string(),
            labels: labels.clone(),
        });
        facts.push(MetricsLabeledFact {
            key: "host.filesystem.inodes_free".to_string(),
            value: inodes_free.to_string(),
            labels,
        });
    }
    facts
}

/// inode 总数 / 剩余数（`statvfs`）。读不到就不发这两个事实。
#[cfg(unix)]
pub(super) fn filesystem_inode_counts(mount: &str) -> Option<(u64, u64)> {
    use std::ffi::CString;

    let path = CString::new(mount).ok()?;
    let mut buf: libc::statvfs = unsafe { std::mem::zeroed() };
    let rc = unsafe { libc::statvfs(path.as_ptr(), &mut buf) };
    if rc != 0 {
        return None;
    }
    Some((buf.f_files as u64, buf.f_ffree as u64))
}

#[cfg(not(unix))]
pub(super) fn filesystem_inode_counts(_mount: &str) -> Option<(u64, u64)> {
    None
}

/// 解析 `/proc/diskstats` 的一行（纯函数，便于在任何平台跑测试）。
#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct DiskIoStat {
    pub device: String,
    pub reads: u64,
    pub read_bytes: u64,
    pub writes: u64,
    pub written_bytes: u64,
    pub io_seconds: f64,
}

/// `/proc/diskstats` 字段：2 name / 3 reads / 5 sectors read / 7 writes /
/// 9 sectors written / 12 ms doing I/O；扇区恒为 512 字节。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_diskstats(text: &str) -> Vec<DiskIoStat> {
    let mut out = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 13 {
            continue;
        }
        let device = fields[2];
        if device.starts_with("loop") || device.starts_with("ram") {
            continue;
        }
        let number = |index: usize| -> u64 { fields[index].parse().unwrap_or(0) };
        out.push(DiskIoStat {
            device: device.to_string(),
            reads: number(3),
            read_bytes: number(5).saturating_mul(512),
            writes: number(7),
            written_bytes: number(9).saturating_mul(512),
            io_seconds: number(12) as f64 / 1000.0,
        });
    }
    out
}

/// 分区（`sda1`、`nvme0n1p1`）与整盘（`sda`、`nvme0n1`）共存于 diskstats；
/// 两者都上报会在求和时双计，因此只保留整盘。
#[cfg(target_os = "linux")]
pub(super) fn is_partition(device: &str) -> bool {
    std::path::Path::new("/sys/class/block")
        .join(device)
        .join("partition")
        .exists()
}

/// 块设备 I/O 累计计数（`/proc/diskstats`）。其它平台见下方 `macos` 实现。
#[cfg(target_os = "linux")]
pub(super) fn collect_disk_io(_disks: &Disks, labeled: &mut Vec<MetricsLabeledFact>) {
    let Ok(text) = fs::read_to_string("/proc/diskstats") else {
        return;
    };
    for stat in parse_diskstats(&text) {
        if is_partition(&stat.device) {
            continue;
        }
        let labels = vec![StringKeyValue::new("device", stat.device.clone())];
        for (key, value) in [
            ("host.disk.read_bytes", stat.read_bytes.to_string()),
            ("host.disk.written_bytes", stat.written_bytes.to_string()),
            ("host.disk.reads", stat.reads.to_string()),
            ("host.disk.writes", stat.writes.to_string()),
            (
                "host.disk.io_time_seconds",
                format!("{:.3}", stat.io_seconds),
            ),
        ] {
            labeled.push(MetricsLabeledFact {
                key: key.to_string(),
                value,
                labels: labels.clone(),
            });
        }
    }
}

/// macOS：IOKit 的统计挂在 `IOBlockStorageDriver`（**整盘**）上，
/// 同一物理盘的多个 APFS 卷会返回**同一组**计数。
///
/// 因此必须按整盘 bsd 名（`disk3s1` → `disk3`）去重后取组内最大值；
/// 逐卷相加会把 I/O 按卷数放大，属于伪造读数。
#[cfg(target_os = "macos")]
pub(super) fn collect_disk_io(disks: &Disks, labeled: &mut Vec<MetricsLabeledFact>) {
    let mut by_device: std::collections::BTreeMap<String, (u64, u64)> =
        std::collections::BTreeMap::new();
    for disk in disks.list() {
        // 网络/虚拟卷的 I/O 不属于本地块设备，混进来会污染“磁盘”语义。
        if !is_local_filesystem_mount(disk) {
            continue;
        }
        let device = macos_whole_disk(&disk.name().to_string_lossy());
        let usage = disk.usage();
        let entry = by_device.entry(device).or_insert((0, 0));
        entry.0 = entry.0.max(usage.total_read_bytes);
        entry.1 = entry.1.max(usage.total_written_bytes);
    }

    for (device, (read_bytes, written_bytes)) in by_device {
        // 两个计数都为 0 只可能是“读不到 I/O”，真实开机盘不可能一次读写都没有；
        // 不发比发一个假 0 安全。
        if read_bytes == 0 && written_bytes == 0 {
            continue;
        }
        let labels = vec![StringKeyValue::new("device", device)];
        for (key, value) in [
            ("host.disk.read_bytes", read_bytes.to_string()),
            ("host.disk.written_bytes", written_bytes.to_string()),
        ] {
            labeled.push(MetricsLabeledFact {
                key: key.to_string(),
                value,
                labels: labels.clone(),
            });
        }
    }
}

/// `disk3s1s1` → `disk3`：反复去掉尾部的 `s<数字>` 分段，得到整盘 bsd 名。
#[cfg(target_os = "macos")]
pub(super) fn macos_whole_disk(device: &str) -> String {
    let mut base = device.rsplit('/').next().unwrap_or(device).to_string();
    loop {
        let Some(index) = base.rfind('s') else {
            return base;
        };
        let (head, tail) = base.split_at(index);
        let is_volume_suffix =
            !head.is_empty() && tail.len() > 1 && tail[1..].chars().all(|c| c.is_ascii_digit());
        if !is_volume_suffix {
            return base;
        }
        base = head.to_string();
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(super) fn collect_disk_io(_disks: &Disks, _labeled: &mut Vec<MetricsLabeledFact>) {}

/// 内存使用率：`(total - available) / total`；总量未知返回 `None`（不发比例）。
pub(super) fn memory_usage_ratio(total: u64, available: u64) -> Option<f64> {
    if total == 0 {
        return None;
    }
    Some(total.saturating_sub(available.min(total)) as f64 / total as f64)
}

#[cfg(test)]
mod tests {
    use super::{choose_primary_host_ip, endpoint_authority, platform_source_ip};
    use crate::discovery::network::HostAddress;

    fn addr(iface: &str, ip: &str, default_route: bool) -> HostAddress {
        HostAddress {
            iface: iface.to_string(),
            ip: ip.to_string(),
            default_route,
        }
    }

    #[test]
    fn platform_route_wins_over_everything() {
        // 平台路由是「内核去平台时会用的源地址」：哪怕网卡字典序更小的存在，也用它。
        assert_eq!(
            choose_primary_host_ip(
                Some("10.0.0.7".to_string()),
                vec![
                    addr("br-1a2b3c4d", "172.19.0.1", false),
                    addr("eth0", "10.0.0.5", true),
                ],
            ),
            Some("10.0.0.7".to_string())
        );
    }

    #[test]
    fn default_route_interface_wins_without_a_platform_route() {
        // 没有平台路由时，选承担默认路由的接口（Linux `/proc/net/route`）。
        assert_eq!(
            choose_primary_host_ip(
                None,
                vec![
                    addr("br-1a2b3c4d", "172.19.0.1", false),
                    addr("docker0", "172.17.0.1", false),
                    addr("eth0", "10.0.0.5", true),
                ],
            ),
            Some("10.0.0.5".to_string())
        );
    }

    #[test]
    fn virtual_interfaces_are_skipped_in_the_fallback() {
        // 既没平台路由也没默认路由：字典序会先命中文档网桥，必须跳过。
        assert_eq!(
            choose_primary_host_ip(
                None,
                vec![
                    addr("bridge100", "192.168.139.3", false),
                    addr("docker0", "172.17.0.1", false),
                    addr("en0", "192.168.1.128", false),
                    addr("utun100", "100.64.0.9", false),
                ],
            ),
            Some("192.168.1.128".to_string())
        );
    }

    #[test]
    fn fallback_still_answers_when_every_interface_is_virtual() {
        // 容器里只有 eth0/veth 这类接口：宁可回一个地址，也不留空。
        assert_eq!(
            choose_primary_host_ip(
                None,
                vec![
                    addr("veth12ab", "172.19.0.2", false),
                    addr("docker0", "172.17.0.1", false),
                ],
            ),
            Some("172.17.0.1".to_string())
        );
    }

    #[test]
    fn no_addresses_means_no_host_ip() {
        // 取不到就不写（不补 127.0.0.1，也不写空串）。
        assert_eq!(choose_primary_host_ip(None, Vec::new()), None);
    }

    #[test]
    fn chooses_deterministically_by_interface_name_within_a_tier() {
        // 同为「非虚拟」：按接口名字典序，不依赖枚举顺序。
        assert_eq!(
            choose_primary_host_ip(
                None,
                vec![
                    addr("en1", "10.0.0.7", false),
                    addr("en0", "192.168.1.5", true),
                ],
            ),
            Some("192.168.1.5".to_string())
        );
    }

    #[test]
    fn endpoint_authority_strips_scheme_path_and_defaults_the_port() {
        assert_eq!(
            endpoint_authority("https://c-dev01.test.gw:3100/api/v1").as_deref(),
            Some("c-dev01.test.gw:3100")
        );
        assert_eq!(
            endpoint_authority("http://10.0.0.5").as_deref(),
            Some("10.0.0.5:80")
        );
        assert_eq!(
            endpoint_authority("https://gateway.example").as_deref(),
            Some("gateway.example:443")
        );
        assert_eq!(
            endpoint_authority("10.0.0.5:3000").as_deref(),
            Some("10.0.0.5:3000")
        );
        // 大写 scheme 一样按 http/https 判断默认端口。
        assert_eq!(
            endpoint_authority("HTTP://10.0.0.5").as_deref(),
            Some("10.0.0.5:80")
        );
        // IPv6 字面量带端口时原样透传（必须带端口，否则 `to_socket_addrs` 无法解析）。
        assert_eq!(
            endpoint_authority("https://[fd00::1]:443").as_deref(),
            Some("[fd00::1]:443")
        );
        assert_eq!(endpoint_authority("  "), None);
        assert_eq!(endpoint_authority("https://"), None);
    }

    #[test]
    fn platform_probe_rejects_loopback_and_unparseable_endpoints() {
        // 回环不是「平台眼里的这台机器」；解析不了 / 没端口也直接放弃（由默认路由兜底）。
        assert_eq!(platform_source_ip("http://127.0.0.1:9"), None);
        assert_eq!(platform_source_ip("[::1]:9"), None);
        assert_eq!(platform_source_ip(""), None);
    }
}
