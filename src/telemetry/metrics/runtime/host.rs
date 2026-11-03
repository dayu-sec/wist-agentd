//! 主机域采集：CPU、负载、内存、磁盘容量、逐挂载点文件系统、块设备 I/O。
//!
//! 只产出 `fact_key`（单位中立），指标名/单位/类型由 `wist-metrics` 注册表决定。

use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
use std::path::Path;

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

    // CPU：逐核逐 mode 的累计秒（不在这里求占用率）。
    for time in cpu::host_cpu_times() {
        labeled_facts.push(MetricsLabeledFact {
            key: "host.cpu.seconds".to_string(),
            value: format!("{:.3}", time.seconds),
            labels: vec![
                StringKeyValue::new("cpu", time.cpu),
                StringKeyValue::new("mode", time.mode),
            ],
        });
    }

    let loadavg = System::load_average();
    for (key, legacy_key, value) in [
        ("host.loadavg.1m", "legacy.host.loadavg.1m", loadavg.one),
        ("host.loadavg.5m", "legacy.host.loadavg.5m", loadavg.five),
        (
            "host.loadavg.15m",
            "legacy.host.loadavg.15m",
            loadavg.fifteen,
        ),
    ] {
        push_fact_if_absent(&mut facts, StringKeyValue::new(key, value.to_string()));
        // 双写期：同一读数按旧名再发一条，老看板不用改。
        push_fact_if_absent(
            &mut facts,
            StringKeyValue::new(legacy_key, value.to_string()),
        );
    }

    let uptime = System::uptime();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.uptime.seconds", uptime.to_string()),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("legacy.host.uptime.seconds", uptime.to_string()),
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
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new(
            "legacy.host.memory.total_kb",
            (total_memory / 1024).to_string(),
        ),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new(
            "legacy.host.memory.available_kb",
            (available_memory / 1024).to_string(),
        ),
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

    HostRuntimeFacts {
        facts,
        labeled_facts,
    }
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
        push_fact_if_absent(
            facts,
            StringKeyValue::new("legacy.host.disk.data.mount_count", data_mounts.to_string()),
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
    // 双写期：旧口径（percent / KiB）。
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("legacy.host.disk.{role}.usage_percent"),
            (usage_ratio * 100.0).to_string(),
        ),
    );
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("legacy.host.disk.{role}.total_kb"),
            (total / 1024).to_string(),
        ),
    );
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("legacy.host.disk.{role}.available_kb"),
            (available / 1024).to_string(),
        ),
    );
}

/// 逐挂载点文件系统容量：同一 fact key 的多条实例用 `mount` / `fstype` 标签区分。
///
/// 这是 `system.filesystem.*` 的来源；过渡版的 `host.disk.*` 汇总仍由
/// [`collect_host_disk_usage`] 产出，两者并存。
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
    facts.push(MetricsLabeledFact {
        key: "legacy.host.filesystem.usage_percent".to_string(),
        value: (usage_ratio * 100.0).to_string(),
        labels: labels.clone(),
    });
    facts.push(MetricsLabeledFact {
        key: "legacy.host.filesystem.total_kb".to_string(),
        value: (total / 1024).to_string(),
        labels: labels.clone(),
    });
    facts.push(MetricsLabeledFact {
        key: "legacy.host.filesystem.available_kb".to_string(),
        value: (available / 1024).to_string(),
        labels: labels.clone(),
    });
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
