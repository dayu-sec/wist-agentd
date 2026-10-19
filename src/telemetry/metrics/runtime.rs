//! Minimal metrics runtime tick built from target view.

use std::collections::HashSet;
#[cfg(target_os = "linux")]
use std::fs;
use std::io;
use std::path::Path;
#[cfg(all(unix, not(target_os = "linux")))]
use std::process::Command;

use serde::{Deserialize, Serialize};
use sysinfo::{Disks, System};
use wist_contracts::discovery::StringKeyValue;
use wist_shared::fs::write_json_atomic;

pub use wist_metrics::provider::{
    MetricProvider, MetricsCollectionOutcome, MetricsCollectionTargetSample, MetricsLabeledFact,
};

#[cfg(test)]
use super::target_view::path_for as target_view_path_for;
use super::target_view::{MetricsTargetView, MetricsTargetViewEntry};
#[cfg(test)]
use wist_shared::fs::read_json;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[serde(deny_unknown_fields)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct MetricsRuntimeSnapshot {
    pub generated_at: String,
    pub total_targets: usize,
    pub host_targets: usize,
    pub process_targets: usize,
    pub container_targets: usize,
    #[serde(default)]
    pub outcomes: Vec<MetricsCollectionOutcome>,
}

#[cfg(test)]
pub fn build_runtime_snapshot(state_dir: &Path) -> io::Result<MetricsRuntimeSnapshot> {
    let view: MetricsTargetView = read_json(&target_view_path_for(state_dir))?;
    Ok(build_runtime_snapshot_from_view(&view))
}

pub fn build_runtime_snapshot_from_view(view: &MetricsTargetView) -> MetricsRuntimeSnapshot {
    let mut host_targets = 0;
    let mut process_targets = 0;
    let mut container_targets = 0;

    for target in &view.targets {
        match target.collection_kind.as_str() {
            "host_metrics" => host_targets += 1,
            "process_metrics" => process_targets += 1,
            "container_metrics" => container_targets += 1,
            _ => {}
        }
    }

    let outcomes = providers()
        .iter()
        .map(|provider| {
            let targets: Vec<&MetricsTargetViewEntry> = view
                .targets
                .iter()
                .filter(|target| target.collection_kind == provider.collection_kind())
                .collect();
            provider.collect(targets)
        })
        .collect();

    MetricsRuntimeSnapshot {
        generated_at: view.generated_at.clone(),
        total_targets: host_targets + process_targets + container_targets,
        host_targets,
        process_targets,
        container_targets,
        outcomes,
    }
}

pub fn path_for(state_dir: &Path) -> std::path::PathBuf {
    state_dir
        .join("telemetry")
        .join("metrics_runtime_snapshot.json")
}

pub fn store(path: &Path, snapshot: &MetricsRuntimeSnapshot) -> io::Result<()> {
    write_json_atomic(path, snapshot)
}

fn build_host_outcome(
    attempted_targets: usize,
    mut sample_targets: Vec<MetricsCollectionTargetSample>,
) -> MetricsCollectionOutcome {
    if attempted_targets == 0 {
        return MetricsCollectionOutcome {
            collection_kind: "host_metrics".to_string(),
            status: "idle".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            last_error: None,
            runtime_facts: vec![StringKeyValue::new("host.target.count", "0")],
            labeled_facts: Vec::new(),
            sample_targets,
        };
    }

    let collected = collect_host_runtime_facts(&sample_targets);
    let runtime_facts = collected.facts;
    let labeled_facts = collected.labeled_facts;
    if runtime_facts.is_empty() && labeled_facts.is_empty() {
        for sample in &mut sample_targets {
            sample.status = "failed".to_string();
            sample.last_error = Some("host metrics probe produced no runtime facts".to_string());
        }
        MetricsCollectionOutcome {
            collection_kind: "host_metrics".to_string(),
            status: "failed".to_string(),
            attempted_targets,
            succeeded_targets: 0,
            failed_targets: attempted_targets,
            last_error: Some("host metrics probe produced no runtime facts".to_string()),
            runtime_facts: vec![StringKeyValue::new(
                "host.target.count",
                attempted_targets.to_string(),
            )],
            labeled_facts: Vec::new(),
            sample_targets,
        }
    } else {
        let mut runtime_facts = runtime_facts;
        push_fact_if_absent(
            &mut runtime_facts,
            StringKeyValue::new("host.target.count", attempted_targets.to_string()),
        );
        for sample in &mut sample_targets {
            sample.status = "succeeded".to_string();
            sample.runtime_facts = runtime_facts.clone();
            sample.labeled_facts = labeled_facts.clone();
        }
        MetricsCollectionOutcome {
            collection_kind: "host_metrics".to_string(),
            status: "succeeded".to_string(),
            attempted_targets,
            succeeded_targets: attempted_targets,
            failed_targets: 0,
            last_error: None,
            runtime_facts,
            labeled_facts,
            sample_targets,
        }
    }
}

fn build_process_outcome(targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
    if targets.is_empty() {
        return MetricsCollectionOutcome {
            collection_kind: "process_metrics".to_string(),
            status: "idle".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        };
    }

    let mut succeeded_targets = 0usize;
    let mut failed_targets = 0usize;
    let mut sample_targets = Vec::new();
    let mut last_error = None;

    for target in &targets {
        let probed = probe_process_target(target);
        if probed.status == "succeeded" {
            succeeded_targets += 1;
        } else {
            failed_targets += 1;
            if last_error.is_none() {
                last_error = probed.last_error.clone();
            }
        }
        if sample_targets.len() < 3 {
            sample_targets.push(probed);
        }
    }

    let status = if failed_targets == 0 {
        "succeeded"
    } else if succeeded_targets == 0 {
        "failed"
    } else {
        "partial"
    };

    MetricsCollectionOutcome {
        collection_kind: "process_metrics".to_string(),
        status: status.to_string(),
        attempted_targets: targets.len(),
        succeeded_targets,
        failed_targets,
        last_error,
        runtime_facts: vec![
            StringKeyValue::new("process.probe.mode", process_probe_mode()),
            StringKeyValue::new("process.probe.success_count", succeeded_targets.to_string()),
            StringKeyValue::new("process.probe.failed_count", failed_targets.to_string()),
        ],
        labeled_facts: Vec::new(),
        sample_targets,
    }
}

fn build_container_outcome(targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
    if targets.is_empty() {
        return MetricsCollectionOutcome {
            collection_kind: "container_metrics".to_string(),
            status: "idle".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        };
    }

    let mut succeeded_targets = 0usize;
    let mut failed_targets = 0usize;
    let mut sample_targets = Vec::new();
    let mut last_error = None;

    for target in &targets {
        let probed = probe_container_target(target);
        if probed.status == "failed" {
            failed_targets += 1;
            if last_error.is_none() {
                last_error = probed.last_error.clone();
            }
        } else {
            succeeded_targets += 1;
        }
        if sample_targets.len() < 3 {
            sample_targets.push(probed);
        }
    }

    let status = if failed_targets == 0 {
        "succeeded"
    } else if succeeded_targets == 0 {
        "failed"
    } else {
        "partial"
    };

    MetricsCollectionOutcome {
        collection_kind: "container_metrics".to_string(),
        status: status.to_string(),
        attempted_targets: targets.len(),
        succeeded_targets,
        failed_targets,
        last_error,
        runtime_facts: vec![
            StringKeyValue::new("container.probe.mode", container_probe_mode()),
            StringKeyValue::new(
                "container.probe.success_count",
                succeeded_targets.to_string(),
            ),
            StringKeyValue::new("container.probe.failed_count", failed_targets.to_string()),
        ],
        labeled_facts: Vec::new(),
        sample_targets,
    }
}

/// 编译期注册的 provider 列表；新增一类指标 = 加一个 provider 并在这里登记。
pub(crate) fn providers() -> &'static [&'static dyn MetricProvider] {
    &[
        &HostMetricsProvider,
        &ProcessMetricsProvider,
        &ContainerMetricsProvider,
    ]
}

pub struct HostMetricsProvider;
pub struct ProcessMetricsProvider;
pub struct ContainerMetricsProvider;

impl MetricProvider for HostMetricsProvider {
    fn collection_kind(&self) -> &'static str {
        "host_metrics"
    }

    fn collect(&self, targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
        let mut sample_targets = Vec::new();
        for target in &targets {
            maybe_push_sample(&mut sample_targets, target);
        }
        build_host_outcome(targets.len(), sample_targets)
    }
}

impl MetricProvider for ProcessMetricsProvider {
    fn collection_kind(&self) -> &'static str {
        "process_metrics"
    }

    fn collect(&self, targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
        build_process_outcome(targets)
    }
}

impl MetricProvider for ContainerMetricsProvider {
    fn collection_kind(&self) -> &'static str {
        "container_metrics"
    }

    fn collect(&self, targets: Vec<&MetricsTargetViewEntry>) -> MetricsCollectionOutcome {
        build_container_outcome(targets)
    }
}

struct HostRuntimeFacts {
    facts: Vec<StringKeyValue>,
    labeled_facts: Vec<MetricsLabeledFact>,
}

fn collect_host_runtime_facts(
    sample_targets: &[MetricsCollectionTargetSample],
) -> HostRuntimeFacts {
    let mut facts = Vec::new();
    let mut labeled_facts = Vec::new();

    for sample in sample_targets {
        for hint in &sample.execution_hints {
            if hint.key == "host.name" {
                push_fact_if_absent(&mut facts, hint.clone());
            }
        }
    }

    let loadavg = System::load_average();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.loadavg.1m", loadavg.one.to_string()),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.loadavg.5m", loadavg.five.to_string()),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.loadavg.15m", loadavg.fifteen.to_string()),
    );

    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("host.uptime.seconds", System::uptime().to_string()),
    );

    let mut system = System::new();
    system.refresh_memory();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new(
            "host.memory.total_kb",
            (system.total_memory() / 1024).to_string(),
        ),
    );
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new(
            "host.memory.available_kb",
            (system.available_memory() / 1024).to_string(),
        ),
    );

    let disks = Disks::new_with_refreshed_list();
    collect_host_disk_usage(&disks, &mut facts);
    collect_host_filesystem_usage(&disks, &mut labeled_facts);

    HostRuntimeFacts {
        facts,
        labeled_facts,
    }
}

fn collect_host_disk_usage(disks: &Disks, facts: &mut Vec<StringKeyValue>) {
    if cfg!(target_os = "linux") {
        collect_linux_disk_usage(disks, facts);
    } else {
        collect_primary_disk_usage(disks, facts);
    }
}

/// 非 Linux 平台只报「主盘」：macOS APFS 把用户数据放在 Data 卷（`/` 只是只读系统快照），
/// 所以优先取 Data、回落到 `/`；其它 Unix 取 `/`。
fn collect_primary_disk_usage(disks: &Disks, facts: &mut Vec<StringKeyValue>) {
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
        push_disk_capacity_facts(facts, "", disk.total_space(), disk.available_space());
        return;
    }
}

/// Linux 把容量拆成两个角色：
/// - `system`：根文件系统 `/`（系统盘）；
/// - `data`：其余本地块设备挂载点（数据盘）。多块数据盘按容量汇总，
///   同一设备被 bind mount 到多个路径时只算一次。
///
/// 原有的 `host.disk.*` 保持为系统盘，兼容既有网关接口与页面。
fn collect_linux_disk_usage(disks: &Disks, facts: &mut Vec<StringKeyValue>) {
    let Some(root) = disks
        .list()
        .iter()
        .find(|disk| disk.mount_point() == Path::new("/"))
    else {
        return;
    };
    let root_total = root.total_space();
    let root_available = root.available_space();
    push_disk_capacity_facts(facts, "", root_total, root_available);
    push_disk_capacity_facts(facts, "system.", root_total, root_available);

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
        push_disk_capacity_facts(facts, "data.", data_total, data_available);
        push_fact_if_absent(
            facts,
            StringKeyValue::new("host.disk.data.mount_count", data_mounts.to_string()),
        );
    }
}

/// 是否计入 Linux「数据盘」。
///
/// `sysinfo::Disks` 已经过滤掉 proc/sys/devtmpfs/tmpfs/NFS 等虚拟或网络挂载；
/// 这里再排除根（系统盘）、引导分区、运行期目录与容器叠加层，避免把系统自身
/// 或临时文件系统误算成数据盘。
fn is_linux_data_mount(disk: &sysinfo::Disk) -> bool {
    is_linux_data_mount_point(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
    )
}

fn is_linux_data_mount_point(mount: &str, file_system: &str, total_space: u64) -> bool {
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

fn push_disk_capacity_facts(
    facts: &mut Vec<StringKeyValue>,
    prefix: &str,
    total: u64,
    available: u64,
) {
    let available = available.min(total);
    let used = total.saturating_sub(available);
    let usage_percent = if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    };
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("host.disk.{prefix}usage_percent"),
            usage_percent.to_string(),
        ),
    );
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("host.disk.{prefix}total_kb"),
            (total / 1024).to_string(),
        ),
    );
    push_fact_if_absent(
        facts,
        StringKeyValue::new(
            format!("host.disk.{prefix}available_kb"),
            (available / 1024).to_string(),
        ),
    );
}

/// 逐挂载点文件系统容量：同一 fact key 的多条实例用 `mount` / `fstype` 标签区分。
///
/// 这是 `system.filesystem.*` 的来源；过渡版的 `host.disk.*` 汇总仍由
/// [`collect_host_disk_usage`] 产出，两者并存。
fn collect_host_filesystem_usage(disks: &Disks, facts: &mut Vec<MetricsLabeledFact>) {
    if cfg!(target_os = "linux") {
        collect_linux_filesystems(disks, facts);
    } else if cfg!(target_os = "macos") {
        collect_macos_filesystems(disks, facts);
    }
}

fn collect_linux_filesystems(disks: &Disks, facts: &mut Vec<MetricsLabeledFact>) {
    let mut seen_devices = HashSet::new();
    // 先固定根文件系统为规范挂载点，避免它的 bind mount 先出现时把 `/` 顶掉。
    if let Some(root) = disks
        .list()
        .iter()
        .find(|disk| disk.mount_point() == Path::new("/"))
        && is_linux_filesystem_mount(root)
    {
        let device = root.name().to_string_lossy();
        seen_devices.insert(filesystem_dedupe_key(&device, "/"));
        push_filesystem_facts(facts, root);
    }
    for disk in disks.list() {
        if !is_linux_filesystem_mount(disk) {
            continue;
        }
        let device = disk.name().to_string_lossy();
        let key = filesystem_dedupe_key(&device, &disk.mount_point().to_string_lossy());
        // 同一文件系统被 bind mount 到多个路径时只报一次（取最先出现的挂载点）。
        if !seen_devices.insert(key) {
            continue;
        }
        push_filesystem_facts(facts, disk);
    }
}

fn collect_macos_filesystems(disks: &Disks, facts: &mut Vec<MetricsLabeledFact>) {
    let mut seen_devices = HashSet::new();
    // Data 卷优先作为内部容量的规范挂载点；`/` 只读，排在它后面。
    for preferred in ["/System/Volumes/Data", "/"] {
        if let Some(disk) = disks
            .list()
            .iter()
            .find(|disk| disk.mount_point() == Path::new(preferred))
            && is_macos_filesystem_mount(disk)
        {
            let device = disk.name().to_string_lossy();
            seen_devices.insert(filesystem_dedupe_key(&device, preferred));
            push_filesystem_facts(facts, disk);
        }
    }
    for disk in disks.list() {
        if !is_macos_filesystem_mount(disk) {
            continue;
        }
        let device = disk.name().to_string_lossy();
        let key = filesystem_dedupe_key(&device, &disk.mount_point().to_string_lossy());
        if !seen_devices.insert(key) {
            continue;
        }
        push_filesystem_facts(facts, disk);
    }
}

/// 同一设备（bind mount / btrfs 子卷）只保留第一条；设备名为空时用挂载点兜底。
fn filesystem_dedupe_key(device: &str, mount: &str) -> String {
    if device.is_empty() {
        format!("mount:{mount}")
    } else {
        device.to_string()
    }
}

fn is_linux_filesystem_mount(disk: &sysinfo::Disk) -> bool {
    is_linux_filesystem_mount_point(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
    )
}

fn is_linux_filesystem_mount_point(mount: &str, file_system: &str, total_space: u64) -> bool {
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

fn is_macos_filesystem_mount(disk: &sysinfo::Disk) -> bool {
    is_macos_filesystem_mount_point(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
    )
}

fn is_macos_filesystem_mount_point(mount: &str, file_system: &str, total_space: u64) -> bool {
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

fn is_excluded_filesystem(file_system: &str) -> bool {
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

fn push_filesystem_facts(facts: &mut Vec<MetricsLabeledFact>, disk: &sysinfo::Disk) {
    facts.extend(filesystem_facts(
        &disk.mount_point().to_string_lossy(),
        &disk.file_system().to_string_lossy(),
        disk.total_space(),
        disk.available_space(),
    ));
}

fn filesystem_facts(
    mount: &str,
    file_system: &str,
    total: u64,
    available: u64,
) -> Vec<MetricsLabeledFact> {
    let available = available.min(total);
    let used = total.saturating_sub(available);
    let usage_percent = if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    };
    let mut labels = vec![StringKeyValue::new("mount", mount)];
    if !file_system.is_empty() {
        labels.push(StringKeyValue::new("fstype", file_system));
    }
    vec![
        MetricsLabeledFact {
            key: "host.filesystem.usage_percent".to_string(),
            value: usage_percent.to_string(),
            labels: labels.clone(),
        },
        MetricsLabeledFact {
            key: "host.filesystem.total_kb".to_string(),
            value: (total / 1024).to_string(),
            labels: labels.clone(),
        },
        MetricsLabeledFact {
            key: "host.filesystem.available_kb".to_string(),
            value: (available / 1024).to_string(),
            labels,
        },
    ]
}

fn push_fact_if_absent(facts: &mut Vec<StringKeyValue>, candidate: StringKeyValue) {
    if facts.iter().any(|fact| fact.key == candidate.key) {
        return;
    }
    facts.push(candidate);
}

fn maybe_push_sample(
    samples: &mut Vec<MetricsCollectionTargetSample>,
    target: &MetricsTargetViewEntry,
) {
    const SAMPLE_LIMIT: usize = 3;

    if samples.len() >= SAMPLE_LIMIT {
        return;
    }

    samples.push(MetricsCollectionTargetSample {
        candidate_id: target.candidate_id.clone(),
        target_ref: target.target_ref.clone(),
        status: "pending".to_string(),
        last_error: None,
        resource_ref: target.resource_ref.clone(),
        execution_hints: target.execution_hints.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
    });
}

fn probe_process_target(target: &MetricsTargetViewEntry) -> MetricsCollectionTargetSample {
    let mut sample = MetricsCollectionTargetSample {
        candidate_id: target.candidate_id.clone(),
        target_ref: target.target_ref.clone(),
        status: "failed".to_string(),
        last_error: None,
        resource_ref: target.resource_ref.clone(),
        execution_hints: target.execution_hints.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
    };

    let Some(pid) = target
        .execution_hints
        .iter()
        .find(|hint| hint.key == "process.pid")
        .and_then(|hint| hint.value.parse::<u32>().ok())
    else {
        sample.last_error = Some("process.pid execution hint missing".to_string());
        return sample;
    };

    match collect_process_runtime_facts(pid, &sample.execution_hints) {
        Ok(runtime_facts) => {
            sample.status = "succeeded".to_string();
            sample.runtime_facts = runtime_facts;
            sample
        }
        Err(err) => {
            sample.last_error = Some(err.to_string());
            sample
        }
    }
}

fn probe_container_target(target: &MetricsTargetViewEntry) -> MetricsCollectionTargetSample {
    let mut sample = MetricsCollectionTargetSample {
        candidate_id: target.candidate_id.clone(),
        target_ref: target.target_ref.clone(),
        status: "failed".to_string(),
        last_error: None,
        resource_ref: target.resource_ref.clone(),
        execution_hints: target.execution_hints.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
    };

    let mut facts = Vec::new();
    for hint in &sample.execution_hints {
        if matches!(
            hint.key.as_str(),
            "container.runtime"
                | "container.runtime.namespace"
                | "cgroup.path"
                | "k8s.namespace.name"
                | "k8s.pod.uid"
                | "k8s.pod.name"
                | "k8s.container.name"
        ) {
            push_fact_if_absent(&mut facts, hint.clone());
        }
    }

    let mut process_probe_error = None;
    if let Some(pid) = sample
        .execution_hints
        .iter()
        .find(|hint| hint.key == "pid")
        .and_then(|hint| hint.value.parse::<u32>().ok())
    {
        match collect_process_runtime_facts(pid, &[]) {
            Ok(process_facts) => {
                push_fact_if_absent(
                    &mut facts,
                    StringKeyValue::new("container.pid", pid.to_string()),
                );
                for fact in process_facts {
                    push_fact_if_absent(&mut facts, fact);
                }
            }
            Err(err) => {
                process_probe_error = Some(err.to_string());
            }
        }
    }

    if facts.is_empty() {
        sample.last_error = process_probe_error
            .or_else(|| Some("container metrics probe produced no runtime facts".to_string()));
        return sample;
    }

    sample.status = if process_probe_error.is_some() {
        "partial".to_string()
    } else {
        "succeeded".to_string()
    };
    sample.last_error = process_probe_error;
    sample.runtime_facts = facts;
    sample
}

fn collect_process_runtime_facts(
    pid: u32,
    execution_hints: &[StringKeyValue],
) -> io::Result<Vec<StringKeyValue>> {
    let mut facts = Vec::new();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("process.pid", pid.to_string()),
    );
    for hint in execution_hints {
        if matches!(
            hint.key.as_str(),
            "process.identity" | "discovery.identity_strength" | "discovery.identity_status"
        ) {
            push_fact_if_absent(&mut facts, hint.clone());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        if let Some(state) = parse_linux_proc_state(&stat) {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.state", state.to_string()),
            );
        }
        if let Some(rss_pages) = parse_linux_proc_rss_pages(&stat) {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.memory.rss_pages", rss_pages.to_string()),
            );
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = Command::new("ps")
            .args(["-o", "state=,rss=,comm=", "-p", &pid.to_string()])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("ps did not exit successfully"));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.trim();
        if line.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "ps returned no process row",
            ));
        }
        let mut parts = line.split_whitespace();
        if let Some(state) = parts.next() {
            push_fact_if_absent(&mut facts, StringKeyValue::new("process.state", state));
        }
        if let Some(rss_kb) = parts.next() {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.memory.rss_kb", rss_kb),
            );
        }
        if let Some(comm) = parts.next() {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.executable.name", comm),
            );
        }
    }

    #[cfg(not(unix))]
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process metrics probe unsupported on this platform",
        ));
    }

    Ok(facts)
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_state(stat: &str) -> Option<char> {
    let (_, tail) = stat.rsplit_once(") ")?;
    tail.chars().next()
}

#[cfg(target_os = "linux")]
fn parse_linux_proc_rss_pages(stat: &str) -> Option<i64> {
    let (_, tail) = stat.rsplit_once(") ")?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    if fields.len() <= 21 {
        return None;
    }
    fields.get(21)?.parse().ok()
}

fn process_probe_mode() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "procfs"
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        "ps"
    }
    #[cfg(not(unix))]
    {
        "unsupported"
    }
}

fn container_probe_mode() -> &'static str {
    "discovery_hints"
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::{MetricsRuntimeSnapshot, build_runtime_snapshot, path_for, store};
    use crate::telemetry::metrics::target_view::{MetricsTargetView, MetricsTargetViewEntry};
    use wist_contracts::discovery::StringKeyValue;

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("warp-insight-metrics-runtime-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn build_runtime_snapshot_counts_batch_a_targets() {
        let state_dir = temp_dir("counts");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![
                MetricsTargetViewEntry {
                    candidate_id: "host-1".to_string(),
                    collection_kind: "host_metrics".to_string(),
                    target_ref: "host-1:host".to_string(),
                    resource_ref: "host-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("host.name", "local-host")],
                },
                MetricsTargetViewEntry {
                    candidate_id: "proc-1".to_string(),
                    collection_kind: "process_metrics".to_string(),
                    target_ref: "proc-1".to_string(),
                    resource_ref: "proc-1".to_string(),
                    execution_hints: vec![StringKeyValue::new("process.pid", "42")],
                },
                MetricsTargetViewEntry {
                    candidate_id: "container-1".to_string(),
                    collection_kind: "container_metrics".to_string(),
                    target_ref: "container-1".to_string(),
                    resource_ref: "container-1".to_string(),
                    execution_hints: vec![
                        StringKeyValue::new("container.runtime", "containerd"),
                        StringKeyValue::new("pid", std::process::id().to_string()),
                    ],
                },
            ],
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");

        assert_eq!(snapshot.generated_at, "2026-04-19T00:00:00Z");
        assert_eq!(snapshot.total_targets, 3);
        assert_eq!(snapshot.host_targets, 1);
        assert_eq!(snapshot.process_targets, 1);
        assert_eq!(snapshot.container_targets, 1);

        let host_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "host_metrics")
            .expect("host outcome");
        assert_eq!(host_outcome.status, "succeeded");
        assert_eq!(host_outcome.attempted_targets, 1);
        assert_eq!(host_outcome.succeeded_targets, 1);
        assert_eq!(host_outcome.failed_targets, 0);
        assert!(host_outcome.last_error.is_none());
        assert!(!host_outcome.runtime_facts.is_empty());
        assert_eq!(host_outcome.sample_targets.len(), 1);

        let process_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "process_metrics")
            .expect("process outcome");
        assert!(matches!(
            process_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(process_outcome.attempted_targets, 1);
        assert_eq!(
            process_outcome.succeeded_targets + process_outcome.failed_targets,
            1
        );
        assert!(!process_outcome.runtime_facts.is_empty());
        assert_eq!(process_outcome.sample_targets.len(), 1);
        assert_eq!(
            process_outcome.sample_targets[0].status,
            if process_outcome.succeeded_targets == 1 {
                "succeeded"
            } else {
                "failed"
            }
        );

        let container_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "container_metrics")
            .expect("container outcome");
        assert!(matches!(
            container_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(container_outcome.attempted_targets, 1);
        assert_eq!(
            container_outcome.succeeded_targets + container_outcome.failed_targets,
            1
        );
        assert!(!container_outcome.runtime_facts.is_empty());
        assert_eq!(container_outcome.sample_targets.len(), 1);
    }

    #[test]
    fn store_runtime_snapshot_round_trip() {
        let state_dir = temp_dir("store");
        let snapshot = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 0,
            host_targets: 0,
            process_targets: 0,
            container_targets: 0,
            outcomes: vec![
                super::MetricsCollectionOutcome {
                    collection_kind: "host_metrics".to_string(),
                    status: "idle".to_string(),
                    attempted_targets: 0,
                    succeeded_targets: 0,
                    failed_targets: 0,
                    last_error: None,
                    runtime_facts: Vec::new(),
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
                super::MetricsCollectionOutcome {
                    collection_kind: "process_metrics".to_string(),
                    status: "idle".to_string(),
                    attempted_targets: 0,
                    succeeded_targets: 0,
                    failed_targets: 0,
                    last_error: None,
                    runtime_facts: Vec::new(),
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
                super::MetricsCollectionOutcome {
                    collection_kind: "container_metrics".to_string(),
                    status: "idle".to_string(),
                    attempted_targets: 0,
                    succeeded_targets: 0,
                    failed_targets: 0,
                    last_error: None,
                    runtime_facts: Vec::new(),
                    labeled_facts: Vec::new(),
                    sample_targets: Vec::new(),
                },
            ],
        };
        let snapshot_path = path_for(&state_dir);

        store(&snapshot_path, &snapshot).expect("store runtime snapshot");
        let loaded: MetricsRuntimeSnapshot =
            wist_shared::fs::read_json(&snapshot_path).expect("load runtime snapshot");

        assert_eq!(loaded, snapshot);
    }

    #[test]
    fn build_runtime_snapshot_limits_samples_per_collection_kind() {
        let state_dir = temp_dir("sample-limit");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: (0..5)
                .map(|idx| MetricsTargetViewEntry {
                    candidate_id: format!("proc-{idx}"),
                    collection_kind: "process_metrics".to_string(),
                    target_ref: format!("proc-{idx}"),
                    resource_ref: format!("proc-{idx}"),
                    execution_hints: vec![StringKeyValue::new("process.pid", idx.to_string())],
                })
                .collect(),
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");
        let process_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "process_metrics")
            .expect("process outcome");

        assert_eq!(process_outcome.attempted_targets, 5);
        assert_eq!(
            process_outcome.succeeded_targets + process_outcome.failed_targets,
            5
        );
        assert!(matches!(
            process_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(process_outcome.sample_targets.len(), 3);
    }

    #[test]
    fn build_runtime_snapshot_marks_process_target_failed_when_pid_hint_missing() {
        let state_dir = temp_dir("process-missing-pid");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![MetricsTargetViewEntry {
                candidate_id: "proc-1".to_string(),
                collection_kind: "process_metrics".to_string(),
                target_ref: "proc-1".to_string(),
                resource_ref: "proc-1".to_string(),
                execution_hints: vec![StringKeyValue::new("process.identity", "demo")],
            }],
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");
        let process_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "process_metrics")
            .expect("process outcome");

        assert_eq!(process_outcome.status, "failed");
        assert_eq!(process_outcome.attempted_targets, 1);
        assert_eq!(process_outcome.succeeded_targets, 0);
        assert_eq!(process_outcome.failed_targets, 1);
        assert!(
            process_outcome
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("process.pid"))
        );
        assert_eq!(process_outcome.sample_targets.len(), 1);
        assert_eq!(process_outcome.sample_targets[0].status, "failed");
    }

    #[test]
    fn build_runtime_snapshot_marks_container_target_failed_when_hints_missing() {
        let state_dir = temp_dir("container-missing-hints");
        let target_view = MetricsTargetView {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            targets: vec![MetricsTargetViewEntry {
                candidate_id: "container-1".to_string(),
                collection_kind: "container_metrics".to_string(),
                target_ref: "container-1".to_string(),
                resource_ref: "container-1".to_string(),
                execution_hints: Vec::new(),
            }],
        };
        crate::telemetry::metrics::target_view::store(
            &crate::telemetry::metrics::target_view::path_for(&state_dir),
            &target_view,
        )
        .expect("store target view");

        let snapshot = build_runtime_snapshot(&state_dir).expect("build runtime snapshot");
        let container_outcome = snapshot
            .outcomes
            .iter()
            .find(|outcome| outcome.collection_kind == "container_metrics")
            .expect("container outcome");

        assert_eq!(container_outcome.status, "failed");
        assert_eq!(container_outcome.attempted_targets, 1);
        assert_eq!(container_outcome.succeeded_targets, 0);
        assert_eq!(container_outcome.failed_targets, 1);
        assert!(
            container_outcome
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("no runtime facts"))
        );
        assert_eq!(container_outcome.sample_targets.len(), 1);
        assert_eq!(container_outcome.sample_targets[0].status, "failed");
    }

    #[test]
    fn provider_registry_covers_batch_a_kinds() {
        let kinds: Vec<&str> = super::providers()
            .iter()
            .map(|provider| provider.collection_kind())
            .collect();
        assert_eq!(
            kinds,
            vec!["host_metrics", "process_metrics", "container_metrics"]
        );
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_host_runtime_facts_are_collected() {
        let facts = super::collect_host_runtime_facts(&[]).facts;
        let fact_value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        for key in ["host.loadavg.1m", "host.loadavg.5m", "host.loadavg.15m"] {
            let value = fact_value(key).unwrap_or_else(|| panic!("missing fact {key}"));
            assert!(
                value.parse::<f64>().is_ok(),
                "{key} should parse as f64, got {value:?}"
            );
        }

        let uptime = fact_value("host.uptime.seconds").expect("host.uptime.seconds");
        let uptime: f64 = uptime.parse().expect("uptime should parse as f64");
        assert!(uptime >= 0.0, "uptime should be non-negative, got {uptime}");

        let total = fact_value("host.memory.total_kb").expect("host.memory.total_kb");
        let total: i64 = total.parse().expect("total should parse as i64");
        assert!(total > 0, "total memory should be positive, got {total}");

        let available = fact_value("host.memory.available_kb").expect("host.memory.available_kb");
        let available: i64 = available.parse().expect("available should parse as i64");
        assert!(
            available > 0,
            "available memory should be positive, got {available}"
        );
    }

    #[cfg(unix)]
    #[test]
    fn host_disk_runtime_facts_are_collected() {
        let facts = super::collect_host_runtime_facts(&[]).facts;
        let fact_value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        let usage = fact_value("host.disk.usage_percent").expect("host.disk.usage_percent");
        let usage: f64 = usage.parse().expect("usage should parse as f64");
        assert!(
            (0.0..=100.0).contains(&usage),
            "usage should be 0..=100, got {usage}"
        );

        let total = fact_value("host.disk.total_kb").expect("host.disk.total_kb");
        let total: i64 = total.parse().expect("total should parse as i64");
        assert!(total > 0, "total disk should be positive, got {total}");

        let available = fact_value("host.disk.available_kb").expect("host.disk.available_kb");
        let available: i64 = available.parse().expect("available should parse as i64");
        assert!(
            available >= 0,
            "available disk should be non-negative, got {available}"
        );

        // Linux 额外提供系统盘 / 数据盘两个显式角色；兼容键等同系统盘。
        #[cfg(target_os = "linux")]
        {
            let system_usage = fact_value("host.disk.system.usage_percent")
                .expect("host.disk.system.usage_percent");
            assert_eq!(
                system_usage,
                fact_value("host.disk.usage_percent").expect("host.disk.usage_percent")
            );
            let system_total =
                fact_value("host.disk.system.total_kb").expect("host.disk.system.total_kb");
            assert_eq!(
                system_total,
                fact_value("host.disk.total_kb").expect("host.disk.total_kb")
            );
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos"))]
    #[test]
    fn host_filesystem_runtime_facts_carry_mount_labels() {
        let collected = super::collect_host_runtime_facts(&[]);
        let usage = collected
            .labeled_facts
            .iter()
            .find(|fact| fact.key == "host.filesystem.usage_percent")
            .expect("host.filesystem.usage_percent");
        let mount = usage
            .labels
            .iter()
            .find(|label| label.key == "mount")
            .expect("mount label");
        let fstype = usage
            .labels
            .iter()
            .find(|label| label.key == "fstype")
            .expect("fstype label");
        assert!(!mount.value.is_empty());
        assert!(!fstype.value.is_empty());
        let usage: f64 = usage.value.parse().expect("usage should parse as f64");
        assert!(
            (0.0..=100.0).contains(&usage),
            "usage should be 0..=100, got {usage}"
        );

        #[cfg(target_os = "linux")]
        assert!(
            collected
                .labeled_facts
                .iter()
                .any(|fact| fact.key == "host.filesystem.usage_percent"
                    && fact
                        .labels
                        .iter()
                        .any(|label| label.key == "mount" && label.value == "/")),
            "root filesystem should be collected on Linux"
        );
    }

    #[test]
    fn host_provider_carries_labeled_facts_to_outcome_and_sample_targets() {
        use super::MetricProvider;

        let target = MetricsTargetViewEntry {
            candidate_id: "host-1:host:host_metrics".to_string(),
            collection_kind: "host_metrics".to_string(),
            target_ref: "host-1:host".to_string(),
            resource_ref: "host-1".to_string(),
            execution_hints: vec![StringKeyValue::new("host.name", "host-a")],
        };

        let outcome = super::HostMetricsProvider.collect(vec![&target]);

        assert_eq!(outcome.status, "succeeded");
        assert!(
            outcome
                .labeled_facts
                .iter()
                .any(|fact| fact.key == "host.filesystem.usage_percent"),
            "outcome should carry filesystem facts"
        );
        assert_eq!(outcome.sample_targets.len(), 1);
        assert_eq!(
            outcome.sample_targets[0].labeled_facts,
            outcome.labeled_facts
        );
    }

    #[test]
    fn disk_capacity_facts_derive_usage_from_total_and_available() {
        let mut facts = Vec::new();
        super::push_disk_capacity_facts(&mut facts, "data.", 4096, 1024);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        assert_eq!(value("host.disk.data.usage_percent"), Some("75"));
        assert_eq!(value("host.disk.data.total_kb"), Some("4"));
        assert_eq!(value("host.disk.data.available_kb"), Some("1"));
    }

    #[test]
    fn linux_data_mounts_exclude_system_and_virtual_filesystems() {
        let is_data = super::is_linux_data_mount_point;

        assert!(is_data("/data", "ext4", 100));
        assert!(is_data("/home", "xfs", 100));
        assert!(is_data("/var/lib/docker", "ext4", 100));

        assert!(!is_data("/", "ext4", 100));
        assert!(!is_data("/boot", "ext4", 100));
        assert!(!is_data("/boot/efi", "vfat", 100));
        assert!(!is_data("/run/media/u/disk", "ext4", 100));
        assert!(!is_data("/sys/fs/cgroup", "cgroup2", 100));
        assert!(!is_data("/proc", "proc", 100));
        assert!(!is_data("/data", "overlay", 100));
        assert!(!is_data("/data", "fuse.sshfs", 100));
        assert!(!is_data("/data", "nfs", 100));
        assert!(!is_data("/data", "ceph", 100));
        assert!(!is_data("/data", "tmpfs", 100));
        assert!(!is_data("/data", "ext4", 0));
    }

    #[test]
    fn linux_filesystem_mount_filter_excludes_virtual_and_network_mounts() {
        let include = super::is_linux_filesystem_mount_point;

        assert!(include("/", "ext4", 100));
        assert!(include("/data", "xfs", 100));
        assert!(include("/var/lib/docker", "ext4", 100));
        assert!(include("/data", "zfs", 100));

        assert!(!include("/boot", "ext4", 100));
        assert!(!include("/boot/efi", "vfat", 100));
        assert!(!include("/run", "tmpfs", 100));
        assert!(!include("/run/media/u/disk", "ext4", 100));
        assert!(!include("/sys/fs/cgroup", "cgroup2", 100));
        assert!(!include("/proc", "proc", 100));
        assert!(!include("/dev/shm", "tmpfs", 100));
        assert!(!include("/data", "overlay", 100));
        assert!(!include("/data", "squashfs", 100));
        assert!(!include("/data", "fuse.sshfs", 100));
        assert!(!include("/data", "nfs4", 100));
        assert!(!include("/data", "ceph", 100));
        assert!(!include("/data", "lustre", 100));
        assert!(!include("/data", "virtiofs", 100));
        assert!(!include("/data", "ext4", 0));
    }

    #[test]
    fn macos_filesystem_mount_filter_keeps_data_and_local_volumes() {
        let include = super::is_macos_filesystem_mount_point;

        assert!(include("/", "apfs", 100));
        assert!(include("/System/Volumes/Data", "apfs", 100));
        assert!(include("/Volumes/Backup", "apfs", 100));
        assert!(include("/Volumes/USB", "exfat", 100));
        assert!(include("/Volumes/Installer", "hfs", 100));

        assert!(!include("/System/Volumes/Preboot", "apfs", 100));
        assert!(!include("/System/Volumes/VM", "apfs", 100));
        assert!(!include("/Volumes/net", "smbfs", 100));
        assert!(!include("/Volumes/net", "nfs", 100));
        assert!(!include("/Volumes/net", "webdav", 100));
        assert!(!include("/Volumes/net", "afpfs", 100));
        assert!(!include("/private/var/vm", "apfs", 100));
        assert!(!include("/Volumes/Backup", "apfs", 0));
    }

    #[test]
    fn filesystem_facts_use_kib_and_mount_labels() {
        let facts = super::filesystem_facts("/var", "xfs", 4096, 1024);
        assert_eq!(facts.len(), 3);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        assert_eq!(value("host.filesystem.usage_percent"), Some("75"));
        assert_eq!(value("host.filesystem.total_kb"), Some("4"));
        assert_eq!(value("host.filesystem.available_kb"), Some("1"));
        for fact in &facts {
            assert!(
                fact.labels
                    .iter()
                    .any(|label| label.key == "mount" && label.value == "/var")
            );
            assert!(
                fact.labels
                    .iter()
                    .any(|label| label.key == "fstype" && label.value == "xfs")
            );
        }
    }

    #[test]
    fn filesystem_dedupe_key_groups_bind_mounts_by_device() {
        assert_eq!(
            super::filesystem_dedupe_key("/dev/sda1", "/data"),
            super::filesystem_dedupe_key("/dev/sda1", "/mnt/data")
        );
        assert_ne!(
            super::filesystem_dedupe_key("", "/data"),
            super::filesystem_dedupe_key("", "/mnt/data")
        );
        assert_eq!(
            super::filesystem_dedupe_key("", "/data"),
            "mount:/data".to_string()
        );
    }

    #[test]
    fn filesystem_facts_skip_empty_fstype_label() {
        let facts = super::filesystem_facts("/data", "", 100, 50);
        assert!(
            facts
                .iter()
                .all(|fact| fact.labels.iter().all(|label| label.key != "fstype"))
        );
    }

    #[test]
    fn filesystem_facts_clamp_available_to_total() {
        let facts = super::filesystem_facts("/", "ext4", 100, 200);
        let value = |key: &str| {
            facts
                .iter()
                .find(|fact| fact.key == key)
                .map(|fact| fact.value.as_str())
        };

        assert_eq!(value("host.filesystem.usage_percent"), Some("0"));
        assert_eq!(value("host.filesystem.available_kb"), Some("0"));
    }
}
