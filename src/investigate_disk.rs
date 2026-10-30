//! 磁盘调查（`wist-agentd investigate disk`）：**磁盘满了，到底是哪几大文件、多大了**。
//!
//! 现场问「磁盘满」时，运维真正要的不是「/ 用了 96%」（`diagnose`/指标早就有了），而是
//! **下一条命令该做什么**：清哪个目录、删哪个文件、还是扩盘。所以这一题固定给四节证据：
//!
//! 1. `disk.filesystems` — 每个本地文件系统的占用（字节 + **inode**）；
//! 2. `disk.top_dirs` — 扫描根下**一级目录**的合计（谁把盘吃掉了）；
//! 3. `disk.top_files` — 最大的 N 个文件（具体删哪个）；
//! 4. `disk.agent_dirs` — **agent 自己**占了多少（日志/状态/数据/运行；先排除「是不是我们自己」）；
//! 5. `disk.scan` — 这次扫描的规模与**完成度**（扫了多少、有没有被上限截断、哪些目录读不了）。
//!
//! 为什么要有第 5 节：目录遍历一定会遇到权限与预算。**「没有大文件」与「没扫到」是两回事**，
//! 不把扫描边界说出来，那张「最大的文件」表会被当成本机的全部真相 —— 这是现场最容易踩的坑。

use std::collections::BTreeMap;
use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{
    Finding, InvestigateRequest, Row, SCAN_ENTRY_LIMIT, human_bytes, percent, scan_budget,
};

/// 空间 / inode 的告警线：到 85% 就该动手，95% 基本已经在掉功能（日志写不进、临时文件建不了）。
pub(crate) const WARN_PERCENT: f64 = 85.0;
pub(crate) const FAIL_PERCENT: f64 = 95.0;

/// agent 自己落点的告警线。日志心跳已经是「只在变化时打」，稳态只有几 MB ——
/// 上到 1 GiB 说明轮转或 spool 出了问题，10 GiB 基本可以确定它就是把盘吃满的那个。
const AGENT_DIR_WARN_BYTES: u64 = 1 << 30;
const AGENT_DIR_FAIL_BYTES: u64 = 10 << 30;

/// 每节最多留几条读不到的例子（只在 hint 里给人看，不做全量清单）。
const UNREADABLE_SAMPLES: usize = 3;

/// 一个文件系统的占用情况。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct FsUsage {
    pub mount: String,
    pub device: String,
    pub file_system: String,
    pub total: u64,
    pub available: u64,
    pub used: u64,
    pub used_percent: f64,
    pub inodes: Option<InodeUsage>,
}

/// inode 占用。**与字节占用是两回事**：inode 用满时盘上还有空间，但新建不了文件 ——
/// 「磁盘 full」的另一种形态，只看容量百分比会漏掉。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct InodeUsage {
    pub total: u64,
    pub used: u64,
    pub used_percent: f64,
}

/// 跑一遍磁盘调查，返回各节结果（顺序即展示顺序）。
pub(crate) fn investigate(
    request: &InvestigateRequest,
    config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    let filesystems = local_filesystems();
    if filesystems.is_empty() {
        return Err("没有读到本机文件系统信息（sysinfo 返回空）".to_string());
    }

    let scan_root = resolve_scan_root(request.path.as_deref(), &filesystems)?;
    let walk = walk(&WalkOptions {
        root: scan_root.clone(),
        max_depth: request.depth,
        min_file_size: request.min_size,
        top: request.top,
        max_entries: SCAN_ENTRY_LIMIT,
        max_duration: scan_budget(request.max_seconds),
    })
    .map_err(|err| format!("扫描 {} 失败：{err}", scan_root.display()))?;

    let mut findings = vec![filesystem_finding(&filesystems)];
    findings.push(top_dirs_finding(&walk, &filesystems));
    findings.push(top_files_finding(&walk, request.min_size));
    if let Some(config) = config {
        findings.push(agent_dirs_finding(config, &scan_root, &walk));
    }
    findings.push(scan_finding(&walk, request));
    Ok(findings)
}

/// 扫描根：显式给了就用它；否则用**最紧张**的那个文件系统的挂载点。
///
/// 为什么是「最紧张」而不是 `/`：盘满的现场常常是数据盘（`/data`、`/var/lib/docker` 单独挂）
/// 先报警，扫 `/` 只会在系统盘上浪费时间并给出一张无关的表。
fn resolve_scan_root(requested: Option<&Path>, filesystems: &[FsUsage]) -> Result<PathBuf, String> {
    if let Some(path) = requested {
        let meta = fs::metadata(path)
            .map_err(|err| format!("扫描路径 {} 不可用：{err}", path.display()))?;
        if !meta.is_dir() {
            return Err(format!("扫描路径 {} 不是目录", path.display()));
        }
        return Ok(path.to_path_buf());
    }
    let mount = filesystems
        .iter()
        .max_by(|a, b| a.used_percent.total_cmp(&b.used_percent))
        .map(|fs| fs.mount.clone())
        .unwrap_or_else(|| "/".to_string());
    Ok(PathBuf::from(mount))
}

fn filesystem_finding(filesystems: &[FsUsage]) -> Finding {
    let mut ranked: Vec<&FsUsage> = filesystems.iter().collect();
    ranked.sort_by(|a, b| b.used_percent.total_cmp(&a.used_percent));

    let mut rows = Vec::new();
    let mut worst_space = Status::Ok;
    let mut worst_inode = Status::Ok;
    for fs in &ranked {
        let mut note = format!(
            "{} / {}（可用 {}）",
            human_bytes(fs.used),
            human_bytes(fs.total),
            human_bytes(fs.available)
        );
        // 设备与类型同列：现场经常是「/data 满了」但真正要扩的是另一块盘。
        if !fs.file_system.is_empty() || !fs.device.is_empty() {
            note.push_str(&format!("；[{} {}]", fs.file_system, fs.device));
        }
        if let Some(inodes) = fs.inodes {
            note.push_str(&format!(
                "；inode {:.1}%（{} / {}）",
                inodes.used_percent, inodes.used, inodes.total
            ));
            worst_inode = worst_inode.max(classify_percent(inodes.used_percent));
        }
        rows.push(Row::new(
            &fs.mount,
            format!("{:.1}% 已用", fs.used_percent),
            note,
        ));
        worst_space = worst_space.max(classify_percent(fs.used_percent));
    }

    let status = worst_space.max(worst_inode);
    let worst = ranked
        .first()
        .map(|fs| format!("{}（{:.1}% 已用）", fs.mount, fs.used_percent))
        .unwrap_or_else(|| "-".to_string());
    let detail = if status == Status::Ok {
        format!(
            "本机 {} 个本地文件系统，都还宽松；最紧张的是 {worst}",
            ranked.len()
        )
    } else {
        format!("本机 {} 个本地文件系统；最紧张的是 {worst}", ranked.len())
    };

    let mut finding = match status {
        Status::Ok => Finding::ok("disk.filesystems", "磁盘占用正常", detail),
        Status::Warn => Finding::warn("disk.filesystems", "磁盘偏紧", detail),
        Status::Fail => Finding::fail("disk.filesystems", "磁盘即将写满", detail),
    }
    .rows(rows);

    if status != Status::Ok {
        let mut hints = Vec::new();
        if worst_space != Status::Ok {
            hints.push(
                "按下面「一级目录占用」→「最大的文件」顺序确认是谁在长；日志/容器层\
                 （/var/log、/var/lib/docker、/var/lib/containerd）常是头号"
                    .to_string(),
            );
        }
        if worst_inode != Status::Ok {
            hints.push(
                "inode 用满与字节数无关：删几个大文件没用，要清**数量**大的小文件\
                 （临时目录、缓存、会话文件）"
                    .to_string(),
            );
        }
        finding = finding.hint(hints.join("\n"));
    }
    finding
}

fn top_dirs_finding(walk: &WalkReport, filesystems: &[FsUsage]) -> Finding {
    let total = walk.total_bytes;
    let rows: Vec<Row> = walk
        .top_dirs
        .iter()
        .map(|(label, bytes)| {
            let path = if label == ROOT_BUCKET {
                format!("{}/（根下直接的文件）", walk.root.display())
            } else {
                walk.root.join(label).display().to_string()
            };
            Row::new(
                path,
                human_bytes(*bytes),
                format!("占扫描总量 {}", percent(*bytes, total)),
            )
        })
        .collect();

    let on = filesystem_for_path(&walk.root, filesystems)
        .filter(|fs| walk.root != Path::new(&fs.mount))
        .map(|fs| format!("；位于 {}（{:.1}% 已用）", fs.mount, fs.used_percent))
        .unwrap_or_default();
    let truncated = if walk.truncated {
        "；**扫描未完成**，占比只代表已扫到的部分"
    } else {
        ""
    };
    let detail = format!(
        "扫描根 {}{on}；共 {} 个一级目录，列出最大的 {} 个（已扫 {}）{truncated}",
        walk.root.display(),
        walk.top_dirs.len(),
        rows.len(),
        human_bytes(total)
    );

    let mut finding = Finding::ok("disk.top_dirs", "一级目录占用", detail).rows(rows);
    if walk.top_dirs.is_empty() {
        finding = Finding::ok(
            "disk.top_dirs",
            "扫描根下没有子目录（只有文件）",
            format!("扫描根 {}{on}", walk.root.display()),
        );
    }
    finding
}

fn top_files_finding(walk: &WalkReport, min_size: u64) -> Finding {
    let rows: Vec<Row> = walk
        .top_files
        .iter()
        .map(|(path, bytes)| {
            Row::new(
                path.display().to_string(),
                human_bytes(*bytes),
                format!("占扫描总量 {}", percent(*bytes, walk.total_bytes)),
            )
        })
        .collect();

    let threshold = if min_size > 0 {
        format!("，只算 ≥ {}", human_bytes(min_size))
    } else {
        String::new()
    };
    let truncated = if walk.truncated {
        "（扫描未完成，可能还漏了更大的）"
    } else {
        ""
    };
    if rows.is_empty() {
        return Finding::ok(
            "disk.top_files",
            "没有可列出的大文件",
            format!(
                "已扫 {} 个文件{}；目录遍历见上一节{truncated}",
                walk.files, threshold
            ),
        );
    }
    Finding::ok(
        "disk.top_files",
        format!("最大的 {} 个文件", rows.len()),
        format!(
            "已扫 {} 个文件{}，列出最大的 {} 个{truncated}",
            walk.files,
            threshold,
            rows.len()
        ),
    )
    .rows(rows)
}

/// agent **自己**的落点：先排除「是不是我们把盘写满了」。
///
/// 只看 4 个目录（root / state / log / run）。互相包含的目录（开发机布局里 root 包着
/// state/log）会被合并 —— 否则同一批字节会被算两遍，反而看不出主因。
fn agent_dirs_finding(config: &AgentConfig, scan_root: &Path, walk: &WalkReport) -> Finding {
    let mut candidates: Vec<(&'static str, PathBuf)> = vec![
        ("root", PathBuf::from(&config.paths.root_dir)),
        ("state", PathBuf::from(&config.paths.state_dir)),
        ("log", PathBuf::from(&config.paths.log_dir)),
        ("run", PathBuf::from(&config.paths.run_dir)),
    ];
    candidates.sort_by_key(|(_, path)| path.as_os_str().len());
    // 短路径先入：后面的子目录被已保留的目录覆盖时就并入它的角色列表，
    // 同一批字节不会被算两遍，但「这个数里含哪些落点」仍然看得出来。
    let mut kept: Vec<(PathBuf, Vec<&'static str>)> = Vec::new();
    for (role, path) in candidates {
        match kept
            .iter_mut()
            .find(|(parent, _)| parent.as_path() != path.as_path() && path.starts_with(parent))
        {
            Some((_, roles)) => roles.push(role),
            None => kept.push((path, vec![role])),
        }
    }

    let mut rows = Vec::new();
    let mut total = 0u64;
    let mut worst = Status::Ok;
    let mut truncated_any = false;
    let mut unreadable_any = false;
    for (path, roles) in &kept {
        // 正好就是扫描根：直接用刚扫完的结果，别再遍历一遍。
        let (size, truncated, unreadable) = if path == scan_root {
            (walk.total_bytes, walk.truncated, walk.unreadable)
        } else {
            match dir_size(path) {
                Some(measured) => measured,
                None => continue,
            }
        };
        let measured = unreadable == 0;
        total = total.saturating_add(size);
        truncated_any |= truncated;
        unreadable_any |= !measured;
        let note = if !measured {
            format!("部分目录读不了（{unreadable} 处，需 root）")
        } else if truncated {
            "至少这么多（遍历未完成）".to_string()
        } else {
            String::new()
        };
        rows.push(Row::new(
            format!("{} {}", roles.join("/"), path.display()),
            human_bytes(size),
            note,
        ));
        // 读不全的大小时不当成「正常」也不当成「超标」—— 没有证据就不下判定。
        if measured {
            worst = worst.max(if size >= AGENT_DIR_FAIL_BYTES {
                Status::Fail
            } else if size >= AGENT_DIR_WARN_BYTES {
                Status::Warn
            } else {
                Status::Ok
            });
        }
    }

    if rows.is_empty() {
        return Finding::ok(
            "disk.agent_dirs",
            "agent 落点还不存在（没跑起来 / 没数据）",
            "没有可统计的日志、状态或数据目录",
        );
    }

    // 「读不全」本身就是一个要报的状态：一个 0 B 的结果不能证明它真的空。
    if unreadable_any {
        worst = worst.max(Status::Warn);
    }

    let mut caveats = String::new();
    if truncated_any {
        caveats.push_str("；有目录遍历未完成，实际可能更多");
    }
    if unreadable_any {
        caveats.push_str("；有目录读不全，合计是下界（以 root 重跑才能看全）");
    }
    let detail = format!(
        "agent 自己合计 {}（日志/状态/数据/运行）{caveats}",
        human_bytes(total)
    );
    let mut finding = match worst {
        Status::Ok => Finding::ok("disk.agent_dirs", "agent 落点体量正常", detail),
        Status::Warn => Finding::warn("disk.agent_dirs", "agent 落点偏大", detail),
        Status::Fail => Finding::fail("disk.agent_dirs", "agent 自己占了很大一块", detail),
    }
    .rows(rows);

    if worst != Status::Ok {
        finding = finding.hint(
            "先 `wist-agentd diagnose` 看 spool 积压与日志轮转；\
             `state/spool` 下的 `*.bad` 是隔离出来的坏行，可以留证后清理；\
             正在写的日志文件不要手工删（轮转由 wist-log 管）",
        );
    }
    finding
}

fn scan_finding(walk: &WalkReport, request: &InvestigateRequest) -> Finding {
    let detail = format!(
        "root={} files={} dirs={} total={} elapsed={:.1}s depth≤{} entries≤{} truncated={} unreadable={} symlinks={} other_mounts={}",
        walk.root.display(),
        walk.files,
        walk.directories,
        human_bytes(walk.total_bytes),
        walk.elapsed_ms as f64 / 1000.0,
        request.depth,
        SCAN_ENTRY_LIMIT,
        walk.truncated,
        walk.unreadable,
        walk.symlinks,
        walk.other_filesystems
    );

    let mut hints = Vec::new();
    if walk.truncated {
        hints.push(format!(
            "扫描没能在预算内走完（上限 {} 条 / {}s）：提高 `--max-seconds` / `--depth`，\
             或把 `--path` 指到更窄的目录（例如 /var）",
            SCAN_ENTRY_LIMIT, request.max_seconds
        ));
    }
    if walk.unreadable > 0 {
        let mut hint = format!(
            "有 {} 个目录/文件读不了：结果只是「能读到的部分」，以 root 重跑（`sudo wist-agentd investigate disk`）才能看全",
            walk.unreadable
        );
        for sample in &walk.unreadable_samples {
            hint.push('\n');
            hint.push_str(sample);
        }
        hints.push(hint);
    }

    let status = if walk.truncated || walk.unreadable > 0 {
        Status::Warn
    } else {
        Status::Ok
    };
    let mut finding = Finding::new(
        "disk.scan",
        status,
        match status {
            Status::Ok => "扫描完成",
            _ => "扫描没走全（结论只覆盖已扫到的部分）",
        },
        detail,
    );
    if !hints.is_empty() {
        finding = finding.hint(hints.join("\n"));
    }
    finding
}

// ---------------------------------------------------------------------------
// 文件系统
// ---------------------------------------------------------------------------

fn local_filesystems() -> Vec<FsUsage> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    crate::telemetry::metrics::runtime::local_filesystems(&disks)
        .into_iter()
        .map(|fs| {
            let available = fs.available_space.min(fs.total_space);
            let used = fs.total_space.saturating_sub(available);
            FsUsage {
                inodes: inode_usage(Path::new(&fs.mount)),
                used_percent: usage_percent(used, fs.total_space),
                mount: fs.mount,
                device: fs.device,
                file_system: fs.file_system,
                total: fs.total_space,
                available,
                used,
            }
        })
        .collect()
}

/// 某个路径落在哪个文件系统上（最长前缀匹配；`None` = 没匹配上，只在异常布局下发生）。
fn filesystem_for_path<'a>(path: &Path, filesystems: &'a [FsUsage]) -> Option<&'a FsUsage> {
    filesystems
        .iter()
        .filter(|fs| path.starts_with(&fs.mount))
        .max_by_key(|fs| fs.mount.len())
}

fn usage_percent(used: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        used as f64 / total as f64 * 100.0
    }
}

fn classify_percent(used_percent: f64) -> Status {
    if used_percent >= FAIL_PERCENT {
        Status::Fail
    } else if used_percent >= WARN_PERCENT {
        Status::Warn
    } else {
        Status::Ok
    }
}

#[cfg(unix)]
fn inode_usage(path: &Path) -> Option<InodeUsage> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt;

    let path = CString::new(path.as_os_str().as_bytes()).ok()?;
    // SAFETY: `statvfs` 只写这块由我们独占的内存；路径是有效的 C 字符串。
    let mut stat: libc::statvfs = unsafe { std::mem::zeroed() };
    // SAFETY: 指针在调用期间有效。
    if unsafe { libc::statvfs(path.as_ptr(), &mut stat) } != 0 {
        return None;
    }
    let total = stat.f_files as u64;
    if total == 0 {
        return None;
    }
    let free = stat.f_ffree as u64;
    let used = total.saturating_sub(free);
    Some(InodeUsage {
        total,
        used,
        used_percent: usage_percent(used, total),
    })
}

#[cfg(not(unix))]
fn inode_usage(_path: &Path) -> Option<InodeUsage> {
    None
}

// ---------------------------------------------------------------------------
// 目录遍历（有界）
// ---------------------------------------------------------------------------

/// 文件直接位于扫描根时的桶名（渲染时换成「<root>/（根下直接的文件）」）。
const ROOT_BUCKET: &str = "(root)";

struct WalkOptions {
    root: PathBuf,
    max_depth: usize,
    min_file_size: u64,
    top: usize,
    max_entries: u64,
    max_duration: Duration,
}

/// 一次目录遍历的结果。`top_files` / `top_dirs` 已按体量降序，`top_dirs` 只到**一级目录**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct WalkReport {
    pub root: PathBuf,
    pub files: u64,
    pub directories: u64,
    pub symlinks: u64,
    pub other_filesystems: u64,
    pub unreadable: u64,
    pub unreadable_samples: Vec<String>,
    pub truncated: bool,
    pub elapsed_ms: u64,
    pub total_bytes: u64,
    pub top_files: Vec<(PathBuf, u64)>,
    pub top_dirs: Vec<(String, u64)>,
}

impl WalkReport {
    fn empty(root: PathBuf) -> Self {
        Self {
            root,
            files: 0,
            directories: 0,
            symlinks: 0,
            other_filesystems: 0,
            unreadable: 0,
            unreadable_samples: Vec::new(),
            truncated: false,
            elapsed_ms: 0,
            total_bytes: 0,
            top_files: Vec::new(),
            top_dirs: Vec::new(),
        }
    }
}

/// 有界目录遍历：**不跟随符号链接**、**不跨文件系统**、按条目/时长/深度三重封顶。
///
/// 三条「不」都是为了现场安全：
/// * 不跟符号链接 —— `/var/lib/docker/...` 里链接成环是常态，跟进去就是无限循环；
/// * 不跨文件系统 —— 扫 `/` 时不能把 `/data`、`/proc`、网络盘一起算进来（那会既慢又错）；
/// * 三重封顶 —— 这台机器正在扛业务，调查不能变成新的故障源。超限只标 `truncated`，不报错。
fn walk(options: &WalkOptions) -> io::Result<WalkReport> {
    let started = Instant::now();
    let root_meta = fs::metadata(&options.root)?;
    if !root_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        ));
    }
    let root_device = device_of(&root_meta);

    let mut report = WalkReport::empty(options.root.clone());
    let mut stack: Vec<(PathBuf, usize)> = vec![(options.root.clone(), 0)];
    let mut seen: u64 = 0;
    let mut buckets: BTreeMap<String, u64> = BTreeMap::new();
    let mut top_files: Vec<(u64, PathBuf)> = Vec::new();

    'walk: while let Some((directory, depth)) = stack.pop() {
        if started.elapsed() >= options.max_duration {
            report.truncated = true;
            break;
        }
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(err) => {
                report.unreadable += 1;
                if report.unreadable_samples.len() < UNREADABLE_SAMPLES {
                    report
                        .unreadable_samples
                        .push(format!("{}：{err}", directory.display()));
                }
                continue;
            }
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(err) => {
                    report.unreadable += 1;
                    if report.unreadable_samples.len() < UNREADABLE_SAMPLES {
                        report
                            .unreadable_samples
                            .push(format!("{}：{err}", directory.display()));
                    }
                    continue;
                }
            };
            if seen >= options.max_entries {
                report.truncated = true;
                break 'walk;
            }
            seen += 1;
            // `symlink_metadata`：**不**跟随链接，链接本身不计入体量（目标可能不在本机）。
            let metadata = match entry.metadata() {
                Ok(metadata) => metadata,
                Err(err) => {
                    report.unreadable += 1;
                    if report.unreadable_samples.len() < UNREADABLE_SAMPLES {
                        report
                            .unreadable_samples
                            .push(format!("{}：{err}", entry.path().display()));
                    }
                    continue;
                }
            };
            let path = entry.path();
            let file_type = metadata.file_type();
            if file_type.is_symlink() {
                report.symlinks += 1;
                continue;
            }
            if !on_device(&metadata, root_device) {
                // 别的挂载点（/proc、/sys、/data…）：不属于这个文件系统，跳过。
                report.other_filesystems += 1;
                continue;
            }
            if file_type.is_dir() {
                report.directories += 1;
                if depth < options.max_depth {
                    stack.push((path, depth + 1));
                }
                continue;
            }
            if !file_type.is_file() {
                continue;
            }
            let size = metadata.len();
            report.files += 1;
            report.total_bytes = report.total_bytes.saturating_add(size);
            *buckets
                .entry(bucket_label(&options.root, &path))
                .or_insert(0) += size;
            if size >= options.min_file_size && options.top > 0 {
                top_files.push((size, path));
                let keep = options.top.saturating_mul(4).max(16);
                if top_files.len() > keep {
                    sort_files(&mut top_files);
                    top_files.truncate(options.top);
                }
            }
        }
    }

    sort_files(&mut top_files);
    top_files.truncate(options.top);
    report.top_files = top_files
        .into_iter()
        .map(|(size, path)| (path, size))
        .collect();

    let mut top_dirs: Vec<(String, u64)> = buckets.into_iter().collect();
    top_dirs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    top_dirs.truncate(options.top);
    report.top_dirs = top_dirs;
    report.elapsed_ms = started.elapsed().as_millis() as u64;
    Ok(report)
}

fn sort_files(files: &mut [(u64, PathBuf)]) {
    files.sort_by(|a, b| b.0.cmp(&a.0).then_with(|| a.1.cmp(&b.1)));
}

/// 文件属于扫描根下的哪个一级目录；直接位于根下的文件归到 [`ROOT_BUCKET`]。
fn bucket_label(root: &Path, path: &Path) -> String {
    let Ok(relative) = path.strip_prefix(root) else {
        return ROOT_BUCKET.to_string();
    };
    let mut components = relative.components();
    let Some(first) = components.next() else {
        return ROOT_BUCKET.to_string();
    };
    if components.next().is_none() {
        return ROOT_BUCKET.to_string();
    }
    first.as_os_str().to_string_lossy().to_string()
}

/// 某个 agent 落点的递归体量；`None` = 目录不存在。
///
/// 返回 `(字节数, 是否被预算截断, 读不了的条目数)`：后两项都要给到调用方 —— 「0 B」
/// 与「没读着」是两件事，不能让一个没权限的目录长得很空。
fn dir_size(path: &Path) -> Option<(u64, bool, u64)> {
    if !path.exists() {
        return None;
    }
    let report = walk(&WalkOptions {
        root: path.to_path_buf(),
        max_depth: crate::investigate::MAX_DEPTH,
        // 不要文件清单，只要合计。
        min_file_size: u64::MAX,
        top: 0,
        max_entries: SCAN_ENTRY_LIMIT,
        // 单个 agent 目录最多给 1s：它只是「顺带排除自己」，不该抢走扫描主预算。
        max_duration: Duration::from_secs(1),
    })
    .ok()?;
    Some((report.total_bytes, report.truncated, report.unreadable))
}

#[cfg(unix)]
fn device_of(metadata: &fs::Metadata) -> u64 {
    use std::os::unix::fs::MetadataExt;
    metadata.dev()
}

#[cfg(not(unix))]
fn device_of(_metadata: &fs::Metadata) -> u64 {
    0
}

#[cfg(unix)]
fn on_device(metadata: &fs::Metadata, device: u64) -> bool {
    use std::os::unix::fs::MetadataExt;
    metadata.dev() == device
}

#[cfg(not(unix))]
fn on_device(_metadata: &fs::Metadata, _device: u64) -> bool {
    true
}

#[cfg(test)]
mod tests {
    use super::*;

    struct TempDir(PathBuf);

    impl TempDir {
        fn new(name: &str) -> Self {
            let suffix = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos();
            let dir = std::env::temp_dir().join(format!("wist-agentd-disk-{name}-{suffix}"));
            fs::create_dir_all(&dir).expect("create temp dir");
            Self(dir)
        }

        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TempDir {
        fn drop(&mut self) {
            let _ = fs::remove_dir_all(&self.0);
        }
    }

    fn write_file(path: &Path, bytes: usize) {
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).expect("create parent");
        }
        fs::write(path, vec![b'x'; bytes]).expect("write file");
    }

    fn options(root: &Path) -> WalkOptions {
        WalkOptions {
            root: root.to_path_buf(),
            max_depth: 8,
            min_file_size: 0,
            top: 5,
            max_entries: 10_000,
            max_duration: Duration::from_secs(10),
        }
    }

    fn fs_usage(mount: &str, total: u64, available: u64) -> FsUsage {
        let used = total - available;
        FsUsage {
            mount: mount.to_string(),
            device: "/dev/x".to_string(),
            file_system: "ext4".to_string(),
            total,
            available,
            used,
            used_percent: usage_percent(used, total),
            inodes: None,
        }
    }

    #[test]
    fn walk_counts_files_and_sums_bytes() {
        let dir = TempDir::new("counts");
        write_file(&dir.path().join("a.bin"), 1000);
        write_file(&dir.path().join("sub/b.bin"), 2000);
        write_file(&dir.path().join("sub/deep/c.bin"), 4000);

        let report = walk(&options(dir.path())).expect("walk");

        assert_eq!(report.files, 3);
        assert!(!report.truncated);
        assert_eq!(report.total_bytes, 7000);
        assert_eq!(report.top_files.len(), 3);
        // 降序，最大的在最前。
        assert_eq!(report.top_files[0].1, 4000);
    }

    #[test]
    fn walk_buckets_files_by_their_first_level_directory() {
        let dir = TempDir::new("buckets");
        write_file(&dir.path().join("root-file.bin"), 10);
        write_file(&dir.path().join("alpha/a.bin"), 100);
        write_file(&dir.path().join("alpha/nested/b.bin"), 50);
        write_file(&dir.path().join("beta/c.bin"), 200);

        let report = walk(&options(dir.path())).expect("walk");

        let by_label: BTreeMap<&str, u64> = report
            .top_dirs
            .iter()
            .map(|(label, bytes)| (label.as_str(), *bytes))
            .collect();
        assert_eq!(by_label.get("alpha"), Some(&150));
        assert_eq!(by_label.get("beta"), Some(&200));
        assert_eq!(by_label.get(ROOT_BUCKET), Some(&10));
        // 按体量降序：beta(200) 在最前。
        assert_eq!(report.top_dirs[0].0, "beta");
    }

    #[test]
    fn walk_does_not_follow_symlinks() {
        let dir = TempDir::new("symlink");
        write_file(&dir.path().join("real.bin"), 4096);
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path().join("real.bin"), dir.path().join("link.bin"))
            .expect("symlink");
        #[cfg(unix)]
        std::os::unix::fs::symlink(dir.path(), dir.path().join("loop")).expect("symlink dir");

        let report = walk(&options(dir.path())).expect("walk");

        // 链接不计体量、不进入（否则 `loop` 会让遍历无限循环）。
        assert_eq!(report.files, 1);
        assert_eq!(report.total_bytes, 4096);
        #[cfg(unix)]
        assert_eq!(report.symlinks, 2);
    }

    #[test]
    fn walk_respects_min_size_and_top() {
        let dir = TempDir::new("min-size");
        for (index, size) in [10usize, 2000, 30_000, 400_000].into_iter().enumerate() {
            write_file(&dir.path().join(format!("f{index}.bin")), size);
        }
        let mut options = options(dir.path());
        options.min_file_size = 2000;
        options.top = 2;

        let report = walk(&options).expect("walk");

        // 四个文件都计入合计，但只列 ≥2000 的前 2 个。
        assert_eq!(report.files, 4);
        assert_eq!(report.total_bytes, 432_010);
        assert_eq!(report.top_files.len(), 2);
        assert_eq!(report.top_files[0].1, 400_000);
        assert_eq!(report.top_files[1].1, 30_000);
    }

    #[test]
    fn walk_stops_at_the_entry_budget_and_says_so() {
        let dir = TempDir::new("budget");
        for index in 0..50 {
            write_file(&dir.path().join(format!("f{index}.bin")), 1);
        }
        let mut options = options(dir.path());
        options.max_entries = 5;

        let report = walk(&options).expect("walk");

        assert!(report.truncated, "超预算必须如实标出来");
        assert!(report.files <= 5);
    }

    #[test]
    fn walk_stops_at_the_time_budget_and_says_so() {
        let dir = TempDir::new("deadline");
        write_file(&dir.path().join("a.bin"), 1);
        let mut options = options(dir.path());
        options.max_duration = Duration::ZERO;

        let report = walk(&options).expect("walk");

        assert!(report.truncated, "超时必须如实标出来");
        assert_eq!(report.files, 0);
    }

    #[test]
    fn walk_reports_a_missing_root_as_an_error() {
        let err =
            walk(&options(Path::new("/definitely/not/here/wist-agentd"))).expect_err("missing");
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn the_scan_root_defaults_to_the_most_pressured_filesystem() {
        let filesystems = vec![
            fs_usage("/", 100, 50),
            fs_usage("/data", 100, 3),
            fs_usage("/var", 100, 90),
        ];
        let root = resolve_scan_root(None, &filesystems).expect("root");
        assert_eq!(root, PathBuf::from("/data"));
    }

    #[test]
    fn an_explicit_scan_root_wins_and_must_be_a_directory() {
        let dir = TempDir::new("explicit");
        let filesystems = vec![fs_usage("/", 100, 0)];
        assert_eq!(
            resolve_scan_root(Some(dir.path()), &filesystems).expect("root"),
            dir.path()
        );

        let file = dir.path().join("file.bin");
        write_file(&file, 1);
        let err = resolve_scan_root(Some(&file), &filesystems).expect_err("not a dir");
        assert!(err.contains("不是目录"), "{err}");

        let err =
            resolve_scan_root(Some(&dir.path().join("nope")), &filesystems).expect_err("missing");
        assert!(err.contains("不可用"), "{err}");
    }

    #[test]
    fn filesystems_are_ranked_by_pressure_in_the_finding() {
        let filesystems = vec![
            fs_usage("/", 100, 50),
            fs_usage("/data", 100, 40),
            fs_usage("/logs", 100, 2),
        ];
        let finding = filesystem_finding(&filesystems);

        assert_eq!(finding.status, Status::Fail);
        assert_eq!(finding.rows.len(), 3);
        // 最紧张的在第一行，让人一眼看到。
        assert_eq!(finding.rows[0].label, "/logs");
        assert!(finding.detail.contains("/logs"), "{}", finding.detail);
        assert!(finding.hint.is_some());
    }

    #[test]
    fn a_comfortable_disk_is_ok_and_has_no_hint() {
        let filesystems = vec![fs_usage("/", 100, 50)];
        let finding = filesystem_finding(&filesystems);
        assert_eq!(finding.status, Status::Ok);
        assert!(finding.hint.is_none());
    }

    #[test]
    fn inode_pressure_alone_is_reported_as_a_problem() {
        let mut fs_usage = fs_usage("/", 1000, 900);
        fs_usage.inodes = Some(InodeUsage {
            total: 100,
            used: 99,
            used_percent: 99.0,
        });
        let finding = filesystem_finding(&[fs_usage]);

        assert_eq!(finding.status, Status::Fail);
        assert!(
            finding
                .hint
                .as_deref()
                .is_some_and(|hint| hint.contains("inode")),
            "inode 用满必须给出不同的处置：{:?}",
            finding.hint
        );
    }

    #[test]
    fn the_loosest_filesystem_governs_the_threshold() {
        assert_eq!(classify_percent(0.0), Status::Ok);
        assert_eq!(classify_percent(84.9), Status::Ok);
        assert_eq!(classify_percent(85.0), Status::Warn);
        assert_eq!(classify_percent(94.9), Status::Warn);
        assert_eq!(classify_percent(95.0), Status::Fail);
        assert_eq!(classify_percent(100.0), Status::Fail);
    }

    #[test]
    fn a_path_is_attributed_to_the_longest_matching_mount() {
        let filesystems = vec![fs_usage("/", 100, 50), fs_usage("/data", 100, 5)];
        let found = filesystem_for_path(Path::new("/data/logs/x"), &filesystems).expect("match");
        assert_eq!(found.mount, "/data");
        let found = filesystem_for_path(Path::new("/etc/x"), &filesystems).expect("match");
        assert_eq!(found.mount, "/");
    }

    #[test]
    fn a_truncated_scan_never_claims_completeness() {
        let mut report = WalkReport::empty(PathBuf::from("/"));
        report.truncated = true;
        report.unreadable = 2;
        report.unreadable_samples = vec!["/root：permission denied".to_string()];
        let finding = scan_finding(&report, &InvestigateRequest::default());

        assert_eq!(finding.status, Status::Warn);
        assert!(
            finding.detail.contains("truncated=true"),
            "{}",
            finding.detail
        );
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("--max-seconds"), "{hint}");
        assert!(hint.contains("permission denied"), "{hint}");
    }

    #[test]
    fn top_dirs_render_paths_and_shares() {
        let dir = TempDir::new("render-dirs");
        write_file(&dir.path().join("alpha/a.bin"), 300);
        write_file(&dir.path().join("beta/b.bin"), 100);
        let report = walk(&options(dir.path())).expect("walk");
        let finding = top_dirs_finding(&report, &[fs_usage("/", 1000, 500)]);

        assert_eq!(finding.rows.len(), 2);
        assert!(
            finding.rows[0].label.ends_with("/alpha"),
            "{}",
            finding.rows[0].label
        );
        assert_eq!(finding.rows[0].note, "占扫描总量 75.0%");
        assert!(finding.detail.contains("扫描根"), "{}", finding.detail);
    }

    #[test]
    fn the_agent_footprint_merges_nested_directories() {
        let dir = TempDir::new("agent-dirs");
        write_file(&dir.path().join("state/a.bin"), 400);
        write_file(&dir.path().join("log/b.bin"), 600);
        let mut config = AgentConfig::new(
            crate::config::agent_config::AgentSection::default(),
            crate::config::agent_config::ControlPlaneSection::default(),
            crate::config::agent_config::PathsSection::default(),
            crate::config::agent_config::ExecutionSection::default(),
        );
        config.paths.root_dir = dir.path().display().to_string();
        config.paths.state_dir = dir.path().join("state").display().to_string();
        config.paths.log_dir = dir.path().join("log").display().to_string();
        config.paths.run_dir = dir.path().join("run").display().to_string();

        let report = walk(&options(dir.path())).expect("walk");
        let finding = agent_dirs_finding(&config, Path::new("/nowhere"), &report);

        // root 覆盖了 state/log：只留一行，合计 1000，不重复计数。
        assert_eq!(finding.rows.len(), 1);
        assert_eq!(finding.rows[0].value, human_bytes(1000));
        assert_eq!(finding.status, Status::Ok);
    }
}
