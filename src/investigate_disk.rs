//! 磁盘调查（`wist-agentd investigate disk`）：**磁盘满了，到底是哪几大文件、多大了**。
//!
//! 现场问「磁盘满」时，运维真正要的不是「/ 用了 96%」（`diagnose`/指标早就有了），而是
//! **下一条命令该做什么**：清哪个目录、删哪个文件、还是扩盘。所以这一题给这几节证据：
//!
//! 1. `disk.filesystems` — 每个本地文件系统的占用（字节 + **inode**）；
//! 2. `disk.largest_dirs` — **递归累计**最大的目录（任意深度）+ **热点下钻链**；
//! 3. `disk.top_dirs` — 扫描根下**一级目录**的合计（粗粒度、便于对账）；
//! 4. `disk.top_files` — 最大的 N 个文件（具体删哪个）；
//! 5. `disk.agent_dirs` — **agent 自己**占了多少（日志/状态/数据/运行；先排除「是不是我们自己」）；
//! 6. `disk.unattributed` — 盘上用了但**不在扫描根里**的那部分（快照/保留块/已删除仍被打开）；
//! 7. `disk.scan` — 这次扫描的规模与**完成度**（扫了多少、有没有被上限截断、哪些目录读不了）。
//!
//! 为什么要有「递归累计目录」这一节：**最大的文件不一定是根因**。现场的典型形态是一堆
//! 中小文件堆在一个深层目录里（容器层、会话目录、把一百万个 4 KiB 小文件写满 inode），
//! 单个文件都不大，而 `du` 式的目录累计一眼就能看出是谁。所以这里用经典的两歩：
//!
//! * **自底向上累计**（`du` 的做法）：每个文件把字节加到它**所有祖先目录**上，得到
//!   每个目录的递归体量；硬链接只算一次（同一 inode 算两次会凭空多出一倍体积）。
//! * **逐层下钻**（`du -h --max-depth=1 | sort -h | tail -1` 重复做）：从扫描根开始，
//!   每次选占父级 ≥ 60% 的那个子目录，直到不再集中 —— 得到一条「热点路径」，
//!   告诉你「到底是哪一层在长」，而不是让你自己对着一级目录表猜。
//!
//! 为什么要有「未归因」这一节：`df` 说满、`du` 却找不出来是经典事故（文件删了但进程还开着、
//! 快照、文件系统保留块、或者数据在别的挂载点）。不说清这块钱，会让人把「找不到」
//! 误当成「工具坏了」。
//!
//! 为什么要有第 7 节：目录遍历一定会遇到权限与预算。**「没有大文件」与「没扫到」是两回事**，
//! 不把扫描边界说出来，那张「最大的文件」表会被当成本机的全部真相 —— 这是现场最容易踩的坑。
//!
//! 预算怎么花（这决定了报告可不可信）：先花极小的代价把**扫描根的一级子目录列全**，
//! 再让这些一级目录**轮流**花剩下的预算。若按深度优先一路走到底，一个巨型目录
//! （macOS 的 `/Applications` 有 14 万条）会把条目上限吃干，同级的 `/Users`（真正占了
//! 200 GiB 的那个）连名字都进不了报告 —— 现场那张「共 3 个一级目录」的表就是这么来的。
//! 轮流分配之后，每个一级目录都至少拿到一份切片，没扫完的会被**点名**并给出单独重扫的命令。

use std::collections::{BTreeMap, BTreeSet, HashSet, VecDeque};
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

/// 一轮轮转里单个一级目录最多消耗多少条目：切片过大就等于让一个巨型目录
/// （`/Applications`、`overlay2/...`）把别的目录挤掉，正是我们要避免的失败形态。
const SCAN_SLICE_ENTRIES: u64 = 4096;
/// 每隔多少个条目复查一次时限（只在目录边界查会让一个巨型目录一路超时跑下去）。
const TIME_CHECK_EVERY: u64 = 512;
/// hint 里最多点几个没扫完的一级目录（其余在表格里已经能看到）。
const INCOMPLETE_DIRS_SHOWN: usize = 4;

/// 各平台「盘满常见的大头」。报告不说这几个地方，运维还是得自己去猜 ——
/// 而这几个目录恰恰是最常见的根因（macOS 的废纸篓能堆到几百 GiB）。
#[cfg(target_os = "macos")]
const USUAL_SUSPECTS: &[&str] = &[
    "~/.Trash —— 废纸篓：删了没清空就会一直占着，常是几十上百 GiB",
    "~/Library/Caches 与 ~/Library/Containers —— 应用缓存与沙盒数据（可安全清缓存）",
    "~/Library/Developer —— 模拟器、Xcode 的 DerivedData",
    "/private/var/folders —— 临时文件（重启会清；先 `--path` 扫一遍确认体量）",
];
#[cfg(target_os = "linux")]
const USUAL_SUSPECTS: &[&str] = &[
    "/var/log —— 没轮转的日志（`du -sh /var/log/* | sort -h`）",
    "/var/lib/docker 与 /var/lib/containerd —— 镜像、容器层、卷（`docker system df`）",
    "/var/cache 与 /tmp —— 包缓存与临时文件",
    "/home/*/.cache —— 用户级缓存",
];
#[cfg(not(any(target_os = "macos", target_os = "linux")))]
const USUAL_SUSPECTS: &[&str] = &["临时目录、日志目录与应用缓存"];

/// 子目录要占父级多少百分比才继续往下钻（经典 `du` 下钻的“还在集中”判据）。
const HOT_PATH_DOMINANCE: u64 = 60;
/// 下钻链最多多少层（报告体量 + 人读得下去）。
const HOT_PATH_MAX_DEPTH: usize = 8;
/// 「未归因」至少这么大才值得单独报（小差量是文件系统元数据/保留块的正常噪声）。
const UNATTRIBUTED_MIN_BYTES: u64 = 512 * 1024 * 1024;
/// 扫「已删除仍打开」的时限与条目上限：它只用来解释差量，不能把调查拖长。
#[cfg(target_os = "linux")]
const DELETED_OPEN_BUDGET_MS: u64 = 150;
#[cfg(target_os = "linux")]
const DELETED_OPEN_MAX_FILES: u64 = 20_000;

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
    findings.push(largest_dirs_finding(&walk));
    findings.push(top_dirs_finding(&walk, &filesystems));
    findings.push(top_files_finding(&walk, request.min_size));
    if let Some(config) = config {
        findings.push(agent_dirs_finding(config, &scan_root, &walk));
    }
    findings.push(unattributed_finding(&walk, &filesystems));
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
            let mut hint = String::from(
                "先看「最大的目录（递归累计）」里的**热点路径**：盘满的根因通常是一个深层目录\
                 （缓存、会话、容器层），而不是某个大文件。本平台常见的大头：",
            );
            for suspect in USUAL_SUSPECTS {
                hint.push_str("\n- ");
                hint.push_str(suspect);
            }
            hints.push(hint);
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

/// 递归累计最大的目录（任意深度）+ 热点下钻链 —— **这就是“盘满了是谁占的”的直接答案**。
///
/// 为什么不是只给一级目录：一级目录都“不大”而盘却满了，是现场最常见的形态（容器层、
/// 会话目录、百万小文件把 inode 写满）。一个 40 GiB 的 overlay 层藏在 `/var/lib/docker` 里时，
/// 一级目录只会告诉你“/var 很大”，对下一步清理没有用。
fn largest_dirs_finding(walk: &WalkReport) -> Finding {
    let total = walk.total_bytes;
    let rows: Vec<Row> = walk
        .largest_dirs
        .iter()
        .map(|(path, bytes)| {
            let note = if walk.truncated {
                format!("占已扫总量 {}（扫描未完成）", percent(*bytes, total))
            } else {
                format!("占扫描总量 {}", percent(*bytes, total))
            };
            Row::new(path.display().to_string(), human_bytes(*bytes), note)
        })
        .collect();

    if rows.is_empty() {
        return Finding::ok(
            "disk.largest_dirs",
            "没有可列出的目录",
            format!(
                "扫描根 {} 下没有非空子目录（已扫 {}）",
                walk.root.display(),
                human_bytes(total)
            ),
        );
    }

    let deepest = walk
        .largest_dirs
        .first()
        .map(|(path, bytes)| {
            format!(
                "{}（{}，占扫描总量 {}）",
                path.display(),
                human_bytes(*bytes),
                percent(*bytes, total)
            )
        })
        .unwrap_or_else(|| "-".to_string());
    // 摘要里优先说**热点链末端**（真正在长的那一层），而不是“最大的那个祖先目录”。
    let hotspot = walk
        .hot_path
        .last()
        .map(|(path, bytes)| {
            format!(
                "热点在 {}（{}，占扫描总量 {}）",
                path.display(),
                human_bytes(*bytes),
                percent(*bytes, total)
            )
        })
        .unwrap_or_else(|| format!("递归累计最大的是 {deepest}"));
    let detail = format!(
        "扫描根 {}；{hotspot}（已扫 {}）{}",
        walk.root.display(),
        human_bytes(total),
        incomplete_caveat(walk)
    );

    let mut finding = Finding::ok("disk.largest_dirs", "最大的目录（递归累计）", detail).rows(rows);

    let hints: Vec<String> = [hot_path_hint(walk), incomplete_hint(walk)]
        .into_iter()
        .flatten()
        .collect();
    if !hints.is_empty() {
        finding = finding.hint(hints.join("\n"));
    }
    finding
}

/// 没扫完的一级目录的相对名（`/Users` 而不是 `/System/Volumes/Data/Users`）。
fn incomplete_labels(walk: &WalkReport) -> Vec<String> {
    walk.incomplete_dirs
        .iter()
        .map(|(path, _)| {
            path.strip_prefix(&walk.root)
                .map(|relative| format!("/{}", relative.display()))
                .unwrap_or_else(|_| path.display().to_string())
        })
        .collect()
}

/// 「有 N 个一级目录没扫完（…）」的短句（空 = 全扫完了）。
fn incomplete_caveat(walk: &WalkReport) -> String {
    if walk.incomplete_dirs.is_empty() {
        return String::new();
    }
    let labels = incomplete_labels(walk);
    let shown = if labels.len() > INCOMPLETE_DIRS_SHOWN {
        format!(
            "{} 等 {} 个",
            labels[..INCOMPLETE_DIRS_SHOWN].join("、"),
            labels.len()
        )
    } else {
        labels.join("、")
    };
    format!(
        "；**{} 个一级目录没扫完**（{shown}），它们实际只会更大",
        labels.len()
    )
}

/// 「这些目录没扫完，单独扫它们能拿到全量」的行动建议。
///
/// 没有这一句，「没扫完」只是一句免责声明；有了它，下一条命令就确定了。
fn incomplete_hint(walk: &WalkReport) -> Option<String> {
    if walk.incomplete_dirs.is_empty() {
        return None;
    }
    let mut hint = String::from(
        "扫描预算按一级目录**轮流**分配，下面这些没扫完（数字是已扫到的下界，实际更大）——\
         单独扫它们能拿到全量：",
    );
    for (path, bytes) in walk.incomplete_dirs.iter().take(INCOMPLETE_DIRS_SHOWN) {
        hint.push_str(&format!(
            "\n- {} ≥ {} → `wist-agentd investigate disk --path {}`",
            path.display(),
            human_bytes(*bytes),
            path.display()
        ));
    }
    Some(hint)
}

/// 把热点链渲染成一行“A → B → C”，并给出“该清哪个”的建议。
///
/// 链上除了根，其余用**相对扫描根**的路径：`/var/lib/docker/...` 已经是相对路径，
/// 而现场常见的长前缀（`/var/folders/…`、挂载点很长的盘）会把这一行撑成一堵墙。
fn hot_path_hint(walk: &WalkReport) -> Option<String> {
    if walk.hot_path.len() < 2 {
        return None;
    }
    let total = walk.total_bytes.max(1);
    let mut chain = String::new();
    for (index, (path, bytes)) in walk.hot_path.iter().enumerate() {
        if index == 0 {
            chain.push_str(&path.display().to_string());
            continue;
        }
        let parent_bytes = walk.hot_path[index - 1].1.max(1);
        let label = path
            .strip_prefix(&walk.root)
            .map(|relative| format!("/{}", relative.display()))
            .unwrap_or_else(|_| path.display().to_string());
        chain.push_str(&format!(
            " → {}（{}，占父级 {} / 占总量 {}）",
            label,
            human_bytes(*bytes),
            percent(*bytes, parent_bytes),
            percent(*bytes, total)
        ));
    }
    let (leaf, leaf_bytes) = walk.hot_path.last()?;
    let mut hint = format!("热点路径（每层占父级 ≥{HOT_PATH_DOMINANCE}%）：{chain}");
    // 如果深处就一个大文件在撑，直接指出来 —— “最大的文件不一定是根因”反过来说：
    // 根因在目录，但落地动作往往是删那个文件。
    if let Some((file, file_bytes)) = walk.top_files.first()
        && file.starts_with(leaf)
        && file_bytes.saturating_mul(100) >= leaf_bytes.saturating_mul(50)
    {
        hint.push_str(&format!(
            "\n这条链最深处的主要体量是一个文件：{}（{}，占该目录 {}）——确认后再删，不要整目录 rm",
            file.display(),
            human_bytes(*file_bytes),
            percent(*file_bytes, *leaf_bytes),
        ));
    }
    Some(hint)
}

/// `df` 说满了、但扫描根里找不到那么多：把差量摊到明面上（经典事故，不是“工具坏了”）。
///
/// 只看「扫描根就是挂载点」的情形：扫的是子目录时，差量里天然包含挂载点的其余部分，
/// 把它当成“未归因”会误导人。
fn unattributed_finding(walk: &WalkReport, filesystems: &[FsUsage]) -> Finding {
    let Some(fs_usage) = filesystem_for_path(&walk.root, filesystems) else {
        return Finding::ok(
            "disk.unattributed",
            "无法归因差量",
            "扫描根没匹配到任何本地文件系统（异常布局）",
        );
    };
    if Path::new(&fs_usage.mount) != walk.root.as_path() {
        return Finding::ok(
            "disk.unattributed",
            "不适用（扫描的是子目录）",
            format!(
                "扫描根 {} 只是 {} 的一部分；盘上其余占用不参与归因",
                walk.root.display(),
                fs_usage.mount
            ),
        );
    }

    let gap = fs_usage.used.saturating_sub(walk.total_bytes);
    let used = fs_usage.used.max(1);
    let gap_percent = percent(gap, used);
    let significant = gap >= UNATTRIBUTED_MIN_BYTES
        && gap.saturating_mul(100) >= fs_usage.total.saturating_mul(5);

    let (deleted_bytes, deleted_files) = deleted_open_bytes();
    let mut detail = format!(
        "盘上已用 {}，扫描归因 {}（{}），差量 {}（占已用 {}）",
        human_bytes(fs_usage.used),
        human_bytes(walk.total_bytes),
        percent(walk.total_bytes, used),
        human_bytes(gap),
        gap_percent
    );
    if walk.truncated {
        detail.push_str("；**扫描未完成**，差量里含未扫到的部分");
        // 盘满但“扫不到东西”时，这一句就是整个报告的结论：大头在没扫完的那几个目录里。
        detail.push_str(&incomplete_caveat(walk));
    }
    if deleted_files > 0 {
        detail.push_str(&format!(
            "；其中 {} 个已删除但仍被进程打开的文件占 {}（需要重启对应进程才能释放）",
            deleted_files,
            human_bytes(deleted_bytes)
        ));
    }

    let status = if significant && !walk.truncated {
        Status::Warn
    } else {
        Status::Ok
    };
    let mut finding = Finding::new(
        "disk.unattributed",
        status,
        if significant && !walk.truncated {
            "有相当一部分盘上占用不在扫描根里"
        } else {
            "扫描基本能解释盘上的占用"
        },
        detail,
    );

    if significant && !walk.truncated {
        let mut hints = vec![
            "差量常见的四个来源：其它挂载点（数据盘、容器卷）、文件系统快照/副本、\
             ext4 保留块（默认 5%，`tune2fs -m`）、**已删除但仍被打开**的文件（重启/重开对应进程才释放）"
                .to_string(),
        ];
        if deleted_files == 0 {
            hints.push(
                "本机没扫到“已删除仍打开”的文件（需 root 才扫得全）；仍建议 `lsof +L1` 交叉核对"
                    .to_string(),
            );
        }
        finding = finding.hint(hints.join("\n"));
    }
    finding
}

/// 已删除但仍被进程打开的文件：`df` 满而 `du` 找不出来的头号原因。
///
/// 只读 `/proc/<pid>/fd` 的链接名，不读内容；按时限与条目双重封顶（它只是解释差量，
/// 不值得让它把调查拖长）。非 Linux 平台没有免依赖的做法，直接返回 0。
#[cfg(target_os = "linux")]
fn deleted_open_bytes() -> (u64, u64) {
    let started = Instant::now();
    let budget = Duration::from_millis(DELETED_OPEN_BUDGET_MS);
    let mut bytes = 0u64;
    let mut files = 0u64;
    let Ok(procs) = fs::read_dir("/proc") else {
        return (0, 0);
    };
    for proc_entry in procs.flatten() {
        if started.elapsed() >= budget || files >= DELETED_OPEN_MAX_FILES {
            break;
        }
        let name = proc_entry.file_name();
        if !name
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let fd_dir = proc_entry.path().join("fd");
        let Ok(fds) = fs::read_dir(&fd_dir) else {
            continue;
        };
        for fd in fds.flatten() {
            if started.elapsed() >= budget || files >= DELETED_OPEN_MAX_FILES {
                break;
            }
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            if !target.to_string_lossy().ends_with(" (deleted)") {
                continue;
            }
            // `fd` 路径可直接 stat（跟随到 inode）：拿到它现在占的字节。
            if let Ok(meta) = fs::metadata(fd.path()) {
                if meta.is_file() {
                    bytes = bytes.saturating_add(meta.len());
                    files += 1;
                }
            }
        }
    }
    (bytes, files)
}

#[cfg(not(target_os = "linux"))]
fn deleted_open_bytes() -> (u64, u64) {
    (0, 0)
}

fn top_dirs_finding(walk: &WalkReport, filesystems: &[FsUsage]) -> Finding {
    let total = walk.total_bytes;
    // 没扫完的一级目录在表里看着“很小”，必须逐行标出来，否则那张表会被当成本机全貌。
    let incomplete: BTreeSet<String> = walk
        .incomplete_dirs
        .iter()
        .filter_map(|(path, _)| {
            path.file_name()
                .map(|name| name.to_string_lossy().to_string())
        })
        .collect();
    let rows: Vec<Row> = walk
        .top_dirs
        .iter()
        .map(|(label, bytes)| {
            let path = if label == ROOT_BUCKET {
                format!("{}/（根下直接的文件）", walk.root.display())
            } else {
                walk.root.join(label).display().to_string()
            };
            let mut note = format!("占扫描总量 {}", percent(*bytes, total));
            if incomplete.contains(label) {
                note.push_str("；**没扫完**，实际更大");
            }
            Row::new(path, human_bytes(*bytes), note)
        })
        .collect();

    let on = filesystem_for_path(&walk.root, filesystems)
        .filter(|fs| walk.root != Path::new(&fs.mount))
        .map(|fs| format!("；位于 {}（{:.1}% 已用）", fs.mount, fs.used_percent))
        .unwrap_or_default();
    let truncated = if !walk.incomplete_dirs.is_empty() {
        incomplete_caveat(walk)
    } else if walk.truncated {
        "；**扫描未完成**，占比只代表已扫到的部分".to_string()
    } else {
        String::new()
    };
    let dir_count = walk.top_level_dirs.max(walk.top_dirs.len());
    let detail = format!(
        "扫描根 {}{on}；共 {} 个一级目录，列出最大的 {} 个（已扫 {}）{truncated}",
        walk.root.display(),
        dir_count,
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
    match incomplete_hint(walk) {
        Some(hint) => finding.hint(hint),
        None => finding,
    }
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
        "root={} files={} dirs={} total={} elapsed={:.1}s depth≤{} entries≤{} truncated={} unreadable={} symlinks={} other_mounts={} incomplete_top_dirs={}",
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
        walk.other_filesystems,
        walk.incomplete_dirs.len()
    );

    let mut hints = Vec::new();
    if walk.truncated {
        hints.push(format!(
            "扫描没能在预算内走完（上限 {} 条 / {}s）：一级目录之间是**轮流**分配预算的，\
             每个目录都拿到了一部分，没扫完的已在「一级目录占用」里点名；\
             要拿全某一个目录，单独扫它（`wist-agentd investigate disk --path <目录> --max-seconds 60`）",
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

/// 一次目录遍历的结果。`top_files` / `top_dirs` 已按体量降序，`top_dirs` 只到**一级目录**；
/// `largest_dirs` 是**任意深度**的递归累计，`hot_path` 是从根下钻的集中链。
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
    /// 扫描根下**一级子目录的总数**（这一层在预算之外先列全，所以它总是可信的）。
    pub top_level_dirs: usize,
    /// 递归累计最大的目录（**任意深度**，不含扫描根本身），按体量降序。
    pub largest_dirs: Vec<(PathBuf, u64)>,
    /// 从扫描根开始的「热点下钻链」（含根；空 = 没有普遍集中的子目录）。
    pub hot_path: Vec<(PathBuf, u64)>,
    /// **没扫完**的一级目录及其已扫到的字节（按字节降序）。空 = 每个一级目录都扫完了。
    /// 这一项不能省：预算撞上限时，没扫的目录在表里看起来就像“很小”。
    pub incomplete_dirs: Vec<(PathBuf, u64)>,
    /// 硬链接被去重的字节数（同一 inode 只算一次；否则容器层会凭空多出一倍体积）。
    pub hardlinks_deduped: u64,
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
            top_level_dirs: 0,
            largest_dirs: Vec::new(),
            hot_path: Vec::new(),
            incomplete_dirs: Vec::new(),
            hardlinks_deduped: 0,
        }
    }
}

/// 单个目录的「可续游标」：预算按条目切片推进，一个巨型目录不会在一轮里吃光子预算。
struct DirCursor {
    path: PathBuf,
    depth: usize,
    /// 祖先链（含自己，从自己到扫描根）：每个文件把字节加到这些目录上（`du` 那一步）。
    ancestors: Vec<PathBuf>,
    entries: fs::ReadDir,
}

/// 一个一级子目录的遍历状态：`stack` = 待展开的目录，`cursor` = 正在读的那个目录。
struct Subtree {
    root: PathBuf,
    stack: Vec<(PathBuf, usize)>,
    cursor: Option<DirCursor>,
}

impl Subtree {
    fn new(root: PathBuf, depth: usize) -> Self {
        let stack = vec![(root.clone(), depth)];
        Self {
            root,
            stack,
            cursor: None,
        }
    }

    fn finished(&self) -> bool {
        self.cursor.is_none() && self.stack.is_empty()
    }
}

/// 一轮推进的结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Step {
    /// 这一路扫完了。
    Ended,
    /// 本轮切片用完，还有活（下一轮接着来）。
    Paused,
    /// 全局条目预算用尽。
    OutOfEntries,
    /// 全局时限用尽。
    OutOfTime,
}

/// 有界目录遍历的执行体：所有可变状态收在这里，遍历被拆成「按切片推进」的可续步骤。
struct Walker<'o> {
    options: &'o WalkOptions,
    root_device: u64,
    started: Instant,
    seen: u64,
    report: WalkReport,
    buckets: BTreeMap<String, u64>,
    top_files: Vec<(u64, PathBuf)>,
    // 目录树（父 → 子）与**递归累计**体量：每个文件把字节加到自己的所有祖先上，
    // 这就是 `du` 那一步。`dir_bytes` 含扫描根本身（算总量用）。
    dir_parent: BTreeMap<PathBuf, PathBuf>,
    children: BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    dir_bytes: BTreeMap<PathBuf, u64>,
    // 硬链接去重：`(dev, ino)` 只算一次（只对 `nlink > 1` 的文件建表，避免白花内存）。
    seen_inodes: HashSet<(u64, u64)>,
}

impl<'o> Walker<'o> {
    fn new(options: &'o WalkOptions, root_device: u64) -> Self {
        let mut dir_bytes = BTreeMap::new();
        dir_bytes.insert(options.root.clone(), 0);
        Self {
            options,
            root_device,
            started: Instant::now(),
            seen: 0,
            report: WalkReport::empty(options.root.clone()),
            buckets: BTreeMap::new(),
            top_files: Vec::new(),
            dir_parent: BTreeMap::new(),
            children: BTreeMap::new(),
            dir_bytes,
            seen_inodes: HashSet::new(),
        }
    }

    fn out_of_entries(&self) -> bool {
        self.seen >= self.options.max_entries
    }

    fn out_of_time(&self) -> bool {
        self.started.elapsed() >= self.options.max_duration
    }

    fn note_unreadable(&mut self, path: &Path, err: &io::Error) {
        self.report.unreadable += 1;
        if self.report.unreadable_samples.len() < UNREADABLE_SAMPLES {
            self.report
                .unreadable_samples
                .push(format!("{}：{err}", path.display()));
        }
    }

    /// 打开一个目录（连带算好祖先链）；读不了只计数，不中断遍历。
    fn open(&mut self, path: PathBuf, depth: usize) -> Option<DirCursor> {
        let entries = match fs::read_dir(&path) {
            Ok(entries) => entries,
            Err(err) => {
                self.note_unreadable(&path, &err);
                return None;
            }
        };
        let mut ancestors = vec![path.clone()];
        let mut current = path.clone();
        while let Some(parent) = self.dir_parent.get(&current) {
            ancestors.push(parent.clone());
            current = parent.clone();
        }
        Some(DirCursor {
            path,
            depth,
            ancestors,
            entries,
        })
    }

    /// 从游标接着读，最多消耗 `budget` 个条目；子目录压进 `sink` 等着展开。
    fn advance(
        &mut self,
        cursor: &mut DirCursor,
        budget: u64,
        sink: &mut Vec<(PathBuf, usize)>,
    ) -> (u64, Step) {
        let mut consumed = 0u64;
        while consumed < budget {
            if self.out_of_entries() {
                return (consumed, Step::OutOfEntries);
            }
            // 时限要按条目复查：只在目录边界查，一个巨型目录会一路超时跑下去。
            if consumed.is_multiple_of(TIME_CHECK_EVERY) && self.out_of_time() {
                return (consumed, Step::OutOfTime);
            }
            let Some(entry) = cursor.entries.next() else {
                return (consumed, Step::Ended);
            };
            consumed += 1;
            self.seen += 1;
            self.absorb(entry, cursor, sink);
        }
        (consumed, Step::Paused)
    }

    /// 处理一个目录项：计数、累计体量、收集子目录。
    fn absorb(
        &mut self,
        entry: io::Result<fs::DirEntry>,
        cursor: &DirCursor,
        sink: &mut Vec<(PathBuf, usize)>,
    ) {
        let entry = match entry {
            Ok(entry) => entry,
            Err(err) => {
                self.note_unreadable(&cursor.path, &err);
                return;
            }
        };
        let path = entry.path();
        // `entry.metadata()` 走 `symlink_metadata` 语义：**不**跟随链接。
        let metadata = match entry.metadata() {
            Ok(metadata) => metadata,
            Err(err) => {
                self.note_unreadable(&path, &err);
                return;
            }
        };
        let file_type = metadata.file_type();
        if file_type.is_symlink() {
            // 链接本身不计体量（目标可能不在本机），也不跟进去（`/var/lib/docker` 里成环是常态）。
            self.report.symlinks += 1;
            return;
        }
        if !on_device(&metadata, self.root_device) {
            // 别的挂载点（/proc、/sys、/data…）：不属于这个文件系统，跳过。
            self.report.other_filesystems += 1;
            return;
        }
        if file_type.is_dir() {
            self.report.directories += 1;
            self.dir_parent.insert(path.clone(), cursor.path.clone());
            self.children
                .entry(cursor.path.clone())
                .or_default()
                .insert(path.clone());
            self.dir_bytes.entry(path.clone()).or_insert(0);
            if cursor.depth < self.options.max_depth {
                sink.push((path, cursor.depth + 1));
            }
            return;
        }
        if !file_type.is_file() {
            return;
        }
        // 硬链接：同一个 inode 的第二个名字不再计字节（经典 `du` 行为）。
        if let Some(inode) = hardlink_identity(&metadata)
            && !self.seen_inodes.insert(inode)
        {
            self.report.files += 1;
            self.report.hardlinks_deduped =
                self.report.hardlinks_deduped.saturating_add(metadata.len());
            return;
        }
        let size = metadata.len();
        self.report.files += 1;
        self.report.total_bytes = self.report.total_bytes.saturating_add(size);
        *self
            .buckets
            .entry(bucket_label(&self.options.root, &path))
            .or_insert(0) += size;
        // 累计到所有祖先（含当前目录与扫描根）——`du` 那一步。
        for ancestor in &cursor.ancestors {
            match self.dir_bytes.get_mut(ancestor) {
                Some(total) => *total = total.saturating_add(size),
                None => {
                    self.dir_bytes.insert(ancestor.clone(), size);
                }
            }
        }
        if size >= self.options.min_file_size && self.options.top > 0 {
            self.top_files.push((size, path));
            let keep = self.options.top.saturating_mul(4).max(16);
            if self.top_files.len() > keep {
                sort_files(&mut self.top_files);
                self.top_files.truncate(self.options.top);
            }
        }
    }

    /// 把一个一级子目录推进 `quantum` 个条目（或推到它扫完）。
    fn drain_subtree(&mut self, subtree: &mut Subtree, quantum: u64) -> Step {
        let mut spent = 0u64;
        loop {
            if let Some(mut cursor) = subtree.cursor.take() {
                let left = quantum.saturating_sub(spent);
                if left == 0 {
                    subtree.cursor = Some(cursor);
                    return Step::Paused;
                }
                let (used, step) = self.advance(&mut cursor, left, &mut subtree.stack);
                spent += used;
                if step == Step::Ended {
                    continue;
                }
                subtree.cursor = Some(cursor);
                return step;
            }
            let Some((path, depth)) = subtree.stack.pop() else {
                return Step::Ended;
            };
            if self.out_of_entries() {
                subtree.stack.push((path, depth));
                return Step::OutOfEntries;
            }
            if self.out_of_time() {
                subtree.stack.push((path, depth));
                return Step::OutOfTime;
            }
            if let Some(cursor) = self.open(path, depth) {
                subtree.cursor = Some(cursor);
            }
        }
    }

    /// 一级目录之间**轮流**花预算：先扫完的会把额度让给还没扫完的。
    ///
    /// 这是「报告可信」的关键：深度优先一路走到底时，`/Applications` 这种十几万条的目录
    /// 会把条目上限吃干，`/Users` 连名字都进不了表；轮流切片的代价几乎为零，
    /// 但能保证**每个一级目录都被看到**。
    fn drain_round_robin(&mut self, subtrees: &mut [Subtree]) -> Step {
        let mut queue: VecDeque<usize> = (0..subtrees.len())
            .filter(|index| !subtrees[*index].finished())
            .collect();
        while let Some(index) = queue.pop_front() {
            let remaining = self.options.max_entries.saturating_sub(self.seen);
            if remaining == 0 {
                return Step::OutOfEntries;
            }
            if self.out_of_time() {
                return Step::OutOfTime;
            }
            // 平分剩下的条目（`+1` = 自己），再夹一个切片上限：
            // 既要公平，也不能让一个巨型目录在一轮里把所有人挤掉。
            let share = remaining / (queue.len() as u64 + 1);
            let quantum = share.clamp(1, SCAN_SLICE_ENTRIES);
            match self.drain_subtree(&mut subtrees[index], quantum) {
                Step::Ended => {}
                Step::Paused => queue.push_back(index),
                stop => return stop,
            }
        }
        Step::Ended
    }

    /// 收尾：排序、裁剪，并把**没扫完的一级目录**点名。
    fn finish(mut self, subtrees: &[Subtree]) -> WalkReport {
        sort_files(&mut self.top_files);
        self.top_files.truncate(self.options.top);
        self.report.top_files = self
            .top_files
            .drain(..)
            .map(|(size, path)| (path, size))
            .collect();

        let mut top_dirs: Vec<(String, u64)> =
            std::mem::take(&mut self.buckets).into_iter().collect();
        top_dirs.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        top_dirs.truncate(self.options.top);
        self.report.top_dirs = top_dirs;

        // 递归累计最大的目录（**任意深度**，不含根）：这才是「谁占的」的直接答案。
        let collected: Vec<(PathBuf, u64)> = self
            .dir_bytes
            .iter()
            .filter(|(path, bytes)| path.as_path() != self.options.root.as_path() && **bytes > 0)
            .map(|(path, bytes)| (path.clone(), *bytes))
            .collect();
        self.report.largest_dirs = prune_nested_ancestors(collected, self.options.top.max(1));

        self.report.hot_path = hot_path(&self.dir_bytes, &self.children, &self.options.root);

        // 没扫完的一级目录：**必须点名**。不然表里那几个数字会被当成本机全貌，
        // “/Users 只有 3 GiB”这种假象比没有结论更糟。
        let mut incomplete: Vec<(PathBuf, u64)> = subtrees
            .iter()
            .filter(|subtree| !subtree.finished())
            .map(|subtree| {
                (
                    subtree.root.clone(),
                    *self.dir_bytes.get(&subtree.root).unwrap_or(&0),
                )
            })
            .collect();
        incomplete.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
        self.report.incomplete_dirs = incomplete;

        self.report.elapsed_ms = self.started.elapsed().as_millis() as u64;
        self.report
    }
}

/// 有界目录遍历：**不跟随符号链接**、**不跨文件系统**、按条目/时长/深度三重封顶。
///
/// 三条「不」都是为了现场安全：
/// * 不跟符号链接 —— `/var/lib/docker/...` 里链接成环是常态，跟进去就是无限循环；
/// * 不跨文件系统 —— 扫 `/` 时不能把 `/data`、`/proc`、网络盘一起算进来（那会既慢又错）；
/// * 三重封顶 —— 这台机器正在扛业务，调查不能变成新的故障源。超限只标 `truncated`，不报错。
fn walk(options: &WalkOptions) -> io::Result<WalkReport> {
    let root_meta = fs::metadata(&options.root)?;
    if !root_meta.is_dir() {
        return Err(io::Error::new(
            io::ErrorKind::NotADirectory,
            "not a directory",
        ));
    }
    let mut walker = Walker::new(options, device_of(&root_meta));

    // 阶段一：先把扫描根的**一级子目录列全**（这层只有几十条，几乎不花预算）。
    // 这一步保证任何情况下「本机有哪些一级目录」都是完整的 —— 现场那句
    // 「共 3 个一级目录」正是这一层被深度优先截断的假象。
    let mut top: Vec<(PathBuf, usize)> = Vec::new();
    let root_step = match walker.open(options.root.clone(), 0) {
        Some(mut cursor) => walker.advance(&mut cursor, u64::MAX, &mut top).1,
        None => Step::Ended,
    };
    walker.report.top_level_dirs = top.len();
    let mut subtrees: Vec<Subtree> = top
        .into_iter()
        .map(|(path, depth)| Subtree::new(path, depth))
        .collect();

    // 阶段二：一级目录之间轮流分配剩下的预算。
    let step = if root_step == Step::Ended {
        walker.drain_round_robin(&mut subtrees)
    } else {
        root_step
    };
    if step != Step::Ended {
        walker.report.truncated = true;
    }

    Ok(walker.finish(&subtrees))
}

/// 排序 + **去掉“不提供新信息”的祖先**。
///
/// 一条主链（`/var → /var/lib → /var/lib/docker → …`）里每一层的递归体量完全一样：
/// 直接把 Top N 交出去，人会看到同一串数字重复四遍，而且真正的叶子可能被挤掉。
/// 所以：同体量时**深的优先**（“是它”要指向最具体的一层），且祖先若与已保留的后代
/// 体量几乎一样（多出来的 < 5%）就不列 —— 那种条目只说“还是那个目录”。
fn prune_nested_ancestors(mut entries: Vec<(PathBuf, u64)>, top: usize) -> Vec<(PathBuf, u64)> {
    entries.sort_by(|a, b| {
        b.1.cmp(&a.1)
            .then_with(|| b.0.components().count().cmp(&a.0.components().count()))
            .then_with(|| a.0.cmp(&b.0))
    });
    let mut kept: Vec<(PathBuf, u64)> = Vec::new();
    for candidate in entries {
        let redundant = kept.iter().any(|(kept_path, kept_bytes)| {
            kept_path.starts_with(&candidate.0)
                && kept_bytes.saturating_mul(100) >= candidate.1.saturating_mul(95)
        });
        if redundant {
            continue;
        }
        kept.push(candidate);
        if kept.len() >= top {
            break;
        }
    }
    kept
}

/// 逐层下钻：从根开始，每层选**占父级 ≥ [`HOT_PATH_DOMINANCE`]** 的子目录，
/// 直到不再集中（或到 [`HOT_PATH_MAX_DEPTH`]）。
///
/// 这就是「`du -h --max-depth=1 | sort -h | tail -1` 重复做」的自动化：
/// 一级目录全都不大但总盘满了时，它会把 `/var → /var/lib → /var/lib/docker → …` 这条
/// 真正在长的路径拎出来，而不是把一级目录表扔给人自己猜。
fn hot_path(
    dir_bytes: &BTreeMap<PathBuf, u64>,
    children: &BTreeMap<PathBuf, BTreeSet<PathBuf>>,
    root: &Path,
) -> Vec<(PathBuf, u64)> {
    let mut chain: Vec<(PathBuf, u64)> =
        vec![(root.to_path_buf(), *dir_bytes.get(root).unwrap_or(&0))];
    let mut current = root.to_path_buf();
    while chain.len() < HOT_PATH_MAX_DEPTH {
        let parent_bytes = *dir_bytes.get(&current).unwrap_or(&0);
        if parent_bytes == 0 {
            break;
        }
        let next = children.get(&current).and_then(|kids| {
            kids.iter()
                .map(|kid| (kid, *dir_bytes.get(kid).unwrap_or(&0)))
                .max_by(|a, b| a.1.cmp(&b.1).then_with(|| b.0.cmp(a.0)))
        });
        let Some((kid, kid_bytes)) = next else { break };
        // 子目录没到「占父级 60%」就不再往下：再往下已经是均摊，不是“谁在长”。
        if kid_bytes == 0
            || kid_bytes.saturating_mul(100) < parent_bytes.saturating_mul(HOT_PATH_DOMINANCE)
        {
            break;
        }
        chain.push((kid.clone(), kid_bytes));
        current = kid.clone();
    }
    // 只有根自己 = 没有集中点：不输出（避免多一节“什么也没说”的表）。
    if chain.len() < 2 { Vec::new() } else { chain }
}

/// 一个文件是否属于「可能被多个名字引用的 inode」；是则返回去重用的标识。
///
/// 非 Unix 平台拿不到 inode，退化成不去重（宁可多算也不误合并）。
#[cfg(unix)]
fn hardlink_identity(metadata: &fs::Metadata) -> Option<(u64, u64)> {
    use std::os::unix::fs::MetadataExt;
    if metadata.nlink() > 1 {
        Some((metadata.dev(), metadata.ino()))
    } else {
        None
    }
}

#[cfg(not(unix))]
fn hardlink_identity(_metadata: &fs::Metadata) -> Option<(u64, u64)> {
    None
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
    fn walk_keeps_every_top_level_directory_visible_under_a_tight_budget() {
        let dir = TempDir::new("fair-share");
        // 一个巨型目录：足够吃光小预算（现场就是 macOS 的 /Applications）。
        for index in 0..400 {
            write_file(&dir.path().join(format!("huge/f{index}.bin")), 1024);
        }
        for name in ["alpha", "beta", "gamma"] {
            write_file(&dir.path().join(format!("{name}/one.bin")), 2048);
        }
        let mut options = options(dir.path());
        options.max_entries = 60;

        let report = walk(&options).expect("walk");

        assert!(report.truncated, "预算不够必须如实标出来");
        // 一级目录的总数在预算之外先列全：不能再出现「共 3 个一级目录」那种假象。
        assert_eq!(report.top_level_dirs, 4);
        let labels: BTreeSet<&str> = report
            .top_dirs
            .iter()
            .map(|(label, _)| label.as_str())
            .collect();
        for name in ["alpha", "beta", "gamma"] {
            assert!(labels.contains(name), "{name} 被巨型目录挤掉了：{labels:?}");
        }
    }

    #[test]
    fn walk_names_the_top_level_dirs_that_did_not_finish() {
        let dir = TempDir::new("incomplete");
        for index in 0..200 {
            write_file(&dir.path().join(format!("big/f{index}.bin")), 4096);
        }
        for index in 0..200 {
            write_file(&dir.path().join(format!("bigger/deep/f{index}.bin")), 8192);
        }
        write_file(&dir.path().join("small/one.bin"), 16);
        let mut options = options(dir.path());
        options.max_entries = 40;

        let report = walk(&options).expect("walk");

        assert!(report.truncated);
        let names: Vec<String> = report
            .incomplete_dirs
            .iter()
            .map(|(path, _)| path.file_name().unwrap().to_string_lossy().to_string())
            .collect();
        // 没扫完的必须点名，否则表里那几个数字会被当成本机全貌。
        assert!(names.contains(&"big".to_string()), "{names:?}");
        assert!(names.contains(&"bigger".to_string()), "{names:?}");
        // 扫完的目录不该出现在「没扫完」里。
        assert!(!names.contains(&"small".to_string()), "{names:?}");
        assert!(
            report
                .incomplete_dirs
                .windows(2)
                .all(|pair| pair[0].1 >= pair[1].1),
            "没扫完的目录要按已扫到的体量降序：{:?}",
            report.incomplete_dirs
        );
    }

    #[test]
    fn a_giant_directory_cannot_swallow_its_siblings_slice() {
        let dir = TempDir::new("slice");
        // 两个都很「重」的一级目录：轮流切片后两边都得有数据。
        for index in 0..300 {
            write_file(&dir.path().join(format!("left/f{index}.bin")), 1024);
            write_file(&dir.path().join(format!("right/f{index}.bin")), 1024);
        }
        let mut options = options(dir.path());
        options.max_entries = 100;

        let report = walk(&options).expect("walk");

        let bytes: BTreeMap<&str, u64> = report
            .top_dirs
            .iter()
            .map(|(label, bytes)| (label.as_str(), *bytes))
            .collect();
        let left = *bytes.get("left").expect("left scanned");
        let right = *bytes.get("right").expect("right scanned");
        assert!(left > 0 && right > 0, "两边都得扫到：{bytes:?}");
        // “均分”不需要精确相等，但绝不允许一边把另一边饿死。
        let smaller = left.min(right);
        let larger = left.max(right);
        assert!(
            smaller.saturating_mul(4) >= larger,
            "切片不公平：left={left} right={right}"
        );
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

    /// 递归累计 + 下钻：一级目录“都不大”但深层目录占大头时，要能直接指出那条路径。
    ///
    /// 场景就是现场：容器层（`/var/lib/docker/overlay2/...`）吃了大块，单个文件都不算最大，
    /// 一级目录上看只有“/var 很大”——对下一步清理没有用。
    #[test]
    fn largest_dirs_aggregates_recursively_and_drills_down_the_dominant_path() {
        let dir = TempDir::new("recursive");
        // 深层元凶：三层以后的一堆中小文件。
        for index in 0..6 {
            write_file(
                &dir.path().join(format!(
                    "var/lib/docker/overlay2/layer{index}/diff/blob.bin"
                )),
                40_000,
            );
        }
        // 噪音：其它一级目录各一点。
        write_file(&dir.path().join("etc/app.conf"), 800);
        write_file(&dir.path().join("home/u/a.txt"), 2_000);

        let report = walk(&options(dir.path())).expect("walk");
        let hot = &report.hot_path;
        // 链：root → var → lib → docker → overlay2 → 某一层 …… 至少 5 层才说明真在往下钻。
        assert!(
            hot.len() >= 5,
            "热点链太短，下钻没生效：{:?}",
            hot.iter()
                .map(|(p, _)| p.display().to_string())
                .collect::<Vec<_>>()
        );
        assert!(hot[0].0 == dir.path(), "链头必须是扫描根");
        assert!(hot.iter().any(|(path, _)| path.ends_with("docker")));
        // 每层都是上一层的子路径（否则不是“链”）。
        for window in hot.windows(2) {
            assert!(
                window[1].0.starts_with(&window[0].0),
                "{:?} 不是 {:?} 的子路径",
                window[1].0,
                window[0].0
            );
            assert!(window[1].1 <= window[0].1, "子目录不能比父目录大");
        }

        // 递归累计第一：`overlay2`（祖先已被剪掉——`var`/`lib`/`docker` 与它体量一样，不提供新信息）。
        let (top_path, top_bytes) = report.largest_dirs.first().expect("largest dirs");
        assert_eq!(*top_bytes, 6 * 40_000);
        assert!(
            top_path.ends_with("overlay2"),
            "体量相同的祖先必须被剪掉，只留最具体的一层，实际 {}",
            top_path.display()
        );
        // 六个容器层均摊，没有单层占 60%：下钻链应在 overlay2 停下来（“集中点就是它”）。
        let (leaf, leaf_bytes) = hot.last().expect("hot path leaf");
        assert!(
            leaf.ends_with("overlay2"),
            "均摊时不该假装钻到某一层，实际 {}",
            leaf.display()
        );
        assert_eq!(*leaf_bytes, 6 * 40_000);

        // 一行人话：有表、有“该清哪里”的提示。
        let finding = largest_dirs_finding(&report);
        assert_eq!(finding.id, "disk.largest_dirs");
        assert!(!finding.rows.is_empty());
        let hint = finding.hint.expect("热点链必须作为提示给出来");
        assert!(hint.contains("热点路径"), "{hint}");
    }

    /// 集中在一层时，下钻必须一级一级地走到底（而不是停在“/var 很大”）。
    #[test]
    fn a_single_dominant_layer_is_drilled_all_the_way_down() {
        let dir = TempDir::new("dominant");
        write_file(
            &dir.path()
                .join("var/lib/docker/overlay2/layer3/diff/app/data.db"),
            500_000,
        );
        // 少量噪音：不能把集中度稀释到 60% 以下。
        write_file(
            &dir.path()
                .join("var/lib/docker/overlay2/layer0/diff/tiny.bin"),
            1_000,
        );
        write_file(&dir.path().join("etc/app.conf"), 500);

        let report = walk(&options(dir.path())).expect("walk");
        assert!(
            report.hot_path.len() >= 7,
            "集中度 99% 以上时必须一路钻到叶子，实际 {}",
            report.hot_path.len()
        );
        let (leaf, bytes) = report.hot_path.last().expect("leaf");
        assert!(
            leaf.ends_with("app"),
            "链末端应落在真正装数据的那个目录（app），实际 {}",
            leaf.display()
        );
        assert!(*bytes >= 500_000);
        // 人话提示里要带「该清哪一层」，而不是只给根目录。
        let hint = hot_path_hint(&report).expect("hint");
        assert!(hint.contains("热点路径"), "{hint}");
    }

    /// 硬链接只算一次：同一 inode 的第二个名字不该再计字节（经典 `du` 行为）。
    #[cfg(unix)]
    #[test]
    fn hardlinks_are_counted_once() {
        let dir = TempDir::new("hardlink");
        let original = dir.path().join("data/blob.bin");
        write_file(&original, 20_000);
        let link = dir.path().join("data/blob-link.bin");
        fs::hard_link(&original, &link).expect("hard link");

        let report = walk(&options(dir.path())).expect("walk");
        assert_eq!(report.total_bytes, 20_000, "硬链接不能把体积算两遍");
        assert_eq!(report.hardlinks_deduped, 20_000);
        // 两个名字都还在（文件数照实计）。
        assert_eq!(report.files, 2);
    }

    /// 「未归因」只对「扫描根就是挂载点」有意义：扫子目录时差量天然来自挂在同一分区的其它东西。
    #[test]
    fn unattributed_is_skipped_when_the_scan_root_is_a_subdirectory() {
        let walk = WalkReport {
            root: PathBuf::from("/var"),
            total_bytes: 1000,
            ..WalkReport::empty(PathBuf::from("/var"))
        };
        let filesystems = vec![fs_usage("/", 100_000, 10_000)];
        let finding = unattributed_finding(&walk, &filesystems);
        assert_eq!(finding.id, "disk.unattributed");
        assert_eq!(finding.status, Status::Ok);
        assert!(
            finding.title.contains("不适用"),
            "扫子目录时不该把整个分区的占用算成差量：{}",
            finding.title
        );
    }

    /// `df` 已用远大于扫描合计（且扫描完成）：必须提醒“还有东西不在这里”。
    #[test]
    fn a_large_gap_between_df_and_du_is_reported_as_unattributed() {
        let root = PathBuf::from("/data");
        let walk = WalkReport {
            root: root.clone(),
            total_bytes: 1_000_000_000,
            ..WalkReport::empty(root)
        };
        // 10 GiB 的盘，用了 9 GiB，但扫描只解释了 1 GB。
        let filesystems = vec![fs_usage("/data", 10 << 30, 1 << 30)];
        let finding = unattributed_finding(&walk, &filesystems);
        assert_eq!(finding.status, Status::Warn);
        assert!(finding.hint.is_some(), "要给出「为什么会差这么多」的方向");
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
    fn an_unfinished_top_level_directory_is_marked_in_the_table_and_the_hint() {
        let dir = TempDir::new("incomplete-render");
        for index in 0..300 {
            write_file(&dir.path().join(format!("big/f{index}.bin")), 512);
        }
        write_file(&dir.path().join("small/one.bin"), 512);
        let mut options = options(dir.path());
        options.max_entries = 40;
        let report = walk(&options).expect("walk");

        let finding = top_dirs_finding(&report, &[]);

        assert!(
            finding.detail.contains("共 2 个一级目录"),
            "一级目录总数必须是真的：{}",
            finding.detail
        );
        let big = finding
            .rows
            .iter()
            .find(|row| row.label.ends_with("big"))
            .expect("big row");
        assert!(
            big.note.contains("没扫完"),
            "没扫完的行必须标出来：{}",
            big.note
        );
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("--path"), "hint 要给重扫命令：{hint}");
        assert!(hint.contains("big"), "hint 要点名没扫完的目录：{hint}");

        // 「最大的目录」那一节同样要说清“还差在哪”，不能只给一张看起来完整的表。
        let largest = largest_dirs_finding(&report);
        assert!(largest.detail.contains("没扫完"), "{}", largest.detail);
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
