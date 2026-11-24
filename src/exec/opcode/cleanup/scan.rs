//! 清理的扫描核心：**只读**、有界、每类跳过原因都计数。
//!
//! 这里的每一条规则都是「不删什么」的证明，而不是「删什么」的建议：
//! 任何一条漏了，`apply` 就会删到不该删的东西。所以规则必须显式、可单测，
//! 不允许用「大概不是我们的文件」这种判断。

use std::collections::BTreeSet;
use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use std::time::{Duration, Instant, SystemTime};

use globset::{Glob, GlobSet, GlobSetBuilder};

/// 单次扫描最多看多少条目。
pub(super) const MAX_ENTRIES: u64 = 200_000;
/// 扫描「谁打开了哪些文件」的预算：与调查面同一量级。
#[cfg(any(target_os = "linux", target_os = "macos"))]
const MAX_FD_LINKS: u64 = 200_000;

#[derive(Debug, Default, serde::Serialize)]
pub(super) struct Skipped {
    pub young: u64,
    pub open: u64,
    pub symlink: u64,
    pub hardlink: u64,
    pub cross_device: u64,
    pub protected: u64,
    pub not_matching: u64,
    pub wrong_type: u64,
    pub unreadable: u64,
    pub dirs: u64,
    /// 根目录不存在。**不算“没扫完”**：`/var/tmp` 在精简容器里经常不存在，
    /// 把它当 incomplete 会让 `apply` 在不相关的主机上永远拒绝执行。
    pub missing_roots: u64,
}

#[derive(Debug)]
pub(super) struct Candidate {
    pub path: PathBuf,
    pub bytes: u64,
    pub age_secs: u64,
    pub open: bool,
}

pub(super) struct ScanOutput {
    pub candidates: Vec<Candidate>,
    pub skipped: Skipped,
    pub entries: u64,
    /// 扫描实际耗时。与预算一起看：只看 `entries` 判断不了“预算够不够”。
    pub duration_ms: u64,
    /// `false` = 有一块没扫完（预算 / 权限 / 占用检查被截断）。`apply` 必须因此中止。
    pub complete: bool,
    /// 本平台有没有「不 exec 就能查占用」的能力（Linux `/proc`、macOS libproc）。
    pub open_files_checked: bool,
}

pub(super) struct ScanRequest<'a> {
    pub roots: &'a [PathBuf],
    /// 根算 level 0；`depth = 1` 只扫根下条目，`2` 再进一层子目录。
    pub depth: usize,
    pub min_age: Duration,
    /// `true` = 按轮转命名过滤（`rotated_logs`）。
    pub rotated_names: bool,
    /// `true` = 被占用的文件也进候选（只在 preview 里有意义）。
    pub include_open_files: bool,
    pub deadline: Instant,
}

#[allow(dead_code)] // 非 Linux 上只会构造 `Unsupported`。
enum OpenScan {
    Unsupported,
    Supported {
        paths: BTreeSet<PathBuf>,
        complete: bool,
    },
}

pub(super) fn scan(req: &ScanRequest<'_>) -> ScanOutput {
    let started = Instant::now();
    let open = open_paths(req);
    let mut out = ScanOutput {
        candidates: Vec::new(),
        skipped: Skipped::default(),
        entries: 0,
        duration_ms: 0,
        complete: true,
        open_files_checked: matches!(open, OpenScan::Supported { .. }),
    };
    if let OpenScan::Supported {
        complete: false, ..
    } = open
    {
        out.complete = false;
    }
    let open_paths = match &open {
        OpenScan::Unsupported => None,
        OpenScan::Supported { paths, .. } => Some(paths),
    };

    for root in req.roots {
        let meta = match fs::metadata(root) {
            Ok(meta) => meta,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                out.skipped.missing_roots += 1;
                continue;
            }
            Err(_) => {
                out.skipped.unreadable += 1;
                out.complete = false;
                continue;
            }
        };
        if !meta.is_dir() {
            out.skipped.unreadable += 1;
            continue;
        }
        let root_dev = meta.dev();
        // 根本身允许是符号链接（macOS 的 `/var/log` → `/private/var/log`）：
        // 只对**条目**拒绝符号链接，根要先解析再扫。
        let canonical = fs::canonicalize(root).unwrap_or_else(|_| root.clone());
        walk(&canonical, 1, root_dev, req, open_paths, &mut out);
    }
    out.candidates.sort_by(|a, b| a.path.cmp(&b.path));
    out.duration_ms = started.elapsed().as_millis() as u64;
    out
}

fn walk(
    dir: &Path,
    level: usize,
    root_dev: u64,
    req: &ScanRequest<'_>,
    open: Option<&BTreeSet<PathBuf>>,
    out: &mut ScanOutput,
) {
    let Ok(entries) = fs::read_dir(dir) else {
        out.skipped.unreadable += 1;
        out.complete = false;
        return;
    };
    let mut entries: Vec<_> = entries.flatten().collect();
    entries.sort_by_key(|entry| entry.file_name());

    for entry in entries {
        if out.entries >= MAX_ENTRIES || Instant::now() >= req.deadline {
            out.complete = false;
            return;
        }
        out.entries += 1;
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().into_owned();

        let Ok(meta) = fs::symlink_metadata(&path) else {
            out.skipped.unreadable += 1;
            continue;
        };
        let file_type = meta.file_type();
        if file_type.is_symlink() {
            out.skipped.symlink += 1;
            continue;
        }
        if file_type.is_dir() {
            // 目标目录本身不再递归（`depth` 决定能进几层），已知的噪声目录也跳过。
            if req.depth > level && !excluded_dir(&name) {
                walk(&path, level + 1, root_dev, req, open, out);
            } else {
                out.skipped.dirs += 1;
            }
            continue;
        }
        if !file_type.is_file() {
            out.skipped.wrong_type += 1;
            continue;
        }
        if meta.dev() != root_dev {
            out.skipped.cross_device += 1;
            continue;
        }
        // 硬链接删一个不释放空间，还可能断掉另一条路径上的引用。
        if meta.nlink() > 1 {
            out.skipped.hardlink += 1;
            continue;
        }
        if protected_name(&name) {
            out.skipped.protected += 1;
            continue;
        }
        if req.rotated_names && !rotated_name(&name) {
            out.skipped.not_matching += 1;
            continue;
        }
        let Some(age_secs) = age_secs(&meta) else {
            out.skipped.unreadable += 1;
            continue;
        };
        if Duration::from_secs(age_secs) < req.min_age {
            out.skipped.young += 1;
            continue;
        }
        let in_use = open.is_some_and(|paths| paths.contains(&path));
        if in_use && !req.include_open_files {
            out.skipped.open += 1;
            continue;
        }
        out.candidates.push(Candidate {
            path,
            bytes: meta.len(),
            age_secs,
            open: in_use,
        });
    }
}

/// 距现在多少秒。mtime 在未来（时钟回拨）按 0 算。
///
/// `apply` 删除前的复查也用它：两边判断“过期”必须同一套算法。
pub(super) fn age_secs(meta: &fs::Metadata) -> Option<u64> {
    let modified = meta.modified().ok()?;
    Some(
        SystemTime::now()
            .duration_since(modified)
            .unwrap_or_default()
            .as_secs(),
    )
}

/// 永远不进清理集的目录（噪声 / 归别的组件管）。
fn excluded_dir(name: &str) -> bool {
    matches!(
        name,
        "journal" | "private" | "audit" | "containers" | "pods" | "lost+found"
    ) || name.starts_with("wist-")
}

/// 永远不删的文件（agent 自己的日志 + 当前正在写的日志 + 安全相关）。
fn protected_name(name: &str) -> bool {
    name.starts_with("wist-")
}

/// 轮转命名的闭集。
fn rotated_set() -> &'static GlobSet {
    static SET: OnceLock<GlobSet> = OnceLock::new();
    SET.get_or_init(|| {
        let mut builder = GlobSetBuilder::new();
        for pattern in [
            "*.gz",
            "*.xz",
            "*.bz2",
            "*.zip",
            "*.zst",
            "*.old",
            "*.[0-9]",
            "*.[0-9][0-9]",
        ] {
            builder.add(Glob::new(pattern).expect("static cleanup glob"));
        }
        builder.build().expect("static cleanup glob set")
    })
}

fn rotated_name(name: &str) -> bool {
    if protected_name(name) || never_rotated(name) {
        return false;
    }
    rotated_set().is_match(name)
}

/// 即使命中 glob 也不许删：当前日志、审计/登录记录、journal。
///
/// 安全/审计类日志用**前缀**判（`secure.1`、`btmp.1` 也算）：它们的保留期是合规策略，
/// 不应由“清理过期临时文件”顺手带走。
fn never_rotated(name: &str) -> bool {
    name.ends_with(".log")
        || name == "journal"
        || name.starts_with("journal.")
        || name.ends_with(".journal")
        || name.ends_with(".journal~")
        || name.starts_with("auth.log")
        || name.starts_with("secure")
        || name.starts_with("btmp")
        || name.starts_with("wtmp")
        || name.starts_with("lastlog")
        || name.starts_with("faillog")
}

fn open_paths(req: &ScanRequest<'_>) -> OpenScan {
    #[cfg(target_os = "linux")]
    {
        open_paths_linux(req)
    }
    #[cfg(target_os = "macos")]
    {
        open_paths_macos(req)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = req;
        OpenScan::Unsupported
    }
}

#[cfg(target_os = "linux")]
fn open_paths_linux(req: &ScanRequest<'_>) -> OpenScan {
    let mut paths = BTreeSet::new();
    let mut budget = MAX_FD_LINKS;
    let Ok(procs) = fs::read_dir("/proc") else {
        return OpenScan::Supported {
            paths,
            complete: false,
        };
    };
    for proc_entry in procs.flatten() {
        if budget == 0 || Instant::now() >= req.deadline {
            return OpenScan::Supported {
                paths,
                complete: false,
            };
        }
        let name = proc_entry.file_name();
        if !name
            .to_string_lossy()
            .bytes()
            .all(|byte| byte.is_ascii_digit())
        {
            continue;
        }
        let Ok(fds) = fs::read_dir(proc_entry.path().join("fd")) else {
            continue;
        };
        for fd in fds.flatten() {
            if budget == 0 || Instant::now() >= req.deadline {
                return OpenScan::Supported {
                    paths,
                    complete: false,
                };
            }
            budget -= 1;
            let Ok(target) = fs::read_link(fd.path()) else {
                continue;
            };
            // 只收绝对路径；`socket:[..]` / `pipe:[..]` / 已删除文件都不算占用。
            if !target.is_absolute() {
                continue;
            }
            if target.to_string_lossy().ends_with(" (deleted)") {
                continue;
            }
            paths.insert(target);
        }
    }
    OpenScan::Supported {
        paths,
        complete: true,
    }
}

/// macOS：`proc_listallpids` → 每个 pid 的 vnode fd → `proc_pidfdinfo(PROC_PIDFDVNODEPATHINFO)`。
///
/// 与 Linux 的 `/proc` 同一套口径：
/// * 看不到某个 pid（权限不足 / 刚退出）就跳过它 —— 和 `/proc/<pid>/fd` 读不开时一样，
///   不把「看不了」当成「除没被占用之外的东西」（两端都是 root 才看得全，agentd 作为
///   系统服务以 root 跑）；
/// * 预算 / deadline 用尽 = 没扫完，`apply` 必须中止；
/// * 只收 vnode（普通文件）路径，socket / pipe / kqueue 不参与。
///
/// 另外一条比 Linux 更严的守闸：拿到的路径**不是绝对路径**时直接认定「没扫完」。
/// 正常 vnode 不会给相对路径；出现这种情况只可能是超长路径被内核截成了尾段，
/// 那这个 fd 到底指向哪个文件就无法确定了 —— 宁可不删，也不猜。
#[cfg(target_os = "macos")]
fn open_paths_macos(req: &ScanRequest<'_>) -> OpenScan {
    use crate::sys_libproc;

    let mut paths = BTreeSet::new();
    let mut budget = MAX_FD_LINKS;
    let Ok(pids) = sys_libproc::list_all_pids() else {
        return OpenScan::Supported {
            paths,
            complete: false,
        };
    };
    for pid in pids {
        if budget == 0 || Instant::now() >= req.deadline {
            return OpenScan::Supported {
                paths,
                complete: false,
            };
        }
        let Ok(fds) = sys_libproc::list_fds(pid) else {
            continue;
        };
        for fd in fds {
            if budget == 0 || Instant::now() >= req.deadline {
                return OpenScan::Supported {
                    paths,
                    complete: false,
                };
            }
            budget -= 1;
            if fd.proc_fdtype as libc::c_int != libc::PROX_FDTYPE_VNODE {
                continue;
            }
            if let Some(path) = sys_libproc::vnode_path(pid, fd.proc_fd) {
                if !path.is_absolute() {
                    return OpenScan::Supported {
                        paths,
                        complete: false,
                    };
                }
                paths.insert(path);
            }
        }
    }
    OpenScan::Supported {
        paths,
        complete: true,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-cleanup-scan-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn request<'a>(roots: &'a [PathBuf], min_age: Duration) -> ScanRequest<'a> {
        ScanRequest {
            roots,
            depth: 1,
            min_age,
            rotated_names: false,
            include_open_files: false,
            deadline: Instant::now() + Duration::from_secs(10),
        }
    }

    fn write_old(path: &Path, bytes: usize, age: Duration) {
        fs::write(path, vec![0u8; bytes]).expect("write file");
        let modified = SystemTime::now() - age;
        filetime_set(path, modified);
    }

    /// 只设 mtime；不引入额外依赖。
    fn filetime_set(path: &Path, modified: SystemTime) {
        use std::fs::FileTimes;
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for times");
        let times = FileTimes::new().set_modified(modified);
        file.set_times(times).expect("set mtime");
    }

    #[test]
    fn old_regular_files_become_candidates_and_young_ones_are_skipped() {
        let dir = temp_dir("age");
        write_old(&dir.join("old.tmp"), 10, Duration::from_secs(48 * 3600));
        write_old(&dir.join("new.tmp"), 10, Duration::from_secs(60));

        let roots = vec![dir.clone()];
        let out = scan(&request(&roots, Duration::from_secs(24 * 3600)));

        assert!(out.complete);
        assert_eq!(out.candidates.len(), 1);
        assert!(out.candidates[0].path.ends_with("old.tmp"));
        assert_eq!(out.skipped.young, 1);
    }

    #[test]
    fn symlinks_and_hardlinks_are_never_candidates() {
        let dir = temp_dir("links");
        let real = dir.join("real.tmp");
        write_old(&real, 10, Duration::from_secs(48 * 3600));
        #[cfg(unix)]
        {
            std::os::unix::fs::symlink(&real, dir.join("link.tmp")).expect("symlink");
            fs::hard_link(&real, dir.join("hard.tmp")).expect("hardlink");
        }

        let roots = vec![dir.clone()];
        let out = scan(&request(&roots, Duration::from_secs(3600)));

        assert_eq!(out.skipped.symlink, 1);
        // real 与 hard 互为硬链接（nlink = 2），两个都应被跳过。
        assert_eq!(out.skipped.hardlink, 2);
        assert!(out.candidates.is_empty());
    }

    #[test]
    fn subdirectories_are_not_descended_when_depth_is_one() {
        let dir = temp_dir("depth");
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).expect("nested");
        write_old(&nested.join("old.tmp"), 10, Duration::from_secs(48 * 3600));

        let roots = vec![dir.clone()];
        let out = scan(&request(&roots, Duration::from_secs(3600)));

        assert!(out.candidates.is_empty());
        assert_eq!(out.skipped.dirs, 1);
    }

    #[test]
    fn a_missing_root_is_not_an_incomplete_scan() {
        // `/var/tmp` 在精简容器里经常不存在；它不能让 apply 永久拒绝执行。
        let dir = temp_dir("missing-root");
        write_old(&dir.join("a.tmp"), 10, Duration::from_secs(48 * 3600));
        let missing = dir.join("does-not-exist");
        let roots = vec![dir.clone(), missing];

        let out = scan(&request(&roots, Duration::from_secs(3600)));

        assert!(out.complete, "a missing root must not block apply");
        assert_eq!(out.skipped.missing_roots, 1);
        assert_eq!(out.candidates.len(), 1);
    }

    /// 占用检查：本进程打开着的文件不进候选（删了也不释放空间）。
    ///
    /// 两端走不同内核接口（Linux `/proc/<pid>/fd`、macOS libproc 的 vnode fd），
    /// 所以这个用例同时也是 macOS 侧 `open_paths_macos` 的第一条真实验证。
    #[test]
    fn files_held_open_are_skipped_unless_requested() {
        let dir = temp_dir("open");
        let path = dir.join("held.tmp");
        write_old(&path, 10, Duration::from_secs(48 * 3600));
        let _held = fs::File::open(&path).expect("hold open");

        let roots = vec![dir.clone()];
        let out = scan(&request(&roots, Duration::from_secs(3600)));
        assert!(out.open_files_checked, "本平台必须能查占用");
        assert_eq!(out.skipped.open, 1, "打开着的文件必须被跳过并计数");
        assert!(out.candidates.is_empty());
        assert!(path.exists(), "跳过 ≠ 删除");

        // `preview` 允许列出被占用的文件（只是标上 `open`）。
        let mut listing = request(&roots, Duration::from_secs(3600));
        listing.include_open_files = true;
        let out = scan(&listing);
        assert_eq!(out.candidates.len(), 1);
        assert!(out.candidates[0].open);
    }

    #[test]
    fn rotated_names_stay_closed_and_never_include_active_logs() {
        for name in ["messages.1", "messages.10", "access.log.2.gz", "old.xz"] {
            assert!(rotated_name(name), "{name} should match");
        }
        for name in [
            "messages.log",
            "journal",
            "system.journal",
            "auth.log.1",
            "wist-agentd.log.1",
            "secure.1",
            "btmp.1",
            "wtmp.2",
            "lastlog.1",
            "faillog.1",
        ] {
            assert!(!rotated_name(name), "{name} must not match");
        }
    }

    #[test]
    fn protected_and_noise_names_are_rejected() {
        assert!(protected_name("wist-agentd.log"));
        for name in [
            "journal",
            "private",
            "audit",
            "containers",
            "pods",
            "lost+found",
        ] {
            assert!(excluded_dir(name), "{name} should be excluded");
        }
    }
}
