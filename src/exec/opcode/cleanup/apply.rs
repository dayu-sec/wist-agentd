//! 删除与后验。删除是**不可回滚**的，所以这里只做机械动作：
//! 候选集与上限的判定在 handler 里，进到这里就只剩「逐条复查、删、如实记」。
//!
//! 为什么要复查：扫描到删除之间有时间窗。路径可能已被别人删掉、被重建为一个新文件
//! （新文件不该顺手删）、被换成符号链接或目录、或者被重新写入。这里不做「再扫一遍」，
//! 只对**已有候选**再确认一次它还是「那个旧的普通文件」，不成立就跳过并计数。

use std::fs;
use std::io;
use std::os::unix::fs::MetadataExt;
use std::path::Path;
use std::time::Duration;

use super::scan::{self, Candidate};

#[derive(Debug)]
pub(super) struct DeleteError {
    pub path: String,
    pub code: &'static str,
}

#[derive(Debug, Default)]
pub(super) struct ApplyOutcome {
    pub deleted_files: u64,
    pub deleted_bytes: u64,
    pub errors: Vec<DeleteError>,
    pub error_total: u64,
}

pub(super) fn delete_all(candidates: &[Candidate], min_age: Duration) -> ApplyOutcome {
    let mut out = ApplyOutcome::default();
    for candidate in candidates {
        if let Err(code) = recheck(candidate, min_age) {
            out.record_error(candidate, code);
            continue;
        }
        match fs::remove_file(&candidate.path) {
            Ok(()) => {
                out.deleted_files += 1;
                out.deleted_bytes = out.deleted_bytes.saturating_add(candidate.bytes);
            }
            Err(err) => out.record_error(candidate, io_code(&err)),
        }
    }
    out
}

impl ApplyOutcome {
    /// 只留前 20 条明细：结果要能看，不是错误日志转储。
    fn record_error(&mut self, candidate: &Candidate, code: &'static str) {
        self.error_total += 1;
        if self.errors.len() < 20 {
            self.errors.push(DeleteError {
                path: candidate.path.display().to_string(),
                code,
            });
        }
    }
}

/// 删除前的最后一道确认：路径还在、还是普通文件、没有多出硬链接、依然“过期”。
fn recheck(candidate: &Candidate, min_age: Duration) -> Result<(), &'static str> {
    let meta = match fs::symlink_metadata(&candidate.path) {
        Ok(meta) => meta,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Err("not_found"),
        Err(_) => return Err("stat_failed"),
    };
    if !meta.file_type().is_file() || meta.nlink() > 1 {
        return Err("changed_since_scan");
    }
    match scan::age_secs(&meta) {
        Some(age) if Duration::from_secs(age) >= min_age => Ok(()),
        // mtime 变新（或读数失败）= 有人在写：它“过期”的前提已经不成立。
        _ => Err("changed_since_scan"),
    }
}

fn io_code(err: &io::Error) -> &'static str {
    match err.kind() {
        io::ErrorKind::PermissionDenied => "permission_denied",
        io::ErrorKind::NotFound => "not_found",
        io::ErrorKind::IsADirectory => "is_directory",
        _ => "remove_failed",
    }
}

/// 根所在挂载点的可用字节。找不到匹配的挂载点返回 `None`（不伪造 0）。
pub(super) fn free_space_for(path: &Path) -> Option<(String, u64)> {
    let disks = sysinfo::Disks::new_with_refreshed_list();
    let mut best: Option<(String, u64)> = None;
    for disk in disks.list() {
        let mount = disk.mount_point();
        if !path.starts_with(mount) {
            continue;
        }
        let longer = best
            .as_ref()
            .map(|(current, _)| mount.as_os_str().len() > current.len())
            .unwrap_or(true);
        if longer {
            best = Some((mount.display().to_string(), disk.available_space()));
        }
    }
    best
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-cleanup-apply-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn candidate(path: PathBuf, bytes: u64) -> Candidate {
        Candidate {
            path,
            bytes,
            age_secs: 100_000,
            open: false,
        }
    }

    /// 写一个「确实过期」的文件：内容 + 48 小时前的 mtime。
    fn write_old(path: &Path, bytes: usize) {
        fs::write(path, vec![0u8; bytes]).expect("write file");
        let file = fs::OpenOptions::new()
            .write(true)
            .open(path)
            .expect("open for times");
        let modified = std::time::SystemTime::now() - Duration::from_secs(48 * 3_600);
        file.set_times(fs::FileTimes::new().set_modified(modified))
            .expect("set mtime");
    }

    const MIN_AGE: Duration = Duration::from_secs(3_600);

    #[test]
    fn deletes_only_the_given_candidates_and_counts_bytes() {
        let dir = temp_dir("delete");
        let a = dir.join("a.tmp");
        let b = dir.join("b.tmp");
        write_old(&a, 11);
        write_old(&b, 7);

        let out = delete_all(
            &[candidate(a.clone(), 11), candidate(b.clone(), 7)],
            MIN_AGE,
        );

        assert_eq!(out.deleted_files, 2);
        assert_eq!(out.deleted_bytes, 18);
        assert!(out.errors.is_empty());
        assert!(!a.exists() && !b.exists());
    }

    #[test]
    fn missing_files_are_reported_per_path_not_fatal() {
        let dir = temp_dir("missing");
        let gone = dir.join("gone.tmp");
        let alive = dir.join("alive.tmp");
        write_old(&alive, 5);

        let out = delete_all(
            &[candidate(gone.clone(), 1), candidate(alive.clone(), 5)],
            MIN_AGE,
        );

        assert_eq!(out.deleted_files, 1);
        assert_eq!(out.error_total, 1);
        assert_eq!(out.errors[0].code, "not_found");
        assert!(!alive.exists());
    }

    #[test]
    fn a_fresh_file_recreated_at_the_same_path_is_not_deleted() {
        // 扫描时它是过期的；删除前被别人删掉并重建了一个新文件 —— 不能顺手删。
        let dir = temp_dir("recreated");
        let path = dir.join("recreated.tmp");
        write_old(&path, 5);
        let candidate = candidate(path.clone(), 5);

        fs::remove_file(&path).expect("simulate removal");
        fs::write(&path, b"fresh").expect("simulate recreation");

        let out = delete_all(&[candidate], MIN_AGE);

        assert_eq!(out.deleted_files, 0);
        assert_eq!(out.errors[0].code, "changed_since_scan");
        assert!(path.exists(), "the fresh file must survive");
    }

    #[test]
    fn a_path_swapped_for_a_symlink_is_not_followed() {
        let dir = temp_dir("swapped");
        let target = dir.join("target.tmp");
        write_old(&target, 5);
        let link = dir.join("link.tmp");
        write_old(&link, 5);
        let candidate = candidate(link.clone(), 5);

        fs::remove_file(&link).expect("simulate removal");
        std::os::unix::fs::symlink(&target, &link).expect("simulate swap");

        let out = delete_all(&[candidate], MIN_AGE);

        assert_eq!(out.deleted_files, 0);
        assert_eq!(out.errors[0].code, "changed_since_scan");
        assert!(target.exists(), "the link target must survive");
    }

    #[test]
    fn free_space_is_reported_for_a_known_mount_or_not_at_all() {
        let dir = temp_dir("free");
        let found = free_space_for(&dir);
        assert!(found.is_some(), "the temp dir must live on some mount");
        let (mount, bytes) = found.expect("mount");
        assert!(!mount.is_empty());
        assert!(bytes > 0);
    }
}
