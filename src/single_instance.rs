//! 单实例锁：同一数据 home（state 目录）下只允许一个 `wist-agentd` 进程。
//!
//! 用 `flock(LOCK_EX | LOCK_NB)` 对 state 目录下的锁文件加排他锁。锁挂在打开的文件
//! 描述符上，进程退出（含崩溃 / kill -9）时内核自动释放，因此不存在 pidfile 那种
//! 「stale 文件要清理、pid 被复用误判」的问题，也覆盖 `start.sh`、`--foreground`、
//! 直接运行二进制等所有入口。

use std::fs::{self, File, OpenOptions};
use std::io;
use std::path::{Path, PathBuf};

use orion_error::{conversion::ToStructError, prelude::*};

use crate::error::{AgentdReason, AgentdResult};

const LOCK_FILE_NAME: &str = ".agentd.lock";

/// 已持有的单实例锁。drop 时释放锁并关闭文件描述符。
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    #[allow(dead_code)]
    path: PathBuf,
}

impl Drop for InstanceLock {
    fn drop(&mut self) {
        // 显式解锁，而不是只靠关 fd：`flock` 的锁挂在**打开文件描述**上，
        // 只 close 本 fd 不会释放锁 —— 要等这份描述的所有副本都关掉才释放。
        // 进程若在此期间 fork 过（其他线程起子进程），子进程会继承一份副本，
        // 于是「drop 即已释放」并不成立（并发跑测试时这就是那个偶发红）。
        // 显式 `LOCK_UN` 直接解掉这份描述上的锁，释放才是确定的。
        unlock(&self._file);
    }
}

/// 为 `state_dir` 获取单实例锁（必要时创建目录）。
///
/// 若已有另一个进程持有该锁，返回 [`AgentdReason::AlreadyRunning`]。
pub fn acquire(state_dir: &Path) -> AgentdResult<InstanceLock> {
    fs::create_dir_all(state_dir).source_err(
        AgentdReason::system_error(),
        "create state dir for instance lock",
    )?;

    let path = state_dir.join(LOCK_FILE_NAME);
    let file = OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .open(&path)
        .source_err(AgentdReason::system_error(), "open instance lock file")?;

    try_lock(&file).map_err(|err| {
        if err.kind() == io::ErrorKind::WouldBlock {
            AgentdReason::AlreadyRunning.to_err().with_detail(format!(
                "another wist-agentd instance is already running (lock file: {})",
                path.display()
            ))
        } else {
            AgentdReason::system_error()
                .to_err()
                .with_detail(format!("lock instance file {}: {err}", path.display()))
        }
    })?;

    Ok(InstanceLock { _file: file, path })
}

#[cfg(unix)]
fn try_lock(file: &File) -> io::Result<()> {
    use std::os::fd::AsRawFd;

    let ret = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) };
    if ret == 0 {
        Ok(())
    } else {
        Err(io::Error::last_os_error())
    }
}

/// 显式释放这把锁（只影响本进程持有的这份打开文件描述）。
#[cfg(unix)]
fn unlock(file: &File) {
    use std::os::fd::AsRawFd;

    // 解不释放都不是发现新错误的时候：drop 里不报错，交给随后的 close 兜底。
    unsafe {
        libc::flock(file.as_raw_fd(), libc::LOCK_UN);
    }
}

#[cfg(not(unix))]
fn unlock(_file: &File) {}

#[cfg(not(unix))]
fn try_lock(_file: &File) -> io::Result<()> {
    // 非 Unix 平台没有 flock；退化为「尽力而为」的锁文件（仍持有打开句柄，但缺少
    // 内核级排他保证）。
    Ok(())
}

/// 只读探测：`state_dir` 下的单实例锁当前是否已被某个进程持有。
///
/// 锁文件不存在时返回 `Ok(false)`（不创建任何目录/文件）；探测成功会立即释放锁，
/// 因此不会影响真正的 daemon 启动。
pub fn is_held(state_dir: &Path) -> io::Result<bool> {
    let path = state_dir.join(LOCK_FILE_NAME);
    if !path.exists() {
        return Ok(false);
    }
    // 只读打开：`flock` 不要求写权限，这样非 root 用户也能探测 root 所属的锁文件
    // （`service status --system` 不该因为读不到写权限就整个失败）。
    let file = OpenOptions::new().read(true).open(&path)?;
    match try_lock(&file) {
        Ok(()) => Ok(false),
        Err(err) if err.kind() == io::ErrorKind::WouldBlock => Ok(true),
        Err(err) => Err(err),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(label: &str) -> PathBuf {
        // 不能只拿时钟拼目录：macOS 上 `SystemTime::now()` 是微秒分辨率，并行跑的
        // 几个用例可能落在同一微秒里 → 撞到同一个目录 → 别人持有的 flock 把
        // `acquire after release` 顶成 AlreadyRunning（就是以前的那个偶发红）。
        // 加一个进程内原子序号，保证每个用例拿到互不相同的目录。
        static COUNTER: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let seq = COUNTER.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-agentd-lock-test-{label}-{nanos}-{seq}"))
    }

    #[cfg(unix)]
    #[test]
    fn second_acquire_fails_until_first_is_dropped() {
        let dir = temp_dir("second-acquire");
        let first = acquire(&dir).expect("first acquire");
        let err = acquire(&dir).expect_err("second acquire should fail");
        assert_eq!(err.reason(), &AgentdReason::AlreadyRunning);

        drop(first);
        let _again = acquire(&dir).expect("acquire after release");
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn is_held_does_not_require_write_permission_on_the_lock_file() {
        use std::os::unix::fs::PermissionsExt;

        let dir = temp_dir("readonly-probe");
        let _lock = acquire(&dir).expect("acquire");
        let lock_path = dir.join(LOCK_FILE_NAME);
        // 模拟“锁文件属于别人”：只读权限也应当能探测（服务级安装以 root 运行时的常见情形）。
        fs::set_permissions(&lock_path, fs::Permissions::from_mode(0o400)).expect("chmod 400");

        assert!(is_held(&dir).expect("probe read-only lock"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[test]
    fn is_held_tracks_lock_ownership_without_creating_state() {
        let dir = temp_dir("held-tracking");
        // 目录/锁文件都不存在时不得产生副作用。
        assert!(!is_held(&dir).expect("no lock file"));
        assert!(!dir.exists());

        let lock = acquire(&dir).expect("acquire");
        assert!(is_held(&dir).expect("held"));

        drop(lock);
        assert!(!is_held(&dir).expect("released"));
        let _ = fs::remove_dir_all(&dir);
    }
}
