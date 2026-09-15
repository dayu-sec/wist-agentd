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

/// 已持有的单实例锁。drop 时关闭文件描述符、释放锁。
#[derive(Debug)]
pub struct InstanceLock {
    _file: File,
    #[allow(dead_code)]
    path: PathBuf,
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

#[cfg(not(unix))]
fn try_lock(_file: &File) -> io::Result<()> {
    // 非 Unix 平台没有 flock；退化为「尽力而为」的锁文件（仍持有打开句柄，但缺少
    // 内核级排他保证）。
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[cfg(unix)]
    #[test]
    fn second_acquire_fails_until_first_is_dropped() {
        let dir = temp_dir();
        let first = acquire(&dir).expect("first acquire");
        let err = acquire(&dir).expect_err("second acquire should fail");
        assert_eq!(err.reason(), &AgentdReason::AlreadyRunning);

        drop(first);
        let _again = acquire(&dir).expect("acquire after release");
        let _ = fs::remove_dir_all(&dir);
    }

    fn temp_dir() -> PathBuf {
        let nanos = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-agentd-lock-test-{nanos}"))
    }
}
