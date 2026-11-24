//! macOS `libproc` 的最小公共层：进程表、fd 表、vnode 路径。
//!
//! 为什么单独一层：两个消费者查的是同一份内核视图，各写一套 FFI 迟早漂。
//!
//! - `discovery::endpoint::endpoint_macos`：按 pid 找 **socket** fd（谁在监听）；
//! - `exec::opcode::cleanup`：按 pid 找 **vnode** fd 的路径（哪些文件被占用，
//!   `disk.cleanup.apply` 据此跳过「删了也不释放空间」的文件）。
//!
//! 为什么是 libproc 而不是 `lsof`（与发现侧同一结论）：长驻探针不该靠外部二进制，
//! 否则生产机上「没装 / 版本不一致 / PATH 不对」都会变成现场故障；而 libproc 的可见性
//! 与 Linux 的 `/proc` 一致 —— root 能看全，普通用户只看得到自己的进程。
//!
//! 结构体的字段顺序/类型必须与 `sys/proc_info.h` 逐字对齐：一个偏移错了，读出来的
//! 就是别的字段（或一段越界的字节）。

use std::ffi::c_void;
use std::io;
use std::mem;
use std::os::unix::ffi::OsStrExt;
use std::path::PathBuf;

/// `sys/proc_info.h`: `PROC_PIDFDVNODEPATHINFO`（libc 只导出了 socket 那组常量）。
const PROC_PIDFDVNODEPATHINFO: libc::c_int = 2;

/// `sys/proc_info.h`: `MAXPATHLEN`。
const MAXPATHLEN: usize = 1024;

// ── libproc 结构体 ─────────────────────────────────────────

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)] // 布局由 C 头文件决定；不读的字段也必须声明。
pub(crate) struct ProcFileInfo {
    pub fi_openflags: u32,
    pub fi_status: u32,
    pub fi_offset: i64,
    pub fi_type: i32,
    pub fi_guardflags: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct VinfoStat {
    pub vst_dev: u32,
    pub vst_mode: u16,
    pub vst_nlink: u16,
    pub vst_ino: u64,
    pub vst_uid: u32,
    pub vst_gid: u32,
    pub vst_atime: i64,
    pub vst_atimensec: i64,
    pub vst_mtime: i64,
    pub vst_mtimensec: i64,
    pub vst_ctime: i64,
    pub vst_ctimensec: i64,
    pub vst_birthtime: i64,
    pub vst_birthtimensec: i64,
    pub vst_size: i64,
    pub vst_blocks: i64,
    pub vst_blksize: i32,
    pub vst_flags: u32,
    pub vst_gen: u32,
    pub vst_rdev: u32,
    pub vst_qspare: [i64; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct Fsid {
    pub val: [i32; 2],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct VnodeInfo {
    pub vi_stat: VinfoStat,
    pub vi_type: libc::c_int,
    pub vi_pad: libc::c_int,
    pub vi_fsid: Fsid,
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct VnodeInfoPath {
    pub vip_vi: VnodeInfo,
    /// 文件路径（`PROC_PIDFDVNODEPATHINFO` 下是**绝对路径**）。
    pub vip_path: [libc::c_char; MAXPATHLEN],
}

#[repr(C)]
#[derive(Clone, Copy)]
#[allow(dead_code)]
pub(crate) struct VnodeFdInfoWithPath {
    pub pfi: ProcFileInfo,
    pub pvip: VnodeInfoPath,
}

// ── 取数 ──────────────────────────────────────────────────

/// 本机全部进程号（升序不保证；调用方按需要自己排）。
///
/// 枚举期间会有进程创建/退出：缓冲区塞满就加大重试（与 [`list_fds`] 同理，
/// 「漏看一个进程」和「漏看一个 fd」一样，都会让占用检查失真）。
pub(crate) fn list_all_pids() -> io::Result<Vec<u32>> {
    let mut margin = 32usize;
    let mut last = Vec::new();

    for _ in 0..3 {
        let count = unsafe { libc::proc_listallpids(std::ptr::null_mut(), 0) };
        if count <= 0 {
            return Err(io::Error::last_os_error());
        }
        let capacity = count as usize + margin;
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
        last = pids
            .into_iter()
            .filter(|pid| *pid > 0)
            .map(|pid| pid as u32)
            .collect();
        if (written as usize) < capacity {
            return Ok(last);
        }
        margin = margin.saturating_mul(8);
    }
    // 三轮都塞满（进程创建风暴）：如实返回最后一轮读到的部分。
    Ok(last)
}

/// 一个进程的全部 fd（含类型，由 `proc_fdtype` 给出）。
///
/// 权限不足 / 进程刚退出时返回 `Err`：调用方按「这个 pid 看不到」处理，
/// 不要把它当成「这个进程没有打开的文件」。
///
/// 先问一次尺寸、再读一次 —— 两次调用之间进程还能再开 fd。余量被塞满就加大重试
/// （最多 3 轮）：对 `disk.cleanup.apply` 来说，「漏看一个 fd」= 删掉一个正在写的文件。
pub(crate) fn list_fds(pid: u32) -> io::Result<Vec<libc::proc_fdinfo>> {
    let pid = pid as libc::c_int;
    let fd_size = mem::size_of::<libc::proc_fdinfo>();
    let mut margin = 8usize;
    let mut last = Vec::new();

    for _ in 0..3 {
        let bytes =
            unsafe { libc::proc_pidinfo(pid, libc::PROC_PIDLISTFDS, 0, std::ptr::null_mut(), 0) };
        if bytes <= 0 {
            return Err(io::Error::last_os_error());
        }
        let capacity = bytes as usize / fd_size + margin;
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
        last = Vec::with_capacity(count);
        for index in 0..count {
            let offset = index * fd_size;
            last.push(unsafe {
                std::ptr::read_unaligned(buffer.as_ptr().add(offset) as *const libc::proc_fdinfo)
            });
        }
        if count < capacity {
            break;
        }
        // 缓冲区被塞满：进程在我们读的间隙又开了 fd，加预算重来。
        margin = margin.saturating_mul(8);
    }
    // 三轮都塞满（异常繁忙的进程）：如实返回最后一轮读到的部分。
    Ok(last)
}

/// vnode fd 指向的路径。读不到（进程刚退出 / 权限 / 不是 vnode）时返回 `None`。
///
/// 两个容易被误读的行为：
/// * **被删除但仍打开的文件会返回它原来的路径**（不像 Linux 会带 ` (deleted)` 后缀）。
///   这比 Linux 更保守：同名文件被重建后，我们会把它当作“被占用”而不删。
/// * 路径超过 `MAXPATHLEN` 时内核只给尾段（见头文件 `vip_path` 的注释），
///   调用方必须拒绝**非绝对路径**的结果（见 `cleanup::scan::open_paths_macos`）。
///
/// **不用 `to_string_lossy`**：路径要和扫描得到的 `PathBuf` 逐字节比对，
/// 非 UTF-8 的名字一旦被替换字符改写，就会「看起来没人占用」而被删掉。
pub(crate) fn vnode_path(pid: u32, fd: i32) -> Option<PathBuf> {
    let mut info: VnodeFdInfoWithPath = unsafe { mem::zeroed() };
    let size = mem::size_of::<VnodeFdInfoWithPath>() as libc::c_int;
    let written = unsafe {
        libc::proc_pidfdinfo(
            pid as libc::c_int,
            fd,
            PROC_PIDFDVNODEPATHINFO,
            &mut info as *mut VnodeFdInfoWithPath as *mut c_void,
            size,
        )
    };
    if written <= 0 {
        return None;
    }
    // 用**有界**的读法：万一内核没有补 NUL，`CStr::from_ptr` 会越界读（UB）。
    let raw: &[u8] =
        unsafe { std::slice::from_raw_parts(info.pvip.vip_path.as_ptr() as *const u8, MAXPATHLEN) };
    let bytes = std::ffi::CStr::from_bytes_until_nul(raw).ok()?.to_bytes();
    if bytes.is_empty() {
        return None;
    }
    Some(PathBuf::from(std::ffi::OsStr::from_bytes(bytes)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;

    /// 布局回归：数字来自 C 侧 `sizeof`（`clang` + SDK 的 `sys/proc_info.h`，
    /// macOS 14 SDK）：`proc_fileinfo=24`、`vinfo_stat=136`、`vnode_info=152`、
    /// `vnode_info_path=1176`、`vnode_fdinfowithpath=1200`、
    /// `offsetof(vnode_fdinfowithpath, pvip.vip_path)=176`。
    ///
    /// 任一数字对不上就说明字段声明漂了 —— `vip_path` 读出来的就是别的字段的字节，
    /// 占用检查会静默失效（比报错危险得多）。
    #[test]
    fn struct_layout_matches_the_sdk() {
        assert_eq!(mem::size_of::<ProcFileInfo>(), 24);
        assert_eq!(mem::size_of::<VinfoStat>(), 136);
        assert_eq!(mem::size_of::<VnodeInfo>(), 152);
        assert_eq!(mem::size_of::<VnodeInfoPath>(), 1176);
        assert_eq!(mem::size_of::<VnodeFdInfoWithPath>(), 1200);
        assert_eq!(mem::offset_of!(VnodeFdInfoWithPath, pvip.vip_path), 176);
    }

    #[test]
    fn the_pid_list_contains_the_current_process() {
        let pids = list_all_pids().expect("pids");
        assert!(
            pids.contains(&(std::process::id())),
            "自己的进程号必须在列表里"
        );
    }

    /// 这是整条「占用检查」的地基：本进程持有的文件必须能被读回来。
    ///
    /// 只测自己（不依赖 root）：别人进程的可见性由内核按权限决定，不该由单测断言。
    #[test]
    fn a_file_held_open_by_this_process_is_visible() {
        let dir = std::env::temp_dir().join(format!("wist-libproc-open-{}", std::process::id()));
        fs::create_dir_all(&dir).expect("create dir");
        let path = dir.join("held.tmp");
        fs::write(&path, b"held").expect("write");
        // 打开的路径可能是软链接（macOS 的 /var → /private/var），内核给的是**真实**路径。
        let canonical = fs::canonicalize(&path).expect("canonicalize");
        let _held = fs::File::open(&path).expect("hold open");

        let pid = std::process::id();
        let fds = list_fds(pid).expect("own fds");
        let found = fds
            .into_iter()
            .filter(|fd| fd.proc_fdtype as libc::c_int == libc::PROX_FDTYPE_VNODE)
            .filter_map(|fd| vnode_path(pid, fd.proc_fd))
            .any(|candidate| candidate == canonical);

        fs::remove_file(&path).ok();
        fs::remove_dir_all(&dir).ok();
        assert!(found, "本进程打开的文件必须能通过 libproc 看到");
    }
}
