//! 老内核上的熵源兼容层（**仅 Linux + 静态 musl** 参与编译）。
//!
//! ## 为什么需要它
//!
//! 现场（CentOS 6 / kernel 2.6.32）：
//!
//! ```text
//! # wist-agentd diagnose
//! getentropy failed.
//! Aborted
//! ```
//!
//! 三个事实叠在一起：
//!
//! 1. `getrandom(2)` 是 **Linux 3.17** 才有的系统调用；2.6.32 / 3.10 上只会返回 `ENOSYS`。
//! 2. musl 的 `getentropy()` 只是 `getrandom()` 的循环包装，**没有 `/dev/urandom` 回退**。
//! 3. aws-lc（rustls 的加密后端）在 Linux 上如果**构建时**没找到 `<linux/random.h>`，就编入
//!    `crypto/rand_extra/getentropy.c`：`getentropy()` 一失败立刻
//!    `fprintf(stderr, "getentropy failed.\n"); abort();`。我们的 musl 交叉构建
//!    （musl-gcc 只带 musl 自己的头，没有内核 UAPI 头）正好走这条路。
//!
//! 结果：这类内核上**任何一次 TLS 握手都会 SIGABRT** —— `enroll`、`diagnose` 的连通性探测、
//! 上报全中。它不是「跑得慢」，是直接退出。
//!
//! ## 做法
//!
//! 静态链接下，我们可以提供一个同名强符号覆盖 libc 里那份实现（musl 的 `getentropy.o`
//! 只在符号仍未定义时才会被从 `libc.a` 拉出来）：先试 `getrandom()`，
//! `ENOSYS` / `EPERM`（seccomp 沙箱）等失败时回退读 `/dev/urandom`。
//! 新内核上行为与 musl 一致（仍是 `getrandom`），老内核上从「abort」变成「可用」。
//!
//! 为什么不是「把 TLS 换回 ring」或「改 aws-lc 构建参数」：前者要换加密后端（面大），
//! 后者依赖构建机的头文件布局（CI 上 musl-gcc 看不到 `<linux/random.h>`，就是这个坑的成因）。
//! 这里只补**一个失败的调用**，范围最小，且可以用真机 A/B 验证。

#![cfg(all(target_os = "linux", target_env = "musl"))]

use std::ffi::{c_int, c_void};
use std::io;

/// POSIX 给 `getentropy(3)` 定的单次上限。
const MAX_REQUEST: usize = 256;

unsafe extern "C" {
    /// musl 导出；与 glibc 同名同义。用它读写 `errno`，避免依赖 `libc` crate 在不同
    /// target 下的暴露差异。
    fn __errno_location() -> *mut c_int;
}

fn errno() -> c_int {
    unsafe { *__errno_location() }
}

fn set_errno(value: c_int) {
    unsafe { *__errno_location() = value }
}

fn last_os_error() -> io::Error {
    io::Error::from_raw_os_error(errno())
}

/// 把 `bytes` 填满熵。
///
/// 先 `getrandom(2)`；内核不认这个系统调用（`ENOSYS`，< 3.17）或被沙箱拒掉（`EPERM`）时，
/// 改为读取 `/dev/urandom`（**只开一次**，后续部分读复用同一个 fd）。`EINTR` 重试。
fn fill(bytes: &mut [u8]) -> io::Result<()> {
    use std::io::Read;

    let mut done = 0usize;
    let mut urandom: Option<std::fs::File> = None;
    while done < bytes.len() {
        let rest = &mut bytes[done..];
        if urandom.is_none() {
            let rc = unsafe {
                libc::syscall(
                    libc::SYS_getrandom,
                    rest.as_mut_ptr(),
                    rest.len(),
                    0 as libc::c_uint,
                )
            };
            if rc < 0 {
                match errno() {
                    libc::EINTR => continue,
                    // 老内核 / 受限沙箱：换 /dev/urandom 这条所有人都有的路。
                    libc::ENOSYS | libc::EPERM => {
                        urandom = Some(std::fs::File::open("/dev/urandom")?);
                        continue;
                    }
                    _ => return Err(last_os_error()),
                }
            }
            if rc == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::UnexpectedEof,
                    "getrandom returned 0 bytes",
                ));
            }
            done += rc as usize;
            continue;
        }
        let file = urandom.as_mut().expect("urandom opened above");
        // 与 musl 一致：`read()` 被信号打断不算失败。
        let n = match file.read(rest) {
            Ok(n) => n,
            Err(err) if err.kind() == io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "/dev/urandom returned 0 bytes",
            ));
        }
        done += n;
    }
    Ok(())
}

/// 安全封装：给测试与内部调用用（`getentropy` 的 256 上限不在这里）。
pub fn fill_random(bytes: &mut [u8]) -> io::Result<()> {
    fill(bytes)
}

/// 覆盖 musl 的 `getentropy(3)`。
///
/// 只有 aws-lc 走 `OPENSSL_RAND_GETENTROPY` 路径时才会被引用；我们的静态 musl 制品正是
/// 那条路（也就是现场 abort 的那条）。签名与 musl 一致：`int getentropy(void *, size_t)`。
///
/// # Safety
///
/// 调用方必须保证 `buf` 对写入 `len` 字节有效（与 C 的 `getentropy` 契约相同）。
#[unsafe(no_mangle)]
pub unsafe extern "C" fn getentropy(buf: *mut c_void, len: usize) -> c_int {
    // `len == 0` 是合法的 no-op（且允许 `buf == null`）：不能把空指针交给
    // `slice::from_raw_parts_mut`（即使长度为 0，也要求指针非空且对齐）。
    if len == 0 {
        return 0;
    }
    if len > MAX_REQUEST {
        set_errno(libc::EIO);
        return -1;
    }
    if buf.is_null() {
        set_errno(libc::EINVAL);
        return -1;
    }
    let bytes = unsafe { std::slice::from_raw_parts_mut(buf as *mut u8, len) };
    match fill(bytes) {
        Ok(()) => 0,
        Err(err) => {
            set_errno(err.raw_os_error().unwrap_or(libc::EIO));
            -1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_requests_larger_than_the_posix_limit() {
        let mut buf = [0u8; MAX_REQUEST + 1];
        let rc = unsafe { getentropy(buf.as_mut_ptr().cast(), buf.len()) };
        assert_eq!(rc, -1);
        assert_eq!(errno(), libc::EIO);
    }

    #[test]
    fn zero_length_is_a_noop_and_tolerates_a_null_pointer() {
        // POSIX：长度 0 时啥也不做；空指针也不应被解引用。
        let rc = unsafe { getentropy(std::ptr::null_mut(), 0) };
        assert_eq!(rc, 0);
    }

    #[test]
    fn fills_a_buffer_larger_than_one_chunk() {
        // `fill_random` 没有 256 上限；部分读/逐次系统调用都要能拼满。
        let mut buf = [0u8; 700];
        fill_random(&mut buf).expect("fill");
        assert!(buf.iter().any(|byte| *byte != 0), "全零说明没取到熵");
    }
}
