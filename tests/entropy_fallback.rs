//! 老内核熵源回归：CentOS 6（kernel 2.6.32）没有 `getrandom(2)`，而 musl 的 `getentropy()`
//! 不回退 `/dev/urandom`，aws-lc 因此会 `abort()`（stderr: `getentropy failed.`）。
//!
//! 这个用例只在 **Linux + musl** 上编译/运行（其它目标上没有任何东西可验），跑法是交叉构建后
//! 把测试二进制拷到目标机执行；见 `src/sys_compat.rs` 的模块文档。

#![cfg(all(target_os = "linux", target_env = "musl"))]

use std::ffi::{c_int, c_void};

unsafe extern "C" {
    /// 由 `wist_agentd::sys_compat` 覆盖的强符号；这里直接按 C ABI 调用，验证它确实被链进来了。
    fn getentropy(buf: *mut c_void, len: usize) -> c_int;
}

#[test]
fn the_exported_getentropy_succeeds_on_this_kernel() {
    let mut buf = [0u8; 32];
    let rc = unsafe { getentropy(buf.as_mut_ptr().cast(), buf.len()) };
    assert_eq!(
        rc, 0,
        "getentropy 失败：内核没有 getrandom(2) 时，兼容层必须回退 /dev/urandom"
    );
    assert!(buf.iter().any(|byte| *byte != 0), "拿到全零说明没真取到熵");
}

#[test]
fn the_safe_wrapper_fills_distinct_values() {
    let mut first = [0u8; 32];
    let mut second = [0u8; 32];
    wist_agentd::sys_compat::fill_random(&mut first).expect("first");
    wist_agentd::sys_compat::fill_random(&mut second).expect("second");
    assert_ne!(first, second, "两次取熵不应相同");
}
