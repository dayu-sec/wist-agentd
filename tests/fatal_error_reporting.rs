//! 致命启动错误必须带着**完整因果链**打到 stderr，并以 1 退出。
//!
//! 为什么值得一个真二进制测试：`main()` 的 `Err` 分支是磁盘满事故里唯一还能留下遗言的地方
//! （stderr → journald，同一段文本再镜像到 `/dev/kmsg`，见 `src/kmsg.rs`）。把它改成
//! `eprintln!("{}", err)` 之类的写法在类型上完全合法，却会把 `-> Caused by:` 整段吞掉，
//! 现场就只剩一句顶层 reason。kmsg 那条通道在非 Linux 上是空实现、在 Linux CI 上也可能不可写，
//! 所以这里把 stderr 这一半钉死。

use std::path::PathBuf;
use std::process::Command;

fn scratch_dir(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-agentd-fatal-{label}-{unique}"));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

#[test]
fn a_fatal_config_error_prints_the_whole_chain_and_exits_one() {
    let dir = scratch_dir("config");
    std::fs::write(dir.join("agentd.toml"), "schema_version = = \"v1\"\n").expect("write config");

    let output = Command::new(env!("CARGO_BIN_EXE_wist-agentd"))
        .arg("--config-dir")
        .arg(&dir)
        .output()
        .expect("run wist-agentd");
    let _ = std::fs::remove_dir_all(&dir);

    let stderr = String::from_utf8_lossy(&output.stderr);
    assert_eq!(output.status.code(), Some(1), "stderr: {stderr}");
    assert!(stderr.contains("wist-agentd failed:"), "stderr: {stderr}");
    // 源错误也要在：只看顶层 reason 说不出“为什么起不来”（/etc 权限、目录不可写都是这种形状）。
    assert!(stderr.contains("Caused by"), "stderr: {stderr}");
    assert!(stderr.contains("TOML parse error"), "stderr: {stderr}");
}
