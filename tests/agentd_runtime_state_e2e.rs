//! 真 agentd 启动后必须把**自己这一版**写进 `state/agent_runtime.json`。
//!
//! 为什么值得一个真机 e2e：升级器判断「新版起来了没有」读的正是这份状态里的 `version`
//! （`upgrade::running_version`）。而升级链路的 e2e 把「新版起来了」这件事**模拟**掉了 ——
//! 重启桩自己往 state 里写目标版本（见 `tests/upgrade_e2e.rs` 的 `restart_stub("ok")`）——
//! 于是**写这份状态的那一端**从未被覆盖：它曾长期不刷新版本，导致**任何**一次由升级器驱动
//! 的升级都以 `not_ready` 回滚。这里起**真的** agentd：先种一份「上一版写下的」状态，
//! 断言它启动后被刷成当前二进制版本。
//!
//! 不碰服务管理器、不要 root：默认配置是 standalone（`[control_plane]` 注释掉，不联网），
//! 且配置目录不在 `/etc` 下时数据/日志就地落在配置目录里。

use std::path::PathBuf;
use std::process::{Child, Command, Stdio};
use std::time::{Duration, Instant};

use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};
use wist_shared::fs::{read_json, write_json_atomic};
use wist_shared::paths::AGENT_RUNTIME_FILE;
use wist_shared::time::now_rfc3339;

/// 刻意与任何真实版本都不同：它只可能来自「上一版写下的」状态。
const STALE_VERSION: &str = "0.0.1-stale";

fn agentd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wist-agentd"))
}

/// 跑 `wist-agentd version`，取二进制自报的版本（与升级器验件同一口径）。
fn binary_version() -> String {
    let output = Command::new(agentd_bin())
        .arg("version")
        .output()
        .expect("run wist-agentd version");
    assert!(output.status.success(), "version exited {}", output.status);
    String::from_utf8_lossy(&output.stdout)
        .split_whitespace()
        .last()
        .expect("version token")
        .to_string()
}

fn scratch_dir(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-agentd-state-e2e-{label}-{unique}"));
    std::fs::create_dir_all(&dir).expect("create scratch dir");
    dir
}

/// 起着的 agentd：离开作用域（含 panic 展开）就杀掉。
struct RunningDaemon {
    child: Child,
}

impl Drop for RunningDaemon {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

#[test]
fn a_starting_agentd_publishes_its_own_version_over_a_stale_state() {
    let root = scratch_dir("publish-version");
    let config_dir = root.join("conf");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    let status = Command::new(agentd_bin())
        .arg("init-config")
        .arg("--config-dir")
        .arg(&config_dir)
        .status()
        .expect("run init-config");
    assert!(status.success(), "init-config failed");

    // 种一份「上一版 agentd 写下的」运行态。仅当这份**已存在的**状态被读出并原样回写，
    // 才会重现回归 —— 所以必须先种，不能依赖「文件不存在」的兜底路径。
    let runtime_path = config_dir.join("state").join(AGENT_RUNTIME_FILE);
    std::fs::create_dir_all(runtime_path.parent().expect("state dir")).expect("state dir");
    let stale = AgentRuntimeState::new(
        "local-agent".to_string(),
        "local-instance".to_string(),
        STALE_VERSION.to_string(),
        RuntimeMode::Normal,
        now_rfc3339(),
    );
    write_json_atomic(&runtime_path, &stale).expect("seed stale state");

    let version = binary_version();
    assert_ne!(version, STALE_VERSION, "陈旧版本不能恰好是当前版本");

    let child = Command::new(agentd_bin())
        .arg("--config-dir")
        .arg(&config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn agentd");
    let daemon = RunningDaemon { child };

    // 启动会把版本刷成当前二进制版本；旧行为是「读回旧文件、原样回写」，于是这里会超时。
    let deadline = Instant::now() + Duration::from_secs(15);
    let mut observed: Option<String> = None;
    while Instant::now() < deadline {
        if let Ok(state) = read_json::<AgentRuntimeState>(&runtime_path)
            && state.version == version
        {
            observed = Some(state.version);
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }

    // 先收掉进程再断言：失败时也留下干净现场。
    drop(daemon);

    assert_eq!(
        observed.as_deref(),
        Some(version.as_str()),
        "启动后 state/agent_runtime.json 的 version 必须刷成当前二进制版本 —— \
         否则升级器的就绪判据（upgrade::running_version）永远不满足，合法升级会被回滚"
    );

    let _ = std::fs::remove_dir_all(&root);
}
