//! 真 agentd + 假网关的 e2e：网关把 agent 判为「吊销」后，agentd 必须进入**终态定住**。
//!
//! 覆盖 `wist-gateway/docs/design/agent-identity-mtls.md` §5.5（续签上报）与 §5.6（拒绝名单
//! → 终态）在**真实进程**上的落地：这里起的是真 `wist-agentd` 二进制
//! （`CARGO_BIN_EXE_wist-agentd`），配一份指向**假网关**的 `[control_plane]`，假网关对
//! `credentials:renew` 与 `status` 回 401 `certificate_revoked`，其余一律 404。
//!
//! 为什么值得一个真机 e2e：单测只能证明「这一轮判定成了 `Revoked`」，证明不了**跨进程的
//! 终态契约** —— 停手（不再向控制面发任何请求）、落台账、**进程不退出**（退出会被
//! launchd/systemd 的 KeepAlive 变成重启风暴）。这三条只有真进程 + 真计时能验。
//!
//! 断言的是**端到端可观测结果**，不是内部状态：
//!   1. `state/identity/renewal.json` 记下 `revoked`（§5.5 续签台账）；
//!   2. stderr 打出 `event=AgentAuthTerminal`（运维按它排查）；
//!   3. 终态之后**不再向控制面发任何请求**（用假网关上的请求计数证明「停手」）；
//!   4. 进程仍在运行（终态 = 定住，不是退出）。
//!
//! 两条进入终态的路径各测一条 —— 它们在现场是**两个发现点**：
//!   - 续期被拒：证书进入续期窗（剩余 ≤ 30 天）→ 启动即走 `credentials:renew`；
//!   - 状态上报被拒：证书仍有效（还早，不续期）→ 每 3s 的 `status` 上报是发现点。

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wist_agentd::state_store::client_identity::{
    ClientIdentityPaths, RenewalLedger, read_renewal_ledger,
};
use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};
use wist_shared::fs::write_json_atomic;
use wist_shared::paths::AGENT_RUNTIME_FILE;
use wist_shared::time::now_rfc3339;

/// 控制面续期端点（§5.5）。
const RENEW_PATH: &str = "/api/v1/agent/credentials:renew";
/// 控制面状态上报端点（每 3s，是最频繁的发现点）。
const STATUS_PATH: &str = "/api/v1/agent/status";
/// 与 `daemon::TICK_INTERVAL` 同口径（守护循环一轮的间隔）。
const TICK: Duration = Duration::from_secs(3);

fn agentd_bin() -> PathBuf {
    PathBuf::from(env!("CARGO_BIN_EXE_wist-agentd"))
}

fn scratch_dir(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-agentd-revoked-e2e-{label}-{unique}"));
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

impl RunningDaemon {
    fn is_alive(&mut self) -> bool {
        self.child.try_wait().expect("try_wait").is_none()
    }
}

/// 写一份指向假网关的配置：先 `init-config` 落默认模板（含 paths / discovery 的默认），
/// 再把 `[control_plane]` 追加上去。默认模板里 `[control_plane]` 是注释，追加不冲突。
fn write_control_plane_config(config_dir: &Path, endpoint: &str) {
    let status = Command::new(agentd_bin())
        .arg("init-config")
        .arg("--config-dir")
        .arg(config_dir)
        .status()
        .expect("run init-config");
    assert!(status.success(), "init-config failed");

    let config_path = config_dir.join("agentd.toml");
    let mut text = std::fs::read_to_string(&config_path).expect("read generated config");
    text.push_str(&format!(
        "\n[control_plane]\nenabled = true\nendpoint = \"{endpoint}\"\n"
    ));
    std::fs::write(&config_path, text).expect("append control_plane section");
}

/// 种一份**已注册**的本机身份（含 bearer 凭据）：有了它，启动路径就不会去「带 token 注册」，
/// 而是走「既有身份」分支（`load_state_identity` → 启动续期检查）。
fn seed_registered_identity(state_dir: &Path) {
    std::fs::create_dir_all(state_dir).expect("state dir");
    let mut state = AgentRuntimeState::new(
        "agent-e2e".to_string(),
        "instance-e2e".to_string(),
        env!("CARGO_PKG_VERSION").to_string(),
        RuntimeMode::Normal,
        now_rfc3339(),
    );
    // 凭据只落 state（`agentd.toml` 里从不写）—— 续期请求要带它就靠这里注入。
    state.bearer_token = Some("wic_e2e_token".to_string());
    let path = state_dir.join(AGENT_RUNTIME_FILE);
    write_json_atomic(&path, &state).expect("seed runtime identity");
}

/// 种一张自签客户端证书（`not_after = 现在 + days`）+ 私钥 —— 这就是「有客户端证书」的 case。
///
/// `days` 决定走哪条发现路径：≤ 30 天落在续期窗内（启动即续期），> 30 天仍有效（靠状态上报发现）。
fn seed_client_certificate(state_dir: &Path, days: i64) {
    let paths = ClientIdentityPaths::under(state_dir);
    let key = rcgen::KeyPair::generate().expect("client key");
    let mut params = rcgen::CertificateParams::default();
    params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
    params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
    let certificate = params
        .self_signed(&key)
        .expect("self-signed client certificate");

    std::fs::create_dir_all(paths.cert_file.parent().expect("identity dir")).expect("identity dir");
    std::fs::write(&paths.key_file, key.serialize_pem()).expect("write client key");
    std::fs::write(&paths.cert_file, certificate.pem()).expect("write client certificate");
}

/// 起真 agentd，stderr 落到文件（结尾要按它断言 `event=AgentAuthTerminal`）。
fn spawn_agentd(config_dir: &Path, stderr_path: &Path) -> RunningDaemon {
    let stderr = File::create(stderr_path).expect("create stderr file");
    let child = Command::new(agentd_bin())
        .arg("--config-dir")
        .arg(config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr))
        .spawn()
        .expect("spawn agentd");
    RunningDaemon { child }
}

/// 假网关：只认两条路 —— `credentials:renew` / `status` 回 401 `certificate_revoked`，
/// 其余（discovery-policies / uplink / work 轮询）一律 404（agentd 当作「旧网关 / 没派活」，
/// 静默回落，不污染终态判定）。每接一个连接计数一次，留给「停手」断言。
async fn serve_fake_gateway(listener: TcpListener, requests: Arc<AtomicUsize>) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        requests.fetch_add(1, Ordering::SeqCst);
        let request = read_http_request(&mut socket).await;
        let response = route(&request);
        // 写失败（对端已走）不是错误：继续接下一个连接。
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    }
}

/// 按请求行只取 path（第二段）精确匹配 —— 比子串匹配更难被别的内容误伤。
fn route(request: &str) -> String {
    let path = request.split_whitespace().nth(1).unwrap_or("");
    if path == RENEW_PATH || path == STATUS_PATH {
        revoked_response()
    } else {
        not_found_response()
    }
}

fn revoked_response() -> String {
    let body = "agent identity rejected: certificate_revoked";
    format!(
        "HTTP/1.1 401 Unauthorized\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
        body.len(),
        body
    )
}

fn not_found_response() -> String {
    "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
}

/// 读一个完整的 HTTP/1.1 请求（头 + 按 content-length 的体）。
async fn read_http_request(socket: &mut TcpStream) -> String {
    let mut request_bytes = Vec::new();
    loop {
        let mut chunk = [0u8; 1024];
        let Ok(read) = socket.read(&mut chunk).await else {
            break;
        };
        if read == 0 {
            break;
        }
        request_bytes.extend_from_slice(&chunk[..read]);
        let Some(header_end) = request_bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
            continue;
        };
        let headers = String::from_utf8_lossy(&request_bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| {
                let (key, value) = line.split_once(':')?;
                if key.trim().eq_ignore_ascii_case("content-length") {
                    value.trim().parse::<usize>().ok()
                } else {
                    None
                }
            })
            .unwrap_or(0);
        if request_bytes.len() >= header_end + 4 + content_length {
            break;
        }
    }
    String::from_utf8_lossy(&request_bytes).into_owned()
}

/// 等续期台账出现指定结论（真 agentd 在启动 / 首轮就会写）。
async fn wait_for_renewal_outcome(
    state_dir: &Path,
    expected: &str,
    timeout: Duration,
) -> Option<RenewalLedger> {
    let paths = ClientIdentityPaths::under(state_dir);
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if let Ok(Some(ledger)) = read_renewal_ledger(&paths)
            && ledger.outcome == expected
        {
            return Some(ledger);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// 等 stderr 出现某段文本，出现即返回全文。
async fn wait_for_stderr(path: &Path, needle: &str, timeout: Duration) -> Option<String> {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        let text = std::fs::read_to_string(path).unwrap_or_default();
        if text.contains(needle) {
            return Some(text);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    None
}

/// 终态之后必须「停手」：等假网关上的请求计数**停止增长**，并确认它此后不再变。
///
/// 为什么要等「停」而不是取个快照就比：发现吊销的那一轮并不会立刻 break —— 它会把本轮
/// 剩余动作（策略表 / 上送 / 工作轮询，以及首轮偏慢的 discovery 之后可能触发的状态上报）
/// 走完，然后才进终态。取快照比大小会把「同轮的收尾请求在途」误判成「没停」。
/// 真正的契约是「最终停手、不再重试」，所以这里等计数**在连续两个 tick 内无新增**。
async fn assert_control_plane_traffic_settles(requests: &Arc<AtomicUsize>) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(30);
    let mut last = requests.load(Ordering::SeqCst);
    let mut stable_since = tokio::time::Instant::now();
    loop {
        tokio::time::sleep(Duration::from_millis(250)).await;
        let now = requests.load(Ordering::SeqCst);
        if now != last {
            last = now;
            stable_since = tokio::time::Instant::now();
        }
        if stable_since.elapsed() >= TICK * 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "被吊销的 agent 没有停止打扰控制面：请求计数仍在增长（当前 {now}）"
        );
    }
    assert!(last > 0, "假网关至少要被联系过一次（否则终态断言无从谈起）");
}

/// 路径一：**续期被拒**（证书进入续期窗）→ 终态。
///
/// 这条路径会交出续签台账（`renewal.json` 记 `revoked`），是 §5.5 与 §5.6 的交点。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_renewal_refused_as_certificate_revoked_puts_agentd_into_a_terminal_standby() {
    let root = scratch_dir("revoked-renewal");
    let config_dir = root.join("conf");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    // 假网关先起好、拿到端口，再写进配置。
    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake gateway");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_fake_gateway(listener, requests.clone()));

    write_control_plane_config(&config_dir, &endpoint);
    let state_dir = config_dir.join("state");
    seed_registered_identity(&state_dir);
    // 剩余 10 天（≤ 30 天续期窗）→ 启动即尝试续期。
    seed_client_certificate(&state_dir, 10);

    let stderr_path = root.join("agentd.err");
    let mut daemon = spawn_agentd(&config_dir, &stderr_path);

    // ① §5.5：续签台账必须记下「被吊销」。
    let ledger = wait_for_renewal_outcome(&state_dir, "revoked", Duration::from_secs(25))
        .await
        .expect("续签台账必须记下 outcome=revoked（否则又是静默）");
    assert_eq!(ledger.outcome, "revoked");

    // ② stderr 打出一行可排查的终态事件。
    let stderr = wait_for_stderr(
        &stderr_path,
        "event=AgentAuthTerminal code=certificate_revoked",
        Duration::from_secs(10),
    )
    .await
    .expect("agentd 必须打出 event=AgentAuthTerminal code=certificate_revoked");

    // ③ §5.6：终态之后不再向控制面发任何请求。
    assert_control_plane_traffic_settles(&requests).await;

    // ④ 终态 = 定住，不是退出（退出会被服务管理器变成重启风暴）。
    assert!(
        daemon.is_alive(),
        "被吊销进入终态后进程必须留着运行，而不是退出"
    );

    // 断言里带上现场，失败时能直接读到线索。
    assert!(
        stderr.contains("reinstall") || stderr.contains("reinstalling"),
        "AgentAuthTerminal 行应当说明「重装也没用、得先解除拒绝名单」，实际 stderr:\n{stderr}"
    );

    drop(daemon);
    server.abort();
    let _ = std::fs::remove_dir_all(&root);
}

/// 路径二：**状态上报被拒**（证书仍有效，不续期）→ 终态。
///
/// 这是现场更常见的那条：agent 正常运行时被运维吊销，续期窗还没到，靠每 3s 的状态上报发现。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_status_report_refused_as_certificate_revoked_is_also_terminal() {
    let root = scratch_dir("revoked-status");
    let config_dir = root.join("conf");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake gateway");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(AtomicUsize::new(0));
    let server = tokio::spawn(serve_fake_gateway(listener, requests.clone()));

    write_control_plane_config(&config_dir, &endpoint);
    let state_dir = config_dir.join("state");
    seed_registered_identity(&state_dir);
    // 剩余 37 天（> 30 天续期窗）→ 续期「还早」，只能靠状态上报发现被吊销。
    seed_client_certificate(&state_dir, 37);

    let stderr_path = root.join("agent.err");
    let mut daemon = spawn_agentd(&config_dir, &stderr_path);

    // 状态上报在第二个 tick（约 3s）首次发出 → 命中 401 → 终态。
    wait_for_stderr(
        &stderr_path,
        "event=AgentAuthTerminal code=certificate_revoked source=status_report",
        Duration::from_secs(30),
    )
    .await
    .expect("状态上报被拒必须进终态并打 event=AgentAuthTerminal code=certificate_revoked source=status_report");

    // 续期并未到期：台账应停在 `not_due` —— 证明终态确实来自「状态上报」这条路径，
    // 而不是被续期顺带触发的。
    let ledger = read_renewal_ledger(&ClientIdentityPaths::under(&state_dir))
        .expect("read ledger")
        .expect("续期检查在启动时就会写一份台账");
    assert_eq!(
        ledger.outcome, "not_due",
        "证书还有 37 天，续期不该到期（终态只能来自状态上报）"
    );

    assert_control_plane_traffic_settles(&requests).await;
    assert!(
        daemon.is_alive(),
        "状态上报路径进入终态后进程也必须留着运行"
    );

    drop(daemon);
    server.abort();
    let _ = std::fs::remove_dir_all(&root);
}
