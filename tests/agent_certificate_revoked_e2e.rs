//! 真 agentd + 假网关的 e2e：网关把 agent 判为「吊销」后，agentd 必须进入**终态定住**。
//!
//! 覆盖 `wist-gateway/docs/design/agent-identity-mtls.md` §5.5（续签上报）与 §5.6（拒绝名单
//! → 终态）在**真实进程**上的落地：这里起的是真 `wist-agentd` 二进制
//! （`CARGO_BIN_EXE_wist-agentd`），配一份指向**假网关**的 `[control_plane]`，假网关对
//! `credentials:renew` 与 `status` 回 401 `certificate_revoked`，其余一律 404。
//!
//! 为什么值得一个真机 e2e：单测只能证明「这一轮判定成了 `Revoked`」，证明不了**跨进程的
//! 终态契约** —— 常规上报停手（只剩低频重试）、落台账、**进程不退出**（退出会被
//! launchd/systemd 的 KeepAlive 变成重启风暴）。这三条只有真进程 + 真计时能验。
//!
//! 断言的是**端到端可观测结果**，不是内部状态：
//!   1. `state/identity/renewal.json` 记下 `revoked`（§5.5 续签台账）；
//!   2. stderr 打出 `event=AgentAuthTerminal`（运维按它排查）；
//!   3. **常规上报停手**（用假网关上的请求计数证明「停」；区间内的低频重试不在本测试窗口内
//!      —— 见 `assert_control_plane_traffic_settles`）；
//!   4. `state/auth_terminal.json` 落台账（跨重启保留，也是 `diagnose` 读的那份）；
//!   5. 进程仍在运行（终态 = 定住，不是退出）。
//!
//! 三条进入 / 离开终态的路径各测一条：
//!   - 续期被拒：证书进入续期窗（剩余 ≤ 30 天）→ 启动即走 `credentials:renew`；
//!   - 状态上报被拒：证书仍有效（还早，不续期）→ 每 3s 的 `status` 上报是发现点；
//!   - **网关恢复**（第三个用例）：假网关翻脸放行后，守护进程**不重启**就自己清掉终态
//!     回到常规上报 —— 这是 `docs/design/agent-uplink-enablement.md` §4.2 的核心行为，
//!     其重试间隔靠 `WIST_AGENTD_TERMINAL_RETRY_SECS` 压到 1s（生产是 300s）。

use std::fs::File;
use std::path::{Path, PathBuf};
use std::process::{Child, Command, Stdio};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

use wist_agentd::state_store::auth_terminal;
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

/// 终态重试间隔的环境覆盖：生产是 300s，而「网关恢复后自动清终态」这条只有把重试压到
/// 秒级才能在 e2e 里观察到。
///
/// **从 crate 导入而不是自己再写一遍字符串**：两处写死的话，改了一边就会静默变成
/// 「设了一个没人读的环境变量」——测试只会超时，不会告诉你原因。
use wist_agentd::runtime::daemon::TERMINAL_RETRY_ENV;

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

/// 种一份**已注册**的本机身份（含 credential_id）：有了它，启动路径就不会去「带 token 注册」，
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
    // 身份只落 state（`agentd.toml` 里从不写）；凭据是客户端证书（`identity/`）。
    state.credential_id = Some("cred-e2e".to_string());
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
    spawn_agentd_with_env(config_dir, stderr_path, &[])
}

/// 同上，额外注入环境变量（自愈用例用它把终态重试压到 1s）。
fn spawn_agentd_with_env(
    config_dir: &Path,
    stderr_path: &Path,
    envs: &[(&str, &str)],
) -> RunningDaemon {
    let stderr = File::create(stderr_path).expect("create stderr file");
    let mut command = Command::new(agentd_bin());
    command
        .arg("--config-dir")
        .arg(config_dir)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::from(stderr));
    for (key, value) in envs {
        command.env(key, value);
    }
    let child = command.spawn().expect("spawn agentd");
    RunningDaemon { child }
}

/// 假网关的行为模式（测试中途可改）。
const MODE_REVOKED: usize = 0;
const MODE_SERVER_ERROR: usize = 1;
const MODE_ACCEPT: usize = 2;

/// 假网关：只认两条路 —— `credentials:renew` / `status` 按 `mode` 应答，
/// 其余（discovery-policies / uplink / work 轮询）一律 404（agentd 当作「旧网关 / 没派活」，
/// 静默回落，不污染终态判定）。每接一个连接计数一次，留给「停手」断言。
async fn serve_fake_gateway(listener: TcpListener, requests: Arc<AtomicUsize>) {
    serve_gateway(listener, requests, None).await
}

/// 会「回心转意」的假网关：`mode` 翻到 `MODE_ACCEPT` 之前一直拒（或报 5xx），之后接受。
/// 用来验「网关侧改好了 → agentd 自己恢复」，即不需要人工重启。
async fn serve_controllable_gateway(
    listener: TcpListener,
    requests: Arc<AtomicUsize>,
    mode: Arc<AtomicUsize>,
) {
    serve_gateway(listener, requests, Some(mode)).await
}

async fn serve_gateway(
    listener: TcpListener,
    requests: Arc<AtomicUsize>,
    mode: Option<Arc<AtomicUsize>>,
) {
    loop {
        let Ok((mut socket, _)) = listener.accept().await else {
            return;
        };
        requests.fetch_add(1, Ordering::SeqCst);
        let request = read_http_request(&mut socket).await;
        let response = route(&request, mode.as_deref());
        // 写失败（对端已走）不是错误：继续接下一个连接。
        let _ = socket.write_all(response.as_bytes()).await;
        let _ = socket.shutdown().await;
    }
}

/// 按请求行只取 path（第二段）精确匹配 —— 比子串匹配更难被别的内容误伤。
fn route(request: &str, mode: Option<&AtomicUsize>) -> String {
    let path = request.split_whitespace().nth(1).unwrap_or("");
    if path == RENEW_PATH || path == STATUS_PATH {
        match mode.map(|mode| mode.load(Ordering::SeqCst)) {
            Some(MODE_ACCEPT) => accepted_response(),
            // 5xx：既不是终态、也不是成功。终态下的低频重试在这条路上必须**不出声**。
            Some(MODE_SERVER_ERROR) => server_error_response(),
            _ => revoked_response(),
        }
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

/// 网关重新接受：状态上报的成功码（与真网关一致，`202 Accepted`）。
fn accepted_response() -> String {
    "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n".to_string()
}

/// 服务端问题（非终态、非成功）：终态下的重试遇到它必须什么都不说。
fn server_error_response() -> String {
    "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n"
        .to_string()
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

/// 终态之后必须「常规上报停手」：等假网关上的请求计数**停止增长**，并确认它此后不再变。
///
/// 契约的准确说法（§4.2）：终态停的是**常规上报**（状态 / 工作 / 上送 / 策略表），
/// 只剩每 `TERMINAL_RETRY_INTERVAL`（生产 300s）一次的状态上报重试。本测试不设那个环境变量，
/// 所以重试落在 30s 窗口之外 —— 这里断言的是「秒级频率的骚扰已经停了」，
/// 自愈那条另有一个把重试压到 1s 的用例。
///
/// 为什么要等「停」而不是取个快照就比：发现吊销的那一轮并不会立刻 break —— 它会把本轮
/// 剩余动作（策略表 / 上送 / 工作轮询，以及首轮偏慢的 discovery 之后可能触发的状态上报）
/// 走完，然后才进终态。取快照比大小会把「同轮的收尾请求在途」误判成「没停」。
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
            "进入终态后常规上报没有停下来：请求计数仍在增长（当前 {now}）"
        );
    }
    assert!(last > 0, "假网关至少要被联系过一次（否则终态断言无从谈起）");
}

/// 等某个文件出现（终态台账是「进入终态」的**外部可见**证据：跨重启保留，也是 `diagnose` 读的）。
async fn wait_for_file(path: &Path, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
}

/// 同上，等到它**消失**。恢复那一轮是「先清台账、再打 `AuthTerminalCleared`」，但写日志与
/// 删除是两个动作，断言不该赌它们之间的那一瞬。
async fn wait_for_file_absent(path: &Path, timeout: Duration) -> bool {
    let deadline = tokio::time::Instant::now() + timeout;
    while tokio::time::Instant::now() < deadline {
        if !path.exists() {
            return true;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    false
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

    // ③ §4.2：终态**落台账** —— 跨重启保留，也是 `diagnose` 读的那份。
    let ledger_path = auth_terminal::path_for(&state_dir);
    assert!(
        wait_for_file(&ledger_path, Duration::from_secs(5)).await,
        "进入终态必须落 {}（否则重启即遗忘、外部也看不见）",
        ledger_path.display()
    );
    let recorded = auth_terminal::load_async(&ledger_path)
        .await
        .expect("load terminal ledger")
        .expect("terminal ledger must exist");
    assert_eq!(recorded.code, "certificate_revoked");
    assert_eq!(recorded.source, auth_terminal::SOURCE_RENEWAL);

    // ④ §5.6：终态之后常规上报不再向控制面发请求。
    assert_control_plane_traffic_settles(&requests).await;

    // ⑤ 终态 = 定住，不是退出（退出会被服务管理器变成重启风暴）。
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

    // 终态必须落台账（与续期路径同一份契约，发现点不同而已）。
    let ledger_path = auth_terminal::path_for(&state_dir);
    assert!(
        wait_for_file(&ledger_path, Duration::from_secs(5)).await,
        "状态上报路径进终态也要落 {}（diagnose 靠它发现哑掉的机器）",
        ledger_path.display()
    );
    let recorded = auth_terminal::load_async(&ledger_path)
        .await
        .expect("load terminal ledger")
        .expect("terminal ledger must exist");
    assert_eq!(recorded.source, auth_terminal::SOURCE_STATUS_REPORT);

    assert_control_plane_traffic_settles(&requests).await;
    assert!(
        daemon.is_alive(),
        "状态上报路径进入终态后进程也必须留着运行"
    );

    drop(daemon);
    server.abort();
    let _ = std::fs::remove_dir_all(&root);
}

/// 路径三：**网关恢复**（§4.2）—— 不重启、不重装，agentd 自己从终态回到常规上报。
///
/// 这是现场那个坑的正面用例：终态原先一入不回，网关侧改好了也得等人重启；而且`diagnose`
/// 看不到它（终态只在内存）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_recovered_gateway_clears_the_terminal_state_without_a_restart() {
    let root = scratch_dir("revoked-recovery");
    let config_dir = root.join("conf");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake gateway");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(AtomicUsize::new(0));
    let mode = Arc::new(AtomicUsize::new(MODE_REVOKED));
    let server = tokio::spawn(serve_controllable_gateway(
        listener,
        requests.clone(),
        mode.clone(),
    ));

    write_control_plane_config(&config_dir, &endpoint);
    let state_dir = config_dir.join("state");
    seed_registered_identity(&state_dir);
    // 37 天：续期未到期，终态只能来自状态上报（与路径二同一前提）。
    seed_client_certificate(&state_dir, 37);

    let stderr_path = root.join("agent.err");
    let mut daemon = spawn_agentd_with_env(
        &config_dir,
        &stderr_path,
        // 生产是 300s，e2e 等不起；把**同一个**旋钮压到 1s。
        &[(TERMINAL_RETRY_ENV, "1")],
    );

    // ① 先真的进终态并落台账（前面的用例已经覆盖了这两步，这里当前置条件用）。
    wait_for_stderr(
        &stderr_path,
        "event=AgentAuthTerminal code=certificate_revoked",
        Duration::from_secs(30),
    )
    .await
    .expect("前置条件：必须先真的进入终态");
    let ledger_path = auth_terminal::path_for(&state_dir);
    assert!(
        wait_for_file(&ledger_path, Duration::from_secs(5)).await,
        "前置条件：终态必须落台账"
    );

    // ② 网关「改好了」：同一台 agent、同一个进程，没有任何重启。
    let before = requests.load(Ordering::SeqCst);
    mode.store(MODE_ACCEPT, Ordering::SeqCst);

    // ③ agentd 自己恢复：留痕一行 + 清掉台账（ diagnose 从此不再报 FAIL）。
    wait_for_stderr(
        &stderr_path,
        "event=AuthTerminalCleared",
        Duration::from_secs(30),
    )
    .await
    .expect("网关恢复后 agentd 必须自己清掉终态，而不是等人重启");
    // 轮询而不是立刻断言：日志行与删除是两个动作，不等就是把时序当成契约。
    assert!(
        wait_for_file_absent(&ledger_path, Duration::from_secs(5)).await,
        "恢复之后终态台账必须被清掉，否则下次启动又会以为自己在终态"
    );

    // ④ 常规上报真的回来了：请求计数继续增长。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    while requests.load(Ordering::SeqCst) <= before {
        assert!(
            tokio::time::Instant::now() < deadline,
            "恢复后常规上报没有回到控制面（计数器停在 {before}）"
        );
        tokio::time::sleep(Duration::from_millis(250)).await;
    }

    assert!(daemon.is_alive(), "自愈全程进程都在，没有被重启过");

    drop(daemon);
    server.abort();
    let _ = std::fs::remove_dir_all(&root);
}

/// 路径四：终态期间网关**报着 5xx**（既不是终态、也不是成功）—— 重试必须**一点都不出声**。
///
/// 这正是「失败静默」那条契约（§4.2）：终态原先的初衷之一就是「不刷日志」，而重试是把控制面
/// 请求重新引回来的唯一例外，所以它更得受这条约束 —— 否则网关一宕机，一台被拒的机器就变成
/// 每 5 分钟一行。顺带用台账里的 `attempts` 证明「确实在重试」（否则「没出声」分不出是
/// 静默还是根本没跑）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_terminal_retry_faced_with_a_server_error_stays_silent() {
    let root = scratch_dir("revoked-silent-retry");
    let config_dir = root.join("conf");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake gateway");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(AtomicUsize::new(0));
    let mode = Arc::new(AtomicUsize::new(MODE_REVOKED));
    let server = tokio::spawn(serve_controllable_gateway(
        listener,
        requests.clone(),
        mode.clone(),
    ));

    write_control_plane_config(&config_dir, &endpoint);
    let state_dir = config_dir.join("state");
    seed_registered_identity(&state_dir);
    seed_client_certificate(&state_dir, 37);

    let stderr_path = root.join("agent.err");
    let mut daemon = spawn_agentd_with_env(&config_dir, &stderr_path, &[(TERMINAL_RETRY_ENV, "1")]);

    wait_for_stderr(
        &stderr_path,
        "event=AgentAuthTerminal code=certificate_revoked",
        Duration::from_secs(30),
    )
    .await
    .expect("前置条件：先真的进入终态");
    let ledger_path = auth_terminal::path_for(&state_dir);
    assert!(
        wait_for_file(&ledger_path, Duration::from_secs(5)).await,
        "前置条件：终态必须落台账"
    );

    // 网关从「拒绝」换成「服务端出错」：重试会一直失败，但不该在日志里出现。
    mode.store(MODE_SERVER_ERROR, Ordering::SeqCst);

    // 等至少两次重试（间隔 1s）落进台账的 `attempts`。
    let deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    loop {
        let attempts = auth_terminal::load_async(&ledger_path)
            .await
            .expect("load ledger")
            .map(|state| state.attempts)
            .unwrap_or(0);
        if attempts >= 2 {
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "终态下的低频重试没有发生（attempts={attempts}）"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    // 再把网关**彻底拿走**（连接直接没人听）：另一条会打印的失败路径 —— 传输层。
    // 5xx 与「连不上」都会走到 `status report failed` 那两行 eprintln 上，所以两条都得验。
    server.abort();
    let transport_deadline = tokio::time::Instant::now() + Duration::from_secs(20);
    let attempts_before = auth_terminal::load_async(&ledger_path)
        .await
        .expect("load ledger")
        .map(|state| state.attempts)
        .unwrap_or(0);
    loop {
        let attempts = auth_terminal::load_async(&ledger_path)
            .await
            .expect("load ledger")
            .map(|state| state.attempts)
            .unwrap_or(0);
        if attempts > attempts_before {
            break;
        }
        assert!(
            tokio::time::Instant::now() < transport_deadline,
            "网关拿走后重试没有继续（attempts={attempts}）"
        );
        tokio::time::sleep(Duration::from_millis(100)).await;
    }

    let stderr = std::fs::read_to_string(&stderr_path).unwrap_or_default();
    assert!(
        !stderr.contains("status report failed"),
        "终态下的重试必须静默（5xx 与连不上都不打日志），实际 stderr:\n{stderr}"
    );
    // 也只该有「进入终态」那一行 —— 重试不刷、不误报恢复。
    assert!(
        !stderr.contains("event=AuthTerminalCleared"),
        "5xx 不是恢复，不得打恢复行:\n{stderr}"
    );
    assert!(daemon.is_alive(), "重试失败不能把进程搞退出");

    drop(daemon);
    let _ = std::fs::remove_dir_all(&root);
}

/// 路径五：**重启后读回台账** —— 跨重启保留是这块落盘存在的全部理由。
///
/// 预置一份终态台账再启动，验证两件事：① 启动即认账（`AuthTerminalRestored`），
/// ② 网关此刻已经接受它 → 一个 tick 内就自愈（不是白等 300s）。
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_restart_reads_the_terminal_ledger_back_and_recovers_immediately() {
    let root = scratch_dir("revoked-restore");
    let config_dir = root.join("conf");
    std::fs::create_dir_all(&config_dir).expect("config dir");

    let listener = TcpListener::bind("127.0.0.1:0")
        .await
        .expect("bind fake gateway");
    let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
    let requests = Arc::new(AtomicUsize::new(0));
    // 从一开始就接受：本用例只验「读回 + 自愈」，终态的**产生**归前面的用例。
    let mode = Arc::new(AtomicUsize::new(MODE_ACCEPT));
    let server = tokio::spawn(serve_controllable_gateway(
        listener,
        requests.clone(),
        mode.clone(),
    ));

    write_control_plane_config(&config_dir, &endpoint);
    let state_dir = config_dir.join("state");
    seed_registered_identity(&state_dir);
    seed_client_certificate(&state_dir, 37);
    // 预置一份「上一个进程留下的」终态台账。
    let ledger_path = auth_terminal::path_for(&state_dir);
    wist_shared::fs::write_json_atomic(
        &ledger_path,
        &serde_json::json!({
            "code": "certificate_mismatch",
            "source": "status_report",
            "detected_at": "2026-09-30T13:02:23Z",
            "attempts": 7,
        }),
    )
    .expect("seed terminal ledger");

    let stderr_path = root.join("agent.err");
    // **不设** `TERMINAL_RETRY_ENV`：要验的正是「进入终态后立刻试一次」，而设成 1s 就无法
    // 把「立即」与「等了一个周期」区分开。默认是 300s —— 只要它在几十秒内恢复，就证明
    // 首次重试确实没等那一整个周期。
    let mut daemon = spawn_agentd(&config_dir, &stderr_path);

    // ① 启动即认账，并把上一份台账的 code / since / attempts 带出来。
    let restored = wait_for_stderr(
        &stderr_path,
        "event=AuthTerminalRestored code=certificate_mismatch",
        Duration::from_secs(30),
    )
    .await
    .expect("重启后必须读回终态台账，而不是当成没进过");
    assert!(
        restored.contains("since=2026-09-30T13:02:23Z"),
        "{restored}"
    );

    // ② 网关已经接受 → 首次重试（进入终态后的下一个 tick）即恢复，
    //    而不是白等一个完整周期（默认 300s）。
    wait_for_stderr(
        &stderr_path,
        "event=AuthTerminalCleared",
        Duration::from_secs(30),
    )
    .await
    .expect("读回终态后应当自己走出去；没走出去就说明首次重试白等了一个周期（默认 300s）");
    assert!(
        wait_for_file_absent(&ledger_path, Duration::from_secs(5)).await,
        "恢复后台账必须不在"
    );
    assert!(daemon.is_alive(), "全程进程都在");

    drop(daemon);
    server.abort();
    let _ = std::fs::remove_dir_all(&root);
}
