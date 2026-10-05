//! 数据面上送启用的拉取与应用（agentd 侧）。
//!
//! 与 [`crate::control::work`] 同构：网关给的是**期望状态**（这个 Agent 现在该不该向数据面
//! 上送、送到哪），这里把它拉下来并在内存里应用。「什么时候拉、拉多密」在主循环里
//! （与工作授权、发现策略同一处，见 `runtime::daemon::refresh_uplink_grant`），本模块
//! 只负责「这一趟到底拿没拿到」这一个判断。
//!
//! ## 为什么另开一条拉取
//!
//! 上送启用是**派生**自工作授权的结果（有生效工作 + 管理面设了上送地址 → 开），但它必须
//! 单独可拉：塞进 `WorkGrant` 会让「新网关 + 旧 agentd」直接解析失败（那个契约
//! `deny_unknown_fields`），旧 agent 连工作都收不到。独立端点对两个方向都安全 ——
//! 旧 agentd 从不调它；新 agentd 遇到旧网关得到 404，按「无下发」回落本机配置。
//!
//! ## 两条关键取舍
//!
//! 1. **拉取失败保留上一次已应用的 grant**（见 [`AppliedUplink::observe`]）。
//!    与工作授权同理 —— 网络抖动不该把「已授权上送」倒退成「无授权」。
//! 2. **「没拿到」要分清是预期还是异常**（见 [`UplinkFetch`]）。旧网关没有这个端点（404）
//!    与「未入网」都是**正常状态**，不该每 30s 打一行 `failed` —— 那正是本特性要消灭的
//!    「把正常状态报成故障」的毛病，只是换了个地方。

use std::time::Duration;

use wist_api::agent_uplink::{AgentUplinkGrant, POLL_AGENT_UPLINK_KIND, PollAgentUplink};
use wist_contracts::agent_config::AgentConfig;
use wist_shared::time::now_rfc3339;

use crate::control::enrollment::enrollment_http_client;

/// 单次拉取请求的超时。
///
/// 与 `work::WORK_REQUEST_TIMEOUT` 同值：这条路径在主循环里排在采集之前，
/// 必须自己封顶，不能吃掉 tick。
const UPLINK_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// 一次拉取的结果。
///
/// 把「没拿到」拆成三类是刻意的：它决定**要不要打日志**、以及**要不要动已应用的 grant**。
///   * [`UplinkFetch::NotDispatched`]：预期内（未入网 / 旧网关没有这个端点）→ 静默。
///   * [`UplinkFetch::Failed`]：传输/服务抖动 → 可见（按签名去重），**保留上次 grant**。
///   * [`UplinkFetch::CredentialRejected`]：凭据被拒（401/403）→ 可见，且**强制回落待命**。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum UplinkFetch {
    Granted(AgentUplinkGrant),
    /// 预期内：未入网，或旧网关没有 `uplink:poll`（404）。按「无下发」处理，静默。
    NotDispatched,
    /// 异常：签名稳定（用于去重），如 `transport: …` / `http 500 from …` / `invalid response …`。
    ///
    /// **保留上次 grant**：一次网络抖动不该把「已授权上送」倒退成「无授权」。
    Failed(String),
    /// 凭据被拒（HTTP 401/403）：**必须回落待命**。
    ///
    /// 与 [`UplinkFetch::Failed`] 刻意区分：那是一次网络抖动，这是一次**授权信号** ——
    /// 凭据被吊销 / 过期 / 换发失败。继续按旧授权外发，等于让平台收不回已经收回的授权
    /// （而数据面入站又不校验身份，见设计文档 §9），所以这里把生效状态压成待命，
    /// 而不是保留。凭据恢复正常后，下一次成功的 poll 会把它重新打开。
    CredentialRejected(String),
}

/// 拉取数据面上送启用。
pub(crate) async fn fetch_uplink_grant(config: &AgentConfig) -> UplinkFetch {
    fetch_uplink_grant_with_timeout(config, UPLINK_REQUEST_TIMEOUT).await
}

/// 同上，但请求超时可注入（单测用它把「超时」这条路径跑成毫秒级，不拖慢测试）。
async fn fetch_uplink_grant_with_timeout(
    config: &AgentConfig,
    request_timeout: Duration,
) -> UplinkFetch {
    // 未入网：缺端点 / 身份任一 —— 这是「无下发」，不是故障。凭据走 mTLS（客户端证书），
    // 这里不再有 bearer token 可缺。
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return UplinkFetch::NotDispatched;
    };
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return UplinkFetch::NotDispatched;
    };
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();

    let request = PollAgentUplink {
        api_version: wist_contracts::API_VERSION_V1.to_string(),
        kind: POLL_AGENT_UPLINK_KIND.to_string(),
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        requested_at: now_rfc3339(),
    };
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        // 建不出客户端是**本机配置/环境**的问题（TLS 信任锚、证书文件等），不是「无下发」：
        // 要看得见，否则「配错了信任锚」会退化成「永远待命且不说为什么」。
        Err(err) => return UplinkFetch::Failed(format!("client: {err}")),
    };
    let url = format!(
        "{}/api/v1/agent/uplink:poll",
        endpoint.trim_end_matches('/')
    );
    match client
        .post(&url)
        .timeout(request_timeout)
        .json(&request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<AgentUplinkGrant>().await {
                Ok(grant) => UplinkFetch::Granted(grant),
                Err(err) => UplinkFetch::Failed(format!("invalid response from {endpoint}: {err}")),
            }
        }
        // 旧网关没有这个端点 → 404。**按「无下发」处理**（回落本机配置），不是错误：
        // 一个还没升级的网关不该让 agentd 每 30s 打一行 failed。
        Ok(response) if response.status() == reqwest::StatusCode::NOT_FOUND => {
            UplinkFetch::NotDispatched
        }
        // 凭据被拒 → 授权信号，不是抖动：强制回落待命（见 `CredentialRejected`）。
        Ok(response)
            if matches!(
                response.status(),
                reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
            ) =>
        {
            let status = response.status();
            // 正文里有网关的**稳定 code**（`unknown_credential` / `certificate_revoked` …）：
            // 捎上它，人和 `diagnose` 才看得出「为什么被拒」。
            let body = response.text().await.unwrap_or_default();
            let detail = match crate::enrollment::auth_rejection_code(&body) {
                Some(code) => format!("http {status} from {endpoint} ({code})"),
                None => format!("http {status} from {endpoint}"),
            };
            UplinkFetch::CredentialRejected(detail)
        }
        Ok(response) => UplinkFetch::Failed(format!("http {} from {endpoint}", response.status())),
        Err(err) => UplinkFetch::Failed(format!("transport: {err}")),
    }
}

/// 当前已应用的数据面上送 grant（内存态，跨 tick 活着）。
///
/// **不落盘**，这一点与工作授权不同（那份会写 `state/work.json`，好让重启后立刻接着干）。
/// 刻意如此：重启时回到**本机配置**（网关签发的初始配置是 `enabled = false`，即待命），
/// 比「离线重启后仍按旧授权继续外发」更安全 —— 一次断网不该让**已被撤回**的授权继续生效。
/// 代价：网关不可达时重启会停在待命（直到网关可达）。这是安全优先的取舍。
#[derive(Debug, Clone, Default)]
pub(crate) struct AppliedUplink {
    grant: Option<AgentUplinkGrant>,
    /// 上一次「异常」的签名，用于把重复的失败压成一行。
    last_failure: Option<String>,
}

impl AppliedUplink {
    /// 本机生效规则要用的那份 grant；`None` = 从未拿到过（未入网 / 旧网关 / 一直失败），
    /// 此时走本机 `[telemetry.logs.output]`。
    pub(crate) fn grant(&self) -> Option<&AgentUplinkGrant> {
        self.grant.as_ref()
    }

    /// 消费一次拉取结果，返回**该打的一行日志**（`None` = 不必打）。
    ///
    /// 四类结果：
    ///   * `Granted`：更新本机 grant；只有**生效状态**（开关 + 目标）真的变了才返回一行。
    ///     刻意**不**比 `granted_at` —— 网关每次 poll 都现算 `now()`，把它算进变化会让每个
    ///     在网 Agent 每 30s 都判为「变了」，既刷日志、又淹没真正的状态变迁。
    ///   * `NotDispatched`：预期内，静默；同时清掉失败记忆（下次真出故障要能再报一次）。
    ///   * `Failed(sig)`：同一签名只报一次；故障形态变了再报。**保留**上次 grant。
    ///   * `CredentialRejected(sig)`：同一签名只报一次；并**强制**把生效状态压成待命。
    pub(crate) fn observe(&mut self, outcome: UplinkFetch) -> Option<String> {
        match outcome {
            UplinkFetch::NotDispatched => {
                self.last_failure = None;
                None
            }
            UplinkFetch::Failed(signature) => {
                if self.last_failure.as_deref() == Some(signature.as_str()) {
                    return None;
                }
                let line = format!("wist-agentd uplink grant fetch failed: {signature}");
                self.last_failure = Some(signature);
                Some(line)
            }
            UplinkFetch::CredentialRejected(signature) => {
                // 强制待命（幂等）：即使客户端本来正按 `enabled = true` 上送，也立刻压回待命。
                // 这是「平台已收回授权」的形态，不能靠保留旧 grant 把它拖下去。
                let was_sending = self.grant.as_ref().map(effective_state) != Some(STANDBY_STATE);
                self.grant = Some(AgentUplinkGrant::standby(now_rfc3339()));
                let first_time = self.last_failure.as_deref() != Some(signature.as_str());
                self.last_failure = Some(signature.clone());
                if !was_sending && !first_time {
                    return None;
                }
                Some(format!(
                    "event=UplinkGrantRejected {signature} action=\"强制回落待命\""
                ))
            }
            UplinkFetch::Granted(grant) => {
                self.last_failure = None;
                let changed =
                    self.grant.as_ref().map(effective_state) != Some(effective_state(&grant));
                self.grant = Some(grant);
                if !changed {
                    return None;
                }
                let applied = self.grant.as_ref().expect("just assigned");
                Some(format!("event=UplinkGrantApplied {}", describe(applied)))
            }
        }
    }
}

/// 待命的生效状态（`enabled = false` 且无目标）。用于判定「当前是否正在上送」。
const STANDBY_STATE: (bool, Option<&str>, Option<u16>) = (false, None, None);

/// 变化判定只看**生效状态**：开关 + 目标。`granted_at` 是每次 poll 的墙钟，不参与。
///
/// `host` 与 `target()` 一样先 `trim`：两处归一化必须一致，否则 `" gw "` 与 `"gw"` 会被判成
/// 「目标变了」，却因为 `describe()` 走 `target()` 而打出**两行内容完全相同**的日志。
fn effective_state(grant: &AgentUplinkGrant) -> (bool, Option<&str>, Option<u16>) {
    (
        grant.enabled,
        grant.host.as_deref().map(str::trim),
        grant.port,
    )
}

/// 一行日志里的可读描述。
fn describe(grant: &AgentUplinkGrant) -> String {
    match (grant.enabled, grant.target()) {
        (false, _) => "enabled=false".to_string(),
        (true, Some((host, port))) => format!("enabled=true target={host}:{port}"),
        (true, None) => "enabled=true target=\"本机配置\"".to_string(),
    }
}

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};
    use wist_contracts::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };

    use super::{AppliedUplink, UplinkFetch, fetch_uplink_grant, fetch_uplink_grant_with_timeout};
    use wist_api::agent_uplink::AgentUplinkGrant;

    fn test_config(endpoint: &str) -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: Some("agent-x".to_string()),
                environment_id: None,
                instance_name: Some("instance-x".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: Some(endpoint.to_string()),
                enrollment_token: None,
                credential_request: None,
                credential_id: None,
                credential_expires_at: None,
                tls_mode: None,
                trust_bundle: None,
                auth_mode: None,
            },
            PathsSection::default(),
            ExecutionSection::default(),
        )
    }

    fn granted(enabled: bool, host: &str, port: u16, granted_at: &str) -> AgentUplinkGrant {
        AgentUplinkGrant {
            enabled,
            host: Some(host.to_string()),
            port: Some(port),
            granted_at: granted_at.to_string(),
        }
    }

    /// 读到一个完整 HTTP 请求（头 + content-length 指定的正文）后返回文本。
    async fn read_http_request(socket: &mut TcpStream) -> String {
        let mut request_bytes = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let read = socket.read(&mut chunk).await.expect("read");
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

    #[tokio::test]
    async fn a_200_response_is_parsed_into_the_grant() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(request.contains("/api/v1/agent/uplink:poll"));
            assert!(request.contains("\"kind\":\"poll_agent_uplink\""));
            assert!(request.contains("\"agent_id\":\"agent-x\""));
            assert!(request.contains("\"instance_id\":\"instance-x\""));
            // 凭据走客户端证书（mTLS）：请求里不再带 Authorization 头。
            assert!(!request.to_lowercase().contains("authorization:"));
            let body = r#"{"enabled":true,"host":"c-001.gateway.example","port":9000,"granted_at":"2026-09-26T00:00:00Z"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let config = test_config(&endpoint);
        let outcome = fetch_uplink_grant(&config).await;
        server.await.expect("server task");

        let UplinkFetch::Granted(grant) = outcome else {
            panic!("expected a granted outcome, got {outcome:?}");
        };
        assert_eq!(grant.target(), Some(("c-001.gateway.example", 9000)));
    }

    #[tokio::test]
    async fn a_404_from_an_old_gateway_is_no_dispatch_not_a_failure() {
        // 旧网关没有这个端点：必须当成「无下发」回落本机配置，且**不算故障**
        // （否则每 30s 一行 `failed`，正是本特性要消灭的噪声）。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = read_http_request(&mut socket).await;
            let response =
                "HTTP/1.1 404 Not Found\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let config = test_config(&endpoint);
        let outcome = fetch_uplink_grant(&config).await;
        server.await.expect("server task");

        assert_eq!(outcome, UplinkFetch::NotDispatched);
    }

    #[tokio::test]
    async fn a_401_or_403_is_a_credential_rejection_not_a_transport_failure() {
        // 凭据被拒是**授权信号**：必须与传输抖动区分开 —— 后者保留上次 grant，
        // 前者要强制回落待命，否则平台收不回已经收回的授权。
        for status in ["401 Unauthorized", "403 Forbidden"] {
            let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
            let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
            let server = tokio::spawn(async move {
                let (mut socket, _) = listener.accept().await.expect("accept");
                let _ = read_http_request(&mut socket).await;
                let response =
                    format!("HTTP/1.1 {status}\r\ncontent-length: 0\r\nconnection: close\r\n\r\n");
                socket.write_all(response.as_bytes()).await.expect("write");
            });

            let config = test_config(&endpoint);
            let outcome = fetch_uplink_grant(&config).await;
            server.await.expect("server task");

            match outcome {
                UplinkFetch::CredentialRejected(signature) => assert!(
                    signature.starts_with("http 40"),
                    "unexpected signature: {signature}"
                ),
                other => panic!("{status} must be a credential rejection, got {other:?}"),
            }
        }
    }

    #[tokio::test]
    async fn a_401_with_a_gateway_code_carries_it_in_the_signature() {
        // 正文里的稳定 code 要揎上：`diagnose`/运维据此分辨「库里没有这条凭据」还是「被拒名单」。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = read_http_request(&mut socket).await;
            let body = "agent identity rejected: certificate_revoked";
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let config = test_config(&endpoint);
        let outcome = fetch_uplink_grant(&config).await;
        server.await.expect("server task");

        match outcome {
            UplinkFetch::CredentialRejected(signature) => assert!(
                signature.contains("certificate_revoked"),
                "signature should carry the gateway code: {signature}"
            ),
            other => panic!("expected CredentialRejected, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_server_error_is_a_failure_with_a_stable_signature() {
        // 非 404 的错误码是真异常：要能被看见，且签名稳定（供上层去重）。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = read_http_request(&mut socket).await;
            let response = "HTTP/1.1 500 Internal Server Error\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let config = test_config(&endpoint);
        let outcome = fetch_uplink_grant(&config).await;
        server.await.expect("server task");

        match outcome {
            UplinkFetch::Failed(signature) => assert!(
                signature.starts_with("http 500"),
                "unexpected signature: {signature}"
            ),
            other => panic!("expected a failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn a_timed_out_request_is_a_transport_failure() {
        // 网关卡住不响应：超时必须封顶在 tick 预算内，并归结为**异常**（可见，按签名去重）。
        // 用注入的短超时把这条路径跑成毫秒级（真实超时 5s，测试不必等）。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            // 接受连接后什么都不写，让客户端超时。
            let (_socket, _) = listener.accept().await.expect("accept");
            tokio::time::sleep(Duration::from_secs(30)).await;
        });

        let config = test_config(&endpoint);
        let outcome = fetch_uplink_grant_with_timeout(&config, Duration::from_millis(100)).await;
        server.abort();

        match outcome {
            UplinkFetch::Failed(signature) => assert!(
                signature.starts_with("transport:"),
                "unexpected signature: {signature}"
            ),
            other => panic!("expected a transport failure, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn not_being_enrolled_is_no_dispatch() {
        // 未入网（缺 endpoint / agent_id 任一）→ 不拉、且是「无下发」不是故障。
        for strip in ["agent_id", "endpoint"] {
            let mut config = test_config("http://127.0.0.1:1");
            match strip {
                "agent_id" => config.agent.agent_id = None,
                "endpoint" => config.control_plane.endpoint = None,
                _ => unreachable!(),
            }
            assert_eq!(
                fetch_uplink_grant(&config).await,
                UplinkFetch::NotDispatched,
                "missing {strip} must be a quiet no-dispatch"
            );
        }
    }

    #[test]
    fn a_credential_rejection_forces_standby_and_is_reported_once() {
        // 凭据被拒 → **立即压回待命**（不是保留），因为那是「平台已收回授权」的形态。
        let mut applied = AppliedUplink::default();
        let _ = applied.observe(UplinkFetch::Granted(granted(true, "gw.example", 9000, "t")));
        assert_eq!(
            applied.grant().and_then(|grant| grant.target()),
            Some(("gw.example", 9000))
        );

        let line = applied
            .observe(UplinkFetch::CredentialRejected(
                "http 401 from gw".to_string(),
            ))
            .expect("forcing standby must be visible");
        assert!(line.contains("UplinkGrantRejected"), "{line}");
        assert_eq!(applied.grant().map(|grant| grant.enabled), Some(false));
        assert_eq!(applied.grant().and_then(|grant| grant.target()), None);

        // 同一个拒绝还在 → 不重刷，但仍是待命（幂等）。
        assert!(
            applied
                .observe(UplinkFetch::CredentialRejected(
                    "http 401 from gw".to_string()
                ))
                .is_none()
        );
        assert_eq!(applied.grant().map(|grant| grant.enabled), Some(false));
    }

    #[test]
    fn a_renewed_credential_reopens_the_uplink() {
        // 强制待命不是「锁死」：凭据恢复后下一个成功的 poll 必须能把上送重新打开。
        let mut applied = AppliedUplink::default();
        let _ = applied.observe(UplinkFetch::CredentialRejected(
            "http 403 from gw".to_string(),
        ));
        assert_eq!(applied.grant().map(|grant| grant.enabled), Some(false));

        let line = applied
            .observe(UplinkFetch::Granted(granted(true, "gw.example", 9000, "t")))
            .expect("recovery must be reported");
        assert!(line.contains("enabled=true"), "{line}");
        assert_eq!(applied.grant().map(|grant| grant.enabled), Some(true));
    }

    #[test]
    fn a_rejection_before_any_grant_still_forces_standby() {
        // 现状（刻意的 fail-closed）：只要网关明确拒了凭据，就不再按本机配置跑 ——
        // 连「从未下发过 grant」的机器也一样（从「本机配置」被压成待命）。
        // 401 的来源不止吊销/过期：本机 token 写错、克隆机 `instance_id` 不匹配、
        // 网关换库/恢复后旧凭据失效 —— agent 分不清，一律按「平台不再认我」处理。
        let mut applied = AppliedUplink::default();
        let line = applied
            .observe(UplinkFetch::CredentialRejected(
                "http 401 from gw".to_string(),
            ))
            .expect("must be visible");
        assert!(line.contains("UplinkGrantRejected"), "{line}");
        assert_eq!(applied.grant().map(|grant| grant.enabled), Some(false));
    }

    #[test]
    fn a_not_dispatched_outcome_after_a_rejection_keeps_the_forced_standby() {
        // 401 之后网关变成 404（降级 / 端点下线）：`NotDispatched` 只清失败记忆、**不改** grant
        // ⇒ 会一直待命到重新出现 `Granted`。方向安全（不外发），但它**不是**「回落本机配置」。
        let mut applied = AppliedUplink::default();
        let _ = applied.observe(UplinkFetch::CredentialRejected(
            "http 401 from gw".to_string(),
        ));
        assert!(applied.observe(UplinkFetch::NotDispatched).is_none());
        assert_eq!(
            applied.grant().map(|grant| grant.enabled),
            Some(false),
            "被拒之后不该因为 404 就回落本机配置"
        );
    }

    #[test]
    fn a_failed_fetch_never_clears_the_last_applied_grant() {
        // 与工作授权同一取舍：失败不覆盖已有的 grant，网络抖动不该把「已开」倒退成「关」。
        let mut applied = AppliedUplink::default();
        let grant = granted(true, "h", 9000, "t1");
        assert!(
            applied
                .observe(UplinkFetch::Granted(grant.clone()))
                .is_some()
        );
        assert!(
            applied
                .observe(UplinkFetch::Failed("transport: boom".to_string()))
                .is_some()
        );
        assert_eq!(applied.grant(), Some(&grant));

        // 未下发同样不清空（旧网关 404 不该把已应用的目标抹掉）。
        assert!(applied.observe(UplinkFetch::NotDispatched).is_none());
        assert_eq!(applied.grant(), Some(&grant));
    }

    #[test]
    fn a_repeat_grant_with_only_granted_at_moved_is_not_reported_again() {
        // 钉住这行的可读性：网关每次 poll 都现算 `granted_at`，若把它算进“变化”，
        // 每个在网 Agent 每 30s 就会打一行 —— 等于把状态日志变成心跳噪声。
        let mut applied = AppliedUplink::default();
        let first = granted(true, "gw.example", 9000, "2026-09-26T00:00:00Z");
        let second = granted(true, "gw.example", 9000, "2026-09-26T00:00:30Z");

        let line = applied
            .observe(UplinkFetch::Granted(first))
            .expect("first line");
        assert!(
            line.contains("enabled=true target=gw.example:9000"),
            "{line}"
        );
        assert!(
            applied.observe(UplinkFetch::Granted(second)).is_none(),
            "同一份状态、只是 granted_at 变了，不该再打一行"
        );
    }

    #[test]
    fn a_changed_effective_state_is_reported_once() {
        let mut applied = AppliedUplink::default();
        assert!(
            applied
                .observe(UplinkFetch::Granted(granted(true, "a", 9000, "t")))
                .is_some()
        );
        // 换目标 → 报。
        let line = applied
            .observe(UplinkFetch::Granted(granted(true, "b", 9001, "t")))
            .expect("target change must be reported");
        assert!(line.contains("enabled=true target=b:9001"), "{line}");
        // 关闸 → 报。
        let line = applied
            .observe(UplinkFetch::Granted(AgentUplinkGrant::standby(
                "t".to_string(),
            )))
            .expect("disable must be reported");
        assert!(line.contains("enabled=false"), "{line}");
    }

    #[test]
    fn a_repeated_failure_is_reported_once_and_again_after_it_changes() {
        let mut applied = AppliedUplink::default();
        let first = applied
            .observe(UplinkFetch::Failed("transport: refused".to_string()))
            .expect("first failure must be visible");
        assert!(first.contains("transport: refused"), "{first}");
        // 同一个故障还在 → 不重刷（每 30s 一行是噪声）。
        assert!(
            applied
                .observe(UplinkFetch::Failed("transport: refused".to_string()))
                .is_none()
        );
        // 故障形态变了 → 再报一次。
        assert!(
            applied
                .observe(UplinkFetch::Failed("http 500 from gw".to_string()))
                .is_some()
        );
        // 恢复正常（NotDispatched）后清掉记忆 → 同一故障再出现要能再报。
        assert!(applied.observe(UplinkFetch::NotDispatched).is_none());
        assert!(
            applied
                .observe(UplinkFetch::Failed("http 500 from gw".to_string()))
                .is_some(),
            "recovery must reset the failure memory"
        );
    }
}
