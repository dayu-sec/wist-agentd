//! Startup enrollment client for managed agents.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use orion_error::{conversion::ToStructError, prelude::*};

use wist_contracts::agent_config::AgentConfig;
use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};
use wist_contracts::enrollment::{
    CredentialRenewal, CredentialRenewed, EnrollmentEnvelope, EnrollmentOutcome, EnrollmentRequest,
    EnrollmentStatus, HostProfile,
};
use wist_shared::fs::write_bytes_private_atomic;
use wist_shared::time::now_rfc3339;

use crate::state_store;

const ENROLLMENT_CONNECT_TIMEOUT: Duration = Duration::from_secs(5);
const ENROLLMENT_REQUEST_TIMEOUT: Duration = Duration::from_secs(10);
const ENROLLMENT_MAX_ATTEMPTS: u32 = 3;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnrollmentDecision {
    Disabled,
    ExistingConfigIdentity,
    ExistingStateIdentity,
    Enrolled,
}

pub use crate::error::{EnrollmentError, EnrollmentReason, EnrollmentResult};

/// 网关 401 正文里代表「**重试也没用、必须运维介入**」的稳定 `code`（`unauthorized_code`）。
///
/// 为什么不是「凡 401 即终态」：「没带证书」（`certificate_required`）与「网关没开 mTLS」
/// （`missing_credential`）都会在配置 / 证书到位后**自愈**，不该让守护进程停死；
/// 下面这些才是**确实回不来**的。
///
/// （mTLS 收口后只剩这两个 —— 旧的 `unknown_credential` / `credential_mismatch` /
/// `credential_inactive` 是 bearer 双轨的产物，网关已不再产生。）
pub(crate) const TERMINAL_AUTH_CODES: &[&str] = &[
    // 被拒名单（§5.6）：得由运维在网关解除，重装/重注册都无效。
    "certificate_revoked",
    // 证书身份与请求体里的 agent 对不上：重试也回不来，只能重新注册。
    "certificate_mismatch",
];

/// 每个终态 code 的**处置**（给运维看的一句话）。
///
/// 为何集中在一张表：守护进程的终态日志与 `diagnose` 的提示词以前各写一份，于是会漂 ——
/// 2026-09-30 实撞过一次：网关回 `credential_mismatch`，而 `diagnose` 的提示词只列了
/// `unknown_credential` 与 `certificate_revoked`，操作者只能猜。现在两边**同源**，
/// 且 [`crate::doctor`] 的测试会卡住「[`TERMINAL_AUTH_CODES`] 里的每个 code 都得有处置」。
pub(crate) fn terminal_auth_advice(code: &str) -> Option<&'static str> {
    match code {
        "certificate_revoked" => Some("在被拒名单里：得运维先在网关解除，重装/重注册都没用"),
        "certificate_mismatch" => {
            Some("证书身份与这台 agent 对不上：用一次性 token 重新注册（`enroll --force`）")
        }
        _ => None,
    }
}

/// 从 401/403 正文里认出网关的稳定 `code`。
pub(crate) fn auth_rejection_code(body: &str) -> Option<&'static str> {
    TERMINAL_AUTH_CODES
        .iter()
        .copied()
        .find(|code| body.contains(code))
}

/// 网关控制面响应里可辨识的**终态**信号（§5.4）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum AuthRejection {
    /// 需要**运维介入**的终态：带上网关的稳定 code（`unknown_credential` / `certificate_revoked` …），
    /// 停下、别重试（重装也未必有用）。
    Terminal(&'static str),
    /// 其它拒绝（凭据过期 / 未带凭据 / 服务端抖动…）：按普通失败处理（可重试 / 可自愈）。
    NotRevoked,
}

/// 从一次控制面响应里认出「需要停下的终态」。
///
/// 稳定 code 见 [`TERMINAL_AUTH_CODES`]；网关在 `agent_ops.rs` 的 `unauthorized_code` 里回它们
/// （`docs/design/agent-identity-mtls.md` §5.4）。
pub(crate) fn classify_auth_rejection(status: reqwest::StatusCode, body: &str) -> AuthRejection {
    if !matches!(
        status,
        reqwest::StatusCode::UNAUTHORIZED | reqwest::StatusCode::FORBIDDEN
    ) {
        return AuthRejection::NotRevoked;
    }
    match auth_rejection_code(body) {
        Some(code) => AuthRejection::Terminal(code),
        None => AuthRejection::NotRevoked,
    }
}

pub async fn ensure_enrolled(
    config: &mut AgentConfig,
    state_dir: &Path,
) -> Result<EnrollmentDecision, EnrollmentError> {
    ensure_enrolled_with_optional_config_path(config, state_dir, None).await
}

pub async fn ensure_enrolled_with_config_path(
    config: &mut AgentConfig,
    state_dir: &Path,
    config_path: &Path,
) -> Result<EnrollmentDecision, EnrollmentError> {
    ensure_enrolled_with_optional_config_path(config, state_dir, Some(config_path)).await
}

/// 用**命令行传入的一次性 token** 完成注册：token 不写入任何文件。
///
/// - 配置必须已存在（`init-config` 生成），其中提供 `control_plane.endpoint`（非秘密，可由 CM 管）；
/// - token 只在本进程内存里使用，注完就走与守护进程启动时**完全相同**的注册路径；
/// - 已注册（state 里有正式 `agent_id`）时直接返回 `ExistingStateIdentity`，不重复注册；
/// - 成功后仅有签发凭据落 `state/agent_runtime.json`（0600）；配置文件不会被改动
///   （配置里本来就没有 token 行，scrub 无事可做）。
///
/// 参数校验（endpoint 必填、token 必填）交给注册路径自身：这样“已注册”与“控制面关掉”
/// 这类不需要 token/endpoint 的情形才能给出正确的返回与报错。
pub async fn enroll_with_token(
    config_root: &Path,
    token: String,
) -> EnrollmentResult<EnrollmentDecision> {
    enroll_with_optional_token(config_root, Some(token), false).await
}

/// `enroll --force`：**先丢掉本地身份**（凭据 state + 已签发的客户端证书），再重新注册。
///
/// 这是「重装 ≠ 重注册」的补口（§8）：state 里已有身份时注册会被跳过，
/// 证书过期/被拒、换网关、或本地身份错乱时就需要它把旧身份扔掉。
pub async fn enroll_with_token_forced(
    config_root: &Path,
    token: String,
) -> EnrollmentResult<EnrollmentDecision> {
    enroll_with_optional_token(config_root, Some(token), true).await
}

/// 不带 token 的注册（用配置／环境变量里的 token）；等价于守护进程启动时的注册。
pub async fn enroll_from_config(config_root: &Path) -> EnrollmentResult<EnrollmentDecision> {
    enroll_with_optional_token(config_root, None, false).await
}

/// `--force` 用：丢掉本地**身份**（凭据 state + 已签发的客户端证书 + 续期台账）。
///
/// 保留本地私钥：私钥是本机耗材，「身份」是网关签出来的东西 ——
/// 重注册只要重新交一次 CSR（§4.2）。
fn discard_local_identity(state_dir: &Path) -> EnrollmentResult<()> {
    let runtime_path = state_store::agent_runtime::path_for(state_dir);
    if runtime_path.exists() {
        fs::remove_file(&runtime_path)
            .source_raw_err(EnrollmentReason::Io, "discard local credential state")?;
    }
    let paths = state_store::client_identity::ClientIdentityPaths::under(state_dir);
    if paths.cert_file.exists() {
        fs::remove_file(&paths.cert_file)
            .source_raw_err(EnrollmentReason::Io, "discard local client certificate")?;
    }
    if paths.renewal_file.exists() {
        fs::remove_file(&paths.renewal_file)
            .source_raw_err(EnrollmentReason::Io, "discard renewal ledger")?;
    }
    Ok(())
}

async fn enroll_with_optional_token(
    config_root: &Path,
    token: Option<String>,
    force: bool,
) -> EnrollmentResult<EnrollmentDecision> {
    let config_path = crate::config_runtime::resolve_config_path(config_root);
    if !config_path.is_file() {
        return Err(EnrollmentReason::MissingConfigFile
            .to_err()
            .with_detail(format!(
                "config file not found: {} (run `wist-agentd init-config --config-dir {}` first)",
                config_path.display(),
                config_root.display()
            )));
    }

    let mut config = crate::config_runtime::load_from_path_async(&config_path)
        .await
        .conv_err()?;

    let root_dir = PathBuf::from(&config.paths.root_dir);
    let run_dir = PathBuf::from(&config.paths.run_dir);
    let state_dir = PathBuf::from(&config.paths.state_dir);
    let log_dir = PathBuf::from(&config.paths.log_dir);
    crate::bootstrap::initialize_async(&root_dir, &run_dir, &state_dir, &log_dir)
        .await
        .source_err(EnrollmentReason::Io, "initialize runtime directories")?;

    if force {
        discard_local_identity(&state_dir)?;
    }

    if let Some(token) = token {
        config.control_plane.enrollment_token = Some(token);
    }
    ensure_enrolled_with_config_path(&mut config, &state_dir, &config_path).await
}

async fn ensure_enrolled_with_optional_config_path(
    config: &mut AgentConfig,
    state_dir: &Path,
    config_path: Option<&Path>,
) -> Result<EnrollmentDecision, EnrollmentError> {
    if has_config_identity(config) {
        if let Some(config_path) = config_path {
            scrub_enrollment_token_from_config_file(config_path)?;
        }
        return Ok(EnrollmentDecision::ExistingConfigIdentity);
    }
    if load_state_identity(config, state_dir)? {
        renew_state_credential_if_needed(config, state_dir).await;
        if let Some(config_path) = config_path {
            scrub_enrollment_token_from_config_file(config_path)?;
        }
        return Ok(EnrollmentDecision::ExistingStateIdentity);
    }
    if !config.control_plane.enabled {
        return Ok(EnrollmentDecision::Disabled);
    }

    let endpoint = required_option(config.control_plane.endpoint.as_deref())
        .ok_or_else(|| {
            EnrollmentReason::MissingEndpoint
                .to_err()
                .with_detail("control_plane.endpoint is required for enrollment")
        })?
        .to_string();
    let token = required_option(config.control_plane.enrollment_token.as_deref())
        .ok_or_else(|| {
            EnrollmentReason::MissingEnrollmentToken.to_err().with_detail(
                "no enrollment token available; enroll first with `wist-agentd enroll --token <token>` \
(or install with `service install --enrollment-token <token>`)",
            )
        })?
        .to_string();
    let request = build_enrollment_request(config, state_dir, token)?;
    let returned = post_enrollment(config, &endpoint, &request).await?;
    apply_enrollment_result(config, state_dir, returned.result)?;
    if let Some(config_path) = config_path {
        scrub_enrollment_token_from_config_file(config_path)?;
    }
    Ok(EnrollmentDecision::Enrolled)
}

fn has_config_identity(config: &AgentConfig) -> bool {
    required_option(config.agent.agent_id.as_deref()).is_some()
}

/// 把 `state/agent_runtime.json` 里的正式身份与凭据注入配置 —— **只读 state，不联网、不续期**。
///
/// 给**升级器**这类独立进程用：daemon 启动时会走 [`ensure_enrolled_with_config_path`] 拿到凭据，
/// 而身份（`agent_id` / 客户端证书路径）**从不写进 `agentd.toml`**、只落在 state / `identity/`；
/// 升级器只 `load_from_path` 就读不到它，取包会发不出安证（网关回 401）。
/// 所以升级器取包前补这一步。
///
/// 与 [`ensure_enrolled_with_config_path`] 的差别：即便配置里已有 `agent_id`（`has_config_identity`
/// 为真，`ensure_enrolled` 会就此早返回）这里也照常从 state 注入，确保凭据一定被带上。
/// 返回是否读到一份已注册的 state 身份。
pub fn restore_runtime_identity(
    config: &mut AgentConfig,
    state_dir: &Path,
) -> Result<bool, EnrollmentError> {
    load_state_identity(config, state_dir)
}

fn load_state_identity(
    config: &mut AgentConfig,
    state_dir: &Path,
) -> Result<bool, EnrollmentError> {
    let runtime_path = state_store::agent_runtime::path_for(state_dir);
    if !runtime_path.exists() {
        return Ok(false);
    }
    let runtime_state = state_store::agent_runtime::load_or_default(&runtime_path)
        .source_err(EnrollmentReason::Io, "load runtime state")?;
    if !is_registered_agent_id(&runtime_state.agent_id) {
        return Ok(false);
    }

    config.agent.agent_id = Some(runtime_state.agent_id.clone());
    config.agent.instance_name = Some(runtime_state.instance_id.clone());
    if let Some(credential_id) = runtime_state
        .credential_id
        .filter(|value| !value.trim().is_empty())
    {
        config.control_plane.credential_id = Some(credential_id);
        // 凭据路径只剩客户端证书；标记一下便于诊断 / 展示。
        config.control_plane.auth_mode = Some("certificate".to_string());
        config.control_plane.enrollment_token = None;
    }
    if let Some(expires_at) = runtime_state
        .credential_expires_at
        .filter(|value| !value.trim().is_empty())
    {
        config.control_plane.credential_expires_at = Some(expires_at);
    }
    Ok(true)
}

fn build_enrollment_request(
    config: &AgentConfig,
    state_dir: &Path,
    token: String,
) -> Result<EnrollmentRequest, EnrollmentError> {
    // mTLS 是唯一凭据路径：注册**必须**带 CSR（网关据此签客户端证书，没有它就没有凭据）。
    let certificate_signing_request = local_certificate_signing_request(state_dir)?;
    Ok(EnrollmentRequest::new(
        token,
        "csr".to_string(),
        certificate_signing_request,
        build_host_profile(config),
        "wist-agentd:discovery,telemetry,local-exec".to_string(),
        now_rfc3339(),
    ))
}

/// 本地生成（或复用）客户端密钥，并用它生成 CSR：**只交公钥**，主体由网关填（§4.2）。
///
/// 生成失败即**注册失败**：mTLS 是唯一凭据路径，没有 CSR 就没有任何可用凭据
/// —— 继续注册等于发回一个拿不到证书、注定连不上的身份。
fn local_certificate_signing_request(state_dir: &Path) -> Result<String, EnrollmentError> {
    let paths = state_store::client_identity::ClientIdentityPaths::under(state_dir);
    let key_pair = state_store::client_identity::load_or_generate_key_pair(&paths).source_err(
        EnrollmentReason::Io,
        "prepare a local client key for the certificate signing request",
    )?;
    state_store::client_identity::build_certificate_signing_request(&key_pair).source_err(
        EnrollmentReason::Io,
        "build the certificate signing request",
    )
}

fn build_host_profile(config: &AgentConfig) -> HostProfile {
    let hostname = hostname_from_sources(
        std::env::var("HOSTNAME").ok().as_deref(),
        std::env::var("COMPUTERNAME").ok().as_deref(),
        hostname_from_file().as_deref(),
    );
    let machine_id = machine_id_from_file().unwrap_or_else(|| "unknown".to_string());
    let node_id = first_non_empty([
        config.agent.instance_name.as_deref(),
        Some(machine_id.as_str()),
        Some(hostname.as_str()),
    ])
    .unwrap_or("local-node")
    .to_string();

    HostProfile {
        node_id,
        hostname,
        os: std::env::consts::OS.to_string(),
        arch: std::env::consts::ARCH.to_string(),
        machine_id,
        cloud_instance_id: std::env::var("WARP_INSIGHT_CLOUD_INSTANCE_ID").ok(),
        k8s_node_uid: std::env::var("WARP_INSIGHT_K8S_NODE_UID").ok(),
        ip_addresses: Vec::new(),
    }
}

async fn post_enrollment(
    config: &AgentConfig,
    endpoint: &str,
    request: &EnrollmentRequest,
) -> Result<EnrollmentEnvelope, EnrollmentError> {
    let url = format!("{}/api/v1/agent/enroll", endpoint.trim_end_matches('/'));
    let client = enrollment_http_client(config)?;
    let response = send_with_retry(&client, |client| client.post(&url).json(request)).await?;
    let response = response
        .error_for_status()
        .source_raw_err(EnrollmentReason::Http, "enrollment http error")?;
    response
        .json::<EnrollmentEnvelope>()
        .await
        .source_raw_err(EnrollmentReason::Http, "decode enrollment response")
}

/// Send the request with bounded retries on transport errors (connect refused,
/// DNS, timeout). HTTP status outcomes (4xx/5xx, rejected) are returned to the
/// caller without retry so single-use bootstrap tokens are not double-spent.
async fn send_with_retry(
    client: &reqwest::Client,
    build: impl Fn(&reqwest::Client) -> reqwest::RequestBuilder,
) -> Result<reqwest::Response, EnrollmentError> {
    for attempt in 0..ENROLLMENT_MAX_ATTEMPTS {
        match build(client).send().await {
            Ok(response) => return Ok(response),
            Err(_) if attempt + 1 < ENROLLMENT_MAX_ATTEMPTS => {
                tokio::time::sleep(retry_backoff(attempt)).await;
            }
            Err(err) => {
                return Err(StructError::builder(EnrollmentReason::Http)
                    .detail("enrollment http error")
                    .source_std(err)
                    .finish());
            }
        }
    }
    unreachable!("send_with_retry loop always returns")
}

fn retry_backoff(attempt: u32) -> Duration {
    Duration::from_millis(200 * 2u64.pow(attempt))
}

/// 一次续期判定的结果（启动续期与周期性续期共用，也是台账里记的东西）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RenewalDecision {
    /// 还早，什么都不用做。
    NotDue,
    /// 续期成功：新凭据已落 state（有证书时新证书也已落盘）。
    Renewed,
    /// 落在续期窗内但续期失败 —— 保留旧凭据，下个周期再试。
    Failed(String),
    /// 证书已过期：**本地不再重试**，需带 token 重装（§4.2 无宽限）。
    NeedsReinstall,
    /// 被网关**吊销**（§5.6）：终态，本地不再重试。
    ///
    /// 与 [`RenewalDecision::NeedsReinstall`] 刻意分开：那个的出路是「带 token 重装」，
    /// 而对被吊销的 agent **重装也没用** —— 得先由运维在网关解除拒绝名单，再重启 agentd。
    Revoked,
}

impl RenewalDecision {
    fn ledger_outcome(&self) -> &'static str {
        match self {
            RenewalDecision::NotDue => "not_due",
            RenewalDecision::Renewed => "renewed",
            RenewalDecision::Failed(_) => "failed",
            RenewalDecision::NeedsReinstall => "needs_reinstall",
            RenewalDecision::Revoked => "revoked",
        }
    }

    fn ledger_detail(&self) -> String {
        match self {
            RenewalDecision::NotDue => "credential is not due for renewal".to_string(),
            RenewalDecision::Renewed => "credential renewed".to_string(),
            RenewalDecision::Failed(detail) => detail.clone(),
            RenewalDecision::NeedsReinstall => {
                "no usable client certificate; re-enroll or reinstall with a token".to_string()
            }
            RenewalDecision::Revoked => {
                "gateway refused this agent as revoked (denylist); an operator must lift the \
                 revocation, then restart — reinstalling will not help"
                    .to_string()
            }
        }
    }

    /// 台账/日志共用的处置文案（避免守护进程日志与台账各写一份而漂移）。
    pub(crate) fn ledger_detail_text(&self) -> String {
        self.ledger_detail()
    }
}

/// 到期就续期；由**启动路径**与**守护进程的周期检查**共同调用（issue #15）。
///
/// 判定与结果都落台账（`identity/renewal.json`）：续签是后台动作，不记录就等于又变成静默。
pub async fn renew_credential_if_due(
    config: &mut AgentConfig,
    state_dir: &Path,
) -> RenewalDecision {
    let decision = renewal_decision(config, state_dir).await;
    record_renewal_ledger(state_dir, &decision);
    decision
}

async fn renewal_decision(config: &mut AgentConfig, state_dir: &Path) -> RenewalDecision {
    use state_store::client_identity::CertificateValidity;

    let paths = state_store::client_identity::ClientIdentityPaths::under(state_dir);
    // ① 有本地客户端证书：**以证书为准** —— mTLS 才是长期身份（§4.2 / §5.4）。
    match state_store::client_identity::client_certificate_status(&paths) {
        Ok(Some(status)) => match status.validity {
            CertificateValidity::Expired => {
                eprintln!(
                    "wist-agentd client certificate expired at {}: re-enroll or reinstall required (not retrying)",
                    status.not_after
                );
                return RenewalDecision::NeedsReinstall;
            }
            CertificateValidity::Valid => return RenewalDecision::NotDue,
            CertificateValidity::RenewDue => {}
        },
        // 没有本地客户端证书：mTLS 是唯一凭据路径，此刻这台机器**没有任何可用身份**
        // （续期也过不去）—— 不重试，记「需重装」（带一次性 token 重新注册）。
        Ok(None) => {
            eprintln!(
                "wist-agentd has no client certificate: re-enroll or reinstall with a token \
                 (mTLS is the only credential path; not retrying)"
            );
            return RenewalDecision::NeedsReinstall;
        }
        Err(err) => {
            eprintln!("wist-agentd cannot read the local client certificate status: {err}");
            return RenewalDecision::Failed(err.to_string());
        }
    }
    renew_now(config, state_dir).await
}

async fn renew_now(config: &mut AgentConfig, state_dir: &Path) -> RenewalDecision {
    match renew_credential(config, state_dir).await {
        Ok(RenewOutcome::Done) => RenewalDecision::Renewed,
        Ok(RenewOutcome::Revoked) => {
            eprintln!(
                "event=AgentAuthTerminal code=certificate_revoked source=renewal detail=\"gateway refused this agent as revoked (denylist); an operator must lift it, then restart — reinstalling will not help\""
            );
            RenewalDecision::Revoked
        }
        Err(err) => {
            eprintln!(
                "wist-agentd credential renewal failed (continuing with existing credential): {err}"
            );
            RenewalDecision::Failed(err.to_string())
        }
    }
}

/// 启动时的续期检查（守护进程启动路径用；周期检查在 daemon 循环里）。
async fn renew_state_credential_if_needed(config: &mut AgentConfig, state_dir: &Path) {
    let _ = renew_credential_if_due(config, state_dir).await;
}

/// 把判定结果写到台账；写不动只记一行，**不影响**续期本身。
fn record_renewal_ledger(state_dir: &Path, decision: &RenewalDecision) {
    let paths = state_store::client_identity::ClientIdentityPaths::under(state_dir);
    let not_after = state_store::client_identity::client_certificate_status(&paths)
        .ok()
        .flatten()
        .map(|status| status.not_after)
        .unwrap_or_default();
    let ledger = state_store::client_identity::RenewalLedger {
        checked_at: now_rfc3339(),
        outcome: decision.ledger_outcome().to_string(),
        detail: decision.ledger_detail(),
        not_after,
    };
    if let Err(err) = state_store::client_identity::store_renewal_ledger(&paths, &ledger) {
        eprintln!("wist-agentd cannot record the renewal ledger: {err}");
    }
}

async fn renew_credential(
    config: &mut AgentConfig,
    state_dir: &Path,
) -> Result<RenewOutcome, EnrollmentError> {
    let Some(endpoint) = required_option(config.control_plane.endpoint.as_deref()) else {
        return Err(EnrollmentReason::MissingEndpoint
            .to_err()
            .with_detail("control_plane.endpoint is required for enrollment"));
    };
    let Some(agent_id) = required_option(config.agent.agent_id.as_deref()) else {
        return Ok(RenewOutcome::Done);
    };
    let instance_id = required_option(config.agent.instance_name.as_deref())
        .unwrap_or_default()
        .to_string();
    let certificate_signing_request = local_certificate_signing_request(state_dir)?;
    let request = CredentialRenewal::new(
        agent_id.to_string(),
        instance_id,
        "csr".to_string(),
        certificate_signing_request,
        now_rfc3339(),
    );
    let client = enrollment_http_client(config)?;
    let url = format!(
        "{}/api/v1/agent/credentials:renew",
        endpoint.trim_end_matches('/')
    );
    // 凭据由客户端证书（mTLS 握手）验明，不再发 Authorization 头。
    let response = send_with_retry(&client, |client| client.post(&url).json(&request)).await?;
    // 不再用 `error_for_status()`：要先读正文，才能把「被吊销（终态）」从普通失败里认出来（§5.4）。
    let status = response.status();
    if !status.is_success() {
        let body = response.text().await.unwrap_or_default();
        if matches!(
            classify_auth_rejection(status, &body),
            AuthRejection::Terminal(_)
        ) {
            return Ok(RenewOutcome::Revoked);
        }
        return Err(EnrollmentReason::Http
            .to_err()
            .with_detail(format!("renewal http error: {status} {}", body.trim())));
    }
    let renewed: CredentialRenewed = response
        .json()
        .await
        .source_raw_err(EnrollmentReason::Http, "decode renewal response")?;
    let credential = renewed.credential_bundle;

    apply_credential_to_config(config, &credential)?;
    // 新证书必须落盘：续期后控制面请求都拿它走 mTLS，不落盘就用不上新证书。
    store_issued_client_certificate(state_dir, &credential)?;
    let runtime_path = state_store::agent_runtime::path_for(state_dir);
    let mut runtime_state = state_store::agent_runtime::load_or_default_async(&runtime_path)
        .await
        .source_err(EnrollmentReason::Io, "load runtime state")?;
    apply_credential_to_runtime_state(&mut runtime_state, credential);
    state_store::agent_runtime::store_async(&runtime_path, &runtime_state)
        .await
        .source_err(EnrollmentReason::Io, "store runtime state")?;
    Ok(RenewOutcome::Done)
}

/// `renew_credential` 的结果。
///
/// 为什么要单独区分 `Revoked`：被吊销是**终态**（§5.6）—— 它不是「这次失败、下次再试」，
/// 继续按 `Failed` 重试就是静默卡死。用 `Ok(Revoked)`（而不是 `Err`）表达「请求成功、答案是被拒」，
/// 把「已判明的终态」与「传输 / 落盘失败」两条通道分开。
enum RenewOutcome {
    /// 续好了，或本来就没东西可续（缺 token / agent_id，与既有行为一致）。
    Done,
    /// 网关明确回了「被吊销」。
    Revoked,
}

pub(crate) fn enrollment_http_client(
    config: &AgentConfig,
) -> Result<reqwest::Client, EnrollmentError> {
    let mut builder = reqwest::Client::builder()
        .connect_timeout(ENROLLMENT_CONNECT_TIMEOUT)
        .timeout(ENROLLMENT_REQUEST_TIMEOUT);
    let endpoint = config.control_plane.endpoint.as_deref().unwrap_or_default();
    let effective_mode = match config.control_plane.tls_mode.as_deref() {
        Some(mode) => mode,
        None if endpoint.starts_with("https://") => "https",
        None => "http",
    };
    let mut loaded_trust_bundle = false;
    match effective_mode {
        // Verify the control-plane certificate; use trust_bundle when provided,
        // otherwise fall back to the platform root store.
        "https" | "verify" => {
            if let Some(trust_bundle) =
                required_option(config.control_plane.trust_bundle.as_deref())
            {
                let certificate =
                    reqwest::Certificate::from_pem(trust_bundle.as_bytes()).map_err(|err| {
                        EnrollmentReason::InvalidTrustBundle
                            .to_err()
                            .with_detail(format!("invalid control_plane.trust_bundle: {err}"))
                    })?;
                builder = builder.add_root_certificate(certificate);
                loaded_trust_bundle = true;
            }
        }
        // Explicitly disable TLS certificate verification (lab / self-signed only).
        "none" => {
            builder = builder.danger_accept_invalid_certs(true);
        }
        // Plain HTTP, no TLS.
        "http" => {}
        other => {
            return Err(EnrollmentReason::InvalidTlsMode
                .to_err()
                .with_detail(format!("invalid control_plane.tls_mode: {other}")));
        }
    }
    // mTLS：有本地客户端证书就出示它（docs/design/agent-identity-mtls.md §5.2）。
    // 证书是**注册后**才有的 —— 首次注册那次请求这里为空，正是「注册前还没有已签发身份」。
    if let Some(identity) = local_client_identity(config) {
        builder = builder.identity(identity);
    }
    builder.build().map_err(|err| {
        if loaded_trust_bundle {
            EnrollmentReason::InvalidTrustBundle
                .to_err()
                .with_detail(format!("invalid control_plane.trust_bundle: {err}"))
        } else {
            StructError::builder(EnrollmentReason::Http)
                .detail("enrollment http error")
                .source_std(err)
                .finish()
        }
    })
}

/// 组装本地客户端身份（证书 + 私钥）供 reqwest 出示；两者齐备**且未过期**才返回。
///
/// 读不出来/解不开只打印一行并返回 `None`：注册与上报不能因为本地证书坏了就断掉 ——
/// 拿不到证书时还有 bearer 双轨可走。
///
/// 已过期也**不出示**：rustls 会把过期证书当作握手失败，那样连「重新注册」都到不了服务端，
/// 只能人工删文件（见 `docs/design/agent-identity-mtls.md` §4.2 无宽限 / §5.4）。
fn local_client_identity(config: &AgentConfig) -> Option<reqwest::Identity> {
    let state_dir = PathBuf::from(&config.paths.state_dir);
    let paths = state_store::client_identity::ClientIdentityPaths::under(&state_dir);
    match state_store::client_identity::client_certificate_status(&paths) {
        Ok(Some(status))
            if status.validity == state_store::client_identity::CertificateValidity::Expired =>
        {
            eprintln!(
                "wist-agentd local client certificate expired at {}; not presenting it (re-enroll or reinstall required)",
                status.not_after
            );
            return None;
        }
        Ok(_) => {}
        Err(err) => {
            eprintln!("wist-agentd cannot read the local client certificate status: {err}");
            return None;
        }
    }
    let combined = match state_store::client_identity::combined_client_identity_pem(&paths) {
        Ok(Some(combined)) => combined,
        Ok(None) => return None,
        Err(err) => {
            eprintln!("wist-agentd cannot read the local client identity: {err}");
            return None;
        }
    };
    match reqwest::Identity::from_pem(combined.as_bytes()) {
        Ok(identity) => Some(identity),
        Err(err) => {
            eprintln!("wist-agentd cannot load the local client identity for mTLS: {err}");
            None
        }
    }
}

fn apply_enrollment_result(
    config: &mut AgentConfig,
    state_dir: &Path,
    result: EnrollmentOutcome,
) -> Result<(), EnrollmentError> {
    if result.status != EnrollmentStatus::Accepted {
        return Err(EnrollmentReason::Rejected.to_err().with_detail(format!(
            "enrollment rejected with status {:?} reason {}",
            result.status,
            result.reason_code.as_deref().unwrap_or("unknown")
        )));
    }

    let agent_id = result
        .agent_id
        .or_else(|| {
            result
                .issued_identity
                .as_ref()
                .map(|identity| identity.agent_id.clone())
        })
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            EnrollmentReason::InvalidAcceptedResult
                .to_err()
                .with_detail("accepted enrollment response is missing agent_id")
        })?;
    let instance_id = result
        .instance_id
        .or_else(|| {
            result
                .issued_identity
                .as_ref()
                .map(|identity| identity.instance_id.clone())
        })
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| {
            EnrollmentReason::InvalidAcceptedResult
                .to_err()
                .with_detail("accepted enrollment response is missing instance_id")
        })?;

    if let Some(identity) = result.issued_identity.as_ref() {
        config.agent.environment_id = Some(identity.environment_id.clone());
    }
    let issued_credential = result.credential_bundle.clone();
    if let Some(credential) = issued_credential.as_ref() {
        apply_credential_to_config(config, credential)?;
        // 带上客户端证书就落盘（0600）：后续所有控制面请求都拿它走 mTLS（§5.2）。
        // 落到 `identity/` 而不是 state：它是**证书**不是 bearer 凭据，
        // 且本地自检（`client_certificate_status`）直接读文件（§5.4）。
        store_issued_client_certificate(state_dir, credential)?;
    }
    config.agent.agent_id = Some(agent_id.clone());
    config.agent.instance_name = Some(instance_id.clone());

    let runtime_path = state_store::agent_runtime::path_for(state_dir);
    let mut runtime_state = AgentRuntimeState::new(
        agent_id,
        instance_id,
        env!("CARGO_PKG_VERSION").to_string(),
        RuntimeMode::Normal,
        now_rfc3339(),
    );
    if let Some(credential) = issued_credential {
        apply_credential_to_runtime_state(&mut runtime_state, credential);
    }
    state_store::agent_runtime::store(&runtime_path, &runtime_state)
        .source_err(EnrollmentReason::Io, "store runtime state")?;
    Ok(())
}

/// 回包里带客户端证书就落盘（0600）；后续控制面请求都拿它走 mTLS（§5.2）。
///
/// 注意别 `trim`：证书 PEM 要原样落盘（去掉尾换行会让拼接/平台工具都变脆）。
fn store_issued_client_certificate(
    state_dir: &Path,
    credential: &wist_contracts::enrollment::CredentialBundle,
) -> Result<(), EnrollmentError> {
    if credential.certificate.trim().is_empty() {
        return Err(EnrollmentReason::InvalidAcceptedResult
            .to_err()
            .with_detail("accepted credential bundle is missing the client certificate"));
    }
    let paths = state_store::client_identity::ClientIdentityPaths::under(state_dir);
    state_store::client_identity::store_client_certificate(&paths, &credential.certificate)
        .source_err(EnrollmentReason::Io, "store client certificate")
}

/// Apply an issued credential bundle to the in-memory agent config. Both the
/// enrollment and renewal paths share this so the credential handling stays consistent.
///
/// mTLS 是唯一凭据路径：这里的凭据**只**是一张客户端证书（已由调用方落盘），
/// 所以这里不再涉及任何 bearer token。
fn apply_credential_to_config(
    config: &mut AgentConfig,
    credential: &wist_contracts::enrollment::CredentialBundle,
) -> Result<(), EnrollmentError> {
    if credential.certificate.trim().is_empty() {
        return Err(EnrollmentReason::InvalidAcceptedResult
            .to_err()
            .with_detail("accepted credential bundle is missing the client certificate"));
    }
    config.control_plane.credential_id = Some(credential.credential_id.clone());
    config.control_plane.auth_mode = Some("certificate".to_string());
    config.control_plane.enrollment_token = None;
    if let Some(expires_at) = credential.not_after.as_ref() {
        config.control_plane.credential_expires_at = Some(expires_at.clone());
    }
    Ok(())
}

fn apply_credential_to_runtime_state(
    runtime_state: &mut AgentRuntimeState,
    credential: wist_contracts::enrollment::CredentialBundle,
) {
    runtime_state.credential_id = Some(credential.credential_id);
    runtime_state.credential_expires_at = credential.not_after;
}

pub(crate) fn is_registered_agent_id(value: &str) -> bool {
    let normalized = value.trim();
    !normalized.is_empty()
        && !matches!(
            normalized,
            "local-agent" | "unregistered-agent" | "unknown" | "unknown-agent"
        )
}

fn required_option(value: Option<&str>) -> Option<&str> {
    value.map(str::trim).filter(|value| !value.is_empty())
}

fn first_non_empty<'a>(values: impl IntoIterator<Item = Option<&'a str>>) -> Option<&'a str> {
    values
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

fn hostname_from_sources(
    hostname_env: Option<&str>,
    computername_env: Option<&str>,
    hostname_file: Option<&str>,
) -> String {
    first_non_empty([hostname_env, computername_env, hostname_file])
        .unwrap_or("local-host")
        .to_string()
}

#[cfg(unix)]
fn hostname_from_file() -> Option<String> {
    fs::read_to_string("/etc/hostname")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(not(unix))]
fn hostname_from_file() -> Option<String> {
    None
}

#[cfg(unix)]
fn machine_id_from_file() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(not(unix))]
fn machine_id_from_file() -> Option<String> {
    None
}

fn scrub_enrollment_token_from_config_file(path: &Path) -> Result<(), EnrollmentError> {
    let text = match fs::read_to_string(path) {
        Ok(text) => text,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => {
            return Err(StructError::builder(EnrollmentReason::Io)
                .detail(format!("read config {}", path.display()))
                .source_std(err)
                .finish());
        }
    };
    let scrubbed: Vec<&str> = text
        .lines()
        .filter(|line| !is_enrollment_scoped_line(line))
        .collect();
    if scrubbed.len() == text.lines().count() {
        return Ok(());
    }
    write_bytes_private_atomic(path, scrubbed.join("\n").as_bytes())
        .source_err(EnrollmentReason::Io, "scrub enrollment token")?;
    Ok(())
}

/// True for lines that must be removed once enrollment completes: the bootstrap
/// `enrollment_token` itself and a stale `auth_mode = "enrollment_token"` that the
/// runtime overrides with `bearer` on every startup.
fn is_enrollment_scoped_line(line: &str) -> bool {
    let trimmed = line.trim_start();
    trimmed.starts_with("enrollment_token")
        || (trimmed.starts_with("auth_mode") && trimmed.contains("enrollment_token"))
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wist_contracts::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };
    use wist_contracts::enrollment::{
        AgentIdentity, AgentIdentityStatus, CredentialBundle, EnrollmentOutcome, EnrollmentStatus,
    };

    use super::{
        EnrollmentDecision, EnrollmentReason, build_enrollment_request, enroll_from_config,
        enroll_with_token, enroll_with_token_forced, enrollment_http_client, ensure_enrolled,
        ensure_enrolled_with_config_path, hostname_from_sources, is_registered_agent_id,
        post_enrollment, renew_credential, restore_runtime_identity,
    };

    #[test]
    fn is_registered_agent_id_rejects_placeholders_and_blanks() {
        // 占位值不算身份：这些正是 agentd 自己生成的默认值，被当成“已注册”会让
        // 安装收尾报告与注册幂等判断都读错。
        for placeholder in [
            "local-agent",
            "unregistered-agent",
            "unknown",
            "unknown-agent",
        ] {
            assert!(!is_registered_agent_id(placeholder), "{placeholder}");
            assert!(
                !is_registered_agent_id(&format!("  {placeholder}  ")),
                "{placeholder} with padding"
            );
        }
        assert!(!is_registered_agent_id(""));
        assert!(!is_registered_agent_id("   "));

        // 真身份（带不带空白都算）。
        assert!(is_registered_agent_id("agent-mbp-01"));
        assert!(is_registered_agent_id("  agent-mbp-01  "));
    }

    fn config() -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: None,
                environment_id: None,
                instance_name: Some("host-a".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: Some("http://127.0.0.1:1".to_string()),
                enrollment_token: Some("token-a".to_string()),
                credential_request: None,
                credential_id: None,
                credential_expires_at: None,
                tls_mode: None,
                trust_bundle: None,
                auth_mode: None,
            },
            PathsSection {
                root_dir: ".".to_string(),
                run_dir: "run".to_string(),
                state_dir: "state".to_string(),
                log_dir: "log".to_string(),
            },
            ExecutionSection {
                max_running_actions: 1,
                cancel_grace_ms: 5_000,
                default_stdout_limit_bytes: 1,
                default_stderr_limit_bytes: 1,
            },
        )
    }

    fn temp_dir(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-agentd-enrollment-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn build_enrollment_request_uses_configured_token_and_instance_name() {
        let config = config();
        let state_dir = temp_dir("build-request");

        let request = build_enrollment_request(&config, &state_dir, "token-a".to_string())
            .expect("build request");

        assert_eq!(request.token, "token-a");
        assert_eq!(request.host_profile.node_id, "host-a");
        assert_eq!(request.credential_request, "csr");
        // CSR 随注册一起上去：本地生成密钥、只交公钥（主体留给网关填）。
        assert!(
            request
                .certificate_signing_request
                .contains("BEGIN CERTIFICATE REQUEST"),
            "enrollment must carry a locally built CSR"
        );
        let _ = fs::remove_dir_all(state_dir);
    }

    #[test]
    fn hostname_from_sources_prefers_env_values() {
        assert_eq!(
            hostname_from_sources(Some("host-env"), Some("pc-env"), Some("file-host")),
            "host-env"
        );
        assert_eq!(
            hostname_from_sources(None, None, Some("file-host")),
            "file-host"
        );
    }

    #[test]
    fn https_enrollment_client_rejects_invalid_trust_bundle() {
        let mut config = config();
        config.control_plane.endpoint = Some("https://control.example".to_string());
        config.control_plane.trust_bundle = Some(
            "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n".to_string(),
        );

        let err = enrollment_http_client(&config).expect_err("invalid trust bundle");

        assert_eq!(err.reason(), &EnrollmentReason::InvalidTrustBundle);
    }

    #[test]
    fn http_enrollment_client_ignores_invalid_trust_bundle() {
        let mut config = config();
        config.control_plane.endpoint = Some("http://127.0.0.1:3000".to_string());
        config.control_plane.trust_bundle = Some("not a pem certificate".to_string());

        enrollment_http_client(&config).expect("http client");
    }

    #[test]
    fn tls_mode_none_disables_verification_even_for_https_endpoint() {
        let mut config = config();
        config.control_plane.endpoint = Some("https://control.example".to_string());
        config.control_plane.tls_mode = Some("none".to_string());
        config.control_plane.trust_bundle = Some("not a valid certificate".to_string());

        enrollment_http_client(&config).expect("tls_mode none client");
    }

    #[test]
    fn tls_mode_verify_still_requires_a_valid_trust_bundle() {
        let mut config = config();
        config.control_plane.endpoint = Some("https://control.example".to_string());
        config.control_plane.tls_mode = Some("verify".to_string());
        config.control_plane.trust_bundle = Some(
            "-----BEGIN CERTIFICATE-----\nnot-base64\n-----END CERTIFICATE-----\n".to_string(),
        );

        let err = enrollment_http_client(&config).expect_err("invalid trust bundle");

        assert_eq!(err.reason(), &EnrollmentReason::InvalidTrustBundle);
    }

    #[test]
    fn tls_mode_invalid_value_is_rejected() {
        let mut config = config();
        config.control_plane.tls_mode = Some("mutual".to_string());

        let err = enrollment_http_client(&config).expect_err("unsupported mode");

        assert_eq!(err.reason(), &EnrollmentReason::InvalidTlsMode);
    }

    #[tokio::test]
    async fn post_enrollment_to_unreachable_endpoint_returns_error() {
        let mut config = config();
        config.control_plane.endpoint = Some("http://127.0.0.1:1".to_string());
        let request =
            build_enrollment_request(&config, &temp_dir("post-enrollment"), "token-a".to_string())
                .expect("build request");

        let err = post_enrollment(&config, "http://127.0.0.1:1", &request)
            .await
            .expect_err("unreachable endpoint");

        assert_eq!(err.reason(), &EnrollmentReason::Http);
    }

    #[tokio::test]
    async fn renew_credential_issues_a_new_certificate_and_updates_state() {
        let state_dir = temp_dir("renew-credential");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        let mut runtime = wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-x".to_string(),
            "instance-x".to_string(),
            "0.1.0".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-07-01T00:00:00Z".to_string(),
        );
        runtime.credential_id = Some("cred-old".to_string());
        runtime.credential_expires_at = Some("2026-08-01T00:00:00Z".to_string());
        crate::state_store::agent_runtime::store(&runtime_path, &runtime).expect("store state");

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_is_complete(&request_bytes) {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request_bytes);
            assert!(request.contains("credentials:renew"));
            // 凭据走客户端证书（mTLS），续期请求不再带 Authorization 头。
            assert!(
                !request.to_lowercase().contains("authorization:"),
                "{request}"
            );
            assert!(request.contains("\"certificate_signing_request\""));
            let body = r#"{"credential_bundle":{"credential_id":"cred-new","agent_id":"agent-x","instance_id":"instance-x","certificate":"-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n","private_key_ref":null,"ca_bundle":null,"issued_at":"2026-08-01T00:00:00Z","not_before":"2026-08-01T00:00:00Z","not_after":"2026-09-01T00:00:00Z"}}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let mut config = config();
        config.agent.agent_id = Some("agent-x".to_string());
        config.control_plane.endpoint = Some(endpoint);
        config.control_plane.credential_id = Some("cred-old".to_string());
        config.control_plane.credential_expires_at = Some("2026-08-01T00:00:00Z".to_string());

        renew_credential(&mut config, &state_dir)
            .await
            .expect("renew");
        server.await.expect("server task");

        assert_eq!(
            config.control_plane.credential_id.as_deref(),
            Some("cred-new")
        );
        assert_eq!(
            config.control_plane.auth_mode.as_deref(),
            Some("certificate")
        );
        let runtime = crate::state_store::agent_runtime::load_or_default(&runtime_path)
            .expect("load runtime");
        assert_eq!(runtime.credential_id.as_deref(), Some("cred-new"));
        // 新证书已落盘：后续控制面请求都拿它走 mTLS。
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        assert!(
            paths.cert_file.exists(),
            "renewed client certificate stored"
        );
    }

    #[tokio::test]
    async fn ensure_enrolled_uses_existing_state_identity() {
        let state_dir = temp_dir("existing-state");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        crate::state_store::agent_runtime::store(
            &runtime_path,
            &wist_contracts::agent_state::AgentRuntimeState::new(
                "agent-state".to_string(),
                "instance-state".to_string(),
                "0.1.0".to_string(),
                wist_contracts::agent_state::RuntimeMode::Normal,
                "2026-07-27T00:00:00Z".to_string(),
            ),
        )
        .expect("store state");
        let mut config = config();

        let decision = ensure_enrolled(&mut config, &state_dir)
            .await
            .expect("ensure");

        assert_eq!(decision, EnrollmentDecision::ExistingStateIdentity);
        assert_eq!(config.agent.agent_id.as_deref(), Some("agent-state"));
    }

    #[tokio::test]
    async fn ensure_enrolled_restores_existing_state_credential() {
        let state_dir = temp_dir("existing-state-credential");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        let mut runtime = wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-state".to_string(),
            "instance-state".to_string(),
            "0.1.0".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-07-27T00:00:00Z".to_string(),
        );
        runtime.credential_id = Some("cred-state".to_string());
        runtime.credential_expires_at = Some("2026-08-27T00:00:00Z".to_string());
        crate::state_store::agent_runtime::store(&runtime_path, &runtime).expect("store state");
        let mut config = config();

        let decision = ensure_enrolled(&mut config, &state_dir)
            .await
            .expect("ensure");

        assert_eq!(decision, EnrollmentDecision::ExistingStateIdentity);
        assert_eq!(
            config.control_plane.credential_id.as_deref(),
            Some("cred-state")
        );
        assert_eq!(
            config.control_plane.auth_mode.as_deref(),
            Some("certificate")
        );
        assert_eq!(
            config.control_plane.credential_expires_at.as_deref(),
            Some("2026-08-27T00:00:00Z")
        );
        assert!(config.control_plane.enrollment_token.is_none());
    }

    /// 升级器场景：配置里**已经有** `agent_id`（`has_config_identity` 为真，`ensure_enrolled` 会
    /// 就此早返回、不碰凭据），`restore_runtime_identity` 仍必须从 state 注入身份。
    #[test]
    fn restore_runtime_identity_injects_identity_despite_config_agent_id() {
        let state_dir = temp_dir("restore-credential");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        let mut runtime = wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-state".to_string(),
            "instance-state".to_string(),
            "0.1.0".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-07-27T00:00:00Z".to_string(),
        );
        runtime.credential_id = Some("cred-state".to_string());
        crate::state_store::agent_runtime::store(&runtime_path, &runtime).expect("store state");

        let mut config = config();
        // 配置已带 agent_id：这正是「升级器只 load 到配置文件」会落到的形态。
        config.agent.agent_id = Some("agent-config".to_string());
        config.control_plane.credential_id = None;

        let restored = restore_runtime_identity(&mut config, &state_dir).expect("restore");

        assert!(restored);
        assert_eq!(
            config.control_plane.credential_id.as_deref(),
            Some("cred-state")
        );
        assert_eq!(
            config.control_plane.auth_mode.as_deref(),
            Some("certificate")
        );
    }

    #[tokio::test]
    async fn ensure_enrolled_requires_token_without_existing_identity() {
        let state_dir = temp_dir("missing-token");
        let mut config = config();
        config.control_plane.enrollment_token = None;

        let err = ensure_enrolled(&mut config, &state_dir)
            .await
            .expect_err("missing token");

        assert_eq!(err.reason(), &EnrollmentReason::MissingEnrollmentToken);
    }

    #[tokio::test]
    async fn ensure_enrolled_posts_request_and_persists_identity() {
        let state_dir = temp_dir("http-register");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_is_complete(&request_bytes) {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request_bytes);
            assert!(request.starts_with("POST /api/v1/agent/enroll "));
            assert!(request.contains("\"token\":\"token-a\""));
            let body = r#"{"result":{"status":"accepted","reason_code":null,"agent_id":"agent-http","instance_id":"instance-http","issued_identity":null,"credential_bundle":null,"initial_config":null,"policy_binding":null}}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let mut config = config();
        config.control_plane.endpoint = Some(endpoint);

        let decision = ensure_enrolled(&mut config, &state_dir)
            .await
            .expect("ensure");
        server.await.expect("server task");

        assert_eq!(decision, EnrollmentDecision::Enrolled);
        assert_eq!(config.agent.agent_id.as_deref(), Some("agent-http"));
        assert!(crate::state_store::agent_runtime::path_for(&state_dir).exists());
    }

    #[tokio::test]
    async fn enroll_with_token_persists_credential_without_touching_config() {
        let config_root = temp_dir("enroll-cli-token");
        let config_path = config_root.join("agentd.toml");
        // 配置里**没有** token：token 只从命令行传进来。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        fs::write(
            &config_path,
            format!(
                r#"schema_version = "v1"

[control_plane]
enabled = true
endpoint = "{endpoint}"
credential_request = "bearer"

[paths]
root_dir = "."
state_dir = "state"
"#
            ),
        )
        .expect("write config");
        let before = fs::read_to_string(&config_path).expect("read config");

        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_is_complete(&request_bytes) {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request_bytes);
            assert!(request.contains("\"token\":\"cli-token\""));
            let body = r#"{"result":{"status":"accepted","reason_code":null,"agent_id":"agent-cli","instance_id":"inst-cli","issued_identity":null,"credential_bundle":null,"initial_config":null,"policy_binding":null}}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });

        let decision = enroll_with_token(&config_root, "cli-token".to_string())
            .await
            .expect("enroll");
        server.await.expect("server task");

        assert_eq!(decision, EnrollmentDecision::Enrolled);
        // 凭据落 state（单独文件），配置文件一字未改。
        let state_path = crate::state_store::agent_runtime::path_for(&config_root.join("state"));
        assert!(state_path.exists());
        let state: wist_contracts::agent_state::AgentRuntimeState =
            wist_shared::fs::read_json(&state_path).expect("read runtime state");
        assert_eq!(state.agent_id, "agent-cli");
        assert_eq!(
            fs::read_to_string(&config_path).expect("read config"),
            before
        );

        // 幂等：已注册后再调（甚至给个别的 token）不再发请求。
        let again = enroll_with_token(&config_root, "other-token".to_string())
            .await
            .expect("enroll again");
        assert_eq!(again, EnrollmentDecision::ExistingStateIdentity);
    }

    /// 有效证书就出示；**过期就不再出示**（否则连重新注册都会被 rustls 握手挡死）。
    #[test]
    fn does_not_present_an_expired_client_certificate() {
        let state_dir = temp_dir("client-cert-presentation");
        let mut config = config();
        config.paths.state_dir = state_dir.display().to_string();
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);

        let (certificate_pem, key_pem) = self_signed_identity_pem(37);
        fs::create_dir_all(paths.key_file.parent().expect("parent")).expect("key dir");
        fs::write(&paths.key_file, &key_pem).expect("write key");
        crate::state_store::client_identity::store_client_certificate(&paths, &certificate_pem)
            .expect("store certificate");
        assert!(
            super::local_client_identity(&config).is_some(),
            "a valid certificate must be presented"
        );

        let (expired_pem, expired_key_pem) = self_signed_identity_pem(-1);
        fs::write(&paths.key_file, &expired_key_pem).expect("write key");
        crate::state_store::client_identity::store_client_certificate(&paths, &expired_pem)
            .expect("store certificate");
        assert!(
            super::local_client_identity(&config).is_none(),
            "an expired certificate must not be presented"
        );

        let _ = fs::remove_dir_all(state_dir);
    }

    /// 证书还新：什么都不做（不联网）。
    #[tokio::test]
    async fn renewal_is_not_due_while_the_certificate_is_fresh() {
        let state_dir = temp_dir("renewal-not-due");
        let mut config = config();
        config.paths.state_dir = state_dir.display().to_string();
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        let (certificate_pem, key_pem) = self_signed_identity_pem(37);
        fs::create_dir_all(paths.key_file.parent().expect("parent")).expect("key dir");
        fs::write(&paths.key_file, &key_pem).expect("write key");
        crate::state_store::client_identity::store_client_certificate(&paths, &certificate_pem)
            .expect("store certificate");

        let decision = super::renew_credential_if_due(&mut config, &state_dir).await;
        assert_eq!(decision, super::RenewalDecision::NotDue);
        let ledger = crate::state_store::client_identity::read_renewal_ledger(&paths)
            .expect("read ledger")
            .expect("ledger written");
        assert_eq!(ledger.outcome, "not_due");
        let _ = fs::remove_dir_all(state_dir);
    }

    /// 证书已过期：**不再重试**，记 `needs_reinstall`（即使端点可用也不试 —— 见 §4.2 无宽限）。
    #[tokio::test]
    async fn expired_certificate_requires_reinstall_and_is_recorded() {
        let state_dir = temp_dir("renewal-expired");
        let mut config = config();
        config.paths.state_dir = state_dir.display().to_string();
        // 指向一个必然连不上的端点：若它真去续期就会是 `Failed`，而不是 `NeedsReinstall`。
        config.control_plane.endpoint = Some("http://127.0.0.1:1".to_string());

        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        let (expired_pem, expired_key_pem) = self_signed_identity_pem(-1);
        fs::create_dir_all(paths.key_file.parent().expect("parent")).expect("key dir");
        fs::write(&paths.key_file, &expired_key_pem).expect("write key");
        crate::state_store::client_identity::store_client_certificate(&paths, &expired_pem)
            .expect("store certificate");

        let decision = super::renew_credential_if_due(&mut config, &state_dir).await;
        assert_eq!(decision, super::RenewalDecision::NeedsReinstall);
        let ledger = crate::state_store::client_identity::read_renewal_ledger(&paths)
            .expect("read ledger")
            .expect("ledger written");
        assert_eq!(ledger.outcome, "needs_reinstall");
        assert!(!ledger.not_after.is_empty());
        let _ = fs::remove_dir_all(state_dir);
    }

    /// 没有本地证书：**不重试**，记 `needs_reinstall`（mTLS 是唯一凭据路径 —— 没证书就没有身份）。
    #[tokio::test]
    async fn renewal_without_a_certificate_requires_reinstall() {
        let state_dir = temp_dir("renewal-no-cert");
        let mut config = config();
        config.paths.state_dir = state_dir.display().to_string();
        // 即便配了「凭据到期时间」，也不能拿它当退回路径：那正是旧的 bearer 双轨假设。
        config.control_plane.credential_expires_at = Some("2099-01-01T00:00:00Z".to_string());

        let decision = super::renew_credential_if_due(&mut config, &state_dir).await;
        assert_eq!(decision, super::RenewalDecision::NeedsReinstall);
        let _ = fs::remove_dir_all(state_dir);
    }

    /// 认出「必须运维介入」的稳定 code；凭据过期这类**不**当终态（避免误停）。
    #[test]
    fn classify_auth_rejection_flags_only_terminal_codes() {
        use super::{AuthRejection, auth_rejection_code, classify_auth_rejection};
        use reqwest::StatusCode;

        assert_eq!(
            classify_auth_rejection(
                StatusCode::UNAUTHORIZED,
                "agent identity rejected: certificate_revoked"
            ),
            AuthRejection::Terminal("certificate_revoked")
        );
        assert_eq!(
            classify_auth_rejection(StatusCode::FORBIDDEN, "certificate_mismatch"),
            AuthRejection::Terminal("certificate_mismatch")
        );
        // 没带证书 / 网关没开 mTLS：会在配置 / 证书到位后自愈 —— 不停。
        assert_eq!(
            classify_auth_rejection(
                StatusCode::UNAUTHORIZED,
                "agent identity rejected: certificate_required"
            ),
            AuthRejection::NotRevoked
        );
        assert_eq!(
            classify_auth_rejection(StatusCode::UNAUTHORIZED, "missing_credential"),
            AuthRejection::NotRevoked
        );
        // 服务端 5xx / 正文里出现这个词但不是 401/403：不当终态（避免误停）。
        assert_eq!(
            classify_auth_rejection(StatusCode::INTERNAL_SERVER_ERROR, "certificate_revoked"),
            AuthRejection::NotRevoked
        );
        assert_eq!(auth_rejection_code("nothing here"), None);
    }

    /// 网关回「被吊销」→ 续期判定是**终态** `Revoked`，且台账记下（不静默）。
    #[tokio::test]
    async fn a_revoked_agent_stops_renewing_and_records_it() {
        let state_dir = temp_dir("renewal-revoked");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_is_complete(&request_bytes) {
                    break;
                }
            }
            assert!(String::from_utf8_lossy(&request_bytes).contains("credentials:renew"));
            let body = "agent identity rejected: certificate_revoked";
            let response = format!(
                "HTTP/1.1 401 Unauthorized\r\ncontent-type: text/plain\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = config();
        config.paths.state_dir = state_dir.display().to_string();
        config.agent.agent_id = Some("agent-x".to_string());
        config.control_plane.endpoint = Some(endpoint);
        // 种一张落在续签窗内的客户端证书（≤ 30 天）→ 判定为「该续期」——mTLS 是唯一凭据路径。
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        let (cert_pem, key_pem) = self_signed_identity_pem(10);
        fs::create_dir_all(paths.key_file.parent().expect("parent")).expect("key dir");
        fs::write(&paths.key_file, &key_pem).expect("write key");
        crate::state_store::client_identity::store_client_certificate(&paths, &cert_pem)
            .expect("store certificate");

        let decision = super::renew_credential_if_due(&mut config, &state_dir).await;
        server.await.expect("server task");
        assert_eq!(decision, super::RenewalDecision::Revoked);

        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        let ledger = crate::state_store::client_identity::read_renewal_ledger(&paths)
            .expect("read ledger")
            .expect("ledger written");
        assert_eq!(ledger.outcome, "revoked");
        assert!(
            ledger.detail.contains("lift"),
            "detail must tell the operator to lift the revocation: {}",
            ledger.detail
        );
        let _ = fs::remove_dir_all(state_dir);
    }

    /// 自签一对证书/私钥，`not_after` = 现在 + `days`。
    fn self_signed_identity_pem(days: i64) -> (String, String) {
        let key = rcgen::KeyPair::generate().expect("client key");
        let mut params = rcgen::CertificateParams::default();
        params.not_before = time::OffsetDateTime::now_utc() - time::Duration::days(1);
        params.not_after = time::OffsetDateTime::now_utc() + time::Duration::days(days);
        let certificate = params.self_signed(&key).expect("self signed");
        (certificate.pem(), key.serialize_pem())
    }

    /// `--force` 不把「state 里已有身份」当成可以跳过的理由 —— 它真会重新注册。
    #[tokio::test]
    async fn forced_enrollment_does_not_skip_an_existing_identity() {
        let config_root = temp_dir("enroll-force-wiring");
        let config_path = config_root.join("agentd.toml");
        // 端点必然连不上：不 force 会直接跳过（不发请求），force 会去发并因此失败。
        fs::write(
            &config_path,
            r#"schema_version = "v1"

[control_plane]
enabled = true
endpoint = "http://127.0.0.1:1"

[paths]
root_dir = "."
state_dir = "state"
"#,
        )
        .expect("write config");

        let state_dir = config_root.join("state");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        let runtime = wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-old".to_string(),
            "inst-old".to_string(),
            "0.1.0".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-09-01T00:00:00Z".to_string(),
        );
        crate::state_store::agent_runtime::store(&runtime_path, &runtime).expect("store state");

        // 不 force：state 里有身份 → 直接跳过，压根不发请求。
        let skipped = enroll_with_token(&config_root, "cli-token".to_string())
            .await
            .expect("enroll");
        assert_eq!(skipped, EnrollmentDecision::ExistingStateIdentity);

        // force：先丢身份再去注册 → 端点连不上，所以是 Http 失败（而不是 ExistingStateIdentity）。
        let err = enroll_with_token_forced(&config_root, "cli-token".to_string())
            .await
            .expect_err("unreachable endpoint");
        assert_eq!(err.reason(), &EnrollmentReason::Http);
        assert!(
            !runtime_path.exists(),
            "the forced run must have discarded the local state"
        );
    }

    /// `--force` 丢掉**身份**（凭据 state + 证书 + 台账），但保留本地私钥。
    #[test]
    fn forced_enrollment_discards_identity_but_keeps_the_private_key() {
        let state_dir = temp_dir("enroll-force-discard");
        fs::create_dir_all(&state_dir).expect("state dir");
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        fs::create_dir_all(paths.key_file.parent().expect("parent")).expect("key dir");
        fs::write(&paths.key_file, "key").expect("write key");
        crate::state_store::client_identity::store_client_certificate(&paths, "cert")
            .expect("cert");
        crate::state_store::client_identity::store_renewal_ledger(
            &paths,
            &crate::state_store::client_identity::RenewalLedger {
                checked_at: "2026-09-28T00:00:00+00:00".to_string(),
                outcome: "renewed".to_string(),
                detail: String::new(),
                not_after: String::new(),
            },
        )
        .expect("ledger");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        fs::write(&runtime_path, "{}").expect("runtime state");

        super::discard_local_identity(&state_dir).expect("discard");

        assert!(!runtime_path.exists(), "credential state must be dropped");
        assert!(
            !paths.cert_file.exists(),
            "issued certificate must be dropped"
        );
        assert!(
            !paths.renewal_file.exists(),
            "renewal ledger must be dropped"
        );
        assert!(
            paths.key_file.exists(),
            "the private key is local consumable material, not identity"
        );
        let _ = fs::remove_dir_all(state_dir);
    }

    /// 带客户端证书的注册回包：证书落 `identity/`，且 `certificate` 方案被接受（不再报 unsupported）。
    #[tokio::test]
    async fn enroll_with_token_stores_the_issued_client_certificate() {
        let config_root = temp_dir("enroll-cli-cert");
        let config_path = config_root.join("agentd.toml");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        fs::write(
            &config_path,
            format!(
                r#"schema_version = "v1"

[control_plane]
enabled = true
endpoint = "{endpoint}"
credential_request = "csr"

[paths]
root_dir = "."
state_dir = "state"
"#
            ),
        )
        .expect("write config");

        let certificate_pem =
            "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n".to_string();
        let not_after = "2026-11-04T00:00:00+00:00".to_string();
        let body = serde_json::to_string(&serde_json::json!({
            "result": {
                "status": "accepted",
                "reason_code": null,
                "agent_id": "agent-cert",
                "instance_id": "inst-cert",
                "issued_identity": null,
                "credential_bundle": {
                    "credential_id": "cred-cert",
                    "agent_id": "agent-cert",
                    "instance_id": "inst-cert",
                    "certificate": certificate_pem,
                    "private_key_ref": null,
                    "ca_bundle": null,
                    "issued_at": "2026-09-28T00:00:00+00:00",
                    "not_before": "2026-09-28T00:00:00+00:00",
                    "not_after": not_after,
                },
                "initial_config": null,
                "policy_binding": null,
            }
        }))
        .expect("serialize response");
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_is_complete(&request_bytes) {
                    break;
                }
            }
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });

        let decision = enroll_with_token(&config_root, "cli-token".to_string())
            .await
            .expect("enroll");
        server.await.expect("server task");
        assert_eq!(decision, EnrollmentDecision::Enrolled);

        // 证书落到 `identity/`（不是 state 里的凭据）。
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(
            &config_root.join("state"),
        );
        assert_eq!(
            fs::read_to_string(&paths.cert_file).expect("read stored certificate"),
            certificate_pem
        );
        // `certificate` 方案：state 里只留 credential_id 与证书到期时间。
        let state_path = crate::state_store::agent_runtime::path_for(&config_root.join("state"));
        let state: wist_contracts::agent_state::AgentRuntimeState =
            wist_shared::fs::read_json(&state_path).expect("read runtime state");
        assert_eq!(state.credential_id.as_deref(), Some("cred-cert"));
        assert_eq!(
            state.credential_expires_at.as_deref(),
            Some(not_after.as_str())
        );
    }

    #[tokio::test]
    async fn enroll_with_token_requires_existing_config() {
        let config_root = temp_dir("enroll-cli-missing-config");
        let err = enroll_with_token(&config_root, "cli-token".to_string())
            .await
            .expect_err("missing config must fail");

        assert_eq!(err.reason(), &EnrollmentReason::MissingConfigFile);
    }

    #[tokio::test]
    async fn enroll_from_config_without_token_points_at_the_cli() {
        let config_root = temp_dir("enroll-no-token");
        fs::write(
            config_root.join("agentd.toml"),
            r#"schema_version = "v1"

[control_plane]
enabled = true
endpoint = "http://127.0.0.1:1"

[paths]
root_dir = "."
state_dir = "state"
"#,
        )
        .expect("write config");

        let err = enroll_from_config(&config_root)
            .await
            .expect_err("no token available");

        assert_eq!(err.reason(), &EnrollmentReason::MissingEnrollmentToken);
        assert!(
            err.to_string().contains("wist-agentd enroll --token"),
            "{err}"
        );
    }

    #[tokio::test]
    async fn ensure_enrolled_scrubs_enrollment_token_from_config_file() {
        let state_dir = temp_dir("scrub-token");
        let config_path = state_dir.join("agentd.toml");
        fs::write(
            &config_path,
            r#"schema_version = "v1"

[control_plane]
enabled = true
endpoint = "http://127.0.0.1:3000"
enrollment_token = "token-a"
credential_request = "bearer"
"#,
        )
        .expect("write config");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_is_complete(&request_bytes) {
                    break;
                }
            }
            let body = r#"{"result":{"status":"accepted","reason_code":null,"agent_id":"agent-http","instance_id":"instance-http","issued_identity":null,"credential_bundle":null,"initial_config":null,"policy_binding":null}}"#;
            let response = format!(
                "HTTP/1.1 201 Created\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
        });
        let mut config = config();
        config.control_plane.endpoint = Some(endpoint);

        let decision = ensure_enrolled_with_config_path(&mut config, &state_dir, &config_path)
            .await
            .expect("ensure");
        server.await.expect("server task");

        assert_eq!(decision, EnrollmentDecision::Enrolled);
        let text = fs::read_to_string(&config_path).expect("read config");
        assert!(!text.contains("enrollment_token"));
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;

            let mode = fs::metadata(&config_path)
                .expect("config metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600);
        }
    }

    fn request_is_complete(bytes: &[u8]) -> bool {
        let Some(header_end) = bytes.windows(4).position(|window| window == b"\r\n\r\n") else {
            return false;
        };
        let headers = String::from_utf8_lossy(&bytes[..header_end]);
        let content_length = headers
            .lines()
            .find_map(|line| line.strip_prefix("content-length: "))
            .or_else(|| {
                headers
                    .lines()
                    .find_map(|line| line.strip_prefix("Content-Length: "))
            })
            .and_then(|value| value.parse::<usize>().ok())
            .unwrap_or(0);
        bytes.len() >= header_end + 4 + content_length
    }

    #[test]
    fn accepted_result_updates_config_and_runtime_state() {
        let state_dir = temp_dir("accepted-result");
        let mut config = config();
        let result = EnrollmentOutcome {
            status: EnrollmentStatus::Accepted,
            reason_code: None,
            agent_id: None,
            instance_id: None,
            issued_identity: Some(AgentIdentity {
                agent_id: "agent-issued".to_string(),
                instance_id: "instance-issued".to_string(),
                tenant_id: "tenant-a".to_string(),
                environment_id: "env-a".to_string(),
                node_id: "node-a".to_string(),
                issued_at: "2026-07-27T00:00:00Z".to_string(),
                expires_at: None,
                status: AgentIdentityStatus::Active,
            }),
            credential_bundle: Some(CredentialBundle {
                credential_id: "cred-issued".to_string(),
                agent_id: "agent-issued".to_string(),
                instance_id: "instance-issued".to_string(),
                certificate: "-----BEGIN CERTIFICATE-----\nMIIB\n-----END CERTIFICATE-----\n"
                    .to_string(),
                private_key_ref: None,
                ca_bundle: None,
                issued_at: "2026-07-27T00:00:00Z".to_string(),
                not_before: Some("2026-07-27T00:00:00Z".to_string()),
                not_after: Some("2026-08-27T00:00:00Z".to_string()),
            }),
            initial_config: None,
            policy_binding: None,
        };

        super::apply_enrollment_result(&mut config, &state_dir, result).expect("apply");

        assert_eq!(config.agent.agent_id.as_deref(), Some("agent-issued"));
        assert_eq!(
            config.agent.instance_name.as_deref(),
            Some("instance-issued")
        );
        assert_eq!(config.agent.environment_id.as_deref(), Some("env-a"));
        assert_eq!(
            config.control_plane.credential_id.as_deref(),
            Some("cred-issued")
        );
        assert_eq!(
            config.control_plane.auth_mode.as_deref(),
            Some("certificate")
        );
        assert_eq!(
            config.control_plane.credential_expires_at.as_deref(),
            Some("2026-08-27T00:00:00Z")
        );
        assert!(config.control_plane.enrollment_token.is_none());
        // 客户端证书落到 `identity/`（后续控制面请求都拿它走 mTLS）。
        let paths = crate::state_store::client_identity::ClientIdentityPaths::under(&state_dir);
        assert!(paths.cert_file.exists(), "issued client certificate stored");
        let runtime = crate::state_store::agent_runtime::load_or_default(
            &crate::state_store::agent_runtime::path_for(&state_dir),
        )
        .expect("load runtime");
        assert_eq!(runtime.credential_id.as_deref(), Some("cred-issued"));
        assert_eq!(
            runtime.credential_expires_at.as_deref(),
            Some("2026-08-27T00:00:00Z")
        );
    }

    #[tokio::test]
    async fn ensure_enrolled_state_restore_scrubs_leftover_token_from_config() {
        let state_dir = temp_dir("state-restore-scrub");
        let runtime_path = crate::state_store::agent_runtime::path_for(&state_dir);
        let mut runtime = wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-state".to_string(),
            "instance-state".to_string(),
            "0.1.0".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-07-27T00:00:00Z".to_string(),
        );
        runtime.credential_id = Some("cred-state".to_string());
        runtime.credential_expires_at = Some("2026-08-27T00:00:00Z".to_string());
        crate::state_store::agent_runtime::store(&runtime_path, &runtime).expect("store state");

        // Simulate a crash window where state was persisted but the config scrub did not run.
        let config_path = state_dir.join("agentd.toml");
        fs::write(
            &config_path,
            r#"schema_version = "v1"

[control_plane]
enabled = true
endpoint = "http://127.0.0.1:3000"
enrollment_token = "leftover-token"
credential_request = "bearer"
"#,
        )
        .expect("write config");
        let mut config = config();

        let decision = ensure_enrolled_with_config_path(&mut config, &state_dir, &config_path)
            .await
            .expect("ensure");

        assert_eq!(decision, EnrollmentDecision::ExistingStateIdentity);
        let text = fs::read_to_string(&config_path).expect("read config");
        assert!(!text.contains("enrollment_token"));
    }

    #[tokio::test]
    async fn ensure_enrolled_config_identity_scrubs_leftover_token_from_config() {
        let state_dir = temp_dir("config-identity-scrub");
        let config_path = state_dir.join("agentd.toml");
        fs::write(
            &config_path,
            r#"schema_version = "v1"

[agent]
agent_id = "pre-provisioned-agent"

[control_plane]
enabled = false
endpoint = "http://127.0.0.1:3000"
enrollment_token = "leftover-token"
credential_request = "bearer"
auth_mode = "enrollment_token"
"#,
        )
        .expect("write config");
        let mut config = config();
        config.agent.agent_id = Some("pre-provisioned-agent".to_string());
        config.control_plane.enabled = false;

        let decision = ensure_enrolled_with_config_path(&mut config, &state_dir, &config_path)
            .await
            .expect("ensure");

        assert_eq!(decision, EnrollmentDecision::ExistingConfigIdentity);
        let text = fs::read_to_string(&config_path).expect("read config");
        assert!(!text.contains("enrollment_token"));
        assert!(!text.contains("auth_mode"));
    }

    #[test]
    fn accepted_result_without_a_certificate_is_rejected() {
        let state_dir = temp_dir("no-certificate");
        let mut config = config();
        let result = EnrollmentOutcome {
            status: EnrollmentStatus::Accepted,
            reason_code: None,
            agent_id: Some("agent-x".to_string()),
            instance_id: Some("instance-x".to_string()),
            issued_identity: None,
            credential_bundle: Some(CredentialBundle {
                credential_id: "cred-x".to_string(),
                agent_id: "agent-x".to_string(),
                instance_id: "instance-x".to_string(),
                // 空证书：mTLS 是唯一凭据路径，没有证书的「已接受」是不合法的。
                certificate: "".to_string(),
                private_key_ref: None,
                ca_bundle: None,
                issued_at: "2026-07-27T00:00:00Z".to_string(),
                not_before: None,
                not_after: Some("2026-08-27T00:00:00Z".to_string()),
            }),
            initial_config: None,
            policy_binding: None,
        };

        let err =
            super::apply_enrollment_result(&mut config, &state_dir, result).expect_err("reject");

        assert_eq!(err.reason(), &EnrollmentReason::InvalidAcceptedResult);
        assert!(config.control_plane.auth_mode.is_none());
    }
}
