//! 下发计划的**本地终审**：网关可以发，agentd 必须自己再判一遍。
//!
//! 五项（与设计承诺 6.4 对应）：
//!
//! 1. **结构**：`wist_validate` 的契约校验；
//! 2. **过期**：`meta.expires_at` 必须晚于本机当前时刻（不是只比 `compiled_at`）；
//! 3. **目标**：`target.agent_id` / `instance_id` 与自身身份一致（防错投 / 重放）；
//! 4. **能力 + 审批**：`required_capabilities` 必须都在注册表里；
//!    `approval_mode = required` 时必须带 `approval_ref`；
//! 5. **签发证明**（attestation）：摘要对得上、签名验得过、审批事实自洽。
//!
//! 第 5 项的行为由 `[attestation] enforced` 决定：
//!
//! * `enforced = true`：R2/R3 计划**没有可信证明就拒绝**；
//! * `enforced = false`：**只记录不拦**（结果里标 `attestation_checked` 与失败原因）。
//!
//! 为什么默认关：灰度要能「先观察、再强制」，而不是「先发版、再发现全被拒」。
//! 但开关只影响**拦不拦**，不影响**验不验** —— 只要计划带了 attestation，就一定会验。
//!
//! 路径白名单（`allow.paths`）不在这里判：它由需要路径的 op 在执行时逐次校验，
//! 因为只有具体 op 才知道「这个路径是干什么用的」。

use time::OffsetDateTime;
use wist_contracts::action_plan::{
    ActionPlan, ActionPlanAttestation, ApprovalMode, RiskLevel, plan_digest,
};

use crate::config::agent_config::AgentConfig;
use crate::exec::attestation::{TrustedKeys, hex_decode, verify_ed25519};
use crate::exec::opcode::{self, codes};

/// 拒绝原因：稳定错误码 + 人读细节。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Rejection {
    pub code: &'static str,
    pub detail: String,
}

impl Rejection {
    fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// 终审通过后的附带信息（只用于**记录**，不参与放行判定）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ReviewOutcome {
    pub attestation: AttestationReport,
}

/// 签发证明的校验结果。
///
/// 三个布尔各自独立，因为运维要能回答三个不同的问题：
/// 「验了吗」（`checked`）、「过了吗」（`verified`）、「不过会拦吗」（`enforced`）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AttestationReport {
    /// 计划带了 attestation 且**真的验过**（`false` = 没带，或带了但没验 —— 后者不存在）。
    pub checked: bool,
    /// 验过了且通过。
    pub verified: bool,
    /// 验不过的原因；`None` = 通过或没验。
    pub failure: Option<Rejection>,
    /// `true` = 这次失败**导致拒绝**（`enforced = true` 且该风险等级需要证明）。
    pub enforced: bool,
    /// 计划声明需要证明（R2/R3）。
    ///
    /// 名字带 `attestation_` 前缀：光叫 `required` 会和 `required_approvers` /
    /// `required_capabilities` 混成一句。
    pub attestation_required: bool,
    /// 从 attestation 里读到的审批单号（审计用）。
    pub approval_id: Option<String>,
    /// 签名覆盖的审批人数。
    pub approvers: usize,
}

impl AttestationReport {
    fn not_required(enforced: bool, required: bool) -> Self {
        Self {
            checked: false,
            verified: false,
            failure: None,
            enforced,
            attestation_required: required,
            approval_id: None,
            approvers: 0,
        }
    }

    /// 一行可读摘要（日志 / 命令结果 `detail` 用）。`None` = 没什么要说的。
    pub fn summary(&self) -> Option<String> {
        if let Some(failure) = &self.failure {
            let mode = if self.enforced {
                "已拒绝"
            } else {
                "仅记录（attestation_enforced=false）"
            };
            return Some(format!(
                "attestation 校验失败（{}，{mode}）：{}",
                failure.code, failure.detail
            ));
        }
        if self.checked {
            return Some(format!(
                "attestation 已验签（审批单 {}，{} 人）",
                self.approval_id.as_deref().unwrap_or("?"),
                self.approvers
            ));
        }
        if self.attestation_required {
            return Some(
                "计划需要签发证明但未携带（attestation_enforced=false，仅记录）".to_string(),
            );
        }
        None
    }
}

/// 风险等级要求的最少审批人数（**硬编码下限**，不允许被计划声明调低）。
///
/// 这里与契约里的 `required_approvers` 是两层：本函数是「执行侧不接受更松的」，`required_approvers`
/// 是「签发方声明的」（可以更严）。两者都要满足。
pub fn policy_min_approvers(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::R0 | RiskLevel::R1 => 0,
        RiskLevel::R2 => 1,
        RiskLevel::R3 => 2,
    }
}

/// 这个风险等级是否**必须**带签发证明。
fn requires_attestation(risk: RiskLevel) -> bool {
    policy_min_approvers(risk) > 0
}

pub fn review(
    plan: &ActionPlan,
    config: &AgentConfig,
    now_ms: i64,
) -> Result<ReviewOutcome, Rejection> {
    wist_validate::action_plan::validate_action_plan(plan)
        .map_err(|err| Rejection::new(err.code, "计划结构不合法（见 error_code）"))?;

    let now = OffsetDateTime::from_unix_timestamp(now_ms / 1_000)
        .map_err(|_| Rejection::new(codes::INVALID_NOW, "本机时钟不可用"))?;
    let expires = wist_validate::parse_rfc3339(&plan.meta.expires_at, "invalid_expires_at")
        .map_err(|err| Rejection::new(err.code, "expires_at 不是合法时间戳"))?;
    if now >= expires {
        return Err(Rejection::new(
            codes::PLAN_EXPIRED,
            format!("计划已于 {} 过期", plan.meta.expires_at),
        ));
    }

    if let Some(agent_id) = config.agent.agent_id.as_deref()
        && !agent_id.trim().is_empty()
        && plan.target.agent_id != agent_id
    {
        return Err(Rejection::new(
            codes::TARGET_MISMATCH,
            format!("计划投给 {}，本机是 {agent_id}", plan.target.agent_id),
        ));
    }
    if let (Some(expected), Some(actual)) = (
        plan.target.instance_id.as_deref(),
        config.agent.instance_name.as_deref(),
    ) && !actual.trim().is_empty()
        && expected != actual
    {
        return Err(Rejection::new(
            codes::TARGET_MISMATCH,
            format!("计划绑定实例 {expected}，本机实例是 {actual}"),
        ));
    }

    for capability in &plan.constraints.required_capabilities {
        if opcode::lookup(capability).is_none() {
            return Err(Rejection::new(
                codes::CAPABILITY_MISSING,
                format!("本机没有 op `{capability}`"),
            ));
        }
    }

    if plan.constraints.approval_mode == ApprovalMode::Required
        && plan
            .constraints
            .approval_ref
            .as_deref()
            .unwrap_or("")
            .trim()
            .is_empty()
    {
        return Err(Rejection::new(
            codes::APPROVAL_MISSING,
            "计划要求审批但没带 approval_ref".to_string(),
        ));
    }

    let attestation = review_attestation(plan, config, now)?;
    Ok(ReviewOutcome { attestation })
}

/// 第 5 项：签发证明。返回**记录**；是否拒绝由调用方按 `enforced` 决定。
fn review_attestation(
    plan: &ActionPlan,
    config: &AgentConfig,
    now: OffsetDateTime,
) -> Result<AttestationReport, Rejection> {
    let enforced = config.attestation.enforced;
    let needs_attestation = requires_attestation(plan.constraints.risk_level);

    let Some(attestation) = plan.attestation.as_ref() else {
        if enforced && needs_attestation {
            return Err(Rejection::new(
                codes::ATTESTATION_MISSING,
                format!(
                    "风险等级 {:?} 的计划必须带签发证明（attestation）",
                    plan.constraints.risk_level
                ),
            ));
        }
        return Ok(AttestationReport::not_required(enforced, needs_attestation));
    };

    let approval_id = Some(attestation.approval.approval_id.clone());
    let approvers = attestation.approval.approvers.len();
    let failure = check_attestation(plan, attestation, config, now).err();

    // 只有「该拦的风险等级 + 强制开关」才真的拒绝；其余只记录。
    if let Some(failure) = &failure
        && enforced
        && needs_attestation
    {
        return Err(failure.clone());
    }

    Ok(AttestationReport {
        checked: true,
        verified: failure.is_none(),
        failure,
        enforced: enforced && needs_attestation,
        attestation_required: needs_attestation,
        approval_id,
        approvers,
    })
}

fn check_attestation(
    plan: &ActionPlan,
    attestation: &ActionPlanAttestation,
    config: &AgentConfig,
    now: OffsetDateTime,
) -> Result<(), Rejection> {
    // 形状（算法 / 签名长度 / 审批人非空且不重复 / 窗口顺序 / 引用一致）已经由
    // `wist_validate` 查过。这里**不再重复**，只做它做不了的三件事：
    // 「签的是不是这一份」、「本机信不信这把钥匙」、「政策下限」。

    // 1. 摘要：先确认「签的是这一份」。签名覆盖不到计划内容时，验签通过也毫无意义。
    let expected_digest = plan_digest(plan);
    if attestation.plan_digest != expected_digest {
        return Err(Rejection::new(
            codes::PLAN_DIGEST_MISMATCH,
            format!(
                "计划内容已被改动：签发时是 {}，本机算出 {expected_digest}",
                attestation.plan_digest
            ),
        ));
    }

    // 2. 信任锚 + 验签。
    let keys = TrustedKeys::from_section(&config.attestation)
        .map_err(|failure| Rejection::new(failure.code, failure.detail))?;
    let Some(public_key) = keys.get(&attestation.key_id) else {
        return Err(Rejection::new(
            codes::UNKNOWN_SIGNING_KEY,
            format!(
                "本机不信任 key_id `{}`（可信：{}）",
                attestation.key_id,
                if keys.is_empty() {
                    "无".to_string()
                } else {
                    keys.key_ids().into_iter().collect::<Vec<_>>().join(", ")
                }
            ),
        ));
    };
    let Some(signature) = hex_decode(attestation.signature.trim()) else {
        return Err(Rejection::new(
            codes::SIGNATURE_INVALID,
            "签名不是合法的 hex 字符串".to_string(),
        ));
    };
    if !verify_ed25519(public_key, &attestation.signing_payload(), &signature) {
        return Err(Rejection::new(
            codes::SIGNATURE_INVALID,
            format!("key_id `{}` 验签失败", attestation.key_id),
        ));
    }

    // 带了签发证明却没在计划里引用审批单：说明这份证明不是给这份计划签的。
    // （`approval_ref` 与 `approval_id` **不相等**的情形已由 validate 报 `approval_ref_mismatch`。）
    if plan
        .constraints
        .approval_ref
        .as_deref()
        .unwrap_or("")
        .trim()
        .is_empty()
    {
        return Err(Rejection::new(
            codes::APPROVAL_MISMATCH,
            "计划带有签发证明，但 constraints.approval_ref 为空".to_string(),
        ));
    }

    // 3. 「批了 R1、跑 R2」：签名里记的风险等级不能低于计划声明的。
    if opcode::risk_rank(attestation.risk_level) < opcode::risk_rank(plan.constraints.risk_level) {
        return Err(Rejection::new(
            codes::APPROVAL_RISK_MISMATCH,
            format!(
                "审批时风险是 {:?}，计划声明 {:?}",
                attestation.risk_level, plan.constraints.risk_level
            ),
        ));
    }

    // 4. 政策下限：签发方可以更严，但不能更松。
    //    validate 已经查了「声明的 required_approvers 与实际人数」；这里查的是
    //    「声明的 required_approvers 与本机硬编码下限」。
    let policy_min = policy_min_approvers(attestation.risk_level);
    if attestation.approval.required_approvers < policy_min {
        return Err(Rejection::new(
            codes::APPROVAL_INSUFFICIENT,
            format!(
                "本机政策要求 {:?} 至少 {policy_min} 人，签发证明只声明了 {} 人",
                attestation.risk_level, attestation.approval.required_approvers
            ),
        ));
    }

    // 5. 证明本身没过期。validate 保证它不晚于计划过期，而计划过期已在前面查过；
    //    但证明可以**比计划更短命**（例如审批单只批 1 小时），所以仍要看它自己。
    let attestation_expires =
        wist_validate::parse_rfc3339(&attestation.expires_at, "invalid_attestation_expires_at")
            .map_err(|err| Rejection::new(err.code, "attestation.expires_at 不是合法时间戳"))?;
    if now >= attestation_expires {
        return Err(Rejection::new(
            codes::ATTESTATION_EXPIRED,
            format!("签发证明已于 {attestation_expires} 过期"),
        ));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;
    use wist_contracts::API_VERSION_V1;
    use wist_contracts::action_plan::{
        ATTESTATION_ALGORITHM_ED25519, ActionPlanApproval, ActionPlanConstraints, ActionPlanMeta,
        ActionPlanProgram, ActionPlanStep, ActionPlanTarget,
    };

    fn plan(expires_at: &str) -> ActionPlan {
        ActionPlan::new(
            ActionPlanMeta {
                action_id: "act-1".to_string(),
                request_id: "req-1".to_string(),
                template_id: None,
                tenant_id: "tenant".to_string(),
                environment_id: "dev".to_string(),
                plan_version: 1,
                compiled_at: "2026-01-01T00:00:00Z".to_string(),
                expires_at: expires_at.to_string(),
            },
            ActionPlanTarget {
                agent_id: "agent-1".to_string(),
                instance_id: None,
                node_id: "node-1".to_string(),
                host_name: None,
                platform: "linux".to_string(),
                arch: "x86_64".to_string(),
                selectors: BTreeMap::new(),
            },
            ActionPlanConstraints {
                risk_level: RiskLevel::R0,
                approval_ref: None,
                approval_mode: ApprovalMode::NotRequired,
                requested_by: "tester".to_string(),
                reason: None,
                max_total_duration_ms: 30_000,
                step_timeout_default_ms: 10_000,
                execution_profile: "agent_exec_v1".to_string(),
                required_capabilities: vec!["disk.cleanup.preview".to_string()],
                allow: None,
            },
            ActionPlanProgram {
                entry: "s1".to_string(),
                steps: vec![ActionPlanStep {
                    id: "s1".to_string(),
                    kind: "invoke".to_string(),
                    op: Some("disk.cleanup.preview".to_string()),
                    args: Some(serde_json::json!({"target": "tmp"})),
                }],
            },
        )
    }

    fn config() -> AgentConfig {
        let mut config = AgentConfig::new(
            crate::config::agent_config::AgentSection::default(),
            Default::default(),
            Default::default(),
            Default::default(),
        );
        config.agent.agent_id = Some("agent-1".to_string());
        config.agent.instance_name = Some("instance-1".to_string());
        config
    }

    // 2026-06-01T00:00:00Z
    const NOW_MS: i64 = 1_780_272_000_000;

    #[test]
    fn a_well_formed_plan_passes() {
        let outcome = review(&plan("2030-01-01T00:00:00Z"), &config(), NOW_MS).expect("valid");
        assert!(!outcome.attestation.checked);
    }

    #[test]
    fn an_expired_plan_is_rejected_even_if_the_window_is_ordered() {
        let err = review(&plan("2026-02-01T00:00:00Z"), &config(), NOW_MS).expect_err("expired");
        assert_eq!(err.code, codes::PLAN_EXPIRED);
    }

    #[test]
    fn a_plan_for_another_agent_is_rejected() {
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.target.agent_id = "agent-2".to_string();
        let err = review(&plan, &config(), NOW_MS).expect_err("wrong agent");
        assert_eq!(err.code, codes::TARGET_MISMATCH);
    }

    #[test]
    fn unknown_capabilities_are_rejected_before_queueing() {
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.required_capabilities = vec!["nope.nope".to_string()];
        let err = review(&plan, &config(), NOW_MS).expect_err("unknown capability");
        assert_eq!(err.code, codes::CAPABILITY_MISSING);
    }

    #[test]
    fn required_approval_must_carry_a_ref() {
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.approval_mode = ApprovalMode::Required;
        let err = review(&plan, &config(), NOW_MS).expect_err("missing approval");
        assert_eq!(err.code, codes::APPROVAL_MISSING);

        plan.constraints.approval_ref = Some("apv-1".to_string());
        review(&plan, &config(), NOW_MS).expect("approval ref present");
    }

    // ── attestation ──

    /// 生成一对密钥 + 一块临时公钥文件，返回（key_id, 公钥文件路径, 签名闭包）。
    struct Signer {
        key_id: String,
        public_key_file: std::path::PathBuf,
        dir: std::path::PathBuf,
        key_pair: ring::signature::Ed25519KeyPair,
    }

    impl Signer {
        fn new(tag: &str) -> Self {
            use ring::signature::{Ed25519KeyPair, KeyPair};
            let rng = ring::rand::SystemRandom::new();
            let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate");
            let key_pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref()).expect("parse");
            let public = key_pair.public_key().as_ref().to_vec();

            let dir = std::env::temp_dir().join(format!(
                "wist-plan-review-{}-{tag}-{}",
                std::process::id(),
                std::time::SystemTime::now()
                    .duration_since(std::time::UNIX_EPOCH)
                    .map(|d| d.as_nanos())
                    .unwrap_or(0)
            ));
            std::fs::create_dir_all(&dir).expect("mkdir");
            let public_key_file = dir.join("k1.pub");
            std::fs::write(&public_key_file, spki_pem(&public)).expect("write pem");

            Self {
                key_id: "test-k1".to_string(),
                public_key_file,
                dir,
                key_pair,
            }
        }

        fn sign(&self, payload: &[u8]) -> String {
            self.key_pair
                .sign(payload)
                .as_ref()
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect()
        }
    }

    impl Drop for Signer {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.dir);
        }
    }

    fn spki_pem(public: &[u8]) -> String {
        use base64::{Engine as _, engine::general_purpose::STANDARD};
        const PREFIX: [u8; 12] = [
            0x30, 0x2A, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x03, 0x21, 0x00,
        ];
        let mut der = PREFIX.to_vec();
        der.extend_from_slice(public);
        let encoded = STANDARD.encode(&der);
        let mut wrapped = String::new();
        for chunk in encoded.as_bytes().chunks(64) {
            wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
            wrapped.push('\n');
        }
        format!("-----BEGIN PUBLIC KEY-----\n{wrapped}-----END PUBLIC KEY-----\n")
    }

    fn enforced_config(signer: &Signer) -> AgentConfig {
        let mut config = config();
        config.attestation.enforced = true;
        config.attestation.trusted_keys =
            vec![crate::config::agent_config::AttestationKeySection {
                key_id: signer.key_id.clone(),
                public_key_pem_file: signer.public_key_file.display().to_string(),
            }];
        config
    }

    fn attested_plan(signer: &Signer, risk: RiskLevel, approvers: &[&str]) -> ActionPlan {
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.risk_level = risk;
        plan.constraints.approval_mode = ApprovalMode::Required;
        plan.constraints.approval_ref = Some("apv-1".to_string());
        let required = if risk == RiskLevel::R3 { 2 } else { 1 };
        let mut attestation = ActionPlanAttestation {
            api_version: API_VERSION_V1.to_string(),
            plan_digest: plan_digest(&plan),
            approval: ActionPlanApproval {
                approval_id: "apv-1".to_string(),
                approvers: approvers.iter().map(|value| value.to_string()).collect(),
                required_approvers: required,
                approved_at: "2026-05-31T00:00:00Z".to_string(),
            },
            risk_level: risk,
            issued_by: "gateway:test".to_string(),
            key_id: signer.key_id.clone(),
            algorithm: ATTESTATION_ALGORITHM_ED25519.to_string(),
            signed_at: "2026-05-31T00:00:00Z".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            signature: String::new(),
        };
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);
        plan
    }

    #[test]
    fn enforced_mode_rejects_r2_without_attestation() {
        let signer = Signer::new("missing");
        let config = enforced_config(&signer);
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.risk_level = RiskLevel::R2;
        let err = review(&plan, &config, NOW_MS).expect_err("must reject");
        assert_eq!(err.code, codes::ATTESTATION_MISSING);
    }

    #[test]
    fn observed_mode_allows_r2_without_attestation_but_records_it() {
        let signer = Signer::new("observed");
        let mut config = enforced_config(&signer);
        config.attestation.enforced = false;
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.risk_level = RiskLevel::R2;
        let outcome = review(&plan, &config, NOW_MS).expect("observed only");
        assert!(!outcome.attestation.checked);
        assert!(outcome.attestation.attestation_required);
        assert!(!outcome.attestation.enforced);
    }

    #[test]
    fn an_attestation_stricter_than_the_plan_is_accepted() {
        let signer = Signer::new("stricter");
        let config = enforced_config(&signer);
        // 先按 R3（2 人）签，再把计划声明改成 R2 —— 签发方比计划更严，不降低保护。
        let mut plan = attested_plan(&signer, RiskLevel::R3, &["user:alice", "user:bob"]);
        plan.constraints.risk_level = RiskLevel::R2;
        // 改风险等级会变摘要，所以重算摘要并重签。
        let mut attestation = plan.attestation.clone().expect("attestation");
        attestation.plan_digest = plan_digest(&plan);
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);

        review(&plan, &config, NOW_MS).expect("stricter attestation is fine");
    }

    /// 边界：`expires_at == now` 就是过期（与计划过期同一口径，`>=`）。
    #[test]
    fn an_attestation_expiring_exactly_now_is_rejected() {
        let signer = Signer::new("edge-expiry");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        let mut attestation = plan.attestation.clone().expect("attestation");
        attestation.signed_at = "2026-05-31T00:00:00Z".to_string();
        attestation.expires_at = "2026-06-01T00:00:00Z".to_string(); // == NOW_MS
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);

        let err = review(&plan, &config, NOW_MS).expect_err("boundary is expired");
        assert_eq!(err.code, codes::ATTESTATION_EXPIRED);
    }

    #[test]
    fn a_correctly_signed_r2_plan_passes() {
        let signer = Signer::new("ok");
        let config = enforced_config(&signer);
        let plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        let outcome = review(&plan, &config, NOW_MS).expect("signed plan passes");
        assert!(outcome.attestation.checked);
        assert!(outcome.attestation.verified);
        assert_eq!(outcome.attestation.approvers, 1);
        assert_eq!(outcome.attestation.approval_id.as_deref(), Some("apv-1"));
    }

    #[test]
    fn tampering_with_the_plan_breaks_the_digest() {
        let signer = Signer::new("tamper");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        // 改参数但保留签名：摘要对不上。
        plan.program.steps[0].args = Some(serde_json::json!({"target": "var_log"}));
        let err = review(&plan, &config, NOW_MS).expect_err("must reject");
        assert_eq!(err.code, codes::PLAN_DIGEST_MISMATCH);
    }

    #[test]
    fn a_forged_signature_is_rejected() {
        let signer = Signer::new("forge");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        if let Some(attestation) = plan.attestation.as_mut() {
            attestation.signature = "00".repeat(64);
        }
        let err = review(&plan, &config, NOW_MS).expect_err("must reject");
        assert_eq!(err.code, codes::SIGNATURE_INVALID);
    }

    #[test]
    fn an_unknown_signing_key_is_rejected() {
        let signer = Signer::new("unknown");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        if let Some(attestation) = plan.attestation.as_mut() {
            attestation.key_id = "some-other-key".to_string();
        }
        let err = review(&plan, &config, NOW_MS).expect_err("must reject");
        assert_eq!(err.code, codes::UNKNOWN_SIGNING_KEY);
    }

    #[test]
    fn approval_understated_risk_is_rejected() {
        let signer = Signer::new("understated");
        let config = enforced_config(&signer);
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.risk_level = RiskLevel::R3;
        plan.constraints.approval_mode = ApprovalMode::Required;
        plan.constraints.approval_ref = Some("apv-1".to_string());
        // 签名里记的是 R1，计划声称 R3：典型的“批了小事、跑大事”。
        let mut attestation = ActionPlanAttestation {
            api_version: API_VERSION_V1.to_string(),
            plan_digest: plan_digest(&plan),
            approval: ActionPlanApproval {
                approval_id: "apv-1".to_string(),
                approvers: vec!["user:alice".to_string()],
                required_approvers: 1,
                approved_at: "2026-05-31T00:00:00Z".to_string(),
            },
            risk_level: RiskLevel::R1,
            issued_by: "gateway:test".to_string(),
            key_id: signer.key_id.clone(),
            algorithm: ATTESTATION_ALGORITHM_ED25519.to_string(),
            signed_at: "2026-05-31T00:00:00Z".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            signature: String::new(),
        };
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);
        let err = review(&plan, &config, NOW_MS).expect_err("must reject");
        assert_eq!(err.code, codes::APPROVAL_RISK_MISMATCH);
    }

    #[test]
    fn r3_policy_minimum_cannot_be_understated_by_the_issuer() {
        let signer = Signer::new("r3-policy");
        let config = enforced_config(&signer);
        let mut plan = plan("2030-01-01T00:00:00Z");
        plan.constraints.risk_level = RiskLevel::R3;
        plan.constraints.approval_mode = ApprovalMode::Required;
        plan.constraints.approval_ref = Some("apv-1".to_string());
        // 形状合法（2 个审批人 ≥ 声明的 1 人），但本机政策要求 R3 至少 2 人声明。
        let mut attestation = ActionPlanAttestation {
            api_version: API_VERSION_V1.to_string(),
            plan_digest: plan_digest(&plan),
            approval: ActionPlanApproval {
                approval_id: "apv-1".to_string(),
                approvers: vec!["user:alice".to_string(), "user:bob".to_string()],
                required_approvers: 1,
                approved_at: "2026-05-31T00:00:00Z".to_string(),
            },
            risk_level: RiskLevel::R3,
            issued_by: "gateway:test".to_string(),
            key_id: signer.key_id.clone(),
            algorithm: ATTESTATION_ALGORITHM_ED25519.to_string(),
            signed_at: "2026-05-31T00:00:00Z".to_string(),
            expires_at: "2030-01-01T00:00:00Z".to_string(),
            signature: String::new(),
        };
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);
        let err = review(&plan, &config, NOW_MS).expect_err("policy minimum is 2");
        assert_eq!(err.code, codes::APPROVAL_INSUFFICIENT);
    }

    #[test]
    fn r3_with_two_approvers_passes() {
        let signer = Signer::new("r3-ok");
        let config = enforced_config(&signer);
        let plan = attested_plan(&signer, RiskLevel::R3, &["user:alice", "user:bob"]);
        let outcome = review(&plan, &config, NOW_MS).expect("two distinct approvers pass");
        assert!(outcome.attestation.verified);
        assert_eq!(outcome.attestation.approvers, 2);
    }

    #[test]
    fn a_mismatched_approval_ref_is_rejected() {
        let signer = Signer::new("ref");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        // `approval_id` 在签名范围内，改它必须重签；摘要不受影响（attestation 被排除）。
        let mut attestation = plan.attestation.clone().expect("attestation");
        attestation.approval.approval_id = "apv-2".to_string();
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);
        // 形状校验（validate）先命中：计划引用 apv-1，证明里是 apv-2。
        let err = review(&plan, &config, NOW_MS).expect_err("mismatch");
        assert_eq!(err.code, "approval_ref_mismatch");
    }

    #[test]
    fn an_attestation_without_an_approval_ref_is_rejected() {
        let signer = Signer::new("no-ref");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        // 计划不再引用审批单：摘要变了，所以重算摘要并重签（模拟“签发方给了一份没被引用的证明”）。
        plan.constraints.approval_ref = None;
        plan.constraints.approval_mode = ApprovalMode::NotRequired;
        let mut attestation = plan.attestation.clone().expect("attestation");
        attestation.plan_digest = plan_digest(&plan);
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);
        let err = review(&plan, &config, NOW_MS).expect_err("orphan attestation");
        assert_eq!(err.code, codes::APPROVAL_MISMATCH);
    }

    #[test]
    fn an_expired_attestation_is_rejected() {
        let signer = Signer::new("expired");
        let config = enforced_config(&signer);
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        // 形状合法（signed_at < expires_at <= plan.expires_at），只是已经过了 expires_at。
        let mut attestation = plan.attestation.clone().expect("attestation");
        attestation.signed_at = "2026-01-01T00:00:00Z".to_string();
        attestation.expires_at = "2026-03-01T00:00:00Z".to_string();
        attestation.signature = signer.sign(&attestation.signing_payload());
        plan.attestation = Some(attestation);
        let err = review(&plan, &config, NOW_MS).expect_err("expired");
        assert_eq!(err.code, codes::ATTESTATION_EXPIRED);
    }

    #[test]
    fn observed_mode_records_but_does_not_block_a_bad_signature() {
        let signer = Signer::new("observed-bad");
        let mut config = enforced_config(&signer);
        config.attestation.enforced = false;
        let mut plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        if let Some(attestation) = plan.attestation.as_mut() {
            attestation.signature = "00".repeat(64);
        }
        let outcome = review(&plan, &config, NOW_MS).expect("observed only, not blocked");
        assert!(outcome.attestation.checked);
        assert!(!outcome.attestation.verified);
        assert!(!outcome.attestation.enforced);
        let failure = outcome.attestation.failure.expect("failure recorded");
        assert_eq!(failure.code, codes::SIGNATURE_INVALID);
    }

    #[test]
    fn an_empty_trust_store_cannot_verify_anything() {
        let signer = Signer::new("empty-store");
        let mut config = config();
        config.attestation.enforced = true;
        let plan = attested_plan(&signer, RiskLevel::R2, &["user:alice"]);
        let err = review(&plan, &config, NOW_MS).expect_err("must reject");
        assert_eq!(err.code, codes::UNKNOWN_SIGNING_KEY);
    }
}
