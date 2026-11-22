//! 本地联调夹具：生成一对 Ed25519 密钥 + 一组**已签发 / 篡改 / 未签发 / 伪签**的 R2 计划。
//!
//! 只给 `run-plan` 的真机验证用（`cargo run --example attestation_fixture -- <dir>`）。
//! 不进发布二进制；`examples/` 不参与 `cargo build`。
//!
//! 产出的四个计划对应四条要验证的路径：
//!
//! * `plan.signed.json`   —— 验签通过，应执行；
//! * `plan.tampered.json` —— 签名不变、内容改了，应 `plan_digest_mismatch`；
//! * `plan.unsigned.json` —— 没有 attestation，应 `attestation_missing`；
//! * `plan.badsig.json`   —— 签名被改，应 `signature_invalid`。

use std::collections::BTreeMap;
use std::path::Path;

use ring::signature::{Ed25519KeyPair, KeyPair};
use wist_contracts::API_VERSION_V1;
use wist_contracts::action_plan::{
    ATTESTATION_ALGORITHM_ED25519, ActionPlan, ActionPlanApproval, ActionPlanAttestation,
    ActionPlanConstraints, ActionPlanMeta, ActionPlanProgram, ActionPlanStep, ActionPlanTarget,
    ApprovalMode, RiskLevel, plan_digest,
};

const KEY_ID: &str = "e2e-k1";

fn main() {
    let dir = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "/tmp/wist-e2e-local".to_string());
    let dir = Path::new(&dir);
    std::fs::create_dir_all(dir).expect("create output dir");

    let rng = ring::rand::SystemRandom::new();
    let pkcs8 = Ed25519KeyPair::generate_pkcs8(&rng).expect("generate key");
    let der = pkcs8.as_ref().to_vec();
    let key_pair = Ed25519KeyPair::from_pkcs8(&der).expect("parse key");
    let public = key_pair.public_key().as_ref().to_vec();

    std::fs::write(dir.join("signing.key.pem"), pkcs8_pem(&der)).expect("write private key");
    std::fs::write(dir.join("signing.pub.pem"), spki_pem(&public)).expect("write public key");

    let plan = sample_plan();
    let digest = plan_digest(&plan);
    let approval = ActionPlanApproval {
        approval_id: "apv_e2e_1".to_string(),
        approvers: vec!["admin:e2e".to_string()],
        required_approvers: 1,
        approved_at: "2026-06-01T00:00:00Z".to_string(),
    };
    let mut attestation = ActionPlanAttestation {
        api_version: API_VERSION_V1.to_string(),
        plan_digest: digest.clone(),
        approval: approval.clone(),
        risk_level: RiskLevel::R2,
        issued_by: "gateway:e2e".to_string(),
        key_id: KEY_ID.to_string(),
        algorithm: ATTESTATION_ALGORITHM_ED25519.to_string(),
        signed_at: "2026-06-01T00:00:00Z".to_string(),
        expires_at: "2031-01-01T00:00:00Z".to_string(),
        signature: String::new(),
    };
    let signature = key_pair.sign(&attestation.signing_payload());
    attestation.signature = signature
        .as_ref()
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect();

    let mut signed = plan.clone();
    signed.attestation = Some(attestation.clone());
    write_json(dir, "plan.signed.json", &signed);

    let mut tampered = signed.clone();
    // 改成**合法但不同**的参数（`rotated_logs` 在闭集内）：如果摘要检查失效，它会真的去动日志目录。
    tampered.program.steps[0].args = Some(serde_json::json!({
        "target": "rotated_logs",
        "max_files": 100,
        "max_bytes": 10_485_760
    }));
    write_json(dir, "plan.tampered.json", &tampered);

    let mut unsigned = signed.clone();
    unsigned.attestation = None;
    write_json(dir, "plan.unsigned.json", &unsigned);

    let mut badsig = signed.clone();
    if let Some(attestation) = badsig.attestation.as_mut() {
        attestation.signature = "00".repeat(64);
    }
    write_json(dir, "plan.badsig.json", &badsig);

    println!("wrote fixtures to {}", dir.display());
    println!("plan_digest = {digest}");
}

fn sample_plan() -> ActionPlan {
    ActionPlan::new(
        ActionPlanMeta {
            action_id: "act_e2e_attestation".to_string(),
            request_id: "req_e2e_attestation".to_string(),
            template_id: None,
            tenant_id: "tenant-e2e".to_string(),
            environment_id: "env-e2e".to_string(),
            plan_version: 1,
            compiled_at: "2026-06-01T00:00:00Z".to_string(),
            expires_at: "2031-01-01T00:00:00Z".to_string(),
        },
        ActionPlanTarget {
            // 与服务端 `agentd.toml` 的 `[agent] agent_id` 必须一致。
            agent_id: "e2e-agent".to_string(),
            instance_id: None,
            node_id: "e2e-node".to_string(),
            host_name: None,
            platform: "linux".to_string(),
            arch: "x86_64".to_string(),
            selectors: BTreeMap::new(),
        },
        ActionPlanConstraints {
            risk_level: RiskLevel::R2,
            approval_ref: Some("apv_e2e_1".to_string()),
            approval_mode: ApprovalMode::Required,
            requested_by: "e2e-operator".to_string(),
            reason: Some("清除临时文件（真机验签用例）".to_string()),
            max_total_duration_ms: 60_000,
            step_timeout_default_ms: 30_000,
            execution_profile: "agent_exec_v1".to_string(),
            required_capabilities: vec!["disk.cleanup.apply".to_string()],
            allow: None,
        },
        ActionPlanProgram {
            entry: "s1".to_string(),
            steps: vec![ActionPlanStep {
                id: "s1".to_string(),
                kind: "invoke".to_string(),
                op: Some("disk.cleanup.apply".to_string()),
                args: Some(serde_json::json!({
                    "target": "tmp",
                    "max_files": 100,
                    "max_bytes": 10_485_760
                })),
            }],
        },
    )
}

fn write_json(dir: &Path, name: &str, plan: &ActionPlan) {
    let json = serde_json::to_string_pretty(plan).expect("encode plan");
    std::fs::write(dir.join(name), json).expect("write plan");
}

fn pkcs8_pem(der: &[u8]) -> String {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let encoded = STANDARD.encode(der);
    let mut wrapped = String::new();
    for chunk in encoded.as_bytes().chunks(64) {
        wrapped.push_str(std::str::from_utf8(chunk).unwrap_or_default());
        wrapped.push('\n');
    }
    format!("-----BEGIN PRIVATE KEY-----\n{wrapped}-----END PRIVATE KEY-----\n")
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
