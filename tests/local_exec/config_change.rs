//! E3 端到端：`config.backup` → `config.apply` → `config.rollback` 的真实执行。
//!
//! 这几条用例走**真实 `wist-exec` 二进制**（`local_exec` 会自动把
//! `<state>/action_backups` 作为 `--backup-dir` 传下去），所以验的是整条链：
//! 计划 → 调度 → 执行器 → 备份目录 → 文件内容 → 结果。

use std::os::unix::fs::PermissionsExt;

use sha2::{Digest, Sha256};
use wist_agentd::bootstrap;
use wist_agentd::scheduler::{
    DrainOutcome, DrainRequest, SchedulerRequest, drain_next_with_report, submit_local_plan,
};
use wist_contracts::action_plan::{
    ActionPlan, ActionPlanAllow, ActionPlanConstraints, ActionPlanMeta, ActionPlanProgram,
    ActionPlanStep, ActionPlanTarget, ApprovalMode, RiskLevel,
};
use wist_contracts::action_result::FinalStatus;

use super::common::{temp_dir, test_exec_bin};

const ORIGINAL: &str = "[server]\nport = 8080\n";
const REPLACEMENT: &str = "[server]\nport = 9090\n";

fn plan_with(name: &str, steps: Vec<ActionPlanStep>, allow: Vec<String>) -> ActionPlan {
    ActionPlan::new(
        ActionPlanMeta {
            action_id: format!("act_{name}"),
            request_id: format!("req_{name}"),
            template_id: None,
            tenant_id: "tenant_a".to_string(),
            environment_id: "dev".to_string(),
            plan_version: 1,
            compiled_at: "2026-01-01T00:00:00Z".to_string(),
            expires_at: "2036-01-01T00:00:00Z".to_string(),
        },
        ActionPlanTarget {
            agent_id: "agent-001".to_string(),
            instance_id: Some("instance-001".to_string()),
            node_id: "node-001".to_string(),
            host_name: None,
            platform: "linux".to_string(),
            arch: "x86_64".to_string(),
            selectors: Default::default(),
        },
        ActionPlanConstraints {
            // 变更是 R2：计划本身必须按 R2 声明，否则 `risk_understated` 会先拦住。
            risk_level: RiskLevel::R2,
            approval_ref: None,
            approval_mode: ApprovalMode::NotRequired,
            requested_by: "tester@example.com".to_string(),
            reason: Some("E3 config change test".to_string()),
            max_total_duration_ms: 60_000,
            step_timeout_default_ms: 15_000,
            execution_profile: "agent_exec_v1".to_string(),
            required_capabilities: Vec::new(),
            allow: Some(ActionPlanAllow { paths: allow }),
        },
        ActionPlanProgram {
            entry: steps
                .first()
                .map(|step| step.id.clone())
                .unwrap_or_default(),
            steps,
        },
    )
}

fn invoke(id: &str, op: &str, args: serde_json::Value) -> ActionPlanStep {
    ActionPlanStep {
        id: id.to_string(),
        kind: "invoke".to_string(),
        op: Some(op.to_string()),
        args: Some(args),
    }
}

fn sha256_hex(body: &str) -> String {
    Sha256::digest(body.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn run_plan(root: &std::path::Path, plan: ActionPlan) -> DrainOutcome {
    let root = root.to_path_buf();
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");

    submit_local_plan(&SchedulerRequest {
        run_dir: run_dir.clone(),
        state_dir: state_dir.clone(),
        plan,
    })
    .expect("submit plan");

    drain_next_with_report(&DrainRequest {
        run_dir,
        state_dir,
        exec_bin: test_exec_bin(&root),
        instance_id: "instance-001".to_string(),
        cancel_grace_ms: 5_000,
        stdout_limit_bytes: 1_048_576,
        stderr_limit_bytes: 1_048_576,
    })
    .expect("drain queue")
    .expect("drain outcome")
}

#[cfg(unix)]
#[test]
fn backup_apply_rollback_runs_as_one_chain() {
    let root = temp_dir("config-chain");
    let etc = root.join("etc");
    std::fs::create_dir_all(&etc).expect("etc dir");
    let target = etc.join("app.toml");
    let source = etc.join("app.toml.new");
    std::fs::write(&target, ORIGINAL).expect("write target");
    std::fs::set_permissions(&target, std::fs::Permissions::from_mode(0o640)).expect("mode");
    std::fs::write(&source, REPLACEMENT).expect("write source");

    let allow = vec![root.display().to_string()];
    let plan = plan_with(
        "config-chain",
        vec![
            invoke(
                "s1",
                "config.backup",
                serde_json::json!({ "path": target.display().to_string() }),
            ),
            invoke(
                "s2",
                "config.apply",
                serde_json::json!({
                    "path": target.display().to_string(),
                    "source": source.display().to_string(),
                    "source_sha256": sha256_hex(REPLACEMENT),
                    "format": "toml",
                }),
            ),
            invoke(
                "s3",
                "config.rollback",
                serde_json::json!({
                    "path": target.display().to_string(),
                    "expect_sha256": sha256_hex(REPLACEMENT),
                }),
            ),
        ],
        allow,
    );

    let outcome = run_plan(&root, plan);
    assert_eq!(
        outcome.report.result.final_status,
        FinalStatus::Succeeded,
        "{:?}",
        outcome.report.result.exit_reason
    );
    let items = &outcome.report.result.outputs.items;
    assert_eq!(items.len(), 3);

    assert_eq!(items[0].value["schema"], "wist.opcode.config_backup/v1");
    assert_eq!(items[0].value["created"], true);
    assert_eq!(items[0].value["backup"]["sha256"], sha256_hex(ORIGINAL));

    assert_eq!(items[1].value["schema"], "wist.opcode.config_apply/v1");
    assert_eq!(items[1].value["written"]["sha256"], sha256_hex(REPLACEMENT));
    assert_eq!(items[1].value["verify"]["parse"], "toml");

    assert_eq!(items[2].value["schema"], "wist.opcode.config_rollback/v1");
    assert_eq!(items[2].value["restored"]["sha256"], sha256_hex(ORIGINAL));

    // 整条链跑完，文件回到原样，权限也回到原样。
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        ORIGINAL
    );
    assert_eq!(
        std::fs::metadata(&target)
            .expect("meta")
            .permissions()
            .mode()
            & 0o7777,
        0o640
    );
    // 备份留在 state 目录（不在 run 目录里被轮转清掉）。
    assert!(
        root.join("state")
            .join("action_backups")
            .join("act_config-chain")
            .is_dir(),
        "备份目录必须落在 state 下"
    );
}

#[cfg(unix)]
#[test]
fn apply_without_backup_is_rejected_and_leaves_the_file_alone() {
    let root = temp_dir("config-no-backup");
    let etc = root.join("etc");
    std::fs::create_dir_all(&etc).expect("etc dir");
    let target = etc.join("app.toml");
    let source = etc.join("app.toml.new");
    std::fs::write(&target, ORIGINAL).expect("write target");
    std::fs::write(&source, REPLACEMENT).expect("write source");

    let plan = plan_with(
        "config-no-backup",
        vec![invoke(
            "s1",
            "config.apply",
            serde_json::json!({
                "path": target.display().to_string(),
                "source": source.display().to_string(),
                "source_sha256": sha256_hex(REPLACEMENT),
                "format": "toml",
            }),
        )],
        vec![root.display().to_string()],
    );

    let outcome = run_plan(&root, plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("backup_missing")
    );
    assert_eq!(
        std::fs::read_to_string(&target).expect("read target"),
        ORIGINAL,
        "没有备份就一个字节都不能写"
    );
}

#[cfg(unix)]
#[test]
fn config_change_outside_the_allow_list_is_rejected() {
    let root = temp_dir("config-allow");
    let outside = temp_dir("config-outside");
    let outside_target = outside.join("keep.toml");
    std::fs::write(&outside_target, ORIGINAL).expect("write outside");

    let plan = plan_with(
        "config-allow",
        vec![invoke(
            "s1",
            "config.backup",
            serde_json::json!({ "path": outside_target.display().to_string() }),
        )],
        vec![root.display().to_string()],
    );

    let outcome = run_plan(&root, plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("path_not_allowed")
    );
    assert_eq!(
        std::fs::read_to_string(&outside_target).expect("read outside"),
        ORIGINAL
    );
}
