//! E3：`log.archive` / `log.rotate` 的接线用例。
//!
//! 这两条 op 的源是**闭集 + 写死的 /var/log 路径**，所以集成测试里**不真跑归档**
//! （否则会往测试机的 /var/log 里写文件）。真正的内容/校验/截断逻辑在
//! `exec::opcode::log_rotate` 的单测里用临时目录覆盖；这里只验两件事：
//! 已登记，且不认识的源被稳定拒绝。

use wist_agentd::bootstrap;
use wist_agentd::scheduler::{
    DrainOutcome, DrainRequest, SchedulerRequest, drain_next_with_report, submit_local_plan,
};
use wist_contracts::action_plan::{
    ActionPlan, ActionPlanConstraints, ActionPlanMeta, ActionPlanProgram, ActionPlanStep,
    ActionPlanTarget, ApprovalMode, RiskLevel,
};
use wist_contracts::action_result::FinalStatus;

use super::common::{temp_dir, test_exec_bin};

fn plan_with(name: &str, op: &str, args: serde_json::Value) -> ActionPlan {
    let step = ActionPlanStep {
        id: "s1".to_string(),
        kind: "invoke".to_string(),
        op: Some(op.to_string()),
        args: Some(args),
    };
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
            risk_level: RiskLevel::R2,
            approval_ref: None,
            approval_mode: ApprovalMode::NotRequired,
            requested_by: "tester@example.com".to_string(),
            reason: Some("E3 log rotation test".to_string()),
            max_total_duration_ms: 30_000,
            step_timeout_default_ms: 15_000,
            execution_profile: "agent_exec_v1".to_string(),
            required_capabilities: vec![op.to_string()],
            allow: None,
        },
        ActionPlanProgram {
            entry: step.id.clone(),
            steps: vec![step],
        },
    )
}

fn run_plan(name: &str, plan: ActionPlan) -> DrainOutcome {
    let root = temp_dir(name);
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

#[test]
fn an_unknown_log_source_is_rejected_for_archive_and_rotate() {
    for op in ["log.archive", "log.rotate"] {
        let plan = plan_with(op, op, serde_json::json!({ "source": "journald" }));
        let outcome = run_plan(op, plan);
        assert_eq!(
            outcome.report.result.final_status,
            FinalStatus::Rejected,
            "{op}"
        );
        assert_eq!(
            outcome.report.result.exit_reason.as_deref(),
            Some("unsupported_target"),
            "{op} 必须已登记，且把 journald 当成不认识的源"
        );
        assert!(outcome.report.result.outputs.items.is_empty());
    }
}
