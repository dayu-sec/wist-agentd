//! E1 只读 opcode 的端到端用例（走真实 `wist-exec` 二进制）。
//!
//! `file.find` 用沙箱目录，跨平台可跑；`service.status` 依赖本机 systemd 目录，
//! 它的目录解析逻辑在 `exec::opcode::service` 的单测里覆盖，这里只验
//! 「注册表接线 + 本地终审」这一段。

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

fn plan_with(name: &str, risk: RiskLevel, steps: Vec<ActionPlanStep>) -> ActionPlan {
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
            risk_level: risk,
            approval_ref: None,
            approval_mode: ApprovalMode::NotRequired,
            requested_by: "tester@example.com".to_string(),
            reason: Some("E1 read-only test".to_string()),
            max_total_duration_ms: 30_000,
            step_timeout_default_ms: 15_000,
            execution_profile: "agent_exec_v1".to_string(),
            required_capabilities: Vec::new(),
            allow: None,
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

#[cfg(unix)]
#[test]
fn file_find_returns_real_matches_inside_the_allow_list() {
    let root = temp_dir("find-sandbox");
    std::fs::write(root.join("a.log"), b"abc").expect("write a");
    std::fs::write(root.join("b.log"), b"de").expect("write b");
    std::fs::write(root.join("skip.txt"), b"x").expect("write skip");
    let nested = root.join("nested");
    std::fs::create_dir_all(&nested).expect("nested");
    std::fs::write(nested.join("c.log"), b"fghi").expect("write c");

    let mut plan = plan_with(
        "find",
        RiskLevel::R0,
        vec![invoke(
            "s1",
            "file.find",
            serde_json::json!({ "root": root.display().to_string(), "pattern": "*.log" }),
        )],
    );
    plan.constraints.allow = Some(ActionPlanAllow {
        paths: vec![root.display().to_string()],
    });

    let outcome = run_plan("find", plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
    let value = &outcome.report.result.outputs.items[0].value;
    assert_eq!(value["schema"], "wist.opcode.file_find/v1");
    assert_eq!(value["kind"], "file");
    // 默认 max_depth = 4：root 下 .log + nested/c.log 都要在结果里。
    assert_eq!(value["matched"], 3);
    assert_eq!(value["scan"]["complete"], true);
    let items = value["items"].as_array().expect("items");
    assert_eq!(items.len(), 3);
    assert!(items.iter().all(|item| item["kind"] == "file"));
    assert!(items.iter().any(|item| {
        item["path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("nested/c.log")
    }));
    assert!(!items.iter().any(|item| {
        item["path"]
            .as_str()
            .unwrap_or_default()
            .ends_with("skip.txt")
    }));
}

#[cfg(unix)]
#[test]
fn file_find_without_an_allow_list_is_rejected_before_scanning() {
    let root = temp_dir("find-deny");
    std::fs::write(root.join("a.log"), b"abc").expect("write");

    let plan = plan_with(
        "find-deny",
        RiskLevel::R0,
        vec![invoke(
            "s1",
            "file.find",
            serde_json::json!({ "root": root.display().to_string(), "pattern": "*" }),
        )],
    );

    let outcome = run_plan("find-deny", plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("path_not_allowed")
    );
    assert!(outcome.report.result.outputs.items.is_empty());
}

#[cfg(target_os = "linux")]
#[test]
fn service_status_is_registered_and_reads_the_platform_gate() {
    // 这条只验接线：查询一个不存在的单元必须得到稳定错误码，而不是 `unknown_op`。
    let plan = plan_with(
        "service-missing",
        RiskLevel::R0,
        vec![invoke(
            "s1",
            "service.status",
            serde_json::json!({ "name": "wist-no-such-unit-xyz" }),
        )],
    );

    let outcome = run_plan("service-missing", plan);
    let reason = outcome.report.result.exit_reason.as_deref();
    assert_ne!(reason, Some("unknown_op"), "service.status 必须已登记");
    assert_ne!(reason, Some("unsupported_platform"));
    // 正常 systemd 主机上是 target_not_found；没有单元目录的容器里是 op_failed。
    assert!(
        matches!(reason, Some("target_not_found") | Some("op_failed")),
        "unexpected exit_reason: {reason:?}"
    );
    assert_ne!(outcome.report.result.final_status, FinalStatus::Succeeded);
}

#[test]
fn log_read_reports_a_stable_outcome() {
    // 测试机不一定有 /var/log/auth.log：只验「已登记 + 错误码稳定」。
    let plan = plan_with(
        "log-read",
        RiskLevel::R1,
        vec![invoke(
            "s1",
            "log.read_range",
            serde_json::json!({ "source": "auth" }),
        )],
    );
    let outcome = run_plan("log-read", plan);
    let reason = outcome.report.result.exit_reason.as_deref();
    assert_ne!(reason, Some("unknown_op"), "log.read_range 必须已登记");
    assert!(
        reason.is_none() || matches!(reason, Some("target_not_found") | Some("op_failed")),
        "意外的 exit_reason: {reason:?}"
    );
}

#[cfg(target_os = "linux")]
#[test]
fn audit_list_is_registered_and_fails_stably() {
    let plan = plan_with(
        "audit-list",
        RiskLevel::R1,
        vec![invoke("s1", "audit.list", serde_json::json!({}))],
    );
    let outcome = run_plan("audit-list", plan);
    let reason = outcome.report.result.exit_reason.as_deref();
    assert_ne!(reason, Some("unknown_op"), "audit.list 必须已登记");
    assert!(
        reason.is_none() || matches!(reason, Some("target_not_found") | Some("op_failed")),
        "意外的 exit_reason: {reason:?}"
    );
}

#[test]
fn journald_is_not_a_log_source() {
    // 源是闭集：journald 与 audit 都不能从 log.read_range 读。
    let plan = plan_with(
        "log-journald",
        RiskLevel::R1,
        vec![invoke(
            "s1",
            "log.read_range",
            serde_json::json!({ "source": "journald" }),
        )],
    );
    let outcome = run_plan("log-journald", plan);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("unsupported_target")
    );
    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
}

#[cfg(target_os = "linux")]
#[test]
fn socket_list_reads_the_real_socket_table() {
    let plan = plan_with(
        "socket-list",
        RiskLevel::R0,
        vec![invoke("s1", "socket.list", serde_json::json!({}))],
    );

    let outcome = run_plan("socket-list", plan);
    let reason = outcome.report.result.exit_reason.as_deref();
    assert_ne!(reason, Some("unknown_op"), "socket.list 必须已登记");

    if outcome.report.result.final_status == FinalStatus::Succeeded {
        let value = &outcome.report.result.outputs.items[0].value;
        assert_eq!(value["schema"], "wist.opcode.socket_list/v1");
        assert!(value["listeners"].is_array());
        assert!(
            value["sources"]["requested"].as_u64().unwrap_or(0) >= 1,
            "至少要读到一个来源"
        );
        // 默认只看在等连接的：每一行都必须是监听的两种状态之一。
        for row in value["listeners"].as_array().expect("listeners") {
            let state = row["state"].as_str().unwrap_or_default();
            assert!(matches!(state, "listen" | "unconnected"), "{state:?}");
        }
    } else {
        // 受限容器里 `/proc/net` 可能被隐藏：那也必须是一个稳定码，不能是 panic。
        assert_eq!(reason, Some("op_failed"));
    }
}

#[cfg(unix)]
#[test]
fn file_hash_reports_the_digest_of_the_real_file() {
    let root = temp_dir("hash-sandbox");
    let file = root.join("sample.bin");
    std::fs::write(&file, b"hello world").expect("write");

    let mut plan = plan_with(
        "hash",
        RiskLevel::R0,
        vec![invoke(
            "s1",
            "file.hash",
            serde_json::json!({ "path": file.display().to_string() }),
        )],
    );
    plan.constraints.allow = Some(ActionPlanAllow {
        paths: vec![root.display().to_string()],
    });

    let outcome = run_plan("hash", plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
    let value = &outcome.report.result.outputs.items[0].value;
    assert_eq!(value["schema"], "wist.opcode.file_hash/v1");
    assert_eq!(value["size_bytes"], 11);
    assert_eq!(value["truncated"], false);
    assert_eq!(
        value["sha256"],
        "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    );
}

#[cfg(unix)]
#[test]
fn config_inspect_never_puts_a_value_in_the_result() {
    let root = temp_dir("config-sandbox");
    let file = root.join("app.toml");
    std::fs::write(
        &file,
        "[db]\nhost = \"127.0.0.1\"\npassword = \"e2e-hunter2-secret\"\n",
    )
    .expect("write");

    let mut plan = plan_with(
        "config-inspect",
        RiskLevel::R1,
        vec![invoke(
            "s1",
            "config.inspect",
            serde_json::json!({
                "path": file.display().to_string(),
                "selectors": ["db.password", "db.host"],
            }),
        )],
    );
    plan.constraints.allow = Some(ActionPlanAllow {
        paths: vec![root.display().to_string()],
    });

    let outcome = run_plan("config-inspect", plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
    let value = &outcome.report.result.outputs.items[0].value;
    assert_eq!(value["schema"], "wist.opcode.config_inspect/v1");
    assert_eq!(value["format_detected"], "toml");
    assert_eq!(value["parsed"], true);
    assert_eq!(value["selected"][0]["value_type"], "string");

    // 整份结果（包括 steps / ack 之外的所有字段）都不许出现配置值。
    let whole = serde_json::to_string(&outcome.report.result).expect("serialize");
    assert!(
        !whole.contains("e2e-hunter2-secret"),
        "配置值被回传了：{whole}"
    );
    assert!(!whole.contains("127.0.0.1"), "配置值被回传了：{whole}");
}
