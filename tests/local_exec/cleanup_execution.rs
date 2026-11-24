//! E0 端到端：清理计划的真实执行。
//!
//! 只读部分（`preview`）在所有平台上都跑真二进制；写入部分（`apply`）只在
//! `test-cleanup-roots` 特性下用沙箱目录跑（Linux / macOS 都跑，避免删到开发机的临时文件）。

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
            reason: Some("E0 cleanup test".to_string()),
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

fn output(id: &str) -> ActionPlanStep {
    ActionPlanStep {
        id: id.to_string(),
        kind: "output".to_string(),
        op: None,
        args: None,
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
fn preview_plan_produces_structured_evidence() {
    let outcome = run_plan(
        "preview",
        plan_with(
            "preview",
            RiskLevel::R0,
            vec![
                invoke(
                    "s1",
                    "disk.cleanup.preview",
                    serde_json::json!({"target": "tmp"}),
                ),
                output("s2"),
            ],
        ),
    );

    assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
    assert_eq!(outcome.report.result.step_records.len(), 2);
    // 真执行过：结果里必须有结构化证据（skeleton 只回空 outputs）。
    assert_eq!(outcome.report.result.outputs.items.len(), 1);
    assert_eq!(outcome.report.result.outputs.items[0].name, "s1");

    let value = &outcome.report.result.outputs.items[0].value;
    assert_eq!(value["schema"], "wist.opcode.disk_cleanup_preview/v1");
    assert_eq!(value["target"], "tmp");
    assert_eq!(value["min_age_hours"], 24);
    assert!(value["candidates"]["files"].is_u64());
    assert!(value["candidates"]["bytes"].is_u64());
    assert!(value["items"].is_array());
}

#[cfg(unix)]
#[test]
fn unknown_op_is_rejected_with_a_stable_code_and_no_outputs() {
    let outcome = run_plan(
        "unknown-op",
        plan_with(
            "unknown-op",
            RiskLevel::R1,
            vec![invoke("s1", "nope.nope", serde_json::json!({}))],
        ),
    );

    // 计划里引用了一个执行器不认识的 op：整份计划没跑，属计划级拒绝而不是执行失败。
    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("unknown_op")
    );
    assert!(outcome.report.result.outputs.items.is_empty());
}

#[cfg(unix)]
#[test]
fn branch_and_guard_steps_are_rejected_instead_of_faked() {
    let outcome = run_plan(
        "branch",
        plan_with(
            "branch",
            RiskLevel::R0,
            vec![ActionPlanStep {
                id: "s1".to_string(),
                kind: "branch".to_string(),
                op: None,
                args: None,
            }],
        ),
    );

    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("unsupported_step_kind")
    );
}

#[cfg(unix)]
#[test]
fn a_read_only_plan_cannot_smuggle_in_a_write_op() {
    // 计划声明 R0，却塞了 R2 的 apply：必须被本地终审挡住（而不是先删再报错）。
    let outcome = run_plan(
        "risk",
        plan_with(
            "risk",
            RiskLevel::R0,
            vec![invoke(
                "s1",
                "disk.cleanup.apply",
                serde_json::json!({"target": "tmp", "max_files": 1, "max_bytes": 1024}),
            )],
        ),
    );

    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("risk_understated")
    );
    assert!(outcome.report.result.outputs.items.is_empty());
}

#[cfg(unix)]
#[test]
fn process_list_reports_real_rows() {
    let outcome = run_plan(
        "process-list",
        plan_with(
            "process-list",
            RiskLevel::R0,
            vec![invoke(
                "s1",
                "process.list",
                serde_json::json!({ "top": 3 }),
            )],
        ),
    );

    assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
    let value = &outcome.report.result.outputs.items[0].value;
    assert_eq!(value["schema"], "wist.opcode.process_list/v1");
    assert!(value["total"].as_u64().unwrap_or(0) >= 1);
    let rows = value["processes"].as_array().expect("process rows");
    assert!(!rows.is_empty());
    assert!(rows[0]["pid"].is_u64());
    // 输出永远不带 argv。
    assert!(rows[0].get("cmdline").is_none());
}

#[cfg(unix)]
#[test]
fn file_stat_denies_without_an_allow_list() {
    let dir = temp_dir("file-deny");
    let file = dir.join("a.txt");
    std::fs::write(&file, b"hello").expect("write");

    let outcome = run_plan(
        "file-deny",
        plan_with(
            "file-deny",
            RiskLevel::R0,
            vec![invoke(
                "s1",
                "file.stat",
                serde_json::json!({ "path": file.display().to_string() }),
            )],
        ),
    );

    assert_eq!(outcome.report.result.final_status, FinalStatus::Rejected);
    assert_eq!(
        outcome.report.result.exit_reason.as_deref(),
        Some("path_not_allowed")
    );
}

#[cfg(unix)]
#[test]
fn file_stat_reads_inside_the_allow_list() {
    let dir = temp_dir("file-allow");
    let file = dir.join("a.txt");
    std::fs::write(&file, b"hello").expect("write");

    let mut plan = plan_with(
        "file-allow",
        RiskLevel::R0,
        vec![invoke(
            "s1",
            "file.stat",
            serde_json::json!({ "path": file.display().to_string() }),
        )],
    );
    plan.constraints.allow = Some(ActionPlanAllow {
        paths: vec![dir.display().to_string()],
    });

    let outcome = run_plan("file-allow", plan);
    assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
    let value = &outcome.report.result.outputs.items[0].value;
    assert_eq!(value["schema"], "wist.opcode.file_stat/v1");
    assert_eq!(value["size_bytes"], 5);
}

#[cfg(unix)]
#[test]
fn the_same_plan_is_not_executed_twice() {
    let root = temp_dir("duplicate");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");

    let plan = plan_with(
        "duplicate",
        RiskLevel::R0,
        vec![invoke(
            "s1",
            "disk.cleanup.preview",
            serde_json::json!({"target": "tmp"}),
        )],
    );

    submit_local_plan(&SchedulerRequest {
        run_dir: run_dir.clone(),
        state_dir: state_dir.clone(),
        plan: plan.clone(),
    })
    .expect("first submit");

    let second = submit_local_plan(&SchedulerRequest {
        run_dir,
        state_dir,
        plan,
    });
    assert!(second.is_err(), "duplicate plan must be rejected");
}

#[cfg(feature = "test-cleanup-roots")]
mod sandbox {
    use std::fs;
    use std::os::unix::fs::MetadataExt;
    use std::path::PathBuf;
    use std::sync::Mutex;
    use std::time::{Duration, SystemTime};

    use super::*;

    static ENV_LOCK: Mutex<()> = Mutex::new(());

    fn write_old(path: &PathBuf, bytes: usize, age: Duration) {
        fs::write(path, vec![7u8; bytes]).expect("write");
        let file = fs::OpenOptions::new().write(true).open(path).expect("open");
        let times = std::fs::FileTimes::new().set_modified(SystemTime::now() - age);
        file.set_times(times).expect("set mtime");
    }

    #[test]
    fn apply_deletes_only_eligible_files_and_reports_freed_bytes() {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let root = temp_dir("sandbox-apply");

        let old = root.join("old.tmp");
        let young = root.join("young.tmp");
        let open = root.join("open.tmp");
        let hard_a = root.join("hard-a.tmp");
        let hard_b = root.join("hard-b.tmp");

        write_old(&old, 100, Duration::from_secs(48 * 3600));
        write_old(&young, 100, Duration::from_secs(60));
        write_old(&open, 100, Duration::from_secs(48 * 3600));
        write_old(&hard_a, 100, Duration::from_secs(48 * 3600));
        fs::hard_link(&hard_a, &hard_b).expect("hardlink");
        std::os::unix::fs::symlink(&old, root.join("link.tmp")).expect("symlink");

        // 让 `open.tmp` 真被本进程占用：扫描会读 `/proc/<pid>/fd`（Linux）
        // 或 libproc 的 vnode fd（macOS）。
        let _held = fs::File::open(&open).expect("hold open");

        // SAFETY: 由 `ENV_LOCK` 串行化；测试进程内没有其它线程读这个变量。
        unsafe { std::env::set_var("WIST_CLEANUP_ROOT", &root) };
        let outcome = run_plan(
            "sandbox",
            plan_with(
                "sandbox",
                RiskLevel::R2,
                vec![invoke(
                    "s1",
                    "disk.cleanup.apply",
                    serde_json::json!({
                        "target": "tmp",
                        "max_files": 10,
                        "max_bytes": 1_048_576,
                    }),
                )],
            ),
        );
        // SAFETY: 同上，仍在 `ENV_LOCK` 内。
        unsafe { std::env::remove_var("WIST_CLEANUP_ROOT") };

        assert_eq!(outcome.report.result.final_status, FinalStatus::Succeeded);
        let value = &outcome.report.result.outputs.items[0].value;
        assert_eq!(value["schema"], "wist.opcode.disk_cleanup_apply/v1");
        assert_eq!(value["deleted"]["files"], 1);
        assert_eq!(value["freed_bytes"], 100);
        assert_eq!(value["skipped"]["open"], 1);
        assert_eq!(value["skipped"]["hardlink"], 2);
        assert_eq!(value["skipped"]["symlink"], 1);
        assert_eq!(value["skipped"]["young"], 1);

        assert!(!old.exists(), "the only eligible file must be gone");
        assert!(young.exists());
        assert!(open.exists(), "open files are skipped");
        assert!(hard_a.exists() && hard_b.exists(), "hardlinks are skipped");
        assert!(
            fs::symlink_metadata(root.join("link.tmp")).is_ok(),
            "symlinks are never followed or deleted"
        );
        // 硬链接计数与 inode 一致（防止误判成普通文件）。
        assert_eq!(fs::metadata(&hard_a).expect("meta").nlink(), 2);
    }
}
