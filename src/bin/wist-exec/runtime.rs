//! Runtime entrypoints.
//!
//! v1 执行语义（刻意保守）：
//!
//! | 项 | 规则 |
//! |---|---|
//! | 起点 / 顺序 | `program.entry` 起，按 `program.steps` 的声明顺序走到末尾 |
//! | `invoke` | 查注册表 → 执行 → 结果进 `outputs.items`（`name = step.id`） |
//! | `output` | 空操作，只记 `StepRecord` |
//! | `abort` | 立即结束，`failed` + `exit_reason = "aborted"` |
//! | `branch` / `guard` | **明确拒绝**：`rejected` + `unsupported_step_kind` |
//! | 失败 | 首个失败步之后不再执行；`exit_reason = error_code` |
//!
//! 不做线程 / 子进程级抢占：handler 自己按预算计时，总超时由 agentd 的进程级 deadline 兜底。

use std::io;
use std::path::Path;
use std::time::Instant;

use wist_agentd::exec::opcode::{self, BackupContext, OpError, OpInput};
use wist_contracts::action_plan::{
    ActionPlan, ActionPlanStep, STEP_KIND_ABORT, STEP_KIND_INVOKE, STEP_KIND_OUTPUT,
};
use wist_contracts::action_result::{
    ActionOutputItem, ActionOutputs, ActionResult, FinalStatus, StepRecord, StepStatus,
};
use wist_shared::time::now_rfc3339;
use wist_validate::action_plan::validate_action_plan;

use crate::workdir::{ExecutionWorkdir, ProgressState};

/// 一步执行完之后对整体计划的影响。
enum StepEffect {
    /// 产生了结构化输出（`invoke`）。
    Produced(serde_json::Value),
    /// 不产生输出（`output` / 普通成功步）。
    NoOutput,
    /// 主动中止计划（`abort`）。
    Abort,
}

pub fn execute(workdir: &ExecutionWorkdir, backup_dir: Option<&Path>) -> io::Result<ActionResult> {
    let runtime = workdir.read_runtime()?;
    let plan = workdir.read_plan()?;
    // 备份上下文：agentd 传入 state 目录下的备份根；`run-plan` 也会传。
    // `None` = 没配置 —— `config.*` 变更会因此拒绝执行（不会默默跳过备份）。
    let backups = backup_dir.map(|root| BackupContext {
        root,
        action_id: plan.meta.action_id.as_str(),
    });

    workdir.write_state(&ProgressState {
        execution_id: runtime.execution_id.clone(),
        action_id: plan.meta.action_id.clone(),
        state: "validating".to_string(),
        updated_at: now_rfc3339(),
        step_id: None,
        attempt: None,
        reason_code: None,
        detail: Some("validating action plan".to_string()),
    })?;

    if let Err(err) = validate_action_plan(&plan) {
        let started_at = now_rfc3339();
        let result = ActionResult {
            request_id: Some(plan.meta.request_id.clone()),
            exit_reason: Some(err.code.to_string()),
            step_records: vec![StepRecord {
                step_id: plan.program.entry.clone(),
                attempt: 1,
                op: None,
                status: StepStatus::Failed,
                started_at: started_at.clone(),
                finished_at: Some(started_at.clone()),
                duration_ms: Some(0),
                error_code: Some(err.code.to_string()),
                stdout_summary: None,
                stderr_summary: None,
                resource_usage: None,
            }],
            started_at: Some(started_at.clone()),
            finished_at: Some(started_at.clone()),
            ..ActionResult::new(
                plan.meta.action_id.clone(),
                runtime.execution_id.clone(),
                FinalStatus::Rejected,
            )
        };
        workdir.write_state(&ProgressState {
            execution_id: runtime.execution_id,
            action_id: plan.meta.action_id,
            state: "rejected".to_string(),
            updated_at: now_rfc3339(),
            step_id: None,
            attempt: None,
            reason_code: Some(err.code.to_string()),
            detail: Some("action plan validation rejected".to_string()),
        })?;
        return Ok(result);
    }

    let started_at = now_rfc3339();
    let mut step_records = Vec::new();
    let mut outputs = ActionOutputs::default();
    let mut final_status = FinalStatus::Succeeded;
    let mut exit_reason: Option<String> = None;

    // 校验已保证 entry 存在；`unwrap_or(0)` 只为防御将来校验被放宽。
    let entry_index = plan
        .program
        .steps
        .iter()
        .position(|step| step.id == plan.program.entry)
        .unwrap_or(0);

    for step in &plan.program.steps[entry_index..] {
        workdir.write_state(&ProgressState {
            execution_id: runtime.execution_id.clone(),
            action_id: plan.meta.action_id.clone(),
            state: "running".to_string(),
            updated_at: now_rfc3339(),
            step_id: Some(step.id.clone()),
            attempt: Some(1),
            reason_code: None,
            detail: Some("executing step".to_string()),
        })?;

        let step_started_at = now_rfc3339();
        let clock = Instant::now();
        let effect = run_step(step, &plan, backups.as_ref());
        let duration_ms = clock.elapsed().as_millis() as u64;

        match effect {
            Ok(StepEffect::Produced(value)) => {
                outputs.items.push(ActionOutputItem {
                    name: step.id.clone(),
                    value,
                    redacted: None,
                });
                step_records.push(step_record(
                    step,
                    StepStatus::Succeeded,
                    step_started_at,
                    duration_ms,
                    None,
                ));
            }
            Ok(StepEffect::NoOutput) => {
                step_records.push(step_record(
                    step,
                    StepStatus::Succeeded,
                    step_started_at,
                    duration_ms,
                    None,
                ));
            }
            Ok(StepEffect::Abort) => {
                step_records.push(step_record(
                    step,
                    StepStatus::Failed,
                    step_started_at,
                    duration_ms,
                    Some("aborted"),
                ));
                final_status = FinalStatus::Failed;
                exit_reason = Some("aborted".to_string());
                break;
            }
            Err(err) => {
                step_records.push(step_record(
                    step,
                    StepStatus::Failed,
                    step_started_at,
                    duration_ms,
                    Some(err.code),
                ));
                // `rejected` = 「这份计划根本没跑」；`failed` = 「跑起来之后出错」。
                // 计划级缺陷 + 此前没有任何步骤成功 → rejected；其余一律 failed。
                // 「此前已成功过」这条必须保留：契约规定 rejected 的结果里不许出现成功步
                // （`wist_validate::action_result::validate_final_status_consistency`）。
                let any_succeeded = step_records
                    .iter()
                    .any(|record| record.status == StepStatus::Succeeded);
                final_status = if is_preflight_rejection(err.code) && !any_succeeded {
                    FinalStatus::Rejected
                } else {
                    FinalStatus::Failed
                };
                exit_reason = Some(err.code.to_string());
                break;
            }
        }
    }

    let finished_at = now_rfc3339();
    Ok(ActionResult {
        request_id: Some(plan.meta.request_id.clone()),
        step_records,
        outputs,
        started_at: Some(started_at),
        finished_at: Some(finished_at),
        exit_reason,
        ..ActionResult::new(
            plan.meta.action_id.clone(),
            runtime.execution_id,
            final_status,
        )
    })
}

fn run_step(
    step: &ActionPlanStep,
    plan: &ActionPlan,
    backups: Option<&opcode::BackupContext<'_>>,
) -> Result<StepEffect, OpError> {
    match step.kind.as_str() {
        STEP_KIND_INVOKE => {
            let op = step.op.as_deref().unwrap_or_default();
            let spec = opcode::lookup(op).ok_or_else(|| {
                OpError::new(
                    opcode::codes::UNKNOWN_OP,
                    format!("op `{op}` 未登记（执行器不认识它）"),
                )
            })?;
            if opcode::risk_rank(plan.constraints.risk_level) < opcode::risk_rank(spec.risk) {
                return Err(OpError::new(
                    opcode::codes::RISK_UNDERSTATED,
                    format!(
                        "计划风险 {:?} 低于 op `{}` 要求的 {:?}",
                        plan.constraints.risk_level, spec.id, spec.risk
                    ),
                ));
            }
            let null = serde_json::Value::Null;
            let args = step.args.as_ref().unwrap_or(&null);
            let input = OpInput {
                args,
                requested_by: &plan.constraints.requested_by,
                config: None,
                allow_paths: plan
                    .constraints
                    .allow
                    .as_ref()
                    .map(|allow| allow.paths.as_slice())
                    .unwrap_or(&[]),
                budget: spec.budget,
                step_timeout_ms: plan.constraints.step_timeout_default_ms,
                backups,
            };
            let output = opcode::execute(spec, &input)?;
            Ok(StepEffect::Produced(output.value))
        }
        STEP_KIND_OUTPUT => Ok(StepEffect::NoOutput),
        STEP_KIND_ABORT => Ok(StepEffect::Abort),
        _ => Err(OpError::new(
            opcode::codes::UNSUPPORTED_STEP_KIND,
            format!("执行器 v1 不支持 step kind `{}`", step.kind),
        )),
    }
}

/// 哪些错误码属于「这份计划本身跑不了」，而不是「跑起来之后失败了」。
///
/// 判据：错误由**计划内容**（或其与执行机环境的静态不匹配）决定，且在产生任何副作用
/// 之前就已确定 —— 查表、风险、平台、预算、参数、策略。运行时才会知道的结果
/// （`op_failed` / `target_not_found` / `budget_exceeded` / `scan_incomplete`）不在此列，
/// 它们是 `failed`。
fn is_preflight_rejection(code: &str) -> bool {
    matches!(
        code,
        opcode::codes::UNKNOWN_OP
            | opcode::codes::UNSUPPORTED_STEP_KIND
            | opcode::codes::RISK_UNDERSTATED
            | opcode::codes::BUDGET_EXCEEDS_STEP_TIMEOUT
            | opcode::codes::UNSUPPORTED_PLATFORM
            | opcode::codes::INVALID_ARGS
            | opcode::codes::UNSUPPORTED_TARGET
            | opcode::codes::PATH_NOT_ALLOWED
            // `config.*` 的两道前置闸：没有备份目录 / 本次没有备份记录 ——
            // 都是「这份计划在这个执行环境里根本不成立」，一个字节都没写。
            | opcode::codes::BACKUP_UNAVAILABLE
            | opcode::codes::BACKUP_MISSING
    )
}

fn step_record(
    step: &ActionPlanStep,
    status: StepStatus,
    started_at: String,
    duration_ms: u64,
    error_code: Option<&str>,
) -> StepRecord {
    StepRecord {
        step_id: step.id.clone(),
        attempt: 1,
        op: step.op.clone(),
        status,
        started_at,
        finished_at: Some(now_rfc3339()),
        duration_ms: Some(duration_ms),
        error_code: error_code.map(str::to_string),
        stdout_summary: None,
        stderr_summary: None,
        resource_usage: None,
    }
}
