//! 执行器 opcode 注册表：**闭集**、带元数据、统一错误码。
//!
//! 分工：
//!
//! * 注册表只回答「有没有这个 op、它是什么风险、在哪些平台可用、预算多大」；
//! * handler 只做一件事并返回结构化 JSON；
//! * `wist-exec` 的 runtime 负责顺序、状态、结果与错误码落盘。
//!
//! 三条硬规矩：
//!
//! 1. **没有 shell**：handler 是 Rust 函数，参数强类型；不存在「拼接命令行」这条路。
//! 2. **没有预算的 op 不许登记**：预算由 agentd 强制，网关不得放宽。
//! 3. **错误码是协议的一部分**：同一类失败在不同 op 上必须是同一个码（见 [`codes`]），
//!    否则网关与页面只能按字符串猜。
//!
//! 词表纪律：op id **只增不改名**；语义变了就出新 id，旧 id 标 deprecated。

use std::path::Path;
use std::time::Duration;

use serde::de::DeserializeOwned;
use wist_contracts::action_plan::RiskLevel;

use crate::config::agent_config::AgentConfig;

pub mod cleanup;
pub mod config;
pub mod file;
pub mod log_rotate;
pub mod logs;
pub mod process;
pub mod service;
pub mod socket;

/// opcode 的预算。handler 必须自己按它夹紧，越界如实标 `truncated`。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct OpBudget {
    /// 单个 op 的最长执行时间。超过计划的 `step_timeout_default_ms` 时该 op 会被拒绝。
    pub max_duration_ms: u64,
    /// 结果里最多返回多少条明细（不是扫描上限，扫描上限在 handler 内部）。
    pub max_items: usize,
    /// 单次 op 最多处理多少字节。
    pub max_bytes: u64,
}

impl OpBudget {
    pub const fn new(max_duration_ms: u64, max_items: usize, max_bytes: u64) -> Self {
        Self {
            max_duration_ms,
            max_items,
            max_bytes,
        }
    }

    pub fn duration(&self) -> Duration {
        Duration::from_millis(self.max_duration_ms)
    }
}

/// handler 的输入。
///
/// 预算也在这里：handler 必须用 `budget` 夹紧自己的扫描/输出，而不是各自写一份常量
/// ——否则注册表里的预算只是装饰，改注册表不会改变行为。
pub struct OpInput<'a> {
    /// 已经确认是 JSON 对象（缺省时是 `{}`）。
    pub args: &'a serde_json::Value,
    /// 审计用：来自 `plan.constraints.requested_by`。
    pub requested_by: &'a str,
    /// 只有需要读取 agent 配置的 op 才用得上；`wist-exec` 目前恒为 `None`。
    pub config: Option<&'a AgentConfig>,
    /// 本次计划显式允许的路径前缀（`plan.constraints.allow.paths`）。
    /// 需要访问调用方指定路径的 op **必须** 先过这一层。
    pub allow_paths: &'a [String],
    /// 本 op 的预算（来自注册表）。
    pub budget: OpBudget,
    /// 本次 step 的限额（`plan.constraints.step_timeout_default_ms`）。
    /// `execute` 保证 `budget.max_duration_ms <= step_timeout_ms`。
    pub step_timeout_ms: u64,
    /// 备份上下文（备份根 + 本次 `action_id`）。
    ///
    /// `None` = 执行器没配备份目录：`config.backup` / `apply` / `rollback`
    /// 会直接报 `backup_unavailable`，**不会**默默跳过备份。
    pub backups: Option<&'a BackupContext<'a>>,
}

/// 一次执行的备份上下文。
///
/// `config.backup` 写入、`config.apply` / `config.rollback` 读取 —— 三者靠
/// `(备份根, action_id)` 串成一条链：**同一个 action 只认一份前像**。
pub struct BackupContext<'a> {
    pub root: &'a Path,
    pub action_id: &'a str,
}

/// handler 的输出。
///
/// 不单设 `truncated` 字段：每个 op 的结果里已有自己的 `truncated`（语义各不相同：
/// 条数 / 字节 / 扫描），执行器不消费它，多一个同名标志只会让人以为它被用在某处。
#[derive(Debug)]
pub struct OpOutput {
    pub value: serde_json::Value,
}

/// 结构化失败。`code` 会进 `StepRecord.error_code` 与最终 `exit_reason`。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OpError {
    pub code: &'static str,
    pub detail: String,
}

impl OpError {
    pub fn new(code: &'static str, detail: impl Into<String>) -> Self {
        Self {
            code,
            detail: detail.into(),
        }
    }
}

/// 稳定错误码（协议的一部分，勿改）。
pub mod codes {
    pub const UNKNOWN_OP: &str = "unknown_op";
    pub const UNSUPPORTED_PLATFORM: &str = "unsupported_platform";
    pub const INVALID_ARGS: &str = "invalid_args";
    pub const UNSUPPORTED_TARGET: &str = "unsupported_target";
    pub const SCAN_INCOMPLETE: &str = "scan_incomplete";
    pub const BUDGET_EXCEEDED: &str = "budget_exceeded";
    pub const BUDGET_EXCEEDS_STEP_TIMEOUT: &str = "budget_exceeds_step_timeout";
    pub const RISK_UNDERSTATED: &str = "risk_understated";
    pub const OP_FAILED: &str = "op_failed";
    pub const UNSUPPORTED_STEP_KIND: &str = "unsupported_step_kind";
    pub const TARGET_NOT_FOUND: &str = "target_not_found";
    pub const PATH_NOT_ALLOWED: &str = "path_not_allowed";
    pub const TARGET_MISMATCH: &str = "target_mismatch";
    pub const PLAN_EXPIRED: &str = "plan_expired";
    pub const INVALID_NOW: &str = "invalid_now";
    pub const APPROVAL_MISSING: &str = "approval_missing";
    pub const CAPABILITY_MISSING: &str = "capability_missing";
    // `config.*` 变更：前四个发生在「写之前」，后两个是写/验阶段的失败。
    pub const BACKUP_UNAVAILABLE: &str = "backup_unavailable";
    pub const BACKUP_MISSING: &str = "backup_missing";
    pub const SOURCE_HASH_MISMATCH: &str = "source_hash_mismatch";
    pub const TARGET_CHANGED: &str = "target_changed";
    pub const INVALID_CONFIG: &str = "invalid_config";
    pub const VERIFY_FAILED: &str = "verify_failed";
    pub const WRITE_FAILED: &str = "write_failed";
    // 日志归档：写完复读对不上（已经删掉残缺文件，原文件未动）。
    pub const ARCHIVE_INCOMPLETE: &str = "archive_incomplete";
    // 签发证明（attestation）：本地验签与信任锚。
    pub const ATTESTATION_MISSING: &str = "attestation_missing";
    pub const PLAN_DIGEST_MISMATCH: &str = "plan_digest_mismatch";
    pub const SIGNATURE_INVALID: &str = "signature_invalid";
    pub const UNKNOWN_SIGNING_KEY: &str = "unknown_signing_key";
    pub const ATTESTATION_KEY_UNAVAILABLE: &str = "attestation_key_unavailable";
    pub const ATTESTATION_KEY_INVALID: &str = "attestation_key_invalid";
    pub const APPROVAL_MISMATCH: &str = "approval_mismatch";
    pub const APPROVAL_RISK_MISMATCH: &str = "approval_risk_mismatch";
    pub const APPROVAL_INSUFFICIENT: &str = "approval_insufficient";
    pub const ATTESTATION_EXPIRED: &str = "attestation_expired";
}

/// 一个已登记的 opcode。
pub struct OpSpec {
    pub id: &'static str,
    pub risk: RiskLevel,
    /// 平台白名单；与 [`current_platform`] 的返回值比较。
    pub platforms: &'static [&'static str],
    pub budget: OpBudget,
    pub handler: fn(&OpInput<'_>) -> Result<OpOutput, OpError>,
}

/// 生产名册。**唯一一份**：测试用的 op 另放一个切片，由 [`lookup`] 合并 ——
/// 两份完整名单一定会漂，而 “test 构建里少一个 op” 这种错在 CI 上很难看出来。
const PROD_REGISTRY: &[OpSpec] = &[
    cleanup::PREVIEW_SPEC,
    cleanup::APPLY_SPEC,
    process::LIST_SPEC,
    process::TREE_SPEC,
    process::OPEN_FILES_SPEC,
    service::STATUS_SPEC,
    socket::LIST_SPEC,
    file::STAT_SPEC,
    file::READ_RANGE_SPEC,
    file::FIND_SPEC,
    file::HASH_SPEC,
    config::INSPECT_SPEC,
    config::BACKUP_SPEC,
    config::APPLY_SPEC,
    config::ROLLBACK_SPEC,
    logs::LOG_READ_SPEC,
    logs::AUDIT_LIST_SPEC,
    log_rotate::ARCHIVE_SPEC,
    log_rotate::ROTATE_SPEC,
];

#[cfg(test)]
const TEST_REGISTRY: &[OpSpec] = &[test_ops::ECHO_SPEC];
#[cfg(not(test))]
const TEST_REGISTRY: &[OpSpec] = &[];

fn registry() -> impl Iterator<Item = &'static OpSpec> {
    PROD_REGISTRY.iter().chain(TEST_REGISTRY.iter())
}

/// 本机**执行能力**：注册表里**当前平台能跑**的 op（与 `investigate::capabilities` 同一条纪律：
/// 从实现处取，不另写一份名单）。
///
/// 必须按 `spec.platforms` 过滤：网关拿这份名单做**下发前**的能力闸
/// （`ensure_plan_capable`）。不过滤的话，机器会声称自己能跑本平台并不支持的 op，
/// 网关把计划排进队列，机器执行时才回 `unsupported_platform`
/// —— 现场看到的就是「命令已下发，几秒后变成一条看不懂的失败回执」。
///
/// 例子：`disk.cleanup.apply` 依赖占用检查（Linux `/proc` / macOS libproc），
/// 哪天某个平台没有这一层，只需收窄它的 `platforms`，这里自动跟上。
pub fn capabilities() -> wist_contracts::capability_report::ExecCapabilities {
    let platform = current_platform();
    wist_contracts::capability_report::ExecCapabilities {
        opcodes: PROD_REGISTRY
            .iter()
            .filter(|spec| platform.is_some_and(|current| spec.platforms.contains(&current)))
            .map(|spec| spec.id.to_string())
            .collect(),
        execution_profiles: vec!["agent_exec_v1".to_string()],
    }
}

pub fn lookup(op: &str) -> Option<&'static OpSpec> {
    registry().find(|spec| spec.id == op)
}

/// 当前平台的词表值。未知平台返回 `None`（所有 op 都会因此被拒）。
pub fn current_platform() -> Option<&'static str> {
    if cfg!(target_os = "linux") {
        Some("linux")
    } else if cfg!(target_os = "macos") {
        Some("macos")
    } else {
        None
    }
}

/// 风险等级的可比较序（契约里的枚举没有实现 `Ord`）。
pub fn risk_rank(risk: RiskLevel) -> u8 {
    match risk {
        RiskLevel::R0 => 0,
        RiskLevel::R1 => 1,
        RiskLevel::R2 => 2,
        RiskLevel::R3 => 3,
    }
}

/// 执行一个已登记的 op：平台 → 预算 → handler。
pub fn execute(spec: &'static OpSpec, input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let Some(platform) = current_platform() else {
        return Err(OpError::new(
            codes::UNSUPPORTED_PLATFORM,
            "当前平台不在支持列表里（仅 linux / macos）".to_string(),
        ));
    };
    if !spec.platforms.contains(&platform) {
        return Err(OpError::new(
            codes::UNSUPPORTED_PLATFORM,
            format!("op {} 不支持当前平台 {platform}", spec.id),
        ));
    }
    if spec.budget.max_duration_ms > input.step_timeout_ms {
        return Err(OpError::new(
            codes::BUDGET_EXCEEDS_STEP_TIMEOUT,
            format!(
                "op {} 的预算 {}ms 超过本次 step 限额 {}ms",
                spec.id, spec.budget.max_duration_ms, input.step_timeout_ms
            ),
        ));
    }
    (spec.handler)(input)
}

/// 把 `args` 解成具体参数类型。`null` / 缺省按空对象处理。
///
/// 用 `deny_unknown_fields` 的入参结构：多传字段直接拒 —— 旧 agentd 不认识的新参数
/// 如果被默默忽略，现场会看到「配了但没生效」。
pub(crate) fn parse_args<T: DeserializeOwned>(args: &serde_json::Value) -> Result<T, OpError> {
    let value = if args.is_null() {
        serde_json::json!({})
    } else {
        args.clone()
    };
    serde_json::from_value(value)
        .map_err(|err| OpError::new(codes::INVALID_ARGS, format!("参数不合法：{err}")))
}

#[cfg(test)]
mod test_ops {
    use super::*;

    /// 测试专用：把 args 原样回显。只在 lib 的测试构建里存在。
    pub const ECHO_SPEC: OpSpec = OpSpec {
        id: "test.echo",
        risk: RiskLevel::R0,
        platforms: &["linux", "macos"],
        budget: OpBudget::new(1_000, 10, 1024),
        handler: echo,
    };

    fn echo(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
        Ok(OpOutput {
            value: serde_json::json!({ "args": input.args, "requested_by": input.requested_by }),
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(args: &'a serde_json::Value, step_timeout_ms: u64) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: &[],
            budget: OpBudget::new(step_timeout_ms, 10, 1024),
            step_timeout_ms,
            backups: None,
        }
    }

    #[test]
    fn registry_contains_both_cleanup_ops() {
        for id in ["disk.cleanup.preview", "disk.cleanup.apply"] {
            let spec = lookup(id).unwrap_or_else(|| panic!("{id} must be registered"));
            assert_eq!(spec.id, id);
        }
    }

    /// 能力上报 = 注册表 ∩ 「当前平台能跑」。
    ///
    /// 两个方向都要锁：
    /// * **不能少报**：支持当前平台的 op 没报 → 网关会拒一条本可以跑的计划；
    /// * **不能多报**（曾经的 bug）：不支持当前平台的 op 也报 → 网关放行，
    ///   机器执行时才回 `unsupported_platform`，现场只看到一条“看不懂的失败回执”。
    #[test]
    fn capabilities_report_exactly_what_this_platform_can_run() {
        let platform = current_platform().expect("tests run on linux or macos");
        let reported = capabilities().opcodes;

        for spec in PROD_REGISTRY {
            let supported = spec.platforms.contains(&platform);
            let listed = reported.iter().any(|op| op == spec.id);
            if supported {
                assert!(listed, "{} 支持 {platform}，但能力上报里没有它", spec.id);
            } else {
                assert!(
                    !listed,
                    "{} 不支持 {platform}，却上报了：网关会派一条注定失败的活",
                    spec.id
                );
            }
        }

        let expected = PROD_REGISTRY
            .iter()
            .filter(|spec| spec.platforms.contains(&platform))
            .count();
        assert_eq!(
            reported.len(),
            expected,
            "上报数量必须等于平台可执行的 op 数"
        );
    }

    /// 具体到那条踩过的 op：`disk.cleanup.apply` 的占用检查两端都实现了
    /// （Linux `/proc` / macOS libproc），所以两端都必须上报。
    #[test]
    fn cleanup_apply_is_advertised_on_every_supported_platform() {
        let reported = capabilities().opcodes;
        assert!(
            reported.iter().any(|op| op == "disk.cleanup.apply"),
            "apply 在 linux/macos 上都能跑，必须在能力名单里"
        );
        assert!(
            reported.iter().any(|op| op == "disk.cleanup.preview"),
            "disk.cleanup.preview 支持 linux+macos，不该被平台过滤掉"
        );
    }

    #[test]
    fn no_op_is_registered_twice() {
        let mut ids: Vec<&str> = PROD_REGISTRY.iter().map(|spec| spec.id).collect();
        let registered = ids.len();
        ids.sort_unstable();
        ids.dedup();
        assert_eq!(ids.len(), registered, "注册表里不许有重名 op");
    }

    #[test]
    fn unknown_op_is_an_error_code_not_a_panic() {
        assert!(lookup("nope.nope").is_none());
    }

    #[test]
    fn budget_larger_than_step_timeout_is_rejected_before_the_handler_runs() {
        let spec = lookup("test.echo").expect("echo spec");
        let args = serde_json::json!({});
        // echo 的预算是 1000ms；step 只给 500ms。
        let err = execute(spec, &input(&args, 500)).expect_err("should reject");
        assert_eq!(err.code, codes::BUDGET_EXCEEDS_STEP_TIMEOUT);
    }

    #[test]
    fn execute_passes_args_through_and_records_the_caller() {
        let spec = lookup("test.echo").expect("echo spec");
        let args = serde_json::json!({ "a": 1 });
        let output = execute(spec, &input(&args, 1_000)).expect("echo runs");
        assert_eq!(output.value["args"]["a"], 1);
        assert_eq!(output.value["requested_by"], "tester");
    }

    #[test]
    fn risk_levels_are_ordered_r0_to_r3() {
        assert!(risk_rank(RiskLevel::R0) < risk_rank(RiskLevel::R1));
        assert!(risk_rank(RiskLevel::R1) < risk_rank(RiskLevel::R2));
        assert!(risk_rank(RiskLevel::R2) < risk_rank(RiskLevel::R3));
    }
}
