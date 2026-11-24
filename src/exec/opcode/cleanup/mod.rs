//! `disk.cleanup.*`：清理**过期临时文件**与**已轮转日志**。
//!
//! 为什么拆成两个 opcode 而不是一个带 `dry_run` 开关：
//!
//! * `preview` 是 R0，只读，可以全量放给所有机器；
//! * `apply` 是 R2，写入，必须显式带上限。
//!
//! 拆开之后，契约里**构造不出「只想看却删了」这种状态**。
//!
//! 共同的硬约束：
//!
//! 1. **参数里没有任意路径**：`target` 是闭集，根目录写死在代码里；
//! 2. **年龄下限硬编码**：低于下限直接报错，不静默夹紧；
//! 3. **只删普通文件**：symlink / 硬链接 / 跨挂载点 / 受保护名 / 被占用文件全部跳过并计数；
//! 4. **`apply` 先定格再删**：扫描不完整或候选超上限都中止，绝不边删边算；
//! 5. **删前再确认一次**：扫描与删除之间的时间窗里路径可能被换掉（重建 / 变链接 / 被写），
//!    删除前逐条复查“还是那个旧的普通文件”，不成立就跳过并记 `changed_since_scan`。
//!
//! 明确不做：清空正在写的日志（`truncate`）、systemd journal（归 journald）、
//! 对全机队定时清理（那是策略，不是一次响应）。

use std::path::PathBuf;
use std::time::{Duration, Instant};

use serde::Deserialize;
use serde_json::{Value, json};
use wist_contracts::action_plan::RiskLevel;

use super::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

mod apply;
mod scan;

const PREVIEW_SCHEMA: &str = "wist.opcode.disk_cleanup_preview/v1";
const APPLY_SCHEMA: &str = "wist.opcode.disk_cleanup_apply/v1";

const DEFAULT_MAX_ITEMS: usize = 200;
const MAX_MAX_ITEMS: usize = 1_000;
const MAX_APPLY_FILES: u32 = 5_000;
const MAX_APPLY_BYTES: u64 = 8 * 1024 * 1024 * 1024;
const MAX_AGE_HOURS: u32 = 8_760;

pub const PREVIEW_SPEC: OpSpec = OpSpec {
    id: "disk.cleanup.preview",
    risk: RiskLevel::R0,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(5_000, MAX_MAX_ITEMS, 0),
    handler: preview,
};

/// `apply` 在 Linux 与 macOS 上开放：两边的占用检查都走「不 exec 就能查」的内核接口
/// （Linux 读 `/proc/<pid>/fd`，macOS 走 libproc 的 vnode fd，见 `scan::open_paths`）。
///
/// 为什么占用检查是硬前提：删掉一个被进程打开着的文件**不释放空间**（inode 要等最后一个
/// 句柄关闭），而且进程会继续往一个看不见的文件里写 —— 现场看到的是「清理了但磁盘没变」。
/// 查不了占用的平台宁可不上报这个 op，也不赌一把（另：`apply` 本身也不接受
/// `include_open_files=true`）。
///
/// `budget.max_duration_ms` 封的是**扫描**（含占用检查）；
/// 删除阶段不再看时间，它的上限是 `max_files`（≤5000）—— 中途按时间停手会留下
/// “删了一半”的不可预测状态，比多删几个已过期的临时文件更糟。
pub const APPLY_SPEC: OpSpec = OpSpec {
    id: "disk.cleanup.apply",
    risk: RiskLevel::R2,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(15_000, MAX_APPLY_FILES as usize, MAX_APPLY_BYTES),
    handler: apply_cleanup,
};

/// 清理位置。**闭集**：新增值要走词表评审（见实施清单 §1.5），
/// 不允许给调用方一个路径参数。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Target {
    Tmp,
    RotatedLogs,
}

impl Target {
    fn parse(value: &str) -> Result<Self, OpError> {
        match value {
            "tmp" => Ok(Self::Tmp),
            "rotated_logs" => Ok(Self::RotatedLogs),
            other => Err(OpError::new(
                codes::UNSUPPORTED_TARGET,
                format!("未知 target `{other}`（支持：tmp | rotated_logs）"),
            )),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::Tmp => "tmp",
            Self::RotatedLogs => "rotated_logs",
        }
    }

    fn roots(self) -> Vec<PathBuf> {
        // 测试沙箱：只在 `test-cleanup-roots` 特性下生效，发布构建里这段不存在。
        #[cfg(feature = "test-cleanup-roots")]
        if let Ok(dir) = std::env::var("WIST_CLEANUP_ROOT")
            && !dir.trim().is_empty()
        {
            return vec![PathBuf::from(dir)];
        }
        match self {
            Self::Tmp => vec![PathBuf::from("/tmp"), PathBuf::from("/var/tmp")],
            Self::RotatedLogs => vec![PathBuf::from("/var/log")],
        }
    }

    /// 根算 level 0；`1` = 只看根下条目，`2` = 再进一层子目录。
    fn depth(self) -> usize {
        match self {
            Self::Tmp => 1,
            Self::RotatedLogs => 2,
        }
    }

    fn rotated(self) -> bool {
        matches!(self, Self::RotatedLogs)
    }

    fn default_age_hours(self) -> u32 {
        match self {
            Self::Tmp => 24,
            Self::RotatedLogs => 168,
        }
    }

    /// 硬下限：低于它的请求一律拒绝（不夹紧）。
    fn floor_age_hours(self) -> u32 {
        match self {
            Self::Tmp => 1,
            Self::RotatedLogs => 24,
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewArgs {
    target: String,
    #[serde(default)]
    min_age_hours: Option<u32>,
    #[serde(default)]
    max_items: Option<usize>,
    #[serde(default)]
    include_open_files: Option<bool>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyArgs {
    target: String,
    #[serde(default)]
    min_age_hours: Option<u32>,
    max_files: u32,
    max_bytes: u64,
    #[serde(default)]
    include_open_files: Option<bool>,
}

fn resolved_age_hours(target: Target, requested: Option<u32>) -> Result<u32, OpError> {
    let requested = requested.unwrap_or_else(|| target.default_age_hours());
    let floor = target.floor_age_hours();
    if requested < floor {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!(
                "min_age_hours={requested} 低于 `{}` 的硬下限 {floor}h；要清更“新”的文件请换一个 target",
                target.id()
            ),
        ));
    }
    if requested > MAX_AGE_HOURS {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("min_age_hours={requested} 超过上限 {MAX_AGE_HOURS}h"),
        ));
    }
    Ok(requested)
}

fn min_age(hours: u32) -> Duration {
    Duration::from_secs(u64::from(hours) * 3_600)
}

fn scan_roots(
    target: Target,
    age_hours: u32,
    include_open_files: bool,
    budget: Duration,
) -> (Vec<PathBuf>, scan::ScanOutput) {
    let roots = target.roots();
    let output = scan::scan(&scan::ScanRequest {
        roots: &roots,
        depth: target.depth(),
        min_age: min_age(age_hours),
        rotated_names: target.rotated(),
        include_open_files,
        deadline: Instant::now() + budget,
    });
    (roots, output)
}

fn preview(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: PreviewArgs = parse_args(input.args)?;
    let target = Target::parse(&args.target)?;
    let age_hours = resolved_age_hours(target, args.min_age_hours)?;
    let max_items = args
        .max_items
        .unwrap_or(DEFAULT_MAX_ITEMS)
        .clamp(1, input.budget.max_items.clamp(1, MAX_MAX_ITEMS));
    let include_open = args.include_open_files.unwrap_or(false);

    let (roots, scanned) = scan_roots(target, age_hours, include_open, input.budget.duration());

    let files = scanned.candidates.len() as u64;
    let bytes = scanned
        .candidates
        .iter()
        .fold(0u64, |sum, candidate| sum.saturating_add(candidate.bytes));
    let items: Vec<Value> = scanned
        .candidates
        .iter()
        .take(max_items)
        .map(|candidate| {
            json!({
                "path": candidate.path.display().to_string(),
                "bytes": candidate.bytes,
                "age_hours": candidate.age_secs / 3_600,
                "open": candidate.open,
            })
        })
        .collect();
    let listing_truncated = scanned.candidates.len() > max_items;

    Ok(OpOutput {
        value: json!({
            "schema": PREVIEW_SCHEMA,
            "target": target.id(),
            "roots": roots.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "min_age_hours": age_hours,
            "requested_by": input.requested_by,
            "open_files_checked": scanned.open_files_checked,
            "scan": {
                "complete": scanned.complete,
                "entries": scanned.entries,
                "duration_ms": scanned.duration_ms,
            },
            "candidates": { "files": files, "bytes": bytes },
            "items": items,
            "listing_truncated": listing_truncated,
            "skipped": scanned.skipped,
        }),
    })
}

fn apply_cleanup(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: ApplyArgs = parse_args(input.args)?;
    let target = Target::parse(&args.target)?;
    if args.include_open_files.unwrap_or(false) {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            "apply 不支持 include_open_files=true：删除被占用的文件不释放空间".to_string(),
        ));
    }
    if args.max_files == 0 || u64::from(args.max_files) > input.budget.max_items as u64 {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("max_files 必须在 1..={}", input.budget.max_items),
        ));
    }
    if args.max_bytes == 0 || args.max_bytes > input.budget.max_bytes {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("max_bytes 必须在 1..={}", input.budget.max_bytes),
        ));
    }
    let age_hours = resolved_age_hours(target, args.min_age_hours)?;

    let (roots, scanned) = scan_roots(target, age_hours, false, input.budget.duration());
    if !scanned.complete {
        return Err(OpError::new(
            codes::SCAN_INCOMPLETE,
            "扫描未完成（预算 / 权限 / 占用检查被截断），本次不删除任何文件".to_string(),
        ));
    }
    let files = scanned.candidates.len() as u64;
    let bytes = scanned
        .candidates
        .iter()
        .fold(0u64, |sum, candidate| sum.saturating_add(candidate.bytes));
    if files > u64::from(args.max_files) || bytes > args.max_bytes {
        return Err(OpError::new(
            codes::BUDGET_EXCEEDED,
            format!(
                "候选 {files} 个 / {bytes} 字节，超过本次上限 {} 个 / {} 字节；未删除任何文件",
                args.max_files, args.max_bytes
            ),
        ));
    }

    let probe = roots.first().map(PathBuf::as_path);
    let free_before = probe.and_then(apply::free_space_for);
    let outcome = apply::delete_all(&scanned.candidates, min_age(age_hours));
    let free_after = probe.and_then(apply::free_space_for);

    if outcome.deleted_files == 0 && !outcome.errors.is_empty() {
        let first = outcome
            .errors
            .first()
            .map(|err| format!("{}（{}）", err.path, err.code))
            .unwrap_or_default();
        return Err(OpError::new(
            codes::OP_FAILED,
            format!("{} 个文件全部删除失败；首个：{first}", outcome.error_total),
        ));
    }

    let partial = outcome.deleted_files > 0 && !outcome.errors.is_empty();
    let errors: Vec<Value> = outcome
        .errors
        .iter()
        .map(|err| json!({ "path": err.path, "code": err.code }))
        .collect();
    let free_space = match (free_before, free_after) {
        (Some((mount, before)), Some((_, after))) => json!({
            "mount": mount,
            "before_bytes": before,
            "after_bytes": after,
        }),
        _ => Value::Null,
    };

    Ok(OpOutput {
        value: json!({
            "schema": APPLY_SCHEMA,
            "target": target.id(),
            "roots": roots.iter().map(|path| path.display().to_string()).collect::<Vec<_>>(),
            "min_age_hours": age_hours,
            "requested_by": input.requested_by,
            "open_files_checked": scanned.open_files_checked,
            "scan": {
                "complete": scanned.complete,
                "entries": scanned.entries,
                "duration_ms": scanned.duration_ms,
            },
            "candidates": { "files": files, "bytes": bytes },
            "deleted": { "files": outcome.deleted_files, "bytes": outcome.deleted_bytes },
            "skipped": scanned.skipped,
            "errors": errors,
            "errors_omitted": outcome.error_total.saturating_sub(errors.len() as u64),
            "partial": partial,
            "freed_bytes": outcome.deleted_bytes,
            "free_space": free_space,
            "limits": {
                "max_files": args.max_files,
                "max_bytes": args.max_bytes,
                "aborted": false,
            },
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input<'a>(args: &'a serde_json::Value) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: &[],
            budget: PREVIEW_SPEC.budget,
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    fn apply_input<'a>(args: &'a serde_json::Value) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: &[],
            budget: APPLY_SPEC.budget,
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    #[test]
    fn target_is_a_closed_set() {
        assert_eq!(Target::parse("tmp").unwrap(), Target::Tmp);
        assert_eq!(Target::parse("rotated_logs").unwrap(), Target::RotatedLogs);
        let err = Target::parse("everything").expect_err("unknown target");
        assert_eq!(err.code, codes::UNSUPPORTED_TARGET);
    }

    #[test]
    fn age_below_the_floor_is_rejected_instead_of_clamped() {
        let args = serde_json::json!({ "target": "tmp", "min_age_hours": 0 });
        let err = preview(&input(&args)).expect_err("0h is below the floor");
        assert_eq!(err.code, codes::INVALID_ARGS);
        assert!(err.detail.contains("硬下限"), "{}", err.detail);
    }

    #[test]
    fn apply_requires_explicit_limits() {
        let args = serde_json::json!({ "target": "tmp" });
        let err = apply_cleanup(&apply_input(&args)).expect_err("max_files/max_bytes are required");
        assert_eq!(err.code, codes::INVALID_ARGS);
    }

    #[test]
    fn apply_limits_cannot_exceed_the_registered_budget() {
        // 预算从注册表取（5000）：这个上限是契约的一部分，不是 handler 里的常量。
        let args = serde_json::json!({
            "target": "tmp", "max_files": 5_001, "max_bytes": 1024
        });
        let err = apply_cleanup(&apply_input(&args)).expect_err("above budget");
        assert_eq!(err.code, codes::INVALID_ARGS);
        assert!(err.detail.contains("5000"), "{}", err.detail);
    }

    #[test]
    fn apply_rejects_zero_limits_and_open_files() {
        let zero = serde_json::json!({
            "target": "tmp", "max_files": 0, "max_bytes": 1024
        });
        assert_eq!(
            apply_cleanup(&apply_input(&zero)).expect_err("zero").code,
            codes::INVALID_ARGS
        );

        let open = serde_json::json!({
            "target": "tmp", "max_files": 1, "max_bytes": 1024, "include_open_files": true
        });
        let err = apply_cleanup(&apply_input(&open)).expect_err("open files unsupported");
        assert_eq!(err.code, codes::INVALID_ARGS);
        assert!(err.detail.contains("include_open_files"), "{}", err.detail);
    }

    #[test]
    fn unknown_args_are_rejected() {
        let args = serde_json::json!({ "target": "tmp", "nope": 1 });
        let err = preview(&input(&args)).expect_err("unknown field");
        assert_eq!(err.code, codes::INVALID_ARGS);
    }

    #[test]
    fn op_metadata_matches_the_plan() {
        assert_eq!(PREVIEW_SPEC.risk, RiskLevel::R0);
        assert_eq!(APPLY_SPEC.risk, RiskLevel::R2);
        // 两端的占用检查都基于内核接口（`/proc` / libproc），所以两端都能上 `apply`。
        assert!(APPLY_SPEC.platforms.contains(&"linux"));
        assert!(APPLY_SPEC.platforms.contains(&"macos"));
    }
}
