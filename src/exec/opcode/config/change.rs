//! `config.apply` / `config.rollback`（R2）：可回滚的配置替换。
//!
//! `apply` 的五道关（前四道都在**写之前**，第五道在写之后）：
//!
//! 1. 本次 `action_id` 必须有 `config.backup` 留下的记录（`backup_missing`）；
//! 2. `source`（暂存的新文件）摘要必须等于计划声明的 `source_sha256`；
//! 3. 目标当前内容必须仍等于**备份时**的内容（否则别人在我们备份后改过 → `target_changed`）；
//! 4. 新内容能按需解析（`format`，默认 `auto`：认得出扩展名就验，认不出就明说跳过）；
//! 5. 写后重读：摘要 + 解析。不过 → **自动回滚**，报 `verify_failed`。
//!
//! `rollback` 不做格式闸门：它的语义就是「把原样放回去」，原始内容哪怕本身不合法
//! 也要还原（只把解析结果作为**信息**报出来）。它只挡两件事：没有备份记录；
//! 或者调用方给了 `expect_sha256` 而当前内容已经不是我们写进去的那一版。

use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::json;
use wist_contracts::action_plan::RiskLevel;

use crate::exec::opcode::file::{ensure_allowed, open_regular, resolve_allowed, sha256_hex};
use crate::exec::opcode::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

use super::inspect::{Format, format_from_extension, parse_as};
use super::store::{BackupMeta, Backups, MAX_BACKUP_BYTES, read_capped, write_bytes_atomic};

const SCHEMA_APPLY: &str = "wist.opcode.config_apply/v1";
const SCHEMA_ROLLBACK: &str = "wist.opcode.config_rollback/v1";

pub const APPLY_SPEC: OpSpec = OpSpec {
    id: "config.apply",
    risk: RiskLevel::R2,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(8_000, 1, 0),
    handler: apply,
};

pub const ROLLBACK_SPEC: OpSpec = OpSpec {
    id: "config.rollback",
    risk: RiskLevel::R2,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(8_000, 1, 0),
    handler: rollback,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyArgs {
    /// 被替换的目标文件。
    path: String,
    /// 暂存的新内容（也必须在 `allow.paths` 内）。
    source: String,
    /// 暂存内容的 sha256（小写 hex）。**必填**：不声明摘要就没法证明写进去的是什么。
    source_sha256: String,
    /// `auto`（默认）/ `none` / `toml` / `json` / `env`。
    #[serde(default)]
    format: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RollbackArgs {
    path: String,
    /// 只在「当前内容确实是我们写进去的那一版」时才回滚。
    #[serde(default)]
    expect_sha256: Option<String>,
}

/// 写前/写后要不要做语法校验。
enum FormatPolicy {
    /// 明确跳过（用于 `nginx.conf` 这类我们没有解析器的文件）。
    Skip,
    /// 认得出扩展名就验（默认）。
    Auto,
    Explicit(Format),
}

impl FormatPolicy {
    fn parse(value: Option<&str>) -> Result<Self, OpError> {
        match value.unwrap_or("auto") {
            "none" => Ok(Self::Skip),
            "auto" => Ok(Self::Auto),
            other => Format::parse(other).map(Self::Explicit),
        }
    }
}

/// 按 policy 校验一段内容。`Ok(None)` = 按策略跳过（不是「验过」）。
fn validate(
    path: &Path,
    bytes: &[u8],
    policy: &FormatPolicy,
) -> Result<Option<&'static str>, OpError> {
    let format = match policy {
        FormatPolicy::Skip => return Ok(None),
        FormatPolicy::Explicit(format) => *format,
        FormatPolicy::Auto => match format_from_extension(path) {
            Some(format) => format,
            None => return Ok(None),
        },
    };
    let text = std::str::from_utf8(bytes)
        .map_err(|_| OpError::new(codes::INVALID_CONFIG, "内容不是合法 UTF-8".to_string()))?;
    parse_as(format, text)
        .map(|_| Some(format.id()))
        .map_err(|failure| OpError::new(codes::INVALID_CONFIG, failure.describe()))
}

fn normalize_sha(value: &str) -> Result<String, OpError> {
    let value = value.trim().to_ascii_lowercase();
    let valid = value.len() == 64 && value.bytes().all(|byte| byte.is_ascii_hexdigit());
    if !valid {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            "sha256 必须是 64 位小写十六进制".to_string(),
        ));
    }
    Ok(value)
}

fn backups_for<'a>(input: &'a OpInput<'a>) -> Result<Backups, OpError> {
    let context = input.backups.ok_or_else(|| {
        OpError::new(
            codes::BACKUP_UNAVAILABLE,
            "执行器没有配置备份目录：`config.*` 变更一律拒绝（不允许悄悄跳过备份）",
        )
    })?;
    Backups::open(context)
}

/// 读一个文件的全部内容（带上限）。
fn read_file(path: &Path, limit: u64) -> Result<Vec<u8>, OpError> {
    let (mut file, _) = open_regular(path)?;
    read_capped(&mut file, limit)
}

/// 写后重读并核对：摘要必须一致；policy 要求时还要能解析。
fn verify_written(
    path: &Path,
    expect_sha: &str,
    policy: &FormatPolicy,
) -> Result<Option<&'static str>, String> {
    let bytes = read_file(path, MAX_BACKUP_BYTES).map_err(|err| err.detail)?;
    let actual = sha256_hex(&bytes);
    if actual != expect_sha {
        return Err(format!("写后摘要不一致：期望 {expect_sha}，实际 {actual}"));
    }
    validate(path, &bytes, policy).map_err(|err| err.detail)
}

/// 把备份原样写回去（`apply` 的自救路径与 `config.rollback` 共用）。
fn restore(path: &Path, meta: &BackupMeta, store: &Backups) -> Result<Vec<u8>, OpError> {
    let bytes = store.read_content(meta)?;
    write_bytes_atomic(path, &bytes, Some((meta.mode, meta.uid, meta.gid)))?;
    Ok(bytes)
}

pub(super) fn apply(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: ApplyArgs = parse_args(input.args)?;
    let policy = FormatPolicy::parse(args.format.as_deref())?;
    let declared = normalize_sha(&args.source_sha256)?;
    let store = backups_for(input)?;

    // ① 备份必须在
    let canonical = resolve_allowed(&args.path, input.allow_paths)?;
    let backup = store.load(&canonical).ok_or_else(|| {
        OpError::new(
            codes::BACKUP_MISSING,
            format!(
                "本次执行没有 `{}` 的备份记录；必须先跑 `config.backup`（本次不写任何字节）",
                args.path
            ),
        )
    })?;

    // ② 暂存文件摘要
    let source_path = resolve_allowed(&args.source, input.allow_paths)?;
    let source_bytes = read_file(&source_path, MAX_BACKUP_BYTES)?;
    let source_sha = sha256_hex(&source_bytes);
    if source_sha != declared {
        return Err(OpError::new(
            codes::SOURCE_HASH_MISMATCH,
            format!(
                "staged 文件摘要 {source_sha} 与计划声明的 {declared} 不一致（本次不写任何字节）"
            ),
        ));
    }

    // ③ 目标必须还是备份时那一份
    let current = read_file(&canonical, MAX_BACKUP_BYTES)?;
    let current_sha = sha256_hex(&current);
    if current_sha != backup.sha256 {
        return Err(OpError::new(
            codes::TARGET_CHANGED,
            format!(
                "目标在备份之后被改过（备份 {} / 现在 {}）；拒绝覆盖（本次不写任何字节）",
                backup.sha256, current_sha
            ),
        ));
    }

    // ④ 新内容能解析（按策略）
    let parsed = validate(&canonical, &source_bytes, &policy)?;

    // ⑤ 写 → 验 → 不过就回滚
    write_bytes_atomic(
        &canonical,
        &source_bytes,
        Some((backup.mode, backup.uid, backup.gid)),
    )?;
    let verified = match verify_written(&canonical, &source_sha, &policy) {
        Ok(parsed_after) => parsed_after,
        Err(reason) => {
            let rolled_back = restore(&canonical, &backup, &store).is_ok();
            let detail = if rolled_back {
                format!("写后校验失败，已自动回滚到备份：{reason}")
            } else {
                format!("写后校验失败，且回滚也失败（需要人工介入）：{reason}")
            };
            return Err(OpError::new(codes::VERIFY_FAILED, detail));
        }
    };

    let mut notes = vec![
        "写盘是「同目录临时文件 → fsync → 保留属主/权限 → rename」，不是截断重写".to_string(),
        "备份仍在 state 目录：需要时可用 `config.rollback` 还原".to_string(),
    ];
    if matches!(policy, FormatPolicy::Auto) && parsed.is_none() {
        notes.push("目标扩展名认不出解析格式：本次没有做语法校验（只验了摘要）".to_string());
    }

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_APPLY,
            "path": args.path,
            "canonical": canonical.display().to_string(),
            "source": source_path.display().to_string(),
            "written": {
                "sha256": source_sha,
                "size_bytes": source_bytes.len(),
                "mode": format!("{:04o}", backup.mode),
                "uid": backup.uid,
                "gid": backup.gid,
            },
            "replaced": { "sha256": backup.sha256, "size_bytes": backup.size_bytes },
            "verify": {
                "hash": true,
                "parse": verified.or(parsed),
            },
            "rolled_back": false,
            "notes": notes,
        }),
    })
}

pub(super) fn rollback(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: RollbackArgs = parse_args(input.args)?;
    let store = backups_for(input)?;

    let backup = store.find(&args.path).ok_or_else(|| {
        OpError::new(
            codes::BACKUP_MISSING,
            format!("本次执行没有 `{}` 的备份记录，无法回滚", args.path),
        )
    })?;
    // 目标可能已经被删了，所以用备份记录里的 canonical 路径；但**白名单必须再过一遍**
    // —— meta.json 也是磁盘上的文件，不能无条件相信它。
    let canonical = PathBuf::from(&backup.canonical_path);
    ensure_allowed(&canonical, input.allow_paths, &args.path)?;

    if let Some(expected) = args.expect_sha256.as_deref() {
        let expected = normalize_sha(expected)?;
        match fs::read(&canonical) {
            Ok(current) => {
                let actual = sha256_hex(&current);
                if actual != expected {
                    return Err(OpError::new(
                        codes::TARGET_CHANGED,
                        format!(
                            "目标当前摘要 {actual} 不是调用方声明的 {expected}；拒绝回滚（可能有别人的改动）"
                        ),
                    ));
                }
            }
            // 文件被删掉了：照样恢复（这正是回滚该做的事）。
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => {
                return Err(OpError::new(
                    codes::OP_FAILED,
                    format!("读取目标失败 {}：{err}", canonical.display()),
                ));
            }
        }
    }

    let restored_bytes = restore(&canonical, &backup, &store)?;
    // 复核：写回去的必须就是备份里那份。
    let after = read_file(&canonical, MAX_BACKUP_BYTES)?;
    let after_sha = sha256_hex(&after);
    if after_sha != backup.sha256 {
        return Err(OpError::new(
            codes::VERIFY_FAILED,
            format!("回滚后摘要 {after_sha} 与备份 {} 不一致", backup.sha256),
        ));
    }

    // 解析结果只作信息：回滚的语义是「原样放回去」，原始内容本身不合法也要还。
    let parse = validate(&canonical, &restored_bytes, &FormatPolicy::Auto)
        .map(|format| json!({ "format": format, "ok": true }))
        .unwrap_or_else(|err| json!({ "ok": false, "error": err.detail }));

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_ROLLBACK,
            "path": args.path,
            "canonical": canonical.display().to_string(),
            "restored": {
                "sha256": backup.sha256,
                "size_bytes": backup.size_bytes,
                "mode": format!("{:04o}", backup.mode),
                "uid": backup.uid,
                "gid": backup.gid,
            },
            "verify": { "hash": true, "parse": parse },
            "notes": [
                "回滚的语义是「原样放回去」：备份内容本身不合法也会被还原（parse 只作信息）",
                "备份记录不会被删除：重复回滚是幂等的"
            ],
        }),
    })
}
