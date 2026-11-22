//! `config.backup`（R2）：把目标文件的原样 + 元数据存进**本次执行**的备份目录。
//!
//! 它是 `config.apply` 的前置闸门：没有这条记录，`apply` 一个字节都不写。
//! 同一 `action_id` 里重跑会复用第一份备份（`created = false`），原因见 `store.rs`。

use std::os::unix::fs::MetadataExt;

use serde::Deserialize;
use serde_json::json;
use wist_contracts::action_plan::RiskLevel;

use crate::exec::opcode::file::{open_regular, resolve_allowed};
use crate::exec::opcode::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

use super::store::{Backups, MAX_BACKUP_BYTES, read_capped};

const SCHEMA: &str = "wist.opcode.config_backup/v1";

pub const BACKUP_SPEC: OpSpec = OpSpec {
    id: "config.backup",
    risk: RiskLevel::R2,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(5_000, 1, 0),
    handler: backup,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct BackupArgs {
    path: String,
}

pub(super) fn backup(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: BackupArgs = parse_args(input.args)?;
    let context = input.backups.ok_or_else(|| {
        OpError::new(
            codes::BACKUP_UNAVAILABLE,
            "执行器没有配置备份目录：`config.*` 变更一律拒绝（不允许悄悄跳过备份）",
        )
    })?;
    let store = Backups::open(context)?;
    let canonical = resolve_allowed(&args.path, input.allow_paths)?;
    let (mut file, metadata) = open_regular(&canonical)?;
    let bytes = read_capped(&mut file, MAX_BACKUP_BYTES)?;

    let (meta, created) = store.save(
        &args.path,
        &canonical,
        &bytes,
        metadata.mode() & 0o7777,
        metadata.uid(),
        metadata.gid(),
    )?;

    let mut notes = vec![
        "同一 action_id 只保留第一份备份：重跑不会把已经改动过的内容当成原始快照".to_string(),
        "备份只存在本机 state 目录；中心侧不留配置内容副本".to_string(),
    ];
    if !created {
        notes.push("本次执行已有同一文件的备份，本次未覆盖它".to_string());
    }

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA,
            "path": args.path,
            "canonical": canonical.display().to_string(),
            "created": created,
            "backup": {
                "sha256": meta.sha256,
                "size_bytes": meta.size_bytes,
                "mode": format!("{:04o}", meta.mode),
                "uid": meta.uid,
                "gid": meta.gid,
                "created_at": meta.created_at,
            },
            "notes": notes,
        }),
    })
}
