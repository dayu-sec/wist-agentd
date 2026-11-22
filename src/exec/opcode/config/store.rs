//! 本次执行的配置备份：`<backup_root>/<action_id>/<sha16>-<basename>/`。
//!
//! 目录布局（一个 action 一个目录，一个文件一个槽）：
//!
//! ```text
//! <state>/action_backups/<action_id>/<sha16>-nginx.conf/
//!     meta.json     # 原文件的路径 / 摘要 / 大小 / mode / uid / gid
//!     content.bak   # 原始字节
//! ```
//!
//! 为什么按 `action_id` 分目录而不是按路径：一次响应对「这份文件」只该有一个前像。
//! 同一个 action 里重跑 `config.backup` 会**复用第一次**的备份（见 [`Backups::save`]），
//! 否则重试会把「已经被改过的内容」当成原始快照 —— 那会让回滚变成 apply。

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt, PermissionsExt};
use std::os::unix::io::AsRawFd;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use wist_shared::fs::{read_json, write_json_atomic};
use wist_shared::time::now_rfc3339;

use crate::exec::opcode::file::{sha256_hex, to_hex};
use crate::exec::opcode::{BackupContext, OpError, codes};

/// 备份文件大小上限：配置不是数据集，超过这个量级就不该走「可回滚的变更」。
pub(super) const MAX_BACKUP_BYTES: u64 = 8 * 1024 * 1024;
const META_FILE: &str = "meta.json";
const CONTENT_FILE: &str = "content.bak";
const SCHEMA: &str = "wist.config_backup/v1";

/// 一份备份的元数据（落在 `meta.json`，回滚与审计都读它）。
#[derive(Debug, Clone, Serialize, Deserialize)]
pub(super) struct BackupMeta {
    pub schema: String,
    pub action_id: String,
    /// 计划里写的路径（原样，便于对账）。
    pub path: String,
    /// 实际读写的 canonical 路径（回滚时即使文件已被删，也用它定位）。
    pub canonical_path: String,
    pub backup_file: String,
    pub sha256: String,
    pub size_bytes: u64,
    /// 权限位（`0o7777` 掩码后的值）。
    pub mode: u32,
    pub uid: u32,
    pub gid: u32,
    pub created_at: String,
}

/// 一个执行内的备份仓库。
pub(super) struct Backups {
    root: PathBuf,
    action_id: String,
}

impl Backups {
    /// `action_id` 会直接进目录名：契约只要求「非空」，这里必须自己再判一次字符集，
    /// 否则 `../..` 之类的 ID 能把备份写到备份根之外。
    pub(super) fn open(context: &BackupContext<'_>) -> Result<Self, OpError> {
        let action_id = context.action_id.trim();
        let valid = !action_id.is_empty()
            && action_id.len() <= 128
            && action_id
                .chars()
                .all(|ch| ch.is_ascii_alphanumeric() || matches!(ch, '-' | '_' | '.'));
        if !valid {
            return Err(OpError::new(
                codes::INVALID_ARGS,
                format!("action_id 不能用作备份目录名：{action_id:?}"),
            ));
        }
        Ok(Self {
            root: context.root.join(action_id),
            action_id: action_id.to_string(),
        })
    }

    /// 一个文件的备份槽：`<sha16>-<sanitized basename>`。
    fn slot(&self, canonical: &Path) -> PathBuf {
        let digest = sha256_hex(canonical.as_os_str().as_encoded_bytes());
        let mut base: String = canonical
            .file_name()
            .map(|name| name.to_string_lossy().to_string())
            .unwrap_or_default()
            .chars()
            .map(|ch| {
                if ch.is_ascii_alphanumeric() || matches!(ch, '.' | '_' | '-') {
                    ch
                } else {
                    '_'
                }
            })
            .take(40)
            .collect();
        if base.is_empty() {
            base.push_str("file");
        }
        self.root.join(format!("{}-{base}", &digest[..16]))
    }

    /// 读已有备份（按 canonical 路径定位槽）。坏 meta 当作「没有备份」
    /// ——**宁可不写，也不拿坏记录当真**。
    pub(super) fn load(&self, canonical: &Path) -> Option<BackupMeta> {
        let meta: BackupMeta = read_json(&self.slot(canonical).join(META_FILE)).ok()?;
        (meta.schema == SCHEMA).then_some(meta)
    }

    /// 按**计划里写的路径**找备份。
    ///
    /// 回滚要用它：目标文件可能已经被删掉了，那时没法 canonicalize，只能凭
    /// 备份记录里的 `path` / `canonical_path` 对。命中的记录还必须再过一道
    /// `allow.paths`（见 `change.rs`）：meta 文件自己也可能被人改过。
    pub(super) fn find(&self, requested: &str) -> Option<BackupMeta> {
        let entries = fs::read_dir(&self.root).ok()?;
        for entry in entries.flatten() {
            let Ok(meta) = read_json::<BackupMeta>(&entry.path().join(META_FILE)) else {
                continue;
            };
            if meta.schema != SCHEMA {
                continue;
            }
            if meta.path == requested || meta.canonical_path == requested {
                return Some(meta);
            }
        }
        None
    }

    /// 落一份备份。已存在同路径备份时**保持不变**并返回它（第二项 `false`）。
    pub(super) fn save(
        &self,
        path: &str,
        canonical: &Path,
        bytes: &[u8],
        mode: u32,
        uid: u32,
        gid: u32,
    ) -> Result<(BackupMeta, bool), OpError> {
        if let Some(existing) = self.load(canonical) {
            return Ok((existing, false));
        }
        let slot = self.slot(canonical);
        fs::create_dir_all(&slot).map_err(|err| {
            OpError::new(
                codes::BACKUP_UNAVAILABLE,
                format!("创建备份目录失败 {}：{err}", slot.display()),
            )
        })?;
        write_bytes_atomic(&slot.join(CONTENT_FILE), bytes, None)?;
        let meta = BackupMeta {
            schema: SCHEMA.to_string(),
            action_id: self.action_id.clone(),
            path: path.to_string(),
            canonical_path: canonical.display().to_string(),
            backup_file: CONTENT_FILE.to_string(),
            sha256: sha256_hex(bytes),
            size_bytes: bytes.len() as u64,
            mode,
            uid,
            gid,
            created_at: now_rfc3339(),
        };
        write_json_atomic(&slot.join(META_FILE), &meta).map_err(|err| {
            OpError::new(
                codes::BACKUP_UNAVAILABLE,
                format!("写入备份元数据失败：{err}"),
            )
        })?;
        Ok((meta, true))
    }

    /// 读回备份内容（回滚用）。内容与 meta 摘要对不上时**拒绝**：
    /// 备份文件自己坏了，就不能拿它去覆盖线上配置。
    pub(super) fn read_content(&self, meta: &BackupMeta) -> Result<Vec<u8>, OpError> {
        let path = self
            .slot(Path::new(&meta.canonical_path))
            .join(&meta.backup_file);
        let bytes = fs::read(&path).map_err(|err| {
            OpError::new(
                codes::BACKUP_UNAVAILABLE,
                format!("读取备份内容失败 {}：{err}", path.display()),
            )
        })?;
        if sha256_hex(&bytes) != meta.sha256 {
            return Err(OpError::new(
                codes::BACKUP_UNAVAILABLE,
                "备份文件内容与 meta 记录的摘要不一致（备份已损坏）".to_string(),
            ));
        }
        Ok(bytes)
    }
}

/// 原子写：同目录临时文件 → 写满 → fsync → 设属主/权限 → rename。
///
/// `preserved` 为 `None` 时（写备份文件本身）只写内容。
/// 顺序是 **fchown 再 chmod**：Linux 上 chown 会清掉 setuid/setgid，反过来的话权限会丢。
pub(super) fn write_bytes_atomic(
    path: &Path,
    bytes: &[u8],
    preserved: Option<(u32, u32, u32)>,
) -> Result<(), OpError> {
    let parent = path.parent().ok_or_else(|| {
        OpError::new(
            codes::WRITE_FAILED,
            format!("目标没有父目录：{}", path.display()),
        )
    })?;
    let file_name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "file".to_string());
    let tmp = parent.join(format!(
        ".{file_name}.wist-tmp-{}-{}",
        std::process::id(),
        to_hex(&nanos().to_le_bytes())
    ));

    let result = (|| -> std::io::Result<()> {
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&tmp)?;
        file.write_all(bytes)?;
        file.sync_all()?;
        if let Some((mode, uid, gid)) = preserved {
            // 只在实际不同时才 chown：root 改自己是多余操作，非 root 改「自己」也常常被拒。
            let meta = file.metadata()?;
            if meta.uid() != uid || meta.gid() != gid {
                let rc = unsafe { libc::fchown(file.as_raw_fd(), uid, gid) };
                if rc != 0 {
                    // 不能假装保留了属主：配置文件属主悄悄变了会直接影响读它的服务。
                    return Err(std::io::Error::last_os_error());
                }
            }
            file.set_permissions(fs::Permissions::from_mode(mode))?;
        }
        fs::rename(&tmp, path)
    })();

    if let Err(err) = result {
        let _ = fs::remove_file(&tmp);
        return Err(OpError::new(
            codes::WRITE_FAILED,
            format!("写入 {} 失败：{err}", path.display()),
        ));
    }
    Ok(())
}

/// 只给临时文件名一个稳定来源。
fn nanos() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_nanos() as u64)
        .unwrap_or(0)
}

/// 读一个普通文件的全部内容（带上限）。超过上限直接报错，不截断 ——
/// 备份半截文件等于没有备份。
pub(super) fn read_capped(file: &mut fs::File, limit: u64) -> Result<Vec<u8>, OpError> {
    let mut bytes = Vec::new();
    file.take(limit + 1)
        .read_to_end(&mut bytes)
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取文件失败：{err}")))?;
    if bytes.len() as u64 > limit {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("文件超过 {limit} 字节上限，不备份也不覆盖"),
        ));
    }
    Ok(bytes)
}
