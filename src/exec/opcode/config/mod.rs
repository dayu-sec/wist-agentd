//! `config.*`：配置的只读体检（`inspect`）与**可回滚的变更**（`backup` / `apply` / `rollback`）。
//!
//! 变更是**一条链**，不是三个独立动作：
//!
//! ```text
//! config.backup ──► config.apply ──► config.rollback
//!    (R2)              (R2)              (R2)
//!      │                 │                  │
//!      └── 备份记录 ──────┴──── apply 必须看到它，否则一个字节都不写
//! ```
//!
//! 四条硬约束（设计 §2.6「备份失败即中止；后验不过自动回滚」）：
//!
//! 1. **没备份就不写**：`apply` 找不到本次 `action_id` 的备份记录 → `backup_missing`，
//!    目标文件保持原样。备份目录必须由执行器显式给出，`None` 时直接 `backup_unavailable`
//!    —— 绝不「悄悄跳过备份」。
//! 2. **写前三道闸**：staged 文件摘要必须等于计划声明的 `source_sha256`；目标当前内容必须
//!    仍等于备份时的内容（否则别人在我们备份之后改过 → `target_changed`）；内容能按需解析
//!    （`format`）。
//! 3. **写后必验**：重新读回、摘要比对、按需解析；验不过**自动回滚**并报 `verify_failed`
//!    （回滚本身也失败时，detail 会直接说「回滚也失败」，不会假装没事）。
//! 4. **回滚也验**：恢复后的摘要必须等于备份摘要。
//!
//! 落盘是「同目录临时文件 → fsync → 保留 mode/owner → rename」，不是 `write` 截断重写：
//! 后者在写一半时断电会把配置变成半截内容。

mod backup;
mod change;
mod inspect;
mod store;

#[cfg(test)]
mod tests;

pub use backup::BACKUP_SPEC;
pub use change::{APPLY_SPEC, ROLLBACK_SPEC};
pub use inspect::INSPECT_SPEC;
