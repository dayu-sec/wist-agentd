//! 安全向调查题共用的小工具：**有界读取 + 覆盖三态 + 时间**。
//!
//! 三个题（`accounts` / `persistence` / `exposure`）都要回答同一件事的三种形态：
//! “这个文件我读到了吗？”——读到、被拒（权限）、还是不存在。把它们混成一种，
//! 就会出现“读不到 = 没有 = 安全”，这是安全类报告最危险的失败方式。
//!
//! 这里只放**没有题目语义**的东西；判定规则留在各自的 `investigate_<topic>.rs`。

use std::fs;
use std::io;
use std::path::{Path, PathBuf};
use std::time::SystemTime;

use crate::investigate::{Coverage, Row};

/// 近多少天内的变更加一条警告（新增授权 / 新单元 / 新 key 是最值得人看一眼的变化）。
pub(crate) const RECENT_DAYS: u64 = 7;

/// 覆盖三态的计数器。只在“读一个具体来源”时用：`checked` 读到了，`denied` 权限不足，
/// `skipped` 不存在 / 类型不对 / 超出预算。
#[derive(Debug, Default, Clone, Copy)]
pub(crate) struct Tally {
    pub(crate) checked: usize,
    pub(crate) denied: usize,
    pub(crate) skipped: usize,
}

impl Tally {
    /// 读一个来源。
    ///
    /// `checked` 记的是**检查次数**（包含不存在与读不了的）：这样一节只要看过任意一个来源，
    /// 就必然带 `coverage`，不会出现“零计数被当成没有边界”。`denied` / `skipped` 再细分原因。
    pub(crate) fn read(&mut self, path: &Path) -> Option<String> {
        self.checked += 1;
        match fs::read_to_string(path) {
            Ok(text) => Some(text),
            Err(err) => {
                self.count_error(&err);
                None
            }
        }
    }

    pub(crate) fn list(&mut self, path: &Path) -> Option<Vec<PathBuf>> {
        self.checked += 1;
        match fs::read_dir(path) {
            Ok(entries) => Some(entries.flatten().map(|entry| entry.path()).collect()),
            Err(err) => {
                self.count_error(&err);
                None
            }
        }
    }

    fn count_error(&mut self, err: &io::Error) {
        if err.kind() == io::ErrorKind::PermissionDenied {
            self.denied += 1;
        } else {
            self.skipped += 1;
        }
    }

    pub(crate) fn coverage(self) -> Coverage {
        Coverage::new(self.checked, self.denied, self.skipped)
    }
}

/// `symlink_metadata`：不跟随符号链接（“这个文件是链接”本身就是证据）。
pub(crate) fn metadata_of(path: &Path) -> Option<fs::Metadata> {
    fs::symlink_metadata(path).ok()
}

/// 文件距今多少天。读不到时间戳时返回 `None`（不是 0 天，也不是“很旧”）。
pub(crate) fn age_days(metadata: &fs::Metadata) -> Option<u64> {
    let modified = metadata.modified().ok()?;
    let age = SystemTime::now().duration_since(modified).ok()?;
    Some(age.as_secs() / 86_400)
}

/// 截到 `top` 行，返回被截掉的数量（调用方必须把这个数字说出来）。
pub(crate) fn truncate_rows(mut rows: Vec<Row>, top: usize) -> (Vec<Row>, usize) {
    let total = rows.len();
    rows.truncate(top);
    (rows, total.saturating_sub(top))
}
