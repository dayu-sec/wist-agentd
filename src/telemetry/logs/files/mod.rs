//! 文件型日志采集运行时（file input ingestion）。

pub mod file;
pub mod file_reader;
pub mod file_watcher;
pub mod glob_match;

pub use file::{
    DEFAULT_MAX_FILES_PER_INPUT, DEFAULT_MAX_NEW_FILES_PER_TICK, DEFAULT_RESCAN_INTERVAL_MS,
    FileFamilyProcessor, FileInputConfig, FileInputProcessor, ProcessOutcome,
};

/// 这个目标要不要走文件族处理器（glob / 目录）。
///
/// 显式单路径继续走 `FileInputProcessor`，行为与既有测试逐字不变。
pub fn is_family_target(path: &str) -> bool {
    glob_match::has_glob(path) || std::path::Path::new(path).is_dir()
}
