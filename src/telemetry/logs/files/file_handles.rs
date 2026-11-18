//! 跨 tick 复用的已打开文件句柄。
//!
//! 为什么需要它（一个真实的放大回路）：采集器每读一次日志都 `open()` 一次，而 `open()` 是
//! 能让审计规则记一笔的动作。在「审计日志自身也被审计」的主机上（等保 / CIS 类基线里
//! 很常见的 `-w /var/log/audit/audit.log -p rwa -k auditlog`），就形成了
//!
//! ```text
//! 读 audit.log → 审计规则记下这次 open → audit.log 多出 4~6 行 → 下一批又有行可读 → 再 open
//! ```
//!
//! 这个环会一直跑到 tick 的追平时间片用尽：实测一台机被打到 ~50 次 open/秒，
//! 10 分钟几十万条记录全是采集器自己踩出来的（并且会顶高 auditd backlog、压掉真正的安全事件）。
//!
//! 这里持住句柄，稳态下 **0 次 open**：只有首次接入、轮转、文件被重建时才重开一次。
//!
//! 淘汰纪律（不这么做会占着 fd 不放）：
//!   * 一轮 tick 结束时，**本轮没用到的**句柄一律关掉 —— 工作授权撤回、文件消失、断点被清之后
//!     那些路径不该继续占着 fd；
//!   * 再兜一个总量上限（[`DEFAULT_MAX_OPEN_HANDLES`]），超了按最久未用淘汰，
//!     免得一个 `**` 通配把进程的 `ulimit -n` 吃穿。

use std::collections::HashMap;
use std::io;
use std::path::{Path, PathBuf};

use super::file_reader::{OpenLogFile, path_identity_async};

/// 一个 agentd 进程同时最多持多少个日志文件句柄。
///
/// 与「每个 input 最多跟踪 512 个文件」同量级：容器日志面本来就要为每个文件持一个 fd
/// （filebeat / vector 也是这么做的），但跨 input 再乘上去就不能不设上限了。
/// service 模板给的 `LimitNOFILE=65536`（`src/service/systemd.rs`），512 远在安全区内；
/// 真超了按最久未用淘汰，代价只是那一轮重开一次，不会出错。
pub const DEFAULT_MAX_OPEN_HANDLES: usize = 512;

/// 路径 → 已打开的句柄。
pub struct LogFileHandles {
    entries: HashMap<PathBuf, Entry>,
    /// 单调递增的使用序号：既是 LRU 的顺序，也是「本轮用过没有」的判据。
    seq: u64,
    max_open: usize,
    /// 真正 `open()` 了几次。稳态应为 0 增长 —— 这是这套机制**唯一**要保证的东西，
    /// 所以留个可断言的计数（生产路径不读它）。
    opens: usize,
}

struct Entry {
    file: OpenLogFile,
    last_used: u64,
}

impl LogFileHandles {
    pub fn new() -> Self {
        Self {
            entries: HashMap::new(),
            seq: 0,
            max_open: DEFAULT_MAX_OPEN_HANDLES,
            opens: 0,
        }
    }

    /// 一轮 tick 的起点：返回标记点，`end_tick(mark)` 用它认出「本轮没用到的句柄」。
    pub fn begin_tick(&mut self) -> u64 {
        self.seq
    }

    /// 拿这个路径当前的句柄。
    ///
    /// * 缓存里有、且与路径现在的 `(device, inode)` 一致 → 直接复用（**0 次 open**）；
    /// * 路径换了文件（轮转 / 被重建）、或还没缓存 → 重开一次。
    ///
    /// 身份判定用 `stat`（不 open）而不是「先 open 再看」：这正是要消掉的那个动作。
    pub async fn acquire(&mut self, path: &Path) -> io::Result<&mut OpenLogFile> {
        let observed = match path_identity_async(path).await {
            Ok(identity) => identity,
            Err(err) => {
                // 路径没了 / 读不了：手上的句柄已经不成立，别留着占 fd。
                self.entries.remove(path);
                return Err(err);
            }
        };
        let reusable = self
            .entries
            .get(path)
            .is_some_and(|entry| entry.file.points_at(observed.0, observed.1));
        self.seq += 1;
        let seq = self.seq;
        if reusable {
            if let Some(entry) = self.entries.get_mut(path) {
                entry.last_used = seq;
            }
        } else {
            let file = match OpenLogFile::open(path).await {
                Ok(file) => file,
                Err(err) => {
                    self.entries.remove(path);
                    return Err(err);
                }
            };
            self.opens += 1;
            self.entries.insert(
                path.to_path_buf(),
                Entry {
                    file,
                    last_used: seq,
                },
            );
        }
        Ok(&mut self
            .entries
            .get_mut(path)
            .expect("句柄在上面已确保存在")
            .file)
    }

    /// 本轮用过哪些句柄、哪些没人用了：一轮 tick 结束时把没人用的关掉（工作授权撤回、
    /// 文件消失、断点被清之后，那些路径不该继续占 fd）。
    pub fn end_tick(&mut self, mark: u64) {
        self.entries.retain(|_, entry| entry.last_used > mark);
        self.enforce_capacity();
    }

    /// 当场地表示「这个句柄不能用了」（读/观测失败）：摘掉它，下一批重新 `open`。
    ///
    /// 为什么需要：旧实现每批都重新 open，一次 fd 级错误（`EIO` 之类）不会“粘”在这个
    /// 文件上；持句柄以后不主动摘，一条坏 fd 会让这条输入永远读不动。
    pub fn invalidate(&mut self, path: &Path) {
        self.entries.remove(path);
    }

    /// 上限按**拍末**执行：拍内可能短暂超出几条（工作集本身就是上限，每条输入最多 512 个文件），
    /// 换来的是每拍一次 O(n log n)，而不是每次 `acquire` 都排一次。
    fn enforce_capacity(&mut self) {
        let overflow = self.entries.len().saturating_sub(self.max_open);
        if overflow == 0 {
            return;
        }
        let mut by_age: Vec<(PathBuf, u64)> = self
            .entries
            .iter()
            .map(|(path, entry)| (path.clone(), entry.last_used))
            .collect();
        by_age.sort_by_key(|(_, last_used)| *last_used);
        for (path, _) in by_age.into_iter().take(overflow) {
            self.entries.remove(&path);
        }
    }

    /// 当前持着多少句柄（测试用）。
    #[cfg(test)]
    pub(super) fn len(&self) -> usize {
        self.entries.len()
    }

    /// 真正 `open()` 过的次数（测试用）：稳态应停止增长。
    #[cfg(test)]
    pub(super) fn open_count(&self) -> usize {
        self.opens
    }

    #[cfg(test)]
    fn set_max_open(&mut self, max_open: usize) {
        self.max_open = max_open;
    }
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::LogFileHandles;

    fn temp_path(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-agentd-handles-{name}-{suffix}.log"))
    }

    fn block_on<T>(future: impl std::future::Future<Output = T>) -> T {
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("build tokio runtime")
            .block_on(future)
    }

    /// 稳态复用必须**不产生新的 open**：这才是审计规则记不记账的分界。
    #[test]
    fn acquire_reuses_the_same_descriptor_while_the_file_is_unchanged() {
        let path = temp_path("reuse");
        fs::write(&path, "first\n").expect("write file");
        let mut handles = LogFileHandles::new();

        block_on(async { handles.acquire(&path).await }).expect("first acquire");
        block_on(async { handles.acquire(&path).await }).expect("second acquire");

        assert_eq!(
            handles.open_count(),
            1,
            "同一文件应复用同一个句柄，不能再 open 一次"
        );
        assert_eq!(handles.len(), 1);
        fs::remove_file(path).ok();
    }

    /// 路径换了文件（rename 轮转 / 删除重建）必须换句柄，否则会一直读旧 inode。
    #[cfg(unix)]
    #[test]
    fn acquire_reopens_when_the_path_points_at_a_new_file() {
        let path = temp_path("rotated");
        let rotated = path.with_extension("log.1");
        fs::write(&path, "old\n").expect("write file");
        let mut handles = LogFileHandles::new();
        let before = block_on(async { handles.acquire(&path).await.map(|file| file.raw_fd()) })
            .expect("first acquire");

        fs::rename(&path, &rotated).expect("rotate");
        fs::write(&path, "new\n").expect("write new file");
        let after = block_on(async { handles.acquire(&path).await.map(|file| file.raw_fd()) })
            .expect("second acquire");

        assert_ne!(before, after, "路径已指向新文件，句柄必须换");
        assert_eq!(handles.open_count(), 2);
        assert_eq!(handles.len(), 1, "旧路径的句柄已被替换");
        fs::remove_file(path).ok();
        fs::remove_file(rotated).ok();
    }

    /// 路径没了就把句柄放掉：否则一个被删掉的文件会被句柄钉着，磁盘块也不归还。
    #[test]
    fn acquire_on_a_missing_path_drops_the_cached_handle() {
        let path = temp_path("missing");
        fs::write(&path, "x\n").expect("write file");
        let mut handles = LogFileHandles::new();
        block_on(async { handles.acquire(&path).await.map(|_| ()) }).expect("first acquire");
        assert_eq!(handles.len(), 1);

        fs::remove_file(&path).expect("remove file");
        let err = match block_on(async { handles.acquire(&path).await.map(|_| ()) }) {
            Ok(()) => panic!("路径不存在时不能算拿到句柄"),
            Err(err) => err,
        };

        assert_eq!(err.kind(), std::io::ErrorKind::NotFound);
        assert_eq!(handles.len(), 0, "路径没了就要把句柄放掉");
        assert_eq!(handles.open_count(), 1);

        // 同路径再出现（logrotate 的 create 下半段）：要重开一次，不能拿旧句柄硬读。
        fs::write(&path, "back\n").expect("recreate file");
        block_on(async { handles.acquire(&path).await.map(|_| ()) }).expect("re-acquire");
        assert_eq!(handles.open_count(), 2);
        fs::remove_file(path).ok();
    }

    #[test]
    fn invalidate_drops_the_handle_so_the_next_acquire_reopens() {
        let path = temp_path("invalidate");
        fs::write(&path, "x\n").expect("write file");
        let mut handles = LogFileHandles::new();

        block_on(async { handles.acquire(&path).await.map(|_| ()) }).expect("acquire");
        assert_eq!(handles.open_count(), 1);

        handles.invalidate(&path);
        assert_eq!(handles.len(), 0);

        block_on(async { handles.acquire(&path).await.map(|_| ()) }).expect("re-acquire");
        assert_eq!(
            handles.open_count(),
            2,
            "被摘掉的句柄必须真重开：坏 fd 不能“粘”在这条输入上"
        );
        fs::remove_file(path).ok();
    }

    #[test]
    fn end_tick_drops_handles_that_were_not_used() {
        let kept = temp_path("kept");
        let dropped = temp_path("dropped");
        fs::write(&kept, "a\n").expect("write kept");
        fs::write(&dropped, "b\n").expect("write dropped");
        let mut handles = LogFileHandles::new();

        let mark = handles.begin_tick();
        block_on(async { handles.acquire(&dropped).await }).expect("acquire dropped");
        handles.end_tick(mark);
        let mark = handles.begin_tick();
        block_on(async { handles.acquire(&kept).await }).expect("acquire kept");
        handles.end_tick(mark);

        assert_eq!(
            handles.len(),
            1,
            "本轮没用到的句柄应被关掉（撤活后不该占 fd）"
        );
        block_on(async { handles.acquire(&kept).await }).expect("re-acquire kept");
        assert_eq!(handles.open_count(), 2, "留下来的那条不该再 open");
        block_on(async { handles.acquire(&dropped).await }).expect("re-acquire dropped");
        assert_eq!(handles.open_count(), 3, "被关掉的那条重开是预期行为");
        fs::remove_file(kept).ok();
        fs::remove_file(dropped).ok();
    }

    #[test]
    fn capacity_evicts_the_least_recently_used() {
        let first = temp_path("cap-first");
        let second = temp_path("cap-second");
        fs::write(&first, "a\n").expect("write first");
        fs::write(&second, "b\n").expect("write second");
        let mut handles = LogFileHandles::new();
        handles.set_max_open(1);

        let mark = handles.begin_tick();
        block_on(async { handles.acquire(&first).await }).expect("acquire first");
        block_on(async { handles.acquire(&second).await }).expect("acquire second");
        handles.end_tick(mark);

        assert_eq!(handles.len(), 1, "上限 1：必须淘汰一条");
        assert_eq!(handles.open_count(), 2);
        block_on(async { handles.acquire(&first).await }).expect("re-acquire first");
        assert_eq!(
            handles.open_count(),
            3,
            "最久未用（first）被淘汰，重开是预期行为"
        );
        block_on(async { handles.acquire(&second).await }).expect("re-acquire second");
        assert_eq!(handles.open_count(), 3, "最近用过的那条仍在缓存里");
        fs::remove_file(first).ok();
        fs::remove_file(second).ok();
    }
}
