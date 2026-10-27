//! L3：受限搜索（roots 由控制面下发，见 `control::source_search_policy`）。
//!
//! 兜底用途：**前四层证据（命令行 / 环境变量 / 配置文件 / 打开的 fd）一条候选都落不了地**
//! 的实例，在**人显式指定的 roots** 下找它的日志目录。
//!
//! ## 为什么要有这一层
//!
//! 现场把库装在 `/data/db/...` 是常态，而进程证据并不总能说清日志在哪：配置读不到、
//! `logging_collector = off`、`pg_ctl` 被包装脚本改写、容器里读不到 `/proc/<pid>/root`……
//! 前面几层覆盖了绝大多数；这一层是**最后的兜底**，所以它必须便宜、可预期、可关：
//!
//! * 默认**关**（策略里没有这个服务 = 不搜索）；
//! * 上限写死：roots ≤ 8、深度 ≤ 4、条目 ≤ 2000、总时长 ≤ 2s；
//! * **不跟随符号链接**（否则一条链指到 roots 外，等于把搜索范围放大到全盘）；
//! * 命中只当**候选**，证据记 `search_hit`（最低信任档），采不采仍由网关判定。
//!
//! ## 认什么
//!
//! 两类标记，任一命中即算（见 [`MARKERS`]）：
//!
//! * **数据目录标记**（`PG_VERSION` / `ibdata1` / `dump.rdb` / `WiredTiger`）——
//!   说明「这里是它的数据目录」，日志目录由 [`Marker::log_subdir`] 推出；
//! * **日志文件本身**（`postgresql-*.log` / `*.err` / `redis*.log` / `mongod.log`）——
//!   说明「这个目录就是日志目录」，直接命中。
//!
//! 两者都要**真的存在**才算命中（数据目录标记命中、但 `<dir>/log` 不存在时不出候选）：
//! 发明一个目录只会静默采到 0 个文件。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// 搜索根的上限。再多就不是「兜底」，而是在扫盘。
pub const MAX_SEARCH_ROOTS: usize = 8;
/// 从根往下钻的层数（根自身是第 0 层）。
pub const MAX_SEARCH_DEPTH: usize = 4;
/// 一次搜索最多看多少个目录条目（跨所有根合计）。
pub const MAX_SEARCH_ENTRIES: usize = 2000;
/// 一次搜索的总时长上限。
pub const MAX_SEARCH_DURATION: Duration = Duration::from_secs(2);
/// 一个服务最多给几条命中（与「每服务最多 4 个实例」对齐）。
pub const MAX_HITS: usize = 4;

/// 一次命中：日志目录（**宿主视角**、已 `realpath`）与给人看/审计的依据。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Hit {
    pub log_dir: String,
    pub detail: String,
}

/// 一个服务的识别标记。
struct Marker {
    /// 与网关服务词表一致。
    service: &'static str,
    /// 数据目录里必然存在的条目（文件或子目录）。
    data_entries: &'static [&'static str],
    /// 日志目录相对数据目录的位置（空串 = 数据目录本身）。
    log_subdir: &'static str,
    /// 日志文件名的 `(前缀, 后缀)`；任一成立即算。
    logs: &'static [(&'static str, &'static str)],
}

/// 标记表。新增服务 = 加一行 + 在网关 `LOG_SERVICES` 里加一个值。
const MARKERS: &[Marker] = &[
    Marker {
        service: "postgresql",
        data_entries: &["PG_VERSION"],
        log_subdir: "log",
        logs: &[("postgresql-", ".log"), ("postgresql-", ".csv")],
    },
    // MySQL 的错误日志 / 慢日志默认就写在 datadir 里（`<hostname>.err`、`<hostname>-slow.log`）。
    Marker {
        service: "mysql",
        data_entries: &["ibdata1", "mysql.ibd"],
        log_subdir: "",
        logs: &[("", ".err"), ("", "-slow.log"), ("slow", ".log")],
    },
    Marker {
        service: "redis",
        data_entries: &["dump.rdb", "appendonly.aof", "appendonlydir"],
        log_subdir: "",
        logs: &[("redis", ".log")],
    },
    // mongod 的日志默认 `<dbpath>/log/mongod.log`。
    Marker {
        service: "mongodb",
        data_entries: &["WiredTiger", "storage.bson"],
        log_subdir: "log",
        logs: &[("mongod.log", "")],
    },
];

/// 在 `roots` 下找 `service` 的日志目录（自带一份新预算）。
///
/// 返回**已存在**的目录（`canonicalize` 之后），按路径排序去重 —— 顺序稳定，
/// 调用方可以「一条实例分一个」地消费。
pub fn search(service: &str, roots: &[String]) -> Vec<Hit> {
    search_with(service, roots, &mut Budget::new())
}

/// 同上，但预算由调用方提供 —— 守护进程要在**一次解析**里搜多个服务，
/// 四个服务各自 2s 就是 8s，落在发现 tick 上不可接受。
pub fn search_with(service: &str, roots: &[String], budget: &mut Budget) -> Vec<Hit> {
    let Some(marker) = MARKERS.iter().find(|marker| marker.service == service) else {
        return Vec::new();
    };
    let started = Instant::now();
    let mut hits = Vec::new();
    for root in roots.iter().take(MAX_SEARCH_ROOTS) {
        let root = root.trim();
        // 只搜绝对路径的普通目录：相对路径的含义取决于 cwd，不该出现在配置里。
        if !root.starts_with('/') || root == "/" {
            continue;
        }
        walk(Path::new(root), 0, marker, budget, &mut hits);
        if budget.exhausted() || hits.len() >= MAX_HITS {
            break;
        }
    }
    hits.sort_by(|left, right| left.log_dir.cmp(&right.log_dir));
    hits.dedup_by(|left, right| left.log_dir == right.log_dir);
    hits.truncate(MAX_HITS);
    // 只在**真的搜了**的时候留一行：走到这里就说明前四层证据全落了空，
    // 现场问「它为什么去搜/搜到了什么」时，这行是唯一能回答的。
    log::info!(
        "event=LogSourceSearch service={service} hits={} elapsed_ms={} exhausted={}",
        hits.len(),
        started.elapsed().as_millis(),
        budget.exhausted()
    );
    hits
}

/// 一次解析的搜索预算（条目数 + 墙钟）。
pub struct Budget {
    entries: usize,
    deadline: Instant,
}

impl Budget {
    pub fn new() -> Self {
        Self {
            entries: MAX_SEARCH_ENTRIES,
            deadline: Instant::now() + MAX_SEARCH_DURATION,
        }
    }

    pub fn exhausted(&self) -> bool {
        self.entries == 0 || Instant::now() >= self.deadline
    }

    /// 取一个条目额度；预算用尽返回 `false`。
    fn take(&mut self) -> bool {
        if self.entries == 0 || Instant::now() >= self.deadline {
            return false;
        }
        self.entries -= 1;
        true
    }
}

impl Default for Budget {
    fn default() -> Self {
        Self::new()
    }
}

fn walk(dir: &Path, depth: usize, marker: &Marker, budget: &mut Budget, hits: &mut Vec<Hit>) {
    if budget.exhausted() || hits.len() >= MAX_HITS || depth > MAX_SEARCH_DEPTH {
        return;
    }
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    let mut data_hit = false;
    let mut log_hit = false;
    let mut subdirs: Vec<PathBuf> = Vec::new();
    for entry in entries {
        if !budget.take() {
            return;
        }
        let Ok(entry) = entry else {
            continue;
        };
        let Ok(file_type) = entry.file_type() else {
            continue;
        };
        // 符号链接一律跳过：跟随它可能跑出 roots（`/data/x -> /`），
        // 也可能绕成环。搜索是兜底，不值得为它引入这两种风险。
        // （**配置里的根本身**是符号链接不算“跟随” —— 那是人显式写的，由 `read_dir` 解析。）
        if file_type.is_symlink() {
            continue;
        }
        let name = entry.file_name().to_string_lossy().into_owned();
        if marker.data_entries.contains(&name.as_str()) {
            data_hit = true;
        }
        if file_type.is_file() && matches_log_name(&name, marker.logs) {
            log_hit = true;
        }
        if file_type.is_dir() {
            subdirs.push(entry.path());
        }
    }

    if log_hit {
        push_hit(
            dir,
            format!("search: {} 日志在 {}", marker.service, dir.display()),
            hits,
        );
    }
    if data_hit {
        let target = if marker.log_subdir.is_empty() {
            dir.to_path_buf()
        } else {
            dir.join(marker.log_subdir)
        };
        push_hit(
            &target,
            format!(
                "search: {} @ {}",
                marker.data_entries.join("|"),
                dir.display()
            ),
            hits,
        );
        // 数据目录已经认出来了，不再往下钻 —— 库里不会嵌着另一个同名库。
        return;
    }
    for subdir in subdirs {
        walk(&subdir, depth + 1, marker, budget, hits);
    }
}

/// 只有**真的存在**的目录才成为命中；已存在同名命中就跳过（多根重叠会走到同一处）。
fn push_hit(path: &Path, detail: String, hits: &mut Vec<Hit>) {
    let Ok(real) = std::fs::canonicalize(path) else {
        return;
    };
    if !real.is_dir() {
        return;
    }
    let log_dir = real.to_string_lossy().into_owned();
    if hits.iter().any(|hit| hit.log_dir == log_dir) {
        return;
    }
    hits.push(Hit { log_dir, detail });
}

fn matches_log_name(name: &str, logs: &[(&str, &str)]) -> bool {
    let lowered = name.to_lowercase();
    logs.iter().any(|(prefix, suffix)| {
        lowered.starts_with(&prefix.to_lowercase()) && lowered.ends_with(&suffix.to_lowercase())
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// 一次性临时目录：`temp_dir()/wist-search-<pid>-<n>-<name>`。
    ///
    /// 不用 `tempfile`：这个仓库的 dev-dependencies 只加「测试需要独立实现」的东西，
    /// 而这里要的只是「建几个目录再删掉」。
    struct TempTree {
        root: PathBuf,
    }

    impl TempTree {
        fn new(name: &str) -> Self {
            static NEXT: AtomicUsize = AtomicUsize::new(0);
            let root = std::env::temp_dir().join(format!(
                "wist-search-{}-{}-{name}",
                std::process::id(),
                NEXT.fetch_add(1, Ordering::Relaxed)
            ));
            let _ = std::fs::remove_dir_all(&root);
            std::fs::create_dir_all(&root).expect("create temp tree");
            Self { root }
        }

        fn dir(&self, relative: &str) -> PathBuf {
            let path = self.root.join(relative);
            std::fs::create_dir_all(&path).expect("create dir");
            path
        }

        fn file(&self, relative: &str) -> PathBuf {
            let path = self.root.join(relative);
            if let Some(parent) = path.parent() {
                std::fs::create_dir_all(parent).expect("create parent");
            }
            std::fs::write(&path, b"x").expect("write file");
            path
        }

        fn roots(&self) -> Vec<String> {
            vec![self.root.to_string_lossy().into_owned()]
        }
    }

    impl Drop for TempTree {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.root);
        }
    }

    fn real(path: &Path) -> String {
        std::fs::canonicalize(path)
            .expect("canonicalize")
            .to_string_lossy()
            .into_owned()
    }

    #[test]
    fn postgres_is_found_by_its_data_directory_marker() {
        let tree = TempTree::new("pg-datadir");
        tree.file("pg/PG_VERSION");
        let log = tree.dir("pg/log");

        let hits = search("postgresql", &tree.roots());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].log_dir, real(&log));
        assert!(hits[0].detail.contains("PG_VERSION"), "{hits:?}");
    }

    #[test]
    fn a_data_directory_without_a_log_directory_is_not_a_hit() {
        // 默认 `logging_collector = off` 的机器就是这样：数据目录在，日志目录不在。
        let tree = TempTree::new("pg-no-log");
        tree.file("pg/PG_VERSION");
        assert!(search("postgresql", &tree.roots()).is_empty());
    }

    #[test]
    fn a_log_file_is_enough_even_when_the_data_directory_is_elsewhere() {
        // 这就是 `/data/db/...` 的现场：日志在 `/data/logs`，数据目录在别处。
        let tree = TempTree::new("pg-log-only");
        let log = tree.dir("logs");
        tree.file("logs/postgresql-2026-10-27.log");

        let hits = search("postgresql", &tree.roots());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].log_dir, real(&log));
    }

    #[test]
    fn a_postgres_log_inside_the_data_directory_wins_over_the_missing_log_subdir() {
        // `log_directory = '.'`：日志就写在数据目录里，没有 `<datadir>/log`。
        let tree = TempTree::new("pg-inline");
        let pg = tree.dir("pg");
        tree.file("pg/PG_VERSION");
        tree.file("pg/postgresql-2026-10-27.log");

        let hits = search("postgresql", &tree.roots());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].log_dir, real(&pg));
    }

    #[test]
    fn mysql_is_found_by_its_error_log_suffix() {
        let tree = TempTree::new("mysql-err");
        let log = tree.dir("mysql");
        tree.file("mysql/db01.err");

        let hits = search("mysql", &tree.roots());
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(hits[0].log_dir, real(&log));
    }

    #[test]
    fn redis_and_mongodb_have_their_own_markers() {
        let tree = TempTree::new("redis-mongo");
        let redis = tree.dir("redis");
        tree.file("redis/dump.rdb");
        let mongo = tree.dir("mongo/log");
        tree.file("mongo/WiredTiger");
        tree.file("mongo/log/mongod.log");

        let redis_hits = search("redis", &tree.roots());
        assert_eq!(redis_hits.len(), 1, "{redis_hits:?}");
        assert_eq!(redis_hits[0].log_dir, real(&redis));

        let mongo_hits = search("mongodb", &tree.roots());
        assert_eq!(mongo_hits.len(), 1, "{mongo_hits:?}");
        assert_eq!(mongo_hits[0].log_dir, real(&mongo));
    }

    #[test]
    fn an_unknown_service_never_matches() {
        let tree = TempTree::new("unknown");
        tree.file("pg/PG_VERSION");
        assert!(search("nginx", &tree.roots()).is_empty());
    }

    #[test]
    fn empty_or_unusable_roots_search_nothing() {
        let tree = TempTree::new("roots");
        tree.file("pg/PG_VERSION");
        tree.dir("pg/log");
        assert!(search("postgresql", &[]).is_empty());
        // 相对路径与 `/` 一律不搜（`/` 在本模块里等于“搜整个盘”）。
        assert!(search("postgresql", &["relative".to_string()]).is_empty());
        assert!(search("postgresql", &["/".to_string()]).is_empty());
    }

    #[test]
    fn symlinks_are_not_followed() {
        let tree = TempTree::new("symlink");
        // 真正的数据目录在 roots **之外**。
        let outside = tree.root.with_extension("outside");
        let _ = std::fs::remove_dir_all(&outside);
        std::fs::create_dir_all(outside.join("pg")).expect("create outside");
        std::fs::write(outside.join("pg/PG_VERSION"), b"x").expect("write marker");
        std::fs::create_dir_all(outside.join("pg/log")).expect("create outside log");

        let inside = tree.dir("inside");
        std::os::unix::fs::symlink(outside.join("pg"), inside.join("link")).expect("symlink");

        assert!(
            search("postgresql", &tree.roots()).is_empty(),
            "符号链接不能被跟随"
        );
        let _ = std::fs::remove_dir_all(&outside);
    }

    #[test]
    fn the_walk_stops_at_the_depth_limit() {
        let tree = TempTree::new("depth");
        // 5 层深：超出 `MAX_SEARCH_DEPTH`（4），不该被找到。
        tree.file("a/b/c/d/e/PG_VERSION");
        tree.dir("a/b/c/d/e/log");

        // 4 层深：正好在上限内。
        tree.file("x/y/z/w/PG_VERSION");
        let log = tree.dir("x/y/z/w/log");

        let hits = search("postgresql", &tree.roots());
        assert_eq!(hits.len(), 1, "只有第 4 层那个该命中：{hits:?}");
        assert_eq!(hits[0].log_dir, real(&log));
    }

    #[test]
    fn the_budget_stops_after_its_entries_and_deadline() {
        let mut budget = Budget {
            entries: 3,
            deadline: Instant::now() + MAX_SEARCH_DURATION,
        };
        assert!(budget.take() && budget.take() && budget.take());
        assert!(!budget.take(), "额度用尽后必须停");
        assert!(budget.exhausted());

        // 已经过期的 deadline：一次也不读。
        let mut expired = Budget {
            entries: 10,
            deadline: Instant::now() - Duration::from_millis(1),
        };
        assert!(!expired.take());
    }

    #[test]
    fn hits_are_sorted_and_deduped() {
        let tree = TempTree::new("dedupe");
        let first = tree.dir("a/log");
        tree.file("a/PG_VERSION");
        let second = tree.dir("b/log");
        tree.file("b/PG_VERSION");

        // 同一个目录报两次根（重叠 roots）也只算一条。
        let roots = vec![
            tree.root.to_string_lossy().into_owned(),
            tree.root.join("a").to_string_lossy().into_owned(),
            tree.root.join("a/").to_string_lossy().into_owned(),
        ];
        let hits = search("postgresql", &roots);
        let dirs: Vec<&str> = hits.iter().map(|hit| hit.log_dir.as_str()).collect();
        assert_eq!(dirs, vec![real(&first), real(&second)], "{hits:?}");
    }
}
