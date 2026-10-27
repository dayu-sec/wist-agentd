//! 日志源定位（v1：PostgreSQL / MySQL / Redis / MongoDB）。
//!
//! ## 为什么需要它
//!
//! 采集面的「服务在不在」从 L1 起可以靠端口判断，但「它的日志在哪个目录」仍然只能写死
//! 在采集目录里。数据库装在 `/data/pg` 这类非标准位置时，页面只会说「找不到日志目录」——
//! 对一台正在跑的数据库，这就是**判定错误**。
//!
//! agentd 以 root 跑在客户主机上，**进程本身就是证据**：`postgres -D /data/pg/data`
//! 的 argv 里写着数据目录，`mysqld --log-error=...` 直接写着日志文件。这里把它们读出来，
//! 作为候选上报给网关；**采不采、采哪个仍由网关判定**（roots 校验 + 覆盖优先）。
//!
//! ## 分层
//!
//! * [`rules`]：每个服务一条纯函数规则（不给 IO，只给证据）—— 4 个服务、6 种证据都在那里；
//! * 本模块：读 `/proc`、把候选目录经 `/proc/<pid>/root` + `realpath` 变成**宿主可见**路径、
//!   按上限收敛、产出 wire 形态的 [`LogSourceEntry`]；
//! * [`search`]：L3 兜底 —— 前几层一条候选都落不了地时，在人显式指定的 roots 下**有界**找。
//!
//! `ProcAccess` / [`SourceSearch`] 抽出来的唯一目的是**可测**：规则、容器路径映射与“搜索什么时候
//! 才该跑”都能用假的实现钉住，不需要真跑一台 MySQL，也不需要依赖宿主机的目录树。
//!
//! ## 边界（写死，不随配置放大）
//!
//! * 进程来自**发现快照**，不自己扫一遍 `/proc`；
//! * cmdline / environ 各 ≤ 4 KiB、打开的 fd ≤ 64 个、配置文件 ≤ 64 KiB；
//! * 每次最多检查 16 个进程，每个服务最多 4 条候选（多实例）；
//! * 目录一律经 `/proc/<pid>/root...` + `realpath`（见 [`rooted`]）；
//! * 搜索只在**没落地**的实例上跑一次（每服务一拍一次），上限见 [`search`]；
//! * 找不到目录时上报 `evidence = unresolved` 的**占位**（分母），而不是发明一个目录。

pub mod rules;
pub mod search;

use std::collections::BTreeMap;

use serde::Serialize;
use wist_contracts::discovery::DiscoverySnapshot;

/// 单次读取 `/proc/<pid>/{cmdline,environ}` 的上限。
///
/// 为什么要有上限：`environ` 可以到 128 KiB，一台机器上几百个进程时无界读取会把
/// 发现 tick 拖长。4 KiB 足够装下任何正常启动参数。
const MAX_PROC_BYTES: usize = 4096;

/// 每个服务最多产出几条候选（= 最多几个实例）。
const MAX_CANDIDATES_PER_SERVICE: usize = 4;

/// 每次解析最多**检查**多少个候选进程（不是产出条数）。
///
/// 为什么另一个上限：`mysqld` / `redis-server` 一般只有一个进程，但异常情况下
/// （反复重启的残留）可能有很多；每个都要读两个 `/proc` 文件和配置，必须封顶。
const MAX_INSPECTED_PROCESSES: usize = 16;

/// 每个进程最多看多少个打开的文件。
///
/// `mysqld` 会打开几十个 InnoDB 数据文件，全读一遍纯属浪费；日志文件通常在 fd 很少的
/// 位置，64 个足够覆盖正常启动顺序。
const MAX_OPEN_FILES: usize = 64;

/// 受限搜索命中的置信度。
///
/// 最低档：搜索只是「看起来像」，不像 `-D` / 打开的 fd 那样是硬证据。
/// 它不参与判定（判定在网关），只影响同档内排序与给人看的解释。
const SEARCH_CONFIDENCE: i64 = 55;

/// 一条候选（wire 形态）。
///
/// 字段名与网关的 `StoredLogSource` / 线报文逐字对齐 —— 两侧不共享类型（各自在 seam
/// 一侧定义，与 `collection-preflight` 同一做法），所以字段名必须靠测试钉住。
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LogSourceEntry {
    pub service: String,
    pub source_ref: String,
    pub dir: String,
    pub evidence: String,
    pub detail: String,
    pub confidence: i64,
}

/// `/proc` 里会被读的两个文件。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ProcFile {
    Cmdline,
    Environ,
}

impl ProcFile {
    fn as_str(self) -> &'static str {
        match self {
            Self::Cmdline => "cmdline",
            Self::Environ => "environ",
        }
    }
}

/// 读进程信息的能力。生产实现是 [`RealProc`]，测试用假实现（见 `tests::FakeProc`）。
trait ProcAccess {
    fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String>;
    /// 进程工作目录（**容器视角**，与其它路径一致）。
    fn cwd(&self, pid: u32) -> Option<String>;
    /// 进程正打开的文件（容器视角、绝对路径）。
    fn open_files(&self, pid: u32) -> Vec<String>;
    /// 读一个文件；`path` 已含 `/proc/<pid>/root` 前缀。
    fn read_file(&self, path: &str) -> Option<String>;
    /// `realpath` 且必须是目录。
    fn canonical_dir(&self, path: &str) -> Option<String>;
}

/// 受限搜索（L3）。抽成 trait 的唯一目的是**可测**：真实现要遍历文件系统，
/// 而“搜索什么时候才该跑、命中怎么分给实例”这条逻辑不该依赖宿主机的目录树。
pub trait SourceSearch {
    /// 在这个服务的日志目录上找证据（**宿主视角**，已 `realpath`）。
    ///
    /// 返回顺序无所谓：调用方按「一个没定位的实例领一条」的顺序消费。
    fn search(&self, service: &str) -> Vec<search::Hit>;
}

/// 搜索关着（策略里没有这个服务）时的实现。
struct NoSearch;

impl SourceSearch for NoSearch {
    fn search(&self, _service: &str) -> Vec<search::Hit> {
        Vec::new()
    }
}

/// 按**下发策略**搜索：服务 → 生效 roots（网关算好的交集，见 `control::source_search_policy`）。
struct PolicySearch<'a> {
    policy: &'a crate::control::source_search_policy::SourceSearchPolicy,
    /// 整个解析共享一份预算（一次最多 2s / 2000 条目）。
    budget: std::cell::RefCell<search::Budget>,
}

impl SourceSearch for PolicySearch<'_> {
    fn search(&self, service: &str) -> Vec<search::Hit> {
        let roots = self.policy.roots_for(service);
        if roots.is_empty() {
            return Vec::new();
        }
        search::search_with(service, roots, &mut self.budget.borrow_mut())
    }
}

/// 从发现快照算出日志源候选。**纯计算 + 受限读取**，失败一律跳过，不阻断发现。
///
/// `policy` 是控制面下发的 L3 搜索范围；**空 = 不做搜索**（缺省、旧网关、未入网都是这个状态）。
pub fn resolve_from_snapshot(
    snapshot: &DiscoverySnapshot,
    policy: &crate::control::source_search_policy::SourceSearchPolicy,
) -> Vec<LogSourceEntry> {
    if policy.is_empty() {
        return resolve(snapshot, &RealProc, &NoSearch);
    }
    let search = PolicySearch {
        policy,
        budget: std::cell::RefCell::new(search::Budget::new()),
    };
    resolve(snapshot, &RealProc, &search)
}

/// 现场诊断用：**立即**跑一次进程 + 端点发现并解析（不读缓存、不写任何东西）。
///
/// 与守护进程走**同一条**解析路径（同一个 [`resolve`]），所以结论一致；
/// 差别只在入口：守护进程用上一拍的快照，这里现场采一次。
pub fn resolve_live(
    policy: &crate::control::source_search_policy::SourceSearchPolicy,
) -> Vec<LogSourceEntry> {
    use crate::discovery::DiscoveryProbe as _;

    let now = std::time::SystemTime::now();
    let stamp = wist_shared::time::now_rfc3339();
    let mut snapshot = DiscoverySnapshot::new(format!("log-sources-live-{stamp}"), 0, stamp);
    for output in [
        crate::discovery::process::ProcessDiscoveryProbe.refresh(now),
        crate::discovery::endpoint::EndpointDiscoveryProbe.refresh(now),
    ]
    .into_iter()
    .flatten()
    {
        snapshot.resources.extend(output.resources);
        snapshot.targets.extend(output.targets);
    }
    resolve_from_snapshot(&snapshot, policy)
}

fn resolve(
    snapshot: &DiscoverySnapshot,
    proc: &dyn ProcAccess,
    search: &dyn SourceSearch,
) -> Vec<LogSourceEntry> {
    let ports = tcp_port_by_pid(snapshot);
    let mut out: Vec<LogSourceEntry> = Vec::new();
    let mut inspected = 0usize;
    let mut per_service: BTreeMap<&'static str, usize> = BTreeMap::new();
    // 受限搜索**每服务一拍只跑一次**：多个实例/多个 worker 不该把同一棵目录树走好多遍。
    // `Some(剩的命中)`，空 vec = 跑过了且没找到（不重复搜）。
    let mut pending_search: BTreeMap<&'static str, Vec<search::Hit>> = BTreeMap::new();

    for process in processes(snapshot) {
        let Some(rule) = rules::rule_for(&process.exe) else {
            continue;
        };
        if inspected >= MAX_INSPECTED_PROCESSES {
            break;
        }
        if per_service.get(rule.service).copied().unwrap_or(0) >= MAX_CANDIDATES_PER_SERVICE {
            continue;
        }
        inspected += 1;

        let argv = proc.nul_list(process.pid, ProcFile::Cmdline);
        let environ = proc.nul_list(process.pid, ProcFile::Environ);
        let cwd = proc.cwd(process.pid);
        let open_files = proc.open_files(process.pid);
        // 配置路径由规则给出**容器视角**的绝对路径，这里按 pid 补 `/proc/<pid>/root`
        // —— 容器里的 MySQL 读的是容器那份 `my.cnf`，不是宿主上同名文件。
        let read = |path: &str| proc.read_file(&rooted(process.pid, path));
        let evidence = rules::Evidence {
            argv: &argv,
            environ: &environ,
            cwd: cwd.as_deref(),
            open_files: &open_files,
            read_file: &read,
        };
        let proposals = (rule.candidates)(&evidence);

        let source_ref = identity(&ports, process.pid);
        let with_container = |detail: &str| match process.container_id.as_deref() {
            Some(id) => format!("{detail}（container {id}）"),
            None => detail.to_string(),
        };

        // 按优先级试候选；第一个「真的存在」的目录胜出。
        let mut chosen: Option<(String, &rules::Proposal, i64)> = None;
        for proposal in &proposals {
            if let Some(dir) = proc.canonical_dir(&rooted(process.pid, &proposal.dir)) {
                chosen = Some((dir, proposal, proposal.confidence));
                break;
            }
            // `/proc/<pid>/root` 读不到（内核限制了 ptrace）：**不在容器里**时退回直接路径。
            // 容器里不能这么退 —— 宿主的同名路径是另一份东西。
            if process.container_id.is_none()
                && let Some(dir) = proc.canonical_dir(&proposal.dir)
            {
                chosen = Some((dir, proposal, proposal.confidence - 10));
                break;
            }
        }

        let entry = match chosen {
            Some((dir, proposal, confidence)) => LogSourceEntry {
                service: rule.service.to_string(),
                source_ref,
                dir,
                evidence: proposal.evidence.to_string(),
                detail: with_container(&proposal.detail),
                confidence,
            },
            None => {
                // 前四层证据都没落地 → **最后才**走受限搜索（默认关）。
                // 只跟「本来就该算一个实例」的进程去搜：postgres 的 worker 没有 `-D`，
                // 让它们领命中会凭空造出并不存在的实例。
                let is_instance = rule.counts_without_candidates || !proposals.is_empty();
                let hit = is_instance
                    .then(|| {
                        pending_search
                            .entry(rule.service)
                            .or_insert_with(|| search.search(rule.service))
                    })
                    .and_then(|hits| (!hits.is_empty()).then(|| hits.remove(0)));
                match hit {
                    Some(hit) => LogSourceEntry {
                        service: rule.service.to_string(),
                        source_ref,
                        dir: hit.log_dir,
                        evidence: "search_hit".to_string(),
                        detail: with_container(&hit.detail),
                        confidence: SEARCH_CONFIDENCE,
                    },
                    // 认得出实例、但一条候选都落不了地：报占位（分母靠它）。
                    None if !proposals.is_empty() => unresolved_entry(
                        rule.service,
                        source_ref,
                        with_container(&proposals[0].detail),
                    ),
                    // 一条线索都没有。postgres 的子进程就是这样（没有 `-D`）—— 不算实例；
                    // 其它服务则确实是一个「日志位置未知」的实例。
                    None if rule.counts_without_candidates => unresolved_entry(
                        rule.service,
                        source_ref,
                        with_container("没有可用的日志路径线索"),
                    ),
                    None => continue,
                }
            }
        };
        out.push(entry);
        *per_service.entry(rule.service).or_default() += 1;
    }
    out
}

fn unresolved_entry(service: &str, source_ref: String, detail: String) -> LogSourceEntry {
    LogSourceEntry {
        service: service.to_string(),
        source_ref,
        dir: String::new(),
        evidence: "unresolved".to_string(),
        detail,
        confidence: 0,
    }
}

/// 身份优先用端口：pid 重启就换，同一实例换个 pid 不该多出一条候选。
fn identity(ports: &BTreeMap<u32, u16>, pid: u32) -> String {
    ports
        .get(&pid)
        .map(|port| format!("port:{port}"))
        .unwrap_or_else(|| format!("pid:{pid}"))
}

/// `/proc/<pid>/root` 下的同一个路径。
///
/// 容器里跑的进程，它的 `-D` / 配置里的路径都是**容器视角**；`/proc/<pid>/root` 指向
/// 那个进程的根，路径解析会走**它自己的挂载表**。realpath 之后就是宿主可见的真实路径：
///
/// * bind mount（`-v /data/pg:/var/lib/postgresql/data`）→ 宿主源目录 `/data/pg/...`；
/// * named volume → `/var/lib/docker/volumes/<name>/_data/...`；
/// * 容器可写层 → `/var/lib/docker/overlay2/<id>/merged/...`（容器重建就换）。
///
/// 宿主上直跑的进程也走同一条路径（它的 root 就是 `/`），所以不需要分支。
fn rooted(pid: u32, path: &str) -> String {
    if path == "/" {
        format!("/proc/{pid}/root")
    } else {
        format!("/proc/{pid}/root{path}")
    }
}

/// 进程列表：来自发现快照的 `process` 资源。
struct ObservedProcess {
    pid: u32,
    exe: String,
    container_id: Option<String>,
}

fn processes(snapshot: &DiscoverySnapshot) -> Vec<ObservedProcess> {
    snapshot
        .resources
        .iter()
        .filter(|resource| resource.kind == "process")
        .filter_map(|resource| {
            let pid = resource.attributes.get("process.pid")?.parse().ok()?;
            let exe = resource.attributes.get("process.executable.name")?.clone();
            Some(ObservedProcess {
                pid,
                exe,
                container_id: resource.attributes.get("container.id").cloned(),
            })
        })
        .collect()
}

/// 监听端口 → pid（只认 `tcp`）。
///
/// 为什么只认 tcp：数据库走 TCP；udp 端口相同不代表就是那个服务，用它做身份会给出一个
/// 「看起来合理但错」的 `source_ref`。
fn tcp_port_by_pid(snapshot: &DiscoverySnapshot) -> BTreeMap<u32, u16> {
    let mut ports = BTreeMap::new();
    for resource in &snapshot.resources {
        if resource.kind != "service_endpoint" {
            continue;
        }
        let attrs = &resource.attributes;
        if attrs.get("endpoint.protocol").map(String::as_str) != Some("tcp") {
            continue;
        }
        let Some(pid) = attrs.get("process.pid").and_then(|pid| pid.parse().ok()) else {
            continue;
        };
        let Some(port) = attrs
            .get("endpoint.bind.port")
            .and_then(|port| port.parse().ok())
        else {
            continue;
        };
        // 同一进程可能监听多个端口（MySQL 还有 33060）：取**最小的**那个作身份，
        // 保证同一实例每轮算出来一样，不会来回跳。
        ports
            .entry(pid)
            .and_modify(|existing: &mut u16| *existing = (*existing).min(port))
            .or_insert(port);
    }
    ports
}

// ─────────────────────────────────────────────────────────────────────────────
// 生产实现
// ─────────────────────────────────────────────────────────────────────────────

struct RealProc;

impl ProcAccess for RealProc {
    fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String> {
        let path = format!("/proc/{pid}/{}", file.as_str());
        let Some(bytes) = read_capped(&path, MAX_PROC_BYTES) else {
            return Vec::new();
        };
        split_nul(&bytes, MAX_PROC_BYTES)
    }

    fn cwd(&self, pid: u32) -> Option<String> {
        read_link_path(&format!("/proc/{pid}/cwd"))
    }

    fn open_files(&self, pid: u32) -> Vec<String> {
        let dir = format!("/proc/{pid}/fd");
        let Ok(entries) = std::fs::read_dir(&dir) else {
            return Vec::new();
        };
        entries
            .take(MAX_OPEN_FILES)
            .filter_map(|entry| entry.ok())
            .filter_map(|entry| {
                std::fs::read_link(entry.path())
                    .ok()
                    .map(|path| path.to_string_lossy().into_owned())
            })
            .filter(|path| path.starts_with('/'))
            .collect()
    }

    fn read_file(&self, path: &str) -> Option<String> {
        let bytes = read_capped(path, rules::MAX_CONFIG_BYTES)?;
        Some(String::from_utf8_lossy(&bytes).into_owned())
    }

    fn canonical_dir(&self, path: &str) -> Option<String> {
        std::fs::canonicalize(path)
            .ok()
            .filter(|path| path.is_dir())
            .map(|path| path.to_string_lossy().into_owned())
    }
}

fn read_capped(path: &str, limit: usize) -> Option<Vec<u8>> {
    use std::io::Read as _;

    let file = std::fs::File::open(path).ok()?;
    let mut buffer = Vec::with_capacity(limit.min(8192));
    file.take(limit as u64).read_to_end(&mut buffer).ok()?;
    Some(buffer)
}

fn read_link_path(path: &str) -> Option<String> {
    let target = std::fs::read_link(path).ok()?;
    let value = target.to_string_lossy().into_owned();
    value.starts_with('/').then_some(value)
}

/// `cmdline` / `environ` 都是 NUL 分隔的字节串；空段一律跳过。
fn split_nul(content: &[u8], limit: usize) -> Vec<String> {
    content
        .split(|byte| *byte == 0)
        .take(limit)
        .map(|segment| String::from_utf8_lossy(segment).trim().to_string())
        .filter(|segment| !segment.is_empty())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::cell::Cell;
    use std::collections::BTreeMap;
    use wist_contracts::discovery::DiscoveredResource;

    /// 假 `/proc`：按 pid 给 cmdline / environ / cwd / fd，按路径给文件与目录。
    #[derive(Default)]
    struct FakeProc {
        argv: BTreeMap<u32, Vec<String>>,
        environ: BTreeMap<u32, Vec<String>>,
        cwd: BTreeMap<u32, String>,
        open_files: BTreeMap<u32, Vec<String>>,
        /// `read_file` 的输入（**已含** `/proc/<pid>/root` 前缀）。
        files: BTreeMap<String, String>,
        /// `canonical_dir` 的输入 → 输出的真实路径（不在表里 = 不存在）。
        dirs: BTreeMap<String, String>,
    }

    impl ProcAccess for FakeProc {
        fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String> {
            match file {
                ProcFile::Cmdline => self.argv.get(&pid).cloned().unwrap_or_default(),
                ProcFile::Environ => self.environ.get(&pid).cloned().unwrap_or_default(),
            }
        }

        fn cwd(&self, pid: u32) -> Option<String> {
            self.cwd.get(&pid).cloned()
        }

        fn open_files(&self, pid: u32) -> Vec<String> {
            self.open_files.get(&pid).cloned().unwrap_or_default()
        }

        fn read_file(&self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn canonical_dir(&self, path: &str) -> Option<String> {
            self.dirs.get(path).cloned()
        }
    }

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn process_resource(pid: u32, exe: &str, container_id: Option<&str>) -> DiscoveredResource {
        let mut attributes = BTreeMap::from([
            ("process.pid".to_string(), pid.to_string()),
            ("process.executable.name".to_string(), exe.to_string()),
        ]);
        if let Some(id) = container_id {
            attributes.insert("container.id".to_string(), id.to_string());
        }
        DiscoveredResource {
            resource_id: format!("host:pid:{pid}"),
            kind: "process".to_string(),
            origin_idx: 0,
            attributes,
            discovered_at: "2026-10-26T00:00:00Z".to_string(),
            last_seen_at: "2026-10-26T00:00:00Z".to_string(),
            health: "healthy".to_string(),
            source: "process".to_string(),
        }
    }

    fn endpoint_resource(pid: u32, port: u16) -> DiscoveredResource {
        DiscoveredResource {
            resource_id: format!("host:endpoint:tcp:{port}"),
            kind: "service_endpoint".to_string(),
            origin_idx: 0,
            attributes: BTreeMap::from([
                ("endpoint.protocol".to_string(), "tcp".to_string()),
                ("endpoint.bind.port".to_string(), port.to_string()),
                ("process.pid".to_string(), pid.to_string()),
            ]),
            discovered_at: "2026-10-26T00:00:00Z".to_string(),
            last_seen_at: "2026-10-26T00:00:00Z".to_string(),
            health: "healthy".to_string(),
            source: "endpoint".to_string(),
        }
    }

    fn snapshot(resources: Vec<DiscoveredResource>) -> DiscoverySnapshot {
        let mut snapshot =
            DiscoverySnapshot::new("snap-1".to_string(), 1, "2026-10-26T00:00:00Z".to_string());
        snapshot.resources = resources;
        snapshot
    }

    #[test]
    fn resolves_postgres_from_the_command_line() {
        let mut proc = FakeProc::default();
        proc.argv.insert(100, args(&["postgres", "-D", "/data/pg"]));
        proc.dirs.insert(
            "/proc/100/root/data/pg/log".to_string(),
            "/data/pg/log".to_string(),
        );
        let snapshot = snapshot(vec![
            process_resource(100, "/usr/lib/postgresql/16/bin/postgres", None),
            endpoint_resource(100, 5432),
        ]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(
            sources,
            vec![LogSourceEntry {
                service: "postgresql".to_string(),
                source_ref: "port:5432".to_string(),
                dir: "/data/pg/log".to_string(),
                evidence: "cmdline_datadir".to_string(),
                detail: "-D /data/pg".to_string(),
                confidence: 90,
            }]
        );
    }

    #[test]
    fn a_containerised_service_resolves_through_its_own_mount_table() {
        // `-D /var/lib/postgresql/data` 是容器视角；宿主路径只能从 `/proc/<pid>/root` 拿到。
        let mut proc = FakeProc::default();
        proc.argv
            .insert(100, args(&["postgres", "-D", "/var/lib/postgresql/data"]));
        // 只登记 rooted 路径 —— 若实现偷偷试了宿主同名路径，这条用例就抓不到证据。
        proc.dirs.insert(
            "/proc/100/root/var/lib/postgresql/data/log".to_string(),
            "/data/pg/log".to_string(),
        );
        let snapshot = snapshot(vec![process_resource(
            100,
            "/usr/lib/postgresql/16/bin/postgres",
            Some("a55a338d7723"),
        )]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].dir, "/data/pg/log");
        assert!(
            sources[0].detail.contains("container a55a338d7723"),
            "依据里要能看出它在哪个容器：{}",
            sources[0].detail
        );
    }

    #[test]
    fn a_host_process_falls_back_when_proc_root_is_unreadable() {
        // 内核限制 ptrace 时 `/proc/<pid>/root/...` 打不开；宿主进程还有退路。
        let mut proc = FakeProc::default();
        proc.argv.insert(100, args(&["postgres", "-D", "/data/pg"]));
        proc.dirs
            .insert("/data/pg/log".to_string(), "/data/pg/log".to_string());
        let snapshot = snapshot(vec![process_resource(100, "/usr/bin/postgres", None)]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].dir, "/data/pg/log");
        assert_eq!(sources[0].confidence, 80, "少一层命名空间校验，置信度要降");
    }

    #[test]
    fn a_container_process_never_falls_back_to_the_host_path() {
        let mut proc = FakeProc::default();
        proc.argv
            .insert(100, args(&["postgres", "-D", "/var/lib/postgresql/data"]));
        // 宿主同名路径存在，但它属于别的东西 —— 绝不能用。
        proc.dirs.insert(
            "/var/lib/postgresql/data/log".to_string(),
            "/var/lib/postgresql/data/log".to_string(),
        );
        let snapshot = snapshot(vec![process_resource(
            100,
            "/usr/bin/postgres",
            Some("abc"),
        )]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].evidence, "unresolved");
        assert_eq!(sources[0].dir, "");
    }

    #[test]
    fn a_missing_log_directory_is_reported_as_unresolved() {
        // 默认 `logging_collector = off`：日志进 stderr/journald，没有目录。
        let mut proc = FakeProc::default();
        proc.argv.insert(100, args(&["postgres", "-D", "/data/pg"]));
        let snapshot = snapshot(vec![process_resource(100, "/usr/bin/postgres", None)]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].evidence, "unresolved");
        assert_eq!(sources[0].source_ref, "pid:100");
        assert_eq!(sources[0].detail, "-D /data/pg");
    }

    #[test]
    fn postgres_workers_are_not_counted_as_instances() {
        // 子进程共用 argv[0] 但没有 `-D`：按它们计数会把一个 PG 数成七八个。
        let mut proc = FakeProc::default();
        proc.argv.insert(100, args(&["postgres", "-D", "/data/pg"]));
        proc.argv.insert(101, args(&["postgres: checkpointer"]));
        proc.argv.insert(102, args(&["postgres: walwriter"]));
        let snapshot = snapshot(vec![
            process_resource(100, "/usr/bin/postgres", None),
            process_resource(101, "/usr/bin/postgres", None),
            process_resource(102, "/usr/bin/postgres", None),
        ]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1, "只有 postmaster 算实例：{sources:?}");
    }

    #[test]
    fn resolves_mysql_through_my_cnf_inside_a_container() {
        let mut proc = FakeProc::default();
        proc.argv
            .insert(200, args(&["mysqld", "--datadir=/var/lib/mysql"]));
        proc.files.insert(
            "/proc/200/root/etc/my.cnf".to_string(),
            "[mysqld]\nlog-error=/var/log/mysql/error.log\n".to_string(),
        );
        proc.dirs.insert(
            "/proc/200/root/var/log/mysql".to_string(),
            "/data/mysql-log".to_string(),
        );
        let snapshot = snapshot(vec![
            process_resource(200, "/usr/sbin/mysqld", Some("c1")),
            endpoint_resource(200, 3306),
        ]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert_eq!(sources[0].service, "mysql");
        assert_eq!(sources[0].dir, "/data/mysql-log");
        assert_eq!(sources[0].evidence, "config_file");
        assert_eq!(sources[0].source_ref, "port:3306");
    }

    #[test]
    fn resolves_redis_through_its_config_and_cwd() {
        let mut proc = FakeProc::default();
        proc.argv
            .insert(300, args(&["redis-server", "conf/redis.conf"]));
        proc.cwd.insert(300, "/srv/redis".to_string());
        // 配置文件的相对路径以 cwd 为基准；`logfile` 的相对路径同样以 cwd 为基准
        // （就是 fopen 的语义 —— redis 启动后不 chdir 到配置目录）。
        proc.files.insert(
            "/proc/300/root/srv/redis/conf/redis.conf".to_string(),
            "logfile ./logs/redis.log\n".to_string(),
        );
        proc.dirs.insert(
            "/proc/300/root/srv/redis/logs".to_string(),
            "/srv/redis/logs".to_string(),
        );
        let snapshot = snapshot(vec![
            process_resource(300, "/usr/bin/redis-server", None),
            endpoint_resource(300, 6379),
        ]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert_eq!(sources[0].service, "redis");
        assert_eq!(sources[0].dir, "/srv/redis/logs");
        assert_eq!(sources[0].evidence, "config_file");
    }

    #[test]
    fn resolves_mongod_from_its_logpath() {
        let mut proc = FakeProc::default();
        proc.argv.insert(
            400,
            args(&["mongod", "--logpath", "/var/log/mongo/mongod.log"]),
        );
        proc.dirs.insert(
            "/proc/400/root/var/log/mongo".to_string(),
            "/var/log/mongo".to_string(),
        );
        let snapshot = snapshot(vec![
            process_resource(400, "/usr/bin/mongod", None),
            endpoint_resource(400, 27017),
        ]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert_eq!(sources[0].service, "mongodb");
        assert_eq!(sources[0].dir, "/var/log/mongo");
        assert_eq!(sources[0].evidence, "cmdline_logfile");
    }

    #[test]
    fn a_service_without_any_clue_is_still_counted_as_an_instance() {
        // mysqld 在跑，但没 -D、读不到 my.cnf、也没有打开的日志：要报占位（分母）。
        let proc = FakeProc::default();
        let snapshot = snapshot(vec![process_resource(200, "/usr/sbin/mysqld", None)]);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), 1);
        assert_eq!(sources[0].service, "mysql");
        assert_eq!(sources[0].evidence, "unresolved");
        assert_eq!(sources[0].source_ref, "pid:200");
    }

    #[test]
    fn at_most_four_instances_are_reported_per_service() {
        let mut proc = FakeProc::default();
        let mut resources = Vec::new();
        for pid in 1..=6 {
            proc.argv
                .insert(pid, args(&["mysqld", "--datadir=/data/mysql"]));
            proc.dirs.insert(
                format!("/proc/{pid}/root/data/mysql"),
                "/data/mysql".to_string(),
            );
            resources.push(process_resource(pid, "/usr/sbin/mysqld", None));
        }
        let snapshot = snapshot(resources);

        let sources = resolve(&snapshot, &proc, &NoSearch);
        assert_eq!(sources.len(), MAX_CANDIDATES_PER_SERVICE);
    }

    #[test]
    fn per_service_cap_bounds_the_inspected_processes() {
        // 反复重启留下的残留进程不该把发现 tick 的耗时拉长：每个服务只看 4 个。
        let mut proc = FakeProc::default();
        let mut resources = Vec::new();
        for pid in 1..=40 {
            proc.argv.insert(pid, args(&["mysqld"]));
            resources.push(process_resource(pid, "/usr/sbin/mysqld", None));
        }
        let snapshot = snapshot(resources);

        let calls = std::cell::Cell::new(0usize);
        struct Counting<'a> {
            inner: &'a FakeProc,
            calls: &'a std::cell::Cell<usize>,
        }
        impl ProcAccess for Counting<'_> {
            fn nul_list(&self, pid: u32, file: ProcFile) -> Vec<String> {
                self.calls.set(self.calls.get() + 1);
                self.inner.nul_list(pid, file)
            }
            fn cwd(&self, pid: u32) -> Option<String> {
                self.inner.cwd(pid)
            }
            fn open_files(&self, pid: u32) -> Vec<String> {
                self.inner.open_files(pid)
            }
            fn read_file(&self, path: &str) -> Option<String> {
                self.inner.read_file(path)
            }
            fn canonical_dir(&self, path: &str) -> Option<String> {
                self.inner.canonical_dir(path)
            }
        }
        let sources = resolve(
            &snapshot,
            &Counting {
                inner: &proc,
                calls: &calls,
            },
            &NoSearch,
        );
        assert_eq!(sources.len(), MAX_CANDIDATES_PER_SERVICE);
        assert_eq!(
            calls.get(),
            MAX_CANDIDATES_PER_SERVICE * 2,
            "到上限就不再读 /proc（每进程两个文件）"
        );
    }

    #[test]
    fn unrelated_processes_are_ignored() {
        let proc = FakeProc::default();
        let snapshot = snapshot(vec![
            process_resource(1, "/usr/bin/mysqld_exporter", None),
            process_resource(2, "/usr/bin/redis-cli", None),
            process_resource(3, "/usr/sbin/nginx", None),
        ]);
        assert!(resolve(&snapshot, &proc, &NoSearch).is_empty());
    }

    #[test]
    fn nul_separated_proc_files_are_split_and_bounded() {
        assert_eq!(
            split_nul(b"postgres\0-D\0/data/pg\0", MAX_PROC_BYTES),
            vec![
                "postgres".to_string(),
                "-D".to_string(),
                "/data/pg".to_string()
            ]
        );
        assert_eq!(split_nul(b"", MAX_PROC_BYTES), Vec::<String>::new());
        // 非法 UTF-8 不 panic（environ 里可能有任意字节）。
        let decoded = split_nul(b"\xff\xfe\0ok\0", MAX_PROC_BYTES);
        assert!(decoded.contains(&"ok".to_string()), "{decoded:?}");
    }

    #[test]
    fn rooted_prefixes_the_process_root() {
        assert_eq!(rooted(7, "/data/pg/log"), "/proc/7/root/data/pg/log");
        assert_eq!(rooted(7, "/"), "/proc/7/root");
    }

    // ── L3 受限搜索：什么时候跑、命中怎么分 ──

    /// 假搜索：按服务返回**宿主视角**的目录。
    #[derive(Default)]
    struct FakeSearch {
        hits: BTreeMap<&'static str, Vec<search::Hit>>,
        calls: Cell<usize>,
    }

    impl FakeSearch {
        fn with(service: &'static str, dirs: &[&str]) -> Self {
            let hits = dirs
                .iter()
                .map(|dir| search::Hit {
                    log_dir: (*dir).to_string(),
                    detail: format!("search: 命中 {dir}"),
                })
                .collect();
            Self {
                hits: BTreeMap::from([(service, hits)]),
                calls: Cell::new(0),
            }
        }
    }

    impl SourceSearch for FakeSearch {
        fn search(&self, service: &str) -> Vec<search::Hit> {
            self.calls.set(self.calls.get() + 1);
            self.hits.get(service).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn search_fills_in_an_instance_whose_evidence_landed_nowhere() {
        // mysqld 跑着，但读不到 my.cnf、也没有打开的日志（容器里 /etc 不在这台机器上）。
        let proc = FakeProc::default();
        let snapshot = snapshot(vec![
            process_resource(200, "/usr/sbin/mysqld", None),
            endpoint_resource(200, 3306),
        ]);
        let search = FakeSearch::with("mysql", &["/data/mysql"]);

        let sources = resolve(&snapshot, &proc, &search);
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert_eq!(sources[0].service, "mysql");
        assert_eq!(sources[0].dir, "/data/mysql");
        assert_eq!(sources[0].evidence, "search_hit");
        // 身份仍是实例自己那个 —— 搜索只补 `dir`，不换身份。
        assert_eq!(sources[0].source_ref, "port:3306");
        assert!(sources[0].confidence < 60, "搜索是最低信任档");
    }

    #[test]
    fn search_never_runs_when_the_process_evidence_already_landed() {
        let mut proc = FakeProc::default();
        proc.argv
            .insert(200, args(&["mysqld", "--log-error=/var/log/mysql/e.log"]));
        proc.dirs.insert(
            "/proc/200/root/var/log/mysql".to_string(),
            "/var/log/mysql".to_string(),
        );
        let snapshot = snapshot(vec![process_resource(200, "/usr/sbin/mysqld", None)]);
        let search = FakeSearch::with("mysql", &["/data/mysql"]);

        let sources = resolve(&snapshot, &proc, &search);
        assert_eq!(sources[0].dir, "/var/log/mysql");
        assert_eq!(sources[0].evidence, "cmdline_logfile");
        assert_eq!(search.calls.get(), 0, "已经落地了就不该去走目录");
    }

    #[test]
    fn search_hits_are_handed_out_one_per_instance_and_searched_once() {
        let proc = FakeProc::default();
        let snapshot = snapshot(vec![
            process_resource(300, "/usr/bin/redis-server", None),
            process_resource(301, "/usr/bin/redis-server", None),
            process_resource(302, "/usr/bin/redis-server", None),
        ]);
        let search = FakeSearch::with("redis", &["/data/redis-1", "/data/redis-2"]);

        let sources = resolve(&snapshot, &proc, &search);
        let dirs: Vec<&str> = sources.iter().map(|source| source.dir.as_str()).collect();
        assert_eq!(
            dirs,
            vec!["/data/redis-1", "/data/redis-2", ""],
            "两个命中各给一个实例，第三个退回占位"
        );
        assert_eq!(sources[2].evidence, "unresolved");
        assert_eq!(search.calls.get(), 1, "每服务一拍只搜一次");
    }

    #[test]
    fn postgres_workers_do_not_consume_search_hits() {
        // worker 没有 `-D`（`proposals` 为空），拿命中去换会凭空造出实例。
        let mut proc = FakeProc::default();
        proc.argv.insert(101, args(&["postgres: checkpointer"]));
        let snapshot = snapshot(vec![
            process_resource(101, "/usr/bin/postgres", None),
            endpoint_resource(101, 5432),
        ]);
        let search = FakeSearch::with("postgresql", &["/data/pg/log"]);

        let sources = resolve(&snapshot, &proc, &search);
        assert!(sources.is_empty(), "{sources:?}");
        assert_eq!(search.calls.get(), 0, "worker 连搜索都不该触发");
    }

    #[test]
    fn a_search_hit_is_reported_for_a_postmaster_whose_log_directory_is_missing() {
        // 有 `-D`（所以是实例），但 `<datadir>/log` 不在；搜索找到了别的日志目录。
        let mut proc = FakeProc::default();
        proc.argv.insert(100, args(&["postgres", "-D", "/data/pg"]));
        let snapshot = snapshot(vec![
            process_resource(100, "/usr/bin/postgres", None),
            endpoint_resource(100, 5432),
        ]);
        let search = FakeSearch::with("postgresql", &["/data/db/pg-logs"]);

        let sources = resolve(&snapshot, &proc, &search);
        assert_eq!(sources.len(), 1, "{sources:?}");
        assert_eq!(sources[0].dir, "/data/db/pg-logs");
        assert_eq!(sources[0].evidence, "search_hit");
        assert_eq!(search.calls.get(), 1);
    }

    /// 策略是唯一入口：没有 roots 的服务**不搜**（不会因为“能搜”就去搜）。
    #[test]
    fn the_policy_decides_which_services_may_search() {
        let root = std::env::temp_dir().join(format!(
            "wist-policy-search-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&root).expect("create root");
        std::fs::write(root.join("dump.rdb"), b"x").expect("write marker");

        let policy = crate::control::source_search_policy::SourceSearchPolicy {
            catalog_version: 15,
            services: BTreeMap::from([(
                "redis".to_string(),
                vec![root.to_string_lossy().into_owned()],
            )]),
            fetched_at: String::new(),
        };
        let search = PolicySearch {
            policy: &policy,
            budget: std::cell::RefCell::new(search::Budget::new()),
        };

        // 策略里没给 postgresql → 一条都不找（也不会白读目录）。
        assert!(search.search("postgresql").is_empty());
        // 给了 redis → 真的找，且命中这个目录。
        let hits = search.search("redis");
        assert_eq!(hits.len(), 1, "{hits:?}");
        assert_eq!(
            hits[0].log_dir,
            std::fs::canonicalize(&root)
                .expect("canonicalize")
                .to_string_lossy()
        );

        let _ = std::fs::remove_dir_all(&root);
    }
}
