//! 负载调查（`wist-agentd investigate load`）：**负载高了，到底是谁在吃 CPU / 内存 / IO**。
//!
//! 现场看到的是「负载 80」这种数字，但负载只是一条**排队长度**：同样 80，可能是 16 核跑满、
//! 也可能 CPU 闲着而一堆进程卡在磁盘上。所以这一题按「先分流 → 再点名」给八节证据：
//!
//! 1. `load.summary` — 1/5/15 分钟负载 + 核数 + **每核负载** + 运行队列 / CPU 压力（Linux）；
//! 2. `load.cpu` — 总体与**每核**占用，Linux 还给 user/system/iowait/idle 的去向；
//! 3. `load.top_services` — 按**服务**聚合（cgroup 归属 + 累加）—— 多 worker 服务只有加总才看得见；
//! 4. `load.top_processes` — 按 CPU 排的进程（**不放 argv**，只给名字，见下）；
//! 5. `load.memory` — 物理内存与 swap（swap 在用 = 已经在换页，延迟会抖）；
//! 6. `load.io` — iowait / PSI io 压力 / **不可中断睡眠（D 状态）进程数**；
//! 7. `load.agent_processes` — 先排除「是不是我们自己」（调查与采集本身也吃 CPU）；
//! 8. `load.sample` — 这次采样的窗口与平台能力（**没有采到 ≠ 正常**）。
//!
//! 为什么必须有一节是**服务**：磁盘题的教训是「最大的文件不是根因，目录才是」；
//! CPU 题一模一样 —— nginx/gunicorn/JVM 都是多进程多 worker，每个子进程单看都不大，
//! 加起来才是一个核。只给进程榜，现场会得出“没人忙”的错误结论。
//!
//! 为什么「每核负载」是核心判据：负载不分平台都只是 runnable + uninterruptible 的**数量**，
//! 拿它跟核数比才有意义。`load 8` 在 32 核上是闲的，在 4 核上已经过载。
//!
//! 为什么单列「不可中断睡眠」：**负载高但 CPU 空闲**的头号原因是进程卡在磁盘/网络存储上
//! （`D` 状态，杀不掉、也不吃 CPU）。只看 CPU 排行会得出「没有谁在忙」的错误结论，然后
//! 去扩容 CPU —— 那不是根因。
//!
//! 关于 argv（脱敏）：`argv` 里经常有数据库密码、令牌、证书路径。这一题**只报进程名**，
//! 需要看完整命令行时由人自己 `ps`（报告会给出确切命令，但不把 argv 写进会上送的文件）。

#[cfg(target_os = "linux")]
use std::fs;
use std::time::Duration;

use sysinfo::{ProcessesToUpdate, System};

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{Finding, InvestigateRequest, Row, human_bytes};

/// 每核负载的判定线：LoadPerCore ≥ 1 = 每个核上都排着队（已经饱和）。
pub(crate) const LOAD_WARN_PER_CORE: f64 = 1.0;
/// ≥ 2 = 排队长度是核数的两倍：不是尖峰，是真顶不住。
pub(crate) const LOAD_FAIL_PER_CORE: f64 = 2.0;

const CPU_WARN_PERCENT: f64 = 85.0;
const CPU_FAIL_PERCENT: f64 = 95.0;
const MEMORY_WARN_PERCENT: f64 = 85.0;
const MEMORY_FAIL_PERCENT: f64 = 95.0;
/// swap 用到一半就该警惕：再往上就是换页风暴（吞吐掉、延迟抖）。
const SWAP_WARN_PERCENT: f64 = 50.0;
/// iowait 占 20% 以上，说明 CPU 在等 IO —— 扩容 CPU 帮不上忙。
const IOWAIT_WARN_PERCENT: f64 = 20.0;
/// 有几个进程整卡在 D 状态，就已经不是偶发。
const D_STATE_WARN: usize = 3;

/// 一个服务（或进程组）吃了多少 CPU 值得报警。
///
/// 为什么不是“单个进程”：nginx/gunicorn/JVM 这类服务是**多进程/多 worker** 的，
/// 每个子进程单看都不大，加起来却是一个核。判据得放在**服务**这一层，
/// 与磁盘题“最大的文件不是根因，目录才是”是同一条道理。
const SERVICE_CPU_WARN: f64 = 100.0;
const SERVICE_CPU_FAIL: f64 = 300.0;

const AGENT_CPU_WARN: f64 = 100.0;
const AGENT_CPU_FAIL: f64 = 300.0;
const AGENT_RSS_WARN: u64 = 1 << 30;
const AGENT_RSS_FAIL: u64 = 4 << 30;

/// CPU 压力（PSI `some avg10`）：有任务在等 CPU 的时间占比。
const PSI_CPU_WARN_PERCENT: f64 = 30.0;

/// 采样窗口：sysinfo 的 CPU% 是**两次刷新之间的增量**，低于
/// `MINIMUM_CPU_UPDATE_INTERVAL`(200ms) 会得到 0。
///
/// 下限 1s（降噪），上限 3s：周期性的批处理/GC 尖峰在 1s 里经常刚好躲过，
/// 而调查多等 2s 是值得的。`--max-seconds` 可以把窗口拉到上限。
const SAMPLE_WINDOW_FLOOR_MS: u64 = 1_000;
const SAMPLE_WINDOW_CEIL_MS: u64 = 3_000;
/// 窗口短于这个值，数字只能当参考（`load.sample` 会判 WARN）。
const SAMPLE_WINDOW_SUSPECT_MS: u64 = 300;

/// `/proc/<pid>/cgroup` 读取上限（每台机器一次调查）。
/// 归属是**锦上添花**：超了就退回可执行名，不能让它把调查拖成 IO 长跑。
const CGROUP_PID_LIMIT: usize = 4_096;
/// 被跟踪的 cgroup 数量上限（容器化机器上可能上千）。
#[cfg(target_os = "linux")]
const CGROUP_TRACK_LIMIT: usize = 256;

/// CPU 排行里最多列几行核（16 核以上全列就是一堵墙）。
const MAX_CORE_ROWS: usize = 8;
/// 一个核忙到这个程度才值得单独列一行。
const CORE_BUSY_PERCENT: f64 = 10.0;

/// agent 自己的进程名（`wist-exec` 是 agentd 拉起的执行器，一起算）。
const AGENT_BINARIES: &[&str] = &["wist-agentd", "wist-exec", "wist-upgrader"];

/// 跑一遍负载调查，返回各节结果（顺序即展示顺序）。
pub(crate) fn investigate(
    request: &InvestigateRequest,
    config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    let snapshot = sample(request, config)?;
    Ok(vec![
        summary_finding(&snapshot),
        cpu_finding(&snapshot),
        // 「哪个服务」比「哪个进程」更接近现场要的答案，排在进程榜前面。
        services_finding(&snapshot),
        top_processes_finding(&snapshot, request.top),
        memory_finding(&snapshot),
        io_finding(&snapshot),
        agent_processes_finding(&snapshot, config.is_some()),
        sample_finding(&snapshot, request),
    ])
}

// ---------------------------------------------------------------------------
// 采样
// ---------------------------------------------------------------------------

/// 一个进程的**只留必要信息**的采样（**不含 argv** —— 见文件头「脱敏」）。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ProcessSample {
    pub pid: u32,
    pub name: String,
    /// CPU 占用（百分比；多线程进程会超过 100）。
    pub cpu: f32,
    /// 常驻内存（字节）。
    pub rss: u64,
    /// 状态缩写（`R` / `S` / `D` / `Z` …）。
    pub state: String,
    /// 已运行秒数。
    pub run_time: u64,
    /// 是不是我们自己的进程。
    pub agent: bool,
    /// **服务归属**：Linux 取 cgroup（unit / daemon / docker / k8s），其它平台按可执行名。
    pub service: String,
    /// 归属来源：`cgroup` / `exe`。
    pub service_source: &'static str,
}

/// 一个服务（当前窗口内）的合计。
///
/// `cpu` 优先用 **cgroup 累计差**（精确，包含窗口内起落的进程），
/// 拿不到时才退化成“把各进程的采样值加起来”（会漏掉已退出的小进程）。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct ServiceGroup {
    pub label: String,
    pub source: &'static str,
    /// 归属到这个名字的**当前存活进程数**（0 = 只在窗口内短暂存在过）。
    pub processes: usize,
    pub cpu: f64,
    pub cpu_exact: bool,
    pub rss: u64,
}

/// Linux 才有的几个信号（其它平台为 `None`，由渲染层**说出来**，而不是假装 0）。
#[derive(Debug, Clone, Copy, Default, PartialEq)]
pub(crate) struct IoSignals {
    /// 采样窗口内 iowait 占 CPU 时间的百分比。
    pub iowait_percent: Option<f64>,
    /// `/proc/loadavg` 第 4 段的「可运行/总线程数」。
    pub runnable: Option<u32>,
    pub total_tasks: Option<u32>,
    /// `/proc/pressure/io` 的 some/full avg10（有 PSI 的内核才有）。
    pub psi_some: Option<f64>,
    pub psi_full: Option<f64>,
}

/// 一次采样的全部证据。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct Snapshot {
    pub logical_cores: usize,
    pub physical_cores: Option<usize>,
    pub load1: f64,
    pub load5: f64,
    pub load15: f64,
    pub global_cpu: f64,
    /// 每个逻辑核的占用（下标 = 核序号）。
    pub cores: Vec<f64>,
    /// Linux 的 CPU 时间去向（采样窗口内的占比）。
    pub cpu_breakdown: Option<CpuBreakdown>,
    /// 按 CPU 降序、已截断到 `top` 的进程。
    pub processes: Vec<ProcessSample>,
    /// 按 CPU 降序、已截断到 `top` 的**服务**（多进程服务已加总）。
    pub services: Vec<ServiceGroup>,
    /// 归因到的服务总数（截断前）。
    pub service_total: usize,
    /// 归属是不是来自 cgroup（`false` = 只能按可执行名，同一服务的多个文件可能被拆开）。
    pub service_identity_cgroup: bool,
    /// 有 cgroup 精确值的服务数（其余靠进程采样加总）。
    pub services_exact: usize,
    /// `/proc/pressure/cpu` 的 some/full avg10。
    pub psi_cpu: Option<(f64, f64)>,
    /// 系统里的进程总数（截断前）。
    pub process_total: usize,
    pub memory_total: u64,
    pub memory_used: u64,
    pub memory_available: u64,
    pub swap_total: u64,
    pub swap_used: u64,
    /// 处于不可中断睡眠（`D`）的进程数。
    pub d_state: usize,
    pub io: IoSignals,
    /// 想等的采样窗口（毫秒）。
    pub window_ms: u64,
    /// **真实**经过的时间（毫秒）：机器忙时 `sleep` 会超时，百分比的分母用的是它。
    pub elapsed_ms: u64,
    pub agent_cpu: f64,
    pub agent_rss: u64,
    pub agent_processes: usize,
}

/// Linux 的 CPU 时间去向（`/proc/stat` 两次采样的增量）。
#[derive(Debug, Clone, Copy, PartialEq)]
pub(crate) struct CpuBreakdown {
    pub user: f64,
    pub system: f64,
    pub iowait: f64,
    pub idle: f64,
}

impl Snapshot {
    fn per_core_load(&self) -> f64 {
        if self.logical_cores == 0 {
            0.0
        } else {
            self.load1 / self.logical_cores as f64
        }
    }

    fn memory_percent(&self) -> f64 {
        if self.memory_total == 0 {
            0.0
        } else {
            self.memory_used as f64 / self.memory_total as f64 * 100.0
        }
    }

    fn swap_percent(&self) -> f64 {
        if self.swap_total == 0 {
            0.0
        } else {
            self.swap_used as f64 / self.swap_total as f64 * 100.0
        }
    }
}

fn sample_window(max_seconds: u64) -> Duration {
    Duration::from_millis(
        (max_seconds.saturating_mul(1000)).clamp(SAMPLE_WINDOW_FLOOR_MS, SAMPLE_WINDOW_CEIL_MS),
    )
}

/// 采一次样：两次刷新之间的增量就是 CPU 占用的定义。
fn sample(request: &InvestigateRequest, config: Option<&AgentConfig>) -> Result<Snapshot, String> {
    let window = sample_window(request.max_seconds);
    let mut system = System::new();
    // 第一次刷新只是把「基准」立起来；sysinfo 的 CPU% 需要前后两次才能算出来。
    system.refresh_cpu_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system.refresh_memory();
    let stat_before = cpu_times_before();
    // cgroup 累计值：CPU 时间的**权威口径**（不依赖进程采样，窗口内起落的也算得到）。
    let pids: Vec<u32> = system.processes().keys().map(|pid| pid.as_u32()).collect();
    let cgroup_before = collect_cgroup_usage(&pids, None);
    // 计时从**基准读完**开始：分母取真实经过的时间，而不是我们想等的 `window`。
    let started = std::time::Instant::now();

    std::thread::sleep(window);

    system.refresh_cpu_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system.refresh_memory();
    let stat_after = cpu_times_before();
    let cgroup_after = collect_cgroup_usage(&[], Some(&cgroup_before));
    let elapsed = started.elapsed().max(window);

    let load = System::load_average();
    let logical_cores = system.cpus().len();
    let mut cores: Vec<f64> = system
        .cpus()
        .iter()
        .map(|cpu| cpu.cpu_usage() as f64)
        .collect();
    cores.sort_by(|a, b| b.total_cmp(a));

    let mut processes: Vec<ProcessSample> = Vec::new();
    let mut d_state = 0usize;
    let mut labels = LabelCache::default();
    for (pid, process) in system.processes() {
        let name = process.name().to_string_lossy().to_string();
        let state = describe_status(process.status());
        if matches!(
            process.status(),
            sysinfo::ProcessStatus::UninterruptibleDiskSleep
        ) {
            d_state += 1;
        }
        let agent = is_agent_process(&name, process.exe(), config);
        let (service, service_source) = labels.get(pid.as_u32(), &name, process.exe());
        processes.push(ProcessSample {
            pid: pid.as_u32(),
            name: if name.is_empty() {
                "(unknown)".to_string()
            } else {
                name
            },
            cpu: process.cpu_usage(),
            rss: process.memory(),
            state: state.to_string(),
            run_time: process.run_time(),
            agent,
            service,
            service_source,
        });
    }
    processes.sort_by(|a, b| {
        b.cpu
            .total_cmp(&a.cpu)
            .then_with(|| b.rss.cmp(&a.rss))
            .then_with(|| a.pid.cmp(&b.pid))
    });
    let process_total = processes.len();
    // agent 的账要在**截断前**算：它可能 CPU 很低、根本进不了前 N。
    let (agent_cpu, agent_rss, agent_processes) = processes
        .iter()
        .filter(|process| process.agent)
        .fold((0.0f64, 0u64, 0usize), |(cpu, rss, count), process| {
            (cpu + process.cpu as f64, rss + process.rss, count + 1)
        });
    let exact_cpu = exact_service_cpu(&cgroup_before, &cgroup_after, elapsed);
    let service_identity_cgroup = processes
        .iter()
        .any(|process| process.service_source == "cgroup");
    let (services, service_total, services_exact) =
        build_services(&processes, &exact_cpu, request.top.max(1));
    processes.truncate(request.top.max(1));

    let loadavg = read_loadavg();
    let cpu_breakdown = match (stat_before, stat_after) {
        (Some(before), Some(after)) => breakdown(before, after),
        _ => None,
    };
    let psi = read_psi_io();

    Ok(Snapshot {
        logical_cores,
        physical_cores: System::physical_core_count(),
        load1: load.one,
        load5: load.five,
        load15: load.fifteen,
        global_cpu: system.global_cpu_usage() as f64,
        cores,
        cpu_breakdown,
        processes,
        services,
        service_total,
        service_identity_cgroup,
        services_exact,
        psi_cpu: read_psi_cpu(),
        process_total,
        memory_total: system.total_memory(),
        memory_used: system.used_memory(),
        memory_available: system.available_memory(),
        swap_total: system.total_swap(),
        swap_used: system.used_swap(),
        d_state,
        io: IoSignals {
            iowait_percent: cpu_breakdown.map(|breakdown| breakdown.iowait),
            runnable: loadavg.map(|value| value.0),
            total_tasks: loadavg.map(|value| value.1),
            psi_some: psi.map(|value| value.0),
            psi_full: psi.map(|value| value.1),
        },
        window_ms: window.as_millis() as u64,
        elapsed_ms: elapsed.as_millis() as u64,
        agent_cpu,
        agent_rss,
        agent_processes,
    })
}

/// sysinfo 的进程状态 → 一个字母（与 `ps` 的 `STAT` 对齐，方便现场对照）。
fn describe_status(status: sysinfo::ProcessStatus) -> &'static str {
    use sysinfo::ProcessStatus as P;
    match status {
        P::Idle => "I",
        P::Run => "R",
        P::Sleep => "S",
        P::Stop => "T",
        P::Zombie => "Z",
        P::Tracing => "t",
        P::Dead => "X",
        P::Wakekill => "K",
        P::Waking => "W",
        P::Parked => "P",
        P::LockBlocked => "L",
        P::UninterruptibleDiskSleep => "D",
        P::Suspended => "T",
        P::Unknown(_) => "?",
    }
}

fn is_agent_process(
    name: &str,
    exe: Option<&std::path::Path>,
    config: Option<&AgentConfig>,
) -> bool {
    if AGENT_BINARIES.iter().any(|binary| name.starts_with(binary)) {
        return true;
    }
    // 名字被改过（或用了带前缀的包装脚本）时，用落点目录兜底：
    // 只有当 exe 在 agent 自己的 root_dir 下才算 —— 不能把「/opt/anything」都算成自己。
    match (exe, config) {
        (Some(exe), Some(config)) => exe.starts_with(&config.paths.root_dir),
        _ => false,
    }
}

// ---------------------------------------------------------------------------
// 服务归属（pid → 服务）：cgroup 优先，退化为可执行名
// ---------------------------------------------------------------------------

/// 一个 pid 的服务归属。
///
/// Linux 上取 cgroup：`systemd` unit、`docker-<id>.scope`、`kubepods…/pod<uid>` ——
/// 这才是“服务”的**权威身份**（进程名会重名，容器里的 `java` 更是到处都有）。
/// 其它平台拿不到这个口径，只能按可执行名聚合，渲染层会**明说**这个局限。
fn service_of(pid: u32, name: &str, exe: Option<&std::path::Path>) -> (String, &'static str) {
    #[cfg(target_os = "linux")]
    if let Some(path) = cgroup_path_of(pid)
        && let Some(label) = service_label_from_cgroup(&path)
    {
        return (label, "cgroup");
    }
    let _ = pid;
    exe_service(name, exe)
}

/// 归属的**退路**：按可执行名（拿不到 cgroup，或读次数超限时用）。
fn exe_service(name: &str, exe: Option<&std::path::Path>) -> (String, &'static str) {
    // `exe` 的 basename 比 `comm`（Linux 上被截到 15 字符）更像服务名。
    let from_exe = exe
        .and_then(|path| path.file_name())
        .map(|value| value.to_string_lossy().to_string())
        .filter(|value| !value.is_empty());
    match from_exe {
        Some(value) => (value, "exe"),
        None if !name.is_empty() => (name.to_string(), "exe"),
        None => ("(unknown)".to_string(), "exe"),
    }
}

/// pid → 归属的缓存：每个 pid 最多读一次 `/proc/<pid>/cgroup`，
/// 总量封顶 [`CGROUP_PID_LIMIT`]（超了退回可执行名）。
#[derive(Default)]
struct LabelCache {
    labels: std::collections::HashMap<u32, (String, &'static str)>,
    reads: usize,
}

impl LabelCache {
    fn get(
        &mut self,
        pid: u32,
        name: &str,
        exe: Option<&std::path::Path>,
    ) -> (String, &'static str) {
        if let Some(hit) = self.labels.get(&pid) {
            return hit.clone();
        }
        let value = if self.reads < CGROUP_PID_LIMIT {
            self.reads += 1;
            service_of(pid, name, exe)
        } else {
            exe_service(name, exe)
        };
        self.labels.insert(pid, value.clone());
        value
    }
}

/// `/proc/<pid>/cgroup` → 统一路径：v2 的 `0::/…` 或 v1 的 `name=systemd:/…`。
#[cfg(any(target_os = "linux", test))]
fn parse_cgroup_path(text: &str) -> Option<String> {
    for line in text.lines() {
        let Some((hierarchy, rest)) = line.split_once(':') else {
            continue;
        };
        let Some((controllers, path)) = rest.split_once(':') else {
            continue;
        };
        let unified = hierarchy == "0" && controllers.is_empty();
        let systemd = controllers.split(',').any(|name| name == "name=systemd");
        if (unified || systemd) && !path.trim().is_empty() {
            return Some(path.trim().to_string());
        }
    }
    None
}

/// cgroup 路径 → 服务名（纯函数）。
///
/// 识别不了就返回 `None`（由调用方退回可执行名）——**不要**把一长串 cgroup 路径
/// 当成服务名塞进表格：那种名字没人能拿去定位。
#[cfg(any(target_os = "linux", test))]
fn service_label_from_cgroup(path: &str) -> Option<String> {
    let last = path.rsplit('/').find(|segment| !segment.is_empty())?;

    // docker run / systemd 包装的容器
    if let Some(id) = last
        .strip_prefix("docker-")
        .and_then(|rest| rest.strip_suffix(".scope"))
    {
        return Some(format!("docker:{}", short_id(id)));
    }
    // containerd / cri-o / podman（podman 的 scope 形如 libpod-<id>.scope）
    for prefix in ["cri-containerd-", "crio-", "libpod-"] {
        if let Some(id) = last
            .strip_prefix(prefix)
            .and_then(|rest| rest.strip_suffix(".scope"))
        {
            return Some(format!("container:{}", short_id(id)));
        }
    }
    // systemd unit（system.slice/nginx.service、user@1000.service…）
    if last.ends_with(".service") {
        return Some(last.to_string());
    }
    // k8s：`kubepods-burstable-pod<uid>.slice`
    //
    // **必须先确认是 kubepods 前缀**：`find("-pod")` 会把 `mypod-worker.service`
    // 这种普通 unit 误判成 pod（服务名里带 “-pod” 并不罕见）。
    if last.starts_with("kubepods") {
        if let Some(index) = last.find("-pod") {
            let uid = last[index + 4..].trim_end_matches(".slice");
            if !uid.is_empty() {
                return Some(format!("k8s:pod/{}", short_id(uid)));
            }
        }
        return Some("k8s:kubepods".to_string());
    }
    // 用户会话（session-3.scope / user@1000.service 已被上面接住）
    if last.starts_with("session-") {
        return Some(format!("user-session:{}", last.trim_end_matches(".scope")));
    }
    None
}

/// 容器 ID / pod uid 太长，取前 12 位（`docker ps --filter id=<前缀>` 能用）。
///
/// pod uid 是 UUID（带连字符），先把 `-` 去掉再截：否则前 12 位会摊上一个 `-`，
/// 看起来像被截坏的 ID。
#[cfg(any(target_os = "linux", test))]
fn short_id(value: &str) -> String {
    value.chars().filter(|ch| *ch != '-').take(12).collect()
}

/// 一次采样里收集到的 cgroup 用量：`path → (服务名, usage_usec)`。
type CgroupUsage = std::collections::BTreeMap<String, (String, u64)>;

/// 收集 cgroup 累计 CPU 用量：`previous = None` 时重新扫一遍 pid，
/// `Some(基准)` 时只重读基准里的路径（进程在窗口内起落不影响口径）。
#[cfg(target_os = "linux")]
fn collect_cgroup_usage(pids: &[u32], previous: Option<&CgroupUsage>) -> CgroupUsage {
    let mut usage = CgroupUsage::new();
    if let Some(before) = previous {
        for (path, (label, _)) in before {
            if let Some(value) = read_cgroup_usage_usec(path) {
                usage.insert(path.clone(), (label.clone(), value));
            }
        }
        return usage;
    }
    for pid in pids.iter().take(CGROUP_PID_LIMIT) {
        if usage.len() >= CGROUP_TRACK_LIMIT {
            break;
        }
        let Some(path) = cgroup_path_of(*pid) else {
            continue;
        };
        if usage.contains_key(&path) {
            continue;
        }
        let Some(label) = service_label_from_cgroup(&path) else {
            continue;
        };
        if let Some(value) = read_cgroup_usage_usec(&path) {
            usage.insert(path, (label, value));
        }
    }
    usage
}

#[cfg(not(target_os = "linux"))]
fn collect_cgroup_usage(_pids: &[u32], _previous: Option<&CgroupUsage>) -> CgroupUsage {
    CgroupUsage::new()
}

/// 两次 cgroup 累计值之差 → 每个服务的 CPU%（100% = 一个核）。
///
/// `elapsed` 必须是**真实经过的时间**，不是我们想等的 `window`：机器越忙，`sleep`
/// 越容易超时 —— 而这种机器恰好就是调查对象用分母去“应该等多久”，会把每个服务的 CPU
/// 都算高（同一个错误会同时抬高所有行，看起来反而像“整体负载高”）。
fn exact_service_cpu(
    before: &CgroupUsage,
    after: &CgroupUsage,
    elapsed: Duration,
) -> std::collections::BTreeMap<String, f64> {
    let window_us = elapsed.as_micros().max(1) as f64;
    let mut totals: std::collections::BTreeMap<String, u64> = std::collections::BTreeMap::new();
    for (path, (label, after_us)) in after {
        let Some((_, before_us)) = before.get(path) else {
            continue;
        };
        let delta = after_us.saturating_sub(*before_us);
        *totals.entry(label.clone()).or_insert(0) += delta;
    }
    totals
        .into_iter()
        .map(|(label, usec)| (label, usec as f64 / window_us * 100.0))
        .collect()
}

/// 把一个进程的采样聚合成服务：**先用 cgroup 精确值，没有才把采样加起来**。
///
/// 精确值还包含「窗口内起落、采样时已经没了」的进程 —— 这正是周期性任务最容易
/// 被单点采样漏掉的那部分，所以它们在表里会出现（`进程数 = 0` 时备注会说明）。
fn build_services(
    processes: &[ProcessSample],
    exact: &std::collections::BTreeMap<String, f64>,
    top: usize,
) -> (Vec<ServiceGroup>, usize, usize) {
    let mut groups: std::collections::BTreeMap<&str, (usize, f64, u64, &'static str)> =
        std::collections::BTreeMap::new();
    for process in processes {
        let entry =
            groups
                .entry(process.service.as_str())
                .or_insert((0, 0.0, 0, process.service_source));
        entry.0 += 1;
        entry.1 += process.cpu as f64;
        entry.2 = entry.2.saturating_add(process.rss);
    }
    let mut services: Vec<ServiceGroup> = groups
        .into_iter()
        .map(
            |(label, (count, sampled, rss, source))| match exact.get(label) {
                Some(value) => ServiceGroup {
                    label: label.to_string(),
                    source,
                    processes: count,
                    cpu: value.max(0.0),
                    cpu_exact: true,
                    rss,
                },
                None => ServiceGroup {
                    label: label.to_string(),
                    source,
                    processes: count,
                    cpu: sampled.max(0.0),
                    cpu_exact: false,
                    rss,
                },
            },
        )
        .collect();
    // 只在窗口内存在过的服务（采样时已经没有进程了）：cgroup 告诉我们它们真的在吃 CPU。
    for (label, cpu) in exact {
        if services.iter().any(|service| &service.label == label) {
            continue;
        }
        services.push(ServiceGroup {
            label: label.clone(),
            source: "cgroup",
            processes: 0,
            cpu: *cpu,
            cpu_exact: true,
            rss: 0,
        });
    }
    services.sort_by(|a, b| {
        b.cpu
            .total_cmp(&a.cpu)
            .then_with(|| b.rss.cmp(&a.rss))
            .then_with(|| a.label.cmp(&b.label))
    });
    let total = services.len();
    // 精确值计数要在**截断前**算：截断后数，会把“有 cgroup 口径但排在前面的都是采样值”
    // 误报成“本机没有 cgroup 口径”。
    let exact_total = services.iter().filter(|service| service.cpu_exact).count();
    services.truncate(top);
    (services, total, exact_total)
}

#[cfg(target_os = "linux")]
fn cgroup_path_of(pid: u32) -> Option<String> {
    let text = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    parse_cgroup_path(&text)
}

/// 读一个 cgroup 的累计 CPU 时间（微秒）。
///
/// v2 是 `cpu.stat` 的 `usage_usec`；v1 是 `cpuacct.usage`（纳秒）。
/// 读不到（权限/不存在）就返回 `None`，由调用方退化成进程采样。
#[cfg(target_os = "linux")]
fn read_cgroup_usage_usec(path: &str) -> Option<u64> {
    let root = path.trim_end_matches('/');
    if let Ok(text) = fs::read_to_string(format!("/sys/fs/cgroup{root}/cpu.stat")) {
        for line in text.lines() {
            if let Some(value) = line.strip_prefix("usage_usec ") {
                return value.trim().parse().ok();
            }
        }
    }
    let text =
        fs::read_to_string(format!("/sys/fs/cgroup/cpu,cpuacct{root}/cpuacct.usage")).ok()?;
    text.trim().parse::<u64>().ok().map(|ns| ns / 1_000)
}

// ---------------------------------------------------------------------------
// 判定
// ---------------------------------------------------------------------------

fn classify_percent(used_percent: f64) -> Status {
    if used_percent >= CPU_FAIL_PERCENT {
        Status::Fail
    } else if used_percent >= CPU_WARN_PERCENT {
        Status::Warn
    } else {
        Status::Ok
    }
}

fn classify_load(per_core: f64) -> Status {
    if per_core >= LOAD_FAIL_PER_CORE {
        Status::Fail
    } else if per_core >= LOAD_WARN_PER_CORE {
        Status::Warn
    } else {
        Status::Ok
    }
}

fn classify_memory(percent: f64) -> Status {
    if percent >= MEMORY_FAIL_PERCENT {
        Status::Fail
    } else if percent >= MEMORY_WARN_PERCENT {
        Status::Warn
    } else {
        Status::Ok
    }
}

// ---------------------------------------------------------------------------
// 八节
// ---------------------------------------------------------------------------

/// 负载本身：**每核负载**才是判据，绝对数字只用于对账。
fn summary_finding(snapshot: &Snapshot) -> Finding {
    let per_core = snapshot.per_core_load();
    let status = classify_load(per_core);

    let mut rows = Vec::new();
    for (label, value) in [
        ("1 分钟负载", snapshot.load1),
        ("5 分钟负载", snapshot.load5),
        ("15 分钟负载", snapshot.load15),
    ] {
        rows.push(Row::new(
            label,
            format!("{value:.2}"),
            format!("每核 {:.2}", value / snapshot.logical_cores.max(1) as f64),
        ));
    }
    if let (Some(runnable), Some(total)) = (snapshot.io.runnable, snapshot.io.total_tasks) {
        rows.push(Row::new(
            "运行队列（可运行/总线程）",
            format!("{runnable} / {total}"),
            format!("{} 个逻辑核", snapshot.logical_cores),
        ));
    }
    if let Some((some, full)) = snapshot.psi_cpu {
        rows.push(Row::new(
            "CPU 压力 some / full（avg10）",
            format!("{some:.1}% / {full:.1}%"),
            "有任务在等 CPU 的时间占比（PSI）",
        ));
    }

    let cores_note = match snapshot.physical_cores {
        Some(physical) if physical != snapshot.logical_cores => {
            format!(
                "{} 个逻辑核（{} 个物理核）",
                snapshot.logical_cores, physical
            )
        }
        _ => format!("{} 个逻辑核", snapshot.logical_cores),
    };
    let trend = if snapshot.load1 > snapshot.load15 {
        "在涨"
    } else if snapshot.load1 < snapshot.load15 {
        "在落"
    } else {
        "持平"
    };
    let detail = format!(
        "{cores_note}；1 分钟负载 {:.2}（每核 {per_core:.2}，{trend}）；CPU {:.1}% 忙",
        snapshot.load1, snapshot.global_cpu
    );

    let title = match status {
        Status::Ok => "负载正常",
        Status::Warn => "负载偏高",
        Status::Fail => "负载远超核数",
    };
    let mut finding = Finding::new("load.summary", status, title, detail).rows(rows);

    if status != Status::Ok {
        let mut hint = String::new();
        if snapshot.global_cpu >= CPU_WARN_PERCENT {
            hint.push_str(
                "CPU 确实在忙：先看「按服务聚合」点名**哪个服务**（多 worker 服务单看进程会被摊薄），\
                 再用「最吃 CPU 的进程」定位到 pid，最后才谈扩容/限流/改并发",
            );
        } else {
            hint.push_str(
                "**CPU 不忙而负载高**：几乎一定是进程卡在磁盘/网络存储上（不可中断睡眠）。\
                 先看「IO 等待与不可中断睡眠」，再用 `wist-agentd investigate disk` 找是谁在写",
            );
        }
        if let Some((some, _)) = snapshot.psi_cpu
            && some >= PSI_CPU_WARN_PERCENT
        {
            hint.push_str(&format!(
                "\nCPU 压力 some avg10 = {some:.1}%：有任务在**排队等 CPU**，光看平均利用率会低估饱和程度",
            ));
        }
        if snapshot.per_core_load() >= 1.0 && snapshot.d_state >= D_STATE_WARN {
            hint.push_str(&format!(
                "\n当前有 {} 个进程处于 D 状态：它们不吃 CPU，但会把负载顶上去",
                snapshot.d_state
            ));
        }
        finding = finding.hint(hint);
    }
    finding
}

fn cpu_finding(snapshot: &Snapshot) -> Finding {
    // 单个核被打满也算异常：总占用可能只有 20%，但那个线程就是卡在 100% 上——
    // 这是「负载不高但服务慢」最常见的形态（单线程/单连接/单 consumer）。
    let saturated = snapshot
        .cores
        .iter()
        .filter(|usage| **usage >= CPU_FAIL_PERCENT)
        .count();
    let status = classify_percent(snapshot.global_cpu).max(if saturated > 0 {
        Status::Warn
    } else {
        Status::Ok
    });
    let busy_count = snapshot
        .cores
        .iter()
        .filter(|usage| **usage >= CORE_BUSY_PERCENT)
        .count();
    let busy: Vec<(usize, f64)> = snapshot
        .cores
        .iter()
        .enumerate()
        .filter(|(_, usage)| **usage >= CORE_BUSY_PERCENT)
        .take(MAX_CORE_ROWS)
        .map(|(index, usage)| (index, *usage))
        .collect();

    let busiest = snapshot
        .cores
        .first()
        .map(|usage| format!("最忙的核 {usage:.1}%"))
        .unwrap_or_else(|| "读不到每核占用".to_string());
    let mut detail = format!(
        "总体 {:.1}% 忙；{} 个逻辑核里 {} 个超过 {CORE_BUSY_PERCENT:.0}%；{busiest}",
        snapshot.global_cpu, snapshot.logical_cores, busy_count
    );
    if let Some(breakdown) = snapshot.cpu_breakdown {
        detail.push_str(&format!(
            "；CPU 时间去向：user {:.1}% / system {:.1}% / iowait {:.1}% / idle {:.1}%",
            breakdown.user, breakdown.system, breakdown.iowait, breakdown.idle
        ));
    }

    let rows: Vec<Row> = busy
        .iter()
        .map(|(index, usage)| {
            Row::new(
                format!("CPU {index}"),
                format!("{usage:.1}% 忙"),
                if *usage >= CPU_FAIL_PERCENT {
                    "基本打满".to_string()
                } else {
                    String::new()
                },
            )
        })
        .collect();

    let title = match (status, saturated) {
        (Status::Ok, _) => "CPU 有余量",
        (Status::Fail, _) => "CPU 基本打满",
        (Status::Warn, count) if count > 0 && snapshot.global_cpu < CPU_WARN_PERCENT => {
            "个别核被打满（单线程瓶颈）"
        }
        (Status::Warn, _) => "CPU 偏忙",
    };
    let mut finding = Finding::new("load.cpu", status, title, detail).rows(rows);
    if status != Status::Ok {
        let hint = if saturated <= 1 && snapshot.logical_cores > 1 {
            format!(
                "只有 {saturated} 个核打满、其它核闲着：这是**单线程瓶颈**（锁、单连接、单 consumer），\
                 加核没用；去看「按服务聚合」里那个服务的线程/连接模型"
            )
        } else {
            format!(
                "{saturated} 个核打满：是**整体并发压力**。先看「按服务聚合」点名，\
                 再看「最吃 CPU 的进程」定位到具体 pid，再考虑限流、拆实例或扩容"
            )
        };
        finding = finding.hint(hint);
    }
    finding
}

/// 按**服务**（而不是单个进程）看谁在吃 CPU。
///
/// 这是本题最容易错的地方：nginx / gunicorn / JVM / 容器里的服务都是**多进程多 worker**，
/// 每个子进程单看都不大，加起来却是一个核。只给进程榜，现场会得出“没人忙”的错误结论 ——
/// 与磁盘题“最大的文件不是根因，目录才是”是同一条道理。
fn services_finding(snapshot: &Snapshot) -> Finding {
    if snapshot.services.is_empty() {
        return Finding::warn(
            "load.top_services",
            "没读到可归因的服务",
            "既拿不到进程列表，也拿不到 cgroup 用量 —— “谁在吃”这一栏是空的，不能当成没人吃",
        )
        .hint("以 root 重跑（`sudo wist-agentd investigate load`），或 `systemd-cgtop` / `docker stats` 交叉核对");
    }

    let capacity = snapshot.logical_cores.max(1) as f64 * 100.0;
    let heaviest = snapshot
        .services
        .first()
        .map(|service| service.cpu)
        .unwrap_or(0.0);
    let status = if heaviest >= SERVICE_CPU_FAIL {
        Status::Fail
    } else if heaviest >= SERVICE_CPU_WARN {
        Status::Warn
    } else {
        Status::Ok
    };

    let rows: Vec<Row> = snapshot
        .services
        .iter()
        .map(|service| {
            let share = service.cpu / capacity * 100.0;
            let mut note = if service.processes > 0 {
                format!(
                    "{} 个进程；占整机 {share:.1}%；RSS {}",
                    service.processes,
                    human_bytes(service.rss)
                )
            } else {
                // cgroup 累计值说明它确实吃 CPU，但采样时已经没进程了（周期性任务/短命子进程）。
                format!("**窗口内已退出**（无存活进程）；占整机 {share:.1}%")
            };
            if service.cpu_exact {
                note.push_str("；cgroup 精确值");
            }
            Row::new(
                service.label.clone(),
                format!("{:.1}% CPU", service.cpu),
                note,
            )
        })
        .collect();

    let top = &snapshot.services[0];
    let precision = if snapshot.services_exact > 0 {
        format!(
            "其中 {} 个有 cgroup 精确值（含窗口内起落的进程）",
            snapshot.services_exact
        )
    } else if snapshot.service_identity_cgroup {
        // 归属拿到了、用量没拿到：这跟“没有 cgroup”是两件事，不能说成同一句。
        "cgroup 归属可用，但读不到累计用量（权限/内核不支持）—— CPU 是进程采样加总".to_string()
    } else {
        "按进程采样加总（无 cgroup 口径：非 Linux）".to_string()
    };
    let identity = if snapshot.service_identity_cgroup {
        ""
    } else {
        "；**按可执行名聚合**（同一服务的多个可执行文件可能被拆开）"
    };
    let detail = format!(
        "按**服务**聚合出 {} 个（列出前 {} 个）；最重的是 {}（{:.1}% CPU，{} 个进程）；{precision}{identity}",
        snapshot.service_total,
        snapshot.services.len(),
        top.label,
        top.cpu,
        top.processes
    );

    let title = match status {
        Status::Ok => "没有单个服务吃掉一个核",
        Status::Warn => "有服务吃了一个核以上",
        Status::Fail => "有个服务几乎吃满多个核",
    };
    let mut finding = Finding::new("load.top_services", status, title, detail).rows(rows);

    if status != Status::Ok {
        let mut hints = vec![format!(
            "{}（{:.1}% CPU = {:.1} 个核）：{}",
            top.label,
            top.cpu,
            top.cpu / 100.0,
            service_next_command(&top.label)
        )];
        if top.source != "cgroup" {
            hints.push(
                "本平台只能按可执行名聚合：同一个服务的多个可执行文件可能被拆开\
                 （例如 Firefox 的 plugin-container / GPU Helper 各自成行），这里的合计是**下界**"
                    .to_string(),
            );
        }
        finding = finding.hint(hints.join("\n"));
    }
    finding
}

/// 针对服务类型给下一条命令（“知道是谁”之后要能马上确认）。
fn service_next_command(label: &str) -> String {
    if let Some(id) = label.strip_prefix("docker:") {
        return format!(
            "`docker stats --no-stream`（容器 ID 前缀 {id}），再看 `docker logs --tail 100 {id}`"
        );
    }
    if let Some(id) = label.strip_prefix("container:") {
        return format!("`ctr -n k8s.io task metrics` / `crictl stats`（容器 {id}）");
    }
    if let Some(pod) = label.strip_prefix("k8s:pod/") {
        return format!("`kubectl top pod -A | grep {pod}` 与 `kubectl describe pod`");
    }
    if let Some(unit) = label.strip_suffix(".service") {
        return format!("`systemctl status {unit}` 与 `journalctl -u {unit} -n 100 --no-pager`");
    }
    format!("`ps -eo pid,pcpu,rss,comm | grep {label}`（Linux 可再加 `pidstat -p <pid> 1`）")
}

fn top_processes_finding(snapshot: &Snapshot, top: usize) -> Finding {
    let rows: Vec<Row> = snapshot
        .processes
        .iter()
        .take(top.max(1))
        .map(|process| {
            let mut note = format!(
                "RSS {}；{}；运行 {}",
                human_bytes(process.rss),
                process.state,
                duration_text(process.run_time)
            );
            if process.agent {
                note.push_str("；**agent 自己**");
            }
            Row::new(
                format!("pid {} · {}", process.pid, process.name),
                format!("{:.1}% CPU", process.cpu),
                note,
            )
        })
        .collect();

    let detail = format!(
        "进程共 {} 个；按 CPU 列出前 {} 个（多进程服务的合计见上一节；采样窗口 {}ms，百分比是**窗口内平均**）",
        snapshot.process_total,
        rows.len(),
        snapshot.elapsed_ms
    );
    if rows.is_empty() {
        return Finding::warn(
            "load.top_processes",
            "没读到进程列表",
            "采不到进程（权限或平台限制）—— 负载的“谁在吃”这一栏是空的，不能当成没人吃",
        )
        .hint("以 root 重跑（`sudo wist-agentd investigate load`），或改用 `ps -eo pid,pcpu,rss,comm --sort=-pcpu | head` 交叉核对");
    }

    Finding::ok("load.top_processes", "最吃 CPU 的进程", detail)
        .rows(rows)
        .hint(
            "报告里**不放完整命令行**（argv 常含密码/令牌）；要看就对着 pid 自己执行：\n\
             `ps -o pid,stat,pcpu,rss,lstart,command -p <pid>`",
        )
}

fn memory_finding(snapshot: &Snapshot) -> Finding {
    let memory_percent = snapshot.memory_percent();
    let swap_percent = snapshot.swap_percent();
    let mut status = classify_memory(memory_percent);
    if snapshot.swap_total > 0 && swap_percent >= SWAP_WARN_PERCENT {
        status = status.max(Status::Warn);
    }

    let mut rows = vec![Row::new(
        "物理内存",
        format!("{memory_percent:.1}% 已用"),
        format!(
            "{} / {}（可用 {}）",
            human_bytes(snapshot.memory_used),
            human_bytes(snapshot.memory_total),
            human_bytes(snapshot.memory_available)
        ),
    )];
    if snapshot.swap_total > 0 {
        rows.push(Row::new(
            "swap",
            format!("{swap_percent:.1}% 已用"),
            format!(
                "{} / {}",
                human_bytes(snapshot.swap_used),
                human_bytes(snapshot.swap_total)
            ),
        ));
    } else if cfg!(target_os = "linux") {
        rows.push(Row::new(
            "swap",
            "未启用",
            "没有 swap：内存一旦用满就是 OOM",
        ));
    } else {
        // macOS 的 swap 是动态的（不预先建分区），sysinfo 常报 0 ——
        // 这时说「未启用」就是一句没有证据的断言，只能说「读不到」。
        rows.push(Row::new(
            "swap",
            "读不到",
            "本平台报 0（不等于没有）：macOS 的 swap 是动态的，用 `vm_stat` 交叉核对",
        ));
    }

    // 「读不到」与「没用 swap」是两件事：前者不能下“没有 swap”的结论。
    let swap_text = if snapshot.swap_total > 0 {
        format!("swap {swap_percent:.1}%")
    } else if cfg!(target_os = "linux") {
        "未启用 swap".to_string()
    } else {
        "swap 读不到（本平台报 0，不等于没有）".to_string()
    };
    let detail = if snapshot.swap_total > 0 && swap_percent >= SWAP_WARN_PERCENT {
        format!(
            "物理内存 {memory_percent:.1}% 已用（可用 {}）；{swap_text} —— 已经在换页，延迟会抖",
            human_bytes(snapshot.memory_available)
        )
    } else {
        format!(
            "物理内存 {memory_percent:.1}% 已用（可用 {}）；{swap_text}",
            human_bytes(snapshot.memory_available)
        )
    };

    let title = match status {
        Status::Ok => "内存够用",
        Status::Warn if swap_percent >= SWAP_WARN_PERCENT => "内存在换页",
        Status::Warn => "内存偏紧",
        Status::Fail => "内存即将耗尽",
    };
    let mut finding = Finding::new("load.memory", status, title, detail).rows(rows);
    if status != Status::Ok {
        finding = finding.hint(
            "先看「最吃 CPU 的进程」里的 RSS 列（内存大户不一定 CPU 高）；\
             swap 在用说明已经过界，OOM killer 随时可能动手",
        );
    }
    finding
}

/// IO 等待与不可中断睡眠：**负载高但 CPU 闲**的头号解释。
fn io_finding(snapshot: &Snapshot) -> Finding {
    let mut rows = Vec::new();
    let mut status = Status::Ok;

    match snapshot.io.iowait_percent {
        Some(iowait) => {
            if iowait >= IOWAIT_WARN_PERCENT {
                status = status.max(Status::Warn);
            }
            rows.push(Row::new(
                "iowait（占 CPU 时间）",
                format!("{iowait:.1}%"),
                "CPU 在等 IO；这段不算“忙”",
            ));
        }
        None => rows.push(Row::new(
            "iowait（占 CPU 时间）",
            "取不到",
            "本平台没有 iowait 口径（Linux 才有）",
        )),
    }
    if let (Some(some), Some(full)) = (snapshot.io.psi_some, snapshot.io.psi_full) {
        if some >= 30.0 || full >= 10.0 {
            status = status.max(Status::Warn);
        }
        rows.push(Row::new(
            "io 压力 some / full（avg10）",
            format!("{some:.1}% / {full:.1}%"),
            "有任务在等 IO 的时间占比（PSI）",
        ));
    }
    rows.push(Row::new(
        "不可中断睡眠（D 状态）进程",
        format!("{} 个", snapshot.d_state),
        if snapshot.d_state >= D_STATE_WARN {
            "杀不掉也不吃 CPU —— 通常卡在磁盘/网络存储".to_string()
        } else if cfg!(target_os = "linux") {
            String::new()
        } else {
            // 非 Linux 的进程状态来自平台 API，D 状态可能映射不全：
            // 0 个不等于「没有」，只能说「没看到」。
            "本平台的状态映射可能不全：0 个 ≠ 没有".to_string()
        },
    ));
    if snapshot.d_state >= D_STATE_WARN && snapshot.load1 > snapshot.logical_cores as f64 {
        status = status.max(Status::Warn);
    }

    let detail = format!(
        "iowait {}；D 状态 {} 个；1 分钟负载 {:.2}（{} 核）",
        match snapshot.io.iowait_percent {
            Some(value) => format!("{value:.1}%"),
            None => "不可得".to_string(),
        },
        snapshot.d_state,
        snapshot.load1,
        snapshot.logical_cores
    );

    let title = match status {
        Status::Ok => "没有明显的 IO 阻塞",
        _ => "进程在等 IO（负载被磁盘/存储顶起来了）",
    };
    let mut finding = Finding::new("load.io", status, title, detail).rows(rows);
    if status != Status::Ok {
        let mut hint = String::from(
            "IO 瓶颈不在 CPU：先找是谁在写（`wist-agentd investigate disk` 看目录与文件），\
             再看容器层/数据库 WAL/日志轮转这几处常见的写入源",
        );
        if snapshot.d_state > 0 {
            hint.push_str(
                "\nD 状态进程杀不掉：**不要 kill -9**（它连信号都不处理），先确认挂的是哪块盘/哪个挂载点",
            );
        }
        finding = finding.hint(hint);
    }
    finding
}

fn agent_processes_finding(snapshot: &Snapshot, have_config: bool) -> Finding {
    if snapshot.agent_processes == 0 {
        return Finding::ok(
            "load.agent_processes",
            "没看到 agent 自己的进程",
            "按进程名（wist-agentd / wist-exec / wist-upgrader）没找到——可能以别的名字运行",
        );
    }
    let status = if snapshot.agent_cpu >= AGENT_CPU_FAIL || snapshot.agent_rss >= AGENT_RSS_FAIL {
        Status::Fail
    } else if snapshot.agent_cpu >= AGENT_CPU_WARN || snapshot.agent_rss >= AGENT_RSS_WARN {
        Status::Warn
    } else {
        Status::Ok
    };

    let mut rows: Vec<Row> = snapshot
        .processes
        .iter()
        .filter(|process| process.agent)
        .map(|process| {
            Row::new(
                format!("pid {} · {}", process.pid, process.name),
                format!("{:.1}% CPU", process.cpu),
                format!("RSS {}", human_bytes(process.rss)),
            )
        })
        .collect();
    // 合计算的是**全量**，行只来自 CPU 前 N。对不上就把剩下的行补一句，
    // 否则「3 个进程」配 1 行会让人以为另外两个不存在。
    if rows.len() < snapshot.agent_processes {
        rows.push(Row::new(
            format!(
                "其余 {} 个 agent 进程",
                snapshot.agent_processes - rows.len()
            ),
            "—",
            "CPU 没进前 N，已计入合计",
        ));
    }

    let detail = format!(
        "agent 自己合计 {:.1}% CPU / {}（{} 个进程）{}",
        snapshot.agent_cpu,
        human_bytes(snapshot.agent_rss),
        snapshot.agent_processes,
        if have_config {
            ""
        } else {
            "；没读到配置，只按进程名识别"
        }
    );
    let title = match status {
        Status::Ok => "agent 自己占得不多",
        Status::Warn => "agent 自己就吃了不少 CPU",
        Status::Fail => "agent 自己就是负载来源",
    };
    let mut finding = Finding::new("load.agent_processes", status, title, detail).rows(rows);
    if status != Status::Ok {
        finding = finding.hint(
            "先 `wist-agentd diagnose` 看 spool 积压、日志轮转与采集面数量；\
             调查/采集本身也会吃 CPU，但它不该吃掉一个核以上",
        );
    }
    finding
}

fn sample_finding(snapshot: &Snapshot, request: &InvestigateRequest) -> Finding {
    let detail = format!(
        "cores={} physical={} window={}ms elapsed={}ms procs={} services={} exact={} top={} iowait={} psi_io={} psi_cpu={} d_state={} platform={}",
        snapshot.logical_cores,
        snapshot
            .physical_cores
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        snapshot.window_ms,
        snapshot.elapsed_ms,
        snapshot.process_total,
        snapshot.service_total,
        snapshot.services_exact,
        request.top,
        if snapshot.io.iowait_percent.is_some() {
            "yes"
        } else {
            "no"
        },
        if snapshot.io.psi_some.is_some() {
            "yes"
        } else {
            "no"
        },
        if snapshot.psi_cpu.is_some() {
            "yes"
        } else {
            "no"
        },
        snapshot.d_state,
        std::env::consts::OS
    );

    // 「没采到」与「采到了 0」必须分开：0 个进程不是健康，是没读到。
    let status = if snapshot.process_total == 0 || snapshot.window_ms < SAMPLE_WINDOW_SUSPECT_MS {
        Status::Warn
    } else {
        Status::Ok
    };
    let title = match status {
        Status::Ok => "采样完成",
        _ => "采样不完整（数字只能当参考）",
    };
    let finding = Finding::new("load.sample", status, title, detail);
    let mut hints = Vec::new();
    if status != Status::Ok {
        hints.push(format!(
            "采样窗口只有 {}ms、或读不到进程：CPU%/负载都是窗口内平均，不要据此下结论 —— \
             复采一次或 `--max-seconds 2` 拉长窗口",
            snapshot.window_ms
        ));
    }
    if snapshot.io.iowait_percent.is_none() {
        hints.push(format!(
            "{} 上取不到 iowait / PSI：**负载高而 CPU 闲**时只能看 D 状态进程数与「最吃 CPU 的进程」，\
             必要时结合 `investigate disk`（是不是某块盘/某个挂载点在卡）",
            std::env::consts::OS
        ));
    }
    if hints.is_empty() {
        finding
    } else {
        finding.hint(hints.join("\n"))
    }
}

// ---------------------------------------------------------------------------
// 平台信号（读文件，有界；读不到就 `None`，由渲染层说出来）
// ---------------------------------------------------------------------------

/// `/proc/stat` 的 CPU 行累计值（Linux）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct CpuTimes {
    total: u64,
    idle: u64,
    iowait: u64,
    user: u64,
    system: u64,
}

#[cfg(target_os = "linux")]
fn cpu_times_before() -> Option<CpuTimes> {
    let text = fs::read_to_string("/proc/stat").ok()?;
    parse_proc_stat(&text)
}

#[cfg(not(target_os = "linux"))]
fn cpu_times_before() -> Option<CpuTimes> {
    None
}

/// 解析 `/proc/stat` 的第一行（`cpu user nice system idle iowait irq softirq steal …`）。
///
/// **只加前 8 个字段**：`guest` / `guest_nice`（第 9/10 项）已经包含在 `user` / `nice` 里，
/// 再加一遍会让分母偏大，于是所有百分比都偏低 —— 跑虚拟机的机器上尤其明显。
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(text: &str) -> Option<CpuTimes> {
    let line = text.lines().find(|line| line.starts_with("cpu "))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
        .take(8)
        .filter_map(|value| value.parse::<u64>().ok())
        .collect();
    if values.len() < 5 {
        return None;
    }
    let total: u64 = values.iter().copied().sum();
    Some(CpuTimes {
        total,
        idle: values[3] + values[4],
        iowait: values[4],
        user: values[0] + values[1],
        system: values[2]
            + values.get(5).copied().unwrap_or(0)
            + values.get(6).copied().unwrap_or(0),
    })
}

/// 两次采样之间的 CPU 时间去向（百分比）。
fn breakdown(before: CpuTimes, after: CpuTimes) -> Option<CpuBreakdown> {
    let total = after.total.checked_sub(before.total)?;
    if total == 0 {
        return None;
    }
    let share = |value: u64| -> f64 { value as f64 / total as f64 * 100.0 };
    Some(CpuBreakdown {
        user: share(after.user.saturating_sub(before.user)),
        system: share(after.system.saturating_sub(before.system)),
        iowait: share(after.iowait.saturating_sub(before.iowait)),
        idle: share(after.idle.saturating_sub(before.idle)),
    })
}

/// `/proc/loadavg` 第 4 段（`runnable/total`）。
#[cfg(target_os = "linux")]
fn read_loadavg() -> Option<(u32, u32)> {
    let text = fs::read_to_string("/proc/loadavg").ok()?;
    parse_loadavg(&text)
}

#[cfg(not(target_os = "linux"))]
fn read_loadavg() -> Option<(u32, u32)> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_loadavg(text: &str) -> Option<(u32, u32)> {
    let field = text.split_whitespace().nth(3)?;
    let (runnable, total) = field.split_once('/')?;
    Some((runnable.parse().ok()?, total.parse().ok()?))
}

/// `/proc/pressure/io` 的 `some avg10` / `full avg10`。
#[cfg(target_os = "linux")]
fn read_psi_io() -> Option<(f64, f64)> {
    let text = fs::read_to_string("/proc/pressure/io").ok()?;
    parse_psi(&text)
}

#[cfg(not(target_os = "linux"))]
fn read_psi_io() -> Option<(f64, f64)> {
    None
}

/// `/proc/pressure/cpu` 的 `some avg10` / `full avg10`：有任务在等 CPU 的时间占比。
#[cfg(target_os = "linux")]
fn read_psi_cpu() -> Option<(f64, f64)> {
    let text = fs::read_to_string("/proc/pressure/cpu").ok()?;
    parse_psi(&text)
}

#[cfg(not(target_os = "linux"))]
fn read_psi_cpu() -> Option<(f64, f64)> {
    None
}

#[cfg(any(target_os = "linux", test))]
fn parse_psi(text: &str) -> Option<(f64, f64)> {
    let mut some = None;
    let mut full = None;
    for line in text.lines() {
        let mut parts = line.split_whitespace();
        let kind = parts.next()?;
        let avg10 = parts
            .find_map(|part| part.strip_prefix("avg10="))
            .and_then(|value| value.parse::<f64>().ok())?;
        match kind {
            "some" => some = Some(avg10),
            "full" => full = Some(avg10),
            _ => {}
        }
    }
    Some((some?, full?))
}

/// 秒 → `3h12m` / `45m` / `12s`。
fn duration_text(seconds: u64) -> String {
    let hours = seconds / 3600;
    let minutes = (seconds % 3600) / 60;
    if hours > 0 {
        format!("{hours}h{minutes}m")
    } else if minutes > 0 {
        format!("{minutes}m")
    } else {
        format!("{seconds}s")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Snapshot {
        Snapshot {
            logical_cores: 8,
            physical_cores: Some(8),
            load1: 2.0,
            load5: 2.0,
            load15: 2.0,
            global_cpu: 25.0,
            cores: vec![25.0; 8],
            cpu_breakdown: None,
            processes: Vec::new(),
            services: Vec::new(),
            service_total: 0,
            service_identity_cgroup: false,
            services_exact: 0,
            psi_cpu: None,
            process_total: 120,
            memory_total: 16 << 30,
            memory_used: 4 << 30,
            memory_available: 12 << 30,
            swap_total: 0,
            swap_used: 0,
            d_state: 0,
            io: IoSignals::default(),
            window_ms: 300,
            elapsed_ms: 300,
            agent_cpu: 1.0,
            agent_rss: 50 << 20,
            agent_processes: 1,
        }
    }

    fn process(pid: u32, name: &str, cpu: f32, rss: u64) -> ProcessSample {
        ProcessSample {
            pid,
            name: name.to_string(),
            cpu,
            rss,
            state: "R".to_string(),
            run_time: 90,
            agent: false,
            service: name.to_string(),
            service_source: "exe",
        }
    }

    #[test]
    fn per_core_load_decides_the_verdict() {
        let mut low = base();
        low.load1 = 1.0; // 8 核 → 0.125/核
        assert_eq!(summary_finding(&low).status, Status::Ok);

        let mut warn = base();
        warn.load1 = 9.0; // 1.125/核
        let finding = summary_finding(&warn);
        assert_eq!(finding.status, Status::Warn);
        assert!(finding.detail.contains("每核 1.12"), "{}", finding.detail);

        let mut fail = base();
        fail.load1 = 20.0; // 2.5/核
        assert_eq!(summary_finding(&fail).status, Status::Fail);
    }

    #[test]
    fn a_busy_cpu_points_at_processes_not_io() {
        let mut busy = base();
        busy.load1 = 20.0;
        busy.global_cpu = 97.0;
        let hint = summary_finding(&busy).hint.expect("hint");
        assert!(hint.contains("最吃 CPU 的进程"), "{hint}");
        assert!(!hint.contains("CPU 不忙"), "{hint}");
    }

    #[test]
    fn high_load_with_idle_cpu_points_at_io() {
        let mut idle_cpu = base();
        idle_cpu.load1 = 24.0;
        idle_cpu.global_cpu = 12.0;
        idle_cpu.d_state = 5;
        let hint = summary_finding(&idle_cpu).hint.expect("hint");
        assert!(hint.contains("CPU 不忙"), "{hint}");
        assert!(hint.contains("D 状态"), "{hint}");
    }

    #[test]
    fn a_single_saturated_core_is_called_a_single_thread_bottleneck() {
        let mut snapshot = base();
        snapshot.global_cpu = 20.0;
        snapshot.cores = vec![100.0, 2.0, 1.0, 0.0, 0.0, 0.0, 0.0, 0.0];
        let finding = cpu_finding(&snapshot);
        assert_eq!(
            finding.status,
            Status::Warn,
            "单核打满也是异常，哪怕总体只有 20%"
        );
        assert!(finding.title.contains("单线程瓶颈"), "{}", finding.title);
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("单线程瓶颈"), "{hint}");
    }

    #[test]
    fn cpu_rows_only_list_the_busy_cores() {
        let mut snapshot = base();
        snapshot.cores = vec![99.0, 88.0, 2.0, 1.0];
        let finding = cpu_finding(&snapshot);
        assert_eq!(finding.rows.len(), 2, "{:?}", finding.rows);
        assert!(finding.rows[0].label.contains("CPU 0"));
    }

    #[test]
    fn swap_pressure_is_reported_even_when_load_is_low() {
        let mut snapshot = base();
        snapshot.swap_total = 4 << 30;
        snapshot.swap_used = 3 << 30; // 75%
        let finding = memory_finding(&snapshot);
        assert_eq!(finding.status, Status::Warn);
        assert!(finding.title.contains("换页"), "{}", finding.title);
        assert!(finding.detail.contains("swap 75.0%"), "{}", finding.detail);
    }

    #[test]
    fn a_full_memory_is_a_failure() {
        let mut snapshot = base();
        snapshot.memory_used = 16 << 30;
        snapshot.memory_available = 0;
        let finding = memory_finding(&snapshot);
        assert_eq!(finding.status, Status::Fail);
    }

    #[test]
    fn no_swap_is_said_explicitly_not_left_blank() {
        let finding = memory_finding(&base());
        let row = finding
            .rows
            .iter()
            .find(|row| row.label == "swap")
            .expect("swap row");
        // Linux 说「未启用」；macOS 读不到，只能说「读不到」—— 不能拿 0 当「没有」。
        assert!(
            row.value == "未启用" || row.value == "读不到",
            "{}",
            row.value
        );
        assert!(!row.note.is_empty());
    }

    #[test]
    fn iowait_above_the_line_is_a_warning() {
        let mut snapshot = base();
        snapshot.io.iowait_percent = Some(35.0);
        let finding = io_finding(&snapshot);
        assert_eq!(finding.status, Status::Warn);
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("investigate disk"), "{hint}");
    }

    #[test]
    fn d_state_processes_flag_io_even_without_iowait() {
        let mut snapshot = base();
        // macOS：没有 iowait，只能靠 D 状态。
        snapshot.io.iowait_percent = None;
        snapshot.d_state = 4;
        snapshot.load1 = 12.0; // > 8 核
        let finding = io_finding(&snapshot);
        assert_eq!(finding.status, Status::Warn);
        assert!(
            finding.rows.iter().any(|row| row.value == "取不到"),
            "缺少 iowait 时必须说出来：{:?}",
            finding.rows
        );
    }

    #[test]
    fn psi_pressure_is_reported_when_available() {
        let mut snapshot = base();
        snapshot.io.psi_some = Some(40.0);
        snapshot.io.psi_full = Some(12.0);
        let finding = io_finding(&snapshot);
        assert_eq!(finding.status, Status::Warn);
        assert!(finding.rows.iter().any(|row| row.value.contains("40.0%")));
    }

    #[test]
    fn top_processes_are_rendered_without_argv() {
        let mut snapshot = base();
        snapshot.processes = vec![
            process(42, "nginx", 250.0, 100 << 20),
            process(7, "postgres", 30.0, 2 << 30),
        ];
        let finding = top_processes_finding(&snapshot, 10);
        assert_eq!(finding.rows.len(), 2);
        assert!(finding.rows[0].label.contains("pid 42 · nginx"));
        assert!(finding.rows[0].note.contains("RSS"));
        // 脱敏：报告里不能出现 argv（本枚举里根本没有这个字段，用断言锁住行为）。
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("不放完整命令行"), "{hint}");
    }

    #[test]
    fn top_processes_respect_top() {
        let mut snapshot = base();
        snapshot.processes = (0..20).map(|index| process(index, "p", 10.0, 1)).collect();
        assert_eq!(top_processes_finding(&snapshot, 3).rows.len(), 3);
    }

    #[test]
    fn an_empty_process_list_never_looks_healthy() {
        let mut snapshot = base();
        snapshot.processes.clear();
        let finding = top_processes_finding(&snapshot, 10);
        assert_eq!(finding.status, Status::Warn);
        assert!(
            finding.detail.contains("不能当成没人吃"),
            "{}",
            finding.detail
        );
    }

    #[test]
    fn agent_footprint_is_judged_apart() {
        let mut busy_agent = base();
        busy_agent.agent_cpu = 350.0;
        busy_agent.agent_processes = 3;
        let finding = agent_processes_finding(&busy_agent, true);
        assert_eq!(finding.status, Status::Fail);
        assert!(finding.detail.contains("350.0% CPU"), "{}", finding.detail);

        let quiet = base();
        assert_eq!(agent_processes_finding(&quiet, true).status, Status::Ok);
    }

    #[test]
    fn agent_rows_account_for_processes_outside_the_top_list() {
        let mut snapshot = base();
        // 全量 3 个 agent 进程，但只有 1 个进了 CPU 前 N 的列表。
        snapshot.agent_processes = 3;
        snapshot.agent_cpu = 40.0;
        snapshot.processes = vec![ProcessSample {
            agent: true,
            ..process(99, "wist-agentd", 20.0, 30 << 20)
        }];

        let finding = agent_processes_finding(&snapshot, true);

        assert_eq!(finding.rows.len(), 2, "{:?}", finding.rows);
        assert!(
            finding.rows[1].label.contains("其余 2 个"),
            "{:?}",
            finding.rows[1]
        );
        assert!(finding.detail.contains("40.0% CPU"), "{}", finding.detail);
    }

    #[test]
    fn missing_agent_processes_are_stated_not_hidden() {
        let mut snapshot = base();
        snapshot.agent_processes = 0;
        let finding = agent_processes_finding(&snapshot, false);
        assert!(finding.detail.contains("没找到"), "{}", finding.detail);
    }

    #[test]
    fn the_sample_section_says_when_numbers_are_not_trustworthy() {
        let mut snapshot = base();
        snapshot.process_total = 0;
        let finding = sample_finding(&snapshot, &InvestigateRequest::default());
        assert_eq!(finding.status, Status::Warn);
        assert!(finding.title.contains("采样不完整"), "{}", finding.title);
    }

    #[test]
    fn the_sample_section_names_platform_limits() {
        let finding = sample_finding(&base(), &InvestigateRequest::default());
        assert!(finding.detail.contains("iowait=no"), "{}", finding.detail);
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("取不到 iowait"), "{hint}");
    }

    #[test]
    fn proc_stat_is_parsed_into_time_buckets() {
        let text = "cpu  100 10 50 800 40 5 5 0 0 0\ncpu0 1 2 3 4 5\n";
        let times = parse_proc_stat(text).expect("parse");
        assert_eq!(times.total, 1010);
        assert_eq!(times.idle, 840);
        assert_eq!(times.iowait, 40);
        assert_eq!(times.user, 110);
        assert_eq!(times.system, 60);

        let after = CpuTimes {
            total: times.total + 100,
            idle: times.idle + 50,
            iowait: times.iowait + 20,
            user: times.user + 20,
            system: times.system + 10,
        };
        let breakdown = breakdown(times, after).expect("breakdown");
        assert!((breakdown.iowait - 20.0).abs() < 0.01, "{breakdown:?}");
        assert!((breakdown.user - 20.0).abs() < 0.01, "{breakdown:?}");
        assert!((breakdown.idle - 50.0).abs() < 0.01, "{breakdown:?}");
    }

    #[test]
    fn loadavg_and_psi_are_parsed_tolerantly() {
        assert_eq!(parse_loadavg("1.20 1.10 0.90 3/612 12345"), Some((3, 612)));
        assert_eq!(parse_loadavg("garbage"), None);
        let psi = "some avg10=35.20 avg60=12.00 avg300=5.00 total=123\n\
                   full avg10=12.10 avg60=3.00 avg300=1.00 total=45\n";
        assert_eq!(parse_psi(psi), Some((35.2, 12.1)));
        assert_eq!(parse_psi("some avg10=1.0\n"), None);
    }

    #[test]
    fn durations_read_like_a_human_wrote_them() {
        assert_eq!(duration_text(5), "5s");
        assert_eq!(duration_text(90), "1m");
        assert_eq!(duration_text(3 * 3600 + 12 * 60), "3h12m");
    }

    // -----------------------------------------------------------------------
    // 服务聚合（这道题的关键：多 worker 服务单看进程会被摊薄）
    // -----------------------------------------------------------------------

    fn service_process(pid: u32, name: &str, service: &str, cpu: f32, rss: u64) -> ProcessSample {
        ProcessSample {
            service: service.to_string(),
            ..process(pid, name, cpu, rss)
        }
    }

    #[test]
    fn many_workers_of_one_service_add_up_instead_of_disappearing() {
        // 现场形态：8 个 worker 各 12% —— 进程榜里一个都不显眼，服务却是 96%。
        let processes: Vec<ProcessSample> = (0..8)
            .map(|index| {
                service_process(
                    1000 + index,
                    "gunicorn",
                    "gunicorn.service",
                    12.0,
                    100 << 20,
                )
            })
            .collect();
        let (services, total, _) = build_services(&processes, &Default::default(), 10);

        assert_eq!(total, 1);
        assert_eq!(services[0].label, "gunicorn.service");
        assert_eq!(services[0].processes, 8);
        assert!((services[0].cpu - 96.0).abs() < 0.01, "{:?}", services[0]);
        assert!(!services[0].cpu_exact);
    }

    #[test]
    fn exact_cgroup_values_win_over_the_sum_of_samples() {
        let processes = vec![
            service_process(1, "worker", "app.service", 10.0, 1),
            service_process(2, "worker", "app.service", 10.0, 1),
        ];
        // cgroup 说它用了 250%（包含采样时已退出的子进程），以 cgroup 为准。
        let exact = std::collections::BTreeMap::from([("app.service".to_string(), 250.0)]);

        let (services, _, _) = build_services(&processes, &exact, 10);

        assert!(services[0].cpu_exact);
        assert!((services[0].cpu - 250.0).abs() < 0.01, "{:?}", services[0]);
    }

    #[test]
    fn a_service_that_only_existed_inside_the_window_still_shows_up() {
        // 周期任务（cron/批处理）：采样时已经没有进程了，但 cgroup 说它真跑了。
        let exact = std::collections::BTreeMap::from([("backup.service".to_string(), 80.0)]);

        let (services, total, _) = build_services(&[], &exact, 10);

        assert_eq!(total, 1);
        assert_eq!(services[0].processes, 0);
        assert!(services[0].cpu_exact);

        let mut snapshot = base();
        snapshot.services = services;
        snapshot.service_total = total;
        snapshot.services_exact = 1;
        let finding = services_finding(&snapshot);
        assert!(
            finding.rows[0].note.contains("窗口内已退出"),
            "{}",
            finding.rows[0].note
        );
    }

    #[test]
    fn services_are_ranked_by_cpu_and_truncated() {
        let processes = vec![
            service_process(1, "a", "a.service", 5.0, 1),
            service_process(2, "b", "b.service", 50.0, 1),
            service_process(3, "c", "c.service", 20.0, 1),
        ];
        let (services, total, _) = build_services(&processes, &Default::default(), 2);

        assert_eq!(total, 3);
        assert_eq!(services.len(), 2);
        assert_eq!(services[0].label, "b.service");
        assert_eq!(services[1].label, "c.service");
    }

    #[test]
    fn a_service_at_one_core_is_a_warning_and_three_cores_is_a_failure() {
        let mut one_core = base();
        one_core.services = vec![ServiceGroup {
            label: "app.service".to_string(),
            source: "cgroup",
            processes: 4,
            cpu: 120.0,
            cpu_exact: true,
            rss: 1 << 30,
        }];
        one_core.service_total = 1;
        one_core.services_exact = 1;
        let finding = services_finding(&one_core);
        assert_eq!(finding.status, Status::Warn);
        assert!(finding.title.contains("一个核以上"), "{}", finding.title);
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("systemctl status app"), "{hint}");

        let mut three_cores = one_core.clone();
        three_cores.services[0].cpu = 320.0;
        assert_eq!(services_finding(&three_cores).status, Status::Fail);

        let mut quiet = one_core;
        quiet.services[0].cpu = 40.0;
        assert_eq!(services_finding(&quiet).status, Status::Ok);
    }

    #[test]
    fn an_exe_based_grouping_says_it_is_a_lower_bound() {
        let mut snapshot = base();
        snapshot.services = vec![ServiceGroup {
            label: "firefox".to_string(),
            source: "exe",
            processes: 1,
            cpu: 150.0,
            cpu_exact: false,
            rss: 1 << 30,
        }];
        snapshot.service_total = 1;

        let finding = services_finding(&snapshot);
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("下界"), "{hint}");
    }

    #[test]
    fn each_service_kind_gets_its_own_next_command() {
        assert!(service_next_command("docker:3f2a1b4c5d6e").contains("docker stats"));
        assert!(service_next_command("container:abc123def456").contains("crictl"));
        assert!(service_next_command("k8s:pod/3f2a1b4c5d6e").contains("kubectl top pod"));
        assert!(service_next_command("nginx.service").contains("systemctl status nginx"));
        assert!(service_next_command("gunicorn").contains("ps -eo"));
    }

    #[test]
    fn cgroup_paths_are_parsed_for_v1_and_v2() {
        assert_eq!(
            parse_cgroup_path("0::/system.slice/nginx.service\n").as_deref(),
            Some("/system.slice/nginx.service")
        );
        assert_eq!(
            parse_cgroup_path("12:cpu,cpuacct:/\n1:name=systemd:/system.slice/app.service\n")
                .as_deref(),
            Some("/system.slice/app.service")
        );
        assert_eq!(parse_cgroup_path("garbage"), None);
    }

    #[test]
    fn cgroup_paths_map_to_readable_service_names() {
        assert_eq!(
            service_label_from_cgroup("/system.slice/nginx.service").as_deref(),
            Some("nginx.service")
        );
        assert_eq!(
            service_label_from_cgroup("/system.slice/docker-3f2a1b4c5d6e7f8091a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f90a1b2c3d4e.scope").as_deref(),
            Some("docker:3f2a1b4c5d6e")
        );
        assert_eq!(
            service_label_from_cgroup("/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d.slice/cri-containerd-abcdef0123456789.scope").as_deref(),
            Some("container:abcdef012345")
        );
        assert_eq!(
            service_label_from_cgroup("/user.slice/user-501.slice/session-3.scope").as_deref(),
            Some("user-session:session-3")
        );
        // 认不出来的不要硬造一个名字：交回调用方按可执行名兜底。
        assert_eq!(service_label_from_cgroup("/"), None);
    }

    #[test]
    fn the_cgroup_delta_is_turned_into_cores() {
        let before: CgroupUsage = std::collections::BTreeMap::from([(
            "/system.slice/app.service".to_string(),
            ("app.service".to_string(), 1_000_000),
        )]);
        let after: CgroupUsage = std::collections::BTreeMap::from([(
            "/system.slice/app.service".to_string(),
            ("app.service".to_string(), 3_000_000),
        )]);

        let exact = exact_service_cpu(&before, &after, Duration::from_secs(1));

        // 2 秒 CPU 时间 / 1 秒窗口 = 200%。
        assert!((exact["app.service"] - 200.0).abs() < 0.01, "{exact:?}");
    }

    #[test]
    fn the_sample_window_is_long_enough_to_catch_short_spikes() {
        assert_eq!(sample_window(1), Duration::from_millis(1_000));
        assert_eq!(sample_window(5), Duration::from_millis(3_000));
        assert_eq!(sample_window(30), Duration::from_millis(3_000));
    }

    #[test]
    fn cpu_pressure_is_shown_in_the_summary_when_available() {
        let mut snapshot = base();
        snapshot.load1 = 40.0;
        snapshot.psi_cpu = Some((45.0, 12.0));
        let finding = summary_finding(&snapshot);
        assert!(
            finding.rows.iter().any(|row| row.value.contains("45.0%")),
            "{:?}",
            finding.rows
        );
        let hint = finding.hint.expect("hint");
        assert!(hint.contains("排队等 CPU"), "{hint}");
    }

    fn group(
        label: &str,
        source: &'static str,
        processes: usize,
        cpu: f64,
        exact: bool,
    ) -> ServiceGroup {
        ServiceGroup {
            label: label.to_string(),
            source,
            processes,
            cpu,
            cpu_exact: exact,
            rss: 1 << 20,
        }
    }

    #[test]
    fn exact_cpu_divides_by_the_real_elapsed_time_not_the_intended_window() {
        // 2 秒 CPU 时间，真实等了 4 秒 → 50%。机器忙时 sleep 会超时，最忌拿“想等多久”当分母。
        let before: CgroupUsage = std::collections::BTreeMap::from([(
            "/system.slice/app.service".to_string(),
            ("app.service".to_string(), 1_000_000),
        )]);
        let after: CgroupUsage = std::collections::BTreeMap::from([(
            "/system.slice/app.service".to_string(),
            ("app.service".to_string(), 3_000_000),
        )]);

        let exact = exact_service_cpu(&before, &after, Duration::from_secs(4));

        assert!((exact["app.service"] - 50.0).abs() < 0.01, "{exact:?}");
    }

    #[test]
    fn guest_time_is_not_counted_twice_in_proc_stat() {
        // user nice system idle iowait irq softirq steal guest guest_nice
        // guest/guest_nice 已经含在 user/nice 里，再加一遍会让分母虚高、所有百分比偏低。
        let text = "cpu  100 10 50 800 40 5 5 0 30 30\n";
        let times = parse_proc_stat(text).expect("parse");
        assert_eq!(times.total, 1_010, "只算前 8 项（不含 guest）");
    }

    #[test]
    fn a_unit_name_containing_pod_is_not_mistaken_for_a_kubernetes_pod() {
        // 服务名里带 “-pod” 很常见，不能因此被归到 k8s。
        assert_eq!(
            service_label_from_cgroup("/system.slice/mypod-worker.service").as_deref(),
            Some("mypod-worker.service")
        );
    }

    #[test]
    fn a_process_sitting_directly_in_a_pod_cgroup_is_recognised() {
        assert_eq!(
            service_label_from_cgroup(
                "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod1a2b3c4d-5e6f-7a8b-9c0d-1e2f3a4b5c6d.slice"
            )
            .as_deref(),
            Some("k8s:pod/1a2b3c4d5e6f")
        );
    }

    #[test]
    fn the_label_cache_reads_each_pid_at_most_once() {
        let mut cache = LabelCache::default();
        let first = cache.get(42, "nginx", None);
        let second = cache.get(42, "nginx", None);
        assert_eq!(first, second);
        assert_eq!(cache.reads, 1, "同一个 pid 不该重复读 /proc");
    }

    #[test]
    fn the_label_cache_stops_reading_at_the_budget() {
        let mut cache = LabelCache {
            labels: std::collections::HashMap::new(),
            reads: CGROUP_PID_LIMIT,
        };
        let (label, source) = cache.get(7, "nginx", None);
        assert_eq!(label, "nginx");
        assert_eq!(source, "exe", "超预算后必须退回可执行名，不能继续读");
    }

    #[test]
    fn an_unnameable_process_still_gets_a_label() {
        assert_eq!(exe_service("", None).0, "(unknown)");
        assert_eq!(exe_service("worker", None).0, "worker");
    }

    #[test]
    fn the_exact_counter_covers_the_whole_list_not_just_the_top() {
        let processes = vec![
            service_process(1, "a", "a.service", 50.0, 1),
            service_process(2, "b", "b.service", 40.0, 1),
            service_process(3, "c", "c.service", 30.0, 1),
        ];
        // 只有排第三的 c 有精确值；只数前两名就会误报“本机没有 cgroup 口径”。
        let exact = std::collections::BTreeMap::from([("c.service".to_string(), 30.0)]);

        let (services, total, exact_total) = build_services(&processes, &exact, 2);

        assert_eq!(total, 3);
        assert_eq!(services.len(), 2);
        assert_eq!(exact_total, 1);
    }

    #[test]
    fn the_detail_tells_missing_usage_apart_from_missing_cgroup() {
        let mut with_exact = base();
        with_exact.services = vec![group("app.service", "cgroup", 2, 150.0, true)];
        with_exact.service_total = 1;
        with_exact.services_exact = 1;
        with_exact.service_identity_cgroup = true;
        assert!(
            services_finding(&with_exact)
                .detail
                .contains("cgroup 精确值")
        );

        // 归属拿到了、用量没读到：与“没有 cgroup”是两件事。
        let mut no_usage = base();
        no_usage.services = vec![group("app.service", "cgroup", 2, 150.0, false)];
        no_usage.service_total = 1;
        no_usage.service_identity_cgroup = true;
        assert!(
            services_finding(&no_usage)
                .detail
                .contains("读不到累计用量")
        );

        let mut non_linux = base();
        non_linux.services = vec![group("firefox", "exe", 1, 150.0, false)];
        non_linux.service_total = 1;
        assert!(services_finding(&non_linux).detail.contains("非 Linux"));
    }

    #[test]
    fn no_services_at_all_is_a_warning_not_a_clean_bill() {
        let mut snapshot = base();
        snapshot.services.clear();
        snapshot.service_total = 0;
        let finding = services_finding(&snapshot);
        assert_eq!(finding.status, Status::Warn);
        assert!(
            finding.detail.contains("不能当成没人吃"),
            "{}",
            finding.detail
        );
    }

    #[test]
    fn the_process_section_points_at_the_service_section() {
        let mut snapshot = base();
        snapshot.processes = vec![process(1, "worker", 10.0, 1)];
        let finding = top_processes_finding(&snapshot, 10);
        assert!(
            finding.detail.contains("多进程服务的合计"),
            "{}",
            finding.detail
        );
    }

    #[test]
    fn the_topic_is_registered() {
        assert!(crate::investigate::TOPICS.contains(&crate::investigate::TOPIC_LOAD));
        assert_eq!(
            crate::investigate::InvestigateRequest::for_topic("load")
                .expect("load topic")
                .topic,
            "load"
        );
    }
}
