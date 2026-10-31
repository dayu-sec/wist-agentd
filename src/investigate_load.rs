//! 负载调查（`wist-agentd investigate load`）：**负载高了，到底是谁在吃 CPU / 内存 / IO**。
//!
//! 现场看到的是「负载 80」这种数字，但负载只是一条**排队长度**：同样 80，可能是 16 核跑满、
//! 也可能 CPU 闲着而一堆进程卡在磁盘上。所以这一题按「先分流 → 再点名」给七节证据：
//!
//! 1. `load.summary` — 1/5/15 分钟负载 + 核数 + **每核负载** + 运行队列（Linux）；
//! 2. `load.cpu` — 总体与**每核**占用，Linux 还给 user/system/iowait/idle 的去向；
//! 3. `load.top_processes` — 按 CPU 排的进程（**不放 argv**，只给名字，见 §脱敏）；
//! 4. `load.memory` — 物理内存与 swap（swap 在用 = 已经在换页，延迟会抖）；
//! 5. `load.io` — iowait / PSI io 压力 / **不可中断睡眠（D 状态）进程数**；
//! 6. `load.agent_processes` — 先排除「是不是我们自己」（调查与采集本身也吃 CPU）；
//! 7. `load.sample` — 这次采样的窗口与平台能力（**没有采到 ≠ 正常**）。
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

const AGENT_CPU_WARN: f64 = 100.0;
const AGENT_CPU_FAIL: f64 = 300.0;
const AGENT_RSS_WARN: u64 = 1 << 30;
const AGENT_RSS_FAIL: u64 = 4 << 30;

/// 采样窗口：sysinfo 的 CPU% 是**两次刷新之间的增量**，低于
/// `MINIMUM_CPU_UPDATE_INTERVAL`(200ms) 会得到 0。给 300ms 起步，
/// `--max-seconds` 可以把它拉长到 1s（更稳，但调查会多等一会儿）。
const SAMPLE_WINDOW_MIN_MS: u64 = 300;
const SAMPLE_WINDOW_MAX_MS: u64 = 1_000;

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
    pub window_ms: u64,
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
        (max_seconds.saturating_mul(1000)).clamp(SAMPLE_WINDOW_MIN_MS, SAMPLE_WINDOW_MAX_MS),
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

    std::thread::sleep(window);

    system.refresh_cpu_all();
    system.refresh_processes(ProcessesToUpdate::All, true);
    system.refresh_memory();
    let stat_after = cpu_times_before();

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
// 七节
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
            hint.push_str("CPU 确实在忙：看「最吃 CPU 的进程」点名，再决定是扩容、限流还是改并发");
        } else {
            hint.push_str(
                "**CPU 不忙而负载高**：几乎一定是进程卡在磁盘/网络存储上（不可中断睡眠）。\
                 先看「IO 等待与不可中断睡眠」，再用 `wist-agentd investigate disk` 找是谁在写",
            );
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
                 加核没用；去看那个进程的线程/连接模型"
            )
        } else {
            format!(
                "{saturated} 个核打满：是**整体并发压力**。先按「最吃 CPU 的进程」点名，\
                 再考虑限流、拆实例或扩容"
            )
        };
        finding = finding.hint(hint);
    }
    finding
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
        "进程共 {} 个；按 CPU 列出前 {} 个（采样窗口 {}ms，百分比是**窗口内平均**）",
        snapshot.process_total,
        rows.len(),
        snapshot.window_ms
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
        "cores={} physical={} window={}ms procs={} top={} iowait={} psi={} d_state={} platform={}",
        snapshot.logical_cores,
        snapshot
            .physical_cores
            .map(|value| value.to_string())
            .unwrap_or_else(|| "-".to_string()),
        snapshot.window_ms,
        snapshot.process_total,
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
        snapshot.d_state,
        std::env::consts::OS
    );

    // 「没采到」与「采到了 0」必须分开：0 个进程不是健康，是没读到。
    let status = if snapshot.process_total == 0 || snapshot.window_ms < SAMPLE_WINDOW_MIN_MS {
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
/// 只在 Linux 与测试里编译：非 Linux 平台没有 `/proc/stat`，但解析本身是纯函数，
/// 值得在每台开发机上都能被单测盖到（不靠“在 macOS 上跑不到就不测”）。
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(text: &str) -> Option<CpuTimes> {
    let line = text.lines().find(|line| line.starts_with("cpu "))?;
    let values: Vec<u64> = line
        .split_whitespace()
        .skip(1)
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
            process_total: 120,
            memory_total: 16 << 30,
            memory_used: 4 << 30,
            memory_available: 12 << 30,
            swap_total: 0,
            swap_used: 0,
            d_state: 0,
            io: IoSignals::default(),
            window_ms: 300,
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
