//! agent 自观测指标：不经采集目标，由 agent 进程自己产出。
//!
//! 这些指标回答「agent 本身是否健康与工作正常」，与主机 / 进程 / 容器域无关：
//! 没有 `instance`，也不受目标采样上限约束。值分两类来源：
//!
//! - **直接可读**：常驻内存、逻辑核数；
//! - **跨批次状态**：单核 CPU 占用率（3 秒窗口）、管理面延迟、已生效策略版本、
//!   指标上送失败累计。这些由运行时在各事件点写入，指标批次只负责读出。
//!
//! 计数器（`*_total`）在进程重启后从 0 重新开始。查询侧按 Prometheus 的重置语义处理
//! （`rate` / `increase` 遇到下降即视为重置），不为了跨重启连续而引入持久化写入。

use std::sync::Mutex;
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::time::Instant;

/// 单核占用率的最小窗口：短于它时差分只反映调度抖动，不发读数。
const MIN_CPU_WINDOW: std::time::Duration = std::time::Duration::from_millis(100);

/// 一次 CPU 计数采样点。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct CpuSample {
    pub(crate) ticks: u64,
    pub(crate) at: Instant,
}

impl CpuSample {
    pub(crate) fn now() -> Option<Self> {
        Some(Self {
            ticks: cpu_ticks()?,
            at: Instant::now(),
        })
    }
}

/// 本进程上一次 CPU 计数（自观测自己的差分基线，与状态上报互不影响）。
static LAST_CPU: Mutex<Option<CpuSample>> = Mutex::new(None);
/// 最近一次管理面交互延迟（毫秒）；`u64::MAX` 表示还没有成功读数。
static ADMIN_LATENCY_MS: AtomicU64 = AtomicU64::new(u64::MAX);
/// 已生效的发现策略版本；`i64::MIN` 表示还没收到过策略。
static POLICY_VERSION: AtomicI64 = AtomicI64::new(i64::MIN);
/// 指标上送失败累计（每批 +1）。
static UPLINK_FAILURES: AtomicU64 = AtomicU64::new(0);

/// 一次自观测读数；`None` 字段表示本批次拿不到可信值（不发该序列）。
#[derive(Debug, Clone, Copy, PartialEq, Default)]
pub(crate) struct SelfObservation {
    pub(crate) cpu_ratio: Option<f64>,
    pub(crate) cpu_cores: Option<u64>,
    pub(crate) memory_bytes: Option<u64>,
    pub(crate) admin_latency_seconds: Option<f64>,
    pub(crate) discovery_policy_version: Option<i64>,
    pub(crate) uplink_metrics_failed_total: u64,
}

/// 记录一次管理面交互延迟（毫秒）。
pub(crate) fn record_admin_latency(ms: u64) {
    ADMIN_LATENCY_MS.store(ms, Ordering::Relaxed);
}

/// 记录当前已生效的发现策略版本。
pub(crate) fn record_policy_version(version: i64) {
    POLICY_VERSION.store(version, Ordering::Relaxed);
}

/// 记录一次指标上送失败（每批一次）。
pub(crate) fn record_uplink_failure() {
    UPLINK_FAILURES.fetch_add(1, Ordering::Relaxed);
}

/// 读出当前自观测值；CPU 占用率用与上次调用之间的差分计算。
pub(crate) fn snapshot() -> SelfObservation {
    SelfObservation {
        cpu_ratio: take_cpu_ratio(),
        cpu_cores: local_cpu_cores().map(u64::from),
        memory_bytes: current_rss_bytes(),
        admin_latency_seconds: admin_latency_seconds(),
        discovery_policy_version: discovery_policy_version(),
        uplink_metrics_failed_total: UPLINK_FAILURES.load(Ordering::Relaxed),
    }
}

fn admin_latency_seconds() -> Option<f64> {
    match ADMIN_LATENCY_MS.load(Ordering::Relaxed) {
        u64::MAX => None,
        ms => Some(ms as f64 / 1000.0),
    }
}

fn discovery_policy_version() -> Option<i64> {
    match POLICY_VERSION.load(Ordering::Relaxed) {
        i64::MIN => None,
        version => Some(version),
    }
}

fn take_cpu_ratio() -> Option<f64> {
    let now = CpuSample::now()?;
    let mut guard = LAST_CPU.lock().unwrap_or_else(|err| err.into_inner());
    let previous = guard.replace(now);
    let previous = previous?;
    let wall = now.at.duration_since(previous.at);
    if wall < MIN_CPU_WINDOW {
        return None;
    }
    cpu_ratio_between(
        previous.ticks,
        now.ticks,
        wall.as_secs_f64(),
        ticks_per_sec(),
    )
}

/// 单核占用率：`ΔCPU秒 / Δ墙钟秒`，`1.0` = 占满一个核（可 > 1，多核并行时）。
fn cpu_ratio_between(
    previous_ticks: u64,
    now_ticks: u64,
    wall_secs: f64,
    ticks_per_sec: u64,
) -> Option<f64> {
    if wall_secs <= 0.0 || ticks_per_sec == 0 {
        return None;
    }
    let tick_delta = now_ticks.saturating_sub(previous_ticks) as f64;
    Some(tick_delta / ticks_per_sec as f64 / wall_secs)
}

/// 单核口径的**百分比**（100 = 占满一个核），状态上报用。
pub(crate) fn cpu_percent_since(
    previous: &CpuSample,
    now: Instant,
    ticks_per_sec: u64,
) -> Option<f64> {
    let now_ticks = cpu_ticks()?;
    let wall = now.duration_since(previous.at).as_secs_f64();
    if wall <= 0.0 {
        return Some(0.0);
    }
    cpu_ratio_between(previous.ticks, now_ticks, wall, ticks_per_sec).map(|ratio| ratio * 100.0)
}

/// 本机**逻辑核数**（`available_parallelism`）。
///
/// 单核口径的占用率需要除以核数才能得到整机占比；分子分母都由 agent 给出，
/// 换算留给查询侧，避免在这里先除一遍再乘回去。
pub(crate) fn local_cpu_cores() -> Option<u32> {
    std::thread::available_parallelism()
        .ok()
        .map(|count| count.get() as u32)
}

/// 当前常驻内存（字节），平台不提供时返回 `None`。
pub(crate) fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/statm").ok()?;
        // statm: size, resident, shared, text, lib, data, dt（单位：页）。
        let resident_pages: u64 = content.split_whitespace().nth(1)?.parse().ok()?;
        Some(resident_pages * page_size())
    }
    #[cfg(target_os = "macos")]
    {
        // proc_pidinfo(PROC_PIDTASKINFO) 的 resident_size 就是字节。
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let written = unsafe {
            libc::proc_pidinfo(
                std::process::id() as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut libc::proc_taskinfo as *mut libc::c_void,
                size,
            )
        };
        if written != size {
            return None;
        }
        Some(info.pti_resident_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// 本进程累计 CPU 时间（user + system），单位是 `ticks_per_sec()` 的 tick。
pub(crate) fn cpu_ticks() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/stat").ok()?;
        // comm 可能含空格与 ')'，所以从最后一个 ')' 之后切：state(3) 起算，
        // utime(14) 是第 11 个字段、stime(15) 是第 12 个。
        let fields: Vec<&str> = content.rsplit(')').next()?.split_whitespace().collect();
        let utime: u64 = fields.get(11)?.parse().ok()?;
        let stime: u64 = fields.get(12)?.parse().ok()?;
        Some(utime + stime)
    }
    #[cfg(target_os = "macos")]
    {
        // getrusage 给的是 timeval（秒 + 微秒）；用微秒作 tick，
        // 于是 ticks_per_sec() = 1_000_000，换算保持线性。
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            return None;
        }
        let user_us = usage.ru_utime.tv_sec as i64 * 1_000_000 + usage.ru_utime.tv_usec as i64;
        let system_us = usage.ru_stime.tv_sec as i64 * 1_000_000 + usage.ru_stime.tv_usec as i64;
        Some((user_us + system_us) as u64)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
pub(crate) fn ticks_per_sec() -> u64 {
    let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if hz <= 0 { 100 } else { hz as u64 }
}

#[cfg(target_os = "macos")]
pub(crate) fn ticks_per_sec() -> u64 {
    1_000_000
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
pub(crate) fn ticks_per_sec() -> u64 {
    100
}

#[cfg(target_os = "linux")]
fn page_size() -> u64 {
    let size = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if size <= 0 { 4096 } else { size as u64 }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn single_core_ratio_is_cpu_seconds_over_wall_seconds() {
        // 3 秒窗口里用掉 1.5 秒 CPU（Linux USER_HZ=100 → 150 tick）= 0.5 个核。
        assert_eq!(cpu_ratio_between(0, 150, 3.0, 100), Some(0.5));
        // 用满两个核：Δ 6 秒 / 3 秒 = 2.0。
        assert_eq!(cpu_ratio_between(0, 600, 3.0, 100), Some(2.0));
    }

    #[test]
    fn ratio_is_none_without_a_usable_window() {
        assert_eq!(cpu_ratio_between(0, 100, 0.0, 100), None);
        assert_eq!(cpu_ratio_between(0, 100, 3.0, 0), None);
    }

    #[test]
    fn counter_ticks_never_go_backwards() {
        // 重启后计数归零，差分必须夹到 0，不能出现负占用。
        assert_eq!(cpu_ratio_between(1_000, 10, 1.0, 100), Some(0.0));
    }

    #[test]
    fn failure_counter_only_moves_forward() {
        let before = snapshot().uplink_metrics_failed_total;
        record_uplink_failure();
        record_uplink_failure();
        let after = snapshot().uplink_metrics_failed_total;
        assert!(
            after >= before + 2,
            "counter must accumulate: {before} -> {after}"
        );
    }
}
