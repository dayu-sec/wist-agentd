//! 主机 CPU 累计时间读取（counter 口径：自开机以来，按核按 mode）。
//!
//! 原始事实只有 `system_cpu_seconds_total`（逐核逐 mode 的累计秒），查询侧仍可用
//! `1 - avg(rate(idle))` 派生利用率。
//!
//! 本模块另外维护一个**固定窗口**的派生量 `system_cpu_usage_ratio`：
//! 窗口内 `idle 增量 / (经过时间 × 核数)` 先得到 idle 比例，再取 `1 -` 得到使用率。
//! 两类序列同时存在是有意的——累计量是权威源，比例是给「不想写 PromQL 的调用方」的
//! 便利值；窗口与分母口径见 [`USAGE_WINDOW`]。

use std::collections::VecDeque;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

/// 一个核在一个 mode 下的累计 CPU 秒。
#[derive(Debug, Clone, PartialEq)]
pub(crate) struct CpuTime {
    /// 逻辑核编号（`0`、`1`…）。
    pub cpu: String,
    /// mode 闭集：`user` / `nice` / `system` / `idle` / `iowait` / `irq` / `softirq` / `steal`。
    pub mode: &'static str,
    /// 累计秒。
    pub seconds: f64,
}

/// `/proc/stat` 首行的 mode 顺序；`guest` / `guest_nice` 不在其中——
/// 它们已经包含在 `user` / `nice` 里，再加一遍会让总量偏大。
#[cfg(any(target_os = "linux", test))]
pub(crate) const LINUX_MODES: [&str; 8] = [
    "user", "nice", "system", "idle", "iowait", "irq", "softirq", "steal",
];

/// 读本机各核各 mode 的累计 CPU 秒；读不到返回空（调用方按"无事实"处理）。
pub(crate) fn host_cpu_times() -> Vec<CpuTime> {
    platform::host_cpu_times()
}

/// `system_cpu_usage_ratio` 的窗口长度。
///
/// 与规范里的参考 PromQL `rate(...[60s])` 对齐：窗口内至少要有两个采样点才出值。
pub(crate) const USAGE_WINDOW: Duration = Duration::from_secs(60);

/// 窗口内保留的最大采样点数。主机采集轮次是 3s，60s 窗口正常只有 ~20 个点；
/// 上限只防止调用方把间隔调得很小后无界增长。
const MAX_SAMPLES: usize = 256;

/// 一次「idle 累计秒 + 核数」读数。时间用单调时钟：墙钟回拨不能把窗口算歪。
#[derive(Debug, Clone, Copy, PartialEq)]
struct IdleSample {
    at: Instant,
    idle_seconds: f64,
    cores: usize,
}

/// 固定窗口的 CPU 使用率窗口。
///
/// 纯状态机，不读硬件：便于把「首轮 / 回退 / 核数变化」这些边界单独测出来。
#[derive(Debug, Default)]
pub(crate) struct CpuUsageWindow {
    samples: VecDeque<IdleSample>,
}

impl CpuUsageWindow {
    pub(crate) fn new() -> Self {
        Self::default()
    }

    /// 记录一轮读数，返回窗口内的整机使用率（`0.0..=1.0`）。
    ///
    /// 返回 `None` 的几种情况，都是「宁可不报，也不伪造 0」：
    /// - 首轮（窗口内不足两个点）；
    /// - 计数器回退（重启 / 热插拔后的计数重置）；
    /// - 核数变化（离线核、cgroup 配额变化）—— 历史点与当前点的分母不可比。
    pub(crate) fn observe(
        &mut self,
        at: Instant,
        idle_seconds: f64,
        cores: usize,
        window: Duration,
    ) -> Option<f64> {
        // 非法读数一律当「这一轮没读到」：保留窗口没有意义，也不能拿它当基线。
        // 负数只可能来自解析/平台缺陷；不拒绝会让下一轮把它当成「计数器回退」。
        if cores == 0 || !idle_seconds.is_finite() || idle_seconds < 0.0 {
            self.samples.clear();
            return None;
        }

        // 回退 = 计数器被重置；旧点不能再参与差分。
        if self
            .samples
            .back()
            .is_some_and(|last| cores != last.cores || idle_seconds < last.idle_seconds)
        {
            self.samples.clear();
        }

        while self
            .samples
            .front()
            .is_some_and(|oldest| at.saturating_duration_since(oldest.at) > window)
        {
            self.samples.pop_front();
        }

        self.samples.push_back(IdleSample {
            at,
            idle_seconds,
            cores,
        });
        while self.samples.len() > MAX_SAMPLES {
            self.samples.pop_front();
        }

        let (Some(first), Some(last)) = (self.samples.front(), self.samples.back()) else {
            return None;
        };
        let elapsed = last.at.saturating_duration_since(first.at).as_secs_f64();
        if self.samples.len() < 2 || elapsed <= 0.0 {
            return None;
        }
        let idle_delta = last.idle_seconds - first.idle_seconds;
        if idle_delta < 0.0 {
            self.samples.clear();
            return None;
        }

        // 分子是 idle：先算 idle 比例，使用率才是 `1 - idle_ratio`。
        let idle_ratio = idle_delta / (elapsed * cores as f64);
        Some((1.0 - idle_ratio).clamp(0.0, 1.0))
    }
}

/// 进程内共享的窗口：采集线程只有一条，窗口必须跨轮次存活。
static CPU_USAGE_WINDOW: OnceLock<Mutex<CpuUsageWindow>> = OnceLock::new();

/// 从一轮逐核逐 mode 的累计秒里取 `idle` 总和与核数。
///
/// 只认 `mode="idle"`；核数按出现过的 `cpu` 去重——平台不报 `idle` 时返回 `(0, 0)`，
/// 调用方据此不出值（不把「读不到」当成「0% 使用」）。
fn idle_total(times: &[CpuTime]) -> (f64, usize) {
    let mut cores = std::collections::BTreeSet::new();
    let mut idle_seconds = 0.0;
    for time in times {
        if time.mode == "idle" {
            cores.insert(time.cpu.as_str());
            idle_seconds += time.seconds;
        }
    }
    (idle_seconds, cores.len())
}

/// 记录一轮读数并返回整机使用率；窗口不足两个点时返回 `None`。
pub(crate) fn usage_ratio(at: Instant, times: &[CpuTime]) -> Option<f64> {
    let (idle_seconds, cores) = idle_total(times);
    if cores == 0 {
        return None;
    }
    let mut window = CPU_USAGE_WINDOW
        .get_or_init(|| Mutex::new(CpuUsageWindow::new()))
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    window.observe(at, idle_seconds, cores, USAGE_WINDOW)
}

/// 解析 `/proc/stat` 的 `cpuN` 行。
///
/// 汇总行（`cpu  1 2 …`，`cpu` 后紧跟空白）**必须**跳过：它的第一段是数值而不是核编号，
/// 误当成 `cpu="100"` 会多出一整组假序列。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn parse_proc_stat(text: &str, hz: f64) -> Vec<CpuTime> {
    let mut out = Vec::new();
    for line in text.lines() {
        let Some(rest) = line.strip_prefix("cpu") else {
            continue;
        };
        // `cpu0 …` 的第一个字符是数字；`cpu  1 2 …` 是空白，属于汇总行。
        let Some(first) = rest.chars().next() else {
            continue;
        };
        if !first.is_ascii_digit() {
            continue;
        }
        let mut parts = rest.split_whitespace();
        let Some(id) = parts.next() else { continue };
        if !id.chars().all(|c| c.is_ascii_digit()) {
            continue;
        }
        let values: Vec<u64> = parts
            .take(LINUX_MODES.len())
            .filter_map(|v| v.parse().ok())
            .collect();
        if values.len() < LINUX_MODES.len() {
            continue;
        }
        for (mode, jiffies) in LINUX_MODES.iter().zip(values) {
            out.push(CpuTime {
                cpu: id.to_string(),
                mode,
                seconds: jiffies as f64 / hz,
            });
        }
    }
    out
}

#[cfg(target_os = "linux")]
mod platform {
    use super::CpuTime;

    pub(super) fn host_cpu_times() -> Vec<CpuTime> {
        let Ok(text) = std::fs::read_to_string("/proc/stat") else {
            return Vec::new();
        };
        super::parse_proc_stat(&text, clock_ticks())
    }

    /// USER_HZ（通常 100）。
    fn clock_ticks() -> f64 {
        let hz = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if hz <= 0 { 100.0 } else { hz as f64 }
    }
}

#[cfg(target_os = "macos")]
mod platform {
    use super::CpuTime;

    /// `host_processor_info(PROCESSOR_CPU_LOAD_INFO)` 的 mode 顺序。
    const MODES: [&str; 4] = ["user", "system", "idle", "nice"];

    pub(super) fn host_cpu_times() -> Vec<CpuTime> {
        read_via_host_processor_info()
    }

    #[allow(deprecated)]
    fn read_via_host_processor_info() -> Vec<CpuTime> {
        use std::ptr;

        unsafe {
            let mut count: libc::natural_t = 0;
            let mut info: libc::processor_info_array_t = ptr::null_mut();
            let mut info_count: libc::mach_msg_type_number_t = 0;
            let host = libc::mach_host_self();
            let kr = libc::host_processor_info(
                host,
                libc::PROCESSOR_CPU_LOAD_INFO,
                &mut count,
                &mut info,
                &mut info_count,
            );
            if kr != libc::KERN_SUCCESS || info.is_null() {
                return Vec::new();
            }

            let hz = {
                let ticks = libc::sysconf(libc::_SC_CLK_TCK);
                if ticks <= 0 { 100.0 } else { ticks as f64 }
            };
            let per_cpu = libc::CPU_STATE_MAX as usize;
            let mut out = Vec::with_capacity(count as usize * per_cpu);
            for cpu in 0..count as usize {
                for (offset, mode) in MODES.iter().enumerate() {
                    let ticks = *info.add(cpu * per_cpu + offset) as u64;
                    out.push(CpuTime {
                        cpu: cpu.to_string(),
                        mode,
                        seconds: ticks as f64 / hz,
                    });
                }
            }

            libc::vm_deallocate(
                libc::mach_task_self(),
                info as libc::vm_address_t,
                (info_count as usize) * std::mem::size_of::<libc::integer_t>(),
            );
            out
        }
    }
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod platform {
    use super::CpuTime;

    pub(super) fn host_cpu_times() -> Vec<CpuTime> {
        Vec::new()
    }
}

#[cfg(test)]
mod tests {
    use std::time::{Duration, Instant};

    use super::{CpuTime, CpuUsageWindow, LINUX_MODES, USAGE_WINDOW, idle_total, parse_proc_stat};

    fn idle(cpu: &str, seconds: f64) -> CpuTime {
        CpuTime {
            cpu: cpu.to_string(),
            mode: "idle",
            seconds,
        }
    }

    /// 只取 `mode="idle"`，核数按 `cpu` 去重（同一核的其它 mode 不参与）。
    #[test]
    fn idle_total_counts_only_idle_and_distinct_cores() {
        let times = [
            idle("0", 10.0),
            idle("1", 20.0),
            CpuTime {
                cpu: "0".to_string(),
                mode: "user",
                seconds: 99.0,
            },
        ];
        assert_eq!(idle_total(&times), (30.0, 2));
        assert_eq!(idle_total(&[]), (0.0, 0));
    }

    /// 首轮只有一个点：分母还没有经过时间，不出值（而不是报 0%）。
    #[test]
    fn first_observation_yields_no_usage() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        assert_eq!(window.observe(t0, 100.0, 4, USAGE_WINDOW), None);
    }

    /// 分子是 idle：`usage = 1 - idle_delta / (elapsed × cores)`。
    #[test]
    fn usage_is_one_minus_idle_ratio() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 100.0, 4, USAGE_WINDOW);

        // 3s 内 idle 涨了 6s，4 核 → idle_ratio = 6 / (3×4) = 0.5
        let usage = window
            .observe(t0 + Duration::from_secs(3), 106.0, 4, USAGE_WINDOW)
            .expect("second sample");
        assert!((usage - 0.5).abs() < 1e-9, "got {usage}");

        // 窗口取的是**最旧点 → 当前点**，不是相邻两点：
        // 6s 内 idle 涨 12s，4 核 → 0.5
        let usage = window
            .observe(t0 + Duration::from_secs(6), 112.0, 4, USAGE_WINDOW)
            .expect("third sample");
        assert!((usage - 0.5).abs() < 1e-9, "got {usage}");
    }

    /// 全忙 / 全闲的两个端点。
    #[test]
    fn usage_hits_both_ends() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 0.0, 2, USAGE_WINDOW);
        // idle 一点没涨 → 全忙
        let busy = window
            .observe(t0 + Duration::from_secs(1), 0.0, 2, USAGE_WINDOW)
            .expect("busy");
        assert!((busy - 1.0).abs() < 1e-9, "got {busy}");

        let mut window = CpuUsageWindow::new();
        // 2 核 1s 最多 2s idle → 全闲
        window.observe(t0, 0.0, 2, USAGE_WINDOW);
        let idle_usage = window
            .observe(t0 + Duration::from_secs(1), 2.0, 2, USAGE_WINDOW)
            .expect("idle");
        assert!(idle_usage.abs() < 1e-9, "got {idle_usage}");
    }

    /// 计数器异常（idle 比物理时间涨得快）时夹到 0，不产出负数。
    #[test]
    fn impossible_idle_delta_clamps_to_zero() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 0.0, 4, USAGE_WINDOW);
        let usage = window
            .observe(t0 + Duration::from_secs(1), 24.0, 4, USAGE_WINDOW)
            .expect("sample");
        assert!(usage.abs() < 1e-9, "got {usage}");
    }

    /// 计数器回退（重启 / 热插拔重置）：丢掉旧窗口，下一轮重新建立基线。
    #[test]
    fn counter_reset_drops_the_window() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 100.0, 4, USAGE_WINDOW);
        assert_eq!(
            window.observe(t0 + Duration::from_secs(3), 50.0, 4, USAGE_WINDOW),
            None
        );

        let usage = window
            .observe(t0 + Duration::from_secs(6), 53.0, 4, USAGE_WINDOW)
            .expect("rebuilt baseline");
        assert!((usage - 0.75).abs() < 1e-9, "got {usage}");
    }

    /// 核数变化让前后两点的分母不可比：重置窗口，不拿 4 核的历史除 2 核的现在。
    #[test]
    fn core_count_change_drops_the_window() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 100.0, 4, USAGE_WINDOW);
        assert_eq!(
            window.observe(t0 + Duration::from_secs(3), 106.0, 2, USAGE_WINDOW),
            None
        );
        assert!(
            window
                .observe(t0 + Duration::from_secs(6), 109.0, 2, USAGE_WINDOW)
                .is_some()
        );
    }

    /// 窗口真的是「最近 W 秒」，而不是「从第一轮开始」：旧基线掉出窗口后，
    /// 分母跟着换成窗口内的新基线。
    #[test]
    fn the_window_only_covers_the_last_w_seconds() {
        let mut window = CpuUsageWindow::new();
        let window_len = Duration::from_secs(10);
        let t0 = Instant::now();
        window.observe(t0, 0.0, 1, window_len);
        // 前 6s 全闲
        let usage = window
            .observe(t0 + Duration::from_secs(6), 6.0, 1, window_len)
            .expect("first interval");
        assert!(usage.abs() < 1e-9, "got {usage}");

        // 到 11s 时 t0 已超出 10s 窗口：只剩 t0+6 这个基线。
        // 这 5s 内 idle 一点没涨 → 全忙；若错用 t0，会算出 ~0.45。
        let usage = window
            .observe(t0 + Duration::from_secs(11), 6.0, 1, window_len)
            .expect("window slid");
        assert!((usage - 1.0).abs() < 1e-9, "got {usage}");
    }

    /// 非法读数：零核 / NaN / 无穷 / 负数都不出值，并丢掉旧窗口重新建基线。
    #[test]
    fn invalid_readings_are_rejected() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 10.0, 2, USAGE_WINDOW);

        assert_eq!(
            window.observe(t0 + Duration::from_secs(1), 10.0, 0, USAGE_WINDOW),
            None,
            "零核"
        );
        assert_eq!(
            window.observe(t0 + Duration::from_secs(2), f64::NAN, 2, USAGE_WINDOW),
            None,
            "NaN"
        );
        assert_eq!(
            window.observe(t0 + Duration::from_secs(3), f64::INFINITY, 2, USAGE_WINDOW),
            None,
            "无穷"
        );
        assert_eq!(
            window.observe(t0 + Duration::from_secs(4), -1.0, 2, USAGE_WINDOW),
            None,
            "负数"
        );

        // 窗口已被清空：下一轮重建基线，再下一轮才出值。
        assert_eq!(
            window.observe(t0 + Duration::from_secs(5), 20.0, 2, USAGE_WINDOW),
            None
        );
        let usage = window
            .observe(t0 + Duration::from_secs(6), 22.0, 2, USAGE_WINDOW)
            .expect("rebuilt baseline");
        assert!(usage.abs() < 1e-9, "got {usage}");
    }

    /// 超出窗口的旧点被丢掉：只剩一个点时不出值。
    #[test]
    fn samples_older_than_the_window_are_pruned() {
        let mut window = CpuUsageWindow::new();
        let t0 = Instant::now();
        window.observe(t0, 100.0, 4, USAGE_WINDOW);
        window.observe(t0 + Duration::from_secs(3), 106.0, 4, USAGE_WINDOW);
        assert_eq!(
            window.observe(t0 + Duration::from_secs(120), 400.0, 4, USAGE_WINDOW),
            None,
            "两分钟内没有其它点，窗口里只剩当前点"
        );
    }

    #[test]
    fn parses_per_cpu_lines_and_skips_the_aggregate_row() {
        let text = "cpu  100 20 30 400 5 1 2 3 9 9\n\
                    cpu0 50 10 15 200 2 0 1 1 4 4\n\
                    cpu1 50 10 15 200 3 1 1 2 5 5\n";
        let times = parse_proc_stat(text, 100.0);
        assert_eq!(times.len(), 2 * LINUX_MODES.len());
        assert_eq!(times[0].cpu, "0");
        assert_eq!(times[0].mode, "user");
        assert!((times[0].seconds - 0.5).abs() < 1e-9);
        assert_eq!(times[LINUX_MODES.len()].cpu, "1");
        assert_eq!(times.last().expect("last").mode, "steal");
    }

    #[test]
    fn ignores_short_or_malformed_lines() {
        let text = "cpu0 1 2 3\ncpu1 1 2 3 4 5 6 7 8\ncpuX 1 2 3 4 5 6 7 8\nintr 0\n";
        let times = parse_proc_stat(text, 100.0);
        assert_eq!(times.len(), LINUX_MODES.len());
        assert_eq!(times[0].cpu, "1");
    }

    #[test]
    fn guest_fields_are_not_counted_separately() {
        // 第 9/10 段（guest / guest_nice）不参与，否则分母偏大。
        let text = "cpu0 10 0 0 90 0 0 0 0 50 50\n";
        let times = parse_proc_stat(text, 100.0);
        let total: f64 = times.iter().map(|t| t.seconds).sum();
        assert!((total - 1.0).abs() < 1e-9, "got {total}");
    }

    #[test]
    fn host_cpu_times_is_present_on_supported_platforms() {
        let times = super::host_cpu_times();
        if cfg!(any(target_os = "linux", target_os = "macos")) {
            assert!(!times.is_empty(), "expected per-cpu times");
            assert!(times.iter().all(|t| t.seconds >= 0.0));
            assert!(times.iter().all(|t| !t.cpu.is_empty()));
        }
    }
}
