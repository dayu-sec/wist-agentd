//! 主机 CPU 累计时间读取（counter 口径：自开机以来，按核按 mode）。
//!
//! 指标契约要求「累计秒」而不是「本周期占用率」：这里只读数、只换算单位，
//! 不做差分、不做平均。占用率由查询层的 `1 - avg(rate(idle))` 派生。

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
    use super::{LINUX_MODES, parse_proc_stat};

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
