//! 进程域采集：CPU 累计时间、RSS、状态；Linux 走 procfs，其它 unix 走 `ps`。

#[cfg(target_os = "linux")]
use std::fs;
use std::io;
#[cfg(all(unix, not(target_os = "linux")))]
use std::process::Command;

use wist_contracts::discovery::StringKeyValue;

use super::push_fact_if_absent;
use super::{MetricsCollectionTargetSample, MetricsTargetViewEntry};

pub(super) fn probe_process_target(
    target: &MetricsTargetViewEntry,
) -> MetricsCollectionTargetSample {
    let mut sample = MetricsCollectionTargetSample {
        candidate_id: target.candidate_id.clone(),
        target_ref: target.target_ref.clone(),
        status: "failed".to_string(),
        last_error: None,
        resource_ref: target.resource_ref.clone(),
        execution_hints: target.execution_hints.clone(),
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
    };

    let Some(pid) = target
        .execution_hints
        .iter()
        .find(|hint| hint.key == "process.pid")
        .and_then(|hint| hint.value.parse::<u32>().ok())
    else {
        sample.last_error = Some("process.pid execution hint missing".to_string());
        return sample;
    };

    match collect_process_runtime_facts(pid, &sample.execution_hints) {
        Ok(runtime_facts) => {
            sample.status = "succeeded".to_string();
            sample.runtime_facts = runtime_facts;
            sample
        }
        Err(err) => {
            sample.last_error = Some(err.to_string());
            sample
        }
    }
}

pub(super) fn collect_process_runtime_facts(
    pid: u32,
    execution_hints: &[StringKeyValue],
) -> io::Result<Vec<StringKeyValue>> {
    let mut facts = Vec::new();
    push_fact_if_absent(
        &mut facts,
        StringKeyValue::new("process.pid", pid.to_string()),
    );
    for hint in execution_hints {
        if matches!(
            hint.key.as_str(),
            "process.identity" | "discovery.identity_strength" | "discovery.identity_status"
        ) {
            push_fact_if_absent(&mut facts, hint.clone());
        }
    }

    #[cfg(target_os = "linux")]
    {
        let stat = fs::read_to_string(format!("/proc/{pid}/stat"))?;
        if let Some(state) = parse_linux_proc_state(&stat) {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.state", process_state_label(state)),
            );
        }
        if let Some(rss_pages) = parse_linux_proc_rss_pages(&stat) {
            let bytes = rss_pages.max(0) as u64 * page_size();
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.memory.rss_bytes", bytes.to_string()),
            );
        }
        if let Some((utime, stime)) = parse_linux_proc_cpu_ticks(&stat) {
            let seconds = (utime + stime) as f64 / clock_ticks();
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.cpu.seconds", format!("{seconds:.3}")),
            );
        }
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    {
        let output = Command::new("ps")
            .args(["-o", "state=,rss=,cputime=,comm=", "-p", &pid.to_string()])
            .output()?;
        if !output.status.success() {
            return Err(io::Error::other("ps did not exit successfully"));
        }
        let stdout = String::from_utf8_lossy(&output.stdout);
        let line = stdout.trim();
        if line.is_empty() {
            return Err(io::Error::new(
                io::ErrorKind::NotFound,
                "ps returned no process row",
            ));
        }
        let mut parts = line.split_whitespace();
        if let Some(state) = parts.next() {
            let label = process_state_label(state.chars().next().unwrap_or('?'));
            push_fact_if_absent(&mut facts, StringKeyValue::new("process.state", label));
        }
        if let Some(rss_kb) = parts.next() {
            let kb = rss_kb.parse::<u64>().unwrap_or(0);
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new(
                    "process.memory.rss_bytes",
                    kb.saturating_mul(1024).to_string(),
                ),
            );
        }
        if let Some(cputime) = parts.next()
            && let Some(seconds) = parse_ps_cputime(cputime)
        {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.cpu.seconds", format!("{seconds:.3}")),
            );
        }
        if let Some(comm) = parts.next() {
            push_fact_if_absent(
                &mut facts,
                StringKeyValue::new("process.executable.name", comm),
            );
        }
    }

    #[cfg(not(unix))]
    {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "process metrics probe unsupported on this platform",
        ));
    }

    Ok(facts)
}

#[cfg(target_os = "linux")]
pub(super) fn parse_linux_proc_state(stat: &str) -> Option<char> {
    let (_, tail) = stat.rsplit_once(") ")?;
    tail.chars().next()
}

/// 状态字符 → 规范闭集取值（未识别的一律 `unknown`）。
pub(super) fn process_state_label(state: char) -> &'static str {
    match state {
        'R' => "running",
        'S' => "sleeping",
        'D' => "disk_sleep",
        'T' | 't' => "stopped",
        'Z' => "zombie",
        'X' | 'x' => "dead",
        'I' => "idle",
        _ => "unknown",
    }
}

#[cfg(target_os = "linux")]
pub(super) fn page_size() -> u64 {
    let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
    if value <= 0 { 4096 } else { value as u64 }
}

#[cfg(target_os = "linux")]
pub(super) fn clock_ticks() -> f64 {
    let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
    if value <= 0 { 100.0 } else { value as f64 }
}

#[cfg(target_os = "linux")]
pub(super) fn parse_linux_proc_rss_pages(stat: &str) -> Option<i64> {
    let (_, tail) = stat.rsplit_once(") ")?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    if fields.len() <= 21 {
        return None;
    }
    fields.get(21)?.parse().ok()
}

/// `utime` / `stime`（field 14/15）→ 累计 CPU ticks。
#[cfg(target_os = "linux")]
pub(super) fn parse_linux_proc_cpu_ticks(stat: &str) -> Option<(u64, u64)> {
    let (_, tail) = stat.rsplit_once(") ")?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    // tail[0] 是 field 3（state）；utime = field 14 → index 11，stime = field 15 → index 12。
    let utime = fields.get(11)?.parse().ok()?;
    let stime = fields.get(12)?.parse().ok()?;
    Some((utime, stime))
}

/// `ps -o cputime` 的 `[[HH:]MM:]SS[.cc]` → 秒。
#[cfg(any(all(unix, not(target_os = "linux")), test))]
pub(super) fn parse_ps_cputime(text: &str) -> Option<f64> {
    let mut seconds = 0.0;
    let mut seen = false;
    for part in text.split(':') {
        let value: f64 = part.parse().ok()?;
        seconds = seconds * 60.0 + value;
        seen = true;
    }
    seen.then_some(seconds)
}

pub(super) fn process_probe_mode() -> &'static str {
    #[cfg(target_os = "linux")]
    {
        "procfs"
    }
    #[cfg(all(unix, not(target_os = "linux")))]
    {
        "ps"
    }
    #[cfg(not(unix))]
    {
        "unsupported"
    }
}
