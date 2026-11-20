//! 一轮一张进程表：本机进程事实的唯一取数入口。
//!
//! 为什么不是「每个 pid 一次外部命令」：macOS 没有 `/proc`，取一个进程的
//! state/rss/cpu 只能靠 `ps`。按目标逐个 fork 时，900 个进程的机器上一轮就是
//! 900 次 fork+exec（实测 1.6ms/次 → 单轮约 1.4s CPU，约占一个核的 20%，
//! launchd 还会把进程判成 `inefficient`）。这里把取数收敛成**每轮一次全表**，
//! 所有消费者查表：指标采集（`process_metrics` / `container_metrics`）、
//! 发现侧的进程清单与身份令牌。
//!
//! 形态上只有一个入口 [`snapshot`]：一次调用覆盖本轮全部目标。让「每个 pid 一次
//! 外部命令」在签名层面写不出来 —— 靠纪律挡不住下一次有人再写一个 `ps`。
//!
//! 身份令牌格式**刻意不变**（`ps_lstart:` / `linux_proc_start:`）：它持久化在
//! `state/running/*` 里，换取数方式不能顺手换格式，否则升级后会把在飞的
//! execution 判成「进程换了」。

use std::collections::BTreeMap;

/// macOS 身份令牌前缀：与 `process_control::process_identity` 保持同一格式。
#[cfg(any(all(unix, not(target_os = "linux")), test))]
const PS_LSTART_PREFIX: &str = "ps_lstart:";

/// Linux 身份令牌前缀：`/proc/<pid>/stat` 的 `starttime`（field 22）。
#[cfg(any(target_os = "linux", test))]
const LINUX_PROC_START_PREFIX: &str = "linux_proc_start:";

/// 一个进程在本轮表里的全部事实。
#[derive(Debug, Clone, PartialEq)]
pub struct ProcRow {
    pub pid: u32,
    /// 状态首字母（macOS 的 `Ss` 这类只取 `S`），取值含义见
    /// `telemetry::metrics::runtime::process::process_state_label`。
    pub state: char,
    pub rss_bytes: u64,
    /// 累计 CPU 时间（user + system），秒。
    pub cpu_seconds: f64,
    /// 身份令牌：拿不到（内核线程等）时是 `None`。
    pub start_token: Option<String>,
    /// 可执行名/路径。两端**都发**（同口径）：macOS 由 `ps` 的 `comm` 列给出（全路径）；
    /// Linux 取 `/proc/<pid>/exe` 的指向，读不到时退回 `/proc/<pid>/comm`（15 字符 basename）。
    pub comm: Option<String>,
}

/// 某一轮采到的进程表。
///
/// 「拿不到」不抛错而是记在 [`ProcSnapshot::error`] 里：调用方对失败的处理各不相同
/// （发现侧要整轮失败，指标侧要逐目标报 failed），由它们自己决定，这里不替它们做
/// 决定，也不伪造空表之外的任何值。
#[derive(Default)]
pub struct ProcSnapshot {
    rows: BTreeMap<u32, ProcRow>,
    error: Option<String>,
}

impl ProcSnapshot {
    pub fn get(&self, pid: u32) -> Option<&ProcRow> {
        self.rows.get(&pid)
    }

    /// 按 pid 升序 —— 顺序必须稳定：发现侧的快照内容摘要会因顺序变化而变。
    ///
    /// 只给 macOS 的发现侧用：Linux 的发现侧仍自己读 `/proc`（`exe → cmdline → comm`
    /// 三级回退不能退化成 15 字符的 basename），所以这张表在 Linux 上只被按 pid 查。
    #[cfg(any(all(unix, not(target_os = "linux")), test))]
    pub fn iter(&self) -> impl Iterator<Item = &ProcRow> {
        self.rows.values()
    }

    #[cfg(any(all(unix, not(target_os = "linux")), test))]
    pub fn is_empty(&self) -> bool {
        self.rows.is_empty()
    }

    pub fn error(&self) -> Option<&str> {
        self.error.as_deref()
    }

    #[cfg(test)]
    pub(crate) fn from_rows(rows: Vec<ProcRow>) -> Self {
        let mut map = BTreeMap::new();
        for row in rows {
            map.insert(row.pid, row);
        }
        Self {
            rows: map,
            error: None,
        }
    }
}

/// 采一轮进程表。每轮调一次，不要按 pid 调。
pub fn snapshot() -> ProcSnapshot {
    imp::snapshot()
}

#[cfg(all(unix, not(target_os = "linux")))]
mod imp {
    use std::process::Command;

    use super::*;

    /// 列序固定，**可含空格的 `comm` 必须在最后**；`lstart` 固定 5 段
    /// （`Fri Nov 20 21:03:13 2026`）。
    const PS_FORMAT: &str = "pid=,state=,rss=,cputime=,lstart=,comm=";

    pub(super) fn snapshot() -> ProcSnapshot {
        let mut table = ProcSnapshot::default();
        let output = Command::new("ps")
            .args(["-axo", PS_FORMAT])
            // `lstart` 的星期/月名随 locale 变。令牌只做相等比较，但两次取值跨了
            // locale 就会被判成「进程换了」，所以这里钉死 C locale。
            .env("LC_ALL", "C")
            .output();
        match output {
            Ok(output) if output.status.success() => {
                for row in parse_ps_table(&String::from_utf8_lossy(&output.stdout)) {
                    table.rows.insert(row.pid, row);
                }
            }
            Ok(output) => table.error = Some(format!("ps exited with {}", output.status)),
            Err(err) => table.error = Some(format!("ps unavailable: {err}")),
        }
        table
    }
}

#[cfg(target_os = "linux")]
mod imp {
    use std::fs;

    use super::*;

    pub(super) fn snapshot() -> ProcSnapshot {
        let mut table = ProcSnapshot::default();
        match fs::read_dir("/proc") {
            Ok(entries) => {
                for entry in entries {
                    let Ok(entry) = entry else { continue };
                    // `file_name()` 是临时值：先转成 owned 再解析（与端点探针同一写法）。
                    let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
                        continue;
                    };
                    let Ok(pid) = file_name.parse::<u32>() else {
                        continue;
                    };
                    // 进程在 read_dir 与这次读之间消失是常态：跳过，不记成失败。
                    let Ok(stat) = fs::read_to_string(format!("/proc/{pid}/stat")) else {
                        continue;
                    };
                    // 多一次 readlink 换「两端同口径的可执行名」：µs 级，且这个 fact
                    // 在指标映射里是 ignored（§7.5），不增加上送序列。
                    let comm = executable_name(pid);
                    if let Some(row) = parse_proc_stat(pid, &stat, page_size(), clock_ticks(), comm)
                    {
                        table.rows.insert(row.pid, row);
                    }
                }
            }
            Err(err) => table.error = Some(format!("/proc unavailable: {err}")),
        }
        table
    }

    fn page_size() -> u64 {
        // SAFETY: `sysconf` 只读系统常量，不涉及 Rust 管理的内存。
        let value = unsafe { libc::sysconf(libc::_SC_PAGESIZE) };
        if value <= 0 { 4096 } else { value as u64 }
    }

    fn clock_ticks() -> f64 {
        // SAFETY: 同上。
        let value = unsafe { libc::sysconf(libc::_SC_CLK_TCK) };
        if value <= 0 { 100.0 } else { value as f64 }
    }

    /// 可执行名：优先 `/proc/<pid>/exe` 的指向（全路径，与 macOS `ps comm` 同口径）。
    ///
    /// 读不到时退回 `/proc/<pid>/comm`：内核线程没有 `exe` 链接；非 root 读别人的
    /// `exe` 会被 `ptrace_may_access` 拒（EACCES）。那是 15 字符的 basename，口径差一档，
    /// 但比「Linux 干脆不发这个 fact」好——两台机的 fact 集合才是可比的。
    fn executable_name(pid: u32) -> Option<String> {
        match fs::read_link(format!("/proc/{pid}/exe")) {
            Ok(path) => {
                let name = path.to_string_lossy().into_owned();
                (!name.is_empty()).then_some(name)
            }
            Err(_) => fs::read_to_string(format!("/proc/{pid}/comm"))
                .ok()
                .map(|value| value.trim().to_string())
                .filter(|value| !value.is_empty()),
        }
    }
}

#[cfg(not(unix))]
mod imp {
    use super::*;

    pub(super) fn snapshot() -> ProcSnapshot {
        let mut table = ProcSnapshot::default();
        table.error = Some("process table unsupported on this platform".to_string());
        table
    }
}

/// `ps -axo pid=,state=,rss=,cputime=,lstart=,comm=` 的输出 → 行。
///
/// 纯函数：Linux CI 上也能单测（生产里只在 macOS 走它）。
#[cfg(any(all(unix, not(target_os = "linux")), test))]
pub fn parse_ps_table(stdout: &str) -> Vec<ProcRow> {
    stdout.lines().filter_map(parse_ps_table_line).collect()
}

#[cfg(any(all(unix, not(target_os = "linux")), test))]
fn parse_ps_table_line(line: &str) -> Option<ProcRow> {
    let (head, head_len) = take_fields(line, 4)?;
    // `lstart` 与 `comm` 都取**原始切片**（只 trim 两端）：
    //   * `lstart` 的日期是 `%e`（空格填充），单位数日会有两个空格 ——
    //     按词重新拼接会改成单空格，令牌就和旧实现（`ps -o lstart=` 原样）不一样了，
    //     升级后会把在飞的 execution 判成「进程换了」。
    //   * `comm` 是路径，里面的连续空格同样不能被归一化，否则 `process_path` 规则对不上。
    let (_, lstart_len) = take_fields(&line[head_len..], 5)?;
    let lstart = line[head_len..head_len + lstart_len].trim();
    let comm = line[head_len + lstart_len..].trim();

    Some(ProcRow {
        pid: head[0].parse().ok()?,
        state: head[1].chars().next()?,
        rss_bytes: head[2].parse::<u64>().ok()?.saturating_mul(1024),
        cpu_seconds: parse_ps_cputime(head[3])?,
        start_token: Some(format!("{PS_LSTART_PREFIX}{lstart}")),
        comm: (!comm.is_empty()).then(|| comm.to_string()),
    })
}

/// 按空白切出前 `n` 个字段，返回（字段, 已消耗的字节数）。
///
/// 返回**消耗长度**而不是拼接好的字符串：调用方要按它切原始切片，
/// 才能保留 `lstart` / `comm` 里的内部空白。
#[cfg(any(all(unix, not(target_os = "linux")), test))]
fn take_fields(line: &str, n: usize) -> Option<(Vec<&str>, usize)> {
    let mut fields = Vec::with_capacity(n);
    let mut cursor = 0usize;
    for _ in 0..n {
        let start = cursor + line[cursor..].find(|c: char| !c.is_whitespace())?;
        let end = line[start..]
            .find(char::is_whitespace)
            .map_or(line.len(), |offset| start + offset);
        fields.push(&line[start..end]);
        cursor = end;
    }
    Some((fields, cursor))
}

/// `ps -o cputime` 的 `[[HH:]MM:]SS[.cc]` → 秒。
#[cfg(any(all(unix, not(target_os = "linux")), test))]
fn parse_ps_cputime(text: &str) -> Option<f64> {
    let mut seconds = 0.0;
    let mut seen = false;
    for part in text.split(':') {
        let value: f64 = part.parse().ok()?;
        seconds = seconds * 60.0 + value;
        seen = true;
    }
    seen.then_some(seconds)
}

/// `/proc/<pid>/stat` → 行。字段口径与 `parse_linux_proc_*` 一致：
/// `)` 之后从 field 3（state）起算，`utime`/`stime` = index 11/12，
/// `starttime`（field 22）= index 19，`rss`（field 24）= index 21。
///
/// `comm` 不在这份文件里，由调用方从 `/proc/<pid>/exe` 取后传进来（保持本函数纯）。
#[cfg(any(target_os = "linux", test))]
fn parse_proc_stat(
    pid: u32,
    stat: &str,
    page_size: u64,
    clock_ticks: f64,
    comm: Option<String>,
) -> Option<ProcRow> {
    let (_, tail) = stat.rsplit_once(") ")?;
    let fields: Vec<&str> = tail.split_whitespace().collect();
    let state = fields.first()?.chars().next()?;
    let utime: u64 = fields.get(11)?.parse().ok()?;
    let stime: u64 = fields.get(12)?.parse().ok()?;
    let start_time: u64 = fields.get(19)?.parse().ok()?;
    let rss_pages: i64 = fields.get(21)?.parse().ok()?;
    Some(ProcRow {
        pid,
        state,
        rss_bytes: rss_pages.max(0) as u64 * page_size,
        cpu_seconds: (utime + stime) as f64 / clock_ticks,
        start_token: Some(format!("{LINUX_PROC_START_PREFIX}{start_time}")),
        comm,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32) -> ProcRow {
        ProcRow {
            pid,
            state: 'S',
            rss_bytes: 1024,
            cpu_seconds: 0.0,
            start_token: Some("ps_lstart:Mon Nov 16 15:45:11 2026".to_string()),
            comm: None,
        }
    }

    /// 真机自检：表必须覆盖当前进程，否则说明列格式/解析已经和平台的 `ps` 脱节。
    #[test]
    fn snapshot_contains_the_current_process() {
        let table = snapshot();
        assert!(
            table.error().is_none(),
            "进程表取数失败: {:?}",
            table.error()
        );
        let own = std::process::id();
        let row = table.get(own).expect("当前进程必须在表里");
        assert!(row.rss_bytes > 0, "rss 必须可读");
        assert!(row.start_token.is_some(), "身份令牌必须可用");
        assert!(
            row.comm.is_some(),
            "可执行名两端都发（macOS `comm` / Linux `/proc/<pid>/exe`）"
        );
    }

    #[test]
    fn ps_table_keeps_command_with_spaces_and_fixed_lstart() {
        let rows = parse_ps_table(
            "  123 Ss    14896   0:26.35 Mon Nov 16 15:45:11 2026     /usr/local/bin/wist-gwlinkd\n\
             \x20 456 R     2048   2:03:04.50 Fri Nov 20 21:03:13 2026     /Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook\n",
        );

        assert_eq!(rows.len(), 2);
        assert_eq!(rows[0].pid, 123);
        // macOS 的 `Ss`：只取状态首字母。
        assert_eq!(rows[0].state, 'S');
        assert_eq!(rows[0].rss_bytes, 14896 * 1024);
        assert_eq!(rows[0].cpu_seconds, 26.35);
        assert_eq!(
            rows[0].start_token.as_deref(),
            Some("ps_lstart:Mon Nov 16 15:45:11 2026")
        );
        assert_eq!(rows[0].comm.as_deref(), Some("/usr/local/bin/wist-gwlinkd"));
        // comm 里的空格不能被拆开。
        assert_eq!(
            rows[1].comm.as_deref(),
            Some("/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook")
        );
        assert_eq!(rows[1].cpu_seconds, 7384.5);
    }

    /// `lstart` 的日期是 `%e`（空格填充），单位数日有两个空格。
    /// 令牌必须和旧实现（`ps -o lstart=` 原样）逐字节一致，否则升级后
    /// 在飞的 execution 会被判成「进程换了」。
    #[test]
    fn ps_table_keeps_the_raw_lstart_spacing() {
        let rows =
            parse_ps_table("  9 Ss    1024   0:01.00 Fri Nov  5 21:03:13 2026     /usr/bin/demo\n");

        assert_eq!(
            rows[0].start_token.as_deref(),
            Some("ps_lstart:Fri Nov  5 21:03:13 2026")
        );
    }

    /// 路径里的连续空格同样不能被归一化，否则 `process_path` 规则对不上。
    #[test]
    fn ps_table_keeps_inner_whitespace_of_the_path() {
        let rows = parse_ps_table(
            " 77 Ss    1024   0:01.00 Mon Nov 16 15:45:11 2026     /Applications/Foo  Bar.app/Contents/MacOS/demo\n",
        );

        assert_eq!(
            rows[0].comm.as_deref(),
            Some("/Applications/Foo  Bar.app/Contents/MacOS/demo")
        );
    }

    #[test]
    fn snapshot_iterates_in_pid_order() {
        let table = ProcSnapshot::from_rows(vec![row(300), row(2), row(77)]);

        assert!(!table.is_empty());
        let pids: Vec<u32> = table.iter().map(|row| row.pid).collect();
        assert_eq!(pids, vec![2, 77, 300], "顺序变化会让发现快照的摘要无端变化");
    }

    #[test]
    fn ps_table_skips_lines_missing_the_fixed_columns() {
        // 少一列 → 整行丢弃（宁可当「进程不存在」，也不编一个 0 出来）。
        assert!(parse_ps_table("123 S 1024 0:01.00 Mon Nov 16 2026").is_empty());
        assert!(parse_ps_table("").is_empty());
    }

    #[test]
    fn ps_cputime_parses_seconds_minutes_and_hours() {
        assert_eq!(parse_ps_cputime("0:00.42"), Some(0.42));
        assert_eq!(parse_ps_cputime("1:02.00"), Some(62.0));
        assert_eq!(parse_ps_cputime("2:03:04.50"), Some(7384.5));
        assert_eq!(parse_ps_cputime("n/a"), None);
    }

    #[test]
    fn proc_stat_maps_state_rss_cpu_and_start_token() {
        // field 3 起：S, ppid, pgrp, session, tty, tpgid, flags, minflt, cminflt,
        // majflt, cmajflt, utime(14), stime(15), cutime, cstime, priority, nice,
        // threads, itrealvalue, starttime(22)=4242, vsize, rss(24)=7
        let stat = "1234 (wist-agentd) S 1 1234 1234 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 7 0 4242 1000000 7 18446744073709551615";
        let row = parse_proc_stat(
            1234,
            stat,
            4096,
            100.0,
            Some("/usr/local/bin/wist-agentd".into()),
        )
        .expect("row");

        assert_eq!(row.pid, 1234);
        assert_eq!(row.state, 'S');
        assert_eq!(row.cpu_seconds, 2.0);
        // 150 + 50 ticks / 100 Hz = 2.0s；starttime 原样进令牌。
        assert_eq!(row.start_token.as_deref(), Some("linux_proc_start:4242"));
        assert_eq!(row.rss_bytes, 7 * 4096);
        // 可执行名由调用方从 `/proc/<pid>/exe` 取（与 macOS `ps comm` 同口径）。
        assert_eq!(row.comm.as_deref(), Some("/usr/local/bin/wist-agentd"));
    }

    #[test]
    fn proc_stat_keeps_a_missing_executable_name_empty() {
        let stat = "1234 (x) S 1 1234 1234 0 -1 4194560 100 0 0 0 150 50 0 0 20 0 7 0 4242 1000000 7 18446744073709551615";
        let row = parse_proc_stat(1234, stat, 4096, 100.0, None).expect("row");

        // 拿不到就留空：不编造一个空串，也不拿 pid 当名字。
        assert_eq!(row.comm, None);
    }

    #[test]
    fn proc_stat_rejects_truncated_input() {
        assert_eq!(
            parse_proc_stat(1, "not-a-stat-line", 4096, 100.0, None),
            None
        );
        assert_eq!(parse_proc_stat(1, "1 (x) S 1 2 3", 4096, 100.0, None), None);
    }
}
