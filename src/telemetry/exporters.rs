//! 定时导出器（`Exporter` 采集来源）的定义、执行与调度。
//!
//! 设计见 `docs/design/log-source-exporters.md`。要点：
//!   * `target` 是**已知导出器 ID**（契约 [`wist_contracts::work::EXPORTER_IDS`]），可带 `:arg`；
//!   * 每个 ID 一条**固定 argv**（无 shell、无字符串拼接），本模块负责起子进程；
//!   * 输出按行变成 [`TelemetryRecord`]，`source_path` 记 `exporter:<target>`；
//!   * 周期是**导出器属性**（首版不来自目录），到点才跑；上次运行时刻落 `state/exporters.json`。
//!
//! 能力边界（诚实写清）：单个导出器只跑**一条**固定命令，多盘/多单元那类需要「先枚举再逐项」
//! 的导出器（如 `smartctl` 逐盘 `-a`）首版只做**能一条命令给出的那部分**，其余留待后续。

use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::time::{now_rfc3339, now_ts_ms};

/// 一个导出器的静态定义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExporterDef {
    pub id: &'static str,
    /// 默认周期（秒）。周期是**导出器属性**，首版不来自目录（见设计稿 §9.2）。
    pub period_secs: u64,
    /// 单次导出超时（秒）：导出器跑飞了不能拖住一轮 tick。
    pub timeout_secs: u64,
}

/// 已实现的导出器。**必须**与契约 [`wist_contracts::work::EXPORTER_IDS`] 一一对应
/// （见 `exporter_table_matches_the_contract_vocabulary`，两边漂了当场红）。
pub const EXPORTERS: &[ExporterDef] = &[
    ExporterDef {
        id: "journalctl-unit",
        period_secs: 300,
        timeout_secs: 30,
    },
    ExporterDef {
        id: "journalctl-shutdown",
        period_secs: 3600,
        timeout_secs: 30,
    },
    ExporterDef {
        id: "last-reboot",
        period_secs: 6 * 3600,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "nft-ruleset",
        period_secs: 1800,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "iptables-save",
        period_secs: 1800,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "smartctl",
        period_secs: 3600,
        timeout_secs: 30,
    },
    ExporterDef {
        id: "dmesg",
        period_secs: 300,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "auditd-execve",
        period_secs: 300,
        timeout_secs: 30,
    },
];

/// 按 ID 找定义。
pub fn def(id: &str) -> Option<&'static ExporterDef> {
    EXPORTERS.iter().find(|d| d.id == id)
}

/// 一个导出器 ID + `arg` 对应的**固定 argv**（绝对路径、无 shell）。
///
/// 这里是唯一的「怎么跑」出口：除 `arg` 外没有任何外部字符串进 argv，而 `arg` 只做**窄解析**
/// （每个 ID 只认自己那几个取值），拼不进额外参数。
///
/// 注意：这里的二进制路径与开关是**按通用发行版**写的，未在目标机核对过
/// （见 `linux-security-audit-log-sources.md` §10）；路径不存在会走失败上报，不会静默。
pub fn argv_for(id: &str, arg: Option<&str>) -> io::Result<Vec<String>> {
    fn v(parts: &[&str]) -> Vec<String> {
        parts.iter().map(|s| s.to_string()).collect()
    }
    match (id, arg) {
        ("journalctl-unit", _) => Ok(v(&["/usr/bin/journalctl", "-o", "json", "--since", "-5m"])),
        ("journalctl-shutdown", _) => Ok(v(&[
            "/usr/bin/journalctl",
            "-o",
            "json",
            "--since",
            "-1d",
            "-u",
            "systemd-shutdown",
            "-u",
            "systemd-logind",
        ])),
        ("last-reboot", _) => Ok(v(&["/usr/bin/last", "-x", "reboot", "shutdown"])),
        ("nft-ruleset", _) => Ok(v(&["/usr/sbin/nft", "list", "ruleset"])),
        ("iptables-save", _) => Ok(v(&["/usr/sbin/iptables-save"])),
        // 首版只给「有哪些盘」；逐盘 `-a` 的详情留待后续（见本模块头部的能力边界）。
        ("smartctl", _) => Ok(v(&["/usr/sbin/smartctl", "--scan-open"])),
        ("dmesg", None) => Ok(v(&["/usr/bin/dmesg"])),
        ("dmesg", Some("panic")) => Ok(v(&["/usr/bin/dmesg", "--level", "emerg,alert,crit"])),
        ("dmesg", Some("nvidia-xid")) => Ok(v(&["/usr/bin/dmesg"])),
        ("auditd-execve", _) => Ok(v(&[
            "/usr/sbin/ausearch",
            "-m",
            "execve",
            "--start",
            "recent",
        ])),
        (other, _) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown exporter {other:?}"),
        )),
    }
}

/// 到点没到点：`last` 为空（从没跑过）或距上次已过 `period_secs`。
pub fn is_due(period_secs: u64, last_run_ms: Option<i64>, now_ms: i64) -> bool {
    match last_run_ms {
        None => true,
        Some(last) => now_ms.saturating_sub(last) >= (period_secs as i64) * 1000,
    }
}

/// 一次导出运行的一行输出 → 一条记录（`seq` 全局递增）。
///
/// `source_path` 用 `exporter:<target>` 明确标注「这不是一个真实文件路径」——让下游
/// 不会去 `state/logs/file_inputs/<input_id>/` 里找它。
pub fn records_from_output(
    agent_id: &str,
    input_id: &str,
    target: &str,
    family: &str,
    unit: &str,
    output: &str,
    next_seq: &mut u64,
) -> Vec<TelemetryRecord> {
    let observed_at = now_rfc3339();
    let source_path = format!("exporter:{target}");
    let mut records = Vec::new();
    let mut offset = 0u64;
    for line in output.lines() {
        let seq = *next_seq;
        *next_seq += 1;
        let body_len = line.len() as u64;
        records.push(
            TelemetryRecord::new_log(
                agent_id.to_string(),
                observed_at.clone(),
                input_id.to_string(),
                source_path.clone(),
                line.to_string(),
                offset,
                offset + body_len,
                seq,
            )
            .with_origin(family.to_string(), unit.to_string()),
        );
        offset += body_len + 1;
    }
    records
}

/// 跑一条固定 argv 并把 stdout 收回来（**无 shell**）。
///
/// 退出码非 0 / 超时 → `Err`（调用方如实上报，不静默）。
pub async fn run_argv(argv: &[String], timeout_secs: u64) -> io::Result<String> {
    let (bin, args) = argv
        .split_first()
        .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "empty argv"))?;
    let child = Command::new(bin)
        .args(args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    match tokio::time::timeout(Duration::from_secs(timeout_secs), child.wait_with_output()).await {
        Ok(Ok(out)) if out.status.success() => {
            Ok(String::from_utf8_lossy(&out.stdout).into_owned())
        }
        Ok(Ok(out)) => Err(io::Error::other(format!(
            "exporter exited with {}: {}",
            out.status,
            String::from_utf8_lossy(&out.stderr).trim()
        ))),
        Ok(Err(err)) => Err(err),
        Err(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            format!("exporter timed out after {timeout_secs}s"),
        )),
    }
}

/// agentd 对导出器的本地状态（跨 restart 保留）：上次跑的时刻 + **缺的工具**。
///
/// 「缺的工具」记在这里（`id -> 二进制路径`），供 `diagnose` 展示 —— 缺件不是靠 `spawn` 报错
/// 得知的，而是**跑前预检**得出的，并在恢复时自动清掉。
#[derive(Debug, Default, Serialize, Deserialize)]
pub struct ExporterState {
    #[serde(default)]
    pub last_run_ms: BTreeMap<String, i64>,
    #[serde(default)]
    pub missing: BTreeMap<String, String>,
}

fn state_path(state_dir: &Path) -> PathBuf {
    state_dir.join("exporters.json")
}

/// 读状态；文件不存在 / 坏了都当空（最多重跑一次快照，不致命）。
pub fn load_state(state_dir: &Path) -> ExporterState {
    std::fs::read(state_path(state_dir))
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ExporterState>(&bytes).ok())
        .unwrap_or_default()
}

/// 写状态（原子替换，避免半份文件）。
pub fn save_state(state_dir: &Path, state: &ExporterState) {
    let Ok(bytes) = serde_json::to_vec_pretty(state) else {
        return;
    };
    let path = state_path(state_dir);
    let tmp = path.with_extension("json.tmp");
    if std::fs::write(&tmp, bytes).is_ok() {
        let _ = std::fs::rename(&tmp, &path);
    }
}

/// 工具在不在：**跑前就判**（不是 `spawn` 报错），且要**可执行**而不只是存在。
///
/// 为什么要预检：缺件是**部署缺口**（如忘装 `smartmontools`），拿「进程启动失败」去表达
/// 既难归因又不能区别「没装」与「跑了但退出非 0」。预检只碰文件系统，不进子进程。
pub fn tool_present(tool: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(tool)
        .map(|meta| meta.is_file() && meta.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

/// argv 里的二进制路径（argv[0]）。
pub fn tool_path(argv: &[String]) -> Option<&str> {
    argv.first().map(String::as_str)
}

/// 当前时刻（毫秒），供调度用。
pub fn now_ms() -> i64 {
    now_ts_ms()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeSet;
    use wist_contracts::work::EXPORTER_IDS;

    #[test]
    fn exporter_table_matches_the_contract_vocabulary() {
        // 契约里承诺「可执行」的 ID，agentd 必须都实现；反过来 agentd 也不许实现契约没收录的 ID
        // —— 两侧漂了，就会出现「网关说可采、agent 拿到后报 unsupported」的矛盾。
        let implemented: BTreeSet<&str> = EXPORTERS.iter().map(|def| def.id).collect();
        let declared: BTreeSet<&str> = EXPORTER_IDS.iter().copied().collect();
        assert_eq!(implemented, declared);
    }

    #[test]
    fn every_exporter_has_a_command_and_a_sane_period() {
        for def in EXPORTERS {
            let argv = argv_for(def.id, None).expect("argv");
            assert!(
                argv[0].starts_with('/'),
                "{}: 二进制要用绝对路径（无 shell / 无 PATH 依赖）",
                def.id
            );
            assert!(
                def.period_secs > 0 && def.timeout_secs > 0,
                "{}: 周期",
                def.id
            );
        }
    }

    #[test]
    fn dmesg_arguments_are_a_narrow_closed_set() {
        assert!(argv_for("dmesg", Some("panic")).is_ok());
        assert!(argv_for("dmesg", Some("nvidia-xid")).is_ok());
        // 不认识的东西不会进 argv。
        assert!(argv_for("dmesg", Some("--help")).is_err());
        assert!(argv_for("nope", None).is_err());
    }

    #[test]
    fn due_logic_is_period_based() {
        assert!(is_due(300, None, 1_000_000));
        assert!(!is_due(300, Some(1_000_000), 1_000_000 + 299_000));
        assert!(is_due(300, Some(1_000_000), 1_000_000 + 300_000));
        // 时钟回拨不 panic。
        assert!(!is_due(300, Some(2_000_000), 1_000_000));
    }

    #[test]
    fn output_becomes_one_record_per_line_with_origin_and_source() {
        let mut seq = 7;
        let records = records_from_output(
            "agent-a",
            "work-NetworkFirewall-nft-ruleset",
            "nft-ruleset",
            "NetworkFirewall",
            "linux-network-firewall",
            "table inet filter {\n\tchain input {\n}\n",
            &mut seq,
        );
        assert_eq!(records.len(), 3);
        assert_eq!(records[0].source_path, "exporter:nft-ruleset");
        assert_eq!(records[0].family, "NetworkFirewall");
        assert_eq!(records[0].unit, "linux-network-firewall");
        assert_eq!(records[0].input_id, "work-NetworkFirewall-nft-ruleset");
        // 序号是全局递增的，不是从 0 从头。
        assert_eq!(records[0].seq, 7);
        assert_eq!(records[2].seq, 9);
        assert_eq!(seq, 10);
    }

    #[tokio::test]
    async fn running_a_fixed_command_captures_stdout() {
        // 用 `/bin/echo` 做等价命令：跑得通、收得到 stdout。真实导出器命令需要真机核对。
        let out = run_argv(&["/bin/echo".to_string(), "hello".to_string()], 5)
            .await
            .expect("run");
        assert_eq!(out.trim(), "hello");
    }

    #[tokio::test]
    async fn a_nonzero_exit_is_an_error_not_a_silent_success() {
        let err = run_argv(
            &[
                "/bin/sh".to_string(),
                "-c".to_string(),
                "exit 3".to_string(),
            ],
            5,
        )
        .await
        .expect_err("must fail");
        assert!(err.to_string().contains("exited with"), "{err}");
    }

    #[test]
    fn state_round_trips_missing_file_and_records_missing_tools() {
        let dir = std::env::temp_dir().join(format!("wist-exporters-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("mkdir");
        // 文件不存在 → 空状态（而不是报错）。
        let empty = load_state(&dir);
        assert!(empty.last_run_ms.is_empty() && empty.missing.is_empty());

        let mut state = ExporterState::default();
        state.last_run_ms.insert("work-1".to_string(), 12345i64);
        state
            .missing
            .insert("smartctl".to_string(), "/usr/sbin/smartctl".to_string());
        save_state(&dir, &state);
        let loaded = load_state(&dir);
        assert_eq!(loaded.last_run_ms, state.last_run_ms);
        assert_eq!(loaded.missing, state.missing);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn tool_presence_preflight_distinguishes_missing_from_present() {
        // 跑前预检：存在的可执行文件为真，不存在的为假。
        assert!(tool_present("/bin/sh"));
        assert!(!tool_present("/usr/sbin/wist-does-not-exist"));
        assert_eq!(
            tool_path(&["/usr/sbin/smartctl".to_string(), "--scan-open".to_string()]),
            Some("/usr/sbin/smartctl")
        );
    }
}
