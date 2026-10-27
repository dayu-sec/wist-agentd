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
//!
//! 有状态导出器：内核日志（[`KERNEL_LOG_EXPORTER`]）是唯一一个**靠游标续读**的 ——
//! 它把上一次读到的游标落盘（`state/exporters/<id>.cursor`），下一轮用 `--after-cursor`
//! 接着读。游标取自 `-o json` 基本输出的 `__CURSOR` 字段（**只取这一个传输层字段**，
//! 记录 body 仍是原行，见 `linux-server-log-coverage-plan.md` D1 / W3）。
//!
//! 唯一一处**发出前改写**：journald `-o json` 会把含控制字符/非法 UTF-8 的字段编成
//! 字节数组（`"MESSAGE":[67,108,...]`），而 WPL 的 `chars@...` 只认字符串，数组会让
//! 字段整条缺失。本模块在成帧前把它们解码回字符串（见 [`normalize_exporter_line`]），
//! 其余导出器与其余字段仍原样透传。

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::io;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::Duration;

use serde::{Deserialize, Serialize};
use tokio::process::Command;
use wist_contracts::telemetry_record::TelemetryRecord;
use wist_contracts::work::KERNEL_LOG_EXPORTER;
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
    // 内核日志（W3）：唯一**有状态**的导出器（游标续读），也是唯一按 60s 周期的。
    // 周期短是因为它是「实时事故解释」（panic / OOM / IO 错误）的唯一来源，
    // 而 journald 本身是本地写入 —— 一次 `-o json` 的开销远小于其他导出器。
    ExporterDef {
        id: KERNEL_LOG_EXPORTER,
        period_secs: 60,
        timeout_secs: 30,
    },
];

/// 按 ID 找定义。
pub fn def(id: &str) -> Option<&'static ExporterDef> {
    EXPORTERS.iter().find(|d| d.id == id)
}

/// 内核日志的首读窗口（没有游标时用）。
///
/// 与周期无关：它是一份“打开机器时该往回看多少”的兜底，5 分钟足够覆盖一次
/// 重启前后的内核噪声，又不会在首跑时把整个 journal 倒出来。
pub const KERNEL_INITIAL_SINCE: &str = "-5m";

/// 内核日志导出的**固定前半段**。
///
/// 为什么不用 `--show-cursor`：它输出到哪个流、空窗口时会不会输出，随版本/输出模式变。
/// 一旦它写进 stdout，游标行就会变成一条假的内核日志；而拿不到游标会让每轮重读同一段
/// （重复上送）。`-o json` 的 `__CURSOR` 字段是稳定的，从那里取只多一次窄到单字段的读取。
///
/// `--quiet` + `--no-pager`：stdout 必须是**纯记录** —— `-- No entries --` 这类 UI 提示
/// 不能变成一条内核日志。
fn kernel_argv() -> Vec<String> {
    [
        "/usr/bin/journalctl",
        "-k",
        "-p",
        "4",
        "-o",
        "json",
        "--no-pager",
        "--quiet",
    ]
    .iter()
    .map(|part| part.to_string())
    .collect()
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
        // 首版只给「哪些盘」；逐盘 `-a` 的详情留待后续（见本模块头部的能力边界）。
        //
        // 安装位置随平台/包管理器不同：Linux 发行版在 `/usr/sbin`，macOS 的 Homebrew 在
        // `/opt/homebrew/sbin`（Apple Silicon）或 `/usr/local/sbin`（Intel）。
        // 逐个探测取**第一个可执行的**；都不在时保留第一个候选，让缺件预检如实报 missing。
        ("smartctl", _) => Ok(vec![
            first_present(&[
                "/usr/sbin/smartctl",
                "/opt/homebrew/sbin/smartctl",
                "/usr/local/sbin/smartctl",
            ]),
            "--scan-open".to_string(),
        ]),
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
        // 没有游标时的「首读 / 回退」命令：只往前看 [`KERNEL_INITIAL_SINCE`]。
        (KERNEL_LOG_EXPORTER, _) => {
            let mut argv = kernel_argv();
            argv.push("--since".to_string());
            argv.push(KERNEL_INITIAL_SINCE.to_string());
            Ok(argv)
        }
        (other, _) => Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("unknown exporter {other:?}"),
        )),
    }
}

/// 这个导出器是不是**靠游标续读**（今天只有内核日志）。
pub fn uses_cursor(id: &str) -> bool {
    id == KERNEL_LOG_EXPORTER
}

/// 真正要跑的 argv：有状态导出器带上次的游标，其余等同 [`argv_for`]。
///
/// 为什么不能把 `--after-cursor` 写死在 [`argv_for`] 里：那条是**无状态快照命令**，
/// 预检、表格测试与回退路径都用它；把外部文件内容拼进去会让“同一定义项有两种行为”。
pub fn argv_for_run(id: &str, arg: Option<&str>, cursor: Option<&str>) -> io::Result<Vec<String>> {
    match (
        uses_cursor(id),
        cursor.map(str::trim).filter(|c| is_plausible_cursor(c)),
    ) {
        (true, Some(cursor)) => {
            let mut argv = kernel_argv();
            // 两者**不能同时给**：`--since` 与 `--after-cursor` 同时出现时，
            // journalctl 从较晚的那个开始，游标就形同虚设。
            argv.push(format!("--after-cursor={cursor}"));
            Ok(argv)
        }
        _ => argv_for(id, arg),
    }
}

/// 这个串像不像一个 journalctl 游标。
///
/// 游标文件是**外部输入**（可能被手改、被截断、是上个版本留下的），进了 argv 就得先验形状：
/// 只收可见 ASCII、无空白、长度有限。格式本身由 journalctl 定（`s=…;i=…;b=…;m=…;t=…;x=…`），
/// 这里不重复实现它 —— 形状不对就当作“没有游标”，走 `--since` 而不是把垃圾交给子进程。
pub fn is_plausible_cursor(cursor: &str) -> bool {
    !cursor.is_empty()
        && cursor.len() <= 512
        && !cursor.contains(char::is_whitespace)
        && cursor.chars().all(|ch| ch.is_ascii_graphic())
}

/// 从 `-o json` 的输出里取**游标**：最后一条带 `__CURSOR` 的 JSON 对象。
///
/// 这是 D1（采集侧只搬原文）的**唯一例外**，而且是传输层字段：它只决定「下次从哪接着读」，
/// 不进记录、不改 body、不参与任何归类。
///
/// 为什么要容错（倒着找而不是只看最后一行）：journalctl 可能把 `-- No entries --` 这类 UI 提示
/// 写在最后，那不该被当成“取不到游标”而产生每轮一次的告警。
///
/// 返回 `None` 的两种情形意义不同（调用方要分开处理）：输出为空 = 窗口内没条目（正常）；
/// 有内容但一行游标都取不到 = 格式变了（告警）。
pub fn cursor_from_output(output: &str) -> Option<String> {
    output.lines().rev().find_map(|line| {
        let value: serde_json::Value = serde_json::from_str(line.trim()).ok()?;
        let cursor = value.get("__CURSOR")?.as_str()?.trim();
        is_plausible_cursor(cursor).then(|| cursor.to_string())
    })
}

/// 这次失败是不是「journalctl 认不出这个游标」。
///
/// 实测（systemd 259）：**格式合法但已不存在的游标不会报错**（静默从 journal 起点重读），
/// 只有畸形游标才退出非 0 并说 `Failed to seek to cursor`（两种写法都认）。
/// 我们自己写出去的游标都过了形状校验，所以这条主要是给「旧版本 / 异常形态」兜底；
/// 真正防「旧游标卡死」的是 [`should_reset_cursor`]。
pub fn is_cursor_error(message: &str) -> bool {
    let message = message.to_ascii_lowercase();
    message.contains("failed to seek to cursor") || message.contains("cursor not found")
}

/// 到点没到点：`last` 为空（从没跑过）或距上次已过 `period_secs`。
pub fn is_due(period_secs: u64, last_run_ms: Option<i64>, now_ms: i64) -> bool {
    match last_run_ms {
        None => true,
        Some(last) => now_ms.saturating_sub(last) >= (period_secs as i64) * 1000,
    }
}

/// stdout 是 journald `-o json` 的导出器：只有这些需要把字节数组字段解码回字符串。
///
/// 用**显式白名单**而不是 `starts_with("journalctl")`：以后真出现一个输出纯文本的
/// `journalctl-*` 导出器时，不会被误当 JSON 改写（方括号是正文的一部分）。
const JOURNALD_JSON_EXPORTERS: &[&str] = &[
    "journalctl-unit",
    "journalctl-shutdown",
    KERNEL_LOG_EXPORTER,
];

/// 这个导出器的 stdout 是不是 journald `-o json`（决定成帧前要不要解码字节数组字段）。
///
/// 判据用**归一后的 `exporter_id`**，不是目录里的原始 `target`：前者是决定 argv 的那个真值
/// （`dmesg:panic` 归一成 `dmesg`），后者只用于记录与审计展示。
pub fn emits_journald_json(exporter_id: &str) -> bool {
    JOURNALD_JSON_EXPORTERS.contains(&exporter_id)
}

/// journald `-o json` 会把**含控制字符或非法 UTF-8** 的字段序列化成「字节数组」
/// （`"MESSAGE":[67,108,...]`：彩色输出的 ESC、`\r`、二进制片段都会触发）。
/// 下游 WPL 的 `chars@MESSAGE` 只认字符串 —— 数组会让该字段整条缺失，网关侧表现为
/// `400 not a data-plane log record: missing field raw`（2026-10-26 现场 clash 日志即此）。
///
/// 所以在**发出前**把「元素全是 0..=255 的数组」按 UTF-8 解码回字符串：
///   - 调用方先用 [`emits_journald_json`] 判定（其余导出器输出纯文本，正文里的方括号
///     不能按 JSON 改写）；
///   - 非法字节**直接丢弃**（不插入 U+FFFD）：`raw` 是给检索/展示用的，替换符只会污染
///     字段值，而原始字节在 journald 里仍可查；整行丢弃才是不可接受的；
///   - ESC / CR 等控制字符**保留**（`raw` 仍是原文；JSON 序列化会转义成 `\u001b` / `\r`）；
///   - 改写过的那行会**按键名排序**重序列化（`serde_json` 未开 `preserve_order`）：
///     下游 WPL 按名取字段，无影响；`wp_event_md5` 也是确定性的，重读同一窗口仍能去重；
///   - 解析失败 / 不是对象 / 数组元素不全是字节 → 原样返回，绝不因一行坏数据打断整轮采集。
///
/// 启发式 `contains("\":[")` 依赖 journalctl 的**紧凑单行** JSON（`"KEY":[...]`，冒号后无空格）；
/// 命中不了就原样透传，不会误改。
fn normalize_journald_json_line<'a>(line: &'a str) -> Cow<'a, str> {
    if !line.contains("\":[") {
        return Cow::Borrowed(line);
    }
    let Ok(mut value) = serde_json::from_str::<serde_json::Value>(line) else {
        return Cow::Borrowed(line);
    };
    let Some(map) = value.as_object_mut() else {
        return Cow::Borrowed(line);
    };
    let mut changed = false;
    for field in map.values_mut() {
        let serde_json::Value::Array(items) = field else {
            continue;
        };
        let Some(bytes) = items
            .iter()
            .map(|item| {
                item.as_u64()
                    .filter(|byte| *byte <= u8::MAX as u64)
                    .map(|byte| byte as u8)
            })
            .collect::<Option<Vec<u8>>>()
        else {
            continue;
        };
        *field = serde_json::Value::String(decode_dropping_invalid(&bytes));
        changed = true;
    }
    if !changed {
        return Cow::Borrowed(line);
    }
    match serde_json::to_string(&value) {
        Ok(encoded) => Cow::Owned(encoded),
        Err(_) => Cow::Borrowed(line),
    }
}

/// 按 UTF-8 解码；**非法字节直接丢弃**（不插入 U+FFFD）。
///
/// 为什么丢弃而不是替换：`raw` 是给检索/展示用的，`�` 只会污染字段值；而原始字节在
/// journald 里仍可查（本模块只搬这一份副本）。尾部被截断的多字节序列也一并丢掉，
/// 不会把半个字符留在字段里。
fn decode_dropping_invalid(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    let mut rest = bytes;
    loop {
        match std::str::from_utf8(rest) {
            Ok(text) => {
                out.push_str(text);
                return out;
            }
            Err(err) => {
                let valid = err.valid_up_to();
                if let Ok(text) = std::str::from_utf8(&rest[..valid]) {
                    out.push_str(text);
                }
                match err.error_len() {
                    Some(len) => rest = &rest[valid + len..],
                    // 尾部是被截断的多字节序列：后面没有可保留的内容了。
                    None => return out,
                }
            }
        }
    }
}

/// 一次导出运行的一行输出 → 一条记录（`seq` 全局递增）。
///
/// `source_path` 用 `exporter:<target>` 明确标注「这不是一个真实文件路径」——让下游
/// 不会去 `state/logs/file_inputs/<input_id>/` 里找它。
///
/// `journald_json` 为真时，成帧前把 journald 的字节数组字段解码成字符串（见
/// [`normalize_journald_json_line`]）；调用方用 [`emits_journald_json`] 判定。
#[allow(clippy::too_many_arguments)] // 参数都是「一条记录的组成部分」，拆成结构体只会多一层包装
pub fn records_from_output(
    agent_id: &str,
    input_id: &str,
    target: &str,
    journald_json: bool,
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
        // journald 的字节数组字段在发出前解码成字符串（见 normalize_journald_json_line）；
        // 其余导出器原样透传。
        let line = if journald_json {
            normalize_journald_json_line(line)
        } else {
            Cow::Borrowed(line)
        };
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
/// 退出码非 0 / 超时 → `Err`（调用方如实上报，不静默）；`Err` 里带上 stderr，
/// 否则「游标被 vacuum 清掉」这种只能从错误文本认出来的失败会被报成“跑失败了”。
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

/// 这次失败该不该回退重跑：**只有**「本来带游标 + 错误说明游标没了」才回退。
///
/// 为什么不“失败就重试”一次：超时/权限/二进制缺失重跑一次只会让一轮 tick 的耗时翻倍，
/// 而且下一轮还会撞同一面墙；游标失效是唯一“换个参数就能恢复”的失败。
fn should_fall_back(cursor: Option<&str>, err: &io::Error) -> bool {
    cursor.is_some() && is_cursor_error(&err.to_string())
}

/// 带游标却超时：该不该把游标清掉。
///
/// 实测（systemd 259）：**格式合法但已不存在的游标不会报错**，journalctl 静默从窗口起点
/// 重读整份 journal；`--since` 又不能与 `--after-cursor` 同时给（会直接报错），
/// 所以无法给这次重读加时间上限。journal 很大时重读会超过超时，而游标留着 → 每轮都超时，
/// 该面就永久失败且只能靠人去删文件。
///
/// 用“少读一段”换“能恢复”：清掉游标，下一轮走有界的 `--since`（会记一条自观测）。
pub fn should_reset_cursor(cursor: Option<&str>, err: &io::Error) -> bool {
    cursor.is_some() && err.kind() == io::ErrorKind::TimedOut
}

/// 跑一次导出；游标被 journalctl 拒绝时**回退到无游标**再跑一次。
///
/// 返回 `(输出, 是否回退过)`。实测 systemd 259：格式合法但已不存在的游标**不报错**
/// （会静默重读整份 journal），只有畸形游标才报 `Failed to seek to cursor`。
/// 所以这条回退覆盖的是「异常形态」；「旧游标导致的无界重读」由调用方用超时 +
/// [`should_reset_cursor`] 处理（`--since` 与 `--after-cursor` 不能同时给，
/// 无法在命令行上给重读加窗口上限）。
pub async fn run_with_cursor_fallback(
    id: &str,
    arg: Option<&str>,
    cursor: Option<&str>,
    timeout_secs: u64,
) -> io::Result<(String, bool)> {
    let argv = argv_for_run(id, arg, cursor)?;
    match run_argv(&argv, timeout_secs).await {
        Ok(output) => Ok((output, false)),
        Err(err) if should_fall_back(cursor, &err) => {
            let argv = argv_for_run(id, arg, None)?;
            run_argv(&argv, timeout_secs)
                .await
                .map(|output| (output, true))
        }
        Err(err) => Err(err),
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

/// 游标文件路径：`state/exporters/<run_id>.cursor`。
///
/// 键是**运行标识**（`WorkExporterRun::input_id`，与 `last_run_ms` 同一把钥匙），不是导出器 ID：
/// 两个单元盯同一个导出器时，共享游标会让后跑的那个永远读到空窗口 ——
/// 表现是“其中一边静默没有数据”。各存各的读位置，最差是重复，不会丢。
///
/// 与 `exporters.json` 分开放：游标是**外部进程定义的格式**（journalctl 的游标串），
/// 混进 JSON 状态里会把“游标读坏了”放大成“整份调度状态读坏了”。
pub fn cursor_path(state_dir: &Path, run_id: &str) -> PathBuf {
    state_dir.join("exporters").join(format!("{run_id}.cursor"))
}

/// 读游标。文件不存在 / 内容不像游标，都算“没有”（下一轮走 `--since`）。
///
/// 不在这里判“这个导出器是否用游标”：那是 `argv_for_run` 的事，且两处各判一次就会漂。
/// 调用方只在 `uses_cursor()` 为真时读它。
pub fn load_cursor(state_dir: &Path, run_id: &str) -> Option<String> {
    let cursor = std::fs::read_to_string(cursor_path(state_dir, run_id)).ok()?;
    let cursor = cursor.trim();
    is_plausible_cursor(cursor).then(|| cursor.to_string())
}

/// 原子落盘（写临时文件 + rename）：进程在写一半时被杀，不能留下半截游标。
pub fn save_cursor(state_dir: &Path, run_id: &str, cursor: &str) -> io::Result<()> {
    let path = cursor_path(state_dir, run_id);
    if let Some(parent) = path.parent() {
        std::fs::create_dir_all(parent)?;
    }
    let tmp = path.with_extension("cursor.tmp");
    std::fs::write(&tmp, cursor.trim())?;
    std::fs::rename(&tmp, &path)
}

/// 删游标：回退重跑后仍没拿到新游标时用。
///
/// 否则下一轮又拿同一个死游标去失败一次、又回退一次 —— 每 60s 一对失败/回退事件，
/// 日志噪声会盖住真正的问题。不存在不算错。
pub fn clear_cursor(state_dir: &Path, run_id: &str) -> io::Result<()> {
    match std::fs::remove_file(cursor_path(state_dir, run_id)) {
        Ok(()) => Ok(()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err),
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

/// 候选路径里第一个**可执行**的那个；一个都没有时返回第一个（让缺件预检如实报缺失）。
fn first_present(candidates: &[&str]) -> String {
    candidates
        .iter()
        .find(|path| tool_present(path))
        .copied()
        .unwrap_or(candidates[0])
        .to_string()
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

    // ── 内核日志（W3）：游标续读 ──

    #[test]
    fn the_kernel_exporter_reads_warnings_and_above_at_a_sixty_second_period() {
        let def = def(KERNEL_LOG_EXPORTER).expect("kernel exporter is defined");
        assert_eq!(def.period_secs, 60);

        let argv = argv_for(KERNEL_LOG_EXPORTER, None).expect("argv");
        assert_eq!(argv[0], "/usr/bin/journalctl");
        // `-k` = 只看内核；`-p 4` = warning 及更严重（info 的噪声不要）。
        assert!(argv.windows(2).any(|pair| pair == ["-k", "-p"]));
        assert_eq!(argv[argv.iter().position(|a| a == "-p").unwrap() + 1], "4");
        assert!(argv.windows(2).any(|pair| pair == ["-o", "json"]));
        // 游标从 `-o json` 基础输出的 `__CURSOR` 取（不靠 `--show-cursor`）。
        assert!(!argv.iter().any(|arg| arg == "--show-cursor"));
        // stdout 必须是纯记录：UI 提示（`-- No entries --`）不能漏进来。
        assert!(argv.iter().any(|arg| arg == "--quiet"));
        assert!(argv.iter().any(|arg| arg == "--no-pager"));
    }

    #[test]
    fn a_known_cursor_becomes_after_cursor_and_drops_the_time_window() {
        let resumed = argv_for_run(KERNEL_LOG_EXPORTER, None, Some("s=abc;i=9;b=1")).expect("argv");
        assert!(
            resumed
                .iter()
                .any(|arg| arg == "--after-cursor=s=abc;i=9;b=1"),
            "{resumed:?}"
        );
        // 两者同时给时 journalctl 从**较晚**的那个开始，游标就形同虚设。
        assert!(!resumed.iter().any(|arg| arg == "--since"), "{resumed:?}");
        // 内核过滤条件不能因为续读就丢掉。
        assert!(resumed.iter().any(|arg| arg == "-k"));
        assert!(resumed.windows(2).any(|pair| pair == ["-p", "4"]));
    }

    #[test]
    fn no_cursor_falls_back_to_a_five_minute_window() {
        let argv = argv_for_run(KERNEL_LOG_EXPORTER, None, None).expect("argv");
        assert!(
            argv.windows(2)
                .any(|pair| pair == ["--since", KERNEL_INITIAL_SINCE]),
            "{argv:?}"
        );
        assert_eq!(KERNEL_INITIAL_SINCE, "-5m");
        assert!(!argv.iter().any(|arg| arg.starts_with("--after-cursor")));
    }

    #[test]
    fn a_corrupt_cursor_file_is_treated_as_no_cursor() {
        // 游标文件是外部输入：带空白/换行/控制字符的一律不往 argv 里放。
        for bad in ["", "   ", "s=abc i=9", "s=abc\n--no-pager", "s=abc\u{7}"] {
            assert!(!is_plausible_cursor(bad), "{bad:?} 不该被当成游标");
            let argv = argv_for_run(KERNEL_LOG_EXPORTER, None, Some(bad)).expect("argv");
            assert!(
                !argv.iter().any(|arg| arg.starts_with("--after-cursor")),
                "{bad:?} 进了 argv: {argv:?}"
            );
            assert!(
                argv.windows(2)
                    .any(|pair| pair == ["--since", KERNEL_INITIAL_SINCE])
            );
        }
        // 正常形状（journalctl 的 `s=…;i=…;b=…`）要认。
        assert!(is_plausible_cursor("s=8f2a;i=1b3;b=9c;m=1;t=6;x=7"));
        // 过长的不收：游标不是“可以随便长”的字段，超过这个长度基本就是文件坏了。
        assert!(!is_plausible_cursor(&"s=1;".repeat(200)));
    }

    #[test]
    fn only_the_kernel_exporter_takes_a_cursor() {
        assert!(uses_cursor(KERNEL_LOG_EXPORTER));
        assert!(!uses_cursor("dmesg"));
        // 无状态导出器即使被塞了游标，argv 也不会变（否则 `dmesg --after-cursor=…` 会直接报错）。
        assert_eq!(
            argv_for_run("dmesg", Some("panic"), Some("s=1")).expect("argv"),
            argv_for("dmesg", Some("panic")).expect("argv")
        );
    }

    #[test]
    fn the_cursor_comes_from_the_json_lines_not_from_a_banner() {
        // `-o json` 每条日志一行；游标就在最后一行的 `__CURSOR`。
        let output = concat!(
            r#"{"__CURSOR":"s=aaa;i=1;b=1","MESSAGE":"first","PRIORITY":"3"}"#,
            "\n",
            r#"{"__CURSOR":"s=bbb;i=2;b=1","MESSAGE":"second","PRIORITY":"4"}"#,
            "\n",
        );
        assert_eq!(cursor_from_output(output).as_deref(), Some("s=bbb;i=2;b=1"));

        // 末尾多一条 UI 提示不该把游标遮住（也不该被当成“取不到”）。
        assert_eq!(
            cursor_from_output(&format!("{output}-- No entries --\n")).as_deref(),
            Some("s=bbb;i=2;b=1")
        );

        // 窗口里没条目：没有游标，但这是**正常**的（调用方保持沉默）。
        assert_eq!(cursor_from_output(""), None);
        assert_eq!(cursor_from_output("\n\n"), None);

        // 有内容但一行都取不到 = 格式变了（调用方要告警）。
        assert_eq!(cursor_from_output("not json\n"), None);
        assert_eq!(cursor_from_output(r#"{"MESSAGE":"no cursor field"}"#), None);
        // 游标形状不对也不认（不能把垃圾交给子进程）。
        assert_eq!(cursor_from_output(r#"{"__CURSOR":"not a cursor"}"#), None);
    }

    #[test]
    fn a_vacuumed_cursor_is_recognized_so_the_run_can_fall_back() {
        // 游标被 vacuum 清掉时 journalctl 的措辞随版本略有出入，两种都要认。
        assert!(is_cursor_error(
            "exporter exited with exit status: 1: Failed to seek to cursor: Invalid argument"
        ));
        assert!(is_cursor_error("Cursor not found"));
        // 其它失败不能误判成“游标没了”（否则会白重跑一次、把真正的原因刷掉）。
        assert!(!is_cursor_error(
            "exporter exited with exit status: 1: No such file or directory"
        ));
        assert!(!is_cursor_error("exporter timed out after 30s"));
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
            false,
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

    #[test]
    fn a_json_line_becomes_exactly_one_record_and_yields_the_cursor() {
        // 输出形状取自**真机**（Ubuntu 26.04 / systemd 259，`-k -p 4 -o json`）的字段集，
        // 只把 MESSAGE 换成 OOM / IO 错误。内核导出器的输出：一行一条记录，body 原样；
        // 同一份输出能取出游标（仅此一个字段）。
        let output = concat!(
            r#"{"_TRANSPORT":"kernel","__CURSOR":"s=a0eb73fc6e164bd9bbb9b97c8abfa77c;i=a8f3;b=3c5bc0d5d86848348f18d525c917a112;m=290dc93b00;t=65e79f9d2c000;x=1111","PRIORITY":"3","_HOSTNAME":"gw-01","SYSLOG_FACILITY":"1","MESSAGE":"Out of memory: Killed process 42"}"#,
            "\n",
            r#"{"_TRANSPORT":"kernel","__CURSOR":"s=a0eb73fc6e164bd9bbb9b97c8abfa77c;i=a8f4;b=3c5bc0d5d86848348f18d525c917a112;m=290dc93bed;t=65e79f9d2cad0;x=9791448d01876c03","PRIORITY":"3","_HOSTNAME":"gw-01","SYSLOG_FACILITY":"1","MESSAGE":"EXT4-fs (sda1): error"}"#,
            "\n",
        );
        let mut seq = 0;
        let records = records_from_output(
            "agent-a",
            "work-KernelSystem-linux-kernel-system-exporter",
            KERNEL_LOG_EXPORTER,
            true,
            "KernelSystem",
            "linux-kernel-system",
            output,
            &mut seq,
        );
        assert_eq!(records.len(), 2);
        assert_eq!(records[0].source_path, "exporter:journalctl-kernel");
        // body 是整行 JSON，没有被“解析成字段”后重写。
        assert!(records[0].body.starts_with("{\"_TRANSPORT\""));
        assert!(records[0].body.contains("Killed process 42"));
        assert_eq!(
            cursor_from_output(output).as_deref(),
            Some(
                "s=a0eb73fc6e164bd9bbb9b97c8abfa77c;i=a8f4;b=3c5bc0d5d86848348f18d525c917a112;m=290dc93bed;t=65e79f9d2cad0;x=9791448d01876c03"
            )
        );
    }

    #[test]
    fn journald_byte_array_fields_are_decoded_before_uplink() {
        // journald 把含 ESC 的 MESSAGE 编成字节数组；不转成字符串的话，
        // WPL 的 `chars@MESSAGE` 取不到值 → 网关 400 `missing field raw`。
        let line = r#"{"_COMM":"start.sh","_SYSTEMD_UNIT":"clash.service","MESSAGE":[67,108,97,115,104,232,174,162,233,152,133,229,156,176,229,157,128,228,184,141,229,143,175,232,174,191,233,151,174,239,188,129,32,27,91,51,49,109,82,69,68,27,91,48,109],"PRIORITY":"6"}"#;
        let normalized = normalize_journald_json_line(line);
        let value: serde_json::Value = serde_json::from_str(&normalized).expect("json");
        let message = value["MESSAGE"].as_str().expect("MESSAGE 应被解码成字符串");
        assert_eq!(message, "Clash订阅地址不可访问！ \u{1b}[31mRED\u{1b}[0m");
        // 其它字段保持原样
        assert_eq!(value["_COMM"].as_str(), Some("start.sh"));
        assert_eq!(value["PRIORITY"].as_str(), Some("6"));
    }

    #[test]
    fn only_journald_json_exporters_opt_into_the_rewrite() {
        assert!(emits_journald_json("journalctl-unit"));
        assert!(emits_journald_json("journalctl-shutdown"));
        assert!(emits_journald_json(KERNEL_LOG_EXPORTER));
        // 纯文本导出器（nft 规则里就有方括号）不能按 JSON 改写。
        assert!(!emits_journald_json("nft-ruleset"));
        assert!(!emits_journald_json("dmesg"));
        // 未来若出现输出纯文本的 journalctl-* 导出器，也不能被白名单误收。
        assert!(!emits_journald_json("journalctl-foo"));
    }

    #[test]
    fn json_rewriting_leaves_non_byte_arrays_and_bad_lines_alone() {
        // 真正的字符串数组（不是字节数组）不能改。
        assert!(matches!(
            normalize_journald_json_line(r#"{"tags":["a","b"]}"#),
            Cow::Borrowed(_)
        ));
        // 坏行原样发，不打断整轮采集。
        assert!(matches!(
            normalize_journald_json_line("not json"),
            Cow::Borrowed(_)
        ));
        // 没有数组时走快路径。
        assert!(matches!(
            normalize_journald_json_line(r#"{"MESSAGE":"ok"}"#),
            Cow::Borrowed(_)
        ));
    }

    #[test]
    fn empty_and_undecodable_byte_arrays_stay_as_strings() {
        // 空数组 → 空字符串（这类 journald 条目本来就没有正文；字段仍在）。
        let empty = normalize_journald_json_line(r#"{"MESSAGE":[]}"#);
        let value: serde_json::Value = serde_json::from_str(&empty).expect("json");
        assert_eq!(value["MESSAGE"].as_str(), Some(""));
    }

    #[test]
    fn invalid_utf8_bytes_are_dropped_not_replaced() {
        // 非法字节直接丢弃（不插入 U+FFFD）：raw 是给检索/展示用的，替换符只会污染字段值。
        let lossy = normalize_journald_json_line(r#"{"MESSAGE":[65,255,66]}"#);
        let value: serde_json::Value = serde_json::from_str(&lossy).expect("json");
        assert_eq!(value["MESSAGE"].as_str(), Some("AB"));
        // 尾部被截断的多字节序列也整段丢弃，不留半个字符。
        assert_eq!(decode_dropping_invalid(&[65, 0xe4, 0xb8]), "A");
        // 合法 UTF-8（中文 + ESC）原样保留。
        assert_eq!(
            decode_dropping_invalid("中文\u{1b}[0m".as_bytes()),
            "中文\u{1b}[0m"
        );
    }

    #[test]
    fn exported_journald_records_carry_decoded_message() {
        let line = r#"{"MESSAGE":[65,66,67]}"#;
        let mut seq = 0;
        let records = records_from_output(
            "agent-a",
            "work-ServiceLifecycle-linux-service-lifecycle",
            "journalctl-unit",
            true,
            "ServiceLifecycle",
            "linux-service-lifecycle",
            line,
            &mut seq,
        );
        assert_eq!(records.len(), 1);
        let value: serde_json::Value = serde_json::from_str(&records[0].body).expect("json");
        assert_eq!(value["MESSAGE"].as_str(), Some("ABC"));
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
    fn the_cursor_round_trips_and_survives_a_missing_file() {
        // 用一个还不存在的 state 目录：`state/exporters/` 要能自己建出来。
        let dir = std::env::temp_dir().join(format!("wist-cursor-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("mkdir");
        let run = "work-KernelSystem-linux-kernel-system-exporter";

        // 没写过游标 → None（不是报错：首跑就该走 `--since`）。
        assert_eq!(load_cursor(&dir, run), None);

        save_cursor(&dir, run, "s=8f2a;i=1b3").expect("save");
        assert_eq!(load_cursor(&dir, run).as_deref(), Some("s=8f2a;i=1b3"));
        // 原子替换：不留下临时文件。
        let tmp = cursor_path(&dir, run).with_extension("cursor.tmp");
        assert!(!tmp.exists(), "临时文件应已 rename 掉");

        // 写坏了（外面被手改）→ 当作没有游标，而不是把垃圾交给子进程。
        std::fs::write(cursor_path(&dir, run), "not a cursor\n").expect("write");
        assert_eq!(load_cursor(&dir, run), None);

        // 内容前后的换行不算内容（很多工具会补一个 \n）。
        save_cursor(&dir, run, "  s=1  ").expect("save");
        assert_eq!(load_cursor(&dir, run).as_deref(), Some("s=1"));

        // 读位置属于**这次运行**：另一个单元盯同一个导出器时不能拿同一个游标
        // （共享会让后跑的那个永远读到空窗口）。
        let other = "work-KernelSystem-linux-kernel-audit-exporter";
        assert_eq!(load_cursor(&dir, other), None);
        save_cursor(&dir, other, "s=9").expect("save other");
        assert_eq!(load_cursor(&dir, run).as_deref(), Some("s=1"));
        assert_eq!(load_cursor(&dir, other).as_deref(), Some("s=9"));

        // 清理幂等：回退后没拿到新游标时会被调两次。
        clear_cursor(&dir, run).expect("clear");
        clear_cursor(&dir, run).expect("clear twice");
        assert_eq!(load_cursor(&dir, run), None);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn only_a_dead_cursor_is_worth_a_second_run() {
        let cursor_error = io::Error::other(
            "exporter exited with exit status: 1: Failed to seek to cursor: Invalid argument",
        );
        let timeout = io::Error::new(io::ErrorKind::TimedOut, "exporter timed out after 30s");
        assert!(should_fall_back(Some("s=1"), &cursor_error));
        // 超时重跑一次只会把一轮 tick 的耗时翻倍，而且下一轮还是同一面墙。
        assert!(!should_fall_back(Some("s=1"), &timeout));
        // 本来就没有游标：
        assert!(!should_fall_back(None, &cursor_error));

        // 反过来：超时带游标 → 该清游标（否则每轮都撞同一个无界重读）。
        assert!(should_reset_cursor(Some("s=1"), &timeout));
        assert!(!should_reset_cursor(None, &timeout));
        assert!(!should_reset_cursor(Some("s=1"), &cursor_error));
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

    #[test]
    fn smartctl_is_resolved_across_linux_and_homebrew_locations() {
        // 不能把路径写死：Linux 在 `/usr/sbin`，macOS 的 Homebrew 在 `/opt/homebrew/sbin`。
        // 这里是纯逻辑层面的断言（本机是否存在 smartctl 不影响结论）。
        let argv = argv_for("smartctl", None).expect("已知导出器");
        assert_eq!(argv[1], "--scan-open");
        let candidates = [
            "/usr/sbin/smartctl",
            "/opt/homebrew/sbin/smartctl",
            "/usr/local/sbin/smartctl",
        ];
        assert!(
            candidates.contains(&argv[0].as_str()),
            "可选位置之一：{}",
            argv[0]
        );
        // 取到的那个一定存在，除非三个都没装（那种情况保留第一个，由缺件预检报缺失）。
        if candidates.iter().any(|path| tool_present(path)) {
            assert!(tool_present(&argv[0]), "应当选到可执行的那个：{}", argv[0]);
        }
    }
}
