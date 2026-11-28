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
use std::sync::RwLock;
use tokio::process::Command;
use wist_contracts::telemetry_record::TelemetryRecord;
use wist_contracts::work::KERNEL_LOG_EXPORTER;
use wist_shared::time::{now_rfc3339, now_ts_ms};

/// 平台下发的搜索目录（`None` = 用内置 [`BIN_DIRS`]）。
static POLICY_DIRS: RwLock<Option<Vec<String>>> = RwLock::new(None);

/// 一条周期 / 超时覆盖：`(exporter_id, period_secs, timeout_secs)`。
pub(crate) type LimitOverride = (String, Option<u64>, Option<u64>);

/// 平台下发的周期 / 超时覆盖。
static POLICY_LIMITS: RwLock<Option<Vec<LimitOverride>>> = RwLock::new(None);

/// 一个导出器的静态定义。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ExporterDef {
    pub id: &'static str,
    /// **可执行文件名**：决定“跑什么”的唯一处所。
    ///
    /// 路径不在这里 —— 而是拿这个名字去 [`BIN_DIRS`]（或平台下发的目录表）里找。
    /// 把绝对路径写死在这里，每遇到一个新发行版/容器镜像就要发一版 agentd；
    /// 而安装位置是**纯环境信息**，不属于“跑什么”。
    pub bin: &'static str,
    /// 默认周期（秒）。周期是**导出器属性**，目录可在策略里覆盖（见 `exporter_policy`）。
    pub period_secs: u64,
    /// 单次导出超时（秒）：导出器跑飞了不能拖住一轮 tick。
    pub timeout_secs: u64,
}

/// 已实现的导出器。**必须**与契约 [`wist_contracts::work::EXPORTER_IDS`] 一一对应
/// （见 `exporter_table_matches_the_contract_vocabulary`，两边漂了当场红）。
pub const EXPORTERS: &[ExporterDef] = &[
    ExporterDef {
        id: "journalctl-unit",
        bin: "journalctl",
        period_secs: 300,
        timeout_secs: 30,
    },
    ExporterDef {
        id: "journalctl-shutdown",
        bin: "journalctl",
        period_secs: 3600,
        timeout_secs: 30,
    },
    ExporterDef {
        id: "last-reboot",
        bin: "last",
        period_secs: 6 * 3600,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "nft-ruleset",
        bin: "nft",
        period_secs: 1800,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "iptables-save",
        bin: "iptables-save",
        period_secs: 1800,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "smartctl",
        bin: "smartctl",
        period_secs: 3600,
        timeout_secs: 30,
    },
    ExporterDef {
        id: "dmesg",
        bin: "dmesg",
        period_secs: 300,
        timeout_secs: 15,
    },
    ExporterDef {
        id: "auditd-execve",
        bin: "ausearch",
        period_secs: 300,
        timeout_secs: 30,
    },
    // 内核日志（W3）：唯一**有状态**的导出器（游标续读），也是唯一按 60s 周期的。
    // 周期短是因为它是「实时事故解释」（panic / OOM / IO 错误）的唯一来源，
    // 而 journald 本身是本地写入 —— 一次 `-o json` 的开销远小于其他导出器。
    ExporterDef {
        id: KERNEL_LOG_EXPORTER,
        bin: "journalctl",
        period_secs: 60,
        timeout_secs: 30,
    },
];

/// 按 ID 找定义。
pub fn def(id: &str) -> Option<&'static ExporterDef> {
    EXPORTERS.iter().find(|d| d.id == id)
}

/// 导出器二进制的**搜索目录**（按优先级，平台内建默认值）。
///
/// 为什么不写绝对文件路径：安装位置是**纯环境信息**，而本仓每遇到一个新发行版 /
/// 容器基础镜像 / 自建前缀就要发一版 agentd，成本远大于换一版知识库。
/// 这里只留“可能装在哪几个目录”，文件名由 [`ExporterDef::bin`] 决定 ——
/// 数据能改“去哪找”，不能改“跑什么”。
///
/// 平台下发的目录表（`exporter_policy`）会盖过这份默认值。
#[cfg(target_os = "macos")]
pub const BIN_DIRS: &[&str] = &[
    "/usr/bin",
    "/bin",
    "/usr/sbin",
    "/sbin",
    // Homebrew（Apple Silicon / Intel 两种前缀）。
    "/opt/homebrew/bin",
    "/usr/local/bin",
    "/opt/homebrew/sbin",
    "/usr/local/sbin",
];

#[cfg(not(target_os = "macos"))]
pub const BIN_DIRS: &[&str] = &[
    "/usr/bin",
    // 非 usrmerge 的发行版、busybox 与最小容器镜像里，工具常常**只在** `/bin`。
    "/bin",
    "/usr/sbin",
    "/sbin",
    "/usr/local/bin",
    "/usr/local/sbin",
];

/// 当前生效的搜索目录（默认 = [`BIN_DIRS`]；平台下发策略后由 [`apply_policy`] 覆盖）。
///
/// **空目录列表按内置表算**：数据写了一张空表或下发了一份空列表时，解析不能退化成
/// “一个目录都不搜”（那会让所有导出器同时报缺件）。与 `None` 同义。
pub fn effective_bin_dirs() -> Vec<String> {
    POLICY_DIRS
        .read()
        .ok()
        .and_then(|guard| guard.clone())
        .filter(|dirs| !dirs.is_empty())
        .unwrap_or_else(|| BIN_DIRS.iter().map(|dir| (*dir).to_string()).collect())
}

/// 应用平台下发的策略（`dirs = None` = 用内置表）。
///
/// 调用方是主循环（`control::exporter_policy` 拉取成功后）；这里只存值，不做 I/O。
pub fn apply_policy(dirs: Option<Vec<String>>, overrides: Vec<LimitOverride>) {
    if let Ok(mut guard) = POLICY_DIRS.write() {
        *guard = dirs;
    }
    if let Ok(mut guard) = POLICY_LIMITS.write() {
        *guard = Some(overrides);
    }
}

/// 导出器的生效周期（策略覆盖 > 内置值）。
pub fn effective_period_secs(def: &ExporterDef) -> u64 {
    current_limits()
        .and_then(|rows| override_for(&rows, def.id))
        .and_then(|(period, _)| period)
        .unwrap_or(def.period_secs)
}

/// 导出器的生效超时（策略覆盖 > 内置值）。
pub fn effective_timeout_secs(def: &ExporterDef) -> u64 {
    current_limits()
        .and_then(|rows| override_for(&rows, def.id))
        .and_then(|(_, timeout)| timeout)
        .unwrap_or(def.timeout_secs)
}

fn current_limits() -> Option<Vec<LimitOverride>> {
    POLICY_LIMITS.read().ok().and_then(|guard| guard.clone())
}

/// 从覆盖表里取某个 ID 的 `(period, timeout)`。
///
/// 抽成纯函数是为了能被直接单测：全局策略在各个测试间是共享的，拿它做断言的用例
/// 会互相干扰（并行跑）。
fn override_for(rows: &[LimitOverride], id: &str) -> Option<(Option<u64>, Option<u64>)> {
    rows.iter()
        .find(|(row_id, _, _)| row_id == id)
        .map(|(_, period, timeout)| (*period, *timeout))
}

/// 在候选目录里找**同名**可执行文件；都没有时返回最标准的位置。
///
/// 返回“最标准的位置”而不是空串：缺件预检与日志要报的路径，应当就是“本来想执行的那个”。
///
/// 组/世界可写的候选会被**跳过**（先找安全的），全都不安全但存在时仍用它并告警 ——
/// root 守护进程执行一个任人可写的二进制就是本地提权，但它也不该让采集静默停摆。
fn resolve_in_dirs(bin: &str, dirs: &[String]) -> String {
    let mut writable_fallback: Option<String> = None;
    for dir in dirs {
        let path = format!("{dir}/{bin}");
        if !tool_present(&path) {
            continue;
        }
        if is_group_or_world_writable(&path) {
            writable_fallback.get_or_insert_with(|| path.clone());
            continue;
        }
        return path;
    }
    if let Some(path) = writable_fallback {
        log::warn!(
            "event=ExporterToolWritable tool={} detail=\"组/世界可写：本可跳过，但这是唯一找到的可执行文件\"",
            path
        );
        return path;
    }
    let fallback_dir = dirs.first().map(String::as_str).unwrap_or("/usr/bin");
    format!("{fallback_dir}/{bin}")
}

/// 解析一个导出器二进制的绝对路径。
pub fn resolve_tool(bin: &str) -> String {
    resolve_in_dirs(bin, &effective_bin_dirs())
}

/// 组/世界可写 = root 跑它就等于“谁写谁执行”。
///
/// `stat` 失败时按**不可写**算（fail-open）：调用方刚刚 `tool_present` 成功才走到这里，
/// 此刻 stat 失败几乎只可能是瞬时竞态。反过来（按可写算）会让一个合法工具凭空被跳过，
/// 最后报成“缺件”—— 用一个假故障换一个不存在的安全收益。
fn is_group_or_world_writable(path: &str) -> bool {
    use std::os::unix::fs::PermissionsExt;
    std::fs::metadata(path)
        .map(|meta| meta.permissions().mode() & 0o022 != 0)
        .unwrap_or(false)
}

/// ID → 可执行文件名。
fn bin_for(id: &str) -> &str {
    def(id).map_or(id, |definition| definition.bin)
}

/// `二进制 + 固定参数`（二进制走目录解析，参数全部来自代码）。
fn argv_with(bin: &str, args: &[&str]) -> Vec<String> {
    let mut argv = Vec::with_capacity(args.len() + 1);
    argv.push(resolve_tool(bin));
    argv.extend(args.iter().map(|arg| (*arg).to_string()));
    argv
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
    argv_with(
        bin_for(KERNEL_LOG_EXPORTER),
        &["-k", "-p", "4", "-o", "json", "--no-pager", "--quiet"],
    )
}

/// 一个导出器 ID + `arg` 对应的**固定 argv**（无 shell）。
///
/// 这里是唯一的「怎么跑」出口：除 `arg` 外没有任何外部字符串进 argv，而 `arg` 只做**窄解析**
/// （每个 ID 只认自己那几个取值），拼不进额外参数。
///
/// **二进制位置不写死**：只给名字（[`ExporterDef::bin`]），由 [`resolve_tool`] 在候选目录里
/// 找同名可执行文件。安装位置是纯环境信息，写死一次就等于把“新发行版”变成一次 agentd 发版。
pub fn argv_for(id: &str, arg: Option<&str>) -> io::Result<Vec<String>> {
    match (id, arg) {
        ("journalctl-unit", _) => Ok(argv_with(bin_for(id), &["-o", "json", "--since", "-5m"])),
        ("journalctl-shutdown", _) => Ok(argv_with(
            bin_for(id),
            &[
                "-o",
                "json",
                "--since",
                "-1d",
                "-u",
                "systemd-shutdown",
                "-u",
                "systemd-logind",
            ],
        )),
        ("last-reboot", _) => Ok(argv_with(bin_for(id), &["-x", "reboot", "shutdown"])),
        ("nft-ruleset", _) => Ok(argv_with(bin_for(id), &["list", "ruleset"])),
        ("iptables-save", _) => Ok(argv_with(bin_for(id), &[])),
        ("smartctl", _) => Ok(argv_with(bin_for(id), &["--scan-open"])),
        ("dmesg", None) => Ok(argv_with(bin_for(id), &[])),
        ("dmesg", Some("panic")) => Ok(argv_with(bin_for(id), &["--level", "emerg,alert,crit"])),
        ("dmesg", Some("nvidia-xid")) => Ok(argv_with(bin_for(id), &[])),
        ("auditd-execve", _) => Ok(argv_with(
            bin_for(id),
            &["-m", "execve", "--start", "recent"],
        )),
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
    /// `exporter_id → 缺失的路径`（跑前预检发现不可执行）。
    #[serde(default)]
    pub missing: BTreeMap<String, String>,
    /// `exporter_id → 实际解析到的绝对路径`（成功预检的那个）。
    ///
    /// 为什么记它：安装位置是**环境信息**，同一台机器上 `/usr/bin/dmesg` 与 `/bin/dmesg`
    /// 都可能命中（usrmerge），换发行版 / 容器镜像后会变。排障时先看这一行，
    /// 不用再猜“它到底找了哪里”。
    #[serde(default)]
    pub resolved: BTreeMap<String, String>,
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
        state
            .resolved
            .insert("dmesg".to_string(), "/bin/dmesg".to_string());
        save_state(&dir, &state);
        let loaded = load_state(&dir);
        assert_eq!(loaded.last_run_ms, state.last_run_ms);
        assert_eq!(loaded.missing, state.missing);
        assert_eq!(loaded.resolved, state.resolved);
        // 旧状态文件（没有 `resolved` 字段）仍要能读 —— 否则升级后瞬间丢掉游标/缺件记忆。
        std::fs::write(
            dir.join("exporters.json"),
            br#"{"last_run_ms":{"work-1":1},"missing":{"dmesg":"/usr/bin/dmesg"}}"#,
        )
        .expect("write legacy");
        let legacy = load_state(&dir);
        assert_eq!(legacy.last_run_ms.get("work-1"), Some(&1));
        assert!(legacy.resolved.is_empty());
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
    fn smartctl_uses_the_scan_open_flag() {
        // 位置不再单独列候选：与其它导出器同一套规则（候选目录 + 同名可执行文件），
        // 由 `every_exporter_runs_the_registered_binary_from_a_candidate_dir` 统一下钉住。
        // Linux 在 `/usr/sbin`、Homebrew 在 `/opt/homebrew/bin|sbin`、`/usr/local/bin|sbin`
        // 这些目录都已经在 `BIN_DIRS` 里。
        let argv = argv_for("smartctl", None).expect("已知导出器");
        assert_eq!(argv[1], "--scan-open");
    }

    #[test]
    fn dmesg_is_resolved_across_the_common_install_paths() {
        // 同一类问题：非 usrmerge 的发行版 / busybox / 最小容器镜像里只有 `/bin/dmesg`。
        // 写死 `/usr/bin/dmesg` 会把「路径猜错」报成「没装」。
        for arg in [None, Some("panic"), Some("nvidia-xid")] {
            let argv = argv_for_run("dmesg", arg, None).expect("已知导出器");
            assert!(
                super::BIN_DIRS
                    .iter()
                    .any(|dir| argv[0] == format!("{dir}/dmesg")),
                "必须落在候选目录里：{}",
                argv[0]
            );
            // 装了的话，选中的那个一定可执行（否则缺件预检会白报）。
            let any_present = super::BIN_DIRS
                .iter()
                .any(|dir| tool_present(&format!("{dir}/dmesg")));
            if any_present {
                assert!(tool_present(&argv[0]), "应当选到可执行的那个：{}", argv[0]);
            }
        }
        // 旗标不能被解析逻辑弄丢。
        let panic = argv_for_run("dmesg", Some("panic"), None).expect("argv");
        assert_eq!(panic[1..], ["--level", "emerg,alert,crit"]);
    }

    /// 每个导出器的 argv[0] 都必须是「候选目录 + 该 ID 登记的可执行名」。
    ///
    /// 这条钉住两件事：不再有人把绝对路径写回 `argv_for`；`ExporterDef::bin` 与 argv 不漂。
    #[test]
    fn every_exporter_runs_the_registered_binary_from_a_candidate_dir() {
        for def in EXPORTERS {
            let argv = argv_for(def.id, None).expect("每个已登记 ID 都要能出 argv");
            let expected = format!("/{}", def.bin);
            assert!(
                argv[0].ends_with(&expected),
                "{} 跑的应该是 {}：{}",
                def.id,
                def.bin,
                argv[0]
            );
            assert!(
                super::BIN_DIRS
                    .iter()
                    .any(|dir| argv[0] == format!("{dir}/{}", def.bin)),
                "{} 不在候选目录里：{}",
                def.id,
                argv[0]
            );
        }
    }

    /// 候选目录里第一个可执行的文件胜出；都不在时返回最标准的位置（交给缺件预检）。
    #[test]
    fn resolve_in_dirs_prefers_the_first_executable_candidate() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "wist-exporter-resolve-{}-{}",
            std::process::id(),
            super::now_ms()
        ));
        std::fs::create_dir_all(&dir).expect("mkdir");
        let first = dir.join("first");
        let second = dir.join("second");
        std::fs::create_dir_all(&first).expect("mkdir first");
        std::fs::create_dir_all(&second).expect("mkdir second");
        // 只在**第二个**目录里放一个可执行文件：应当跳过第一个。
        let tool = second.join("dmesg");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write");
        let mut perms = std::fs::metadata(&tool).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&tool, perms).expect("chmod");

        let first = first.display().to_string();
        let second = second.display().to_string();
        assert_eq!(
            resolve_in_dirs("dmesg", &[first.clone(), second.clone()]),
            format!("{second}/dmesg"),
            "跳过没有这个文件的目录"
        );
        // 一个都没有：保留第一个目录下的路径，让预检报的路径与“试图执行的那个”一致。
        assert_eq!(
            resolve_in_dirs(
                "dmesg",
                &[
                    "/does/not/exist/a".to_string(),
                    "/does/not/exist/b".to_string()
                ],
            ),
            "/does/not/exist/a/dmesg"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 空策略列表等价于 `None`：不能因为下发了一张空表就让所有导出器同时报缺件。
    #[test]
    fn an_empty_policy_dir_list_falls_back_to_the_builtin_table() {
        apply_policy(Some(Vec::new()), Vec::new());
        assert_eq!(
            effective_bin_dirs(),
            BIN_DIRS
                .iter()
                .map(|dir| (*dir).to_string())
                .collect::<Vec<_>>()
        );
        // 收尾：别给并行跑的其它用例留下全局状态。
        apply_policy(None, Vec::new());
    }

    /// 周期 / 超时覆盖：只改写了的那一项，另一项仍取内置值。
    #[test]
    fn period_and_timeout_overrides_are_merged_field_by_field() {
        let rows = vec![
            ("dmesg".to_string(), Some(120u64), None),
            ("smartctl".to_string(), None, Some(45u64)),
            ("nft-ruleset".to_string(), Some(600u64), Some(20u64)),
        ];
        assert_eq!(override_for(&rows, "dmesg"), Some((Some(120), None)));
        assert_eq!(override_for(&rows, "smartctl"), Some((None, Some(45))));
        assert_eq!(
            override_for(&rows, "nft-ruleset"),
            Some((Some(600), Some(20)))
        );
        assert_eq!(override_for(&rows, "last-reboot"), None);

        // 没有策略时，生效值就是内置值。
        let dmesg = def("dmesg").expect("registered");
        assert_eq!(effective_period_secs(dmesg), dmesg.period_secs);
        assert_eq!(effective_timeout_secs(dmesg), dmesg.timeout_secs);
    }

    /// 组/世界可写的候选要跳过（root 跑一个任人可写的二进制 = 本地提权）。
    #[test]
    fn a_group_or_world_writable_candidate_is_skipped() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "wist-exporter-writable-{}-{}",
            std::process::id(),
            super::now_ms()
        ));
        let writable_dir = dir.join("writable");
        let safe_dir = dir.join("safe");
        std::fs::create_dir_all(&writable_dir).expect("mkdir writable");
        std::fs::create_dir_all(&safe_dir).expect("mkdir safe");

        let writable = writable_dir.join("dmesg");
        std::fs::write(&writable, b"#!/bin/sh\n").expect("write");
        let mut perms = std::fs::metadata(&writable).expect("meta").permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&writable, perms).expect("chmod");

        let safe = safe_dir.join("dmesg");
        std::fs::write(&safe, b"#!/bin/sh\n").expect("write");
        let mut perms = std::fs::metadata(&safe).expect("meta").permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(&safe, perms).expect("chmod");

        let dirs = vec![
            writable_dir.display().to_string(),
            safe_dir.display().to_string(),
        ];
        assert_eq!(
            resolve_in_dirs("dmesg", &dirs),
            safe.display().to_string(),
            "应跳过组/世界可写的那一个"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// 候选全都组/世界可写时**仍要选它**（只告警），不能退回一个不存在的路径。
    ///
    /// 这条钉住“宁可带风险地采，也不要假装没装”：后者会让这一路采集静默停摆，
    /// 而停摆本身没人会察觉（缺件预检会报“没装”，运维去装一个已经装了的工具）。
    /// 风险由 `event=ExporterToolWritable` 暴露，不由静默兜。
    #[test]
    fn an_all_writable_candidate_set_still_resolves_to_the_present_tool() {
        use std::os::unix::fs::PermissionsExt;

        let dir = std::env::temp_dir().join(format!(
            "wist-exporter-all-writable-{}-{}",
            std::process::id(),
            super::now_ms()
        ));
        let loose = dir.join("loose");
        std::fs::create_dir_all(&loose).expect("mkdir loose");
        let tool = loose.join("dmesg");
        std::fs::write(&tool, b"#!/bin/sh\n").expect("write");
        let mut perms = std::fs::metadata(&tool).expect("meta").permissions();
        perms.set_mode(0o777);
        std::fs::set_permissions(&tool, perms).expect("chmod");

        assert_eq!(
            resolve_in_dirs("dmesg", &[loose.display().to_string()]),
            tool.display().to_string(),
            "全可写仍选存在的那个（告警但不假称缺件）"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
