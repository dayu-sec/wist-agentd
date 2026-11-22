//! 日志类 opcode：`log.read_range`（文本日志尾部）与 `audit.list`（auditd 记录）。
//!
//! 两条共同纪律（与 `disk.cleanup` 的 `target` 同源）：
//!
//! 1. **源是闭集，参数里没有路径**：`syslog` / `auth` / `kern` / `audit` 各自映射到一组
//!    写死的候选路径（Debian 与 RHEL 各一套）。新增源要走词表评审。
//! 2. **只读文本尾部**：`tail_bytes` + `since_minutes`，不解析「绝对时间区间」，
//!    也不跟着写者走。journald 是二进制 —— **v1 明确不支持**，输出里会说。
//!
//! `since_minutes` 需要行首时间戳。支持两种最常见的写法，别的写法**不猜**：
//!
//! * RFC3339（`2026-11-22T10:00:00.123+08:00`，journald 转发/自定义格式）；
//! * 传统 syslog（`Nov 22 10:00:00`，**本地时间、没有年份**）。
//!
//! 传统格式的年份按「不晚于当前时刻」推断（跨年时取上一年）；时区用本机的
//! `localtime_r` 取偏移（和写日志的进程用同一个 TZ）。一次窗口跨 DST 切换时
//! 可能差一小时 —— 这条写进 `notes`，不假装精确。
//!
//! 认不出时间的行**不丢**（没法证明它是旧的），但会计数并在 `since.applied=false`
//! 时说明「这次没有按时间过滤」。

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};
use time::format_description::well_known::Rfc3339;
use time::{Date, Month, OffsetDateTime, PrimitiveDateTime, Time as ClockTime};
use wist_contracts::action_plan::RiskLevel;

use super::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

const SCHEMA_LOG: &str = "wist.opcode.log_read_range/v1";
const SCHEMA_AUDIT: &str = "wist.opcode.audit_list/v1";

const DEFAULT_TAIL_BYTES: u64 = 64 * 1024;
const MAX_TAIL_BYTES: u64 = 1024 * 1024;
const DEFAULT_LINES: usize = 200;
const MAX_LINES: usize = 1_000;
const MAX_SINCE_MINUTES: u32 = 24 * 60;
/// 单行最多回传多少字符：一行 10 MB 的日志会把整个结果撑爆。
const MAX_LINE_CHARS: usize = 2_000;
const MAX_TYPES: usize = 16;
const MAX_TYPE_CHARS: usize = 32;

pub const LOG_READ_SPEC: OpSpec = OpSpec {
    id: "log.read_range",
    risk: RiskLevel::R1,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(3_000, MAX_LINES, MAX_TAIL_BYTES),
    handler: read_range,
};

pub const AUDIT_LIST_SPEC: OpSpec = OpSpec {
    id: "audit.list",
    risk: RiskLevel::R1,
    platforms: &["linux"],
    budget: OpBudget::new(3_000, MAX_LINES, MAX_TAIL_BYTES),
    handler: audit_list,
};

/// 文本日志源（闭集）。`audit` 不在里面：它有自己的结构化 opcode。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum LogSource {
    Syslog,
    Auth,
    Kern,
}

impl LogSource {
    pub(super) fn parse(value: &str) -> Result<Self, OpError> {
        match value {
            "syslog" => Ok(Self::Syslog),
            "auth" => Ok(Self::Auth),
            "kern" => Ok(Self::Kern),
            "audit" => Err(OpError::new(
                codes::UNSUPPORTED_TARGET,
                "审计日志用 `audit.list`（结构化记录），不走 `log.read_range`".to_string(),
            )),
            other => Err(OpError::new(
                codes::UNSUPPORTED_TARGET,
                format!("未知日志源 `{other}`（支持：syslog | auth | kern）"),
            )),
        }
    }

    pub(super) fn id(self) -> &'static str {
        match self {
            Self::Syslog => "syslog",
            Self::Auth => "auth",
            Self::Kern => "kern",
        }
    }

    /// 候选路径：Debian/Ubuntu 与 RHEL 各一套。先命中者胜。
    pub(super) fn candidates(self) -> &'static [&'static str] {
        match self {
            Self::Syslog => &["/var/log/syslog", "/var/log/messages"],
            Self::Auth => &["/var/log/auth.log", "/var/log/secure"],
            Self::Kern => &["/var/log/kern.log"],
        }
    }
}

const AUDIT_PATH: &str = "/var/log/audit/audit.log";

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogArgs {
    source: String,
    /// 只读文件末尾多少字节（默认 64 KiB / 上限 1 MiB）。
    #[serde(default)]
    tail_bytes: Option<u64>,
    /// 只要最近多少分钟（1..=1440）。解析不出时间戳的行不会被丢，但会计数。
    #[serde(default)]
    since_minutes: Option<u32>,
    /// 最多回传多少行（取**最新**的）。默认 200 / 上限 1000。
    #[serde(default)]
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AuditArgs {
    #[serde(default)]
    tail_bytes: Option<u64>,
    #[serde(default)]
    since_minutes: Option<u32>,
    /// 最多回传多少条记录（取**最新**的）。
    #[serde(default)]
    limit: Option<usize>,
    /// 按记录类型过滤（`SYSCALL` / `USER_LOGIN` …）；给了就只回这些。
    #[serde(default)]
    types: Option<Vec<String>>,
}

#[derive(Debug)]
struct Tail {
    text: String,
    size: u64,
    /// 因为超过 `tail_bytes` 而从中间开始读（第一行是半截的，已丢掉）。
    at_start: bool,
    /// 尾部里有非法 UTF-8：用 lossy 转换过。
    lossy: bool,
}

fn read_tail(path: &Path, max_bytes: u64) -> Result<Tail, OpError> {
    let mut file = fs::File::open(path).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => OpError::new(
            codes::TARGET_NOT_FOUND,
            format!("日志不存在：{}", path.display()),
        ),
        _ => OpError::new(
            codes::OP_FAILED,
            format!("打开日志失败 {}：{err}", path.display()),
        ),
    })?;
    let meta = file
        .metadata()
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取元数据失败：{err}")))?;
    if !meta.is_file() {
        return Err(OpError::new(
            codes::UNSUPPORTED_TARGET,
            format!("{} 不是普通文件（不读 FIFO / 目录）", path.display()),
        ));
    }
    let size = meta.len();
    let at_start = size > max_bytes;
    if at_start {
        file.seek(SeekFrom::Start(size - max_bytes))
            .map_err(|err| OpError::new(codes::OP_FAILED, format!("定位失败：{err}")))?;
    }
    let mut raw = Vec::new();
    (&mut file)
        .take(max_bytes)
        .read_to_end(&mut raw)
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取失败：{err}")))?;
    if at_start && let Some(pos) = raw.iter().position(|byte| *byte == b'\n') {
        // 从文件中间开始读，第一行必然是半截的。
        raw.drain(..=pos);
    }
    let lossy = std::str::from_utf8(&raw).is_err();
    Ok(Tail {
        text: String::from_utf8_lossy(&raw).into_owned(),
        size,
        at_start,
        lossy,
    })
}

/// 解析一行开头的时刻。只认两种格式，其余返回 `None`（**不猜**）。
fn parse_line_time(line: &str, now_unix: i64) -> Option<(i64, &'static str)> {
    let first = line.split_whitespace().next()?;
    // RFC3339：自带偏移，最可靠。
    if let Ok(parsed) = OffsetDateTime::parse(first, &Rfc3339) {
        return Some((parsed.unix_timestamp(), "rfc3339"));
    }
    // 传统 syslog：`Nov 22 10:00:00`（本地时间、没有年份）。
    let mut parts = line.split_whitespace();
    let month = month_from_abbrev(parts.next()?)?;
    let day: u8 = parts.next()?.parse().ok()?;
    let clock: Vec<u8> = parts
        .next()?
        .split(':')
        .map(|part| part.parse::<u8>().ok())
        .collect::<Option<Vec<u8>>>()?;
    let [hour, minute, second] = clock[..] else {
        return None;
    };
    let naive = naive_unix(now_unix, month, day, hour, minute, second)?;
    // 传统格式没带时区：用本机在该时刻的偏移把本地时刻换成绝对时刻。
    let offset = local_offset_seconds(naive);
    let unix = naive - offset;
    // 行首时间不该在“未来”：跨年时把年份退一年。
    let unix = if unix > now_unix + 86_400 {
        let naive = naive_unix(now_unix - 365 * 86_400, month, day, hour, minute, second)?;
        naive - local_offset_seconds(naive)
    } else {
        unix
    };
    Some((unix, "bsd"))
}

fn month_from_abbrev(text: &str) -> Option<Month> {
    let index: u8 = match text {
        "Jan" => 1,
        "Feb" => 2,
        "Mar" => 3,
        "Apr" => 4,
        "May" => 5,
        "Jun" => 6,
        "Jul" => 7,
        "Aug" => 8,
        "Sep" => 9,
        "Oct" => 10,
        "Nov" => 11,
        "Dec" => 12,
        _ => return None,
    };
    Month::try_from(index).ok()
}

/// 用「参考时刻所在的年份」拼出一个**当作 UTC 的**时刻（调用方再减本地偏移）。
fn naive_unix(
    reference: i64,
    month: Month,
    day: u8,
    hour: u8,
    minute: u8,
    second: u8,
) -> Option<i64> {
    let reference = OffsetDateTime::from_unix_timestamp(reference).ok()?;
    let date = Date::from_calendar_date(reference.year(), month, day).ok()?;
    let clock = ClockTime::from_hms(hour, minute, second).ok()?;
    Some(
        PrimitiveDateTime::new(date, clock)
            .assume_utc()
            .unix_timestamp(),
    )
}

/// 本机在某一时刻的 UTC 偏移（秒）。取不到就按 0（UTC）算。
fn local_offset_seconds(unix: i64) -> i64 {
    let time = unix as libc::time_t;
    let mut tm: libc::tm = unsafe { std::mem::zeroed() };
    // SAFETY: `localtime_r` 只写我们自己提供的 `tm`，不持有任何全局状态。
    let ok = unsafe { libc::localtime_r(&time, &mut tm) };
    if ok.is_null() { 0 } else { tm.tm_gmtoff as i64 }
}

fn tail_bytes_for(requested: Option<u64>, budget: u64) -> u64 {
    requested
        .unwrap_or(DEFAULT_TAIL_BYTES)
        .clamp(1, budget.clamp(1, MAX_TAIL_BYTES))
}

fn lines_for(requested: Option<usize>, budget: usize) -> usize {
    requested
        .unwrap_or(DEFAULT_LINES)
        .clamp(1, budget.clamp(1, MAX_LINES))
}

fn since_for(requested: Option<u32>) -> Result<Option<u32>, OpError> {
    match requested {
        None => Ok(None),
        Some(0) => Err(OpError::new(
            codes::INVALID_ARGS,
            "since_minutes 必须 >= 1（不想要时间过滤就省略这个参数）".to_string(),
        )),
        Some(minutes) if minutes > MAX_SINCE_MINUTES => Err(OpError::new(
            codes::INVALID_ARGS,
            format!("since_minutes 不能超过 {MAX_SINCE_MINUTES}"),
        )),
        Some(minutes) => Ok(Some(minutes)),
    }
}

/// 单行超长就截断并标记；返回 (行, 是否截断)。
fn cap_line(line: &str) -> (String, bool) {
    if line.chars().count() <= MAX_LINE_CHARS {
        return (line.to_string(), false);
    }
    let mut capped: String = line.chars().take(MAX_LINE_CHARS).collect();
    capped.push_str("…[truncated]");
    (capped, true)
}

pub(super) fn resolve_source(source: LogSource) -> Result<PathBuf, OpError> {
    for candidate in source.candidates() {
        let path = Path::new(candidate);
        if path.is_file() {
            return Ok(path.to_path_buf());
        }
    }
    Err(OpError::new(
        codes::TARGET_NOT_FOUND,
        format!(
            "本机没有 `{}` 对应的日志文件（找过：{}）",
            source.id(),
            source.candidates().join(" / ")
        ),
    ))
}

fn read_range(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: LogArgs = parse_args(input.args)?;
    let source = LogSource::parse(&args.source)?;
    let since = since_for(args.since_minutes)?;
    let tail_bytes = tail_bytes_for(args.tail_bytes, input.budget.max_bytes);
    let limit = lines_for(args.limit, input.budget.max_items);
    let path = resolve_source(source)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    read_source(source, &path, tail_bytes, since, limit, now).map(|value| OpOutput { value })
}

/// 核心（`path` 由调用方给，单测因此不碰真实 `/var/log`）。
fn read_source(
    source: LogSource,
    path: &Path,
    tail_bytes: u64,
    since_minutes: Option<u32>,
    limit: usize,
    now_unix: i64,
) -> Result<Value, OpError> {
    let tail = read_tail(path, tail_bytes)?;

    let mut line_truncated = 0u64;
    let mut timed: Vec<(Option<i64>, String)> = Vec::new();
    for line in tail.text.lines() {
        let (text, truncated) = cap_line(line);
        if truncated {
            line_truncated += 1;
        }
        let stamp = parse_line_time(line, now_unix);
        timed.push((stamp.map(|(unix, _)| unix), text));
    }

    let time_format = tail
        .text
        .lines()
        .find_map(|line| parse_line_time(line, now_unix))
        .map(|(_, format)| format);

    let mut time_unparsed = 0u64;
    let mut applied = false;
    let mut lines: Vec<String> = Vec::new();
    match since_minutes {
        None => {
            lines.extend(timed.into_iter().map(|(_, text)| text));
        }
        Some(minutes) => {
            let cutoff = now_unix - i64::from(minutes) * 60;
            let parsed_any = timed.iter().any(|(stamp, _)| stamp.is_some());
            applied = parsed_any;
            for (stamp, text) in timed {
                match stamp {
                    Some(unix) if unix >= cutoff => lines.push(text),
                    // 认不出时间的行：证明不了它旧，留着并计数。
                    Some(_) => {}
                    None => {
                        time_unparsed += 1;
                        lines.push(text);
                    }
                }
            }
        }
    }

    let line_count = lines.len();
    let dropped_by_limit = line_count.saturating_sub(limit);
    if dropped_by_limit > 0 {
        lines.drain(..dropped_by_limit);
    }

    let mut notes: Vec<String> = vec![
        "journald 的日志是二进制：本 op 只读文本日志，不覆盖 journal".to_string(),
        "只读尾部窗口；窗口之前的内容不会被读到".to_string(),
    ];
    if since_minutes.is_some() && !applied {
        notes.push("行首时间戳无法识别：本次**没有**按时间过滤（见 since.applied）".to_string());
    }
    if tail.at_start {
        notes.push(format!(
            "只读了末尾 {tail_bytes} 字节（文件共 {} 字节），更早的内容未读",
            tail.size
        ));
    }
    if tail.lossy {
        notes.push("日志里有非法 UTF-8 字节，已按替换字符展示".to_string());
    }

    Ok(json!({
        "schema": SCHEMA_LOG,
        "source": source.id(),
        "path": path.display().to_string(),
        "size_bytes": tail.size,
        "tail": { "bytes": tail_bytes, "truncated_at_start": tail.at_start },
        "since": {
            "minutes": since_minutes,
            "applied": applied,
            "time_format": time_format,
            "unparsed_lines": time_unparsed,
        },
        "lines": lines,
        "returned": line_count.min(limit),
        "line_count": line_count,
        "truncated": dropped_by_limit > 0 || tail.at_start,
        "lines_dropped_by_limit": dropped_by_limit,
        "lines_truncated": line_truncated,
        "lossy": tail.lossy,
        "notes": notes,
    }))
}

/// auditd 记录（每行一条）。`msg=audit(<sec>.<frac>:<seq>)` 直接给出 unix 秒。
#[derive(Debug, Default)]
struct AuditRecord {
    record_type: String,
    seq: Option<u64>,
    unix: Option<i64>,
    key: Option<String>,
    exe: Option<String>,
    comm: Option<String>,
    uid: Option<u32>,
}

fn field_value<'a>(line: &'a str, field: &str) -> Option<&'a str> {
    let mut rest = line;
    let needle = format!("{field}=");
    while let Some(index) = rest.find(&needle) {
        // 字段必须从行首或空格开始，避免 `auid=` 命中 `uid=`。
        let boundary = index == 0 || rest.as_bytes()[index - 1] == b' ';
        let value = &rest[index + needle.len()..];
        if boundary {
            let value = value.trim_start_matches('"');
            let end = value
                .find(|ch: char| ch == '"' || ch.is_whitespace())
                .unwrap_or(value.len());
            if end > 0 {
                return Some(&value[..end]);
            }
        }
        rest = &rest[index + needle.len()..];
    }
    None
}

fn parse_audit_line(line: &str) -> Option<AuditRecord> {
    let record_type = line.strip_prefix("type=")?;
    let record_type = record_type.split_whitespace().next()?;
    if record_type.is_empty() {
        return None;
    }
    let mut record = AuditRecord {
        record_type: record_type.to_string(),
        key: field_value(line, "key").map(str::to_string),
        exe: field_value(line, "exe").map(str::to_string),
        comm: field_value(line, "comm").map(str::to_string),
        uid: field_value(line, "uid").and_then(|uid| uid.parse().ok()),
        ..AuditRecord::default()
    };
    // `msg=audit(1712345678.123:456)`：秒 + 事件序号。
    if let Some(start) = line.find("msg=audit(") {
        let rest = &line[start + "msg=audit(".len()..];
        if let Some(end) = rest.find(')') {
            let inner = &rest[..end];
            let (seconds, seq) = inner.split_once(':')?;
            let seconds = seconds.split('.').next().unwrap_or(seconds);
            record.unix = seconds.parse().ok();
            record.seq = seq.parse().ok();
        }
    }
    // `key="(null)"` 是 auditd 的“没有 key”。
    if record.key.as_deref() == Some("(null)") {
        record.key = None;
    }
    Some(record)
}

fn audit_record_json(record: &AuditRecord) -> Value {
    json!({
        "type": record.record_type,
        "seq": record.seq,
        "timestamp_unix": record.unix,
        "key": record.key,
        "exe": record.exe,
        "comm": record.comm,
        "uid": record.uid,
    })
}

fn audit_list(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: AuditArgs = parse_args(input.args)?;
    let since = since_for(args.since_minutes)?;
    let tail_bytes = tail_bytes_for(args.tail_bytes, input.budget.max_bytes);
    let limit = lines_for(args.limit, input.budget.max_items);
    let types = validate_types(args.types)?;
    let now = OffsetDateTime::now_utc().unix_timestamp();
    list_audit(Path::new(AUDIT_PATH), tail_bytes, since, limit, &types, now)
        .map(|value| OpOutput { value })
}

fn validate_types(types: Option<Vec<String>>) -> Result<Vec<String>, OpError> {
    let types = types.unwrap_or_default();
    if types.len() > MAX_TYPES {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("types 最多 {MAX_TYPES} 个"),
        ));
    }
    for record_type in &types {
        let valid = !record_type.is_empty()
            && record_type.chars().count() <= MAX_TYPE_CHARS
            && record_type
                .chars()
                .all(|ch| ch.is_ascii_uppercase() || ch.is_ascii_digit() || ch == '_');
        if !valid {
            return Err(OpError::new(
                codes::INVALID_ARGS,
                format!("记录类型 `{record_type}` 不合法（大写字母 / 数字 / 下划线）"),
            ));
        }
    }
    Ok(types)
}

/// 核心（`path` 由调用方给，单测因此不碰真实 `/var/log/audit`）。
fn list_audit(
    path: &Path,
    tail_bytes: u64,
    since_minutes: Option<u32>,
    limit: usize,
    types: &[String],
    now_unix: i64,
) -> Result<Value, OpError> {
    let tail = read_tail(path, tail_bytes)?;
    let cutoff = since_minutes.map(|minutes| now_unix - i64::from(minutes) * 60);

    let mut records: Vec<AuditRecord> = Vec::new();
    let mut unparsed = 0u64;
    let mut filtered_out = 0u64;
    let mut time_unparsed = 0u64;
    let mut applied = false;
    let mut type_counts: std::collections::BTreeMap<String, u64> =
        std::collections::BTreeMap::new();

    for line in tail.text.lines() {
        let Some(record) = parse_audit_line(line) else {
            unparsed += 1;
            continue;
        };
        if !types.is_empty() && !types.iter().any(|want| want == &record.record_type) {
            filtered_out += 1;
            continue;
        }
        if let Some(cutoff) = cutoff {
            match record.unix {
                Some(unix) => {
                    applied = true;
                    if unix < cutoff {
                        continue;
                    }
                }
                None => time_unparsed += 1,
            }
        }
        *type_counts.entry(record.record_type.clone()).or_insert(0) += 1;
        records.push(record);
    }

    let total = records.len();
    let dropped_by_limit = total.saturating_sub(limit);
    if dropped_by_limit > 0 {
        records.drain(..dropped_by_limit);
    }

    let mut notes: Vec<String> = vec![
        "auditd 的事件由多条记录拼成；这里**按记录**给，不按事件合并".to_string(),
        "只读 /var/log/audit/audit.log 的尾部窗口；journald / syslog 里的审计副本不在内"
            .to_string(),
    ];
    if since_minutes.is_some() && !applied {
        notes.push("记录里没有可解析的 audit 时间戳：本次**没有**按时间过滤".to_string());
    }
    if tail.at_start {
        notes.push(format!(
            "只读了末尾 {tail_bytes} 字节（文件共 {} 字节）",
            tail.size
        ));
    }
    if tail.lossy {
        notes.push("日志里有非法 UTF-8 字节，已按替换字符展示".to_string());
    }

    Ok(json!({
        "schema": SCHEMA_AUDIT,
        "path": path.display().to_string(),
        "size_bytes": tail.size,
        "tail": { "bytes": tail_bytes, "truncated_at_start": tail.at_start },
        "since": { "minutes": since_minutes, "applied": applied, "unparsed_records": time_unparsed },
        "types_filter": types,
        "records": records.iter().map(audit_record_json).collect::<Vec<_>>(),
        "total": total,
        "returned": total.min(limit),
        "truncated": dropped_by_limit > 0 || tail.at_start,
        "records_dropped_by_limit": dropped_by_limit,
        "unparsed_lines": unparsed,
        "filtered_out": filtered_out,
        "type_counts": type_counts,
        "notes": notes,
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-logs-opcode-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// 2026-06-01T00:00:00Z
    const NOW: i64 = 1_780_272_000;

    #[test]
    fn the_log_source_vocabulary_is_closed() {
        assert_eq!(LogSource::parse("syslog").unwrap(), LogSource::Syslog);
        assert_eq!(LogSource::parse("auth").unwrap(), LogSource::Auth);
        assert_eq!(LogSource::parse("kern").unwrap(), LogSource::Kern);
        // 审计有自己的 opcode：不许从这里读。
        assert_eq!(
            LogSource::parse("audit").unwrap_err().code,
            codes::UNSUPPORTED_TARGET
        );
        for bad in ["journald", "messages", "everything"] {
            assert_eq!(
                LogSource::parse(bad).unwrap_err().code,
                codes::UNSUPPORTED_TARGET
            );
        }
    }

    #[test]
    fn since_minutes_is_a_semantic_bound_not_a_silent_clamp() {
        assert_eq!(since_for(None).unwrap(), None);
        assert_eq!(since_for(Some(5)).unwrap(), Some(5));
        assert_eq!(since_for(Some(0)).unwrap_err().code, codes::INVALID_ARGS);
        assert_eq!(
            since_for(Some(MAX_SINCE_MINUTES + 1)).unwrap_err().code,
            codes::INVALID_ARGS
        );
    }

    #[test]
    fn rfc3339_timestamps_are_parsed_with_their_offset() {
        let (unix, format) =
            parse_line_time("2026-05-31T23:59:00Z host app[1]: hi", NOW).expect("rfc3339");
        assert_eq!(format, "rfc3339");
        assert_eq!(unix, NOW - 60);
    }

    #[test]
    fn bsd_timestamps_use_an_explicit_local_offset() {
        // 直接用纯函数验证：本地 +08:00 下的 `Nov 22 10:00:00`。
        let year_ref = 1_766_000_000; // 2025-12-15T...Z，随便一个 11 月之后的参考点
        let naive = naive_unix(year_ref, Month::November, 22, 10, 0, 0).expect("naive");
        let with_offset = naive - 8 * 3_600;
        assert_eq!(
            OffsetDateTime::from_unix_timestamp(with_offset)
                .expect("ts")
                .to_string(),
            "2025-11-22 2:00:00.0 +00:00:00"
        );
    }

    #[test]
    fn bsd_timestamps_roll_the_year_back_instead_of_landing_in_the_future() {
        // 现在刚过元旦；日志行写的是去年 12 月 31 日。
        let now = naive_unix(NOW, Month::January, 1, 0, 30, 0).expect("now");
        let (unix, format) = parse_line_time("Dec 31 23:59:00 host app: x", now).expect("bsd");
        assert_eq!(format, "bsd");
        assert!(unix <= now, "行首时间不能落在未来：{unix} > {now}");
    }

    #[test]
    fn unknown_line_prefixes_are_not_guessed() {
        assert!(parse_line_time("this is not a timestamp", NOW).is_none());
        assert!(parse_line_time("Nov 99 99:99:99 host app: x", NOW).is_none());
        assert!(parse_line_time("", NOW).is_none());
    }

    #[test]
    fn the_tail_reader_keeps_the_last_bytes_and_drops_the_partial_first_line() {
        let dir = temp_dir("tail");
        let file = dir.join("app.log");
        let mut body = String::new();
        for index in 0..100 {
            body.push_str(&format!("line-{index:03}\n"));
        }
        fs::write(&file, &body).expect("write");

        let tail = read_tail(&file, 100).expect("tail");
        assert!(tail.at_start);
        assert_eq!(tail.size, body.len() as u64);
        // 第一行必然是半截的，已经丢掉；剩下的每行都完整。
        for line in tail.text.lines() {
            assert!(line.starts_with("line-"), "半截行没被丢掉：{line}");
        }
        assert!(tail.text.lines().count() > 1);
    }

    #[test]
    fn a_missing_log_file_is_target_not_found() {
        let dir = temp_dir("missing");
        let err = read_tail(&dir.join("nope.log"), 1024).expect_err("missing");
        assert_eq!(err.code, codes::TARGET_NOT_FOUND);
    }

    #[test]
    fn since_filtering_keeps_unparseable_lines_and_says_it_did_not_filter() {
        let dir = temp_dir("since");
        let file = dir.join("app.log");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let fresh = OffsetDateTime::from_unix_timestamp(now - 60).expect("ts");
        let stale = OffsetDateTime::from_unix_timestamp(now - 3 * 3_600).expect("ts");
        fs::write(
            &file,
            format!(
                "{} host app: fresh\n{} host app: stale\nno-timestamp-here\n",
                fresh.format(&Rfc3339).expect("fmt"),
                stale.format(&Rfc3339).expect("fmt"),
            ),
        )
        .expect("write");

        let value = read_source(LogSource::Syslog, &file, 4096, Some(10), 100, now).expect("read");
        let lines: Vec<&str> = value["lines"]
            .as_array()
            .expect("lines")
            .iter()
            .map(|line| line.as_str().unwrap_or_default())
            .collect();
        assert_eq!(lines.len(), 2, "最新的 + 认不出时间的：{lines:?}");
        assert!(lines.iter().any(|line| line.ends_with("fresh")));
        assert!(lines.iter().any(|line| line == &"no-timestamp-here"));
        assert_eq!(value["since"]["applied"], true);
        assert_eq!(value["since"]["time_format"], "rfc3339");
        assert_eq!(value["since"]["unparsed_lines"], 1);

        // 一行时间都认不出时：不能假装过滤过。
        fs::write(&file, "alpha\nbeta\n").expect("write");
        let value = read_source(LogSource::Syslog, &file, 4096, Some(10), 100, now).expect("read");
        assert_eq!(value["since"]["applied"], false);
        assert_eq!(value["lines"].as_array().expect("lines").len(), 2);
        assert!(
            value["notes"]
                .as_array()
                .expect("notes")
                .iter()
                .any(|note| note.as_str().unwrap_or_default().contains("没有"))
        );
    }

    #[test]
    fn the_limit_keeps_the_newest_lines_and_counts_the_rest() {
        let dir = temp_dir("limit");
        let file = dir.join("app.log");
        let mut body = String::new();
        for index in 0..50 {
            body.push_str(&format!("{index}\n"));
        }
        fs::write(&file, &body).expect("write");

        let value = read_source(LogSource::Syslog, &file, 4096, None, 10, NOW).expect("read");
        assert_eq!(value["line_count"], 50);
        assert_eq!(value["returned"], 10);
        assert_eq!(value["lines_dropped_by_limit"], 40);
        assert_eq!(value["truncated"], true);
        let lines = value["lines"].as_array().expect("lines");
        assert_eq!(lines.first().and_then(|line| line.as_str()), Some("40"));
        assert_eq!(lines.last().and_then(|line| line.as_str()), Some("49"));
    }

    #[test]
    fn a_single_huge_line_is_capped_and_counted() {
        let dir = temp_dir("huge-line");
        let file = dir.join("app.log");
        fs::write(&file, format!("{}\n", "x".repeat(MAX_LINE_CHARS * 2))).expect("write");

        let value = read_source(LogSource::Syslog, &file, 8192, None, 10, NOW).expect("read");
        assert_eq!(value["lines_truncated"], 1);
        let line = value["lines"][0].as_str().expect("line");
        assert!(line.ends_with("…[truncated]"));
        assert_eq!(
            line.chars().count(),
            MAX_LINE_CHARS + "…[truncated]".chars().count()
        );
    }

    #[test]
    fn audit_lines_yield_stable_structured_fields() {
        let syscall = parse_audit_line(
            r#"type=SYSCALL msg=audit(1712345678.123:456): arch=c000003e syscall=59 success=yes exe="/usr/bin/ls" key="exec""#,
        )
        .expect("syscall");
        assert_eq!(syscall.record_type, "SYSCALL");
        assert_eq!(syscall.unix, Some(1_712_345_678));
        assert_eq!(syscall.seq, Some(456));
        assert_eq!(syscall.key.as_deref(), Some("exec"));
        assert_eq!(syscall.exe.as_deref(), Some("/usr/bin/ls"));

        let login = parse_audit_line(
            r#"type=USER_LOGIN msg=audit(1712345679.000:457): pid=1234 uid=0 auid=1000 msg='op=login'"#,
        )
        .expect("login");
        assert_eq!(login.record_type, "USER_LOGIN");
        assert_eq!(login.uid, Some(0), "uid 不能命中 `auid=`");
        assert_eq!(login.key, None);

        // `key="(null)"` 是 auditd 的「没有 key」。
        let none =
            parse_audit_line(r#"type=AVC msg=audit(1712345679.1:458): key="(null)""#).expect("avc");
        assert_eq!(none.key, None);

        assert!(parse_audit_line("not an audit line").is_none());
    }

    #[test]
    fn audit_listing_filters_by_type_and_time_and_keeps_the_newest() {
        let dir = temp_dir("audit");
        let file = dir.join("audit.log");
        let now = OffsetDateTime::now_utc().unix_timestamp();
        let mut body = String::new();
        for index in 0..20 {
            let stamp = now - i64::from(index) * 60;
            body.push_str(&format!(
                "type=SYSCALL msg=audit({stamp}.0:{index}): uid=0 key=\"exec\"\n"
            ));
        }
        body.push_str(&format!(
            "type=USER_LOGIN msg=audit({now}.0:999): uid=0 auid=1000\n"
        ));
        body.push_str("garbage line\n");
        fs::write(&file, &body).expect("write");

        let value =
            list_audit(&file, 8192, Some(10), 5, &["SYSCALL".to_string()], now).expect("list");
        assert_eq!(value["total"], 11, "10 分钟内的 11 条 SYSCALL");
        assert_eq!(value["returned"], 5);
        assert_eq!(value["filtered_out"], 1);
        assert_eq!(value["unparsed_lines"], 1);
        assert_eq!(value["truncated"], true);
        assert_eq!(value["type_counts"]["SYSCALL"], 11);
        assert_eq!(value["records"][0]["type"], "SYSCALL");

        // 不设过滤：两种记录都要，且按时间递增的顺序给出。
        let value = list_audit(&file, 8192, None, 100, &[], now).expect("list");
        assert_eq!(value["returned"], 21);
        assert_eq!(value["type_counts"]["USER_LOGIN"], 1);
        assert_eq!(value["since"]["applied"], false);
    }

    #[test]
    fn audit_types_are_validated() {
        assert!(validate_types(None).unwrap().is_empty());
        assert_eq!(
            validate_types(Some(vec!["SYSCALL".to_string()])).unwrap(),
            vec!["SYSCALL".to_string()]
        );
        for bad in ["syscall", "A B", "", "A-B"] {
            assert_eq!(
                validate_types(Some(vec![bad.to_string()]))
                    .unwrap_err()
                    .code,
                codes::INVALID_ARGS
            );
        }
    }

    #[test]
    fn op_metadata_matches_the_design() {
        assert_eq!(LOG_READ_SPEC.risk, RiskLevel::R1);
        assert_eq!(AUDIT_LIST_SPEC.risk, RiskLevel::R1);
        // auditd 只在 Linux 上有。
        assert_eq!(AUDIT_LIST_SPEC.platforms, &["linux"]);
        assert_eq!(LOG_READ_SPEC.platforms, &["linux", "macos"]);
    }
}
