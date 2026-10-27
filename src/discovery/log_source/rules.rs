//! 每个服务一条**日志目录**规则（L2b）。
//!
//! 设计原则：规则层是**纯函数** —— 输入是已经采好的进程证据（argv / environ / cwd /
//! 打开的 fd / 读配置文件的闭包），输出是**候选目录**（容器视角，由外层统一做
//! `/proc/<pid>/root` + realpath）。这样每个服务的「怎么推」都能用字符串夹具测，
//! 不需要真跑一个 MySQL。
//!
//! ## 为什么是「候选 + 优先级」而不是一条规则
//!
//! 现场没有统一写法：日志路径可以写在命令行、写进配置文件、也可以由进程**打开着**
//! （open fd 是最硬的证据 —— 无论配置怎么写，它正在写的那个文件就是日志）。
//! 所以每个服务给一组**有序候选**，外层按顺序试「这个目录真的存在吗」，第一个成立的胜出。
//!
//! ## 证据词表
//!
//! | 值 | 含义 |
//! |---|---|
//! | `cmdline_datadir` | 命令行给了数据目录（`-D` / `--datadir` / `--dbpath`） |
//! | `env_datadir` | 环境变量给了数据目录（`PGDATA`） |
//! | `cmdline_logfile` | 命令行直接给了日志文件（`--log-error` / `--logpath` / `--logfile`） |
//! | `config_file` | 配置文件里给了日志路径或数据目录 |
//! | `open_fd` | 进程**正打开着**一个日志文件（最硬的证据） |
//! | `cwd` | 相对路径以进程工作目录为基准（只作为基准，不单独作为信号） |
//!
//! 最后一条是有意的：一个服务的 cwd 通常是 `/`、`/data` 或它的数据目录，**从来不是**
//! 日志目录。拿 cwd 当独立信号只会制造误报，所以它只用来解析配置文件/命令行里的相对路径。

use std::collections::BTreeMap;

/// 单个配置文件的读取上限（字节）。`my.cnf` 通常 < 10 KiB，64 KiB 足够且不会拖慢 tick。
pub const MAX_CONFIG_BYTES: usize = 64 * 1024;

/// 一个进程的全部证据（已读好，规则层不再做 IO）。
pub struct Evidence<'a> {
    pub argv: &'a [String],
    pub environ: &'a [String],
    pub cwd: Option<&'a str>,
    /// 进程正打开的文件（绝对路径，容器视角）。外层已过滤掉 socket / pipe / anon_inode。
    pub open_files: &'a [String],
    /// 读配置文件；`path` 已含 `/proc/<pid>/root` 前缀（容器里读到的就是容器那份）。
    pub read_file: &'a dyn Fn(&str) -> Option<String>,
}

/// 一个候选目录（容器视角）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Proposal {
    pub dir: String,
    /// 证据词表里的值（见模块注释）。
    pub evidence: &'static str,
    /// 原始依据片段，给人看 / 给审计。
    pub detail: String,
    /// 0..100；只在同一证据档内比较。
    pub confidence: i64,
}

impl Proposal {
    fn new(
        dir: impl Into<String>,
        evidence: &'static str,
        detail: String,
        confidence: i64,
    ) -> Self {
        Self {
            dir: dir.into(),
            evidence,
            detail,
            confidence,
        }
    }
}

/// 本端会产出的证据值合集（wire 词表，与网关 `LOG_SOURCE_EVIDENCE` 逐字对应）。
///
/// 注意里面有两个值不是规则层产出的：`search_hit` 来自 L3 受限搜索、`unresolved` 来自
/// “看得见实例但一条线索都没有”。放在同一张表里，是为了让两侧的**字面清单**只有一份。
///
/// 两侧不共享类型，只能靠**各自持一份同样的清单 + 测试**钉住；`unresolved` 不是
/// 一条候选（`dir` 为空），它的意义只是让网关能说“2 个实例，1 个没定位”。
pub const EVIDENCE_VALUES: &[&str] = &[
    "cmdline_datadir",
    "env_datadir",
    "cmdline_logfile",
    "config_file",
    "open_fd",
    "search_hit",
    "unresolved",
];

pub struct Rule {
    /// 与网关 `LOG_SERVICES` 对齐的服务标识。
    pub service: &'static str,
    /// 可执行文件名（`/usr/sbin/mysqld` → `mysqld`）。
    pub executables: &'static [&'static str],
    /// 一条候选都给不出来时，这个进程要不要算「一个看见了但没定位到的实例」。
    ///
    /// postgres 必须为 `false`：它的子进程（checkpointer / walwriter / 每个连接的 backend）
    /// 共用 `argv[0]` 却没有 `-D`，按它们计数会把一个 PG 数成七八个。
    /// 其它服务的主进程就是唯一进程，没有这个问题。
    pub counts_without_candidates: bool,
    pub candidates: fn(&Evidence<'_>) -> Vec<Proposal>,
}

/// 按可执行文件 basename 找规则。
pub fn rule_for(exe: &str) -> Option<&'static Rule> {
    let name = exe.rsplit('/').next().unwrap_or(exe).trim();
    RULES.iter().find(|rule| rule.executables.contains(&name))
}

static RULES: &[Rule] = &[POSTGRES, MYSQL, REDIS, MONGOD];

// ─────────────────────────────────────────────────────────────────────────────
// PostgreSQL
// ─────────────────────────────────────────────────────────────────────────────

const POSTGRES: Rule = Rule {
    service: "postgresql",
    executables: &["postgres", "postmaster"],
    counts_without_candidates: false,
    candidates: postgres_candidates,
};

/// `<datadir>/log`，外加 `postgresql.conf` 里的 `log_directory` 与「正打开着的 csvlog」。
fn postgres_candidates(ev: &Evidence<'_>) -> Vec<Proposal> {
    let Some((datadir, evidence, detail)) = postgres_datadir(ev) else {
        return Vec::new();
    };
    let mut out = vec![Proposal::new(
        format!("{datadir}/log"),
        evidence,
        detail,
        90,
    )];
    // `logging_collector = on` 且 `log_directory` 指向别处：那才是真正的目录。
    if let Some(conf) = (ev.read_file)(&format!("{datadir}/postgresql.conf"))
        && let Some(dir) = pg_log_directory(&conf)
        && let Some(dir) = absolute(&dir, Some(&datadir))
    {
        out.push(Proposal::new(
            dir,
            "config_file",
            "postgresql.conf: log_directory".to_string(),
            85,
        ));
    }
    // 正打开着的 csvlog（`logging_collector` 的产物）：无论配置怎么写，这个目录是真的。
    if let Some(dir) = ev
        .open_files
        .iter()
        .filter(|file| file.starts_with(&format!("{datadir}/log/")))
        .find(|file| {
            let name = basename(file).to_lowercase();
            name.ends_with(".csv") || name.ends_with(".log")
        })
        .and_then(|file| parent_dir(file))
    {
        out.push(Proposal::new(
            dir.to_string(),
            "open_fd",
            format!("open fd {dir}"),
            80,
        ));
    }
    out
}

fn postgres_datadir(ev: &Evidence<'_>) -> Option<(String, &'static str, String)> {
    if let Some(value) = flag_value(ev.argv, "datadir").or_else(|| short_value(ev.argv, "-D"))
        && let Some(dir) = absolute(&value, None)
    {
        return Some((dir, "cmdline_datadir", format!("-D {value}")));
    }
    if let Some(value) = environ_value(ev.environ, "PGDATA")
        && let Some(dir) = absolute(&value, None)
    {
        return Some((dir, "env_datadir", format!("PGDATA={value}")));
    }
    None
}

/// `postgresql.conf` 里 `logging_collector = on` 时的 `log_directory`。
///
/// 为什么要求 `logging_collector = on`：它关着时 `log_directory` 根本不生效
/// （日志进 stderr/journald），拿它当目录只会得到一个空目录。
fn pg_log_directory(text: &str) -> Option<String> {
    let values = key_value_lines(text, '=');
    if !values
        .get("logging_collector")
        .is_some_and(|value| value.eq_ignore_ascii_case("on") || value == "true")
    {
        return None;
    }
    values.get("log_directory").cloned()
}

// ─────────────────────────────────────────────────────────────────────────────
// MySQL / MariaDB
// ─────────────────────────────────────────────────────────────────────────────

const MYSQL: Rule = Rule {
    service: "mysql",
    executables: &["mysqld", "mariadbd"],
    counts_without_candidates: true,
    candidates: mysql_candidates,
};

fn mysql_candidates(ev: &Evidence<'_>) -> Vec<Proposal> {
    let config = mysql_config(ev);
    // `datadir` 是 MySQL 解析**相对**日志路径的基准（`log-error=mysqld.err` 就在 datadir 下）。
    let datadir = flag_value(ev.argv, "datadir")
        .or_else(|| config.get("datadir").cloned())
        .and_then(|value| absolute(&value, None));
    let base = datadir.as_deref().or(ev.cwd);

    let mut out = Vec::new();
    // 1) 命令行直接给日志文件（`--log-error` 等，`-`/`_` 等价）。
    for (key, label) in [
        ("log_error", "--log-error"),
        ("slow_query_log_file", "--slow-query-log-file"),
        ("general_log_file", "--general-log-file"),
    ] {
        if let Some(value) = flag_value(ev.argv, key)
            && let Some(dir) = file_parent(&value, base)
        {
            out.push(Proposal::new(
                dir,
                "cmdline_logfile",
                format!("{label} {value}"),
                90,
            ));
        }
    }
    // 2) 配置文件（`--defaults-file` / `--defaults-extra-file` / 常见默认位置）。
    for key in ["log_error", "slow_query_log_file", "general_log_file"] {
        if let Some(value) = config.get(key).map(String::as_str)
            && let Some(dir) = file_parent(value, base)
        {
            out.push(Proposal::new(
                dir,
                "config_file",
                format!("my.cnf: {key}={value}"),
                85,
            ));
        }
    }
    // 3) 正打开着的错误日志 / 慢日志（进程正在写的那个文件最硬）。
    for file in ev.open_files {
        if let Some(dir) = parent_dir(file).filter(|_| looks_like_mysql_log(file)) {
            out.push(Proposal::new(
                dir.to_string(),
                "open_fd",
                format!("open fd {file}"),
                80,
            ));
        }
    }
    out
}

/// 读 `[mysqld]` 段里的键（`-` 与 `_` 视为等价，大小写不敏感）。
fn mysql_config(ev: &Evidence<'_>) -> BTreeMap<String, String> {
    let mut paths: Vec<String> = Vec::new();
    for flag in ["defaults-file", "defaults-extra-file"] {
        if let Some(value) = flag_value(ev.argv, flag)
            && let Some(path) = absolute(&value, None)
        {
            paths.push(path);
        }
    }
    paths.push("/etc/my.cnf".to_string());
    paths.push("/etc/mysql/my.cnf".to_string());
    for path in paths {
        if let Some(text) = (ev.read_file)(&path) {
            return ini_section(&text, "mysqld");
        }
    }
    BTreeMap::new()
}

fn looks_like_mysql_log(path: &str) -> bool {
    let name = basename(path).to_lowercase();
    name.ends_with(".err") || name.ends_with(".log") || name.contains("slow")
}

// ─────────────────────────────────────────────────────────────────────────────
// Redis
// ─────────────────────────────────────────────────────────────────────────────

const REDIS: Rule = Rule {
    service: "redis",
    executables: &["redis-server"],
    counts_without_candidates: true,
    candidates: redis_candidates,
};

fn redis_candidates(ev: &Evidence<'_>) -> Vec<Proposal> {
    let mut out = Vec::new();
    // 1) `--logfile <path>`（相对路径以 cwd 为基准）。
    if let Some(value) = flag_value(ev.argv, "logfile")
        && let Some(dir) = file_parent(&value, ev.cwd)
    {
        out.push(Proposal::new(
            dir,
            "cmdline_logfile",
            format!("--logfile {value}"),
            90,
        ));
    }
    // 2) 配置文件：`redis-server /etc/redis/redis.conf`（第一个不以 `-` 开头的参数）。
    if let Some(path) = ev
        .argv
        .iter()
        .skip(1)
        .find(|arg| !arg.trim_start().starts_with('-'))
        .and_then(|arg| absolute(arg, ev.cwd))
        && let Some(text) = (ev.read_file)(&path)
        && let Some(value) = redis_config_value(&text, "logfile")
        // `logfile ""` 是「写 stdout」，不是目录。
        && !value.trim().is_empty()
        && let Some(dir) = file_parent(&value, ev.cwd)
    {
        out.push(Proposal::new(
            dir,
            "config_file",
            format!("redis.conf: logfile {value}"),
            85,
        ));
    }
    // 3) 正打开着的 .log。
    for file in ev.open_files {
        if let Some(dir) = parent_dir(file)
            && basename(file).to_lowercase().ends_with(".log")
        {
            out.push(Proposal::new(
                dir.to_string(),
                "open_fd",
                format!("open fd {file}"),
                80,
            ));
        }
    }
    out
}

/// redis.conf 是**空格分隔**（不是 `key=value`），值可以带引号。
fn redis_config_value(text: &str, key: &str) -> Option<String> {
    for line in text.lines().take(MAX_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        if parts.next().map(str::trim) != Some(key) {
            continue;
        }
        let value = parts.next().unwrap_or_default().trim();
        return Some(unquote(value).to_string());
    }
    None
}

// ─────────────────────────────────────────────────────────────────────────────
// MongoDB
// ─────────────────────────────────────────────────────────────────────────────

const MONGOD: Rule = Rule {
    service: "mongodb",
    executables: &["mongod"],
    counts_without_candidates: true,
    candidates: mongod_candidates,
};

fn mongod_candidates(ev: &Evidence<'_>) -> Vec<Proposal> {
    let mut out = Vec::new();
    let config_path = flag_value(ev.argv, "config")
        .or_else(|| short_value(ev.argv, "-f"))
        .and_then(|value| absolute(&value, ev.cwd))
        .or_else(|| Some("/etc/mongod.conf".to_string()));
    let config = config_path
        .as_deref()
        .and_then(|path| (ev.read_file)(path))
        .map(|text| mongod_config(&text));

    // 1) `--logpath`。
    if let Some(value) = flag_value(ev.argv, "logpath")
        && let Some(dir) = file_parent(&value, ev.cwd)
    {
        out.push(Proposal::new(
            dir,
            "cmdline_logfile",
            format!("--logpath {value}"),
            90,
        ));
    }
    // 2) 配置文件里的 `systemLog.path`。
    if let Some(Some(value)) = config.as_ref().map(|(log, _)| log)
        && let Some(dir) = file_parent(value, ev.cwd)
    {
        out.push(Proposal::new(
            dir,
            "config_file",
            format!("mongod.conf: systemLog.path={value}"),
            85,
        ));
    }
    // 3) `--dbpath`（mongod 默认日志在 `<dbpath>/log`）。
    let dbpath = flag_value(ev.argv, "dbpath")
        .or_else(|| config.as_ref().and_then(|(_, db)| db.clone()))
        .and_then(|value| absolute(&value, ev.cwd));
    if let Some(dbpath) = dbpath {
        out.push(Proposal::new(
            format!("{dbpath}/log"),
            "cmdline_datadir",
            format!("dbpath {dbpath}"),
            80,
        ));
    }
    // 4) 正打开着的 .log。
    for file in ev.open_files {
        if let Some(dir) = parent_dir(file)
            && basename(file).to_lowercase().ends_with(".log")
        {
            out.push(Proposal::new(
                dir.to_string(),
                "open_fd",
                format!("open fd {file}"),
                75,
            ));
        }
    }
    out
}

/// YAML 子集：只认 `systemLog:` 下的 `path:` 与 `storage:` 下的 `dbPath:`。
///
/// 为什么不上 YAML 解析器：这里只要两个键，而且 mongod.conf 在客户现场常被注释/缩进
/// 手工改过。一个**按缩进分块**的两键扫描比引入依赖更好审 —— 认不出就返回 `None`，
/// 由后面的 `--dbpath` / open fd 兜底。
fn mongod_config(text: &str) -> (Option<String>, Option<String>) {
    let mut section: Option<&str> = None;
    let mut log_path = None;
    let mut db_path = None;
    for line in text.lines().take(MAX_LINES) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') {
            continue;
        }
        // 顶层键：`systemLog:` / `storage:` / 其它。
        if !line.starts_with(char::is_whitespace) {
            section = trimmed.strip_suffix(':').map(str::trim);
            continue;
        }
        let Some((key, value)) = trimmed.split_once(':') else {
            continue;
        };
        let value = unquote(value.trim());
        match (section, key.trim()) {
            (Some("systemLog"), "path") => log_path = Some(value.to_string()),
            (Some("storage"), "dbPath") => db_path = Some(value.to_string()),
            _ => {}
        }
    }
    (log_path, db_path)
}

// ─────────────────────────────────────────────────────────────────────────────
// 通用小工具
// ─────────────────────────────────────────────────────────────────────────────

const MAX_LINES: usize = 2000;

fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path).trim()
}

/// 容器视角的父目录（`/var/log/mysql/error.log` → `/var/log/mysql`）。
fn parent_dir(path: &str) -> Option<&str> {
    let (parent, _) = path.rsplit_once('/')?;
    if parent.is_empty() {
        Some("/")
    } else {
        Some(parent)
    }
}

/// 把一个「日志文件路径」变成它的目录；相对路径以 `base` 为基准（没有基准就放弃）。
fn file_parent(raw: &str, base: Option<&str>) -> Option<String> {
    let path = absolute(raw, base)?;
    parent_dir(&path).map(str::to_string)
}

/// 绝对化 + 去引号 + 拒绝 `..`；相对路径需要 `base`。
fn absolute(raw: &str, base: Option<&str>) -> Option<String> {
    let value = unquote(raw.trim());
    if value.is_empty() || value.contains('\0') {
        return None;
    }
    let joined = if value.starts_with('/') {
        value.to_string()
    } else {
        let base = base?.trim_end_matches('/');
        if base.is_empty() {
            return None;
        }
        format!("{base}/{value}")
    };
    // 归一：去掉空段与 `.`，`..` 按文件系统语义**回退一段**（配置里的相对日志路径很常见）；
    // 越过根就拒（那是拼错了，不是有意）。最终安全性仍由 agent 的 realpath +
    // 网关的 roots 校验保证 —— 这里只负责“把路径写清楚”。
    let mut segments: Vec<&str> = Vec::new();
    for segment in joined.split('/') {
        match segment {
            "" | "." => continue,
            ".." => {
                segments.pop()?;
            }
            other => segments.push(other),
        }
    }
    if segments.is_empty() {
        return None;
    }
    Some(format!("/{}", segments.join("/")))
}

fn unquote(value: &str) -> &str {
    let value = value.trim();
    let bytes = value.as_bytes();
    if bytes.len() >= 2 {
        let first = bytes[0];
        let last = bytes[bytes.len() - 1];
        if (first == b'"' && last == b'"') || (first == b'\'' && last == b'\'') {
            return &value[1..value.len() - 1];
        }
    }
    value
}

/// `--flag=value` / `--flag value`；`-` 与 `_` 等价、大小写不敏感（MySQL 的规矩，对别人也无害）。
fn flag_value(argv: &[String], flag: &str) -> Option<String> {
    let wanted = normalize_key(flag);
    for (index, arg) in argv.iter().enumerate() {
        let Some(rest) = arg.strip_prefix("--") else {
            continue;
        };
        match rest.split_once('=') {
            Some((key, value)) if normalize_key(key) == wanted => return Some(value.to_string()),
            None if normalize_key(rest) == wanted => {
                return argv.get(index + 1).cloned();
            }
            _ => {}
        }
    }
    None
}

fn short_value(argv: &[String], flag: &str) -> Option<String> {
    argv.iter()
        .position(|arg| arg == flag)
        .and_then(|index| argv.get(index + 1).cloned())
}

fn environ_value(environ: &[String], key: &str) -> Option<String> {
    environ.iter().find_map(|entry| {
        let (name, value) = entry.split_once('=')?;
        (name == key).then(|| value.to_string())
    })
}

fn normalize_key(value: &str) -> String {
    value.replace('-', "_").to_ascii_lowercase()
}

/// `key = value` 的行（PostgreSQL 的配置是这个形状）。
fn key_value_lines(text: &str, separator: char) -> BTreeMap<String, String> {
    let mut values = BTreeMap::new();
    for line in text.lines().take(MAX_LINES) {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        let Some((key, value)) = line.split_once(separator) else {
            continue;
        };
        // 行尾注释：`log_error = /var/log/x.err # 注释`
        let value = value.split('#').next().unwrap_or(value);
        values.insert(normalize_key(key.trim()), unquote(value.trim()).to_string());
    }
    values
}

/// INI 段里的键（`[mysqld]` … 下一个段头）。
fn ini_section(text: &str, section: &str) -> BTreeMap<String, String> {
    let wanted = section.to_ascii_lowercase();
    let mut current: Option<String> = None;
    let mut values = BTreeMap::new();
    for line in text.lines().take(MAX_LINES) {
        let trimmed = line.trim();
        if trimmed.is_empty() || trimmed.starts_with('#') || trimmed.starts_with(';') {
            continue;
        }
        if let Some(name) = trimmed
            .strip_prefix('[')
            .and_then(|rest| rest.split(']').next())
        {
            current = Some(name.trim().to_ascii_lowercase());
            continue;
        }
        if current.as_deref() != Some(wanted.as_str()) {
            continue;
        }
        let Some((key, value)) = trimmed.split_once('=') else {
            continue;
        };
        let value = value.split('#').next().unwrap_or(value);
        values.insert(normalize_key(key.trim()), unquote(value.trim()).to_string());
    }
    values
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(items: &[&str]) -> Vec<String> {
        items.iter().map(|item| item.to_string()).collect()
    }

    fn evidence<'a>(
        argv: &'a [String],
        environ: &'a [String],
        cwd: Option<&'a str>,
        open_files: &'a [String],
        read_file: &'a dyn Fn(&str) -> Option<String>,
    ) -> Evidence<'a> {
        Evidence {
            argv,
            environ,
            cwd,
            open_files,
            read_file,
        }
    }

    fn no_files() -> impl Fn(&str) -> Option<String> {
        |_: &str| None
    }

    #[test]
    fn rules_are_selected_by_executable_basename() {
        assert_eq!(
            rule_for("/usr/sbin/mysqld").map(|r| r.service),
            Some("mysql")
        );
        assert_eq!(rule_for("mariadbd").map(|r| r.service), Some("mysql"));
        assert_eq!(
            rule_for("/usr/bin/redis-server").map(|r| r.service),
            Some("redis")
        );
        assert_eq!(
            rule_for("/usr/bin/mongod").map(|r| r.service),
            Some("mongodb")
        );
        assert_eq!(
            rule_for("/usr/lib/postgresql/16/bin/postgres").map(|r| r.service),
            Some("postgresql")
        );
        // 只是名字相近的不算。
        assert!(rule_for("/usr/bin/mysqld_exporter").is_none());
        assert!(rule_for("/usr/bin/redis-cli").is_none());
    }

    // ── flag / 路径小工具 ──

    #[test]
    fn flag_values_accept_both_spellings_and_separators() {
        let argv = args(&["mysqld", "--log-error=/var/log/mysql/error.log"]);
        assert_eq!(
            flag_value(&argv, "log_error").as_deref(),
            Some("/var/log/mysql/error.log")
        );
        let argv = args(&["mysqld", "--log-error", "/var/log/mysql/error.log"]);
        assert_eq!(
            flag_value(&argv, "log_error").as_deref(),
            Some("/var/log/mysql/error.log")
        );
        assert_eq!(
            short_value(&args(&["postgres", "-D", "/data/pg"]), "-D").as_deref(),
            Some("/data/pg")
        );
        assert_eq!(flag_value(&args(&["redis-server"]), "logfile"), None);
    }

    #[test]
    fn relative_paths_need_a_base_and_resolve_dotdot() {
        assert_eq!(absolute("/var/log/x", None).as_deref(), Some("/var/log/x"));
        assert_eq!(
            absolute("mysqld.err", Some("/data/mysql")).as_deref(),
            Some("/data/mysql/mysqld.err")
        );
        assert_eq!(absolute("mysqld.err", None), None);
        // 配置里的 `../logs/x.log` 是合法的：按文件系统语义回退一段。
        assert_eq!(
            absolute("../logs/x.log", Some("/srv/redis")).as_deref(),
            Some("/srv/logs/x.log")
        );
        // 越过根是拼错了，不是有意。
        assert_eq!(absolute("/../etc/x", None), None);
        // 配置里的引号是语法糖，不是路径的一部分。
        assert_eq!(
            absolute("\"/var/log/x\"", None).as_deref(),
            Some("/var/log/x")
        );
        assert_eq!(absolute("   ", Some("/data")), None);
    }

    // ── PostgreSQL ──

    #[test]
    fn postgres_reads_log_directory_from_its_conf() {
        let argv = args(&["postgres", "-D", "/data/pg"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = |path: &str| {
            (path == "/data/pg/postgresql.conf")
                .then(|| "logging_collector = on\nlog_directory = 'pg_log'\n".to_string())
        };
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = postgres_candidates(&ev);
        assert_eq!(out[0].dir, "/data/pg/log");
        assert_eq!(out[0].evidence, "cmdline_datadir");
        // 相对目录按 datadir 展开。
        assert_eq!(out[1].dir, "/data/pg/pg_log");
        assert_eq!(out[1].evidence, "config_file");
    }

    #[test]
    fn postgres_ignores_log_directory_when_the_collector_is_off() {
        // `logging_collector = off` 时 `log_directory` 不生效（日志进 stderr / journald）。
        let argv = args(&["postgres", "-D", "/data/pg"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read =
            |_: &str| Some("logging_collector = off\nlog_directory = '/var/log/pg'\n".to_string());
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = postgres_candidates(&ev);
        assert!(
            out.iter()
                .all(|proposal| proposal.evidence != "config_file")
        );
    }

    #[test]
    fn postgres_uses_an_open_csvlog_as_evidence() {
        let argv = args(&["postgres", "-D", "/data/pg"]);
        let environ = args(&[]);
        let files = args(&["/data/pg/log/postgresql-2026-10-26.csv", "/data/pg/base/1"]);
        let read = no_files();
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = postgres_candidates(&ev);
        assert!(
            out.iter()
                .any(|proposal| proposal.evidence == "open_fd" && proposal.dir == "/data/pg/log"),
            "{out:?}"
        );
    }

    // ── MySQL ──

    #[test]
    fn mysql_reads_log_error_from_the_command_line() {
        let argv = args(&[
            "mysqld",
            "--datadir=/data/mysql",
            "--log-error=/var/log/mysql/error.log",
        ]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = no_files();
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = mysql_candidates(&ev);
        assert_eq!(out[0].dir, "/var/log/mysql");
        assert_eq!(out[0].evidence, "cmdline_logfile");
    }

    #[test]
    fn mysql_resolves_relative_log_paths_against_datadir() {
        // MySQL 的规矩：相对路径以 datadir 为基准。
        let argv = args(&["mysqld", "--datadir=/data/mysql"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = |path: &str| {
            (path == "/etc/my.cnf").then(|| {
                "[mysqld]\nlog-error=mysqld.err\nslow_query_log_file=slow.log\n".to_string()
            })
        };
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = mysql_candidates(&ev);
        assert_eq!(out[0].dir, "/data/mysql", "相对路径以 datadir 为基准");
        assert_eq!(out[0].evidence, "config_file");
    }

    #[test]
    fn mysql_prefers_an_explicit_defaults_file() {
        let argv = args(&["mysqld", "--defaults-file=/etc/custom.cnf"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = |path: &str| match path {
            "/etc/custom.cnf" => Some("[mysqld]\nlog-error=/srv/mysql/error.log\n".to_string()),
            "/etc/my.cnf" => Some("[mysqld]\nlog-error=/wrong/error.log\n".to_string()),
            _ => None,
        };
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = mysql_candidates(&ev);
        assert_eq!(out[0].dir, "/srv/mysql");
    }

    // ── Redis ──

    #[test]
    fn redis_reads_logfile_from_its_config_file() {
        let argv = args(&["redis-server", "/etc/redis/redis.conf"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = |path: &str| {
            (path == "/etc/redis/redis.conf")
                .then(|| "# comment\nlogfile \"/data/redis/redis.log\"\n".to_string())
        };
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = redis_candidates(&ev);
        assert_eq!(out[0].dir, "/data/redis");
        assert_eq!(out[0].evidence, "config_file");
    }

    #[test]
    fn redis_config_supports_relative_logfiles_via_cwd() {
        let argv = args(&["redis-server", "redis.conf"]);
        let environ = args(&[]);
        let files = Vec::new();
        // 配置文件相对 cwd 解析；`logfile ./logs/x.log` 也相对 cwd。
        let read = |path: &str| {
            (path == "/srv/redis/redis.conf").then(|| "logfile ./logs/x.log\n".to_string())
        };
        let ev = evidence(&argv, &environ, Some("/srv/redis"), &files, &read);
        let out = redis_candidates(&ev);
        assert_eq!(out[0].dir, "/srv/redis/logs");
        assert_eq!(out[0].evidence, "config_file");
    }

    #[test]
    fn redis_to_stdout_is_not_a_directory() {
        // `logfile ""` = 写 stdout：没有目录可采。
        let argv = args(&["redis-server", "/etc/redis/redis.conf"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = |_: &str| Some("logfile \"\"\n".to_string());
        let ev = evidence(&argv, &environ, None, &files, &read);
        assert!(redis_candidates(&ev).is_empty());
    }

    // ── MongoDB ──

    #[test]
    fn mongod_reads_logpath_from_the_command_line() {
        let argv = args(&[
            "mongod",
            "--dbpath",
            "/data/mongo",
            "--logpath",
            "/var/log/mongo/mongod.log",
        ]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = no_files();
        let ev = evidence(&argv, &environ, None, &files, &read);
        let out = mongod_candidates(&ev);
        assert_eq!(out[0].dir, "/var/log/mongo");
        assert_eq!(out[0].evidence, "cmdline_logfile");
        // 其次才是 `<dbpath>/log`。
        assert_eq!(out[1].dir, "/data/mongo/log");
    }

    #[test]
    fn mongod_reads_the_yaml_subset() {
        let argv = args(&["mongod", "--config", "/etc/mongod.conf"]);
        let environ = args(&[]);
        let files = Vec::new();
        let read = |path: &str| {
            (path == "/etc/mongod.conf").then(|| {
                "storage:\n  dbPath: /data/mongo\nsystemLog:\n  destination: file\n  path: /var/log/mongo/mongod.log\n".to_string()
            })
        };
        let ev = evidence(&argv, &environ, Some("/"), &files, &read);
        let out = mongod_candidates(&ev);
        assert_eq!(out[0].dir, "/var/log/mongo");
        assert_eq!(out[0].evidence, "config_file");
        assert!(out.iter().any(|proposal| proposal.dir == "/data/mongo/log"));
    }

    #[test]
    fn mongod_config_without_the_keys_is_harmless() {
        let (log, db) = mongod_config("# only comments\nnet:\n  port: 27017\n");
        assert!(log.is_none());
        assert!(db.is_none());
    }

    /// 任何规则都不许自己造证据词 —— 词表外一个值就会被网关逐条丢掉。
    #[test]
    fn every_rule_only_emits_values_from_the_shared_vocabulary() {
        // 一份“什么都给了”的证据：四个规则各取所需，都能落到候选分支。
        let argv = args(&[
            "daemon",
            "--datadir=/data/d",
            "--log-error=/data/d/err.log",
            "--dbpath=/data/d",
            "--logpath=/data/d/mongod.log",
            "--logfile=/data/d/redis.log",
            "/etc/app.conf",
        ]);
        let environ = args(&["PGDATA=/data/d"]);
        let files = args(&["/data/d/open.log"]);
        let read = |_: &str| Some(String::new());
        let ev = evidence(&argv, &environ, Some("/data"), &files, &read);
        for rule in RULES {
            for proposal in (rule.candidates)(&ev) {
                assert!(
                    EVIDENCE_VALUES.contains(&proposal.evidence),
                    "{} 产出了词表外的证据 {:?}",
                    rule.service,
                    proposal.evidence
                );
            }
        }
    }
}
