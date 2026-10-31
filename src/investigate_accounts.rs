//! 账号与授权（`wist-agentd investigate accounts`）：**谁能在本机登录、谁能提权**。
//!
//! 为什么这题必须由主机自己答：登录/提权**事件**在采集面（`LoginSession` / `PrivilegeExecution`），
//! 但"现在这台机器允许谁进来"是**状态**，事件流永远答不了。它也解释不了"为什么这条事件不存在"——
//! 而账号配置正是那类"没人再检查过"的东西。
//!
//! 四条刻意划死的边界：
//!
//! 1. **只读、只 stat / 只读小文件**：不 exec（不跑 `sshd -T`、不调 `dscl`、不跑 `sudo -l`），
//!    不碰网络，不写盘。
//! 2. **永不回传正文**：口令只分类成 `none` / `locked` / `set`，哈希不出现；`authorized_keys`
//!    只给条数与类型，密钥正文不出现；`sudoers` 只给归一化后的规则行。出口还有
//!    `investigate_safety` 的整值替换兜底（策略见 `investigation/redaction-policy.toml`）。
//! 3. **读不到 = `unknown`**：非 root 时 `/etc/shadow` 与 `sudoers` 读不到，那两节必须
//!    如实说"无法判定"，**不能**显示成"正常"（安全题的假阴性就是这么来的）。
//! 4. **平台先只做 Linux**：macOS 的用户库是 DirectoryService（`dscl` + TCC），
//!    要走"只读查询命令白名单"那条讨论，不在这版里假装支持。
//!
//! 五节：`accounts.uids` / `.passwords` / `.sudoers` / `.keys` / `.ssh`。

use std::collections::{BTreeMap, BTreeSet, HashSet};
use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{Finding, InvestigateRequest, Row};
use crate::investigate_probe::{RECENT_DAYS, Tally, age_days, metadata_of, truncate_rows};

/// 单个 `authorized_keys` 最多读多少条（再多就截断并说明）。
const MAX_KEY_ENTRIES: usize = 200;
/// 单个 `authorized_keys` 的文件大小上限：超过就不读（避免把一份异常大的文件拖进内存）。
const MAX_KEY_FILE_BYTES: u64 = 1 << 20;
/// `Include` 递归深度上限（sshd_config 正常只有一层）。
const MAX_INCLUDE_DEPTH: usize = 8;
/// 系统账号的 uid 上界（Debian / RHEL 都在 1000 以下；高于它的当普通账号）。
const SYSTEM_UID_MAX: u32 = 1000;

pub(crate) fn investigate(
    request: &InvestigateRequest,
    _config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    if !cfg!(target_os = "linux") {
        return Err("accounts 调查暂只支持 Linux（macOS 的用户库需要只读查询命令白名单）".into());
    }
    let top = request.top;
    Ok(vec![
        uids_finding(top),
        passwords_finding(top),
        sudoers_finding(top),
        keys_finding(top),
        ssh_finding(),
    ])
}

// ---------------------------------------------------------------------------
// /etc/passwd
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct PasswdEntry {
    name: String,
    uid: u32,
    home: String,
    shell: String,
}

/// 解析 `/etc/passwd`。跳过注释与 NIS 兼容行（`+` / `-` 开头），字段坏的行直接丢。
fn parse_passwd(text: &str) -> Vec<PasswdEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('+')
            || line.starts_with('-')
        {
            continue;
        }
        let mut fields = line.split(':');
        let (
            Some(name),
            Some(_password),
            Some(uid),
            Some(_gid),
            Some(_gecos),
            Some(home),
            Some(shell),
        ) = (
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
            fields.next(),
        )
        else {
            continue;
        };
        let Ok(uid) = uid.trim().parse::<u32>() else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.push(PasswdEntry {
            name: name.to_string(),
            uid,
            home: home.trim().to_string(),
            shell: shell.trim().to_string(),
        });
    }
    out
}

/// 能交互登录的 shell。空 shell 与 `nologin` / `false` 一类都算不能登录。
fn is_login_shell(shell: &str) -> bool {
    const NON_LOGIN: &[&str] = &[
        "",
        "/bin/false",
        "/usr/bin/false",
        "/bin/true",
        "/usr/bin/true",
        "/bin/nologin",
        "/usr/bin/nologin",
        "/sbin/nologin",
        "/usr/sbin/nologin",
        "/bin/sync",
        "/sbin/sync",
        "/sbin/shutdown",
        "/sbin/halt",
    ];
    !NON_LOGIN.contains(&shell)
}

fn uids_finding(top: usize) -> Finding {
    let mut tally = Tally::default();
    let Some(text) = tally.read(Path::new("/etc/passwd")) else {
        return Finding::new(
            "accounts.uids",
            Status::Unknown,
            "账号列表无法判定",
            "读取 /etc/passwd 失败",
        )
        .coverage(tally.coverage())
        .limit("以 root 重跑才完整");
    };
    let entries = parse_passwd(&text);
    let aliases: Vec<&PasswdEntry> = entries
        .iter()
        .filter(|entry| entry.uid == 0 && entry.name != "root")
        .collect();
    let system_shells: Vec<&PasswdEntry> = entries
        .iter()
        .filter(|entry| {
            entry.uid != 0 && entry.uid < SYSTEM_UID_MAX && is_login_shell(&entry.shell)
        })
        .collect();

    let mut rows: Vec<Row> = Vec::new();
    for entry in aliases.iter().chain(system_shells.iter()) {
        let note = if entry.uid == 0 {
            "uid 0 别名（与 root 等价）".to_string()
        } else {
            format!("系统账号（uid {}）却可登录", entry.uid)
        };
        rows.push(Row::new(
            entry.name.clone(),
            format!("uid {}", entry.uid),
            note,
        ));
    }
    let (rows, omitted) = truncate_rows(rows, top);

    let (status, title) = if !aliases.is_empty() {
        (
            Status::Fail,
            format!("发现 {} 个 uid 0 别名", aliases.len()),
        )
    } else if !system_shells.is_empty() {
        (
            Status::Warn,
            format!("{} 个系统账号仍可登录", system_shells.len()),
        )
    } else {
        (Status::Ok, "账号 uid 分布正常".to_string())
    };
    let mut detail = format!(
        "共 {} 个本地账号；uid 0 别名 {} 个；系统账号带登录 shell {} 个",
        entries.len(),
        aliases.len(),
        system_shells.len()
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    let mut finding = Finding::new("accounts.uids", status, title, detail)
        .rows(rows)
        .coverage(tally.coverage());
    if !aliases.is_empty() {
        finding = finding.hint("`uid 0 别名` 等于多了一个 root：先确认它是不是基线/堡垒机留下的");
    }
    finding.limit("只看 /etc/passwd；LDAP/SSSD/NIS 提供的账号不在其中")
}

// ---------------------------------------------------------------------------
// /etc/shadow（只分类，不碰哈希）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum PasswordKind {
    /// 空口令字段：**谁都能登录**。
    None,
    /// `!` / `*` 开头：锁定或不可登录。
    Locked,
    Set,
}

fn classify_password(hash: &str) -> PasswordKind {
    if hash.is_empty() {
        PasswordKind::None
    } else if hash.starts_with('!') || hash.starts_with('*') {
        PasswordKind::Locked
    } else {
        PasswordKind::Set
    }
}

fn parse_shadow(text: &str) -> BTreeMap<String, PasswordKind> {
    let mut out = BTreeMap::new();
    for line in text.lines() {
        let line = line.trim_end();
        if line.is_empty()
            || line.starts_with('#')
            || line.starts_with('+')
            || line.starts_with('-')
        {
            continue;
        }
        let mut fields = line.split(':');
        let (Some(name), Some(hash)) = (fields.next(), fields.next()) else {
            continue;
        };
        let name = name.trim();
        if name.is_empty() {
            continue;
        }
        out.insert(name.to_string(), classify_password(hash));
    }
    out
}

fn passwords_finding(top: usize) -> Finding {
    let mut passwd_tally = Tally::default();
    let Some(passwd_text) = passwd_tally.read(Path::new("/etc/passwd")) else {
        return Finding::new(
            "accounts.passwords",
            Status::Unknown,
            "口令状态无法判定",
            "读取 /etc/passwd 失败",
        )
        .coverage(passwd_tally.coverage());
    };
    let entries = parse_passwd(&passwd_text);

    let mut tally = Tally::default();
    let Some(shadow_text) = tally.read(Path::new("/etc/shadow")) else {
        return Finding::new(
            "accounts.passwords",
            Status::Unknown,
            "口令状态无法判定",
            "读取 /etc/shadow 失败（需要 root）",
        )
        .coverage(tally.coverage())
        .limit("以 root 重跑才能看到口令是否为空");
    };
    let shadow = parse_shadow(&shadow_text);

    let mut empty: Vec<&PasswdEntry> = Vec::new();
    let mut no_record: Vec<&PasswdEntry> = Vec::new();
    let mut locked: Vec<&PasswdEntry> = Vec::new();
    let mut set: Vec<&PasswdEntry> = Vec::new();
    for entry in &entries {
        if !is_login_shell(&entry.shell) {
            continue;
        }
        match shadow.get(&entry.name) {
            Some(PasswordKind::None) => empty.push(entry),
            Some(PasswordKind::Locked) => locked.push(entry),
            Some(PasswordKind::Set) => set.push(entry),
            None => no_record.push(entry),
        }
    }

    // 行的 `value` 用**机器稳定的 token**（`none` / `no-record` / `locked` / `set`），
    // 文案放 `note`：脚本与网关按 value 判定，不靠中文字符串。
    let mut rows: Vec<Row> = Vec::new();
    for entry in &empty {
        rows.push(Row::new(entry.name.clone(), "none", "空口令字段且可登录"));
    }
    for entry in &no_record {
        rows.push(Row::new(
            entry.name.clone(),
            "no-record",
            "本机 shadow 里没有条目（可能由 LDAP/SSSD 提供）",
        ));
    }
    for entry in &locked {
        rows.push(Row::new(entry.name.clone(), "locked", "不可口令登录"));
    }
    for entry in &set {
        rows.push(Row::new(entry.name.clone(), "set", "可口令登录"));
    }
    let (rows, omitted) = truncate_rows(rows, top);

    let (status, title) = if !empty.is_empty() {
        (Status::Fail, format!("{} 个账号口令为空", empty.len()))
    } else {
        (Status::Ok, "口令状态正常".to_string())
    };
    let mut detail = format!(
        "可登录账号 {} 个：已设口令 {}、锁定 {}、空口令 {}、无本机记录 {}",
        empty.len() + no_record.len() + locked.len() + set.len(),
        set.len(),
        locked.len(),
        empty.len(),
        no_record.len()
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    let mut finding = Finding::new("accounts.passwords", status, title, detail)
        .rows(rows)
        .coverage(tally.coverage());
    if !empty.is_empty() {
        finding = finding.hint("空口令一旦配上可达的 ssh/tty 就是直接入口：先 `passwd -l <用户>`");
    }
    finding
        .limit("只分类口令状态（none/locked/set），口令哈希永不回传")
        .limit("不连认证后端：LDAP/SSSD 账号在本机 shadow 里没有记录属正常")
}

// ---------------------------------------------------------------------------
// sudoers
// ---------------------------------------------------------------------------

/// 一条能提权的 sudo 规则（已归一化，不含注释）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct SudoSpec {
    who: String,
    /// 去掉多余空白后的一句话规则（给证据表用）。
    raw: String,
    nopasswd: bool,
    all_commands: bool,
}

#[derive(Debug, Default)]
struct SudoersDoc {
    specs: Vec<SudoSpec>,
    includes: Vec<String>,
    includedirs: Vec<String>,
    /// 含别名定义的行数：别名不展开，必须作为边界说出来（否则“没有 NOPASSWD”可能是假的）。
    aliases: usize,
}

/// 解析 sudoers 文本。只做**词法级**识别：不展开别名、不做主机/命令匹配求值。
fn parse_sudoers(text: &str) -> SudoersDoc {
    let mut doc = SudoersDoc::default();
    let mut joined = String::new();
    for line in text.lines() {
        let line = line.trim_end();
        if joined.is_empty() {
            let trimmed = line.trim_start();
            if let Some(path) = directive_arg(trimmed, "#includedir")
                .or_else(|| directive_arg(trimmed, "@includedir"))
            {
                doc.includedirs.push(path.to_string());
                continue;
            }
            if let Some(path) =
                directive_arg(trimmed, "#include").or_else(|| directive_arg(trimmed, "@include"))
            {
                doc.includes.push(path.to_string());
                continue;
            }
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
        }
        // 续行：行尾 `\` 拼下一行（sudoers(5) 的规矩）。
        let continued = line.ends_with('\\');
        let piece = line.trim_end_matches('\\').trim();
        if !joined.is_empty() {
            joined.push(' ');
        }
        joined.push_str(piece);
        if continued {
            continue;
        }
        let statement = std::mem::take(&mut joined);
        parse_sudo_statement(&statement, &mut doc);
    }
    doc
}

/// 取 `#include <path>` 这类指令的参数。
///
/// 必须**要求关键字后跟空白**，否则 `#includedir` 会被 `#include` 前缀吃掉 ——
/// 这是实现时实际踩到的坑（单测钉住）。
fn directive_arg<'a>(line: &'a str, keyword: &str) -> Option<&'a str> {
    let rest = line.strip_prefix(keyword)?;
    if !rest.starts_with(char::is_whitespace) {
        return None;
    }
    let arg = rest.trim();
    (!arg.is_empty()).then_some(arg)
}

fn parse_sudo_statement(statement: &str, doc: &mut SudoersDoc) {
    let Some((left, right)) = statement.split_once('=') else {
        return;
    };
    let left = left.trim();
    if left.starts_with("Defaults")
        || left.starts_with("User_Alias")
        || left.starts_with("Runas_Alias")
        || left.starts_with("Host_Alias")
        || left.starts_with("Cmnd_Alias")
    {
        if left.contains("_Alias") {
            doc.aliases += 1;
        }
        return;
    }
    let Some(who) = left.split_whitespace().next() else {
        return;
    };
    let mut right = right.trim();
    // `(runas)` 部分不参与判定，但要从命令列表里去掉。
    if right.starts_with('(')
        && let Some(close) = right.find(')')
    {
        right = right[close + 1..].trim();
    }
    let nopasswd = right.to_ascii_uppercase().contains("NOPASSWD:");
    // `NOPASSWD:` / `PASSWD:` 之类的标签去掉后再看命令。
    let commands = right
        .split(',')
        .map(|item| item.trim())
        .map(|item| {
            item.rsplit_once(':')
                .map(|(_, command)| command.trim())
                .unwrap_or(item)
        })
        .collect::<Vec<_>>();
    let all_commands = commands.iter().any(|command| {
        let command = command.to_ascii_uppercase();
        command == "ALL" || command.starts_with("ALL ")
    });
    let raw = statement.split_whitespace().collect::<Vec<_>>().join(" ");
    doc.specs.push(SudoSpec {
        who: who.to_string(),
        raw,
        nopasswd,
        all_commands,
    });
}

fn sudoers_finding(top: usize) -> Finding {
    let mut tally = Tally::default();
    let Some(main_text) = tally.read(Path::new("/etc/sudoers")) else {
        // 不存在（未装 sudo）与读不到（非 root 的 0440）是两件事。
        let status = if Path::new("/etc/sudoers").exists() {
            Status::Unknown
        } else {
            Status::Ok
        };
        let detail = if Path::new("/etc/sudoers").exists() {
            "读取 /etc/sudoers 失败（需要 root）"
        } else {
            "未发现 /etc/sudoers（可能未安装 sudo）"
        };
        let mut finding = Finding::new("accounts.sudoers", status, "sudo 授权无法判定", detail)
            .coverage(tally.coverage());
        if status == Status::Unknown {
            finding = finding.limit("以 root 重跑才能看到 sudo 授权");
        }
        return finding;
    };

    let merged = expand_sudoers(&main_text, &mut FsSudoersReader { tally: &mut tally });

    let risky: Vec<&SudoSpec> = merged
        .specs
        .iter()
        .filter(|spec| spec.nopasswd && spec.all_commands && spec.who != "root")
        .collect();
    let all_specs: Vec<&SudoSpec> = merged
        .specs
        .iter()
        .filter(|spec| spec.all_commands)
        .collect();

    let mut rows: Vec<Row> = Vec::new();
    for spec in &risky {
        rows.push(Row::new(
            spec.raw.clone(),
            "NOPASSWD: ALL",
            "无需口令即可提权",
        ));
    }
    for spec in all_specs
        .iter()
        .filter(|spec| !risky.iter().any(|r| std::ptr::eq(*r, **spec)))
    {
        rows.push(Row::new(spec.raw.clone(), "ALL", "证据"));
    }
    let (rows, omitted) = truncate_rows(rows, top);

    let (status, title) = if !risky.is_empty() {
        (
            Status::Warn,
            format!("{} 条 NOPASSWD: ALL 授权", risky.len()),
        )
    } else {
        (Status::Ok, "未发现 NOPASSWD 全权授权".to_string())
    };
    let mut detail = format!(
        "规则 {} 条；全权（ALL）{} 条；NOPASSWD 全权 {} 条",
        merged.specs.len(),
        all_specs.len(),
        risky.len()
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    let mut finding = Finding::new("accounts.sudoers", status, title, detail)
        .rows(rows)
        .coverage(tally.coverage());
    if !risky.is_empty() {
        finding = finding.hint("NOPASSWD: ALL 等于把这台机器的 root 交给该用户：确认是否必须");
    }
    if merged.aliases > 0 {
        finding = finding.limit(format!(
            "含 {} 行别名（User_Alias/Cmnd_Alias）未展开，“没有全权授权”可能是下界",
            merged.aliases
        ));
    }
    finding
}

fn merge_sudoers(into: &mut SudoersDoc, from: SudoersDoc) {
    into.specs.extend(from.specs);
    into.includes.extend(from.includes);
    into.includedirs.extend(from.includedirs);
    into.aliases += from.aliases;
}

/// 读 sudoers 的依赖（`#include` 文件、`#includedir` 目录）。
///
/// 抽成 trait 的目的：**嵌套 include**（sudoers.d 里的文件再 include 另一个文件）
/// 必须用工作队列展开，而队列逻辑要能在不碰真实文件的前提下被测试。
trait SudoersReader {
    fn read(&mut self, path: &str) -> Option<String>;
    fn list(&mut self, dir: &str) -> Vec<String>;
}

struct FsSudoersReader<'a> {
    tally: &'a mut Tally,
}

impl SudoersReader for FsSudoersReader<'_> {
    fn read(&mut self, path: &str) -> Option<String> {
        self.tally.read(Path::new(path))
    }

    fn list(&mut self, dir: &str) -> Vec<String> {
        let Some(entries) = self.tally.list(Path::new(dir)) else {
            return Vec::new();
        };
        let mut files: Vec<String> = entries
            .into_iter()
            .filter(|path| {
                // sudo 忽略带 `.` 的文件名与 `~` 备份（sudoers(5)）。
                let name = path
                    .file_name()
                    .map(|name| name.to_string_lossy().to_string())
                    .unwrap_or_default();
                !name.contains('.') && !name.ends_with('~')
            })
            .map(|path| path.display().to_string())
            .collect();
        files.sort();
        files
    }
}

/// 展开 sudoers 及其 include（多层、防环）。
///
/// `seen` 同时防两件事：同一文件被 include 两次（规则重复）与**环**
/// （`a` include `b`、`b` 又 include `a`）—— 后者会让一个只会读一次的实现永远停不下来。
fn expand_sudoers(main: &str, reader: &mut dyn SudoersReader) -> SudoersDoc {
    let mut merged = parse_sudoers(main);
    let mut pending_includes: Vec<String> = std::mem::take(&mut merged.includes);
    let mut pending_dirs: Vec<String> = std::mem::take(&mut merged.includedirs);
    let mut seen: BTreeSet<String> = BTreeSet::new();

    // 两个队列必须在**同一个循环**里交替消费：处理目录时新发现的 include 也要接着展开
    // （先跑完 include 队列、再跑目录队列的写法，会漏掉“目录里的文件又 include 别人”）。
    loop {
        if let Some(path) = pending_includes.pop() {
            if !seen.insert(format!("file:{path}")) {
                continue;
            }
            let Some(text) = reader.read(&path) else {
                continue;
            };
            let doc = parse_sudoers(&text);
            pending_includes.extend(doc.includes.iter().cloned());
            pending_dirs.extend(doc.includedirs.iter().cloned());
            merge_sudoers(&mut merged, doc);
            continue;
        }
        if let Some(dir) = pending_dirs.pop() {
            if !seen.insert(format!("dir:{dir}")) {
                continue;
            }
            for file in reader.list(&dir) {
                if !seen.insert(format!("file:{file}")) {
                    continue;
                }
                let Some(text) = reader.read(&file) else {
                    continue;
                };
                let doc = parse_sudoers(&text);
                pending_includes.extend(doc.includes.iter().cloned());
                pending_dirs.extend(doc.includedirs.iter().cloned());
                merge_sudoers(&mut merged, doc);
            }
            continue;
        }
        break;
    }

    merged
}

// ---------------------------------------------------------------------------
// authorized_keys
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, PartialEq, Eq)]
struct KeyEntry {
    key_type: String,
    comment: String,
}

/// 解析一行 `authorized_keys`。**只取类型与注释，正文一概不要**。
///
/// 行首可能有一串选项（`from="…",command="…"`），所以要先跳过 `选项=值` 的 token。
fn parse_authorized_keys(text: &str) -> Vec<KeyEntry> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut tokens = line.split_whitespace();
        let mut key_type = None;
        let mut body_seen = false;
        let mut comment: Vec<&str> = Vec::new();
        for token in tokens.by_ref() {
            if !body_seen {
                if token.starts_with("ssh-")
                    || token.starts_with("ecdsa-")
                    || token.starts_with("sk-")
                {
                    key_type = Some(token.to_string());
                    body_seen = true;
                }
                // 其余是选项 token（含 `=`），继续找类型。
                continue;
            }
            if token.len() > 20
                && token
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || "+/=._-".contains(c))
            {
                // 密钥正文：**刻意丢弃**（不回传）。
                continue;
            }
            comment.push(token);
        }
        if let Some(key_type) = key_type {
            out.push(KeyEntry {
                key_type,
                comment: comment.join(" "),
            });
        }
    }
    out
}

/// 读一个 `authorized_keys`。`checked` 由“检查过的家目录数”计（见 [`keys_finding`]），
/// 所以这里只记 `denied` / `skipped`，避免同一个文件被计两次。
fn read_key_file(path: &Path, tally: &mut Tally) -> Option<String> {
    match fs::read_to_string(path) {
        Ok(text) => Some(text),
        Err(err) => {
            if err.kind() == io::ErrorKind::PermissionDenied {
                tally.denied += 1;
            } else if err.kind() != io::ErrorKind::NotFound {
                tally.skipped += 1;
            }
            None
        }
    }
}

fn keys_finding(top: usize) -> Finding {
    let mut tally = Tally::default();
    let Some(passwd_text) = tally.read(Path::new("/etc/passwd")) else {
        return Finding::new(
            "accounts.keys",
            Status::Unknown,
            "授权密钥无法判定",
            "读取 /etc/passwd 失败",
        )
        .coverage(tally.coverage());
    };
    let users = parse_passwd(&passwd_text);

    struct Summary {
        user: String,
        count: usize,
        types: BTreeSet<String>,
        recent: bool,
        symlink: bool,
    }
    let mut summaries: Vec<Summary> = Vec::new();
    let mut homes = 0usize;
    for user in &users {
        if !user.home.starts_with('/') || user.home == "/" {
            continue;
        }
        homes += 1;
        let path = Path::new(&user.home).join(".ssh/authorized_keys");
        let Some(metadata) = metadata_of(&path) else {
            // 大多数用户没有 `.ssh/authorized_keys` —— 这是常态，不是“跳过”。
            continue;
        };
        if metadata.is_symlink() {
            // 符号链接本身是证据（可以指向别处，或成为跨用户的跳板）。
            summaries.push(Summary {
                user: user.name.clone(),
                count: 0,
                types: BTreeSet::new(),
                recent: false,
                symlink: true,
            });
            tally.checked += 1;
            continue;
        }
        if metadata.len() > MAX_KEY_FILE_BYTES {
            tally.skipped += 1;
            continue;
        }
        let Some(text) = read_key_file(&path, &mut tally) else {
            continue;
        };
        let entries = parse_authorized_keys(&text);
        if entries.is_empty() {
            continue;
        }
        let recent = age_days(&metadata).is_some_and(|days| days <= RECENT_DAYS);
        summaries.push(Summary {
            user: user.name.clone(),
            count: entries.len().min(MAX_KEY_ENTRIES),
            types: entries.into_iter().map(|entry| entry.key_type).collect(),
            recent,
            symlink: false,
        });
    }

    let total: usize = summaries.iter().map(|summary| summary.count).sum();
    let recent: Vec<&Summary> = summaries.iter().filter(|summary| summary.recent).collect();
    let symlinks: Vec<&Summary> = summaries.iter().filter(|summary| summary.symlink).collect();

    let mut rows: Vec<Row> = Vec::new();
    for summary in &summaries {
        let note = if summary.symlink {
            "authorized_keys 是符号链接".to_string()
        } else if summary.recent {
            format!("近 {RECENT_DAYS} 天有变更")
        } else {
            summary.types.iter().cloned().collect::<Vec<_>>().join(", ")
        };
        let value = if summary.symlink {
            "符号链接".to_string()
        } else {
            format!("{} 条", summary.count)
        };
        rows.push(Row::new(summary.user.clone(), value, note));
    }
    let (rows, omitted) = truncate_rows(rows, top);

    let (status, title) = if !symlinks.is_empty() {
        (
            Status::Warn,
            format!("{} 个 authorized_keys 是符号链接", symlinks.len()),
        )
    } else if !recent.is_empty() {
        (
            Status::Warn,
            format!("{} 个用户近 {RECENT_DAYS} 天新增授权", recent.len()),
        )
    } else if total > 0 {
        (Status::Ok, "授权密钥已列出".to_string())
    } else {
        (Status::Ok, "未发现 authorized_keys".to_string())
    };
    let mut detail = format!(
        "{} 个用户配置了授权密钥，共 {total} 条；近 {RECENT_DAYS} 天有变更 {} 个",
        summaries.iter().filter(|summary| !summary.symlink).count(),
        recent.len()
    );
    if omitted > 0 {
        let _ =
            std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 个用户未列出"));
    }
    let mut finding = Finding::new("accounts.keys", status, title, detail)
        .rows(rows)
        .coverage(crate::investigate::Coverage::new(
            homes,
            tally.denied,
            tally.skipped,
        ));
    if !recent.is_empty() {
        finding = finding.hint("新增 key 常是合法运维，也常是后门：确认每个新 key 的来源");
    }
    finding
        .limit("只读 `~/.ssh/authorized_keys`；sshd 的自定义 AuthorizedKeysFile 未覆盖")
        .limit("密钥正文永不回传（只给类型与条数）")
        .limit("单个文件超过 200 条已截断")
}

// ---------------------------------------------------------------------------
// sshd 生效配置
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct SshdValues {
    /// 指令名（小写）→ (值, 来源文件)。
    values: BTreeMap<String, (String, String)>,
}

/// 按 sshd_config(5) 的语义求值：**首个取值生效**（不是“后者覆盖”），
/// `Include` 在原位置展开，遇到 `Match` 即停止取全局值。
///
/// 这一点很容易写反：大多数配置是“后者覆盖”，OpenSSH 恰恰相反。
/// 发行版把 `Include /etc/ssh/sshd_config.d/*.conf` 放在文件顶部，于是 drop-in 优先。
fn collect_sshd(
    path: &Path,
    values: &mut SshdValues,
    tally: &mut Tally,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
) {
    if depth > MAX_INCLUDE_DEPTH || !seen.insert(path.to_path_buf()) {
        return;
    }
    let Some(text) = tally.read(path) else {
        return;
    };
    apply_sshd_text(&text, path, values, tally, seen, depth);
}

/// 把一个 sshd 配置文件的行并入生效值。抽成独立函数是为了能直接测“首个取值生效”
/// 与“`Match` 之后停”这两条语义，不用造临时文件。
fn apply_sshd_text(
    text: &str,
    source: &Path,
    values: &mut SshdValues,
    tally: &mut Tally,
    seen: &mut HashSet<PathBuf>,
    depth: usize,
) {
    let base = source.parent().unwrap_or_else(|| Path::new("/"));
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let mut parts = line.splitn(2, char::is_whitespace);
        let Some(key) = parts.next() else { continue };
        let key = key.to_ascii_lowercase();
        let value = parts.next().unwrap_or("").trim();
        if key == "match" {
            // 之后是条件块：不属于“全局生效值”，本版不求值。
            return;
        }
        if key == "include" {
            for included in expand_include(value, base) {
                collect_sshd(&included, values, tally, seen, depth + 1);
            }
            continue;
        }
        let source = source.display().to_string();
        values
            .values
            .entry(key)
            .or_insert_with(|| (value.to_string(), source));
    }
}

/// `Include` 的路径可以是相对 `/etc/ssh` 的（sshd_config(5)）；相对路径按**当前文件所在目录**解。
fn resolve_include(pattern: &str, base: &Path) -> PathBuf {
    let path = Path::new(pattern.trim());
    if path.is_absolute() {
        path.to_path_buf()
    } else {
        base.join(path)
    }
}

/// 单星号通配（sshd/sudo 目录里的现实形态：`dir/*.conf`）。
fn glob_matches(pattern: &str, name: &str) -> bool {
    match pattern.split_once('*') {
        None => pattern == name,
        Some((prefix, suffix)) => {
            name.len() >= prefix.len() + suffix.len()
                && name.starts_with(prefix)
                && name.ends_with(suffix)
        }
    }
}

/// 展开 `Include`：只支持“目录 + 单星号”这种现实形态（如 `/etc/ssh/sshd_config.d/*.conf`）。
fn expand_include(pattern: &str, base: &Path) -> Vec<PathBuf> {
    let path = resolve_include(pattern, base);
    let path = path.as_path();
    let Some(parent) = path.parent() else {
        return Vec::new();
    };
    let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
        return Vec::new();
    };
    if !name.contains('*') {
        return vec![path.to_path_buf()];
    }
    let Ok(entries) = fs::read_dir(parent) else {
        return Vec::new();
    };
    let mut out: Vec<PathBuf> = entries
        .flatten()
        .filter(|entry| glob_matches(name, &entry.file_name().to_string_lossy()))
        .map(|entry| entry.path())
        .collect();
    out.sort();
    out
}

fn ssh_finding() -> Finding {
    let mut tally = Tally::default();
    let main = Path::new("/etc/ssh/sshd_config");
    if !main.exists() {
        // “没装 sshd”是一项**检查结果**，不是“零覆盖”：记一次 checked，
        // 否则这一节的 coverage 会因为全 0 而被省略，前端就看不出“这节到底看没看过”。
        tally.checked += 1;
        return Finding::new(
            "accounts.ssh",
            Status::Ok,
            "未安装 OpenSSH 服务端",
            "/etc/ssh/sshd_config 不存在",
        )
        .coverage(tally.coverage());
    }
    let mut values = SshdValues::default();
    let mut seen = HashSet::new();
    collect_sshd(main, &mut values, &mut tally, &mut seen, 0);
    if values.values.is_empty() {
        return Finding::new(
            "accounts.ssh",
            Status::Unknown,
            "SSH 配置无法判定",
            "读取 /etc/ssh/sshd_config 失败",
        )
        .coverage(tally.coverage())
        .limit("以 root 重跑才完整");
    }

    let lookup = |key: &str, default: &str| -> (String, String) {
        values
            .values
            .get(key)
            .cloned()
            .unwrap_or_else(|| (default.to_string(), "默认值".to_string()))
    };
    let (root_login, root_source) = lookup("permitrootlogin", "prohibit-password");
    let (passwords, password_source) = lookup("passwordauthentication", "yes");
    let (empty, empty_source) = lookup("permitemptypasswords", "no");
    let (pubkey, pubkey_source) = lookup("pubkeyauthentication", "yes");

    let root_allows_login = matches!(
        root_login.as_str(),
        "yes" | "without-password" | "prohibit-password"
    );
    let (status, title) = if empty.eq_ignore_ascii_case("yes") {
        (Status::Fail, "允许空口令登录".to_string())
    } else if root_login.eq_ignore_ascii_case("yes") {
        (Status::Warn, "允许 root 直接登录".to_string())
    } else {
        (Status::Ok, "SSH 登录策略未发现高风险项".to_string())
    };

    let rows = vec![
        Row::new("PermitRootLogin", root_login.clone(), root_source),
        Row::new("PasswordAuthentication", passwords.clone(), password_source),
        Row::new("PermitEmptyPasswords", empty.clone(), empty_source),
        Row::new("PubkeyAuthentication", pubkey, pubkey_source),
    ];
    let detail = format!(
        "root 登录：{}；口令登录：{}；空口令：{}",
        root_login, passwords, empty
    );
    let mut finding = Finding::new("accounts.ssh", status, title, detail)
        .rows(rows)
        .coverage(tally.coverage());
    if root_allows_login && root_login.eq_ignore_ascii_case("yes") {
        finding = finding.limit("root 直接登录 + 口令登录同时开启时，暴力破解就是直达 root 的路径");
    }
    if status == Status::Fail {
        finding = finding.hint("空口令 + 可达的 22 端口 = 直接接管：先 `PermitEmptyPasswords no`");
    }
    finding
        .limit("按 sshd_config(5) 的“首个取值生效”求值；`Match` 块未求值")
        .limit("不 exec `sshd -T`：运行时生效值可能被命令行参数覆盖")
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn passwd_parsing_skips_comments_and_nis_lines() {
        let text = "# comment\n+\n-\nroot:x:0:0:root:/root:/bin/bash\ndaemon:x:1:1::/usr/sbin:/usr/sbin/nologin\n";
        let entries = parse_passwd(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].name, "root");
        assert_eq!(entries[0].uid, 0);
        assert!(is_login_shell(&entries[0].shell));
        assert!(!is_login_shell(&entries[1].shell));
    }

    #[test]
    fn password_classification_never_needs_the_hash() {
        assert_eq!(classify_password(""), PasswordKind::None);
        assert_eq!(classify_password("!"), PasswordKind::Locked);
        assert_eq!(classify_password("*"), PasswordKind::Locked);
        assert_eq!(
            classify_password("$6$abcdefgh$0123456789abcdefghijklmnopqrstuvwxyz"),
            PasswordKind::Set
        );
    }

    #[test]
    fn shadow_lines_map_to_kinds() {
        let shadow = parse_shadow(
            "root:$6$abcdefgh$0123:19000:0:99999:7:::\n\
             empty::19000:0:99999:7:::\n\
             locked:!$6$abcdefgh$0123:19000:0:99999:7:::\n",
        );
        assert_eq!(shadow["root"], PasswordKind::Set);
        assert_eq!(shadow["empty"], PasswordKind::None);
        assert_eq!(shadow["locked"], PasswordKind::Locked);
    }

    #[test]
    fn non_login_shells_are_recognised() {
        for shell in [
            "",
            "/bin/false",
            "/usr/bin/false",
            "/bin/nologin",
            "/usr/sbin/nologin",
            "/sbin/nologin",
            "/bin/sync",
        ] {
            assert!(!is_login_shell(shell), "{shell} 不应算可登录 shell");
        }
        for shell in ["/bin/bash", "/bin/zsh", "/usr/bin/fish"] {
            assert!(is_login_shell(shell), "{shell} 应算可登录 shell");
        }
    }

    #[test]
    fn sudoers_finds_nopasswd_all_but_not_plain_all() {
        let doc = parse_sudoers(
            "Defaults env_reset\n\
             User_Alias OPS = alice\n\
             deploy ALL=(ALL) NOPASSWD: ALL\n\
             alice ALL=(ALL) /usr/bin/systemctl\n\
             %wheel ALL=(ALL) ALL\n",
        );
        assert_eq!(doc.aliases, 1);
        let risky: Vec<&SudoSpec> = doc
            .specs
            .iter()
            .filter(|spec| spec.nopasswd && spec.all_commands)
            .collect();
        assert_eq!(risky.len(), 1);
        assert_eq!(risky[0].who, "deploy");
        // `%wheel ALL=(ALL) ALL` 是全权但不需要口令 —— 不算 NOPASSWD。
        assert_eq!(doc.specs.iter().filter(|spec| spec.all_commands).count(), 2);
    }

    #[test]
    fn sudoers_honours_line_continuations_and_includes() {
        let doc = parse_sudoers(
            "#includedir /etc/sudoers.d\n\
             deploy ALL=(ALL) \\\n   NOPASSWD: ALL\n",
        );
        assert_eq!(doc.includedirs, vec!["/etc/sudoers.d".to_string()]);
        assert_eq!(doc.specs.len(), 1);
        assert!(doc.specs[0].nopasswd && doc.specs[0].all_commands);
    }

    #[test]
    fn authorized_keys_parsing_drops_the_body_but_keeps_type_and_comment() {
        let text = "# comment\n\
                    ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIOMqqnkVzrm0SdG6UOoqKLsabgH5C9okWi0dh2l9GKJl dev@laptop\n\
                    from=\"10.0.0.0/8\",command=\"/bin/true\" ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQ== ops@jump\n";
        let entries = parse_authorized_keys(text);
        assert_eq!(entries.len(), 2);
        assert_eq!(entries[0].key_type, "ssh-ed25519");
        assert_eq!(entries[0].comment, "dev@laptop");
        assert_eq!(entries[1].key_type, "ssh-rsa");
        assert_eq!(entries[1].comment, "ops@jump");
        // 正文永远不进结构。
        assert!(!format!("{entries:?}").contains("AAAAC3NzaC1lZDI1NTE5"));
    }

    #[test]
    fn sshd_first_value_wins_and_match_stops_the_global_scope() {
        let mut values = SshdValues::default();
        let mut tally = Tally::default();
        let mut seen = HashSet::new();
        let text = "PermitRootLogin no\n\
                    PermitRootLogin yes\n\
                    Match User backup\n\
                    PermitRootLogin yes\n";
        apply_sshd_text(
            text,
            Path::new("/etc/ssh/sshd_config"),
            &mut values,
            &mut tally,
            &mut seen,
            0,
        );
        // 首个取值生效（不是“后者覆盖”），Match 之后的 `yes` 不算全局值。
        assert_eq!(values.values["permitrootlogin"].0, "no");
        assert_eq!(values.values["permitrootlogin"].1, "/etc/ssh/sshd_config");
    }

    #[test]
    fn sshd_relative_include_is_resolved_from_the_config_dir() {
        assert_eq!(
            resolve_include("sshd_config.d/*.conf", Path::new("/etc/ssh")),
            PathBuf::from("/etc/ssh/sshd_config.d/*.conf")
        );
        assert_eq!(
            resolve_include("/etc/ssh/sshd_config.d/*.conf", Path::new("/etc/ssh")),
            PathBuf::from("/etc/ssh/sshd_config.d/*.conf")
        );
    }

    #[test]
    fn sshd_reports_the_default_when_nothing_is_configured() {
        let mut values = SshdValues::default();
        let mut tally = Tally::default();
        let mut seen = HashSet::new();
        apply_sshd_text(
            "# empty\n",
            Path::new("/etc/ssh/sshd_config"),
            &mut values,
            &mut tally,
            &mut seen,
            0,
        );
        assert!(values.values.is_empty());
    }

    struct MapReader {
        files: BTreeMap<String, String>,
        dirs: BTreeMap<String, Vec<String>>,
    }

    impl SudoersReader for MapReader {
        fn read(&mut self, path: &str) -> Option<String> {
            self.files.get(path).cloned()
        }

        fn list(&mut self, dir: &str) -> Vec<String> {
            self.dirs.get(dir).cloned().unwrap_or_default()
        }
    }

    #[test]
    fn sudoers_expands_nested_includes_and_survives_cycles() {
        let mut files = BTreeMap::new();
        files.insert(
            "/etc/sudoers.d/10-a".to_string(),
            "#include /etc/sudoers.d/20-b\n".to_string(),
        );
        files.insert(
            "/etc/sudoers.d/20-b".to_string(),
            "deploy ALL=(ALL) NOPASSWD: ALL\n#include /etc/sudoers.d/10-a\n".to_string(),
        );
        let mut dirs = BTreeMap::new();
        dirs.insert(
            "/etc/sudoers.d".to_string(),
            vec!["/etc/sudoers.d/10-a".to_string()],
        );
        let mut reader = MapReader { files, dirs };
        let doc = expand_sudoers("#includedir /etc/sudoers.d\n", &mut reader);
        assert!(
            doc.specs
                .iter()
                .any(|spec| spec.who == "deploy" && spec.nopasswd && spec.all_commands),
            "嵌套 include 里的规则必须被展开: {:?}",
            doc.specs
        );
    }

    #[test]
    fn include_globs_match_one_star() {
        assert!(glob_matches("*.conf", "10-hardening.conf"));
        assert!(glob_matches("sshd_config.d_*", "sshd_config.d_50"));
        assert!(!glob_matches("*.conf", "10-hardening.conf.disabled"));
        assert!(!glob_matches("*.conf", "10-hardening"));
    }
}
