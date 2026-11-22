//! `service.status`：单元（unit）状态的**只读**查询。v1 只支持 Linux / systemd。
//!
//! 与 `investigate_persistence` 同一条纪律：**不 exec `systemctl`、不走 D-Bus**。
//! 因此「能答什么」与「答不了什么」必须分清楚：
//!
//! 能如实回答：
//!
//! 1. 单元文件在哪（本地 `/etc` / 生成 `/run` / 打包 `/usr/lib`），以及 `Description=`；
//! 2. 是否被某个 target 的 `.wants` / `.requires` 链接启用；是否 masked（→ `/dev/null`）；
//! 3. 当前有没有进程归属到它（cgroup 口径，与 `process.list` / `load` 同一份数据）。
//!
//! **答不了**：systemd 自己的 `ActiveState` / `SubState` / `NRestarts` / `ExecMainPID`
//! —— 那些只存在于 systemd 守护进程的内存里。所以 `state` 只有三种值：
//! `running` / `no_process_observed` / `unknown`，并用 `state_source` 写明口径。
//! **绝不**把「没看到进程」写成 `inactive` 或 `failed`：oneshot、socket 激活、
//! 正在重试这三种情况下那句话都是错的。
//!
//! `enabled` 的含义也要看清：它只表示「被某个 target 的 `.wants`/`.requires` 链接」。
//! 静态单元（没有 `[Install]` 段）天然是 `false`，那不代表它有问题。

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::{Value, json};
use wist_contracts::action_plan::RiskLevel;

use super::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};
use crate::investigate_load::{self, ProcessSample};

const SCHEMA: &str = "wist.opcode.service_status/v1";
const DEFAULT_LIMIT: usize = 20;
const MAX_LIMIT: usize = 200;
const MAX_PIDS: usize = 20;
const MAX_ENABLED_BY: usize = 10;
const MAX_NAME_CHARS: usize = 128;
/// 单元文件只用来取 `Description=`：超过这个大小就说明它不像单元文件。
const MAX_UNIT_FILE_BYTES: u64 = 64 * 1024;
/// 每个目录最多看多少条目（`/usr/lib/systemd/system` 正常也就几百个）。
const MAX_DIR_ENTRIES: usize = 10_000;

/// 单元文件的搜索顺序：**先本地，再生成，再打包**（与 systemd 的优先级一致，先命中者胜）。
const UNIT_DIRS: &[&str] = &[
    "/etc/systemd/system",
    "/run/systemd/system",
    "/usr/lib/systemd/system",
    "/lib/systemd/system",
];

/// v1 不支持的 unit 类型：明确拒绝，而不是拼成 `foo.socket.service` 去猜。
const OTHER_SUFFIXES: &[&str] = &[
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

pub const STATUS_SPEC: OpSpec = OpSpec {
    id: "service.status",
    risk: RiskLevel::R0,
    platforms: &["linux"],
    budget: OpBudget::new(3_000, MAX_LIMIT, 0),
    handler: status,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatusArgs {
    /// 单元名：`nginx` 或 `nginx.service`。缺省 = 列出全部（受 `limit` 限）。
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    limit: Option<usize>,
}

fn invalid(detail: impl Into<String>) -> OpError {
    OpError::new(codes::INVALID_ARGS, detail)
}

/// 把 `name` 规范成 `<unit>.service`。
fn normalized_unit(name: &str) -> Result<String, OpError> {
    let name = name.trim();
    if name.is_empty() {
        return Err(invalid("name 不能为空（省略 name 表示看全部）"));
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(invalid(format!("name 超过 {MAX_NAME_CHARS} 个字符")));
    }
    if name.contains('/') || name.chars().any(char::is_whitespace) {
        return Err(invalid(format!("name 不是合法单元名：`{name}`")));
    }
    if name.ends_with(".service") {
        return Ok(name.to_string());
    }
    if let Some(suffix) = OTHER_SUFFIXES.iter().find(|suffix| name.ends_with(*suffix)) {
        return Err(OpError::new(
            codes::UNSUPPORTED_TARGET,
            format!("v1 只看 `.service`，收到 `{name}`（{suffix}）"),
        ));
    }
    // `php8.1` 这种带点的裸名字也要拼 `.service`，所以只认「后缀」不认「有没有点」。
    Ok(format!("{name}.service"))
}

#[derive(Debug, Clone)]
struct UnitFile {
    path: PathBuf,
    origin: &'static str,
    masked: bool,
}

fn is_dev_null(link: &Path) -> bool {
    fs::read_link(link).is_ok_and(|target| target == Path::new("/dev/null"))
}

fn file_name(path: &Path) -> String {
    path.file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_default()
}

/// 扫一遍单元目录，得到 `单元名 → 文件位置`。先命中的目录胜出。
///
/// 返回 `(单元表, 可读目录数)`：一个目录都读不到时必须让调用方报错，
/// 否则「没找到」会变成一句假话。
fn discover_units(dirs: &[PathBuf]) -> (BTreeMap<String, UnitFile>, usize) {
    let mut units: BTreeMap<String, UnitFile> = BTreeMap::new();
    let mut readable = 0usize;
    for (index, dir) in dirs.iter().enumerate() {
        let origin = match index {
            0 => "local",
            1 => "generated",
            _ => "packaged",
        };
        let Ok(entries) = fs::read_dir(dir) else {
            continue;
        };
        readable += 1;
        for (seen, entry) in entries.flatten().enumerate() {
            if seen >= MAX_DIR_ENTRIES {
                break;
            }
            let name = file_name(&entry.path());
            if !name.ends_with(".service") {
                continue;
            }
            let Ok(meta) = fs::symlink_metadata(entry.path()) else {
                continue;
            };
            if meta.is_dir() {
                continue;
            }
            let masked = meta.file_type().is_symlink() && is_dev_null(&entry.path());
            units.entry(name).or_insert(UnitFile {
                path: entry.path(),
                origin,
                masked,
            });
        }
    }
    (units, readable)
}

/// `单元名 → 启用它的 target`。enable 的证据就是 `<local>/<target>.wants/<unit>` 链接。
fn enabled_units(local: &Path) -> BTreeMap<String, BTreeSet<String>> {
    let mut enabled: BTreeMap<String, BTreeSet<String>> = BTreeMap::new();
    let Ok(entries) = fs::read_dir(local) else {
        return enabled;
    };
    for (seen, entry) in entries.flatten().enumerate() {
        if seen >= MAX_DIR_ENTRIES {
            break;
        }
        let dir_name = file_name(&entry.path());
        let target = dir_name
            .strip_suffix(".wants")
            .or_else(|| dir_name.strip_suffix(".requires"));
        let Some(target) = target else {
            continue;
        };
        let Ok(links) = fs::read_dir(entry.path()) else {
            continue;
        };
        for link in links.flatten() {
            let unit = file_name(&link.path());
            if unit.ends_with(".service") {
                enabled.entry(unit).or_default().insert(target.to_string());
            }
        }
    }
    enabled
}

/// `[Unit]` 段的 `Description=`。读不到就是 `None`（不编一个）。
fn description_of(path: &Path) -> Option<String> {
    let meta = fs::metadata(path).ok()?;
    if !meta.is_file() || meta.len() > MAX_UNIT_FILE_BYTES {
        return None;
    }
    let text = fs::read_to_string(path).ok()?;
    let mut in_unit = false;
    for line in text.lines() {
        let line = line.trim();
        if line.starts_with('[') {
            in_unit = line.eq_ignore_ascii_case("[Unit]");
            continue;
        }
        if in_unit && let Some(value) = line.strip_prefix("Description=") {
            let value = value.trim();
            if value.is_empty() {
                return None;
            }
            return Some(value.chars().take(200).collect());
        }
    }
    None
}

/// cgroup 口径的进程归属。
#[derive(Debug, Default)]
struct Attribution {
    /// 本机能不能做归属（有进程的 `service_source == "cgroup"`）。
    available: bool,
    by_unit: BTreeMap<String, UnitStat>,
}

#[derive(Debug, Default)]
struct UnitStat {
    count: usize,
    rss: u64,
    pids: Vec<u32>,
}

impl Attribution {
    fn from_samples(samples: &[ProcessSample]) -> Self {
        let mut out = Self::default();
        for sample in samples {
            if sample.service_source != "cgroup" || !sample.service.ends_with(".service") {
                continue;
            }
            out.available = true;
            let stat = out.by_unit.entry(sample.service.clone()).or_default();
            stat.count += 1;
            stat.rss = stat.rss.saturating_add(sample.rss);
            stat.pids.push(sample.pid);
        }
        for stat in out.by_unit.values_mut() {
            stat.pids.sort_unstable();
            stat.pids.truncate(MAX_PIDS);
        }
        out
    }

    fn state_of(&self, unit: &str) -> (&'static str, Option<&UnitStat>) {
        if !self.available {
            return ("unknown", None);
        }
        match self.by_unit.get(unit) {
            Some(stat) if stat.count > 0 => ("running", Some(stat)),
            _ => ("no_process_observed", None),
        }
    }
}

fn unit_row(
    name: &str,
    file: Option<&UnitFile>,
    enabled_by: &BTreeSet<String>,
    who: &Attribution,
) -> Value {
    let (state, stat) = who.state_of(name);
    let mut targets: Vec<&String> = enabled_by.iter().collect();
    targets.truncate(MAX_ENABLED_BY);
    let fragment = file.map(|file| {
        json!({
            "path": file.path.display().to_string(),
            "origin": file.origin,
            "masked": file.masked,
            "description": description_of(&file.path),
        })
    });
    json!({
        "name": name,
        "fragment": fragment,
        "enabled": !enabled_by.is_empty(),
        "enabled_by": targets,
        "state": state,
        "state_source": if who.available { "cgroup" } else { "unavailable" },
        "process_count": stat.map(|stat| stat.count).unwrap_or(0),
        "rss_bytes": stat.map(|stat| stat.rss).unwrap_or(0),
        "pids": stat.map(|stat| stat.pids.clone()).unwrap_or_default(),
    })
}

fn default_dirs() -> Vec<PathBuf> {
    UNIT_DIRS.iter().map(PathBuf::from).collect()
}

fn status(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: StatusArgs = parse_args(input.args)?;
    let limit = args
        .limit
        .unwrap_or(DEFAULT_LIMIT)
        .clamp(1, input.budget.max_items.clamp(1, MAX_LIMIT));
    let samples = investigate_load::snapshot_processes_once(None)
        .map_err(|detail| OpError::new(codes::OP_FAILED, detail))?;
    let who = Attribution::from_samples(&samples);
    let value = inspect(&default_dirs(), &args, limit, &who)?;
    Ok(OpOutput { value })
}

/// 纯逻辑：目录与进程归属都由调用方给（单测因此不依赖本机是不是 systemd 主机）。
///
/// `limit` 已由调用方按预算解析好（`args.limit` 在这里**不再读**）：
/// 两个地方各算一次很容易分叉，尤其是预算被注册表调小的时候。
fn inspect(
    dirs: &[PathBuf],
    args: &StatusArgs,
    limit: usize,
    who: &Attribution,
) -> Result<Value, OpError> {
    let (units, readable_dirs) = discover_units(dirs);
    if readable_dirs == 0 {
        return Err(OpError::new(
            codes::OP_FAILED,
            format!("读不到任何 systemd 单元目录（{UNIT_DIRS:?}）；本机可能不是 systemd 主机"),
        ));
    }
    let enabled = dirs
        .first()
        .map(|local| enabled_units(local))
        .unwrap_or_default();

    let queried = match args.name.as_deref() {
        Some(raw) => Some(normalized_unit(raw)?),
        None => None,
    };

    let (names, total): (Vec<String>, usize) = match &queried {
        Some(unit) => {
            if !units.contains_key(unit) && !who.by_unit.contains_key(unit) {
                return Err(OpError::new(
                    codes::TARGET_NOT_FOUND,
                    format!(
                        "本机没有单元 `{unit}`：{UNIT_DIRS:?} 里都没有这个文件，也没有进程归属到它"
                    ),
                ));
            }
            (vec![unit.clone()], 1)
        }
        None => {
            // 单元表 ∪ 启用链接 ∪ 进程归属：三处都算「这台机器上存在的单元」。
            let mut all: BTreeSet<String> = units.keys().cloned().collect();
            all.extend(enabled.keys().cloned());
            all.extend(who.by_unit.keys().cloned());
            let all: Vec<String> = all.into_iter().collect();
            let total = all.len();
            (all, total)
        }
    };

    let rows: Vec<Value> = names
        .iter()
        .take(limit)
        .map(|unit| {
            unit_row(
                unit,
                units.get(unit),
                enabled.get(unit).unwrap_or(&BTreeSet::new()),
                who,
            )
        })
        .collect();

    let mut notes: Vec<&str> = Vec::new();
    if !who.available {
        notes.push("cgroup 归属不可用：state 只能是 unknown（不是「没在跑」）");
    }
    notes.push("enabled 只看 .wants/.requires 链接；静态单元天然为 false");

    Ok(json!({
        "schema": SCHEMA,
        "manager": "systemd",
        "state_source": if who.available { "unit_file+cgroup" } else { "unit_file" },
        "queried_name": queried,
        "units": rows,
        "total": total,
        "returned": rows.len(),
        "truncated": total > rows.len(),
        "limits": { "pids_per_unit": MAX_PIDS, "enabled_by": MAX_ENABLED_BY },
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
        let dir = std::env::temp_dir().join(format!("wist-service-opcode-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn args(value: serde_json::Value) -> StatusArgs {
        serde_json::from_value(value).expect("parse args")
    }

    fn sample(pid: u32, unit: &str, source: &'static str, rss: u64) -> ProcessSample {
        ProcessSample {
            pid,
            name: "nginx".to_string(),
            ppid: Some(1),
            uid: Some(0),
            cpu: 0.0,
            rss,
            state: "S".to_string(),
            run_time: 60,
            agent: false,
            service: unit.to_string(),
            service_source: source,
        }
    }

    #[test]
    fn unit_names_are_normalized_or_rejected_explicitly() {
        assert_eq!(normalized_unit("nginx").unwrap(), "nginx.service");
        assert_eq!(normalized_unit(" nginx.service ").unwrap(), "nginx.service");
        assert_eq!(
            normalized_unit("com.example.App").unwrap(),
            "com.example.App.service"
        );
        assert_eq!(
            normalized_unit("php8.1").unwrap(),
            "php8.1.service",
            "带点的裸名字也要拼 .service"
        );
        for bad in ["", "   ", "a b", "/etc/passwd"] {
            assert_eq!(normalized_unit(bad).unwrap_err().code, codes::INVALID_ARGS);
        }
        assert_eq!(
            normalized_unit("nginx.socket").unwrap_err().code,
            codes::UNSUPPORTED_TARGET
        );
    }

    #[test]
    fn local_units_win_over_packaged_ones_and_masked_is_visible() {
        let local = temp_dir("local");
        let generated = temp_dir("generated");
        let packaged = temp_dir("packaged");
        fs::write(
            local.join("both.service"),
            "[Unit]\nDescription=local copy\n",
        )
        .expect("write");
        fs::write(
            packaged.join("both.service"),
            "[Unit]\nDescription=packaged\n",
        )
        .expect("write");
        fs::write(packaged.join("only-packaged.service"), "[Unit]\n").expect("write");
        std::os::unix::fs::symlink("/dev/null", local.join("gone.service")).expect("mask symlink");

        let (units, readable) = discover_units(&[local, generated, packaged]);
        assert_eq!(readable, 3);
        assert_eq!(units["both.service"].origin, "local");
        assert_eq!(units["only-packaged.service"].origin, "packaged");
        assert!(units["gone.service"].masked);
        assert!(!units["both.service"].masked);
        assert_eq!(
            description_of(&units["both.service"].path).as_deref(),
            Some("local copy")
        );
        // 指向 /dev/null 的 masked 单元读不出描述，也不能编一个。
        assert!(description_of(&units["gone.service"].path).is_none());
    }

    #[test]
    fn only_the_unit_section_describes_the_unit() {
        let dir = temp_dir("description");
        let file = dir.join("a.service");
        fs::write(
            &file,
            "[Service]\nDescription=not this one\n\n[Unit]\nDescription=  spaced  \n",
        )
        .expect("write");
        assert_eq!(description_of(&file).as_deref(), Some("spaced"));
    }

    #[test]
    fn enablement_comes_from_wants_and_requires_links_only() {
        let local = temp_dir("wants");
        let wants = local.join("multi-user.target.wants");
        let requires = local.join("basic.target.requires");
        fs::create_dir_all(&wants).expect("wants");
        fs::create_dir_all(&requires).expect("requires");
        for unit in ["nginx.service", "sshd.service"] {
            std::os::unix::fs::symlink(
                local.join("../../usr/lib/systemd/system").join(unit),
                wants.join(unit),
            )
            .expect("wants link");
        }
        std::os::unix::fs::symlink(
            local.join("../../usr/lib/systemd/system/sshd.service"),
            requires.join("sshd.service"),
        )
        .expect("requires link");
        fs::write(local.join("static.service"), "[Unit]\n").expect("write");

        let enabled = enabled_units(&local);
        assert!(enabled["nginx.service"].contains("multi-user.target"));
        assert_eq!(enabled["sshd.service"].len(), 2);
        assert!(
            !enabled.contains_key("static.service"),
            "没被链接的单元不能算 enabled"
        );
    }

    #[test]
    fn state_is_running_only_when_cgroup_shows_processes() {
        let samples = vec![
            sample(30, "nginx.service", "cgroup", 100),
            sample(10, "nginx.service", "cgroup", 200),
            sample(99, "nginx", "exe", 500),
        ];
        let who = Attribution::from_samples(&samples);
        assert!(who.available);

        let (state, stat) = who.state_of("nginx.service");
        assert_eq!(state, "running");
        let stat = stat.expect("stat");
        assert_eq!(stat.count, 2);
        assert_eq!(stat.rss, 300);
        assert_eq!(stat.pids, vec![10, 30], "pids 要排序");

        let (state, stat) = who.state_of("idle.service");
        assert_eq!(state, "no_process_observed");
        assert!(stat.is_none());
    }

    #[test]
    fn without_cgroup_the_state_is_unknown_not_absent() {
        let samples = vec![sample(99, "nginx", "exe", 500)];
        let who = Attribution::from_samples(&samples);
        assert!(!who.available);
        assert_eq!(who.state_of("nginx.service").0, "unknown");
    }

    #[test]
    fn a_row_carries_fragment_enablement_and_processes() {
        let dir = temp_dir("row");
        let file = dir.join("nginx.service");
        fs::write(&file, "[Unit]\nDescription=A high performance web server\n").expect("write");
        let unit_file = UnitFile {
            path: file,
            origin: "packaged",
            masked: false,
        };
        let enabled: BTreeSet<String> = ["multi-user.target".to_string()].into();
        let who = Attribution::from_samples(&[sample(7, "nginx.service", "cgroup", 42)]);

        let row = unit_row("nginx.service", Some(&unit_file), &enabled, &who);
        assert_eq!(row["name"], "nginx.service");
        assert_eq!(row["enabled"], true);
        assert_eq!(row["enabled_by"][0], "multi-user.target");
        assert_eq!(row["fragment"]["origin"], "packaged");
        assert_eq!(
            row["fragment"]["description"],
            "A high performance web server"
        );
        assert_eq!(row["state"], "running");
        assert_eq!(row["process_count"], 1);
        assert_eq!(row["pids"][0], 7);

        // 没有单元文件时 `fragment` 必须是 null，不能是空对象。
        let row = unit_row("ghost.service", None, &BTreeSet::new(), &who);
        assert!(row["fragment"].is_null());
        assert_eq!(row["enabled"], false);
    }

    #[test]
    fn a_single_query_reports_exactly_one_unit() {
        let local = temp_dir("single");
        fs::write(local.join("nginx.service"), "[Unit]\nDescription=web\n").expect("write");
        fs::write(local.join("other.service"), "[Unit]\n").expect("write");
        let who = Attribution::from_samples(&[]);

        let value = inspect(&[local], &args(json!({ "name": "nginx" })), 20, &who).expect("query");
        assert_eq!(value["queried_name"], "nginx.service");
        assert_eq!(value["units"].as_array().expect("units").len(), 1);
        assert_eq!(value["units"][0]["name"], "nginx.service");
        assert_eq!(value["total"], 1);
        assert_eq!(value["truncated"], false);
    }

    #[test]
    fn listing_is_alphabetical_counted_and_truncated_honestly() {
        let local = temp_dir("list");
        for unit in ["c.service", "a.service", "b.service"] {
            fs::write(local.join(unit), "[Unit]\n").expect("write");
        }
        let who = Attribution::from_samples(&[sample(1, "zz-orphan.service", "cgroup", 0)]);

        let value = inspect(&[local], &args(json!({ "limit": 2 })), 2, &who).expect("list");
        let names: Vec<&str> = value["units"]
            .as_array()
            .expect("units")
            .iter()
            .map(|row| row["name"].as_str().unwrap_or_default())
            .collect();
        assert_eq!(names, vec!["a.service", "b.service"]);
        // 4 个单元（3 个文件 + 1 个只有进程归属的）被 limit=2 截断。
        assert_eq!(value["total"], 4);
        assert_eq!(value["returned"], 2);
        assert_eq!(value["truncated"], true);
    }

    #[test]
    fn a_missing_unit_is_target_not_found() {
        let local = temp_dir("missing");
        let who = Attribution::from_samples(&[]);
        let err = inspect(
            &[local],
            &args(json!({ "name": "wist-no-such-unit-xyz" })),
            20,
            &who,
        )
        .expect_err("missing unit");
        assert_eq!(err.code, codes::TARGET_NOT_FOUND);
    }

    #[test]
    fn no_readable_unit_dir_is_an_error_not_an_empty_list() {
        let dir = temp_dir("no-dirs");
        let missing = dir.join("nope");
        let who = Attribution::from_samples(&[]);
        let err = inspect(&[missing], &args(json!({})), 20, &who).expect_err("unreadable");
        assert_eq!(err.code, codes::OP_FAILED);
    }

    #[test]
    fn bad_selector_stays_invalid_args() {
        let local = temp_dir("bad-selector");
        let who = Attribution::from_samples(&[]);
        for bad in [json!({ "name": "" }), json!({ "name": "a b" })] {
            let err =
                inspect(std::slice::from_ref(&local), &args(bad), 20, &who).expect_err("bad name");
            assert_eq!(err.code, codes::INVALID_ARGS);
        }
        let err = inspect(&[local], &args(json!({ "name": "nginx.socket" })), 20, &who)
            .expect_err("foreign suffix");
        assert_eq!(err.code, codes::UNSUPPORTED_TARGET);
    }

    #[test]
    fn op_metadata_is_read_only_and_linux_only() {
        assert_eq!(STATUS_SPEC.risk, RiskLevel::R0);
        assert_eq!(STATUS_SPEC.platforms, &["linux"]);
    }
}
