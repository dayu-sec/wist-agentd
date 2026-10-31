//! 遥测健康调查（`wist-agentd investigate telemetry-health`）：
//! **我们瞎了多久** —— 配好的安全日志源还活着吗，采到的东西送得出去吗。
//!
//! 这是安全向调查里最“反向”的一题：别的题回答“这台机器有什么”，它回答
//! “**我们的眼睛还在不在**”。审计日志断流时，`accounts` / `persistence`
//! 一样能给出漂亮的报告 —— 报告越漂亮越危险，因为它掩盖了“这 6 小时什么都没采到”。
//!
//! 三节：
//!
//! 1. `telemetry.sources` —— 每个配置的输入：来源在不在、读到没有、最近一次**提交**是多久前；
//! 2. `telemetry.backlog` —— 每个输入的 spool 积压（离线时这里涨，涨到上限会暂停采集）；
//! 3. `telemetry.pipeline` —— agent 自己的采集闸门：输出是否关闭、全局 seq 高水位多久没动。
//!
//! 三处**不做判定**的地方（写进 `limits`）：
//!
//! * 不读日志正文，只看 checkpoint / spool 的元数据；
//! * “源静默”不等于“源坏了”：低流量日志本来就安静，报告给的是**时长**，让人结合业务判断；
//! * spool 是否真的 `pause` 由运行时决定，这里只按“是否到上限”推断。
//!
//! 为什么静默要分两档：15 分钟是“该看一眼”，24 小时是“这个源基本不会再有数据了”。
//! 只有一档阈值时，要么天天误报（低流量源），要么在真正的停摆上保持沉默。

use std::fmt::Write as _;
use std::fs;
use std::io;
use std::path::Path;
use std::time::UNIX_EPOCH;

use serde::Deserialize;

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::investigate::{Coverage, Finding, InvestigateRequest, Row, human_bytes};
use crate::investigate_probe::truncate_rows;
use crate::runtime::daemon::telemetry_support::spool_path_for;
use crate::state_store::log_checkpoints;
use crate::telemetry::logs::files::is_family_target;

/// 源静默多久开始警告：15 分钟足够跨过一次网络抖动与一次轮转。
pub(crate) const SILENCE_WARN_SECONDS: i64 = 15 * 60;
/// 静默一整天：基本可以认定这个源不会再有数据了（服务停了 / 轮转换文件 / 路径写错）。
pub(crate) const SILENCE_FAIL_SECONDS: i64 = 24 * 60 * 60;

/// 单个 checkpoint 的读取上限（R2：没有预算的面不许登记）。
///
/// 真实值在几 KB 量级（512 个容器的文件族也只有百 KB 级）；上限是挡住
/// “状态文件被写成 1 GB / 被别的东西占位”把调查本身拖死—— 那种情况应当
/// 如实报 `unknown`，而不是把内存吃光。
pub(crate) const MAX_CHECKPOINT_BYTES: u64 = 16 * 1024 * 1024;

pub(crate) fn investigate(
    request: &InvestigateRequest,
    config: Option<&AgentConfig>,
) -> Result<Vec<Finding>, String> {
    let Some(config) = config else {
        // 读不到配置时**不能**输出“0 个输入，一切正常”：那正好是反向结论。
        return Ok(vec![
            Finding::new(
                "telemetry.sources",
                Status::Unknown,
                "没有读到 agentd 配置，无法判断该采什么",
                "遥测健康要对照 `[telemetry.logs] file_inputs` 才说得清“该有而没来”",
            )
            .hint("用 `--config-dir` 指向 agentd 配置目录；或确认 /etc/wist-agentd 下的配置可读"),
        ]);
    };
    if config.telemetry.logs.file_inputs.is_empty() {
        return Ok(vec![
            Finding::new(
                "telemetry.sources",
                Status::Unknown,
                "没有配置任何日志输入",
                "`[telemetry.logs] file_inputs` 为空：agentd 不会采集任何主机日志",
            )
            .hint("这台机器本该有安全日志的话，先补上 `[[telemetry.logs.file_inputs]]`"),
        ]);
    }
    let top = request.top.max(1);
    Ok(vec![
        sources_finding(config, top),
        backlog_finding(config, top),
        pipeline_finding(config),
    ])
}

// ---------------------------------------------------------------------------
// telemetry.sources
// ---------------------------------------------------------------------------

fn sources_finding(config: &AgentConfig, top: usize) -> Finding {
    let state_dir = Path::new(&config.paths.state_dir);
    let now = now_secs();
    let mut coverage = Coverage::new(0, 0, 0);
    let mut rows = Vec::new();
    let mut status = Status::Ok;
    let mut read_ok = 0usize;
    let mut never = 0usize;
    let mut silent_fail = 0usize;
    let mut silent_warn = 0usize;
    let mut behind = 0usize;
    let mut missing = 0usize;

    for input in &config.telemetry.logs.file_inputs {
        coverage.checked += 1;
        if !is_plain_segment(&input.input_id) {
            // 配置坏了，不当来源去读：`input_id` 是要拼进路径的。
            coverage.skipped += 1;
            rows.push(Row::new(
                &input.input_id,
                "跳过",
                "input_id 不是合法路径段，按配置错误处理",
            ));
            status = worse(status, Status::Unknown);
            continue;
        }

        let checkpoint_path = log_checkpoints::path_for(state_dir, &input.input_id);
        // 先看体量再读：JSON 要整份解析，所以“读一半”没有意义，只能明确拒绝。
        if let Ok(metadata) = fs::metadata(&checkpoint_path)
            && metadata.len() > MAX_CHECKPOINT_BYTES
        {
            coverage.checked += 1;
            coverage.skipped += 1;
            rows.push(Row::new(
                &input.input_id,
                "checkpoint 过大",
                format!("超过 {} 上限，未解析", human_bytes(MAX_CHECKPOINT_BYTES)),
            ));
            status = worse(status, Status::Unknown);
            continue;
        }
        let text = match fs::read_to_string(&checkpoint_path) {
            Ok(text) => text,
            Err(err) if err.kind() == io::ErrorKind::NotFound => {
                coverage.skipped += 1;
                never += 1;
                rows.push(Row::new(
                    &input.input_id,
                    "无 checkpoint",
                    "agentd 还没读到过这个源（输入刚加 / 状态被删 / 从没扫到）",
                ));
                status = worse(status, Status::Unknown);
                continue;
            }
            Err(err) => {
                if err.kind() == io::ErrorKind::PermissionDenied {
                    coverage.denied += 1;
                } else {
                    coverage.skipped += 1;
                }
                rows.push(Row::new(
                    &input.input_id,
                    "读不到",
                    "checkpoint 读取失败（权限 / IO）",
                ));
                status = worse(status, Status::Unknown);
                continue;
            }
        };
        read_ok += 1;

        // 宽容解析：checkpoint 是**我们自己的**状态，字段会随版本增减；
        // 一个调查工具不该因为状态里多了个键就整节失效（真实结构体是 `deny_unknown_fields`）。
        let view: CheckpointView = match serde_json::from_str(&text) {
            Ok(view) => view,
            Err(_) => {
                coverage.skipped += 1;
                rows.push(Row::new(
                    &input.input_id,
                    "checkpoint 损坏",
                    "不是合法 JSON（旧版本 / 半写）",
                ));
                status = worse(status, Status::Unknown);
                continue;
            }
        };

        let mut note = format!("{} 个文件", view.files.len());
        let presence = source_presence(&input.path);
        match presence {
            Presence::Present | Presence::Family => {}
            Presence::Missing => {
                missing += 1;
                note.push_str("；源路径不存在");
                status = worse(status, Status::Warn);
            }
            Presence::Denied => {
                note.push_str("；源路径不可读");
                status = worse(status, Status::Unknown);
            }
        }
        let unread = view.unread_bytes();
        if unread > 0 {
            let _ = write!(note, "；未读 {}", human_bytes(unread));
        }
        if view.files.is_empty() {
            note.push_str("；选源没匹配到文件");
            status = worse(status, Status::Unknown);
        }

        let age = view.newest_commit().map(|at| now - at);
        let (value, row_status) = match age {
            Some(age) if age >= SILENCE_FAIL_SECONDS => {
                silent_fail += 1;
                (age_text(age), Status::Fail)
            }
            Some(age) if age >= SILENCE_WARN_SECONDS => {
                silent_warn += 1;
                (age_text(age), Status::Warn)
            }
            Some(age) => (age_text(age), Status::Ok),
            None if unread > 0 => {
                // 有未读字节但一条都没提交：采集在看，但没送出来。
                behind += 1;
                ("有未读数据".to_string(), Status::Warn)
            }
            None => ("从未提交".to_string(), Status::Unknown),
        };
        status = worse(status, row_status);
        rows.push(Row::new(&input.input_id, value, note));
    }

    let (rows, omitted) = truncate_rows(rows, top);
    let mut detail = format!(
        "配置输入 {} 个；读到 checkpoint {read_ok} 个；无 checkpoint {never} 个；静默 {} 个",
        config.telemetry.logs.file_inputs.len(),
        silent_fail + silent_warn
    );
    if missing > 0 {
        let _ = write!(detail, "；源路径不存在 {missing} 个");
    }
    if behind > 0 {
        let _ = write!(detail, "；有未读未提交 {behind} 个");
    }
    if omitted > 0 {
        let _ = write!(detail, "；另有 {omitted} 条未列出");
    }

    let mut problems: Vec<String> = Vec::new();
    if silent_fail > 0 {
        problems.push(format!("{silent_fail} 个源静默超过 24 小时"));
    }
    if silent_warn > 0 {
        problems.push(format!("{silent_warn} 个源静默超过 15 分钟"));
    }
    if missing > 0 {
        problems.push(format!("{missing} 个源路径不存在"));
    }
    if behind > 0 {
        // “有未读但一条都没提交”与“静默”是两回事：前者是读到了没送出去，标题必须分开说。
        problems.push(format!("{behind} 个源有未读数据"));
    }
    let title = if problems.is_empty() {
        match status {
            Status::Ok => "配置的源都在产出".to_string(),
            _ => "部分源的状态无法判定".to_string(),
        }
    } else {
        problems.join("；")
    };

    let mut finding = Finding::new("telemetry.sources", status, title, detail)
        .rows(rows)
        .coverage(coverage)
        .limit("静默时长按 checkpoint 里最近一次**提交**记录算；低流量源本来就安静，不等于采集坏了")
        .limit("只对字面路径做存在性检查；文件族（glob / 目录）只按 checkpoint 判断，不展开匹配")
        .limit("不读日志正文，只看 checkpoint 元数据");
    if silent_fail + silent_warn > 0 {
        finding = finding.hint(
            "静默可能是真的没流量，也可能是服务停了 / 轮转换了文件 / 路径写错：\
             先去源上确认最后一条日志是什么时候、服务是否还在跑",
        );
    } else if missing > 0 {
        finding = finding.hint("配置的路径不存在：确认服务已启动、路径没写错、轮转没有把文件挪走");
    } else if never > 0 {
        finding = finding
            .hint("这些源还没有 checkpoint：确认 agentd 在跑、路径可读、输入已经在生效配置里");
    } else if behind > 0 {
        finding = finding.hint("源里有未读字节但一条都没提交：先看 spool 积压与 uplink 是否断开");
    }
    finding
}

/// 配置里的源在磁盘上的状态。**只有字面路径才检查**：glob / 目录展开是采集器的事。
enum Presence {
    Present,
    Family,
    Missing,
    Denied,
}

/// 文件名里的 `*` / `?` / `[` 之外，还要按“目录”判断 —— 与采集器同一个判据。
fn source_presence(path: &str) -> Presence {
    if is_family_target(path) {
        return Presence::Family;
    }
    match fs::metadata(path) {
        Ok(_) => Presence::Present,
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => Presence::Denied,
        Err(_) => Presence::Missing,
    }
}

// ---------------------------------------------------------------------------
// telemetry.backlog
// ---------------------------------------------------------------------------

fn backlog_finding(config: &AgentConfig, top: usize) -> Finding {
    let cap = config.telemetry.logs.spool_max_bytes;
    let spool_dir = Path::new(&config.telemetry.logs.spool_dir);
    let now = now_secs();
    let mut coverage = Coverage::new(0, 0, 0);
    let mut rows = Vec::new();
    let mut status = Status::Ok;
    let mut backlogged = 0usize;
    let mut at_cap = 0usize;
    let mut readable = 0usize;

    for input in &config.telemetry.logs.file_inputs {
        coverage.checked += 1;
        if !is_plain_segment(&input.input_id) {
            coverage.skipped += 1;
            continue;
        }
        let path = spool_path_for(config, input);
        let metadata = match fs::metadata(&path) {
            Ok(metadata) => metadata,
            // 没有 spool 文件 = 从没积压过（直投时根本不落盘），这不是异常。
            Err(err) if err.kind() == io::ErrorKind::NotFound => continue,
            Err(err) => {
                if err.kind() == io::ErrorKind::PermissionDenied {
                    coverage.denied += 1;
                } else {
                    coverage.skipped += 1;
                }
                status = worse(status, Status::Unknown);
                rows.push(Row::new(&input.input_id, "读不到", "spool 文件读取失败"));
                continue;
            }
        };
        readable += 1;
        let size = metadata.len();
        if size == 0 {
            continue;
        }
        let note = match mtime_age_secs(&metadata, now) {
            Some(age) => format!("上限 {}；最后写入 {}", human_bytes(cap), age_text(age)),
            None => format!("上限 {}", human_bytes(cap)),
        };
        if size >= cap {
            at_cap += 1;
            status = worse(status, Status::Fail);
        } else {
            backlogged += 1;
            status = worse(status, Status::Warn);
        }
        rows.push(Row::new(&input.input_id, human_bytes(size), note));
    }

    let (rows, omitted) = truncate_rows(rows, top);
    let mut detail = format!(
        "输入 {} 个；spool 可读 {readable} 个；有积压 {} 个",
        config.telemetry.logs.file_inputs.len(),
        backlogged + at_cap
    );
    if at_cap > 0 {
        let _ = write!(detail, "（其中 {at_cap} 个到达上限）");
    }
    if omitted > 0 {
        let _ = write!(detail, "；另有 {omitted} 条未列出");
    }
    let title = if at_cap > 0 {
        format!("{at_cap} 个输入的积压到达上限，采集会暂停")
    } else if backlogged > 0 {
        format!("{backlogged} 个输入有未送出的积压")
    } else if status == Status::Unknown {
        "部分输入的积压无法判定".to_string()
    } else {
        "没有积压".to_string()
    };

    let mut finding = Finding::new("telemetry.backlog", status, title, detail)
        .rows(rows)
        .coverage(coverage)
        .limit("积压按 spool 文件字节数估算；是否 `pause` 由运行时决定（`spool_over_limit` 当前只有 `pause`）")
        .limit("只统计 agentd 自己的 spool；平台侧是否收到不在这一题里");
    if backlogged + at_cap > 0 {
        finding = finding.hint(
            "积压说明记录还在本地、没送到平台：先看 uplink 是否断开（`diagnose`），再谈采集本身",
        );
    }
    // `spool_dir` 不存在单独提一句：它说明“从没发生过离线积压”，不是故障。
    if !spool_dir.exists() {
        finding = finding.limit("spool 目录不存在：本机还没发生过离线积压（direct 投递不落盘）");
    }
    finding
}

// ---------------------------------------------------------------------------
// telemetry.pipeline
// ---------------------------------------------------------------------------

fn pipeline_finding(config: &AgentConfig) -> Finding {
    let state_dir = Path::new(&config.paths.state_dir);
    let seq_path = crate::state_store::log_seq_state::path_for(state_dir);
    let now = now_secs();
    let mut coverage = Coverage::new(0, 0, 0);
    let mut status = Status::Ok;

    // 全局 `seq` 只在**确实处理过记录**时才推进（`ran_any`），所以它的写入时间
    // 就是“最后一次见到任何记录”的时间 —— 比任何单源都更像“我们还在不在看”。
    let seq_row = match fs::metadata(&seq_path) {
        Ok(metadata) => {
            coverage.checked += 1;
            match mtime_age_secs(&metadata, now) {
                Some(age) => Row::new("最近产出", age_text(age), "state/logs/seq.json 的写入时间"),
                None => Row::new("最近产出", "时间未知", "读不到文件时间戳"),
            }
        }
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            // `checked` 记“检查次数”（含不存在），与 `Tally` 的口径一致：
            // 否则“一份报告里这节到底看过没有”就无从判断。
            coverage.checked += 1;
            coverage.skipped += 1;
            status = worse(status, Status::Unknown);
            Row::new(
                "最近产出",
                "从未",
                "还没有处理过任何记录（seq 高水位不存在）",
            )
        }
        Err(err) => {
            coverage.checked += 1;
            if err.kind() == io::ErrorKind::PermissionDenied {
                coverage.denied += 1;
            } else {
                coverage.skipped += 1;
            }
            status = worse(status, Status::Unknown);
            Row::new("最近产出", "读不到", "state/logs/seq.json 读取失败")
        }
    };

    let output = &config.telemetry.logs.output;
    let (gate, destination) = if output.enabled {
        let destination = if output.kind == "tcp" {
            format!("tcp {}:{}", output.tcp.addr, output.tcp.port)
        } else {
            format!("file {}", output.file.path)
        };
        ("开启", destination)
    } else {
        status = worse(status, Status::Warn);
        (
            "关闭",
            "待命态：主机内容不上送（也不写本地文件）".to_string(),
        )
    };

    let title = match status {
        Status::Warn => "采集输出已关闭：这台机器的主机内容不上送",
        Status::Unknown => "还没有产出过任何记录",
        _ => "采集链路在产出",
    };
    let detail = format!(
        "配置输入 {} 个；输出闸门 {gate}（{destination}）",
        config.telemetry.logs.file_inputs.len()
    );

    let mut finding = Finding::new("telemetry.pipeline", status, title, detail)
        .rows(vec![Row::new("采集输出", gate, destination), seq_row])
        .coverage(coverage)
        .limit("只读 agentd 自己的状态（`state/logs/seq.json` / 输出配置）；控制面连通性由 `diagnose` 判定");
    if !output.enabled {
        finding =
            finding.hint("如果不是有意的待命态，把 `[telemetry.logs.output] enabled` 改回 true");
    }
    finding
}

// ---------------------------------------------------------------------------
// checkpoint 视图（宽容解析）
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct CheckpointView {
    #[serde(default)]
    files: Vec<FileView>,
}

#[derive(Debug, Deserialize)]
struct FileView {
    #[serde(default)]
    last_commit_point_at: Option<String>,
    #[serde(default)]
    checkpoint_offset: u64,
    #[serde(default)]
    last_size: Option<u64>,
}

impl CheckpointView {
    /// 最近一次**提交**（真有一条记录送出去）的时间戳（秒）。
    fn newest_commit(&self) -> Option<i64> {
        self.files
            .iter()
            .filter_map(|file| file.last_commit_point_at.as_deref())
            .filter_map(parse_rfc3339_secs)
            .max()
    }

    /// 已经长出来但还没读的字节数：采集在源这一侧掉队了。
    fn unread_bytes(&self) -> u64 {
        self.files
            .iter()
            .map(|file| {
                file.last_size
                    .unwrap_or(0)
                    .saturating_sub(file.checkpoint_offset)
            })
            .sum()
    }
}

// ---------------------------------------------------------------------------
// 小工具
// ---------------------------------------------------------------------------

/// `input_id` 会拼进 `state/logs/file_inputs/<id>/`，不是路径段就不读（配置错误，不是来源）。
pub(crate) fn is_plain_segment(value: &str) -> bool {
    !value.is_empty()
        && value != "."
        && value != ".."
        && !value.contains('/')
        && !value.contains('\\')
}

fn now_secs() -> i64 {
    time::OffsetDateTime::now_utc().unix_timestamp()
}

fn parse_rfc3339_secs(text: &str) -> Option<i64> {
    time::OffsetDateTime::parse(text, &time::format_description::well_known::Rfc3339)
        .ok()
        .map(|at| at.unix_timestamp())
}

fn mtime_age_secs(metadata: &fs::Metadata, now: i64) -> Option<i64> {
    let modified = metadata.modified().ok()?;
    let secs = modified.duration_since(UNIX_EPOCH).ok()?.as_secs() as i64;
    Some(now - secs)
}

/// 人话时长。**负数是证据不是噪声**：时钟被回拨时如实说出来，而不是显示“0 分钟前”。
fn age_text(seconds: i64) -> String {
    if seconds < 0 {
        return "时间戳在未来（时钟回拨？）".to_string();
    }
    let days = seconds / 86_400;
    let hours = (seconds % 86_400) / 3_600;
    let minutes = (seconds % 3_600) / 60;
    if days > 0 {
        format!("{days} 天 {hours} 小时前")
    } else if hours > 0 {
        format!("{hours} 小时 {minutes} 分钟前")
    } else if minutes > 0 {
        format!("{minutes} 分钟前")
    } else {
        "刚刚".to_string()
    }
}

/// 报告的总体优先级是 `Fail > Warn > Unknown > Ok`，不是枚举的声明顺序。
fn worse(left: Status, right: Status) -> Status {
    fn rank(status: Status) -> u8 {
        match status {
            Status::Ok => 0,
            Status::Unknown => 1,
            Status::Warn => 2,
            Status::Fail => 3,
        }
    }
    if rank(right) > rank(left) {
        right
    } else {
        left
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::{Path, PathBuf};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-agentd-telemetry-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// 用真实配置解析路径：这样 `file_inputs` / `spool_dir` 的默认值与解析规则都参与测试。
    fn config_with(
        state_dir: &Path,
        spool_dir: &Path,
        spool_max_bytes: u64,
        inputs: &[(&str, &str)],
        output_enabled: bool,
    ) -> AgentConfig {
        let mut text = format!(
            "schema_version = \"v1\"\n\
             [paths]\n\
             state_dir = \"{}\"\n\
             [telemetry.logs]\n\
             spool_dir = \"{}\"\n\
             spool_max_bytes = {spool_max_bytes}\n\
             [telemetry.logs.output]\n\
             enabled = {output_enabled}\n",
            state_dir.display(),
            spool_dir.display()
        );
        for (input_id, path) in inputs {
            let _ = write!(
                text,
                "\n[[telemetry.logs.file_inputs]]\ninput_id = \"{input_id}\"\npath = \"{path}\"\n"
            );
        }
        toml::from_str(&text).expect("config parses")
    }

    fn write_checkpoint(state_dir: &Path, input_id: &str, files: &str) {
        let dir = state_dir.join("logs").join("file_inputs").join(input_id);
        fs::create_dir_all(&dir).expect("checkpoint dir");
        fs::write(
            dir.join("checkpoints.json"),
            format!("{{\"schema_version\":\"v1\",\"input_id\":\"{input_id}\",\"updated_at\":\"2026-01-01T00:00:00Z\",\"files\":[{files}]}}"),
        )
        .expect("write checkpoint");
    }

    fn ago(seconds: i64) -> String {
        let at = time::OffsetDateTime::now_utc() - time::Duration::seconds(seconds);
        at.format(&time::format_description::well_known::Rfc3339)
            .expect("format")
    }

    fn file_entry(last_commit: Option<i64>, size: u64, offset: u64) -> String {
        let commit = match last_commit {
            Some(seconds) => format!("\"{}\"", ago(seconds)),
            None => "null".to_string(),
        };
        format!(
            "{{\"file_id\":\"f1\",\"path\":\"/var/log/x.log\",\"device_id\":null,\"inode\":null,\
             \"fingerprint\":null,\"checkpoint_offset\":{offset},\"checkpoint_probe\":null,\
             \"last_size\":{size},\"last_read_at\":\"2026-01-01T00:00:00Z\",\
             \"last_commit_point_at\":{commit},\"rotated_from_path\":null}}"
        )
    }

    fn one_input_config(
        name: &str,
        spool_max_bytes: u64,
        output_enabled: bool,
    ) -> (AgentConfig, PathBuf) {
        let root = temp_dir(name);
        let state_dir = root.join("state");
        let spool_dir = root.join("spool");
        // 源文件要真的存在：否则每道用例都会同时命中“源路径不存在”的警告，
        // 判定就测不准了。
        let source = root.join("app.log");
        fs::write(&source, b"").expect("source file");
        let source_text = source.to_string_lossy().to_string();
        let config = config_with(
            &state_dir,
            &spool_dir,
            spool_max_bytes,
            &[("audit", source_text.as_str())],
            output_enabled,
        );
        (config, root)
    }

    fn findings(config: &AgentConfig) -> Vec<Finding> {
        investigate(
            &InvestigateRequest::for_topic("telemetry-health").unwrap(),
            Some(config),
        )
        .expect("investigate runs")
    }

    fn find(findings: Vec<Finding>, id: &str) -> Finding {
        findings
            .into_iter()
            .find(|finding| finding.id == id)
            .unwrap_or_else(|| panic!("缺少 `{id}`"))
    }

    #[test]
    fn no_config_is_unknown_not_healthy() {
        let findings = investigate(
            &InvestigateRequest::for_topic("telemetry-health").unwrap(),
            None,
        )
        .expect("runs");
        assert_eq!(findings[0].status, Status::Unknown);
        assert!(!findings[0].title.contains("正常"));
    }

    #[test]
    fn no_inputs_is_unknown_not_healthy() {
        let root = temp_dir("no-inputs");
        let config = config_with(&root, &root.join("spool"), 1024, &[], true);
        let findings = findings(&config);
        assert_eq!(findings[0].status, Status::Unknown);
    }

    /// 没有 checkpoint ≠ 一切正常：这是安全报告最危险的假阴性。
    #[test]
    fn a_missing_checkpoint_is_unknown() {
        let (config, _root) = one_input_config("missing-checkpoint", 1024, true);
        let findings = findings(&config);
        let sources = find(findings, "telemetry.sources");
        assert_eq!(sources.status, Status::Unknown);
        assert_eq!(sources.coverage.skipped, 1);
        assert!(
            sources.detail.contains("无 checkpoint 1 个"),
            "{}",
            sources.detail
        );
    }

    #[test]
    fn a_recent_commit_is_ok() {
        let (config, _root) = one_input_config("recent", 1024, true);
        let state_dir = Path::new(&config.paths.state_dir);
        write_checkpoint(state_dir, "audit", &file_entry(Some(30), 100, 100));
        let findings = findings(&config);
        let sources = find(findings, "telemetry.sources");
        assert_eq!(sources.status, Status::Ok);
        assert_eq!(sources.rows[0].value, "刚刚");
    }

    #[test]
    fn silence_past_the_warning_line_warns() {
        let (config, _root) = one_input_config("silent-warn", 1024, true);
        let state_dir = Path::new(&config.paths.state_dir);
        write_checkpoint(
            state_dir,
            "audit",
            &file_entry(Some(SILENCE_WARN_SECONDS + 60), 100, 100),
        );
        let sources = find(findings(&config), "telemetry.sources");
        assert_eq!(sources.status, Status::Warn);
        assert!(
            sources.title.contains("静默超过 15 分钟"),
            "{}",
            sources.title
        );
    }

    #[test]
    fn silence_for_a_day_fails() {
        let (config, _root) = one_input_config("silent-fail", 1024, true);
        let state_dir = Path::new(&config.paths.state_dir);
        write_checkpoint(
            state_dir,
            "audit",
            &file_entry(Some(SILENCE_FAIL_SECONDS + 60), 100, 100),
        );
        let sources = find(findings(&config), "telemetry.sources");
        assert_eq!(sources.status, Status::Fail);
        assert!(sources.title.contains("超过 24 小时"), "{}", sources.title);
    }

    /// 文件长出来了却没读：采集在源这一侧就掉队了。标题必须说“未读”，
    /// 不能落到“状态无法判定”—— 那是两回事。
    #[test]
    fn unread_bytes_without_any_commit_warns() {
        let (config, _root) = one_input_config("unread", 1024, true);
        let state_dir = Path::new(&config.paths.state_dir);
        write_checkpoint(state_dir, "audit", &file_entry(None, 4096, 0));
        let sources = find(findings(&config), "telemetry.sources");
        assert_eq!(sources.status, Status::Warn);
        assert!(sources.title.contains("有未读数据"), "{}", sources.title);
        assert!(
            sources.detail.contains("有未读未提交 1 个"),
            "{}",
            sources.detail
        );
    }

    #[test]
    fn a_missing_spool_file_is_not_backlog() {
        let (config, _root) = one_input_config("no-spool", 1024, true);
        let backlog = find(findings(&config), "telemetry.backlog");
        assert_eq!(backlog.status, Status::Ok);
        assert!(backlog.rows.is_empty());
    }

    #[test]
    fn a_small_backlog_warns() {
        let (config, _root) = one_input_config("small-backlog", 1024, true);
        fs::create_dir_all(&config.telemetry.logs.spool_dir).expect("spool dir");
        fs::write(
            Path::new(&config.telemetry.logs.spool_dir).join("audit.ndjson"),
            b"{\"seq\":1}\n",
        )
        .expect("spool");
        let backlog = find(findings(&config), "telemetry.backlog");
        assert_eq!(backlog.status, Status::Warn);
        assert!(backlog.title.contains("未送出的积压"), "{}", backlog.title);
    }

    /// 到上限 = 运行时会把输入 `pause`：这是“我们已经不看这台机器了”。
    #[test]
    fn a_backlog_at_the_cap_fails() {
        let (config, _root) = one_input_config("cap-backlog", 16, true);
        fs::create_dir_all(&config.telemetry.logs.spool_dir).expect("spool dir");
        fs::write(
            Path::new(&config.telemetry.logs.spool_dir).join("audit.ndjson"),
            vec![b'x'; 64],
        )
        .expect("spool");
        let backlog = find(findings(&config), "telemetry.backlog");
        assert_eq!(backlog.status, Status::Fail);
        assert!(backlog.title.contains("到达上限"), "{}", backlog.title);
    }

    #[test]
    fn a_disabled_output_warns() {
        let (config, _root) = one_input_config("output-off", 1024, false);
        let pipeline = find(findings(&config), "telemetry.pipeline");
        assert_eq!(pipeline.status, Status::Warn);
        assert!(pipeline.title.contains("不上送"), "{}", pipeline.title);
    }

    /// 没产出过任何记录：是 `unknown`，不是“链路正常”。
    #[test]
    fn a_missing_seq_high_water_is_unknown() {
        let (config, _root) = one_input_config("no-seq", 1024, true);
        let pipeline = find(findings(&config), "telemetry.pipeline");
        assert_eq!(pipeline.status, Status::Unknown);
        assert!(
            pipeline.detail.contains("输出闸门 开启"),
            "{}",
            pipeline.detail
        );
        // `checked` 含“不存在”：这节确实被看过了，不是“没检查”。
        assert_eq!(pipeline.coverage.checked, 1);
        assert_eq!(pipeline.coverage.skipped, 1);
    }

    /// 体量超预算的 checkpoint 不能把调查拖死：明确报 `unknown`。
    #[test]
    fn an_oversized_checkpoint_is_unknown_not_parsed() {
        let (config, root) = one_input_config("oversized", 1024, true);
        let dir = Path::new(&config.paths.state_dir)
            .join("logs")
            .join("file_inputs")
            .join("audit");
        fs::create_dir_all(&dir).expect("checkpoint dir");
        fs::write(
            dir.join("checkpoints.json"),
            vec![b' '; (MAX_CHECKPOINT_BYTES + 1) as usize],
        )
        .expect("write oversized");
        let sources = find(findings(&config), "telemetry.sources");
        assert_eq!(sources.status, Status::Unknown);
        assert_eq!(sources.rows[0].value, "checkpoint 过大");
        let _ = fs::remove_dir_all(root);
    }

    /// `input_id` 要拼进路径：不是路径段就不读，宁可 `skipped` 也不越界。
    #[test]
    fn an_unsafe_input_id_is_skipped() {
        let root = temp_dir("unsafe-id");
        let config = config_with(
            &root,
            &root.join("spool"),
            1024,
            &[("../etc", "/var/log/x.log")],
            true,
        );
        let sources = find(findings(&config), "telemetry.sources");
        assert_eq!(sources.coverage.skipped, 1);
        assert_eq!(sources.rows[0].value, "跳过");
    }

    #[test]
    fn age_text_states_clock_skew_instead_of_zero() {
        assert!(age_text(-60).contains("时钟回拨"));
        assert_eq!(age_text(0), "刚刚");
        assert_eq!(age_text(120), "2 分钟前");
        assert_eq!(age_text(3 * 3600 + 60), "3 小时 1 分钟前");
        assert_eq!(age_text(2 * 86_400 + 5 * 3600), "2 天 5 小时前");
    }

    #[test]
    fn the_report_json_carries_the_telemetry_topic() {
        let (config, _root) = one_input_config("json", 1024, true);
        let report = crate::investigate::Report {
            topic: "telemetry-health".to_string(),
            observed_at: "2026-01-01T00:00:00Z".to_string(),
            findings: findings(&config),
        };
        let value = report.to_json();
        assert_eq!(value["topic"], "telemetry-health");
        assert_eq!(
            value["report_schema"],
            "wist.investigation.telemetry-health/v1"
        );
        assert_eq!(value["judged"], true);
        assert_eq!(value["findings"][0]["id"], "telemetry.sources");
    }
}
