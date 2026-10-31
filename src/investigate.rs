//! `wist-agentd investigate`：**一次性调查** —— 问一件具体的事，当场给答案。
//!
//! 与 [`crate::doctor`]（`diagnose`）的分工是刻意的：
//!
//! * `diagnose` 回答「**它自己**为什么不对」：配置 / 身份 / 服务 / 连通 / 上送，检查项固定、有红绿判定。
//! * `investigate` 回答「**这台机器**现在怎么了」：题目按现场来（磁盘满、谁占的、多大），
//!   输出是**证据表**（路径 + 字节数 + 占比），不是布尔检查。
//!
//! 三条取舍：
//!
//! 1. **一次性**：不起守护进程、不等 tick、不写配置。有 `--path` 就查那里，没有就查**最紧张的
//!    那个文件系统**的挂载点 —— 磁盘满的时候人想知道的就是「这台机器上哪儿大」，不是「agent 的
//!    配置对不对」。读不到 `/etc/wist-agentd` 也能跑（只是少一节「agent 自己占了多少」）。
//! 2. **有界**：扫描有**条目 / 时长 / 深度**三重上限（默认 200k 条目 / 5s / 16 层）。超了就如实标
//!    `truncated`，而不是为了答案把一台已经在扛业务的机器再压一遍。
//! 3. **同一条实现两处用**：CLI（`wist-agentd investigate disk`）与网关下发的一次性命令
//!    （`AgentCommand.kind = "investigate"`）都走 [`execute`] —— 「人在机器上跑出来的」与
//!    「网关拿到的」不会两套口径。
//!
//! 判定语义与 `diagnose` 一致：**有 FAIL 退出码非零**，脚本/AI 可以直接当门禁。

use std::fmt::Write as _;
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::time::Duration;

use orion_error::conversion::ToStructError;
use wist_shared::time::now_rfc3339;

use crate::config::agent_config::AgentConfig;
use crate::doctor::Status;
use crate::error::{AgentdReason, AgentdResult};

/// 调查题目的词表。加一个题目 = 加一个常量 + 一个 `match` 分支（见 [`execute`]）。
pub const TOPIC_DISK: &str = "disk";

pub const TOPICS: &[&str] = &[TOPIC_DISK];

/// 网关下发的一次性命令 `kind`（词表的家在 `wist_api::status::command_kind`）。
///
/// 与采集预检（`refresh_facts` + `params.scope=paths`）不同，这是一条**独立 kind**：旧 agentd 会
/// 如实回 `unsupported`，正好等于「这台机器还没升级，调查做不了」—— 调查本来就不该在旧版本上
/// 假装成功。这里只做别名，**不再写一份字面量**（两处字面量迟早会漂）。
pub const COMMAND_KIND: &str = wist_api::status::command_kind::INVESTIGATE;

/// 列前多少条（文件 / 目录）。默认 10，上限 50：再多就不是「一眼看出谁大」而是让人自己 `du`。
pub const DEFAULT_TOP: usize = 10;
pub const MAX_TOP: usize = 50;

/// 扫描深度上限（相对扫描根）。默认 16 层：`/var/lib/docker/overlay2/<id>/diff/...` 能数到。
pub const DEFAULT_DEPTH: usize = 16;
pub const MAX_DEPTH: usize = 64;

/// 单次扫描的时长上限（秒）。默认 5s：足够扫完一台普通机器的根盘，又不至于卡住一次状态上报。
pub const DEFAULT_MAX_SCAN_SECONDS: u64 = 5;
pub const MAX_SCAN_SECONDS: u64 = 30;

/// 扫描条目上限（个）：挡住「几百万小文件」把时间和内存吃掉的情况。
pub const SCAN_ENTRY_LIMIT: u64 = 200_000;

/// 报告契约前缀：完整报告与数据面 `IVSREP` 帧共用一个带版本的 id
/// （`wist.investigation.<topic>/v1`）。网关按它选渲染/落库规则，未知版本降级为原文展示。
pub const REPORT_SCHEMA_PREFIX: &str = "wist.investigation";

/// 数据面回传单帧正文的上限。
///
/// 为什么必须有：一帧就是**一整条记录**（行分帧），塞不下会被截断成半条 —— 那比不发更糟。
/// 典型的 `disk` 报告（10 行文件 + 10 行目录）只有几 KB；64 KiB 足够装下 `--top 50`。
/// 再大的时侯**逐级退化**（去 `rows` → 去 `hint` + 截 `detail`），见 [`Report::to_uplink_body`]：
/// 永远不发半条 JSON，也永远不把结论（`title` / `status` / `verdict`）丢掉。
pub const MAX_UPLINK_BODY_BYTES: usize = 64 * 1024;

/// 一次调查的请求（CLI 参数与网关 `params` 都收敛到它）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct InvestigateRequest {
    pub topic: String,
    /// 扫描根；`None` = 由题目自己挑（磁盘题：最紧张的文件系统挂载点）。
    pub path: Option<PathBuf>,
    pub top: usize,
    /// 只列不小于这个字节数的文件（目录合计不受影响）。
    pub min_size: u64,
    pub depth: usize,
    pub max_seconds: u64,
}

impl Default for InvestigateRequest {
    fn default() -> Self {
        Self {
            topic: TOPIC_DISK.to_string(),
            path: None,
            top: DEFAULT_TOP,
            min_size: 0,
            depth: DEFAULT_DEPTH,
            max_seconds: DEFAULT_MAX_SCAN_SECONDS,
        }
    }
}

impl InvestigateRequest {
    /// 按题目名建一份默认请求；空题目 = `disk`。
    pub fn for_topic(topic: &str) -> Result<Self, String> {
        let topic = topic.trim();
        if topic.is_empty() {
            return Ok(Self::default());
        }
        if !TOPICS.contains(&topic) {
            return Err(format!(
                "unknown investigation topic `{topic}` (supported: {})",
                TOPICS.join(" | ")
            ));
        }
        Ok(Self {
            topic: topic.to_string(),
            ..Self::default()
        })
    }

    /// 把参数夹到安全区间。CLI 在解析后、命令在执行前都调一次（幂等）。
    pub fn normalize(&mut self) {
        self.top = self.top.clamp(1, MAX_TOP);
        self.depth = self.depth.clamp(1, MAX_DEPTH);
        self.max_seconds = self.max_seconds.clamp(1, MAX_SCAN_SECONDS);
    }

    /// 解析网关下发的 `params`（JSON 文本）。
    ///
    /// 宽容解析是刻意的（与采集预检同一条理由）：`params` 是网关写的，版本会错位。空串 = 默认
    /// 题目（磁盘）；认不出的字段忽略；**只有题目本身不认识**才报错 —— 那是唯一会让这次调查
    /// 完全做不成的东西，应当明确回 `failed` 而不是猜一个题目去扫盘。
    pub fn from_params(params: &str) -> Result<Self, String> {
        let params = params.trim();
        if params.is_empty() {
            return Ok(Self::default());
        }
        let value: serde_json::Value = serde_json::from_str(params)
            .map_err(|err| format!("investigate params 不是合法 JSON：{err}"))?;
        let Some(object) = value.as_object() else {
            return Err("investigate params 必须是 JSON 对象".to_string());
        };
        let topic = object
            .get("topic")
            .and_then(serde_json::Value::as_str)
            .unwrap_or(TOPIC_DISK);
        let mut request = Self::for_topic(topic)?;
        if let Some(path) = object.get("path").and_then(serde_json::Value::as_str) {
            let path = path.trim();
            // 只认绝对路径：相对路径取决于进程 cwd，同一台机器换一种启动方式就翻面。
            if path.starts_with('/') {
                request.path = Some(PathBuf::from(path));
            }
        }
        if let Some(top) = object.get("top").and_then(serde_json::Value::as_u64) {
            request.top = top as usize;
        }
        if let Some(min_size) = object.get("min_size").and_then(serde_json::Value::as_u64) {
            request.min_size = min_size;
        }
        if let Some(depth) = object.get("depth").and_then(serde_json::Value::as_u64) {
            request.depth = depth as usize;
        }
        if let Some(max_seconds) = object
            .get("max_seconds")
            .and_then(serde_json::Value::as_u64)
        {
            request.max_seconds = max_seconds;
        }
        request.normalize();
        Ok(request)
    }
}

/// 证据表里的一行：`label` 是路径 / 挂载点，`value` 是体量，`note` 是补充（占比、inode…）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Row {
    pub label: String,
    pub value: String,
    pub note: String,
}

impl Row {
    pub fn new(
        label: impl Into<String>,
        value: impl Into<String>,
        note: impl Into<String>,
    ) -> Self {
        Self {
            label: label.into(),
            value: value.into(),
            note: note.into(),
        }
    }
}

/// 一节调查结果。`id` 稳定（供脚本/AI 按项取用），`rows` 是可选的证据表。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub id: &'static str,
    pub status: Status,
    pub title: String,
    pub detail: String,
    pub hint: Option<String>,
    pub rows: Vec<Row>,
}

impl Finding {
    pub fn new(
        id: &'static str,
        status: Status,
        title: impl Into<String>,
        detail: impl Into<String>,
    ) -> Self {
        Self {
            id,
            status,
            title: title.into(),
            detail: detail.into(),
            hint: None,
            rows: Vec::new(),
        }
    }

    pub fn ok(id: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(id, Status::Ok, title, detail)
    }

    pub fn warn(id: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(id, Status::Warn, title, detail)
    }

    pub fn fail(id: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self::new(id, Status::Fail, title, detail)
    }

    pub fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }

    pub fn rows(mut self, rows: Vec<Row>) -> Self {
        self.rows = rows;
        self
    }
}

/// 一次调查的完整结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub topic: String,
    pub observed_at: String,
    pub findings: Vec<Finding>,
}

impl Report {
    fn counts(&self) -> (usize, usize, usize) {
        let count = |status: Status| self.findings.iter().filter(|f| f.status == status).count();
        (count(Status::Ok), count(Status::Warn), count(Status::Fail))
    }

    pub fn overall(&self) -> Status {
        if self.findings.iter().any(|f| f.status == Status::Fail) {
            Status::Fail
        } else if self.findings.iter().any(|f| f.status == Status::Warn) {
            Status::Warn
        } else {
            Status::Ok
        }
    }

    /// 有 FAIL → 1；其余 0（与 `diagnose` 同一口径，脚本可直接当门禁）。
    pub fn exit_code(&self) -> i32 {
        i32::from(self.counts().2 > 0)
    }

    pub fn verdict(&self) -> String {
        let (ok, warn, fail) = self.counts();
        if fail == 0 && warn == 0 {
            return format!("全部正常（{ok} 项）");
        }
        let mut verdict = format!("{ok} 项正常 / {warn} 项警告 / {fail} 项失败");
        if let Some(first) = self.findings.iter().find(|f| f.status == Status::Fail) {
            let _ = write!(verdict, "；首要问题：{}", first.title);
        }
        verdict
    }

    /// 一段话摘要（回传网关的 `AgentCommandAck.detail` 用它）。
    ///
    /// 为什么不是整份报告：ack 的 `detail` 是一条状态上报里的短文本，塞不进一张表；完整报告
    /// 落到 `state/investigations/<topic>.json`，这里只给「结论 + 最要紧的几条证据」。
    pub fn summary(&self) -> String {
        let mut out = format!("{} 调查：{}", self.topic, self.verdict());
        for finding in &self.findings {
            if finding.status != Status::Ok {
                let _ = write!(out, "；{}（{}）", finding.title, finding.detail);
            }
        }
        if let Some(finding) = self.evidence() {
            let rows: Vec<String> = finding
                .rows
                .iter()
                .take(3)
                .map(|row| format!("{} {}", row.label, row.value))
                .collect();
            if !rows.is_empty() {
                let _ = write!(out, "；{}：{}", finding.title, rows.join("，"));
            }
        }
        truncate_chars(out, 600)
    }

    /// 挑**最像证据**的一节：题目无关。
    ///
    /// 优先 `*.largest_dirs`（盘满时“哪个目录”才是根因，单个大文件常常不是），
    /// 其次 `*.top_files`（最具体：哪个文件、多大），再次 `*.top_dirs`，最后退到第一个带表的节。
    /// 为什么不写死 id：`summary` 是题目无关的 —— 写死 `disk.top_files` 会让加第二道题时，
    /// 摘要静默只剩结论、没有任何证据（而且不会报错）。
    fn evidence(&self) -> Option<&Finding> {
        for suffix in [".largest_dirs", ".top_files", ".top_dirs"] {
            if let Some(finding) = self
                .findings
                .iter()
                .find(|finding| finding.id.ends_with(suffix) && !finding.rows.is_empty())
            {
                return Some(finding);
            }
        }
        self.findings
            .iter()
            .find(|finding| !finding.rows.is_empty())
    }

    /// 人读文本。`color = false` 时输出**纯文本**，逐字节可断言（与 `diagnose` 同一版式）。
    pub fn render_text(&self, color: bool) -> String {
        let paint = |code: &str, text: &str| -> String {
            if color {
                format!("\x1b[{code}m{text}{RESET}")
            } else {
                text.to_string()
            }
        };

        let mut out = String::new();
        let header = format!(
            "wist-agentd investigate {}  ({})  observed_at={}",
            self.topic,
            env!("CARGO_PKG_VERSION"),
            self.observed_at
        );
        let _ = writeln!(out, "{}", paint(BOLD, &header));
        for finding in &self.findings {
            let tag = paint(
                &format!("1;{}", finding.status.color()),
                finding.status.tag(),
            );
            let title = paint(BOLD, &finding.title);
            let _ = writeln!(out, "{tag} {title}\n       {}", finding.detail);
            for row in &finding.rows {
                let line = if row.note.is_empty() {
                    format!("{:<52} {:>12}", row.label, row.value)
                } else {
                    format!("{:<52} {:>12}   {}", row.label, row.value, row.note)
                };
                let _ = writeln!(out, "         {line}");
            }
            if let Some(hint) = &finding.hint {
                for (index, line) in hint.lines().enumerate() {
                    let marker = if index == 0 { "→ " } else { "  " };
                    let _ = writeln!(out, "       {}", paint(CYAN, &format!("{marker}{line}")));
                }
            }
        }
        let verdict = paint(&format!("1;{}", self.overall().color()), &self.verdict());
        let _ = writeln!(out, "\n{} {verdict}", paint(BOLD, "结论:"));
        out
    }

    /// 机器可读形态（CLI `--json` 与落盘报告同一份）。
    pub fn to_json(&self) -> serde_json::Value {
        let (ok, warn, fail) = self.counts();
        let findings: Vec<serde_json::Value> = self
            .findings
            .iter()
            .map(|finding| {
                serde_json::json!({
                    "id": finding.id,
                    "status": finding.status.as_str(),
                    "title": finding.title,
                    "detail": finding.detail,
                    "hint": finding.hint,
                    "rows": finding
                        .rows
                        .iter()
                        .map(|row| serde_json::json!({
                            "label": row.label,
                            "value": row.value,
                            "note": row.note,
                        }))
                        .collect::<Vec<_>>(),
                })
            })
            .collect();
        serde_json::json!({
            "command": "investigate",
            "topic": self.topic,
            "report_schema": self.report_schema(),
            "version": env!("CARGO_PKG_VERSION"),
            "observed_at": self.observed_at,
            "findings": findings,
            "summary": { "ok": ok, "warn": warn, "fail": fail, "overall": self.overall().as_str() },
            "verdict": self.verdict(),
        })
    }

    /// 报告契约 id（带版本）：`wist.investigation.<topic>/v1`。
    pub fn report_schema(&self) -> String {
        format!("{REPORT_SCHEMA_PREFIX}.{}/v1", self.topic)
    }

    /// 数据面回传用的正文（` IVSREP: ` 帧的 body）。
    ///
    /// 与 [`Self::to_json`] 的差别只有两处，都是为了**关联与体积**：
    /// * 带 `command_id` —— 报告走数据面、ack 走控制面，两者靠它 join；
    /// * 超 [`MAX_UPLINK_BODY_BYTES`] 时**逐级退化**（去 `rows` → 去 `hint` + 截 `detail`），
    ///   宁可只给结论，也不发半条 JSON（行分帧下一个断开的 JSON 会被当成丢失的记录）。
    ///   退化分两级是刻意的：第一次只丢证据表（典型大报告），第二次才动“结论文本”——
    ///   而结论才是这张报告存在的理由。
    pub fn to_uplink_body(&self, command_id: &str) -> Vec<u8> {
        let mut value = self.to_json();
        if let Some(object) = value.as_object_mut() {
            object.insert(
                "command_id".to_string(),
                serde_json::Value::String(command_id.to_string()),
            );
        }
        let body = serde_json::to_vec(&value).unwrap_or_default();
        if body.len() <= MAX_UPLINK_BODY_BYTES {
            return body;
        }

        // 一级退化：去掉证据表。
        if let Some(object) = value.as_object_mut() {
            if let Some(findings) = object.get_mut("findings").and_then(|f| f.as_array_mut()) {
                for finding in findings {
                    if let Some(finding) = finding.as_object_mut() {
                        finding.remove("rows");
                    }
                }
            }
            object.insert("rows_omitted".to_string(), serde_json::Value::Bool(true));
        }
        let body = serde_json::to_vec(&value).unwrap_or_default();
        if body.len() <= MAX_UPLINK_BODY_BYTES {
            return body;
        }

        // 二级退化：再去提示、截短正文（仍保留 title/status/verdict —— 那是结论本身）。
        if let Some(findings) = value.get_mut("findings").and_then(|f| f.as_array_mut()) {
            for finding in findings {
                if let Some(finding) = finding.as_object_mut() {
                    finding.remove("hint");
                    if let Some(detail) = finding.get("detail").and_then(|d| d.as_str()) {
                        finding.insert(
                            "detail".to_string(),
                            serde_json::Value::String(truncate_chars(detail.to_string(), 240)),
                        );
                    }
                }
            }
        }
        serde_json::to_vec(&value).unwrap_or_default()
    }

    /// 单行 JSON（`--json` 用；与 `diagnose --json` 同样紧凑可控）。
    pub fn render_json(&self) -> String {
        self.to_json().to_string()
    }
}

const BOLD: &str = "1";
const CYAN: &str = "36";
const RESET: &str = "\x1b[0m";

/// 跑一次调查（**不含 IO 输出**）。CLI 与一次性命令都从这里进。
pub async fn execute(
    request: &InvestigateRequest,
    config: Option<&AgentConfig>,
) -> Result<Report, String> {
    let mut request = request.clone();
    request.normalize();
    let topic = request.topic.clone();
    let topic_for_task = topic.clone();
    let config_for_task = config.cloned();
    // 扫描是**同步阻塞**的（目录遍历 + stat），而守护进程跑在同一套 tokio 运行时上：
    // 留在 async 线程里会把 3s 的心跳/上报一起拖住。丢到 blocking 池，tick 照常走。
    let findings = tokio::task::spawn_blocking(move || match topic_for_task.as_str() {
        TOPIC_DISK => crate::investigate_disk::investigate(&request, config_for_task.as_ref()),
        other => Err(format!("unknown investigation topic `{other}`")),
    })
    .await
    .map_err(|err| format!("调查任务执行失败：{err}"))??;
    Ok(Report {
        topic,
        observed_at: now_rfc3339(),
        findings,
    })
}

/// CLI 入口：`wist-agentd investigate [topic] [--path …] [--json]`。
///
/// 返回进程退出码：**有 FAIL = 1**（与 `diagnose` 一致，可直接 `|| 处理`）。
pub async fn run(
    config_root: Option<&Path>,
    request: InvestigateRequest,
    json: bool,
) -> AgentdResult<i32> {
    let config = config_root.and_then(load_optional_config);
    let report = execute(&request, config.as_ref())
        .await
        .map_err(|detail| AgentdReason::system_error().to_err().with_detail(detail))?;
    let text = if json {
        // JSON 永不上色：它是给机器/脚本读的。
        report.render_json()
    } else {
        report.render_text(crate::doctor::should_color())
    };
    // 保证恰好一个结尾换行；不用 `println!`：下游提前关管道（如 `| head`）时它会 panic。
    let mut text = text;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let _ = write!(std::io::stdout(), "{text}");
    Ok(report.exit_code())
}

/// 网关下发的一次性命令：跑完调查并落一份完整报告，返回 `(report, 报告路径)`。
///
/// **不在这里回传**：数据面的回传由 daemon 做（它才持有 sink / seq）。`outcome` 的语义
/// （调查做成了没有）也由 daemon 组装 —— 本函数只回答「调查跑完了没有」。
///
/// 落盘失败**不当作失败**：盘满正是最需要调查的时候，报告还在内存里，能回传就够了。
pub(crate) async fn run_for_command(
    config: &AgentConfig,
    request: &InvestigateRequest,
) -> Result<(Report, PathBuf), String> {
    let report = execute(request, Some(config)).await?;
    let path = report_path(Path::new(&config.paths.state_dir), &report.topic);
    if let Err(err) = crate::fs_async::write_json_atomic_async(&path, &report.to_json()).await {
        log::warn!(
            "event=InvestigationReportStoreFailed path={} detail=\"{err}\"",
            path.display()
        );
    }
    Ok((report, path))
}

/// 完整报告的落点：`state/investigations/<topic>.json`（每个题目只留最新一份，不会长）。
pub fn report_path(state_dir: &Path, topic: &str) -> PathBuf {
    state_dir
        .join("investigations")
        .join(format!("{topic}.json"))
}

/// 本机**调查能力**：能跑哪些面、是不是 root。
///
/// 与 `declared_logs_capabilities`（采集能力）同一条纪律：**从实现处取**，不另写一份名单
/// ——否则新增一道题时，上报与实现在这里静默漂移，网关会把新题当成“这台机器不会”。
///
/// `privileged` 单独一轴的原因：同一个面在非 root 下**能跑但答不全**（读不到
/// `/var/lib/docker`、`/root`），网关用它在界面上区分“完整答案”与“部分答案”。
pub fn capabilities() -> wist_contracts::capability_report::InvestigationCapabilities {
    wist_contracts::capability_report::InvestigationCapabilities {
        surfaces: TOPICS.iter().map(|topic| topic.to_string()).collect(),
        privileged: running_as_root(),
    }
}

#[cfg(unix)]
fn running_as_root() -> bool {
    // SAFETY: `geteuid` 无参数、无副作用，永远成功。
    unsafe { libc::geteuid() == 0 }
}

#[cfg(not(unix))]
fn running_as_root() -> bool {
    false
}

/// 读配置；**读不到不是错误**：磁盘调查不依赖 agentd 配置，只是少一节「agent 自己占多少」。
fn load_optional_config(config_root: &Path) -> Option<AgentConfig> {
    let path = crate::config_runtime::resolve_config_path(config_root);
    crate::config_runtime::load_from_path(&path).ok()
}

/// 人类可读的体量（二进制单位，一位小数）：`12.3 GiB`。
pub fn human_bytes(bytes: u64) -> String {
    const UNITS: [&str; 6] = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"];
    if bytes < 1024 {
        return format!("{bytes} B");
    }
    let mut value = bytes as f64;
    let mut unit = 0usize;
    while value >= 1024.0 && unit + 1 < UNITS.len() {
        value /= 1024.0;
        unit += 1;
    }
    format!("{value:.1} {}", UNITS[unit])
}

/// 占比文案：`68.2%`；分母为 0 时给 `-`（**不是** 0%，那会被读成「一点没占」）。
pub fn percent(part: u64, total: u64) -> String {
    if total == 0 {
        return "-".to_string();
    }
    format!("{:.1}%", part as f64 / total as f64 * 100.0)
}

/// 解析 `--min-size`：`0` / `1024` / `512k` / `8MiB` / `2G`（二进制单位，大小写不敏感）。
pub fn parse_size(text: &str) -> Result<u64, String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("missing size value".to_string());
    }
    let digits_end = text
        .find(|character: char| !character.is_ascii_digit())
        .unwrap_or(text.len());
    if digits_end == 0 {
        return Err(format!(
            "invalid size `{text}` (expected e.g. 1024, 512k, 8MiB)"
        ));
    }
    let (number, unit) = text.split_at(digits_end);
    let number: u64 = number
        .parse()
        .map_err(|_| format!("invalid size `{text}` (expected e.g. 1024, 512k, 8MiB)"))?;
    let multiplier: u64 = match unit.trim().to_ascii_lowercase().as_str() {
        "" | "b" => 1,
        "k" | "kb" | "kib" => 1024,
        "m" | "mb" | "mib" => 1024 * 1024,
        "g" | "gb" | "gib" => 1024 * 1024 * 1024,
        "t" | "tb" | "tib" => 1024u64.pow(4),
        other => {
            return Err(format!(
                "unknown size unit `{other}` in `{text}` (use B / K / M / G / T)"
            ));
        }
    };
    number
        .checked_mul(multiplier)
        .ok_or_else(|| format!("size `{text}` is too large"))
}

/// 按字符截断（不切坏 UTF-8），尾部给 `…`。
pub fn truncate_chars(text: String, limit: usize) -> String {
    if text.chars().count() <= limit {
        return text;
    }
    let mut truncated: String = text.chars().take(limit.saturating_sub(1)).collect();
    truncated.push('…');
    truncated
}

/// 扫描的时长预算（秒 → `Duration`）。
pub fn scan_budget(max_seconds: u64) -> Duration {
    Duration::from_secs(max_seconds.clamp(1, MAX_SCAN_SECONDS))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finding_with(id: &'static str, status: Status, title: &str) -> Finding {
        Finding::new(id, status, title, "detail")
    }

    #[test]
    fn sizes_are_binary_units_with_one_decimal() {
        assert_eq!(human_bytes(0), "0 B");
        assert_eq!(human_bytes(1023), "1023 B");
        assert_eq!(human_bytes(1024), "1.0 KiB");
        assert_eq!(human_bytes(1536), "1.5 KiB");
        assert_eq!(human_bytes(12 * 1024 * 1024 * 1024), "12.0 GiB");
        assert_eq!(human_bytes(3 * 1024u64.pow(4)), "3.0 TiB");
        // 大到 PiB 就停在 PiB，不越界到不存在的单位。
        assert_eq!(human_bytes(u64::MAX), "16384.0 PiB");
    }

    #[test]
    fn percent_never_reports_zero_for_an_empty_denominator() {
        assert_eq!(percent(0, 0), "-");
        assert_eq!(percent(1, 2), "50.0%");
        assert_eq!(percent(460, 460), "100.0%");
    }

    #[test]
    fn size_parser_accepts_plain_and_unit_suffixed_values() {
        assert_eq!(parse_size("0"), Ok(0));
        assert_eq!(parse_size("1024"), Ok(1024));
        assert_eq!(parse_size("512k"), Ok(512 * 1024));
        assert_eq!(parse_size("8 MiB"), Ok(8 * 1024 * 1024));
        assert_eq!(parse_size("2G"), Ok(2 * 1024 * 1024 * 1024));
        assert_eq!(parse_size("1TB"), Ok(1024u64.pow(4)));
    }

    #[test]
    fn size_parser_rejects_nonsense() {
        for bad in ["", "k", "-1", "1.5G", "12x", "99999999999999999999999T"] {
            assert!(parse_size(bad).is_err(), "should reject `{bad}`");
        }
    }

    #[test]
    fn topics_are_validated_against_the_vocabulary() {
        assert_eq!(
            InvestigateRequest::for_topic("").expect("default").topic,
            TOPIC_DISK
        );
        assert_eq!(
            InvestigateRequest::for_topic("  disk  ")
                .expect("disk")
                .topic,
            TOPIC_DISK
        );
        let err = InvestigateRequest::for_topic("memory").expect_err("unknown topic");
        assert!(err.contains("memory"), "{err}");
        assert!(err.contains(TOPIC_DISK), "{err}");
    }

    #[test]
    fn params_default_to_a_disk_investigation() {
        let request = InvestigateRequest::from_params("").expect("default");
        assert_eq!(request, InvestigateRequest::default());
        let request = InvestigateRequest::from_params("{}").expect("empty object");
        assert_eq!(request.topic, TOPIC_DISK);
        assert!(request.path.is_none());
    }

    #[test]
    fn params_only_carry_known_well_typed_fields() {
        let request = InvestigateRequest::from_params(
            r#"{"topic":"disk","path":"/var","top":3,"min_size":1048576,"depth":4,"max_seconds":2,"unknown":1}"#,
        )
        .expect("params");
        assert_eq!(request.path, Some(PathBuf::from("/var")));
        assert_eq!(request.top, 3);
        assert_eq!(request.min_size, 1_048_576);
        assert_eq!(request.depth, 4);
        assert_eq!(request.max_seconds, 2);
    }

    #[test]
    fn params_ignore_relative_paths_and_clamp_ranges() {
        let request = InvestigateRequest::from_params(
            r#"{"path":"relative/dir","top":9999,"depth":0,"max_seconds":9999}"#,
        )
        .expect("params");
        assert!(request.path.is_none(), "相对路径不认");
        assert_eq!(request.top, MAX_TOP);
        assert_eq!(request.depth, 1);
        assert_eq!(request.max_seconds, MAX_SCAN_SECONDS);
    }

    #[test]
    fn params_that_are_not_json_objects_are_rejected() {
        assert!(InvestigateRequest::from_params("not json").is_err());
        assert!(InvestigateRequest::from_params("[1,2]").is_err());
        // 未知题目必须报错：猜一个题目去扫盘比明确说「不认识」更糟。
        let err = InvestigateRequest::from_params(r#"{"topic":"memory"}"#).expect_err("unknown");
        assert!(err.contains("memory"), "{err}");
    }

    #[test]
    fn a_single_fail_makes_the_exit_code_nonzero() {
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "t".to_string(),
            findings: vec![
                finding_with("a", Status::Ok, "ok"),
                finding_with("b", Status::Fail, "full"),
            ],
        };
        assert_eq!(report.exit_code(), 1);
        assert_eq!(report.overall(), Status::Fail);
        assert!(report.verdict().contains("首要问题：full"));
    }

    #[test]
    fn warnings_do_not_fail_the_exit_code() {
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "t".to_string(),
            findings: vec![
                finding_with("a", Status::Ok, "ok"),
                finding_with("b", Status::Warn, "tight"),
            ],
        };
        assert_eq!(report.exit_code(), 0);
        assert_eq!(report.overall(), Status::Warn);
    }

    #[test]
    fn text_rendering_is_plain_and_lists_rows() {
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "2026-10-30T00:00:00Z".to_string(),
            findings: vec![
                Finding::fail("disk.filesystems", "磁盘占用", "/ 96.4% 已用")
                    .hint("先看一级目录")
                    .rows(vec![Row::new("/", "96.4% 已用", "443 GiB / 460 GiB")]),
            ],
        };
        let text = report.render_text(false);
        assert!(!text.contains('\u{1b}'), "纯文本里不该有颜色码");
        assert!(text.contains("investigate disk"), "{text}");
        assert!(text.contains("[FAIL] 磁盘占用"), "{text}");
        assert!(text.contains("443 GiB / 460 GiB"), "{text}");
        assert!(text.contains("→ 先看一级目录"), "{text}");
        assert!(
            text.contains("结论: 0 项正常 / 0 项警告 / 1 项失败"),
            "{text}"
        );
    }

    #[test]
    fn json_carries_rows_and_the_overall_status() {
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "2026-10-30T00:00:00Z".to_string(),
            findings: vec![
                Finding::warn("disk.filesystems", "磁盘占用", "tight").rows(vec![Row::new(
                    "/",
                    "88.0% 已用",
                    "",
                )]),
            ],
        };
        let value = report.to_json();
        assert_eq!(value["command"], "investigate");
        assert_eq!(value["topic"], TOPIC_DISK);
        assert_eq!(value["report_schema"], "wist.investigation.disk/v1");
        assert_eq!(value["summary"]["overall"], "warn");
        assert_eq!(value["summary"]["warn"], 1);
        assert_eq!(value["findings"][0]["id"], "disk.filesystems");
        assert_eq!(value["findings"][0]["rows"][0]["label"], "/");
        // 落盘报告必须能再读回来（网关那份完整报告就是它）。
        let _: serde_json::Value = serde_json::from_str(&report.render_json()).expect("valid json");
    }

    #[test]
    fn the_uplink_body_carries_the_command_id_for_correlation() {
        // 报告走数据面、ack 走控制面：`command_id` 是两者唯一的关联键。
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "2026-10-30T00:00:00Z".to_string(),
            findings: vec![Finding::ok("disk.filesystems", "磁盘占用正常", "ok")],
        };
        let body = report.to_uplink_body("cmd_agent_1_refresh_123");
        let value: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        assert_eq!(value["command_id"], "cmd_agent_1_refresh_123");
        assert_eq!(value["report_schema"], "wist.investigation.disk/v1");
        assert!(value.get("rows_omitted").is_none(), "小报告不该退化");
        // 行分帧：正文里不能有换行（否则一帧会被拆成两条记录）。
        assert!(!body.contains(&b'\n'), "body must stay single-line");
    }

    #[test]
    fn an_oversized_uplink_body_drops_rows_instead_of_being_truncated() {
        // 50 行超长路径 x 2 节，很容易超 64 KiB；超了就去掉 rows，而不是发半条 JSON。
        let long = format!("/var/log/{}", "x".repeat(2000));
        let rows: Vec<Row> = (0..50)
            .map(|index| Row::new(format!("{long}-{index}"), "1.0 GiB", "占 1.0%"))
            .collect();
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "t".to_string(),
            findings: vec![
                Finding::ok("disk.top_files", "最大的文件", "d").rows(rows.clone()),
                Finding::ok("disk.top_dirs", "一级目录占用", "d").rows(rows),
            ],
        };

        let body = report.to_uplink_body("cmd-1");
        assert!(
            body.len() <= MAX_UPLINK_BODY_BYTES,
            "body must stay bounded"
        );
        let value: serde_json::Value = serde_json::from_slice(&body).expect("still valid json");
        assert_eq!(value["rows_omitted"], true);
        assert_eq!(value["command_id"], "cmd-1");
        // 结论仍在：退化的只是证据表。
        assert_eq!(value["findings"][0]["id"], "disk.top_files");
        assert!(value["findings"][0].get("rows").is_none());
    }

    #[test]
    fn the_summary_picks_evidence_from_any_topic() {
        // 摘要不能用“id == disk.top_files”写死：换一道题也应有证据行、而不是只剩结论。
        let report = Report {
            topic: "mem".to_string(),
            observed_at: "t".to_string(),
            findings: vec![
                Finding::ok("mem.processes", "进程概览", "共 210 个进程"),
                Finding::ok("mem.top_procs", "内存占用前 3", "按 RSS").rows(vec![
                    Row::new("postgres", "1.2 GiB", "占 12%"),
                    Row::new("java", "900.0 MiB", "占 9%"),
                ]),
            ],
        };
        let summary = report.summary();
        assert!(summary.contains("内存占用前 3"), "{summary}");
        assert!(summary.contains("postgres 1.2 GiB"), "{summary}");
        // 第一个带证据表的节也会被用上（题目只给了非 top_* 的节时）。
        let fallback = Report {
            topic: "mem".to_string(),
            observed_at: "t".to_string(),
            findings: vec![
                Finding::ok("mem.processes", "进程概览", "共 3 个")
                    .rows(vec![Row::new("pid 1", "init", "")]),
            ],
        };
        assert!(
            fallback.summary().contains("进程概览：pid 1 init"),
            "{}",
            fallback.summary()
        );
    }

    #[test]
    fn the_summary_leads_with_the_verdict_and_names_bad_findings() {
        let report =
            Report {
                topic: TOPIC_DISK.to_string(),
                observed_at: "t".to_string(),
                findings: vec![
                    Finding::fail("disk.filesystems", "磁盘占用", "/ 96.4% 已用"),
                    Finding::ok("disk.top_files", "最大的文件", "列出前 1 个")
                        .rows(vec![Row::new("/var/log/a.log", "12.3 GiB", "")]),
                ],
            };
        let summary = report.summary();
        assert!(summary.starts_with("disk 调查："), "{summary}");
        assert!(summary.contains("磁盘占用"), "{summary}");
        assert!(summary.contains("/var/log/a.log 12.3 GiB"), "{summary}");
        assert!(summary.chars().count() <= 600);
    }

    #[test]
    fn truncate_keeps_chars_intact() {
        let text = "磁盘已经写满写满写满";
        let truncated = truncate_chars(text.to_string(), 5);
        assert_eq!(truncated.chars().count(), 5);
        assert!(truncated.ends_with('…'));
    }

    #[test]
    fn capabilities_come_from_the_topic_registry() {
        // 上报与实现**同源**：新增一道题时，这里自动跟上；网关不会把新题当成“不会”。
        let capabilities = capabilities();
        assert_eq!(capabilities.surfaces, vec![TOPIC_DISK.to_string()]);
        // `privileged` 取决于跑测试的身份：只要求它与 `geteuid` 一致，不假设是 root。
        #[cfg(unix)]
        // SAFETY: 同 `running_as_root`。
        assert_eq!(capabilities.privileged, unsafe { libc::geteuid() == 0 });
    }

    #[test]
    fn a_pathological_detail_degrades_all_the_way_down_to_the_cap() {
        // 一级退化（去 rows）救不了“单条 detail 就 80 KB”这种病态输入：
        // 二级退化必须把它截到 240 字，且**结论**（title/status/verdict）仍在。
        let report = Report {
            topic: TOPIC_DISK.to_string(),
            observed_at: "t".to_string(),
            findings: vec![
                Finding::fail("disk.filesystems", "磁盘即将写满", "x".repeat(80_000))
                    .hint("y".repeat(20_000)),
            ],
        };

        let body = report.to_uplink_body("cmd-1");
        assert!(
            body.len() <= MAX_UPLINK_BODY_BYTES,
            "body must stay under the frame cap: {}",
            body.len()
        );
        let value: serde_json::Value = serde_json::from_slice(&body).expect("valid json");
        assert_eq!(value["rows_omitted"], true);
        let finding = &value["findings"][0];
        assert_eq!(finding["status"], "fail", "结论不能一起丢");
        assert_eq!(finding["title"], "磁盘即将写满");
        assert!(finding.get("hint").is_none(), "二级退化要去掉提示");
        let detail = finding["detail"].as_str().expect("detail");
        assert!(
            detail.chars().count() <= 240,
            "detail must be truncated: {}",
            detail.chars().count()
        );
        assert!(value["verdict"].as_str().is_some_and(|v| !v.is_empty()));
    }

    #[tokio::test]
    async fn an_unknown_topic_fails_before_touching_the_disk() {
        let request = InvestigateRequest {
            topic: "memory".to_string(),
            ..InvestigateRequest::default()
        };
        let err = execute(&request, None).await.expect_err("unknown topic");
        assert!(err.contains("memory"), "{err}");
    }

    #[tokio::test]
    async fn the_disk_topic_produces_findings_without_a_config() {
        let request = InvestigateRequest {
            path: Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
            top: 2,
            max_seconds: 5,
            ..InvestigateRequest::default()
        };
        let report = execute(&request, None).await.expect("report");
        assert_eq!(report.topic, TOPIC_DISK);
        assert!(report.findings.iter().any(|f| f.id == "disk.filesystems"));
        assert!(report.findings.iter().any(|f| f.id == "disk.top_files"));
        assert!(
            !report.findings.iter().any(|f| f.id == "disk.agent_dirs"),
            "没有配置时不该编一节 agent 目录出来"
        );
    }

    /// 网关下发路径的完整回路：跑完 → 完整报告落盘 → ack 里带结论与落点。
    #[tokio::test]
    async fn the_command_path_stores_a_full_report_and_acks_with_the_verdict() {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let state_dir = std::env::temp_dir().join(format!("wist-agentd-investigate-{suffix}"));
        std::fs::create_dir_all(&state_dir).expect("state dir");

        let config = AgentConfig::new(
            crate::config::agent_config::AgentSection::default(),
            crate::config::agent_config::ControlPlaneSection::default(),
            crate::config::agent_config::PathsSection {
                state_dir: state_dir.display().to_string(),
                ..crate::config::agent_config::PathsSection::default()
            },
            crate::config::agent_config::ExecutionSection::default(),
        );
        let request = InvestigateRequest {
            path: Some(PathBuf::from(env!("CARGO_MANIFEST_DIR"))),
            top: 2,
            max_seconds: 2,
            ..InvestigateRequest::default()
        };

        let (report, path) = run_for_command(&config, &request)
            .await
            .expect("investigation ran");
        assert_eq!(report.topic, TOPIC_DISK);
        // 报告落盘：盘满时中心可能收不到帧，运维 SSH 上来还能读到它。
        assert_eq!(path, report_path(&state_dir, TOPIC_DISK));
        let text = std::fs::read_to_string(&path).expect("report file");
        let value: serde_json::Value = serde_json::from_str(&text).expect("valid json");
        assert_eq!(value["command"], "investigate");
        assert_eq!(value["topic"], TOPIC_DISK);
        assert_eq!(value["report_schema"], "wist.investigation.disk/v1");
        assert!(value["findings"].as_array().is_some_and(|f| !f.is_empty()));

        let _ = std::fs::remove_dir_all(&state_dir);
    }
}
