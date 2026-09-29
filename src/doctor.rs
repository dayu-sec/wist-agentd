//! `wist-agentd diagnose`：一屏内回答「这台机器现在有什么问题」。
//!
//! 为什么要有它：agentd 的故障大多出在**进程外** —— 配置里的 endpoint 端口与网关实际监听的不一致、
//! 信任锚被换过、凭据被拒或过期、网关换了库/锚、服务根本没起来……这些在日志里各是一行，
//! 读起来要自己拼因果（而且要 root 才能读日志）。`diagnose` 按
//! 「配置 → 身份 → 安装/服务 → 控制面连通 → 数据面（上送）→ 本地工作」
//! 自己探一遍，每项给 `OK` / `WARN` / `FAIL` 与**下一步怎么做**，最后给一个总判定：
//! **退出码非零 = 有 FAIL**，脚本与 AI 可以直接用。
//!
//! 三条刻意的取舍：
//!
//! 1. **复用守护进程同款判定**：生效的上送输出用 [`effective_output`]、
//!    控制面探测用 [`fetch_uplink_grant`] —— 所以「`diagnose` 说通」与「守护进程能通」是同一套规则，
//!    不会出现工具说一套、进程做一套；
//! 2. **分层报错**：DNS → TCP → TLS/HTTP/鉴权 逐层报，断在哪层就说哪层（这正是「端口不对」与
//!    「证书不受信」的区别所在），并给出该改哪里；
//! 3. **只读**：不发心跳（不改网关状态）、不改配置、不建目录；唯一副作用是 `paths.writable`
//!    会临时建/删一个空探针文件。`--offline` 跳过网络探测，但**本地能得出的结论**
//!    （生效输出 / spool / 本地工作）照常报。

use std::fmt::Write as _;
use std::io::{self, IsTerminal, Write as _};
use std::net::{SocketAddr, ToSocketAddrs};
use std::path::{Path, PathBuf};
use std::time::Duration;

use wist_contracts::agent_config::AgentConfig;
use wist_contracts::agent_uplink::AgentUplinkGrant;

use crate::config_runtime;
use crate::control::uplink::{UplinkFetch, fetch_uplink_grant};
use crate::enrollment::is_registered_agent_id;
use crate::error::AgentdResult;
use crate::runtime::daemon::telemetry_support::effective_output;
use crate::service::{self, ServiceLayout, ServicePlatform, ServiceScope, ServiceSpec};
use crate::state_store::{agent_runtime, client_identity, work};

/// 单次网络探测的超时（TCP 连接 / 数据面目标）。
///
/// 与上送/工作拉取同量级：诊断要快出结论，不该让一次黑洞连接把整条命令拖到分钟级。
const PROBE_TIMEOUT: Duration = Duration::from_secs(3);

/// 凭据/证书剩余不足这个时长就告警（与证书 30 天续签窗口同一口径的来源）。
const EXPIRY_WARN_WINDOW: Duration = Duration::from_secs(7 * 24 * 60 * 60);

/// spool 积压到这个体量就告警：说明出口在失败或长期跟不上。
const SPOOL_WARN_BYTES: u64 = 8 * 1024 * 1024;

/// ANSI 样式码（不引依赖；终端不支持时不会走到这里——
/// [`should_color`] 已经是 TTY 才开）。
const BOLD: &str = "1";
const RED: &str = "31";
const GREEN: &str = "32";
const YELLOW: &str = "33";
const CYAN: &str = "36";
const RESET: &str = "\x1b[0m";

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Status {
    Ok,
    Warn,
    Fail,
}

impl Status {
    fn tag(self) -> &'static str {
        match self {
            Status::Ok => "[OK]",
            Status::Warn => "[WARN]",
            Status::Fail => "[FAIL]",
        }
    }

    fn as_str(self) -> &'static str {
        match self {
            Status::Ok => "ok",
            Status::Warn => "warn",
            Status::Fail => "fail",
        }
    }

    /// 状态对应的前景色（绿 / 黄 / 红）。
    fn color(self) -> &'static str {
        match self {
            Status::Ok => GREEN,
            Status::Warn => YELLOW,
            Status::Fail => RED,
        }
    }
}

/// 一项检查结果。`id` 稳定（供脚本/AI 按项取用），`hint` 只在该项不是 OK 时给。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Check {
    pub(crate) id: &'static str,
    pub(crate) status: Status,
    pub(crate) title: String,
    pub(crate) detail: String,
    pub(crate) hint: Option<String>,
}

impl Check {
    fn ok(id: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Ok,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    fn warn(id: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Warn,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    fn fail(id: &'static str, title: impl Into<String>, detail: impl Into<String>) -> Self {
        Self {
            id,
            status: Status::Fail,
            title: title.into(),
            detail: detail.into(),
            hint: None,
        }
    }

    fn hint(mut self, hint: impl Into<String>) -> Self {
        self.hint = Some(hint.into());
        self
    }
}

/// 一次诊断的全部结果。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Report {
    pub(crate) checks: Vec<Check>,
}

impl Report {
    fn counts(&self) -> (usize, usize, usize) {
        let count = |status: Status| self.checks.iter().filter(|c| c.status == status).count();
        (count(Status::Ok), count(Status::Warn), count(Status::Fail))
    }

    /// 有 FAIL → 1（便于 `wist-agentd diagnose || 处理`）；其余 0。
    pub(crate) fn exit_code(&self) -> i32 {
        i32::from(self.counts().2 > 0)
    }

    /// 总体状态：只要有一项 FAIL 就是 FAIL，否则有 WARN 就是 WARN，再否则 OK。
    fn overall(&self) -> Status {
        if self.checks.iter().any(|c| c.status == Status::Fail) {
            Status::Fail
        } else if self.checks.iter().any(|c| c.status == Status::Warn) {
            Status::Warn
        } else {
            Status::Ok
        }
    }

    /// 一句话总判定：先报计数，再点出第一个 FAIL（那是优先要处理的）。
    pub(crate) fn verdict(&self) -> String {
        let (ok, warn, fail) = self.counts();
        if fail == 0 && warn == 0 {
            return format!("全部正常（{ok} 项）");
        }
        let mut verdict = format!("{ok} 项正常 / {warn} 项警告 / {fail} 项失败");
        if let Some(first) = self.checks.iter().find(|c| c.status == Status::Fail) {
            let _ = write!(verdict, "；首要问题：{}", first.title);
        }
        verdict
    }

    /// 人读文本。`color = false`（重定向 / `NO_COLOR`）时输出**纯文本**，逐字节可断言。
    pub(crate) fn render_text(&self, color: bool) -> String {
        let paint = |code: &str, text: &str| -> String {
            if color {
                format!("\x1b[{code}m{text}{RESET}")
            } else {
                text.to_string()
            }
        };

        let mut out = String::new();
        let header = format!("wist-agentd diagnose  ({})", env!("CARGO_PKG_VERSION"));
        let _ = writeln!(out, "{}", paint(BOLD, &header));
        for check in &self.checks {
            // 标签按状态上色加粗（一眼扫到 FAIL/WARN）；标题加粗；提示用青色，跟“是什么毛病”区分开。
            let tag = paint(&format!("1;{}", check.status.color()), check.status.tag());
            let title = paint(BOLD, &check.title);
            let _ = writeln!(out, "{tag} {title}\n       {}", check.detail);
            if let Some(hint) = &check.hint {
                let _ = writeln!(out, "       {}", paint(CYAN, &format!("→ {hint}")));
            }
        }
        let verdict = paint(&format!("1;{}", self.overall().color()), &self.verdict());
        let _ = writeln!(out, "\n{} {verdict}", paint(BOLD, "结论:"));
        out
    }

    pub(crate) fn render_json(&self) -> String {
        let (ok, warn, fail) = self.counts();
        let checks: Vec<serde_json::Value> = self
            .checks
            .iter()
            .map(|check| {
                serde_json::json!({
                    "id": check.id,
                    "status": check.status.as_str(),
                    "title": check.title,
                    "detail": check.detail,
                    "hint": check.hint,
                })
            })
            .collect();
        serde_json::json!({
            "command": "diagnose",
            "version": env!("CARGO_PKG_VERSION"),
            "checks": checks,
            "summary": { "ok": ok, "warn": warn, "fail": fail },
            "verdict": self.verdict(),
        })
        .to_string()
    }
}

/// 跑一遍诊断并打印结果；返回进程退出码（有 FAIL 时为 1）。
pub(crate) async fn run(config_root: &Path, json: bool, offline: bool) -> AgentdResult<i32> {
    let report = diagnose(config_root, offline).await;
    let text = if json {
        // JSON 永不上色：它是给机器/脚本读的。
        report.render_json()
    } else {
        report.render_text(should_color())
    };
    // 保证恰好一个结尾换行；不用 `println!`：下游提前关管道（如 `| head`）时它会 panic。
    let mut text = text;
    if !text.ends_with('\n') {
        text.push('\n');
    }
    let _ = write!(std::io::stdout(), "{text}");
    Ok(report.exit_code())
}

/// 纯函数版的上色判定（把环境取值与是否 TTY 作为入参）。
///
/// 约定：`NO_COLOR` 非空 → 关；否则 `CLICOLOR_FORCE` 非空且非 `0` → 开；再否则看是不是 TTY。
fn color_enabled(no_color: Option<&str>, force: Option<&str>, is_tty: bool) -> bool {
    if no_color.is_some_and(|value| !value.is_empty()) {
        return false;
    }
    if force.is_some_and(|value| !value.is_empty() && value != "0") {
        return true;
    }
    is_tty
}

/// 文本输出是否上色：默认**只在 TTY** 上色（重定向 / 管道输出保持纯文本）。
fn should_color() -> bool {
    color_enabled(
        std::env::var("NO_COLOR").ok().as_deref(),
        std::env::var("CLICOLOR_FORCE").ok().as_deref(),
        std::io::stdout().is_terminal(),
    )
}

async fn diagnose(config_root: &Path, offline: bool) -> Report {
    let mut checks = Vec::new();
    let config_path = config_runtime::resolve_config_path(config_root);

    let config = match load_config_with_state_identity(&config_path, &mut checks) {
        Some(config) => config,
        // 配置读不出来，后面的检查都无从谈起（服务状态、凭据、网络目标都来自它）。
        None => return Report { checks },
    };

    checks.push(config_path_check(&config_path));
    checks.extend(control_plane_checks(&config));
    checks.extend(path_checks(&config));
    checks.extend(identity_checks(&config).await);
    checks.extend(service_checks(config_root, &config));

    if offline {
        checks.push(Check::warn(
            "network.skipped",
            "已跳过网络探测（--offline）",
            "控制面与数据面是否可达**未验证**",
        ));
        // 网络相关的跳过，但**本地就能得出的结论不该跟着丢**：生效输出 / spool 积压 / 本地工作。
        checks.extend(uplink_local_checks(&config, None, true).await);
    } else {
        let (network_checks, grant) = network_checks(&config).await;
        checks.extend(network_checks);
        checks.extend(uplink_local_checks(&config, grant.as_ref(), false).await);
        checks.extend(uplink_target_check(&config, grant.as_ref()).await);
    }

    Report { checks }
}

/// 读配置；失败时压成一条 FAIL（附完整因果链的一行版本）。
///
/// 先看 `metadata` 而不是 `is_file()`：这样「忘了 sudo」这种**权限不足**能与「真的没有文件」
/// 分开报 —— 否则系统级部署下非 root 运行会误报「配置文件不存在」。
fn load_config(path: &Path, checks: &mut Vec<Check>) -> Option<AgentConfig> {
    match std::fs::metadata(path) {
        Ok(meta) if meta.is_file() => {}
        Ok(_) => {
            checks.push(
                Check::fail(
                    "config.file",
                    "配置路径不是文件",
                    path.display().to_string(),
                )
                .hint("把配置写成 `agentd.toml` 文件"),
            );
            return None;
        }
        Err(err) if err.kind() == io::ErrorKind::PermissionDenied => {
            checks.push(
                Check::fail(
                    "config.file",
                    "配置文件读不了（权限不足）",
                    format!("{}：{err}", path.display()),
                )
                .hint("系统级部署在 /etc/wist-agentd（需 root）：用 `sudo wist-agentd diagnose`"),
            );
            return None;
        }
        Err(_) => {
            checks.push(
                Check::fail("config.file", "配置文件不存在", path.display().to_string())
                    .hint("先初始化/安装：`wist-agentd init-config`，或跑安装脚本"),
            );
            return None;
        }
    }
    match config_runtime::load_from_path(path) {
        Ok(config) => Some(config),
        Err(err) => {
            checks.push(
                Check::fail(
                    "config.file",
                    "配置文件读不出来",
                    one_line(&err.display_chain()),
                )
                .hint("检查 TOML 语法、字段名与文件权限"),
            );
            None
        }
    }
}

fn config_path_check(path: &Path) -> Check {
    Check::ok("config.file", "配置文件可读", path.display().to_string())
}

/// 读配置，并**注入 state 里的身份与凭据** —— 与守护进程启动同一步
/// （`ensure_enrolled_with_config_path` → `load_state_identity`）。
///
/// 为什么必须做：**bearer 凭据从不写进 `agentd.toml`，只落 state**。不注入的话
/// `fetch_uplink_grant` 会因为“配置里没凭据”直接短路成 `NotDispatched`，工具就会把
/// 「网关应答正常、只是这次没下发授权」假报成「未入网 / 旧网关」—— 正是设计上要避免的
/// 「工具说一套、进程做一套」。这里只读 state 注入（内存态），不联网、不落盘。
fn load_config_with_state_identity(
    config_path: &Path,
    checks: &mut Vec<Check>,
) -> Option<AgentConfig> {
    let mut config = load_config(config_path, checks)?;
    let state_dir = PathBuf::from(&config.paths.state_dir);
    if let Err(err) = crate::enrollment::restore_runtime_identity(&mut config, &state_dir) {
        checks.push(Check::warn(
            "identity.state",
            "state 身份读不出来",
            one_line(&err.display_chain()),
        ));
    }
    Some(config)
}

/// 控制面配置本身是否自洽：开关、endpoint（含**推导出的端口**）、TLS 形态、信任锚。
///
/// 「推导出的端口」是刻意打出来的：`endpoint = "https://host"`（不写端口）实际会连 **443**，
/// 而网关可能发布在别的端口上 —— 这一条是本工具的常见命中点。
fn control_plane_checks(config: &AgentConfig) -> Vec<Check> {
    let control = &config.control_plane;
    let mut checks = Vec::new();

    if !control.enabled {
        checks.push(
            Check::warn(
                "config.control_plane",
                "控制面未启用（[control_plane] enabled = false）",
                "这台机器不会注册、不上报状态、也拿不到工作",
            )
            .hint("要接入网关就设 enabled = true 并填 endpoint"),
        );
        return checks;
    }

    let Some(endpoint) = control
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|v| !v.is_empty())
    else {
        checks.push(
            Check::fail(
                "config.control_plane",
                "没配 [control_plane] endpoint",
                "控制面地址为空，agent 无处可连",
            )
            .hint("填 https://<网关域名>[:<端口>]"),
        );
        return checks;
    };

    let tls_mode = effective_tls_mode(control.tls_mode.as_deref(), endpoint);
    match split_endpoint(endpoint) {
        Some(target) => checks.push(Check::ok(
            "config.control_plane",
            format!("控制面 endpoint 将连接 {}:{}", target.host, target.port),
            format!(
                "endpoint={endpoint} tls_mode={tls_mode}{}",
                if target.port_explicit {
                    ""
                } else {
                    "（未写端口 ⇒ 按 scheme 的默认端口）"
                }
            ),
        )),
        None => checks.push(
            Check::fail(
                "config.control_plane",
                "endpoint 解析不出主机与端口",
                format!("endpoint={endpoint}"),
            )
            .hint("写成 https://host 或 https://host:port"),
        ),
    }

    if tls_mode == "none" {
        checks.push(
            Check::warn(
                "config.tls",
                "已关闭 TLS 证书校验（tls_mode = \"none\"）",
                "仅限自签/实验室环境；生产上会失去对网关的身份校验",
            )
            .hint("改成 tls_mode = \"https\" 并用 trust_bundle 做锚"),
        );
    } else if tls_mode == "http" {
        checks.push(Check::ok(
            "config.tls",
            "明文 HTTP（无 TLS）",
            format!("tls_mode={tls_mode}"),
        ));
    } else if control.trust_bundle.is_some() {
        checks.push(Check::ok(
            "config.tls",
            format!("TLS 形态：{tls_mode}"),
            "信任锚来自配置里的 trust_bundle",
        ));
    } else {
        // 没配信任锚**本身不是问题**：`https`/`verify` 下 reqwest 会回落到平台/公有根证书
        // （见 `enrollment.rs` 的 `https|verify` 分支）；只有网关用自签/私有 CA 才需要显式
        // trust_bundle，而那种情况由**实际握手结果**（`network.control_plane`）暴露 ——
        // 这里只作说明，不误报 WARN。
        checks.push(Check::ok(
            "config.tls",
            format!("TLS 形态：{tls_mode}（信任锚：平台根证书）"),
            "未配 trust_bundle；网关用公有 CA 正常，自签/私有 CA 需把网关 CA 填进 trust_bundle",
        ));
    }

    checks
}

/// 运行期落点（root / state / log / run）是否可写 —— 这几个目录写不了，守护进程起不来或不上报。
/// **不新建目录**：不存在的目录回到最近的已存在祖先探写（见 [`probe_writable`]）。
fn path_checks(config: &AgentConfig) -> Vec<Check> {
    let mut checks = Vec::new();
    let dirs = [
        ("root", &config.paths.root_dir),
        ("state", &config.paths.state_dir),
        ("log", &config.paths.log_dir),
        ("run", &config.paths.run_dir),
    ];
    let mut bad = Vec::new();
    let mut will_create = Vec::new();
    for (name, dir) in dirs {
        match probe_writable(Path::new(dir)) {
            Ok(true) => {}
            Ok(false) => will_create.push(name),
            Err(err) => bad.push(format!("{name}={dir}（{err}）")),
        }
    }
    if !bad.is_empty() {
        checks.push(
            Check::fail("paths.writable", "运行目录写不了", bad.join("；"))
                .hint("系统级安装要看权限/挂载（/var/lib、/var/log）；用 `wist-agentd service status` 看落点"),
        );
    } else {
        let detail = if will_create.is_empty() {
            format!(
                "state={} log={}",
                config.paths.state_dir, config.paths.log_dir
            )
        } else {
            format!(
                "state={} log={}；尚不存在（启动时会创建）：{}",
                config.paths.state_dir,
                config.paths.log_dir,
                will_create.join(", ")
            )
        };
        checks.push(Check::ok("paths.writable", "运行目录可写", detail));
    }
    checks
}

/// 身份与凭据：agent_id / instance_id、bearer 凭据有效期、客户端证书（mTLS）状态、最近一次续签。
async fn identity_checks(config: &AgentConfig) -> Vec<Check> {
    let mut checks = Vec::new();
    let state_dir = PathBuf::from(&config.paths.state_dir);

    let runtime_state =
        match agent_runtime::load_or_default_async(&agent_runtime::path_for(&state_dir)).await {
            Ok(state) => state,
            Err(err) => {
                checks.push(
                    Check::fail(
                        "identity.state",
                        "身份状态文件读不出来",
                        format!("{}：{err}", agent_runtime::path_for(&state_dir).display()),
                    )
                    .hint("守护进程会因此起不来：恢复或删掉该文件后重装/重新注册"),
                );
                return checks;
            }
        };

    // 配置里声明的身份优先（安装脚本写进去的），否则看 state。
    let agent_id = config
        .agent
        .agent_id
        .as_deref()
        .map(str::trim)
        .filter(|value| is_registered_agent_id(value))
        .map(str::to_string)
        .or_else(|| {
            let from_state = runtime_state.agent_id.trim();
            is_registered_agent_id(from_state).then(|| from_state.to_string())
        });

    match agent_id {
        Some(agent_id) => checks.push(Check::ok(
            "identity.agent",
            format!("已注册身份 {agent_id}"),
            format!(
                "instance_id={} mode={:?}",
                runtime_state.instance_id, runtime_state.mode
            ),
        )),
        None => checks.push(
            Check::fail(
                "identity.agent",
                "还没注册（拿不到已注册身份）",
                format!("state 里的身份是占位值：{}", runtime_state.agent_id),
            )
            .hint("用一次性 token 注册：`wist-agentd service install --system --enrollment-token <token>`"),
        ),
    }

    checks.push(credential_check(config, &runtime_state));
    checks.push(certificate_check(&state_dir));
    checks
}

/// bearer 凭据：有没有、过没过期。
///
/// 只有 mTLS 证书而无 bearer 也算可用（双轨），所以那种情况是 WARN 而不是 FAIL。
fn credential_check(
    config: &AgentConfig,
    runtime_state: &wist_contracts::agent_state::AgentRuntimeState,
) -> Check {
    let expires = config
        .control_plane
        .credential_expires_at
        .as_deref()
        .or(runtime_state.credential_expires_at.as_deref());
    let has_token = config
        .control_plane
        .bearer_token
        .as_deref()
        .is_some_and(|token| !token.trim().is_empty())
        || runtime_state
            .bearer_token
            .as_deref()
            .is_some_and(|token| !token.trim().is_empty());
    // 凭据 id（注册时网关下发的那个）：**网关库里查不到它 = 库里没有这条凭据**（换过库/被清），
    // 这正是 `401 unknown_credential` 的判据 —— 打出来，省得再去查库。
    let credential_id = config
        .control_plane
        .credential_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty());
    let with_cred = |detail: String| match credential_id {
        Some(id) => format!("{detail}；credential_id={id}"),
        None => detail,
    };

    match (has_token, expires.and_then(parse_time)) {
        (true, Some(expires_at)) => {
            let remaining = expires_at - time::OffsetDateTime::now_utc();
            if remaining <= time::Duration::ZERO {
                Check::fail(
                    "identity.credential",
                    "控制面凭据已过期",
                    with_cred(format!("到期时间 {}", expires.unwrap_or_default())),
                )
                .hint("重新注册（带一次性 token 重装），或确认网关没有把凭据吊销")
            } else if remaining < time::Duration::seconds(EXPIRY_WARN_WINDOW.as_secs() as i64) {
                Check::warn(
                    "identity.credential",
                    "控制面凭据即将过期",
                    with_cred(format!("剩余约 {} 小时", remaining.whole_hours())),
                )
                .hint("重启 agentd 会触发续期；到期未续需要重装")
            } else {
                Check::ok(
                    "identity.credential",
                    "控制面凭据有效",
                    with_cred(format!("剩余约 {} 天", remaining.whole_days())),
                )
            }
        }
        (true, None) => Check::ok(
            "identity.credential",
            "控制面凭据存在（没有到期时间）",
            with_cred("旧版网关不写入过期时间".to_string()),
        ),
        (false, _) => Check::warn(
            "identity.credential",
            "本机没有 bearer 凭据",
            with_cred("若客户端证书有效则仍可上报（mTLS 双轨）；两者都没有就会 401".to_string()),
        )
        .hint(
            "重新注册拿一份凭据：`wist-agentd service install --system --enrollment-token <token>`",
        ),
    }
}

/// 客户端证书（mTLS）：有、有效、临期还是过期；并带上最近一次续签判定的结果。
fn certificate_check(state_dir: &Path) -> Check {
    let paths = client_identity::ClientIdentityPaths::under(state_dir);
    // 台账里的 detail 可能是**多行**错误链（`display_chain`）—— 先压成一行，
    // 否则原始换行会把这里的单行排版冲乱（还会冒出一个开头是 `；` 的裸短语）。
    let renewal = client_identity::read_renewal_ledger(&paths)
        .ok()
        .flatten()
        .map(|ledger| {
            format!(
                "最近一次续签：{}（{}）",
                ledger.outcome,
                one_line(&ledger.detail)
            )
        });
    // 有续签记录就接在正文后面（`；` 分隔）；没有就原样。
    let with_renewal = |detail: String| match &renewal {
        Some(renewal) => format!("{detail}；{renewal}"),
        None => detail,
    };

    match client_identity::client_certificate_status(&paths) {
        Ok(None) => {
            let detail = match &renewal {
                Some(renewal) => format!("按 bearer 凭据认证；{renewal}"),
                None => "按 bearer 凭据认证".to_string(),
            };
            Check::ok(
                "identity.certificate",
                "没有客户端证书（未启用 mTLS）",
                detail,
            )
        }
        Ok(Some(status)) => {
            let detail = format!("到期 {}", status.not_after);
            match status.validity {
                client_identity::CertificateValidity::Valid => Check::ok(
                    "identity.certificate",
                    "客户端证书有效",
                    with_renewal(detail),
                ),
                client_identity::CertificateValidity::RenewDue => Check::warn(
                    "identity.certificate",
                    "客户端证书该续签了",
                    with_renewal(format!("{detail}（在续签窗口内）")),
                )
                .hint("守护进程会在窗口内自动续签；长期没续上说明控制面不通"),
                client_identity::CertificateValidity::Expired => Check::fail(
                    "identity.certificate",
                    "客户端证书已过期",
                    with_renewal(detail),
                )
                .hint("过期证书进不来（无宽限）：带一次性 token 重装"),
            }
        }
        Err(err) => Check::warn(
            "identity.certificate",
            "客户端证书读不出来",
            err.to_string(),
        ),
    }
}

/// 常驻服务与二进制：服务定义在不在、agentd 在不在跑、升级三件套版本一致不一致。
fn service_checks(config_root: &Path, config: &AgentConfig) -> Vec<Check> {
    let mut checks = Vec::new();
    let Some(platform) = ServicePlatform::current() else {
        checks.push(Check::warn(
            "service.platform",
            "本平台没有托管服务支持",
            "只在 Linux(systemd) / macOS(launchd) 下检查服务定义",
        ));
        checks.extend(binary_checks());
        return checks;
    };

    let installed = [ServiceScope::System, ServiceScope::User]
        .into_iter()
        .find_map(|scope| {
            let layout = ServiceLayout::resolve(platform, scope).ok()?;
            layout.definition_path.is_file().then_some((scope, layout))
        });

    let state_dir = PathBuf::from(&config.paths.state_dir);
    match installed {
        Some((scope, layout)) => {
            let bin = service::default_bin().unwrap_or_default();
            let spec = ServiceSpec::new(scope, bin, config_root.to_path_buf());
            match service::status(&layout, &spec) {
                Ok(status) => {
                    let detail = format!(
                        "{}（{}）；日志：{}",
                        layout.definition_path.display(),
                        if status.running == Some(true) {
                            "运行中"
                        } else {
                            "未在运行"
                        },
                        status.log_hint
                    );
                    if status.running == Some(true) {
                        checks.push(Check::ok(
                            "service.definition",
                            "常驻服务已安装并在跑",
                            detail,
                        ));
                    } else {
                        checks.push(
                            Check::fail("service.definition", "常驻服务已安装但没有在跑", detail)
                                .hint("按上面的日志路径看退出原因；必要时重装服务"),
                        );
                    }
                    if !status.bin_present {
                        checks.push(
                            Check::fail(
                                "service.binary",
                                "agentd 二进制不在",
                                status.bin.display().to_string(),
                            )
                            .hint("重装 agentd"),
                        );
                    } else if !status.exec_bin_present {
                        checks.push(
                            Check::warn(
                                "service.binary",
                                "wist-exec 不在",
                                status.exec_bin.display().to_string(),
                            )
                            .hint("执行类工作会失败；重装会补齐三件套"),
                        );
                    }
                }
                Err(err) => checks.push(Check::warn(
                    "service.definition",
                    "服务状态读不出来",
                    one_line(&err.display_chain()),
                )),
            }
        }
        None => {
            let running = crate::single_instance::is_held(&state_dir).unwrap_or(false);
            if running {
                checks.push(Check::ok(
                    "service.definition",
                    "没有托管服务定义，但有 agentd 在跑",
                    "开发态（手工启动）运行时属正常",
                ));
            } else {
                checks.push(
                    Check::warn(
                        "service.definition",
                        "没有托管服务定义，也没有在跑的 agentd",
                        "这台机器当前不会上报、也不会执行工作",
                    )
                    .hint("`wist-agentd service install --system --enrollment-token <token>`"),
                );
            }
        }
    }

    checks.extend(binary_checks());
    checks
}

/// 二进制齐全与版本一致：`wist-exec` **没有** `version` 子命令（只能看它在不在）；
/// `wist-upgrader` 能自报版本，混版会让升级失败（升级器只换自己同版本的那套）。
fn binary_checks() -> Vec<Check> {
    let mut checks = Vec::new();
    let our_version = env!("CARGO_PKG_VERSION");
    let Some(dir) = std::env::current_exe()
        .ok()
        .and_then(|exe| exe.parent().map(Path::to_path_buf))
    else {
        return checks;
    };

    let exec = dir.join("wist-exec");
    if exec.is_file() {
        checks.push(Check::ok(
            "version.tools",
            "wist-exec 在 agentd 旁边",
            exec.display().to_string(),
        ));
    } else {
        checks.push(
            Check::warn(
                "version.tools",
                "wist-exec 不在 agentd 旁边",
                format!("{}（执行体）", exec.display()),
            )
            .hint("重装会补齐三件套；缺文件会让执行类工作失败"),
        );
    }

    let upgrader = dir.join("wist-upgrader");
    if !upgrader.is_file() {
        checks.push(
            Check::warn(
                "version.tools",
                "wist-upgrader 不在 agentd 旁边",
                format!("{}（升级器）", upgrader.display()),
            )
            .hint("重装会补齐三件套；缺文件会让升级类工作失败"),
        );
        return checks;
    }
    match reported_version(&upgrader) {
        Some(version) if version.trim() == our_version => checks.push(Check::ok(
            "version.tools",
            "wist-upgrader 与 agentd 同版本",
            format!("wist-upgrader {version}"),
        )),
        Some(version) => checks.push(
            Check::warn(
                "version.tools",
                "wist-upgrader 与 agentd 版本不一致",
                format!("agentd {our_version} vs wist-upgrader {version}"),
            )
            .hint("升级会因混版失败：用同一个安装包重装三件套"),
        ),
        None => checks.push(Check::warn(
            "version.tools",
            "wist-upgrader 版本读不出来",
            upgrader.display().to_string(),
        )),
    }
    checks
}

/// 控制面连通：DNS → TCP → 应用层（TLS + 鉴权）。
///
/// 返回检查项与**这一趟拿到的上送授权**（拿不到就是 `None`），后者给上送组用 —— 一次探测、
/// 两处结论，避免「控制面通不通」与「为什么不上送」各探一次而结论打架。
async fn network_checks(config: &AgentConfig) -> (Vec<Check>, Option<AgentUplinkGrant>) {
    let mut checks = Vec::new();
    let Some(endpoint) = config.control_plane.endpoint.as_deref().map(str::trim) else {
        return (checks, None);
    };
    let Some(target) = split_endpoint(endpoint) else {
        return (checks, None);
    };

    let addrs = match resolve(&target.host, target.port).await {
        Ok(addrs) => {
            checks.push(Check::ok(
                "network.dns",
                "控制面域名可解析",
                format!(
                    "{}:{} → {}",
                    target.host,
                    target.port,
                    addrs
                        .iter()
                        .map(SocketAddr::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                ),
            ));
            addrs
        }
        Err(err) => {
            checks.push(
                Check::fail(
                    "network.dns",
                    "控制面域名解析失败",
                    format!("{}:{}：{err}", target.host, target.port),
                )
                .hint("检查域名拼写、DNS 与 /etc/hosts（客户内网常见：域名没指向这台机器）"),
            );
            return (checks, None);
        }
    };

    match connect_tcp(&addrs).await {
        Ok(addr) => checks.push(Check::ok(
            "network.tcp",
            format!("TCP 可达 {}:{}", target.host, target.port),
            format!("已连上 {addr}"),
        )),
        Err(err) => {
            checks.push(
                Check::fail(
                    "network.tcp",
                    format!("TCP 连不上 {}:{}", target.host, target.port),
                    err,
                )
                .hint(
                    "先确认**端口**：endpoint 不写端口时按 443 连，而网关可能发布在别的端口（如 3000）；\
                     其次看网关进程/容器是否在跑、防火墙是否放行",
                ),
            );
            return (checks, None);
        }
    }

    // 应用层：复用守护进程那句「拉一次上送授权」——它自带证书校验/鉴权/超时的同一套判定。
    let fetch = fetch_uplink_grant(config).await;
    let (check, grant) = classify_control_plane_probe(fetch);
    checks.push(check);
    (checks, grant)
}

/// 把一次上送拉取的结果翻成检查项（纯函数，便于断言与复用）。
fn classify_control_plane_probe(fetch: UplinkFetch) -> (Check, Option<AgentUplinkGrant>) {
    match fetch {
        UplinkFetch::Granted(grant) => {
            let target = grant
                .target()
                .map(|(host, port)| format!("{host}:{port}"))
                .unwrap_or_else(|| "-".to_string());
            let check = Check::ok(
                "network.control_plane",
                "控制面可达且凭据被接受",
                format!(
                    "uplink grant: enabled={} target={target} granted_at={}",
                    grant.enabled, grant.granted_at
                ),
            );
            (check, Some(grant))
        }
        UplinkFetch::NotDispatched => (
            Check::warn(
                "network.control_plane",
                "控制面在应答，但没有上送授权下发",
                "未入网，或网关没有 `uplink:poll` 这个端点（旧网关回 404）",
            )
            .hint("确认网关版本 ≥ 0.1.7，并确认这台机器的凭据是这套网关签发的"),
            None,
        ),
        UplinkFetch::CredentialRejected(detail) => (
            Check::fail(
                "network.control_plane",
                "控制面拒绝了本机凭据（401/403）",
                detail,
            )
            .hint(
                "按正文里的 code 处理：`unknown_credential` = 网关库里没有这条凭据（库被换/重置过）→ \
                 用一次性 token 重新注册（`enroll --force`）；`certificate_revoked` = 在被拒名单，需先在网关解除；\
                 两者都对不上时看 `identity.credential` 打出的 `credential_id`",
            ),
            None,
        ),
        UplinkFetch::Failed(detail) => (
            Check::fail("network.control_plane", "控制面请求失败", detail)
                .hint("按上面的原因看：TLS 证书不受信 / 信任锚不对 / 超时 / 响应看不懂"),
            None,
        ),
    }
}

/// 上送（本地部分）：生效输出（复用守护进程那套合并规则）、spool 积压、本地工作视图。
///
/// 这三项都不需要网络 —— `--offline` 时也要报（否则本机能得出的结论被一并丢掉了）。
/// `grant = None` + `offline = true` 时，生效输出按本机配置算，但不声称“没有控制面授权”。
async fn uplink_local_checks(
    config: &AgentConfig,
    grant: Option<&AgentUplinkGrant>,
    offline: bool,
) -> Vec<Check> {
    let mut checks = Vec::new();
    let effective = effective_output(config, grant);

    let detail = format!(
        "enabled={} kind={} addr={} port={}",
        effective.enabled, effective.kind, effective.tcp.addr, effective.tcp.port
    );
    match grant {
        None if offline => checks.push(
            Check::warn(
                "uplink.effective",
                "按本机配置走（--offline，未向控制面确认）",
                detail,
            )
            .hint("去掉 --offline 可确认控制面是否已授权上送"),
        ),
        None => checks.push(
            Check::warn("uplink.effective", "没有控制面授权，按本机配置走", detail)
                .hint("未入网或旧网关；派活后控制面会下发目标并自动打开上送"),
        ),
        Some(grant) if !grant.enabled => {
            let why = if grant.target().is_some() {
                "控制面给过目标但没启用（多半是还没有生效工作）→ 到管理面派一份常驻工作"
            } else {
                "控制面没给目标（网关侧没有可用的数据面上送地址）→ 在网关侧确认上送地址"
            };
            checks.push(Check::warn(
                "uplink.effective",
                "待命：控制面没启用上送",
                format!("{detail}；{why}"),
            ));
        }
        Some(_) => checks.push(Check::ok(
            "uplink.effective",
            "控制面已启用上送",
            detail.clone(),
        )),
    }

    checks.push(spool_check(config).await);
    checks.push(local_work_check(config).await);
    checks
}

/// 数据面目标可达性（需要网络）：只有「生效输出是 tcp 且给了目标」时才探。
async fn uplink_target_check(config: &AgentConfig, grant: Option<&AgentUplinkGrant>) -> Vec<Check> {
    let mut checks = Vec::new();
    let effective = effective_output(config, grant);
    if !(effective.enabled && effective.kind == "tcp" && !effective.tcp.addr.trim().is_empty()) {
        return checks;
    }
    match resolve(&effective.tcp.addr, effective.tcp.port).await {
        Ok(addrs) => match connect_tcp(&addrs).await {
            Ok(addr) => checks.push(Check::ok(
                "uplink.target",
                format!("数据面可达 {}:{}", effective.tcp.addr, effective.tcp.port),
                format!("已连上 {addr}"),
            )),
            Err(err) => checks.push(
                Check::fail(
                    "uplink.target",
                    format!("数据面连不上 {}:{}", effective.tcp.addr, effective.tcp.port),
                    err,
                )
                .hint("数据面（wparse）没跑、宿主没发布该端口、或防火墙挡了"),
            ),
        },
        Err(err) => checks.push(Check::fail(
            "uplink.target",
            "数据面地址解析失败",
            format!("{}:{}：{err}", effective.tcp.addr, effective.tcp.port),
        )),
    }
    checks
}

/// spool 积压：出口长期失败/跟不上时，本地会堆日志。
async fn spool_check(config: &AgentConfig) -> Check {
    let dir = PathBuf::from(&config.paths.state_dir)
        .join("spool")
        .join("logs");
    let mut entries = match tokio::fs::read_dir(&dir).await {
        Ok(entries) => entries,
        Err(_) => {
            return Check::ok(
                "uplink.spool",
                "本机没有 spool 积压目录",
                dir.display().to_string(),
            );
        }
    };
    let (mut files, mut bytes, mut corrupt) = (0u64, 0u64, 0u64);
    while let Ok(Some(entry)) = entries.next_entry().await {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.ends_with(".bad") {
            corrupt += 1;
        }
        if let Ok(meta) = entry.metadata().await {
            files += 1;
            bytes += meta.len();
        }
    }
    let detail = format!("{files} 个文件 / {} KiB", bytes / 1024);
    if corrupt > 0 {
        return Check::warn(
            "uplink.spool",
            format!("spool 里有 {corrupt} 个坏文件（{detail}）"),
            "坏行已被隔离到 *.bad，说明曾有写入失败",
        )
        .hint("看出口错误原因（数据面不可达/磁盘满）；坏文件可留证后删除");
    }
    if bytes > SPOOL_WARN_BYTES {
        return Check::warn(
            "uplink.spool",
            format!("spool 积压 {detail}"),
            "日志在本地排队说明上送没跟上（出口失败或目标不可达）",
        )
        .hint("先查 `uplink.target` 是否可达；积压会在恢复后自动回放");
    }
    Check::ok("uplink.spool", "没有明显 spool 积压", detail)
}

/// 本地工作视图（`state/work.json`）：手里有多少活、是不是还没派活。
async fn local_work_check(config: &AgentConfig) -> Check {
    let path = work::path_for(Path::new(&config.paths.state_dir));
    match work::load_async(&path).await {
        Ok(None) => Check::warn(
            "work.local",
            "还没有本地工作视图（没派过活）",
            path.display().to_string(),
        )
        .hint("采集由授权驱动：到管理面给这台机器派一份常驻工作"),
        Ok(Some(record)) => {
            let active = record
                .standing
                .iter()
                .filter(|item| item.status == "active")
                .count();
            let paused = record.standing.len() - active;
            let detail = format!(
                "常驻 {}（active {active} / paused {paused}）一次性 {} 指标周期 {:?}；recorded_at={}",
                record.standing.len(),
                record.one_shot.len(),
                record.metrics_interval_seconds,
                record.recorded_at
            );
            if record.standing.is_empty() && record.one_shot.is_empty() {
                Check::warn("work.local", "本地没有生效工作", detail)
                    .hint("到管理面派活；没有工作就不会采集，也不会上送")
            } else {
                Check::ok("work.local", "本地工作视图正常", detail)
            }
        }
        Err(err) => Check::warn("work.local", "本地工作视图读不出来", err.to_string()),
    }
}

/// endpoint 拆成（主机，端口，端口是否显式写了）。
#[derive(Debug, Clone, PartialEq, Eq)]
struct EndpointTarget {
    host: String,
    port: u16,
    port_explicit: bool,
}

/// 解析 `scheme://host[:port][/path]`（host 可为 IPv4 / 域名 / 方括号 IPv6）。
///
/// 端口规则与守护进程一致：**显式端口优先；没写就按 scheme 的默认端口**（https → 443，
/// 其余 → 80）。没有 scheme 时按 http（与 `enrollment_http_client` 的推导一致）。
fn split_endpoint(endpoint: &str) -> Option<EndpointTarget> {
    let trimmed = endpoint.trim();
    let (scheme, rest) = match trimmed.split_once("://") {
        Some((scheme, rest)) => (scheme.to_ascii_lowercase(), rest),
        None => ("http".to_string(), trimmed),
    };
    let authority = rest.split(['/', '?', '#']).next().unwrap_or_default();
    if authority.is_empty() {
        return None;
    }
    let default_port: u16 = if scheme == "https" { 443 } else { 80 };

    let (host, port, port_explicit) = if let Some(bracketed) = authority.strip_prefix('[') {
        // IPv6 字面量：`[::1]` 或 `[::1]:3000`。
        let (host, after) = bracketed.split_once(']')?;
        match after.strip_prefix(':') {
            Some(port) => (host, port.parse().ok()?, true),
            None if after.is_empty() => (host, default_port, false),
            None => return None,
        }
    } else {
        match authority.rsplit_once(':') {
            Some((host, port)) => {
                // 非方括号形式里出现多个冒号 = 没加方括号的 IPv6（URL 不合法），拒绝。
                if host.contains(':') {
                    return None;
                }
                (host, port.parse().ok()?, true)
            }
            None => (authority, default_port, false),
        }
    };
    let host = host.trim();
    if host.is_empty() {
        return None;
    }
    Some(EndpointTarget {
        host: host.to_string(),
        port,
        port_explicit,
    })
}

/// `tls_mode` 的有效值：显式配置优先，否则按 endpoint 前缀推导（与守护进程同一口径）。
fn effective_tls_mode(configured: Option<&str>, endpoint: &str) -> String {
    match configured.map(str::trim).filter(|mode| !mode.is_empty()) {
        Some(mode) => mode.to_string(),
        None if endpoint.starts_with("https://") => "https".to_string(),
        None => "http".to_string(),
    }
}

async fn resolve(host: &str, port: u16) -> Result<Vec<SocketAddr>, String> {
    let (host, port) = (host.to_string(), port);
    tokio::task::spawn_blocking(move || {
        (host.as_str(), port)
            .to_socket_addrs()
            .map(|addrs| addrs.collect::<Vec<_>>())
            .map_err(|err| err.to_string())
    })
    .await
    .map_err(|err| err.to_string())?
    .and_then(|addrs| {
        if addrs.is_empty() {
            Err("没有解析到地址".to_string())
        } else {
            Ok(addrs)
        }
    })
}

async fn connect_tcp(addrs: &[SocketAddr]) -> Result<SocketAddr, String> {
    let mut last = String::from("没有可用地址");
    for addr in addrs {
        match tokio::time::timeout(PROBE_TIMEOUT, tokio::net::TcpStream::connect(addr)).await {
            Ok(Ok(_)) => return Ok(*addr),
            Ok(Err(err)) => last = err.to_string(),
            Err(_) => last = format!("连接 {addr} 超时（{}s）", PROBE_TIMEOUT.as_secs()),
        }
    }
    Err(last)
}

/// 目标目录能不能写：**不新建目录**（说好只读就得真只读）。
///
/// - 目录已存在 → 在其中建/删一个空探针文件，返回 `Ok(true)`；
/// - 目录不存在 → 回到最近的已存在祖先探写（能写祖先 ⇒ 守护进程启动时 `create_dir_all`
///   也能把它建出来），返回 `Ok(false)`；
/// - 路径存在但不是目录（或找不到可写的祖先）→ `Err`。
///
/// 唯一副作用是那个用完即删的探针文件；不改配置、不建目录。
fn probe_writable(dir: &Path) -> Result<bool, String> {
    let mut target = dir;
    let mut existed = true;
    loop {
        match std::fs::metadata(target) {
            Ok(meta) if meta.is_dir() => break,
            Ok(_) => return Err(format!("{} 不是目录", target.display())),
            Err(_) => {
                existed = false;
                match target.parent() {
                    Some(parent) if !parent.as_os_str().is_empty() => target = parent,
                    _ => return Err(format!("{} 不存在，且找不到可写的祖先目录", dir.display())),
                }
            }
        }
    }
    let probe = target.join(format!(".diagnose-write-probe-{}", std::process::id()));
    std::fs::write(&probe, b"probe").map_err(|err| format!("{}：{err}", target.display()))?;
    let _ = std::fs::remove_file(&probe);
    Ok(existed)
}

/// 取某个二进制的自报版本（`<bin> version` 的最后一段）。
fn reported_version(bin: &Path) -> Option<String> {
    let output = std::process::Command::new(bin)
        .arg("version")
        .output()
        .ok()?;
    if !output.status.success() {
        return None;
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    stdout.split_whitespace().last().map(str::to_string)
}

fn parse_time(value: &str) -> Option<time::OffsetDateTime> {
    time::OffsetDateTime::parse(value, &time::format_description::well_known::Rfc3339).ok()
}

/// 把可能多行的错误压成一行（诊断输出里一行一条最好读）。
fn one_line(value: &str) -> String {
    value
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect::<Vec<_>>()
        .join(" | ")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn check(id: &'static str, status: Status) -> Check {
        Check {
            id,
            status,
            title: id.to_string(),
            detail: String::new(),
            hint: None,
        }
    }

    #[test]
    fn endpoint_without_a_port_uses_the_scheme_default() {
        // 这是本工具最常命中的一条：不写端口时实际连的是 443，而网关可能发布在别的端口。
        let target = split_endpoint("https://gw.example.com").expect("parsed");
        assert_eq!(target.host, "gw.example.com");
        assert_eq!(target.port, 443);
        assert!(!target.port_explicit);

        let explicit = split_endpoint("https://gw.example.com:3000/api").expect("parsed");
        assert_eq!(explicit.port, 3000);
        assert!(explicit.port_explicit);

        let plain = split_endpoint("http://10.0.0.1").expect("parsed");
        assert_eq!(plain.port, 80);

        // 没有 scheme 时按 http（与守护进程的推导一致）。
        let bare = split_endpoint("gw.example.com:8080").expect("parsed");
        assert_eq!((bare.host.as_str(), bare.port), ("gw.example.com", 8080));

        for bad in [
            "",
            "https://",
            "https://[::1",
            "https://::1",
            "https://[::1]x",
        ] {
            assert!(split_endpoint(bad).is_none(), "should reject {bad}");
        }
    }

    #[test]
    fn endpoint_parses_ipv6_literals() {
        let bare = split_endpoint("https://[::1]").expect("parsed");
        assert_eq!((bare.host.as_str(), bare.port), ("::1", 443));
        assert!(!bare.port_explicit);

        let explicit = split_endpoint("https://[2001:db8::1]:8443/api").expect("parsed");
        assert_eq!(
            (explicit.host.as_str(), explicit.port),
            ("2001:db8::1", 8443)
        );
        assert!(explicit.port_explicit);
    }

    #[test]
    fn tls_mode_falls_back_to_the_endpoint_scheme() {
        assert_eq!(effective_tls_mode(None, "https://gw"), "https");
        assert_eq!(effective_tls_mode(None, "http://gw"), "http");
        assert_eq!(effective_tls_mode(Some("none"), "https://gw"), "none");
        assert_eq!(effective_tls_mode(Some("  "), "https://gw"), "https");
    }

    #[test]
    fn verdict_and_exit_code_follow_failures() {
        let clean = Report {
            checks: vec![check("a", Status::Ok), check("b", Status::Warn)],
        };
        assert_eq!(clean.exit_code(), 0);
        assert!(clean.verdict().contains("1 项警告"));

        let broken = Report {
            checks: vec![check("a", Status::Ok), check("first-fail", Status::Fail)],
        };
        assert_eq!(broken.exit_code(), 1);
        assert!(broken.verdict().contains("首要问题：first-fail"));
    }

    #[test]
    fn json_report_carries_ids_statuses_and_summary() {
        let report = Report {
            checks: vec![
                Check::fail("network.tcp", "连不上", "connection refused").hint("看端口"),
                Check::ok("config.file", "可读", "/etc/wist-agentd/agentd.toml"),
            ],
        };
        let parsed: serde_json::Value =
            serde_json::from_str(&report.render_json()).expect("valid json");
        assert_eq!(parsed["command"], "diagnose");
        assert_eq!(parsed["summary"]["fail"], 1);
        assert_eq!(parsed["summary"]["ok"], 1);
        assert_eq!(parsed["checks"][0]["id"], "network.tcp");
        assert_eq!(parsed["checks"][0]["status"], "fail");
        assert_eq!(parsed["checks"][0]["hint"], "看端口");
    }

    #[test]
    fn probe_results_are_classified_per_layer() {
        let granted: AgentUplinkGrant = serde_json::from_value(serde_json::json!({
            "enabled": true,
            "host": "10.0.0.9",
            "port": 9000,
            "granted_at": "2026-09-29T00:00:00Z",
        }))
        .expect("grant");
        let (check, grant) = classify_control_plane_probe(UplinkFetch::Granted(granted));
        assert_eq!(check.status, Status::Ok);
        assert!(check.detail.contains("10.0.0.9:9000"));
        assert!(grant.is_some());

        let (rejected, grant) =
            classify_control_plane_probe(UplinkFetch::CredentialRejected("http 401".to_string()));
        assert_eq!(rejected.status, Status::Fail);
        assert!(grant.is_none());

        let (old_gateway, _) = classify_control_plane_probe(UplinkFetch::NotDispatched);
        assert_eq!(old_gateway.status, Status::Warn);

        let (failed, _) =
            classify_control_plane_probe(UplinkFetch::Failed("transport: refused".to_string()));
        assert_eq!(failed.status, Status::Fail);
        assert!(failed.detail.contains("refused"));
    }

    #[test]
    fn text_report_prints_tags_and_hints() {
        let report = Report {
            checks: vec![Check::fail("network.tcp", "TCP 连不上", "refused").hint("看端口")],
        };
        let text = report.render_text(false);
        assert!(text.contains("[FAIL] TCP 连不上"), "{text}");
        assert!(text.contains("→ 看端口"), "{text}");
        assert!(text.contains("结论:"), "{text}");
    }

    #[test]
    fn text_report_colors_statuses_only_when_asked() {
        let report = Report {
            checks: vec![
                Check::ok("a", "正常", "x"),
                Check::warn("b", "警告", "x"),
                Check::fail("c", "失败", "x"),
            ],
        };

        // 重定向 / `NO_COLOR` 走这条路：不能混进任何 ANSI 码。
        let plain = report.render_text(false);
        assert!(
            !plain.contains('\x1b'),
            "plain output must be colorless: {plain:?}"
        );

        // TTY 走这条路：绿 / 黄 / 红加粗标签。
        let colored = report.render_text(true);
        assert!(colored.contains("\x1b[1;32m[OK]\x1b[0m"), "{colored:?}");
        assert!(colored.contains("\x1b[1;33m[WARN]\x1b[0m"), "{colored:?}");
        assert!(colored.contains("\x1b[1;31m[FAIL]\x1b[0m"), "{colored:?}");
    }

    #[tokio::test]
    async fn spool_check_counts_files_and_flags_corrupt_ones() {
        let root = std::env::temp_dir().join(format!("doctor-spool-{}", std::process::id()));
        let spool = root.join("spool").join("logs");
        std::fs::create_dir_all(&spool).expect("create spool");
        std::fs::write(spool.join("input-a.ndjson"), b"{}\n").expect("write");
        let mut config: AgentConfig =
            toml::from_str(&crate::config_runtime::default_config_template())
                .expect("default config parses");
        config.paths.state_dir = root.to_string_lossy().to_string();
        assert_eq!(spool_check(&config).await.status, Status::Ok);

        std::fs::write(spool.join("input-a.ndjson.bad"), b"broken\n").expect("write bad");
        let with_corrupt = spool_check(&config).await;
        assert_eq!(with_corrupt.status, Status::Warn);
        assert!(with_corrupt.title.contains("坏文件"), "{with_corrupt:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn certificate_check_collapses_a_multiline_renewal_detail() {
        let state = std::env::temp_dir().join(format!("doctor-cert-{}", std::process::id()));
        let paths = client_identity::ClientIdentityPaths::under(&state);
        client_identity::store_renewal_ledger(
            &paths,
            &client_identity::RenewalLedger {
                checked_at: "2026-09-29T00:00:00Z".to_string(),
                outcome: "failed".to_string(),
                // 台账里的错误链是多行的（`display_chain`）—— 曾经直接把它塞进单行输出，
                // 冒出一个“裸 `->` 行”和一个开头的 `；`。
                detail: "http\n  -> Info: enrollment http error".to_string(),
                not_after: String::new(),
            },
        )
        .expect("store renewal ledger");

        let check = certificate_check(&state);
        assert_eq!(check.status, Status::Ok);
        assert!(
            !check.detail.contains('\n'),
            "detail must stay single-line: {}",
            check.detail
        );
        assert!(
            !check.detail.starts_with('；'),
            "no dangling separator: {}",
            check.detail
        );
        assert!(
            check.detail.contains("按 bearer 凭据认证"),
            "{}",
            check.detail
        );
        assert!(
            check.detail.contains("最近一次续签：failed"),
            "{}",
            check.detail
        );
        let _ = std::fs::remove_dir_all(state);
    }

    fn template_config() -> AgentConfig {
        toml::from_str(&crate::config_runtime::default_config_template())
            .expect("default config template parses")
    }

    fn runtime_state() -> wist_contracts::agent_state::AgentRuntimeState {
        wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-test".to_string(),
            "inst-test".to_string(),
            "0.1.15".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-09-29T00:00:00Z".to_string(),
        )
    }

    /// 距现在 `seconds` 秒的 RFC3339 时刻（负数为过去）。
    fn rfc3339_in(seconds: i64) -> String {
        (time::OffsetDateTime::now_utc() + time::Duration::seconds(seconds))
            .format(&time::format_description::well_known::Rfc3339)
            .expect("format timestamp")
    }

    #[test]
    fn overall_reflects_the_worst_status() {
        assert_eq!(Report { checks: vec![] }.overall(), Status::Ok);
        assert_eq!(
            Report {
                checks: vec![check("a", Status::Ok), check("b", Status::Ok)]
            }
            .overall(),
            Status::Ok
        );
        assert_eq!(
            Report {
                checks: vec![check("a", Status::Ok), check("b", Status::Warn)]
            }
            .overall(),
            Status::Warn
        );
        assert_eq!(
            Report {
                checks: vec![check("a", Status::Warn), check("b", Status::Fail)]
            }
            .overall(),
            Status::Fail
        );
    }

    #[test]
    fn color_enabled_follows_env_precedence() {
        // 默认看 TTY。
        assert!(color_enabled(None, None, true));
        assert!(!color_enabled(None, None, false));
        // NO_COLOR 非空 → 关（连 TTY 也关）。
        assert!(!color_enabled(Some("1"), Some("1"), true));
        // 空的 NO_COLOR 不算设置（按规范：空串不生效）。
        assert!(color_enabled(Some(""), None, true));
        // CLICOLOR_FORCE 非空且非 0 → 强制开（即使非 TTY）。
        assert!(color_enabled(None, Some("1"), false));
        // 空 / "0" 的 CLICOLOR_FORCE 不强制。
        assert!(!color_enabled(None, Some(""), false));
        assert!(!color_enabled(None, Some("0"), false));
    }

    #[test]
    fn control_plane_checks_flag_disabled_and_missing_endpoint() {
        // 默认模板里 [control_plane] 是注释掉的 ⇒ enabled=false ⇒ 只有一条 WARN。
        let disabled = control_plane_checks(&template_config());
        assert_eq!(disabled.len(), 1);
        assert_eq!(disabled[0].status, Status::Warn);

        let mut no_endpoint = template_config();
        no_endpoint.control_plane.enabled = true;
        no_endpoint.control_plane.endpoint = None;
        assert_eq!(control_plane_checks(&no_endpoint)[0].status, Status::Fail);

        let mut unparsable = template_config();
        unparsable.control_plane.enabled = true;
        unparsable.control_plane.endpoint = Some("https://".to_string());
        unparsable.control_plane.tls_mode = Some("https".to_string());
        assert_eq!(control_plane_checks(&unparsable)[0].status, Status::Fail);

        let mut good = template_config();
        good.control_plane.enabled = true;
        good.control_plane.endpoint = Some("https://gw.example:3000".to_string());
        good.control_plane.tls_mode = Some("https".to_string());
        good.control_plane.trust_bundle = Some("PEM".to_string());
        assert!(
            control_plane_checks(&good)
                .iter()
                .all(|c| c.status == Status::Ok),
            "{good:?}"
        );
    }

    #[test]
    fn control_plane_checks_treat_missing_trust_bundle_as_informational() {
        // 没配 trust_bundle **不是问题**（https/verify 会回落平台/公有根证书）；以前这里误报 WARN。
        let mut config = template_config();
        config.control_plane.enabled = true;
        config.control_plane.endpoint = Some("https://gw.example:3000".to_string());
        config.control_plane.tls_mode = Some("https".to_string());
        config.control_plane.trust_bundle = None;

        let checks = control_plane_checks(&config);
        assert!(checks.iter().all(|c| c.status == Status::Ok), "{checks:?}");
        let tls = checks
            .iter()
            .find(|c| c.id == "config.tls")
            .expect("tls check");
        assert!(tls.title.contains("平台根证书"), "{tls:?}");
    }

    #[test]
    fn credential_check_covers_expiry_states() {
        let state = runtime_state();
        let day = 24 * 60 * 60;
        let with = |token: Option<&str>, expires: Option<String>| {
            let mut config = template_config();
            config.control_plane.bearer_token = token.map(str::to_string);
            config.control_plane.credential_expires_at = expires;
            config
        };

        // 已过期 → FAIL。
        assert_eq!(
            credential_check(&with(Some("tok"), Some(rfc3339_in(-day))), &state).status,
            Status::Fail
        );
        // 续期窗内（< 7 天）→ WARN。
        assert_eq!(
            credential_check(&with(Some("tok"), Some(rfc3339_in(3 * day))), &state).status,
            Status::Warn
        );
        // 还早 → OK。
        assert_eq!(
            credential_check(&with(Some("tok"), Some(rfc3339_in(20 * day))), &state).status,
            Status::Ok
        );
        // 有凭据但没到期时间 → OK。
        assert_eq!(
            credential_check(&with(Some("tok"), None), &state).status,
            Status::Ok
        );
        // 本机没有凭据（state 里也没有）→ WARN。
        assert_eq!(
            credential_check(&with(None, None), &state).status,
            Status::Warn
        );
    }

    #[test]
    fn credential_check_prints_the_credential_id() {
        // 打出凭据 id：与网关库对照就能一眼判断「库里有没有这条」。
        let state = runtime_state();
        let mut config = template_config();
        config.control_plane.bearer_token = Some("tok".to_string());
        config.control_plane.credential_id = Some("cred_abc123".to_string());
        config.control_plane.credential_expires_at = Some(rfc3339_in(20 * 24 * 60 * 60));

        let check = credential_check(&config, &state);
        assert_eq!(check.status, Status::Ok);
        assert!(
            check.detail.contains("credential_id=cred_abc123"),
            "{check:?}"
        );
    }

    #[test]
    fn credential_check_reports_the_expiry_even_when_everything_else_is_quiet() {
        // 到期时间只在 config 里（state 里没有）时，失败消息不能打空。
        let state = runtime_state();
        let stamp = rfc3339_in(-24 * 60 * 60);
        let mut config = template_config();
        config.control_plane.bearer_token = Some("tok".to_string());
        config.control_plane.credential_expires_at = Some(stamp.clone());

        let check = credential_check(&config, &state);
        assert_eq!(check.status, Status::Fail);
        assert!(
            check.detail.contains(&stamp),
            "detail should show the real expiry: {check:?}"
        );
    }

    #[test]
    fn probe_writable_probes_without_creating_directories() {
        let root = std::env::temp_dir().join(format!("doctor-probe-{}", std::process::id()));
        std::fs::create_dir_all(&root).expect("create root");
        let leaf = root.join("a").join("b").join("c");

        // 叶子不存在 → 用祖先探写，返回 Ok(false)，且**不把叶子/中间目录建出来**。
        assert_eq!(probe_writable(&leaf), Ok(false));
        assert!(!leaf.exists(), "probe must not create the leaf");
        assert!(
            !root.join("a").exists(),
            "probe must not create intermediates"
        );

        // 已存在的目录 → Ok(true)。
        assert_eq!(probe_writable(&root), Ok(true));

        // 路径存在但是文件 → Err。
        let file = root.join("not-a-dir");
        std::fs::write(&file, b"x").expect("write file");
        assert!(probe_writable(&file).is_err());

        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn diagnose_offline_keeps_local_uplink_spool_and_work() {
        let root = std::env::temp_dir().join(format!("doctor-offline-{}", std::process::id()));
        let config_dir = root.join("wist-agentd");
        std::fs::create_dir_all(&config_dir).expect("create config dir");
        std::fs::write(
            config_dir.join("agentd.toml"),
            format!(
                "schema_version = \"v1\"\n\n[control_plane]\nenabled = false\n\n[paths]\nroot_dir = \"{d}/data\"\nrun_dir = \"run\"\nstate_dir = \"state\"\nlog_dir = \"{d}/log\"\n",
                d = root.display()
            ),
        )
        .expect("write config");

        let report = diagnose(&config_dir, true).await;
        let ids: Vec<&str> = report.checks.iter().map(|c| c.id).collect();

        // 本地结论照常 —— 这正是本轮修的点：以前 `--offline` 把它们一起丢了。
        assert!(ids.contains(&"uplink.effective"), "{ids:?}");
        assert!(ids.contains(&"uplink.spool"), "{ids:?}");
        assert!(ids.contains(&"work.local"), "{ids:?}");
        // 网络项一个都不该出现（除了那条“已跳过”的说明）。
        assert!(ids.contains(&"network.skipped"), "{ids:?}");
        assert!(
            !ids.iter()
                .any(|id| id.starts_with("network.") && *id != "network.skipped"),
            "{ids:?}"
        );
        assert!(!ids.contains(&"uplink.target"), "{ids:?}");
        let _ = std::fs::remove_dir_all(root);
    }

    #[tokio::test]
    async fn diagnose_treats_a_directory_config_path_as_not_a_file() {
        let root = std::env::temp_dir().join(format!("doctor-configdir-{}", std::process::id()));
        let config_dir = root.join("wist-agentd");
        // `agentd.toml` 是个目录（而不是文件）。
        std::fs::create_dir_all(config_dir.join("agentd.toml")).expect("create fake config dir");

        let report = diagnose(&config_dir, true).await;

        assert_eq!(report.checks.len(), 1);
        assert_eq!(report.checks[0].id, "config.file");
        assert!(
            report.checks[0].title.contains("不是文件"),
            "{:?}",
            report.checks[0]
        );
        assert_eq!(report.exit_code(), 1);
        let _ = std::fs::remove_dir_all(root);
    }

    #[test]
    fn load_config_with_state_identity_injects_credentials_from_state() {
        let root = std::env::temp_dir().join(format!("doctor-inject-{}", std::process::id()));
        let config_dir = root.join("wist-agentd");
        let state_dir = config_dir.join("state");
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        std::fs::write(
            config_dir.join("agentd.toml"),
            "schema_version = \"v1\"\n\n[control_plane]\nenabled = true\nendpoint = \"https://gw.example\"\n\n[paths]\nroot_dir = \".\"\nrun_dir = \"run\"\nstate_dir = \"state\"\nlog_dir = \"log\"\n",
        )
        .expect("write config");

        let mut state = wist_contracts::agent_state::AgentRuntimeState::new(
            "agent-real".to_string(),
            "inst-real".to_string(),
            "0.1.16".to_string(),
            wist_contracts::agent_state::RuntimeMode::Normal,
            "2026-09-29T00:00:00Z".to_string(),
        );
        state.bearer_token = Some("bearer-from-state".to_string());
        state.credential_expires_at = Some(rfc3339_in(30 * 24 * 60 * 60));
        agent_runtime::store(&agent_runtime::path_for(&state_dir), &state).expect("store state");

        let config_path = config_runtime::resolve_config_path(&config_dir);

        // 前提：凭据**不在** toml 里（只落 state）—— 这正是要注入的理由。
        let mut raw_checks = Vec::new();
        let plain = load_config(&config_path, &mut raw_checks).expect("plain load");
        assert!(
            plain.control_plane.bearer_token.is_none(),
            "凭据不应写进 toml"
        );
        assert!(plain.agent.agent_id.is_none(), "agent_id 不应写进 toml");

        // 注入后：配置拿到 state 的凭据与身份，控制面探测不再误判为「无下发」。
        let mut checks = Vec::new();
        let config = load_config_with_state_identity(&config_path, &mut checks).expect("load");
        assert_eq!(
            config.control_plane.bearer_token.as_deref(),
            Some("bearer-from-state")
        );
        assert_eq!(config.agent.agent_id.as_deref(), Some("agent-real"));
        assert!(
            checks.iter().all(|c| c.status != Status::Fail),
            "{checks:?}"
        );

        let _ = std::fs::remove_dir_all(root);
    }
}
