//! 升级执行体（`wist-upgrader`）：把「让这台机器的 Agent 换到目标版本」真正做掉。
//!
//! ## 为什么与 agentd 同 crate、但**单独一个二进制**
//!
//! - 同 crate：升级要替换的正是 `wist-agentd` + `wist-exec` 这一对（它们**版本锁死**，错配会让
//!   执行类任务直接失败）。同一个 package 里的三个 bin 天然同版本，不存在「升级器与 agentd 版本
//!   对不上」这一类问题；同时它要复用 agentd 的配置加载、带信任锚的 HTTP 客户端、state 目录约定，
//!   分成独立 crate 就得把这些再抄一遍。
//! - 单独二进制：它必须能在 **agentd 被换掉的那个窗口里活着** —— 等新版起来、失败回滚。
//!   agentd 对 `wist-exec` 的每个子进程有完整生命周期控制（超时杀 / cancel / kill），
//!   所以**不能**把它塞进 `wist-exec`；它也不该进 agentd 自己的调度，而是以分离进程运行。
//!   Linux 上还要再进一步：由 agentd 把它包成一个**独立的 systemd 瞬态 unit** 拉起
//!   （见 [`spawn_upgrader`]）—— 否则 agentd 的 `KillMode=control-group` 会在
//!   `systemctl restart` 时按 cgroup 把它一起收走。
//!
//! ## 与 `install.sh` 的关系：同一份制品、同一套动作
//!
//! 升级不是另一条供应链：包还是那一个（网关缓存的同一份制品、同一个 sha256），动作还是那几步
//! （取包 → 校验摘要 → 按形态解包 → 先写 `.new` 再改名 → 重启常驻）。区别只有两点：
//! 升级的**来源**是网关自己的分发端点（由网关在派活时给出），以及升级必须**可回滚**。
//!
//! ## 这个模块只做「执行」，不做「决定」
//!
//! 「要不要升、升到哪一版」是控制面的事（一次性工作 + 动作目录）。执行体只保证：
//! 版本只会前进、摘要必须相符、换件是原子的、失败能回到原样。

use std::path::{Path, PathBuf};
use std::time::Duration;

use serde::{Deserialize, Serialize};
use wist_artifact::digest::{parse_digest, sha256_hex_bytes};
use wist_artifact::source::{ArtifactError, read_local_source, read_source_with_client};
use wist_artifact::version::{parse_version, version_is_newer};
use wist_contracts::agent_config::AgentConfig;
use wist_shared::fs::{read_json, write_json_atomic};
use wist_shared::time::now_rfc3339;

use crate::control::enrollment::enrollment_http_client;
#[cfg(target_os = "macos")]
use crate::service::LAUNCHD_LABEL;
#[cfg(not(target_os = "macos"))]
use crate::service::SERVICE_NAME;

/// 与 `wist-agentd` 同级发布的二进制：制品里必须都带上，换的时候**一起换**。
pub const AGENTD_BIN_NAME: &str = "wist-agentd";
pub const EXEC_BIN_NAME: &str = "wist-exec";
/// 本执行体自己也在制品里 —— 它也一起换（新版 agentd 下次会用新的升级器）。
pub const UPGRADER_BIN_NAME: &str = "wist-upgrader";

/// 升级进度/结果落盘（放 agentd 的 state 目录下）：agentd 重启后据此回报并识别「有一件在做」。
pub const UPGRADE_RECORD_FILE: &str = "upgrade.json";
/// 升级器的**心跳**文件：活着就持续写，agentd 据此判定「那个进程还在不在」。
///
/// 为什么不看升级记录的 `updated_at`：正常升级里有**合法的长静默**（`wait_ready` 默认等 60s、
/// 取包最多 300s），那段时间记录本来就不动。心跳是另一条持续在写的线，
/// 于是「60s 没动静」才真的等于「进程没了（被 kill / 卡死）」。
pub const UPGRADE_HEARTBEAT_FILE: &str = "upgrade.heartbeat";
/// 下载与暂存的子目录（放 state 下而不是 run 下：它要跨重启留着，便于事后取证）。
pub const UPGRADE_WORK_DIR: &str = "upgrade";
/// 换件后等新版起来的默认上限。
pub const DEFAULT_READY_WAIT: Duration = Duration::from_secs(60);
/// 心跳间隔：要明显小于 [`UPGRADER_DEAD_AFTER`]，否则任务调度抖动会被误判成死亡。
const HEARTBEAT_INTERVAL: Duration = Duration::from_secs(10);
/// 升级器多久没心跳就**当它死了**（被 kill / 崩溃 / 卡死）。
///
/// 为什么由 agentd 判：升级器是**分离进程**，agentd 对它有调度权、没有生命周期权。
/// 不判就会有件活永远占着「有升级在飞」这把互斥锁，之后再派升级都不做。
pub const UPGRADER_DEAD_AFTER: Duration = Duration::from_secs(60);
/// 取包超时：制品几十 MB，给足时间但不能无限等。
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// 取包**大小**上限：制品几十 MB，这是远高于正常值的天花板。
///
/// 少了它，`response.bytes()` 是无界的 —— 一个坏掉的 / 被投毒的网关（或它重定向到的
/// 第三方）就能让 agentd 把内存吃光。
const MAX_PACKAGE_BYTES: u64 = 512 * 1024 * 1024;
/// 等新版起来的轮询间隔。
const READY_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// 在解包目录里找二进制时最多往下走几层（制品常带一层 `wist-agentd-<ver>-<target>/`）。
const MAX_ARTIFACT_DEPTH: usize = 3;

/// 一次性工作里 `action = upgrade` 的参数形状（JSON）。
///
/// `package_url` / `package_sha256` 由网关在派活时按**当前分发端点**与**实际缓存制品**填入，
/// 而不是让运维手抄：摘要必须与真正会被分发出去的那份字节同源，否则升级会变成
/// 「谁写这个字段谁决定装什么」。
///
/// `target_version` **可省**（空串等同于没给）：版本本来就是「那份包里 agentd 自报的版本」，
/// 缺省时由升级器解包后从二进制读出来 —— 让运维手抄只会多一个「填错就 version_mismatch」的坑。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UpgradeSpec {
    #[serde(default)]
    pub target_version: Option<String>,
    pub package_url: String,
    pub package_sha256: String,
    /// 是否允许同版本/降级。默认 `false`：只前进。
    ///
    /// 守卫默认在最严的一侧：降级会真的把机器往回退，所以要**显式**在这里写 `true`，
    /// 而不是靠缺省字段静默放行（见 [`validate_request`] / [`resolve_target_version`]）。
    #[serde(default)]
    pub allow_downgrade: bool,
}

/// 一次升级请求：把工作参数与「本机现状」凑在一起。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// 触发这次升级的一次性工作 id（结果要挂回它）。
    pub work_id: String,
    /// 目标版本：`Some` = 显式要求（必须与包内自报版本一致）；`None` = 由包决定。
    pub target_version: Option<String>,
    /// agentd 自报的版本（来自它自己的 `CARGO_PKG_VERSION`，不是从文件名猜的）。
    pub current_version: String,
    /// 要替换的 `wist-agentd` 路径（agentd 传自己的 `current_exe`）。
    pub agentd_bin: PathBuf,
    pub package_url: String,
    pub package_sha256: String,
    /// 是否允许同版本/降级。默认 `false`：只前进（见 [`validate_request`]）。
    pub allow_downgrade: bool,
}

impl UpgradeRequest {
    /// 与守护进程同级发布的执行器路径。
    pub fn exec_bin(&self) -> PathBuf {
        self.agentd_bin.with_file_name(EXEC_BIN_NAME)
    }

    /// 升级器自身路径（它也会被换）。
    pub fn upgrader_bin(&self) -> PathBuf {
        self.agentd_bin.with_file_name(UPGRADER_BIN_NAME)
    }
}

/// 重启手段。默认按平台推导，但允许显式给命令（联调、非常规安装）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RestartPlan {
    /// 不重启（演练：只走到换件之前）。
    None,
    Command {
        program: String,
        args: Vec<String>,
    },
}

/// 执行选项。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeOptions {
    /// 只做到「准备好新件」，不落盘、不重启（第一次在真机上试的时候用）。
    pub dry_run: bool,
    pub ready_wait: Duration,
    pub restart: RestartPlan,
}

impl Default for UpgradeOptions {
    fn default() -> Self {
        Self {
            dry_run: true,
            ready_wait: DEFAULT_READY_WAIT,
            restart: RestartPlan::None,
        }
    }
}

/// 升级过程落盘的进度/结果。`step` + `status` 合起来回答「做到哪一步了、成没成」。
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UpgradeRecord {
    pub work_id: String,
    pub from_version: String,
    pub to_version: String,
    /// 走到/停在哪一步。
    pub step: String,
    /// `running` | `succeeded` | `failed` | `rolled_back`。
    pub status: String,
    /// 给人看的说明（失败原因原样带上）。
    pub detail: String,
    pub agentd_bin: String,
    pub updated_at: String,
}

impl UpgradeRecord {
    fn new(request: &UpgradeRequest) -> Self {
        Self {
            work_id: request.work_id.clone(),
            from_version: request.current_version.clone(),
            // 目标版本要等解包读到包内自报版本才能定；这里先落显式给的那个（可能为空）。
            to_version: request.target_version.clone().unwrap_or_default(),
            step: "validate".to_string(),
            status: "running".to_string(),
            detail: String::new(),
            agentd_bin: request.agentd_bin.display().to_string(),
            updated_at: now_rfc3339(),
        }
    }

    fn step(&mut self, step: &str) {
        self.step = step.to_string();
        self.updated_at = now_rfc3339();
    }

    fn finish(&mut self, status: &str, detail: impl Into<String>) {
        self.status = status.to_string();
        self.detail = detail.into();
        self.updated_at = now_rfc3339();
    }
}

/// 执行体的失败：给人看的原因 + 机器可读的短码（回报网关时只带短码与说明）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeError {
    pub reason: &'static str,
    pub detail: String,
}

impl std::fmt::Display for UpgradeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(formatter, "{}: {}", self.reason, self.detail)
    }
}

impl std::error::Error for UpgradeError {}

fn fail(reason: &'static str, detail: impl Into<String>) -> UpgradeError {
    UpgradeError {
        reason,
        detail: detail.into(),
    }
}

/// 解析工作参数。形状不对就直接拒（宁可不升，也不要猜参数）。
///
/// `target_version` 可省：空串等同于「没给」，交给包内自报的版本决定（见
/// [`resolve_target_version`]）。
pub fn parse_spec(text: &str) -> Result<UpgradeSpec, UpgradeError> {
    let mut spec: UpgradeSpec = serde_json::from_str(text).map_err(|err| {
        fail(
            "spec_invalid",
            format!(
                "expected JSON {{\"package_url\":\"…\",\"package_sha256\":\"…\"}} (optional \"target_version\":\"…\"), got: {err}"
            ),
        )
    })?;
    if spec.package_url.trim().is_empty() {
        return Err(fail("spec_invalid", "package_url is empty"));
    }
    if spec
        .target_version
        .as_deref()
        .map(str::trim)
        .unwrap_or("")
        .is_empty()
    {
        spec.target_version = None;
    }
    Ok(spec)
}

/// 版本号拆成可比的分段（`0.1.4` → `[0,1,4]`）。带 `-pre` 后缀时只看前面的数字段。
///
/// 认不出来就返回 `None`：升级方向宁可拒绝，也不要拿字符串比较去猜大小。
///
/// 实现在**底座** crate `wist-artifact`（与「该不该升 / 是不是降级」同一口径）；中心、网关、
/// gwlinkd 将来都用它。旧的本地实现已删。
fn version_parts(value: &str) -> Option<Vec<u64>> {
    parse_version(value)
}

/// 摘要字段：允许 `sha256:` 前缀（管理面/模型里就是那个写法），但必须是 64 位裸 hex。
///
/// 口径（前缀 / 大小写 / 长度）在**底座** crate `wist-artifact`（与网关缓存、中心发布同一份）；
/// 这里只把它翻成 agentd 自己的错误码。
fn digest_hex(value: &str) -> Result<String, UpgradeError> {
    parse_digest(value).map_err(|_| {
        fail(
            "digest_invalid",
            format!("package_sha256 must be 64 hex chars, got {value:?}"),
        )
    })
}

fn validate_request(request: &UpgradeRequest) -> Result<(), UpgradeError> {
    if request.work_id.trim().is_empty() {
        return Err(fail("spec_invalid", "work_id is empty"));
    }
    // 与 `parse_spec` 同口径：空地址在这里就拒。少了这道，空地址会一路走到 `fetch_package`
    // 才以一条费解的 HTTP 错误暴露（而 `build_launch` 的路径不经过 `parse_spec`）。
    if request.package_url.trim().is_empty() {
        return Err(fail("spec_invalid", "package_url is empty"));
    }
    // 显式给了目标版本就先比一次（早失败）；没给就跳过 —— 它要等解包、读到包内
    // agentd 自报的版本才能比（见 `resolve_target_version`）。
    if let Some(target) = provided_target(request) {
        // 默认只前进；降级要**显式声明** `allow_downgrade` 才放行。
        if !request.allow_downgrade {
            ensure_newer(target, &request.current_version)?;
        }
    }
    digest_hex(&request.package_sha256)?;
    Ok(())
}

/// 请求里**显式给的**目标版本（空串当作没给）。
fn provided_target(request: &UpgradeRequest) -> Option<&str> {
    request
        .target_version
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
}

/// 只前进：目标必须比当前运行版本新（降级与重装一律拒），且两者都得是点分数字。
fn ensure_newer(target: &str, current: &str) -> Result<(), UpgradeError> {
    match version_is_newer(target, current) {
        Some(true) => Ok(()),
        Some(false) => Err(fail(
            "not_newer",
            format!(
                "target {target} is not newer than running {current} (downgrade and reinstall are refused)"
            ),
        )),
        None => Err(fail(
            "version_uncomparable",
            format!("cannot compare {target} with {current} as dotted numeric versions"),
        )),
    }
}

/// 定下这次升级的**目标版本**：
///
/// * 显式给了就用它，但要求与包内 agentd 自报的版本**一致**（不一致 = 说的与装的是两回事）；
/// * 没给（常见）就**以包内自报的版本为准** —— 版本本来就是那份包里的版本;
///
/// 无论哪条，最后都要比当前运行版本新（只前进）—— 除非请求**显式声明**了
/// `allow_downgrade`（同版本/降级才放行；目标版本仍以包内自报为准，这里不改）。
fn resolve_target_version(
    request: &UpgradeRequest,
    reported: &str,
) -> Result<String, UpgradeError> {
    let target = match provided_target(request) {
        Some(target) => {
            if target != reported {
                return Err(fail(
                    "version_mismatch",
                    format!("package reports {reported:?}, target is {target:?}"),
                ));
            }
            target.to_string()
        }
        None => reported.to_string(),
    };
    // 默认只前进；降级要**显式声明** `allow_downgrade` 才放行。
    if !request.allow_downgrade {
        ensure_newer(&target, &request.current_version)?;
    }
    Ok(target)
}

fn verify_digest(bytes: &[u8], expected: &str) -> Result<(), UpgradeError> {
    let expected = digest_hex(expected)?;
    // 摘要算法在共享 crate（`ring`）——与网关缓存那份、中心发布那份同一个实现。
    let actual = sha256_hex_bytes(bytes);
    if actual != expected {
        return Err(fail(
            "digest_mismatch",
            format!("expected {expected}, got {actual}"),
        ));
    }
    Ok(())
}

/// 取包：`https://…` 走网关（带信任锚与 mTLS 客户端证书），`/abs/path` 直接读本机（联调与离线演练）。
///
/// 读字节这套**机制**（甄别路径 / URL、读完前拦大小超限）在**底座** crate `wist-artifact`，
/// 与网关缓存、中心发布同一份；这里只保留 agentd 的**策略与错误码**：
/// 超时 300s、上限 512 MiB、`package_too_large` / `package_unavailable`。
///
/// 本机路径分支**刻意不建 client**：联调 / 离线演练常在没有已签发身份、甚至没有 trust
/// bundle 的机器上跑，那边一旦要求 client，就把「能读本地文件」变成了读不了。
async fn fetch_package(config: &AgentConfig, source: &str) -> Result<Vec<u8>, UpgradeError> {
    let source = source.trim();
    if source.starts_with('/') {
        return read_local_source(source, MAX_PACKAGE_BYTES).map_err(map_fetch_error);
    }
    // 网关的分发端点要 agent 身份：靠 `enrollment_http_client` 里挂上的客户端证书（mTLS）
    // 认证，不再有 bearer token。client 交给共享 crate，就是为了不把这层身份丢掉。
    let client = enrollment_http_client(config)
        .map_err(|err| fail("package_unavailable", format!("build http client: {err}")))?;
    read_source_with_client(&client, source, MAX_PACKAGE_BYTES, DOWNLOAD_TIMEOUT)
        .await
        .map_err(map_fetch_error)
}

/// 把共享 crate 的取包错误翻成 agentd 自己的码：`package_too_large` 单独一类（可操作：
/// 「你指的包太大」），其余「拿不到」统一归 `package_unavailable`。
fn map_fetch_error(err: ArtifactError) -> UpgradeError {
    match err {
        ArtifactError::TooLarge(detail) => fail("package_too_large", detail),
        other => fail("package_unavailable", other.to_string()),
    }
}

/// 制品里被认出来的一个二进制。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StagedBinary {
    pub name: String,
    pub path: PathBuf,
}

fn looks_gzipped(bytes: &[u8]) -> bool {
    bytes.len() >= 2 && bytes[0] == 0x1f && bytes[1] == 0x8b
}

/// 给暂存件补执行位（`0755`）。
fn set_executable(path: &Path) -> Result<(), UpgradeError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perms = std::fs::metadata(path)
            .map_err(|err| fail("staging_failed", format!("stat {}: {err}", path.display())))?
            .permissions();
        perms.set_mode(0o755);
        std::fs::set_permissions(path, perms)
            .map_err(|err| fail("staging_failed", format!("chmod {}: {err}", path.display())))?;
    }
    let _ = path;
    Ok(())
}

fn is_known_binary(name: &str) -> bool {
    matches!(name, AGENTD_BIN_NAME | EXEC_BIN_NAME | UPGRADER_BIN_NAME)
}

/// 在解包目录里找已知二进制（制品常带一层 `wist-agentd-<ver>-<target>/`）。
fn find_binaries(root: &Path) -> Result<Vec<StagedBinary>, UpgradeError> {
    let mut found: Vec<StagedBinary> = Vec::new();
    let mut queue: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 0)];
    while let Some((dir, depth)) = queue.pop() {
        let entries = std::fs::read_dir(&dir)
            .map_err(|err| fail("artifact_invalid", format!("read {}: {err}", dir.display())))?;
        for entry in entries {
            let entry = entry.map_err(|err| {
                fail("artifact_invalid", format!("read {}: {err}", dir.display()))
            })?;
            let path = entry.path();
            let name = entry.file_name().to_string_lossy().to_string();
            // 符号链接不认：`install` 会**跟随**它，把链接指向的东西（甚至制品之外的文件）
            // 当成本件装进去。已知件名上出现链接直接拒；其它链接与安装无关，跳过。
            if path.is_symlink() {
                if is_known_binary(&name) {
                    return Err(fail(
                        "artifact_invalid",
                        format!("{name} is a symlink ({})", path.display()),
                    ));
                }
                continue;
            }
            if path.is_dir() {
                if depth < MAX_ARTIFACT_DEPTH {
                    queue.push((path, depth + 1));
                }
                continue;
            }
            if is_known_binary(&name) {
                // 同名多份：制品有歧义（哪一份才是要装的？），正规产出不会这样 —— 拒，
                // 而不是「先遍历到谁就装谁」。
                if found.iter().any(|item| item.name == name) {
                    return Err(fail(
                        "artifact_invalid",
                        format!("artifact carries more than one {name}"),
                    ));
                }
                found.push(StagedBinary { name, path });
            }
        }
    }
    if !found.iter().any(|item| item.name == AGENTD_BIN_NAME) {
        return Err(fail(
            "artifact_invalid",
            format!("{AGENTD_BIN_NAME} not found in the artifact"),
        ));
    }
    found.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(found)
}

/// 把下载到的字节摊成可安装的二进制：tarball 解包，裸二进制就当作 `wist-agentd`。
///
/// 每次升级都**重建暂存目录**：上一次失败留下的半截文件绝不能被当成本次的件。
/// 升级**不许把机器变成混合版本**。两条一起看：
///
///   1. **制品形态**只能是两种之一：「三件齐全」（发布 tarball）或「只有 `wist-agentd`」
///      （网关内置的裸包）。带两件不带第三件不是任何正规产出，直接拒。
///   2. **盘上已有的件，制品必须也带了**：升级只装不删，制品没带的那个件会原样留着 ——
///      于是 agentd 换成了新版、它还是旧版，而升级器去换的正是 agentd 自己。
///
/// 为什么必须在换件**之前**拦：换完才发现就晚了（得回滚）。而**摘要校验拦不住**：
/// 网关按它自己缓存的那份字节算摘要，漏打包的包自己跟自己对得上。
///
/// 为什么不能只查制品形态：**裸包盖在三件套机器上**同样会留混合版本 ——
/// 制品的形态完全合法，问题出在「它与这台机器」的组合上。
fn check_upgrade_keeps_bin_directory_consistent(
    staged: &[StagedBinary],
    bin_dir: &Path,
) -> Result<(), UpgradeError> {
    let brings = |name: &str| staged.iter().any(|item| item.name == name);
    let exec = brings(EXEC_BIN_NAME);
    let upgrader = brings(UPGRADER_BIN_NAME);

    // 1) 制品形态：两个兄弟件要么都在，要么都不在。
    if exec != upgrader {
        return Err(fail(
            "artifact_invalid",
            format!(
                "the artifact carries {EXEC_BIN_NAME}={exec}, {UPGRADER_BIN_NAME}={upgrader}: \
                 a package must carry all three binaries, or only {AGENTD_BIN_NAME}"
            ),
        ));
    }
    // 2) 三件齐全：缺的那两件自己也换新，没有什么可挑的。
    if exec {
        return Ok(());
    }
    // 3) 只带 agentd：盘上不能已经有那两件 —— 升级只装不删，它们会留在旧版本。
    for name in [EXEC_BIN_NAME, UPGRADER_BIN_NAME] {
        if bin_dir.join(name).exists() {
            return Err(fail(
                "artifact_invalid",
                format!(
                    "{name} already exists in {}: the artifact must carry it too, \
                     otherwise the upgrade would leave it at the old version",
                    bin_dir.display()
                ),
            ));
        }
    }
    Ok(())
}

fn stage_package(bytes: &[u8], staging_dir: &Path) -> Result<Vec<StagedBinary>, UpgradeError> {
    if staging_dir.exists() {
        std::fs::remove_dir_all(staging_dir).map_err(|err| {
            fail(
                "staging_failed",
                format!("clear {}: {err}", staging_dir.display()),
            )
        })?;
    }
    std::fs::create_dir_all(staging_dir).map_err(|err| {
        fail(
            "staging_failed",
            format!("create {}: {err}", staging_dir.display()),
        )
    })?;

    if !looks_gzipped(bytes) {
        let path = staging_dir.join(AGENTD_BIN_NAME);
        std::fs::write(&path, bytes)
            .map_err(|err| fail("staging_failed", format!("write {}: {err}", path.display())))?;
        // 裸二进制也可能没带执行位（制品打包时丢掉）：不补的话下一步「让它自报版本」会失败。
        set_executable(&path)?;
        return Ok(vec![StagedBinary {
            name: AGENTD_BIN_NAME.to_string(),
            path,
        }]);
    }

    let archive = staging_dir.join("package.tar.gz");
    std::fs::write(&archive, bytes).map_err(|err| {
        fail(
            "staging_failed",
            format!("write {}: {err}", archive.display()),
        )
    })?;
    let unpacked = staging_dir.join("unpacked");
    std::fs::create_dir_all(&unpacked).map_err(|err| {
        fail(
            "staging_failed",
            format!("create {}: {err}", unpacked.display()),
        )
    })?;
    // 用系统的 tar：与 install.sh 同一动作、同一失败面，且不必为此给 agentd 加解包依赖。
    let status = std::process::Command::new("tar")
        .arg("-xzf")
        .arg(&archive)
        .arg("-C")
        .arg(&unpacked)
        .status()
        .map_err(|err| fail("staging_failed", format!("run tar: {err}")))?;
    if !status.success() {
        return Err(fail(
            "staging_failed",
            format!("tar -xzf exited with {status}"),
        ));
    }
    find_binaries(&unpacked)
}

/// 版本号输出形如 `wist-agentd 0.1.3`，也可能只是 `0.1.3`：取最后一个**像版本号**的词。
///
/// 「像版本号」= **至少两段点分数字**（`0.1.11`）。只要求「含点」不够：输出里若在版本后面
/// 又跟了别的带点词（`…T16:05:49.090849Z` 这种时间戳也含点），会被误当版本 —— 而
/// [`version_parts`] 把时间戳读成 `[2026]`，于是「目标版本 = 2026」、`ensure_newer` 恒成立。
/// 找不到多段数字就当「没报版本」（`None`）：宁可拒升级，也不要猜。
fn parse_version_output(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .rev()
        .find(|token| version_parts(token).is_some_and(|parts| parts.len() >= 2))
        .map(|token| token.trim().to_string())
}

/// 让包里的 agentd **自报版本**并返回 —— 这就是这次升级的目标版本。
///
/// 摘要对了不代表版本对（例如把旧包重新压了一遍），所以换件前要问一句「你到底自称哪一版」。
/// 调用方拿这个值去定目标版本（见 `resolve_target_version`），并等新版起来后与运行态对账。
fn verify_staged_agentd(staged: &[StagedBinary]) -> Result<String, UpgradeError> {
    let agentd = staged
        .iter()
        .find(|item| item.name == AGENTD_BIN_NAME)
        .ok_or_else(|| fail("artifact_invalid", "staged artifact has no wist-agentd"))?;
    let output = std::process::Command::new(&agentd.path)
        .arg("version")
        .output()
        .map_err(|err| {
            fail(
                "artifact_invalid",
                format!("run {} version: {err}", agentd.path.display()),
            )
        })?;
    if !output.status.success() {
        return Err(fail(
            "artifact_invalid",
            format!(
                "{} version exited with {}",
                agentd.path.display(),
                output.status
            ),
        ));
    }
    let reported =
        parse_version_output(&String::from_utf8_lossy(&output.stdout)).unwrap_or_default();
    if reported.trim().is_empty() {
        return Err(fail(
            "artifact_invalid",
            format!("{} did not report a version", agentd.path.display()),
        ));
    }
    Ok(reported)
}

/// 一件被换掉的二进制及其备份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub installed: PathBuf,
    pub backup: PathBuf,
    /// 换之前这个位置**有没有东西**：回滚时据此决定「放回旧件」还是「删掉新件」。
    /// 不能靠「备份文件在不在」推断：`.bak-<版本>` 是刻意保留的，_上一次_升级留下的备份
    /// 会让一个本来就不存在的文件看起来像「有过旧件」。
    pub existed: bool,
}

fn run_command(program: &str, args: &[String]) -> Result<(), UpgradeError> {
    let status = std::process::Command::new(program)
        .args(args)
        .status()
        .map_err(|err| fail("command_failed", format!("run {program}: {err}")))?;
    if !status.success() {
        return Err(fail(
            "command_failed",
            format!("{program} exited with {status}"),
        ));
    }
    Ok(())
}

/// 原子换件：备份现值 → 写 `.new` → 改名。
///
/// 为什么不原地覆盖：运行中的进程持有旧 inode，原地改写等于给「正在跑的那个」投毒；
/// 改名换的是 inode，运行中的进程不受影响，重启后自然拿到新件。
/// 换件：备份 → 落新件 → 原子换入（`install` + `mv`，不直接覆写正在跑的二进制）。
///
/// **失败时自己收尾**：换到一半出错，就把已经换掉的那几个放回去再返回错误。
/// 半套制品（agentd 新版 + exec 旧版）比整套旧版更危险，而调用方拿不到「换成功了哪几个」
/// （`Err` 里没有 `backups`），所以这副收尾只能在这里做。
fn install_binaries(
    staged: &[StagedBinary],
    bin_dir: &Path,
    current_version: &str,
    dry_run: bool,
) -> Result<Vec<Backup>, UpgradeError> {
    let mut backups = Vec::new();
    for item in staged {
        let installed = bin_dir.join(&item.name);
        let backup = bin_dir.join(format!("{}.bak-{current_version}", item.name));
        let new_path = bin_dir.join(format!("{}.new", item.name));
        // 先问「换之前有没有」，再动手 —— 动手之后这个判断就没了。
        let existed = installed.exists();
        if dry_run {
            backups.push(Backup {
                installed,
                backup,
                existed,
            });
            continue;
        }

        let attempt = (|| -> Result<(), UpgradeError> {
            if existed && !backup.exists() {
                std::fs::copy(&installed, &backup).map_err(|err| {
                    fail(
                        "install_failed",
                        format!("backup {}: {err}", installed.display()),
                    )
                })?;
            }
            let mode_args = vec![
                "-m".to_string(),
                "0755".to_string(),
                item.path.display().to_string(),
                new_path.display().to_string(),
            ];
            run_command("install", &mode_args)?;
            let move_args = vec![
                "-f".to_string(),
                new_path.display().to_string(),
                installed.display().to_string(),
            ];
            run_command("mv", &move_args)
        })();

        if let Err(err) = attempt {
            // 换到一半失败：把**已经换掉的那几个**先放回去。否则盘上会留一个
            // 「agentd 是新版、exec 还是旧版」的半套制品 —— 两个件版本不一致正是
            // 「一起换」要防的事，而这一刻还没人知道。
            // 当前这个件没换成功（它还没进 `backups`），所以只回滚前面几个。
            let note = match restore_backups(&backups, bin_dir) {
                Ok(()) => "; already-replaced binaries were rolled back".to_string(),
                Err(rollback_err) => {
                    format!("; rollback of the already-replaced binaries failed: {rollback_err}")
                }
            };
            return Err(fail(err.reason, format!("{}{note}", err.detail)));
        }
        backups.push(Backup {
            installed,
            backup,
            existed,
        });
    }
    Ok(backups)
}

/// 回滚：把备份放回去（备份本身保留，事后要能取证）。
fn restore_backups(backups: &[Backup], bin_dir: &Path) -> Result<(), UpgradeError> {
    for backup in backups {
        if !backup.existed {
            // 换之前这个位置**本来就没有**（例如裸包装的机器升到三件套制品）：
            // 「回到原样」就是把它删掉，而不是去找一份不存在的备份。
            // 留一个没人核对过的新件，比什么都没有更危险。
            if backup.installed.is_file() {
                std::fs::remove_file(&backup.installed).map_err(|err| {
                    fail(
                        "rollback_failed",
                        format!("remove {}: {err}", backup.installed.display()),
                    )
                })?;
            }
            continue;
        }
        if !backup.backup.is_file() {
            return Err(fail(
                "rollback_failed",
                format!("missing backup {}", backup.backup.display()),
            ));
        }
        let name = backup
            .installed
            .file_name()
            .map(|value| value.to_string_lossy().to_string())
            .unwrap_or_default();
        let new_path = bin_dir.join(format!("{name}.rollback"));
        let mode_args = vec![
            "-m".to_string(),
            "0755".to_string(),
            backup.backup.display().to_string(),
            new_path.display().to_string(),
        ];
        run_command("install", &mode_args)?;
        let move_args = vec![
            "-f".to_string(),
            new_path.display().to_string(),
            backup.installed.display().to_string(),
        ];
        run_command("mv", &move_args)?;
    }
    Ok(())
}

/// 新版「起来了」的判据：`state/agent_runtime.json` 里的 `version` 变成目标版本。
///
/// 为什么不另加一个新行为：agentd 每轮都在重写这份派生状态、里面本来就有版本，
/// 让它再写一个「我起来了」的标记文件，等于给同一个事实造两个来源。
fn running_version(state_dir: &Path) -> Option<String> {
    let path = state_dir.join(wist_shared::paths::AGENT_RUNTIME_FILE);
    let state: wist_contracts::agent_state::AgentRuntimeState = read_json(&path).ok()?;
    Some(state.version)
}

async fn wait_for_version(state_dir: &Path, target_version: &str, limit: Duration) -> bool {
    let deadline = std::time::Instant::now() + limit;
    loop {
        if running_version(state_dir).as_deref() == Some(target_version) {
            return true;
        }
        if std::time::Instant::now() >= deadline {
            return false;
        }
        tokio::time::sleep(READY_POLL_INTERVAL).await;
    }
}

fn store_record(state_dir: &Path, record: &UpgradeRecord) -> std::io::Result<()> {
    write_json_atomic(&state_dir.join(UPGRADE_RECORD_FILE), record)
}

/// 跳一次心跳（内容给人看“现在几点”，判新旧看的是文件时间戳 —— 就是 `touch` 的语义）。
pub fn touch_heartbeat(state_dir: &Path) -> std::io::Result<()> {
    write_json_atomic(&state_dir.join(UPGRADE_HEARTBEAT_FILE), &now_rfc3339())
}

/// 心跳还新不新。读不到心跳文件也算「没在跳」：没有证据就不能当成活着。
pub fn heartbeat_is_fresh(state_dir: &Path, now: std::time::SystemTime) -> bool {
    let Ok(modified) =
        std::fs::metadata(state_dir.join(UPGRADE_HEARTBEAT_FILE)).and_then(|meta| meta.modified())
    else {
        return false;
    };
    match now.duration_since(modified) {
        Ok(age) => age < UPGRADER_DEAD_AFTER,
        // 时间戳在未来（时钟回拨 / 跨机拷贝）：不拿它当死亡证据。
        Err(_) => true,
    }
}

/// 只要进程活着就每隔 [`HEARTBEAT_INTERVAL`] 写一次心跳。
///
/// 它跑在自己的任务里，所以**不管升级走到哪一步都在跳** —— 取包、解包、换件、等新版起来
/// 都不会留下让 agentd 误判的静默。
fn spawn_heartbeat(state_dir: PathBuf) {
    // 先**同步**跳一次再交给任务循环：从「记录写成 running」到「心跳任务第一次被调度」
    // 之间有一段窗口，agentd 若恰好在那时来看，会把一份陈旧（或缺席）的心跳当成
    // 「那个进程已经没了」。写一次是原子的，代价可以忽略。
    let _ = touch_heartbeat(&state_dir);
    tokio::spawn(async move {
        loop {
            tokio::time::sleep(HEARTBEAT_INTERVAL).await;
            // 写失败只忽略：心跳是尽力而为的存活性信号，不该反过来把升级弄挂。
            let _ = touch_heartbeat(&state_dir);
        }
    });
}

/// 按平台给默认重启手段。
///
/// `system` 作用域：launchd 用 `system/<label>`、systemd 用系统 unit；用户级换成 gui 域 / `--user`。
/// 只做**重启**（定义不动）：换的是二进制，不是服务定义。
pub fn default_restart_plan(system_scope: bool) -> RestartPlan {
    #[cfg(target_os = "macos")]
    {
        let domain = if system_scope {
            format!("system/{LAUNCHD_LABEL}")
        } else {
            let uid = unsafe { libc::getuid() };
            format!("gui/{uid}/{LAUNCHD_LABEL}")
        };
        RestartPlan::Command {
            program: "launchctl".to_string(),
            args: vec!["kickstart".to_string(), "-k".to_string(), domain],
        }
    }
    #[cfg(not(target_os = "macos"))]
    {
        let mut args = Vec::new();
        if !system_scope {
            args.push("--user".to_string());
        }
        args.push("restart".to_string());
        args.push(SERVICE_NAME.to_string());
        RestartPlan::Command {
            program: "systemctl".to_string(),
            args,
        }
    }
}

fn run_restart(plan: &RestartPlan) -> Result<(), UpgradeError> {
    match plan {
        RestartPlan::None => Ok(()),
        RestartPlan::Command { program, args } => run_command(program, args),
    }
}

/// 解析升级器自己的路径：`WARP_INSIGHT_UPGRADER_BIN` 覆盖 → 与 agentd 同级。
///
/// 与 `wist-exec` 的解析同一优先级（见 `runtime_entry::resolve_exec_bin`），只是**不再回退 PATH**：
/// 升级器与 agentd 是同一份制品里的两个件，必须挨着放（否则「一起换」这个前提就不成立）。
pub fn resolve_upgrader_bin() -> Result<PathBuf, String> {
    let env_override = std::env::var_os("WARP_INSIGHT_UPGRADER_BIN").map(PathBuf::from);
    let current_exe =
        std::env::current_exe().map_err(|err| format!("resolve current exe: {err}"))?;
    resolve_upgrader_bin_from(&current_exe, env_override.as_deref())
}

fn resolve_upgrader_bin_from(
    current_exe: &Path,
    env_override: Option<&Path>,
) -> Result<PathBuf, String> {
    let candidate = match env_override {
        Some(path) => (path.to_path_buf(), "WARP_INSIGHT_UPGRADER_BIN"),
        None => (
            current_exe.with_file_name(UPGRADER_BIN_NAME),
            "sibling of the running agentd",
        ),
    };
    if !candidate.0.is_file() {
        return Err(format!(
            "{UPGRADER_BIN_NAME} not found at {} ({})",
            candidate.0.display(),
            candidate.1
        ));
    }
    Ok(candidate.0)
}

/// 交给 agentd 去起的那条命令（只构造，不执行 —— 可测的部分与副作用分开）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeLaunch {
    pub program: PathBuf,
    pub args: Vec<String>,
}

/// 构造拉起升级器的命令行。
///
/// 参数全部**显式**给（包括 `--bin`：默认值会猜成「升级器自己」，那就换错对象了），
/// 且一律带 `--apply`：预演是人在终端里做的事，agentd 派下来的活就是要求执行。
/// `--target-version` 只在**显式给了**时才传：不给就让升级器从包里自报的版本取。
pub fn build_launch(program: &Path, config_dir: &Path, request: &UpgradeRequest) -> UpgradeLaunch {
    let mut args = vec![
        "apply".to_string(),
        "--config-dir".to_string(),
        config_dir.display().to_string(),
        "--bin".to_string(),
        request.agentd_bin.display().to_string(),
        "--work-id".to_string(),
        request.work_id.clone(),
    ];
    if let Some(target) = provided_target(request) {
        args.push("--target-version".to_string());
        args.push(target.to_string());
    }
    // 降级是显式动作：只有请求声明了才把这条事实传给升级器（缺省不带 = 只前进）。
    if request.allow_downgrade {
        args.push("--allow-downgrade".to_string());
    }
    args.extend([
        "--current-version".to_string(),
        request.current_version.clone(),
        "--package-url".to_string(),
        request.package_url.clone(),
        "--package-sha256".to_string(),
        request.package_sha256.clone(),
        "--apply".to_string(),
    ]);
    UpgradeLaunch {
        program: program.to_path_buf(),
        args,
    }
}

/// 把升级器作为**分离进程**起起来（不等待、不随 agentd 退出而死），返回其 pid。
///
/// 为什么要自成会话：agentd 马上就会被这个进程换掉并重启，它必须在那个窗口里活着。
/// `setsid()` 能逃开**按会话/进程组**回收的服务管理器（launchd），但**逃不开 systemd 的
/// cgroup** —— `wist-agentd.service` 是 `KillMode=control-group`，`systemctl restart` 按 cgroup
/// 把整组进程一起收走。所以 Linux 上真正的入口是 [`spawn_upgrader`]（先包成独立瞬态 unit），
/// 本函数只作为它的退化路径（无 `systemd-run`）与 launchd 路径。
pub fn launch_detached(launch: &UpgradeLaunch, log_path: &Path) -> std::io::Result<u32> {
    if let Some(parent) = log_path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent)?;
    }
    let log = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .open(log_path)?;
    let log_err = log.try_clone()?;
    let mut command = std::process::Command::new(&launch.program);
    command
        .args(&launch.args)
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::from(log))
        .stderr(std::process::Stdio::from(log_err));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: `setsid` 只动本进程的会话/进程组归属，不碰内存；子进程在 exec 前调用它
        // 是标准做法（daemonize 的第一步）。
        unsafe {
            command.pre_exec(|| {
                if libc::setsid() == -1 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
    }
    let child = command.spawn()?;
    // 不 `wait`：它的生命周期比本次调用长得多（要活到新版 agentd 起来）。
    // 它退出时会短暂成为僵尸，旧 agentd 一死就由服务管理器收尸 —— 对一件稀有动作可接受。
    Ok(child.id())
}

/// systemd 瞬态 unit 名前缀：一眼能看出这是「一次升级」的进程。
const UPGRADER_UNIT_PREFIX: &str = "wist-upgrader-";

/// 瞬态 unit 名：unit 名只允许 `[A-Za-z0-9:_.-]`，`work_id` 里其余字符一律换成 `_`。
///
/// 用 `work_id`（而非随机名）是为了运维能直接 `systemctl status wist-upgrader-<id>` 找到它。
pub fn upgrader_unit_name(work_id: &str) -> String {
    let mut name = String::from(UPGRADER_UNIT_PREFIX);
    for ch in work_id.chars() {
        if ch.is_ascii_alphanumeric() || matches!(ch, ':' | '_' | '.' | '-') {
            name.push(ch);
        } else {
            name.push('_');
        }
    }
    name
}

/// 把升级器包进一个**独立的 systemd 瞬态 unit**（纯构造，便于单测）。
///
/// 为什么必须独立成 unit：`wist-agentd.service` 用 `KillMode=control-group`，`systemctl restart`
/// 是按 **cgroup** 回收进程的；升级器是 agentd 的子进程，`setsid()` 只换会话、换不掉 cgroup，
/// 于是会被这次 restart 一起杀掉（记录停在 `restart`，心跳断 60s 后即被判死）。
/// 拉成瞬态 unit 后它自带一个新 cgroup，restart 收不到它，`wait_ready` 才有机会跑完并上报成功。
pub fn build_systemd_run_launch(
    inner: &UpgradeLaunch,
    scope_is_system: bool,
    unit_name: &str,
    log_path: &Path,
    env_file: &Path,
) -> UpgradeLaunch {
    let mut args = Vec::new();
    if !scope_is_system {
        args.push("--user".to_string());
    }
    args.push(format!("--unit={unit_name}"));
    // 退出即清（成功失败都清）：留着同名 unit 会让下一次同 work_id 的升级起不来。
    args.push("--collect".to_string());
    // `exec`：让 systemd-run 等到 `execve` 成功才算起 unit 成功。默认的 `simple` 在 execve
    // **之前**就报成功 —— 那样一个起不来的升级器会被当成“已派发”，白白占住互斥锁。
    args.push("--service-type=exec".to_string());
    // 日志仍去 agentd 那份文件（与不包 unit 时一致，运维不用换地方找）。
    let log = systemd_property_path_escape(&log_path.display().to_string());
    args.push(format!("--property=StandardOutput=append:{log}"));
    args.push(format!("--property=StandardError=append:{log}"));
    // 瞬态 unit 跑在 systemd 给的干净环境里，**不继承** agentd 的进程环境；长期环境变量
    // （代理等）得显式指向 agentd 用的同一份 EnvironmentFile。
    let env = systemd_property_path_escape(&env_file.display().to_string());
    args.push(format!("--property=EnvironmentFile=-{env}"));
    args.push(format!("--property=SyslogIdentifier={unit_name}"));
    // `--` 把 systemd-run 的选项与要跑的命令分开，命令原样跟在后面。
    args.push("--".to_string());
    args.push(systemd_exec_escape(&inner.program.display().to_string()));
    args.extend(inner.args.iter().map(|arg| systemd_exec_escape(arg)));
    UpgradeLaunch {
        program: PathBuf::from("systemd-run"),
        args,
    }
}

/// 命令（会被当成 `ExecStart`）里不该被服务管理器展开的字符要转义：
/// `$`→`$$`（环境变量展开）、`%`→`%%`（specifier 展开）。
///
/// 不转义的话，URL 里的百分号编码（如 `%2F`）会被当成 specifier 吞掉，`$` 会被当变量展开 ——
/// 而走 [`launch_detached`] 时这些参数是逐字传的，两条路径的语义必须一致。
fn systemd_exec_escape(arg: &str) -> String {
    arg.replace('$', "$$").replace('%', "%%")
}

/// unit 属性里的路径只做 specifier 转义（`%`→`%%`）。
///
/// 属性值不做 `$` 展开，所以**不能**顺手把 `$` 也转了（那会把一个 `$` 写成两个）——
/// 只转 `%`。这也跟 unit 文件里对 `EnvironmentFile=` / `StandardOutput=` 路径的处理一致。
fn systemd_property_path_escape(value: &str) -> String {
    value.replace('%', "%%")
}

/// 拉起升级器，并保证它能**活过**紧接着的 `systemctl restart wist-agentd`。
///
/// Linux/systemd 上包成独立瞬态 unit（见 [`build_systemd_run_launch`]）；没有 `systemd-run`
///（容器 / 非 systemd 发行版）或其他平台（launchd 按进程组回收，`setsid` 已足够）沿用
/// [`launch_detached`]。返回一个用于日志的句柄：瞬态 unit 名，或分离进程的 pid。
pub fn spawn_upgrader(
    launch: &UpgradeLaunch,
    log_path: &Path,
    work_id: &str,
    scope_is_system: bool,
    env_file: &Path,
) -> Result<String, String> {
    #[cfg(target_os = "linux")]
    {
        if let Some(parent) = log_path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent).map_err(|err| format!("create log dir: {err}"))?;
        }
        let unit = upgrader_unit_name(work_id);
        let wrapped = build_systemd_run_launch(launch, scope_is_system, &unit, log_path, env_file);
        match std::process::Command::new(&wrapped.program)
            .args(&wrapped.args)
            .output()
        {
            // 起 unit 成功即返回：`systemd-run` 只是个 D-Bus 客户端，立刻退出；升级器在那个
            // 瞬态 unit 里继续跑（不等它：它的生命周期比本次调用长得多）。
            Ok(output) if output.status.success() => return Ok(unit),
            // `systemd-run` 在，但没起起来（权限 / 总线不可达 / 重名）：如实报错，绝不确认这活。
            Ok(output) => {
                let stderr = String::from_utf8_lossy(&output.stderr);
                let detail = if stderr.trim().is_empty() {
                    format!("exit status {}", output.status)
                } else {
                    stderr.trim().to_string()
                };
                return Err(format!("systemd-run {unit}: {detail}"));
            }
            // 没有 systemd-run：不是 systemd 环境，退回到分离进程。
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(format!("run systemd-run: {err}")),
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = (work_id, scope_is_system, env_file);
    launch_detached(launch, log_path)
        .map(|pid| pid.to_string())
        .map_err(|err| format!("launch {}: {err}", launch.program.display()))
}

/// 执行一次升级，并把进度/结果落盘。
///
/// 返回值同时已经写进 `<state_dir>/upgrade.json`（写失败只记在返回值的 detail 里，
/// 不让「记不上账」把升级本身判成失败）。
pub async fn apply(
    config: &AgentConfig,
    request: &UpgradeRequest,
    options: &UpgradeOptions,
) -> UpgradeRecord {
    let state_dir = PathBuf::from(&config.paths.state_dir);
    // 心跳跟本次进程同生共死：不需要收尾，进程一走心跳自然就旧了。
    spawn_heartbeat(state_dir.clone());
    let mut record = UpgradeRecord::new(request);
    match apply_inner(config, request, options, &state_dir, &mut record).await {
        Ok(()) => record.finish("succeeded", ""),
        Err(err) => {
            // 回滚过的结果与「纯失败」必须分开：前者机器已经回到原样，后者可能停在中间态。
            let status = if record.status == "rolled_back" {
                "rolled_back"
            } else {
                "failed"
            };
            record.finish(status, err.to_string());
        }
    }
    if let Err(err) = store_record(&state_dir, &record) {
        let note = format!("; record store failed: {err}");
        record.detail.push_str(&note);
    }
    record
}

async fn apply_inner(
    config: &AgentConfig,
    request: &UpgradeRequest,
    options: &UpgradeOptions,
    state_dir: &Path,
    record: &mut UpgradeRecord,
) -> Result<(), UpgradeError> {
    record.step("validate");
    validate_request(request)?;

    let staging_dir = state_dir.join(UPGRADE_WORK_DIR);
    record.step("fetch");
    // 每一步都落盘，不只开头那一条：agentd 每 tick 读这份记录来更新本机工作视图，
    // 它也是「升级进行中、不许再派第二件」的唯一依据 —— 进程活着却不落盘，外面就没人知道。
    // 更重要的是「判死」要报「停在哪一步」：`step` 只在内存里推进的话，进程被 kill / 掉电后
    // 留下的记录永远停在「fetch」，判死说明会把「换到一半」误说成「还没开始」。
    let _ = store_record(state_dir, record);
    let bytes = fetch_package(config, &request.package_url).await?;

    record.step("verify_digest");
    let _ = store_record(state_dir, record);
    verify_digest(&bytes, &request.package_sha256)?;

    record.step("stage");
    let _ = store_record(state_dir, record);
    let staged = stage_package(&bytes, &staging_dir)?;

    record.step("verify_artifact");
    let _ = store_record(state_dir, record);
    // 让包里的 agentd 自报版本 —— **目标版本以它为准**（没显式给就是它）；
    // 显式给了则要求两者一致（说的与装的是两回事就拒）。
    let reported = verify_staged_agentd(&staged)?;
    let target_version = resolve_target_version(request, &reported)?;
    record.to_version = target_version.clone();
    let _ = store_record(state_dir, record);
    // 制品本身没问题，还要看它与**这台机器**组合起来能不能落地（见函数注释）——
    // 与「验制品」同一步：都是换件之前的体检，都只读不写。
    let bin_dir = request
        .agentd_bin
        .parent()
        .ok_or_else(|| {
            fail(
                "install_failed",
                format!("no parent directory for {}", request.agentd_bin.display()),
            )
        })?
        .to_path_buf();
    check_upgrade_keeps_bin_directory_consistent(&staged, &bin_dir)?;

    record.step("install");
    let _ = store_record(state_dir, record);
    let backups = install_binaries(&staged, &bin_dir, &request.current_version, options.dry_run)?;
    if options.dry_run {
        return Ok(());
    }

    record.step("restart");
    let _ = store_record(state_dir, record);
    if let Err(err) = run_restart(&options.restart) {
        // 换件已经发生但没重启：先回滚，否则机器上会留一个「装着新版、跑着旧版」的中间态。
        let rollback = restore_backups(&backups, &bin_dir).err();
        let retry = run_restart(&options.restart).err();
        // `rolled_back` 的含义是「机器已回到原样」—— **回退真成了**才敢这么写。
        // 回退也失败就落成 `failed`：控制面该看到的是「这台机器停在一个说不清的状态」，
        // 而不是一个听起来很干净的「已回滚」。
        if rollback.is_none() {
            record.status = "rolled_back".to_string();
        }
        return Err(fail(
            "restart_failed",
            format!(
                "{err}{}{}",
                rollback
                    .map(|err| format!("; rollback failed: {err}"))
                    .unwrap_or_default(),
                retry
                    .map(|err| format!("; restart after rollback failed: {err}"))
                    .unwrap_or_default(),
            ),
        ));
    }

    record.step("wait_ready");
    let _ = store_record(state_dir, record);
    if !wait_for_version(state_dir, &target_version, options.ready_wait).await {
        let rollback = restore_backups(&backups, &bin_dir).err();
        let retry = run_restart(&options.restart).err();
        // 同 `restart` 那条：回退没成就不算 `rolled_back`。
        if rollback.is_none() {
            record.status = "rolled_back".to_string();
        }
        return Err(fail(
            "not_ready",
            format!(
                "new version did not report {} within {:?}{}{}",
                target_version,
                options.ready_wait,
                rollback
                    .map(|err| format!("; rollback failed: {err}"))
                    .unwrap_or_default(),
                retry
                    .map(|err| format!("; restart after rollback failed: {err}"))
                    .unwrap_or_default(),
            ),
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wist_contracts::agent_config::{
        AgentConfig, AgentSection, ControlPlaneSection, PathsSection,
    };
    use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};

    use super::*;

    fn temp_dir(label: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-upgrade-{label}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn config_with_state(state_dir: &Path) -> AgentConfig {
        let mut config = AgentConfig::new(
            AgentSection::default(),
            ControlPlaneSection::default(),
            PathsSection::default(),
            Default::default(),
        );
        config.paths.state_dir = state_dir.display().to_string();
        config
    }

    fn request(agentd_bin: PathBuf) -> UpgradeRequest {
        UpgradeRequest {
            work_id: "work-upgrade-1".to_string(),
            target_version: Some("0.1.4".to_string()),
            current_version: "0.1.3".to_string(),
            agentd_bin,
            package_url: "/nonexistent/package.tar.gz".to_string(),
            package_sha256: "0".repeat(64),
            allow_downgrade: false,
        }
    }

    /// 一个「自称某个版本」的假 agentd（脚本），供 artifact 校验用。
    fn fake_agentd(dir: &Path, reported_version: &str) -> PathBuf {
        let path = dir.join(AGENTD_BIN_NAME);
        fs::write(
            &path,
            format!("#!/bin/sh\necho \"wist-agentd {reported_version}\"\n"),
        )
        .expect("write fake agentd");
        let mut perms = fs::metadata(&path).expect("metadata").permissions();
        std::os::unix::fs::PermissionsExt::set_mode(&mut perms, 0o755);
        fs::set_permissions(&path, perms).expect("chmod");
        path
    }

    #[test]
    fn parse_spec_reads_the_three_fields() {
        let spec = parse_spec(
            r#"{"target_version":"0.1.4","package_url":"https://gw/api/v1/agent/packages/current","package_sha256":"sha256:abc"}"#,
        )
        .expect("parse");
        assert_eq!(spec.target_version.as_deref(), Some("0.1.4"));
        assert_eq!(spec.package_url, "https://gw/api/v1/agent/packages/current");
        assert_eq!(spec.package_sha256, "sha256:abc");
    }

    #[test]
    fn parse_spec_explains_the_expected_shape() {
        let err = parse_spec("0.1.4").expect_err("garbage must fail");
        assert_eq!(err.reason, "spec_invalid");
        assert!(err.detail.contains("target_version"), "{err}");
    }

    #[test]
    fn validate_refuses_downgrade_and_reinstall() {
        let dir = temp_dir("validate-downgrade");
        for (target, current) in [("0.1.3", "0.1.3"), ("0.1.2", "0.1.3")] {
            let mut request = request(dir.join(AGENTD_BIN_NAME));
            request.target_version = Some(target.to_string());
            request.current_version = current.to_string();
            let err = validate_request(&request).expect_err("must refuse");
            assert_eq!(err.reason, "not_newer", "{err}");
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_refuses_uncomparable_versions() {
        let dir = temp_dir("validate-version");
        let mut request = request(dir.join(AGENTD_BIN_NAME));
        request.current_version = "dev".to_string();
        let err = validate_request(&request).expect_err("must refuse");
        assert_eq!(err.reason, "version_uncomparable");
        let _ = fs::remove_dir_all(dir);
    }

    /// 版本比较的边界逐条钉住：相等 / 数值段 / 预发布后缀 / 四段 / `v` 前缀 / 空串 / 非数字。
    /// 判据只有两档：能比就比出新旧，比不出来一律 `version_uncomparable`（宁可拒绝也不猜）。
    #[test]
    fn validate_maps_version_boundaries_to_the_right_codes() {
        let dir = temp_dir("validate-boundaries");
        // (target, current, allow_downgrade, 该不该拒)
        let cases: &[(&str, &str, bool, Option<&str>)] = &[
            // 数值比较：0.1.10 比 0.1.9 新（不是字典序），反过来旧。
            ("0.1.10", "0.1.9", false, None),
            ("0.1.9", "0.1.10", false, Some("not_newer")),
            // 相等：同版本重装也算「不更新」→ not_newer（不是 uncomparable）。
            ("0.1.9", "0.1.9", false, Some("not_newer")),
            // 显式声明降级：同版本/低版本都放行。
            ("0.1.9", "0.1.9", true, None),
            ("0.1.9", "0.1.10", true, None),
            // 预发布后缀只看前面的数字段。
            ("0.2.0-beta.1", "0.1.9", false, None),
            // 四段：多一段视为更细的补丁，比三段新。
            ("0.1.9.1", "0.1.9", false, None),
            // 空前缀 `v` / 非数字 / 当前版本不可比 → 认不出来，拒。
            ("v0.1.9", "0.1.9", false, Some("version_uncomparable")),
            ("abc", "0.1.9", false, Some("version_uncomparable")),
            ("0.1.9", "dev", false, Some("version_uncomparable")),
            ("0.1.9", "", false, Some("version_uncomparable")),
            // 显式声明降级会连同「可比性」一起让开：这是刻意的取舍 ——
            // 版本来自摘要校验过的包，且没有方向可判时不该替运维对非语义化版本猜大小。
            ("abc", "0.1.9", true, None),
        ];
        for (target, current, allow_downgrade, expected) in cases {
            let mut request = request(dir.join(AGENTD_BIN_NAME));
            request.target_version = Some((*target).to_string());
            request.current_version = (*current).to_string();
            request.allow_downgrade = *allow_downgrade;
            let outcome = validate_request(&request);
            match expected {
                None => {
                    outcome.unwrap_or_else(|err| {
                        panic!("{target} vs {current} (allow={allow_downgrade}) should pass: {err}")
                    });
                }
                Some(code) => {
                    let err = outcome.expect_err(&format!(
                        "{target} vs {current} (allow={allow_downgrade}) should be refused"
                    ));
                    assert_eq!(err.reason, *code, "{target} vs {current}");
                }
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_refuses_a_malformed_digest() {
        let dir = temp_dir("validate-digest");
        let mut request = request(dir.join(AGENTD_BIN_NAME));
        request.package_sha256 = "sha256:nothex".to_string();
        let err = validate_request(&request).expect_err("must refuse");
        assert_eq!(err.reason, "digest_invalid");
        let _ = fs::remove_dir_all(dir);
    }

    /// 版本比较只看数字段：带 `-pre` / `+meta` 后缀也认；多段按数值比而不是按字符串比；
    /// 认不出来的宁可拒绝也不猜（返回 `None`）。
    #[test]
    fn version_is_newer_handles_suffixes_and_multi_segment_versions() {
        assert_eq!(version_is_newer("0.1.4-pre", "0.1.3"), Some(true));
        assert_eq!(version_is_newer("0.1.4+meta", "0.1.3"), Some(true));
        // 多段按数值比：0.10 比 0.9 新，不能拿字符串比成 0.10 < 0.9。
        assert_eq!(version_is_newer("0.10.0", "0.9.9"), Some(true));
        assert_eq!(version_is_newer("1.0.0", "0.9.9"), Some(true));
        // 前缀关系：0.1.0 看成 0.1 的补零补丁，比 0.1 新。
        assert_eq!(version_is_newer("0.1.0", "0.1"), Some(true));
        // 认不出来的版本：宁可拒绝也不猜大小。
        assert_eq!(version_is_newer("dev", "0.1.3"), None);
        assert_eq!(version_is_newer("0.1.3", "dev"), None);
        assert_eq!(version_is_newer("v0.1.4", "0.1.3"), None);
    }

    /// 版本比较的三档结果本身（`Some(true)` / `Some(false)` / `None`）在边界上的取值。
    ///
    /// 这条把「相等」显式钉成 `Some(false)`（不是 `None`）：`ensure_newer` 据此报 `not_newer`
    /// 而不是 `version_uncomparable` —— 同版本重装的错误码靠它定。
    #[test]
    fn version_is_newer_boundaries_return_the_right_three_ways() {
        // 相等 → Some(false)（不是「新」，也不是「比不出来」）。
        assert_eq!(version_is_newer("0.1.9", "0.1.9"), Some(false));
        assert_eq!(version_is_newer("1.2.3", "1.2.3"), Some(false));
        // 数值比较而不是字典序："0.1.10" > "0.1.9"。
        assert_eq!(version_is_newer("0.1.10", "0.1.9"), Some(true));
        assert_eq!(version_is_newer("0.1.9", "0.1.10"), Some(false));
        // 预发布后缀：只看前缀的数字段。
        assert_eq!(version_is_newer("0.2.0-beta.1", "0.1.9"), Some(true));
        assert_eq!(version_is_newer("0.2.0-beta.1", "0.2.0"), Some(false));
        // 四段：段数更多（同一前缀）视为更新。
        assert_eq!(version_is_newer("0.1.9.1", "0.1.9"), Some(true));
        assert_eq!(version_is_newer("1.2.3.4", "1.2.3.3"), Some(true));
        // 空前缀 `v`：不是点分数字 → 不可比（即使数值部分相同也拒）。
        assert_eq!(version_is_newer("v0.1.9", "0.1.9"), None);
        assert_eq!(version_is_newer("0.1.9", "v0.1.9"), None);
        // 空串 / 非数字 → 不可比。
        assert_eq!(version_is_newer("", "0.1.9"), None);
        assert_eq!(version_is_newer("0.1.9", ""), None);
        assert_eq!(version_is_newer("abc", "0.1.9"), None);
    }

    #[test]
    fn parse_spec_treats_the_target_version_as_optional() {
        // 包地址空 → 拒（它必须有）。
        let err =
            parse_spec(r#"{"target_version":"0.1.4","package_url":"","package_sha256":"abc"}"#)
                .expect_err("empty url must fail");
        assert_eq!(err.reason, "spec_invalid");

        // 目标版本空/缺 → **可以**：空串归一成 None，由包内自报的版本决定。
        for text in [
            r#"{"target_version":"","package_url":"https://gw/x","package_sha256":"abc"}"#,
            r#"{"package_url":"https://gw/x","package_sha256":"abc"}"#,
        ] {
            let spec = parse_spec(text).expect("target_version is optional");
            assert_eq!(spec.target_version, None);
            assert_eq!(spec.package_url, "https://gw/x");
        }

        // 包地址/摘要键缺失仍是形状不对（宁可不升，也不拿默认值猜参数）。
        let err = parse_spec(r#"{"target_version":"0.1.4"}"#).expect_err("missing fields");
        assert_eq!(err.reason, "spec_invalid");
    }

    #[test]
    fn resolve_target_version_derives_from_the_package_or_checks_the_explicit_one() {
        let dir = temp_dir("resolve-target");

        // 没显式给 → 以包内自报为准。
        let mut req = request(dir.join(AGENTD_BIN_NAME));
        req.target_version = None;
        assert_eq!(
            resolve_target_version(&req, "0.1.4").expect("derive"),
            "0.1.4"
        );

        // 显式给了且一致 → 用它。
        req.target_version = Some("0.1.4".to_string());
        assert_eq!(
            resolve_target_version(&req, "0.1.4").expect("explicit matches"),
            "0.1.4"
        );

        // 显式给了但对不上 → version_mismatch。
        let err = resolve_target_version(&req, "0.1.5").expect_err("mismatch must fail");
        assert_eq!(err.reason, "version_mismatch");

        // 推导出来的版本也得比当前运行的新。
        req.target_version = None;
        let err = resolve_target_version(&req, "0.1.3").expect_err("not newer");
        assert_eq!(err.reason, "not_newer");

        let _ = fs::remove_dir_all(dir);
    }

    /// `resolve_target_version` 这条路上的边界：相等 → `not_newer`；包内自报不可比 →
    /// `version_uncomparable`；显式声明降级后相等也放行。
    #[test]
    fn resolve_target_version_handles_equal_and_uncomparable_versions() {
        let dir = temp_dir("resolve-boundaries");
        let mut req = request(dir.join(AGENTD_BIN_NAME));
        req.current_version = "0.1.4".to_string();

        // 同版本（目标 == 当前）默认拒 —— 错码是 `not_newer`，不是 `version_uncomparable`。
        req.target_version = Some("0.1.4".to_string());
        let err = resolve_target_version(&req, "0.1.4").expect_err("same version refused");
        assert_eq!(err.reason, "not_newer");

        // 没显式给时以包内自报为准；自报的版本不可比（空串）→ `version_uncomparable`。
        req.target_version = None;
        let err = resolve_target_version(&req, "").expect_err("uncomparable refused");
        assert_eq!(err.reason, "version_uncomparable");

        // 显式声明降级后，同版本放行。
        req.target_version = Some("0.1.4".to_string());
        req.allow_downgrade = true;
        assert_eq!(
            resolve_target_version(&req, "0.1.4").expect("declared reinstall"),
            "0.1.4"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn validate_request_rejects_an_empty_work_id() {
        let dir = temp_dir("validate-work-id");
        let mut request = request(dir.join(AGENTD_BIN_NAME));
        request.work_id = "   ".to_string();
        let err = validate_request(&request).expect_err("empty work_id must fail");
        assert_eq!(err.reason, "spec_invalid");
        let _ = fs::remove_dir_all(dir);
    }

    /// 空 / 空白的 `package_url` 在 `validate_request` 就被拒 —— 与 `parse_spec` 同口径。
    /// 少了这道，空地址会一路走到 `fetch_package` 才以一条费解的 HTTP 错误暴露
    /// （而 `build_launch` 那条路径不经过 `parse_spec`）。
    #[test]
    fn validate_request_rejects_an_empty_package_url() {
        let dir = temp_dir("validate-package-url");
        let mut request = request(dir.join(AGENTD_BIN_NAME));
        request.package_url = "   ".to_string();
        let err = validate_request(&request).expect_err("empty package_url must fail");
        assert_eq!(err.reason, "spec_invalid", "{err:?}");
        assert!(err.detail.contains("package_url"), "{}", err.detail);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn build_launch_passes_every_fact_explicitly() {
        let request = UpgradeRequest {
            work_id: "work-upgrade-1".to_string(),
            target_version: Some("0.1.4".to_string()),
            current_version: "0.1.3".to_string(),
            agentd_bin: PathBuf::from("/usr/local/bin/wist-agentd"),
            package_url: "https://gw/api/v1/agent/packages/current".to_string(),
            package_sha256: "sha256:abc".to_string(),
            allow_downgrade: false,
        };
        let launch = build_launch(
            Path::new("/usr/local/bin/wist-upgrader"),
            Path::new("/etc/wist-agentd"),
            &request,
        );
        assert_eq!(
            launch.program,
            PathBuf::from("/usr/local/bin/wist-upgrader")
        );
        let args = launch.args;
        // 三个事实都不能靠默认值去猜：换哪个件、换到哪一版、从哪取包。
        assert!(args.iter().any(|arg| arg == "--bin"));
        assert!(args.iter().any(|arg| arg == "/usr/local/bin/wist-agentd"));
        assert!(args.iter().any(|arg| arg == "0.1.4"));
        assert!(args.iter().any(|arg| arg == "0.1.3"));
        assert!(
            args.iter()
                .any(|arg| arg == "https://gw/api/v1/agent/packages/current")
        );
        assert!(args.iter().any(|arg| arg == "sha256:abc"));
        // 派下来的活就是要求执行：预演是人在终端里做的事。
        assert_eq!(args.last().map(String::as_str), Some("--apply"));
    }

    /// `allow_downgrade` 的传递：只前进时 argv 里**不该**出现该标志（负例），
    /// 显式声明降级时**必须**带上（否则升级器会按「只前进」把降级拒掉）。
    #[test]
    fn build_launch_carries_allow_downgrade_only_when_declared() {
        let dir = temp_dir("launch-downgrade");
        let mut request = request(dir.join(AGENTD_BIN_NAME));

        // 缺省 = 只前进：负例 —— 标志不该被“顺手”带上。
        assert!(!request.allow_downgrade);
        let launch = build_launch(
            Path::new("/usr/local/bin/wist-upgrader"),
            Path::new("/etc/wist-agentd"),
            &request,
        );
        assert!(
            !launch.args.iter().any(|arg| arg == "--allow-downgrade"),
            "only-forward launch must not carry the flag: {:?}",
            launch.args
        );

        // 显式声明降级：标志必须出现。
        request.allow_downgrade = true;
        let launch = build_launch(
            Path::new("/usr/local/bin/wist-upgrader"),
            Path::new("/etc/wist-agentd"),
            &request,
        );
        assert!(
            launch.args.iter().any(|arg| arg == "--allow-downgrade"),
            "declared downgrade must reach the upgrader: {:?}",
            launch.args
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn resolve_upgrader_bin_finds_the_sibling_and_reports_misses() {
        let dir = temp_dir("resolve-bin");
        let agentd = dir.join(AGENTD_BIN_NAME);
        let missing = resolve_upgrader_bin_from(&agentd, None).expect_err("no sibling yet");
        assert!(missing.contains(UPGRADER_BIN_NAME), "{missing}");

        let sibling = dir.join(UPGRADER_BIN_NAME);
        fs::write(&sibling, "#!/bin/sh\n").expect("write sibling");
        assert_eq!(
            resolve_upgrader_bin_from(&agentd, None).expect("sibling found"),
            sibling
        );

        let override_path = dir.join("elsewhere");
        fs::write(&override_path, "#!/bin/sh\n").expect("write override");
        assert_eq!(
            resolve_upgrader_bin_from(&agentd, Some(&override_path)).expect("override wins"),
            override_path
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn launch_detached_starts_a_process_outside_this_one() {
        let dir = temp_dir("launch-detached");
        let marker = dir.join("marker");
        let script = dir.join("fake-upgrader");
        fs::write(
            &script,
            format!("#!/bin/sh\necho started > {}\n", marker.display()),
        )
        .expect("write script");
        set_executable(&script).expect("chmod");

        let launch = UpgradeLaunch {
            program: script,
            args: Vec::new(),
        };
        let pid = launch_detached(&launch, &dir.join("log").join("out.log")).expect("launch");
        assert!(pid > 0);

        // 子进程是**分离**的：这里不能 wait 到它，但它的副作用应当很快出现。
        for _ in 0..50 {
            if marker.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(marker.is_file(), "detached child should have run");
        assert!(dir.join("log").join("out.log").is_file(), "log file");
        let _ = fs::remove_dir_all(dir);
    }

    /// systemd 上必须把升级器包成**独立瞬态 unit**：否则 `systemctl restart wist-agentd`
    /// （`KillMode=control-group`，按 cgroup 回收）会把它和旧 agentd 一起收走 ——
    /// 记录停在 `restart`、心跳断 60s，于是每次成功升级都被判死。
    #[test]
    fn systemd_run_launch_wraps_the_upgrader_in_its_own_unit() {
        let inner = UpgradeLaunch {
            program: PathBuf::from("/usr/local/bin/wist-upgrader"),
            args: vec![
                "apply".to_string(),
                "--work-id".to_string(),
                "work-1".to_string(),
            ],
        };
        let log = Path::new("/var/log/wist-agentd/wist-upgrader.log");
        let env_file = Path::new("/etc/wist-agentd/agentd.env");

        let system = build_systemd_run_launch(&inner, true, "wist-upgrader-work-1", log, env_file);
        assert_eq!(system.program, PathBuf::from("systemd-run"));
        assert!(
            !system.args.iter().any(|arg| arg == "--user"),
            "system 作用域不带 --user：{:?}",
            system.args
        );
        assert!(
            system
                .args
                .iter()
                .any(|arg| arg == "--unit=wist-upgrader-work-1")
        );
        // `--collect`：退出即清，免得同名 unit 残留挡住下一次同 work_id 的升级。
        assert!(system.args.iter().any(|arg| arg == "--collect"));
        // `exec`：起 unit 成功要到 execve 成功为止，否则起不来的升级器会被误当成已派发。
        assert!(system.args.iter().any(|arg| arg == "--service-type=exec"));
        assert!(
            system
                .args
                .iter()
                .any(|arg| arg == "--property=EnvironmentFile=-/etc/wist-agentd/agentd.env"),
            "瞬态 unit 不继承 agentd 进程环境，要显式指出 EnvironmentFile：{:?}",
            system.args
        );
        assert!(system.args.iter().any(|arg| {
            arg == "--property=StandardOutput=append:/var/log/wist-agentd/wist-upgrader.log"
        }));
        assert!(
            system
                .args
                .iter()
                .any(|arg| arg == "--property=SyslogIdentifier=wist-upgrader-work-1")
        );
        // `--` 把 systemd-run 的选项与命令分开：它只能出现一次，且之前全是以 `-` 开头的选项。
        assert_eq!(system.args.iter().filter(|arg| *arg == "--").count(), 1);
        let sep = system
            .args
            .iter()
            .position(|arg| arg == "--")
            .expect("separator before the command");
        assert!(
            system.args[..sep].iter().all(|arg| arg.starts_with('-')),
            "选项必须在 `--` 之前：{:?}",
            system.args
        );
        assert_eq!(system.args[sep + 1], "/usr/local/bin/wist-upgrader");
        assert_eq!(&system.args[sep + 2..], &inner.args[..]);

        // user 作用域要带 `--user`（走用户的 systemd 实例）。
        let user = build_systemd_run_launch(&inner, false, "wist-upgrader-work-1", log, env_file);
        assert!(user.args.iter().any(|arg| arg == "--user"));
    }

    /// 命令（会被当成 `ExecStart`）里带 `$` / `%` 必须转义：systemd-run 会把它们当变量 / specifier
    /// 展开。`%` 不是可选项 —— URL 里的百分号编码（`%2F`）不加转义就会被吞掉。
    #[test]
    fn systemd_run_launch_escapes_dollar_and_percent_in_the_command() {
        let inner = UpgradeLaunch {
            program: PathBuf::from("/usr/local/bin/wist-upgrader"),
            args: vec![
                "https://gw/pkg%2Fa?token=$FILE".to_string(),
                "plain".to_string(),
            ],
        };
        let wrapped = build_systemd_run_launch(
            &inner,
            true,
            "wist-upgrader-w",
            Path::new("/var/log/x.log"),
            Path::new("/etc/wist-agentd/agentd.env"),
        );
        let sep = wrapped.args.iter().position(|a| a == "--").expect("--");
        // `$`→`$$`、`%`→`%%`；不含这两个字符的参数原样不动。
        assert_eq!(&wrapped.args[sep + 2], "https://gw/pkg%%2Fa?token=$$FILE");
        assert_eq!(&wrapped.args[sep + 3], "plain");
    }

    /// 属性里的路径只转 `%`（不转 `$`）：属性值不做 `$` 展开，多转会把一个 `$` 写成两个。
    #[test]
    fn systemd_run_launch_escapes_percent_in_property_paths() {
        let inner = UpgradeLaunch {
            program: PathBuf::from("/usr/local/bin/wist-upgrader"),
            args: Vec::new(),
        };
        let wrapped = build_systemd_run_launch(
            &inner,
            true,
            "wist-upgrader-w",
            Path::new("/var/log/%d/up.log"),
            Path::new("/etc/%n/agentd.env"),
        );
        assert!(
            wrapped
                .args
                .iter()
                .any(|arg| { arg == "--property=StandardOutput=append:/var/log/%%d/up.log" })
        );
        assert!(
            wrapped
                .args
                .iter()
                .any(|arg| arg == "--property=EnvironmentFile=-/etc/%%n/agentd.env")
        );
    }

    #[test]
    fn upgrader_unit_name_sanitizes_the_work_id() {
        assert_eq!(upgrader_unit_name("work-1"), "wist-upgrader-work-1");
        // unit 名只允许 [A-Za-z0-9:_.-]，其余一律替换，避免 systemd 拒收。
        assert_eq!(upgrader_unit_name("a/b c@d"), "wist-upgrader-a_b_c_d");
        // 空 work_id 也得是个合法 unit 名（前面有固定前缀）。
        assert_eq!(upgrader_unit_name(""), "wist-upgrader-");
        // 非 ASCII 一律替换（systemd unit 名只接受 ASCII 白名单）。
        assert_eq!(upgrader_unit_name("工单-1"), "wist-upgrader-__-1");
        // 白名单内的字符原样保留。
        assert_eq!(upgrader_unit_name("a:b_c.d-e"), "wist-upgrader-a:b_c.d-e");
    }

    /// 非 Linux（以及无 `systemd-run` 的 Linux）走原来的分离进程：句柄是 pid，且脚本真跑起来了。
    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn spawn_upgrader_falls_back_to_a_detached_process() {
        let dir = temp_dir("spawn-fallback");
        let marker = dir.join("marker");
        let script = dir.join("fake-upgrader");
        fs::write(
            &script,
            format!("#!/bin/sh\necho started > {}\n", marker.display()),
        )
        .expect("write script");
        set_executable(&script).expect("chmod");

        let launch = UpgradeLaunch {
            program: script,
            args: Vec::new(),
        };
        let log_path = dir.join("log").join("out.log");
        let handle = spawn_upgrader(
            &launch,
            &log_path,
            "work-fallback",
            true,
            Path::new("/etc/wist-agentd/agentd.env"),
        )
        .expect("spawn");
        // 分离进程路径返回 pid（纯数字），而不是瞬态 unit 名。
        assert!(
            handle.parse::<u32>().is_ok(),
            "expected a pid, got {handle}"
        );

        for _ in 0..50 {
            if marker.is_file() {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
        assert!(marker.is_file(), "detached child should have run");
        assert!(log_path.is_file(), "log file");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn default_restart_plan_targets_the_agentd_service() {
        match default_restart_plan(true) {
            RestartPlan::Command { program, args } => {
                #[cfg(target_os = "macos")]
                {
                    assert_eq!(program, "launchctl");
                    assert!(args.iter().any(|arg| arg == "kickstart"));
                    assert!(args.iter().any(|arg| arg == "-k"));
                    assert!(
                        args.iter().any(|arg| arg.starts_with("system/")),
                        "{args:?}"
                    );
                }
                #[cfg(not(target_os = "macos"))]
                {
                    assert_eq!(program, "systemctl");
                    assert_eq!(
                        args.last().map(String::as_str),
                        Some(crate::service::SERVICE_NAME)
                    );
                }
            }
            RestartPlan::None => panic!("default plan must be a command"),
        }
    }

    #[test]
    fn parse_version_output_takes_the_last_version_like_token() {
        assert_eq!(
            parse_version_output("wist-agentd 0.1.3\n").as_deref(),
            Some("0.1.3")
        );
        assert_eq!(parse_version_output("0.1.3").as_deref(), Some("0.1.3"));
        assert_eq!(parse_version_output("no version here"), None);
    }

    /// 挑版本词必须认「多段点分数字」，不能被版本后面跟的时间戳骗到：
    /// `…T16:05:49.090849Z` 也含点、也能被 `version_parts` 读成 `[2026]` —— 选错会让「目标版本」
    /// 变成 2026、`ensure_newer` 恒成立（包里的东西是什么就不重要了）。
    #[test]
    fn parse_version_output_ignores_a_trailing_dotted_timestamp() {
        assert_eq!(
            parse_version_output("wist-agentd 0.1.11 built 2026-09-27T16:05:49.090849Z").as_deref(),
            Some("0.1.11")
        );
        // 只有单段数字的词（时间戳 / 日期）时**不猜**：当作没报版本，让升级器拒掉。
        assert_eq!(
            parse_version_output("built 2026-09-27T16:05:49.090849Z"),
            None
        );
    }

    #[test]
    fn verify_digest_accepts_with_and_without_prefix() {
        let bytes = b"package-bytes";
        let hex = sha256_hex_bytes(bytes);
        verify_digest(bytes, &hex).expect("bare hex");
        verify_digest(bytes, &format!("sha256:{hex}")).expect("prefixed hex");
        let err = verify_digest(bytes, &"1".repeat(64)).expect_err("mismatch");
        assert_eq!(err.reason, "digest_mismatch");
    }

    #[test]
    fn stage_package_treats_a_bare_binary_as_agentd() {
        let dir = temp_dir("stage-bare");
        let staging = dir.join("upgrade");
        let staged = stage_package(b"#!/bin/sh\necho hi\n", &staging).expect("stage");
        assert_eq!(staged.len(), 1);
        assert_eq!(staged[0].name, AGENTD_BIN_NAME);
        assert!(staged[0].path.is_file());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stage_package_unpacks_a_tarball_and_ignores_unknown_files() {
        let dir = temp_dir("stage-tar");
        let payload = dir.join("payload").join("wist-agentd-0.1.4");
        fs::create_dir_all(&payload).expect("payload dir");
        fake_agentd(&payload, "0.1.4");
        fs::write(payload.join(EXEC_BIN_NAME), "exec").expect("exec");
        fs::write(payload.join("README.md"), "docs").expect("readme");
        let archive = dir.join("package.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(dir.join("payload"))
            .arg("wist-agentd-0.1.4")
            .status()
            .expect("tar");
        assert!(status.success());

        let bytes = fs::read(&archive).expect("read archive");
        let staged = stage_package(&bytes, &dir.join("upgrade")).expect("stage");
        let names: Vec<&str> = staged.iter().map(|item| item.name.as_str()).collect();
        assert_eq!(names, vec![AGENTD_BIN_NAME, EXEC_BIN_NAME]);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stage_package_rejects_an_artifact_without_agentd() {
        let dir = temp_dir("stage-missing");
        let payload = dir.join("payload");
        fs::create_dir_all(&payload).expect("payload dir");
        fs::write(payload.join(EXEC_BIN_NAME), "exec").expect("exec");
        let archive = dir.join("package.tar.gz");
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(&payload)
            .arg(EXEC_BIN_NAME)
            .status()
            .expect("tar");
        assert!(status.success());

        let bytes = fs::read(&archive).expect("read archive");
        let err = stage_package(&bytes, &dir.join("upgrade")).expect_err("must refuse");
        assert_eq!(err.reason, "artifact_invalid");
        let _ = fs::remove_dir_all(dir);
    }

    /// 制品里的 `wist-agentd` 如果是**符号链接**必须拒：`install` 会跟随它，把链接指向的东西
    /// （可能在制品之外）当成本件装进去。
    #[test]
    fn find_binaries_rejects_a_symlinked_agentd() {
        let dir = temp_dir("find-symlink");
        let outside = dir.join("outside-binary");
        fs::write(&outside, "#!/bin/sh\necho pwned\n").expect("write target");
        std::os::unix::fs::symlink(&outside, dir.join(AGENTD_BIN_NAME)).expect("symlink");

        let err = find_binaries(&dir).expect_err("symlink must be refused");
        assert_eq!(err.reason, "artifact_invalid", "{err:?}");
        let _ = fs::remove_dir_all(dir);
    }

    /// 制品里出现**两份**同名已知件是有歧义的（哪一份才是要装的？），正规产出不会这样 —— 拒，
    /// 而不是「先遍历到谁就装谁」。
    #[test]
    fn find_binaries_rejects_a_duplicate_known_binary() {
        let dir = temp_dir("find-duplicate");
        let nested = dir.join("nested");
        fs::create_dir_all(&nested).expect("nested");
        fs::write(dir.join(AGENTD_BIN_NAME), "#!/bin/sh\necho a\n").expect("write a");
        fs::write(nested.join(AGENTD_BIN_NAME), "#!/bin/sh\necho b\n").expect("write b");

        let err = find_binaries(&dir).expect_err("duplicate must be refused");
        assert_eq!(err.reason, "artifact_invalid", "{err:?}");
        assert!(err.detail.contains("more than one"), "{}", err.detail);
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn stage_package_rebuilds_the_staging_dir_every_time() {
        let dir = temp_dir("stage-rebuild");
        let staging = dir.join("upgrade");
        fs::create_dir_all(&staging).expect("staging");
        fs::write(staging.join("leftover"), "half-written").expect("leftover");
        stage_package(b"bare", &staging).expect("stage");
        assert!(!staging.join("leftover").exists());
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn verify_staged_agentd_reports_the_version_the_package_claims() {
        let dir = temp_dir("verify-version");
        let staging = dir.join("staging");
        fs::create_dir_all(&staging).expect("staging");
        let bin = fake_agentd(&staging, "0.1.4");
        let staged = vec![StagedBinary {
            name: AGENTD_BIN_NAME.to_string(),
            path: bin,
        }];

        // 现在它只负责「问一句你自称哪一版」；与目标对不对由 `resolve_target_version` 判。
        assert_eq!(verify_staged_agentd(&staged).expect("reports"), "0.1.4");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn install_binaries_backs_up_and_replaces() {
        let dir = temp_dir("install");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let installed = fake_agentd(&bin_dir, "0.1.3");
        let staged = dir.join("staged");
        fs::create_dir_all(&staged).expect("staged");
        let new_bin = fake_agentd(&staged, "0.1.4");
        let items = vec![StagedBinary {
            name: AGENTD_BIN_NAME.to_string(),
            path: new_bin,
        }];

        let backups = install_binaries(&items, &bin_dir, "0.1.3", false).expect("install");
        assert_eq!(backups.len(), 1);
        assert!(backups[0].backup.is_file(), "old binary must be kept");
        let installed_text = fs::read_to_string(&installed).expect("read installed");
        assert!(installed_text.contains("0.1.4"), "{installed_text}");

        restore_backups(&backups, &bin_dir).expect("rollback");
        let restored = fs::read_to_string(&installed).expect("read restored");
        assert!(restored.contains("0.1.3"), "{restored}");
        assert!(backups[0].backup.is_file(), "backup survives rollback");
        let _ = fs::remove_dir_all(dir);
    }

    /// 换之前**本来不存在**的位置：回滚要把它删掉（回到原样），
    /// 而不是去找一份不存在的备份、把整轮回滚卡在那儿。
    #[test]
    fn restoring_a_binary_that_did_not_exist_before_removes_it() {
        let dir = temp_dir("restore-missing");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let staged = dir.join("staged");
        fs::create_dir_all(&staged).expect("staged");
        let new_bin = staged.join(EXEC_BIN_NAME);
        fs::write(&new_bin, "#!/bin/sh\nexit 0\n").expect("write staged exec");
        // 只带来执行器，而机器上本来没有它（裸包装升到三件套制品）。
        let items = vec![StagedBinary {
            name: EXEC_BIN_NAME.to_string(),
            path: new_bin,
        }];

        let backups = install_binaries(&items, &bin_dir, "0.1.3", false).expect("install");
        assert!(bin_dir.join(EXEC_BIN_NAME).is_file(), "新件该被装上");
        assert!(!backups[0].backup.exists(), "本来没有的件不该有备份");
        assert!(!backups[0].existed);

        restore_backups(&backups, &bin_dir).expect("rollback");
        assert!(
            !bin_dir.join(EXEC_BIN_NAME).exists(),
            "回滚后该回到「本来没有」"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// `existed` 但备份文件不在（备份那一步没成功 / 被占位）：回滚必须报 `rollback_failed`，
    /// 而不是假装放回了旧件 —— 否则机器停在一个没人核对过的状态，却对外声称「已回到原样」。
    #[test]
    fn restore_backups_reports_a_missing_backup() {
        let dir = temp_dir("restore-missing-backup");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        fs::write(bin_dir.join(AGENTD_BIN_NAME), "new").expect("write installed");
        let backup = Backup {
            installed: bin_dir.join(AGENTD_BIN_NAME),
            backup: bin_dir.join(format!("{AGENTD_BIN_NAME}.bak-0.1.3")),
            existed: true,
        };
        let err = restore_backups(&[backup], &bin_dir).expect_err("must refuse");
        assert_eq!(err.reason, "rollback_failed");
        let _ = fs::remove_dir_all(dir);
    }

    /// 换到一半失败：**已经换掉的那几个**必须放回去。否则盘上会留一个
    /// 「agentd 是新版、exec 还是旧版」的半套制品 —— 两个件版本不一致正是「一起换」要防的事，
    /// 而这一刻还没人知道。
    #[test]
    fn a_failure_halfway_through_install_rolls_back_what_was_already_replaced() {
        let dir = temp_dir("install-partial");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let installed_agentd = fake_agentd(&bin_dir, "0.1.3");
        let staged = dir.join("staged");
        fs::create_dir_all(&staged).expect("staged");
        let new_agentd = fake_agentd(&staged, "0.1.4");
        let items = vec![
            StagedBinary {
                name: AGENTD_BIN_NAME.to_string(),
                path: new_agentd,
            },
            // 第二个件的实体不在（制品不完整 / 文件半途丢了）：`install` 这一步会失败。
            StagedBinary {
                name: EXEC_BIN_NAME.to_string(),
                path: staged.join("not-here"),
            },
        ];

        let err = install_binaries(&items, &bin_dir, "0.1.3", false).expect_err("必须失败");
        assert_eq!(err.reason, "command_failed", "{err:?}");
        assert!(err.detail.contains("rolled back"), "{}", err.detail);

        // 第一个件已经换过，必须回滚；第二个件从没被换上。
        let restored = fs::read_to_string(&installed_agentd).expect("read agentd");
        assert!(restored.contains("0.1.3"), "{restored}");
        assert!(!bin_dir.join(EXEC_BIN_NAME).exists());
        let _ = fs::remove_dir_all(dir);
    }

    /// 「升级不许把机器变成混合版本」：只有「换完三件齐全」与「换完只有 agentd」两种放行。
    #[test]
    fn an_upgrade_must_not_leave_a_mixed_set_of_binaries() {
        let dir = temp_dir("mixed-bins");
        let bin_dir = dir.join("bin");
        let staged_dir = dir.join("staged");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        fs::create_dir_all(&staged_dir).expect("staged dir");

        let staged = |names: &[&str]| -> Vec<StagedBinary> {
            names
                .iter()
                .map(|name| StagedBinary {
                    name: (*name).to_string(),
                    path: staged_dir.join(name),
                })
                .collect()
        };

        let full: &[&str] = &[AGENTD_BIN_NAME, EXEC_BIN_NAME, UPGRADER_BIN_NAME];
        let bare: &[&str] = &[AGENTD_BIN_NAME];
        let no_upgrader: &[&str] = &[AGENTD_BIN_NAME, EXEC_BIN_NAME];

        // (盘上原本有谁, 制品带了谁, 该不该放行)
        let cases: [(&[&str], &[&str], bool); 6] = [
            (bare, full, true),         // 裸机升三件套：补全，放行
            (full, full, true),         // 三件套升三件套
            (bare, bare, true),         // 裸机升裸包（网关内置的形态）
            (full, bare, false),        // 裸包盖三件套：会留下 agentd 新版 + 另两件旧版
            (full, no_upgrader, false), // 漏件的制品
            (bare, no_upgrader, false), // 会有 exec 而没有 upgrader：将来没人能换 agentd
        ];
        for (installed, artifact, allowed) in cases {
            let _ = fs::remove_dir_all(&bin_dir);
            fs::create_dir_all(&bin_dir).expect("bin dir");
            for name in installed {
                fs::write(bin_dir.join(name), b"old").expect("write installed");
            }
            let outcome = check_upgrade_keeps_bin_directory_consistent(&staged(artifact), &bin_dir);
            assert_eq!(
                outcome.is_ok(),
                allowed,
                "installed={installed:?} artifact={artifact:?}: {outcome:?}"
            );
            if let Err(err) = outcome {
                assert_eq!(err.reason, "artifact_invalid");
            }
        }
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn install_binaries_dry_run_touches_nothing() {
        let dir = temp_dir("install-dry");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let installed = fake_agentd(&bin_dir, "0.1.3");
        let staged = dir.join("staged");
        fs::create_dir_all(&staged).expect("staged");
        let new_bin = fake_agentd(&staged, "0.1.4");
        let items = vec![StagedBinary {
            name: AGENTD_BIN_NAME.to_string(),
            path: new_bin,
        }];

        let backups = install_binaries(&items, &bin_dir, "0.1.3", true).expect("dry run");
        assert_eq!(backups.len(), 1);
        assert!(!backups[0].backup.exists());
        let installed_text = fs::read_to_string(&installed).expect("read installed");
        assert!(installed_text.contains("0.1.3"), "{installed_text}");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn parse_spec_reads_the_optional_allow_downgrade() {
        // `allow_downgrade` 可省、可显式给：给 `true` 就认，缺字段默认 `false`（只前进）。
        let spec = parse_spec(
            r#"{"package_url":"https://gw/x","package_sha256":"abc","allow_downgrade":true}"#,
        )
        .expect("parse");
        assert!(spec.allow_downgrade);

        let spec =
            parse_spec(r#"{"package_url":"https://gw/x","package_sha256":"abc"}"#).expect("parse");
        assert!(!spec.allow_downgrade, "缺字段时默认就必须是「只前进」");
    }

    #[test]
    fn declared_downgrade_is_allowed() {
        let dir = temp_dir("allow-downgrade");
        let mut req = request(dir.join(AGENTD_BIN_NAME));
        req.current_version = "0.1.5".to_string();
        req.target_version = Some("0.1.3".to_string());
        req.allow_downgrade = true;

        // 显式声明降级：校验放行，目标版本仍以（这里的显式值 = 包内自报）为准。
        validate_request(&req).expect("declared downgrade passes validate");
        assert_eq!(
            resolve_target_version(&req, "0.1.3").expect("declared downgrade resolves"),
            "0.1.3"
        );

        // 同版本（重装）也放行。
        req.current_version = "0.1.3".to_string();
        validate_request(&req).expect("declared reinstall passes validate");
        assert_eq!(
            resolve_target_version(&req, "0.1.3").expect("declared reinstall resolves"),
            "0.1.3"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn downgrade_is_refused_unless_declared() {
        let dir = temp_dir("refuse-downgrade");
        let mut req = request(dir.join(AGENTD_BIN_NAME));
        req.current_version = "0.1.5".to_string();
        req.target_version = Some("0.1.3".to_string());
        // 缺省（或显式 `false`）= 只前进：降级与重装照样拒。
        assert!(!req.allow_downgrade, "默认必须是「只前进」");

        let err = validate_request(&req).expect_err("default must refuse downgrade");
        assert_eq!(err.reason, "not_newer", "{err}");
        let err = resolve_target_version(&req, "0.1.3").expect_err("default must refuse downgrade");
        assert_eq!(err.reason, "not_newer", "{err}");

        // 显式 `false` 与缺省等价。
        req.allow_downgrade = false;
        let err = validate_request(&req).expect_err("explicit false must refuse");
        assert_eq!(err.reason, "not_newer", "{err}");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn fetch_package_sends_no_authorization_header() {
        let dir = temp_dir("fetch-cert");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let source = format!("http://{}/package", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8_lossy(&request_bytes);
            // 凭据走客户端证书（mTLS）：取包请求不再带 Authorization 头。
            assert!(
                !request.to_lowercase().contains("authorization:"),
                "{request}"
            );
            socket
                .write_all(b"HTTP/1.1 200 OK\r\ncontent-length: 3\r\nconnection: close\r\n\r\nPKG")
                .await
                .expect("write response");
        });

        let config = config_with_state(&dir);
        let bytes = fetch_package(&config, &source).await.expect("fetch");
        server.await.expect("server task");

        assert_eq!(bytes, b"PKG");
        let _ = fs::remove_dir_all(dir);
    }

    /// 取包有大小上限：对端报一个超过上限的 `content-length` 时**先拦**，不去读那个体。
    /// 没有这道，`response.bytes()` 无界 —— 坏掉 / 被投毒的网关能把 agentd 内存吃光。
    #[tokio::test]
    async fn fetch_package_rejects_an_oversized_content_length() {
        let dir = temp_dir("fetch-too-large");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let source = format!("http://{}/package", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut request_bytes = Vec::new();
            loop {
                let mut chunk = [0u8; 1024];
                let read = socket.read(&mut chunk).await.expect("read");
                if read == 0 {
                    break;
                }
                request_bytes.extend_from_slice(&chunk[..read]);
                if request_bytes.windows(4).any(|window| window == b"\r\n\r\n") {
                    break;
                }
            }
            // 只发头、不发体：要钉的正是「在读到 body 之前就按 content-length 拒掉」。
            socket
                .write_all(
                    b"HTTP/1.1 200 OK\r\ncontent-length: 900000000000\r\nconnection: close\r\n\r\n",
                )
                .await
                .expect("write response");
            // 留一会儿再关，免得 RST 抢在客户端读到头之前。
            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
        });

        let config = config_with_state(&dir);
        let err = fetch_package(&config, &source)
            .await
            .expect_err("must refuse");
        assert_eq!(err.reason, "package_too_large", "{err:?}");
        server.await.expect("server task");
        let _ = fs::remove_dir_all(dir);
    }

    /// 本地路径分支不发 HTTP：直接读文件，与任何凭据无关。
    #[tokio::test]
    async fn fetch_package_reads_a_local_path() {
        let dir = temp_dir("fetch-local");
        let package = dir.join("package.tar.gz");
        fs::write(&package, b"LOCAL").expect("write package");
        let config = config_with_state(&dir);
        let bytes = fetch_package(&config, &package.display().to_string())
            .await
            .expect("local read");
        assert_eq!(bytes, b"LOCAL");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn apply_reports_an_unreachable_package_without_touching_anything() {
        let dir = temp_dir("apply-fetch");
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).expect("state dir");
        let config = config_with_state(&state_dir);
        let request = request(dir.join(AGENTD_BIN_NAME));

        let record = apply(&config, &request, &UpgradeOptions::default()).await;
        assert_eq!(record.status, "failed");
        assert_eq!(record.step, "fetch");
        assert!(record.detail.contains("package_unavailable"), "{record:?}");
        // 记录必须落盘：agentd 重启后要靠它回报，也不能让「记不上账」变成静默失败。
        let stored: UpgradeRecord =
            read_json(&state_dir.join(UPGRADE_RECORD_FILE)).expect("record stored");
        assert_eq!(stored.status, "failed");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn apply_dry_run_stops_before_install_and_succeeds() {
        let dir = temp_dir("apply-dry");
        let state_dir = dir.join("state");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let installed = fake_agentd(&bin_dir, "0.1.3");
        // 制品：一个自称 0.1.4 的 agentd，放在本地路径上（离线演练）。
        let artifact = dir.join("artifact");
        fs::create_dir_all(&artifact).expect("artifact dir");
        let packaged = artifact.join(AGENTD_BIN_NAME);
        fs::write(&packaged, "#!/bin/sh\necho \"wist-agentd 0.1.4\"\n").expect("write artifact");
        let bytes = fs::read(&packaged).expect("read artifact");

        let config = config_with_state(&state_dir);
        let mut request = request(installed.clone());
        request.package_url = packaged.display().to_string();
        request.package_sha256 = sha256_hex_bytes(&bytes);

        let record = apply(&config, &request, &UpgradeOptions::default()).await;
        assert_eq!(record.status, "succeeded", "{record:?}");
        assert_eq!(record.step, "install");
        let installed_text = fs::read_to_string(&installed).expect("read installed");
        assert!(installed_text.contains("0.1.3"), "dry run must not replace");
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn apply_derives_the_target_version_from_the_package_when_not_given() {
        let dir = temp_dir("apply-derived");
        let state_dir = dir.join("state");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        let installed = fake_agentd(&bin_dir, "0.1.3");
        let artifact = dir.join("artifact");
        fs::create_dir_all(&artifact).expect("artifact dir");
        let packaged = artifact.join(AGENTD_BIN_NAME);
        fs::write(&packaged, "#!/bin/sh\necho \"wist-agentd 0.1.4\"\n").expect("write artifact");
        let bytes = fs::read(&packaged).expect("read artifact");

        let config = config_with_state(&state_dir);
        let mut request = request(installed);
        request.target_version = None; // 没给 → 以包内 agentd 自报的版本为准
        request.package_url = packaged.display().to_string();
        request.package_sha256 = sha256_hex_bytes(&bytes);

        let record = apply(&config, &request, &UpgradeOptions::default()).await;
        assert_eq!(record.status, "succeeded", "{record:?}");
        assert_eq!(record.to_version, "0.1.4", "目标版本应从包里推出来");
        let _ = fs::remove_dir_all(dir);
    }

    /// 降级全流程（演练到换件前）：声明降级则落地，记录里 `from` 高 `to` 低，状态仍是成功 ——
    /// 不因为「版本变小」被判失败。没声明则在验制品这步被 `not_newer` 拦下。
    #[tokio::test]
    async fn apply_records_a_declared_downgrade_as_succeeded_high_to_low() {
        let dir = temp_dir("apply-downgrade");
        let state_dir = dir.join("state");
        let bin_dir = dir.join("bin");
        fs::create_dir_all(&state_dir).expect("state dir");
        fs::create_dir_all(&bin_dir).expect("bin dir");
        // 盘上跑的是 0.1.5，包里是更低的 0.1.3。
        let installed = fake_agentd(&bin_dir, "0.1.5");
        let artifact = dir.join("artifact");
        fs::create_dir_all(&artifact).expect("artifact dir");
        let packaged = artifact.join(AGENTD_BIN_NAME);
        fs::write(&packaged, "#!/bin/sh\necho \"wist-agentd 0.1.3\"\n").expect("write artifact");
        let bytes = fs::read(&packaged).expect("read artifact");

        let config = config_with_state(&state_dir);
        let mut request = request(installed);
        request.current_version = "0.1.5".to_string();
        request.target_version = None; // 版本由包内自报决定 → 更低的 0.1.3
        request.package_url = packaged.display().to_string();
        request.package_sha256 = sha256_hex_bytes(&bytes);

        // 没声明降级：默认只前进，在“验制品”这步被 `not_newer` 拦住（不落件）。
        let record = apply(&config, &request, &UpgradeOptions::default()).await;
        assert_eq!(record.status, "failed", "{record:?}");
        assert_eq!(record.step, "verify_artifact", "{record:?}");
        assert!(record.detail.contains("not_newer"), "{record:?}");

        // 显式声明降级：放行；演练停在换件前，记录里 from 高 to 低，状态是成功。
        request.allow_downgrade = true;
        let record = apply(&config, &request, &UpgradeOptions::default()).await;
        assert_eq!(record.status, "succeeded", "{record:?}");
        assert_eq!(record.step, "install", "{record:?}");
        assert_eq!(record.from_version, "0.1.5");
        assert_eq!(record.to_version, "0.1.3");
        // 演练不落件：旧件原样在。
        let installed_text =
            fs::read_to_string(bin_dir.join(AGENTD_BIN_NAME)).expect("read installed");
        assert!(
            installed_text.contains("0.1.5"),
            "dry run must not replace: {installed_text}"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[tokio::test]
    async fn wait_for_version_reads_the_running_state() {
        let dir = temp_dir("wait-ready");
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).expect("state dir");
        let path = state_dir.join(wist_shared::paths::AGENT_RUNTIME_FILE);
        let state = AgentRuntimeState::new(
            "agent-a".to_string(),
            "instance-a".to_string(),
            "0.1.4".to_string(),
            RuntimeMode::Normal,
            now_rfc3339(),
        );
        write_json_atomic(&path, &state).expect("store runtime state");

        assert!(
            wait_for_version(&state_dir, "0.1.4", Duration::from_millis(200)).await,
            "matching version must be seen"
        );
        assert!(
            !wait_for_version(&state_dir, "9.9.9", Duration::from_millis(200)).await,
            "other version must time out"
        );
        let _ = fs::remove_dir_all(dir);
    }

    /// 降级专用：就绪判据是 `==`，不是「必须比原来更高」。
    ///
    /// 场景：原本跑 0.1.5，降级到 0.1.3。重启那一刻盘上的状态还是**高的** 0.1.5，
    /// 此时等 0.1.3 必须判「还没起来」；新版自报 0.1.3 后才算就绪 —— 这证明判据对低版本同样成立。
    #[tokio::test]
    async fn wait_for_version_accepts_a_lower_downgrade_target() {
        let dir = temp_dir("wait-downgrade");
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).expect("state dir");
        let path = state_dir.join(wist_shared::paths::AGENT_RUNTIME_FILE);

        // 旧（高）版本还在报着：它不等于降级目标，不能当成「新版本起来了」。
        let old = AgentRuntimeState::new(
            "agent-a".to_string(),
            "instance-a".to_string(),
            "0.1.5".to_string(),
            RuntimeMode::Normal,
            now_rfc3339(),
        );
        write_json_atomic(&path, &old).expect("store old runtime state");
        assert!(
            !wait_for_version(&state_dir, "0.1.3", Duration::from_millis(200)).await,
            "the still-running higher version must not satisfy a downgrade target"
        );

        // 降级后的新版自报**低**版本：`==` 成立，判就绪。
        let downgraded = AgentRuntimeState::new(
            "agent-a".to_string(),
            "instance-a".to_string(),
            "0.1.3".to_string(),
            RuntimeMode::Normal,
            now_rfc3339(),
        );
        write_json_atomic(&path, &downgraded).expect("store downgraded runtime state");
        assert!(
            wait_for_version(&state_dir, "0.1.3", Duration::from_millis(200)).await,
            "a lower (downgraded) target must count as ready"
        );
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn running_version_requires_a_readable_runtime_state() {
        let dir = temp_dir("running-version");
        let state_dir = dir.join("state");
        fs::create_dir_all(&state_dir).expect("state dir");
        let path = state_dir.join(wist_shared::paths::AGENT_RUNTIME_FILE);

        // 没有文件：无从判断 —— 不能当成「已经是新版」。
        assert_eq!(running_version(&state_dir), None);

        // 文件在但内容坏了：同样不认。就绪判据宁可判「没起来」，也不拿坏数据当依据。
        fs::write(&path, b"{ not json").expect("write garbage");
        assert_eq!(running_version(&state_dir), None);

        // 正常一份：读出它的 `version` —— 这也是启动时被刷新的那个字段。
        let state = AgentRuntimeState::new(
            "agent-a".to_string(),
            "instance-a".to_string(),
            "0.1.5".to_string(),
            RuntimeMode::Normal,
            now_rfc3339(),
        );
        write_json_atomic(&path, &state).expect("store runtime state");
        assert_eq!(running_version(&state_dir).as_deref(), Some("0.1.5"));

        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn heartbeat_freshness_ages_out() {
        let dir = temp_dir("heartbeat");
        // 没有心跳文件 = 没在跳：没有证据就不能当成活着。
        assert!(!heartbeat_is_fresh(&dir, SystemTime::now()));

        touch_heartbeat(&dir).expect("touch heartbeat");
        assert!(heartbeat_is_fresh(&dir, SystemTime::now()));
        // 阈值：过了它就旧。
        assert!(!heartbeat_is_fresh(
            &dir,
            SystemTime::now() + UPGRADER_DEAD_AFTER + Duration::from_secs(1)
        ));
        // 时间戳在未来（时钟回拨 / 跨机拷贝）不拿它当死亡证据。
        assert!(heartbeat_is_fresh(
            &dir,
            SystemTime::now() - Duration::from_secs(5)
        ));

        let _ = fs::remove_dir_all(dir);
    }
}
