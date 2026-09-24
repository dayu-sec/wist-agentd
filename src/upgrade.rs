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
use sha2::{Digest, Sha256};
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
/// 下载与暂存的子目录（放 state 下而不是 run 下：它要跨重启留着，便于事后取证）。
pub const UPGRADE_WORK_DIR: &str = "upgrade";
/// 换件后等新版起来的默认上限。
pub const DEFAULT_READY_WAIT: Duration = Duration::from_secs(60);
/// 取包超时：制品几十 MB，给足时间但不能无限等。
const DOWNLOAD_TIMEOUT: Duration = Duration::from_secs(300);
/// 等新版起来的轮询间隔。
const READY_POLL_INTERVAL: Duration = Duration::from_secs(1);
/// 在解包目录里找二进制时最多往下走几层（制品常带一层 `wist-agentd-<ver>-<target>/`）。
const MAX_ARTIFACT_DEPTH: usize = 3;

/// 一次性工作里 `action = upgrade` 的参数形状（JSON）。
///
/// `package_url` / `package_sha256` 由网关在派活时按**当前分发端点**与**实际缓存制品**填入，
/// 而不是让运维手抄：摘要必须与真正会被分发出去的那份字节同源，否则升级会变成
/// 「谁写这个字段谁决定装什么」。
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
pub struct UpgradeSpec {
    pub target_version: String,
    pub package_url: String,
    pub package_sha256: String,
}

/// 一次升级请求：把工作参数与「本机现状」凑在一起。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UpgradeRequest {
    /// 触发这次升级的一次性工作 id（结果要挂回它）。
    pub work_id: String,
    pub target_version: String,
    /// agentd 自报的版本（来自它自己的 `CARGO_PKG_VERSION`，不是从文件名猜的）。
    pub current_version: String,
    /// 要替换的 `wist-agentd` 路径（agentd 传自己的 `current_exe`）。
    pub agentd_bin: PathBuf,
    pub package_url: String,
    pub package_sha256: String,
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
            to_version: request.target_version.clone(),
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
pub fn parse_spec(text: &str) -> Result<UpgradeSpec, UpgradeError> {
    let spec: UpgradeSpec = serde_json::from_str(text).map_err(|err| {
        fail(
            "spec_invalid",
            format!(
                "expected JSON {{\"target_version\":\"…\",\"package_url\":\"…\",\"package_sha256\":\"…\"}}, got: {err}"
            ),
        )
    })?;
    if spec.target_version.trim().is_empty() {
        return Err(fail("spec_invalid", "target_version is empty"));
    }
    if spec.package_url.trim().is_empty() {
        return Err(fail("spec_invalid", "package_url is empty"));
    }
    Ok(spec)
}

/// 版本号拆成可比的分段（`0.1.4` → `[0,1,4]`）。带 `-pre` 后缀时只看前面的数字段。
///
/// 认不出来就返回 `None`：升级方向宁可拒绝，也不要拿字符串比较去猜大小。
fn version_parts(value: &str) -> Option<Vec<u64>> {
    let core = value.trim().split(['-', '+']).next()?;
    if core.is_empty() {
        return None;
    }
    let mut parts = Vec::new();
    for segment in core.split('.') {
        parts.push(segment.parse::<u64>().ok()?);
    }
    Some(parts)
}

fn version_is_newer(target: &str, current: &str) -> Option<bool> {
    let target = version_parts(target)?;
    let current = version_parts(current)?;
    Some(target > current)
}

/// 摘要字段：允许 `sha256:` 前缀（管理面/模型里就是那个写法），但必须是 64 位裸 hex。
fn digest_hex(value: &str) -> Result<String, UpgradeError> {
    let hex = value.trim().strip_prefix("sha256:").unwrap_or(value.trim());
    let ok = hex.len() == 64 && hex.chars().all(|c| c.is_ascii_hexdigit());
    if !ok {
        return Err(fail(
            "digest_invalid",
            format!("package_sha256 must be 64 hex chars, got {value:?}"),
        ));
    }
    Ok(hex.to_ascii_lowercase())
}

fn validate_request(request: &UpgradeRequest) -> Result<(), UpgradeError> {
    if request.work_id.trim().is_empty() {
        return Err(fail("spec_invalid", "work_id is empty"));
    }
    match version_is_newer(&request.target_version, &request.current_version) {
        Some(true) => {}
        Some(false) => {
            return Err(fail(
                "not_newer",
                format!(
                    "target {} is not newer than running {} (downgrade and reinstall are refused)",
                    request.target_version, request.current_version
                ),
            ));
        }
        None => {
            return Err(fail(
                "version_uncomparable",
                format!(
                    "cannot compare {} with {} as dotted numeric versions",
                    request.target_version, request.current_version
                ),
            ));
        }
    }
    digest_hex(&request.package_sha256)?;
    Ok(())
}

fn sha256_hex(bytes: &[u8]) -> String {
    let hash = Sha256::digest(bytes);
    hash.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn verify_digest(bytes: &[u8], expected: &str) -> Result<(), UpgradeError> {
    let expected = digest_hex(expected)?;
    let actual = sha256_hex(bytes);
    if actual != expected {
        return Err(fail(
            "digest_mismatch",
            format!("expected {expected}, got {actual}"),
        ));
    }
    Ok(())
}

/// 取包：`https://…` 走网关（带信任锚），`/abs/path` 直接读本机（联调与离线演练）。
async fn fetch_package(config: &AgentConfig, source: &str) -> Result<Vec<u8>, UpgradeError> {
    let source = source.trim();
    if source.starts_with('/') {
        return std::fs::read(source)
            .map_err(|err| fail("package_unavailable", format!("read {source}: {err}")));
    }
    let client = enrollment_http_client(config)
        .map_err(|err| fail("package_unavailable", format!("build http client: {err}")))?;
    let response = client
        .get(source)
        .timeout(DOWNLOAD_TIMEOUT)
        .send()
        .await
        .map_err(|err| fail("package_unavailable", format!("GET {source}: {err}")))?;
    if !response.status().is_success() {
        return Err(fail(
            "package_unavailable",
            format!("GET {source}: HTTP {}", response.status()),
        ));
    }
    response
        .bytes()
        .await
        .map(|bytes| bytes.to_vec())
        .map_err(|err| {
            fail(
                "package_unavailable",
                format!("read body from {source}: {err}"),
            )
        })
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
            if path.is_dir() {
                if depth < MAX_ARTIFACT_DEPTH {
                    queue.push((path, depth + 1));
                }
                continue;
            }
            if is_known_binary(&name) && !found.iter().any(|item| item.name == name) {
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

/// 版本号输出形如 `wist-agentd 0.1.3`，也可能只是 `0.1.3`：取最后一个像版本号的词。
fn parse_version_output(stdout: &str) -> Option<String> {
    stdout
        .split_whitespace()
        .rev()
        .find(|token| token.contains('.'))
        .map(|token| token.trim().to_string())
}

/// 校验暂存件**自称的版本**：摘要对了不代表版本对（例如把旧包重新压了一遍）。
///
/// 这是「装上去之前唯一能问的一句」：让新二进制自己报版本，与目标比对。
fn verify_staged_agentd(staged: &[StagedBinary], target_version: &str) -> Result<(), UpgradeError> {
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
    if reported != target_version {
        return Err(fail(
            "version_mismatch",
            format!("package reports {reported:?}, target is {target_version:?}"),
        ));
    }
    Ok(())
}

/// 一件被换掉的二进制及其备份。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Backup {
    pub installed: PathBuf,
    pub backup: PathBuf,
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
        if dry_run {
            backups.push(Backup { installed, backup });
            continue;
        }
        if installed.exists() && !backup.exists() {
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
        run_command("mv", &move_args)?;
        backups.push(Backup { installed, backup });
    }
    Ok(backups)
}

/// 回滚：把备份放回去（备份本身保留，事后要能取证）。
fn restore_backups(backups: &[Backup], bin_dir: &Path) -> Result<(), UpgradeError> {
    for backup in backups {
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
pub fn build_launch(program: &Path, config_dir: &Path, request: &UpgradeRequest) -> UpgradeLaunch {
    UpgradeLaunch {
        program: program.to_path_buf(),
        args: vec![
            "apply".to_string(),
            "--config-dir".to_string(),
            config_dir.display().to_string(),
            "--bin".to_string(),
            request.agentd_bin.display().to_string(),
            "--work-id".to_string(),
            request.work_id.clone(),
            "--target-version".to_string(),
            request.target_version.clone(),
            "--current-version".to_string(),
            request.current_version.clone(),
            "--package-url".to_string(),
            request.package_url.clone(),
            "--package-sha256".to_string(),
            request.package_sha256.clone(),
            "--apply".to_string(),
        ],
    }
}

/// 把升级器作为**分离进程**起起来（不等待、不随 agentd 退出而死），返回其 pid。
///
/// 为什么要自成会话：agentd 马上就会被这个进程换掉并重启。留在同一个会话里，
/// 服务管理器回收整个会话时会把它一起收走 —— 而它正是「在 agentd 死掉的窗口里必须活着」的那个。
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
    // 先落一条「我在做」再开干：agentd 每 tick 读这份记录来更新本机工作视图，
    // 也是「升级进行中、不许再派第二件」的唯一依据 —— 进程活着却不落盘，外面就没人知道。
    let _ = store_record(state_dir, record);
    let bytes = fetch_package(config, &request.package_url).await?;

    record.step("verify_digest");
    verify_digest(&bytes, &request.package_sha256)?;

    record.step("stage");
    let staged = stage_package(&bytes, &staging_dir)?;

    record.step("verify_artifact");
    verify_staged_agentd(&staged, &request.target_version)?;

    record.step("install");
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
    let backups = install_binaries(&staged, &bin_dir, &request.current_version, options.dry_run)?;
    if options.dry_run {
        return Ok(());
    }

    record.step("restart");
    if let Err(err) = run_restart(&options.restart) {
        // 换件已经发生但没重启：先回滚，否则机器上会留一个「装着新版、跑着旧版」的中间态。
        let rollback = restore_backups(&backups, &bin_dir).err();
        let retry = run_restart(&options.restart).err();
        record.status = "rolled_back".to_string();
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
    if !wait_for_version(state_dir, &request.target_version, options.ready_wait).await {
        let rollback = restore_backups(&backups, &bin_dir).err();
        let retry = run_restart(&options.restart).err();
        record.status = "rolled_back".to_string();
        return Err(fail(
            "not_ready",
            format!(
                "new version did not report {} within {:?}{}{}",
                request.target_version,
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
            target_version: "0.1.4".to_string(),
            current_version: "0.1.3".to_string(),
            agentd_bin,
            package_url: "/nonexistent/package.tar.gz".to_string(),
            package_sha256: "0".repeat(64),
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
        assert_eq!(spec.target_version, "0.1.4");
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
            request.target_version = target.to_string();
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

    #[test]
    fn validate_refuses_a_malformed_digest() {
        let dir = temp_dir("validate-digest");
        let mut request = request(dir.join(AGENTD_BIN_NAME));
        request.package_sha256 = "sha256:nothex".to_string();
        let err = validate_request(&request).expect_err("must refuse");
        assert_eq!(err.reason, "digest_invalid");
        let _ = fs::remove_dir_all(dir);
    }

    #[test]
    fn build_launch_passes_every_fact_explicitly() {
        let request = UpgradeRequest {
            work_id: "work-upgrade-1".to_string(),
            target_version: "0.1.4".to_string(),
            current_version: "0.1.3".to_string(),
            agentd_bin: PathBuf::from("/usr/local/bin/wist-agentd"),
            package_url: "https://gw/api/v1/agent/packages/current".to_string(),
            package_sha256: "sha256:abc".to_string(),
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

    #[test]
    fn verify_digest_accepts_with_and_without_prefix() {
        let bytes = b"package-bytes";
        let hex = sha256_hex(bytes);
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
    fn verify_staged_agentd_compares_the_reported_version() {
        let dir = temp_dir("verify-version");
        let staging = dir.join("staging");
        fs::create_dir_all(&staging).expect("staging");
        let bin = fake_agentd(&staging, "0.1.4");
        let staged = vec![StagedBinary {
            name: AGENTD_BIN_NAME.to_string(),
            path: bin,
        }];

        verify_staged_agentd(&staged, "0.1.4").expect("same version passes");
        let err = verify_staged_agentd(&staged, "0.1.5").expect_err("different version must fail");
        assert_eq!(err.reason, "version_mismatch");
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
        request.package_sha256 = sha256_hex(&bytes);

        let record = apply(&config, &request, &UpgradeOptions::default()).await;
        assert_eq!(record.status, "succeeded", "{record:?}");
        assert_eq!(record.step, "install");
        let installed_text = fs::read_to_string(&installed).expect("read installed");
        assert!(installed_text.contains("0.1.3"), "dry run must not replace");
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
}
