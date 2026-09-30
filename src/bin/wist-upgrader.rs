//! `wist-upgrader` 升级执行体（作为 `wist-agentd` 的同仓二进制构建）。
//!
//! 它是**分离进程**：由 agentd 在收到 `action = upgrade` 的一次性工作时拉起 —— 不等待、
//! 不随 agentd 退出而死（agentd 会被它自己换掉并重启）。职责是「执行」不是「决定」：
//! 取包 → 校验摘要 → 按形态解包 → 让新件自报版本 → 原子换件 → 重启 → 等新版起来 → 失败回滚。
//!
//! **默认只演练**（取包 / 验摘要 / 解包 / 验版本，但不动已装二进制）：第一次在真机上跑升级，
//! 应该先看清「包里是什么、摘要对不对」，再决定换。真正执行要显式 `--apply`。

use std::path::{Path, PathBuf};
use std::time::Duration;

use wist_agentd::config_runtime;
use wist_agentd::upgrade::{
    DEFAULT_READY_WAIT, RestartPlan, UpgradeOptions, UpgradeRequest, apply, default_restart_plan,
};
use wist_contracts::agent_config::AgentConfig;

const USAGE: &str = "\
Usage:
  wist-upgrader apply --config-dir <dir> --work-id <id> --current-version <v>
                      --package-url <url> --package-sha256 <sha>
                      [--target-version <v>] [--bin <agentd path>] [--apply]
                      [--allow-downgrade] [--scope system|user] [--ready-wait-secs <n>]
  wist-upgrader version
  wist-upgrader help

Options:
  --target-version <v>   目标版本（**可选**：不给就以包内 agentd 自报的版本为准）
  --apply                真的换件并重启（不加 = 演练：取包/验摘要/解包/验版本，不动已装二进制）
  --allow-downgrade      允许同版本/降级（**默认只前进**；要降级必须显式加这个开关）
  --bin <path>           要替换的 wist-agentd 路径（默认：本可执行文件同级的 wist-agentd）
  --scope <system|user>  服务作用域（默认：配置目录在 /etc/wist-agentd 下即 system）
  --ready-wait-secs <n>  换件后等新版起来的秒数（默认 60）
";

#[derive(Debug, Clone, PartialEq, Eq)]
struct Args {
    config_dir: PathBuf,
    bin: Option<PathBuf>,
    work_id: String,
    /// 目标版本：`Some` = 显式要求（必须与包内自报一致）；`None` = 由包内自报的版本决定。
    target_version: Option<String>,
    current_version: String,
    package_url: String,
    package_sha256: String,
    scope_is_system: bool,
    scope_explicit: bool,
    dry_run: bool,
    /// 是否允许同版本/降级。默认 `false`：只前进（见 `--allow-downgrade`）。
    allow_downgrade: bool,
    ready_wait: Duration,
}

fn main() {
    if let Err(err) = run() {
        eprintln!("wist-upgrader: {err}");
        std::process::exit(2);
    }
}

#[tokio::main]
async fn run() -> Result<(), String> {
    let mut args = std::env::args().skip(1);
    match args.next().as_deref() {
        Some("apply") => {}
        Some("version") => {
            println!("wist-upgrader {}", env!("CARGO_PKG_VERSION"));
            return Ok(());
        }
        Some("help") | Some("--help") | Some("-h") | None => {
            print!("{USAGE}");
            return Ok(());
        }
        Some(other) => return Err(format!("unsupported subcommand: {other}")),
    }
    let parsed = parse_args(args)?;
    execute(parsed).await
}

fn parse_args<I>(mut args: I) -> Result<Args, String>
where
    I: Iterator<Item = String>,
{
    let mut config_dir: Option<PathBuf> = None;
    let mut bin: Option<PathBuf> = None;
    let mut work_id: Option<String> = None;
    let mut target_version: Option<String> = None;
    let mut current_version: Option<String> = None;
    let mut package_url: Option<String> = None;
    let mut package_sha256: Option<String> = None;
    let mut scope: Option<String> = None;
    let mut dry_run = true;
    let mut allow_downgrade = false;
    let mut ready_wait = DEFAULT_READY_WAIT;

    while let Some(flag) = args.next() {
        let mut value = || {
            args.next()
                .ok_or_else(|| format!("missing value for {flag}"))
        };
        match flag.as_str() {
            "--config-dir" => config_dir = Some(PathBuf::from(value()?)),
            "--bin" => bin = Some(PathBuf::from(value()?)),
            "--work-id" => work_id = Some(value()?),
            "--target-version" => target_version = Some(value()?),
            "--current-version" => current_version = Some(value()?),
            "--package-url" => package_url = Some(value()?),
            "--package-sha256" => package_sha256 = Some(value()?),
            "--scope" => scope = Some(value()?),
            "--ready-wait-secs" => {
                let raw = value()?;
                let secs = raw
                    .parse::<u64>()
                    .map_err(|err| format!("--ready-wait-secs must be a number: {err}"))?;
                ready_wait = Duration::from_secs(secs);
            }
            "--apply" => dry_run = false,
            "--allow-downgrade" => allow_downgrade = true,
            other => return Err(format!("unsupported flag: {other}\n\n{USAGE}")),
        }
    }

    let scope_explicit = scope.is_some();
    let scope_is_system = match scope.as_deref() {
        Some("system") => true,
        Some("user") => false,
        Some(other) => return Err(format!("--scope must be system or user, got {other}")),
        None => false,
    };

    Ok(Args {
        config_dir: config_dir.ok_or("missing --config-dir")?,
        bin,
        work_id: work_id.ok_or("missing --work-id")?,
        target_version,
        current_version: current_version.ok_or("missing --current-version")?,
        package_url: package_url.ok_or("missing --package-url")?,
        package_sha256: package_sha256.ok_or("missing --package-sha256")?,
        scope_is_system,
        scope_explicit,
        dry_run,
        allow_downgrade,
        ready_wait,
    })
}

async fn execute(args: Args) -> Result<(), String> {
    let config = load_upgrader_config(&args.config_dir)?;

    let agentd_bin = match args.bin {
        Some(path) => path,
        None => default_agentd_bin()?,
    };
    let system_scope = if args.scope_explicit {
        args.scope_is_system
    } else {
        config_runtime::system_data_root_for(&args.config_dir).is_some()
    };

    let request = UpgradeRequest {
        work_id: args.work_id,
        target_version: args.target_version,
        current_version: args.current_version,
        agentd_bin,
        package_url: args.package_url,
        package_sha256: args.package_sha256,
        allow_downgrade: args.allow_downgrade,
    };
    let options = UpgradeOptions {
        dry_run: args.dry_run,
        ready_wait: args.ready_wait,
        restart: if args.dry_run {
            RestartPlan::None
        } else {
            default_restart_plan(system_scope)
        },
    };

    let record = apply(&config, &request, &options).await;
    println!(
        "wist-upgrader: status={} step={} {} -> {}",
        record.status, record.step, record.from_version, record.to_version
    );
    if !record.detail.is_empty() {
        println!("  detail: {}", record.detail);
    }
    if record.status == "succeeded" {
        Ok(())
    } else {
        Err(format!("upgrade {} at step {}", record.status, record.step))
    }
}

/// 加载升级器要用的配置：`agentd.toml` **加上**从 state 注入的正式身份。
///
/// 配置由 agentd 负责生成 / 维护，升级器只读：没有配置说明这台机器还没装好 agentd。
/// 取包靠 `enrollment_http_client` 挂上的**客户端证书**（mTLS），不再是 bearer token；
/// 证书路径来自配置里的 `state_dir`，而 agent_id 等身份只落在 state。
/// 这里补上 daemon 启动时同一步（`restore_runtime_identity`），与 agentd 用同一份身份。
fn load_upgrader_config(config_dir: &Path) -> Result<AgentConfig, String> {
    let config_path = config_runtime::resolve_config_path(config_dir);
    if !config_path.is_file() {
        return Err(format!(
            "config not found: {} (install wist-agentd first)",
            config_path.display()
        ));
    }
    let mut config: AgentConfig = config_runtime::load_from_path(&config_path)
        .map_err(|err| format!("load config: {err}"))?;
    let state_dir = PathBuf::from(&config.paths.state_dir);
    if let Err(err) = wist_agentd::enrollment::restore_runtime_identity(&mut config, &state_dir) {
        // 注入失败不阻止升级：本地路径包不需要凭据，https 包随后会以 401 如实暴露。
        eprintln!("wist-upgrader: warning: restore runtime credential from state: {err}");
    }
    Ok(config)
}

/// 默认要替换的 `wist-agentd`：与本可执行文件同级的那个。
fn default_agentd_bin() -> Result<PathBuf, String> {
    let exe = std::env::current_exe().map_err(|err| format!("resolve current exe: {err}"))?;
    Ok(exe.with_file_name(wist_agentd::upgrade::AGENTD_BIN_NAME))
}

#[cfg(test)]
mod tests {
    use super::{Args, load_upgrader_config, parse_args};
    use std::path::PathBuf;
    use std::time::Duration;
    use wist_agentd::{config_runtime, state_store::agent_runtime};
    use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};

    fn parse(args: &[&str]) -> Result<Args, String> {
        parse_args(args.iter().map(|value| value.to_string()))
    }

    #[test]
    fn parse_requires_the_upgrade_facts() {
        let err = parse(&["--config-dir", "/etc/wist-agentd"]).expect_err("missing flags");
        assert!(err.contains("--work-id"), "{err}");

        // `--target-version` **不是**必填了：不给就以包内自报的版本为准。
        let args = parse(&[
            "--config-dir",
            "/etc/wist-agentd",
            "--work-id",
            "w",
            "--current-version",
            "0.1.3",
            "--package-url",
            "/x",
            "--package-sha256",
            "abc",
        ])
        .expect("target version is optional");
        assert_eq!(args.target_version, None);
    }

    #[test]
    fn parse_defaults_to_a_dry_run_with_the_platform_restart() {
        let args = parse(&[
            "--config-dir",
            "/etc/wist-agentd",
            "--work-id",
            "work-1",
            "--target-version",
            "0.1.4",
            "--current-version",
            "0.1.3",
            "--package-url",
            "https://gw/api/v1/agent/packages/current",
            "--package-sha256",
            "abc",
        ])
        .expect("parse");
        assert!(args.dry_run, "must not replace anything unless --apply");
        assert!(!args.scope_explicit);
        assert_eq!(args.ready_wait, Duration::from_secs(60));
        assert_eq!(args.bin, None);
    }

    /// `--allow-downgrade` 默认关（只前进），显式给了才开。
    /// 这是传递链的最后一跳：argv 到底有没有带这个事实，就靠 `args.allow_downgrade`。
    #[test]
    fn parse_defaults_to_only_forward_and_accepts_allow_downgrade() {
        let base = [
            "--config-dir",
            "/etc/wist-agentd",
            "--work-id",
            "work-1",
            "--current-version",
            "0.1.3",
            "--package-url",
            "/tmp/package.tar.gz",
            "--package-sha256",
            "sha256:abc",
        ];

        // 缺省 = 只前进。
        let args = parse(&base).expect("parse");
        assert!(!args.allow_downgrade, "缺省必须是「只前进」");

        // 显式声明降级。
        let mut with_flag = base.to_vec();
        with_flag.push("--allow-downgrade");
        let args = parse(&with_flag).expect("parse");
        assert!(args.allow_downgrade);
    }

    #[test]
    fn parse_accepts_apply_bin_scope_and_wait() {
        let args = parse(&[
            "--config-dir",
            "/etc/wist-agentd",
            "--bin",
            "/usr/local/bin/wist-agentd",
            "--work-id",
            "work-1",
            "--target-version",
            "0.1.4",
            "--current-version",
            "0.1.3",
            "--package-url",
            "/tmp/package.tar.gz",
            "--package-sha256",
            "sha256:abc",
            "--scope",
            "user",
            "--ready-wait-secs",
            "5",
            "--apply",
        ])
        .expect("parse");
        assert!(!args.dry_run);
        assert!(args.scope_explicit);
        assert!(!args.scope_is_system);
        assert_eq!(args.ready_wait, Duration::from_secs(5));
        assert_eq!(args.bin, Some(PathBuf::from("/usr/local/bin/wist-agentd")));
    }

    #[test]
    fn parse_rejects_unknown_flags_and_bad_values() {
        let unknown = parse(&["--nope"]).expect_err("unknown flag");
        assert!(unknown.contains("unsupported flag"), "{unknown}");
        let bad_scope = parse(&[
            "--config-dir",
            "/etc/wist-agentd",
            "--work-id",
            "w",
            "--target-version",
            "1.0.0",
            "--current-version",
            "0.1.0",
            "--package-url",
            "/x",
            "--package-sha256",
            "abc",
            "--scope",
            "global",
        ])
        .expect_err("bad scope");
        assert!(bad_scope.contains("system or user"), "{bad_scope}");
    }

    /// 升级器必须带上 agent 身份：身份只落在 state（`agent_runtime.json`），`agentd.toml` 里没有
    /// —— 取包靠客户端证书（mTLS），身份注入后控制面才认得这台机器。
    #[test]
    fn load_upgrader_config_restores_the_state_identity() {
        let dir = unique_dir("upgrader-cred");
        std::fs::create_dir_all(&dir).expect("create config dir");
        let config_path = config_runtime::resolve_config_path(&dir);
        std::fs::write(&config_path, config_runtime::default_config_template())
            .expect("write default config");

        // 先解一次拿到真实的 state 目录（默认随配置目录而定），再把身份落进去。
        let base = config_runtime::load_from_path(&config_path).expect("base config");
        let state_dir = PathBuf::from(&base.paths.state_dir);
        std::fs::create_dir_all(&state_dir).expect("create state dir");
        let mut runtime = AgentRuntimeState::new(
            "agent-cred".to_string(),
            "instance-cred".to_string(),
            "0.1.7".to_string(),
            RuntimeMode::Normal,
            "2026-01-01T00:00:00Z".to_string(),
        );
        runtime.credential_id = Some("cred-1".to_string());
        agent_runtime::store(&agent_runtime::path_for(&state_dir), &runtime)
            .expect("store runtime state");

        let config = load_upgrader_config(&dir).expect("load upgrader config");
        assert_eq!(
            config.control_plane.credential_id.as_deref(),
            Some("cred-1"),
            "升级器必须从 state 注入身份，否则取包/控制面认不出这台机器"
        );
        assert_eq!(config.agent.agent_id.as_deref(), Some("agent-cred"));

        let _ = std::fs::remove_dir_all(dir);
    }

    fn unique_dir(label: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("time")
            .as_nanos();
        std::env::temp_dir().join(format!("wist-upgrader-{label}-{suffix}"))
    }
}
