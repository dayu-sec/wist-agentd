//! Runtime config loading and mode selection.

use std::fs;
use std::io;
use std::path::{Path, PathBuf};

use orion_error::{conversion::ToStructError, prelude::*};

use crate::config::agent_config::{AgentConfig, LogFileInputsFile};
use crate::config::validate::validate_config;
use crate::fs_async::write_bytes_atomic_async;
use wist_shared::fs::write_bytes_atomic;
use wist_shared::paths::{AGENTD_CONFIG_FILE, LEGACY_AGENT_CONFIG_FILE};

#[path = "config_runtime_support.rs"]
mod support;

use support::{
    absolutize, apply_path_defaults, default_file_config_text, expand_env_contract, expand_string,
    is_system_config_dir, resolve_paths,
};

/// 系统级部署的配置目录：普通运行、`init-config`、`service install` 的默认值。
pub const SYSTEM_CONFIG_DIR: &str = "/etc/wist-agentd";
/// 系统级部署的数据根目录：配置在 [`SYSTEM_CONFIG_DIR`] 下时，`run/state/spool` 默认落在这里。
pub const SYSTEM_DATA_ROOT: &str = "/var/lib/wist-agentd";
/// 系统级部署的日志目录：配置在 [`SYSTEM_CONFIG_DIR`] 下时，agent 日志与采集输出默认落在这里。
pub const SYSTEM_LOG_DIR: &str = "/var/log/wist-agentd";

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Config")]
pub struct EnsuredConfigFile {
    pub path: PathBuf,
    pub created: bool,
}

pub use crate::error::{ConfigError, ConfigReason};

pub fn load_or_init(config_root: &Path) -> Result<AgentConfig, ConfigError> {
    let ensured = ensure_default_config(config_root)?;
    load_from_path(&ensured.path)
}

pub fn ensure_default_config(config_root: &Path) -> Result<EnsuredConfigFile, ConfigError> {
    fs::create_dir_all(config_root).source_err(
        ConfigReason::Io,
        format!("create config dir {}", config_root.display()),
    )?;
    let config_path = resolve_config_path(config_root);
    let created = if config_path.exists() {
        false
    } else {
        let text = default_file_config_text();
        write_bytes_atomic(&config_path, text.as_bytes()).source_err(
            ConfigReason::Io,
            format!("write config {}", config_path.display()),
        )?;
        true
    };
    Ok(EnsuredConfigFile {
        path: config_path,
        created,
    })
}

pub fn default_config_template() -> String {
    default_file_config_text()
}

pub fn load_from_path(config_path: &Path) -> Result<AgentConfig, ConfigError> {
    let text = fs::read_to_string(config_path).source_err(
        ConfigReason::Io,
        format!("read config {}", config_path.display()),
    )?;
    let text = migrate_legacy_container_flag(config_path, &text)?;
    let raw = toml::from_str::<toml::Value>(&text)
        .source_raw_err(ConfigReason::ParseToml, "parse config")?;
    let mut parsed = toml::from_str::<AgentConfig>(&text)
        .source_raw_err(ConfigReason::ParseToml, "parse config")?;
    apply_path_defaults(&mut parsed, config_path, &raw);
    load_file_inputs_from_task_file(&mut parsed, config_path)?;
    let env_resolved = expand_env_contract(parsed)?;
    let path_resolved = resolve_paths(env_resolved, config_path);
    validate_config(&path_resolved)
        .map_err(|err| ConfigReason::Validation.to_err().with_detail(err.code))?;
    Ok(path_resolved)
}

/// 0.9.10 及更早版本生成的配置模板把 `container_enabled` 写成了 `false`（当时定位是
/// 「高基数发现，按需打开」）。现在默认改开，而那些配置文件已经落盘落地 ——
/// 光改默认值对它们不生效，所以在这里做一次**一次性**改写。
///
/// 只动**仍然带着旧模板那行注释**的配置：说明没人动过这一块。
/// 手写过 `container_enabled = false` 但没保留注释的配置一律不碰 —— 那是明确的选择。
const LEGACY_CONTAINER_COMMENT: &str =
    "# container 属于更高基数发现，只有启用对应场景时再显式打开。";
const LEGACY_CONTAINER_LINE: &str = "container_enabled = false";
const REPLACEMENT_CONTAINER_COMMENT: &str =
    "# container 默认开：Linux 上容器是最基本的资产层。确实不需要的部署显式写 false。";
const REPLACEMENT_CONTAINER_LINE: &str = "container_enabled = true";

/// 把旧模板里的 `container_enabled = false` 改写为 `true`，返回新文本。
///
/// 不改就是 `None`（没有旧模板标记 / 已经被改过）。纯字符串操作，方便单测。
fn rewritten_legacy_container_text(text: &str) -> Option<String> {
    if !text.contains(LEGACY_CONTAINER_COMMENT) {
        return None;
    }
    let mut replaced = false;
    let lines: Vec<String> = text
        .lines()
        .map(|line| match line.trim_end() {
            LEGACY_CONTAINER_COMMENT => REPLACEMENT_CONTAINER_COMMENT.to_string(),
            LEGACY_CONTAINER_LINE if !replaced => {
                replaced = true;
                REPLACEMENT_CONTAINER_LINE.to_string()
            }
            _ => line.to_string(),
        })
        .collect();
    if !replaced {
        return None;
    }
    let mut rewritten = lines.join("\n");
    if text.ends_with('\n') {
        rewritten.push('\n');
    }
    Some(rewritten)
}

/// 加载时的一次性迁移：改写到磁盘，并打一行日志（配置文件被悄悄改掉很难排查）。
fn migrate_legacy_container_flag(config_path: &Path, text: &str) -> Result<String, ConfigError> {
    let Some(rewritten) = rewritten_legacy_container_text(text) else {
        return Ok(text.to_string());
    };
    write_bytes_atomic(config_path, rewritten.as_bytes()).source_err(
        ConfigReason::Io,
        format!("rewrite config {}", config_path.display()),
    )?;
    log::warn!(
        "config {}: container_enabled 已由旧模板的 false 改写为 true（容器采集默认开）；要关闭请显式改回 false",
        config_path.display()
    );
    Ok(rewritten)
}

async fn migrate_legacy_container_flag_async(
    config_path: &Path,
    text: String,
) -> Result<String, ConfigError> {
    let Some(rewritten) = rewritten_legacy_container_text(&text) else {
        return Ok(text);
    };
    write_bytes_atomic_async(config_path, rewritten.as_bytes())
        .await
        .source_err(
            ConfigReason::Io,
            format!("rewrite config {}", config_path.display()),
        )?;
    log::warn!(
        "config {}: container_enabled 已由旧模板的 false 改写为 true（容器采集默认开）；要关闭请显式改回 false",
        config_path.display()
    );
    Ok(rewritten)
}

/// 配置目录在 `/etc` 下时，数据默认根目录（供 `init-config` 提示使用）。
pub fn system_data_root_for(config_dir: &Path) -> Option<PathBuf> {
    is_system_config_dir(config_dir).then(|| PathBuf::from(SYSTEM_DATA_ROOT))
}

/// 若声明了 `[telemetry.logs] file_inputs_file`，从该外置任务清单加载 `file_inputs`。
///
/// 任务清单路径相对本配置文件解析（支持 `${ENV}` 展开），与内联
/// `[[telemetry.logs.file_inputs]]` 互斥：同时出现时拒绝加载，避免来源不明。
fn load_file_inputs_from_task_file(
    config: &mut AgentConfig,
    config_path: &Path,
) -> Result<(), ConfigError> {
    let Some(raw_path) = config.telemetry.logs.file_inputs_file.take() else {
        return Ok(());
    };
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let task_path = absolutize(config_dir, &expand_string(raw_path)?);
    let text = fs::read_to_string(&task_path).source_err(
        ConfigReason::Io,
        format!("read file_inputs_file {}", task_path.display()),
    )?;
    if !config.telemetry.logs.file_inputs.is_empty() {
        return Err(ConfigReason::Validation.to_err().with_detail(format!(
            "file_inputs_file {} conflicts with inline [[telemetry.logs.file_inputs]]; declare one or the other",
            task_path.display()
        )));
    }
    let tasks = toml::from_str::<LogFileInputsFile>(&text).source_raw_err(
        ConfigReason::ParseToml,
        format!("parse file_inputs_file {}", task_path.display()),
    )?;
    config.telemetry.logs.file_inputs = tasks.file_inputs;
    Ok(())
}

pub fn resolve_config_path(config_root: &Path) -> PathBuf {
    let preferred = config_root.join(AGENTD_CONFIG_FILE);
    if preferred.is_file() {
        return preferred;
    }

    let legacy = config_root.join(LEGACY_AGENT_CONFIG_FILE);
    if legacy.is_file() {
        return legacy;
    }

    preferred
}

pub async fn load_or_init_async(config_root: &Path) -> Result<AgentConfig, ConfigError> {
    let ensured = ensure_default_config_async(config_root).await?;
    load_from_path_async(&ensured.path).await
}

pub async fn ensure_default_config_async(
    config_root: &Path,
) -> Result<EnsuredConfigFile, ConfigError> {
    tokio::fs::create_dir_all(config_root).await.source_err(
        ConfigReason::Io,
        format!("create config dir {}", config_root.display()),
    )?;
    let config_path = resolve_config_path(config_root);
    let created = match tokio::fs::metadata(&config_path).await {
        Ok(_) => false,
        Err(err) if err.kind() == io::ErrorKind::NotFound => {
            let text = default_file_config_text();
            write_bytes_atomic_async(&config_path, text.as_bytes())
                .await
                .source_err(
                    ConfigReason::Io,
                    format!("write config {}", config_path.display()),
                )?;
            true
        }
        Err(err) => {
            return Err(StructError::builder(ConfigReason::Io)
                .detail(format!("stat config {}", config_path.display()))
                .source_std(err)
                .finish());
        }
    };
    Ok(EnsuredConfigFile {
        path: config_path,
        created,
    })
}

pub async fn load_from_path_async(config_path: &Path) -> Result<AgentConfig, ConfigError> {
    let text = tokio::fs::read_to_string(config_path).await.source_err(
        ConfigReason::Io,
        format!("read config {}", config_path.display()),
    )?;
    let text = migrate_legacy_container_flag_async(config_path, text).await?;
    let raw = toml::from_str::<toml::Value>(&text)
        .source_raw_err(ConfigReason::ParseToml, "parse config")?;
    let mut parsed = toml::from_str::<AgentConfig>(&text)
        .source_raw_err(ConfigReason::ParseToml, "parse config")?;
    apply_path_defaults(&mut parsed, config_path, &raw);
    load_file_inputs_from_task_file_async(&mut parsed, config_path).await?;
    let env_resolved = expand_env_contract(parsed)?;
    let path_resolved = resolve_paths(env_resolved, config_path);
    validate_config(&path_resolved)
        .map_err(|err| ConfigReason::Validation.to_err().with_detail(err.code))?;
    Ok(path_resolved)
}

async fn load_file_inputs_from_task_file_async(
    config: &mut AgentConfig,
    config_path: &Path,
) -> Result<(), ConfigError> {
    let Some(raw_path) = config.telemetry.logs.file_inputs_file.take() else {
        return Ok(());
    };
    let config_dir = config_path.parent().unwrap_or_else(|| Path::new("."));
    let task_path = absolutize(config_dir, &expand_string(raw_path)?);
    let text = tokio::fs::read_to_string(&task_path).await.source_err(
        ConfigReason::Io,
        format!("read file_inputs_file {}", task_path.display()),
    )?;
    if !config.telemetry.logs.file_inputs.is_empty() {
        return Err(ConfigReason::Validation.to_err().with_detail(format!(
            "file_inputs_file {} conflicts with inline [[telemetry.logs.file_inputs]]; declare one or the other",
            task_path.display()
        )));
    }
    let tasks = toml::from_str::<LogFileInputsFile>(&text).source_raw_err(
        ConfigReason::ParseToml,
        format!("parse file_inputs_file {}", task_path.display()),
    )?;
    config.telemetry.logs.file_inputs = tasks.file_inputs;
    Ok(())
}

#[cfg(test)]
#[path = "config_runtime_tests.rs"]
mod tests;
