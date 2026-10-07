//! Host discovery probe skeleton.

use std::fs;

use std::collections::BTreeMap;

use wist_contracts::discovery::{DiscoveredResource, DiscoveredTarget, DiscoveryOrigin};
use wist_shared::time::now_rfc3339;

use super::{DiscoveryError, DiscoveryProbe, DiscoverySourceKind, ProbeOutput};

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct HostDiscoveryProbe;

impl DiscoveryProbe for HostDiscoveryProbe {
    fn name(&self) -> &'static str {
        "host"
    }

    fn source(&self) -> DiscoverySourceKind {
        DiscoverySourceKind::LocalRuntime
    }

    fn refresh_interval(&self) -> std::time::Duration {
        // 这是**内建默认值**：与策展数据 `wist-knowledge/aspect-policies.toml` 里的
        // `default_interval_seconds` 同值，只在拿不到平台下发的策略表（断网 / 网关未配表）时生效。
        // 拿得到表就由表盖过（见 `DiscoveryRuntime` 的到期判定）；改策展值不必改这里。

        std::time::Duration::from_secs(900)
    }

    fn refresh(&self, _now: std::time::SystemTime) -> Result<ProbeOutput, DiscoveryError> {
        let discovered_at = now_rfc3339();
        let host_id = default_host_id();
        let host_name = default_host_name();
        let source = self.source().as_str().to_string();
        let origin_id = format!("{}:{}:{}", source, self.name(), discovered_at);

        Ok(ProbeOutput {
            probe: self.name().to_string(),
            source: self.source(),
            refreshed_at: discovered_at.clone(),
            origin: DiscoveryOrigin {
                origin_id: origin_id.clone(),
                probe: self.name().to_string(),
                source: source.clone(),
                observed_at: discovered_at.clone(),
            },
            resources: vec![DiscoveredResource {
                resource_id: host_id.clone(),
                kind: "host".to_string(),
                origin_idx: 0,
                attributes: BTreeMap::from([
                    ("host.id".to_string(), host_id.clone()),
                    ("host.name".to_string(), host_name.clone()),
                ]),
                discovered_at: discovered_at.clone(),
                last_seen_at: discovered_at.clone(),
                health: "healthy".to_string(),
                source: self.name().to_string(),
            }],
            targets: vec![DiscoveredTarget {
                target_id: format!("{host_id}:host"),
                kind: "host".to_string(),
                origin_idx: 0,
                resource_ref: host_id,
                execution_hints: BTreeMap::from([("host.name".to_string(), host_name.clone())]),
                state: "active".to_string(),
            }],
        })
    }
}

/// 机器名的**唯一**来源优先级：`HOSTNAME` → `COMPUTERNAME` → `/etc/hostname` → 系统主机名
/// （`gethostname`）。返回 `None` = 四个来源都拿不到 —— 占位名由调用方按语境定
/// （`local-host` / `local-instance`）。
///
/// 三处都需要「这台机器叫什么」（发现探针、注册/状态上报的机器画像、实例名兜底），优先级只在这里
/// 定义一次。前两个来源不可靠：macOS 没有 `/etc/hostname`、守护进程环境里也常常没有 `HOSTNAME`，
/// 只靠它们会退化成占位名；系统主机名才是管理面想看的那个（macOS 上是 `MacBook-Pro-2.local`）。
pub(crate) fn host_name_from_sources<'a>(
    hostname_env: Option<&'a str>,
    computername_env: Option<&'a str>,
    hostname_file: Option<&'a str>,
    os_hostname: Option<&'a str>,
) -> Option<&'a str> {
    [hostname_env, computername_env, hostname_file, os_hostname]
        .into_iter()
        .flatten()
        .map(str::trim)
        .find(|value| !value.is_empty())
}

/// 从**本机**来源解析机器名（优先级见 [`host_name_from_sources`]）。
pub(crate) fn resolve_host_name() -> Option<String> {
    host_name_from_sources(
        std::env::var("HOSTNAME").ok().as_deref(),
        std::env::var("COMPUTERNAME").ok().as_deref(),
        hostname_from_file().as_deref(),
        os_hostname().as_deref(),
    )
    .map(str::to_string)
}

/// 当前机器名，四个来源都拿不到时回落占位名 `local-host`。
pub(crate) fn default_host_name() -> String {
    resolve_host_name().unwrap_or_else(|| "local-host".to_string())
}

/// 本机操作系统主机名（`gethostname`）。
///
/// `HOSTNAME` / `COMPUTERNAME` / `/etc/hostname` 是「好来源」，但都不可靠：macOS 没有
/// `/etc/hostname`，守护进程环境里也常常没有导出的 `HOSTNAME`。两者都拿不到时会退化成占位名
/// `local-host` —— 而系统主机名正是管理面想看的那个（macOS 上是 `MacBook-Pro-2.local`）。
/// 所以让它排在占位名之前。
pub(crate) fn os_hostname() -> Option<String> {
    sysinfo::System::host_name()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

pub(crate) fn default_host_id() -> String {
    machine_id_from_known_locations()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("hostname:{}", default_host_name()))
}

#[cfg(unix)]
fn hostname_from_file() -> Option<String> {
    fs::read_to_string("/etc/hostname").ok()
}

#[cfg(not(unix))]
fn hostname_from_file() -> Option<String> {
    None
}

#[cfg(unix)]
fn machine_id_from_known_locations() -> Option<String> {
    ["/etc/machine-id", "/var/lib/dbus/machine-id"]
        .into_iter()
        .find_map(|path| fs::read_to_string(path).ok())
}

#[cfg(not(unix))]
fn machine_id_from_known_locations() -> Option<String> {
    None
}

#[cfg(test)]
mod tests {
    use super::{default_host_name, host_name_from_sources};

    #[test]
    fn host_name_prefers_hostname_env() {
        assert_eq!(
            host_name_from_sources(Some("host-a"), Some("pc-a"), Some("file-a"), Some("os-a")),
            Some("host-a")
        );
    }

    #[test]
    fn host_name_falls_back_to_hostname_file() {
        assert_eq!(
            host_name_from_sources(None, None, Some("file-a"), Some("os-a")),
            Some("file-a")
        );
    }

    #[test]
    fn host_name_falls_back_to_os_hostname_before_placeholder() {
        // env / file 都拿不到（macOS 的常态）时，得用系统主机名，而不是占位名。
        assert_eq!(
            host_name_from_sources(None, None, None, Some("MacBook-Pro-2.local")),
            Some("MacBook-Pro-2.local")
        );
    }

    #[test]
    fn host_name_is_none_when_all_sources_missing() {
        assert_eq!(host_name_from_sources(None, None, None, None), None);
    }

    #[test]
    fn host_name_skips_blank_sources() {
        // 空串 / 纯空白不算来源，继续往后找。
        assert_eq!(
            host_name_from_sources(Some("  "), None, Some(""), Some("os-a")),
            Some("os-a")
        );
    }

    #[test]
    fn default_host_name_is_never_empty() {
        assert!(!default_host_name().is_empty());
    }
}
