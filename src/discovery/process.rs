//! Process discovery probe skeleton.

#[cfg(target_os = "linux")]
use std::fs;
use std::io;
#[cfg(all(unix, not(target_os = "linux")))]
use std::process::Command;

use std::collections::BTreeMap;

use wist_contracts::discovery::{DiscoveredResource, DiscoveredTarget, DiscoveryOrigin};
use wist_shared::time::now_rfc3339;

use crate::process_control::process_identity;

use super::host::default_host_id;
use super::{DiscoveryError, DiscoveryProbe, DiscoverySourceKind, ProbeOutput};

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct ProcessDiscoveryProbe;

impl DiscoveryProbe for ProcessDiscoveryProbe {
    fn name(&self) -> &'static str {
        "process"
    }

    fn source(&self) -> DiscoverySourceKind {
        DiscoverySourceKind::LocalRuntime
    }

    fn refresh_interval(&self) -> std::time::Duration {
        // 这是**内建默认值**：与策展数据 `wist-knowledge/aspect-policies.toml` 里的
        // `default_interval_seconds` 同值，只在拿不到平台下发的策略表（断网 / 网关未配表）时生效。
        // 拿得到表就由表盖过（见 `DiscoveryRuntime` 的到期判定）；改策展值不必改这里。

        std::time::Duration::from_secs(300)
    }

    fn refresh(&self, _now: std::time::SystemTime) -> Result<ProbeOutput, DiscoveryError> {
        let discovered_at = now_rfc3339();
        let host_id = default_host_id();
        let source = self.source().as_str().to_string();
        let observed_at = discovered_at.clone();
        let origin_id = format!("{}:{}:{}", source, self.name(), observed_at);
        let processes = list_processes().map_err(|err| {
            super::probe_failed(
                self.name(),
                self.source(),
                format!("process discovery failed: {err}"),
            )
        })?;

        let mut resources = Vec::with_capacity(processes.len());
        let mut targets = Vec::with_capacity(processes.len());
        for process in processes {
            let resource_id = process.resource_id(&host_id);
            let target_id = process.target_id(&host_id);
            let mut attributes = BTreeMap::new();
            attributes.insert("process.pid".to_string(), process.pid.to_string());
            if let Some(name) = &process.name {
                attributes.insert("process.executable.name".to_string(), name.clone());
            }
            let mut execution_hints = BTreeMap::new();
            execution_hints.insert("process.pid".to_string(), process.pid.to_string());
            if let Some(identity) = &process.identity {
                execution_hints.insert("process.identity".to_string(), identity.clone());
            }
            if process.identity.is_none() {
                execution_hints.insert(
                    "discovery.identity_strength".to_string(),
                    "weak".to_string(),
                );
            }
            if process.identity_unavailable {
                execution_hints.insert(
                    "discovery.identity_status".to_string(),
                    "unavailable".to_string(),
                );
            }

            resources.push(DiscoveredResource {
                resource_id: resource_id.clone(),
                kind: "process".to_string(),
                origin_idx: 0,
                attributes,
                discovered_at: discovered_at.clone(),
                last_seen_at: discovered_at.clone(),
                health: "healthy".to_string(),
                source: self.name().to_string(),
            });
            targets.push(DiscoveredTarget {
                target_id,
                kind: "process".to_string(),
                origin_idx: 0,
                resource_ref: resource_id,
                execution_hints,
                state: "active".to_string(),
            });
        }

        Ok(ProbeOutput {
            probe: self.name().to_string(),
            source: self.source(),
            refreshed_at: discovered_at,
            origin: DiscoveryOrigin {
                origin_id,
                probe: self.name().to_string(),
                source,
                observed_at,
            },
            resources,
            targets,
        })
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Observed", module = "Observed.Entity")]
struct ObservedProcess {
    pid: u32,
    identity: Option<String>,
    name: Option<String>,
    identity_unavailable: bool,
}

impl ObservedProcess {
    fn resource_id(&self, host_id: &str) -> String {
        match &self.identity {
            Some(identity) => format!("{host_id}:pid:{}:{identity}", self.pid),
            None => format!("{host_id}:pid:{}", self.pid),
        }
    }

    fn target_id(&self, host_id: &str) -> String {
        match &self.identity {
            Some(identity) => format!("{host_id}:pid:{}:{identity}:process", self.pid),
            None => format!("{host_id}:pid:{}:process", self.pid),
        }
    }
}

#[cfg(target_os = "linux")]
fn list_processes() -> io::Result<Vec<ObservedProcess>> {
    let mut processes = Vec::new();
    for entry in fs::read_dir("/proc")? {
        let entry = entry?;
        let Some(file_name) = entry.file_name().to_str().map(str::to_string) else {
            continue;
        };
        let Ok(pid) = file_name.parse::<u32>() else {
            continue;
        };
        // 内核线程与僵尸没有可执行实体：既推不出用途，名字还会随调度漂移。
        let Some(name) = linux_process_name(pid) else {
            continue;
        };
        let (identity, identity_unavailable) = match process_identity(pid) {
            Ok(identity) => (identity, false),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) =>
            {
                (None, true)
            }
            Err(err) => return Err(err),
        };
        processes.push(ObservedProcess {
            pid,
            identity,
            name: Some(name),
            identity_unavailable,
        });
    }
    Ok(processes)
}

/// 取进程的可执行标识：优先 `/proc/<pid>/exe` 的**完整路径**。
///
/// 为什么不再用 `comm`：它是 15 字符截断的 basename（`victoria-logs-p` 这种），
/// 既会撞名也会丢路径 —— 而 `process_path` 类规则（`/opt/homebrew`、`/Docker.app`…）
/// 要的正是路径。
///
/// 返回 `None` = 这条 `/proc` 记录没有可执行实体（内核线程 / 僵尸），整条跳过：
/// 内核线程的名字还会随工作队列绑定漂移（`kworker/0:1-cgroup_destroy`），
/// 把它们放进事实只会让内容摘要永远不稳定。
#[cfg(target_os = "linux")]
fn linux_process_name(pid: u32) -> Option<String> {
    match fs::read_link(format!("/proc/{pid}/exe")) {
        Ok(path) => Some(path.to_string_lossy().into_owned()),
        // 内核线程与僵尸都没有 `exe` 链接（ENOENT）。内核线程的 cmdline 也是空，
        // 两者都会被 `first_cmdline_arg` 判成 None；真出现「无 exe 但有 argv」仍按 argv 保留。
        Err(err) if err.kind() == io::ErrorKind::NotFound => read_cmdline_argv(pid),
        // 读不到别人的 `exe`（权限）不等于不存在：退回 argv，再退回 comm。
        Err(_) => read_cmdline_argv(pid).or_else(|| read_process_comm(pid)),
    }
}

#[cfg(target_os = "linux")]
fn read_cmdline_argv(pid: u32) -> Option<String> {
    let content = fs::read(format!("/proc/{pid}/cmdline")).ok()?;
    first_cmdline_arg(&content)
}

/// 取 `argv[0]`：`/proc/<pid>/cmdline` 是 NUL 分隔的字节串，内核线程与僵尸是空文件。
///
/// `cfg` 带上 `test` 是为了在 macOS 上也能单测这个纯函数（生产构建里它只在 Linux 存在）。
#[cfg(any(target_os = "linux", test))]
fn first_cmdline_arg(content: &[u8]) -> Option<String> {
    let first = content.split(|byte| *byte == 0).next()?;
    let value = String::from_utf8_lossy(first).trim().to_string();
    (!value.is_empty()).then_some(value)
}

#[cfg(target_os = "linux")]
fn read_process_comm(pid: u32) -> Option<String> {
    fs::read_to_string(format!("/proc/{pid}/comm"))
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

#[cfg(all(unix, not(target_os = "linux")))]
fn list_processes() -> io::Result<Vec<ObservedProcess>> {
    let output = Command::new("ps").args(["-axo", "pid=,comm="]).output()?;
    if !output.status.success() {
        return Err(io::Error::other("ps did not exit successfully"));
    }

    let stdout = String::from_utf8_lossy(&output.stdout);
    let mut processes = Vec::new();
    for line in stdout.lines() {
        let Some((pid, name)) = parse_unix_ps_process_line(line) else {
            continue;
        };
        let (identity, identity_unavailable) = match process_identity(pid) {
            Ok(identity) => (identity, false),
            Err(err)
                if matches!(
                    err.kind(),
                    io::ErrorKind::PermissionDenied | io::ErrorKind::NotFound
                ) =>
            {
                (None, true)
            }
            Err(err) => return Err(err),
        };
        processes.push(ObservedProcess {
            pid,
            identity,
            name,
            identity_unavailable,
        });
    }
    Ok(processes)
}

#[cfg(all(unix, not(target_os = "linux")))]
fn parse_unix_ps_process_line(line: &str) -> Option<(u32, Option<String>)> {
    let trimmed = line.trim();
    if trimmed.is_empty() {
        return None;
    }
    let first_non_pid = trimmed.find(char::is_whitespace).unwrap_or(trimmed.len());
    let pid_text = &trimmed[..first_non_pid];
    let pid = pid_text.parse::<u32>().ok()?;
    let name = trimmed[first_non_pid..].trim();
    let name = if name.is_empty() {
        None
    } else {
        Some(name.to_string())
    };
    Some((pid, name))
}

#[cfg(not(unix))]
fn list_processes() -> io::Result<Vec<ObservedProcess>> {
    Ok(Vec::new())
}

#[cfg(test)]
mod tests {
    use super::ObservedProcess;
    #[cfg(any(target_os = "linux", test))]
    use super::first_cmdline_arg;
    #[cfg(all(unix, not(target_os = "linux")))]
    use super::parse_unix_ps_process_line;

    #[test]
    fn first_cmdline_arg_stops_at_the_first_nul() {
        assert_eq!(
            first_cmdline_arg(b"/usr/sbin/nginx\0-g\0daemon off;\0"),
            Some("/usr/sbin/nginx".to_string())
        );
        // 内核线程 / 僵尸：空文件，或第一个参数就是空串。
        assert_eq!(first_cmdline_arg(b""), None);
        assert_eq!(first_cmdline_arg(b"\0later-arg\0"), None);
    }

    /// Linux 侧的可执行标识必须是**路径**（`process_path` 规则与网关资产清单都靠它）。
    #[cfg(target_os = "linux")]
    #[test]
    fn own_process_has_an_absolute_executable_path() {
        let name = super::linux_process_name(std::process::id()).expect("own process");
        assert!(name.starts_with('/'), "not a path: {name}");
    }

    #[test]
    fn process_identity_uses_identity_when_present() {
        let observed = ObservedProcess {
            pid: 42,
            identity: Some("linux_proc_start:123".to_string()),
            name: Some("demo".to_string()),
            identity_unavailable: false,
        };

        assert_eq!(
            observed.resource_id("host-1"),
            "host-1:pid:42:linux_proc_start:123"
        );
        assert_eq!(
            observed.target_id("host-1"),
            "host-1:pid:42:linux_proc_start:123:process"
        );
    }

    #[test]
    fn process_identity_falls_back_to_pid_when_missing() {
        let observed = ObservedProcess {
            pid: 42,
            identity: None,
            name: Some("demo".to_string()),
            identity_unavailable: false,
        };

        assert_eq!(observed.resource_id("host-1"), "host-1:pid:42");
        assert_eq!(observed.target_id("host-1"), "host-1:pid:42:process");
    }

    #[cfg(all(unix, not(target_os = "linux")))]
    #[test]
    fn parse_unix_ps_process_line_keeps_command_with_spaces() {
        let parsed = parse_unix_ps_process_line(
            "123 /Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook",
        );

        assert_eq!(
            parsed,
            Some((
                123,
                Some(
                    "/Applications/Microsoft Outlook.app/Contents/MacOS/Microsoft Outlook"
                        .to_string(),
                ),
            ))
        );
    }
}
