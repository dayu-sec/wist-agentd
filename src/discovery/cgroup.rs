//! `/proc/<pid>/cgroup` → 容器 id。
//!
//! 端点探针和进程探针都需要回答「这个 pid 在哪个容器里」：前者用来标注监听端口的容器归属，
//! 后者用来把容器化进程（包括不监听端口的）挂到容器上。判定规则只该有一份，
//! 所以从端点探针里抽出来放这里。

#[cfg(target_os = "linux")]
use std::fs;

/// 进程的 cgroup 路径。
///
/// `/proc/<pid>/cgroup` 每行是 `hierarchy-id:controller-list:path`；cgroup v1 有多行，
/// 优先取「路径里能认出容器 id」的那一行，否则退回第一个非根路径。
#[cfg(target_os = "linux")]
pub(crate) fn process_cgroup_path(pid: u32) -> Option<String> {
    let content = fs::read_to_string(format!("/proc/{pid}/cgroup")).ok()?;
    cgroup_path_from_proc_content(&content)
}

#[cfg(any(target_os = "linux", test))]
fn cgroup_path_from_proc_content(content: &str) -> Option<String> {
    let paths: Vec<_> = content
        .lines()
        .filter_map(|line| line.rsplit_once(':').map(|(_, path)| path.trim()))
        .filter(|path| !path.is_empty() && *path != "/")
        .collect();
    paths
        .iter()
        .find(|path| container_id_from_cgroup_path(path).is_some())
        .or_else(|| paths.first())
        .map(|path| (*path).to_string())
}

/// 进程所属的容器 id。拿不到（不在容器里 / 读不到 cgroup）时返回 `None`。
#[cfg(target_os = "linux")]
pub(crate) fn process_container_id(pid: u32) -> Option<String> {
    process_cgroup_path(pid)
        .as_deref()
        .and_then(container_id_from_cgroup_path)
}

/// 从 cgroup 路径里认出容器 id。
///
/// 从后往前找第一段像容器 id 的：`cri-containerd-<id>.scope` / `docker-<id>.scope` /
/// `crio-<id>.scope` 是常见的三种写法，裸的 `/k8s.io/<id>` 也要认。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn container_id_from_cgroup_path(path: &str) -> Option<String> {
    path.split(['/', ':'])
        .rev()
        .find_map(container_id_from_cgroup_segment)
}

#[cfg(any(target_os = "linux", test))]
fn container_id_from_cgroup_segment(segment: &str) -> Option<String> {
    let trimmed = segment.trim().trim_end_matches(".scope");
    for prefix in ["cri-containerd-", "docker-", "crio-"] {
        if let Some(value) = trimmed.strip_prefix(prefix) {
            return valid_container_id(value);
        }
    }
    valid_container_id(trimmed)
}

/// 容器 id 是一段**完整的**十六进制串（sha256），至少 12 位。
///
/// 只认整段、不认前缀：`/system.slice/123456789012-backup.service` 这种数字开头的
/// 单元名也有 12 位十六进制前缀。端点探针里误判只多一条容器的边，
/// 到了进程探针就是「整台机的进程都挂到一个不存在的容器上」—— 必须收紧。
///
/// 顺便归一成小写：容器探针报的是运行时目录名（规范里是小写），
/// cgroup 里偶尔出现大写时不该被当成另一个容器。
#[cfg(any(target_os = "linux", test))]
fn valid_container_id(value: &str) -> Option<String> {
    if value.len() < 12 || !value.chars().all(|ch| ch.is_ascii_hexdigit()) {
        return None;
    }
    Some(value.to_ascii_lowercase())
}

#[cfg(test)]
mod tests {
    use super::{cgroup_path_from_proc_content, container_id_from_cgroup_path};

    #[test]
    fn containerd_scope_yields_the_container_id() {
        let path = "/kubepods.slice/kubepods-burstable.slice/kubepods-burstable-pod123.slice/cri-containerd-3f2c9f3c1b8e4a1d.scope";
        assert_eq!(
            container_id_from_cgroup_path(path).as_deref(),
            Some("3f2c9f3c1b8e4a1d")
        );
    }

    #[test]
    fn docker_scope_and_bare_task_dir_are_recognized() {
        assert_eq!(
            container_id_from_cgroup_path("/system.slice/docker-7a1b2c3d4e5f6a7b.scope").as_deref(),
            Some("7a1b2c3d4e5f6a7b")
        );
        assert_eq!(
            container_id_from_cgroup_path("/k8s.io/abcdef1234567890").as_deref(),
            Some("abcdef1234567890")
        );
    }

    #[test]
    fn ordinary_slices_are_not_containers() {
        assert_eq!(container_id_from_cgroup_path("/"), None);
        assert_eq!(
            container_id_from_cgroup_path("/user.slice/user-1000.slice/session-2.scope"),
            None
        );
        // 短 hex 只是名字，不是容器 id。
        assert_eq!(
            container_id_from_cgroup_path("/system.slice/deadbeef"),
            None
        );
    }

    #[test]
    fn a_numeric_leading_unit_name_is_not_a_container() {
        // 数字开头的 systemd 单元名也有 12 位十六进制前缀 —— 只认前缀的话，
        // 进程探针会把整台主机的进程都挂到这个「容器」上。
        assert_eq!(
            container_id_from_cgroup_path("/system.slice/123456789012-backup.service"),
            None
        );
        assert_eq!(
            container_id_from_cgroup_path("/system.slice/abcdef1234567890.scope"),
            Some("abcdef1234567890".to_string())
        );
    }

    #[test]
    fn uppercase_hex_is_normalized_to_lowercase() {
        // 运行时目录名是小写；cgroup 里出现大写时不该被当成另一个容器。
        assert_eq!(
            container_id_from_cgroup_path("/system.slice/docker-ABCDEF123456.scope"),
            Some("abcdef123456".to_string())
        );
    }

    #[test]
    fn cgroup_v1_multi_line_content_prefers_the_container_path() {
        let content = "12:cpuset:/\n11:memory:/docker/3f2c9f3c1b8e\n1:name=systemd:/user.slice\n";
        assert_eq!(
            cgroup_path_from_proc_content(content).as_deref(),
            Some("/docker/3f2c9f3c1b8e")
        );
    }

    #[test]
    fn a_non_container_process_falls_back_to_the_first_path() {
        let content = "0::/user.slice/user-1000.slice/session-2.scope\n";
        assert_eq!(
            cgroup_path_from_proc_content(content).as_deref(),
            Some("/user.slice/user-1000.slice/session-2.scope")
        );
    }
}
