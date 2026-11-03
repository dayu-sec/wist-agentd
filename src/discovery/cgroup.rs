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

/// 进程所属的 **systemd 单元**（已归一：去掉 `.service` 等类型后缀、小写）。
///
/// **保留 `@实例`**（`kafka@broker-1`）：实例名里带的是部署者写的角色词（`broker`），
/// 那是 `role` 推断的输入；抹掉它，网关就再也分不出 broker 与 controller。
/// 「哪个 app」由网关按模板名比对（`kafka@broker-1` → `kafka`），两边各取所需。
///
/// 为什么不 fork `systemctl`：每个进程的 cgroup 路径里就有单元名
/// （`/system.slice/kafka.service`、`/user.slice/.../app.slice/foo.service`），
/// 而进程探针本来就在读 `/proc/<pid>`。一次 `systemctl` 子进程既慢又要额外权限，
/// 还会在每次发现 tick 里起一个进程。
///
/// 只认 `.service` / `.socket` / `.timer` 三类：`*.slice` 是分组（`system.slice` 本身
/// 不是服务），`.scope` 是会话/容器作用域（它的名字是容器 id，不是用途）。
#[cfg(any(target_os = "linux", test))]
pub(crate) fn unit_from_cgroup_path(path: &str) -> Option<String> {
    path.split('/').rev().find_map(|segment| {
        // 先小写再拆：cgroup 里偶尔出现大写（`Kafka.Service`），按原样比类型后缀会漏。
        let segment = segment.trim().to_ascii_lowercase();
        let (name, kind) = segment.rsplit_once('.')?;
        if !matches!(kind, "service" | "socket" | "timer") || name.is_empty() {
            return None;
        }
        Some(name.to_string())
    })
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
    use super::{
        cgroup_path_from_proc_content, container_id_from_cgroup_path, unit_from_cgroup_path,
    };

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
    fn service_units_are_read_off_the_cgroup_path() {
        // 系统服务：`/system.slice/kafka.service` → `kafka`。
        assert_eq!(
            unit_from_cgroup_path("/system.slice/kafka.service").as_deref(),
            Some("kafka")
        );
        // 用户级服务：路径更深，取最后一段。
        assert_eq!(
            unit_from_cgroup_path(
                "/user.slice/user-1000.slice/user@1000.service/app.slice/orders.service"
            )
            .as_deref(),
            Some("orders")
        );
        // 实例名**保留** `@实例`：里面的 `broker` 是 `role` 推断的输入。
        assert_eq!(
            unit_from_cgroup_path("/system.slice/kafka@broker-1.service").as_deref(),
            Some("kafka@broker-1")
        );
        // socket / timer 也是「部署者命名的单元」。
        assert_eq!(
            unit_from_cgroup_path("/system.slice/backup.timer").as_deref(),
            Some("backup")
        );
        // slice 是分组、scope 是会话/容器作用域 —— 都不是用途。
        assert_eq!(unit_from_cgroup_path("/system.slice"), None);
        assert_eq!(
            unit_from_cgroup_path("/system.slice/docker-abc123.scope"),
            None
        );
        assert_eq!(unit_from_cgroup_path(""), None);
        // 大写归一（cgroup 里偶尔有）。
        assert_eq!(
            unit_from_cgroup_path("/system.slice/Kafka.Service").as_deref(),
            Some("kafka")
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
