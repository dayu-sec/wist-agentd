//! 从**日志路径**还原 k8s 容器日志的身份（namespace / pod / pod UID / 容器 / 真实文件）。
//!
//! 与 [`crate::telemetry::container_ref`] 分工：
//!
//! * Docker 主机的文件名只有容器 id，名字 / 镜像只能去同目录的 `config.v2.json` 读；
//! * k8s 的身份**全在路径里** —— kubelet 建的两条路径：
//!   - 软链接 `/var/log/containers/<pod>_<ns>_<container>-<容器ID>.log`；
//!   - 真实文件 `/var/log/pods/<ns>_<pod>_<podUID>/<container>/0.log`（软链接指向它）。
//!
//! 所以这里**只做路径解析 + 一次 `readlink`**，不碰正文，也不查容器运行时。
//!
//! 几条口径：
//!
//! * Kubernetes 的 namespace / pod / container 名都是 DNS label，**不含下划线** ——
//!   所以按 `_` 切开是安全的（这也是 issue 里给的判据）；
//! * pod UID 不按 UUID 格式解析：静态 Pod 的 UID 可能没有连字符
//!   （如 `bbe03b0a0e4187285b53e1b7abd044b1`），劈开以后原样带走；
//! * `service` 取**容器名**，不取 pod 名：一个 pod 可以有多个容器
//!   （`wp-station` 下面还有 `wp-station-gitea` / `wp-station-bootstrap`）；
//! * 镜像不在路径里（要查容器运行时），这里留空 —— 空是可解释的事实（“没查到”）。
//!
//! `log_path` 是**真实文件**路径（软链接解析后）：`file_offset` 是对着它量的，
//! 数据面要能按同一路径回查。软链接解析不了（不是软链接 / 被换掉）时退回来源路径本身，
//! 此时 `pod_uid` 为空 —— 那确实是“不知道”，不拿 pod 目录里的猜测去填。

use std::path::{Component, Path, PathBuf};

use wist_contracts::telemetry_record::{ContainerRef, PodLogRef};

/// kubelet 现在用的容器 id 长度（64 位十六进制）。
///
/// 长度是**判据的一部分**：容器名里也会出现连字符，不钉住 id 形状就会把
/// `<container>-<一眼看像 id 的名字>` 切错。
const CONTAINER_ID_LEN: usize = 64;

/// 从来源路径还原身份；不是 k8s 容器日志路径时返回 `None`。
///
/// 两种路径形状都认（软链接目录与真实文件目录）—— 采集目录通常配 `/var/log/containers/*.log`，
/// 但人工点名 `/var/log/pods/...` 也是合法的绝对路径来源。
pub fn for_source_path(path: &str) -> Option<PodLogRef> {
    // 采集端的来源路径是绝对路径（契约要求）。相对路径的基准是进程 cwd，换个启动方式
    // 就翻面 —— 与 `container_ref` 同一个口径：不拿它猜身份。
    if !path.starts_with('/') {
        return None;
    }
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();

    if let Some(found) = from_link(&parts, path) {
        return Some(found);
    }
    from_pods_dir(&parts, path)
}

/// `/var/log/containers/<pod>_<namespace>_<container>-<id>.log`（软链接）。
fn from_link(parts: &[&str], source_path: &str) -> Option<PodLogRef> {
    let index = parts.iter().rposition(|part| *part == "containers")?;
    // 软链接目录下**直接**是文件。Docker 的 `<root>/containers/<id>/<file>` 多一层，
    // 会在这里被排除 —— 那条链路由 `container_ref` 负责。
    let file = parts.get(index + 1)?;
    if parts.len() != index + 2 {
        return None;
    }
    let (pod_name, namespace, container, id) = split_link_name(file)?;

    // 软链接的目标就是真实文件；解析不了时退回来源路径（见模块说明）。
    let log_path = resolve_link(Path::new(source_path));
    let pod_uid = pod_uid_from_pods_path(Path::new(&log_path)).unwrap_or_default();

    Some(PodLogRef {
        // 节点名是**本机**事实，由采集运行时填（这一层只认识路径）。
        node_name: String::new(),
        namespace,
        pod_name,
        pod_uid,
        service: container.clone(),
        log_path,
        container: ContainerRef {
            name: container,
            // 镜像不在路径里：查不到就是空串，其余字段仍然齐。
            image: String::new(),
            id,
        },
    })
}

/// `/var/log/pods/<ns>_<pod>_<podUID>/<container>/<n>.log`（真实文件）。
fn from_pods_dir(parts: &[&str], source_path: &str) -> Option<PodLogRef> {
    let index = parts.iter().rposition(|part| *part == "pods")?;
    let pod_dir = parts.get(index + 1)?;
    let container = parts.get(index + 2)?;
    let file = parts.get(index + 3)?;
    // 必须是“pod 目录 / 容器目录 / 文件”这一形状，不猜更深的层级。
    if parts.len() != index + 4 || !file.ends_with(".log") || container.is_empty() {
        return None;
    }
    let (namespace, pod_name, pod_uid) = split_pod_dir(pod_dir)?;
    Some(PodLogRef {
        node_name: String::new(),
        namespace,
        pod_name,
        pod_uid,
        service: container.to_string(),
        log_path: source_path.to_string(),
        container: ContainerRef {
            name: container.to_string(),
            image: String::new(),
            // 真实文件路径里没有容器 id（id 只在软链接文件名里）—— 空，不猜。
            id: String::new(),
        },
    })
}

/// `<pod>_<namespace>_<container>-<容器ID>.log` → 四段。
fn split_link_name(file: &str) -> Option<(String, String, String, String)> {
    let stem = file.strip_suffix(".log")?;
    let mut parts = stem.split('_');
    let pod_name = parts.next()?;
    let namespace = parts.next()?;
    let tail = parts.next()?;
    // 名称里不含 `_`：多出来一段说明这不是 kubelet 的命名，别硬套。
    if parts.next().is_some() || pod_name.is_empty() || namespace.is_empty() {
        return None;
    }
    // 容器名自己带连字符（`wist-center-stack-postgres`），所以从**最后一个**连字符切 id。
    let (container, id) = tail.rsplit_once('-')?;
    if container.is_empty() || !is_container_id(id) {
        return None;
    }
    Some((
        pod_name.to_string(),
        namespace.to_string(),
        container.to_string(),
        id.to_string(),
    ))
}

/// `<namespace>_<pod>_<podUID>` → 三段。UID 不校验格式：静态 Pod 的可能没有连字符。
fn split_pod_dir(dir: &str) -> Option<(String, String, String)> {
    let mut parts = dir.splitn(4, '_');
    let namespace = parts.next()?;
    let pod_name = parts.next()?;
    let pod_uid = parts.next()?;
    if parts.next().is_some() || namespace.is_empty() || pod_name.is_empty() || pod_uid.is_empty() {
        return None;
    }
    Some((
        namespace.to_string(),
        pod_name.to_string(),
        pod_uid.to_string(),
    ))
}

/// 从真实文件路径取 pod UID（`/var/log/pods/<ns>_<pod>_<uid>/...`）；不是这个形状就 `None`。
fn pod_uid_from_pods_path(path: &Path) -> Option<String> {
    let parts: Vec<&str> = path
        .to_str()?
        .split('/')
        .filter(|part| !part.is_empty())
        .collect();
    let index = parts.iter().rposition(|part| *part == "pods")?;
    let (_, _, pod_uid) = split_pod_dir(parts.get(index + 1)?)?;
    Some(pod_uid)
}

/// 软链接 → 目标路径（相对目标按链接所在目录展开）；读不到就是路径本身。
///
/// 展开后做**词法**规范化（折叠 `.` / `..`）：目标可能暂时不存在，所以不用 `canonicalize`；
/// 但 `log_path` 要能被数据面按路径回查，不能挂着 `../`。
fn resolve_link(path: &Path) -> String {
    let Ok(target) = std::fs::read_link(path) else {
        return path.display().to_string();
    };
    let joined = if target.is_absolute() {
        target
    } else {
        match path.parent() {
            Some(parent) => parent.join(target),
            None => target,
        }
    };
    normalize_lexically(&joined).display().to_string()
}

/// 只折叠 `.` / `..`，不碰文件系统（不要求目标存在）。
fn normalize_lexically(path: &Path) -> PathBuf {
    let mut out = PathBuf::new();
    for component in path.components() {
        match component {
            // 根目录的 `..` 不越过根（`PathBuf::pop` 在 `/` 上返回 false，正好）。
            Component::ParentDir => {
                out.pop();
            }
            Component::CurDir => {}
            other => out.push(other),
        }
    }
    out
}

/// 64 位十六进制；大小写都认（运行时之间不统一）。
fn is_container_id(value: &str) -> bool {
    value.len() == CONTAINER_ID_LEN && value.bytes().all(|byte| byte.is_ascii_hexdigit())
}

#[cfg(test)]
mod tests {
    use super::for_source_path;
    use std::fs;
    use std::path::{Path, PathBuf};

    const ID: &str = "ca018a1ea97ad12934aa236df87fc3c2816ea70c41a07134b1f3298c9d73e217";
    const POD_DIR: &str = "default_doriscluster-helm-ms-2_98af449f-af1b-4a19-8f82-f5f82a198794";

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wist-pod-log-ref-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// 造一棵 kubelet 形状的目录：`.../pods/<pod_dir>/<container>/0.log`，
    /// 软链接放在同级的 `containers/` 下（与现场一致）。
    fn write_kubelet_layout(root: &Path, container: &str, link_name: &str) -> (PathBuf, PathBuf) {
        let real_dir = root.join("pods").join(POD_DIR).join(container);
        fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("0.log");
        fs::write(&real, "line\n").unwrap();
        let links = root.join("containers");
        fs::create_dir_all(&links).unwrap();
        let link = links.join(link_name);
        #[cfg(unix)]
        std::os::unix::fs::symlink(&real, &link).unwrap();
        (real, link)
    }

    #[cfg(unix)]
    #[test]
    fn reads_the_whole_identity_from_the_symlink_name_and_its_target() {
        // issue 里的 Meta Service 样本。
        let root = temp_dir("symlink");
        let link_name = format!("doriscluster-helm-ms-2_default_metaservice-{ID}.log");
        let (real, link) = write_kubelet_layout(&root, "metaservice", &link_name);

        let found = for_source_path(&link.display().to_string()).expect("identity");
        assert_eq!(found.namespace, "default");
        assert_eq!(found.pod_name, "doriscluster-helm-ms-2");
        assert_eq!(found.pod_uid, "98af449f-af1b-4a19-8f82-f5f82a198794");
        assert_eq!(found.service, "metaservice");
        assert_eq!(found.log_path, real.display().to_string());
        assert_eq!(found.container.name, "metaservice");
        assert_eq!(found.container.id, ID);
        assert_eq!(found.container.image, "", "镜像不在路径里");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_container_name_with_hyphens_is_not_split_at_the_first_hyphen() {
        let root = temp_dir("hyphen");
        let link_name =
            format!("wp-station-77984b4b6f-hszhg_wp_wist-center-stack-postgres-{ID}.log");
        let (_, link) = write_kubelet_layout(&root, "wist-center-stack-postgres", &link_name);

        let found = for_source_path(&link.display().to_string()).expect("identity");
        assert_eq!(found.pod_name, "wp-station-77984b4b6f-hszhg");
        assert_eq!(found.namespace, "wp");
        assert_eq!(found.service, "wist-center-stack-postgres");
        assert_eq!(found.container.name, "wist-center-stack-postgres");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_static_pod_uid_without_hyphens_is_kept_verbatim() {
        let root = temp_dir("static");
        let pod_dir = "kube-system_etcd-ent-bas-warpaxis-01_bbe03b0a0e4187285b53e1b7abd044b1";
        let real_dir = root.join("pods").join(pod_dir).join("etcd");
        fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("0.log");
        fs::write(&real, "line\n").unwrap();
        let links = root.join("containers");
        fs::create_dir_all(&links).unwrap();
        let link = links.join(format!(
            "etcd-ent-bas-warpaxis-01_kube-system_etcd-{ID}.log"
        ));
        std::os::unix::fs::symlink(&real, &link).unwrap();

        let found = for_source_path(&link.display().to_string()).expect("identity");
        assert_eq!(found.namespace, "kube-system");
        assert_eq!(found.pod_name, "etcd-ent-bas-warpaxis-01");
        assert_eq!(
            found.pod_uid, "bbe03b0a0e4187285b53e1b7abd044b1",
            "不按 UUID 格式解析"
        );
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_relative_symlink_target_is_expanded_and_normalized() {
        // kubelet 也可能建相对链接（`../pods/...`）：`log_path` 不能挂着 `../`。
        let root = temp_dir("relative-link");
        let real_dir = root.join("pods").join(POD_DIR).join("metaservice");
        fs::create_dir_all(&real_dir).unwrap();
        let real = real_dir.join("0.log");
        fs::write(&real, "line\n").unwrap();
        let links = root.join("containers");
        fs::create_dir_all(&links).unwrap();
        let link = links.join(format!("pod_ns_metaservice-{ID}.log"));
        std::os::unix::fs::symlink(
            "../pods/./".to_string() + POD_DIR + "/metaservice/0.log",
            &link,
        )
        .unwrap();

        let found = for_source_path(&link.display().to_string()).expect("identity");
        assert_eq!(found.log_path, real.display().to_string());
        assert_eq!(found.pod_uid, "98af449f-af1b-4a19-8f82-f5f82a198794");
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_pod_name_with_dots_and_an_upper_case_id_are_kept_verbatim() {
        // pod 名是 DNS subdomain，可以带 `.`；容器 id 大小写都不做改写。
        let root = temp_dir("dotted");
        let upper = ID.to_uppercase();
        let link_name = format!("otel-agent.v2_default_sidecar-{upper}.log");
        let (_, link) = write_kubelet_layout(&root, "sidecar", &link_name);

        let found = for_source_path(&link.display().to_string()).expect("identity");
        assert_eq!(found.pod_name, "otel-agent.v2");
        assert_eq!(found.container.id, upper);
        let _ = fs::remove_dir_all(&root);
    }

    #[cfg(unix)]
    #[test]
    fn a_regular_file_with_a_kubelet_name_still_yields_what_the_name_proves() {
        // 有人把容器日志拷到 `containers/` 下（不是软链接）：名字能证明的照给，
        // `pod_uid` 留空、`log_path` 就是它自己。
        let root = temp_dir("regular");
        let links = root.join("containers");
        fs::create_dir_all(&links).unwrap();
        let file = links.join(format!("pod_ns_metaservice-{ID}.log"));
        fs::write(&file, "line\n").unwrap();

        let found = for_source_path(&file.display().to_string()).expect("identity");
        assert_eq!(found.pod_uid, "");
        assert_eq!(found.log_path, file.display().to_string());
        assert_eq!(found.container.id, ID);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_malformed_pods_directory_is_not_guessed() {
        for path in [
            // pod 目录不是三段（多一个下划线）：不硬拆。
            "/var/log/pods/default_pod_extra_uid/ctr/0.log",
            // 缺容器层。
            "/var/log/pods/default_pod_uid/0.log",
            // 更深的层级不是 kubelet 的形状。
            "/var/log/pods/default_pod_uid/ctr/sub/0.log",
        ] {
            assert!(for_source_path(path).is_none(), "{path}");
        }
    }

    #[test]
    fn a_real_pods_path_is_understood_even_without_the_container_id() {
        let path = format!("/var/log/pods/{POD_DIR}/metaservice/0.log");
        let found = for_source_path(&path).expect("identity");
        assert_eq!(found.namespace, "default");
        assert_eq!(found.pod_name, "doriscluster-helm-ms-2");
        assert_eq!(found.pod_uid, "98af449f-af1b-4a19-8f82-f5f82a198794");
        assert_eq!(found.service, "metaservice");
        assert_eq!(found.log_path, path, "本身就是真实文件");
        assert_eq!(found.container.id, "", "路径里没有 id，不能猜");
    }

    #[test]
    fn non_kubelet_paths_are_ignored() {
        for path in [
            "/var/log/auth.log",
            // Docker 的容器目录：多一层 id 目录，交给 `container_ref`。
            "/var/lib/docker/containers/0123/0123-json.log",
            // 形状不对的软链接名（缺 namespace / 缺 id / id 不是 64 位十六进制）。
            "/var/log/containers/only-one-segment.log",
            "/var/log/containers/pod_ns_container-not-hex.log",
            "/var/log/containers/pod_ns_container-0123.log",
            "/var/log/containers/pod_a_b_c-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.log",
            // 相对路径的基准是进程 cwd，不能当身份。
            "var/log/containers/pod_ns_container-0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef.log",
        ] {
            assert!(for_source_path(path).is_none(), "{path}");
        }
    }

    #[cfg(unix)]
    #[test]
    fn a_link_whose_target_is_missing_still_yields_what_the_name_proves() {
        // 软链接被换掉 / 目标暂时读不到：名字能证明的部分照给，`log_path` 退回链接路径，
        // `pod_uid` 留空 —— 不拿目录里别的 pod 去猜。
        let root = temp_dir("dangling");
        let links = root.join("containers");
        fs::create_dir_all(&links).unwrap();
        let link = links.join(format!("pod_ns_container-{ID}.log"));
        std::os::unix::fs::symlink(root.join("pods/missing/0.log"), &link).unwrap();

        let found = for_source_path(&link.display().to_string()).expect("identity");
        assert_eq!(found.namespace, "ns");
        assert_eq!(found.pod_name, "pod");
        assert_eq!(found.pod_uid, "");
        assert_eq!(found.container.id, ID);
        let _ = fs::remove_dir_all(&root);
    }
}
