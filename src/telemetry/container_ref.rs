//! 从容器日志的**文件路径**反推「这条来自哪个容器」。
//!
//! 为什么在采集端做：k8s 侧的 pod / namespace / container 编码在**文件名**里
//! （`<pod>_<ns>_<container>-<id>.log`），而 Docker 侧文件名只有容器 id ——
//! 名字与镜像只在同目录的 `config.v2.json` 里。没有它，数据面只能看到一串 64 位十六进制。
//!
//! 边界很清楚：**只读元数据，不碰正文**。正文仍原样上送，解码归数据面
//! （见 `doc/design/center/docker-container-logs.md`）。
//!
//! 为什么不调 docker CLI / socket：读文件不需要 socket、不受 dockerd 重启影响，
//! 也不会在容器“创建中”时拿到空名字；而且日志目录与配置目录本来就是同一处。

use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Mutex, OnceLock};
use std::time::SystemTime;

use serde::Deserialize;
use wist_contracts::telemetry_record::ContainerRef;

/// 从容器日志路径反推身份；不是 Docker 容器目录、或配置读不出来时返回 `None`。
///
/// 识别方式是**路径形状**（`<root>/containers/<id>/<file>`），不写死 `/var/lib/docker`：
/// 改过 `data-root` 的现场照样能认。是否真是 Docker 目录，最终由 `config.v2.json` 是否存在决定。
pub fn for_source_path(path: &str) -> Option<ContainerRef> {
    let parts: Vec<&str> = path.split('/').filter(|part| !part.is_empty()).collect();
    // 从后往前找 `containers`：名字里带 containers 的目录不该被误认。
    let index = parts.iter().rposition(|part| *part == "containers")?;
    let id = parts.get(index + 1)?;
    // 至少得还有一层文件（`<root>/containers/<id>/<file>`）。
    if index + 2 >= parts.len() || id.is_empty() {
        return None;
    }
    let config = format!("/{}/{}/config.v2.json", parts[..=index].join("/"), id);
    resolve(&config, id)
}

/// `config.v2.json` 里我们关心的两处。Docker 的键是 `Name` / `Config.Image`（大小写敏感）。
#[derive(Deserialize)]
struct ConfigV2 {
    #[serde(rename = "Name", default)]
    name: String,
    #[serde(rename = "Config", default)]
    config: Option<ContainerConfig>,
}

#[derive(Deserialize)]
struct ContainerConfig {
    #[serde(rename = "Image", default)]
    image: String,
}

struct CacheEntry {
    modified: Option<SystemTime>,
    len: u64,
    value: Option<ContainerRef>,
}

fn cache() -> &'static Mutex<HashMap<PathBuf, CacheEntry>> {
    static CACHE: OnceLock<Mutex<HashMap<PathBuf, CacheEntry>>> = OnceLock::new();
    CACHE.get_or_init(|| Mutex::new(HashMap::new()))
}

/// 读 `<id>/config.v2.json` 并解析，按 (mtime, size) 缓存。
///
/// 缓存的意义：每轮每文件都会问一次，而容器配置几乎不变；容器重建时 mtime/size 会变，
/// 自然失效（id 也变了，本来就是一个新键）。
fn resolve(config: &str, id: &str) -> Option<ContainerRef> {
    let path = PathBuf::from(config);
    let metadata = std::fs::metadata(&path).ok()?;
    let modified = metadata.modified().ok();
    let len = metadata.len();
    if let Ok(guard) = cache().lock()
        && let Some(entry) = guard.get(&path)
        && entry.modified == modified
        && entry.len == len
    {
        return entry.value.clone();
    }

    let value = std::fs::read(&path)
        .ok()
        .and_then(|bytes| serde_json::from_slice::<ConfigV2>(&bytes).ok())
        .and_then(|parsed| {
            // `Name` 形如 `/mysql`：去掉前导 `/` 才是容器名。
            let name = parsed.name.trim_start_matches('/').to_string();
            if name.is_empty() {
                return None;
            }
            let image = parsed.config.map(|config| config.image).unwrap_or_default();
            Some(ContainerRef {
                name,
                image,
                id: id.to_string(),
            })
        });

    if let Ok(mut guard) = cache().lock() {
        // 上限只是防御：容器数量不可能无限增长（重建会换 id，旧键留着也无害）。
        if guard.len() > 1024 {
            guard.clear();
        }
        guard.insert(
            path,
            CacheEntry {
                modified,
                len,
                value: value.clone(),
            },
        );
    }
    value
}

#[cfg(test)]
mod tests {
    use super::for_source_path;
    use std::fs;
    use std::path::{Path, PathBuf};

    fn temp_dir(name: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("wist-container-ref-{name}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    fn write_config(root: &Path, id: &str, name: &str, image: &str) -> String {
        let dir = root.join("containers").join(id);
        fs::create_dir_all(&dir).unwrap();
        let config = format!(
            r#"{{"ID":"{id}","Name":"/{name}","Config":{{"Image":"{image}","Env":["A=1"]}}}}"#
        );
        fs::write(dir.join("config.v2.json"), config).unwrap();
        let log = dir.join(format!("{id}-json.log"));
        fs::write(&log, "{\"log\":\"x\\n\"}\n").unwrap();
        log.display().to_string()
    }

    #[test]
    fn reads_name_and_image_from_config_v2() {
        let root = temp_dir("basic");
        let id = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        let path = write_config(&root, id, "mysql", "bitnami/mysql:8.0");
        let found = for_source_path(&path).expect("container");
        assert_eq!(found.name, "mysql");
        assert_eq!(found.image, "bitnami/mysql:8.0");
        assert_eq!(found.id, id);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn non_docker_paths_are_ignored() {
        // 普通文件、以及“名字里带 containers 但形状不对”的路径，都不该被认成容器。
        assert!(for_source_path("/var/log/auth.log").is_none());
        assert!(for_source_path("/srv/containers").is_none());
        assert!(for_source_path("/srv/containers/only-one-segment").is_none());
        assert!(for_source_path("/var/log/containers/x_probe_0/not-a-log").is_none());
    }

    #[test]
    fn a_missing_or_broken_config_yields_none_without_panicking() {
        let root = temp_dir("broken");
        let id = "aaaa";
        let dir = root.join("containers").join(id);
        fs::create_dir_all(&dir).unwrap();
        let log = dir.join(format!("{id}-json.log"));
        fs::write(&log, "{}\n").unwrap();

        // 没有 config.v2.json。
        assert!(for_source_path(&log.display().to_string()).is_none());
        // 有但坏了。
        fs::write(dir.join("config.v2.json"), b"not json").unwrap();
        assert!(for_source_path(&log.display().to_string()).is_none());
        // 有 JSON 但没有名字。
        fs::write(dir.join("config.v2.json"), br#"{"ID":"aaaa"}"#).unwrap();
        assert!(for_source_path(&log.display().to_string()).is_none());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn a_recreated_container_with_the_same_name_keeps_the_name_and_changes_the_id() {
        let root = temp_dir("recreated");
        let first = write_config(&root, "1111", "mysql", "bitnami/mysql:8.0");
        assert_eq!(for_source_path(&first).unwrap().id, "1111");
        let second = write_config(&root, "2222", "mysql", "bitnami/mysql:8.1");
        let found = for_source_path(&second).unwrap();
        assert_eq!(found.name, "mysql");
        assert_eq!(found.id, "2222");
        assert_eq!(found.image, "bitnami/mysql:8.1");
        let _ = fs::remove_dir_all(&root);
    }
}
