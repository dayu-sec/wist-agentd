//! 文件族目标解析：显式路径 / 目录 / glob。
//!
//! 约束（见 `log-file-input-spec.md` 与 W1 方案）：
//! - 只支持**绝对路径**；`~` 不展开；
//! - `*` 不跨目录（`GlobBuilder::literal_separator(true)`），不支持 `**`；
//! - 只扫 pattern 的**固定前缀目录**，按剩余组件逐层 `read_dir`，深度 = 剩余组件数；
//! - 目录目标 = 该目录下**直接子文件**（不递归）；
//! - pattern 无匹配不是失败；目录不可读是失败（`Err`）；
//! - 符号链接在最终判定时**跟随**（容器日志的 `/var/log/containers/*.log` 就是 symlink）。
//!
//! 上限：`max_paths` 是**扫描**上限（不是跟踪上限）。超过上限时留下哪几条取决于
//! `read_dir` 顺序（未定义）—— 但这不会丢文件：每轮重扫会换一批，最终都会进跟踪集。

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};

use globset::{GlobBuilder, GlobMatcher};
use wist_contracts::work::ContainerFilters;

/// 一次解析的结果。
///
/// `deselected` 里放的是「**目标匹配上了、但被选择层剔掉**」的现存路径。它存在的理由：
/// 策展人收紧 `filters` / `exclude_globs` 后，已跟踪的容器日志必须**立刻停读** ——
/// 这类文件持续增长，靠“排空到 EOF”永远排不完，现场表现就是「取消了选择却还在采」。
/// 而轮转/删除后的旧名字不会出现在枚举结果里，所以不会误伤原有的排空逻辑。
#[derive(Debug)]
pub(super) struct FamilySelection {
    pub selected: Vec<PathBuf>,
    pub deselected: BTreeSet<String>,
}

impl FamilySelection {
    /// 本轮没有扫描（不到重扫间隔）：两者都空。
    pub fn none() -> Self {
        Self {
            selected: Vec::new(),
            deselected: BTreeSet::new(),
        }
    }
}

/// 解析一个文件族目标。
///
/// `filters` 在**发现阶段**求值（展开 → 剔 exclude → 剔 filters），读取器不参与：
/// 它只决定“哪些文件进工作集”，不影响 tail / checkpoint / 轮转。
pub(super) async fn resolve_family_paths(
    target: &Path,
    exclude_globs: &[String],
    filters: &ContainerFilters,
    max_paths: usize,
) -> io::Result<FamilySelection> {
    let target_text = target.display().to_string();
    if target_text.contains("**") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recursive glob `**` is not supported",
        ));
    }
    // 选择层（排除项 + 结构化过滤器）在**收集时**求值：`max_paths` 必须只数“留下的”。
    //
    // 否则目录里候选很多时会先被截断、再被过滤 —— 留下的可能远少于上限（甚至为空），
    // 而“超过上限”又被当成正常状态，没人会发现少采了。
    let excludes = if exclude_globs.is_empty() {
        Vec::new()
    } else {
        compile_excludes(exclude_globs)?
    };
    let rejected = std::sync::Mutex::new(BTreeSet::new());
    let keep = |path: &Path| {
        let selected = !excludes.iter().any(|matcher| matcher.is_match(path))
            && container_filters_keep(filters, path);
        if !selected {
            rejected
                .lock()
                .expect("deselected set")
                .insert(path.display().to_string());
        }
        selected
    };
    let selected = if !has_glob(&target_text) {
        resolve_explicit_or_dir(target, max_paths, &keep).await?
    } else {
        resolve_glob(&target_text, max_paths, &keep).await?
    };
    Ok(FamilySelection {
        selected,
        deselected: rejected.into_inner().expect("deselected set"),
    })
}

/// 容器日志文件名 `<pod>_<namespace>_<container>-<id>.log` 里选源要用的部分。
///
/// 为什么能无歧义解析：kubelet 在 `/var/log/containers/` 下为每个活容器放一条 symlink，
/// pod / namespace / container 三段都是 RFC1123 label（**不含 `_`**），而 container id
/// 是不带 `-` 的十六进制串 —— 所以「从右切最后一个 `-` 拿 id，剩下的按 `_` 切三段」。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct ContainerLogName<'a> {
    pod: &'a str,
    namespace: &'a str,
}

fn parse_container_log_name(path: &Path) -> Option<ContainerLogName<'_>> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".log")?;
    let (head, id) = stem.rsplit_once('-')?;
    if id.is_empty() {
        return None;
    }
    let mut parts = head.splitn(3, '_');
    let pod = parts.next()?;
    let namespace = parts.next()?;
    let _container = parts.next()?;
    if pod.is_empty() || namespace.is_empty() {
        return None;
    }
    Some(ContainerLogName { pod, namespace })
}

/// 过滤器求值：空过滤器 = 全收；非空时**名字不符约定的一律不收**。
///
/// “不符约定”不是故障：`filters` 只在容器选源（`/var/log/containers`）上合法，
/// 网关装载期已经约束目标；这里只是不把解析不了的条目当作候选。
fn container_filters_keep(filters: &ContainerFilters, path: &Path) -> bool {
    if filters.is_empty() {
        return true;
    }
    let Some(name) = parse_container_log_name(path) else {
        return false;
    };
    if !filters.namespace_in.is_empty()
        && !filters
            .namespace_in
            .iter()
            .any(|namespace| namespace == name.namespace)
    {
        return false;
    }
    !filters.pod_not_in.iter().any(|pod| pod == name.pod)
}

/// 目标里有没有 glob 元字符。
pub(super) fn has_glob(target: &str) -> bool {
    target.contains(['*', '?', '['])
}

/// 目录或显式文件（两者都不含 glob 元字符）。
async fn resolve_explicit_or_dir(
    target: &Path,
    max_paths: usize,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<Vec<PathBuf>> {
    match tokio::fs::metadata(target).await {
        Ok(metadata) if metadata.is_dir() => list_dir_files(target, max_paths, keep).await,
        Ok(_) if keep(target) => Ok(vec![target.to_path_buf()]),
        Ok(_) => Ok(Vec::new()),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// 目录下的**直接子文件**（跟随 symlink；不递归）。
async fn list_dir_files(
    dir: &Path,
    max_paths: usize,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<Vec<PathBuf>> {
    let mut out = BTreeSet::new();
    let mut entries = tokio::fs::read_dir(dir).await?;
    while let Some(entry) = entries.next_entry().await? {
        if out.len() >= max_paths {
            break;
        }
        let path = entry.path();
        // 跟随 symlink；断链 / 无权限的单条目跳过，不拖垮整个目录。
        if let Ok(metadata) = tokio::fs::metadata(&path).await
            && metadata.is_file()
            && keep(&path)
        {
            out.insert(path);
        }
    }
    Ok(out.into_iter().collect())
}

/// 按 pattern 的固定前缀逐层展开。
async fn resolve_glob(
    pattern: &str,
    max_paths: usize,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<Vec<PathBuf>> {
    let components: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let first_glob = components
        .iter()
        .position(|component| has_glob(component))
        .unwrap_or(components.len());
    let mut base = PathBuf::from("/");
    for component in &components[..first_glob] {
        base.push(component);
    }
    if first_glob == components.len() {
        // 没有元字符（调用方已判定有 glob，这里只做防御）：按显式路径处理。
        return resolve_explicit_or_dir(&base, max_paths, keep).await;
    }
    let mut out = BTreeSet::new();
    walk_components(&base, &components[first_glob..], max_paths, &mut out, keep).await?;
    Ok(out.into_iter().collect())
}

async fn walk_components(
    base: &Path,
    remaining: &[&str],
    max_paths: usize,
    out: &mut BTreeSet<PathBuf>,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<()> {
    if out.len() >= max_paths || remaining.is_empty() {
        return Ok(());
    }
    let matcher = component_matcher(remaining[0])?;
    let mut entries = match tokio::fs::read_dir(base).await {
        Ok(entries) => entries,
        // 固定前缀不存在 = 没匹配；无权限 / 其它 IO 错误要报出来。
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(()),
        Err(err) => return Err(err),
    };
    while let Some(entry) = entries.next_entry().await? {
        if out.len() >= max_paths {
            break;
        }
        let name = entry.file_name();
        let name = name.to_string_lossy();
        if !matcher.is_match(name.as_ref()) {
            continue;
        }
        let path = entry.path();
        let Ok(metadata) = tokio::fs::metadata(&path).await else {
            // 断链 symlink / 读取中被删：跳过这个条目。
            continue;
        };
        if remaining.len() == 1 {
            if metadata.is_file() && keep(&path) {
                out.insert(path);
            }
        } else if metadata.is_dir() {
            Box::pin(walk_components(
                &path,
                &remaining[1..],
                max_paths,
                out,
                keep,
            ))
            .await?;
        }
    }
    Ok(())
}

fn component_matcher(component: &str) -> io::Result<GlobMatcher> {
    GlobBuilder::new(component)
        .literal_separator(true)
        .build()
        .map(|glob| glob.compile_matcher())
        .map_err(|err| invalid_glob(component, err))
}

fn compile_excludes(patterns: &[String]) -> io::Result<Vec<GlobMatcher>> {
    patterns
        .iter()
        .map(|pattern| {
            GlobBuilder::new(pattern)
                .literal_separator(true)
                .build()
                .map(|glob| glob.compile_matcher())
                .map_err(|err| invalid_glob(pattern, err))
        })
        .collect()
}

fn invalid_glob(pattern: &str, err: globset::Error) -> io::Error {
    io::Error::new(
        io::ErrorKind::InvalidInput,
        format!("invalid glob pattern {pattern:?}: {err}"),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-agentd-glob-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn names(paths: &[PathBuf]) -> Vec<String> {
        paths
            .iter()
            .map(|path| path.file_name().unwrap().to_string_lossy().to_string())
            .collect()
    }

    /// 只关心“留下的”：把 `FamilySelection` 收窄成路径列表（保留 `io::Result` 便于断言报错）。
    async fn resolve_selected(
        target: &Path,
        excludes: &[String],
        filters: &ContainerFilters,
        max_paths: usize,
    ) -> io::Result<Vec<PathBuf>> {
        let selection = resolve_family_paths(target, excludes, filters, max_paths).await?;
        Ok(selection.selected)
    }

    fn no_filters() -> ContainerFilters {
        ContainerFilters::default()
    }

    fn filters(namespaces: &[&str], pods: &[&str]) -> ContainerFilters {
        ContainerFilters {
            namespace_in: namespaces.iter().map(|v| v.to_string()).collect(),
            pod_not_in: pods.iter().map(|v| v.to_string()).collect(),
        }
    }

    #[tokio::test]
    async fn expands_a_glob_and_sorts_the_result() {
        let dir = temp_dir("expand");
        fs::write(dir.join("b.log"), "b\n").unwrap();
        fs::write(dir.join("a.log"), "a\n").unwrap();
        fs::write(dir.join("ignore.txt"), "x\n").unwrap();

        let pattern = dir.join("*.log");
        let paths = resolve_selected(&pattern, &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["a.log", "b.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn excludes_match_full_paths() {
        let dir = temp_dir("exclude");
        fs::write(dir.join("a.log"), "a\n").unwrap();
        fs::write(dir.join("b.log"), "b\n").unwrap();

        let pattern = dir.join("*.log");
        let excludes = vec![format!("{}/*b.log", dir.display())];
        let paths = resolve_selected(&pattern, &excludes, &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["a.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_directory_target_lists_direct_files_only() {
        let dir = temp_dir("dir-target");
        fs::write(dir.join("a.log"), "a\n").unwrap();
        fs::create_dir_all(dir.join("nested")).unwrap();
        fs::write(dir.join("nested").join("b.log"), "b\n").unwrap();

        let paths = resolve_selected(&dir, &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["a.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_match_is_empty_not_an_error() {
        let dir = temp_dir("no-match");
        let paths = resolve_selected(&dir.join("*.log"), &[], &no_filters(), 512)
            .await
            .unwrap();
        assert!(paths.is_empty());
        let missing = dir.join("missing-dir").join("*.log");
        assert!(
            resolve_selected(&missing, &[], &no_filters(), 512)
                .await
                .unwrap()
                .is_empty()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn honors_the_path_cap() {
        let dir = temp_dir("cap");
        for index in 0..5 {
            fs::write(dir.join(format!("{index}.log")), "x\n").unwrap();
        }
        let paths = resolve_selected(&dir.join("*.log"), &[], &no_filters(), 3)
            .await
            .unwrap();
        assert_eq!(paths.len(), 3);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn follows_symlinks_to_files() {
        let dir = temp_dir("symlink");
        let target = dir.join("real.log");
        fs::write(&target, "x\n").unwrap();
        std::os::unix::fs::symlink(&target, dir.join("link.log")).unwrap();

        let paths = resolve_selected(&dir.join("*.log"), &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["link.log", "real.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rejects_recursive_globs() {
        let dir = temp_dir("recursive");
        let err = resolve_family_paths(&dir.join("**.log"), &[], &no_filters(), 512)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains("**"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn an_invalid_exclude_is_reported() {
        let dir = temp_dir("bad-exclude");
        fs::write(dir.join("a.log"), "a\n").unwrap();
        let err = resolve_family_paths(&dir.join("*.log"), &["[".to_string()], &no_filters(), 512)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_dir_all(&dir);
    }

    // ── W2：容器选源过滤器 ────────────────────────────────────────────

    #[test]
    fn parses_pod_and_namespace_out_of_a_container_log_name() {
        // pod 带 hash、container 带连字符 —— 只有 id 不含 `-`，所以从右切是对的。
        let path =
            Path::new("/var/log/containers/web-7d9f8c6b5-x2k4l_prod_nginx-sidecar-a1b2c3.log");
        let name = parse_container_log_name(path).expect("parse");
        assert_eq!(name.pod, "web-7d9f8c6b5-x2k4l");
        assert_eq!(name.namespace, "prod");

        // 不像容器日志的一律解析不出来（不能靠猜）。
        assert!(parse_container_log_name(Path::new("/var/log/containers/README")).is_none());
        assert!(parse_container_log_name(Path::new("/var/log/containers/a.log")).is_none());
        assert!(parse_container_log_name(Path::new("/var/log/containers/a_b.log")).is_none());
    }

    #[tokio::test]
    async fn container_filters_select_by_namespace_and_skip_listed_pods() {
        let dir = temp_dir("filters");
        for name in [
            "web-1_prod_nginx-aaa.log",
            "api-1_prod_api-bbb.log",
            "jobs-1_batch_cron-ccc.log",
            "debug-1_prod_debug-ddd.log",
        ] {
            fs::write(dir.join(name), "x\n").unwrap();
        }

        let pattern = dir.join("*.log");
        let paths = resolve_selected(&pattern, &[], &filters(&["prod"], &["debug-1"]), 512)
            .await
            .unwrap();
        assert_eq!(
            names(&paths),
            vec!["api-1_prod_api-bbb.log", "web-1_prod_nginx-aaa.log"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn non_container_names_are_dropped_only_when_filters_are_present() {
        let dir = temp_dir("filters-noncontainer");
        fs::write(dir.join("web-1_prod_nginx-aaa.log"), "x\n").unwrap();
        fs::write(dir.join("stray.log"), "x\n").unwrap();

        let pattern = dir.join("*.log");
        // 没有过滤器：一个都不碰（W1 行为不变）。
        let all = resolve_selected(&pattern, &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&all), vec!["stray.log", "web-1_prod_nginx-aaa.log"]);

        // 有过滤器：解析不出 pod/ns 的不当候选（选源根就是容器目录）。
        let filtered = resolve_selected(&pattern, &[], &filters(&["prod"], &[]), 512)
            .await
            .unwrap();
        assert_eq!(names(&filtered), vec!["web-1_prod_nginx-aaa.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn filters_compose_with_exclude_globs() {
        let dir = temp_dir("filters-exclude");
        for name in ["web-1_prod_nginx-aaa.log", "api-1_prod_api-bbb.log"] {
            fs::write(dir.join(name), "x\n").unwrap();
        }
        let pattern = dir.join("*.log");
        let excludes = vec![format!("{}/*api*.log", dir.display())];
        let paths = resolve_selected(&pattern, &excludes, &filters(&["prod"], &[]), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["web-1_prod_nginx-aaa.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn selection_happens_before_the_scan_cap() {
        // 目录里候选比上限多、且绝大部分会被过滤掉：上限必须只数**留下的**，
        // 否则会出现“先截断再过滤 → 留下的远少于上限（甚至为空）”，
        // 而 `max_files` 触顶又被当成正常状态，没人会发现少采了。
        let dir = temp_dir("cap-before-filter");
        for index in 0..40 {
            let name = format!("noise-{index:02}_batch_cron-{index:02}.log");
            fs::write(dir.join(&name), "x\n").unwrap();
        }
        let keep = "web-1_prod_nginx-aaa.log";
        fs::write(dir.join(keep), "x\n").unwrap();

        // 上限 = 1：只能是那条通过过滤的。
        let filtered = resolve_selected(&dir, &[], &filters(&["prod"], &[]), 1)
            .await
            .unwrap();
        assert_eq!(names(&filtered), vec![keep], "过滤要先于截断");

        // 排除项同理：它也不能吃掉扫描名额。
        let excludes = vec![format!("{}/*noise*", dir.display())];
        let excluded = resolve_selected(&dir, &excludes, &no_filters(), 1)
            .await
            .unwrap();
        assert_eq!(names(&excluded), vec![keep], "排除项也要先于截断");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn selection_accepts_two_namespaces_and_three_pods() {
        // 验收场景（2 ns × 3 pod）：按 ns 白名单 + pod 黑名单挑，不靠改 pattern。
        let dir = temp_dir("two-ns-three-pods");
        let fixtures = [
            "web-1_prod_nginx-a1.log",
            "api-1_prod_api-b1.log",
            "debug-1_prod_debug-c1.log",
            "web-2_kube-system_dns-d1.log",
            "api-2_kube-system_cni-e1.log",
            "job-1_batch_cron-f1.log",
        ];
        for name in fixtures {
            fs::write(dir.join(name), "x\n").unwrap();
        }
        let paths = resolve_selected(
            &dir,
            &[],
            &filters(&["prod", "kube-system"], &["debug-1"]),
            512,
        )
        .await
        .unwrap();
        assert_eq!(
            names(&paths),
            vec![
                "api-1_prod_api-b1.log",
                "api-2_kube-system_cni-e1.log",
                "web-1_prod_nginx-a1.log",
                "web-2_kube-system_dns-d1.log",
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn explicit_file_targets_are_also_subject_to_filters() {
        // 过滤器不区分“glob 还是显式路径”：显式文件如果名字不符容器约定，
        // 一律不当候选（否则一个 `/var/log/containers/app.log` 会静默采进去）。
        let dir = temp_dir("explicit-filter");
        let plain = dir.join("app.log");
        fs::write(&plain, "x\n").unwrap();
        let kept = dir.join("web-1_prod_nginx-a1.log");
        fs::write(&kept, "x\n").unwrap();

        assert!(
            resolve_selected(&plain, &[], &filters(&["prod"], &[]), 512)
                .await
                .unwrap()
                .is_empty()
        );
        assert_eq!(
            names(
                &resolve_selected(&kept, &[], &filters(&["prod"], &[]), 512)
                    .await
                    .unwrap()
            ),
            vec!["web-1_prod_nginx-a1.log"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn filters_are_exact_and_case_sensitive() {
        let dir = temp_dir("filters-exact");
        fs::write(dir.join("web-1_prod_nginx-a1.log"), "x\n").unwrap();
        let pattern = dir.join("*.log");

        // 大小写不同 = 不同名字（不折叠）：k8s 名字永远小写，折叠反而会把写错的值当能用。
        assert!(
            resolve_selected(&pattern, &[], &filters(&["PROD"], &[]), 512)
                .await
                .unwrap()
                .is_empty()
        );
        // 黑名单也是**整名**匹配，不是前缀/子串：`web` 不会误伤 `web-1`。
        assert_eq!(
            resolve_selected(&pattern, &[], &filters(&[], &["web"]), 512)
                .await
                .unwrap()
                .len(),
            1
        );
        assert!(
            resolve_selected(&pattern, &[], &filters(&[], &["web-1"]), 512)
                .await
                .unwrap()
                .is_empty()
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn container_name_parsing_covers_the_awkward_shapes() {
        // 大小写：kubelet 永远写小写 `.log`；`.LOG` 不当容器日志。
        assert!(parse_container_log_name(Path::new("/var/log/containers/a_b_c-d.LOG")).is_none());
        // 轮转件（`*.log.1` / `*.log-20261023`）不在选源约定里。
        assert!(parse_container_log_name(Path::new("/var/log/containers/a_b_c-d.log.1")).is_none());
        // 段数不够 / 有空段。
        assert!(parse_container_log_name(Path::new("/var/log/containers/a_b-c.log")).is_none());
        assert!(parse_container_log_name(Path::new("/var/log/containers/_b_c-d.log")).is_none());
        // 四段以上：第三段把剩下的吃掉（容器名里不可能有 `_`，真出现就是格式变了）。
        let odd = parse_container_log_name(Path::new("/var/log/containers/a_b_c_d-e.log"))
            .expect("still parses");
        assert_eq!(odd.pod, "a");
        assert_eq!(odd.namespace, "b");
    }
}
