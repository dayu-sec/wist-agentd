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
use std::sync::Mutex;

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
    /// 本轮被 `filters` 剔掉的现存路径数（`exclude_globs` 不计）。
    pub filtered: usize,
    /// 本轮因为**取不到容器身份**而作判定的候选数（包含式不命中 / 排除式保留都在内）。
    ///
    /// 为什么单独计数：身份来自 `config.v2.json`，权限 / 驱动 / 容器创建中都会让它读不到，
    /// 而两种维度的降级方向相反 —— 不报出来就无从区分“配置真生效”与“静默 no-op”。
    pub identity_unknown: usize,
}

impl FamilySelection {
    /// 本轮没有扫描（不到重扫间隔）：全空。
    pub fn none() -> Self {
        Self {
            selected: Vec::new(),
            deselected: BTreeSet::new(),
            filtered: 0,
            identity_unknown: 0,
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
    reject_recursive_glob(&target_text)?;
    // 选择层（排除项 + 结构化过滤器）在**收集时**求值：`max_paths` 必须只数“留下的”。
    //
    // 否则目录里候选很多时会先被截断、再被过滤 —— 留下的可能远少于上限（甚至为空），
    // 而“超过上限”又被当成正常状态，没人会发现少采了。
    let gate = SelectionGate::new(exclude_globs, filters)?;
    let keep = |path: &Path| gate.keep(path);
    let selected = if has_glob(&target_text) {
        resolve_glob(&target_text, max_paths, &keep).await?
    } else {
        resolve_explicit_or_dir(target, max_paths, &keep).await?
    };
    Ok(gate.finish(selected))
}

/// `**` 不支持：整棵树递归展开不在方案内（深度与代价都不可控）。
fn reject_recursive_glob(target: &str) -> io::Result<()> {
    if target.contains("**") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recursive glob `**` is not supported",
        ));
    }
    Ok(())
}

/// 发现阶段的**选择层**：排除 glob + 结构化过滤器，并在收集过程中累计自观测计数。
///
/// 为什么是结构体而不是内联闭包：判定要用到「排除项 + 过滤器 + 两个计数器」四份状态，
/// 而遍历把它当 `&dyn Fn` 传入（同一轮里会被反复调用），所以计数用互斥量做内部可变性 ——
/// 与旧实现的 `Mutex` + 闭包逐字等价，只是把「判定」和「记账」收进同一处。
struct SelectionGate<'a> {
    filters: &'a ContainerFilters,
    excludes: Vec<GlobMatcher>,
    deselected: Mutex<BTreeSet<String>>,
    stats: Mutex<SelectionStats>,
}

/// 选择层自观测：被结构化过滤器剔掉的候选数，其中「取不到容器身份」的候选数。
#[derive(Debug, Default, Clone, Copy)]
struct SelectionStats {
    filtered: usize,
    identity_unknown: usize,
}

impl<'a> SelectionGate<'a> {
    fn new(exclude_globs: &[String], filters: &'a ContainerFilters) -> io::Result<Self> {
        Ok(Self {
            filters,
            excludes: compile_excludes(exclude_globs)?,
            deselected: Mutex::new(BTreeSet::new()),
            stats: Mutex::new(SelectionStats::default()),
        })
    }

    /// 这条候选进不进工作集；被剔掉的现存路径记进 `deselected`。
    fn keep(&self, path: &Path) -> bool {
        if self.is_excluded(path) {
            // 排除项**不**计入 `filtered`：那个计数只回答“结构化过滤器剔了多少”。
            self.reject(path);
            return false;
        }
        let verdict = container_filters_verdict(self.filters, path);
        if verdict.identity_unknown() {
            self.bump(|stats| stats.identity_unknown += 1);
        }
        if verdict.keeps() {
            return true;
        }
        self.bump(|stats| stats.filtered += 1);
        self.reject(path);
        false
    }

    fn is_excluded(&self, path: &Path) -> bool {
        self.excludes.iter().any(|matcher| matcher.is_match(path))
    }

    fn reject(&self, path: &Path) {
        self.deselected
            .lock()
            .expect("deselected set")
            .insert(path.display().to_string());
    }

    fn bump(&self, update: impl FnOnce(&mut SelectionStats)) {
        update(&mut self.stats.lock().expect("selection stats"));
    }

    /// 收尾：把本轮留下的路径与自观测计数拼成结果。
    fn finish(self, selected: Vec<PathBuf>) -> FamilySelection {
        let stats = self.stats.into_inner().expect("selection stats");
        FamilySelection {
            selected,
            deselected: self.deselected.into_inner().expect("deselected set"),
            filtered: stats.filtered,
            identity_unknown: stats.identity_unknown,
        }
    }
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
    container: &'a str,
}

fn parse_container_log_name(path: &Path) -> Option<ContainerLogName<'_>> {
    let (pod, namespace, container) = split_container_labels(container_log_stem(path)?)?;
    Some(ContainerLogName {
        pod,
        namespace,
        container,
    })
}

/// 去掉 `.log` 与 `-<id>` 之后的 `<pod>_<ns>_<container>`。
///
/// `-` 之后必须有东西（空 id 不是容器日志），这样 `a_b_c-.log` 不会被当成候选。
fn container_log_stem(path: &Path) -> Option<&str> {
    let name = path.file_name()?.to_str()?;
    let stem = name.strip_suffix(".log")?;
    let (head, id) = stem.rsplit_once('-')?;
    if id.is_empty() {
        return None;
    }
    Some(head)
}

/// 按 `_` 切三段：第三段吃掉剩余部分，任何一段为空都是坏形状。
fn split_container_labels(head: &str) -> Option<(&str, &str, &str)> {
    let mut parts = head.splitn(3, '_');
    let pod = parts.next()?;
    let namespace = parts.next()?;
    let container = parts.next()?;
    if pod.is_empty() || namespace.is_empty() || container.is_empty() {
        return None;
    }
    Some((pod, namespace, container))
}

/// 选择层的判定结果。多出两个 `IdentityUnknown` 态，是为了让“身份读不到”可被计数：
/// 它与“确实不匹配”在现场是两回事（前者是读 `config.v2.json` 失败）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum FilterVerdict {
    Keep,
    Drop,
    /// 排除式因取不到身份而**保留**（安全侧）。
    KeepIdentityUnknown,
    /// 包含式因取不到身份而**不命中**。
    DropIdentityUnknown,
}

impl FilterVerdict {
    fn keeps(self) -> bool {
        matches!(self, Self::Keep | Self::KeepIdentityUnknown)
    }

    fn identity_unknown(self) -> bool {
        matches!(self, Self::KeepIdentityUnknown | Self::DropIdentityUnknown)
    }

    /// 维度内判定的结果：命中保留、不命中剔除。
    fn of_match(matched: bool) -> Self {
        if matched { Self::Keep } else { Self::Drop }
    }

    /// 取不到容器身份时的降级：包含式（`name_in`）要求“证明确实是它” → 不命中；
    /// 排除式不能因为读不到配置就把日志全丢了 → 保留。
    fn unknown_identity(requires_identity: bool) -> Self {
        if requires_identity {
            Self::DropIdentityUnknown
        } else {
            Self::KeepIdentityUnknown
        }
    }
}

/// 过滤器求值：空过滤器 = 全收。
///
/// 两道维度各有各的适用面：
/// * `namespace_in` / `pod_not_in` 只对 **k8s 命名**（`<pod>_<ns>_<container>-<id>.log`）有意义；
///   名字解析不出来 = 不是这个载体上的候选，直接不收（与旧行为一致）。
/// * `name_in` / `name_not_in` 对两种载体都适用：k8s 取文件名第三段，Docker 取
///   `config.v2.json` 里的 `Name`（见 [`crate::telemetry::container_ref`]）。
///
/// 取不到容器身份时的三态是**刻意不对称**的，见 [`FilterVerdict::unknown_identity`]。
fn container_filters_verdict(filters: &ContainerFilters, path: &Path) -> FilterVerdict {
    if filters.is_empty() {
        return FilterVerdict::Keep;
    }
    let k8s = parse_container_log_name(path);
    if let Some(verdict) = k8s_dimension_verdict(filters, k8s) {
        return verdict;
    }
    if !uses_name_dimension(filters) {
        // 只用 k8s 维度时，非 k8s 命名的候选一律不收（旧行为）。
        return FilterVerdict::of_match(k8s.is_some());
    }
    name_dimension_verdict(filters, path, k8s)
}

/// k8s 维度（`namespace_in` / `pod_not_in`）：只认 `<pod>_<ns>_<container>-<id>.log`。
///
/// `Some` = 这一维度已经否决了这条候选；`None` = 它没意见，交给名字维度。
fn k8s_dimension_verdict(
    filters: &ContainerFilters,
    k8s: Option<ContainerLogName<'_>>,
) -> Option<FilterVerdict> {
    if filters.namespace_in.is_empty() && filters.pod_not_in.is_empty() {
        return None;
    }
    let Some(name) = k8s else {
        return Some(FilterVerdict::Drop);
    };
    let namespace_ok =
        filters.namespace_in.is_empty() || list_contains(&filters.namespace_in, name.namespace);
    let pod_allowed = !list_contains(&filters.pod_not_in, name.pod);
    if namespace_ok && pod_allowed {
        None
    } else {
        Some(FilterVerdict::Drop)
    }
}

/// 名字维度（`name_in` / `name_not_in`）：两种载体都适用。
///
/// 黑名单优先于白名单的含义不变：命中任一黑名单即剔，白名单只在“没被剔”之后才要求命中。
fn name_dimension_verdict(
    filters: &ContainerFilters,
    path: &Path,
    k8s: Option<ContainerLogName<'_>>,
) -> FilterVerdict {
    let requires_identity = !filters.name_in.is_empty();
    let Some(container) = resolve_container_name(path, k8s) else {
        return FilterVerdict::unknown_identity(requires_identity);
    };
    if requires_identity && !list_contains(&filters.name_in, &container) {
        return FilterVerdict::Drop;
    }
    if list_contains(&filters.name_not_in, &container) {
        return FilterVerdict::Drop;
    }
    FilterVerdict::Keep
}

fn uses_name_dimension(filters: &ContainerFilters) -> bool {
    !filters.name_in.is_empty() || !filters.name_not_in.is_empty()
}

/// 容器名：k8s 取文件名第三段；Docker 读 `config.v2.json`（读不到就是“身份未知”）。
fn resolve_container_name(path: &Path, k8s: Option<ContainerLogName<'_>>) -> Option<String> {
    if let Some(name) = k8s {
        return Some(name.container.to_string());
    }
    crate::telemetry::container_ref::for_source_path(path.to_str()?).map(|found| found.name)
}

/// 白名单 / 黑名单都是**整名**匹配（大小写敏感）：k8s 名字永远小写，折叠只会把写错的值当能用。
fn list_contains(list: &[String], value: &str) -> bool {
    list.iter().any(|item| item == value)
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
    let metadata = match tokio::fs::metadata(target).await {
        Ok(metadata) => metadata,
        Err(err) if err.kind() == io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(err) => return Err(err),
    };
    if metadata.is_dir() {
        return list_dir_files(target, max_paths, keep).await;
    }
    if keep(target) {
        Ok(vec![target.to_path_buf()])
    } else {
        Ok(Vec::new())
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
        collect_file(&entry.path(), &mut out, keep).await;
    }
    Ok(out.into_iter().collect())
}

/// 跟随 symlink 后确实是普通文件、且通过选择层时收进集合。
///
/// 断链 / 无权限的单条目直接跳过，不拖垮整个目录。
async fn collect_file(
    path: &Path,
    out: &mut BTreeSet<PathBuf>,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) {
    let Ok(metadata) = tokio::fs::metadata(path).await else {
        return;
    };
    if metadata.is_file() && keep(path) {
        out.insert(path.to_path_buf());
    }
}

/// 按 pattern 的固定前缀逐层展开。
async fn resolve_glob(
    pattern: &str,
    max_paths: usize,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<Vec<PathBuf>> {
    let (base, wildcard_components) = split_pattern(pattern);
    if wildcard_components.is_empty() {
        // 没有元字符（调用方已判定有 glob，这里只做防御）：按显式路径处理。
        return resolve_explicit_or_dir(&base, max_paths, keep).await;
    }
    let mut out = BTreeSet::new();
    walk_components(&base, &wildcard_components, max_paths, &mut out, keep).await?;
    Ok(out.into_iter().collect())
}

/// 把 pattern 拆成「固定前缀目录 + 从第一个含元字符的组件起的剩余段」。
///
/// 固定前缀仍以 `/` 为根拼回去 —— 只扫前缀、不扫整棵树，是这条采集路径的代价边界。
fn split_pattern(pattern: &str) -> (PathBuf, Vec<&str>) {
    let components: Vec<&str> = pattern.split('/').filter(|part| !part.is_empty()).collect();
    let first_glob = components
        .iter()
        .position(|component| has_glob(component))
        .unwrap_or(components.len());
    let mut base = PathBuf::from("/");
    for component in &components[..first_glob] {
        base.push(component);
    }
    (base, components[first_glob..].to_vec())
}

/// 逐层展开剩余组件；`out` 到上限即停（上限只数**留下的**）。
async fn walk_components(
    base: &Path,
    remaining: &[&str],
    max_paths: usize,
    out: &mut BTreeSet<PathBuf>,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<()> {
    if remaining.is_empty() || out.len() >= max_paths {
        return Ok(());
    }
    let matcher = compile_glob(remaining[0])?;
    // 固定前缀不存在 = 没匹配；无权限 / 其它 IO 错误要报出来。
    let Some(mut entries) = open_dir(base).await? else {
        return Ok(());
    };
    while let Some(entry) = entries.next_entry().await? {
        if out.len() >= max_paths {
            break;
        }
        walk_entry(&entry, &matcher, remaining, max_paths, out, keep).await?;
    }
    Ok(())
}

/// 一个目录项的分派：最后一层收文件，否则只在目录上下探。
async fn walk_entry(
    entry: &tokio::fs::DirEntry,
    matcher: &GlobMatcher,
    remaining: &[&str],
    max_paths: usize,
    out: &mut BTreeSet<PathBuf>,
    keep: &(dyn Fn(&Path) -> bool + Sync),
) -> io::Result<()> {
    let Some((path, metadata)) = matched_child(entry, matcher).await else {
        return Ok(());
    };
    if remaining.len() > 1 {
        if metadata.is_dir() {
            Box::pin(walk_components(
                &path,
                &remaining[1..],
                max_paths,
                out,
                keep,
            ))
            .await?;
        }
        return Ok(());
    }
    if metadata.is_file() && keep(&path) {
        out.insert(path);
    }
    Ok(())
}

/// 条目名匹配、且元数据可读（跟随 symlink）时返回路径与元数据。
///
/// 断链 symlink / 读取中被删：`None` 单条目跳过，不拖垮整个遍历。
async fn matched_child(
    entry: &tokio::fs::DirEntry,
    matcher: &GlobMatcher,
) -> Option<(PathBuf, std::fs::Metadata)> {
    let name = entry.file_name();
    if !matcher.is_match(name.to_string_lossy().as_ref()) {
        return None;
    }
    let path = entry.path();
    let metadata = tokio::fs::metadata(&path).await.ok()?;
    Some((path, metadata))
}

/// 打开目录：固定前缀不存在当「没匹配」（`Ok(None)`），其它 IO 错误如实上报。
async fn open_dir(dir: &Path) -> io::Result<Option<tokio::fs::ReadDir>> {
    match tokio::fs::read_dir(dir).await {
        Ok(entries) => Ok(Some(entries)),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(None),
        Err(err) => Err(err),
    }
}

/// 编译一段 glob（组件或排除项）。`*` 不跨目录：`literal_separator(true)`。
fn compile_glob(pattern: &str) -> io::Result<GlobMatcher> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map(|glob| glob.compile_matcher())
        .map_err(|err| invalid_glob(pattern, err))
}

fn compile_excludes(patterns: &[String]) -> io::Result<Vec<GlobMatcher>> {
    patterns
        .iter()
        .map(|pattern| compile_glob(pattern))
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
            ..Default::default()
        }
    }

    fn name_filters(name_in: &[&str], name_not_in: &[&str]) -> ContainerFilters {
        ContainerFilters {
            name_in: name_in.iter().map(|v| v.to_string()).collect(),
            name_not_in: name_not_in.iter().map(|v| v.to_string()).collect(),
            ..Default::default()
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
    async fn a_wildcard_directory_segment_expands_one_level() {
        // Docker 容器日志：`containers/<id>/<id>-json.log*` —— 通配在**中间段**（容器 id 是目录名）。
        // 目录里的 `linux-docker-container-stdout` 就靠这个形态，它必须能展开，
        // 否则那条来源会静默采到 0 个文件。
        let dir = temp_dir("two-level");
        for id in ["aaa", "bbb"] {
            let sub = dir.join(id);
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join(format!("{id}-json.log")), "{\n").unwrap();
            fs::write(sub.join(format!("{id}-json.log.1")), "{\n").unwrap();
        }
        // 同层但名字不匹配的文件不应被收。
        fs::write(dir.join("notes.txt"), "x\n").unwrap();

        let pattern = dir.join("*").join("*-json.log*");
        let paths = resolve_selected(&pattern, &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(
            names(&paths),
            vec![
                "aaa-json.log",
                "aaa-json.log.1",
                "bbb-json.log",
                "bbb-json.log.1"
            ]
        );
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
        // 第三段是容器名：`name_in` / `name_not_in` 用的就是它。
        assert_eq!(name.container, "nginx-sidecar");

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
        // 容器段为空同样是坏形状：`name_in` / `name_not_in` 靠的就是这一段。
        assert!(parse_container_log_name(Path::new("/var/log/containers/a_b_-d.log")).is_none());
        // 四段以上：第三段把剩下的吃掉（容器名里不可能有 `_`，真出现就是格式变了）。
        let odd = parse_container_log_name(Path::new("/var/log/containers/a_b_c_d-e.log"))
            .expect("still parses");
        assert_eq!(odd.pod, "a");
        assert_eq!(odd.namespace, "b");
        assert_eq!(odd.container, "c_d", "容器名段要完整吃掉剩余部分");
    }

    // ── M1.5：容器名过滤（k8s 文件名 / Docker config.v2.json）─────────────

    #[tokio::test]
    async fn container_name_filters_select_k8s_containers_by_the_third_segment() {
        let dir = temp_dir("name-k8s");
        for name in [
            "web-1_prod_nginx-aaa.log",
            "web-1_prod_sidecar-bbb.log",
            "api-1_prod_nginx-ccc.log",
        ] {
            fs::write(dir.join(name), "x\n").unwrap();
        }
        let pattern = dir.join("*.log");

        let selected = resolve_selected(&pattern, &[], &name_filters(&["nginx"], &[]), 512)
            .await
            .unwrap();
        assert_eq!(
            names(&selected),
            vec!["api-1_prod_nginx-ccc.log", "web-1_prod_nginx-aaa.log"]
        );

        let selected = resolve_selected(&pattern, &[], &name_filters(&[], &["sidecar"]), 512)
            .await
            .unwrap();
        assert_eq!(
            names(&selected),
            vec!["api-1_prod_nginx-ccc.log", "web-1_prod_nginx-aaa.log"]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// Docker 载体：名字只在 `config.v2.json` 里；读不到时包含式不命中、排除式保留。
    #[tokio::test]
    async fn container_name_filters_read_docker_identity_and_treat_unknown_asymmetric() {
        let root = temp_dir("name-docker");
        let id_known = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111";
        let id_unknown = "bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222bbbb2222";
        for (id, config) in [(id_known, Some(r#"{"Name":"/mysql"}"#)), (id_unknown, None)] {
            let dir = root.join("containers").join(id);
            fs::create_dir_all(&dir).unwrap();
            fs::write(dir.join(format!("{id}-json.log")), "{}\n").unwrap();
            if let Some(config) = config {
                fs::write(dir.join("config.v2.json"), config).unwrap();
            }
        }
        let pattern = root.join("containers").join("*").join("*-json.log");

        let selected = resolve_selected(&pattern, &[], &name_filters(&["mysql"], &[]), 512)
            .await
            .unwrap();
        assert_eq!(selected.len(), 1, "取不到身份的不能被当成 mysql");
        assert!(selected[0].to_string_lossy().contains(id_known));

        let selected = resolve_selected(&pattern, &[], &name_filters(&[], &["mysql"]), 512)
            .await
            .unwrap();
        assert_eq!(selected.len(), 1, "排除式不能因读不到配置而丢日志");
        assert!(selected[0].to_string_lossy().contains(id_unknown));

        // 选择层的自观测：剔了多少、其中多少是“身份读不到”要能分开报。
        let selection = resolve_family_paths(&pattern, &[], &name_filters(&["mysql"], &[]), 512)
            .await
            .expect("selection");
        assert_eq!(selection.filtered, 1, "身份未知的那个要被算作被剔");
        assert_eq!(selection.identity_unknown, 1);

        let selection = resolve_family_paths(&pattern, &[], &name_filters(&[], &["mysql"]), 512)
            .await
            .expect("selection");
        assert_eq!(selection.filtered, 1, "mysql 被剔掉");
        assert_eq!(
            selection.identity_unknown, 1,
            "排除式保留了它，但仍然要计入“身份读不到”"
        );
        let _ = fs::remove_dir_all(&root);
    }

    // ── 重构后拆出的内聚单元（过滤器判定 / pattern 拆分 / 遍历原子）──────

    const K8S_LOG: &str = "/var/log/containers/web-1_prod_nginx-a1.log";

    /// 既不是 k8s 命名、也没有 `containers` 段：两条身份通道都读不到。
    const PLAIN_LOG: &str = "/tmp/wist-agentd-fixture/agent.log";

    fn verdict(filters: &ContainerFilters, path: &str) -> FilterVerdict {
        container_filters_verdict(filters, Path::new(path))
    }

    /// 判定矩阵：k8s / 非 k8s 命名 × 两道维度 × 空过滤器。
    #[test]
    fn verdict_matrix_separates_mismatch_from_unknown_identity() {
        // 空过滤器 = 全收，连“不是容器日志”的路径也收。
        assert_eq!(verdict(&no_filters(), K8S_LOG), FilterVerdict::Keep);
        assert_eq!(verdict(&no_filters(), PLAIN_LOG), FilterVerdict::Keep);

        // k8s 维度：namespace 白名单命中 / 不命中；pod 黑名单整名匹配（不是前缀）。
        let k8s_cases = [
            (filters(&["prod"], &[]), FilterVerdict::Keep),
            (filters(&["batch"], &[]), FilterVerdict::Drop),
            (filters(&[], &["web-1"]), FilterVerdict::Drop),
            (filters(&[], &["web"]), FilterVerdict::Keep),
        ];
        for (filters, expected) in k8s_cases {
            assert_eq!(verdict(&filters, K8S_LOG), expected);
        }

        // 名字维度：k8s 取文件名第三段。
        let name_cases = [
            (name_filters(&["nginx"], &[]), FilterVerdict::Keep),
            (name_filters(&[], &["nginx"]), FilterVerdict::Drop),
        ];
        for (filters, expected) in name_cases {
            assert_eq!(verdict(&filters, K8S_LOG), expected);
        }

        // 非 k8s 命名：k8s 维度当“不是候选”，名字维度退化成“身份未知”的两种降级。
        let unknown = [
            (filters(&["prod"], &[]), FilterVerdict::Drop),
            (
                name_filters(&["nginx"], &[]),
                FilterVerdict::DropIdentityUnknown,
            ),
            (
                name_filters(&[], &["nginx"]),
                FilterVerdict::KeepIdentityUnknown,
            ),
        ];
        for (filters, expected) in unknown {
            assert_eq!(verdict(&filters, PLAIN_LOG), expected);
        }
    }

    #[test]
    fn pattern_splitting_stops_at_the_first_wildcard_component() {
        // 元字符识别：`*` / `?` / `[` 才算 glob。
        assert!(has_glob("*.log") && has_glob("app?.log") && has_glob("[ab].log"));
        assert!(!has_glob("/var/log/app.log") && !has_glob("/var/log/app.log.1"));

        let (base, rest) = split_pattern("/var/log/containers/*/*-json.log");
        assert_eq!(base, PathBuf::from("/var/log/containers"));
        assert_eq!(rest, vec!["*", "*-json.log"]);

        // 元字符出现在中间段时，前缀仍必须是绝对路径（不能被拼成相对路径）。
        let (base, rest) = split_pattern("/var/lib/docker/containers/[0-9a-f]*/*-json.log");
        assert_eq!(base, PathBuf::from("/var/lib/docker/containers"));
        assert_eq!(rest, vec!["[0-9a-f]*", "*-json.log"]);

        // 没有元字符：整条都是固定前缀，剩余为空（调用方走显式路径分支）。
        let (base, rest) = split_pattern("/var/log/app.log");
        assert_eq!(base, PathBuf::from("/var/log/app.log"));
        assert!(rest.is_empty());

        // 重复 / 结尾的 `/` 不影响拆分。
        let (base, rest) = split_pattern("//var//log//*.log");
        assert_eq!(base, PathBuf::from("/var/log"));
        assert_eq!(rest, vec!["*.log"]);
    }

    #[test]
    fn container_log_name_splitting_rejects_bad_shapes() {
        let path = Path::new("/x").join("a_b_c-d1.log");
        assert_eq!(container_log_stem(&path), Some("a_b_c"));
        // 空 id / 缺 id 段 / 轮转件 / 大小写不同的后缀都不是容器日志。
        for name in ["a_b_c-.log", "a_b_c.log", "a_b_c-d.log.1", "a_b_c-d.LOG"] {
            let path = Path::new("/x").join(name);
            assert!(container_log_stem(&path).is_none(), "{name}");
        }

        assert_eq!(split_container_labels("a_b_c"), Some(("a", "b", "c")));
        // 第三段吃掉剩余部分：真出现多余 `_` 就是格式变了，不猜。
        assert_eq!(split_container_labels("a_b_c_d"), Some(("a", "b", "c_d")));
        for head in ["a_b", "_b_c", "a_b_"] {
            assert!(split_container_labels(head).is_none(), "{head}");
        }
    }

    #[test]
    fn component_globs_do_not_cross_separators_and_report_bad_patterns() {
        let matcher = compile_glob("*").expect("compile");
        assert!(matcher.is_match("a.log"));
        assert!(!matcher.is_match("nested/a.log"), "`*` 不跨目录");

        let err = compile_glob("[").expect_err("invalid glob");
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        assert!(err.to_string().contains('['), "{err}");
    }

    #[tokio::test]
    async fn opening_a_missing_directory_is_not_an_error() {
        let dir = temp_dir("open-dir");
        assert!(open_dir(&dir.join("missing")).await.expect("io").is_none());
        assert!(open_dir(&dir).await.expect("io").is_some());
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn a_file_in_an_intermediate_component_is_not_descended_into() {
        let dir = temp_dir("intermediate-file");
        // 同名层里既有文件也有目录：文件不该被当成目录下探。
        fs::write(dir.join("aaa"), "x\n").unwrap();
        fs::create_dir_all(dir.join("bbb")).unwrap();
        fs::write(dir.join("bbb").join("b-json.log"), "x\n").unwrap();

        let paths = resolve_selected(&dir.join("*").join("*-json.log"), &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["b-json.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[cfg(unix)]
    #[tokio::test]
    async fn broken_symlinks_are_skipped_not_fatal() {
        let dir = temp_dir("broken-link");
        fs::write(dir.join("real.log"), "x\n").unwrap();
        std::os::unix::fs::symlink(dir.join("missing.log"), dir.join("dangling.log")).unwrap();

        let paths = resolve_selected(&dir, &[], &no_filters(), 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["real.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn the_path_cap_is_global_across_wildcard_levels() {
        let dir = temp_dir("cap-two-levels");
        for id in ["aaa", "bbb", "ccc"] {
            let sub = dir.join(id);
            fs::create_dir_all(&sub).unwrap();
            fs::write(sub.join(format!("{id}-json.log")), "x\n").unwrap();
        }

        let paths = resolve_selected(&dir.join("*").join("*-json.log"), &[], &no_filters(), 2)
            .await
            .unwrap();
        assert_eq!(paths.len(), 2, "上限是整个 pattern 的，不是每层各算一份");
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn exclude_drops_are_deselected_but_not_counted_as_filtered() {
        let dir = temp_dir("exclude-stats");
        for name in ["keep-1_prod_nginx-a.log", "skip-1_prod_nginx-b.log"] {
            fs::write(dir.join(name), "x\n").unwrap();
        }
        let excludes = vec![format!("{}/*skip-1*", dir.display())];

        let selection = resolve_family_paths(&dir, &excludes, &filters(&["prod"], &[]), 512)
            .await
            .expect("selection");
        assert_eq!(names(&selection.selected), vec!["keep-1_prod_nginx-a.log"]);
        assert_eq!(
            selection.filtered, 0,
            "排除项只进 deselected，不计入结构化过滤器"
        );
        assert_eq!(selection.identity_unknown, 0);
        assert_eq!(
            selection.deselected.len(),
            1,
            "被剔的现存路径要能被“立刻停读”看见"
        );
        assert!(
            selection
                .deselected
                .iter()
                .any(|path| path.contains("skip-1"))
        );
        let _ = fs::remove_dir_all(&dir);
    }
}
