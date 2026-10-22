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

/// 解析一个文件族目标。
pub(super) async fn resolve_family_paths(
    target: &Path,
    exclude_globs: &[String],
    max_paths: usize,
) -> io::Result<Vec<PathBuf>> {
    let target_text = target.display().to_string();
    if target_text.contains("**") {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "recursive glob `**` is not supported",
        ));
    }
    let mut paths = if !has_glob(&target_text) {
        resolve_explicit_or_dir(target, max_paths).await?
    } else {
        resolve_glob(&target_text, max_paths).await?
    };
    if !exclude_globs.is_empty() {
        let excludes = compile_excludes(exclude_globs)?;
        paths.retain(|path| !excludes.iter().any(|matcher| matcher.is_match(path)));
    }
    Ok(paths)
}

/// 目标里有没有 glob 元字符。
pub(super) fn has_glob(target: &str) -> bool {
    target.contains(['*', '?', '['])
}

/// 目录或显式文件（两者都不含 glob 元字符）。
async fn resolve_explicit_or_dir(target: &Path, max_paths: usize) -> io::Result<Vec<PathBuf>> {
    match tokio::fs::metadata(target).await {
        Ok(metadata) if metadata.is_dir() => list_dir_files(target, max_paths).await,
        Ok(_) => Ok(vec![target.to_path_buf()]),
        Err(err) if err.kind() == io::ErrorKind::NotFound => Ok(Vec::new()),
        Err(err) => Err(err),
    }
}

/// 目录下的**直接子文件**（跟随 symlink；不递归）。
async fn list_dir_files(dir: &Path, max_paths: usize) -> io::Result<Vec<PathBuf>> {
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
        {
            out.insert(path);
        }
    }
    Ok(out.into_iter().collect())
}

/// 按 pattern 的固定前缀逐层展开。
async fn resolve_glob(pattern: &str, max_paths: usize) -> io::Result<Vec<PathBuf>> {
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
        return resolve_explicit_or_dir(&base, max_paths).await;
    }
    let mut out = BTreeSet::new();
    walk_components(&base, &components[first_glob..], max_paths, &mut out).await?;
    Ok(out.into_iter().collect())
}

async fn walk_components(
    base: &Path,
    remaining: &[&str],
    max_paths: usize,
    out: &mut BTreeSet<PathBuf>,
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
            if metadata.is_file() {
                out.insert(path);
            }
        } else if metadata.is_dir() {
            Box::pin(walk_components(&path, &remaining[1..], max_paths, out)).await?;
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

    #[tokio::test]
    async fn expands_a_glob_and_sorts_the_result() {
        let dir = temp_dir("expand");
        fs::write(dir.join("b.log"), "b\n").unwrap();
        fs::write(dir.join("a.log"), "a\n").unwrap();
        fs::write(dir.join("ignore.txt"), "x\n").unwrap();

        let pattern = dir.join("*.log");
        let paths = resolve_family_paths(&pattern, &[], 512).await.unwrap();
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
        let paths = resolve_family_paths(&pattern, &excludes, 512)
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

        let paths = resolve_family_paths(&dir, &[], 512).await.unwrap();
        assert_eq!(names(&paths), vec!["a.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn no_match_is_empty_not_an_error() {
        let dir = temp_dir("no-match");
        let paths = resolve_family_paths(&dir.join("*.log"), &[], 512)
            .await
            .unwrap();
        assert!(paths.is_empty());
        let missing = dir.join("missing-dir").join("*.log");
        assert!(
            resolve_family_paths(&missing, &[], 512)
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
        let paths = resolve_family_paths(&dir.join("*.log"), &[], 3)
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

        let paths = resolve_family_paths(&dir.join("*.log"), &[], 512)
            .await
            .unwrap();
        assert_eq!(names(&paths), vec!["link.log", "real.log"]);
        let _ = fs::remove_dir_all(&dir);
    }

    #[tokio::test]
    async fn rejects_recursive_globs() {
        let dir = temp_dir("recursive");
        let err = resolve_family_paths(&dir.join("**.log"), &[], 512)
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
        let err = resolve_family_paths(&dir.join("*.log"), &["[".to_string()], 512)
            .await
            .unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::InvalidInput);
        let _ = fs::remove_dir_all(&dir);
    }
}
