//! 文件类 opcode：`file.stat` / `file.read_range`。
//!
//! **路径必须来自 `plan.constraints.allow.paths`**：这是 R1/R0 的分界线，
//! 也是「不提供任意文件读写」的唯一落点。三条规则：
//!
//! 1. 只接受绝对路径；
//! 2. 必须 canonicalize 后落在某个允许前缀之下（符号链接逃逸因此无效）；
//! 3. 允许列表为空 = 什么都不许读（不是“什么都可以”）。
//!
//! `read_range` 有硬上限（64 KiB）并如实标 `truncated`；二进制内容不回传，只说 `binary`。

use std::fs;
use std::io::{Read, Seek, SeekFrom};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;

use globset::{Glob, GlobSet, GlobSetBuilder};
use serde::Deserialize;
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use wist_contracts::action_plan::RiskLevel;

use super::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

const SCHEMA_STAT: &str = "wist.opcode.file_stat/v1";
const SCHEMA_READ: &str = "wist.opcode.file_read_range/v1";
const SCHEMA_FIND: &str = "wist.opcode.file_find/v1";
const SCHEMA_HASH: &str = "wist.opcode.file_hash/v1";
const MAX_READ_BYTES: u64 = 64 * 1024;
/// `file.hash` 单次最多哈希多少字节（更大的文件只报大小，**不给半截哈希**）。
const MAX_HASH_BYTES: u64 = 256 * 1024 * 1024;
const DEFAULT_FIND_DEPTH: usize = 4;
const MAX_FIND_DEPTH: usize = 16;
const DEFAULT_FIND_LIMIT: usize = 100;
const MAX_FIND_LIMIT: usize = 200;
/// 一次 `file.find` 最多看多少条目：到顶就标 `complete=false`，**不假装扫完了**。
const MAX_FIND_ENTRIES: u64 = 100_000;
const MAX_PATTERN_CHARS: usize = 256;

pub const STAT_SPEC: OpSpec = OpSpec {
    id: "file.stat",
    risk: RiskLevel::R0,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(2_000, 1, 0),
    handler: stat,
};

pub const READ_RANGE_SPEC: OpSpec = OpSpec {
    id: "file.read_range",
    risk: RiskLevel::R1,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(2_000, 1, MAX_READ_BYTES),
    handler: read_range,
};

/// 只读的名字搜索：匹配**文件名**，不跟符号链接，必须在 `allow.paths` 之内。
pub const FIND_SPEC: OpSpec = OpSpec {
    id: "file.find",
    risk: RiskLevel::R0,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(5_000, MAX_FIND_LIMIT, 0),
    handler: find,
};

/// 内容摘要：**只对完整文件**算哈希（拿不到全文件就返回 `sha256: null`）。
pub const HASH_SPEC: OpSpec = OpSpec {
    id: "file.hash",
    risk: RiskLevel::R0,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(8_000, 1, MAX_HASH_BYTES),
    handler: hash,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct StatArgs {
    path: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct ReadRangeArgs {
    path: String,
    #[serde(default)]
    offset: Option<u64>,
    #[serde(default)]
    length: Option<u64>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct FindArgs {
    root: String,
    pattern: String,
    #[serde(default)]
    max_depth: Option<usize>,
    #[serde(default)]
    limit: Option<usize>,
    #[serde(default)]
    kind: Option<String>,
}

/// 结果类型的闭集：`file` / `dir` / `any`。链接永远只是 `symlink`，不会被当成目标本身。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum KindFilter {
    File,
    Dir,
    Any,
}

impl KindFilter {
    fn parse(value: Option<&str>) -> Result<Self, OpError> {
        match value.unwrap_or("file") {
            "file" => Ok(Self::File),
            "dir" => Ok(Self::Dir),
            "any" => Ok(Self::Any),
            other => Err(OpError::new(
                codes::INVALID_ARGS,
                format!("kind 只能是 file | dir | any，收到 `{other}`"),
            )),
        }
    }

    fn id(self) -> &'static str {
        match self {
            Self::File => "file",
            Self::Dir => "dir",
            Self::Any => "any",
        }
    }

    /// `symlink` 只被 `any` 接受：把链接算成它指向的类型，等于跟着链接走。
    fn accepts(self, kind: &str) -> bool {
        match self {
            Self::Any => true,
            Self::File => kind == "file",
            Self::Dir => kind == "dir",
        }
    }
}

fn compile_pattern(pattern: &str) -> Result<GlobSet, OpError> {
    if pattern.trim().is_empty() {
        return Err(OpError::new(codes::INVALID_ARGS, "pattern 不能为空"));
    }
    if pattern.chars().count() > MAX_PATTERN_CHARS {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("pattern 超过 {MAX_PATTERN_CHARS} 个字符"),
        ));
    }
    if pattern.contains('/') || pattern.contains('\\') {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            "pattern 只匹配文件名，不能含路径分隔符（用 root 指目录）".to_string(),
        ));
    }
    let glob = Glob::new(pattern).map_err(|err| {
        OpError::new(codes::INVALID_ARGS, format!("pattern 不是合法 glob：{err}"))
    })?;
    GlobSetBuilder::new()
        .add(glob)
        .build()
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("编译 pattern 失败：{err}")))
}

fn mtime_unix(meta: &fs::Metadata) -> Option<u64> {
    meta.modified()
        .ok()
        .and_then(|time| time.duration_since(std::time::UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs())
}

/// 把请求路径落到「允许前缀之内」的 canonical 路径上。
pub(super) fn resolve_allowed(path: &str, allow_paths: &[String]) -> Result<PathBuf, OpError> {
    let requested = Path::new(path);
    if !requested.is_absolute() {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("path 必须是绝对路径：{path}"),
        ));
    }
    let canonical = fs::canonicalize(requested).map_err(|err| match err.kind() {
        std::io::ErrorKind::NotFound => {
            OpError::new(codes::TARGET_NOT_FOUND, format!("路径不存在：{path}"))
        }
        _ => OpError::new(codes::OP_FAILED, format!("解析路径失败 {path}：{err}")),
    })?;
    ensure_allowed(&canonical, allow_paths, path)?;
    Ok(canonical)
}

/// 一个**已 canonical** 的路径是否落在 `allow.paths` 里。
///
/// 允许项本身不存在就跳过：配置错误不应放大成「全部允许」。
pub(super) fn is_allowed(canonical: &Path, allow_paths: &[String]) -> bool {
    allow_paths.iter().any(|allowed| {
        let allowed = Path::new(allowed);
        if !allowed.is_absolute() {
            return false;
        }
        fs::canonicalize(allowed).is_ok_and(|allowed| canonical.starts_with(&allowed))
    })
}

/// `ensure_allowed` 的入参已经 canonical：用于「文件可能已经不存在」的场景
/// （例如回滚一个被删掉的配置）—— 那时 `resolve_allowed` 没法 canonicalize。
pub(super) fn ensure_allowed(
    canonical: &Path,
    allow_paths: &[String],
    requested: &str,
) -> Result<(), OpError> {
    if allow_paths.is_empty() {
        return Err(OpError::new(
            codes::PATH_NOT_ALLOWED,
            "计划没有给出 allow.paths；本机不允许读写任何调用方指定路径".to_string(),
        ));
    }
    // 相对路径的允许项是**计划本身写错了**：既不能「按当前目录猜」，也不能静默跳过
    // ——静默跳过会让现场看到「配了 allow.paths 却永远 path_not_allowed」，以为是权限问题。
    if let Some(bad) = allow_paths
        .iter()
        .find(|allowed| !Path::new(allowed).is_absolute())
    {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("allow.paths 只接受绝对路径，收到 `{bad}`"),
        ));
    }
    if is_allowed(canonical, allow_paths) {
        return Ok(());
    }
    Err(OpError::new(
        codes::PATH_NOT_ALLOWED,
        format!(
            "路径 {requested} 不在 allow.paths 之内（允许：{}）",
            allow_paths.join(" / ")
        ),
    ))
}

fn kind_of(metadata: &fs::Metadata) -> &'static str {
    if metadata.is_dir() {
        "dir"
    } else if metadata.is_file() {
        "file"
    } else if metadata.file_type().is_symlink() {
        "symlink"
    } else {
        "other"
    }
}

/// 打开一个**普通文件**，返回句柄与打开后的元数据。
///
/// `O_NONBLOCK` + 打开后再 fstat：既防 FIFO 把执行器挂住，也避开
/// 「先 stat 后 open」之间的替换竞态。普通文件不受 `O_NONBLOCK` 影响。
pub(super) fn open_regular(path: &Path) -> Result<(fs::File, fs::Metadata), OpError> {
    let file = fs::OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NONBLOCK)
        .open(path)
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("打开文件失败：{err}")))?;
    let metadata = file
        .metadata()
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取文件元数据失败：{err}")))?;
    if !metadata.is_file() {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!(
                "只能读取普通文件（{} 是 {}）",
                path.display(),
                kind_of(&metadata)
            ),
        ));
    }
    Ok((file, metadata))
}

fn stat(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: StatArgs = parse_args(input.args)?;
    let path = resolve_allowed(&args.path, input.allow_paths)?;
    let metadata = fs::symlink_metadata(&path)
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("stat 失败：{err}")))?;

    // `resolve_allowed` 已经 canonicalize，末级符号链接已被解开；
    // 这里用 `symlink_metadata` 只是为了「打开前不跟随新建的链接」这一层保险。
    let kind = kind_of(&metadata);
    let modified = mtime_unix(&metadata);

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_STAT,
            "path": args.path,
            "canonical": path.display().to_string(),
            "kind": kind,
            "size_bytes": metadata.len(),
            "mode": format!("{:o}", metadata.mode() & 0o7777),
            "uid": metadata.uid(),
            "gid": metadata.gid(),
            "mtime_unix": modified,
        }),
    })
}

fn read_range(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: ReadRangeArgs = parse_args(input.args)?;
    let offset = args.offset.unwrap_or(0);
    let requested = args.length.unwrap_or(4 * 1024);
    if requested == 0 {
        return Err(OpError::new(codes::INVALID_ARGS, "length 必须大于 0"));
    }
    let cap = MAX_READ_BYTES.min(input.budget.max_bytes.max(1));
    let length = requested.min(cap);
    let path = resolve_allowed(&args.path, input.allow_paths)?;
    let (mut file, _metadata) = open_regular(&path)?;

    file.seek(SeekFrom::Start(offset))
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("定位失败：{err}")))?;

    let mut buffer = vec![0u8; length as usize];
    let mut read_total = 0usize;
    loop {
        let read = file
            .read(&mut buffer[read_total..])
            .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取失败：{err}")))?;
        if read == 0 {
            break;
        }
        read_total += read;
        if read_total >= length as usize {
            break;
        }
    }
    buffer.truncate(read_total);

    // 「刚好读满」不等于「后面没有」：再探一个字节，才能说准 `truncated`。
    let mut truncated = false;
    if read_total as u64 == length {
        let mut probe = [0u8; 1];
        truncated = file.read(&mut probe).map(|read| read > 0).unwrap_or(false);
    }

    // 只回显 UTF-8 正文；二进制只报长度，不把字节塞进 JSON。
    let text = String::from_utf8(buffer);
    let (body, binary) = match text {
        Ok(text) => (Value::String(text), false),
        Err(_) => (Value::Null, true),
    };

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_READ,
            "path": args.path,
            "canonical": path.display().to_string(),
            "offset": offset,
            "length": length,
            "bytes_read": read_total,
            "truncated": truncated,
            "binary": binary,
            "text": body,
        }),
    })
}

#[derive(Debug)]
struct FindRun {
    limit: usize,
    items: Vec<Value>,
    matched: u64,
    entries: u64,
    complete: bool,
    /// 名字命中了但被 `kind` 过滤掉。
    by_kind: u64,
    symlink: u64,
    unreadable: u64,
    /// 到了 `max_depth` 就不再往下走（不是错误，但要让人知道看到的是浅层）。
    depth_capped: u64,
}

impl FindRun {
    fn new(limit: usize) -> Self {
        Self {
            limit,
            items: Vec::new(),
            matched: 0,
            entries: 0,
            complete: true,
            by_kind: 0,
            symlink: 0,
            unreadable: 0,
            depth_capped: 0,
        }
    }
}

/// 名字搜索：**只看文件名、永不跟随符号链接**，条目与时间都有界。
///
/// `max_depth` 的算法：`root` 自己算 level 0，所以 `max_depth = 1` 只看 root 直接子项。
fn walk_find(
    root: &Path,
    max_depth: usize,
    matcher: &GlobSet,
    kind: KindFilter,
    deadline: Instant,
    run: &mut FindRun,
) {
    let mut stack: Vec<(PathBuf, usize)> = vec![(root.to_path_buf(), 1)];
    while let Some((dir, level)) = stack.pop() {
        if run.entries >= MAX_FIND_ENTRIES || Instant::now() >= deadline {
            run.complete = false;
            return;
        }
        let Ok(read) = fs::read_dir(&dir) else {
            run.unreadable += 1;
            continue;
        };
        // 排序：同样一棵树两次跑出的 `items` 必须一致，否则结果无法比对。
        let mut entries: Vec<_> = read.flatten().collect();
        entries.sort_by_key(|entry| entry.file_name());

        for entry in entries {
            if run.entries >= MAX_FIND_ENTRIES || Instant::now() >= deadline {
                run.complete = false;
                return;
            }
            run.entries += 1;
            let path = entry.path();
            let Ok(meta) = fs::symlink_metadata(&path) else {
                run.unreadable += 1;
                continue;
            };
            let kind_str = kind_of(&meta);
            if kind_str == "symlink" {
                run.symlink += 1;
            }

            let name = entry.file_name().to_string_lossy().into_owned();
            if matcher.is_match(&name) {
                if kind.accepts(kind_str) {
                    // 计数不受 `limit` 影响，否则 `truncated` 会报成 false。
                    run.matched += 1;
                    if run.items.len() < run.limit {
                        run.items.push(json!({
                            "path": path.display().to_string(),
                            "kind": kind_str,
                            "size_bytes": if meta.is_file() { Some(meta.len()) } else { None },
                            "mtime_unix": mtime_unix(&meta),
                        }));
                    }
                } else {
                    run.by_kind += 1;
                }
            }

            // 目录才递归；符号链接指向的目录不跟（否则循环 + 越出白名单都可能）。
            if meta.is_dir() {
                if level < max_depth {
                    stack.push((path, level + 1));
                } else {
                    run.depth_capped += 1;
                }
            }
        }
    }
}

fn find(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: FindArgs = parse_args(input.args)?;
    let matcher = compile_pattern(&args.pattern)?;
    let kind = KindFilter::parse(args.kind.as_deref())?;
    let max_depth = args
        .max_depth
        .unwrap_or(DEFAULT_FIND_DEPTH)
        .clamp(1, MAX_FIND_DEPTH);
    let limit = args
        .limit
        .unwrap_or(DEFAULT_FIND_LIMIT)
        .clamp(1, input.budget.max_items.clamp(1, MAX_FIND_LIMIT));
    // root 必须命中 `allow.paths`；子项都在它下面且不跟链接，所以不用逐项再判。
    let root = resolve_allowed(&args.root, input.allow_paths)?;

    let started = Instant::now();
    let mut run = FindRun::new(limit);
    walk_find(
        &root,
        max_depth,
        &matcher,
        kind,
        started + input.budget.duration(),
        &mut run,
    );

    let truncated = run.matched > run.items.len() as u64;
    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_FIND,
            "root": args.root,
            "canonical_root": root.display().to_string(),
            "pattern": args.pattern,
            "kind": kind.id(),
            "max_depth": max_depth,
            "limit": limit,
            "scan": {
                "entries": run.entries,
                "complete": run.complete,
                "duration_ms": started.elapsed().as_millis() as u64,
            },
            "matched": run.matched,
            "returned": run.items.len(),
            "truncated": truncated,
            "items": run.items,
            "skipped": {
                "symlink": run.symlink,
                "by_kind": run.by_kind,
                "unreadable": run.unreadable,
                "depth_capped": run.depth_capped,
            },
        }),
    })
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct HashArgs {
    path: String,
    #[serde(default)]
    max_bytes: Option<u64>,
}

/// 64 KiB 读缓冲：与 `read_range` 同量级。
const HASH_CHUNK: usize = 64 * 1024;

pub(super) fn to_hex(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(HEX[(byte >> 4) as usize] as char);
        out.push(HEX[(byte & 0x0f) as usize] as char);
    }
    out
}

/// 一段字节的 sha256（小写 hex）。`file.hash` 与 `config.*` 的备份/前后验共用。
pub(super) fn sha256_hex(bytes: &[u8]) -> String {
    to_hex(&Sha256::digest(bytes))
}

/// 只对**完整文件**算摘要。
///
/// 超上限或文件在读取中长大时，`sha256 = null` + `truncated = true`：
/// 半截哈希看起来像真哈希，比没有更危险。
fn hash(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: HashArgs = parse_args(input.args)?;
    let cap = args
        .max_bytes
        .unwrap_or(input.budget.max_bytes)
        .min(input.budget.max_bytes);
    if cap == 0 {
        return Err(OpError::new(codes::INVALID_ARGS, "max_bytes 必须大于 0"));
    }
    let path = resolve_allowed(&args.path, input.allow_paths)?;
    let (mut file, metadata) = open_regular(&path)?;
    let size = metadata.len();

    let mut hasher = Sha256::new();
    let mut hashed = 0u64;
    let mut too_large = size > cap;
    if !too_large {
        let mut buffer = vec![0u8; HASH_CHUNK];
        loop {
            let read = file
                .read(&mut buffer)
                .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取失败：{err}")))?;
            if read == 0 {
                break;
            }
            hashed += read as u64;
            // 文件可能在 fstat 之后长大：超预算就停，**不给半截哈希**。
            if hashed > cap {
                too_large = true;
                break;
            }
            hasher.update(&buffer[..read]);
        }
    }

    let mut value = json!({
        "schema": SCHEMA_HASH,
        "path": args.path,
        "canonical": path.display().to_string(),
        "algorithm": "sha256",
        "size_bytes": size,
        "hashed_bytes": if too_large { 0 } else { hashed },
        "sha256": if too_large { None } else { Some(to_hex(&hasher.finalize())) },
        "truncated": too_large,
        "mtime_unix": mtime_unix(&metadata),
        "limits": { "max_bytes": cap },
    });
    if too_large {
        value["notes"] = json!([format!(
            "文件超过 {cap} 字节上限或读取中变大：未计算摘要（半截哈希比没有更危险）"
        )]);
    }
    Ok(OpOutput { value })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-file-opcode-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn input<'a>(args: &'a serde_json::Value, allow: &'a [String]) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: allow,
            budget: super::OpBudget::new(60_000, 1, MAX_READ_BYTES),
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    #[test]
    fn an_empty_allow_list_denies_everything() {
        let dir = temp_dir("empty-allow");
        let file = dir.join("a.txt");
        fs::write(&file, b"hello").expect("write");
        let args = json!({ "path": file.display().to_string() });
        let err = stat(&input(&args, &[])).expect_err("empty allow list must deny");
        assert_eq!(err.code, codes::PATH_NOT_ALLOWED);
    }

    #[test]
    fn paths_outside_the_allow_list_are_rejected() {
        let allowed = temp_dir("allowed");
        let outside = temp_dir("outside");
        let file = outside.join("a.txt");
        fs::write(&file, b"hello").expect("write");

        let allow = vec![allowed.display().to_string()];
        let args = json!({ "path": file.display().to_string() });
        let err = stat(&input(&args, &allow)).expect_err("outside path");
        assert_eq!(err.code, codes::PATH_NOT_ALLOWED);
    }

    #[test]
    fn relative_paths_are_rejected() {
        let allow = vec!["/tmp".to_string()];
        let args = json!({ "path": "etc/passwd" });
        let err = stat(&input(&args, &allow)).expect_err("relative path");
        assert_eq!(err.code, codes::INVALID_ARGS);
    }

    #[test]
    fn relative_allow_entries_are_rejected_instead_of_silently_skipped() {
        // 静默跳过会让现场以为「配了白名单」却永远被拒：这是计划自身的错，要报出来。
        let dir = temp_dir("relative-allow");
        let file = dir.join("a.txt");
        fs::write(&file, b"hello").expect("write");

        let allow = vec![dir.display().to_string(), "var/log".to_string()];
        let args = json!({ "path": file.display().to_string() });
        let err = stat(&input(&args, &allow)).expect_err("relative allow entry");
        assert_eq!(err.code, codes::INVALID_ARGS);
        assert!(err.detail.contains("var/log"), "{}", err.detail);
    }

    #[test]
    fn stat_and_read_work_inside_the_allow_list() {
        let dir = temp_dir("inside");
        let file = dir.join("a.txt");
        fs::write(&file, b"hello world").expect("write");
        let allow = vec![dir.display().to_string()];

        let stat_args = json!({ "path": file.display().to_string() });
        let stat_out = stat(&input(&stat_args, &allow)).expect("stat");
        assert_eq!(stat_out.value["kind"], "file");
        assert_eq!(stat_out.value["size_bytes"], 11);

        let read_args = json!({
            "path": file.display().to_string(),
            "offset": 6,
            "length": 5,
        });
        let read_out = read_range(&input(&read_args, &allow)).expect("read");
        assert_eq!(read_out.value["text"], "world");
        assert_eq!(read_out.value["bytes_read"], 5);
    }

    #[test]
    fn read_length_is_capped_and_reported() {
        let dir = temp_dir("cap");
        let file = dir.join("a.txt");
        fs::write(&file, vec![b'x'; 70 * 1024]).expect("write");
        let allow = vec![dir.display().to_string()];

        let args = json!({
            "path": file.display().to_string(),
            "length": 10 * 1024 * 1024,
        });
        let output = read_range(&input(&args, &allow)).expect("read");
        assert_eq!(output.value["length"], MAX_READ_BYTES);
        assert_eq!(output.value["bytes_read"], MAX_READ_BYTES);
        assert_eq!(output.value["truncated"], true);
    }

    #[test]
    fn read_truncation_is_about_more_bytes_not_about_hitting_the_cap() {
        let dir = temp_dir("trunc-boundary");
        let allow = vec![dir.display().to_string()];

        let exact = dir.join("exact.txt");
        fs::write(&exact, b"abcde").expect("write exact");
        let args = json!({ "path": exact.display().to_string(), "length": 5 });
        let output = read_range(&input(&args, &allow)).expect("read exact");
        assert_eq!(output.value["bytes_read"], 5);
        assert_eq!(output.value["truncated"], false);

        let longer = dir.join("longer.txt");
        fs::write(&longer, b"abcdef").expect("write longer");
        let args = json!({ "path": longer.display().to_string(), "length": 5 });
        let output = read_range(&input(&args, &allow)).expect("read longer");
        assert_eq!(output.value["bytes_read"], 5);
        assert_eq!(output.value["truncated"], true);
    }

    #[test]
    fn read_range_refuses_non_regular_files() {
        let dir = temp_dir("non-regular");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).expect("sub dir");
        let allow = vec![dir.display().to_string()];

        let args = json!({ "path": sub.display().to_string() });
        let err = read_range(&input(&args, &allow)).expect_err("directory is not readable");
        assert_eq!(err.code, codes::INVALID_ARGS);
    }

    #[test]
    fn a_symlink_escape_is_rejected_even_if_the_parent_is_allowed() {
        let allowed = temp_dir("escape-allowed");
        let outside = temp_dir("escape-outside");
        let secret = outside.join("secret.txt");
        fs::write(&secret, b"topsecret").expect("write secret");
        let link = allowed.join("leak.txt");
        std::os::unix::fs::symlink(&secret, &link).expect("symlink");

        let allow = vec![allowed.display().to_string()];
        let args = json!({ "path": link.display().to_string() });
        let err = read_range(&input(&args, &allow)).expect_err("escape must be rejected");
        assert_eq!(err.code, codes::PATH_NOT_ALLOWED);
    }

    #[test]
    fn binary_content_is_not_echoed() {
        let dir = temp_dir("binary");
        let file = dir.join("a.bin");
        fs::write(&file, [0xff, 0xfe, 0x00, 0x01]).expect("write");
        let allow = vec![dir.display().to_string()];

        let args = json!({ "path": file.display().to_string() });
        let output = read_range(&input(&args, &allow)).expect("read");
        assert_eq!(output.value["binary"], true);
        assert!(output.value["text"].is_null());
        assert_eq!(output.value["bytes_read"], 4);
    }

    fn find_input<'a>(args: &'a serde_json::Value, allow: &'a [String]) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: allow,
            budget: FIND_SPEC.budget,
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    fn find_tree(name: &str) -> PathBuf {
        let dir = temp_dir(name);
        fs::write(dir.join("a.log"), b"a").expect("write a");
        fs::write(dir.join("other.txt"), b"o").expect("write other");
        let sub = dir.join("sub");
        fs::create_dir_all(&sub).expect("sub");
        fs::write(sub.join("b.log"), b"bb").expect("write b");
        let deeper = sub.join("deeper");
        fs::create_dir_all(&deeper).expect("deeper");
        fs::write(deeper.join("c.log"), b"ccc").expect("write c");
        dir
    }

    fn found_paths(value: &Value) -> Vec<String> {
        value["items"]
            .as_array()
            .expect("items")
            .iter()
            .map(|item| item["path"].as_str().unwrap_or_default().to_string())
            .collect()
    }

    #[test]
    fn find_matches_file_names_within_the_requested_depth() {
        let root = find_tree("find-depth");
        let allow = vec![root.display().to_string()];
        let base = json!({ "root": root.display().to_string(), "pattern": "*.log" });

        let mut shallow = base.clone();
        shallow["max_depth"] = json!(1);
        let out = find(&find_input(&shallow, &allow)).expect("shallow");
        assert_eq!(found_paths(&out.value).len(), 1);
        assert_eq!(out.value["skipped"]["depth_capped"], 1);

        let out = find(&find_input(&base, &allow)).expect("full");
        assert_eq!(found_paths(&out.value).len(), 3);
        assert_eq!(out.value["scan"]["complete"], true);
        assert_eq!(out.value["matched"], 3);
        assert_eq!(out.value["truncated"], false);
        assert_eq!(out.value["kind"], "file");
        // 非文件类型不占 `items`，也不计入 matched。
        assert!(
            !found_paths(&out.value)
                .iter()
                .any(|path| path.ends_with("other.txt"))
        );
    }

    #[test]
    fn find_keeps_counting_matches_after_the_listing_is_capped() {
        let root = find_tree("find-limit");
        let allow = vec![root.display().to_string()];
        let args = json!({
            "root": root.display().to_string(),
            "pattern": "*.log",
            "limit": 1,
        });
        let out = find(&find_input(&args, &allow)).expect("find");
        assert_eq!(out.value["returned"], 1);
        assert_eq!(out.value["matched"], 3);
        assert_eq!(out.value["truncated"], true);
    }

    #[test]
    fn find_never_follows_symlinks() {
        let root = temp_dir("find-links");
        let outside = temp_dir("find-outside");
        fs::write(outside.join("secret.log"), b"secret").expect("write secret");
        std::os::unix::fs::symlink(outside.join("secret.log"), root.join("link.log"))
            .expect("file link");
        std::os::unix::fs::symlink(&outside, root.join("dirlink")).expect("dir link");

        let allow = vec![root.display().to_string()];
        let args = json!({ "root": root.display().to_string(), "pattern": "*.log" });
        let out = find(&find_input(&args, &allow)).expect("find");

        // 默认 kind=file：链接不是文件，一条都不返回，但如实计入 by_kind/symlink。
        assert!(found_paths(&out.value).is_empty());
        assert_eq!(out.value["matched"], 0);
        assert_eq!(out.value["skipped"]["symlink"], 2);
        assert_eq!(out.value["skipped"]["by_kind"], 1);

        // kind=any 时链接会被列出（只给路径，不给目标），目录链接也**不会**被展开。
        let args = json!({
            "root": root.display().to_string(),
            "pattern": "*",
            "kind": "any",
        });
        let out = find(&find_input(&args, &allow)).expect("find any");
        let names = found_paths(&out.value);
        assert!(names.iter().any(|path| path.ends_with("link.log")));
        assert!(names.iter().any(|path| path.ends_with("dirlink")));
        assert!(
            !names.iter().any(|path| path.ends_with("secret.log")),
            "符号链接指向的目录不能被展开"
        );
    }

    #[test]
    fn find_respects_the_allow_list_and_the_pattern_shape() {
        let root = temp_dir("find-allow");
        fs::write(root.join("a.log"), b"a").expect("write");
        let args = json!({ "root": root.display().to_string(), "pattern": "*.log" });

        let err = find(&find_input(&args, &[])).expect_err("no allow list");
        assert_eq!(err.code, codes::PATH_NOT_ALLOWED);

        let allow = vec![root.display().to_string()];
        for bad in ["", "sub/*.log", "a\\b"] {
            let args = json!({ "root": root.display().to_string(), "pattern": bad });
            let err = find(&find_input(&args, &allow)).expect_err("bad pattern");
            assert_eq!(err.code, codes::INVALID_ARGS, "pattern {bad:?}");
        }

        let args = json!({ "root": root.display().to_string(), "pattern": "*", "kind": "socket" });
        let err = find(&find_input(&args, &allow)).expect_err("bad kind");
        assert_eq!(err.code, codes::INVALID_ARGS);
    }

    #[test]
    fn find_can_look_for_directories_only() {
        let root = find_tree("find-dirs");
        let allow = vec![root.display().to_string()];
        let args = json!({
            "root": root.display().to_string(),
            "pattern": "*",
            "kind": "dir",
        });
        let out = find(&find_input(&args, &allow)).expect("find dirs");
        let names = found_paths(&out.value);
        assert_eq!(names.len(), 2, "{names:?}");
        assert!(names.iter().all(|path| !path.ends_with(".log")));
    }

    #[test]
    fn find_depth_is_clamped_to_the_registered_range() {
        let root = find_tree("find-clamp");
        let allow = vec![root.display().to_string()];
        for (requested, expected) in [(0usize, 1usize), (9_999, MAX_FIND_DEPTH)] {
            let args = json!({
                "root": root.display().to_string(),
                "pattern": "*.log",
                "max_depth": requested,
            });
            let out = find(&find_input(&args, &allow)).expect("find");
            assert_eq!(out.value["max_depth"], expected);
        }
    }

    #[test]
    fn find_of_a_missing_root_is_target_not_found() {
        let root = temp_dir("find-missing");
        let allow = vec![root.display().to_string()];
        let args = json!({
            "root": root.join("nope").display().to_string(),
            "pattern": "*",
        });
        let err = find(&find_input(&args, &allow)).expect_err("missing root");
        assert_eq!(err.code, codes::TARGET_NOT_FOUND);
    }

    fn hash_input<'a>(
        args: &'a serde_json::Value,
        allow: &'a [String],
        max_bytes: u64,
    ) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: allow,
            budget: super::OpBudget::new(60_000, 1, max_bytes),
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    #[test]
    fn hash_reports_the_digest_of_a_whole_file() {
        let dir = temp_dir("hash");
        let file = dir.join("a.txt");
        fs::write(&file, b"hello world").expect("write");
        let allow = vec![dir.display().to_string()];
        let args = json!({ "path": file.display().to_string() });

        let out = hash(&hash_input(&args, &allow, MAX_HASH_BYTES)).expect("hash");
        assert_eq!(out.value["schema"], SCHEMA_HASH);
        assert_eq!(out.value["algorithm"], "sha256");
        assert_eq!(out.value["size_bytes"], 11);
        assert_eq!(out.value["hashed_bytes"], 11);
        assert_eq!(out.value["truncated"], false);
        assert_eq!(
            out.value["sha256"],
            "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        );
        assert!(out.value.get("notes").is_none());

        // 空文件也要是一个确定值，不能拿“没内容”当“没算”。
        let empty = dir.join("empty.txt");
        fs::write(&empty, b"").expect("write empty");
        let args = json!({ "path": empty.display().to_string() });
        let out = hash(&hash_input(&args, &allow, MAX_HASH_BYTES)).expect("hash empty");
        assert_eq!(
            out.value["sha256"],
            "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
        );
    }

    #[test]
    fn hash_refuses_to_report_a_partial_digest() {
        let dir = temp_dir("hash-large");
        let file = dir.join("big.bin");
        fs::write(&file, vec![7u8; 200]).expect("write");
        let allow = vec![dir.display().to_string()];
        let args = json!({ "path": file.display().to_string() });

        let out = hash(&hash_input(&args, &allow, 100)).expect("hash");
        assert_eq!(out.value["truncated"], true);
        assert!(out.value["sha256"].is_null(), "不能给半截哈希");
        assert_eq!(out.value["size_bytes"], 200);
        assert_eq!(out.value["hashed_bytes"], 0);
        assert_eq!(out.value["limits"]["max_bytes"], 100);
        assert!(out.value["notes"].is_array());
    }

    #[test]
    fn hash_args_can_lower_the_cap_but_not_raise_it() {
        let dir = temp_dir("hash-cap");
        let file = dir.join("a.txt");
        fs::write(&file, b"hello world").expect("write");
        let allow = vec![dir.display().to_string()];

        // 参数写很大也只会被预算夹回去。
        let args = json!({ "path": file.display().to_string(), "max_bytes": 10_000_000 });
        let out = hash(&hash_input(&args, &allow, 1024)).expect("hash");
        assert_eq!(out.value["limits"]["max_bytes"], 1024);

        let args = json!({ "path": file.display().to_string(), "max_bytes": 4 });
        let out = hash(&hash_input(&args, &allow, 1024)).expect("hash");
        assert_eq!(out.value["limits"]["max_bytes"], 4);
        assert_eq!(out.value["truncated"], true);
    }

    #[test]
    fn hash_obeys_the_allow_list_and_file_type_rules() {
        let dir = temp_dir("hash-deny");
        let file = dir.join("a.txt");
        fs::write(&file, b"hello").expect("write");
        let args = json!({ "path": file.display().to_string() });

        let err = hash(&hash_input(&args, &[], MAX_HASH_BYTES)).expect_err("no allow");
        assert_eq!(err.code, codes::PATH_NOT_ALLOWED);

        let allow = vec![dir.display().to_string()];
        let err = hash(&hash_input(&args, &allow, 0)).expect_err("zero cap");
        assert_eq!(err.code, codes::INVALID_ARGS);

        let dir_args = json!({ "path": dir.display().to_string() });
        let err = hash(&hash_input(&dir_args, &allow, MAX_HASH_BYTES)).expect_err("dir");
        assert_eq!(err.code, codes::INVALID_ARGS);

        let missing = json!({ "path": dir.join("gone.txt").display().to_string() });
        let err = hash(&hash_input(&missing, &allow, MAX_HASH_BYTES)).expect_err("missing");
        assert_eq!(err.code, codes::TARGET_NOT_FOUND);
    }
}
