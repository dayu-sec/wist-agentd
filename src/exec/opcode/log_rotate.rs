//! `log.archive` / `log.rotate`（R2）：**先归档、校验、再截断**。
//!
//! 采用 copytruncate 而不是 rename：轮转的「正确」做法是 rename + 让写者重开文件，那需要
//! 给写者发信号 —— 而执行器**不 exec、也不猜主 pid**（见 `service.status` 的说明：systemd
//! 的 `ExecReload` 只有它自己知道，猜 cgroup 里哪个是主进程一旦猜错就是在给 worker 发信号）。
//! copytruncate 不需要写者配合：复制 → 复读校验 → 原地截断。
//!
//! 代价必须说清：**复制完成到截断之间写入的行会丢**（毫秒级窗口，logrotate 的
//! `copytruncate` 一样），且要求写者以 `O_APPEND` 打开文件（否则截断后会出现稀疏空洞）。
//! 两条都写进输出的 `notes`。
//!
//! 两条 op 的分工（不合并成一个带布尔的 op）：
//!
//! * `log.archive`：只归档，**不动原文件**；
//! * `log.rotate`：归档并校验通过后，才把原文件截断成 0。
//!
//! 归档名：`<原文件名>.<UTC 时间戳>.archive`，与原文件同目录。这个名字**刻意不匹配**
//! `disk.cleanup` 的轮转词表（`*.gz` / `*.[0-9]` …）：归档什么时候删是运维的决定，
//! 不该被「清理过期临时文件」顺手带走。

use std::fs;
use std::io::{Read, Write};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::path::{Path, PathBuf};

use serde::Deserialize;
use serde_json::json;
use sha2::{Digest, Sha256};
use time::OffsetDateTime;
use wist_contracts::action_plan::RiskLevel;

use crate::exec::opcode::file::{open_regular, to_hex};
use crate::exec::opcode::logs::{LogSource, resolve_source};
use crate::exec::opcode::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

const SCHEMA_ARCHIVE: &str = "wist.opcode.log_archive/v1";
const SCHEMA_ROTATE: &str = "wist.opcode.log_rotate/v1";

/// 单次归档的上限：日志比配置大，但也不是数据库。
const MAX_ARCHIVE_BYTES: u64 = 64 * 1024 * 1024;
const CHUNK: usize = 64 * 1024;
/// 同一秒内最多允许几个归档（`<stamp>`、`<stamp>-2` …）。
const MAX_ARCHIVE_ATTEMPTS: usize = 100;

pub const ARCHIVE_SPEC: OpSpec = OpSpec {
    id: "log.archive",
    risk: RiskLevel::R2,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(15_000, 1, 0),
    handler: archive,
};

pub const ROTATE_SPEC: OpSpec = OpSpec {
    id: "log.rotate",
    risk: RiskLevel::R2,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(15_000, 1, 0),
    handler: rotate,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogArgs {
    /// 闭集：`syslog` / `auth` / `kern`（与 `log.read_range` 同一份词表）。
    source: String,
}

#[derive(Debug)]
struct Archived {
    path: PathBuf,
    sha256: String,
    size_bytes: u64,
}

fn archive_path_for(path: &Path, stamp: &str) -> PathBuf {
    let parent = path.parent().unwrap_or_else(|| Path::new("/"));
    let name = path
        .file_name()
        .map(|name| name.to_string_lossy().to_string())
        .unwrap_or_else(|| "log".to_string());
    parent.join(format!("{name}.{stamp}.archive"))
}

/// 时间戳只用于命名：`20261122T153000Z`（排序即时间序）。
///
/// 不用 `time::macros` 的格式串：本仓没有开那个 feature，手拼四个字段更省依赖。
fn stamp_now() -> String {
    let now = OffsetDateTime::now_utc();
    format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        now.year(),
        u8::from(now.month()),
        now.day(),
        now.hour(),
        now.minute(),
        now.second()
    )
}

fn sha256_of_file(path: &Path) -> Result<(String, u64), OpError> {
    let mut file = fs::File::open(path).map_err(|err| {
        OpError::new(
            codes::OP_FAILED,
            format!("打开失败 {}：{err}", path.display()),
        )
    })?;
    let mut hasher = Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = file.read(&mut buffer).map_err(|err| {
            OpError::new(
                codes::OP_FAILED,
                format!("读取失败 {}：{err}", path.display()),
            )
        })?;
        if read == 0 {
            break;
        }
        hasher.update(&buffer[..read]);
        total += read as u64;
    }
    Ok((to_hex(&hasher.finalize()), total))
}

/// 复制 + 复读校验。**校验不过会把半成品删掉**，不留一个看起来像归档的坏文件。
fn copy_and_verify(source: &Path, stamp: &str, limit: u64) -> Result<Archived, OpError> {
    let (mut file, meta) = open_regular(source)?;
    let size = meta.len();
    if size > limit {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("日志 {size} 字节超过归档上限 {limit}，不在这一版处理"),
        ));
    }
    if size == 0 {
        return Err(OpError::new(
            codes::OP_FAILED,
            format!("{} 是空的，没有可归档的内容", source.display()),
        ));
    }

    // 同一秒内做两次归档（例如 archive 紧跟 rotate）会撞名。
    // 归档名要能按名字排序，所以保留时间戳、只追加序号，并在循环里用 `create_new`
    // 完成「检查 + 创建」——**任何情况下都不覆盖已有归档**。
    let (mut out, archive_path) = open_archive(source, stamp)?;

    let mut hasher = Sha256::new();
    let mut copied = 0u64;
    let mut buffer = vec![0u8; CHUNK];
    let copy_result = (|| -> std::io::Result<()> {
        loop {
            let read = file.read(&mut buffer)?;
            if read == 0 {
                break;
            }
            hasher.update(&buffer[..read]);
            out.write_all(&buffer[..read])?;
            copied += read as u64;
            // 文件在复制过程中长大：超上限就停手，不拿半截当归档。
            if copied > limit {
                return Err(std::io::Error::other(format!(
                    "日志在复制过程中超过上限 {limit}"
                )));
            }
        }
        out.sync_all()
    })();

    if let Err(err) = copy_result {
        let _ = fs::remove_file(&archive_path);
        return Err(OpError::new(
            codes::OP_FAILED,
            format!("归档复制失败（已删除半成品）：{err}"),
        ));
    }
    let digest = to_hex(&hasher.finalize());

    // 复读校验：归档自己必须是完整的，否则不能拿它当「原文件已经被保存过」的依据。
    let (archived_sha, archived_len) = sha256_of_file(&archive_path)?;
    if archived_sha != digest || archived_len != copied {
        let _ = fs::remove_file(&archive_path);
        return Err(OpError::new(
            codes::ARCHIVE_INCOMPLETE,
            format!(
                "归档复读校验不通过（写入 {copied} 字节 / 读回 {archived_len} 字节）；已删除残缺归档，原文件未动"
            ),
        ));
    }

    Ok(Archived {
        path: archive_path,
        sha256: digest,
        size_bytes: copied,
    })
}

/// 原子地拿到一个可写的归档路径：`<name>.<stamp>.archive`，撞名就试 `-2`、`-3` ……
fn open_archive(source: &Path, stamp: &str) -> Result<(fs::File, PathBuf), OpError> {
    for attempt in 1..=MAX_ARCHIVE_ATTEMPTS {
        let candidate = if attempt == 1 {
            archive_path_for(source, stamp)
        } else {
            archive_path_for(source, &format!("{stamp}-{attempt}"))
        };
        match fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&candidate)
        {
            Ok(file) => return Ok((file, candidate)),
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(err) => {
                return Err(OpError::new(
                    codes::OP_FAILED,
                    format!("创建归档失败 {}：{err}", candidate.display()),
                ));
            }
        }
    }
    Err(OpError::new(
        codes::OP_FAILED,
        format!(
            "{} 个候选归档名都被占用（同一秒归档次数异常），本次不归档",
            MAX_ARCHIVE_ATTEMPTS
        ),
    ))
}

fn limits_note() -> &'static str {
    "copytruncate：复制完成到截断之间写入的行会丢（毫秒级窗口，无法消除）；\
     写入方需要用 O_APPEND 打开，否则截断后会留下空洞"
}

fn archive(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: LogArgs = parse_args(input.args)?;
    let source = LogSource::parse(&args.source)?;
    let path = resolve_source(source)?;
    let archived = copy_and_verify(&path, &stamp_now(), MAX_ARCHIVE_BYTES)?;

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_ARCHIVE,
            "source": source.id(),
            "path": path.display().to_string(),
            "archive": {
                "path": archived.path.display().to_string(),
                "sha256": archived.sha256,
                "size_bytes": archived.size_bytes,
                "mode": "0600",
            },
            "truncated": false,
            "notes": [
                "只归档，不动原文件；要腾空间请接着跑 `log.rotate`",
                "归档名不匹配 disk.cleanup 的轮转词表：什么时候删由运维决定",
            ],
        }),
    })
}

fn rotate(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: LogArgs = parse_args(input.args)?;
    let source = LogSource::parse(&args.source)?;
    let path = resolve_source(source)?;

    // ① 归档并校验：**这一步失败就什么都不截断**。
    let archived = copy_and_verify(&path, &stamp_now(), MAX_ARCHIVE_BYTES)?;
    let size_before = archived.size_bytes;

    // ② 原地截断：写者保持自己的 fd，继续往新文件头写。
    let (file, meta) = open_regular(&path)?;
    let mode = meta.mode() & 0o7777;
    let uid = meta.uid();
    let gid = meta.gid();
    drop(file);
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .and_then(|file| file.set_len(0))
        .map_err(|err| {
            OpError::new(
                codes::WRITE_FAILED,
                format!(
                    "截断 {} 失败：{err}（归档已在 {}，内容没有丢）",
                    path.display(),
                    archived.path.display()
                ),
            )
        })?;

    // ③ 复核：截断后必须真的变 0。
    let size_after = fs::metadata(&path)
        .map_err(|err| {
            OpError::new(
                codes::OP_FAILED,
                format!("截断后读取 {} 失败：{err}", path.display()),
            )
        })?
        .len();
    if size_after != 0 {
        return Err(OpError::new(
            codes::VERIFY_FAILED,
            format!(
                "截断后文件仍有 {size_after} 字节（归档在 {}）",
                archived.path.display()
            ),
        ));
    }

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA_ROTATE,
            "source": source.id(),
            "path": path.display().to_string(),
            "archive": {
                "path": archived.path.display().to_string(),
                "sha256": archived.sha256,
                "size_bytes": archived.size_bytes,
                "mode": "0600",
            },
            "truncated": {
                "size_before": size_before,
                "size_after": size_after,
                // 截断只改元数据，属主/权限不动 —— 这里如实回显，便于对账。
                "mode": format!("{mode:04o}"),
                "uid": uid,
                "gid": gid,
            },
            "notes": [
                limits_note(),
                "原文件是原地截断（inode 不变），所以写者的 fd 继续有效",
                "归档名不匹配 disk.cleanup 的轮转词表：什么时候删由运维决定",
            ],
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-log-rotate-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn write_log(path: &Path, body: &str) {
        fs::write(path, body).expect("write log");
        fs::set_permissions(path, fs::Permissions::from_mode(0o640)).expect("mode");
    }

    #[test]
    fn the_source_vocabulary_is_shared_with_read_range() {
        assert_eq!(LogSource::parse("syslog").unwrap().id(), "syslog");
        for bad in ["journald", "audit", "everything"] {
            assert_eq!(
                LogSource::parse(bad).unwrap_err().code,
                codes::UNSUPPORTED_TARGET
            );
        }
    }

    #[test]
    fn archive_copies_bytes_and_verifies_them_without_touching_the_original() {
        let dir = temp_dir("archive");
        let log = dir.join("auth.log");
        let body = "line-1\nline-2\nline-3\n";
        write_log(&log, body);

        let archived =
            copy_and_verify(&log, "20261122T153000Z", MAX_ARCHIVE_BYTES).expect("archive");
        assert_eq!(archived.path, dir.join("auth.log.20261122T153000Z.archive"));
        assert_eq!(archived.size_bytes, body.len() as u64);
        assert_eq!(fs::read_to_string(&archived.path).expect("read"), body);
        // 原文件一字未动。
        assert_eq!(fs::read_to_string(&log).expect("read"), body);
        // 归档是 0600：里面可能有敏感行。
        assert_eq!(
            fs::metadata(&archived.path)
                .expect("meta")
                .permissions()
                .mode()
                & 0o7777,
            0o600
        );
    }

    #[test]
    fn a_second_archive_in_the_same_second_gets_a_suffix_instead_of_overwriting() {
        let dir = temp_dir("collision");
        let log = dir.join("syslog");
        write_log(&log, "first snapshot\n");

        let first = copy_and_verify(&log, "STAMP", MAX_ARCHIVE_BYTES).expect("first");
        assert_eq!(first.path, dir.join("syslog.STAMP.archive"));

        // 同一个时间戳再归档一次（archive 紧跟 rotate 就是这个形状）：
        // 不能覆盖已有归档，也不能直接失败。
        fs::write(&log, "second snapshot\n").expect("append");
        let second = copy_and_verify(&log, "STAMP", MAX_ARCHIVE_BYTES).expect("second");
        assert_eq!(second.path, dir.join("syslog.STAMP-2.archive"));
        assert_eq!(
            fs::read_to_string(&first.path).expect("read first"),
            "first snapshot\n",
            "已有归档不能被覆盖"
        );
        assert_eq!(
            fs::read_to_string(&second.path).expect("read second"),
            "second snapshot\n"
        );
    }

    #[test]
    fn a_hand_made_collision_is_skipped_rather_than_trusted() {
        let dir = temp_dir("hand-made");
        let log = dir.join("syslog");
        write_log(&log, "x\n");
        let existing = dir.join("syslog.STAMP.archive");
        fs::write(&existing, "keep me").expect("write existing");

        let archived = copy_and_verify(&log, "STAMP", MAX_ARCHIVE_BYTES).expect("archive");
        assert_eq!(archived.path, dir.join("syslog.STAMP-2.archive"));
        assert_eq!(
            fs::read_to_string(&existing).expect("read"),
            "keep me",
            "别人放的归档文件不能被覆盖"
        );
    }

    #[test]
    fn oversized_and_empty_logs_are_refused() {
        let dir = temp_dir("bounds");
        let big = dir.join("big.log");
        write_log(&big, &"x".repeat(2048));
        let err = copy_and_verify(&big, "S", 1024).expect_err("oversized");
        assert_eq!(err.code, codes::INVALID_ARGS);

        let empty = dir.join("empty.log");
        write_log(&empty, "");
        let err = copy_and_verify(&empty, "S", 1024).expect_err("empty");
        assert_eq!(err.code, codes::OP_FAILED);
        // 两种拒绝都不能留下归档文件。
        assert!(!dir.join("big.log.S.archive").exists());
        assert!(!dir.join("empty.log.S.archive").exists());
    }

    #[test]
    fn verification_reads_the_archive_back_from_disk() {
        // 校验必须依据「从磁盘读回来的内容」，不能信内存里的缓冲。
        let dir = temp_dir("verify");
        let log = dir.join("kern.log");
        write_log(&log, "kernel line\n");
        let archived = copy_and_verify(&log, "V1", MAX_ARCHIVE_BYTES).expect("archive");
        fs::write(&archived.path, "tampered").expect("tamper");
        let (sha, len) = sha256_of_file(&archived.path).expect("hash");
        assert_ne!(sha, archived.sha256);
        assert_ne!(len, archived.size_bytes);
    }

    #[test]
    fn archive_paths_sort_by_time_and_sit_next_to_the_log() {
        let log = Path::new("/var/log/syslog");
        let earlier = archive_path_for(log, "20261122T100000Z");
        let later = archive_path_for(log, "20261122T110000Z");
        assert_eq!(
            earlier.parent(),
            Some(Path::new("/var/log")),
            "归档与原文件同目录"
        );
        assert!(earlier.to_string_lossy() < later.to_string_lossy());
        assert!(
            !earlier
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .ends_with(".gz"),
            "归档名刻意不匹配 disk.cleanup 的轮转词表"
        );
    }

    #[test]
    fn op_metadata_is_a_change_class_action() {
        assert_eq!(ARCHIVE_SPEC.risk, RiskLevel::R2);
        assert_eq!(ROTATE_SPEC.risk, RiskLevel::R2);
        assert_eq!(ARCHIVE_SPEC.id, "log.archive");
        assert_eq!(ROTATE_SPEC.id, "log.rotate");
    }
}
