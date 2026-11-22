//! `config.backup` / `apply` / `rollback` 的单测。
//!
//! 这里刻意不做「假的文件系统」：三个 op 的核心是**真实落盘语义**（临时文件 + rename +
//! 属主/权限 + 摘要），用内存假件测出来的「通过」没有意义。

use std::fs;
use std::os::unix::fs::{MetadataExt, PermissionsExt};
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

use serde_json::{Value, json};

use crate::exec::opcode::file::sha256_hex;
use crate::exec::opcode::{BackupContext, OpBudget, OpError, OpInput, OpOutput, codes};

use super::backup::backup;
use super::change::{apply, rollback};
use super::store::MAX_BACKUP_BYTES;

struct Harness {
    root: PathBuf,
    backups_root: PathBuf,
    allow: Vec<String>,
    action_id: String,
}

impl Harness {
    fn new(name: &str) -> Self {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let root = std::env::temp_dir().join(format!("wist-config-change-{name}-{suffix}"));
        fs::create_dir_all(root.join("etc")).expect("etc dir");
        fs::create_dir_all(root.join("backups")).expect("backups dir");
        Self {
            allow: vec![root.display().to_string()],
            backups_root: root.join("backups"),
            root,
            action_id: "act_config_1".to_string(),
        }
    }

    fn target(&self) -> PathBuf {
        self.root.join("etc").join("app.toml")
    }

    fn source(&self) -> PathBuf {
        self.root.join("etc").join("app.toml.new")
    }

    fn context(&self) -> BackupContext<'_> {
        BackupContext {
            root: &self.backups_root,
            action_id: &self.action_id,
        }
    }

    fn write(&self, path: &Path, body: &str, mode: u32) {
        fs::write(path, body).expect("write");
        fs::set_permissions(path, fs::Permissions::from_mode(mode)).expect("set mode");
    }

    fn run(
        &self,
        handler: fn(&OpInput<'_>) -> Result<OpOutput, OpError>,
        args: &Value,
    ) -> Result<Value, OpError> {
        let context = self.context();
        let input = OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: &self.allow,
            budget: OpBudget::new(60_000, 1, MAX_BACKUP_BYTES),
            step_timeout_ms: 60_000,
            backups: Some(&context),
        };
        handler(&input).map(|output| output.value)
    }

    fn backup(&self) -> Result<Value, OpError> {
        self.run(
            backup,
            &json!({ "path": self.target().display().to_string() }),
        )
    }

    fn apply(&self, format: &str) -> Result<Value, OpError> {
        let source = fs::read(self.source()).expect("read source");
        self.run(
            apply,
            &json!({
                "path": self.target().display().to_string(),
                "source": self.source().display().to_string(),
                "source_sha256": sha256_hex(&source),
                "format": format,
            }),
        )
    }

    fn rollback(&self, expect: Option<&str>) -> Result<Value, OpError> {
        let mut args = json!({ "path": self.target().display().to_string() });
        if let Some(expect) = expect {
            args["expect_sha256"] = json!(expect);
        }
        self.run(rollback, &args)
    }
}

fn content(path: &Path) -> String {
    fs::read_to_string(path).expect("read target")
}

fn mode_of(path: &Path) -> u32 {
    fs::metadata(path).expect("metadata").mode() & 0o7777
}

const ORIGINAL: &str = "[server]\nport = 8080\n";
const REPLACEMENT: &str = "[server]\nport = 9090\n";

#[test]
fn backup_then_apply_replaces_the_file_and_keeps_mode_and_owner() {
    let harness = Harness::new("happy");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);

    let backed_up = harness.backup().expect("backup");
    assert_eq!(backed_up["created"], true);
    assert_eq!(
        backed_up["backup"]["sha256"],
        sha256_hex(ORIGINAL.as_bytes())
    );
    assert_eq!(backed_up["backup"]["mode"], "0640");

    let applied = harness.apply("toml").expect("apply");
    assert_eq!(
        applied["written"]["sha256"],
        sha256_hex(REPLACEMENT.as_bytes())
    );
    assert_eq!(
        applied["replaced"]["sha256"],
        sha256_hex(ORIGINAL.as_bytes())
    );
    assert_eq!(applied["verify"]["hash"], true);
    assert_eq!(applied["verify"]["parse"], "toml");
    assert_eq!(applied["rolled_back"], false);

    assert_eq!(content(&harness.target()), REPLACEMENT);
    // 权限是**原文件的**，不是 staged 文件的。
    assert_eq!(mode_of(&harness.target()), 0o640);
    let owner = fs::metadata(harness.source()).expect("source meta");
    let target = fs::metadata(harness.target()).expect("target meta");
    assert_eq!(target.uid(), owner.uid());
    assert_eq!(target.gid(), owner.gid());
}

#[test]
fn apply_without_a_backup_writes_nothing() {
    let harness = Harness::new("no-backup");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);

    let err = harness.apply("toml").expect_err("no backup");
    assert_eq!(err.code, codes::BACKUP_MISSING);
    assert_eq!(content(&harness.target()), ORIGINAL, "一个字节都不能写");
}

#[test]
fn apply_without_a_backup_directory_is_refused_not_skipped() {
    let harness = Harness::new("no-store");
    harness.write(&harness.target(), ORIGINAL, 0o640);

    // 不传 context：执行器没有备份目录时，备份/应用一律拒绝。
    let input = OpInput {
        args: &json!({ "path": harness.target().display().to_string() }),
        requested_by: "tester",
        config: None,
        allow_paths: &harness.allow,
        budget: OpBudget::new(60_000, 1, MAX_BACKUP_BYTES),
        step_timeout_ms: 60_000,
        backups: None,
    };
    let err = backup(&input).expect_err("no backup dir");
    assert_eq!(err.code, codes::BACKUP_UNAVAILABLE);
    assert!(!harness.backups_root.join("act_config_1").exists());
}

#[test]
fn apply_rejects_a_source_that_does_not_match_the_declared_hash() {
    let harness = Harness::new("bad-hash");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);
    harness.backup().expect("backup");

    let err = harness
        .run(
            apply,
            &json!({
                "path": harness.target().display().to_string(),
                "source": harness.source().display().to_string(),
                "source_sha256": sha256_hex(b"something else"),
                "format": "toml",
            }),
        )
        .expect_err("hash mismatch");
    assert_eq!(err.code, codes::SOURCE_HASH_MISMATCH);
    assert_eq!(content(&harness.target()), ORIGINAL);
}

#[test]
fn apply_rejects_a_target_that_changed_after_the_backup() {
    let harness = Harness::new("target-changed");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);
    harness.backup().expect("backup");

    // 备份之后别人又改了这个文件：覆盖它会悄悄吞掉别人的改动。
    harness.write(&harness.target(), "[server]\nport = 7070\n", 0o640);
    let err = harness.apply("toml").expect_err("changed");
    assert_eq!(err.code, codes::TARGET_CHANGED);
    assert_eq!(content(&harness.target()), "[server]\nport = 7070\n");
}

#[test]
fn apply_validates_the_new_content_before_touching_the_file() {
    let harness = Harness::new("invalid");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), "[server\nport = = 9090\n", 0o644);
    harness.backup().expect("backup");

    let err = harness.apply("toml").expect_err("invalid toml");
    assert_eq!(err.code, codes::INVALID_CONFIG);
    assert!(err.detail.contains("行"), "{}", err.detail);
    assert_eq!(content(&harness.target()), ORIGINAL, "校验不过就不写");
}

#[test]
fn format_auto_skips_unknown_extensions_and_says_so() {
    let harness = Harness::new("auto-skip");
    let target = harness.root.join("etc").join("nginx.conf");
    let source = harness.root.join("etc").join("nginx.conf.new");
    harness.write(&target, "server { }\n", 0o640);
    harness.write(&source, "server { listen 80; }\n", 0o644);

    harness
        .run(backup, &json!({ "path": target.display().to_string() }))
        .expect("backup");
    let source_bytes = fs::read(&source).expect("read");
    let applied = harness
        .run(
            apply,
            &json!({
                "path": target.display().to_string(),
                "source": source.display().to_string(),
                "source_sha256": sha256_hex(&source_bytes),
            }),
        )
        .expect("apply");
    assert!(
        applied["verify"]["parse"].is_null(),
        "认不出格式就别假装验过"
    );
    assert!(
        applied["notes"]
            .as_array()
            .expect("notes")
            .iter()
            .any(|note| note.as_str().unwrap_or_default().contains("没有做语法校验"))
    );
    assert_eq!(content(&target), "server { listen 80; }\n");
}

#[test]
fn rollback_restores_the_original_bytes_and_mode() {
    let harness = Harness::new("rollback");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);
    harness.backup().expect("backup");
    let applied = harness.apply("toml").expect("apply");
    let written = applied["written"]["sha256"].as_str().expect("sha");

    let rolled = harness.rollback(Some(written)).expect("rollback");
    assert_eq!(
        rolled["restored"]["sha256"],
        sha256_hex(ORIGINAL.as_bytes())
    );
    assert_eq!(rolled["verify"]["hash"], true);
    assert_eq!(content(&harness.target()), ORIGINAL);
    assert_eq!(mode_of(&harness.target()), 0o640);

    // 幂等：再回滚一次结果相同。
    let again = harness.rollback(None).expect("rollback again");
    assert_eq!(again["restored"]["sha256"], sha256_hex(ORIGINAL.as_bytes()));
    assert_eq!(content(&harness.target()), ORIGINAL);
}

#[test]
fn rollback_refuses_when_the_current_content_is_not_what_we_wrote() {
    let harness = Harness::new("rollback-guard");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);
    harness.backup().expect("backup");
    harness.apply("toml").expect("apply");

    // 调用方以为线上是 REPLACEMENT，但有人又改过了。
    harness.write(&harness.target(), "[server]\nport = 6060\n", 0o640);
    let err = harness
        .rollback(Some(&sha256_hex(REPLACEMENT.as_bytes())))
        .expect_err("guard");
    assert_eq!(err.code, codes::TARGET_CHANGED);
    assert_eq!(content(&harness.target()), "[server]\nport = 6060\n");
}

#[test]
fn rollback_can_restore_a_file_that_was_deleted() {
    let harness = Harness::new("rollback-deleted");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);
    harness.backup().expect("backup");
    harness.apply("toml").expect("apply");
    fs::remove_file(harness.target()).expect("delete target");

    let rolled = harness.rollback(None).expect("rollback");
    assert_eq!(
        rolled["restored"]["sha256"],
        sha256_hex(ORIGINAL.as_bytes())
    );
    assert_eq!(content(&harness.target()), ORIGINAL);
}

#[test]
fn rollback_without_a_backup_record_is_refused() {
    let harness = Harness::new("rollback-none");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    let err = harness.rollback(None).expect_err("no backup");
    assert_eq!(err.code, codes::BACKUP_MISSING);
}

#[test]
fn a_second_backup_in_the_same_action_keeps_the_first_snapshot() {
    let harness = Harness::new("idempotent");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    let first = harness.backup().expect("first");

    // 中间有人改了文件：第二次 backup 不能把「改动后的内容」当成原始快照。
    harness.write(&harness.target(), REPLACEMENT, 0o640);
    let second = harness.backup().expect("second");
    assert_eq!(second["created"], false);
    assert_eq!(second["backup"]["sha256"], first["backup"]["sha256"]);
    assert_eq!(second["backup"]["sha256"], sha256_hex(ORIGINAL.as_bytes()));
}

#[test]
fn an_action_id_that_could_escape_the_backup_root_is_rejected() {
    let harness = Harness::new("bad-action-id");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    let bad_id = "../../etc".to_string();
    let context = BackupContext {
        root: &harness.backups_root,
        action_id: &bad_id,
    };
    let input = OpInput {
        args: &json!({ "path": harness.target().display().to_string() }),
        requested_by: "tester",
        config: None,
        allow_paths: &harness.allow,
        budget: OpBudget::new(60_000, 1, MAX_BACKUP_BYTES),
        step_timeout_ms: 60_000,
        backups: Some(&context),
    };
    let err = backup(&input).expect_err("bad action id");
    assert_eq!(err.code, codes::INVALID_ARGS);
}

#[test]
fn backup_refuses_directories_and_oversized_files() {
    let harness = Harness::new("backup-bounds");
    let dir = harness.root.join("etc").join("sub");
    fs::create_dir_all(&dir).expect("sub dir");
    let err = harness
        .run(backup, &json!({ "path": dir.display().to_string() }))
        .expect_err("directory");
    assert_eq!(err.code, codes::INVALID_ARGS);

    let big = harness.root.join("etc").join("huge.toml");
    fs::write(&big, vec![b'a'; (MAX_BACKUP_BYTES + 10) as usize]).expect("write big");
    let err = harness
        .run(backup, &json!({ "path": big.display().to_string() }))
        .expect_err("oversized");
    assert_eq!(err.code, codes::INVALID_ARGS);
}

#[test]
fn everything_stays_inside_the_allow_list() {
    let harness = Harness::new("allow");
    harness.write(&harness.target(), ORIGINAL, 0o640);
    harness.write(&harness.source(), REPLACEMENT, 0o644);

    let outside = std::env::temp_dir().join("wist-config-outside.toml");
    fs::write(&outside, b"x").expect("write outside");
    let err = harness
        .run(backup, &json!({ "path": outside.display().to_string() }))
        .expect_err("outside");
    assert_eq!(err.code, codes::PATH_NOT_ALLOWED);

    // apply 的 source 也要在名单里。
    harness.backup().expect("backup");
    let err = harness
        .run(
            apply,
            &json!({
                "path": harness.target().display().to_string(),
                "source": outside.display().to_string(),
                "source_sha256": sha256_hex(b"x"),
            }),
        )
        .expect_err("source outside");
    assert_eq!(err.code, codes::PATH_NOT_ALLOWED);

    let _ = fs::remove_file(outside);
}
