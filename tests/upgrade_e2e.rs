//! 升级链路的集成测试：把 `apply` 从取包一路跑到（失败时）回滚。
//!
//! 覆盖两条主线 —— **升级成功**与**升级失败回退** —— 以及回滚的忠实度：
//! 换成新版后回退必须把机器带回原样（旧件放回、本来没有的件删掉），
//! 回退本身没成时不能声称「已回到原样」。
//!
//! 为什么走库接口而不是跑 `wist-upgrader apply --apply`：后者默认的重启手段是**本机的
//! launchd / systemctl** —— 在开发机上跑它会把真的 agentd 服务重启掉。这里把「重启」换成
//! 沙箱里的桩脚本：桩模拟「新版 agentd 起来了」（把自报版本写进 runtime state）或
//! 「起不来」（什么都不做 / 直接失败）。于是整条链路（取包 → 校验摘要 → 解包 → 让新件自报
//! 版本 → 换件 → 重启 → 等新版 → 失败回滚）能在任何机器上完整跑一遍：不要 root，
//! 不碰服务管理器，也不用连网关（包走本地路径）。
//!
//! 真机上的那一段（真实 launchd/systemd 拉起、真实服务重启）仍由 `dev/` 下的脚本负责。

use std::path::{Path, PathBuf};
use std::time::Duration;

use sha2::{Digest, Sha256};
use wist_agentd::upgrade::{
    AGENTD_BIN_NAME, EXEC_BIN_NAME, RestartPlan, UPGRADE_HEARTBEAT_FILE, UPGRADE_RECORD_FILE,
    UPGRADER_BIN_NAME, UpgradeOptions, UpgradeRecord, UpgradeRequest, apply,
};
use wist_contracts::agent_config::{AgentConfig, AgentSection, ControlPlaneSection, PathsSection};
use wist_contracts::agent_state::{AgentRuntimeState, RuntimeMode};
use wist_shared::fs::{read_json, write_json_atomic};
use wist_shared::time::now_rfc3339;

/// 升级前 / 升级后的版本。升级器只接受「目标比当前新」，别改反。
const FROM: &str = "0.1.3";
const TO: &str = "0.1.4";

/// 一件活从「已在装」到「做完」的全部件（制品形态：三个一起换）。
const ALL_BINS: [&str; 3] = [AGENTD_BIN_NAME, EXEC_BIN_NAME, UPGRADER_BIN_NAME];

/// 一个升级沙箱：`bin/` 是「已装的」二进制，`state/` 是本机状态，制品与桩放根下。
struct Sandbox {
    root: PathBuf,
    /// 是否在请求里声明允许降级（缺省关 = 只前进）。
    allow_downgrade: bool,
}

impl Sandbox {
    /// `installed` 是这台机器**升级前**已经有的件（裸包装只有 `wist-agentd`）。
    fn new(label: &str, installed: &[&str]) -> Self {
        let root = scratch_dir(label);
        std::fs::create_dir_all(root.join("bin")).expect("bin dir");
        std::fs::create_dir_all(root.join("state")).expect("state dir");
        for name in installed {
            write_fake_binary(&root.join("bin").join(name), name, FROM);
        }
        Self {
            root,
            allow_downgrade: false,
        }
    }

    fn bin_dir(&self) -> PathBuf {
        self.root.join("bin")
    }

    fn state_dir(&self) -> PathBuf {
        self.root.join("state")
    }

    /// 打开降级开关（缺省关 = 只前进，与 agentd 的 `--allow-downgrade` 缺省一致）。
    fn allow_downgrade(mut self) -> Self {
        self.allow_downgrade = true;
        self
    }

    /// 把已装的件改写成自报 `version`（降级演练：机器上跑着**更高**的版本）。
    fn seed_installed_version(&self, version: &str) {
        for name in ALL_BINS {
            write_fake_binary(&self.bin_dir().join(name), name, version);
        }
    }

    /// 种一份「这台机器现在跑的是 `version`」的本机状态（真机上是 agentd 一直在写的）。
    fn seed_running_version(&self, version: &str) {
        write_json_atomic(
            &self
                .state_dir()
                .join(wist_shared::paths::AGENT_RUNTIME_FILE),
            &runtime_state(version),
        )
        .expect("seed runtime state");
    }

    /// 造一个 tarball 制品（`<name>-<version>/` 里放三个件），返回（路径, 摘要裸 hex）。
    fn package(&self, version: &str) -> (PathBuf, String) {
        self.package_with(version, &ALL_BINS)
    }

    /// 指定包里带哪几件（用来造「漏件制品」）。
    fn package_with(&self, version: &str, names: &[&str]) -> (PathBuf, String) {
        let payload = self
            .root
            .join("payload")
            .join(format!("{AGENTD_BIN_NAME}-{version}"));
        std::fs::create_dir_all(&payload).expect("payload dir");
        for name in names {
            write_fake_binary(&payload.join(name), name, version);
        }
        let archive = self.root.join(format!("package-{version}.tar.gz"));
        let status = std::process::Command::new("tar")
            .arg("-czf")
            .arg(&archive)
            .arg("-C")
            .arg(self.root.join("payload"))
            .arg(format!("{AGENTD_BIN_NAME}-{version}"))
            .status()
            .expect("tar");
        assert!(status.success(), "tar failed");
        let bytes = std::fs::read(&archive).expect("read archive");
        (archive, hex(&bytes))
    }

    /// 造一个「裸包」制品（单个 `wist-agentd` 裸二进制，不打 tarball）——
    /// 这是网关内置默认包的形态，与 `package_with` 的发布 tarball 是两条解包路径。
    fn bare_package(&self, version: &str) -> (PathBuf, String) {
        let path = self.root.join("bare-agentd");
        write_fake_binary(&path, AGENTD_BIN_NAME, version);
        let bytes = std::fs::read(&path).expect("read bare package");
        (path, hex(&bytes))
    }

    /// 写一个「重启」桩，返回可以交给 `apply` 的重启计划。
    ///
    /// * `ok`   —— 模拟「新版起来了」：把它自报的版本写进 runtime state
    ///   （真机上是服务管理器拉起新版 agentd，agentd 自己写这份状态）。
    /// * `noop` —— 重启命令成功、但新版**永远不起来**（不写状态）。
    /// * `fail` —— 重启命令本身就失败。
    fn restart_stub(&self, mode: &str, version: &str) -> RestartPlan {
        let script = self.root.join(format!("restart-{mode}.sh"));
        let body = match mode {
            "ok" => {
                // 目标状态写在 `state/` **外面**：放在里面等于「一开始就是新版」，就测不到等了。
                let prepared = self.root.join("next-runtime.json");
                write_json_atomic(&prepared, &runtime_state(version)).expect("prepare next state");
                format!(
                    "#!/bin/sh\ncp -f '{}' '{}'\n",
                    prepared.display(),
                    self.state_dir()
                        .join(wist_shared::paths::AGENT_RUNTIME_FILE)
                        .display()
                )
            }
            "noop" => "#!/bin/sh\nexit 0\n".to_string(),
            "fail" => "#!/bin/sh\nexit 1\n".to_string(),
            other => panic!("unknown restart stub mode {other}"),
        };
        std::fs::write(&script, body).expect("write restart stub");
        make_executable(&script);
        RestartPlan::Command {
            program: script.display().to_string(),
            args: Vec::new(),
        }
    }

    fn config(&self) -> AgentConfig {
        let mut config = AgentConfig::new(
            AgentSection::default(),
            ControlPlaneSection::default(),
            PathsSection::default(),
            Default::default(),
        );
        config.paths.state_dir = self.state_dir().display().to_string();
        config
    }

    fn request(&self, package: &Path, sha256: &str) -> UpgradeRequest {
        UpgradeRequest {
            work_id: "work-upgrade-1".to_string(),
            target_version: Some(TO.to_string()),
            current_version: FROM.to_string(),
            agentd_bin: self.bin_dir().join(AGENTD_BIN_NAME),
            package_url: package.display().to_string(),
            package_sha256: sha256.to_string(),
            allow_downgrade: self.allow_downgrade,
        }
    }

    async fn run(
        &self,
        package: &Path,
        sha256: &str,
        restart: RestartPlan,
        ready_wait: Duration,
    ) -> UpgradeRecord {
        self.run_request(self.request(package, sha256), restart, ready_wait)
            .await
    }

    /// 用**给定**的请求跑一次（降级演练要显式控制 `current`/`target` 的方向）。
    async fn run_request(
        &self,
        request: UpgradeRequest,
        restart: RestartPlan,
        ready_wait: Duration,
    ) -> UpgradeRecord {
        let config = self.config();
        let options = UpgradeOptions {
            dry_run: false,
            ready_wait,
            restart,
        };
        apply(&config, &request, &options).await
    }

    /// 盘上那个 `wist-agentd` 现在自报什么版本（跑一下它，与升级器验件同一口径）。
    fn installed_agentd_version(&self) -> String {
        self.version_of(&self.bin_dir().join(AGENTD_BIN_NAME))
    }

    fn version_of(&self, path: &Path) -> String {
        let output = std::process::Command::new(path)
            .arg("version")
            .output()
            .unwrap_or_else(|err| panic!("run {}: {err}", path.display()));
        assert!(
            output.status.success(),
            "{} exited {}",
            path.display(),
            output.status
        );
        String::from_utf8_lossy(&output.stdout)
            .split_whitespace()
            .last()
            .expect("version token")
            .to_string()
    }

    fn backup_of(&self, name: &str) -> PathBuf {
        self.bin_dir().join(format!("{name}.bak-{FROM}"))
    }

    /// 升级器落盘的那份记录（agentd 重启后靠它回报）。
    fn stored_record(&self) -> UpgradeRecord {
        read_json(&self.state_dir().join(UPGRADE_RECORD_FILE)).expect("record stored")
    }
}

impl Drop for Sandbox {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.root);
    }
}

// ─────────────────────────────────────────────────────────────────────────────
// 升级成功
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_successful_upgrade_replaces_every_binary_and_reports_success() {
    let sandbox = Sandbox::new("success", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.package(TO);

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("ok", TO),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "succeeded", "{record:?}");
    // 三个件一起换（同版本前提：升级器去换的正是 agentd 自己）。
    assert_eq!(sandbox.installed_agentd_version(), TO);
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(EXEC_BIN_NAME)),
        TO
    );
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(UPGRADER_BIN_NAME)),
        TO
    );
    // 旧件留了备份（事后取证），升级记录落盘，心跳文件也在（agentd 靠它判活）。
    assert!(sandbox.backup_of(AGENTD_BIN_NAME).is_file());
    assert_eq!(sandbox.stored_record().status, "succeeded");
    assert!(sandbox.state_dir().join(UPGRADE_HEARTBEAT_FILE).is_file());
}

// ─────────────────────────────────────────────────────────────────────────────
// 升级失败回退
// ─────────────────────────────────────────────────────────────────────────────

/// 换件成功、但新版**起不来**：回退到旧件，并报 `rolled_back`（机器已回到原样）。
#[tokio::test]
async fn a_new_version_that_never_comes_up_rolls_back_to_the_old_binaries() {
    let sandbox = Sandbox::new("rollback-not-ready", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.package(TO);

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("noop", TO),
            Duration::from_millis(300),
        )
        .await;

    assert_eq!(record.status, "rolled_back", "{record:?}");
    assert_eq!(record.step, "wait_ready");
    assert!(
        record.detail.contains("did not report"),
        "{}",
        record.detail
    );
    // 三个件都回到旧版（不是只放回 agentd）。
    assert_eq!(sandbox.installed_agentd_version(), FROM);
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(EXEC_BIN_NAME)),
        FROM
    );
    assert_eq!(sandbox.stored_record().status, "rolled_back");
}

/// 重启命令本身就失败：不等 `wait_ready`，立刻回退。
#[tokio::test]
async fn a_restart_command_that_fails_rolls_back_without_waiting() {
    let sandbox = Sandbox::new("rollback-restart", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.package(TO);

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("fail", TO),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "rolled_back", "{record:?}");
    assert_eq!(record.step, "restart");
    assert_eq!(sandbox.installed_agentd_version(), FROM);
    assert_eq!(sandbox.stored_record().status, "rolled_back");
}

/// **裸包装的机器**（只有 `wist-agentd`）升到三件套制品：回退要回到裸包装本身 ——
/// 新带来的执行器与升级器也得撤掉，否则机器停在一个没人核对过的中间态。
#[tokio::test]
async fn rolling_back_a_bare_install_removes_the_binaries_that_were_not_there_before() {
    let sandbox = Sandbox::new("rollback-bare", &[AGENTD_BIN_NAME]);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.package(TO);

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("noop", TO),
            Duration::from_millis(300),
        )
        .await;

    assert_eq!(record.status, "rolled_back", "{record:?}");
    assert_eq!(sandbox.installed_agentd_version(), FROM, "旧件要放回去");
    assert!(
        !sandbox.bin_dir().join(EXEC_BIN_NAME).exists(),
        "本来没有的件回滚后不该留下"
    );
    assert!(
        !sandbox.bin_dir().join(UPGRADER_BIN_NAME).exists(),
        "本来没有的件回滚后不该留下"
    );
}

/// 回退**自己也没成**时不能写 `rolled_back`（那个取值的含义就是「机器已回到原样」）：
/// 落成 `failed`，让控制面看到的是「这台机器停在一个说不清的状态」。
#[tokio::test]
async fn a_failed_rollback_is_reported_as_failed_not_rolled_back() {
    let sandbox = Sandbox::new("rollback-failed", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.package(TO);
    // 让回退必然失败：把备份位置先占成目录 —— `install_binaries` 见「已存在」就不再复制，
    // 回退时找不到可用的备份。真机上对应的是「备份这一步没成功」。
    for name in ALL_BINS {
        std::fs::create_dir_all(sandbox.backup_of(name)).expect("squat backup path");
    }

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("noop", TO),
            Duration::from_millis(300),
        )
        .await;

    assert_eq!(record.status, "failed", "{record:?}");
    assert!(
        record.detail.contains("rollback failed"),
        "{}",
        record.detail
    );
}

/// 漏件的制品（只带 agentd）不能悄悄升 —— 那会把机器留成
/// 「agentd 新版 + exec/upgrader 旧版」，而且记录写的是成功。
#[tokio::test]
async fn a_partial_artifact_is_refused_before_the_installed_binaries_are_touched() {
    let sandbox = Sandbox::new("partial-artifact", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    // 制品里只有 agentd（漏打另两件）。摘要与这份字节同源，所以校验拦不住它。
    let (package, sha) = sandbox.package_with(TO, &[AGENTD_BIN_NAME]);

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("ok", TO),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "failed", "{record:?}");
    assert_eq!(record.step, "verify_artifact", "换件之前就该停住");
    assert!(
        record.detail.contains("artifact_invalid"),
        "{}",
        record.detail
    );
    // 盘上一点没动。
    assert_eq!(sandbox.installed_agentd_version(), FROM);
    assert!(!sandbox.backup_of(AGENTD_BIN_NAME).exists(), "不该留下备份");
}

/// 裸包（网关内置默认包，单个裸二进制）盖在三件套机器上：升级只装不删，那两个兄弟件
/// 会留在旧版本，于是换完 agentd 就是新版、它们还是旧版 —— 必须拒掉。
/// 这与「漏件 tarball」是**两条解包路径**（裸包不进 tar），但要防的是同一件事：混合版本。
#[tokio::test]
async fn a_bare_package_over_a_three_binary_machine_is_refused() {
    let sandbox = Sandbox::new("bare-over-full", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.bare_package(TO);

    let record = sandbox
        .run(
            &package,
            &sha,
            sandbox.restart_stub("ok", TO),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "failed", "{record:?}");
    assert_eq!(record.step, "verify_artifact", "换件之前就该停住");
    assert!(
        record.detail.contains("artifact_invalid"),
        "{}",
        record.detail
    );
    // 三件仍是旧版，一点没动。
    assert_eq!(sandbox.installed_agentd_version(), FROM);
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(EXEC_BIN_NAME)),
        FROM
    );
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(UPGRADER_BIN_NAME)),
        FROM
    );
    assert!(!sandbox.backup_of(AGENTD_BIN_NAME).exists(), "不该留下备份");
}

// ─────────────────────────────────────────────────────────────────────────────
// 还没换件就失败：不该动盘上的东西
// ─────────────────────────────────────────────────────────────────────────────

#[tokio::test]
async fn a_digest_mismatch_fails_before_touching_the_installed_binaries() {
    let sandbox = Sandbox::new("digest", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, _real_sha) = sandbox.package(TO);

    let record = sandbox
        .run(
            &package,
            &"0".repeat(64),
            sandbox.restart_stub("ok", TO),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "failed", "{record:?}");
    assert_eq!(record.step, "verify_digest");
    assert_eq!(sandbox.installed_agentd_version(), FROM, "没换过件");
    assert!(!sandbox.backup_of(AGENTD_BIN_NAME).exists(), "不该留下备份");
}

// ─────────────────────────────────────────────────────────────────────────────
// 升级进行中的可观察性
// ─────────────────────────────────────────────────────────────────────────────

/// 升级进行中，记录里的 `step` 要跟着往前写：进程被 kill / 掉电后，agentd 判死要报
/// 「停在哪一步」。这里用「重启成功但新版永远起不来」让升级停在 `wait_ready`，
/// 再从盘上读到这一步 —— 没有这份持久化，盘上记录会一直停在开头的 `fetch`。
#[tokio::test]
async fn the_record_persists_its_step_while_the_upgrade_is_in_flight() {
    let sandbox = Sandbox::new("step-persist", &ALL_BINS);
    sandbox.seed_running_version(FROM);
    let (package, sha) = sandbox.package(TO);

    let config = sandbox.config();
    let request = sandbox.request(&package, &sha);
    let options = UpgradeOptions {
        dry_run: false,
        ready_wait: Duration::from_secs(5),
        restart: sandbox.restart_stub("noop", TO),
    };
    let handle = tokio::spawn(async move { apply(&config, &request, &options).await });

    // 轮询盘上的记录，直到它走到 `wait_ready`（升级此刻还「在飞」，没到终态）。
    let record_path = sandbox.state_dir().join(UPGRADE_RECORD_FILE);
    let mut observed_step = None;
    for _ in 0..200 {
        if let Ok(record) = read_json::<UpgradeRecord>(&record_path)
            && record.step == "wait_ready"
        {
            observed_step = Some(record.step);
            break;
        }
        tokio::time::sleep(Duration::from_millis(25)).await;
    }

    let record = handle.await.expect("apply task");
    assert_eq!(record.status, "rolled_back", "{record:?}");
    assert_eq!(
        observed_step.as_deref(),
        Some("wait_ready"),
        "盘上的记录该在升级进行中推进到 wait_ready，而不是停在 fetch"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 显式降级
// ─────────────────────────────────────────────────────────────────────────────

/// 声明了降级（`allow_downgrade`）就能把机器退到**更低**的版本：换件 → 重启 → `wait_ready`
/// 全过，结果 `succeeded`，记录里 `from` 高 `to` 低 —— 不因为「版本变小」被判失败。
///
/// 用显式目标版本走「说好就是这一版」那支；「目标以包内自报为准」的降级另有一条单测。
#[tokio::test]
async fn a_declared_downgrade_replaces_binaries_and_reports_success() {
    let sandbox = Sandbox::new("downgrade-ok", &ALL_BINS).allow_downgrade();
    // 现装的是更高的版本，目标包是更低的版本。
    sandbox.seed_installed_version(TO);
    sandbox.seed_running_version(TO);
    let (package, sha) = sandbox.package(FROM);

    let mut request = sandbox.request(&package, &sha);
    request.current_version = TO.to_string();
    request.target_version = Some(FROM.to_string());
    assert!(request.allow_downgrade, "沙箱开关要进到请求里");

    let record = sandbox
        .run_request(
            request,
            sandbox.restart_stub("ok", FROM),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "succeeded", "{record:?}");
    assert_eq!(record.from_version, TO);
    assert_eq!(record.to_version, FROM, "目标版本是更低的那一版");
    // 三个件都换成低版本（不是只换 agentd）。
    assert_eq!(sandbox.installed_agentd_version(), FROM);
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(EXEC_BIN_NAME)),
        FROM
    );
    assert_eq!(
        sandbox.version_of(&sandbox.bin_dir().join(UPGRADER_BIN_NAME)),
        FROM
    );
    // 换件前的高版本留了备份（名字按 current_version 拼）。
    assert!(
        sandbox
            .bin_dir()
            .join(format!("{AGENTD_BIN_NAME}.bak-{TO}"))
            .is_file(),
        "换掉的高版本要留备份"
    );
}

/// 没声明降级（缺省只前进）：目标版本更低 → `not_newer` 拦下，盘上一点没动。
#[tokio::test]
async fn a_downgrade_without_the_flag_is_refused_as_not_newer() {
    let sandbox = Sandbox::new("downgrade-refused", &ALL_BINS);
    sandbox.seed_installed_version(TO);
    sandbox.seed_running_version(TO);
    let (package, sha) = sandbox.package(FROM);

    let mut request = sandbox.request(&package, &sha);
    request.current_version = TO.to_string();
    request.target_version = Some(FROM.to_string());
    assert!(!request.allow_downgrade, "缺省必须是「只前进」");

    let record = sandbox
        .run_request(
            request,
            sandbox.restart_stub("ok", FROM),
            Duration::from_secs(10),
        )
        .await;

    assert_eq!(record.status, "failed", "{record:?}");
    assert!(record.detail.contains("not_newer"), "{}", record.detail);
    // 没换件：盘上还是高版本，也没留备份。
    assert_eq!(sandbox.installed_agentd_version(), TO);
    assert!(
        !sandbox
            .bin_dir()
            .join(format!("{AGENTD_BIN_NAME}.bak-{TO}"))
            .exists(),
        "被拦下就不该留下备份"
    );
}

// ─────────────────────────────────────────────────────────────────────────────
// 沙箱脚手架
// ─────────────────────────────────────────────────────────────────────────────

/// 一个「自称某个版本」的假二进制：升级器会跑它 `version` 让它自报家门。
fn write_fake_binary(path: &Path, name: &str, version: &str) {
    std::fs::write(path, format!("#!/bin/sh\necho \"{name} {version}\"\n"))
        .unwrap_or_else(|err| panic!("write {}: {err}", path.display()));
    make_executable(path);
}

fn make_executable(path: &Path) {
    use std::os::unix::fs::PermissionsExt;
    let mut perms = std::fs::metadata(path).expect("metadata").permissions();
    perms.set_mode(0o755);
    std::fs::set_permissions(path, perms).expect("chmod");
}

fn runtime_state(version: &str) -> AgentRuntimeState {
    AgentRuntimeState::new(
        "agent-verify".to_string(),
        "instance-verify".to_string(),
        version.to_string(),
        RuntimeMode::Normal,
        now_rfc3339(),
    )
}

fn hex(bytes: &[u8]) -> String {
    Sha256::digest(bytes)
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn scratch_dir(label: &str) -> PathBuf {
    let unique = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("time")
        .as_nanos();
    let dir = std::env::temp_dir().join(format!("wist-upgrade-e2e-{label}-{unique}"));
    std::fs::create_dir_all(&dir).expect("create sandbox");
    dir
}
