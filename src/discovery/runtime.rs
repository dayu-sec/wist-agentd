//! Discovery runtime orchestration skeleton.

use std::path::Path;
use std::time::{Duration, Instant};

use wist_contracts::discovery::{
    DiscoveredResource, DiscoveredTarget, DiscoveryCacheMeta, DiscoveryOrigin, DiscoverySnapshot,
};
use wist_shared::time::now_rfc3339;

use super::DiscoveryError;
use super::DiscoveryProbe;
use super::ProbeOutput;
use super::cache::{
    DiscoveryCacheLoadFailure, DiscoveryCachePaths, load_meta, load_meta_async, load_snapshot,
    load_snapshot_async, store_snapshot, store_snapshot_async,
};
use super::policy::AppliedDiscoveryPolicy;
use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct DiscoveryRuntime {
    probes: Vec<Box<dyn DiscoveryProbe + Send + Sync>>,
    latest_snapshot: Option<DiscoverySnapshot>,
    // 每探针的**上次成功输出**与**上次尝试时刻**（内存态）。
    //
    // 为什么放内存而不落盘：调度只需“跨 tick”的记忆，重启后全量刷一次本来就是对的
    // （也顺带把重启当成一次按需全量）。落盘会多一个会损坏的状态。
    //
    // 为什么必须缓存上次输出：未到期的探针不能“什么都不交” —— 快照是从各探针输出**重新拼**出来的，
    // 少了谁就等于把它的资源从快照里删掉（进程/端口会凭空消失）。
    last_outputs: Vec<Option<ProbeOutput>>,
    last_run_at: Vec<Option<Instant>>,
    // 平台下发的策略表（已应用）与**上次拉取尝试时刻**。
    //
    // 为什么放在运行时而不是主循环局部变量：拉取要用 config 走网络，最省事是落在
    // `refresh_discovery_snapshot`（那里 config / runtime 都在手上）；而「上次尝试时刻」必须
    // 跨 tick，运行时本来就是那个跨 tick 的内存对象（与 `last_run_at` 同类）。放主循环局部
    // 变量则要把 `&mut Option<Instant>` 一路透传给下游函数，徒增签名改动。
    // 同样不落盘：重启后重新拉一次本来就是对的（拿不到就用内建默认值）。
    policy: Option<AppliedDiscoveryPolicy>,
    last_policy_fetch_at: Option<Instant>,
}

impl DiscoveryRuntime {
    pub fn new(probes: Vec<Box<dyn DiscoveryProbe + Send + Sync>>) -> Self {
        let output_slots = probes.len();
        Self {
            probes,
            latest_snapshot: None,
            last_outputs: vec![None; output_slots],
            last_run_at: vec![None; output_slots],
            policy: None,
            last_policy_fetch_at: None,
        }
    }

    /// 应用一份策略表；返回**版本是否变化**（调用方据此决定要不要打日志 —— 版本没变就不吭声，
    /// 否则每 5 分钟重新拉到同一版就会刷一次屏）。
    ///
    /// 无论版本是否变化都**覆盖**：agentd 只认「最近拿到的那一份」，不替网关保管历史。
    pub fn apply_discovery_policy(&mut self, set: DiscoveryAspectPolicySet) -> bool {
        let changed = match self.policy.as_ref() {
            Some(current) => current.policy_version() != set.policy_version,
            None => true,
        };
        self.policy = Some(AppliedDiscoveryPolicy::new(set));
        changed
    }

    pub fn policy_version(&self) -> Option<i64> {
        self.policy.as_ref().map(|policy| policy.policy_version())
    }

    /// 是否到了该拉取策略表的时刻：从未拉过 → 到期（**启动即拉**），否则看过没过最小间隔。
    ///
    /// 用 `Instant`（单调）而不是墙钟：回拨不会把节流窗口算歪。
    pub fn policy_fetch_due(&self, now: Instant, min_interval: Duration) -> bool {
        match self.last_policy_fetch_at {
            None => true,
            Some(last) => now.duration_since(last) >= min_interval,
        }
    }

    /// 记录一次拉取**尝试**（无论成败），下次到期由它与最小间隔共同决定。
    ///
    /// 记尝试而不是记成功：失败也必须被节流，否则网关宕机时每 tick（3s）重试一次。
    pub fn record_policy_fetch_attempt(&mut self, now: Instant) {
        self.last_policy_fetch_at = Some(now);
    }

    pub fn probe_count(&self) -> usize {
        self.probes.len()
    }

    pub fn latest_snapshot(&self) -> Option<&DiscoverySnapshot> {
        self.latest_snapshot.as_ref()
    }

    pub fn set_latest_snapshot(&mut self, snapshot: DiscoverySnapshot) {
        self.latest_snapshot = Some(snapshot);
    }

    pub fn load_from_state_dir(
        &mut self,
        state_dir: &Path,
    ) -> (Option<DiscoverySnapshot>, Option<DiscoveryCacheLoadFailure>) {
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        let (snapshot, failure) = load_snapshot(&paths);
        if let Some(snapshot) = snapshot.as_ref() {
            self.latest_snapshot = Some(snapshot.clone());
        }
        (snapshot, failure)
    }

    pub fn load_meta_from_state_dir(
        &self,
        state_dir: &Path,
    ) -> (
        Option<DiscoveryCacheMeta>,
        Option<DiscoveryCacheLoadFailure>,
    ) {
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        load_meta(&paths)
    }

    pub async fn load_from_state_dir_async(
        &mut self,
        state_dir: &Path,
    ) -> (Option<DiscoverySnapshot>, Option<DiscoveryCacheLoadFailure>) {
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        let (snapshot, failure) = load_snapshot_async(&paths).await;
        if let Some(snapshot) = snapshot.as_ref() {
            self.latest_snapshot = Some(snapshot.clone());
        }
        (snapshot, failure)
    }

    pub async fn load_meta_from_state_dir_async(
        &self,
        state_dir: &Path,
    ) -> (
        Option<DiscoveryCacheMeta>,
        Option<DiscoveryCacheLoadFailure>,
    ) {
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        load_meta_async(&paths).await
    }

    pub async fn refresh_and_store_async(&mut self, state_dir: &Path) -> DiscoveryRefreshResult {
        let mut result = self.refresh_all();
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        if let Err(err) = store_snapshot_async(
            &paths,
            &result.persisted_snapshot,
            result.last_success_at.as_deref(),
            result.last_error.clone(),
        )
        .await
        {
            result.record_store_error(err);
        }
        result
    }

    /// 按各探针的 `refresh_interval()` 调度（只刷到期的），并把结果落盘。
    ///
    /// 这是常驻循环用的那个；一次性 / 按需路径仍用 [`Self::refresh_all`]（全量）。
    pub async fn refresh_due_and_store_async(
        &mut self,
        state_dir: &Path,
        now: Instant,
    ) -> DiscoveryRefreshResult {
        let mut result = self.refresh_due(now);
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        if let Err(err) = store_snapshot_async(
            &paths,
            &result.persisted_snapshot,
            result.last_success_at.as_deref(),
            result.last_error.clone(),
        )
        .await
        {
            result.record_store_error(err);
        }
        result
    }

    pub fn refresh_and_store(&mut self, state_dir: &Path) -> DiscoveryRefreshResult {
        let mut result = self.refresh_all();
        let paths = DiscoveryCachePaths::under_state_dir(state_dir);
        if let Err(err) = store_snapshot(
            &paths,
            &result.persisted_snapshot,
            result.last_success_at.as_deref(),
            result.last_error.clone(),
        ) {
            result.record_store_error(err);
        }
        result
    }

    pub fn refresh_all(&mut self) -> DiscoveryRefreshResult {
        self.refresh_inner(None)
    }

    /// 只刷新**到期**的探针（按各自 `refresh_interval()`）。
    ///
    /// 未到期的沿用上次成功输出 —— 不是“什么都不交”，因为快照是从各探针输出重新拼出来的，
    /// 少交一个就等于把它的资源从快照里删掉。
    ///
    /// `now` 由调用方给（而不是内部取），这样调度可以测。
    pub fn refresh_due(&mut self, now: Instant) -> DiscoveryRefreshResult {
        self.refresh_inner(Some(now))
    }

    /// `due_at = None` 表示全量刷新（一次性 / 按需路径，保持原语义）。
    fn refresh_inner(&mut self, due_at: Option<Instant>) -> DiscoveryRefreshResult {
        let now = std::time::SystemTime::now();
        let mut resources = Vec::new();
        let mut targets = Vec::new();
        let mut origins = Vec::new();
        let mut errors = Vec::new();
        let mut successful_probes = Vec::new();

        for index in 0..self.probes.len() {
            // 到期判定：没跑过 → 到期；跑过 → 看间隔。
            let due = match due_at {
                None => true,
                Some(instant) => match self.last_run_at[index] {
                    None => true,
                    Some(last) => {
                        // 周期优先取自平台下发的策略表（按探针名查）。策略表是**平台级**取舍，
                        // 应当盖过二进制里的内建默认值；表里没有这个方向（或周期非正）才回退到
                        // `refresh_interval()`。
                        let interval = self
                            .policy
                            .as_ref()
                            .and_then(|policy| policy.interval_for(self.probes[index].name()))
                            .unwrap_or_else(|| self.probes[index].refresh_interval());
                        instant.duration_since(last) >= interval
                    }
                },
            };
            let output = if due {
                self.last_run_at[index] = due_at;
                match self.probes[index].refresh(now) {
                    Ok(output) => {
                        // 只记**成功**的输出：失败的那一轮不该让旧结果被“刷新”了。
                        self.last_outputs[index] = Some(output.clone());
                        Ok(output)
                    }
                    Err(err) => Err(err),
                }
            } else {
                match self.last_outputs[index].clone() {
                    Some(cached) => Ok(cached),
                    // 没有历史（首次且被判定为未到期，理论上不会发生）→ 还是刷一次。
                    None => match self.probes[index].refresh(now) {
                        Ok(output) => {
                            self.last_outputs[index] = Some(output.clone());
                            self.last_run_at[index] = due_at;
                            Ok(output)
                        }
                        Err(err) => Err(err),
                    },
                }
            };

            match output {
                Ok(mut output) => {
                    let origin_idx = origins.len();
                    for resource in &mut output.resources {
                        resource.origin_idx = origin_idx;
                    }
                    for target in &mut output.targets {
                        target.origin_idx = origin_idx;
                    }
                    successful_probes.push(SuccessfulProbeRefresh {
                        probe: output.probe.clone(),
                        source: output.source,
                        resource_count: output.resources.len(),
                        target_count: output.targets.len(),
                    });
                    origins.push(output.origin);
                    resources.extend(output.resources);
                    targets.extend(output.targets);
                }
                Err(err) => errors.push(err),
            }
        }

        self.compose_snapshot(resources, targets, origins, errors, successful_probes)
    }

    fn compose_snapshot(
        &mut self,
        resources: Vec<DiscoveredResource>,
        targets: Vec<DiscoveredTarget>,
        origins: Vec<DiscoveryOrigin>,
        errors: Vec<DiscoveryError>,
        successful_probes: Vec<SuccessfulProbeRefresh>,
    ) -> DiscoveryRefreshResult {
        let now_generated = now_rfc3339();

        let previous_snapshot = self.latest_snapshot.clone();
        let previous_last_success_at = previous_snapshot
            .as_ref()
            .map(|snapshot| snapshot.generated_at.clone());
        let revision = previous_snapshot
            .as_ref()
            .map_or(1, |snapshot| snapshot.revision + 1);
        let generated_at = now_generated;
        let snapshot_id = format!("discovery:{revision}:{generated_at}");
        let mut refreshed_snapshot =
            DiscoverySnapshot::new(snapshot_id, revision, generated_at.clone());
        refreshed_snapshot.origins = origins;
        refreshed_snapshot.resources = resources;
        refreshed_snapshot.targets = targets;

        let has_successful_probe_output = !refreshed_snapshot.resources.is_empty()
            || !refreshed_snapshot.targets.is_empty()
            || errors.len() < self.probes.len();
        let persisted_snapshot = if has_successful_probe_output {
            refreshed_snapshot.clone()
        } else {
            previous_snapshot
                .clone()
                .unwrap_or_else(|| refreshed_snapshot.clone())
        };
        self.latest_snapshot = Some(persisted_snapshot.clone());
        let last_error = errors
            .first()
            .map(|error| error.detail().clone().unwrap_or_else(|| error.to_string()));

        DiscoveryRefreshResult {
            refreshed_snapshot,
            persisted_snapshot,
            errors,
            last_success_at: if has_successful_probe_output {
                Some(generated_at)
            } else {
                previous_last_success_at
            },
            last_error,
            used_cached_snapshot: !has_successful_probe_output && previous_snapshot.is_some(),
            had_successful_refresh: has_successful_probe_output,
            successful_probes,
            store_failure: None,
        }
    }
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct DiscoveryRefreshResult {
    pub refreshed_snapshot: DiscoverySnapshot,
    pub persisted_snapshot: DiscoverySnapshot,
    pub errors: Vec<super::DiscoveryError>,
    pub last_success_at: Option<String>,
    pub last_error: Option<String>,
    pub used_cached_snapshot: bool,
    pub had_successful_refresh: bool,
    pub successful_probes: Vec<SuccessfulProbeRefresh>,
    pub store_failure: Option<DiscoveryStoreFailure>,
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct SuccessfulProbeRefresh {
    pub probe: String,
    pub source: super::DiscoverySourceKind,
    pub resource_count: usize,
    pub target_count: usize,
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct DiscoveryStoreFailure {
    pub phase: &'static str,
    pub detail: String,
}

impl DiscoveryRefreshResult {
    fn record_store_error(&mut self, err: DiscoveryError) {
        let detail = format!("discovery cache store failed: {err}");
        self.last_error = Some(detail.clone());
        self.store_failure = Some(DiscoveryStoreFailure {
            phase: "cache_store",
            detail,
        });
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::time::{Duration, Instant, SystemTime};
    use std::{fs, path::PathBuf};

    use wist_contracts::discovery::{DiscoveredResource, DiscoveryOrigin, DiscoverySnapshot};
    use wist_contracts::discovery_policy::{DiscoveryAspectPolicy, DiscoveryAspectPolicySet};

    use crate::discovery::{DiscoveryError, DiscoverySourceKind, ProbeOutput};

    use super::DiscoveryRuntime;

    struct StubProbe {
        name: &'static str,
        source: DiscoverySourceKind,
        output: Result<ProbeOutput, DiscoveryError>,
    }

    impl crate::discovery::DiscoveryProbe for StubProbe {
        fn name(&self) -> &'static str {
            self.name
        }

        fn source(&self) -> DiscoverySourceKind {
            self.source
        }

        fn refresh_interval(&self) -> Duration {
            Duration::from_secs(1)
        }

        fn refresh(&self, _now: SystemTime) -> Result<ProbeOutput, DiscoveryError> {
            self.output.clone()
        }
    }

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir =
            std::env::temp_dir().join(format!("warp-insight-discovery-runtime-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    #[test]
    fn refresh_all_collects_probe_outputs_and_advances_revision() {
        let output = ProbeOutput {
            probe: "host".to_string(),
            source: DiscoverySourceKind::LocalRuntime,
            refreshed_at: "2026-04-19T00:00:00Z".to_string(),
            origin: DiscoveryOrigin {
                origin_id: "origin-1".to_string(),
                probe: "host".to_string(),
                source: "local_runtime".to_string(),
                observed_at: "2026-04-19T00:00:00Z".to_string(),
            },
            resources: vec![DiscoveredResource {
                resource_id: "host-1".to_string(),
                kind: "host".to_string(),
                origin_idx: 0,
                attributes: BTreeMap::from([("host.id".to_string(), "host-1".to_string())]),
                discovered_at: "2026-04-19T00:00:00Z".to_string(),
                last_seen_at: "2026-04-19T00:00:00Z".to_string(),
                health: "healthy".to_string(),
                source: "local_runtime".to_string(),
            }],
            targets: Vec::new(),
        };

        let mut runtime = DiscoveryRuntime::new(vec![Box::new(StubProbe {
            name: "host",
            source: DiscoverySourceKind::LocalRuntime,
            output: Ok(output),
        })]);

        let first = runtime.refresh_all();
        assert_eq!(first.refreshed_snapshot.revision, 1);
        assert_eq!(first.persisted_snapshot.revision, 1);
        assert_eq!(first.persisted_snapshot.resources.len(), 1);
        assert!(first.errors.is_empty());
        assert!(!first.used_cached_snapshot);
        assert!(first.had_successful_refresh);

        let second = runtime.refresh_all();
        assert_eq!(second.refreshed_snapshot.revision, 2);
        assert_eq!(second.persisted_snapshot.revision, 2);
    }

    #[test]
    fn refresh_all_keeps_snapshot_when_one_probe_fails() {
        let output = ProbeOutput {
            probe: "host".to_string(),
            source: DiscoverySourceKind::LocalRuntime,
            refreshed_at: "2026-04-19T00:00:00Z".to_string(),
            origin: DiscoveryOrigin {
                origin_id: "origin-1".to_string(),
                probe: "host".to_string(),
                source: "local_runtime".to_string(),
                observed_at: "2026-04-19T00:00:00Z".to_string(),
            },
            resources: vec![DiscoveredResource {
                resource_id: "host-1".to_string(),
                kind: "host".to_string(),
                origin_idx: 0,
                attributes: BTreeMap::from([("host.id".to_string(), "host-1".to_string())]),
                discovered_at: "2026-04-19T00:00:00Z".to_string(),
                last_seen_at: "2026-04-19T00:00:00Z".to_string(),
                health: "healthy".to_string(),
                source: "local_runtime".to_string(),
            }],
            targets: Vec::new(),
        };

        let mut runtime = DiscoveryRuntime::new(vec![
            Box::new(StubProbe {
                name: "host",
                source: DiscoverySourceKind::LocalRuntime,
                output: Ok(output),
            }),
            Box::new(StubProbe {
                name: "k8s",
                source: DiscoverySourceKind::K8s,
                output: Err(crate::discovery::probe_failed(
                    "k8s",
                    DiscoverySourceKind::K8s,
                    "k8s unavailable",
                )),
            }),
        ]);

        let result = runtime.refresh_all();
        assert_eq!(result.persisted_snapshot.resources.len(), 1);
        assert_eq!(result.errors.len(), 1);
        assert_eq!(
            result.errors[0].context_metadata().get_str("source"),
            Some(DiscoverySourceKind::K8s.as_str())
        );
        assert!(!result.used_cached_snapshot);
        assert!(result.had_successful_refresh);
    }

    #[test]
    fn refresh_all_keeps_last_successful_snapshot_when_all_probes_fail() {
        let mut previous = DiscoverySnapshot::new(
            "snapshot-1".to_string(),
            1,
            "2026-04-19T00:00:00Z".to_string(),
        );
        previous.resources = vec![DiscoveredResource {
            resource_id: "host-1".to_string(),
            kind: "host".to_string(),
            origin_idx: 0,
            attributes: BTreeMap::from([("host.id".to_string(), "host-1".to_string())]),
            discovered_at: "2026-04-19T00:00:00Z".to_string(),
            last_seen_at: "2026-04-19T00:00:00Z".to_string(),
            health: "healthy".to_string(),
            source: "local_runtime".to_string(),
        }];

        let mut runtime = DiscoveryRuntime::new(vec![Box::new(StubProbe {
            name: "process",
            source: DiscoverySourceKind::LocalRuntime,
            output: Err(crate::discovery::probe_failed(
                "process",
                DiscoverySourceKind::LocalRuntime,
                "process discovery failed",
            )),
        })]);
        runtime.set_latest_snapshot(previous.clone());

        let result = runtime.refresh_all();

        assert!(result.refreshed_snapshot.resources.is_empty());
        assert_eq!(result.persisted_snapshot, previous);
        assert_eq!(
            result.last_success_at.as_deref(),
            Some("2026-04-19T00:00:00Z")
        );
        assert!(result.used_cached_snapshot);
        assert!(!result.had_successful_refresh);
    }

    #[test]
    fn refresh_and_store_persists_last_error_when_probe_fails_without_success_snapshot() {
        let state_dir = temp_dir("persist-last-error");
        let mut runtime = DiscoveryRuntime::new(vec![Box::new(StubProbe {
            name: "process",
            source: DiscoverySourceKind::LocalRuntime,
            output: Err(crate::discovery::probe_failed(
                "process",
                DiscoverySourceKind::LocalRuntime,
                "process discovery failed",
            )),
        })]);

        let result = runtime.refresh_and_store(&state_dir);
        let (meta, meta_failure) = runtime.load_meta_from_state_dir(&state_dir);
        let meta = meta.expect("meta exists");

        assert_eq!(
            result.last_error.as_deref(),
            Some("process discovery failed")
        );
        assert_eq!(meta.last_error.as_deref(), Some("process discovery failed"));
        assert_eq!(meta.last_success_at, None);
        assert_eq!(meta_failure, None);
    }

    // ── 观测频率调度 ───────────────────────────────────────────
    //
    // 在此之前各探针声明的 `refresh_interval()` 是死代码：运行时每 tick 把所有探针全刷一遍。

    /// 自带周期与调用计数的探针。每次调用输出一个以探针名命名的资源，便于断言资源是否还在快照里。
    struct IntervalProbe {
        name: &'static str,
        interval: Duration,
        calls: Arc<AtomicUsize>,
    }

    impl crate::discovery::DiscoveryProbe for IntervalProbe {
        fn name(&self) -> &'static str {
            self.name
        }

        fn source(&self) -> DiscoverySourceKind {
            DiscoverySourceKind::LocalRuntime
        }

        fn refresh_interval(&self) -> Duration {
            self.interval
        }

        fn refresh(&self, _now: SystemTime) -> Result<ProbeOutput, DiscoveryError> {
            self.calls.fetch_add(1, Ordering::SeqCst);
            Ok(ProbeOutput {
                probe: self.name.to_string(),
                source: DiscoverySourceKind::LocalRuntime,
                refreshed_at: "2026-09-22T00:00:00Z".to_string(),
                origin: DiscoveryOrigin {
                    origin_id: format!("origin-{}", self.name),
                    probe: self.name.to_string(),
                    source: "local_runtime".to_string(),
                    observed_at: "2026-09-22T00:00:00Z".to_string(),
                },
                resources: vec![DiscoveredResource {
                    resource_id: format!("{}-1", self.name),
                    kind: self.name.to_string(),
                    origin_idx: 0,
                    attributes: BTreeMap::new(),
                    discovered_at: "2026-09-22T00:00:00Z".to_string(),
                    last_seen_at: "2026-09-22T00:00:00Z".to_string(),
                    health: "healthy".to_string(),
                    source: self.name.to_string(),
                }],
                targets: Vec::new(),
            })
        }
    }

    fn interval_probe(
        name: &'static str,
        interval: Duration,
    ) -> (
        Box<dyn crate::discovery::DiscoveryProbe + Send + Sync>,
        Arc<AtomicUsize>,
    ) {
        let calls = Arc::new(AtomicUsize::new(0));
        (
            Box::new(IntervalProbe {
                name,
                interval,
                calls: Arc::clone(&calls),
            }),
            calls,
        )
    }

    /// 构造一份只带周期的最小策略表（其余字段不是调度用的，填占位值即可）。
    fn policy_set(version: i64, intervals: &[(&str, i64)]) -> DiscoveryAspectPolicySet {
        let policies = intervals
            .iter()
            .map(|(aspect, interval)| DiscoveryAspectPolicy {
                aspect: aspect.to_string(),
                default_interval_seconds: *interval,
                min_interval_seconds: 1,
                max_interval_seconds: 86_400,
                baseline: false,
                enabled_by_default: true,
                platforms: vec!["macos".to_string()],
                yields: String::new(),
            })
            .collect();
        DiscoveryAspectPolicySet::new(version, "2026-09-22T00:00:00Z".to_string(), policies)
    }

    fn resource_ids(runtime: &DiscoveryRuntime) -> Vec<String> {
        let mut ids: Vec<String> = runtime
            .latest_snapshot()
            .expect("snapshot")
            .resources
            .iter()
            .map(|resource| resource.resource_id.clone())
            .collect();
        ids.sort();
        ids
    }

    #[test]
    fn refresh_due_prefers_the_applied_policy_interval() {
        // 探针自报 1 小时，策略表把 host 压到 1s：过了 2s 就该按**策略表**的周期再刷。
        let (probe, calls) = interval_probe("host", Duration::from_secs(3600));
        let mut runtime = DiscoveryRuntime::new(vec![probe]);
        assert!(runtime.apply_discovery_policy(policy_set(1, &[("host", 1)])));
        let t0 = Instant::now();

        runtime.refresh_due(t0);
        assert_eq!(calls.load(Ordering::SeqCst), 1);

        runtime.refresh_due(t0 + Duration::from_secs(2));
        assert_eq!(calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_due_without_a_policy_uses_the_probe_interval() {
        // 没有策略表（断网 / 网关未配表）→ 回退探针内建周期，行为与从前一致。
        let (probe, calls) = interval_probe("host", Duration::from_secs(3600));
        let mut runtime = DiscoveryRuntime::new(vec![probe]);
        let t0 = Instant::now();

        runtime.refresh_due(t0);
        runtime.refresh_due(t0 + Duration::from_secs(2));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn refresh_due_keeps_the_probe_interval_when_the_policy_omits_the_aspect() {
        // 表里有，但**没提** host：这一方向仍按内建周期走，不能被别人的周期带偏。
        let (probe, calls) = interval_probe("host", Duration::from_secs(3600));
        let mut runtime = DiscoveryRuntime::new(vec![probe]);
        runtime.apply_discovery_policy(policy_set(1, &[("process", 1)]));
        let t0 = Instant::now();

        runtime.refresh_due(t0);
        runtime.refresh_due(t0 + Duration::from_secs(2));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn apply_discovery_policy_reports_only_version_changes() {
        let mut runtime = DiscoveryRuntime::new(Vec::new());
        assert_eq!(runtime.policy_version(), None);

        // 首份 → 视为变化（要打日志）。
        assert!(runtime.apply_discovery_policy(policy_set(1, &[("host", 900)])));
        assert_eq!(runtime.policy_version(), Some(1));

        // 同一版再来 → 不报变化（agentd 据此不重复打日志）。
        assert!(!runtime.apply_discovery_policy(policy_set(1, &[("host", 600)])));
        assert_eq!(runtime.policy_version(), Some(1));

        // 版本递增 → 报变化，且新周期被采纳。
        assert!(runtime.apply_discovery_policy(policy_set(2, &[("host", 600)])));
        assert_eq!(runtime.policy_version(), Some(2));
    }

    #[test]
    fn policy_fetch_is_due_until_the_first_attempt_then_throttled() {
        let mut runtime = DiscoveryRuntime::new(Vec::new());
        let min = Duration::from_millis(300_000);
        let t0 = Instant::now();

        // 从未拉过 → 启动即到期。
        assert!(runtime.policy_fetch_due(t0, min));

        runtime.record_policy_fetch_attempt(t0);
        // 刚记过尝试 → 未到期（失败也一样被节流）。
        assert!(!runtime.policy_fetch_due(t0 + Duration::from_secs(1), min));
        // 过了最小间隔 → 到期。
        assert!(runtime.policy_fetch_due(t0 + min, min));
    }

    #[test]
    fn refresh_due_skips_probes_that_are_not_due_and_keeps_their_resources() {
        let (fast, fast_calls) = interval_probe("fast", Duration::from_secs(1));
        let (slow, slow_calls) = interval_probe("slow", Duration::from_secs(3600));
        let mut runtime = DiscoveryRuntime::new(vec![fast, slow]);
        let t0 = Instant::now();

        // 第一次：谁都没跑过 → 都到期。
        runtime.refresh_due(t0);
        assert_eq!(fast_calls.load(Ordering::SeqCst), 1);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resource_ids(&runtime), vec!["fast-1", "slow-1"]);

        // 过了 2 秒：只有 1s 周期的到期；未到期的**沿用上次输出**，
        // 而不是“什么都不交” —— 否则未到期探针的资源会从快照里消失。
        runtime.refresh_due(t0 + Duration::from_secs(2));
        assert_eq!(fast_calls.load(Ordering::SeqCst), 2);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 1);
        assert_eq!(resource_ids(&runtime), vec!["fast-1", "slow-1"]);

        // 过了 1 小时 + 1 秒：两边都到期。
        runtime.refresh_due(t0 + Duration::from_secs(3601));
        assert_eq!(fast_calls.load(Ordering::SeqCst), 3);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
        assert_eq!(resource_ids(&runtime), vec!["fast-1", "slow-1"]);
    }

    #[test]
    fn refresh_all_ignores_the_intervals() {
        // 一次性 / 按需路径必须仍然全量刷新（它的语义是“现在就扫一遍”）。
        let (fast, fast_calls) = interval_probe("fast", Duration::from_secs(3600));
        let (slow, slow_calls) = interval_probe("slow", Duration::from_secs(3600));
        let mut runtime = DiscoveryRuntime::new(vec![fast, slow]);

        runtime.refresh_all();
        runtime.refresh_all();

        assert_eq!(fast_calls.load(Ordering::SeqCst), 2);
        assert_eq!(slow_calls.load(Ordering::SeqCst), 2);
    }

    #[test]
    fn refresh_due_keeps_the_last_successful_output_when_a_probe_fails() {
        // 探针上一轮成功、这一轮失败：快照里不该凭空多出又少掉它的资源，
        // 而“上次成功输出”要留着当未到期时的替补。
        let (flaky, calls) = interval_probe("flaky", Duration::from_secs(1));
        let mut runtime = DiscoveryRuntime::new(vec![flaky]);
        let t0 = Instant::now();
        runtime.refresh_due(t0);
        assert_eq!(resource_ids(&runtime), vec!["flaky-1"]);

        // 未到期 → 用缓存；调用次数不变。
        runtime.refresh_due(t0 + Duration::from_millis(100));
        assert_eq!(calls.load(Ordering::SeqCst), 1);
        assert_eq!(resource_ids(&runtime), vec!["flaky-1"]);
    }
}
