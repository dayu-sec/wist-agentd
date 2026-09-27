use std::fs;
use std::io::Read;
use std::net::TcpListener;
use std::thread;
use std::time::Duration;

use serde::Deserialize;
use wist_agentd::bootstrap;
use wist_agentd::control::work::AppliedWorkGrant;
use wist_agentd::daemon;
use wist_agentd::self_observability::DiscoveryReadiness;
use wist_contracts::agent_config::{DiscoverySection, LogFileInputSection};
use wist_contracts::discovery::{
    CollectionCandidate, DiscoveredResource, DiscoveredTarget, DiscoveryCacheMeta,
};
use wist_contracts::telemetry_record::TelemetryRecord;
use wist_contracts::work::{StandingWork, WorkGrant, WorkSpec, WorkSpecSource, WorkSpecUnit};
use wist_shared::fs::read_json;

use super::common::{
    TestLogCheckpointState, standalone_config_with_file_input, standalone_config_with_file_inputs,
    standalone_config_with_tcp_file_input, temp_dir, test_exec_bin,
};

fn bind_tcp_listener(addr: &str) -> Option<TcpListener> {
    match TcpListener::bind(addr) {
        Ok(listener) => Some(listener),
        Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
        Err(err) => panic!("bind tcp listener: {err}"),
    }
}

/// 从 `{json} LOGRAW: <raw>` 帧中提取原始日志正文，供 TCP 输出断言使用。
/// 指标帧（` METRICS: `）与日志帧（` LOGRAW: `）共用同一连接、指标优先，这里只取日志正文。
fn raw_body_sections(payload: &str) -> Vec<String> {
    payload
        .lines()
        .filter(|line| !line.is_empty())
        .filter_map(|line| {
            line.rsplit_once(" LOGRAW: ")
                .map(|(_, raw)| raw.to_string())
        })
        .collect()
}

/// 一份“网关授权了指标采集”的授权快照（`run_once` 不做轮询，得直接给）。
fn granted_metrics_work() -> AppliedWorkGrant {
    granted_work("HostMetrics", "collect_metrics", "MetricInterval", "15s")
}

/// 授权一份工作（一个单元、一个来源）——授权快照是 agentd 唯一的工作来源。
fn granted_work(
    family: &str,
    capability: &str,
    source_kind: &str,
    source_target: &str,
) -> AppliedWorkGrant {
    granted_work_multiline(family, capability, source_kind, source_target, "none")
}

/// 同上，但可声明来源的读法（`none` / `indented`）。
fn granted_work_multiline(
    family: &str,
    capability: &str,
    source_kind: &str,
    source_target: &str,
    multiline: &str,
) -> AppliedWorkGrant {
    let spec = WorkSpec {
        units: vec![WorkSpecUnit {
            unit_id: format!("unit-{family}"),
            capability: capability.to_string(),
            rule_ref: "agent_uplink".to_string(),
            requires_privilege: "none".to_string(),
            sources: vec![WorkSpecSource {
                kind: source_kind.to_string(),
                target: source_target.to_string(),
                multiline: multiline.to_string(),
            }],
        }],
    };
    let mut applied = AppliedWorkGrant::default();
    applied.apply(&WorkGrant {
        agent_id: "agent-001".to_string(),
        standing: vec![StandingWork {
            work_id: format!("work-agent-001-{family}"),
            agent_id: "agent-001".to_string(),
            family: family.to_string(),
            spec: spec.encode().expect("encode spec"),
            catalog_version: 1,
            proposal_id: None,
            plan_version: 1,
            effective_from: "2026-09-23T00:00:00Z".to_string(),
            status: "active".to_string(),
            updated_by: "admin".to_string(),
            updated_at: "2026-09-23T00:00:00Z".to_string(),
        }],
        one_shot: Vec::new(),
        sequence: 1,
        granted_at: "2026-09-23T00:00:00Z".to_string(),
    });
    applied
}

#[derive(Debug, Deserialize)]
struct TestMetricsTargetView {
    targets: Vec<TestMetricsTargetViewEntry>,
}

#[derive(Debug, Deserialize)]
struct TestMetricsTargetViewEntry {
    collection_kind: String,
}

#[derive(Debug, Deserialize)]
struct TestMetricsRuntimeSnapshot {
    total_targets: usize,
    host_targets: usize,
    process_targets: usize,
    container_targets: usize,
    outcomes: Vec<TestMetricsCollectionOutcome>,
}

#[derive(Debug, Deserialize)]
struct TestMetricsCollectionOutcome {
    collection_kind: String,
    status: String,
    attempted_targets: usize,
    succeeded_targets: usize,
    failed_targets: usize,
    last_error: Option<String>,
    runtime_facts: Vec<wist_contracts::discovery::StringKeyValue>,
    sample_targets: Vec<TestMetricsCollectionTargetSample>,
}

#[derive(Debug, Deserialize)]
struct TestMetricsCollectionTargetSample {
    candidate_id: String,
    target_ref: String,
}

#[cfg(unix)]
#[test]
fn daemon_run_once_processes_configured_file_input() {
    let root = temp_dir("daemon-file-input");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\nsecond\n").expect("write input log");

    let config = standalone_config_with_file_input(&root, &input_path);
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<wist_contracts::telemetry_record::TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "app");
    let checkpoint: TestLogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");
    let discovery_root = state_dir.join("discovery");
    let discovery_resources: Vec<DiscoveredResource> =
        read_json(&discovery_root.join("resources.json")).expect("read discovery resources");
    let discovery_targets: Vec<DiscoveredTarget> =
        read_json(&discovery_root.join("targets.json")).expect("read discovery targets");
    let discovery_meta: DiscoveryCacheMeta =
        read_json(&discovery_root.join("meta.json")).expect("read discovery meta");
    let host_planner_candidates: Vec<CollectionCandidate> = read_json(
        &state_dir
            .join("planner")
            .join("host_metrics_candidates.json"),
    )
    .expect("read host planner candidates");
    let process_planner_candidates: Vec<CollectionCandidate> = read_json(
        &state_dir
            .join("planner")
            .join("process_metrics_candidates.json"),
    )
    .expect("read process planner candidates");
    let container_planner_candidates: Vec<CollectionCandidate> = read_json(
        &state_dir
            .join("planner")
            .join("container_metrics_candidates.json"),
    )
    .expect("read container planner candidates");
    let metrics_target_view: TestMetricsTargetView =
        read_json(&state_dir.join("telemetry").join("metrics_target_view.json"))
            .expect("read metrics target view");
    let metrics_runtime_snapshot: TestMetricsRuntimeSnapshot = read_json(
        &state_dir
            .join("telemetry")
            .join("metrics_runtime_snapshot.json"),
    )
    .expect("read metrics runtime snapshot");
    let _metrics_samples_exporter = state_dir.join("export").join("metrics.jsonl");

    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert_eq!(snapshot.discovery.readiness, DiscoveryReadiness::Ready);
    assert!(!snapshot.discovery.used_cached_snapshot);
    assert!(snapshot.discovery.failure_count <= 1);
    assert!(snapshot.metrics.target_view_loaded);
    assert!(!snapshot.metrics.used_cached_snapshot);
    assert_eq!(
        snapshot.metrics.attempted_targets,
        metrics_runtime_snapshot.total_targets
    );
    assert_eq!(
        snapshot.metrics.succeeded_targets + snapshot.metrics.failed_targets,
        metrics_runtime_snapshot.total_targets
    );
    assert_eq!(snapshot.metrics.failure_count, 0);
    assert!(!snapshot.discovery.probes.is_empty());
    assert!(snapshot.discovery.probes.iter().any(|probe| {
        probe.source == "local_runtime"
            && probe.probe == "host"
            && probe.phase == "refresh"
            && probe.status == "ok"
    }));
    assert!(
        snapshot
            .discovery
            .probes
            .iter()
            .any(|probe| probe.probe == "process")
    );
    assert!(
        snapshot
            .discovery
            .probes
            .iter()
            .all(|probe| probe.probe != "container")
    );
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].body, "first\n");
    assert_eq!(records[1].body, "second\n");
    assert_eq!(checkpoint.files.len(), 1);
    assert_eq!(
        checkpoint.files[0].checkpoint_offset,
        "first\nsecond\n".len() as u64
    );
    assert!(!discovery_resources.is_empty());
    assert!(!discovery_targets.is_empty());
    assert!(
        discovery_resources
            .iter()
            .any(|resource| resource.kind == "host")
    );
    assert!(discovery_targets.iter().any(|target| target.kind == "host"));
    assert_eq!(discovery_meta.schema_version, "v1");
    assert_eq!(
        discovery_meta.last_success_at,
        Some(discovery_meta.generated_at.clone())
    );
    assert!(
        host_planner_candidates
            .iter()
            .all(|candidate| candidate.collection_kind == "host_metrics")
    );
    assert!(
        process_planner_candidates
            .iter()
            .all(|candidate| candidate.collection_kind == "process_metrics")
    );
    assert!(
        container_planner_candidates
            .iter()
            .all(|candidate| candidate.collection_kind == "container_metrics")
    );
    assert!(container_planner_candidates.is_empty());
    assert!(
        metrics_target_view
            .targets
            .iter()
            .any(|target| target.collection_kind == "host_metrics")
    );
    if !process_planner_candidates.is_empty() {
        assert!(
            metrics_target_view
                .targets
                .iter()
                .any(|target| target.collection_kind == "process_metrics")
        );
    }
    if !container_planner_candidates.is_empty() {
        assert!(
            metrics_target_view
                .targets
                .iter()
                .any(|target| target.collection_kind == "container_metrics")
        );
    }
    assert!(metrics_runtime_snapshot.total_targets >= metrics_runtime_snapshot.host_targets);
    assert!(metrics_runtime_snapshot.host_targets >= 1);
    assert_eq!(metrics_runtime_snapshot.container_targets, 0);
    assert_eq!(
        metrics_runtime_snapshot.total_targets,
        metrics_runtime_snapshot.host_targets
            + metrics_runtime_snapshot.process_targets
            + metrics_runtime_snapshot.container_targets
    );
    assert_eq!(
        snapshot.metrics.total_targets,
        metrics_runtime_snapshot.total_targets
    );
    assert_eq!(
        snapshot.metrics.host_targets,
        metrics_runtime_snapshot.host_targets
    );
    assert_eq!(
        snapshot.metrics.process_targets,
        metrics_runtime_snapshot.process_targets
    );
    assert_eq!(
        snapshot.metrics.container_targets,
        metrics_runtime_snapshot.container_targets
    );
    assert_eq!(
        metrics_runtime_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.attempted_targets)
            .sum::<usize>(),
        metrics_runtime_snapshot.total_targets
    );
    assert!(
        metrics_runtime_snapshot
            .outcomes
            .iter()
            .all(|outcome| outcome.attempted_targets
                == outcome.succeeded_targets + outcome.failed_targets)
    );
    let host_outcome = metrics_runtime_snapshot
        .outcomes
        .iter()
        .find(|outcome| outcome.collection_kind == "host_metrics")
        .expect("host outcome");
    assert_eq!(host_outcome.status, "succeeded");
    assert!(host_outcome.last_error.is_none());
    assert!(!host_outcome.runtime_facts.is_empty());
    assert!(
        host_outcome
            .runtime_facts
            .iter()
            .any(|fact| fact.key == "discovery.source" || fact.key.starts_with("host."))
    );
    let process_outcome = metrics_runtime_snapshot
        .outcomes
        .iter()
        .find(|outcome| outcome.collection_kind == "process_metrics")
        .expect("process outcome");
    if metrics_runtime_snapshot.process_targets > 0 {
        assert!(matches!(
            process_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(
            process_outcome.succeeded_targets + process_outcome.failed_targets,
            process_outcome.attempted_targets
        );
        assert!(!process_outcome.runtime_facts.is_empty());
    } else {
        assert_eq!(process_outcome.status, "idle");
        assert!(process_outcome.last_error.is_none());
        assert!(process_outcome.runtime_facts.is_empty());
    }
    let container_outcome = metrics_runtime_snapshot
        .outcomes
        .iter()
        .find(|outcome| outcome.collection_kind == "container_metrics")
        .expect("container outcome");
    if metrics_runtime_snapshot.container_targets > 0 {
        assert!(matches!(
            container_outcome.status.as_str(),
            "succeeded" | "partial" | "failed"
        ));
        assert_eq!(
            container_outcome.succeeded_targets + container_outcome.failed_targets,
            container_outcome.attempted_targets
        );
        assert!(!container_outcome.runtime_facts.is_empty());
    } else {
        assert_eq!(container_outcome.status, "idle");
        assert!(container_outcome.last_error.is_none());
        assert!(container_outcome.runtime_facts.is_empty());
    }
    assert!(
        metrics_runtime_snapshot
            .outcomes
            .iter()
            .any(|outcome| outcome.collection_kind == "host_metrics")
    );
    assert!(
        metrics_runtime_snapshot
            .outcomes
            .iter()
            .flat_map(|outcome| outcome.sample_targets.iter())
            .any(|sample| !sample.candidate_id.is_empty() && !sample.target_ref.is_empty())
    );
    assert!(
        _metrics_samples_exporter.exists(),
        "metrics exporter output should exist"
    );
    assert!(snapshot.metrics.updated_at.is_some());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_can_enable_high_cardinality_discovery_explicitly() {
    let root = temp_dir("daemon-explicit-discovery");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\n").expect("write input log");

    let mut config = standalone_config_with_file_input(&root, &input_path);
    config.discovery = DiscoverySection {
        host_enabled: true,
        network_enabled: true,
        endpoint_enabled: true,
        process_enabled: true,
        container_enabled: true,
    };

    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    let discovery_resources: Vec<DiscoveredResource> =
        read_json(&state_dir.join("discovery").join("resources.json"))
            .expect("read discovery resources");

    let process_probe = snapshot
        .discovery
        .probes
        .iter()
        .find(|probe| probe.probe == "process")
        .expect("process probe should be scheduled when explicitly enabled");
    if process_probe.status == "ok" {
        assert!(
            discovery_resources
                .iter()
                .any(|resource| resource.kind == "process")
        );
    } else {
        assert!(process_probe.error.is_some());
    }
}

#[cfg(unix)]
#[test]
fn daemon_run_once_continues_when_discovery_cache_store_fails() {
    let root = temp_dir("daemon-discovery-store-fail");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\n").expect("write input log");

    let discovery_dir = state_dir.join("discovery");
    let config = standalone_config_with_file_input(&root, &input_path);
    daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("initial daemon run once");

    let mut perms = fs::metadata(&discovery_dir)
        .expect("discovery dir metadata")
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o500);
    fs::set_permissions(&discovery_dir, perms).expect("set discovery dir readonly");

    fs::write(&input_path, "first\nsecond\n").expect("append test input");
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once with discovery store failure");

    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<wist_contracts::telemetry_record::TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();

    assert_eq!(records.len(), 2);
    assert_eq!(snapshot.discovery.readiness, DiscoveryReadiness::Ready);
    assert!(snapshot.discovery.failure_count >= 1);
    assert!(snapshot.discovery.probes.iter().any(|probe| {
        probe.source == "cache"
            && probe.probe == "discovery"
            && probe.phase == "cache_store"
            && probe.status == "failed"
    }));
}

#[cfg(unix)]
#[test]
fn daemon_run_once_rebuilds_when_discovery_cache_is_corrupt() {
    let root = temp_dir("daemon-discovery-cache-corrupt");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\n").expect("write input log");

    let config = standalone_config_with_file_input(&root, &input_path);
    daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("initial daemon run once");

    let discovery_dir = state_dir.join("discovery");
    fs::write(discovery_dir.join("meta.json"), "{broken-json}\n").expect("corrupt meta");
    fs::write(&input_path, "first\nsecond\n").expect("update input log");

    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once after corrupt cache");

    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<wist_contracts::telemetry_record::TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();
    let discovery_meta: DiscoveryCacheMeta =
        read_json(&discovery_dir.join("meta.json")).expect("reloaded discovery meta");

    assert_eq!(records.len(), 2);
    assert_eq!(snapshot.discovery.readiness, DiscoveryReadiness::Ready);
    let cache_load_failures = snapshot
        .discovery
        .probes
        .iter()
        .filter(|probe| {
            probe.source == "cache"
                && probe.probe == "discovery"
                && probe.phase == "cache_load_meta"
                && probe.status == "failed"
        })
        .count();
    assert_eq!(cache_load_failures, 1);
    assert_eq!(discovery_meta.schema_version, "v1");
}

#[cfg(unix)]
#[test]
fn daemon_run_once_uses_cached_metrics_snapshot_when_target_view_is_missing() {
    let root = temp_dir("daemon-metrics-target-view-missing");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\n").expect("write input log");

    let config = standalone_config_with_file_input(&root, &input_path);
    daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("initial daemon run once");

    let telemetry_dir = state_dir.join("telemetry");
    let target_view_path = telemetry_dir.join("metrics_target_view.json");
    let runtime_snapshot_path = telemetry_dir.join("metrics_runtime_snapshot.json");
    let cached_snapshot: TestMetricsRuntimeSnapshot =
        read_json(&runtime_snapshot_path).expect("read cached runtime snapshot");
    fs::remove_file(&target_view_path).expect("remove target view");

    let mut perms = fs::metadata(&telemetry_dir)
        .expect("telemetry dir metadata")
        .permissions();
    use std::os::unix::fs::PermissionsExt;
    perms.set_mode(0o500);
    fs::set_permissions(&telemetry_dir, perms).expect("set telemetry dir readonly");

    fs::write(&input_path, "first\nsecond\n").expect("append input log");
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once with missing target view");

    let runtime_snapshot: TestMetricsRuntimeSnapshot =
        read_json(&runtime_snapshot_path).expect("read runtime snapshot after fallback");
    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<wist_contracts::telemetry_record::TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();

    assert_eq!(records.len(), 2);
    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert!(!snapshot.metrics.target_view_loaded);
    assert!(snapshot.metrics.used_cached_snapshot);
    assert!(snapshot.metrics.failure_count >= 1);
    assert_eq!(
        snapshot.metrics.attempted_targets,
        cached_snapshot.total_targets
    );
    assert_eq!(
        snapshot.metrics.succeeded_targets,
        cached_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.succeeded_targets)
            .sum::<usize>()
    );
    assert_eq!(
        snapshot.metrics.failed_targets,
        cached_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.failed_targets)
            .sum::<usize>()
    );
    assert!(
        snapshot
            .metrics
            .last_error
            .as_deref()
            .is_some_and(|error| error.contains("target_view_load"))
    );
    assert_eq!(
        snapshot.metrics.total_targets,
        cached_snapshot.total_targets
    );
    assert_eq!(snapshot.metrics.host_targets, cached_snapshot.host_targets);
    assert_eq!(
        snapshot.metrics.process_targets,
        cached_snapshot.process_targets
    );
    assert_eq!(
        snapshot.metrics.container_targets,
        cached_snapshot.container_targets
    );
    assert_eq!(
        runtime_snapshot.total_targets,
        cached_snapshot.total_targets
    );
    assert_eq!(runtime_snapshot.host_targets, cached_snapshot.host_targets);
    assert_eq!(
        runtime_snapshot.process_targets,
        cached_snapshot.process_targets
    );
    assert_eq!(
        runtime_snapshot.container_targets,
        cached_snapshot.container_targets
    );
    assert_eq!(
        runtime_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.succeeded_targets)
            .sum::<usize>(),
        cached_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.succeeded_targets)
            .sum::<usize>()
    );
    assert_eq!(
        runtime_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.failed_targets)
            .sum::<usize>(),
        cached_snapshot
            .outcomes
            .iter()
            .map(|outcome| outcome.failed_targets)
            .sum::<usize>()
    );
}

#[cfg(unix)]
#[test]
fn daemon_run_once_continues_when_one_file_input_fails() {
    let root = temp_dir("daemon-file-input-error-isolated");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let good_input = root.join("good.log");
    let bad_input = root.join("bad-dir");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&good_input, "good\n").expect("write good input");
    fs::create_dir_all(&bad_input).expect("create bad input dir");

    let config = standalone_config_with_file_inputs(
        &root,
        vec![
            LogFileInputSection {
                input_id: "bad".to_string(),
                path: bad_input.display().to_string(),
                startup_position: "head".to_string(),
                multiline_mode: "none".to_string(),
            },
            LogFileInputSection {
                input_id: "good".to_string(),
                path: good_input.display().to_string(),
                startup_position: "head".to_string(),
                multiline_mode: "none".to_string(),
            },
        ],
    );
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<wist_contracts::telemetry_record::TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "good");
    let checkpoint: TestLogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");

    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert_eq!(records.len(), 1);
    assert_eq!(records[0].body, "good\n");
    assert_eq!(checkpoint.files.len(), 1);
    assert!(!wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "bad").exists());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_assigns_globally_monotonic_seq_across_inputs() {
    let root = temp_dir("daemon-global-seq");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_a = root.join("a.log");
    let input_b = root.join("b.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_a, "a1\na2\n").expect("write input a");
    fs::write(&input_b, "b1\nb2\nb3\n").expect("write input b");

    let config = standalone_config_with_file_inputs(
        &root,
        vec![
            LogFileInputSection {
                input_id: "a".to_string(),
                path: input_a.display().to_string(),
                startup_position: "head".to_string(),
                multiline_mode: "none".to_string(),
            },
            LogFileInputSection {
                input_id: "b".to_string(),
                path: input_b.display().to_string(),
                startup_position: "head".to_string(),
                multiline_mode: "none".to_string(),
            },
        ],
    );
    daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();

    assert_eq!(records.len(), 5);
    // 跨 input 共享同一个单调计数器：5 条日志 seq 全局连续且不撞号（起始值被先行发送的指标帧占掉）。
    let seqs: Vec<u64> = records.iter().map(|record| record.seq).collect();
    let start = seqs[0];
    assert_eq!(seqs, (start..start + 5).collect::<Vec<u64>>());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_marks_active_when_only_file_input_fails() {
    let root = temp_dir("daemon-file-input-only-error");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let bad_input = root.join("bad-dir");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::create_dir_all(&bad_input).expect("create bad input dir");

    let config = standalone_config_with_file_inputs(
        &root,
        vec![LogFileInputSection {
            input_id: "bad".to_string(),
            path: bad_input.display().to_string(),
            startup_position: "head".to_string(),
            multiline_mode: "none".to_string(),
        }],
    );
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert!(!root.join("log").join("wist-records.ndjson").exists());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_marks_active_when_configured_file_is_missing() {
    let root = temp_dir("daemon-file-input-missing");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let missing_input = root.join("missing.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");

    let config = standalone_config_with_file_inputs(
        &root,
        vec![LogFileInputSection {
            input_id: "missing".to_string(),
            path: missing_input.display().to_string(),
            startup_position: "head".to_string(),
            multiline_mode: "none".to_string(),
        }],
    );
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert!(!root.join("log").join("wist-records.ndjson").exists());
    assert!(!wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "missing").exists());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_replays_existing_spool_even_when_source_file_is_missing() {
    let root = temp_dir("daemon-file-input-missing-replay");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let missing_input = root.join("missing.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");

    let spool_path = root
        .join("state")
        .join("spool")
        .join("logs")
        .join("missing.ndjson");
    fs::create_dir_all(spool_path.parent().expect("spool dir")).expect("create spool dir");
    let first = serde_json::to_string(&TelemetryRecord::new_log(
        "agent-test".to_string(),
        "2026-04-14T00:00:00Z".to_string(),
        "missing".to_string(),
        missing_input.display().to_string(),
        "first\n".to_string(),
        0,
        6,
        0,
    ))
    .expect("encode first");
    let second = serde_json::to_string(&TelemetryRecord::new_log(
        "agent-test".to_string(),
        "2026-04-14T00:00:01Z".to_string(),
        "missing".to_string(),
        missing_input.display().to_string(),
        "second\n".to_string(),
        6,
        13,
        1,
    ))
    .expect("encode second");
    fs::write(&spool_path, format!("{first}\n{second}\n")).expect("write spool");

    let config = standalone_config_with_file_inputs(
        &root,
        vec![LogFileInputSection {
            input_id: "missing".to_string(),
            path: missing_input.display().to_string(),
            startup_position: "head".to_string(),
            multiline_mode: "none".to_string(),
        }],
    );
    let snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let records: Vec<wist_contracts::telemetry_record::TelemetryRecord> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| serde_json::from_str(line).expect("parse telemetry record"))
        .collect();

    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].body, "first\n");
    assert_eq!(records[1].body, "second\n");
    assert!(!spool_path.exists());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_sends_raw_log_lines_to_tcp_output() {
    let root = temp_dir("daemon-file-input-tcp");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "alpha\nbeta\n").expect("write input log");

    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    let port = listener.local_addr().expect("listener addr").port();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("read tcp payload: {err}"),
            }
        }
        String::from_utf8(buf).expect("utf8 payload")
    });

    let config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    // 指标上送需要**授权的指标工作**：没有授权就不上送（见下一个用例）。
    let work = granted_metrics_work();
    let snapshot = daemon::run_once_with_work(
        &daemon::DaemonLoop {
            config: &config,
            exec_bin: &test_exec_bin(&root),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        },
        &work,
    )
    .expect("daemon run once");

    let payload = server.join().expect("join server");
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "app");
    let checkpoint: TestLogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");

    assert_eq!(
        snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    let raws = raw_body_sections(&payload);
    assert_eq!(raws, vec!["alpha".to_string(), "beta".to_string()]);
    // 指标帧与日志帧共用同一 TCP 连接，且指标优先（先于日志帧）。
    let metrics_pos = payload
        .find(" METRICS: ")
        .expect("metrics frame on shared uplink");
    let raw_pos = payload.find(" LOGRAW: ").expect("raw log frame");
    assert!(
        metrics_pos < raw_pos,
        "metrics frame should precede log frames"
    );
    assert!(payload.contains("\"schema\":\"v1\""));
    assert!(payload.contains("\"agent\":\"agent-001\""));
    assert!(payload.contains("\"seq\":0"));
    // 本机手工配置的输入**不来自任何采集面**：帧里就不带 `family`/`unit`。
    // 这不是缺字段 —— “不是平台派活来的”本身就是有用的信息。
    assert!(
        !payload.contains("\"family\":"),
        "手工配置的输入不该带采集面：{payload}"
    );
    assert_eq!(checkpoint.files.len(), 1);
    assert_eq!(
        checkpoint.files[0].checkpoint_offset,
        "alpha\nbeta\n".len() as u64
    );
    assert!(!root.join("log").join("wist-records.ndjson").exists());
}

/// 输出总闸关闭（`enabled = false`）→ **只发事实摘要，不发别的**。
///
/// 待命指「不产出**主机内容**」：不读源、不上送日志/指标、不推进 log checkpoint。但**事实摘要
/// 照发** —— 新装机器靠它把进程列表推给网关，否则连「该派什么活」都定不下来（实测的死锁）。
///
/// 关键回归点：待命期不能推进 log checkpoint —— 否则重新启用后从新 offset 续读，
/// 待命期间写入的行会被永久丢掉。
#[test]
fn daemon_run_once_with_output_disabled_only_reports_facts() {
    let root = temp_dir("daemon-output-disabled");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "alpha\nbeta\n").expect("write input log");

    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("listener addr").port();

    // 目标齐全但总闸关闭：连接里只该有事实帧。
    let mut config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    config.telemetry.logs.output.enabled = false;

    daemon::run_once_with_work(
        &daemon::DaemonLoop {
            config: &config,
            exec_bin: &test_exec_bin(&root),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        },
        &granted_metrics_work(),
    )
    .expect("daemon run once");

    // 待命期**会**建连接（推进程列表），但连接里只有事实帧。
    let payload = accept_and_drain(&listener);
    assert!(
        payload.contains(" OBSFACT: "),
        "待命必须仍把进程列表推出去: {payload}"
    );
    assert!(!payload.contains(" LOGRAW: "), "待命不发日志帧: {payload}");
    assert!(!payload.contains(" METRICS: "), "待命不发指标帧: {payload}");
    assert!(!root.join("log").join("wist-records.ndjson").exists());

    // 源文件 offset 不前进：待命期根本不读源，checkpoint 不该被创建/推进。
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "app");
    assert!(
        !checkpoint_path.exists(),
        "待命期不该推进 log checkpoint：{}",
        checkpoint_path.display()
    );
}

/// 接受待命期的那条上行连接并把它读尽（sink 在轮次末断开，所以能读到 EOF）。
///
/// 待命期**会**建连接（推进程列表），所以不能再断言「无连接」—— 要断言的是**连接里装了什么**。
fn accept_and_drain(listener: &TcpListener) -> String {
    // 有上限地等：连接在 `run_once` 返回前就已排队，正常第一轮就 accept 到；
    // 上限只是防止回归时挂死。
    let mut socket = None;
    for _ in 0..250 {
        if let Ok((accepted, _)) = listener.accept() {
            socket = Some(accepted);
            break;
        }
        thread::sleep(Duration::from_millis(20));
    }
    let mut socket = socket.expect("待命期必须建立上行连接推进程列表");
    socket
        .set_read_timeout(Some(Duration::from_secs(2)))
        .expect("set read timeout");
    let mut payload = String::new();
    let mut chunk = [0u8; 512];
    loop {
        match socket.read(&mut chunk) {
            Ok(0) => break,
            Ok(n) => payload.push_str(&String::from_utf8_lossy(&chunk[..n])),
            Err(_) => break,
        }
    }
    payload
}

/// 跑一轮 `run_once`，把这一轮上送出去的**日志原文**收集回来（按 ` LOGRAW: ` 帧切分）。
///
/// 用于跨轮断言：`run_once` 每轮自己建 sink、连一次、写完整轮、断开，所以“这一轮发了什么”
/// 就是一次 accept + 读到 EOF。
#[cfg(unix)]
fn run_once_collecting_tcp(
    root: &std::path::Path,
    input_path: &std::path::Path,
    enabled: bool,
) -> Vec<String> {
    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return Vec::new();
    };
    let port = listener.local_addr().expect("listener addr").port();
    let reader = thread::spawn(move || {
        let Ok((mut socket, _)) = listener.accept() else {
            return Vec::new();
        };
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set read timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 256];
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        raw_body_sections(&String::from_utf8_lossy(&buf))
    });

    let mut config =
        standalone_config_with_tcp_file_input(root, input_path, "127.0.0.1", port, "line");
    config.telemetry.logs.output.enabled = enabled;
    daemon::run_once_with_work(
        &daemon::DaemonLoop {
            config: &config,
            exec_bin: &test_exec_bin(root),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        },
        &granted_metrics_work(),
    )
    .expect("daemon run once");
    reader.join().expect("reader thread")
}

/// 关闸（`enabled = false`）不是「没数据」：它**不该动 spool**。
///
/// 待命期若照常回放 spool，就是拿「上次没发出去的记录」在**未被授权**时再试着发一次；
/// 反过来若把 spool 当垃圾清掉，则是静默丢数据。两种都不能发生 —— 这份文件要原样留着，
/// 等重新启用时按原顺序发。
#[cfg(unix)]
#[test]
fn daemon_standby_leaves_the_spool_untouched() {
    let root = temp_dir("daemon-standby-keeps-spool");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "alpha\n").expect("write input log");

    // 预置一份「上次没发出去」的 spool。
    let spool_path = state_dir.join("spool").join("logs").join("app.ndjson");
    fs::create_dir_all(spool_path.parent().expect("spool parent")).expect("mkdir spool");
    let spooled = "{\"agent_id\":\"agent-001\",\"raw\":\"beta\"}\n";
    fs::write(&spool_path, spooled).expect("seed spool");
    let before = fs::read(&spool_path).expect("read spool");

    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("listener addr").port();

    let mut config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    config.telemetry.logs.output.enabled = false;

    daemon::run_once_with_work(
        &daemon::DaemonLoop {
            config: &config,
            exec_bin: &test_exec_bin(&root),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        },
        &granted_metrics_work(),
    )
    .expect("daemon run once");

    thread::sleep(Duration::from_millis(200));
    // 待命**会**建连接推进程列表，但它不该回放 spool：上行里不能有日志帧（` LOGRAW: `）。
    let payload = accept_and_drain(&listener);
    assert!(
        !payload.contains(" LOGRAW: "),
        "待命期不该回放 spool（上行里不该有日志帧）: {payload}"
    );
    let after = fs::read(&spool_path).expect("read spool");
    assert_eq!(
        before, after,
        "待命期不该回放、也不该清理 spool：它要原样留到重新启用"
    );
}

/// 待命期**不读源** ⇒ 不推进 checkpoint。所以「启用 → 关闸 → 再启用」不该丢待命期写入的行，
/// 也不该把已经很早发出去的行重复发一遍。
#[cfg(unix)]
#[test]
fn daemon_reenable_after_standby_resumes_from_the_previous_checkpoint() {
    let root = temp_dir("daemon-reenable-resumes");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "alpha\n").expect("write input log");

    // 第一轮：启用，把 alpha 发出去，checkpoint 前进到文件尾。
    let first = run_once_collecting_tcp(&root, &input_path, true);
    assert!(first.iter().any(|body| body.contains("alpha")), "{first:?}");

    // 追加 beta，然后**关闸**跑一轮：不该有任何连接（也不该推进 checkpoint）。
    fs::write(&input_path, "alpha\nbeta\n").expect("append input log");
    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    listener.set_nonblocking(true).expect("nonblocking");
    let port = listener.local_addr().expect("listener addr").port();
    let mut gated =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    gated.telemetry.logs.output.enabled = false;
    daemon::run_once_with_work(
        &daemon::DaemonLoop {
            config: &gated,
            exec_bin: &test_exec_bin(&root),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        },
        &granted_metrics_work(),
    )
    .expect("gated run");
    thread::sleep(Duration::from_millis(200));
    assert!(listener.accept().is_err(), "关闸那一轮不该建立连接");

    // 再启用：beta 必须发出来（从旧 offset 续读，没丢），alpha 不该重复发。
    let resumed = run_once_collecting_tcp(&root, &input_path, true);
    assert!(
        resumed.iter().any(|body| body.contains("beta")),
        "重新启用后待命期写入的行不能丢：{resumed:?}"
    );
    assert!(
        !resumed.iter().any(|body| body.contains("alpha")),
        "checkpoint 不该回退：已发过的行不能重复发：{resumed:?}"
    );
}

/// 没有授权的指标工作 → **不上送指标**，但配置里的日志采集照旧。
///
/// 这是“不做任务工作的 Agent”在数据面上的具体含义：默认不发指标；
/// 而本机运维在配置里手工加的那条日志任务是逃生舱，不该被平台派活机制连带关掉。
#[cfg(unix)]
#[test]
fn daemon_run_once_without_granted_metrics_work_skips_the_metrics_frame() {
    let root = temp_dir("daemon-no-metrics-work");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "alpha\n").expect("write input log");

    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    let port = listener.local_addr().expect("listener addr").port();
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(_) => break,
            }
        }
        String::from_utf8(buf).expect("utf8 payload")
    });

    let config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    daemon::run_once(&daemon::DaemonLoop {
        config: &config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("daemon run once");

    let payload = server.join().expect("join server");
    assert!(!payload.contains(" METRICS: "), "{payload}");
    assert!(payload.contains(" LOGRAW: alpha"), "{payload}");
}

/// 网关派的日志活真的变成采集：工作里的 FileGlob 直接变成一个采集任务，
/// 配置里**什么都没写**。这是「网关决定这台机器该采什么」在 agentd 侧的落点。
#[cfg(unix)]
#[test]
fn a_granted_log_work_collects_the_glob_without_any_config_file_input() {
    let root = temp_dir("daemon-work-log-input");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("granted.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    // 先放一行历史：授权采集是 tail（不重放历史），所以这行**不该**被采。
    fs::write(&input_path, "history\n").expect("write input log");

    let Some(listener) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    let port = listener.local_addr().expect("listener addr").port();
    // 两轮采集各自开一条连接，服务端收两条并拼起来。
    let server = thread::spawn(move || {
        let mut collected = String::new();
        for _ in 0..2 {
            let (mut socket, _) = listener.accept().expect("accept");
            socket
                .set_read_timeout(Some(Duration::from_secs(2)))
                .expect("set timeout");
            let mut buf = Vec::new();
            let mut chunk = [0u8; 128];
            loop {
                match socket.read(&mut chunk) {
                    Ok(0) => break,
                    Ok(n) => buf.extend_from_slice(&chunk[..n]),
                    Err(_) => break,
                }
            }
            collected.push_str(&String::from_utf8(buf).expect("utf8 payload"));
        }
        collected
    });

    let mut config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    // 配置里**没有**任何 file_inputs：本用例要证明采集完全来自授权工作。
    config.telemetry.logs.file_inputs.clear();
    let work = granted_work(
        "CrashPanic",
        "collect_logs",
        "FileGlob",
        input_path.to_str().expect("utf8 path"),
    );
    let run = || {
        daemon::run_once_with_work(
            &daemon::DaemonLoop {
                config: &config,
                exec_bin: &test_exec_bin(&root),
                upgrader_bin: ::std::path::Path::new(""),
                config_dir: ::std::path::Path::new(""),
            },
            &work,
        )
        .expect("daemon run once")
    };

    run();
    fs::write(&input_path, "history\nfrom-work\n").expect("append input log");
    run();

    let payload = server.join().expect("join server");
    assert!(
        payload.contains(" LOGRAW: from-work"),
        "授权工作应当采到新增行：{payload}"
    );
    assert!(
        !payload.contains(" LOGRAW: history"),
        "授权采集不重放历史（tail）：{payload}"
    );
    // 授权派活的输入把**来源身份**带进帧：这是「这条来自哪个面」唯一的依据 ——
    // 正文规则没写时 `category` 恒为泛化的 `agent.log`，两个面一起跑就分不出来了。
    assert!(
        payload.contains(r#""family":"CrashPanic","unit":"unit-CrashPanic""#),
        "授权采集要把面与目录单元带进帧：{payload}"
    );
    // 工作折算出的输入 id 带 `work-` 前缀，checkpoint 建在这个名字上。
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(
        &state_dir,
        "work-CrashPanic-unit-CrashPanic",
    );
    assert!(checkpoint_path.exists(), "{}", checkpoint_path.display());
    assert!(!root.join("log").join("wist-records.ndjson").exists());
}

#[cfg(unix)]
#[test]
fn daemon_run_once_replays_spool_when_tcp_output_recovers() {
    let root = temp_dir("daemon-file-input-tcp-replay");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\nsecond\n").expect("write input log");

    let Some(reserved) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    let port = reserved.local_addr().expect("listener addr").port();
    drop(reserved);

    let failing_config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    let first_snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &failing_config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("first daemon run once");
    let spool_path = root
        .join("state")
        .join("spool")
        .join("logs")
        .join("app.ndjson");
    let spooled = fs::read_to_string(&spool_path).expect("read spool");

    assert_eq!(
        first_snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert!(spooled.contains("\"body\":\"first\\n\""));
    assert!(spooled.contains("\"body\":\"second\\n\""));

    fs::write(&input_path, "first\nsecond\nthird\n").expect("append third line");
    let Some(listener) = bind_tcp_listener(&format!("127.0.0.1:{port}")) else {
        return;
    };
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("read tcp payload: {err}"),
            }
        }
        String::from_utf8(buf).expect("utf8 payload")
    });

    let recovered_config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    let second_snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &recovered_config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("second daemon run once");
    let payload = server.join().expect("join server");
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "app");
    let checkpoint: TestLogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");

    assert_eq!(
        second_snapshot.state,
        wist_agentd::self_observability::DaemonWorkState::Active
    );
    assert_eq!(
        raw_body_sections(&payload),
        vec![
            "first".to_string(),
            "second".to_string(),
            "third".to_string()
        ]
    );
    assert!(!spool_path.exists());
    assert_eq!(checkpoint.files.len(), 1);
    assert_eq!(
        checkpoint.files[0].checkpoint_offset,
        "first\nsecond\nthird\n".len() as u64
    );
}

#[cfg(unix)]
#[test]
fn daemon_run_once_exposes_paused_input_and_recovers_in_health_snapshot() {
    let root = temp_dir("daemon-file-input-pause");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");
    fs::write(&input_path, "first\nsecond\n").expect("write input log");

    // 预留一个端口后立即释放，模拟 TCP 输出不可达，从而触发 spool。
    let Some(reserved) = bind_tcp_listener("127.0.0.1:0") else {
        return;
    };
    let port = reserved.local_addr().expect("listener addr").port();
    drop(reserved);

    let mut failing_config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    // 任意非空 spool 都视为超限，便于固定背压路径。
    failing_config.telemetry.logs.spool_max_bytes = 1;

    // 第一次：尚无 spool，先落 spool，不进入暂停。
    let first_snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &failing_config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("first daemon run once");
    assert!(first_snapshot.paused_inputs.is_empty());

    // 第二次：spool 已存在且上报仍不通，进入暂停，健康快照应暴露该输入。
    let paused_snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &failing_config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("paused daemon run once");
    assert_eq!(paused_snapshot.paused_inputs, vec!["app".to_string()]);

    // 恢复：TCP 可连后 spool 回放成功，退出暂停。
    let Some(listener) = bind_tcp_listener(&format!("127.0.0.1:{port}")) else {
        return;
    };
    let server = thread::spawn(move || {
        let (mut socket, _) = listener.accept().expect("accept");
        socket
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("set timeout");
        let mut buf = Vec::new();
        let mut chunk = [0u8; 128];
        loop {
            match socket.read(&mut chunk) {
                Ok(0) => break,
                Ok(n) => buf.extend_from_slice(&chunk[..n]),
                Err(err)
                    if matches!(
                        err.kind(),
                        std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                    ) =>
                {
                    break;
                }
                Err(err) => panic!("read tcp payload: {err}"),
            }
        }
        String::from_utf8(buf).expect("utf8 payload")
    });

    let recovered_config =
        standalone_config_with_tcp_file_input(&root, &input_path, "127.0.0.1", port, "line");
    let recovered_snapshot = daemon::run_once(&daemon::DaemonLoop {
        config: &recovered_config,
        exec_bin: &test_exec_bin(&root),
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    })
    .expect("recovered daemon run once");
    let _payload = server.join().expect("join server");

    assert!(recovered_snapshot.paused_inputs.is_empty());
}

#[cfg(unix)]
#[test]
fn daemon_restart_recovers_checkpoint_without_loss_or_duplication() {
    let root = temp_dir("daemon-restart");
    let run_dir = root.join("run");
    let state_dir = root.join("state");
    let log_dir = root.join("log");
    let input_path = root.join("app.log");
    bootstrap::initialize(&root, &run_dir, &state_dir, &log_dir).expect("bootstrap");

    let first_lines = "first\nsecond\n";
    fs::write(&input_path, first_lines).expect("write initial log");

    let config = standalone_config_with_file_input(&root, &input_path);
    let exec_bin = test_exec_bin(&root);
    let daemon_loop = daemon::DaemonLoop {
        config: &config,
        exec_bin: &exec_bin,
        upgrader_bin: ::std::path::Path::new(""),
        config_dir: ::std::path::Path::new(""),
    };

    // 第一次运行：处理初始两行，并持久化 checkpoint 到磁盘。
    daemon::run_once(&daemon_loop).expect("first run");

    // 崩溃窗口：进程已退出（不优雅停机），但源文件仍在增长。
    let second_lines = "third\nfourth\n";
    fs::write(&input_path, format!("{first_lines}{second_lines}")).expect("append after crash");

    // 重启：新的一次 run_once 从持久化 checkpoint 恢复，只读新增行。
    daemon::run_once(&daemon_loop).expect("restart run");

    // 不丢不重：四行各恰好一次、顺序正确。
    let output_path = root.join("log").join("wist-records.ndjson");
    let output = fs::read_to_string(&output_path).expect("read output");
    let bodies: Vec<String> = output
        .lines()
        .filter(|line| !line.trim().is_empty())
        .map(|line| {
            let record: TelemetryRecord = serde_json::from_str(line).expect("parse record");
            record.body
        })
        .collect();

    assert_eq!(bodies, vec!["first\n", "second\n", "third\n", "fourth\n"]);

    // checkpoint 最终偏移覆盖全部内容，确认无回退。
    let checkpoint_path = wist_agentd::state_store::log_checkpoints::path_for(&state_dir, "app");
    let checkpoint: TestLogCheckpointState = read_json(&checkpoint_path).expect("read checkpoint");
    assert_eq!(
        checkpoint.files[0].checkpoint_offset,
        (first_lines.len() + second_lines.len()) as u64
    );
}
