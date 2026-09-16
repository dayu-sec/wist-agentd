//! Self-observability placeholders.

use crate::runtime::steady_log;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum DiscoveryReadiness {
    NotReady,
    ReadyWithStaleSnapshot,
    Ready,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub struct DiscoveryProbeHealth {
    pub source: String,
    pub probe: String,
    pub phase: String,
    pub status: String,
    pub resource_count: usize,
    pub target_count: usize,
    pub error: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub struct DiscoveryHealthSnapshot {
    pub readiness: DiscoveryReadiness,
    pub cached_snapshot_loaded: bool,
    pub used_cached_snapshot: bool,
    pub resource_count: usize,
    pub target_count: usize,
    pub failure_count: usize,
    pub last_success_at: Option<String>,
    pub updated_at: String,
    pub probes: Vec<DiscoveryProbeHealth>,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub struct MetricsHealthSnapshot {
    pub target_view_loaded: bool,
    pub used_cached_snapshot: bool,
    pub total_targets: usize,
    pub host_targets: usize,
    pub process_targets: usize,
    pub container_targets: usize,
    pub attempted_targets: usize,
    pub succeeded_targets: usize,
    pub failed_targets: usize,
    pub failure_count: usize,
    pub last_error: Option<String>,
    pub updated_at: Option<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HealthState {
    Idle,
    Active,
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Health")]
pub struct RuntimeHealthSnapshot {
    pub state: HealthState,
    pub queue_depth: usize,
    pub running_count: usize,
    pub reporting_count: usize,
    pub discovery: DiscoveryHealthSnapshot,
    pub metrics: MetricsHealthSnapshot,
    /// 当前因 spool 超限而暂停采集的输入（工作状态，非告警/失败）。
    pub paused_inputs: Vec<String>,
    pub updated_at: String,
}

pub fn register() {
    eprintln!("self-observability registered");
}

/// 稳态日志收敛用的稳定签名：只包含改变运维语义的字段，排除每 tick 都会变化的
/// `updated_at`（整体 / 发现 / 指标三个时间戳）。内容不变时[`emit`] 只补心跳。
pub fn health_signature(snapshot: &RuntimeHealthSnapshot) -> String {
    let mut signature = format!(
        "state={:?} queue={} running={} reporting={} paused={}",
        snapshot.state,
        snapshot.queue_depth,
        snapshot.running_count,
        snapshot.reporting_count,
        snapshot.paused_inputs.join(",")
    );
    signature.push_str(&format!(
        " discovery={:?} cached_loaded={} used_cached={} resources={} targets={} failures={} last_success={}",
        snapshot.discovery.readiness,
        snapshot.discovery.cached_snapshot_loaded,
        snapshot.discovery.used_cached_snapshot,
        snapshot.discovery.resource_count,
        snapshot.discovery.target_count,
        snapshot.discovery.failure_count,
        snapshot.discovery.last_success_at.as_deref().unwrap_or("-"),
    ));
    for probe in &snapshot.discovery.probes {
        signature.push_str(&format!(
            "\nprobe={} {} {} {} {} {}",
            probe.source,
            probe.probe,
            probe.phase,
            probe.status,
            probe.resource_count,
            probe.target_count,
        ));
    }
    signature.push_str(" metrics=");
    signature.push_str(&metrics_signature(&snapshot.metrics));
    signature
}

/// 指标快照的稳定签名（同样排除 `updated_at`）。
pub fn metrics_signature(metrics: &MetricsHealthSnapshot) -> String {
    format!(
        "target_view_loaded={} used_cached={} total={} host={} process={} container={} attempted={} succeeded={} failed={} failures={} last_error={}",
        metrics.target_view_loaded,
        metrics.used_cached_snapshot,
        metrics.total_targets,
        metrics.host_targets,
        metrics.process_targets,
        metrics.container_targets,
        metrics.attempted_targets,
        metrics.succeeded_targets,
        metrics.failed_targets,
        metrics.failure_count,
        metrics.last_error.as_deref().unwrap_or("-"),
    )
}

pub fn emit(snapshot: &RuntimeHealthSnapshot) {
    if !steady_log::should_emit_health(&health_signature(snapshot)) {
        return;
    }
    emit_full(snapshot);
}

fn emit_full(snapshot: &RuntimeHealthSnapshot) {
    eprintln!(
        "health state={:?} queue={} running={} reporting={} paused_inputs={} discovery_readiness={:?} discovery_cached_loaded={} discovery_used_cached={} discovery_resources={} discovery_targets={} discovery_failures={} discovery_last_success_at={} updated_at={}",
        snapshot.state,
        snapshot.queue_depth,
        snapshot.running_count,
        snapshot.reporting_count,
        snapshot.paused_inputs.join(","),
        snapshot.discovery.readiness,
        snapshot.discovery.cached_snapshot_loaded,
        snapshot.discovery.used_cached_snapshot,
        snapshot.discovery.resource_count,
        snapshot.discovery.target_count,
        snapshot.discovery.failure_count,
        snapshot.discovery.last_success_at.as_deref().unwrap_or("-"),
        snapshot.updated_at
    );
    eprintln!(
        "metrics_runtime target_view_loaded={} used_cached_snapshot={} total_targets={} host_targets={} process_targets={} container_targets={} attempted_targets={} succeeded_targets={} failed_targets={} failures={} last_error={} updated_at={}",
        snapshot.metrics.target_view_loaded,
        snapshot.metrics.used_cached_snapshot,
        snapshot.metrics.total_targets,
        snapshot.metrics.host_targets,
        snapshot.metrics.process_targets,
        snapshot.metrics.container_targets,
        snapshot.metrics.attempted_targets,
        snapshot.metrics.succeeded_targets,
        snapshot.metrics.failed_targets,
        snapshot.metrics.failure_count,
        snapshot.metrics.last_error.as_deref().unwrap_or("-"),
        snapshot.metrics.updated_at.as_deref().unwrap_or("-"),
    );

    for probe in &snapshot.discovery.probes {
        eprintln!(
            "discovery_probe source={} probe={} phase={} status={} resources={} targets={} error={}",
            probe.source,
            probe.probe,
            probe.phase,
            probe.status,
            probe.resource_count,
            probe.target_count,
            probe.error.as_deref().unwrap_or("-"),
        );
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn snapshot(updated_at: &str) -> RuntimeHealthSnapshot {
        RuntimeHealthSnapshot {
            state: HealthState::Idle,
            queue_depth: 0,
            running_count: 0,
            reporting_count: 0,
            discovery: DiscoveryHealthSnapshot {
                readiness: DiscoveryReadiness::Ready,
                cached_snapshot_loaded: true,
                used_cached_snapshot: false,
                resource_count: 3,
                target_count: 2,
                failure_count: 0,
                last_success_at: Some("2026-01-01T00:00:00Z".to_string()),
                updated_at: updated_at.to_string(),
                probes: vec![DiscoveryProbeHealth {
                    source: "host".to_string(),
                    probe: "host".to_string(),
                    phase: "refresh".to_string(),
                    status: "ok".to_string(),
                    resource_count: 3,
                    target_count: 2,
                    error: None,
                }],
            },
            metrics: MetricsHealthSnapshot {
                target_view_loaded: true,
                used_cached_snapshot: false,
                total_targets: 2,
                host_targets: 1,
                process_targets: 1,
                container_targets: 0,
                attempted_targets: 2,
                succeeded_targets: 2,
                failed_targets: 0,
                failure_count: 0,
                last_error: None,
                updated_at: Some(updated_at.to_string()),
            },
            paused_inputs: Vec::new(),
            updated_at: updated_at.to_string(),
        }
    }

    #[test]
    fn health_signature_ignores_per_tick_timestamps() {
        let first = snapshot("2026-01-01T00:00:00Z");
        let second = snapshot("2026-01-01T00:00:01Z");

        assert_eq!(health_signature(&first), health_signature(&second));
    }

    #[test]
    fn health_signature_tracks_meaningful_changes() {
        let base = snapshot("2026-01-01T00:00:00Z");

        let mut queued = snapshot("2026-01-01T00:00:00Z");
        queued.queue_depth = 1;
        assert_ne!(health_signature(&base), health_signature(&queued));

        let mut probe_failed = snapshot("2026-01-01T00:00:00Z");
        probe_failed.discovery.probes[0].status = "failed".to_string();
        assert_ne!(health_signature(&base), health_signature(&probe_failed));

        let mut metrics_failed = snapshot("2026-01-01T00:00:00Z");
        metrics_failed.metrics.failed_targets = 1;
        assert_ne!(health_signature(&base), health_signature(&metrics_failed));
    }

    #[test]
    fn metrics_signature_ignores_updated_at() {
        let first = snapshot("2026-01-01T00:00:00Z").metrics;
        let second = snapshot("2027-02-03T04:05:06Z").metrics;
        assert_eq!(metrics_signature(&first), metrics_signature(&second));

        let mut failing = second;
        failing.failure_count = 1;
        assert_ne!(metrics_signature(&first), metrics_signature(&failing));
    }
}
