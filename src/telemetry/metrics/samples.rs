//! 指标样本规范化：采集 fact + 注册表 → 样本 → VM JSON line。
//!
//! 规则（对应《指标数据规范》）：
//! - 指标名/单位/类型/常量 label 只来自注册表；采集侧只产 `fact_key`。
//! - 一条样本 = 一条时间序列的一个点；身份是 `(name, agent, instance, 实例 label)`。
//! - 指标通道只收数值；解析失败丢弃样本，不降级为字符串。
//! - 失败目标不上送样本。

use std::collections::BTreeMap;
use std::sync::atomic::{AtomicU64, Ordering};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;
use wist_contracts::discovery::StringKeyValue;
use wist_shared::time::now_ts_ms;

use super::runtime::{
    MetricsCollectionOutcome, MetricsCollectionTargetSample, MetricsRuntimeSnapshot,
};
use super::spec::find_metric_spec;

static METRICS_BATCH_SEQ: AtomicU64 = AtomicU64::new(0);

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[serde(deny_unknown_fields)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct MetricsSamplesSnapshot {
    pub batch_seq: u64,
    pub collected_at: String,
    #[serde(default)]
    pub groups: Vec<MetricsSampleGroup>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[serde(deny_unknown_fields)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct MetricsSampleGroup {
    /// 稳定身份（主机资源 id / `host:proc:identity` / 容器资源 id）。
    pub instance: String,
    #[serde(default)]
    pub samples: Vec<MetricsSampleRecord>,
}

#[derive(Debug, Clone, PartialEq, Serialize, Deserialize, ::jumo_derive::Jumo)]
#[serde(deny_unknown_fields)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Collect")]
pub struct MetricsSampleRecord {
    pub name: String,
    pub value: Value,
    #[serde(rename = "type")]
    pub value_type: String,
    /// 注册表声明的常量 label（如 `disk_role`）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub const_labels: Vec<StringKeyValue>,
    /// 来自采集事实的动态 label（如 `mountpoint` / `device` / `state`）。
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub labels: Vec<StringKeyValue>,
}

/// VM（VictoriaMetrics）`/api/v1/import` 的 JSON line 单条指标。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmMetricLine {
    pub metric: VmMetricLabels,
    pub values: Vec<f64>,
    pub timestamps: Vec<i64>,
}

/// VM JSON line 的 `metric` 对象：`__name__` 为指标名，其余为 label。
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct VmMetricLabels {
    #[serde(rename = "__name__")]
    pub name: String,
    pub agent: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub instance: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disk_role: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mountpoint: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fstype: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_kind: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub outcome: Option<String>,
    /// 选择类 label（`app` / `env` / `cluster` …）：由配置下发，不参与身份。
    #[serde(flatten)]
    pub selection: BTreeMap<String, String>,
}

/// 把样本快照拍平成 VM JSON lines（一 sample 一行）。
pub fn build_vm_metric_lines(
    snapshot: &MetricsSamplesSnapshot,
    agent_id: &str,
) -> Vec<VmMetricLine> {
    build_vm_metric_lines_with(snapshot, agent_id, &BTreeMap::new())
}

/// 同 [`build_vm_metric_lines`]，额外把选择类 label 贴到每条序列上。
pub fn build_vm_metric_lines_with(
    snapshot: &MetricsSamplesSnapshot,
    agent_id: &str,
    selection: &BTreeMap<String, String>,
) -> Vec<VmMetricLine> {
    let timestamp_ms = timestamp_ms(&snapshot.collected_at).unwrap_or_else(now_ts_ms);
    let mut lines = Vec::new();
    for group in &snapshot.groups {
        for sample in &group.samples {
            if !is_numeric_sample(&sample.value_type) {
                continue;
            }
            let Some(value) = sample.value.as_f64() else {
                continue;
            };
            lines.push(VmMetricLine {
                metric: VmMetricLabels {
                    name: sample.name.clone(),
                    agent: agent_id.to_string(),
                    instance: group.instance.clone(),
                    disk_role: label_value(&sample.const_labels, "disk_role").map(str::to_string),
                    mountpoint: label_value(&sample.labels, "mountpoint").map(str::to_string),
                    fstype: label_value(&sample.labels, "fstype").map(str::to_string),
                    device: label_value(&sample.labels, "device").map(str::to_string),
                    cpu: label_value(&sample.labels, "cpu").map(str::to_string),
                    mode: label_value(&sample.labels, "mode").map(str::to_string),
                    state: label_value(&sample.labels, "state").map(str::to_string),
                    target_kind: label_value(&sample.labels, "target_kind").map(str::to_string),
                    outcome: label_value(&sample.labels, "outcome").map(str::to_string),
                    selection: selection.clone(),
                },
                values: vec![value],
                timestamps: vec![timestamp_ms],
            });
        }
    }
    lines
}

fn timestamp_ms(collected_at: &str) -> Option<i64> {
    let parsed = OffsetDateTime::parse(collected_at, &Rfc3339).ok()?;
    i64::try_from(parsed.unix_timestamp_nanos() / 1_000_000).ok()
}

fn is_numeric_sample(value_type: &str) -> bool {
    matches!(
        value_type,
        "gauge_i64" | "counter_i64" | "gauge_f64" | "counter_f64"
    )
}

pub fn build_samples_snapshot(runtime: &MetricsRuntimeSnapshot) -> MetricsSamplesSnapshot {
    let seq = METRICS_BATCH_SEQ.fetch_add(1, Ordering::Relaxed);
    let mut groups = Vec::new();

    for outcome in &runtime.outcomes {
        build_outcome_groups(outcome, &mut groups);
    }
    if let Some(group) = build_collect_targets_group(runtime) {
        groups.push(group);
    }

    MetricsSamplesSnapshot {
        batch_seq: seq,
        collected_at: runtime.generated_at.clone(),
        groups,
    }
}

/// 采集记账：每批按 `target_kind × outcome` 报目标数（`dropped` 必须有账）。
fn build_collect_targets_group(runtime: &MetricsRuntimeSnapshot) -> Option<MetricsSampleGroup> {
    let mut samples = Vec::new();
    for outcome in &runtime.outcomes {
        let kind = match outcome.collection_kind.as_str() {
            "host_metrics" => "host",
            "process_metrics" => "process",
            "container_metrics" => "container",
            _ => continue,
        };
        // 部分成功（partial）计入 succeeded：outcome 只给了 succeeded/failed 两个计数。
        for (result, count) in [
            ("succeeded", outcome.succeeded_targets),
            ("failed", outcome.failed_targets),
            ("dropped", outcome.dropped_targets),
        ] {
            if count == 0 {
                continue;
            }
            samples.push(MetricsSampleRecord {
                name: "agent_collect_targets".to_string(),
                value: Value::Number(count.into()),
                value_type: "gauge_i64".to_string(),
                const_labels: Vec::new(),
                labels: vec![
                    StringKeyValue::new("target_kind", kind),
                    StringKeyValue::new("outcome", result),
                ],
            });
        }
    }
    (!samples.is_empty()).then(|| MetricsSampleGroup {
        instance: String::new(),
        samples,
    })
}

fn build_outcome_groups(outcome: &MetricsCollectionOutcome, groups: &mut Vec<MetricsSampleGroup>) {
    for target in &outcome.sample_targets {
        // 失败目标没有可信读数：不上送，也不补 0。
        if target.status == "failed" {
            continue;
        }
        let mut samples = Vec::new();

        for fact in &target.runtime_facts {
            push_metric_sample(
                &mut samples,
                &outcome.collection_kind,
                &fact.key,
                &fact.value,
                &[],
            );
        }
        for fact in &target.labeled_facts {
            push_metric_sample(
                &mut samples,
                &outcome.collection_kind,
                &fact.key,
                &fact.value,
                &fact.labels,
            );
        }

        if !samples.is_empty() {
            groups.push(MetricsSampleGroup {
                instance: stable_instance(&outcome.collection_kind, target),
                samples,
            });
        }
    }
}

/// 稳定身份：进程用 `host:proc:<identity>`，主机/容器用资源 id。
///
/// PID 会被回收，因此不作为身份；`process.identity` 缺失时退回资源 id
/// （此时身份里可能含 PID，属于降级路径，调用方应保证发现层给出 identity）。
fn stable_instance(collection_kind: &str, target: &MetricsCollectionTargetSample) -> String {
    if collection_kind != "process_metrics" {
        return target.resource_ref.clone();
    }
    let host = target
        .resource_ref
        .split(':')
        .next()
        .unwrap_or(&target.resource_ref);
    let identity = label_value(&target.execution_hints, "process.identity")
        .unwrap_or(target.resource_ref.as_str());
    format!("{host}:proc:{identity}")
}

fn push_metric_sample(
    samples: &mut Vec<MetricsSampleRecord>,
    collection_kind: &str,
    fact_key: &str,
    raw_value: &str,
    fact_labels: &[StringKeyValue],
) {
    let Some(spec) = find_metric_spec(collection_kind, fact_key) else {
        return;
    };

    // 枚举类 fact：取值进 `state` label，样本值恒为 1（一热）。
    if spec.dynamic_labels.contains(&"state") {
        samples.push(MetricsSampleRecord {
            name: spec.name.to_string(),
            value: Value::Number(1.into()),
            value_type: spec.value_type.to_string(),
            const_labels: spec
                .const_labels
                .iter()
                .map(|(key, value)| StringKeyValue::new(*key, *value))
                .collect(),
            labels: vec![StringKeyValue::new("state", normalize_state(raw_value))],
        });
        return;
    }

    let Some(value) = sample_value(spec.value_type, raw_value) else {
        return;
    };
    let labels = spec
        .dynamic_labels
        .iter()
        .filter_map(|key| {
            label_value(fact_labels, key).map(|value| StringKeyValue::new(*key, value))
        })
        .collect();

    samples.push(MetricsSampleRecord {
        name: spec.name.to_string(),
        value,
        value_type: spec.value_type.to_string(),
        const_labels: spec
            .const_labels
            .iter()
            .map(|(key, value)| StringKeyValue::new(*key, *value))
            .collect(),
        labels,
    });
}

/// `state` 取值必须落在闭集内；未识别的值一律折成 `unknown`，不得新增取值。
fn normalize_state(raw: &str) -> &str {
    match raw {
        "running" | "sleeping" | "disk_sleep" | "stopped" | "zombie" | "dead" | "idle"
        | "unknown" => raw,
        _ => "unknown",
    }
}

fn label_value<'a>(labels: &'a [StringKeyValue], key: &str) -> Option<&'a str> {
    labels
        .iter()
        .find(|label| label.key == key)
        .map(|label| label.value.as_str())
}

/// 只接受可表示的数值：`NaN` / `±Inf` / 解析失败一律丢弃。
fn sample_value(value_type: &str, raw: &str) -> Option<Value> {
    match value_type {
        "gauge_i64" | "counter_i64" => raw.parse::<i64>().ok().map(|v| Value::Number(v.into())),
        "gauge_f64" | "counter_f64" => raw
            .parse::<f64>()
            .ok()
            .filter(|v| v.is_finite())
            .and_then(|v| serde_json::Number::from_f64(v).map(Value::Number)),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;

    use wist_contracts::discovery::StringKeyValue;

    use super::{
        MetricsSampleGroup, MetricsSampleRecord, MetricsSamplesSnapshot, build_samples_snapshot,
        build_vm_metric_lines, build_vm_metric_lines_with,
    };
    use crate::telemetry::metrics::runtime::{
        MetricsCollectionOutcome, MetricsCollectionTargetSample, MetricsLabeledFact,
        MetricsRuntimeSnapshot,
    };

    fn target(status: &str, resource_ref: &str) -> MetricsCollectionTargetSample {
        MetricsCollectionTargetSample {
            candidate_id: format!("{resource_ref}:candidate"),
            target_ref: format!("{resource_ref}:target"),
            status: status.to_string(),
            last_error: None,
            resource_ref: resource_ref.to_string(),
            execution_hints: vec![StringKeyValue::new(
                "process.identity",
                "linux_proc_start:7",
            )],
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
        }
    }

    fn group_of<'a>(
        snapshot: &'a MetricsSamplesSnapshot,
        instance: &str,
    ) -> &'a MetricsSampleGroup {
        snapshot
            .groups
            .iter()
            .find(|group| group.instance == instance)
            .unwrap_or_else(|| panic!("missing group {instance}"))
    }

    fn snapshot(kind: &str, targets: Vec<MetricsCollectionTargetSample>) -> MetricsRuntimeSnapshot {
        MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: targets.len(),
            host_targets: 0,
            process_targets: 0,
            container_targets: 0,
            outcomes: vec![MetricsCollectionOutcome {
                collection_kind: kind.to_string(),
                status: "succeeded".to_string(),
                attempted_targets: targets.len(),
                succeeded_targets: targets.len(),
                failed_targets: 0,
                dropped_targets: 0,
                last_error: None,
                runtime_facts: Vec::new(),
                labeled_facts: Vec::new(),
                sample_targets: targets,
            }],
        }
    }

    #[test]
    fn host_facts_become_snake_case_samples() {
        let mut sample_target = target("succeeded", "host-1");
        sample_target.runtime_facts = vec![
            StringKeyValue::new("host.loadavg.1m", "0.5"),
            StringKeyValue::new("host.memory.total_bytes", "17179869184"),
        ];

        let snapshot = build_samples_snapshot(&snapshot("host_metrics", vec![sample_target]));

        let group = group_of(&snapshot, "host-1");
        assert_eq!(group.instance, "host-1");
        let names: Vec<&str> = group
            .samples
            .iter()
            .map(|sample| sample.name.as_str())
            .collect();
        assert!(names.contains(&"system_load_average_1m"));
        assert!(names.contains(&"system_memory_total_bytes"));
    }

    #[test]
    fn failed_targets_do_not_emit_samples() {
        let mut sample_target = target("failed", "host-1");
        sample_target.runtime_facts = vec![StringKeyValue::new("host.loadavg.1m", "0.5")];
        let snapshot = build_samples_snapshot(&snapshot("host_metrics", vec![sample_target]));
        assert!(
            snapshot
                .groups
                .iter()
                .all(|group| group.instance.is_empty()),
            "failed targets must not produce sample groups"
        );
    }

    #[test]
    fn invalid_numbers_are_dropped_not_stringified() {
        let mut sample_target = target("succeeded", "host-1");
        sample_target.runtime_facts = vec![
            StringKeyValue::new("host.loadavg.1m", "not-a-number"),
            StringKeyValue::new("host.uptime.seconds", "12.5"),
        ];
        let snapshot = build_samples_snapshot(&snapshot("host_metrics", vec![sample_target]));
        let samples = &snapshot.groups[0].samples;
        assert_eq!(samples.len(), 1);
        assert_eq!(samples[0].name, "system_uptime_seconds");
        assert!(samples[0].value.is_number());
    }

    #[test]
    fn const_labels_and_dynamic_labels_follow_the_registry() {
        let mut sample_target = target("succeeded", "host-1");
        sample_target.labeled_facts = vec![MetricsLabeledFact {
            key: "host.filesystem.available_bytes".to_string(),
            value: "1024".to_string(),
            labels: vec![
                StringKeyValue::new("mountpoint", "/data"),
                StringKeyValue::new("fstype", "xfs"),
                StringKeyValue::new("unexpected", "x"),
            ],
        }];
        let snapshot = build_samples_snapshot(&snapshot("host_metrics", vec![sample_target]));
        let group = group_of(&snapshot, "host-1");
        let sample = &group.samples[0];
        assert_eq!(sample.name, "system_filesystem_available_bytes");
        assert_eq!(sample.labels.len(), 2, "unknown label must be dropped");
        assert!(sample.const_labels.is_empty());

        let lines = build_vm_metric_lines(&snapshot, "agent-1");
        let line = lines
            .iter()
            .find(|line| line.metric.name == "system_filesystem_available_bytes")
            .expect("filesystem line");
        assert_eq!(line.metric.mountpoint.as_deref(), Some("/data"));
        assert_eq!(line.metric.fstype.as_deref(), Some("xfs"));
        assert_eq!(line.timestamps[0], 1_776_556_800_000);
    }

    #[test]
    fn state_facts_become_one_hot_samples() {
        let mut sample_target = target("succeeded", "host-1:pid:42");
        sample_target.runtime_facts = vec![StringKeyValue::new("process.state", "running")];
        let snapshot = build_samples_snapshot(&snapshot("process_metrics", vec![sample_target]));
        let sample = &group_of(&snapshot, "host-1:proc:linux_proc_start:7").samples[0];
        assert_eq!(sample.name, "process_state");
        assert_eq!(sample.value.as_i64(), Some(1));
        assert_eq!(sample.labels[0].key, "state");
        assert_eq!(sample.labels[0].value, "running");
    }

    #[test]
    fn unknown_state_values_collapse_to_unknown() {
        let mut sample_target = target("succeeded", "host-1:pid:42");
        sample_target.runtime_facts = vec![StringKeyValue::new("process.state", "weird")];
        let snapshot = build_samples_snapshot(&snapshot("process_metrics", vec![sample_target]));
        assert_eq!(
            group_of(&snapshot, "host-1:proc:linux_proc_start:7").samples[0].labels[0].value,
            "unknown"
        );
    }

    #[test]
    fn process_instance_is_stable_identity_not_pid() {
        let sample_target = target("succeeded", "host-1:pid:42");
        let mut sample_target = sample_target;
        sample_target.runtime_facts = vec![StringKeyValue::new("process.cpu.seconds", "12.5")];
        let snapshot = build_samples_snapshot(&snapshot("process_metrics", vec![sample_target]));
        assert_eq!(
            group_of(&snapshot, "host-1:proc:linux_proc_start:7").instance,
            "host-1:proc:linux_proc_start:7"
        );
    }

    #[test]
    fn host_instance_is_the_host_resource_id() {
        let target = target("succeeded", "host-1");
        assert_eq!(super::stable_instance("host_metrics", &target), "host-1");
    }

    #[test]
    fn process_instance_without_identity_falls_back_to_resource_ref() {
        // 降级路径：发现层没给 process.identity 时，只能用资源 id（含 PID）。
        let mut target = target("succeeded", "host-1:pid:42");
        target.execution_hints.clear();
        assert_eq!(
            super::stable_instance("process_metrics", &target),
            "host-1:proc:host-1:pid:42"
        );
    }

    #[test]
    fn container_instance_falls_back_to_resource_ref() {
        // 已知缺口：发现层的容器 hint 里没有 container id，
        // 规范要求的 `<host>:ctr:<id>` 暂时拿不到，先退化为资源 id。
        let target = target("succeeded", "container-1");
        assert_eq!(
            super::stable_instance("container_metrics", &target),
            "container-1"
        );
    }

    #[test]
    fn vm_timestamps_follow_collected_at_not_send_time() {
        let snapshot = MetricsSamplesSnapshot {
            batch_seq: 0,
            collected_at: "2026-04-19T00:00:00Z".to_string(),
            groups: vec![MetricsSampleGroup {
                instance: "host-1".to_string(),
                samples: vec![MetricsSampleRecord {
                    name: "system_uptime_seconds".to_string(),
                    value: serde_json::json!(42.0),
                    value_type: "gauge_f64".to_string(),
                    const_labels: Vec::new(),
                    labels: Vec::new(),
                }],
            }],
        };
        let lines = build_vm_metric_lines(&snapshot, "agent-1");
        assert_eq!(lines[0].timestamps, vec![1_776_556_800_000]);
    }

    #[test]
    fn collect_targets_are_reported_per_kind_and_outcome() {
        let runtime = MetricsRuntimeSnapshot {
            generated_at: "2026-04-19T00:00:00Z".to_string(),
            total_targets: 10,
            host_targets: 0,
            process_targets: 10,
            container_targets: 0,
            outcomes: vec![MetricsCollectionOutcome {
                collection_kind: "process_metrics".to_string(),
                status: "partial".to_string(),
                attempted_targets: 10,
                succeeded_targets: 5,
                failed_targets: 2,
                dropped_targets: 3,
                last_error: None,
                runtime_facts: Vec::new(),
                labeled_facts: Vec::new(),
                sample_targets: Vec::new(),
            }],
        };
        let snapshot = build_samples_snapshot(&runtime);

        let group = group_of(&snapshot, "");
        let value = |outcome: &str| {
            group
                .samples
                .iter()
                .find(|sample| {
                    sample.name == "agent_collect_targets"
                        && sample
                            .labels
                            .iter()
                            .any(|label| label.key == "outcome" && label.value == outcome)
                })
                .and_then(|sample| sample.value.as_i64())
        };
        assert_eq!(value("succeeded"), Some(5));
        assert_eq!(value("failed"), Some(2));
        assert_eq!(
            value("dropped"),
            Some(3),
            "dropped targets must be accounted"
        );

        let lines = build_vm_metric_lines(&snapshot, "agent-1");
        let line = &lines[0];
        assert_eq!(line.metric.name, "agent_collect_targets");
        assert_eq!(line.metric.target_kind.as_deref(), Some("process"));
        assert!(line.metric.instance.is_empty());
        let json = serde_json::to_value(line).expect("serialize");
        assert!(json["metric"].get("instance").is_none());
    }

    #[test]
    fn vm_line_json_has_no_null_labels() {
        let mut sample_target = target("succeeded", "host-1");
        sample_target.runtime_facts = vec![StringKeyValue::new("host.loadavg.1m", "0.25")];
        let snapshot = build_samples_snapshot(&snapshot("host_metrics", vec![sample_target]));
        let lines = build_vm_metric_lines(&snapshot, "agent-1");
        let line = lines
            .iter()
            .find(|line| line.metric.name == "system_load_average_1m")
            .expect("load line");
        let json = serde_json::to_value(line).expect("serialize line");

        assert_eq!(
            json["metric"],
            serde_json::json!({
                "__name__": "system_load_average_1m",
                "agent": "agent-1",
                "instance": "host-1",
            })
        );
        assert!(json.get("unit").is_none());
    }

    #[test]
    fn selection_labels_are_plain_labels_on_every_line() {
        let mut sample_target = target("succeeded", "host-1");
        sample_target.runtime_facts = vec![StringKeyValue::new("host.loadavg.1m", "0.25")];
        let snapshot = build_samples_snapshot(&snapshot("host_metrics", vec![sample_target]));
        let selection = BTreeMap::from([
            ("app".to_string(), "kafka".to_string()),
            ("env".to_string(), "prod".to_string()),
            ("cluster".to_string(), "kafka-prod".to_string()),
        ]);

        let lines = build_vm_metric_lines_with(&snapshot, "agent-1", &selection);
        let json = serde_json::to_value(&lines[0]).expect("serialize line");

        assert_eq!(json["metric"]["app"], "kafka");
        assert_eq!(json["metric"]["env"], "prod");
        assert_eq!(json["metric"]["cluster"], "kafka-prod");
        // 选择类 label 不是身份的一部分：`instance` 仍是目标身份。
        assert_eq!(json["metric"]["instance"], "host-1");
    }

    #[test]
    fn batch_seq_is_monotonic_across_snapshots() {
        let first = build_samples_snapshot(&snapshot("host_metrics", Vec::new()));
        let second = build_samples_snapshot(&snapshot("host_metrics", Vec::new()));
        assert!(
            second.batch_seq > first.batch_seq,
            "batch_seq must increase: {} -> {}",
            first.batch_seq,
            second.batch_seq
        );
    }

    #[test]
    fn vm_lines_skip_non_numeric_samples() {
        let snapshot = MetricsSamplesSnapshot {
            batch_seq: 1,
            collected_at: "2026-04-19T00:00:00Z".to_string(),
            groups: vec![MetricsSampleGroup {
                instance: "host-1".to_string(),
                samples: vec![MetricsSampleRecord {
                    name: "process_state".to_string(),
                    value: serde_json::json!("running"),
                    value_type: "gauge_string".to_string(),
                    const_labels: Vec::new(),
                    labels: Vec::new(),
                }],
            }],
        };
        assert!(build_vm_metric_lines(&snapshot, "agent-1").is_empty());
    }
}
