//! 每个采集面的**采集结果**（本机观测）：到底采成没采成。
//!
//! 为什么单独一份：`AgentLocalStandingWork` 的 `status` / `acknowledged_version` / `tasks`
//! 只说「工作收到没、准备采哪些文件」，都是**期望**侧的事实。文件不存在、权限不够、
//! 导出器没装、指标目标全部失败，都不改变它们 —— 管理面于是看到一张“看起来正常”的卡。
//! 这里把本 tick 的失败面折算成每个面的结论，随状态上报带给网关。
//!
//! 诚实性边界（与 `telemetry::logs::gate::Withheld` / `UplinkHealth` 同一取向）：
//!   * `ok` 只代表**没观测到失败**，不代表这 tick 有新数据 —— 安静的日志文件是正常态；
//!   * 没有可判定观测时给 `unknown`，不臆造健康；
//!   * 被暂停 / 输出关闸给 `paused`，不报成失败。
//!
//! 覆盖面：日志文件任务、导出器运行、指标采集域，以及签发时就折算不了的单元
//! （`unsupported`）和工作参数解析失败。只做**汇总**，不替代 gateway 侧的就绪度判断。

use std::collections::{BTreeMap, BTreeSet};

use wist_contracts::local_work::{
    AgentLocalCollection, CollectionReason, collection_prerequisites, collection_reason_kind,
    collection_result, collection_status,
};
use wist_metrics::provider::MetricsCollectionOutcome;

use super::metrics_support::MetricsTick;
use super::telemetry_support::{
    ExporterFailure, ExporterFailureKind, ExporterReport, TelemetryFailure, TelemetryFailureKind,
    TelemetryTick,
};
use crate::control::work::{AppliedWorkGrant, UnsupportedUnit, WorkExporterRun};
use crate::state_store::work::StandingWorkRecord;

/// 每个常驻工作（采集面）最近一轮的采集结果。
#[derive(Debug, Clone, Default)]
pub(super) struct CollectionHealth {
    entries: BTreeMap<String, AgentLocalCollection>,
    /// 导出器失败跨 tick 记忆（`input_id` → 失败）：下一次**成功运行**才清。
    ///
    /// 为什么需要：导出器是周期任务（如 60s），失败后中间每个 tick 都没有新证据 ——
    /// 只看当前 tick 会把 59 秒内的状态错报成 `ok`。
    exporter_failures: BTreeMap<String, ExporterFailure>,
}

impl CollectionHealth {
    /// 某个面的采集结果；`None` = 还没有观测（旧版 seq=0 / 尚未跑过一轮）。
    pub(super) fn get(&self, work_id: &str) -> Option<&AgentLocalCollection> {
        self.entries.get(work_id)
    }

    #[cfg(test)]
    pub(super) fn insert_for_test(&mut self, work_id: &str, collection: AgentLocalCollection) {
        self.entries.insert(work_id.to_string(), collection);
    }

    /// 用本 tick 的证据重算所有面的结论。
    ///
    /// 每 tick 全量重算而不是增量累积：状态要能**恢复**（上一轮失败、这一轮好了就该回到
    /// `ok`），增量记账很容易忘了清。
    pub(super) fn observe(
        &mut self,
        work: &AppliedWorkGrant,
        telemetry: &TelemetryTick,
        metrics: &MetricsTick,
        exporter_report: &ExporterReport,
        uplink_enabled: bool,
        now: &str,
    ) {
        let Some(view) = work.device_view(now) else {
            self.entries.clear();
            self.exporter_failures.clear();
            return;
        };
        let spec_failures: BTreeMap<String, String> = work.spec_failures().into_iter().collect();
        let unsupported = work.unsupported_units();
        let exporters = work.exporter_runs();
        // 导出器失败按「下次成功运行」清，不按 tick 清（见字段说明）。
        for failure in &exporter_report.failures {
            self.exporter_failures
                .insert(failure.input_id.clone(), failure.clone());
        }
        for input_id in &exporter_report.succeeded {
            self.exporter_failures.remove(input_id);
        }
        let active_inputs: BTreeSet<&str> =
            exporters.iter().map(|run| run.input_id.as_str()).collect();
        self.exporter_failures
            .retain(|input_id, _| active_inputs.contains(input_id.as_str()));
        let effective_exporter_failures: Vec<ExporterFailure> =
            self.exporter_failures.values().cloned().collect();
        let outcomes = metrics
            .snapshot
            .as_ref()
            .map(|snapshot| snapshot.outcomes.as_slice())
            .unwrap_or(&[]);
        // spool 暂停只走 notifications（工作状态），不进 failures —— 但它确实意味着
        // 「这条输入现在没在读」。合成一条 ProcessingFailed 证据，否则健康面会错报 ok。
        let mut failures = telemetry.failures.clone();
        for notification in &telemetry.notifications {
            if notification.state == super::telemetry_support::WorkState::Paused {
                failures.push(TelemetryFailure {
                    kind: TelemetryFailureKind::ProcessingFailed,
                    input_id: notification.input_id.clone(),
                    path: "-".to_string(),
                    detail: notification.reason.clone(),
                    magnitude: None,
                });
            }
        }
        let mut entries = BTreeMap::new();
        for standing in &view.standing {
            entries.insert(
                standing.work_id.clone(),
                assess(
                    standing,
                    spec_failures.get(&standing.work_id).map(String::as_str),
                    &unsupported,
                    &exporters,
                    &effective_exporter_failures,
                    &failures,
                    &metrics.failures,
                    outcomes,
                    uplink_enabled,
                    now,
                ),
            );
        }
        self.entries = entries;
    }
}

/// 失败的严重度。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Severity {
    /// 不是故障，或只是配置的正常结果（噪音行 / 选源过滤）。
    Ignore,
    /// 采到了，但少了一部分（截断 / 挡下 / 容量触顶）。
    Warn,
    /// 这一项**没有采成**。
    Hard,
}

fn severity(kind: &TelemetryFailureKind) -> Severity {
    match kind {
        TelemetryFailureKind::NoiseDropped | TelemetryFailureKind::SelectionFiltered => {
            Severity::Ignore
        }
        TelemetryFailureKind::RecordWithheld
        | TelemetryFailureKind::TruncatedLine
        | TelemetryFailureKind::CapacityExceeded
        | TelemetryFailureKind::HeadlessLinesDropped => Severity::Warn,
        TelemetryFailureKind::MissingInput
        | TelemetryFailureKind::ProcessingFailed
        | TelemetryFailureKind::InvalidOutput
        | TelemetryFailureKind::OutputWriteFailed => Severity::Hard,
    }
}

/// 面 → 指标采集域。命名空间跟着源系统，不跟着面：一个面可能覆盖多个域。
fn metric_domains(family: &str) -> &'static [&'static str] {
    match family {
        "HostMetrics" => &["host_metrics", "process_metrics", "container_metrics"],
        "DatabaseMetrics" => &["pg_metrics", "mysql_metrics", "doris_metrics"],
        "MessageQueueMetrics" => &["kafka_broker_metrics"],
        _ => &[],
    }
}

#[allow(clippy::too_many_arguments)]
fn assess(
    standing: &StandingWorkRecord,
    spec_failure: Option<&str>,
    unsupported: &[UnsupportedUnit],
    exporters: &[WorkExporterRun],
    exporter_failures: &[ExporterFailure],
    telemetry_failures: &[TelemetryFailure],
    metrics_failures: &[super::metrics_support::MetricsFailure],
    metric_outcomes: &[MetricsCollectionOutcome],
    uplink_enabled: bool,
    now: &str,
) -> AgentLocalCollection {
    // 关闸与暂停都不是失败：本就不该采，报成故障只会制造噪音。
    if !uplink_enabled {
        return build_collection(
            collection_prerequisites::READY,
            collection_result::CANCELLED,
            vec![reason(
                collection_reason_kind::STANDBY,
                "",
                "数据面上送已关闸（待命）：本机未采集",
            )],
            now,
        );
    }
    if standing.status != "active" {
        return build_collection(
            collection_prerequisites::READY,
            collection_result::CANCELLED,
            vec![reason(
                collection_reason_kind::PAUSED,
                "",
                "工作已暂停（不是采集失败）",
            )],
            now,
        );
    }
    if let Some(detail) = spec_failure {
        return build_collection(
            collection_prerequisites::READY,
            collection_result::FAILURE,
            vec![reason(
                collection_reason_kind::INVALID_SPEC,
                "",
                format!("工作参数无法解析：{detail}"),
            )],
            now,
        );
    }
    // active 但零单元：网关不会下发这种工作；能走到这里通常是恢复时参数丢了/被改坏。
    if standing.units.is_empty() {
        return build_collection(
            collection_prerequisites::READY,
            collection_result::FAILURE,
            vec![reason(
                collection_reason_kind::NO_UNITS,
                "",
                "工作没有可执行单元（参数为空或解析失败）",
            )],
            now,
        );
    }

    let unsupported: Vec<&UnsupportedUnit> = unsupported
        .iter()
        .filter(|unit| unit.work_id == standing.work_id)
        .collect();
    let runs: Vec<&WorkExporterRun> = exporters
        .iter()
        .filter(|run| run.work_id == standing.work_id)
        .collect();

    let task_ids: BTreeSet<&str> = standing
        .tasks
        .iter()
        .map(|task| task.input_id.as_str())
        .collect();

    let mut reasons: Vec<CollectionReason> = Vec::new();
    let mut hard_inputs: BTreeSet<&str> = BTreeSet::new();
    let mut hard = 0usize;
    let mut soft = 0usize;
    let mut blocked_tool = 0usize;
    let mut blocked_input = 0usize;

    for failure in telemetry_failures {
        if !task_ids.contains(failure.input_id.as_str()) {
            continue;
        }
        let reason = reason(
            reason_kind_for_telemetry(&failure.kind),
            failure.path.clone(),
            failure.detail.clone(),
        );
        match severity(&failure.kind) {
            Severity::Ignore => {}
            Severity::Warn => {
                soft += 1;
                push_reason(&mut reasons, reason);
            }
            Severity::Hard => {
                hard_inputs.insert(failure.input_id.as_str());
                push_reason(&mut reasons, reason);
            }
        }
    }

    // 签发时就折算不了的单元：不是本 tick 的偶发，但同样意味着「这个面采不全」。
    for unit in &unsupported {
        hard += 1;
        push_reason(
            &mut reasons,
            reason(
                collection_reason_kind::UNSUPPORTED,
                unit.unit_id.clone(),
                unit.detail.clone(),
            ),
        );
    }

    // 导出器：失败按运行记（同一个导出器可能被多个单元各跑一份）。
    //
    // 关键区分：**缺工具是前置条件，不是采集错误**。报成 hard failure 会让一个只含
    // 导出器的工作整面变 `failed`（页面红）；这里只当警告 —— 有其它健康的采集内容就
    // `degraded`，没有就 `unknown`（「还采不成」），装上工具后自动回到 `ok`。
    let mut exporter_failed_ids: BTreeSet<&str> = BTreeSet::new();
    let mut exporter_blocked_ids: BTreeSet<&str> = BTreeSet::new();
    for failure in exporter_failures
        .iter()
        .filter(|failure| failure.work_id == standing.work_id)
    {
        match failure.kind {
            ExporterFailureKind::Precondition => {
                exporter_blocked_ids.insert(failure.input_id.as_str());
                blocked_tool += 1;
                push_reason(
                    &mut reasons,
                    reason(
                        collection_reason_kind::MISSING_TOOL,
                        failure.exporter_id.clone(),
                        failure.detail.clone(),
                    ),
                );
            }
            ExporterFailureKind::Run => {
                exporter_failed_ids.insert(failure.input_id.as_str());
                hard += 1;
                push_reason(
                    &mut reasons,
                    reason(
                        collection_reason_kind::RUN_FAILED,
                        failure.exporter_id.clone(),
                        failure.detail.clone(),
                    ),
                );
            }
        }
    }
    let exporter_healthy = runs
        .len()
        .saturating_sub(exporter_failed_ids.len() + exporter_blocked_ids.len());

    // 指标：只看这个面真有的域；快照里没有的域 = 没授权（不是「未知」）。
    let has_metrics_units = standing
        .units
        .iter()
        .any(|unit| unit.capability == "collect_metrics");
    let mut metric_healthy = 0usize;
    if has_metrics_units {
        // tick 级失败（目标视图读不到 / 快照落盘失败）不是“采集失败”：快照可能还在用缓存，
        // 指标也可能已经发出去了 —— 只算软问题。
        for failure in metrics_failures {
            soft += 1;
            push_reason(
                &mut reasons,
                reason(
                    collection_reason_kind::RUN_FAILED,
                    failure.phase.clone(),
                    failure.detail.clone(),
                ),
            );
        }
        for domain in metric_domains(&standing.family) {
            let Some(outcome) = metric_outcomes
                .iter()
                .find(|outcome| outcome.collection_kind == *domain)
            else {
                continue;
            };
            match outcome.status.as_str() {
                "succeeded" => metric_healthy += 1,
                "partial" => {
                    // 部分目标成功：算“有内容在采”，但带上软问题。
                    metric_healthy += 1;
                    soft += 1;
                    push_reason(
                        &mut reasons,
                        reason(
                            collection_reason_kind::METRIC_PARTIAL,
                            *domain,
                            format!(
                                "{} 个目标失败（{} 个成功）",
                                outcome.failed_targets, outcome.succeeded_targets
                            ),
                        ),
                    );
                }
                "failed" => {
                    hard += 1;
                    push_reason(
                        &mut reasons,
                        reason(
                            collection_reason_kind::RUN_FAILED,
                            *domain,
                            outcome
                                .last_error
                                .clone()
                                .unwrap_or_else(|| "全部目标采集失败".to_string()),
                        ),
                    );
                }
                // pending / idle：授权了但还没有可判定的一轮 —— 目标/来源未就绪。
                _ => {
                    blocked_input += 1;
                    push_reason(
                        &mut reasons,
                        reason(
                            collection_reason_kind::TARGET_NOT_READY,
                            *domain,
                            "已授权，尚未观测到采集结果（首轮未完成 / 目标未就绪）",
                        ),
                    );
                }
            }
        }
    }
    let task_hard = hard_inputs.len();
    hard += task_hard;
    let task_healthy = task_ids.len().saturating_sub(task_hard);
    let healthy = task_healthy + exporter_healthy + metric_healthy;
    let has_content = !task_ids.is_empty() || !runs.is_empty() || has_metrics_units;
    let has_unsupported = !unsupported.is_empty();

    if !has_content && !has_unsupported {
        push_reason(
            &mut reasons,
            reason(
                collection_reason_kind::NO_CONTENT,
                "",
                "这份授权里没有可执行的采集内容",
            ),
        );
        return build_collection(
            collection_prerequisites::READY,
            collection_result::PENDING,
            reasons,
            now,
        );
    }

    let prerequisites = if blocked_tool + blocked_input > 0 {
        collection_prerequisites::BLOCKED
    } else {
        collection_prerequisites::READY
    };
    let result = if hard > 0 {
        if healthy > 0 {
            collection_result::PARTIAL
        } else {
            collection_result::FAILURE
        }
    } else if blocked_tool > 0 {
        // 缺工具：没执行。没有其它内容就是取消，不是失败。
        if healthy > 0 {
            collection_result::PARTIAL
        } else {
            collection_result::CANCELLED
        }
    } else if blocked_input > 0 {
        // 目标/来源未就绪：还没有可判定的观测。
        if healthy > 0 {
            collection_result::PARTIAL
        } else {
            collection_result::PENDING
        }
    } else if soft > 0 {
        if healthy > 0 {
            collection_result::PARTIAL
        } else {
            // 只有软问题、也没有任何健康信号：不冒充失败。
            collection_result::PENDING
        }
    } else if healthy > 0 {
        collection_result::SUCCESS
    } else {
        collection_result::PENDING
    };

    build_collection(prerequisites, result, reasons, now)
}

/// 结构化原因上限：报告要小，页面扫一眼；完整原因在 agent 日志里。
const MAX_REASON_ITEMS: usize = 5;

/// 旧 `detail` 的上限（与旧页面一致：最多 3 条 + 省略计数）。
const MAX_DETAIL_ITEMS: usize = 3;

fn reason(kind: &str, subject: impl Into<String>, detail: impl Into<String>) -> CollectionReason {
    CollectionReason {
        kind: kind.to_string(),
        subject: subject.into(),
        detail: detail.into(),
    }
}

fn push_reason(reasons: &mut Vec<CollectionReason>, reason: CollectionReason) {
    if !reasons.iter().any(|existing| {
        existing.kind == reason.kind
            && existing.subject == reason.subject
            && existing.detail == reason.detail
    }) {
        reasons.push(reason);
    }
}

fn reason_text(reason: &CollectionReason) -> String {
    if reason.subject.is_empty() {
        reason.detail.clone()
    } else {
        format!("{}: {}", reason.subject, reason.detail)
    }
}

/// 折叠成旧 `status`（滚动升级期给旧消费方）。新消费方只看三字段。
fn legacy_status(result: &str, prerequisites: &str) -> &'static str {
    match result {
        collection_result::SUCCESS => collection_status::OK,
        collection_result::PARTIAL => collection_status::DEGRADED,
        collection_result::FAILURE => collection_status::FAILED,
        // 前置条件缺失不是“人为暂停”：旧页面没有对应值，用 unknown 更中性。
        collection_result::CANCELLED if prerequisites == collection_prerequisites::BLOCKED => {
            collection_status::UNKNOWN
        }
        collection_result::CANCELLED => collection_status::PAUSED,
        _ => collection_status::UNKNOWN,
    }
}

fn legacy_detail(reasons: &[CollectionReason]) -> String {
    let mut items: Vec<String> = reasons.iter().map(reason_text).collect();
    if items.len() > MAX_DETAIL_ITEMS {
        let extra = items.len() - MAX_DETAIL_ITEMS;
        items.truncate(MAX_DETAIL_ITEMS);
        items.push(format!("等 {extra} 项"));
    }
    items.join("；")
}

fn build_collection(
    prerequisites: &str,
    result: &str,
    mut reasons: Vec<CollectionReason>,
    now: &str,
) -> AgentLocalCollection {
    let detail = legacy_detail(&reasons);
    reasons.truncate(MAX_REASON_ITEMS);
    AgentLocalCollection {
        prerequisites: prerequisites.to_string(),
        result: result.to_string(),
        reasons,
        observed_at: now.to_string(),
        status: legacy_status(result, prerequisites).to_string(),
        detail,
    }
}

fn reason_kind_for_telemetry(kind: &TelemetryFailureKind) -> &'static str {
    use TelemetryFailureKind::*;
    match kind {
        MissingInput => collection_reason_kind::MISSING_INPUT,
        ProcessingFailed | InvalidOutput | OutputWriteFailed => collection_reason_kind::RUN_FAILED,
        TruncatedLine => collection_reason_kind::TRUNCATED,
        RecordWithheld | CapacityExceeded | HeadlessLinesDropped => {
            collection_reason_kind::INCOMPLETE_DATA
        }
        // Ignore 类不会走到这里（调用方先按 severity 过滤）。
        NoiseDropped | SelectionFiltered => "",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::control::work::UnsupportedUnit;
    use crate::state_store::work::{StandingWorkRecord, WorkTaskRecord};
    use wist_contracts::work::WorkSpecUnit;

    fn task(input_id: &str, path: &str) -> WorkTaskRecord {
        WorkTaskRecord {
            input_id: input_id.to_string(),
            path: path.to_string(),
            startup_position: "tail".to_string(),
        }
    }

    fn standing(tasks: Vec<WorkTaskRecord>) -> StandingWorkRecord {
        StandingWorkRecord {
            work_id: "work-1".to_string(),
            family: "LoginSession".to_string(),
            status: "active".to_string(),
            plan_version: 1,
            acknowledged_version: Some(1),
            effective_from: "2026-11-08T00:00:00Z".to_string(),
            // 真实工作总是带单元；任务是由单元折算出来的。需要零单元的用例自己清空。
            units: vec![WorkSpecUnit {
                unit_id: "unit-1".to_string(),
                capability: "collect_logs".to_string(),
                rule_ref: "r".to_string(),
                requires_privilege: "none".to_string(),
                sources: Vec::new(),
            }],
            tasks,
        }
    }

    fn failure(
        kind: TelemetryFailureKind,
        input_id: &str,
        path: &str,
        detail: &str,
    ) -> TelemetryFailure {
        TelemetryFailure {
            kind,
            input_id: input_id.to_string(),
            path: path.to_string(),
            detail: detail.to_string(),
            magnitude: None,
        }
    }

    fn assess_simple(
        standing: &StandingWorkRecord,
        failures: &[TelemetryFailure],
    ) -> AgentLocalCollection {
        assess(
            standing,
            None,
            &[],
            &[],
            &[],
            failures,
            &[],
            &[],
            true,
            "2026-11-08T00:00:00Z",
        )
    }

    fn quiet_metrics() -> MetricsTick {
        MetricsTick {
            snapshot: None,
            failures: Vec::new(),
            target_view_loaded: false,
            used_cached_snapshot: false,
        }
    }

    fn exporter_grant() -> AppliedWorkGrant {
        AppliedWorkGrant::restore(&exporter_record())
    }

    fn exporter_record() -> crate::state_store::work::WorkRecord {
        use wist_contracts::work::WorkSpecSource;
        crate::state_store::work::WorkRecord {
            schema_version: crate::state_store::work::SCHEMA_VERSION_V1.to_string(),
            recorded_at: "2026-11-08T00:00:00Z".to_string(),
            gateway_sequence: 1,
            standing: vec![StandingWorkRecord {
                work_id: "work-x".to_string(),
                family: "StorageHealth".to_string(),
                status: "active".to_string(),
                plan_version: 1,
                acknowledged_version: Some(1),
                effective_from: "2026-11-08T00:00:00Z".to_string(),
                units: vec![WorkSpecUnit {
                    unit_id: "smart".to_string(),
                    capability: "collect_logs".to_string(),
                    rule_ref: "r".to_string(),
                    requires_privilege: "root".to_string(),
                    sources: vec![WorkSpecSource {
                        kind: "Exporter".to_string(),
                        target: "smartctl".to_string(),
                        multiline: "none".to_string(),
                        exclude_globs: Vec::new(),
                        filters: Default::default(),
                        drop_if_contains: Vec::new(),
                    }],
                }],
                tasks: Vec::new(),
            }],
            one_shot: Vec::new(),
            metrics_interval_seconds: None,
        }
    }

    /// 同一份授权里既有缺工具的导出器，也有正常的日志采集单元。
    fn exporter_grant_with_healthy_task() -> AppliedWorkGrant {
        use wist_contracts::work::WorkSpecSource;
        let mut record = exporter_record();
        record.standing[0].units.push(WorkSpecUnit {
            unit_id: "auth".to_string(),
            capability: "collect_logs".to_string(),
            rule_ref: "r".to_string(),
            requires_privilege: "root".to_string(),
            sources: vec![WorkSpecSource {
                kind: "FileGlob".to_string(),
                target: "/var/log/auth.log".to_string(),
                multiline: "none".to_string(),
                exclude_globs: Vec::new(),
                filters: Default::default(),
                drop_if_contains: Vec::new(),
            }],
        });
        AppliedWorkGrant::restore(&record)
    }

    fn log_grant() -> AppliedWorkGrant {
        use wist_contracts::work::WorkSpecSource;
        let record = crate::state_store::work::WorkRecord {
            schema_version: crate::state_store::work::SCHEMA_VERSION_V1.to_string(),
            recorded_at: "2026-11-08T00:00:00Z".to_string(),
            gateway_sequence: 1,
            standing: vec![StandingWorkRecord {
                work_id: "work-l".to_string(),
                family: "LoginSession".to_string(),
                status: "active".to_string(),
                plan_version: 1,
                acknowledged_version: Some(1),
                effective_from: "2026-11-08T00:00:00Z".to_string(),
                units: vec![WorkSpecUnit {
                    unit_id: "auth".to_string(),
                    capability: "collect_logs".to_string(),
                    rule_ref: "r".to_string(),
                    requires_privilege: "root".to_string(),
                    sources: vec![WorkSpecSource {
                        kind: "FileGlob".to_string(),
                        target: "/var/log/auth.log".to_string(),
                        multiline: "none".to_string(),
                        exclude_globs: Vec::new(),
                        filters: Default::default(),
                        drop_if_contains: Vec::new(),
                    }],
                }],
                tasks: Vec::new(),
            }],
            one_shot: Vec::new(),
            metrics_interval_seconds: None,
        };
        AppliedWorkGrant::restore(&record)
    }

    fn metrics_work(family: &str) -> StandingWorkRecord {
        let mut work = standing(Vec::new());
        work.family = family.to_string();
        work.units = vec![WorkSpecUnit {
            unit_id: "metrics".to_string(),
            capability: "collect_metrics".to_string(),
            rule_ref: String::new(),
            requires_privilege: "root".to_string(),
            sources: Vec::new(),
        }];
        work
    }

    fn outcome(
        kind: &str,
        status: &str,
        attempted: usize,
        succeeded: usize,
        failed: usize,
        last_error: Option<&str>,
    ) -> MetricsCollectionOutcome {
        MetricsCollectionOutcome {
            collection_kind: kind.to_string(),
            status: status.to_string(),
            attempted_targets: attempted,
            succeeded_targets: succeeded,
            failed_targets: failed,
            dropped_targets: 0,
            last_error: last_error.map(str::to_string),
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        }
    }

    #[test]
    fn a_quiet_file_with_no_failure_is_ok() {
        let result = assess_simple(&standing(vec![task("a", "/var/log/a.log")]), &[]);
        assert_eq!(result.status, collection_status::OK);
        assert!(result.detail.is_empty());
        assert_eq!(result.prerequisites, collection_prerequisites::READY);
        assert_eq!(result.result, collection_result::SUCCESS);
    }

    #[test]
    fn one_missing_file_out_of_two_is_degraded() {
        let result = assess_simple(
            &standing(vec![
                task("a", "/var/log/a.log"),
                task("b", "/var/log/b.log"),
            ]),
            &[failure(
                TelemetryFailureKind::MissingInput,
                "b",
                "/var/log/b.log",
                "source path does not exist",
            )],
        );
        assert_eq!(result.status, collection_status::DEGRADED);
        assert_eq!(result.prerequisites, collection_prerequisites::READY);
        assert_eq!(result.result, collection_result::PARTIAL);
        assert!(
            result.reasons.iter().any(|reason| reason.kind
                == collection_reason_kind::MISSING_INPUT
                && reason.subject == "/var/log/b.log"),
            "{:?}",
            result.reasons
        );
        assert!(
            result.detail.contains("/var/log/b.log"),
            "{}",
            result.detail
        );
    }

    #[test]
    fn every_task_missing_is_failed() {
        let result = assess_simple(
            &standing(vec![task("a", "/var/log/a.log")]),
            &[failure(
                TelemetryFailureKind::MissingInput,
                "a",
                "/var/log/a.log",
                "source path does not exist",
            )],
        );
        assert_eq!(result.status, collection_status::FAILED);
        assert_eq!(result.prerequisites, collection_prerequisites::READY);
        assert_eq!(result.result, collection_result::FAILURE);
    }

    #[test]
    fn noise_and_selection_filters_do_not_count_as_failures() {
        let result = assess_simple(
            &standing(vec![task("a", "/var/log/a.log")]),
            &[
                failure(
                    TelemetryFailureKind::NoiseDropped,
                    "a",
                    "/var/log/a.log",
                    "drop_if_contains matched",
                ),
                failure(
                    TelemetryFailureKind::SelectionFiltered,
                    "a",
                    "/var/log/a.log",
                    "filters excluded files",
                ),
            ],
        );
        assert_eq!(result.status, collection_status::OK);
    }

    #[test]
    fn a_soft_problem_alone_does_not_fake_success() {
        let result = assess_simple(
            &standing(vec![task("a", "/var/log/a.log")]),
            &[failure(
                TelemetryFailureKind::TruncatedLine,
                "a",
                "/var/log/a.log",
                "line exceeded max_line_bytes; submitted truncated",
            )],
        );
        assert_eq!(result.status, collection_status::DEGRADED);
        assert_eq!(result.result, collection_result::PARTIAL);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.kind == collection_reason_kind::TRUNCATED),
            "{:?}",
            result.reasons
        );
        assert!(result.detail.contains("truncated"), "{}", result.detail);
    }

    #[test]
    fn standby_is_paused_not_failed() {
        let result = assess(
            &standing(vec![task("a", "/var/log/a.log")]),
            None,
            &[],
            &[],
            &[],
            &[failure(
                TelemetryFailureKind::MissingInput,
                "a",
                "/var/log/a.log",
                "source path does not exist",
            )],
            &[],
            &[],
            false,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::PAUSED);
        assert_eq!(result.prerequisites, collection_prerequisites::READY);
        assert_eq!(result.result, collection_result::CANCELLED);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.kind == collection_reason_kind::STANDBY),
            "{:?}",
            result.reasons
        );
    }

    #[test]
    fn a_paused_work_is_paused_not_failed() {
        let mut work = standing(vec![task("a", "/var/log/a.log")]);
        work.status = "paused".to_string();
        let result = assess_simple(&work, &[]);
        assert_eq!(result.status, collection_status::PAUSED);
        assert_eq!(result.result, collection_result::CANCELLED);
        assert!(
            result
                .reasons
                .iter()
                .any(|reason| reason.kind == collection_reason_kind::PAUSED),
            "{:?}",
            result.reasons
        );
    }

    #[test]
    fn unsupported_units_make_an_otherwise_healthy_family_degraded() {
        let result = assess(
            &standing(vec![task("a", "/var/log/a.log")]),
            None,
            &[UnsupportedUnit {
                work_id: "work-1".to_string(),
                unit_id: "unit-2".to_string(),
                detail: "UnifiedLogPredicate is not supported".to_string(),
            }],
            &[],
            &[],
            &[],
            &[],
            &[],
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::DEGRADED);
        assert!(result.detail.contains("unit-2"), "{}", result.detail);
    }

    #[test]
    fn a_metrics_family_with_no_targets_is_unknown() {
        let mut work = standing(Vec::new());
        work.family = "DatabaseMetrics".to_string();
        work.units = vec![WorkSpecUnit {
            unit_id: "db".to_string(),
            capability: "collect_metrics".to_string(),
            rule_ref: String::new(),
            requires_privilege: "root".to_string(),
            sources: Vec::new(),
        }];
        let outcome = MetricsCollectionOutcome {
            collection_kind: "mysql_metrics".to_string(),
            status: "pending".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            dropped_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        };
        let result = assess(
            &work,
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[outcome],
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::UNKNOWN);
        assert_eq!(result.prerequisites, collection_prerequisites::BLOCKED);
        assert_eq!(result.result, collection_result::PENDING);
        assert!(
            result.reasons.iter().any(|reason| reason.kind
                == collection_reason_kind::TARGET_NOT_READY
                && reason.subject == "mysql_metrics"),
            "{:?}",
            result.reasons
        );
    }

    #[test]
    fn a_failed_metrics_domain_is_failed() {
        let mut work = standing(Vec::new());
        work.family = "MessageQueueMetrics".to_string();
        work.units = vec![WorkSpecUnit {
            unit_id: "kafka".to_string(),
            capability: "collect_metrics".to_string(),
            rule_ref: String::new(),
            requires_privilege: "root".to_string(),
            sources: Vec::new(),
        }];
        let outcome = MetricsCollectionOutcome {
            collection_kind: "kafka_broker_metrics".to_string(),
            status: "failed".to_string(),
            attempted_targets: 1,
            succeeded_targets: 0,
            failed_targets: 1,
            dropped_targets: 0,
            last_error: Some("connection refused".to_string()),
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        };
        let result = assess(
            &work,
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
            &[outcome],
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::FAILED);
        assert!(
            result.detail.contains("connection refused"),
            "{}",
            result.detail
        );
    }

    #[test]
    fn a_spec_failure_is_failed() {
        let result = assess(
            &standing(vec![task("a", "/var/log/a.log")]),
            Some("work spec is not json"),
            &[],
            &[],
            &[],
            &[],
            &[],
            &[],
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::FAILED);
        assert!(
            result.detail.contains("work spec is not json"),
            "{}",
            result.detail
        );
    }

    #[test]
    fn an_active_work_without_units_is_failed() {
        let mut work = standing(Vec::new());
        work.units.clear();
        let result = assess_simple(&work, &[]);
        assert_eq!(result.status, collection_status::FAILED);
        assert!(
            result.detail.contains("没有可执行单元"),
            "{}",
            result.detail
        );
    }

    #[test]
    fn every_unit_unsupported_without_tasks_is_failed() {
        let work = standing(Vec::new());
        let result = assess(
            &work,
            None,
            &[UnsupportedUnit {
                work_id: "work-1".to_string(),
                unit_id: "u1".to_string(),
                detail: "UnifiedLogPredicate is not supported".to_string(),
            }],
            &[],
            &[],
            &[],
            &[],
            &[],
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::FAILED);
        assert!(result.detail.contains("u1"), "{}", result.detail);
    }

    #[test]
    fn failures_and_unsupported_units_from_other_works_do_not_leak() {
        let result = assess(
            &standing(vec![task("a", "/var/log/a.log")]),
            None,
            &[UnsupportedUnit {
                work_id: "work-2".to_string(),
                unit_id: "other".to_string(),
                detail: "not supported".to_string(),
            }],
            &[],
            &[],
            &[failure(
                TelemetryFailureKind::MissingInput,
                "other-input",
                "/var/log/other.log",
                "source path does not exist",
            )],
            &[],
            &[],
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::OK);
    }

    #[test]
    fn an_output_write_failure_marks_the_task_failed() {
        let result = assess_simple(
            &standing(vec![task("a", "/var/log/a.log")]),
            &[failure(
                TelemetryFailureKind::OutputWriteFailed,
                "a",
                "/var/log/a.log",
                "output write failed; records buffered to spool",
            )],
        );
        assert_eq!(result.status, collection_status::FAILED);
    }

    #[test]
    fn a_partial_metrics_domain_with_a_healthy_one_is_degraded() {
        let work = metrics_work("DatabaseMetrics");
        let outcomes = vec![
            outcome("mysql_metrics", "succeeded", 1, 1, 0, None),
            outcome("pg_metrics", "partial", 2, 1, 1, Some("role missing")),
        ];
        let result = assess(
            &work,
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
            &outcomes,
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::DEGRADED);
        assert!(result.detail.contains("pg_metrics"), "{}", result.detail);
    }

    #[test]
    fn a_lone_partial_metrics_domain_is_still_degraded() {
        // 部分目标成功 = 有内容在采：不能因为“不是全部成功”就报 unknown。
        let work = metrics_work("DatabaseMetrics");
        let outcomes = vec![outcome(
            "mysql_metrics",
            "partial",
            2,
            1,
            1,
            Some("role missing"),
        )];
        let result = assess(
            &work,
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
            &outcomes,
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::DEGRADED);
        assert!(result.detail.contains("pg_metrics") || result.detail.contains("mysql_metrics"));
    }

    #[test]
    fn an_unauthorized_metric_domain_is_not_counted_as_unknown() {
        // 只有 MySQL 被授权：快照里没有 pg/doris 是正常的，不能因此把整个面报成 unknown。
        let work = metrics_work("DatabaseMetrics");
        let outcomes = vec![outcome("mysql_metrics", "succeeded", 1, 1, 0, None)];
        let result = assess(
            &work,
            None,
            &[],
            &[],
            &[],
            &[],
            &[],
            &outcomes,
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(result.status, collection_status::OK);
    }

    #[test]
    fn a_metrics_tick_failure_without_any_outcome_stays_unknown() {
        use super::super::metrics_support::{MetricsFailure, MetricsFailureKind};
        let work = metrics_work("DatabaseMetrics");
        let failures = vec![MetricsFailure {
            kind: MetricsFailureKind::TargetViewLoad,
            phase: "target_view_load".to_string(),
            collection: "-".to_string(),
            target: "-".to_string(),
            status: String::new(),
            path: "/tmp/target_view.json".to_string(),
            detail: "no such file".to_string(),
        }];
        let result = assess(
            &work,
            None,
            &[],
            &[],
            &[],
            &[],
            &failures,
            &[],
            true,
            "2026-11-08T00:00:00Z",
        );
        // 没有成功证据：不冒充 failed，也不冒充 ok —— 给出原因。
        assert_eq!(result.status, collection_status::UNKNOWN);
        assert!(
            result.detail.contains("target_view_load"),
            "{}",
            result.detail
        );
    }

    /// 缺工具是**前置条件**，不是错误：只含导出器的工作不得报 failed。
    #[test]
    fn a_missing_exporter_tool_is_unknown_not_failed() {
        let work = exporter_grant();
        let run = work
            .exporter_runs()
            .into_iter()
            .next()
            .expect("exporter run");
        let mut health = CollectionHealth::default();
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport {
                failures: vec![ExporterFailure {
                    work_id: run.work_id,
                    input_id: run.input_id,
                    exporter_id: run.exporter_id,
                    kind: ExporterFailureKind::Precondition,
                    detail: "工具缺失：/usr/sbin/smartctl（装上后自动恢复）".to_string(),
                }],
                succeeded: Vec::new(),
            },
            true,
            "2026-11-08T00:00:00Z",
        );
        let entry = health.get("work-x").expect("entry");
        assert_eq!(entry.status, collection_status::UNKNOWN);
        assert_eq!(entry.prerequisites, collection_prerequisites::BLOCKED);
        assert_eq!(entry.result, collection_result::CANCELLED);
        assert!(
            entry
                .reasons
                .iter()
                .any(|reason| reason.kind == collection_reason_kind::MISSING_TOOL
                    && reason.subject == "smartctl"),
            "{:?}",
            entry.reasons
        );
        assert!(
            entry.detail.contains("工具缺失"),
            "原因必须留给页面：{}",
            entry.detail
        );
    }

    /// 缺工具但又握有其它健康采集单元：整面是「降级」（部分采到），不是取消。
    #[test]
    fn a_missing_exporter_tool_beside_healthy_content_is_partial() {
        let work = exporter_grant_with_healthy_task();
        let run = work
            .exporter_runs()
            .into_iter()
            .next()
            .expect("exporter run");
        let mut health = CollectionHealth::default();
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport {
                failures: vec![ExporterFailure {
                    work_id: run.work_id,
                    input_id: run.input_id,
                    exporter_id: run.exporter_id,
                    kind: ExporterFailureKind::Precondition,
                    detail: "工具缺失：/usr/sbin/smartctl（装上后自动恢复）".to_string(),
                }],
                succeeded: Vec::new(),
            },
            true,
            "2026-11-08T00:00:00Z",
        );
        let entry = health.get("work-x").expect("entry");
        // 前置条件不满足（工具缺失），但日志单元仍在采：结果是部分成功。
        assert_eq!(entry.prerequisites, collection_prerequisites::BLOCKED);
        assert_eq!(entry.result, collection_result::PARTIAL);
        assert_eq!(entry.status, collection_status::DEGRADED);
        assert!(
            entry
                .reasons
                .iter()
                .any(|reason| reason.kind == collection_reason_kind::MISSING_TOOL
                    && reason.subject == "smartctl"),
            "{:?}",
            entry.reasons
        );
    }

    /// 真跑失败（参数/命令/上送）仍然是硬失败：没有其它内容就该报 failed。
    #[test]
    fn an_exporter_run_failure_is_failed() {
        let work = exporter_grant();
        let run = work
            .exporter_runs()
            .into_iter()
            .next()
            .expect("exporter run");
        let mut health = CollectionHealth::default();
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport {
                failures: vec![ExporterFailure {
                    work_id: run.work_id,
                    input_id: run.input_id,
                    exporter_id: run.exporter_id,
                    kind: ExporterFailureKind::Run,
                    detail: "参数无法解析：bad arg".to_string(),
                }],
                succeeded: Vec::new(),
            },
            true,
            "2026-11-08T00:00:00Z",
        );
        let entry = health.get("work-x").expect("entry");
        assert_eq!(entry.status, collection_status::FAILED);
        assert_eq!(entry.prerequisites, collection_prerequisites::READY);
        assert_eq!(entry.result, collection_result::FAILURE);
        assert!(
            entry
                .reasons
                .iter()
                .any(|reason| reason.kind == collection_reason_kind::RUN_FAILED),
            "{:?}",
            entry.reasons
        );
    }

    #[test]
    fn an_exporter_failure_persists_until_a_successful_run() {
        let work = exporter_grant();
        let run = work
            .exporter_runs()
            .into_iter()
            .next()
            .expect("exporter run");
        let mut health = CollectionHealth::default();
        let failure = ExporterFailure {
            work_id: run.work_id.clone(),
            input_id: run.input_id.clone(),
            exporter_id: run.exporter_id.clone(),
            kind: ExporterFailureKind::Precondition,
            detail: "工具缺失：smartctl".to_string(),
        };

        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport {
                failures: vec![failure],
                succeeded: Vec::new(),
            },
            true,
            "2026-11-08T00:00:00Z",
        );
        assert_eq!(
            health.get("work-x").expect("entry").status,
            collection_status::UNKNOWN
        );

        // 导出器没到点（本轮没有新证据）：不能因为“这轮没报错”就假装好了。
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport::default(),
            true,
            "2026-11-08T00:00:03Z",
        );
        assert_eq!(
            health.get("work-x").expect("entry").status,
            collection_status::UNKNOWN
        );

        // 下一次真跑成功才清掉失败记忆。
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport {
                failures: Vec::new(),
                succeeded: vec![run.input_id.clone()],
            },
            true,
            "2026-11-08T00:00:06Z",
        );
        assert_eq!(
            health.get("work-x").expect("entry").status,
            collection_status::OK
        );
    }

    #[test]
    fn losing_the_grant_snapshot_clears_health_and_exporter_memory() {
        let work = exporter_grant();
        let run = work
            .exporter_runs()
            .into_iter()
            .next()
            .expect("exporter run");
        let mut health = CollectionHealth::default();
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport {
                failures: vec![ExporterFailure {
                    work_id: run.work_id,
                    input_id: run.input_id,
                    exporter_id: run.exporter_id,
                    kind: ExporterFailureKind::Run,
                    detail: "boom".to_string(),
                }],
                succeeded: Vec::new(),
            },
            true,
            "2026-11-08T00:00:00Z",
        );
        assert!(health.get("work-x").is_some());

        // 没有授权快照（seq=0）：不再声称任何采集结论，也不留旧失败记忆。
        health.observe(
            &AppliedWorkGrant::default(),
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport::default(),
            true,
            "2026-11-08T00:00:03Z",
        );
        assert!(health.get("work-x").is_none());
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport::default(),
            true,
            "2026-11-08T00:00:06Z",
        );
        assert_eq!(
            health.get("work-x").expect("entry").status,
            collection_status::OK,
            "清掉的失败记忆不能复活"
        );
    }

    #[test]
    fn a_spool_paused_input_is_not_reported_as_ok() {
        use super::super::telemetry_support::{TelemetryWorkState, WorkState};
        let work = log_grant();
        let input_id = work.log_inputs()[0].input.input_id.clone();
        let mut health = CollectionHealth::default();
        let paused = TelemetryTick {
            outcomes: Vec::new(),
            failures: Vec::new(),
            notifications: vec![TelemetryWorkState {
                input_id: input_id.clone(),
                state: WorkState::Paused,
                reason: "spool over limit; source read paused".to_string(),
                at: "2026-11-08T00:00:00Z".to_string(),
            }],
        };
        health.observe(
            &work,
            &paused,
            &quiet_metrics(),
            &ExporterReport::default(),
            true,
            "2026-11-08T00:00:00Z",
        );
        let entry = health.get("work-l").expect("entry");
        assert_eq!(entry.status, collection_status::FAILED);
        assert!(entry.detail.contains("spool"), "{}", entry.detail);

        // 下一轮不再暂停（但没有新数据）：应回到 ok —— 状态要能恢复。
        health.observe(
            &work,
            &TelemetryTick::silent(),
            &quiet_metrics(),
            &ExporterReport::default(),
            true,
            "2026-11-08T00:00:03Z",
        );
        assert_eq!(
            health.get("work-l").expect("entry").status,
            collection_status::OK
        );
    }
}
