//! 主机流记录（` FLOW: ` 帧）的 daemon 接线：授权 → 能力探测 → 采集器启停 → 窗口上送。
//!
//! 设计见 `docs/design/host-ebpf-flow-collection.md`。这一层只做**编排**，三条边界：
//! 1. 采不采由**工作授权**决定（`AppliedWorkGrant::flow_grants`）：撤授权就卸掉 tc filter，
//!    不留常驻采集；
//! 2. 能不能采由**本机事实**决定（`flows::probe` / `Collector::start` / 网卡选择）：
//!    采不了必须进采集状态（[`FlowReport::failures`]），**不静默** —— 那正是设计 §11 要防的
//!    「授权了、没数据、也不报错」；
//! 3. 记录的构造只有一处（`HostFlowRecord::from_window`），这里只填上下文：
//!    `host_id`/`host_name` 与 `OBSFACT` 同源（事实摘要），云侧身份一律不碰。

use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use wist_contracts::local_work::collection_reason_kind;
use wist_contracts::telemetry_record::DataFrame;
use wist_shared::time::{now_rfc3339, now_ts_ms};

use crate::control::work::AppliedWorkGrant;
use crate::state_store::flows as flows_state;
use crate::state_store::log_seq_state;
use crate::telemetry::flows::iface::{is_flow_addr, select_observed};
use crate::telemetry::flows::record::{
    HostFlowRecord, MAX_FLOWS_PER_FLUSH, PartialReason, WINDOW_SECONDS, WindowCtx, is_flushable,
    window_from_bucket,
};
use crate::telemetry::flows::support::{FlowSupport, Unavailable};
use crate::telemetry::flows::{self, Collector, WatchedIface};
use crate::telemetry::warp_parse::TelemetryRecordSink;

/// 采集器起不来之后的重试间隔。
///
/// 3s 一拍重试没有意义（权限没补上之前必然失败，只会把日志刷满），但**永不重试**也不行：
/// 现场补上 CAP 或清掉冲突的 qdisc 之后就应当自愈，而不是等有人重启 agent。
const START_RETRY: Duration = Duration::from_secs(60);

/// 网卡集合的复查间隔。热插拔 / ifindex 复用只在这个节奏上被发现。
const IFACE_RECHECK: Duration = Duration::from_secs(30);

/// 墙钟与单调时钟的偏差超过这个值就当成**跳变**（NTP 步进 / 手改时间）。
///
/// 取半个窗口：慢速纠偏（每分钟几十毫秒）碰不到它，而真正的跳变至少差一个整分。
const CLOCK_JUMP_SECS: i64 = (WINDOW_SECONDS / 2) as i64;

/// 运行态快照（`state/flows/status.json`）的落盘节流。
///
/// 稳态每 3s 一拍，每拍都写盘等于白付 fsync；但失败面变化必须**立刻**可见 ——
/// 所以「到期」或「签名变了」任一成立就写。
const STATUS_INTERVAL: Duration = Duration::from_secs(30);

/// 一条被**人为截断**的窗口：从哪个桶、哪个墙钟秒开始，以及为什么。
#[derive(Debug, Clone, Copy)]
struct WindowCut {
    bucket: u64,
    from_secs: u64,
    reason: PartialReason,
}

/// 拿旧锚点外推「这个桶在墙钟上应该是哪一秒」。饱和运算：桶倒退（时钟读数异常）不会 panic。
fn extrapolate(anchor_wall: u64, anchor_bucket: u64, bucket: u64) -> u64 {
    anchor_wall.saturating_add(
        bucket
            .saturating_sub(anchor_bucket)
            .saturating_mul(WINDOW_SECONDS),
    )
}

/// 一条流采集失败（`kind` 已映射到 `collection-status.md` 的原因闭集）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FlowFailure {
    /// `collection_reason_kind::*` 中的一项；采集健康据此决定严重度。
    pub(super) kind: &'static str,
    pub(super) subject: String,
    pub(super) detail: String,
}

impl FlowFailure {
    fn from_unavailable(reason: &Unavailable) -> Self {
        Self {
            kind: reason.reason_kind(),
            subject: reason.subject(),
            detail: reason.detail(),
        }
    }
}

/// 一拍流采集的结论（进采集健康 + 日志）。
#[derive(Debug, Default)]
pub(super) struct FlowReport {
    /// 本拍采集器是否在跑。
    pub(super) collecting: bool,
    /// 本拍 flush 出的窗口记录数（上送前）。
    pub(super) flushed: usize,
    /// 其中真的交出去的数量（上送失败时为 0）。
    pub(super) delivered: usize,
    /// 本拍有多少条记录带着 `truncated`（状态级的软问题）。
    pub(super) truncated_windows: usize,
    /// 本拍因为**批量上限**没取完（剩下的留在表里，下一拍继续）。
    pub(super) flush_capped: bool,
    /// 本拍因观测上下文丢失（网卡在窗口结束前消失）而丢掉的记录数。
    pub(super) lost_records: usize,
    /// 本拍累计的迟到丢弃：可见，但**不补发**（补发会破坏幂等键）。
    pub(super) late_dropped: u64,
    /// 硬失败：采不了 / 发不出去。一条一条进采集状态。
    pub(super) failures: Vec<FlowFailure>,
}

/// 本拍填记录所需的上下文（本机事实；`host_*` 与 `OBSFACT` 同源）。
pub(super) struct FlowHostContext<'a> {
    /// `agent_id`：既是帧信封的 `agent`，也是 `collector_instance_id` 的来源 ——
    /// 一台主机只有一个采集实例，agent 身份本身就是重启不变的稳定标识。
    pub agent_id: &'a str,
    /// 事实摘要的 `host.id`；空（事实还没产出）时退回 `agent_id`。
    pub host_id: &'a str,
    pub host_name: Option<&'a str>,
}

/// 跨 tick 的流采集运行态。
pub(super) struct FlowRuntime {
    collector: Option<Collector>,
    /// 最近一次起不来的原因：冷却期内不重试，但**每拍照报** —— 只报第一拍等于事后看不见。
    unavailable: Option<Unavailable>,
    last_start_attempt: Option<Instant>,
    last_iface_check: Option<Instant>,
    /// 正在观测的网卡（`(ifindex, name)`，升序）：集合变了就要切窗重挂。
    watched: Vec<(u32, String)>,
    /// 有一窗被**人为截断**（采集器启动 / 墙钟跳变）：那个窗口的 `window_seconds` 不足 60。
    /// `None` = 没有待处理的截断。
    cut: Option<WindowCut>,
    /// 上一拍的 `(墙钟秒, 单调桶)`：用来发现墙钟跳变（见 [`FlowRuntime::clock_jump`]）。
    anchor: Option<(u64, u64)>,
    /// 自观测计数器（累计到这次运行结束）。
    counters: flows_state::FlowCounters,
    /// 上次写状态快照的时刻 / 签名（节流用）。
    last_status_at: Option<Instant>,
    last_status_sig: Option<String>,
    /// 运行内核版本（`partial`/排障时进记录）。
    kernel: String,
    /// 上一拍的本机身份（`host_id`/`host_name` 来自事实摘要）。
    /// 停机时没有外部上下文可用，靠这份快照把在途窗口发出去。
    host: Option<HostFacts>,
    /// file 输出只提醒一次（每 3s 一行会把日志刷满）。
    warned_file_output: bool,
}

/// 本机身份快照（与 `OBSFACT` 同源）。
#[derive(Debug, Clone)]
struct HostFacts {
    agent_id: String,
    host_id: String,
    host_name: Option<String>,
}

impl FlowRuntime {
    pub(super) fn new() -> Self {
        Self {
            collector: None,
            unavailable: None,
            last_start_attempt: None,
            last_iface_check: None,
            watched: Vec::new(),
            cut: None,
            anchor: None,
            counters: flows_state::FlowCounters::default(),
            last_status_at: None,
            last_status_sig: None,
            kernel: "unknown".to_string(),
            host: None,
            warned_file_output: false,
        }
    }

    /// 跑一拍：启停采集器、flush 窗口、上送记录。
    ///
    /// **不返回错误**：流采集失败不该让整个 tick 失败（它是补充来源，不是主链路）。
    /// 失败一律进 [`FlowReport::failures`]，由采集状态如实上送。
    pub(super) async fn tick(
        &mut self,
        work: &AppliedWorkGrant,
        host: &FlowHostContext<'_>,
        sink: &mut TelemetryRecordSink,
        next_seq: &mut u64,
        state_dir: &Path,
    ) -> FlowReport {
        let global_seq_path = log_seq_state::path_for(state_dir);
        let report = self
            .run_tick(work, host, sink, next_seq, &global_seq_path)
            .await;
        self.absorb(&report);
        self.persist_status(state_dir, &report).await;
        report
    }

    /// 一拍的实际工作（不含计数与落盘：那两件事对所有退出路径都要做）。
    async fn run_tick(
        &mut self,
        work: &AppliedWorkGrant,
        host: &FlowHostContext<'_>,
        sink: &mut TelemetryRecordSink,
        next_seq: &mut u64,
        global_seq_path: &Path,
    ) -> FlowReport {
        let mut report = FlowReport::default();
        // 记住这一拍的本机身份：停机时没有外部上下文，要靠它把在途窗口发出去。
        self.host = Some(HostFacts {
            agent_id: host.agent_id.to_string(),
            host_id: if host.host_id.is_empty() {
                host.agent_id.to_string()
            } else {
                host.host_id.to_string()
            },
            host_name: host.host_name.map(str::to_string),
        });
        if work.flow_grants().is_empty() {
            // 撤授权 / 工作暂停：授权期内采到的在途窗口照发（标 `partial=paused`），再卸 filter。
            self.stop(
                PartialReason::Paused,
                host,
                sink,
                next_seq,
                global_seq_path,
                &mut report,
            )
            .await;
            return report;
        }
        if !sink.carries_flow_frames() {
            // 本地 file 输出只承载日志：采了也没处送。不采（省掉整条 BPF 路径），
            // 但**必须让采集面看得见** —— 否则就是「授权了、没数据、也不报错」。
            self.teardown();
            if !self.warned_file_output {
                self.warned_file_output = true;
                log::warn!(
                    "event=HostFlowUplinkUnavailable detail=\"FLOW 帧只能走数据面 tcp 上行；当前输出是本地 file，本机不采集流记录\""
                );
            }
            report.failures.push(FlowFailure {
                kind: collection_reason_kind::TARGET_NOT_READY,
                subject: "flow_output".to_string(),
                detail: "FLOW frames need the data-plane TCP uplink; the current output is a \
                         local file sink, so nothing would be sent"
                    .to_string(),
            });
            return report;
        }
        self.warned_file_output = false;

        // 接口集合变了（网卡热插拔 / ifindex 复用）：先把在途窗口切开发出去，再重挂。
        if self.collector.is_some() && self.interfaces_changed() {
            self.counters.interface_changes = self.counters.interface_changes.saturating_add(1);
            log::info!(
                "event=HostFlowInterfaceChanged detail=\"被观测网卡集合变化：切窗后重挂 tc filter\""
            );
            self.stop(
                PartialReason::InterfaceChanged,
                host,
                sink,
                next_seq,
                global_seq_path,
                &mut report,
            )
            .await;
        }

        self.start_if_needed(&mut report);

        let now_secs = now_secs();
        let now_bucket = flows::monotonic_bucket();
        // 墙钟跳变：窗口归属靠「单调桶差 + 当前墙钟」，跳了就不能按新墙钟重算（会撞幂等键）。
        if self.collector.is_some()
            && let Some(drift) = self.clock_jump(now_secs, now_bucket)
        {
            self.counters.clock_jumps = self.counters.clock_jumps.saturating_add(1);
            log::warn!(
                "event=HostFlowClockJump drift_secs={drift} detail=\"墙钟跳变：本轮按旧锚点外推归窗并标 partial=clock_changed，下一窗重新锚定\""
            );
            let map_wall = self.extrapolated_wall(now_secs, now_bucket);
            self.collect_and_upload_with(
                Some(PartialReason::ClockChanged),
                Some(map_wall),
                host,
                sink,
                next_seq,
                global_seq_path,
                &mut report,
            )
            .await;
            // 新锚点当「窗中启动」：跳变后的这一窗也是截断的。
            self.cut = Some(WindowCut {
                bucket: now_bucket,
                from_secs: now_secs,
                reason: PartialReason::ClockChanged,
            });
        } else if self.collector.is_some() {
            self.collect_and_upload(host, sink, next_seq, global_seq_path, &mut report)
                .await;
        }
        // 锚点每拍都更新（采集器没在跑也更新）：否则停一段再起来会被当成跳变。
        self.anchor = Some((now_secs, now_bucket));
        report.collecting = self.collector.is_some();
        report
    }

    /// 墙钟与单调时钟对不上多少秒（`None` = 没跳 / 无法判定）。
    ///
    /// 判据：拿上一拍的 `(墙钟, 桶)` 外推出「现在应该是几点」，与真实墙钟比。
    /// 慢速 NTP 纠偏（每分钟几十毫秒）不会触发；只有**跳**（回拨/手改时间）会。
    fn clock_jump(&self, now_wall: u64, now_bucket: u64) -> Option<i64> {
        let (anchor_wall, anchor_bucket) = self.anchor?;
        let expected = extrapolate(anchor_wall, anchor_bucket, now_bucket);
        let drift = now_wall as i64 - expected as i64;
        (drift.abs() >= CLOCK_JUMP_SECS).then_some(drift)
    }

    /// 按**旧锚点**外推的墙钟：跳变那一拍用它给桶归窗。
    fn extrapolated_wall(&self, now_wall: u64, now_bucket: u64) -> u64 {
        match self.anchor {
            Some((anchor_wall, anchor_bucket)) => {
                extrapolate(anchor_wall, anchor_bucket, now_bucket)
            }
            None => now_wall,
        }
    }

    /// 把本拍的增量并进累计计数器。
    fn absorb(&mut self, report: &FlowReport) {
        let counters = &mut self.counters;
        counters.windows_sent = counters
            .windows_sent
            .saturating_add(report.delivered as u64);
        counters.flush_capped = counters
            .flush_capped
            .saturating_add(u64::from(report.flush_capped));
        counters.late_dropped = counters.late_dropped.saturating_add(report.late_dropped);
        counters.truncated_windows = counters
            .truncated_windows
            .saturating_add(report.truncated_windows as u64);
        counters.lost_records = counters
            .lost_records
            .saturating_add(report.lost_records as u64);
    }

    /// 落一份运行态快照（节流）。
    ///
    /// 失败只告警：诊断信息不该反过来影响采集。
    async fn persist_status(&mut self, state_dir: &Path, report: &FlowReport) {
        let signature = status_signature(self.collector.is_some(), report);
        let due = self
            .last_status_at
            .is_none_or(|at| at.elapsed() >= STATUS_INTERVAL);
        if !due && self.last_status_sig.as_deref() == Some(signature.as_str()) {
            return;
        }
        let status = flows_state::FlowStatus {
            schema_version: flows_state::SCHEMA_VERSION.to_string(),
            updated_at: now_rfc3339(),
            collecting: self.collector.is_some(),
            attach_path: flows::attach_path().to_string(),
            kernel: self.kernel.clone(),
            ifaces: self.watched.iter().map(|(_, name)| name.clone()).collect(),
            counters: self.counters.clone(),
            last_error: report
                .failures
                .last()
                .map(|failure| format!("{}: {} {}", failure.kind, failure.subject, failure.detail)),
        };
        match flows_state::store_async(&flows_state::path_for(state_dir), &status).await {
            Ok(()) => {
                self.last_status_at = Some(Instant::now());
                self.last_status_sig = Some(signature);
            }
            Err(err) => log::warn!("event=HostFlowStatusStoreFailed detail=\"{err}\""),
        }
    }

    /// 停采：把**所有**桶（含在途窗口）取出上送并标记截断原因，然后卸掉 filter。
    async fn stop(
        &mut self,
        reason: PartialReason,
        host: &FlowHostContext<'_>,
        sink: &mut TelemetryRecordSink,
        next_seq: &mut u64,
        global_seq_path: &Path,
        report: &mut FlowReport,
    ) {
        if self.collector.is_none() {
            return;
        }
        self.collect_and_upload_with(
            Some(reason),
            None,
            host,
            sink,
            next_seq,
            global_seq_path,
            report,
        )
        .await;
        let names: Vec<&str> = self.watched.iter().map(|(_, name)| name.as_str()).collect();
        log::info!(
            "event=HostFlowStopped reason={} ifaces={}",
            reason.as_str(),
            names.join(",")
        );
        self.teardown();
    }

    /// 起采集器（带冷却）：探不到能力 / 没网卡 / 挂不上，都如实进 `report`。
    ///
    /// 冷却期内**不重试但每拍照报** —— 只报第一拍等于事后看不见；反之每拍都重试只会
    /// 白烧 CPU（权限没补上之前必然失败）。
    fn start_if_needed(&mut self, report: &mut FlowReport) {
        if self.collector.is_some() {
            return;
        }
        if let Some(reason) = self.unavailable.clone() {
            report.failures.push(FlowFailure::from_unavailable(&reason));
            let cooled = self
                .last_start_attempt
                .is_none_or(|at| at.elapsed() >= START_RETRY);
            if !cooled {
                return;
            }
            self.unavailable = None;
        }

        // 三步都可能失败（能力 → 选卡 → 挂载），走同一个出口上报。
        let attempt = match flows::probe() {
            FlowSupport::Unavailable(reason) => Err(reason),
            FlowSupport::Available => {
                let snapshot = flows::interfaces();
                let chosen = select_observed(&snapshot);
                if chosen.is_empty() {
                    Err(Unavailable::NoObservedInterface {
                        detail: format!("{} interfaces present", snapshot.len()),
                    })
                } else {
                    Collector::start(&chosen)
                }
            }
        };

        match attempt {
            Ok(collector) => {
                let now_secs = now_secs();
                let start_bucket = flows::monotonic_bucket();
                let offset = now_secs % WINDOW_SECONDS;
                self.cut = (offset != 0).then_some(WindowCut {
                    bucket: start_bucket,
                    from_secs: now_secs,
                    reason: PartialReason::AgentStart,
                });
                self.kernel = flows::kernel_release();
                self.watched = collector
                    .watched()
                    .iter()
                    .map(|iface| (iface.ifindex, iface.name.clone()))
                    .collect();
                self.last_start_attempt = Some(Instant::now());
                self.last_iface_check = Some(Instant::now());
                let names: Vec<&str> = self.watched.iter().map(|(_, name)| name.as_str()).collect();
                log::info!(
                    "event=HostFlowCollecting ifaces={} kernel={}",
                    names.join(","),
                    self.kernel
                );
                self.collector = Some(collector);
            }
            Err(reason) => {
                // 只在原因**变化**时打一行：冷却期内每 3s 重复同一句只会把日志刷满。
                if self.unavailable.as_ref() != Some(&reason) {
                    self.counters.load_failures = self.counters.load_failures.saturating_add(1);
                    log::warn!(
                        "event=HostFlowStartFailed kind={} subject={} detail=\"{}\"",
                        reason.reason_kind(),
                        reason.subject(),
                        reason.detail()
                    );
                }
                report.failures.push(FlowFailure::from_unavailable(&reason));
                self.unavailable = Some(reason);
                self.last_start_attempt = Some(Instant::now());
            }
        }
    }

    /// 被观测的网卡集合变了？（节流到 [`IFACE_RECHECK`]）
    fn interfaces_changed(&mut self) -> bool {
        if self
            .last_iface_check
            .is_some_and(|at| at.elapsed() < IFACE_RECHECK)
        {
            return false;
        }
        self.last_iface_check = Some(Instant::now());
        let snapshot = flows::interfaces();
        let current: Vec<(u32, String)> = select_observed(&snapshot)
            .iter()
            .map(|iface| (iface.ifindex, iface.name.clone()))
            .collect();
        current != self.watched
    }

    fn teardown(&mut self) {
        // aya 的 `Ebpf::drop` 负责摘掉自己挂上去的 tc filter（不动宿主已有的 qdisc）。
        self.collector = None;
        self.watched.clear();
        self.cut = None;
    }

    /// 收到停机信号（SIGTERM/SIGINT）：把在途窗口按 `partial_reason=shutdown` 发出去
    /// （最尽力），然后卸掉 filter。
    ///
    /// 顺序不能反：先卸 filter 就等于把这一分钟丢掉。发不出去（没 sink / 上送失败）也要
    /// 卸 —— 留下的 filter 会一直烧 CPU。
    pub(super) async fn shutdown(
        &mut self,
        sink: Option<&mut TelemetryRecordSink>,
        next_seq: &mut u64,
        state_dir: &Path,
    ) {
        if self.collector.is_none() {
            return;
        }
        let global_seq_path = log_seq_state::path_for(state_dir);
        let Some(facts) = self.host.clone() else {
            log::info!(
                "event=HostFlowStopped reason=shutdown flushed=0 detail=\"没有本机身份快照，在途窗口丢弃\""
            );
            self.teardown();
            return;
        };
        let ctx = FlowHostContext {
            agent_id: &facts.agent_id,
            host_id: &facts.host_id,
            host_name: facts.host_name.as_deref(),
        };
        let mut report = FlowReport::default();
        let has_sink = sink.is_some();
        if let Some(sink) = sink {
            self.collect_and_upload_with(
                Some(PartialReason::Shutdown),
                None,
                &ctx,
                sink,
                next_seq,
                &global_seq_path,
                &mut report,
            )
            .await;
        }
        log::info!(
            "event=HostFlowStopped reason=shutdown flushed={} delivered={} sink={}",
            report.flushed,
            report.delivered,
            has_sink
        );
        self.teardown();
        // 停机后再落一份（`collecting=false`）：否则 diagnose 会一直读到上一次的“在跑”。
        self.persist_status(state_dir, &FlowReport::default()).await;
    }

    /// 待命 / 终态时把采集器卸掉。
    ///
    /// 与 `LogInputRuntime::release_for_idle` 同一取向：**不采就不该占着资源** ——
    /// 关闸期数据面不收，继续 attach 只是白烧 CPU（聚合表还会被 LRU 淘汰）。
    /// 在途窗口没有可交付的出口，只能丢弃，但丢一整个窗口这件事要留一行日志。
    pub(super) fn release_for_idle(&mut self) {
        if self.collector.is_none() {
            return;
        }
        let names: Vec<&str> = self.watched.iter().map(|(_, name)| name.as_str()).collect();
        log::info!(
            "event=HostFlowStopped reason=idle ifaces={} detail=\"待命/终态：不采流记录，在途窗口丢弃\"",
            names.join(",")
        );
        self.teardown();
    }

    /// 常规 flush：只取已经 settle 的桶。
    async fn collect_and_upload(
        &mut self,
        host: &FlowHostContext<'_>,
        sink: &mut TelemetryRecordSink,
        next_seq: &mut u64,
        global_seq_path: &Path,
        report: &mut FlowReport,
    ) {
        self.collect_and_upload_with(None, None, host, sink, next_seq, global_seq_path, report)
            .await;
    }

    /// `force = Some(reason)` 表示停采：把在途窗口也取出来，并标记截断原因。
    ///
    /// `map_wall` 是**给桶归窗用**的墙钟（`None` = 用真实当前时间）。只有墙钟跳变那一拍
    /// 会传入「按旧锚点外推的时间」—— 那些桶是跳变**之前**采的，按新墙钟重算会撞幂等键。
    #[allow(clippy::too_many_arguments)]
    async fn collect_and_upload_with(
        &mut self,
        force: Option<PartialReason>,
        map_wall: Option<u64>,
        host: &FlowHostContext<'_>,
        sink: &mut TelemetryRecordSink,
        next_seq: &mut u64,
        global_seq_path: &Path,
        report: &mut FlowReport,
    ) {
        let now_secs = map_wall.unwrap_or_else(now_secs);
        let (now_bucket, flushed, deferred, watched, late) = {
            let Some(collector) = self.collector.as_mut() else {
                return;
            };
            let now_bucket = flows::monotonic_bucket();
            let (flushed, deferred) = match force {
                // 停采：一次取完（采集器马上要被 drop，剩下的就真丢了）。
                Some(_) => (collector.flush_all(now_bucket), false),
                None => {
                    let batch = collector.flush(now_bucket, MAX_FLOWS_PER_FLUSH);
                    (batch.flows, batch.deferred)
                }
            };
            let late = collector.take_late_dropped();
            (
                now_bucket,
                flushed,
                deferred,
                collector.watched().to_vec(),
                late,
            )
        };
        report.late_dropped = report.late_dropped.saturating_add(late);
        if deferred {
            // 不是丢数据：桶留在 BPF 表里，下一拍照着取（最老的先走）。但现场应当能看见“跟不上”。
            report.flush_capped = true;
            log::info!(
                "event=HostFlowFlushCapped limit={MAX_FLOWS_PER_FLUSH} detail=\"本拍到达批量上限，剩余窗口留在 BPF 表里下拍照着取\""
            );
        }
        if flushed.is_empty() {
            return;
        }

        let mut records = Vec::with_capacity(flushed.len());
        let mut lost = 0usize;
        for flow in &flushed {
            // 观测上下文按 `ifindex` 取：接口在 start 之后不会再变（变了就重挂）。
            let Some(iface) = watched.iter().find(|iface| iface.ifindex == flow.ifindex) else {
                // 网卡在窗口结束前消失：没有 ifname/MAC 就组不出一条合法记录，只能丢 ——
                // 但**必须留痕迹**，静默丢一整个窗口是这条链路最糟糕的失败形状。
                lost += 1;
                continue;
            };
            let start = window_from_bucket(now_secs, now_bucket, flow.window_bucket);
            let (partial, seconds) = self.window_shape(flow.window_bucket, start, now_secs, force);
            if flow.agg.truncated {
                report.truncated_windows += 1;
            }
            records.push(HostFlowRecord::from_window(
                &window_ctx(host, iface, &self.kernel),
                &flow.key,
                start,
                seconds,
                &flow.agg,
                partial,
            ));
        }
        if lost > 0 {
            report.lost_records += lost;
            log::warn!(
                "event=HostFlowRecordsLost count={lost} detail=\"窗口里有记录找不到对应网卡（网卡在窗口结束前消失），已丢弃\""
            );
            report.failures.push(FlowFailure {
                kind: collection_reason_kind::INCOMPLETE_DATA,
                subject: "flow_iface".to_string(),
                detail: format!("丢弃 {lost} 条窗口记录：找不到对应网卡（网卡在窗口结束前消失）"),
            });
        }
        if records.is_empty() {
            return;
        }
        report.flushed += records.len();
        let ifaces = watched.len();
        match write_flow_uplink(sink, host.agent_id, &records, next_seq, global_seq_path).await {
            Ok(()) => {
                report.delivered += records.len();
                log::info!(
                    "event=HostFlowUplinkSent records={} ifaces={} late_dropped={}",
                    records.len(),
                    ifaces,
                    report.late_dropped
                );
            }
            Err(err) => {
                // 至多一次：本批丢弃，不重发（重发会破坏「一个幂等键一条记录」）。
                self.counters.uplink_failures = self.counters.uplink_failures.saturating_add(1);
                crate::telemetry::metrics::self_obs::record_uplink_failure();
                log::warn!("wist-agentd flow uplink failed: {err}");
                report.failures.push(FlowFailure {
                    kind: collection_reason_kind::RUN_FAILED,
                    subject: "uplink".to_string(),
                    detail: format!("FLOW 帧上送失败：{err}（本批丢弃，不重发）"),
                });
            }
        }
    }

    /// 这个窗口是否被截断、实际覆盖了多少秒。
    fn window_shape(
        &self,
        bucket: u64,
        window: u64,
        now_secs: u64,
        force: Option<PartialReason>,
    ) -> (Option<PartialReason>, u32) {
        if let Some(cut) = self.cut
            && cut.bucket == bucket
        {
            // 采集器在窗口中间才起来：覆盖 `[started_at, min(窗口结束, 现在))`。
            // 取 `min` 是因为这个窗口也可能被**停采**强制切走：那时它既短于整窗口，
            // 也确实只覆盖到停采那一刻。
            let covered = now_secs
                .min(window + WINDOW_SECONDS)
                .saturating_sub(cut.from_secs);
            return (Some(cut.reason), covered.clamp(1, WINDOW_SECONDS) as u32);
        }
        if !is_flushable(window, now_secs) {
            // 只有停采时的强制 flush 才会取到在途窗口；常规路径不会走到这里。
            let Some(reason) = force else {
                return (None, WINDOW_SECONDS as u32);
            };
            // 覆盖 `[窗口开始, 现在)`。
            let covered = now_secs.saturating_sub(window);
            return (Some(reason), covered.clamp(1, WINDOW_SECONDS) as u32);
        }
        (None, WINDOW_SECONDS as u32)
    }
}

fn window_ctx(host: &FlowHostContext<'_>, iface: &WatchedIface, kernel: &str) -> WindowCtx {
    WindowCtx {
        collector_instance_id: host.agent_id.to_string(),
        host_id: if host.host_id.is_empty() {
            host.agent_id.to_string()
        } else {
            host.host_id.to_string()
        },
        host_name: host.host_name.map(str::to_string),
        kernel: kernel.to_string(),
        ifname: iface.name.clone(),
        ifindex: iface.ifindex,
        if_mac: iface.mac.clone(),
        // 只留可在网络上路由的地址：`fe80::` / 回环进 `local_addrs` 只会让下游 join 变噪音。
        local_addrs: iface
            .addrs
            .iter()
            .copied()
            .filter(|addr| is_flow_addr(*addr))
            .collect(),
    }
}

/// 逐条上送 ` FLOW: ` 帧。
///
/// 与指标帧同一套号（agent 级全局 `seq`）：先取号、再持久化高水位、最后发送 ——
/// 崩溃只会浪费号，绝不回退撞号（`(agent, seq)` 是数据面的去重键）。
async fn write_flow_uplink(
    sink: &mut TelemetryRecordSink,
    agent_id: &str,
    records: &[HostFlowRecord],
    next_seq: &mut u64,
    global_seq_path: &Path,
) -> io::Result<()> {
    if records.is_empty() {
        return Ok(());
    }
    let observed_at = now_rfc3339();
    let mut frames = Vec::with_capacity(records.len());
    for record in records {
        let body = serde_json::to_vec(record)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
        let seq = *next_seq;
        *next_seq += 1;
        frames.push((DataFrame::new(agent_id, observed_at.clone(), seq), body));
    }
    // 前移一位持久化：崩溃只会浪费号，绝不回退撞号。
    log_seq_state::store_async(global_seq_path, *next_seq).await?;
    for (envelope, body) in frames {
        sink.write_flow(&envelope, &body).await?;
    }
    Ok(())
}

/// 失败面 + 采集态的签名：变了就立刻落盘（不等 [`STATUS_INTERVAL`]）。
fn status_signature(collecting: bool, report: &FlowReport) -> String {
    let mut signature = format!("c={collecting}");
    for failure in &report.failures {
        signature.push('|');
        signature.push_str(failure.kind);
        signature.push(':');
        signature.push_str(&failure.subject);
    }
    signature
}

fn now_secs() -> u64 {
    u64::try_from(now_ts_ms()).unwrap_or(0) / 1000
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_store::work::{SCHEMA_VERSION_V1, StandingWorkRecord, WorkRecord};
    use crate::telemetry::flows::record::{Direction, FlowKey, PROTO_TCP, WindowAgg};
    use crate::telemetry::warp_parse::{FileRecordSink, TcpFraming, TcpRecordSink};
    use std::net::{IpAddr, Ipv4Addr};
    use std::path::PathBuf;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;
    use wist_contracts::work::{WorkSpecSource, WorkSpecUnit};

    fn temp_dir(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "wist-agentd-{name}-{}-{:?}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .expect("clock")
                .as_nanos()
        ));
        std::fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    /// 一份只含 `HostFlow:auto` 的授权（与网关实际下发的最小形状一致）。
    fn flow_grant() -> AppliedWorkGrant {
        let record = WorkRecord {
            schema_version: SCHEMA_VERSION_V1.to_string(),
            recorded_at: "2026-11-27T00:00:00Z".to_string(),
            gateway_sequence: 1,
            standing: vec![StandingWorkRecord {
                work_id: "w-flow".to_string(),
                family: "NetworkFlow".to_string(),
                status: "active".to_string(),
                plan_version: 1,
                acknowledged_version: Some(1),
                effective_from: "2026-11-27T00:00:00Z".to_string(),
                units: vec![WorkSpecUnit {
                    unit_id: "flow".to_string(),
                    capability: "collect_logs".to_string(),
                    rule_ref: "r".to_string(),
                    requires_privilege: "root".to_string(),
                    sources: vec![WorkSpecSource {
                        kind: "HostFlow".to_string(),
                        target: "auto".to_string(),
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

    fn host_ctx<'a>(host_id: &'a str, host_name: &'a str) -> FlowHostContext<'a> {
        FlowHostContext {
            agent_id: "agent-1",
            host_id,
            host_name: Some(host_name),
        }
    }

    fn record(start: u64) -> HostFlowRecord {
        let ctx = WindowCtx {
            collector_instance_id: "agent-1".to_string(),
            host_id: "host-1".to_string(),
            host_name: Some("vm-1".to_string()),
            kernel: "5.15.0".to_string(),
            ifname: "eth0".to_string(),
            ifindex: 2,
            if_mac: Some("52:54:00:00:00:02".to_string()),
            local_addrs: vec![IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))],
        };
        let key = FlowKey {
            direction: Direction::Out,
            protocol: PROTO_TCP,
            src: "10.0.0.1".parse().expect("src"),
            dst: "10.0.0.2".parse().expect("dst"),
            src_port: 50123,
            dst_port: 443,
            icmp_type: None,
            icmp_code: None,
            port_unavailable: false,
        };
        let agg = WindowAgg {
            packets: 13,
            bytes: 1460,
            wire_bytes: None,
            skb_count: 4,
            gso_skb_count: 1,
            dropped: 0,
            truncated: false,
        };
        HostFlowRecord::from_window(&ctx, &key, start, WINDOW_SECONDS as u32, &agg, None)
    }

    async fn tcp_listener() -> Option<(TcpListener, u16)> {
        match TcpListener::bind("127.0.0.1:0").await {
            Ok(listener) => {
                let port = listener.local_addr().expect("addr").port();
                Some((listener, port))
            }
            // 沙箱里不允许监听：跳过（与既有上行测试同一处理）。
            Err(err) if err.kind() == std::io::ErrorKind::PermissionDenied => None,
            Err(err) => panic!("bind listener: {err}"),
        }
    }

    fn drain(listener: TcpListener) -> tokio::task::JoinHandle<String> {
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let mut body = Vec::new();
            let mut buf = vec![0u8; 4096];
            loop {
                let n = socket.read(&mut buf).await.expect("read");
                if n == 0 {
                    break;
                }
                body.extend_from_slice(&buf[..n]);
            }
            String::from_utf8_lossy(&body).into_owned()
        })
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_flow_uplink_sends_one_flow_frame_per_record() {
        let Some((listener, port)) = tcp_listener().await else {
            return;
        };
        let server = drain(listener);
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));
        let state_dir = temp_dir("flow-uplink");
        let seq_path = log_seq_state::path_for(&state_dir);
        let mut next_seq = 0u64;
        write_flow_uplink(
            &mut sink,
            "agent-1",
            &[record(1_700_000_040), record(1_700_000_100)],
            &mut next_seq,
            &seq_path,
        )
        .await
        .expect("flow uplink");
        drop(sink);

        let body = server.await.expect("join");
        assert_eq!(body.lines().count(), 2, "一条记录一帧：{body}");
        // 信封只有 schema/agent/ts/seq（设计 §5.1），正文才是记录。
        assert!(body.contains("\"schema\":\"v1\""), "{body}");
        assert!(body.contains("\"agent\":\"agent-1\""), "{body}");
        assert!(body.contains("\"seq\":0"), "{body}");
        assert!(body.contains("\"seq\":1"), "{body}");
        assert_eq!(body.matches(" FLOW: ").count(), 2, "{body}");
        for marker in [" LOGRAW: ", " METRICS: ", " OBSFACT: ", " DSNAP: "] {
            assert!(!body.contains(marker), "不能蹭 {marker}：{body}");
        }
        assert!(
            body.contains("\"record_schema\":\"wist.host_flow/v1\""),
            "{body}"
        );
        assert!(body.contains("\"direction\":\"out\""), "{body}");
        assert!(body.contains("\"srcport\":\"50123\""), "{body}");
    }

    #[tokio::test(flavor = "current_thread")]
    async fn write_flow_uplink_persists_the_seq_high_water_mark() {
        let Some((listener, port)) = tcp_listener().await else {
            return;
        };
        let server = drain(listener);
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));
        let state_dir = temp_dir("flow-seq");
        let seq_path = log_seq_state::path_for(&state_dir);
        let mut next_seq = 7u64;
        write_flow_uplink(
            &mut sink,
            "agent-1",
            &[record(1_700_000_040)],
            &mut next_seq,
            &seq_path,
        )
        .await
        .expect("flow uplink");
        drop(sink);
        let body = server.await.expect("join");
        assert!(body.contains("\"seq\":7"), "{body}");
        assert_eq!(next_seq, 8);
        let persisted = log_seq_state::load_or_default_async(&seq_path)
            .await
            .expect("load seq");
        assert_eq!(persisted, 8, "先落盘高水位再发送：崩溃只浪费号，不回退");
    }

    #[test]
    fn window_shape_reports_truncated_start_and_forced_windows() {
        let mut runtime = FlowRuntime::new();
        // 采集器在 `:30` 才起来 → 那个窗口只覆盖后 30 秒。
        let bucket = 10u64;
        let window = 1_700_000_040u64;
        runtime.cut = Some(WindowCut {
            bucket,
            from_secs: 1_700_000_070,
            reason: PartialReason::AgentStart,
        });
        assert_eq!(
            runtime.window_shape(bucket, window, 1_700_000_300, None),
            (Some(PartialReason::AgentStart), 30)
        );
        // 同一个窗口若被**停采**切走：只覆盖到停采那一刻（不能声称采到了窗口结束）。
        assert_eq!(
            runtime.window_shape(bucket, window, 1_700_000_080, Some(PartialReason::Paused)),
            (Some(PartialReason::AgentStart), 10)
        );

        // 已经 settle 的窗口：完整 60 秒，不带 partial（即使这拍是强制 flush）。
        assert_eq!(
            runtime.window_shape(bucket + 2, window + 120, 1_700_000_300, None),
            (None, 60)
        );
        assert_eq!(
            runtime.window_shape(
                bucket + 2,
                window + 120,
                1_700_000_300,
                Some(PartialReason::Paused)
            ),
            (None, 60)
        );

        // 停采时被强制取出的在途窗口：覆盖 [窗口开始, 现在)。
        let in_flight = 1_700_000_240u64;
        assert_eq!(
            runtime.window_shape(
                bucket + 3,
                in_flight,
                1_700_000_270,
                Some(PartialReason::Paused)
            ),
            (Some(PartialReason::Paused), 30)
        );
    }

    /// 墙钟跳变：用**旧锚点**外推的时间判断，桶没动、墙钟回拨也不能当成正常。
    #[test]
    fn a_wall_clock_jump_is_detected_against_the_monotonic_bucket() {
        let mut runtime = FlowRuntime::new();
        runtime.anchor = Some((1_700_000_100, 10));
        // 同桶、墙钟走 10s：正常（慢速纠偏在这个量级）。
        assert_eq!(runtime.clock_jump(1_700_000_110, 10), None);
        // 桶进 1（=60s），墙钟走 70s：+10s，仍正常。
        assert_eq!(runtime.clock_jump(1_700_000_170, 11), None);
        // 桶进 1，墙钟却走了 100s：+40s → 跳变。
        assert_eq!(runtime.clock_jump(1_700_000_200, 11), Some(40));
        // 回拨 150s：负数也要认出来。
        assert_eq!(runtime.clock_jump(1_700_000_010, 11), Some(-150));
        // 没有锚点（刚启动）：无从判定，不报跳变。
        let fresh = FlowRuntime::new();
        assert_eq!(fresh.clock_jump(1_700_000_010, 11), None);
    }

    /// 跳变那一拍必须按**旧锚点**归窗：按新墙钟重算会把桶挪回 60s×N，撞上已发的幂等键。
    #[test]
    fn a_jump_maps_the_in_flight_window_on_the_old_timeline() {
        let mut runtime = FlowRuntime::new();
        runtime.anchor = Some((1_700_000_100, 10));
        let jumped_wall = 1_700_000_010; // 回拨 90s
        let old_timeline = runtime.extrapolated_wall(jumped_wall, 10);
        assert_eq!(old_timeline, 1_700_000_100);

        let mapped = window_from_bucket(old_timeline, 10, 9);
        let naive = window_from_bucket(jumped_wall, 10, 9);
        assert_ne!(mapped, naive, "按新墙钟重算会落到别的窗口");
        assert_eq!(mapped, 1_700_000_040);
    }

    /// 跳变后的这一窗同样是“截断”的：原因要写成 `clock_changed` 而不是 `agent_start`。
    #[test]
    fn a_clock_changed_window_says_so() {
        let mut runtime = FlowRuntime::new();
        let bucket = 10u64;
        let window = 1_700_000_040u64;
        runtime.cut = Some(WindowCut {
            bucket,
            from_secs: 1_700_000_070,
            reason: PartialReason::ClockChanged,
        });
        assert_eq!(
            runtime.window_shape(bucket, window, 1_700_000_300, None),
            (Some(PartialReason::ClockChanged), 30)
        );
    }

    /// 计数器是**累计**的（每拍增量并进去），diagnose 读的就是它们。
    #[test]
    fn counters_accumulate_from_each_report() {
        let mut runtime = FlowRuntime::new();
        runtime.absorb(&FlowReport {
            delivered: 5,
            flush_capped: true,
            late_dropped: 2,
            truncated_windows: 1,
            lost_records: 3,
            ..Default::default()
        });
        runtime.absorb(&FlowReport {
            delivered: 1,
            ..Default::default()
        });
        assert_eq!(runtime.counters.windows_sent, 6);
        assert_eq!(runtime.counters.flush_capped, 1);
        assert_eq!(runtime.counters.late_dropped, 2);
        assert_eq!(runtime.counters.truncated_windows, 1);
        assert_eq!(runtime.counters.lost_records, 3);
    }

    /// `state/flows/status.json` 是 `agentd diagnose` 的唯一数据源：失败面要写进去，
    /// 而且**签名没变就不重复落盘**（否则每 3s 一次 fsync）。
    #[tokio::test(flavor = "current_thread")]
    async fn the_status_file_records_failures_without_rewriting_every_tick() {
        let state_dir = temp_dir("flow-status");
        let mut sink =
            TelemetryRecordSink::File(FileRecordSink::new(state_dir.join("records.jsonl")));
        let mut runtime = FlowRuntime::new();
        let mut next_seq = 0u64;
        let work = flow_grant();

        let _ = runtime
            .tick(
                &work,
                &host_ctx("host-1", "vm-1"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;

        let path = flows_state::path_for(&state_dir);
        let status = flows_state::load(&path).expect("load").expect("status");
        assert!(!status.collecting, "file 输出下不采");
        assert!(
            status
                .last_error
                .as_deref()
                .is_some_and(|error| error.contains("target_not_ready")),
            "{status:?}"
        );

        // 同一失败面再跑一拍：签名没变 → 不重写。
        let written_at = runtime.last_status_at.expect("first write");
        let _ = runtime
            .tick(
                &work,
                &host_ctx("host-1", "vm-1"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;
        assert_eq!(
            runtime.last_status_at,
            Some(written_at),
            "签名没变就不该重复落盘"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn a_file_output_is_reported_instead_of_collecting_silently() {
        let state_dir = temp_dir("flow-file-output");
        let mut sink =
            TelemetryRecordSink::File(FileRecordSink::new(state_dir.join("records.jsonl")));
        let mut runtime = FlowRuntime::new();
        let mut next_seq = 0u64;
        let work = flow_grant();

        let report = runtime
            .tick(
                &work,
                &host_ctx("host-1", "vm-1"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;

        assert!(!report.collecting, "file 输出下不采（采了也没处送）");
        assert_eq!(report.delivered, 0);
        assert_eq!(report.failures.len(), 1, "{report:?}");
        assert_eq!(
            report.failures[0].kind,
            collection_reason_kind::TARGET_NOT_READY,
            "要如实说清「无处可送」，不能静默：{report:?}"
        );
    }

    #[tokio::test(flavor = "current_thread")]
    async fn no_grant_means_no_collector_and_no_failure() {
        let state_dir = temp_dir("flow-no-grant");
        let mut sink =
            TelemetryRecordSink::File(FileRecordSink::new(state_dir.join("records.jsonl")));
        let mut runtime = FlowRuntime::new();
        let mut next_seq = 0u64;

        let report = runtime
            .tick(
                &AppliedWorkGrant::default(),
                &host_ctx("host-1", "vm-1"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;

        assert!(!report.collecting);
        assert!(report.failures.is_empty(), "没授权不是失败：{report:?}");
        assert_eq!(report.flushed, 0);
    }

    /// 没有采集器的平台（macOS / 没 clang 的构建）必须报 `unsupported`，不能静默。
    #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
    #[tokio::test(flavor = "current_thread")]
    async fn a_platform_without_the_collector_reports_unsupported() {
        let Some((listener, port)) = tcp_listener().await else {
            return;
        };
        // 起不来就不会写连接：把 listener 留着，测试结束随作用域关闭。
        let _listener = listener;
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));
        let state_dir = temp_dir("flow-not-built");
        let mut runtime = FlowRuntime::new();
        let mut next_seq = 0u64;

        let report = runtime
            .tick(
                &flow_grant(),
                &host_ctx("host-1", "vm-1"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;

        assert!(!report.collecting);
        assert_eq!(report.failures.len(), 1, "{report:?}");
        assert_eq!(report.failures[0].kind, "unsupported", "{report:?}");
    }

    /// 真机端到端（需 root + 默认路由 + clang）：起采集器 → 真发一个 UDP → 停采 → 收到 ` FLOW: ` 帧。
    ///
    /// 为什么在**停采**时才取：常规 flush 要等窗口结束 2 窗（≥120s）；`flush_all`（停采）能把
    /// 在途窗口立即取出并标 `partial` —— 这正好同时验证了「授权一撤就把窗口切开交出去」。
    ///
    /// 与既有的真机冒烟测试一样标 `#[ignore]`：它要求 root、会 attach 到**真网卡**，
    /// 不能进并行测试集（多个 attach 会互相干扰）。
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    #[ignore = "needs root + a default route + a real NIC; run with --ignored on a Linux host"]
    #[tokio::test(flavor = "current_thread")]
    // 持锁跨 `.await` 是故意的：这把锁就是用来把两个 attach 真网卡的测试串起来的；
    // 同一个 runtime 里没有别的任务会去抢它，不会自锁。
    #[allow(clippy::await_holding_lock)]
    async fn a_real_udp_becomes_a_partial_flow_frame_when_the_grant_is_revoked() {
        let _exclusive = flows::REAL_NIC_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(gateway) = default_gateway() else {
            eprintln!("skip: 本机没有默认路由（无对外网卡，采集器也起不来）");
            return;
        };
        let Some((listener, port)) = tcp_listener().await else {
            eprintln!("skip: 不允许监听本地端口");
            return;
        };
        let server = drain(listener);
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));
        let state_dir = temp_dir("flow-real");
        let mut next_seq = 0u64;
        let mut runtime = FlowRuntime::new();
        let work = flow_grant();

        let started = runtime
            .tick(
                &work,
                &host_ctx("host-real", "vm-real"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;
        if !started.collecting {
            eprintln!("skip: 采集器没起来（需要 root/CAP 与可用内核）：{started:?}");
            return;
        }

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind udp");
        let src_port = socket.local_addr().expect("udp local addr").port();
        // 发往默认网关（它一定经被观测网卡出去）；不关心有没有回应。
        for _ in 0..3 {
            socket
                .send_to(b"wist-flow-probe", (gateway, 9))
                .expect("send udp");
        }

        // 撤授权 → 停采（flush_all + 标 partial）→ 上送。
        let stopped = runtime
            .tick(
                &AppliedWorkGrant::default(),
                &host_ctx("host-real", "vm-real"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;
        assert!(!stopped.collecting, "撤授权后必须卸掉采集器");
        drop(sink);

        let body = server.await.expect("join");
        assert!(!body.is_empty(), "停采时应该把在途窗口发出来");
        assert!(body.contains("\"schema\":\"v1\""), "{body}");
        let udp = body
            .lines()
            .filter(|line| line.contains(" FLOW: "))
            .find(|line| {
                line.contains(&format!("\"srcport\":\"{src_port}\""))
                    && line.contains("\"protocol\":\"17\"")
            })
            .unwrap_or_else(|| panic!("没找到这条 UDP 流：{body}"));
        assert!(udp.contains("\"direction\":\"out\""), "{udp}");
        assert!(
            udp.contains("\"partial\":true"),
            "在途窗口要标 partial：{udp}"
        );
        assert!(
            udp.contains("\"partial_reason\":\"agent_start\"")
                || udp.contains("\"partial_reason\":\"paused\""),
            "{udp}"
        );
        assert!(udp.contains("\"window_seconds\":"), "{udp}");
        assert!(udp.contains("\"host_id\":\"host-real\""), "{udp}");
    }

    /// 真机端到端（需 root + 默认路由 + clang）：停机收尾要把在途窗口标 `shutdown` 发出去。
    ///
    /// 这是 SIGTERM 路径下半段（信号本身由 `ShutdownSignal` 负责，不好在单测里自杀）。
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    #[ignore = "needs root + a default route + a real NIC; run with --ignored on a Linux host"]
    #[tokio::test(flavor = "current_thread")]
    #[allow(clippy::await_holding_lock)]
    async fn a_graceful_shutdown_flushes_the_in_flight_window() {
        let _exclusive = flows::REAL_NIC_TEST_LOCK
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        let Some(gateway) = default_gateway() else {
            eprintln!("skip: 本机没有默认路由");
            return;
        };
        let Some((listener, port)) = tcp_listener().await else {
            eprintln!("skip: 不允许监听本地端口");
            return;
        };
        let server = drain(listener);
        let mut sink = TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ));
        let state_dir = temp_dir("flow-shutdown");
        let mut next_seq = 0u64;
        let mut runtime = FlowRuntime::new();

        let started = runtime
            .tick(
                &flow_grant(),
                &host_ctx("host-real", "vm-real"),
                &mut sink,
                &mut next_seq,
                &state_dir,
            )
            .await;
        if !started.collecting {
            eprintln!("skip: 采集器没起来（需要 root/CAP 与可用内核）：{started:?}");
            return;
        }

        let socket = std::net::UdpSocket::bind("0.0.0.0:0").expect("bind udp");
        let src_port = socket.local_addr().expect("udp local addr").port();
        for _ in 0..3 {
            socket
                .send_to(b"wist-flow-probe", (gateway, 9))
                .expect("send udp");
        }

        runtime
            .shutdown(Some(&mut sink), &mut next_seq, &state_dir)
            .await;
        drop(sink);

        let body = server.await.expect("join");
        let udp = body
            .lines()
            .filter(|line| line.contains(" FLOW: "))
            .find(|line| line.contains(&format!("\"srcport\":\"{src_port}\"")))
            .unwrap_or_else(|| panic!("停机时应该把在途窗口发出来：{body}"));
        assert!(udp.contains("\"partial\":true"), "{udp}");
        assert!(
            udp.contains("\"partial_reason\":\"shutdown\"")
                || udp.contains("\"partial_reason\":\"agent_start\""),
            "{udp}"
        );
    }

    /// 默认网关（v4）：`/proc/net/route` 里 dest=0 且带 RTF_UP 的那条。
    ///
    /// `/proc/net/route` 里的地址是「按小端打印的 32 位值」，要 `u32::from_be`。
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    fn default_gateway() -> Option<Ipv4Addr> {
        let text = std::fs::read_to_string("/proc/net/route").ok()?;
        for line in text.lines().skip(1) {
            let mut fields = line.split_whitespace();
            let _iface = fields.next()?;
            let dest = fields.next()?;
            let gateway = fields.next()?;
            if dest == "00000000" {
                let raw = u32::from_str_radix(gateway, 16).ok()?;
                let addr = Ipv4Addr::from(raw.to_be());
                return (!addr.is_unspecified()).then_some(addr);
            }
        }
        None
    }
}
