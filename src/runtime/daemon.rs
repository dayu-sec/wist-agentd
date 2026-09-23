//! `wist-agentd` runtime loop and recovery helpers.

use std::collections::BTreeSet;
use std::io;
use std::path::Path;
use std::time::{Duration, Instant};

use crate::telemetry::warp_parse::TelemetryRecordSink;
use wist_contracts::agent_config::AgentConfig;
use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;
use wist_contracts::gateway::{
    AgentStatusReport, AgentWorkState, AgentWorkStateChange, DiscoveryPoliciesReturned,
    POLL_DISCOVERY_POLICIES_KIND, PollDiscoveryPolicies, ReportAgentFactSummary,
};
use wist_contracts::telemetry_record::DataFrame;
use wist_shared::time::{now_rfc3339, now_ts_ms};

use crate::enrollment::enrollment_http_client;

use crate::error::RuntimeResult;

use crate::control::work::{AppliedWorkGrant, ack_work, fetch_work_grant};
use crate::discovery::DiscoveryProbe;
use crate::discovery::container::ContainerDiscoveryProbe;
use crate::discovery::endpoint::EndpointDiscoveryProbe;
use crate::discovery::host::HostDiscoveryProbe;
use crate::discovery::network::NetworkDiscoveryProbe;
use crate::discovery::process::ProcessDiscoveryProbe;
use crate::discovery::runtime::{DiscoveryRefreshResult, DiscoveryRuntime};
use wist_contracts::exporter::ExporterSource;

use crate::exporter;
use crate::planner_bridge;
use crate::reporting::fact_summary;
use crate::scheduler;
use crate::self_observability::{
    DaemonWorkState, DiscoveryHealthSnapshot, DiscoveryProbeHealth, DiscoveryReadiness,
    RuntimeHealthSnapshot, emit,
};
use crate::state_store::{
    agent_runtime, execution_queue, fact_report, log_seq_state, planner_candidates, work_grant,
};
use crate::telemetry::metrics::target_view;

#[path = "daemon_metrics.rs"]
mod metrics_support;
#[path = "daemon_recovery.rs"]
mod recovery_support;
#[path = "daemon_runtime_state.rs"]
mod runtime_state_support;
#[path = "daemon_telemetry.rs"]
mod telemetry_support;

/// How often the daemon reports its own status (memory / CPU / admin latency)
/// to the control plane.
const STATUS_REPORT_INTERVAL: Duration = Duration::from_secs(3);

/// 主循环空闲节拍。
///
/// 每轮都要重算/落盘派生状态（指标快照、`state/export/*.jsonl`、`agent_runtime`）并扫描
/// `state/`，所以这个值直接等于“稳态每秒多少次磁盘动作”。250ms（4Hz）在空闲主机上也
/// 会持续写盘，属于白付的代价；3s 把稳态开销降到 1/12，同时：
/// - file 输入最坏延迟 3s（采集类负载可接受，仍远优于 scan 周期）；
/// - `drain` 每轮只处理一个队列项且**等它跑完**，因此这个值是空闲轮询间隔，不是执行吞吐上限。
const TICK_INTERVAL: Duration = Duration::from_secs(3);

/// 事实上送的最小间隔。
///
/// 为什么需要它：探针目前是**每 tick 全刷**（3s）—— 各探针声明的 `refresh_interval()`
/// 还没被调度器用上，而进程集合在忙机器上会持续微变。没有下限的话，事实链路的节拍
/// 会跟着采集同频，与「发现是慢变量（分钟级）」的设计相反。
/// 等批次 2 把探针周期改成按策略调度后，这个下限就可以去掉（那时 tick 本身就是慢的）。
const FACT_REPORT_MIN_INTERVAL_MS: i64 = 300_000;

/// 拉取发现方向**策略表**的最小间隔。
///
/// 与事实摘要同理，记的是「上次**尝试**」而不是「上次成功」—— 失败也要被节流，
/// 否则网关宕机时会每 tick（3s）重试一次。策略表是**慢变量**（平台按版本策展发布），
/// 5 分钟一次足够及时；而 agentd 的内建默认周期与表同值，所以拿不到也不影响采集。
const DISCOVERY_POLICY_FETCH_MIN_INTERVAL_MS: i64 = 300_000;

/// 策略表拉取的到期判定用 `Duration`；值只有一个来源（上面的毫秒常量）。
const DISCOVERY_POLICY_FETCH_MIN_INTERVAL: Duration =
    Duration::from_millis(DISCOVERY_POLICY_FETCH_MIN_INTERVAL_MS as u64);

/// 策略表拉取单次请求的超时。
///
/// 与事实摘要同理：它在主循环里排在采集之前，必须自己封顶，不能吃掉 tick。
const DISCOVERY_POLICY_FETCH_TIMEOUT: Duration = Duration::from_secs(5);

/// 拉取**工作授权快照**的最小间隔。
///
/// 比策略表密得多：策略是平台级策展（版本级慢变量），而工作授权是运维对**这一台机器**
/// 的动作 —— 派活、暂停、撤回都期望“立刻生效”。30s 是在“够快”与“别把网关当心跳打”
/// 之间的取值（真正的推送要 agentd 有入站监听，那是另一条路）。
const WORK_FETCH_MIN_INTERVAL_MS: i64 = 30_000;

/// A sampled CPU-time reading used to compute a percentage across the report interval.
struct CpuSample {
    ticks: u64,
    at: Instant,
}

/// Current resident set size in bytes, when the platform exposes it.
fn current_rss_bytes() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/statm").ok()?;
        // statm: size, resident, shared, text, lib, data, dt (all in pages).
        let resident_pages: u64 = content.split_whitespace().nth(1)?.parse().ok()?;
        Some(resident_pages * 4096)
    }
    #[cfg(target_os = "macos")]
    {
        // proc_pidinfo(PROC_PIDTASKINFO) reports the current resident size in bytes.
        let mut info: libc::proc_taskinfo = unsafe { std::mem::zeroed() };
        let size = std::mem::size_of::<libc::proc_taskinfo>() as libc::c_int;
        let written = unsafe {
            libc::proc_pidinfo(
                std::process::id() as libc::c_int,
                libc::PROC_PIDTASKINFO,
                0,
                &mut info as *mut libc::proc_taskinfo as *mut libc::c_void,
                size,
            )
        };
        if written != size {
            return None;
        }
        Some(info.pti_resident_size)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

/// Total CPU time (user + system) of this process in clock ticks.
fn cpu_ticks() -> Option<u64> {
    #[cfg(target_os = "linux")]
    {
        let content = std::fs::read_to_string("/proc/self/stat").ok()?;
        // After the closing ')' of comm, fields are state(3), ppid(4), ...,
        // utime(14) at index 11, stime(15) at index 12.
        let fields: Vec<&str> = content.rsplit(')').next()?.split_whitespace().collect();
        let utime: u64 = fields.get(11)?.parse().ok()?;
        let stime: u64 = fields.get(12)?.parse().ok()?;
        Some(utime + stime)
    }
    #[cfg(target_os = "macos")]
    {
        // getrusage reports user + system CPU time; both are timeval (seconds
        // + microseconds). Total is expressed in microseconds so that
        // ticks_per_sec() = 1_000_000 makes cpu_percent_since() linear in
        // wall-clock seconds.
        let mut usage: libc::rusage = unsafe { std::mem::zeroed() };
        if unsafe { libc::getrusage(libc::RUSAGE_SELF, &mut usage) } != 0 {
            return None;
        }
        let user_us = usage.ru_utime.tv_sec as i64 * 1_000_000 + usage.ru_utime.tv_usec as i64;
        let system_us = usage.ru_stime.tv_sec as i64 * 1_000_000 + usage.ru_stime.tv_usec as i64;
        Some((user_us + system_us) as u64)
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        None
    }
}

#[cfg(target_os = "linux")]
fn ticks_per_sec() -> u64 {
    unsafe { libc::sysconf(libc::_SC_CLK_TCK) as u64 }
}

#[cfg(target_os = "macos")]
fn ticks_per_sec() -> u64 {
    1_000_000
}

#[cfg(not(any(target_os = "linux", target_os = "macos")))]
fn ticks_per_sec() -> u64 {
    100
}

fn cpu_percent_since(previous: &CpuSample, now: Instant, ticks_per_sec: u64) -> Option<f64> {
    let now_ticks = cpu_ticks()?;
    let wall = now.duration_since(previous.at).as_secs_f64();
    if wall <= 0.0 {
        return Some(0.0);
    }
    let tick_delta = now_ticks.saturating_sub(previous.ticks);
    Some(tick_delta as f64 / wall / ticks_per_sec as f64 * 100.0)
}

/// Best-effort status heartbeat to the admin control plane. Returns the measured
/// round-trip latency in milliseconds when the report succeeded.
///
/// `discovery_policy_version` 是**本机实际生效**的发现方向策略版本：
/// 网关知道自己发布了哪一版，但不知道哪台机器拉到了、应用了 ——
/// 而「我改了策略，哪些机器还没生效」只能由 agent 回答。
async fn report_status_to_control_plane(
    config: &AgentConfig,
    cpu_percent: Option<f64>,
    last_latency_ms: Option<u64>,
    work_state_changes: Option<Vec<AgentWorkStateChange>>,
    discovery_policy_version: Option<i64>,
) -> Option<u64> {
    let endpoint = config.control_plane.endpoint.as_deref()?;
    let bearer_token = config.control_plane.bearer_token.as_deref()?;
    let agent_id = config.agent.agent_id.as_deref()?;
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    let report = AgentStatusReport {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        memory_bytes: current_rss_bytes(),
        cpu_percent,
        admin_latency_ms: last_latency_ms,
        work_state_changes,
        discovery_policy_version,
    };
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("wist-agentd status report: failed to build client: {err}");
            return None;
        }
    };
    let url = format!("{}/api/v1/agent/status", endpoint.trim_end_matches('/'));
    let started = Instant::now();
    match client
        .post(&url)
        .bearer_auth(bearer_token)
        .json(&report)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            Some(started.elapsed().as_millis() as u64)
        }
        Ok(response) => {
            eprintln!(
                "wist-agentd status report failed: HTTP {} from {}",
                response.status(),
                endpoint
            );
            None
        }
        Err(err) => {
            eprintln!("wist-agentd status report failed: {err}");
            None
        }
    }
}

/// 把事实摘要上送数据面（走 TCP uplink，与日志/指标同一条连接）。
///
/// 返回 `Ok(true)` = 这次真发出去了；`Ok(false)` = 还在最小间隔内，或缺 `agent_id`。
///
/// **为什么不再走控制面 HTTP**：事实只有**一条上行通道** —— agentd → 数据面（`OBSFACT:` 帧），
/// 网关与中心各自订阅。控制面那条直报端点（`POST /api/v1/agent/facts`）已废弃，见
/// `doc/design/center/agent-work-delivery-plan.md` §4.1。两套通道就是两套连接、两套节流、
/// 两套失败模式。
///
/// **不做本地判重**：判重归网关（它从收到的内容自己重算摘要，判定 `accepted`/`duplicate`）。
/// 这里只按最小间隔节流 —— agentd 必须**无条件周期全量**上送，否则本地算法或状态一退化
/// 就会静默停报，而且没有任何一层能发现。多发一次的代价是流量，停报的代价是视图停滞。
async fn report_fact_summary(
    sink: &mut TelemetryRecordSink,
    config: &AgentConfig,
    state_dir: &Path,
    summary: &fact_summary::FactSummaryDraft,
    next_seq: &mut u64,
    global_seq_path: &Path,
) -> RuntimeResult<bool> {
    // 这里**不**再检查控制面端点与凭据：帧走的是数据面，身份校验尚未落地
    // （见计划 §9 风险行）。缺 agent_id 时仍然跳过 —— 它是信封里的自称。
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return Ok(false);
    };

    let state_path = fact_report::path_for(state_dir);
    // 读到坏 JSON 时 fail-open —— 当作「没有历史状态」继续（`None`）。
    // 否则 load 每次都 Err，摘要永远发不出去，且文件也永远不会被重写修复；
    // 成功送达后会重写该文件，自愈。
    let previous = match fact_report::load_async(&state_path).await {
        Ok(state) => state,
        Err(err) => {
            eprintln!(
                "wist-agentd fact summary report: ignoring unreadable state {}: {err}",
                state_path.display()
            );
            None
        }
    };
    let now_ms = now_ts_ms();
    if previous
        .as_ref()
        .is_some_and(|state| within_fact_report_min_interval(state.last_attempt_at_ms, now_ms))
    {
        return Ok(false);
    }

    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    let reported_at = now_rfc3339();
    // 摘要只作**声明**：网关会自己重算一遍并比对，不一致时记告警。
    // 带它出去的价值是当版本金丝雀 —— 两侧实现同源，所以正常永远一致。
    let digest = summary.content_digest();
    let report = ReportAgentFactSummary::new_agent_facts(
        format!("fact_{agent_id}_{now_ms}"),
        agent_id.to_string(),
        instance_id.to_string(),
        digest,
        summary.revision,
        summary.observed_at.clone(),
        summary.os.clone(),
        summary.arch.clone(),
        summary.process_count,
        summary.process_executables.clone(),
        summary.packages.clone(),
        summary.listen_ports.clone(),
        reported_at.clone(),
    )
    // 主机标识与网卡地址：**留痕/展示**，不进内容摘要（见 `ReportAgentFactSummary` 的注释）。
    .with_display(
        summary.host_id.clone(),
        summary.host_name.clone(),
        summary.network_addresses.clone(),
    );
    // 节流键用「上次尝试」而不是「上次成功」。真正发送前先落一次盘，
    // 这样即使这次失败，下一个 tick 也在下限内，不会每 3s 重试一次（数据面宕机时尤其重要）。
    // 发起前的写入失败只记日志、**不阻止发送** —— 至多退化成不节流，好过不发。
    // 取舍：下限本身 ≥5 分钟，所以最坏只是「每 5 分钟多一次写盘」，完全可接受。
    let attempt_state = fact_report::FactReportState {
        last_attempt_at_ms: now_ms,
    };
    if let Err(err) = fact_report::store_async(&state_path, &attempt_state).await {
        eprintln!("wist-agentd fact summary report: failed to record attempt: {err}");
    }

    // 正文是**契约对象原样**（`ReportAgentFactSummary`）：订阅端按 `wist-contracts` 解析，
    // 不做字段建模。
    let body = serde_json::to_vec(&report)
        .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err))?;
    // 取号 → 先持久化高水位 → 再发送（与日志/指标同一个 seq 空间；
    // `(agent, seq)` 是数据面的去重键，跳号可以、撞号不行）。
    let seq = *next_seq;
    *next_seq += 1;
    log_seq_state::store_async(global_seq_path, *next_seq).await?;
    let envelope = DataFrame::new(agent_id, reported_at, seq);
    sink.write_fact(&envelope, &body).await?;
    Ok(true)
}

/// 是否还在事实摘要上送的最小间隔内（即应当跳过）。
///
/// 节流必须 **fail-open**：宁可多发一次，不可因为时钟问题永远不发。
/// 因此时间戳为 0（没有历史尝试）或晚于 `now_ms`（墙钟回拨 / 状态损坏）
/// 都判为**已到期**（放行）；只有真正落在下限窗口内的才拦截。
fn within_fact_report_min_interval(last_attempt_at_ms: i64, now_ms: i64) -> bool {
    last_attempt_at_ms != 0
        && last_attempt_at_ms <= now_ms
        && now_ms.saturating_sub(last_attempt_at_ms) < FACT_REPORT_MIN_INTERVAL_MS
}

/// 拉取平台发布的发现方向**策略表**（尽力而为，失败只进日志）。
///
/// 返回 `None` = 这次没拿到表，且**全部**情况都归结为同一种处理：
///   - 没配端点 / 没配 bearer / 没配 agent_id（未入网，同 `report_fact_summary` 的早退）；
///   - 网关回 503（契约里的「网关未配表」语义，不是错误）；
///   - 传输失败或响应体坏 JSON。
///
/// 为什么返回 `Option` 而不是 `RuntimeResult`（紧邻的 `report_fact_summary` 是后者）：
/// 它真的没有失败路径 —— 每一条错都归到「没拿到表」并只进日志。用一个带 `Err` 的签名，
/// 会让调用方写下一个永远走不到的 `Err` 分支，并让读代码的人以为存在 fatal 情形。
///
/// 关键取舍：**这些都不是致命错误**。agentd 必须继续采集 —— 拉不到表就用自己的内建默认周期
/// （与策展值同值），行为与策略表没引入之前一致。把拉取失败变成 fatal 会让「网关没配表」
/// 直接等于「agent 不干活」。
async fn fetch_discovery_policies(config: &AgentConfig) -> Option<DiscoveryAspectPolicySet> {
    // 返回 `Option` 后这三行可以写成 `?`：语义与之前的 `let ... else { return None }` 一致，
    // 且不用为每一步重复一遍早退。
    let endpoint = config.control_plane.endpoint.as_deref()?;
    let bearer_token = config.control_plane.bearer_token.as_deref()?;
    let agent_id = config.agent.agent_id.as_deref()?;

    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    let request = PollDiscoveryPolicies {
        api_version: wist_contracts::API_VERSION_V1.to_string(),
        kind: POLL_DISCOVERY_POLICIES_KIND.to_string(),
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        requested_at: now_rfc3339(),
    };
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("wist-agentd discovery policy fetch: failed to build client: {err}");
            return None;
        }
    };
    let url = format!(
        "{}/api/v1/agent/discovery-policies:poll",
        endpoint.trim_end_matches('/')
    );

    match client
        .post(&url)
        // 这条路径在主循环里，必须自己封顶，不能吃掉 tick。
        .timeout(DISCOVERY_POLICY_FETCH_TIMEOUT)
        .bearer_auth(bearer_token)
        .json(&request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<DiscoveryPoliciesReturned>().await {
                Ok(returned) => Some(DiscoveryAspectPolicySet::new(
                    returned.policy_version,
                    returned.published_at,
                    returned.policies,
                )),
                Err(err) => {
                    eprintln!(
                        "wist-agentd discovery policy fetch failed: invalid response from {endpoint}: {err}"
                    );
                    None
                }
            }
        }
        Ok(response) => {
            eprintln!(
                "wist-agentd discovery policy fetch failed: HTTP {} from {}",
                response.status(),
                endpoint
            );
            None
        }
        Err(err) => {
            eprintln!("wist-agentd discovery policy fetch failed: {err}");
            None
        }
    }
}

use metrics_support::{
    emit_metrics_failure, emit_metrics_failures, emit_metrics_tick,
    failure_signatures as metrics_failure_signatures,
    filter_new_failures as filter_new_metrics_failures, process_metrics_tick, write_metrics_uplink,
};
use recovery_support::recover_incomplete_executions_impl_async;
use runtime_state_support::{
    count_reporting_entries_async, count_running_entries_async, emit_telemetry_failure,
    emit_telemetry_failures, emit_work_state_notification, emit_work_state_notifications,
    failure_signatures, filter_new_failures, instance_id, paused_input_signatures,
    work_state_changes,
};
use telemetry_support::{
    TelemetryWorkState, WorkState, build_telemetry_sink, invalid_output_tick,
    process_telemetry_inputs,
};

fn to_agent_work_state_changes(changes: &[TelemetryWorkState]) -> Vec<AgentWorkStateChange> {
    changes
        .iter()
        .map(|change| AgentWorkStateChange {
            input_id: change.input_id.clone(),
            state: match change.state {
                WorkState::Paused => AgentWorkState::Paused,
                WorkState::Resumed => AgentWorkState::Resumed,
            },
            reason: change.reason.clone(),
            at: change.at.clone(),
        })
        .collect()
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Pipeline")]
pub struct DaemonLoop<'a> {
    pub config: &'a AgentConfig,
    pub exec_bin: &'a Path,
}

pub async fn run_forever_async(loop_ctx: DaemonLoop<'_>) -> RuntimeResult<()> {
    // 运行时**跨 tick 活着**：观测频率的调度记忆就在它里面（内存态，不落盘）。
    let mut discovery_runtime = DiscoveryRuntime::new(discovery_probes(loop_ctx.config));
    // 工作授权跨 tick 活着：`acked_plan_version` 就在里面，它决定
    // “这一版我确认过了，不用每 30s 重复确认”。
    //
    // 启动时先用**上次落盘的留痕**恢复（`state/work_grant.json`）：它不是期望状态的
    // 第二份真相，只是「最后已知的那一份」，好处是把确认记忆一起带回来 ——
    // 重启后不会重复确认，页面也不会先闪一次「从未确认」。
    let work_record_path = work_grant::path_for(Path::new(&loop_ctx.config.paths.state_dir));
    let mut work_runtime = match work_grant::load_async(&work_record_path).await {
        Ok(Some(record)) => {
            let restored = AppliedWorkGrant::restore(&record);
            eprintln!(
                "event=WorkGrantRestored path={} sequence={} applied_at={} {} note=\"以网关为准；仅在拉不到快照时用这份\"",
                work_record_path.display(),
                restored.sequence(),
                record.applied_at,
                restored.summary()
            );
            restored
        }
        Ok(None) => AppliedWorkGrant::default(),
        Err(err) => {
            // 一份留痕不该有让采集停下的权力：读不动就记一行、当没有。
            eprintln!(
                "wist-agentd work grant state: ignoring unreadable {}: {err}",
                work_record_path.display()
            );
            AppliedWorkGrant::default()
        }
    };
    let mut last_work_fetch: Option<Instant> = None;
    let mut last_metrics_uplink: Option<Instant> = None;
    let mut previous_telemetry_failures = BTreeSet::new();
    let mut previous_metrics_failures = BTreeSet::new();
    let mut previous_telemetry_paused = BTreeSet::new();
    let mut last_report_at = Instant::now();
    let mut last_cpu_sample = cpu_ticks().map(|ticks| CpuSample {
        ticks,
        at: Instant::now(),
    });
    let mut last_latency_ms: Option<u64> = None;
    let mut pending_work_state_changes: Vec<TelemetryWorkState> = Vec::new();
    loop {
        // 到达拉取间隔就拉一次策略表并应用（启动首轮即拉）。必须在 refresh_due 之前，
        // 这样本轮采集就用上新周期。
        refresh_discovery_policy(loop_ctx.config, &mut discovery_runtime).await;
        // 工作授权同样在采集之前应用：本轮就按新的授权采（或停）。
        refresh_work_grant(
            loop_ctx.config,
            &mut work_runtime,
            &mut last_work_fetch,
            &work_record_path,
        )
        .await;
        // 指标上送要不要发生在**这里**决定（而不是深入采集内部）：
        //   没授权 = 不上送（不做任务工作的 Agent 不该顺手送指标）；
        //   授权了但没到周期 = 本轮跳过，不算失败。
        let send_metrics = match work_runtime.metrics_interval() {
            None => false,
            Some(interval) => match last_metrics_uplink {
                None => true,
                Some(at) => at.elapsed() >= interval,
            },
        };
        if send_metrics {
            // 记“尝试”而不是“成功”：与策略表拉取同一取舍 —— 失败也要被周期节流，
            // 否则输出端坏掉时会每 tick（3s）重试并刷满日志。
            last_metrics_uplink = Some(Instant::now());
        }
        let (snapshot, changes) = run_once_with_failure_cache(
            &loop_ctx,
            Some(&mut previous_telemetry_failures),
            Some(&mut previous_metrics_failures),
            Some(&mut previous_telemetry_paused),
            &mut discovery_runtime,
            &work_runtime,
            send_metrics,
        )
        .await?;
        pending_work_state_changes.extend(changes);
        emit(&snapshot);
        if last_report_at.elapsed() >= STATUS_REPORT_INTERVAL {
            last_report_at = Instant::now();
            let now = Instant::now();
            let cpu_percent = last_cpu_sample
                .as_ref()
                .and_then(|sample| cpu_percent_since(sample, now, ticks_per_sec()));
            if let Some(ticks) = cpu_ticks() {
                last_cpu_sample = Some(CpuSample { ticks, at: now });
            }
            let changes = std::mem::take(&mut pending_work_state_changes);
            let changes = if changes.is_empty() {
                None
            } else {
                Some(to_agent_work_state_changes(&changes))
            };
            if let Some(latency) = report_status_to_control_plane(
                loop_ctx.config,
                cpu_percent,
                last_latency_ms,
                changes,
                // 还没拿到策略表时为 None（网关据此区分「在用内建默认周期」）。
                discovery_runtime.policy_version(),
            )
            .await
            {
                last_latency_ms = Some(latency);
            }
        }
        tokio::time::sleep(TICK_INTERVAL).await;
    }
}

pub async fn run_once_async(loop_ctx: &DaemonLoop<'_>) -> RuntimeResult<RuntimeHealthSnapshot> {
    run_once_with_work_async(loop_ctx, &AppliedWorkGrant::default()).await
}

async fn run_once_with_failure_cache(
    loop_ctx: &DaemonLoop<'_>,
    previous_telemetry_failures: Option<&mut BTreeSet<String>>,
    previous_metrics_failures: Option<&mut BTreeSet<String>>,
    previous_telemetry_paused: Option<&mut BTreeSet<String>>,
    discovery_runtime: &mut DiscoveryRuntime,
    // 当前持有的工作授权：日志任务由它折算而来，指标上送由它开关。
    work: &AppliedWorkGrant,
    // 本轮要不要上送指标（由调用方按授权与周期定；一次性路径按授权定）。
    send_metrics: bool,
) -> RuntimeResult<(RuntimeHealthSnapshot, Vec<TelemetryWorkState>)> {
    let run_dir = Path::new(&loop_ctx.config.paths.run_dir);
    let state_dir = Path::new(&loop_ctx.config.paths.state_dir);
    let instance_id = instance_id(loop_ctx.config);
    let agent_id = loop_ctx
        .config
        .agent
        .agent_id
        .as_deref()
        .unwrap_or("unknown");
    let (discovery, fact_summary) = refresh_discovery_snapshot(state_dir, discovery_runtime).await;
    let metrics_tick = process_metrics_tick(state_dir);
    emit_metrics_tick(&metrics_tick);
    if let Some(previous) = previous_metrics_failures {
        for failure in filter_new_metrics_failures(&metrics_tick.failures, previous) {
            emit_metrics_failure(failure);
        }
        *previous = metrics_failure_signatures(&metrics_tick.failures);
    } else {
        emit_metrics_failures(&metrics_tick.failures);
    }
    let global_seq_path = log_seq_state::path_for(state_dir);
    let mut next_seq = log_seq_state::load_or_default_async(&global_seq_path)
        .await
        .unwrap_or(0);
    let telemetry_tick = match build_telemetry_sink(loop_ctx.config) {
        Ok(mut sink) => {
            // 指标优先：先上送指标帧（与日志共用同一 sink/连接 + 同一个全局 seq），再处理日志。
            //
            // 但只在**授权允许且到了周期**时才发：没有指标工作就没有指标上送，
            // 这是“不做任务工作的 Agent”在数据面上的具体含义。
            if let Some(snapshot) = metrics_tick.snapshot.as_ref()
                && send_metrics
            {
                match write_metrics_uplink(
                    &mut sink,
                    agent_id,
                    snapshot,
                    &mut next_seq,
                    &global_seq_path,
                )
                .await
                {
                    // 成功也记一行：否则“指标到底发没发”只能靠间接迹象去猜，
                    // 而运维问的第一个问题往往是这个（尤其是刚授权完）。
                    Ok(()) => eprintln!(
                        "event=MetricsUplinkSent agent_id={agent_id} targets={}",
                        snapshot.total_targets
                    ),
                    Err(err) => eprintln!("wist-agentd metrics uplink failed: {err}"),
                }
            }
            // 事实摘要在**指标之后**发：同样共用这条连接与全局 `seq`，只是帧标记不同。
            match report_fact_summary(
                &mut sink,
                loop_ctx.config,
                state_dir,
                &fact_summary,
                &mut next_seq,
                &global_seq_path,
            )
            .await
            {
                Ok(true) => eprintln!(
                    "event=FactSummaryReported digest={} processes={} executables={} ports={}",
                    fact_summary.content_digest(),
                    fact_summary.process_count,
                    fact_summary.process_executables.len(),
                    fact_summary.listen_ports.len()
                ),
                Ok(false) => {}
                Err(err) => eprintln!("wist-agentd fact summary uplink failed: {err}"),
            }
            process_telemetry_inputs(loop_ctx.config, work, &mut sink, &mut next_seq).await
        }
        Err(err) => invalid_output_tick(loop_ctx.config, work, err.to_string()),
    };
    if let Some(previous) = previous_telemetry_failures {
        for failure in filter_new_failures(&telemetry_tick.failures, previous) {
            emit_telemetry_failure(failure);
        }
        *previous = failure_signatures(&telemetry_tick.failures);
    } else {
        emit_telemetry_failures(&telemetry_tick.failures);
    }
    let current_paused = paused_input_signatures(&telemetry_tick.notifications);
    let tick_changes = if let Some(previous) = previous_telemetry_paused {
        let changes = work_state_changes(previous, &telemetry_tick.notifications, &current_paused);
        for change in &changes {
            emit_work_state_notification(change);
        }
        *previous = current_paused.clone();
        changes
    } else {
        emit_work_state_notifications(&telemetry_tick.notifications);
        Vec::new()
    };
    let telemetry_active = telemetry_tick.is_active();
    let metrics_active = metrics_tick.is_active();

    recover_incomplete_executions_impl_async(state_dir, &instance_id).await?;

    // Step 0: export unified-envelope output alongside existing cache files
    let export_source = ExporterSource::new(agent_id, &instance_id);
    exporter::export_all_async(state_dir, &export_source).await;

    let drained = scheduler::drain_next_async(&scheduler::DrainRequest {
        run_dir: run_dir.to_path_buf(),
        state_dir: state_dir.to_path_buf(),
        exec_bin: loop_ctx.exec_bin.to_path_buf(),
        instance_id,
        cancel_grace_ms: loop_ctx.config.execution.cancel_grace_ms,
        stdout_limit_bytes: loop_ctx.config.execution.default_stdout_limit_bytes,
        stderr_limit_bytes: loop_ctx.config.execution.default_stderr_limit_bytes,
    })
    .await?;

    let queue =
        execution_queue::load_or_default_async(&execution_queue::path_for(state_dir)).await?;
    let running_count = count_running_entries_async(state_dir).await?;
    let reporting_count = count_reporting_entries_async(state_dir).await?;
    let metrics = metrics_tick.health_snapshot();
    let health = RuntimeHealthSnapshot {
        state: if telemetry_active
            || metrics_active
            || drained
            || running_count > 0
            || reporting_count > 0
            || !queue.items.is_empty()
        {
            DaemonWorkState::Active
        } else {
            DaemonWorkState::Idle
        },
        queue_depth: queue.items.len(),
        running_count,
        reporting_count,
        paused_inputs: current_paused.into_iter().collect(),
        discovery: discovery.snapshot,
        metrics,
        updated_at: now_rfc3339(),
    };

    let runtime_path = agent_runtime::path_for(state_dir);
    let mut runtime_state = agent_runtime::load_or_default_async(&runtime_path).await?;
    runtime_state.updated_at = health.updated_at.clone();
    agent_runtime::store_async(&runtime_path, &runtime_state).await?;

    Ok((health, tick_changes))
}

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Reporting", module = "Reporting.Pipeline")]
struct DiscoveryHealth {
    snapshot: DiscoveryHealthSnapshot,
}

/// 若到了拉取间隔，拉取并应用发现方向策略表。
///
/// 为什么放在主循环而不是 `refresh_discovery_snapshot`：后者一次性路径（`run_once`）也会走，
/// 而一次性路径是 `refresh_all`（全量、**忽略周期**），策略表对它没有意义 —— 在那儿拉
/// 等于白付一次网络往返（最坏 `DISCOVERY_POLICY_FETCH_TIMEOUT`）。常驻循环才有「下一 tick」，
/// 策略也才有落点。计时状态随 `DiscoveryRuntime` 跨 tick（见该字段的注释）。
async fn refresh_discovery_policy(config: &AgentConfig, runtime: &mut DiscoveryRuntime) {
    let now = Instant::now();
    if !runtime.policy_fetch_due(now, DISCOVERY_POLICY_FETCH_MIN_INTERVAL) {
        return;
    }
    // 先记「尝试」再发：失败也要被最小间隔节流，否则网关宕机时会每 tick（3s）重试。
    // 与事实摘要同一取舍（记尝试，不记成功）。
    runtime.record_policy_fetch_attempt(now);
    // 拿到就应用；没拿到（未入网 / 网关联 503 / 出错）则**保留上次应用的表**，什么都不改 ——
    // 失败清空已应用表会让 agent 从「有策略」倒退成「无策略」，与「失败不致命」相悖。
    if let Some(set) = fetch_discovery_policies(config).await {
        let policy_version = set.policy_version;
        let aspects = set.policies.len();
        // 版本没变就不吭声：策略是慢变量，每 5 分钟都会重新拉到同一版，
        // 每次都打日志就是每 5 分钟一行噪声。
        if runtime.apply_discovery_policy(set) {
            // 夹取/弃用过的周期一并带出来：这不是错误，但静默夹取会把
            // 「网关发布了一份坏表」伪装成一切正常。
            let adjustments = runtime.policy_adjustments_summary();
            let adjustments = if adjustments.is_empty() {
                String::new()
            } else {
                format!(" adjustments=[{adjustments}]")
            };
            eprintln!(
                "event=DiscoveryPolicyApplied policy_version={policy_version} aspects={aspects}{adjustments}"
            );
        }
    }
}

/// 拉取并应用工作授权（启动首轮即拉，之后按最小间隔节流）。
///
/// 与发现策略表的差别：这里**会**回报确认。确认只对“真正应用了的工作”发（见
/// `AppliedWorkGrant::apply`），回报成功才记下版本 —— 否则下一轮会重复回报。
async fn refresh_work_grant(
    config: &AgentConfig,
    runtime: &mut AppliedWorkGrant,
    last_fetch: &mut Option<Instant>,
    record_path: &Path,
) {
    let now = Instant::now();
    if let Some(at) = *last_fetch
        && at.elapsed() < Duration::from_millis(WORK_FETCH_MIN_INTERVAL_MS as u64)
    {
        return;
    }
    // 先记“尝试”再发：失败也要被节流，否则网关宕机时会每 tick（3s）重试。
    *last_fetch = Some(now);
    let Some(grant) = fetch_work_grant(config, runtime.sequence()).await else {
        // 拿不到就**保留上次应用的工作**：与策略表同理，失败清空会让 agent 从
        // 「有活干」倒退成「什么都没授权」—— 那是把网络抖动放大成采集中断。
        return;
    };
    let received_at = now_rfc3339();
    let outcome = runtime.apply(&grant);
    if outcome.changed {
        eprintln!(
            "event=WorkGrantApplied sequence={} {}",
            runtime.sequence(),
            runtime.summary()
        );
    }
    for (work_id, detail) in &outcome.broken {
        // 参数读不懂就不确认：网关那边“期望版本一直没被确认”正是这条坏参数真被看见的形态。
        eprintln!("event=WorkSpecUnparsable work_id={work_id} detail={detail}");
    }
    for unit in &outcome.unsupported {
        eprintln!(
            "event=WorkUnitUnsupported work_id={} unit_id={} detail={}",
            unit.work_id, unit.unit_id, unit.detail
        );
    }
    for work_id in &outcome.stopped {
        eprintln!("event=WorkStopped work_id={work_id}");
    }
    for work_id in &outcome.started {
        eprintln!("event=WorkStarted work_id={work_id}");
    }
    for work_id in &outcome.unexecutable_one_shot {
        // 收到了但不执行：说清楚，否则网关页面上只剩一个无法解释的“派了没确认”。
        eprintln!(
            "event=OneShotWorkNotExecuted work_id={work_id} detail=\"agentd 尚未实现一次性工作的执行\""
        );
    }
    let mut acked_anything = false;
    for (work_id, plan_version) in outcome.to_ack {
        if ack_work(config, &work_id, plan_version).await {
            runtime.mark_acked(&work_id, plan_version);
            acked_anything = true;
        } else {
            eprintln!("event=WorkAckFailed work_id={work_id} plan_version={plan_version}");
        }
    }
    // 有变化（含“确认了某个版本”）才落盘：留痕是给人看的，不必每 30s 重写一遍。
    // 写失败只记一行日志：一份留痕不该影响采集本身。
    if (outcome.changed || acked_anything)
        && let Some(record) = runtime.record(&received_at, &now_rfc3339())
        && let Err(err) = work_grant::store_async(record_path, &record).await
    {
        eprintln!(
            "wist-agentd work grant state: failed to write {}: {err}",
            record_path.display()
        );
    }
}

async fn refresh_discovery_snapshot(
    state_dir: &Path,
    runtime: &mut DiscoveryRuntime,
) -> (DiscoveryHealth, fact_summary::FactSummaryDraft) {
    let (cached, cache_load_failure) = runtime.load_from_state_dir_async(state_dir).await;
    let (cached_meta, meta_load_failure) = runtime.load_meta_from_state_dir_async(state_dir).await;
    // 按各探针的 `refresh_interval()` 调度：只刷到期的，未到期的沿用上次输出。
    // 这是“基础观测频率”真的生效的地方 —— 在此之前各探针声明的周期是死代码，
    // 运行时每 tick（3s）把所有探针全刷一遍（含 906 个进程的枚举）。
    let mut result = runtime
        .refresh_due_and_store_async(state_dir, Instant::now())
        .await;
    let candidates = planner_bridge::build_collection_candidates(&result.persisted_snapshot);
    let host_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.collection_kind == "host_metrics")
        .cloned()
        .collect();
    let process_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.collection_kind == "process_metrics")
        .cloned()
        .collect();
    let container_candidates: Vec<_> = candidates
        .iter()
        .filter(|candidate| candidate.collection_kind == "container_metrics")
        .cloned()
        .collect();
    let planner_store_result: io::Result<()> = async {
        planner_candidates::store_async(
            &planner_candidates::host_metrics_path_for(state_dir),
            &host_candidates,
        )
        .await?;
        planner_candidates::store_async(
            &planner_candidates::process_metrics_path_for(state_dir),
            &process_candidates,
        )
        .await?;
        planner_candidates::store_async(
            &planner_candidates::container_metrics_path_for(state_dir),
            &container_candidates,
        )
        .await
    }
    .await;
    if let Err(err) = planner_store_result {
        result.last_error = Some(format!("planner candidate store failed: {err}"));
        result.store_failure = Some(crate::discovery::runtime::DiscoveryStoreFailure {
            phase: "planner_store",
            detail: format!("planner candidate store failed: {err}"),
        });
    } else {
        let target_view_result: io::Result<()> = async {
            let view = target_view::build_metrics_target_view_async(
                state_dir,
                &result.persisted_snapshot.generated_at,
            )
            .await?;
            target_view::store_async(&target_view::path_for(state_dir), &view).await
        }
        .await;
        if let Err(err) = target_view_result {
            result.last_error = Some(format!("metrics target view store failed: {err}"));
            result.store_failure = Some(crate::discovery::runtime::DiscoveryStoreFailure {
                phase: "metrics_target_view_store",
                detail: format!("metrics target view store failed: {err}"),
            });
        }
    }
    let probes = build_probe_health(
        &result,
        cache_load_failure.as_ref(),
        meta_load_failure.as_ref(),
    );
    emit_discovery_refresh(&result, &probes);

    // 事实摘要**在这里压缩，不在这里上送**：摘要要从快照算（快照就在手上，不必再读一遍
    // discovery 缓存再解析一次），但上行走 TCP uplink，而 sink 在调用方（主 tick）才建。
    // 所以带回主 tick，与指标一起发 —— 同一条连接、同一个全局 `seq`。
    let fact_summary = fact_summary::build_summary(&result.persisted_snapshot);

    let readiness = if result.used_cached_snapshot {
        DiscoveryReadiness::ReadyWithStaleSnapshot
    } else if result.had_successful_refresh {
        DiscoveryReadiness::Ready
    } else if cached.is_some() {
        DiscoveryReadiness::ReadyWithStaleSnapshot
    } else {
        DiscoveryReadiness::NotReady
    };

    let health = DiscoveryHealth {
        snapshot: DiscoveryHealthSnapshot {
            readiness,
            cached_snapshot_loaded: cached.is_some(),
            used_cached_snapshot: result.used_cached_snapshot,
            resource_count: result.persisted_snapshot.resources.len(),
            target_count: result.persisted_snapshot.targets.len(),
            failure_count: probes
                .iter()
                .filter(|probe| probe.status == "failed")
                .count(),
            last_success_at: result
                .last_success_at
                .clone()
                .or_else(|| cached_meta.and_then(|meta| meta.last_success_at)),
            updated_at: result.refreshed_snapshot.generated_at.clone(),
            probes,
        },
    };
    (health, fact_summary)
}

fn discovery_probes(config: &AgentConfig) -> Vec<Box<dyn DiscoveryProbe + Send + Sync>> {
    let mut probes: Vec<Box<dyn DiscoveryProbe + Send + Sync>> = Vec::new();
    if config.discovery.host_enabled {
        probes.push(Box::new(HostDiscoveryProbe));
    }
    if config.discovery.network_enabled {
        probes.push(Box::new(NetworkDiscoveryProbe));
    }
    if config.discovery.endpoint_enabled {
        probes.push(Box::new(EndpointDiscoveryProbe));
    }
    if config.discovery.process_enabled {
        probes.push(Box::new(ProcessDiscoveryProbe));
    }
    if config.discovery.container_enabled {
        probes.push(Box::new(ContainerDiscoveryProbe));
    }
    probes
}

fn build_probe_health(
    result: &DiscoveryRefreshResult,
    cache_load_failure: Option<&crate::discovery::cache::DiscoveryCacheLoadFailure>,
    meta_load_failure: Option<&crate::discovery::cache::DiscoveryCacheLoadFailure>,
) -> Vec<DiscoveryProbeHealth> {
    let mut probes = Vec::new();
    let mut seen_failures = std::collections::BTreeSet::new();

    for successful in &result.successful_probes {
        probes.push(DiscoveryProbeHealth {
            source: successful.source.as_str().to_string(),
            probe: successful.probe.clone(),
            phase: "refresh".to_string(),
            status: "ok".to_string(),
            resource_count: successful.resource_count,
            target_count: successful.target_count,
            error: None,
        });
    }

    for error in &result.errors {
        let source = error
            .context_metadata()
            .get_str("source")
            .unwrap_or("unknown")
            .to_string();
        let probe = error
            .context_metadata()
            .get_str("probe")
            .unwrap_or("unknown")
            .to_string();
        let phase = "refresh".to_string();
        let detail = error.detail().clone().unwrap_or_else(|| error.to_string());
        if seen_failures.insert((source.clone(), probe.clone(), phase.clone(), detail.clone())) {
            probes.push(DiscoveryProbeHealth {
                source,
                probe,
                phase,
                status: "failed".to_string(),
                resource_count: 0,
                target_count: 0,
                error: Some(detail),
            });
        }
    }

    if let Some(store_failure) = &result.store_failure {
        let source = "cache".to_string();
        let probe = "discovery".to_string();
        let phase = store_failure.phase.to_string();
        let detail = store_failure.detail.clone();
        if seen_failures.insert((source.clone(), probe.clone(), phase.clone(), detail.clone())) {
            probes.push(DiscoveryProbeHealth {
                source,
                probe,
                phase,
                status: "failed".to_string(),
                resource_count: 0,
                target_count: 0,
                error: Some(detail),
            });
        }
    }

    for load_failure in [cache_load_failure, meta_load_failure]
        .into_iter()
        .flatten()
    {
        let source = "cache".to_string();
        let probe = "discovery".to_string();
        let phase = load_failure.phase.to_string();
        let detail = load_failure.detail.clone();
        if seen_failures.insert((source.clone(), probe.clone(), phase.clone(), detail.clone())) {
            probes.push(DiscoveryProbeHealth {
                source,
                probe,
                phase,
                status: "failed".to_string(),
                resource_count: 0,
                target_count: 0,
                error: Some(detail),
            });
        }
    }

    probes
}

fn emit_discovery_refresh(result: &DiscoveryRefreshResult, probes: &[DiscoveryProbeHealth]) {
    eprintln!(
        "event=DiscoveryRefreshed revision={} persisted_revision={} resources={} targets={} failures={} used_cached_snapshot={} last_success_at={}",
        result.refreshed_snapshot.revision,
        result.persisted_snapshot.revision,
        result.persisted_snapshot.resources.len(),
        result.persisted_snapshot.targets.len(),
        result.errors.len(),
        result.used_cached_snapshot,
        result.last_success_at.as_deref().unwrap_or("-"),
    );

    for probe in probes {
        if probe.status == "failed" {
            eprintln!(
                "event=DiscoveryRefreshFailed source={} probe={} phase={} error={}",
                probe.source,
                probe.probe,
                probe.phase,
                probe.error.as_deref().unwrap_or("-"),
            );
        }
    }
}

pub fn run_once(loop_ctx: &DaemonLoop<'_>) -> RuntimeResult<RuntimeHealthSnapshot> {
    run_once_with_work(loop_ctx, &AppliedWorkGrant::default())
}

/// 跑一次，并指定当前持有的工作授权。
///
/// 存在的理由：工作授权决定了采集任务与指标上送，而一次性路径**不拉工作** ——
/// 要把“有授权时应该发生什么”测出来（或将来做只跑一轮的 `--once`），就得能把它传进来。
/// `run_once` 传的是“没有授权”，也就是一个不做任务工作的 Agent。
pub fn run_once_with_work(
    loop_ctx: &DaemonLoop<'_>,
    work: &AppliedWorkGrant,
) -> RuntimeResult<RuntimeHealthSnapshot> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(run_once_with_work_async(loop_ctx, work))
}

async fn run_once_with_work_async(
    loop_ctx: &DaemonLoop<'_>,
    work: &AppliedWorkGrant,
) -> RuntimeResult<RuntimeHealthSnapshot> {
    // 一次性路径：运行时只活这一次，所以每个探针都是“没过” → 全量刷新（与旧语义一致）。
    let mut discovery_runtime = DiscoveryRuntime::new(discovery_probes(loop_ctx.config));
    // 只跑一轮，所以“到没到周期”没有意义：授权允许就发。
    let send_metrics = work.metrics_interval().is_some();
    run_once_with_failure_cache(
        loop_ctx,
        None,
        None,
        None,
        &mut discovery_runtime,
        work,
        send_metrics,
    )
    .await
    .map(|(snapshot, _)| snapshot)
}

pub fn recover_incomplete_executions(state_dir: &Path, instance_id: &str) -> RuntimeResult<()> {
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?
        .block_on(recover_incomplete_executions_impl_async(
            state_dir,
            instance_id,
        ))
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use wist_contracts::agent_config::{
        AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };

    use crate::telemetry::warp_parse::{FileRecordSink, TcpFraming, TcpRecordSink};

    fn test_config() -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: Some("agent-x".to_string()),
                environment_id: None,
                instance_name: Some("instance-x".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: Some("http://127.0.0.1:1".to_string()),
                enrollment_token: None,
                credential_request: None,
                credential_id: None,
                bearer_token: Some("wic_test_token".to_string()),
                credential_expires_at: None,
                tls_mode: None,
                trust_bundle: None,
                auth_mode: None,
            },
            PathsSection {
                root_dir: ".".to_string(),
                run_dir: "run".to_string(),
                state_dir: "state".to_string(),
                log_dir: "log".to_string(),
            },
            ExecutionSection {
                max_running_actions: 1,
                cancel_grace_ms: 5_000,
                default_stdout_limit_bytes: 1,
                default_stderr_limit_bytes: 1,
            },
        )
    }

    async fn read_http_request(socket: &mut tokio::net::TcpStream) -> String {
        let mut request_bytes = Vec::new();
        loop {
            let mut chunk = [0u8; 1024];
            let read = socket.read(&mut chunk).await.expect("read");
            if read == 0 {
                break;
            }
            request_bytes.extend_from_slice(&chunk[..read]);
            let Some(header_end) = request_bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&request_bytes[..header_end]);
            let content_length = headers
                .lines()
                .find_map(|line| {
                    let (key, value) = line.split_once(':')?;
                    if key.trim().eq_ignore_ascii_case("content-length") {
                        value.trim().parse::<usize>().ok()
                    } else {
                        None
                    }
                })
                .unwrap_or(0);
            if request_bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8_lossy(&request_bytes).into_owned()
    }

    #[tokio::test]
    async fn report_status_posts_agent_status_report_with_metrics() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(request.contains("/api/v1/agent/status"));
            assert!(
                request
                    .to_lowercase()
                    .contains("authorization: bearer wic_test_token")
            );
            assert!(request.contains("\"agent_id\":\"agent-x\""));
            assert!(request.contains("\"memory_bytes\":"));
            assert!(request.contains("\"cpu_percent\":"));
            assert!(request.contains("\"admin_latency_ms\":"));
            assert!(request.contains("\"work_state_changes\":null"));
            // 本机实际生效的策略版本随状态上报一起上去（`null` = 还没拉到策略表）。
            assert!(request.contains("\"discovery_policy_version\":7"));
            let response =
                "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let latency =
            report_status_to_control_plane(&config, Some(12.5), Some(3), None, Some(7)).await;
        server.await.expect("server task");
        assert!(latency.is_some());
    }

    #[tokio::test]
    async fn report_status_sends_a_null_policy_version_before_any_policy_arrives() {
        // 没拿到策略表时必须显式送 null，而不是省略字段更不能送 0：
        // 网关那边 0 是「确实生效了第 0 版」，混同会让「谁还没生效」看错。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(
                request.contains("\"discovery_policy_version\":null"),
                "{request}"
            );
            let response =
                "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let latency = report_status_to_control_plane(&config, None, None, None, None).await;
        server.await.expect("server task");
        assert!(latency.is_some());
    }

    // ── 事实摘要上送 ─────────────────────────────────────────────────

    fn fact_summary_state_dir(name: &str) -> std::path::PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("warp-insight-fact-summary-{name}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("create state dir");
        dir
    }

    fn draft(executables: &[&str]) -> fact_summary::FactSummaryDraft {
        fact_summary::FactSummaryDraft {
            revision: 7,
            observed_at: "2026-09-22T00:00:00Z".to_string(),
            os: "macos".to_string(),
            arch: "arm64".to_string(),
            process_count: executables.len() as i64,
            process_executables: executables.iter().map(|value| value.to_string()).collect(),
            packages: Vec::new(),
            listen_ports: Vec::new(),
            host_id: "machine-id".to_string(),
            host_name: "demo-host".to_string(),
            network_addresses: vec!["en0 192.168.1.5/24".to_string()],
        }
    }

    /// 种一份「上次尝试在 `last_attempt_at_ms`」的节流状态。
    async fn seeded_attempt(state_dir: &Path, last_attempt_at_ms: i64) {
        fact_report::store_async(
            &fact_report::path_for(state_dir),
            &fact_report::FactReportState { last_attempt_at_ms },
        )
        .await
        .expect("seed state");
    }

    async fn loaded_attempt(state_dir: &Path) -> i64 {
        fact_report::load_async(&fact_report::path_for(state_dir))
            .await
            .expect("load state")
            .expect("state recorded")
            .last_attempt_at_ms
    }

    /// 断言短窗口内没有任何连接进来。loopback 上真发了就会立刻排队，
    /// 而调用方是 await 到底的，所以这个断言不靠“抢时间”。
    async fn assert_no_request(listener: &TcpListener) {
        match tokio::time::timeout(Duration::from_millis(200), listener.accept()).await {
            Err(_elapsed) => {}
            Ok(Ok(_)) => panic!("unexpected fact summary request was sent"),
            Ok(Err(err)) => panic!("accept failed: {err}"),
        }
    }

    /// 收**一帧**（line framing：一帧一行）后返回文本。
    ///
    /// 不读到 EOF：sink 会把连接留着复用，读 EOF 会挂到测试结束。
    fn frame_server(listener: TcpListener) -> tokio::task::JoinHandle<String> {
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
                if body.contains(&b'\n') {
                    break;
                }
            }
            String::from_utf8_lossy(&body).into_owned()
        })
    }

    fn tcp_sink(port: u16) -> TelemetryRecordSink {
        TelemetryRecordSink::Tcp(TcpRecordSink::new(
            "127.0.0.1".to_string(),
            port,
            TcpFraming::Line,
        ))
    }

    /// 一个确定没人监听的端口：`bind` 后立刻 drop，端口即被释放。
    async fn closed_port() -> u16 {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        listener.local_addr().expect("addr").port()
    }

    /// 走共用的 `test_config()` + 自己的 seq 状态，把六个参数收成一个调用。
    async fn report_fact(
        sink: &mut TelemetryRecordSink,
        state_dir: &Path,
        summary: &fact_summary::FactSummaryDraft,
    ) -> RuntimeResult<bool> {
        let seq_path = log_seq_state::path_for(state_dir);
        let mut next_seq = log_seq_state::load_or_default_async(&seq_path)
            .await
            .unwrap_or(0);
        report_fact_summary(
            sink,
            &test_config(),
            state_dir,
            summary,
            &mut next_seq,
            &seq_path,
        )
        .await
    }

    #[tokio::test]
    async fn fact_summary_sends_an_obsfact_frame_over_the_uplink() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = frame_server(listener);

        let state_dir = fact_summary_state_dir("periodic");
        let mut sink = tcp_sink(port);
        let summary = draft(&["/usr/bin/xcodebuild"]);
        let reported = report_fact(&mut sink, &state_dir, &summary)
            .await
            .expect("report");
        let frame = server.await.expect("server task");

        assert!(reported);
        // 帧标记 + 信封：身份在信封里（`agent`），正文里也有一份用于交叉核对。
        assert!(
            frame.contains(" OBSFACT: "),
            "frame missing marker: {frame}"
        );
        assert!(frame.contains("\"agent\":\"agent-x\""));
        assert!(frame.contains("\"seq\":0"));
        // 正文是契约对象**原样透传**（订阅端按 wist-contracts 解析）。
        assert!(frame.contains("\"agent_id\":\"agent-x\""));
        assert!(frame.contains("\"instance_id\":\"instance-x\""));
        assert!(frame.contains("\"kind\":\"report_agent_fact_summary\""));
        // 声明用的是与网关同源的实现（版本前缀 fact-v1）。
        assert!(frame.contains("\"content_digest\":\"fact-v1:sha256:"));
        assert!(frame.contains("\"process_executables\":[\"/usr/bin/xcodebuild\"]"));
        assert!(frame.contains("\"process_count\":1"));
        // 主机标识与网卡地址随摘要一起上去（留痕/展示，不进内容摘要）。
        assert!(frame.contains("\"host_id\":\"machine-id\""));
        assert!(frame.contains("\"host_name\":\"demo-host\""));
        assert!(frame.contains("\"network_addresses\":[\"en0 192.168.1.5/24\"]"));
        assert!(frame.contains("\"revision\":7"));
        assert!(frame.contains("\"observed_at\":\"2026-09-22T00:00:00Z\""));
        // 走数据面就不应该再出现控制面那条路的东西（端点/凭据）。
        assert!(!frame.to_lowercase().contains("authorization"));
        assert!(!frame.contains("/api/v1/agent/facts"));

        assert!(loaded_attempt(&state_dir).await > 0);
        assert!(summary.content_digest().starts_with("fact-v1:sha256:"));
    }

    #[tokio::test]
    async fn fact_summary_fails_loudly_when_the_uplink_is_not_tcp() {
        // 文件输出只承载日志（本地调试）：事实发不出去必须**报错**，不能像指标那样静默跳过 ——
        // “数据面上行没开”会让网关永远拿不到事实（推断与清单全空），而这种故障两侧都不显形。
        let state_dir = fact_summary_state_dir("file-only");
        let mut sink = TelemetryRecordSink::File(FileRecordSink::new(PathBuf::from(
            "fact-should-not-be-written.ndjson",
        )));
        let result = report_fact(&mut sink, &state_dir, &draft(&["/usr/bin/xcodebuild"])).await;
        let err = result.expect_err("file sink must reject fact frames");
        assert!(
            err.to_string().contains("kind = \"tcp\""),
            "error should point at the config knob: {err}"
        );
        // 这次尝试仍然被记下：配置错也不会变成每 3s 一条日志。
        assert!(loaded_attempt(&state_dir).await > 0);
    }

    #[tokio::test]
    async fn fact_summary_reports_even_when_the_content_is_unchanged() {
        // agentd 不做本地判重：只要过了下限，内容一模一样也照发。
        // （以前的实现会因「摘要没变」静默跳过；一旦本地算法或状态退化那就是永久漏报。）
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let state_dir = fact_summary_state_dir("unchanged");
        seeded_attempt(&state_dir, now_ts_ms() - FACT_REPORT_MIN_INTERVAL_MS - 1).await;

        let mut sink = tcp_sink(port);
        let summary = draft(&["/usr/bin/xcodebuild"]);

        let (reported, frame) = tokio::join!(
            report_fact(&mut sink, &state_dir, &summary),
            frame_server(listener)
        );
        assert!(reported.expect("report ok"));
        assert!(frame.expect("server task").contains(" OBSFACT: "));
        let after_first = loaded_attempt(&state_dir).await;

        // 第二次立刻再调：刚写过尝试时刻 → 这次才被下限拦住，且**不改写**状态
        // （改写了会把重试窗口往后推，变成“越重试越晚”）。
        let second = report_fact(&mut sink, &state_dir, &summary)
            .await
            .expect("second report");
        assert!(!second);
        assert_eq!(loaded_attempt(&state_dir).await, after_first);
    }

    #[tokio::test]
    async fn fact_summary_respects_the_minimum_interval() {
        // 刚刚才送过：这次不发，且不能改写状态（否则重试窗口会被推后）。
        let state_dir = fact_summary_state_dir("interval");
        let seeded = now_ts_ms() - 1_000;
        seeded_attempt(&state_dir, seeded).await;

        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let mut sink = tcp_sink(port);
        let reported = report_fact(&mut sink, &state_dir, &draft(&["/usr/bin/xcodebuild"]))
            .await
            .expect("report");

        assert!(!reported);
        assert_no_request(&listener).await;
        assert_eq!(loaded_attempt(&state_dir).await, seeded);
    }

    #[tokio::test]
    async fn fact_summary_records_the_attempt_even_when_the_send_fails() {
        // 数据面不在：发不出去也要记下这次尝试 —— 否则服务宕机时会每 tick（3s）重试。
        // 与旧版“网关回 500”同一个不变式，只是失败形式换成 TCP 连不上。
        let state_dir = fact_summary_state_dir("failed");
        let mut sink = tcp_sink(closed_port().await);
        let result = report_fact(&mut sink, &state_dir, &draft(&["/usr/bin/xcodebuild"])).await;
        assert!(
            result.is_err(),
            "send to a closed port must surface as an error"
        );
        assert!(loaded_attempt(&state_dir).await > 0);
    }

    #[tokio::test]
    async fn fact_summary_respects_a_rolled_back_clock() {
        // 状态里的尝试时刻在未来（墙钟回拨 / 状态损坏）→ 放行，不能被节流按死。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let state_dir = fact_summary_state_dir("rolled-back");
        let future_ms = now_ts_ms() + 10 * FACT_REPORT_MIN_INTERVAL_MS;
        seeded_attempt(&state_dir, future_ms).await;

        let mut sink = tcp_sink(port);
        let summary = draft(&["/usr/bin/xcodebuild"]);

        let (reported, frame) = tokio::join!(
            report_fact(&mut sink, &state_dir, &summary),
            frame_server(listener)
        );
        assert!(reported.expect("report ok"));
        assert!(frame.expect("server task").contains(" OBSFACT: "));
    }

    #[tokio::test]
    async fn fact_summary_recovers_from_a_corrupt_state_file() {
        // 状态文件坏掉不能永久停摆：fail-open，照常发送并成功重写状态（自愈）。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let state_dir = fact_summary_state_dir("corrupt");
        let state_path = fact_report::path_for(&state_dir);
        tokio::fs::write(&state_path, b"{ this is not json")
            .await
            .expect("write corrupt state");

        let mut sink = tcp_sink(port);
        let summary = draft(&["/usr/bin/xcodebuild"]);

        let (reported, frame) = tokio::join!(
            report_fact(&mut sink, &state_dir, &summary),
            frame_server(listener)
        );
        assert!(reported.expect("report ok (fail-open)"));
        assert!(frame.expect("server task").contains(" OBSFACT: "));

        assert!(loaded_attempt(&state_dir).await > 0);
    }

    #[tokio::test]
    async fn fact_summary_state_ignores_superseded_fields() {
        // 老版本的状态文件带 content_digest / reported_at；反序列化必须兼容（不报错），
        // 因为读到坏 JSON 会 fail-open，但那会把下限让出去、每次 tick 都发。
        let state_dir = fact_summary_state_dir("legacy-fields");
        let state_path = fact_report::path_for(&state_dir);
        tokio::fs::write(
            &state_path,
            br#"{"content_digest":"sha256:old","reported_at":"2026-09-01T00:00:00Z","reported_at_ms":1000,"last_attempt_at_ms":1234}"#,
        )
        .await
        .expect("write legacy state");

        assert_eq!(loaded_attempt(&state_dir).await, 1234);
    }

    #[tokio::test]
    async fn fact_summary_is_skipped_without_an_agent_id() {
        // 信封里的身份是自称的，但它仍然必需：没有 agent_id 就无从表达「这是谁的观测」。
        // （控制面凭据**不再**是前提 —— 帧走数据面，身份校验尚未落地，见计划 §9 风险行。）
        let state_dir = fact_summary_state_dir("unenrolled");
        let seq_path = log_seq_state::path_for(&state_dir);
        let mut next_seq = 0;
        let mut config = test_config();
        config.agent.agent_id = None;
        let mut sink = tcp_sink(closed_port().await);
        let reported = report_fact_summary(
            &mut sink,
            &config,
            &state_dir,
            &draft(&["/usr/bin/xcodebuild"]),
            &mut next_seq,
            &seq_path,
        )
        .await
        .expect("report");
        assert!(!reported);
        assert!(
            fact_report::load_async(&fact_report::path_for(&state_dir))
                .await
                .expect("load state")
                .is_none(),
            "缺少 agent_id 时不应记录尝试"
        );
    }

    // ── 发现方向策略表拉取 ────────────────────────────────────

    #[tokio::test]
    async fn fetch_discovery_policies_posts_poll_and_parses_the_table() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(request.contains("/api/v1/agent/discovery-policies:poll"));
            assert!(
                request
                    .to_lowercase()
                    .contains("authorization: bearer wic_test_token")
            );
            assert!(request.contains("\"kind\":\"poll_discovery_policies\""));
            assert!(request.contains("\"api_version\":\"v1\""));
            assert!(request.contains("\"agent_id\":\"agent-x\""));
            assert!(request.contains("\"instance_id\":\"instance-x\""));
            assert!(request.contains("\"requested_at\":\""));
            let body = r#"{"policy_version":4,"published_at":"2026-09-22T00:00:00Z","policies":[{"aspect":"host","default_interval_seconds":900,"min_interval_seconds":300,"max_interval_seconds":3600,"baseline":true,"enabled_by_default":true,"platforms":["macos","linux"],"yields":"os/arch"}],"returned_at":"2026-09-22T00:00:00Z"}"#;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let set = fetch_discovery_policies(&config)
            .await
            .expect("table returned");
        server.await.expect("server task");

        assert_eq!(set.policy_version, 4);
        assert_eq!(set.interval_seconds_for("host"), Some(900));
    }

    #[tokio::test]
    async fn fetch_discovery_policies_returns_none_on_503() {
        // 网关没配策略表就回 503：这是「未配置」而非错误，agentd 必须静默回退到内建周期。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = read_http_request(&mut socket).await;
            let response = "HTTP/1.1 503 Service Unavailable\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let result = fetch_discovery_policies(&config).await;
        server.await.expect("server task");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_discovery_policies_returns_none_on_a_malformed_body() {
        // 坏 JSON 既不能 panic，也不能是致命错误 —— 回 None，继续用内建周期采集。
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let _ = read_http_request(&mut socket).await;
            let body = "{ this is not json";
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let result = fetch_discovery_policies(&config).await;
        server.await.expect("server task");

        assert!(result.is_none());
    }

    #[tokio::test]
    async fn fetch_discovery_policies_is_skipped_without_an_endpoint() {
        let mut config = test_config();
        config.control_plane.endpoint = None;
        let result = fetch_discovery_policies(&config).await;
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn report_status_posts_work_state_changes() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(request.contains("\"work_state_changes\":["));
            assert!(request.contains("\"input_id\":\"app\""));
            assert!(request.contains("\"state\":\"paused\""));
            let response =
                "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let changes = Some(vec![wist_contracts::gateway::AgentWorkStateChange {
            input_id: "app".to_string(),
            state: wist_contracts::gateway::AgentWorkState::Paused,
            reason: "spool over limit".to_string(),
            at: "now".to_string(),
        }]);
        let latency =
            report_status_to_control_plane(&config, Some(12.5), Some(3), changes, None).await;
        server.await.expect("server task");
        assert!(latency.is_some());
    }

    #[tokio::test]
    async fn report_status_skips_when_not_enrolled() {
        let mut config = test_config();
        config.control_plane.bearer_token = None;
        let latency = report_status_to_control_plane(&config, None, None, None, None).await;
        assert!(latency.is_none());
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_resource_measurements_return_values() {
        let rss = current_rss_bytes().expect("current_rss_bytes on macos");
        assert!(rss > 0, "resident memory should be positive, got {rss}");
        let first = cpu_ticks().expect("cpu_ticks on macos");
        let second = cpu_ticks().expect("cpu_ticks on macos");
        assert!(second >= first, "cpu time should not decrease");
        assert_eq!(ticks_per_sec(), 1_000_000);
    }
}
