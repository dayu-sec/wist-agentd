//! `wist-agentd` runtime loop and recovery helpers.

use std::collections::BTreeSet;
use std::io;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::telemetry::warp_parse::TelemetryRecordSink;
use wist_contracts::agent_config::AgentConfig;
use wist_contracts::agent_uplink::AgentUplinkState;
use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;
use wist_contracts::gateway::{
    AgentStatusReport, AgentWorkState, AgentWorkStateChange, DiscoveryPoliciesReturned,
    POLL_DISCOVERY_POLICIES_KIND, PollDiscoveryPolicies, ReportAgentFactSummary,
};
use wist_contracts::local_work::{
    AgentLocalOneShotWork, AgentLocalStandingWork, AgentLocalTask, AgentLocalWork,
};
use wist_contracts::telemetry_record::DataFrame;
use wist_shared::time::{now_rfc3339, now_ts_ms};

use crate::enrollment::enrollment_http_client;

use crate::error::RuntimeResult;

use crate::control::uplink::{AppliedUplink, fetch_uplink_grant};
use crate::control::work::{AppliedWorkGrant, ack_work, fetch_work_grant, report_work_result};
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
    agent_runtime, execution_queue, fact_report, log_seq_state, planner_candidates, work,
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

/// 凭据续期的检查周期：没必要每 3s 都查，1 小时足够，而续期窗是 30 天。
const RENEWAL_CHECK_INTERVAL: Duration = Duration::from_secs(60 * 60);

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

/// 本机**逻辑核数**（`available_parallelism`）。
///
/// 为什么要跟 `cpu_percent` 一起报：那个数是**单核口径**（100% = 占满一个核），
/// 而运维看图时要回答的往往是「这台机器被它占了百分之几」——那是 `cpu_percent / 核数`。
/// 只报百分比不报核数，右侧那个数既算不出来、也无法复核（4 核上的 13% 与 64 核上的 13%
/// 完全不是一回事）。换算留给网关做：agent 只交原始事实。
fn local_cpu_cores() -> Option<u32> {
    std::thread::available_parallelism()
        .ok()
        .map(|count| count.get() as u32)
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

/// 构造上报用的**本机工作内容视图**：`state/work.json` 的同形子集 + 本机配置里手工加的日志输入。
///
/// 两处数据缺一不可 —— 网关要回答「这台机器到底在采哪些文件」，一半是本机授权折算出的采集
/// 任务（`device_view`），另一半是配置里手工加的输入（`telemetry.logs.file_inputs`）；后者
/// **不在**工作视图里，网关无从得知。
///
/// 没收到过任何授权快照时（`device_view` 返回 `None`）也要上报：授权那半为空
/// （空 standing/one_shot、序号 0），但配置里那半必须照报 —— 它独立于网关。
/// 这里没有可错的输入，构造**不会失败**，所以直接返回 `AgentLocalWork`。
fn build_local_work(
    config: &AgentConfig,
    work: &AppliedWorkGrant,
    recorded_at: &str,
) -> AgentLocalWork {
    let view = work.device_view(recorded_at);
    let standing = view
        .as_ref()
        .map(|view| {
            view.standing
                .iter()
                .map(|work| AgentLocalStandingWork {
                    work_id: work.work_id.clone(),
                    family: work.family.clone(),
                    status: work.status.clone(),
                    plan_version: work.plan_version,
                    acknowledged_version: work.acknowledged_version,
                    effective_from: work.effective_from.clone(),
                    // `units`（工作内容）刻意不带：那是网关发下去的，网关自己有。
                    tasks: work
                        .tasks
                        .iter()
                        .map(|task| AgentLocalTask {
                            input_id: task.input_id.clone(),
                            path: task.path.clone(),
                            startup_position: task.startup_position.clone(),
                        })
                        .collect(),
                })
                .collect()
        })
        .unwrap_or_default();
    let one_shot = view
        .as_ref()
        .map(|view| {
            view.one_shot
                .iter()
                .map(|work| AgentLocalOneShotWork {
                    work_id: work.work_id.clone(),
                    action: work.action.clone(),
                    status: work.status.clone(),
                    execution: work.execution.clone(),
                    scheduled_at: work.scheduled_at.clone(),
                    deadline_at: work.deadline_at.clone(),
                    timeout_seconds: work.timeout_seconds,
                })
                .collect()
        })
        .unwrap_or_default();
    AgentLocalWork {
        recorded_at: recorded_at.to_string(),
        gateway_sequence: view.as_ref().map_or(0, |view| view.gateway_sequence),
        standing,
        one_shot,
        // 本机配置里手工加的日志输入（运维逃生舱）：不来自任何采集面，只能由 agent 自报。
        local_inputs: config
            .telemetry
            .logs
            .file_inputs
            .iter()
            .map(|input| AgentLocalTask {
                input_id: input.input_id.clone(),
                path: input.path.clone(),
                startup_position: input.startup_position.clone(),
            })
            .collect(),
        metrics_interval_seconds: view.and_then(|view| view.metrics_interval_seconds),
    }
}

/// 构造上报用的**本机实际生效的上送状态**：`AgentUplinkGrant` 与本机配置合流后的结论。
///
/// 为什么必须由 agent 自报、且必须复用 [`effective_output`]：网关知道自己**下发**了
/// 「启用 + 目标」，但不知道 agent **生效**成了什么 —— grant 可能还没拉到、可能被本机总闸
/// 拦住、可能是「enabled 但没带目标」而回落本机 kind。这里刻意**不**自己重算覆盖规则，
/// 只把真正出效果的那份解析结果翻译成上报字段；否则平台看到的是一份与实际行为不符的假状态。
/// 与 [`build_local_work`] 同风格：纯函数、无 IO、不会失败。
fn build_uplink_state(
    config: &AgentConfig,
    uplink: &AppliedUplink,
    health: &UplinkHealth,
) -> AgentUplinkState {
    let grant = uplink.grant();
    let effective = effective_output(config, grant);
    AgentUplinkState {
        enabled: effective.enabled,
        kind: effective.kind.clone(),
        // 目标只在 tcp 下有：file 输出没有 `host:port`，tcp 无目标时也无可报的目标。
        target: (effective.kind == "tcp")
            .then(|| format!("{}:{}", effective.tcp.addr, effective.tcp.port)),
        // 来源只看 grant **在不在**（而不是它是否启用）：`grant` + `enabled = false` 是
        // 「控制面明确关掉」，与「本机配置关掉」是两种事实，平台要靠它区分。
        source: if grant.is_some() { "grant" } else { "local" }.to_string(),
        output_write_failing: health.is_failing(),
    }
}

/// Best-effort status heartbeat to the admin control plane. Returns the measured
/// round-trip latency in milliseconds when the report succeeded.
///
/// `discovery_policy_version` 是**本机实际生效**的发现方向策略版本：
/// 网关知道自己发布了哪一版，但不知道哪台机器拉到了、应用了 ——
/// 而「我改了策略，哪些机器还没生效」只能由 agent 回答。
///
/// `cpu_cores` 是**本机逻辑核数**：`cpu_percent` 是单核口径（100% = 占满一个核），
/// 网关要用核数才能把它换算成「整台机器的百分之几」。换算**不在 agent 做** ——
/// agent 只交原始事实（自己的 CPU 时间、自己的核数），派生值只留一处实现。
///
/// `work` 用来构造上报里的本机工作内容视图（[`build_local_work`]）。
///
/// `uplink` / `uplink_health` 用来构造**本机实际生效的上送状态**（[`build_uplink_state`]）：
/// 同样是「网关不知道我生效成了什么」的那类事实，与 `discovery_policy_version` 同口径。
// 参数多但每一个来源不同（采样值 / 差量 / 策略版本 / 两份期望状态），
// 打包成结构体只会把构造点与调用点都弄长 —— 与 `run_once_with_failure_cache` 同一取舍。
#[allow(clippy::too_many_arguments)]
async fn report_status_to_control_plane(
    config: &AgentConfig,
    cpu_percent: Option<f64>,
    last_latency_ms: Option<u64>,
    work_state_changes: Option<Vec<AgentWorkStateChange>>,
    discovery_policy_version: Option<i64>,
    work: &AppliedWorkGrant,
    uplink: &AppliedUplink,
    uplink_health: &UplinkHealth,
) -> Option<u64> {
    let endpoint = config.control_plane.endpoint.as_deref()?;
    let bearer_token = config.control_plane.bearer_token.as_deref()?;
    let agent_id = config.agent.agent_id.as_deref()?;
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();
    // 本机工作视图是 best-effort：它只决定页面能不能看见「在采哪些文件」，
    // 构造不出来也不该影响状态上报本身，所以始终送 `Some(...)`（没快照时授权那半为空）。
    let local_work = Some(build_local_work(config, work, &now_rfc3339()));
    // 生效上送状态同样是 best-effort 的**声明**：没有可错的输入，所以始终送 `Some(...)`
    // （`None` 的语义是「本次没带」，与本机工作视图同口径，留给旧版本 agent）。
    let uplink_state = Some(build_uplink_state(config, uplink, uplink_health));
    let report = AgentStatusReport {
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        version: env!("CARGO_PKG_VERSION").to_string(),
        memory_bytes: current_rss_bytes(),
        cpu_percent,
        cpu_cores: local_cpu_cores(),
        admin_latency_ms: last_latency_ms,
        work_state_changes,
        discovery_policy_version,
        local_work,
        uplink_state,
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

/// 发一次事实摘要，并把它该打的那一行打出来（成功 / 失败各一行；`Ok(false)` = 还在最小间隔内，静默）。
///
/// 抽出来是因为两条路都要发它：**启用**时（与指标/日志同一轮）和**待命**时（只有它）——
/// 「这台机器是什么」不需要授权就能决定该派什么活，见 `run_once_with_failure_cache`。
async fn send_fact_summary(
    sink: &mut TelemetryRecordSink,
    config: &AgentConfig,
    state_dir: &Path,
    summary: &fact_summary::FactSummaryDraft,
    next_seq: &mut u64,
    global_seq_path: &Path,
) {
    match report_fact_summary(sink, config, state_dir, summary, next_seq, global_seq_path).await {
        Ok(true) => eprintln!(
            "event=FactSummaryReported digest={} processes={} executables={} ports={}",
            summary.content_digest(),
            summary.process_count,
            summary.process_executables.len(),
            summary.listen_ports.len()
        ),
        Ok(false) => {}
        Err(err) => eprintln!("wist-agentd fact summary uplink failed: {err}"),
    }
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
    TelemetryFailureKind, TelemetryTick, TelemetryWorkState, UplinkHealth, WorkState,
    build_telemetry_sink, effective_output, invalid_output_tick, process_telemetry_inputs,
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
    /// 升级器（同 crate 的另一个二进制）：一次性工作 `upgrade` 由它执行。
    pub upgrader_bin: &'a Path,
    /// 配置目录：交给升级器读取（它要用同一份端点与信任锚去取包）。
    pub config_dir: &'a Path,
}

pub async fn run_forever_async(loop_ctx: DaemonLoop<'_>) -> RuntimeResult<()> {
    // 运行时**跨 tick 活着**：观测频率的调度记忆就在它里面（内存态，不落盘）。
    let mut discovery_runtime = DiscoveryRuntime::new(discovery_probes(loop_ctx.config));
    // 工作授权跨 tick 活着：`acked_plan_version` 就在里面，它决定
    // “这一版我确认过了，不用每 30s 重复确认”。
    //
    // 启动时先用**上次落盘的本机工作视图**恢复（`state/work.json`）：它记的是「我最后
    // 已知在干什么」。好处是重启后立刻接着干（网关不可达也能干），且确认记忆一起带回来 ——
    // 不会重复确认，页面也不会先闪一次「从未确认」。代价：**断网期间撤回会晚一步生效**。
    let work_record_path = work::path_for(Path::new(&loop_ctx.config.paths.state_dir));
    let mut work_runtime = match work::load_async(&work_record_path).await {
        Ok(Some(record)) => {
            let restored = AppliedWorkGrant::restore(&record);
            eprintln!(
                "event=WorkRestored path={} sequence={} recorded_at={} {} note=\"以网关为准；仅在拉不到快照时用这份\"",
                work_record_path.display(),
                restored.sequence(),
                record.recorded_at,
                restored.summary()
            );
            restored
        }
        Ok(None) => AppliedWorkGrant::default(),
        Err(err) => {
            // 一份工作视图不该有让采集停下的权力：读不动就记一行、当没有。
            eprintln!(
                "wist-agentd work view state: ignoring unreadable {}: {err}",
                work_record_path.display()
            );
            AppliedWorkGrant::default()
        }
    };
    let mut last_work_fetch: Option<Instant> = None;
    // 数据面上送启用同样跨 tick 活着：上一次已应用的 grant 就在里面（拉取失败保留它）。
    let mut uplink_runtime = AppliedUplink::default();
    let mut last_uplink_fetch: Option<Instant> = None;
    // 出口健康的跨 tick 记忆（只在「失败 → 恢复」时补一行）。
    let mut uplink_health = UplinkHealth::default();
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
    // 凭据会在**本进程运行期间**到期，所以这里持有一份**可变**副本：续期成功后替换它，
    // 本轮往后的调用立刻用上新凭据（`loop_ctx.config` 只是启动时的快照）。
    // 续期判定本身只读一个文件，但对不上就是“静默卡死”——issue #15。
    let exec_bin = loop_ctx.exec_bin;
    let upgrader_bin = loop_ctx.upgrader_bin;
    let config_dir = loop_ctx.config_dir;
    let mut runtime_config: AgentConfig = loop_ctx.config.clone();
    let mut last_renewal_check: Option<Instant> = None;
    loop {
        // 续期检查**放在建本轮 loop_ctx 之前**：要可变借用 `runtime_config`。
        if last_renewal_check.is_none_or(|at| at.elapsed() >= RENEWAL_CHECK_INTERVAL) {
            last_renewal_check = Some(Instant::now());
            let state_dir = std::path::PathBuf::from(&runtime_config.paths.state_dir);
            match crate::enrollment::renew_credential_if_due(&mut runtime_config, &state_dir).await
            {
                crate::enrollment::RenewalDecision::NotDue => {}
                crate::enrollment::RenewalDecision::Renewed => {
                    eprintln!("event=CredentialRenewed detail=\"credential rotated\"");
                }
                crate::enrollment::RenewalDecision::Failed(detail) => {
                    eprintln!("event=CredentialRenewalFailed detail=\"{detail}\"");
                }
                crate::enrollment::RenewalDecision::NeedsReinstall => {
                    eprintln!(
                        "event=CredentialNeedsReinstall detail=\"client certificate expired; re-enroll or reinstall with a token\""
                    );
                }
            }
        }
        let loop_ctx = DaemonLoop {
            config: &runtime_config,
            exec_bin,
            upgrader_bin,
            config_dir,
        };
        // 到达拉取间隔就拉一次策略表并应用（启动首轮即拉）。必须在 refresh_due 之前，
        // 这样本轮采集就用上新周期。
        refresh_discovery_policy(loop_ctx.config, &mut discovery_runtime).await;
        // 上送启用要**先于**工作授权与采集：否则会出现「工作已应用、上送还关着」的一个 tick
        // —— 派活后第一轮采到了却发不出去。上送开关是采集的前置条件。
        refresh_uplink_grant(loop_ctx.config, &mut uplink_runtime, &mut last_uplink_fetch).await;
        // 工作授权同样在采集之前应用：本轮就按新的授权采（或停）。
        refresh_work_grant(
            &loop_ctx,
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
            &uplink_runtime,
            Some(&mut uplink_health),
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
                // 本机工作视图的来源：授权折算 + 配置里手工加的输入（见 `build_local_work`）。
                &work_runtime,
                // 上送状态的来源：已应用 grant + 本机配置合流（见 `build_uplink_state`）。
                // `uplink_health` 上面的 `run_once_with_failure_cache` 只借用它一轮（`&mut`），
                // 到这里那次可变借用早已结束，所以这里用 `&` 不会冲突。
                &uplink_runtime,
                &uplink_health,
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

// 这个函数把「跨 tick 的失败/暂停去重缓存」与「本轮两份期望状态」都收在参数里；
// 参数虽多但每一个都是不同来源，打包成结构体只会把调用点弄得更长。
#[allow(clippy::too_many_arguments)]
async fn run_once_with_failure_cache(
    loop_ctx: &DaemonLoop<'_>,
    previous_telemetry_failures: Option<&mut BTreeSet<String>>,
    previous_metrics_failures: Option<&mut BTreeSet<String>>,
    previous_telemetry_paused: Option<&mut BTreeSet<String>>,
    discovery_runtime: &mut DiscoveryRuntime,
    // 当前持有的工作授权：日志任务由它折算而来，指标上送由它开关。
    work: &AppliedWorkGrant,
    // 当前已应用的数据面上送 grant：它与本机配置合流出「本轮该用哪个输出」。
    uplink: &AppliedUplink,
    // 出口健康的跨 tick 记忆（只在「失败 → 恢复」时补一行）；一次性路径传 `None`。
    uplink_health: Option<&mut UplinkHealth>,
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
    let effective = effective_output(loop_ctx.config, uplink.grant());
    let telemetry_tick = match build_telemetry_sink(loop_ctx.config, work, &effective) {
        Ok(mut sink) => {
            if !effective.enabled {
                // 待命（本机 `enabled = false`，或控制面 grant 明确 `enabled = false`）：
                // 不读源、不写本地采集输出、不发指标/日志帧、不推进 log checkpoint。
                // 关键在**位置**：这一切排在读任何源文件之前，否则待命期会推进 log
                // checkpoint，重新启用后就从新 offset 续读，把待命期间写入的行永久丢掉。
                //
                // 但**事实摘要照发** —— 它不是主机内容，而是让平台能推断“这台机器是什么”的
                // 最小元数据（进程列表 / 监听端口 / os / arch）。没有它，新装机器在网关侧一片
                // 空白，连「该派什么活」都定不下来 —— 这正是“新装了什么也干不了”的死锁。
                //
                // 只有 tcp 能承载事实帧：本机 file 输出（未设上送地址）时事实无处可去，
                // 静默跳过 —— 否则会走 `write_fact` 的 `Err` 分支，把正常状态报成故障
                // （旧实现每 5 分钟一行 `fact summary uplink failed` 的毛病，别再引回）。
                if sink.carries_fact_frames() {
                    send_fact_summary(
                        &mut sink,
                        loop_ctx.config,
                        state_dir,
                        &fact_summary,
                        &mut next_seq,
                        &global_seq_path,
                    )
                    .await;
                }
                TelemetryTick::silent()
            } else {
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
                if sink.carries_fact_frames() {
                    send_fact_summary(
                        &mut sink,
                        loop_ctx.config,
                        state_dir,
                        &fact_summary,
                        &mut next_seq,
                        &global_seq_path,
                    )
                    .await;
                }
                process_telemetry_inputs(loop_ctx.config, work, &mut sink, &mut next_seq).await
            }
        }
        Err(err) => {
            // 待命时 sink 建不起来（例如本机 `kind` 非法）也只是“没有可发的目标”，静默即可 ——
            // 不能报成故障（待命本就是正常态）。只有启用后才把输出配置错误报出来。
            if effective.enabled {
                invalid_output_tick(loop_ctx.config, work, err.to_string())
            } else {
                TelemetryTick::silent()
            }
        }
    };
    // 出口恢复：上一轮报过出口写失败、这一轮真的发出去了 → 补一行（见 `UplinkHealth`）。
    // 位置在失败行之后：先报错、再报好，读日志时顺序与因果一致。
    if let Some(health) = uplink_health {
        let failed = telemetry_tick
            .failures
            .iter()
            .any(|failure| failure.kind == TelemetryFailureKind::OutputWriteFailed);
        let sent_something = telemetry_tick
            .outcomes
            .iter()
            .any(|outcome| outcome.emitted_directly > 0 || outcome.replayed_spool > 0);
        if let Some(line) = health.note_tick(failed, sent_something) {
            eprintln!("{line}");
        }
    }
    if let Some(previous) = previous_telemetry_failures {
        for failure in filter_new_failures(&telemetry_tick.failures, previous) {
            emit_telemetry_failure(failure);
        }
        *previous = failure_signatures(&telemetry_tick.failures);
    } else {
        emit_telemetry_failures(&telemetry_tick.failures);
    }
    // 关闸（`enabled = false`）那一轮的 tick 是**静默**的（零通知）。此时照常做暂停差量是错的：
    // 静默 tick 没有通知，差量会把「上次因 spool 超限暂停」的输入全判成「已恢复」并回报给控制面
    // （reason 还会写成 `spool replay recovered`）—— 那是把「被关闸」误报成「恢复正常」。
    // 所以关闸期两条都不动：不产生通知，也不推进 `previous_telemetry_paused`。
    let current_paused = if effective.enabled {
        paused_input_signatures(&telemetry_tick.notifications)
    } else {
        previous_telemetry_paused
            .as_deref()
            .cloned()
            .unwrap_or_default()
    };
    let tick_changes = if !effective.enabled {
        Vec::new()
    } else if let Some(previous) = previous_telemetry_paused {
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

/// 拉取并应用数据面上送启用（启动首轮即拉，之后按最小间隔节流）。
///
/// 用与工作授权相同的 30s 节流：它同样是一个**期望状态**（派活 / 撤回都期望尽快生效），
/// 但也不该把网关当心跳打。先记「尝试」再发，失败保留上次已应用的 grant。
async fn refresh_uplink_grant(
    config: &AgentConfig,
    runtime: &mut AppliedUplink,
    last_fetch: &mut Option<Instant>,
) {
    let now = Instant::now();
    if let Some(at) = *last_fetch
        && at.elapsed() < Duration::from_millis(WORK_FETCH_MIN_INTERVAL_MS as u64)
    {
        return;
    }
    // 先记“尝试”再发：失败也要被节流，否则网关宕机时会每 tick（3s）重试。
    *last_fetch = Some(now);
    // 拿不到（未入网 / 旧网关 404 / 网络失败）就**保留上次已应用的 grant**：
    // 与工作授权同一取舍 —— 失败清空会把一次网络抖动放大成采集中断。
    // 「该不该打日志」交给 `observe`：预期内（未入网 / 404）静默，异常按签名去重。
    if let Some(line) = runtime.observe(fetch_uplink_grant(config).await) {
        eprintln!("{line}");
    }
}

/// 拉取并应用工作授权（启动首轮即拉，之后按最小间隔节流）。
///
/// 与发现策略表的差别：这里**会**回报确认。确认只对“真正应用了的工作”发（见
/// `AppliedWorkGrant::apply`），回报成功才记下版本 —— 否则下一轮会重复回报。
async fn refresh_work_grant(
    loop_ctx: &DaemonLoop<'_>,
    runtime: &mut AppliedWorkGrant,
    last_fetch: &mut Option<Instant>,
    record_path: &Path,
) {
    let config = loop_ctx.config;
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
            "event=OneShotWorkNotExecuted work_id={work_id} detail=\"agentd 尚未实现这个动作的执行\""
        );
    }
    // 能做的动作：交给升级器（分离进程），并把它的进度/结果同步回本机视图。
    let mut dispatched_anything = false;
    for work in &outcome.one_shot_to_dispatch {
        if runtime.has_upgrade_in_flight() {
            // 互斥：升级会换掉 agentd 自己，同时跑两件只会两败俱伤。
            eprintln!(
                "event=UpgradeBusy work_id={} detail=\"已有一件升级在进行，本轮不派\"",
                work.work_id
            );
            continue;
        }
        match dispatch_upgrade(loop_ctx, work) {
            Ok(pid) => {
                runtime.mark_one_shot_execution(&work.work_id, "dispatched");
                eprintln!("event=UpgradeDispatched work_id={} pid={pid}", work.work_id);
                // 确认只对“真派出去的活”发：起不了进程就不确认，网关页面上「一直没确认」
                // 正是这种情况该有的样子（与常驻工作“参数读不懂就不确认”同一取舍）。
                if ack_work(config, &work.work_id, 0).await {
                    dispatched_anything = true;
                } else {
                    eprintln!(
                        "event=WorkAckFailed work_id={} plan_version=0",
                        work.work_id
                    );
                }
            }
            Err(err) => {
                // 起不了进程 = 这次活**做不成**：报结果说清楚。确认依旧不发（我们并没有真的在
                // 执行它），但「没成」必须到网关 —— 否则页面上只剩一个无法解释的「派了没确认」，
                // 运维要等到期判定才能知道它没做成，而原因（参数坏了 / 升级器不在）完全看不到。
                runtime.mark_one_shot_execution(&work.work_id, "rejected");
                let detail = format!("agentd 未能启动升级器：{err}");
                if !report_work_result(config, &work.work_id, "failed", &detail).await {
                    eprintln!(
                        "event=WorkResultReportFailed work_id={} status=failed",
                        work.work_id
                    );
                }
                eprintln!(
                    "event=UpgradeDispatchFailed work_id={} detail={err}",
                    work.work_id
                );
            }
        }
    }
    let progressed =
        reconcile_upgrade_record(config, runtime, Path::new(&loop_ctx.config.paths.state_dir))
            .await;
    let mut acked_anything = false;
    for (work_id, plan_version) in outcome.to_ack {
        if ack_work(config, &work_id, plan_version).await {
            runtime.mark_acked(&work_id, plan_version);
            acked_anything = true;
        } else {
            eprintln!("event=WorkAckFailed work_id={work_id} plan_version={plan_version}");
        }
    }
    // 有变化（含“确认了某个版本”）才落盘：这份视图是给人看的，不必每 30s 重写一遍。
    // 写失败只记一行日志：一份工作视图不该影响采集本身。
    if (outcome.changed || acked_anything || dispatched_anything || progressed)
        && let Some(record) = runtime.device_view(&now_rfc3339())
        && let Err(err) = work::store_async(record_path, &record).await
    {
        eprintln!(
            "wist-agentd work view state: failed to write {}: {err}",
            record_path.display()
        );
    }
}

/// 把一件升级的**工作参数**（`entry.spec`）加上本机现状凑成一次升级请求。
///
/// 单独抽成纯函数，是为了给「`spec` → 请求」这一跳一个**可直接单测**的缝：它是派发链上
/// 唯一一处「把网关的话翻译成本机动作」的地方（取哪个包、目标版本是哪一版、允不允许降级），
/// 翻译错了的表现是「派了一件错的活」，靠集成测试兜太贵、覆盖太窄。
///
/// `agentd_bin` 由调用方注入（真机上是 `current_exe`），当前版本取编译期写死的
/// `CARGO_PKG_VERSION`：要换的是**正在跑的这一份**，不是从文件名猜的。
fn upgrade_request_for(
    agentd_bin: PathBuf,
    entry: &wist_contracts::work::OneShotWork,
) -> Result<crate::upgrade::UpgradeRequest, String> {
    // 参数读不懂就返回 Err（调用方据此不派、也不确认）：网关那边「期望一直没被确认」
    // 正是坏参数真被看见的形态。
    let spec = crate::upgrade::parse_spec(&entry.spec).map_err(|err| err.to_string())?;
    Ok(crate::upgrade::UpgradeRequest {
        work_id: entry.work_id.clone(),
        target_version: spec.target_version,
        current_version: env!("CARGO_PKG_VERSION").to_string(),
        agentd_bin,
        package_url: spec.package_url,
        package_sha256: spec.package_sha256,
        allow_downgrade: spec.allow_downgrade,
    })
}

/// 把一件升级交给升级器执行（分离进程），返回其 pid。
///
/// 参数全部从工作参数里取，**不做任何默认**：取哪个包必须写在 `spec` 里 ——
/// 让「升级」这件事只有一个证据来源（网关派下来的那份），而不是 agent 自己的猜测。
/// 目标版本例外：它可以不写（那就以**包内 agentd 自报的版本**为准）。
fn dispatch_upgrade(
    loop_ctx: &DaemonLoop<'_>,
    entry: &wist_contracts::work::OneShotWork,
) -> Result<u32, String> {
    let agentd_bin =
        std::env::current_exe().map_err(|err| format!("resolve current exe: {err}"))?;
    let request = upgrade_request_for(agentd_bin, entry)?;
    let target_label = request
        .target_version
        .clone()
        .unwrap_or_else(|| "(由包内自报)".to_string());
    let launch = crate::upgrade::build_launch(loop_ctx.upgrader_bin, loop_ctx.config_dir, &request);
    let log_path = Path::new(&loop_ctx.config.paths.log_dir).join("wist-upgrader.log");
    eprintln!(
        "event=UpgradeLaunching work_id={} target={} program={} log={}",
        entry.work_id,
        target_label,
        launch.program.display(),
        log_path.display()
    );
    crate::upgrade::launch_detached(&launch, &log_path)
        .map_err(|err| format!("launch {}: {err}", launch.program.display()))
}

/// 从升级器落盘的记录里同步进度/结果，返回「本机视图是否因此变了」。
///
/// 为什么以它为唯一来源：升级器是**跨过 agentd 重启**的那个进程，而 agentd 重启后没有任何
/// 内存记忆（`one_shot_execution` 就是从 `state/work.json` 恢复的）。所以「这件活做到哪一步了」
/// 只能读它落盘的那份记录 —— 拿网关侧的状态当进度会差一个网络往返，而且恰好在这条链上失真。
async fn reconcile_upgrade_record(
    config: &AgentConfig,
    runtime: &mut AppliedWorkGrant,
    state_dir: &Path,
) -> bool {
    let path = state_dir.join(crate::upgrade::UPGRADE_RECORD_FILE);
    let Ok(record) = wist_shared::fs::read_json::<crate::upgrade::UpgradeRecord>(&path) else {
        return false;
    };
    let Some(current) = runtime.one_shot_execution(&record.work_id) else {
        // 本机没有这件活的执行状态：不认它（比如升级器留下了一份不属于本机工作视图的记录）。
        // 不动本机视图，也不报一行无主的日志。
        return false;
    };
    // 升级器是**分离进程**，agentd 有调度权、没有生命周期权。记录停在 `running` 而心跳已经旧了，
    // 说明那个进程没了（被 kill / 崩溃 / 卡死）—— 这件事不会自己往前走。
    // 不在这里结掉，它就会永久占着「有升级在飞」那把互斥锁：之后再派升级都不做。
    let dead = record.status == "running"
        && !crate::upgrade::heartbeat_is_fresh(state_dir, std::time::SystemTime::now());
    // 本机视图记的档位（与报给控制面的取值可能不同：回滚本地记 `rolled_back`，报出去是 `failed`）。
    let local_status = if dead {
        "failed"
    } else {
        record.status.as_str()
    };
    if current == local_status {
        return false;
    }
    eprintln!(
        "event=UpgradeProgress work_id={} step={} status={} detail=\"{}\"",
        record.work_id, record.step, record.status, record.detail
    );
    let mapped = if dead {
        // 要报成 failed；说明里必须写清“是被判死的”，否则页面上只是一个无法解释的失败。
        eprintln!(
            "event=UpgradeDeclaredDead work_id={} step={}",
            record.work_id, record.step
        );
        Some((
            "failed",
            format!(
                "升级器 {}s 没有心跳，判定已死（步骤 {}）；机器可能停在中间态",
                crate::upgrade::UPGRADER_DEAD_AFTER.as_secs(),
                record.step
            ),
        ))
    } else {
        work_result_of(&record)
    };
    let Some((status, detail)) = mapped else {
        // 升级器写了本机视图认得、控制面却不认的状态：不动视图也不报，
        // 免得编一个网关会拒的取值，把“状态闭集不一致”变成一个无限重试。
        eprintln!(
            "event=UpgradeResultUnmappable work_id={} status={}",
            record.work_id, record.status
        );
        return false;
    };
    // 先报控制面、再推进本机视图：报不出去就**不推进**，下一 tick 读到同一份记录会重试。
    // 反过来（先推进）会让一次网络抖动把“升级做完了”永久留在机器上，而控制面永远停在“已接受”。
    if !report_work_result(config, &record.work_id, status, &detail).await {
        eprintln!(
            "event=WorkResultReportFailed work_id={} status={status}",
            record.work_id
        );
        return false;
    }
    runtime.mark_one_shot_execution(&record.work_id, local_status);
    true
}

/// 把升级记录折算成**控制面认得的**工作状态与说明。
///
/// 关键映射是回滚：升级器把 “换件后又退回去” 记为 `rolled_back`，但网关的一次性工作状态闭集里
/// 没有这个取值（那是**授权**状态，agent 无权新增）。回滚 = 这次升级没成、机器已回到原样，
/// 在控制面上它就是 `failed`；但说明必须写清 “已回滚到哪一版”—— 否则页面上只剩一个无法解释的失败。
fn work_result_of(record: &crate::upgrade::UpgradeRecord) -> Option<(&'static str, String)> {
    match record.status.as_str() {
        "running" => Some(("running", format!("正在 {}", record.step))),
        // 成功也要带一句「从哪一版升到哪一版」：`target_version` 现在可以不写（由包里自报决定），
        // 这个值只有升级器知道 —— 不报回去，页面上就看不到到底升到了哪一版。
        "succeeded" => Some((
            "succeeded",
            format!("{} -> {}", record.from_version, record.to_version),
        )),
        "failed" => Some(("failed", record.detail.clone())),
        "rolled_back" => Some((
            "failed",
            format!("已回滚到 {}：{}", record.from_version, record.detail),
        )),
        _ => None,
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
    // 一次性路径不拉 grant：按「未下发」处理，输出完全由本机配置决定。
    let uplink = AppliedUplink::default();
    run_once_with_failure_cache(
        loop_ctx,
        None,
        None,
        None,
        &mut discovery_runtime,
        work,
        &uplink,
        None,
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

    use crate::control::uplink::UplinkFetch;
    use crate::telemetry::warp_parse::{FileRecordSink, TcpFraming, TcpRecordSink};
    use wist_contracts::agent_uplink::AgentUplinkGrant;

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

    /// 关闸轮（`enabled = false`）**不参与暂停差量**：静默 tick 没有通知，若照常做差量，
    /// 上次因 spool 超限暂停的输入会被判成「已恢复」并回报给控制面 —— 把「被关闸」误报成
    /// 「恢复正常」。这一层决策是私有的，只有同文件测试能直接碰。
    #[tokio::test]
    async fn a_gated_tick_neither_reports_resumed_inputs_nor_drops_the_paused_set() {
        let root = local_state_dir("gated-paused-diff");
        let mut config = test_config();
        config.paths.root_dir = root.display().to_string();
        config.paths.run_dir = root.join("run").display().to_string();
        config.paths.state_dir = root.join("state").display().to_string();
        config.paths.log_dir = root.join("log").display().to_string();
        config.telemetry.logs.output.enabled = false;

        let loop_ctx = DaemonLoop {
            config: &config,
            exec_bin: ::std::path::Path::new(""),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        };
        let mut discovery_runtime = DiscoveryRuntime::new(discovery_probes(&config));
        let mut telemetry_failures = BTreeSet::new();
        let mut metrics_failures = BTreeSet::new();
        let mut paused = BTreeSet::from(["app".to_string()]);

        let (_health, changes) = run_once_with_failure_cache(
            &loop_ctx,
            Some(&mut telemetry_failures),
            Some(&mut metrics_failures),
            Some(&mut paused),
            &mut discovery_runtime,
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            None,
            false,
        )
        .await
        .expect("gated tick");

        assert!(
            changes.is_empty(),
            "关闸轮不该产生任何 work-state 变更（更不该报 Resumed）"
        );
        assert_eq!(
            paused,
            BTreeSet::from(["app".to_string()]),
            "关闸轮不该推进暂停集合：留着上次已知的暂停事实，而不是报成空"
        );
    }

    /// 给上面这个测试用的临时 state 目录（别写进仓目录）。
    fn local_state_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("duration")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("warp-insight-{name}-{suffix}"));
        std::fs::create_dir_all(&dir).expect("create state dir");
        dir
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
            // 核数必须**是实测的那个**，不能是写死的常量：网关要靠它把单核占比
            // 换算成整机占比，写死等于把换算整体带偏。
            let expected_cores = std::thread::available_parallelism()
                .expect("available_parallelism")
                .get();
            assert!(
                request.contains(&format!("\"cpu_cores\":{expected_cores}")),
                "cpu_cores must be the measured core count, got {request}"
            );
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
        let latency = report_status_to_control_plane(
            &config,
            Some(12.5),
            Some(3),
            None,
            Some(7),
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            &UplinkHealth::default(),
        )
        .await;
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
        let latency = report_status_to_control_plane(
            &config,
            None,
            None,
            None,
            None,
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            &UplinkHealth::default(),
        )
        .await;
        server.await.expect("server task");
        assert!(latency.is_some());
    }

    // ── 实际生效的上送状态上报 ───────────────────────────────────────

    /// 造一份「已应用了某个 grant」的运行时（同 `control/uplink.rs` 里测试的用法）。
    fn applied_uplink(grant: AgentUplinkGrant) -> AppliedUplink {
        let mut applied = AppliedUplink::default();
        applied.observe(UplinkFetch::Granted(grant));
        applied
    }

    /// 控制面**明确待命**（`enabled = false`）：生效总闸关，且来源是 `grant`（而不是 `local`）。
    /// 平台要靠这个来源区分「控制面没启用」与「启用了但 agent 没听从」（后者才是故障）。
    #[test]
    fn a_standby_grant_reports_source_grant_and_no_target() {
        let config = test_config();
        let uplink = applied_uplink(AgentUplinkGrant::standby(
            "2026-09-26T00:00:00Z".to_string(),
        ));
        let state = build_uplink_state(&config, &uplink, &UplinkHealth::default());
        assert!(!state.enabled);
        assert_eq!(state.source, "grant");
        assert_eq!(state.target, None);
    }

    /// 授权带目标时**强制 tcp**：即使本机 `kind = "file"`，生效的也是 tcp，目标就是 grant 给的
    /// `host:port`。这与 `effective_output` 的覆盖规则必须是同一份，否则平台看到的是假状态。
    #[test]
    fn an_enabled_grant_forces_tcp_over_a_local_file_output() {
        let mut config = test_config();
        config.telemetry.logs.output.kind = "file".to_string();
        let uplink = applied_uplink(AgentUplinkGrant::enabled_at(
            "10.0.1.9".to_string(),
            9000,
            "2026-09-26T00:00:00Z".to_string(),
        ));
        let state = build_uplink_state(&config, &uplink, &UplinkHealth::default());
        assert!(state.enabled);
        assert_eq!(state.source, "grant");
        assert_eq!(state.kind, "tcp");
        assert_eq!(state.target.as_deref(), Some("10.0.1.9:9000"));
    }

    /// 未下发（`AppliedUplink::default()`）：来源是 `local`，输出完全由本机配置决定 ——
    /// 本机 `file` 时没有 tcp 目标可报。
    #[test]
    fn without_a_grant_the_local_config_is_the_source() {
        let mut config = test_config();
        config.telemetry.logs.output.kind = "file".to_string();
        let state =
            build_uplink_state(&config, &AppliedUplink::default(), &UplinkHealth::default());
        assert_eq!(state.source, "local");
        assert_eq!(state.kind, "file");
        assert_eq!(state.target, None);
    }

    /// 出口写失败是否**尚未恢复**随状态上报：记过失败 → true；真的又发出去了 → false。
    #[test]
    fn the_uplink_state_reflects_an_unrecovered_write_failure() {
        let config = test_config();
        let uplink = AppliedUplink::default();

        let mut health = UplinkHealth::default();
        health.note_tick(true, false);
        let failing = build_uplink_state(&config, &uplink, &health);
        assert!(failing.output_write_failing);

        // 只有「真的发出去了」才算恢复（`note_tick(false, true)`），与 `UplinkHealth` 的语义一致。
        health.note_tick(false, true);
        let recovered = build_uplink_state(&config, &uplink, &health);
        assert!(!recovered.output_write_failing);
    }

    /// 生效上送状态必须**真的进入**上送的报告体（不是构造了却忘了接上 `AgentStatusReport`）。
    #[tokio::test]
    async fn report_status_carries_the_effective_uplink_state() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(
                request.contains(
                    "\"uplink_state\":{\"enabled\":true,\"kind\":\"tcp\",\"target\":\"10.0.1.9:9000\",\"source\":\"grant\",\"output_write_failing\":false}"
                ),
                "{request}"
            );
            let response =
                "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let uplink = applied_uplink(AgentUplinkGrant::enabled_at(
            "10.0.1.9".to_string(),
            9000,
            "2026-09-26T00:00:00Z".to_string(),
        ));
        let latency = report_status_to_control_plane(
            &config,
            None,
            None,
            None,
            None,
            &AppliedWorkGrant::default(),
            &uplink,
            &UplinkHealth::default(),
        )
        .await;
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

    /// 待命（`enabled = false`）**也要推进程列表**。
    ///
    /// 为什么必须钉住：新装的机器在被派活之前，网关只能靠事实摘要推断「这台机器是什么」，
    /// 否则连「该派什么活」都定不下来 —— 实测就是「新装了什么也干不了」的死锁。
    /// 上送目标（tcp）在安装时就已设好，所以待命期也能把它发出去。
    #[tokio::test]
    async fn a_standby_tick_still_reports_the_fact_summary() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let port = listener.local_addr().expect("addr").port();
        let server = frame_server(listener);

        let root = local_state_dir("standby-fact");
        let mut config = test_config();
        config.paths.root_dir = root.display().to_string();
        config.paths.run_dir = root.join("run").display().to_string();
        config.paths.state_dir = root.join("state").display().to_string();
        config.paths.log_dir = root.join("log").display().to_string();
        // 待命：本机总闸关掉（安装模板就是这个），且控制面没派活。
        config.telemetry.logs.output.enabled = false;
        // 但上送地址已在（安装时管理面已设），事实帧就得靠它出去。
        config.telemetry.logs.output.kind = "tcp".to_string();
        config.telemetry.logs.output.tcp.addr = "127.0.0.1".to_string();
        config.telemetry.logs.output.tcp.port = port;

        let loop_ctx = DaemonLoop {
            config: &config,
            exec_bin: ::std::path::Path::new(""),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        };
        let mut discovery_runtime = DiscoveryRuntime::new(discovery_probes(&config));
        run_once_with_failure_cache(
            &loop_ctx,
            None,
            None,
            None,
            &mut discovery_runtime,
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            None,
            false,
        )
        .await
        .expect("standby tick");

        let frame = server.await.expect("server task");
        assert!(
            frame.contains(" OBSFACT: "),
            "待命必须仍把进程列表推出去: {frame}"
        );
        assert!(frame.contains("\"agent_id\":\"agent-x\""));
    }

    /// 待命 + 本机 `file` 输出（连上送地址都没设）：事实无处可去，**静默跳过**而不是报错 ——
    /// 旧实现正是这里每 5 分钟一行 `fact summary uplink failed`（把正常待命报成故障）。
    #[tokio::test]
    async fn a_standby_tick_with_a_file_output_sends_nothing() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");

        let root = local_state_dir("standby-file");
        let mut config = test_config();
        config.paths.root_dir = root.display().to_string();
        config.paths.run_dir = root.join("run").display().to_string();
        config.paths.state_dir = root.join("state").display().to_string();
        config.paths.log_dir = root.join("log").display().to_string();
        config.telemetry.logs.output.enabled = false;
        // `test_config()` 默认 kind = "file"：没有可发的目标。
        assert_eq!(config.telemetry.logs.output.kind, "file");

        let loop_ctx = DaemonLoop {
            config: &config,
            exec_bin: ::std::path::Path::new(""),
            upgrader_bin: ::std::path::Path::new(""),
            config_dir: ::std::path::Path::new(""),
        };
        let mut discovery_runtime = DiscoveryRuntime::new(discovery_probes(&config));
        run_once_with_failure_cache(
            &loop_ctx,
            None,
            None,
            None,
            &mut discovery_runtime,
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            None,
            false,
        )
        .await
        .expect("standby tick");

        assert_no_request(&listener).await;
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
        let latency = report_status_to_control_plane(
            &config,
            Some(12.5),
            Some(3),
            changes,
            None,
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            &UplinkHealth::default(),
        )
        .await;
        server.await.expect("server task");
        assert!(latency.is_some());
    }

    /// 一份「手里在采一份日志工作」的本机工作视图（授权折算出一条采集任务）。
    fn grant_with_a_log_task() -> AppliedWorkGrant {
        use wist_contracts::work::{WorkSpecSource, WorkSpecUnit};

        let record = crate::state_store::work::WorkRecord {
            schema_version: crate::state_store::work::SCHEMA_VERSION_V1.to_string(),
            recorded_at: "2026-09-24T00:00:00Z".to_string(),
            gateway_sequence: 9,
            standing: vec![crate::state_store::work::StandingWorkRecord {
                work_id: "work-l".to_string(),
                family: "CrashPanic".to_string(),
                status: "active".to_string(),
                plan_version: 1,
                acknowledged_version: Some(1),
                effective_from: "2026-09-23T00:00:00Z".to_string(),
                units: vec![WorkSpecUnit {
                    unit_id: "mac-crash".to_string(),
                    capability: "collect_logs".to_string(),
                    rule_ref: "r".to_string(),
                    requires_privilege: "none".to_string(),
                    sources: vec![WorkSpecSource {
                        kind: "FileGlob".to_string(),
                        target: "/Library/Logs/DiagnosticReports/crash.ips".to_string(),
                        multiline: "none".to_string(),
                    }],
                }],
                tasks: Vec::new(),
            }],
            one_shot: Vec::new(),
            metrics_interval_seconds: Some(15),
        };
        AppliedWorkGrant::restore(&record)
    }

    /// 状态上报必须带上**本机工作内容视图**：授权折算出的采集任务 + 配置里手工加的输入，
    /// 两半合起来才是「这台机器在采哪些文件」（见 `build_local_work`）。
    #[tokio::test]
    async fn report_status_carries_the_local_work_view_and_configured_inputs() {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            assert!(request.contains("\"local_work\":{"), "{request}");
            // 授权那半：工作折算出的采集任务（任务 id + 盯的路径）。
            assert!(
                request.contains(
                    "\"tasks\":[{\"input_id\":\"work-CrashPanic-mac-crash\",\"path\":\"/Library/Logs/DiagnosticReports/crash.ips\""
                ),
                "{request}"
            );
            // 配置那半：手工加的日志输入（不在 work.json 里）。
            assert!(
                request.contains(
                    "\"local_inputs\":[{\"input_id\":\"manual-app\",\"path\":\"/var/log/manual.log\""
                ),
                "{request}"
            );
            let response =
                "HTTP/1.1 202 Accepted\r\ncontent-length: 0\r\nconnection: close\r\n\r\n";
            socket.write_all(response.as_bytes()).await.expect("write");
        });

        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        config.telemetry.logs.file_inputs =
            vec![wist_contracts::agent_config::LogFileInputSection {
                input_id: "manual-app".to_string(),
                path: "/var/log/manual.log".to_string(),
                startup_position: "tail".to_string(),
                multiline_mode: "none".to_string(),
            }];
        let grant = grant_with_a_log_task();
        let latency = report_status_to_control_plane(
            &config,
            Some(12.5),
            Some(3),
            None,
            None,
            &grant,
            &AppliedUplink::default(),
            &UplinkHealth::default(),
        )
        .await;
        server.await.expect("server task");
        assert!(latency.is_some());
    }

    #[tokio::test]
    async fn report_status_skips_when_not_enrolled() {
        let mut config = test_config();
        config.control_plane.bearer_token = None;
        let latency = report_status_to_control_plane(
            &config,
            None,
            None,
            None,
            None,
            &AppliedWorkGrant::default(),
            &AppliedUplink::default(),
            &UplinkHealth::default(),
        )
        .await;
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

    // ── 一次性工作的执行结果上报 ──────────────────────────────────────

    fn upgrade_record_at(status: &str, step: &str, detail: &str) -> crate::upgrade::UpgradeRecord {
        crate::upgrade::UpgradeRecord {
            work_id: "work-upgrade".to_string(),
            from_version: "0.1.3".to_string(),
            to_version: "0.1.4".to_string(),
            step: step.to_string(),
            status: status.to_string(),
            detail: detail.to_string(),
            agentd_bin: "/opt/bin/wist-agentd".to_string(),
            updated_at: "2026-09-24T00:00:00Z".to_string(),
        }
    }

    /// 一份「手里正拿着一件升级、已派出去还没回来了」的本机工作视图。
    fn grant_holding_the_upgrade() -> AppliedWorkGrant {
        let record = crate::state_store::work::WorkRecord {
            schema_version: crate::state_store::work::SCHEMA_VERSION_V1.to_string(),
            recorded_at: "t".to_string(),
            gateway_sequence: 1,
            standing: Vec::new(),
            one_shot: vec![crate::state_store::work::OneShotWorkRecord {
                work_id: "work-upgrade".to_string(),
                action: "upgrade".to_string(),
                spec: "0.1.4".to_string(),
                status: "accepted".to_string(),
                execution: "dispatched".to_string(),
                scheduled_at: "t".to_string(),
                deadline_at: "2026-09-25T00:00:00Z".to_string(),
                timeout_seconds: 600,
            }],
            metrics_interval_seconds: None,
        };
        AppliedWorkGrant::restore(&record)
    }

    fn write_upgrade_record(state_dir: &std::path::Path, record: &crate::upgrade::UpgradeRecord) {
        std::fs::write(
            state_dir.join(crate::upgrade::UPGRADE_RECORD_FILE),
            serde_json::to_vec(record).expect("serialize record"),
        )
        .expect("write record");
    }

    /// 收一次 POST 后回一份 JSON，返回收到的请求原文。
    fn json_server_once(
        listener: TcpListener,
        body: &'static str,
    ) -> tokio::task::JoinHandle<String> {
        tokio::spawn(async move {
            let (mut socket, _) = listener.accept().await.expect("accept");
            let request = read_http_request(&mut socket).await;
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .await
                .expect("write response");
            request
        })
    }

    /// 回滚在控制面上就是「失败」，但说明必须写清回到哪一版 —— 否则页面上只剩一个无法解释的失败。
    #[test]
    fn work_result_of_maps_upgrade_statuses_onto_the_control_plane_closed_set() {
        let (status, detail) = work_result_of(&upgrade_record_at(
            "rolled_back",
            "wait_ready",
            "new version did not report 0.1.4",
        ))
        .expect("rolled_back 是能映射的");
        assert_eq!(status, "failed");
        assert!(detail.starts_with("已回滚到 0.1.3"), "{detail}");

        assert_eq!(
            work_result_of(&upgrade_record_at("running", "fetch", ""))
                .unwrap()
                .0,
            "running"
        );
        let (status, detail) = work_result_of(&upgrade_record_at("succeeded", "done", ""))
            .expect("succeeded 是能映射的");
        assert_eq!(status, "succeeded");
        // 目标版本由包里决定，所以成功时必须把「从哪一版到哪一版」带回去。
        assert_eq!(detail, "0.1.3 -> 0.1.4");
        assert_eq!(
            work_result_of(&upgrade_record_at("failed", "install", "boom"))
                .unwrap()
                .0,
            "failed"
        );
        // 控制面不认的状态不编：宁可不动也不发一个会被 400 掉的取值。
        assert!(work_result_of(&upgrade_record_at("bogus", "?", "")).is_none());
    }

    #[tokio::test]
    async fn a_terminal_upgrade_is_reported_before_the_local_view_moves() {
        let state_dir = fact_summary_state_dir("upgrade-report-ok");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let server = json_server_once(
            listener,
            r#"{"work_id":"work-upgrade","status":"accepted","accepted_at":"t"}"#,
        );
        write_upgrade_record(
            &state_dir,
            &upgrade_record_at(
                "rolled_back",
                "wait_ready",
                "new version did not report 0.1.4",
            ),
        );

        let mut runtime = grant_holding_the_upgrade();
        assert!(reconcile_upgrade_record(&config, &mut runtime, &state_dir).await);

        let request = server.await.expect("server");
        assert!(request.contains("/api/v1/agent/work:result"));
        assert!(request.contains("\"status\":\"failed\""));
        assert!(request.contains("已回滚到 0.1.3"));
        // 报出去之后才推进本机视图（存的是升级器原样的终态，视图仍看得出“这是回滚”）。
        assert_eq!(
            runtime.one_shot_execution("work-upgrade").as_deref(),
            Some("rolled_back")
        );
    }

    #[tokio::test]
    async fn an_undeliverable_upgrade_result_is_retried_and_does_not_move_the_local_view() {
        let state_dir = fact_summary_state_dir("upgrade-report-retry");
        // test_config 的 endpoint 是个没人监听的地址：这一轮必然报不出去。
        let config = test_config();
        write_upgrade_record(&state_dir, &upgrade_record_at("succeeded", "done", ""));

        let mut runtime = grant_holding_the_upgrade();
        assert!(!reconcile_upgrade_record(&config, &mut runtime, &state_dir).await);
        // 本机视图停在旧状态：下一 tick 读到同一份记录会重投，而不是「报过就忘」。
        assert_eq!(
            runtime.one_shot_execution("work-upgrade").as_deref(),
            Some("dispatched")
        );
    }

    /// 心跳停了 = 升级器进程没了（被 kill / 卡死）：当它死了报 `failed`，把互斥锁解开。
    #[tokio::test]
    async fn a_silent_upgrader_is_declared_dead_and_reported_as_failed() {
        let state_dir = fact_summary_state_dir("upgrade-dead");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let server = json_server_once(
            listener,
            r#"{"work_id":"work-upgrade","status":"accepted","accepted_at":"t"}"#,
        );
        write_upgrade_record(&state_dir, &upgrade_record_at("running", "wait_ready", ""));
        // 故意不写心跳文件（= 心跳早就停了）。

        let mut runtime = grant_holding_the_upgrade();
        assert!(reconcile_upgrade_record(&config, &mut runtime, &state_dir).await);

        let request = server.await.expect("server");
        assert!(request.contains("\"status\":\"failed\""), "{request}");
        assert!(request.contains("判定已死"), "{request}");
        assert!(!request.contains("已回滚"), "判死不该被当成回滚：{request}");
        // 本机记的是 `failed`（不是升级器那个 `running`），互斥锁由此解开。
        assert_eq!(
            runtime.one_shot_execution("work-upgrade").as_deref(),
            Some("failed")
        );
        assert!(!runtime.has_upgrade_in_flight());
    }

    /// 心跳还在跳就不该判死：`wait_ready` 这类**合法静默**（默认整整 60s）不能当死亡。
    #[tokio::test]
    async fn a_heartbeating_upgrader_is_not_declared_dead() {
        let state_dir = fact_summary_state_dir("upgrade-alive");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let mut config = test_config();
        config.control_plane.endpoint = Some(endpoint);
        let server = json_server_once(
            listener,
            r#"{"work_id":"work-upgrade","status":"accepted","accepted_at":"t"}"#,
        );
        write_upgrade_record(&state_dir, &upgrade_record_at("running", "wait_ready", ""));
        crate::upgrade::touch_heartbeat(&state_dir).expect("touch heartbeat");

        let mut runtime = grant_holding_the_upgrade();
        assert!(reconcile_upgrade_record(&config, &mut runtime, &state_dir).await);

        let request = server.await.expect("server");
        assert!(request.contains("\"status\":\"running\""), "{request}");
        assert_eq!(
            runtime.one_shot_execution("work-upgrade").as_deref(),
            Some("running")
        );
        assert!(runtime.has_upgrade_in_flight(), "还在做，互斥照旧");
    }

    /// 升级器落盘的记录若是本机工作视图里没有的活（不属于这台机的视图）：不认它、也不报 ——
    /// 既不编一个网关会拒的取值，也不动本机视图。
    #[tokio::test]
    async fn an_upgrade_record_for_a_work_outside_the_view_is_ignored() {
        let state_dir = fact_summary_state_dir("upgrade-unknown");
        // endpoint 是没人监听的地址：真要报也报不出去；这里断言的是它**根本不去报**。
        let config = test_config();
        let mut record = upgrade_record_at("succeeded", "done", "");
        record.work_id = "someone-elses-work".to_string();
        write_upgrade_record(&state_dir, &record);

        let mut runtime = grant_holding_the_upgrade();
        assert!(!reconcile_upgrade_record(&config, &mut runtime, &state_dir).await);
        // 本机视图一点没动：那件活仍停在 dispatched，互斥照旧。
        assert_eq!(
            runtime.one_shot_execution("work-upgrade").as_deref(),
            Some("dispatched")
        );
        assert!(runtime.has_upgrade_in_flight());
    }

    /// 一件 `action = upgrade` 的一次性工作：这一跳只读 `work_id` 与 `spec`，其余字段不参与。
    fn upgrade_work(spec: &str) -> wist_contracts::work::OneShotWork {
        wist_contracts::work::OneShotWork {
            work_id: "work-upgrade-1".to_string(),
            agent_id: "agent-1".to_string(),
            action: "upgrade".to_string(),
            spec: spec.to_string(),
            scheduled_at: "2026-09-23T00:00:00Z".to_string(),
            deadline_at: "2026-09-24T00:00:00Z".to_string(),
            timeout_seconds: 600,
            interruptible: false,
            status: "dispatched".to_string(),
            paused_at: None,
            paused_total_seconds: 0,
            current_step: None,
            completed_steps: Vec::new(),
            attempt: 0,
            issued_by: "admin".to_string(),
            issued_at: "2026-09-23T00:00:00Z".to_string(),
        }
    }

    /// 派发链上唯一一处「把网关的话翻译成本机动作」：逐字段钉住 `spec → UpgradeRequest`。
    ///
    /// 这一段以前只能靠 `dispatch_upgrade` 整体兜（要真起进程），现在抽成纯函数后直接单测。
    #[test]
    fn upgrade_request_for_carries_the_spec_and_the_build_identity() {
        let bin = PathBuf::from("/opt/wist/wist-agentd");
        let sha = "a".repeat(64);
        // allow_downgrade 显式声明 → true，从 spec 原样带出。
        let spec = format!(
            r#"{{"target_version":"0.1.4","package_url":"https://gw/api/v1/agent/packages/current","package_sha256":"{sha}","allow_downgrade":true}}"#
        );
        let request = upgrade_request_for(bin.clone(), &upgrade_work(&spec)).expect("build");

        assert_eq!(request.work_id, "work-upgrade-1", "work_id 从工作取");
        assert_eq!(request.target_version.as_deref(), Some("0.1.4"));
        assert_eq!(
            request.current_version,
            env!("CARGO_PKG_VERSION"),
            "当前版本取正在跑的这一份（编译期写死），不是从文件名猜的"
        );
        assert_eq!(request.agentd_bin, bin, "要换的路径由调用方注入");
        assert_eq!(
            request.package_url,
            "https://gw/api/v1/agent/packages/current"
        );
        assert_eq!(request.package_sha256, sha);
        assert!(request.allow_downgrade, "spec 声明了降级就要带出来");

        // 缺字段：默认只前进（false），且没给目标版本就交给包内自报。
        let spec = format!(r#"{{"package_url":"https://gw/x","package_sha256":"{sha}"}}"#);
        let request = upgrade_request_for(bin.clone(), &upgrade_work(&spec)).expect("build");
        assert!(!request.allow_downgrade, "缺字段必须是「只前进」");
        assert_eq!(request.target_version, None, "没给目标版本就交给包内自报");

        // 显式 `false` 与缺省等价。
        let spec = format!(
            r#"{{"package_url":"https://gw/x","package_sha256":"{sha}","allow_downgrade":false}}"#
        );
        let request = upgrade_request_for(bin, &upgrade_work(&spec)).expect("build");
        assert!(!request.allow_downgrade);
    }

    /// spec 坏（不是 JSON / 缺包地址）→ `Err`，调用方据此**不派发**（也不确认）。
    #[test]
    fn upgrade_request_for_refuses_a_broken_spec() {
        let bin = PathBuf::from("/opt/wist/wist-agentd");

        // 不是 JSON。
        let err = upgrade_request_for(bin.clone(), &upgrade_work("not json"))
            .expect_err("unparseable spec must not build a request");
        assert!(err.contains("spec_invalid"), "{err}");

        // 形状对但包地址为空 —— 同样是坏 spec。
        let err = upgrade_request_for(
            bin.clone(),
            &upgrade_work(r#"{"package_url":"   ","package_sha256":"x"}"#),
        )
        .expect_err("empty package_url must not build a request");
        assert!(err.contains("spec_invalid"), "{err}");

        // 缺必填字段。
        let err = upgrade_request_for(bin, &upgrade_work(r#"{"package_url":"https://gw/x"}"#))
            .expect_err("missing sha must not build a request");
        assert!(err.contains("spec_invalid"), "{err}");
    }
}
