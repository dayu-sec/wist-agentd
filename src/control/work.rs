//! 网关授权的工作（agentd 侧的**应用视图**）与折算。
//!
//! 与 `discovery::policy::AppliedDiscoveryPolicy` 同一路子：网关给的是**期望状态**
//! （一份授权快照），这里把它折算成 agentd 真能执行的东西 —— 日志采集任务、
//! 指标上送的开关与周期。HTTP 拉取/确认在 `runtime::daemon` 里（与发现策略一致）。
//!
//! 三条规矩：
//!   1. **默认不做**：没有授权就没有采集任务，也不往数据面上送指标。
//!      一个不做任务工作的 Agent 不该有"顺手的默认采集"。
//!   2. **暂停 ≠ 撤回**：`paused` 的工作仍被持有（记得版本、保留确认），但折算不出任务；
//!      恢复沿用同一版本，不重新审定。
//!   3. **折算不了就说**：`Exporter` / `UnifiedLogPredicate` 这类来源 agentd 现在接不了，
//!      如实记进 `unsupported`，绝不当成"没这回事"。
//!
//! 关于确认（ack）：只对**真正应用了**的工作回报版本。工作参数解析不了就**不回报** ——
//! 网关那边「期望版本一直没被确认」正是漂移的可见形态，回一个确认反而把问题盖住。

use std::collections::BTreeMap;
use std::time::Duration;

use wist_contracts::agent_config::{AgentConfig, LogFileInputSection};
use wist_contracts::work::{
    ACK_WORK_KIND, AckWork, OneShotWork, POLL_WORK_KIND, PollWork, StandingWork, WorkAccepted,
    WorkGrant, WorkSpec,
};
use wist_shared::time::now_rfc3339;

use crate::control::enrollment::enrollment_http_client;

/// 单次拉取/确认请求的超时。
///
/// 两条路径都在主循环里排在采集之前，必须自己封顶 —— 否则网关卡住会连采集一起停。
const WORK_REQUEST_TIMEOUT: Duration = Duration::from_secs(5);

/// 工作里没写清指标周期时的上送间隔（与采集目录里 `MetricInterval` 的策展值同值）。
///
/// 为什么要有默认：`collect_metrics` 单元理论上都带一条 `MetricInterval` 来源，
/// 但"理论上"不该是**必须**——一份缺了周期的授权不该让指标彻底不上送，
/// 该做的是用一个保守的默认值继续上送，并把这件事写进日志。
pub const DEFAULT_METRICS_UPLINK_SECONDS: u64 = 15;

/// 从工作折算出来的一条日志采集任务。
///
/// 带上 `work_id`/`family`/`unit_id` 是为了审计：日志里出现某个采集任务的异常时，
/// 要能立刻回答"这是谁派的活"。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WorkLogInput {
    pub work_id: String,
    pub family: String,
    pub unit_id: String,
    pub input: LogFileInputSection,
}

/// 折算不了的单元（来源类型 agentd 现在接不了）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsupportedUnit {
    pub work_id: String,
    pub unit_id: String,
    /// 具体接不了什么（写清 kind，别让人去猜）。
    pub detail: String,
}

/// 一份被持有的工作。
#[derive(Debug, Clone, PartialEq, Eq)]
struct AppliedWork {
    family: String,
    plan_version: i64,
    /// `active` | `paused` | …
    status: String,
    /// 网关发这份工作时声明的生效时间（落盘时原样记）。
    effective_from: String,
    /// 解析成功的工作参数；`None` = 参数坏了（`spec_detail` 说明哪里坏）。
    spec: Option<WorkSpec>,
    spec_detail: Option<String>,
    /// 已经回报给网关的版本；`None` = 还没确认过。
    acked_plan_version: Option<i64>,
}

impl AppliedWork {
    /// 本工作现在**该不该干活**（期望状态是"做"，且参数能读懂）。
    fn is_working(&self) -> bool {
        self.status == "active" && self.spec.is_some()
    }
}

/// `apply` 的结论：调用方据此决定要回报哪些确认、要打哪些日志。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct ApplyOutcome {
    /// 授权序号变了（哪怕是撤回/暂停也算）。
    pub changed: bool,
    /// 需要回报确认的 `(work_id, plan_version)`。
    pub to_ack: Vec<(String, i64)>,
    /// 刚开始工作的（新授权、恢复、或参数从坏变好）。
    pub started: Vec<String>,
    /// 刚停止工作的（撤回、暂停、或参数变坏）。
    pub stopped: Vec<String>,
    /// 折算不了的单元。
    pub unsupported: Vec<UnsupportedUnit>,
    /// 参数坏了的工作 `(work_id, detail)`。
    pub broken: Vec<(String, String)>,
    /// 新收到的**未执行**的一次性工作（agentd 侧还没实现执行）。
    ///
    /// 为什么要单独列出来而不是直接忽略：收下却不说，运维在网关页面上看到的就是
    /// “派了活但一直没确认”，而具体原因（agent 还不支持）无处可查。
    pub unexecutable_one_shot: Vec<String>,
}

/// 当前持有与在执行的工作（跨 tick 活着）。
#[derive(Debug, Clone, Default)]
pub struct AppliedWorkGrant {
    sequence: i64,
    works: BTreeMap<String, AppliedWork>,
    /// 未了结的一次性工作（网关侧状态 + 内容）。本机还没执行，但要记下来：
    /// 「我手里有这件活」本身是工作内容的一部分。
    one_shot_works: BTreeMap<String, OneShotWork>,
    /// 收到但**未执行**的一次性工作 id（已排序）：留在这里是为了每轮只报一次新增的。
    unexecutable_one_shot: Vec<String>,
}

impl AppliedWorkGrant {
    pub fn sequence(&self) -> i64 {
        self.sequence
    }

    pub fn is_empty(&self) -> bool {
        self.works.is_empty()
    }

    /// 应用一份授权快照（幂等：同一份快照重复应用不产生变化）。
    ///
    /// 全量替换而不是增量合并：快照就是**期望状态**，它没提到的就不该继续做。
    /// 增量合并会让「网关撤回了某份工作」永远生效不了。
    pub fn apply(&mut self, grant: &WorkGrant) -> ApplyOutcome {
        let mut outcome = ApplyOutcome {
            changed: grant.sequence != self.sequence,
            ..Default::default()
        };
        let mut next: BTreeMap<String, AppliedWork> = BTreeMap::new();
        for work in &grant.standing {
            let (spec, spec_detail) = match WorkSpec::parse(&work.spec) {
                Ok(spec) => (Some(spec), None),
                Err(err) => (None, Some(format!("unparsable work spec: {err}"))),
            };
            let previous_ack = self
                .works
                .get(&work.work_id)
                .filter(|previous| previous.plan_version == work.plan_version)
                .and_then(|previous| previous.acked_plan_version);
            if let Some(detail) = spec_detail.clone() {
                outcome.broken.push((work.work_id.clone(), detail));
            }
            next.insert(
                work.work_id.clone(),
                AppliedWork {
                    family: work.family.clone(),
                    plan_version: work.plan_version,
                    status: work.status.clone(),
                    effective_from: work.effective_from.clone(),
                    spec,
                    spec_detail,
                    acked_plan_version: previous_ack,
                },
            );
        }

        // 「开始/停止」按**是否在干活**判定，而不是按有没有这条记录：
        // 暂停（或参数变坏）后不干活了，对采集而言就是停；恢复就是开始。
        for (work_id, work) in &next {
            let was = self.works.get(work_id).is_some_and(AppliedWork::is_working);
            if work.is_working() && !was {
                outcome.started.push(work_id.clone());
            }
        }
        for (work_id, work) in &self.works {
            let is = next.get(work_id).is_some_and(AppliedWork::is_working);
            if work.is_working() && !is {
                outcome.stopped.push(work_id.clone());
            }
        }
        outcome.started.sort();
        outcome.stopped.sort();

        for (work_id, work) in &next {
            // 参数读不懂就不回报（网关会看到漂移，那正是我们要它看见的）。
            if work.spec.is_none() {
                continue;
            }
            if work.acked_plan_version != Some(work.plan_version) {
                outcome.to_ack.push((work_id.clone(), work.plan_version));
            }
        }

        // 一次性工作：**收到了但还不会执行**。不假装收到就完事（不确认），
        // 也不能不说 —— 列出来，让调用方打一行日志，让网关页面上的“一直没确认”有个解释。
        let one_shot_now: Vec<String> = grant
            .one_shot
            .iter()
            .filter(|work| work.is_outstanding())
            .map(|work| work.work_id.clone())
            .collect();
        for work_id in &one_shot_now {
            if !self.unexecutable_one_shot.contains(work_id) {
                outcome.unexecutable_one_shot.push(work_id.clone());
            }
        }
        self.unexecutable_one_shot = one_shot_now;

        self.sequence = grant.sequence;
        self.works = next;
        // 「我手里有哪些一次性工作」跟快照走（快照只带**未了结**的活）。全量替换：
        // 了结的活不该继续留在本机工作视图里 —— 那会让人以为还在等它做什么。
        self.one_shot_works = grant
            .one_shot
            .iter()
            .filter(|work| work.is_outstanding())
            .map(|work| (work.work_id.clone(), work.clone()))
            .collect();
        outcome
    }

    /// 记下某份工作已回报的版本（HTTP 确认成功之后调）。
    pub fn mark_acked(&mut self, work_id: &str, plan_version: i64) {
        if let Some(work) = self.works.get_mut(work_id) {
            work.acked_plan_version = Some(plan_version);
        }
    }

    /// 生成**本机工作视图**（`state/work.json`）：我手里有哪些工作、各自在采什么、
    /// 跑成了哪些任务、哪一版确认过了。
    ///
    /// 从来没收到过任何快照（网关序号还是初始的 0）时返回 `None`：
    /// 那时“没有工作”是一个**未知**而不是事实，不该凭空写一份空清单让人以为“确实没活干”。
    pub fn device_view(&self, recorded_at: &str) -> Option<crate::state_store::work::WorkRecord> {
        if self.sequence == 0 {
            return None;
        }
        let standing = self
            .works
            .iter()
            .map(
                |(work_id, work)| crate::state_store::work::StandingWorkRecord {
                    work_id: work_id.clone(),
                    family: work.family.clone(),
                    status: work.status.clone(),
                    plan_version: work.plan_version,
                    acknowledged_version: work.acked_plan_version,
                    effective_from: work.effective_from.clone(),
                    // 工作内容：直接就是折算时用的那份单元清单。
                    units: work
                        .spec
                        .as_ref()
                        .map(|spec| spec.units.clone())
                        .unwrap_or_default(),
                    // 本机跑起来的采集任务（指标类工作没有任务）。
                    tasks: self
                        .log_inputs()
                        .into_iter()
                        .filter(|entry| &entry.work_id == work_id)
                        .map(|entry| crate::state_store::work::WorkTaskRecord {
                            input_id: entry.input.input_id,
                            path: entry.input.path,
                            startup_position: entry.input.startup_position,
                        })
                        .collect(),
                },
            )
            .collect();
        let one_shot = self
            .one_shot_works
            .values()
            .map(|work| crate::state_store::work::OneShotWorkRecord {
                work_id: work.work_id.clone(),
                action: work.action.clone(),
                spec: work.spec.clone(),
                status: work.status.clone(),
                // 本机执行状态：网关派发的活还没做（agentd 尚未实现一次性工作的执行）。
                execution: "unexecuted".to_string(),
                scheduled_at: work.scheduled_at.clone(),
                deadline_at: work.deadline_at.clone(),
                timeout_seconds: work.timeout_seconds,
            })
            .collect();
        Some(crate::state_store::work::WorkRecord {
            schema_version: crate::state_store::work::SCHEMA_VERSION_V1.to_string(),
            recorded_at: recorded_at.to_string(),
            gateway_sequence: self.sequence,
            standing,
            one_shot,
            metrics_interval_seconds: self
                .metrics_interval()
                .map(|interval| interval.as_secs() as i64),
        })
    }

    /// 从本机工作视图恢复（重启时用）。
    ///
    /// 恢复走的就是 [`apply`](Self::apply) + [`mark_acked`](Self::mark_acked) 这两条既有路径 ——
    /// 不另写一套「从文件推状态」的逻辑，否则那份逻辑迟早与主路不一致。
    /// 效果：重启后**立刻**就按最后已知的工作干活（不再等下一次拉取，网关不可达也能干），
    /// 且已回报的版本被承认、不会把每个版本再点头一遍。
    pub fn restore(record: &crate::state_store::work::WorkRecord) -> Self {
        // 把「本机工作视图」反推成一份等价快照，再走主路应用 —— 两条路算出来的结论必须一样，
        // 这也顺便让「落盘/恢复」这对操作自带一致性检查（单测里锁的正是这一点）。
        let standing = record
            .standing
            .iter()
            .map(|entry| StandingWork {
                work_id: entry.work_id.clone(),
                agent_id: String::new(),
                family: entry.family.clone(),
                spec: WorkSpec {
                    units: entry.units.clone(),
                }
                .encode()
                // 单元清单由本机自己写的，编不回去说明文件被改坏了：
                // 用空清单让它**报出参数坏**（与网关发了坏参数同一处置），不静默当没工作。
                .unwrap_or_else(|_| "unparsable".to_string()),
                catalog_version: 0,
                proposal_id: None,
                plan_version: entry.plan_version,
                effective_from: entry.effective_from.clone(),
                status: entry.status.clone(),
                updated_by: String::new(),
                updated_at: String::new(),
            })
            .collect();
        let mut runtime = Self {
            sequence: record.gateway_sequence,
            ..Default::default()
        };
        let _ = runtime.apply(&WorkGrant {
            agent_id: String::new(),
            standing,
            one_shot: Vec::new(),
            sequence: record.gateway_sequence,
            granted_at: record.recorded_at.clone(),
        });
        for entry in &record.standing {
            if let Some(version) = entry.acknowledged_version {
                runtime.mark_acked(&entry.work_id, version);
            }
        }
        // 一次性工作也要回到「我手里有哪些」里（页面/日志看得到），而不仅是 `unexecutable` 名单。
        for entry in &record.one_shot {
            runtime.one_shot_works.insert(
                entry.work_id.clone(),
                OneShotWork {
                    work_id: entry.work_id.clone(),
                    agent_id: String::new(),
                    action: entry.action.clone(),
                    spec: entry.spec.clone(),
                    scheduled_at: entry.scheduled_at.clone(),
                    deadline_at: entry.deadline_at.clone(),
                    timeout_seconds: entry.timeout_seconds,
                    interruptible: false,
                    status: entry.status.clone(),
                    paused_at: None,
                    paused_total_seconds: 0,
                    current_step: None,
                    completed_steps: Vec::new(),
                    attempt: 0,
                    issued_by: String::new(),
                    issued_at: String::new(),
                },
            );
            if !runtime.unexecutable_one_shot.contains(&entry.work_id) {
                runtime.unexecutable_one_shot.push(entry.work_id.clone());
            }
        }
        runtime.unexecutable_one_shot.sort();
        runtime
    }

    /// 折算出的日志采集任务（只来自**正在干活**的单元）。
    pub fn log_inputs(&self) -> Vec<WorkLogInput> {
        let mut inputs = Vec::new();
        for (work_id, work) in &self.works {
            if !work.is_working() {
                continue;
            }
            let Some(spec) = work.spec.as_ref() else {
                continue;
            };
            for unit in &spec.units {
                if unit.capability != "collect_logs" {
                    continue;
                }
                let globs = unit.file_globs();
                for (index, glob) in globs.iter().enumerate() {
                    // 一个单元可能有多条路径通配，任务 id 必须各不相同（它是落盘文件名的一部分）。
                    let suffix = if globs.len() > 1 {
                        format!("-{}", index + 1)
                    } else {
                        String::new()
                    };
                    inputs.push(WorkLogInput {
                        work_id: work_id.clone(),
                        family: work.family.clone(),
                        unit_id: unit.unit_id.clone(),
                        input: LogFileInputSection {
                            input_id: format!(
                                "work-{}-{}{}",
                                safe_token(&work.family),
                                safe_token(&unit.unit_id),
                                suffix
                            ),
                            path: glob.to_string(),
                            // 授权采集不重放历史：平台派活时若从文件头读，一台机器上
                            // 几百 MB 的历史日志会在派活瞬间灌进数据面。要回放历史是
                            // **运维的一次性动作**，不该由"授权"顺带触发。
                            startup_position: "tail".to_string(),
                            multiline_mode: "none".to_string(),
                        },
                    });
                }
            }
        }
        inputs
    }

    /// 指标上送的周期；`None` = 现在不该上送（没有授权的指标工作）。
    ///
    /// 取所有在干活的指标工作里**最密**的那个周期：要得最急的需求是上送频率的下界。
    pub fn metrics_interval(&self) -> Option<Duration> {
        let mut seconds: Option<i64> = None;
        for work in self.works.values() {
            if !work.is_working() {
                continue;
            }
            let Some(spec) = work.spec.as_ref() else {
                continue;
            };
            if !spec
                .units
                .iter()
                .any(|unit| unit.capability == "collect_metrics")
            {
                continue;
            }
            let interval = spec
                .metric_interval_seconds()
                .unwrap_or(DEFAULT_METRICS_UPLINK_SECONDS as i64);
            seconds = Some(match seconds {
                Some(current) => current.min(interval),
                None => interval,
            });
        }
        seconds.map(|seconds| Duration::from_secs(seconds.max(1) as u64))
    }

    /// 折算不了的单元（`Exporter` / `UnifiedLogPredicate` …）。
    pub fn unsupported_units(&self) -> Vec<UnsupportedUnit> {
        let mut unsupported = Vec::new();
        for (work_id, work) in &self.works {
            if !work.is_working() {
                continue;
            }
            let Some(spec) = work.spec.as_ref() else {
                continue;
            };
            for unit in &spec.units {
                for source in unit.unsupported_sources() {
                    unsupported.push(UnsupportedUnit {
                        work_id: work_id.clone(),
                        unit_id: unit.unit_id.clone(),
                        detail: format!(
                            "source kind {} is not collectable on this agent",
                            source.kind
                        ),
                    });
                }
            }
        }
        unsupported
    }

    /// 一行可读状态（日志用）。刻意包含"几份在干活、几条任务、指标开没开"，
    /// 因为运维问的第一个问题就是这些，不该逼人从别处的数字反推。
    pub fn summary(&self) -> String {
        let working = self.works.values().filter(|work| work.is_working()).count();
        let log_inputs = self.log_inputs().len();
        let metrics = match self.metrics_interval() {
            Some(interval) => format!("on({}s)", interval.as_secs()),
            None => "off".to_string(),
        };
        let unsupported = self.unsupported_units().len();
        format!(
            "held={} working={} log_inputs={} metrics={} unsupported_units={} one_shot_pending={}",
            self.works.len(),
            working,
            log_inputs,
            metrics,
            unsupported,
            self.unexecutable_one_shot.len()
        )
    }

    /// 收到但未执行的一次性工作（agentd 侧未实现执行）。
    pub fn unexecutable_one_shot(&self) -> &[String] {
        &self.unexecutable_one_shot
    }
}

/// 让 id 能安全地当**文件名**用（spool 与 checkpoint 都拿 input_id 拼路径）。
///
/// 目录里的 unit_id 是策展数据、由人手写，没有一个字符集校验兜着；
/// 一个带 `/` 的 id 会让落盘路径跑到别处去 —— 这里做一次收敛，而不是指望上游。
fn safe_token(raw: &str) -> String {
    raw.chars()
        .map(|ch| {
            if ch.is_ascii_alphanumeric() || ch == '-' || ch == '_' {
                ch
            } else {
                '-'
            }
        })
        .collect()
}

/// 拉取工作授权快照。
///
/// 返回 `None` 表示“这次没拿到”（未入网 / 网关出错 / 响应看不懂），
/// 调用方应**保留上次应用的工作** —— 拉不到不等于没授权。
/// 这条路径在主循环里，所以单次请求超时由调用方封顶（见 `WORK_FETCH_TIMEOUT`）。
pub(crate) async fn fetch_work_grant(
    config: &AgentConfig,
    last_seen_sequence: i64,
) -> Option<WorkGrant> {
    let endpoint = config.control_plane.endpoint.as_deref()?;
    let bearer_token = config.control_plane.bearer_token.as_deref()?;
    let agent_id = config.agent.agent_id.as_deref()?;
    let instance_id = config.agent.instance_name.as_deref().unwrap_or_default();

    let request = PollWork {
        api_version: wist_contracts::API_VERSION_V1.to_string(),
        kind: POLL_WORK_KIND.to_string(),
        agent_id: agent_id.to_string(),
        instance_id: instance_id.to_string(),
        last_seen_sequence,
        // 不带长轮询：快照是幂等的，拉一次就够；带 wait 会让主循环被网关牵着走。
        wait_ms: 0,
        requested_at: now_rfc3339(),
    };
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("wist-agentd work grant fetch: failed to build client: {err}");
            return None;
        }
    };
    let url = format!("{}/api/v1/agent/work:poll", endpoint.trim_end_matches('/'));
    match client
        .post(&url)
        .timeout(WORK_REQUEST_TIMEOUT)
        .bearer_auth(bearer_token)
        .json(&request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<WorkGrant>().await {
                Ok(grant) => Some(grant),
                Err(err) => {
                    eprintln!(
                        "wist-agentd work grant fetch failed: invalid response from {endpoint}: {err}"
                    );
                    None
                }
            }
        }
        Ok(response) => {
            eprintln!(
                "wist-agentd work grant fetch failed: HTTP {} from {endpoint}",
                response.status()
            );
            None
        }
        Err(err) => {
            eprintln!("wist-agentd work grant fetch failed: {err}");
            None
        }
    }
}

/// 回报收到某份工作（含生效版本）。
///
/// 返回是否**真的回报成功**：失败就不算确认，下一轮还会再报（而不是当已经报过了）。
/// 三种结果（`accepted` / `stale` / `unknown`）里只有 `accepted` 才算成功：
/// `stale` 说明网关已经改过版（下一轮会拉到新版本），`unknown` 说明这份工作已经没了。
pub(crate) async fn ack_work(config: &AgentConfig, work_id: &str, plan_version: i64) -> bool {
    let Some(endpoint) = config.control_plane.endpoint.as_deref() else {
        return false;
    };
    let Some(bearer_token) = config.control_plane.bearer_token.as_deref() else {
        return false;
    };
    let Some(agent_id) = config.agent.agent_id.as_deref() else {
        return false;
    };
    let request = AckWork {
        api_version: wist_contracts::API_VERSION_V1.to_string(),
        kind: ACK_WORK_KIND.to_string(),
        agent_id: agent_id.to_string(),
        instance_id: config
            .agent
            .instance_name
            .as_deref()
            .unwrap_or_default()
            .to_string(),
        work_id: work_id.to_string(),
        plan_version,
        acknowledged_at: now_rfc3339(),
    };
    let client = match enrollment_http_client(config) {
        Ok(client) => client,
        Err(err) => {
            eprintln!("wist-agentd work ack: failed to build client: {err}");
            return false;
        }
    };
    let url = format!("{}/api/v1/agent/work:ack", endpoint.trim_end_matches('/'));
    match client
        .post(&url)
        .timeout(WORK_REQUEST_TIMEOUT)
        .bearer_auth(bearer_token)
        .json(&request)
        .send()
        .await
    {
        Ok(response) if response.status().is_success() => {
            match response.json::<WorkAccepted>().await {
                Ok(accepted) => accepted.status == "accepted",
                Err(err) => {
                    eprintln!("wist-agentd work ack failed: invalid response: {err}");
                    false
                }
            }
        }
        Ok(response) => {
            eprintln!(
                "wist-agentd work ack failed: HTTP {} from {endpoint}",
                response.status()
            );
            false
        }
        Err(err) => {
            eprintln!("wist-agentd work ack failed: {err}");
            false
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::state_store::work::SCHEMA_VERSION_V1;

    fn spec(units: &[(&str, &str, &str)]) -> String {
        // (unit_id, capability, source) —— source 形如 `FileGlob:/a/b*`。
        let units: Vec<String> = units
            .iter()
            .map(|(unit_id, capability, source)| {
                let (kind, target) = source.split_once(':').expect("source kind:target");
                format!(
                    r#"{{"unit_id":"{unit_id}","capability":"{capability}","rule_ref":"r","requires_privilege":"none","sources":[{{"kind":"{kind}","target":"{target}"}}]}}"#
                )
            })
            .collect();
        format!(r#"{{"units":[{}]}}"#, units.join(","))
    }

    fn standing(
        work_id: &str,
        family: &str,
        plan_version: i64,
        status: &str,
        spec: &str,
    ) -> StandingWork {
        StandingWork {
            work_id: work_id.to_string(),
            agent_id: "agent-1".to_string(),
            family: family.to_string(),
            spec: spec.to_string(),
            catalog_version: 1,
            proposal_id: None,
            plan_version,
            effective_from: "2026-09-23T00:00:00Z".to_string(),
            status: status.to_string(),
            updated_by: "admin".to_string(),
            updated_at: "2026-09-23T00:00:00Z".to_string(),
        }
    }

    fn grant(sequence: i64, standing: Vec<StandingWork>) -> WorkGrant {
        WorkGrant {
            agent_id: "agent-1".to_string(),
            standing,
            one_shot: Vec::new(),
            sequence,
            granted_at: "2026-09-23T00:00:00Z".to_string(),
        }
    }

    #[test]
    fn nothing_is_granted_means_nothing_gets_done() {
        // 一个不做任务工作的 Agent：没有授权就没有日志任务，也不上送指标。
        let applied = AppliedWorkGrant::default();
        assert!(applied.log_inputs().is_empty());
        assert_eq!(applied.metrics_interval(), None);
        assert!(applied.is_empty());
    }

    #[test]
    fn a_granted_log_family_becomes_a_local_collection_task() {
        let mut applied = AppliedWorkGrant::default();
        let outcome = applied.apply(&grant(
            1,
            vec![standing(
                "work-1",
                "CrashPanic",
                1,
                "active",
                &spec(&[
                    (
                        "mac-crash-panic",
                        "collect_logs",
                        "FileGlob:/Library/Logs/DiagnosticReports/*.ips",
                    ),
                    (
                        "mac-crash-other",
                        "collect_logs",
                        "FileGlob:/Library/Logs/DiagnosticReports/*.panic",
                    ),
                ]),
            )],
        ));

        assert!(outcome.changed);
        assert_eq!(outcome.started, vec!["work-1"]);
        assert_eq!(outcome.to_ack, vec![("work-1".to_string(), 1)]);

        let inputs = applied.log_inputs();
        assert_eq!(inputs.len(), 2);
        assert_eq!(inputs[0].input.input_id, "work-CrashPanic-mac-crash-panic");
        assert_eq!(
            inputs[0].input.path,
            "/Library/Logs/DiagnosticReports/*.ips"
        );
        assert_eq!(inputs[1].input.input_id, "work-CrashPanic-mac-crash-other");
        assert_eq!(
            inputs[1].input.path,
            "/Library/Logs/DiagnosticReports/*.panic"
        );
        // 授权采集不重放历史（否则派活瞬间会灌进几百 MB）。
        assert_eq!(inputs[0].input.startup_position, "tail");
        assert_eq!(inputs[0].family, "CrashPanic");
        // 指标面无授权 → 不上送。
        assert_eq!(applied.metrics_interval(), None);
    }

    #[test]
    fn metrics_follow_the_granted_interval_and_the_tightest_one_wins() {
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            1,
            vec![
                standing(
                    "work-m",
                    "HostMetrics",
                    1,
                    "active",
                    &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
                ),
                standing(
                    "work-x",
                    "ComputeWorkload",
                    1,
                    "active",
                    &spec(&[("c-metrics", "collect_metrics", "MetricInterval:60s")]),
                ),
            ],
        ));
        assert_eq!(applied.metrics_interval(), Some(Duration::from_secs(15)));

        // 没写周期的指标工作用默认值继续上送，而不是彻底不上送。
        let mut missing = AppliedWorkGrant::default();
        missing.apply(&grant(
            1,
            vec![standing(
                "work-m",
                "HostMetrics",
                1,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "FileGlob:/x")]),
            )],
        ));
        assert_eq!(
            missing.metrics_interval(),
            Some(Duration::from_secs(DEFAULT_METRICS_UPLINK_SECONDS))
        );
    }

    #[test]
    fn a_paused_work_is_held_but_produces_no_tasks() {
        let mut applied = AppliedWorkGrant::default();
        let applied_once = applied.apply(&grant(
            1,
            vec![standing(
                "work-m",
                "HostMetrics",
                3,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        assert_eq!(applied_once.to_ack, vec![("work-m".to_string(), 3)]);
        applied.mark_acked("work-m", 3);
        assert!(applied.metrics_interval().is_some());

        let outcome = applied.apply(&grant(
            2,
            vec![standing(
                "work-m",
                "HostMetrics",
                3,
                "paused",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        assert_eq!(outcome.stopped, vec!["work-m"]);
        // 暂停是期望状态的一部分：没在做不算漂移，所以不产生"要确认"。
        assert!(outcome.to_ack.is_empty());
        assert_eq!(applied.metrics_interval(), None);
        // 但工作仍被持有，恢复也不重新审定（版本还是 3，直接开始干活）。
        assert!(!applied.is_empty());
        let resumed = applied.apply(&grant(
            3,
            vec![standing(
                "work-m",
                "HostMetrics",
                3,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        assert_eq!(resumed.started, vec!["work-m"]);
        assert!(resumed.to_ack.is_empty(), "版本没变就不重复确认");
    }

    #[test]
    fn a_bumped_plan_version_is_re_acked_and_re_applied() {
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            1,
            vec![standing(
                "work-1",
                "HostMetrics",
                1,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        applied.mark_acked("work-1", 1);
        // 幂等：同一份快照再来一次，不产生任何变化。
        let repeat = applied.apply(&grant(
            1,
            vec![standing(
                "work-1",
                "HostMetrics",
                1,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        assert!(!repeat.changed);
        assert!(repeat.to_ack.is_empty());
        assert!(repeat.started.is_empty());

        // 版本 +1（网关改过内容）→ 重新应用、重新确认。
        let bumped = applied.apply(&grant(
            2,
            vec![standing(
                "work-1",
                "HostMetrics",
                2,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:60s")]),
            )],
        ));
        assert!(bumped.changed);
        assert_eq!(bumped.to_ack, vec![("work-1".to_string(), 2)]);
        assert_eq!(applied.metrics_interval(), Some(Duration::from_secs(60)));
        // 还没回报之前，下一次 apply 仍会要求确认（不会"就地当已确认"）。
        assert_eq!(
            applied
                .apply(&grant(
                    2,
                    vec![standing(
                        "work-1",
                        "HostMetrics",
                        2,
                        "active",
                        &spec(&[("h-metrics", "collect_metrics", "MetricInterval:60s")])
                    )],
                ))
                .to_ack,
            vec![("work-1".to_string(), 2)]
        );
        applied.mark_acked("work-1", 2);
        assert!(
            applied
                .apply(&grant(
                    2,
                    vec![standing(
                        "work-1",
                        "HostMetrics",
                        2,
                        "active",
                        &spec(&[("h-metrics", "collect_metrics", "MetricInterval:60s")])
                    )],
                ))
                .to_ack
                .is_empty()
        );
    }

    #[test]
    fn a_revoked_work_stops_and_an_empty_grant_clears_everything() {
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            1,
            vec![standing(
                "work-1",
                "HostMetrics",
                1,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        // 撤回 = 快照里不再有这条（网关侧状态是 revoked，不再下发）。
        let outcome = applied.apply(&grant(2, Vec::new()));
        assert!(outcome.changed);
        assert_eq!(outcome.stopped, vec!["work-1"]);
        assert_eq!(applied.metrics_interval(), None);
        assert!(applied.is_empty());
    }

    #[test]
    fn an_outstanding_one_shot_work_is_reported_as_unexecutable() {
        // agentd 还没实现一次性工作的执行：收到了就**说出来**（不确认、也不装看不见）。
        let mut applied = AppliedWorkGrant::default();
        let mut snapshot = grant(1, Vec::new());
        snapshot.one_shot = vec![wist_contracts::work::OneShotWork {
            work_id: "work-upgrade".to_string(),
            agent_id: "agent-1".to_string(),
            action: "upgrade".to_string(),
            spec: "0.1.4".to_string(),
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
        }];

        let outcome = applied.apply(&snapshot);
        assert_eq!(outcome.unexecutable_one_shot, vec!["work-upgrade"]);
        assert!(outcome.to_ack.is_empty(), "不确认没执行的活");
        assert!(applied.summary().contains("one_shot_pending=1"));

        // 同一份快照重复应用不重复报（幂等）。
        assert!(applied.apply(&snapshot).unexecutable_one_shot.is_empty());

        // 了结了就不再挂着（快照里不再带它）。
        let outcome = applied.apply(&grant(2, Vec::new()));
        assert!(!outcome.changed || outcome.unexecutable_one_shot.is_empty());
        assert!(applied.summary().contains("one_shot_pending=0"));
    }

    #[test]
    fn a_broken_spec_is_reported_and_not_acked() {
        let mut applied = AppliedWorkGrant::default();
        let outcome = applied.apply(&grant(
            1,
            vec![standing("work-1", "HostMetrics", 1, "active", "not-json")],
        ));
        // 不确认：网关看到「期望版本没被确认」才是这条坏参数真被看见的形态。
        assert!(outcome.to_ack.is_empty());
        assert_eq!(outcome.broken.len(), 1);
        assert_eq!(outcome.broken[0].0, "work-1");
        assert!(outcome.started.is_empty());
        assert_eq!(applied.metrics_interval(), None);

        // 参数从坏变好 → 开始干活并确认。
        let fixed = applied.apply(&grant(
            2,
            vec![standing(
                "work-1",
                "HostMetrics",
                1,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        assert_eq!(fixed.started, vec!["work-1"]);
        assert_eq!(fixed.to_ack, vec![("work-1".to_string(), 1)]);
    }

    #[test]
    fn unsupported_sources_are_reported_not_swallowed() {
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            1,
            vec![standing(
                "work-1",
                "PrivilegeExecution",
                1,
                "active",
                &spec(&[
                    (
                        "mac-privilege-exec",
                        "collect_logs",
                        "Exporter:praudit(/var/audit)",
                    ),
                    (
                        "mac-privilege-files",
                        "collect_logs",
                        "FileGlob:/var/log/pra*",
                    ),
                ]),
            )],
        ));
        // 能接的接了（一条 FileGlob），接不了的如实报出来。
        assert_eq!(applied.log_inputs().len(), 1);
        let unsupported = applied.unsupported_units();
        assert_eq!(unsupported.len(), 1);
        assert_eq!(unsupported[0].unit_id, "mac-privilege-exec");
        assert!(unsupported[0].detail.contains("Exporter"));
    }

    #[test]
    fn task_ids_are_filename_safe() {
        // 目录是策展数据，unit_id 由一个没有字符集校验的上游手写。
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            1,
            vec![standing(
                "work-1",
                "MiscSystem",
                1,
                "active",
                &spec(&[("weird/../id", "collect_logs", "FileGlob:/var/log/a*")]),
            )],
        ));
        let inputs = applied.log_inputs();
        assert_eq!(inputs[0].input.input_id, "work-MiscSystem-weird----id");
        assert!(!inputs[0].input.input_id.contains('/'));
    }

    // ── 本机工作视图（state/work.json）──

    #[test]
    fn a_work_view_needs_a_received_grant_and_carries_what_we_are_doing() {
        // 还没收到任何快照（序号仍是初始的 0）："没有工作"此刻是个**未知**而不是事实，
        // 不该凭空写一份空清单让人以为"确实没活干"。
        assert!(AppliedWorkGrant::default().device_view("t0").is_none());

        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            4,
            vec![
                standing(
                    "work-m",
                    "HostMetrics",
                    2,
                    "active",
                    &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
                ),
                standing(
                    "work-l",
                    "CrashPanic",
                    1,
                    "active",
                    &spec(&[(
                        "mac-crash",
                        "collect_logs",
                        "FileGlob:/Library/Logs/DiagnosticReports/*.ips",
                    )]),
                ),
            ],
        ));
        applied.mark_acked("work-m", 2);

        let view = applied.device_view("t-recorded").expect("view");
        assert_eq!(view.schema_version, SCHEMA_VERSION_V1);
        assert_eq!(view.recorded_at, "t-recorded");
        // 只留最小溯源，不是授权副本：想知道网关当时发了什么，答案在网关。
        assert_eq!(view.gateway_sequence, 4);
        assert_eq!(view.metrics_interval_seconds, Some(15));
        assert!(view.one_shot.is_empty());

        let metrics = view
            .standing
            .iter()
            .find(|work| work.work_id == "work-m")
            .expect("work-m");
        assert_eq!(metrics.family, "HostMetrics");
        assert_eq!(metrics.status, "active");
        assert_eq!(metrics.plan_version, 2);
        assert_eq!(metrics.acknowledged_version, Some(2));
        // 工作内容：真在采什么。
        assert_eq!(metrics.units.len(), 1);
        assert_eq!(metrics.units[0].unit_id, "h-metrics");
        assert!(metrics.tasks.is_empty(), "指标类工作没有采集任务");

        let logs = view
            .standing
            .iter()
            .find(|work| work.work_id == "work-l")
            .expect("work-l");
        // 没确认的就不该写成已确认。
        assert_eq!(logs.acknowledged_version, None);
        assert_eq!(logs.units.len(), 1);
        assert_eq!(logs.units[0].sources[0].kind, "FileGlob");
        // 本机跑起来的采集任务：任务 id 同时是落盘目录名。
        assert_eq!(logs.tasks.len(), 1);
        assert_eq!(logs.tasks[0].input_id, "work-CrashPanic-mac-crash");
        assert_eq!(logs.tasks[0].path, "/Library/Logs/DiagnosticReports/*.ips");
        assert_eq!(logs.tasks[0].startup_position, "tail");
    }

    #[test]
    fn the_work_view_holds_the_one_shot_work_we_have_not_executed() {
        let mut applied = AppliedWorkGrant::default();
        let mut snapshot = grant(1, Vec::new());
        snapshot.one_shot = vec![wist_contracts::work::OneShotWork {
            work_id: "work-upgrade".to_string(),
            agent_id: "agent-1".to_string(),
            action: "upgrade".to_string(),
            spec: "0.1.4".to_string(),
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
        }];
        applied.apply(&snapshot);

        let view = applied.device_view("t0").expect("view");
        assert_eq!(view.one_shot.len(), 1);
        let work = &view.one_shot[0];
        assert_eq!(work.work_id, "work-upgrade");
        assert_eq!(work.action, "upgrade");
        assert_eq!(work.spec, "0.1.4");
        // 两个轴分开记：`status` 是网关侧的派发状态，`execution` 是本机执行状态。
        assert_eq!(work.status, "dispatched");
        assert_eq!(work.execution, "unexecuted");
        assert_eq!(work.deadline_at, "2026-09-24T00:00:00Z");
        assert_eq!(work.timeout_seconds, 600);

        // 了结了就不该继续挂在"我手里的活"里。
        applied.apply(&grant(2, Vec::new()));
        assert!(applied.device_view("t1").expect("view").one_shot.is_empty());
    }

    #[test]
    fn restore_brings_back_the_confirmed_versions_so_nothing_is_re_acked() {
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            4,
            vec![standing(
                "work-m",
                "HostMetrics",
                2,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        ));
        applied.mark_acked("work-m", 2);
        let view = applied.device_view("t0").expect("view");

        // 重启：从本机工作视图恢复（照的就是 apply + mark_acked 这条主路）。
        let mut restored = AppliedWorkGrant::restore(&view);
        assert_eq!(restored.sequence(), 4);
        assert_eq!(restored.metrics_interval(), Some(Duration::from_secs(15)));
        assert!(restored.summary().contains("working=1"));

        // 关键：同一份快照再来一次**不会**重复确认，也不会在页面上闪一次漂移。
        let repeat = restored.apply(&applied_grant_repeat());
        assert!(!repeat.changed);
        assert!(repeat.to_ack.is_empty());
        assert!(restored.apply(&applied_grant_repeat()).to_ack.is_empty());

        // 但真涨了版本还是要重新应用并重新确认。
        let bumped = restored.apply(&grant(
            5,
            vec![standing(
                "work-m",
                "HostMetrics",
                3,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:60s")]),
            )],
        ));
        assert_eq!(bumped.to_ack, vec![("work-m".to_string(), 3)]);
        assert_eq!(restored.metrics_interval(), Some(Duration::from_secs(60)));
    }

    #[test]
    fn restore_writes_back_an_identical_view() {
        // 落盘 → 恢复 → 再落盘：两份视图必须一样。这条往返把"视图"与"恢复"
        // 锁在一起，否则恢复漏掉的字段会一直安静地退化。
        let mut applied = AppliedWorkGrant::default();
        let mut snapshot = grant(
            7,
            vec![standing(
                "work-l",
                "CrashPanic",
                1,
                "active",
                &spec(&[("mac-crash", "collect_logs", "FileGlob:/a/*")]),
            )],
        );
        snapshot.one_shot = vec![wist_contracts::work::OneShotWork {
            work_id: "work-exec".to_string(),
            agent_id: "agent-1".to_string(),
            action: "exec".to_string(),
            spec: "id".to_string(),
            scheduled_at: "2026-09-23T00:00:00Z".to_string(),
            deadline_at: "2026-09-24T00:00:00Z".to_string(),
            timeout_seconds: 60,
            interruptible: true,
            status: "dispatched".to_string(),
            paused_at: None,
            paused_total_seconds: 0,
            current_step: None,
            completed_steps: Vec::new(),
            attempt: 0,
            issued_by: "admin".to_string(),
            issued_at: "2026-09-23T00:00:00Z".to_string(),
        }];
        applied.apply(&snapshot);
        let first = applied.device_view("t-recorded").expect("view");

        let back = AppliedWorkGrant::restore(&first)
            .device_view("t-recorded")
            .expect("view");
        assert_eq!(first, back);
    }

    fn applied_grant_repeat() -> WorkGrant {
        grant(
            4,
            vec![standing(
                "work-m",
                "HostMetrics",
                2,
                "active",
                &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
            )],
        )
    }

    #[test]
    fn summary_answers_what_is_going_on_at_a_glance() {
        let mut applied = AppliedWorkGrant::default();
        applied.apply(&grant(
            1,
            vec![
                standing(
                    "work-m",
                    "HostMetrics",
                    1,
                    "active",
                    &spec(&[("h-metrics", "collect_metrics", "MetricInterval:15s")]),
                ),
                standing(
                    "work-l",
                    "CrashPanic",
                    1,
                    "active",
                    &spec(&[("mac-crash", "collect_logs", "FileGlob:/a/*")]),
                ),
                standing(
                    "work-p",
                    "LoginSession",
                    1,
                    "paused",
                    &spec(&[("mac-login", "collect_logs", "FileGlob:/b/*")]),
                ),
            ],
        ));
        let summary = applied.summary();
        assert!(summary.contains("held=3"), "{summary}");
        assert!(summary.contains("working=2"), "{summary}");
        assert!(summary.contains("log_inputs=1"), "{summary}");
        assert!(summary.contains("metrics=on(15s)"), "{summary}");
    }

    // ── 与网关的往返（拉快照 / 回报确认） ──

    use std::io::{Read, Write as _};
    use std::net::TcpListener;

    use wist_contracts::agent_config::{
        AgentSection, ControlPlaneSection, ExecutionSection, PathsSection,
    };

    fn test_config(endpoint: String) -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: Some("agent-x".to_string()),
                environment_id: None,
                instance_name: Some("instance-x".to_string()),
            },
            ControlPlaneSection {
                enabled: true,
                endpoint: Some(endpoint),
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
            ExecutionSection::default(),
        )
    }

    /// 收一个完整请求（含 body）。
    fn read_http_request(socket: &mut std::net::TcpStream) -> String {
        socket
            .set_read_timeout(Some(Duration::from_secs(5)))
            .expect("set read timeout");
        let mut bytes = Vec::new();
        let mut chunk = [0u8; 1024];
        loop {
            let read = socket.read(&mut chunk).expect("read request");
            if read == 0 {
                break;
            }
            bytes.extend_from_slice(&chunk[..read]);
            let Some(header_end) = bytes.windows(4).position(|w| w == b"\r\n\r\n") else {
                continue;
            };
            let headers = String::from_utf8_lossy(&bytes[..header_end]).to_string();
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
            if bytes.len() >= header_end + 4 + content_length {
                break;
            }
        }
        String::from_utf8_lossy(&bytes).into_owned()
    }

    fn serve_once(listener: TcpListener, body: &'static str) -> std::thread::JoinHandle<String> {
        std::thread::spawn(move || {
            let (mut socket, _) = listener.accept().expect("accept");
            let request = read_http_request(&mut socket);
            let response = format!(
                "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{}",
                body.len(),
                body
            );
            socket
                .write_all(response.as_bytes())
                .expect("write response");
            request
        })
    }

    #[tokio::test]
    async fn fetch_work_grant_posts_poll_and_parses_the_snapshot() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let body = r#"{"agent_id":"agent-x","standing":[{"work_id":"w1","agent_id":"agent-x","family":"HostMetrics","spec":"{\"units\":[]}","catalog_version":1,"plan_version":2,"effective_from":"t","status":"active","updated_by":"admin","updated_at":"t"}],"one_shot":[],"sequence":7,"granted_at":"t"}"#;
        let server = serve_once(listener, body);

        let grant = fetch_work_grant(&test_config(endpoint), 3)
            .await
            .expect("grant returned");
        let request = server.join().expect("join server");

        assert!(request.contains("/api/v1/agent/work:poll"));
        assert!(
            request
                .to_lowercase()
                .contains("authorization: bearer wic_test_token")
        );
        assert!(request.contains("\"kind\":\"poll_work\""));
        assert!(request.contains("\"api_version\":\"v1\""));
        assert!(request.contains("\"agent_id\":\"agent-x\""));
        assert!(request.contains("\"instance_id\":\"instance-x\""));
        // 带上手上那份的授权序号：网关可以据此在没变化时短路。
        assert!(request.contains("\"last_seen_sequence\":3"));
        assert_eq!(grant.sequence, 7);
        assert_eq!(grant.standing[0].plan_version, 2);
    }

    #[tokio::test]
    async fn fetch_work_grant_returns_none_when_the_gateway_is_unreachable() {
        // 拉不到 ≠ 没授权：返回 None，调用方保留上次应用的工作。
        let config = test_config("http://127.0.0.1:1".to_string());
        assert!(fetch_work_grant(&config, 0).await.is_none());
        // 没入网（没有端点/凭据）时同样安静地返回 None，而不是报错。
        let mut offline = test_config("http://127.0.0.1:1".to_string());
        offline.control_plane.endpoint = None;
        assert!(fetch_work_grant(&offline, 0).await.is_none());
    }

    #[tokio::test]
    async fn ack_work_reports_the_version_and_only_accepted_counts() {
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let body = r#"{"work_id":"w1","status":"accepted","accepted_at":"t"}"#;
        let server = serve_once(listener, body);
        assert!(ack_work(&test_config(endpoint), "w1", 2).await);
        let request = server.join().expect("join server");
        assert!(request.contains("/api/v1/agent/work:ack"));
        assert!(request.contains("\"kind\":\"ack_work\""));
        assert!(request.contains("\"work_id\":\"w1\""));
        assert!(request.contains("\"plan_version\":2"));

        // `stale`（网关已改版）不算确认：下一轮拉新版本再报。
        let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
        let endpoint = format!("http://{}", listener.local_addr().expect("addr"));
        let server = serve_once(
            listener,
            r#"{"work_id":"w1","status":"stale","accepted_at":"t"}"#,
        );
        assert!(!ack_work(&test_config(endpoint), "w1", 2).await);
        server.join().expect("join server");
    }
}
