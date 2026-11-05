//! 采集契约：结果形状、日志闸门与告警聚合。
//!
//! 为什么单独一层：调度器（[`super::scheduler`]）要同时管主机、Kafka，以及后面的数据库。
//! 它们只在「结果长什么样」「失败怎么报」上统一，协议与查询各写各的 ——
//! 统一的边界就落在这个文件里。
//!
//! 设计见 `docs/design/metrics-collection-runtime.md` §6。

use std::collections::BTreeMap;

use super::kafka::{GroupCache, KafkaProbeConfig};
use super::mysql::MysqlProbeConfig;
use super::runtime::{MetricsCollectionOutcome, MetricsCollectionTargetSample};
use super::target_view::{MetricsTargetView, MetricsTargetViewEntry};

/// 一次采集作业。
///
/// 为什么是 `enum` 而不是 `trait object`：域只有两个，`match` 分发零分配、也没有
/// 对象安全负担；域超过 5 个再评估换成 boxed-future 的 trait（见设计文档 §6.2 / §12）。
/// 作业**拥有**它需要的那份状态：异步执行时不能借用调度器锁里的东西。
pub(super) enum Collector {
    /// 主机 / 进程 / 容器：目标来自 `target_view`（发现策略），不是工作授权。
    Host(MetricsTargetView),
    /// Kafka：目标来自采集面授权 + 本机自探。
    Kafka {
        /// 盒子是为了不把 enum 撑大（`large_enum_variant`）。
        config: Box<KafkaProbeConfig>,
        groups: GroupCache,
    },
    /// MySQL / TiDB：作业内部自己开连接（不进调度器状态）。
    Mysql(Box<MysqlProbeConfig>),
}

/// 一轮采集的产物。
pub(super) enum CollectorOutput {
    Host {
        /// 用于回填校验：采集期间目标集合被换掉就丢弃这一轮。
        used: Vec<MetricsTargetViewEntry>,
        outcomes: Vec<MetricsCollectionOutcome>,
    },
    Kafka {
        result: ProbeResult,
        /// 消费组缓存跟着作业走，回来时交还调度器（下一轮继续用）。
        groups: GroupCache,
    },
    Mysql {
        result: ProbeResult,
    },
}

impl Collector {
    fn domain(&self) -> &'static str {
        match self {
            Self::Host(_) => "host_metrics",
            Self::Kafka { .. } => super::kafka::COLLECTION_KIND,
            Self::Mysql(_) => super::mysql::COLLECTION_KIND,
        }
    }

    /// 异步执行一轮。
    ///
    /// 同步实现统一丢到 `spawn_blocking`：采集线程上的 async 执行器不能被 `/proc`
    /// 读取或 Kafka 握手的阻塞调用霸住。**SQL 采集器不经过这一步** —— 它整个就是
    /// async 的（`sqlx` + tokio），丢进阻塞池反而是倒退。
    pub(super) async fn collect(self) -> CollectorOutput {
        let domain = self.domain();
        if let Self::Mysql(config) = self {
            return CollectorOutput::Mysql {
                result: super::mysql::probe_once(config.as_ref()).await,
            };
        }
        tokio::task::spawn_blocking(move || match self {
            Self::Host(view) => {
                let used = view.targets.clone();
                CollectorOutput::Host {
                    used,
                    outcomes: host_outcomes(&view),
                }
            }
            Self::Kafka { config, mut groups } => {
                let result = super::kafka::probe_once(config.as_ref(), &mut groups);
                CollectorOutput::Kafka { result, groups }
            }
            // 上面已经拦住；这里只是让匹配穷尽。
            Self::Mysql(_) => CollectorOutput::panicked(domain),
        })
        .await
        .unwrap_or_else(|err| {
            // 阻塞任务 panic：只丢这一轮，线程继续（调度器会把在飞标记清掉）。
            log::error!("event=CollectorRoundPanicked domain={domain} detail=\"{err}\"");
            CollectorOutput::panicked(domain)
        })
    }
}

impl CollectorOutput {
    /// 产物的域（分派错误时的留痕用）。
    pub(super) fn domain_name(&self) -> &'static str {
        match self {
            Self::Host { .. } => "host_metrics",
            Self::Kafka { .. } => super::kafka::COLLECTION_KIND,
            Self::Mysql { .. } => super::mysql::COLLECTION_KIND,
        }
    }

    fn panicked(domain: &str) -> Self {
        if domain == super::kafka::COLLECTION_KIND {
            Self::Kafka {
                result: ProbeResult {
                    targets: Vec::new(),
                    attempted: 1,
                    failed: 1,
                    last_error: Some("采集任务 panic（已丢弃这一轮）".to_string()),
                    warnings: Vec::new(),
                },
                groups: GroupCache::default(),
            }
        } else if domain == super::mysql::COLLECTION_KIND {
            Self::Mysql {
                result: ProbeResult {
                    targets: Vec::new(),
                    attempted: 1,
                    failed: 1,
                    last_error: Some("采集任务 panic（已丢弃这一轮）".to_string()),
                    warnings: Vec::new(),
                },
            }
        } else {
            Self::Host {
                used: Vec::new(),
                outcomes: Vec::new(),
            }
        }
    }
}

/// 一次探测的产物（与具体线程解耦，便于测试）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeResult {
    pub targets: Vec<MetricsCollectionTargetSample>,
    /// 本轮**尝试**的目标数：成功时 = `targets.len()`；整轮失败时仍记 1（且 `failed = 1`），
    /// 保证 `succeeded <= attempted`。
    pub attempted: usize,
    pub failed: usize,
    pub last_error: Option<String>,
    /// 不影响本轮成败、但**确实造成了样本缺失**的原因
    /// （例如某个 broker 的 `DescribeLogDirs` 失败：该 broker 只是少了容量读数）。
    ///
    /// 单独立项是因为这类缺失在上面的汇总里看不见：没有它，现场只能看到
    /// 「`kafka_log_dir.size_bytes` 没有数据」而猜不出是哪个 broker、哪个 API。
    pub warnings: Vec<String>,
}

/// warnings 的日志闸门：内容变了（包括从「有」变成「没有」）才打。
///
/// **只打 warnings**：域级成败已经由指标运行时统一打（`MetricsCollectionFailed` /
/// `MetricsCollectionRecovered`），这里再打一遍只会让同一个故障出现两行。
#[derive(Default)]
pub(super) struct WarningGate {
    warnings: Option<String>,
}

impl WarningGate {
    /// 内容变了就返回 `true`（调用方负责真正打日志）。
    pub(super) fn changed(&mut self, warnings: &[String]) -> bool {
        let joined = warnings.join(" | ");
        if self.warnings.as_deref() == Some(joined.as_str()) {
            return false;
        }
        self.warnings = Some(joined);
        true
    }
}

/// 本机三个域（host / process / container）在给定目标视图上同步采一轮。
///
/// 保持原来的批量语义：一个域一条 `MetricsCollectionOutcome`，域内按目标独立成败。
pub(super) fn host_outcomes(view: &MetricsTargetView) -> Vec<MetricsCollectionOutcome> {
    super::runtime::providers()
        .iter()
        .map(|provider| {
            let targets: Vec<&MetricsTargetViewEntry> = view
                .targets
                .iter()
                .filter(|target| target.collection_kind == provider.collection_kind())
                .collect();
            provider.collect(targets)
        })
        .collect()
}

/// 把各集群最近一轮结果合并成一条采集结果。
///
/// - 没有授权（`configured == false`）→ `None`：快照里不出现这个域；
/// - 授权到了但首轮还没跑完 → `pending`（如实说「还没数据」）；
/// - 同一台机器可能跑多个 broker（每个进程一条候选），而每轮 Metadata 都会返回
///   **整个集群**的 broker 列表 —— 必须按 `resource_ref` 去重，否则同一个 broker
///   会产出重复序列。
pub(super) fn probe_outcome<'a>(
    collection_kind: &str,
    configured: bool,
    results: impl Iterator<Item = &'a ProbeResult>,
) -> Option<MetricsCollectionOutcome> {
    if !configured {
        return None;
    }

    let mut targets = Vec::new();
    let mut attempted = 0usize;
    let mut failed = 0usize;
    let mut last_error: Option<String> = None;
    let mut any_result = false;
    for result in results {
        any_result = true;
        attempted += result.attempted;
        failed += result.failed;
        if last_error.is_none() {
            last_error = result.last_error.clone();
        }
        targets.extend(result.targets.iter().cloned());
    }

    let mut seen = std::collections::BTreeSet::new();
    targets.retain(|target| seen.insert(target.resource_ref.clone()));

    if !any_result {
        return Some(MetricsCollectionOutcome {
            collection_kind: collection_kind.to_string(),
            status: "pending".to_string(),
            attempted_targets: 0,
            succeeded_targets: 0,
            failed_targets: 0,
            dropped_targets: 0,
            last_error: None,
            runtime_facts: Vec::new(),
            labeled_facts: Vec::new(),
            sample_targets: Vec::new(),
        });
    }

    let succeeded = targets
        .iter()
        .filter(|target| target.status != "failed")
        .count();
    Some(MetricsCollectionOutcome {
        collection_kind: collection_kind.to_string(),
        status: if failed == 0 && succeeded > 0 {
            "succeeded".to_string()
        } else if succeeded == 0 {
            "failed".to_string()
        } else {
            "partial".to_string()
        },
        attempted_targets: attempted,
        succeeded_targets: succeeded,
        failed_targets: failed,
        dropped_targets: 0,
        last_error,
        runtime_facts: Vec::new(),
        labeled_facts: Vec::new(),
        sample_targets: targets,
    })
}

/// 逐组告警的**聚合器**。
///
/// 大集群里「所有组都没权限 / 协调者都在迁移」是常态故障：200 个组各打一行会在
/// 一轮里把日志刷满，真正有用的那行反而被挤掉（而且 `KafkaProbeWarning` 的闸门
/// 按「内容变化」判断，组集合一变就重打一整屏）。
///
/// 所以按**原因**聚合：单组保留原来的一句话，多组变成「N 个组（如 a, b, c…）…」。
#[derive(Default)]
pub(super) struct GroupWarnings {
    /// 原因（不含组名）→ 受影响的组（按出现顺序、去重）。
    failures: BTreeMap<String, Vec<String>>,
    /// 分区级缺失的原因 → 受影响组与缺失分区总数。
    partitions: BTreeMap<&'static str, PartitionShortfall>,
}

#[derive(Default)]
struct PartitionShortfall {
    groups: Vec<String>,
    total: usize,
}

impl GroupWarnings {
    /// `reason` 里**不能**带组名（否则聚合失效）。
    pub(super) fn failure(&mut self, reason: String, group: &str) {
        push_group(self.failures.entry(reason).or_default(), group);
    }

    pub(super) fn partitions(&mut self, reason: &'static str, group: &str, count: usize) {
        let entry = self.partitions.entry(reason).or_default();
        push_group(&mut entry.groups, group);
        entry.total += count;
    }

    pub(super) fn finish(self) -> Vec<String> {
        let mut lines = Vec::new();
        for (reason, groups) in self.failures {
            lines.push(format!("{} {reason}", group_subject(&groups)));
        }
        for (reason, shortfall) in self.partitions {
            if shortfall.groups.len() == 1 {
                lines.push(format!(
                    "组 {} 有 {} 个分区{reason}",
                    shortfall.groups[0], shortfall.total
                ));
            } else {
                lines.push(format!(
                    "{} 共 {} 个分区{reason}",
                    group_subject(&shortfall.groups),
                    shortfall.total
                ));
            }
        }
        lines
    }
}

fn push_group(groups: &mut Vec<String>, group: &str) {
    if !groups.iter().any(|existing| existing == group) {
        groups.push(group.to_string());
    }
}

/// 聚合行里最多列多少个组名（剩下的用 `…` 略去）。
const GROUP_SAMPLES: usize = 3;

fn group_subject(groups: &[String]) -> String {
    match groups.len() {
        1 => format!("组 {}", groups[0]),
        n if n <= GROUP_SAMPLES => format!("组 {}", groups.join(", ")),
        n => format!(
            "{n} 个组（如 {}…）",
            groups
                .iter()
                .take(GROUP_SAMPLES)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn many_group_failures_collapse_into_one_line_per_reason() {
        let mut warnings = GroupWarnings::default();
        for index in 0..50 {
            let group = format!("g-{index:02}");
            warnings.failure(
                "DescribeGroups 失败：error_code 15（组不存在 / 无权限）".to_string(),
                &group,
            );
            warnings.partitions("拿不到 log end offset（lag 会偏低）", &group, 2);
        }

        let lines = warnings.finish();
        assert_eq!(lines.len(), 2, "{lines:?}");
        assert!(
            lines[0].starts_with("50 个组（如 g-00, g-01, g-02…） DescribeGroups 失败"),
            "{:?}",
            lines[0]
        );
        assert!(lines[1].contains("共 100 个分区"), "{:?}", lines[1]);
    }

    #[test]
    fn a_single_group_warning_keeps_the_plain_sentence() {
        let mut warnings = GroupWarnings::default();
        warnings.failure("DescribeGroups 失败：boom".to_string(), "orders");
        warnings.partitions("拿不到 log end offset（lag 会偏低）", "orders", 3);

        let lines = warnings.finish();
        assert_eq!(lines[0], "组 orders DescribeGroups 失败：boom");
        assert_eq!(
            lines[1],
            "组 orders 有 3 个分区拿不到 log end offset（lag 会偏低）"
        );
    }

    #[test]
    fn the_warning_gate_only_fires_on_change() {
        let mut gate = WarningGate::default();
        let warning = "broker 7 (127.0.0.1:9092) DescribeLogDirs 失败：refused".to_string();

        assert!(gate.changed(std::slice::from_ref(&warning)), "第一次就要打");
        assert!(
            !gate.changed(std::slice::from_ref(&warning)),
            "同一句话不重复"
        );
        assert!(gate.changed(&[]), "恢复要清闸门");
        assert!(gate.changed(&[warning]), "恢复之后再坏，得能再打一次");
    }

    #[test]
    fn a_probe_outcome_is_absent_without_a_grant() {
        assert!(
            probe_outcome("kafka_broker_metrics", false, std::iter::empty()).is_none(),
            "没授权就不能凭空出一个域"
        );
    }

    #[test]
    fn a_probe_outcome_is_pending_before_the_first_round() {
        let outcome =
            probe_outcome("mysql_metrics", true, std::iter::empty()).expect("授权了就有域");
        assert_eq!(outcome.collection_kind, "mysql_metrics");
        assert_eq!(outcome.status, "pending");
        assert_eq!(outcome.attempted_targets, 0);
        assert!(outcome.sample_targets.is_empty());
    }
}
