//! 已应用的**发现方向策略表**（agentd 侧的内存视图）。
//!
//! 只保留能被调度的那部分 —— 每方向的**观测周期**。表里还有 `baseline` /
//! `enabled_by_default` / `platforms` / `yields`，但那些决定的是「探针开不开、适不适用」，
//! 而 agentd 的探针开关目前仍由本地 `[discovery] *_enabled`（在 `discovery_probes` 里读）
//! 决定；改成由策略表接管需要一份三态配置（未声明 / 显式开 / 显式关），是另一步。
//! 这里刻意不落它们，免得读代码的人以为它们已经生效。

use std::time::Duration;

use wist_contracts::discovery_policy::{DiscoveryAspectPolicy, DiscoveryAspectPolicySet};

/// 一条被**调整**过的周期：策略里写的默认值与它自己声明的 `[min,max]` 不符。
///
/// 为什么要记下来而不是悄悄夹取：夹取本身是对的（宁可采慢/采快一点，也不能让被管机器
/// 被打满或干脆不采），但**静默**夹取会把「网关发布了一份坏表」伪装成「一切正常」。
/// 所以每次应用策略都把调整清单带出来，由调用方打一行日志。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct IntervalAdjustment {
    pub aspect: String,
    /// 策略里写的默认周期。
    pub requested_seconds: i64,
    /// 实际采用的周期；`None` = 这条不可用，回退到探针内建周期。
    pub applied_seconds: Option<u64>,
    /// 为什么调整（日志与测试都看它）。
    pub reason: &'static str,
}

/// 一次折算的结论。
enum IntervalOutcome {
    /// 原值可直接使用。
    AsIs(u64),
    /// 被夹取到策略自己声明的区间内。
    Clamped {
        requested: i64,
        applied: u64,
        reason: &'static str,
    },
    /// 区间自相矛盾，这条方向没法用：回退探针内建周期。
    Unusable { reason: &'static str },
}

/// 把策略里写的默认周期折算成**实际采用**的秒数，必要时按策略自己声明的 `[min,max]` 夹取。
///
/// 为什么 agentd 要自己夹（网关装载时已经校验过 `min ≤ default ≤ max`）：
/// 边界就写在**同一条策略**里，用它们不需要任何额外知识；而「上游永远正确」不该当前提 ——
/// 一份坏表最坏应当退化成「用内建默认值」，而不是把被管机器打满（`0` 会让到期判定恒真、
/// 探针退化成每 tick 热循环）。
fn evaluate(policy: &DiscoveryAspectPolicy) -> IntervalOutcome {
    // 下限不低于 1s：秒级以下既没有意义，也无法用 `Duration::from_secs(0)` 表达。
    let lower = policy.min_interval_seconds.max(1);
    let upper = policy.max_interval_seconds;
    if upper < lower {
        return IntervalOutcome::Unusable {
            reason: "max_interval_seconds below the usable minimum",
        };
    }

    let requested = policy.default_interval_seconds;
    let clamped = |reason| IntervalOutcome::Clamped {
        requested,
        applied: lower as u64,
        reason,
    };
    if requested <= 0 {
        return clamped("non-positive interval");
    }
    if requested < lower {
        return clamped("below min_interval_seconds");
    }
    if requested > upper {
        return IntervalOutcome::Clamped {
            requested,
            applied: upper as u64,
            reason: "above max_interval_seconds",
        };
    }
    IntervalOutcome::AsIs(requested as u64)
}

/// 一份已应用（且已按策略自带边界折算过）的策略表。
#[derive(Debug, Clone)]
pub struct AppliedDiscoveryPolicy {
    set: DiscoveryAspectPolicySet,
    adjustments: Vec<IntervalAdjustment>,
}

impl AppliedDiscoveryPolicy {
    pub fn new(set: DiscoveryAspectPolicySet) -> Self {
        // 调整清单在构造时算一次：它只取决于表本身，`interval_for` 则是每轮要走的快路径。
        let adjustments = set
            .policies
            .iter()
            .filter_map(|policy| match evaluate(policy) {
                IntervalOutcome::AsIs(_) => None,
                IntervalOutcome::Clamped {
                    requested,
                    applied,
                    reason,
                } => Some(IntervalAdjustment {
                    aspect: policy.aspect.clone(),
                    requested_seconds: requested,
                    applied_seconds: Some(applied),
                    reason,
                }),
                IntervalOutcome::Unusable { reason } => Some(IntervalAdjustment {
                    aspect: policy.aspect.clone(),
                    requested_seconds: policy.default_interval_seconds,
                    applied_seconds: None,
                    reason,
                }),
            })
            .collect();
        Self { set, adjustments }
    }

    pub fn policy_version(&self) -> i64 {
        self.set.policy_version
    }

    /// 取某方向的观测周期；表里没有该方向、或该方向的区间不可用，返回 `None`
    /// （调用方回退探针内建周期）。
    pub fn interval_for(&self, aspect: &str) -> Option<Duration> {
        let policy = self.set.for_aspect(aspect)?;
        match evaluate(policy) {
            IntervalOutcome::AsIs(seconds)
            | IntervalOutcome::Clamped {
                applied: seconds, ..
            } => Some(Duration::from_secs(seconds)),
            IntervalOutcome::Unusable { .. } => None,
        }
    }

    pub fn adjustments(&self) -> &[IntervalAdjustment] {
        &self.adjustments
    }

    /// 一行日志用的摘要，如 `process:1→60(below min_interval_seconds)`。
    ///
    /// 上限 3 条 + 计数：条数由对端给的表决定，不封顶就等于让对端决定我们日志行的长度。
    pub fn adjustments_summary(&self) -> String {
        const SHOWN: usize = 3;
        let mut parts: Vec<String> = self
            .adjustments
            .iter()
            .take(SHOWN)
            .map(|adjustment| match adjustment.applied_seconds {
                Some(applied) => format!(
                    "{}:{}→{}({})",
                    adjustment.aspect, adjustment.requested_seconds, applied, adjustment.reason
                ),
                None => format!("{}:不可用({})", adjustment.aspect, adjustment.reason),
            })
            .collect();
        let hidden = self.adjustments.len().saturating_sub(parts.len());
        if hidden > 0 {
            parts.push(format!("+{hidden}"));
        }
        parts.join(", ")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn policy(aspect: &str, interval: i64, min: i64, max: i64) -> DiscoveryAspectPolicy {
        DiscoveryAspectPolicy {
            aspect: aspect.to_string(),
            default_interval_seconds: interval,
            min_interval_seconds: min,
            max_interval_seconds: max,
            baseline: false,
            enabled_by_default: true,
            platforms: vec!["macos".to_string()],
            yields: String::new(),
        }
    }

    fn set(policies: Vec<DiscoveryAspectPolicy>) -> DiscoveryAspectPolicySet {
        DiscoveryAspectPolicySet::new(3, "2026-09-22T00:00:00Z".to_string(), policies)
    }

    #[test]
    fn looks_up_the_interval_by_aspect_name() {
        let applied = AppliedDiscoveryPolicy::new(set(vec![
            policy("host", 900, 60, 3600),
            policy("process", 300, 60, 1800),
        ]));

        assert_eq!(
            applied.interval_for("process"),
            Some(Duration::from_secs(300))
        );
        assert_eq!(applied.interval_for("host"), Some(Duration::from_secs(900)));
        assert_eq!(applied.policy_version(), 3);
        assert!(applied.adjustments().is_empty());
        assert_eq!(applied.adjustments_summary(), "");
    }

    #[test]
    fn unknown_aspect_has_no_interval() {
        let applied = AppliedDiscoveryPolicy::new(set(vec![policy("host", 900, 60, 3600)]));

        // 表里没有的方向：回退由调用方（探针内建周期）决定，这里如实返回 None。
        assert_eq!(applied.interval_for("package"), None);
    }

    #[test]
    fn non_positive_interval_is_clamped_to_the_lower_bound() {
        // 0 会让到期判定恒真、探针每 tick 热循环：夹到下限，而不是放行原值。
        let applied = AppliedDiscoveryPolicy::new(set(vec![
            policy("host", 0, 60, 3600),
            policy("process", -5, 60, 3600),
        ]));

        assert_eq!(applied.interval_for("host"), Some(Duration::from_secs(60)));
        assert_eq!(
            applied.interval_for("process"),
            Some(Duration::from_secs(60))
        );
        assert_eq!(applied.adjustments().len(), 2);
        assert_eq!(applied.adjustments()[0].reason, "non-positive interval");
        assert_eq!(applied.adjustments()[0].applied_seconds, Some(60));
    }

    #[test]
    fn clamps_below_min_and_above_max() {
        let applied = AppliedDiscoveryPolicy::new(set(vec![
            policy("host", 10, 300, 3600),
            policy("process", 99_999, 60, 1800),
        ]));

        assert_eq!(applied.interval_for("host"), Some(Duration::from_secs(300)));
        assert_eq!(
            applied.interval_for("process"),
            Some(Duration::from_secs(1800))
        );

        let reasons: Vec<&str> = applied
            .adjustments()
            .iter()
            .map(|adjustment| adjustment.reason)
            .collect();
        assert_eq!(
            reasons,
            vec!["below min_interval_seconds", "above max_interval_seconds"]
        );
    }

    #[test]
    fn clamps_to_one_second_when_the_declared_minimum_is_unusable() {
        // min ≤ 0 无法兑现：下限抬到 1s，不能让 0 漏过去。
        let applied = AppliedDiscoveryPolicy::new(set(vec![policy("host", 0, 0, 3600)]));

        assert_eq!(applied.interval_for("host"), Some(Duration::from_secs(1)));
    }

    #[test]
    fn a_self_contradictory_range_falls_back_to_the_probe_default() {
        // max < min：这条方向没法用 → None（调用方回退探针内建周期），而不是猜一个值。
        let applied = AppliedDiscoveryPolicy::new(set(vec![
            policy("host", 900, 600, 30),
            policy("process", 300, 60, 0),
        ]));

        assert_eq!(applied.interval_for("host"), None);
        assert_eq!(applied.interval_for("process"), None);
        assert_eq!(applied.adjustments().len(), 2);
        assert!(
            applied
                .adjustments()
                .iter()
                .all(|adjustment| adjustment.applied_seconds.is_none())
        );
        assert!(
            applied.adjustments_summary().contains("不可用"),
            "{}",
            applied.adjustments_summary()
        );
    }

    #[test]
    fn summary_is_bounded() {
        // 条数由对端给的表决定：不封顶就等于让对端决定我们日志行的长度。
        let policies: Vec<DiscoveryAspectPolicy> = (0..10)
            .map(|index| policy(&format!("aspect-{index}"), 0, 60, 3600))
            .collect();
        let summary = AppliedDiscoveryPolicy::new(set(policies)).adjustments_summary();

        assert!(summary.ends_with("+7"), "{summary}");
        assert_eq!(summary.matches('→').count(), 3);
    }
}
