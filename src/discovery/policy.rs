//! 已应用的**发现方向策略表**（agentd 侧的内存视图）。
//!
//! 只保留能被调度的那部分 —— 每方向的**观测周期**。表里还有 `baseline` /
//! `enabled_by_default` / `platforms` / `yields`，但那些决定的是「探针开不开、适不适用」，
//! 而 agentd 的探针开关目前仍由本地 `[discovery] *_enabled`（在 `discovery_probes` 里读）
//! 决定；改成由策略表接管需要一份三态配置（未声明 / 显式开 / 显式关），是另一步。
//! 这里刻意不落它们，免得读代码的人以为它们已经生效。

use std::time::Duration;

use wist_contracts::discovery_policy::DiscoveryAspectPolicySet;

/// 一份已应用（且已校验过可调度部分）的策略表。
#[derive(Debug, Clone)]
pub struct AppliedDiscoveryPolicy {
    set: DiscoveryAspectPolicySet,
}

impl AppliedDiscoveryPolicy {
    pub fn new(set: DiscoveryAspectPolicySet) -> Self {
        Self { set }
    }

    pub fn policy_version(&self) -> i64 {
        self.set.policy_version
    }

    /// 取某方向的观测周期；表里没有该方向返回 `None`（调用方回退探针内建周期）。
    ///
    /// **非正周期一律当作「没给」**：`0`（或负数）会让到期判定恒真，探针退化成每 tick 热循环，
    /// 比策略表不存在更糟。网关装载时本来就校验 `min ≥ 1`，但 agentd 不该把「上游永远正确」
    /// 当前提 —— 一份坏表最坏应当退化成「用内建默认值」，而不是把被管机器打满。
    pub fn interval_for(&self, aspect: &str) -> Option<Duration> {
        let seconds = self.set.interval_seconds_for(aspect)?;
        if seconds <= 0 {
            return None;
        }
        Some(Duration::from_secs(seconds as u64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::discovery_policy::DiscoveryAspectPolicy;

    fn policy(aspect: &str, interval: i64) -> DiscoveryAspectPolicy {
        DiscoveryAspectPolicy {
            aspect: aspect.to_string(),
            default_interval_seconds: interval,
            min_interval_seconds: 1,
            max_interval_seconds: 3600,
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
        let applied =
            AppliedDiscoveryPolicy::new(set(vec![policy("host", 900), policy("process", 300)]));

        assert_eq!(
            applied.interval_for("process"),
            Some(Duration::from_secs(300))
        );
        assert_eq!(applied.interval_for("host"), Some(Duration::from_secs(900)));
        assert_eq!(applied.policy_version(), 3);
    }

    #[test]
    fn unknown_aspect_has_no_interval() {
        let applied = AppliedDiscoveryPolicy::new(set(vec![policy("host", 900)]));

        // 表里没有的方向：回退由调用方（探针内建周期）决定，这里如实返回 None。
        assert_eq!(applied.interval_for("package"), None);
    }

    #[test]
    fn non_positive_interval_is_treated_as_absent() {
        let applied =
            AppliedDiscoveryPolicy::new(set(vec![policy("host", 0), policy("process", -5)]));

        assert_eq!(applied.interval_for("host"), None);
        assert_eq!(applied.interval_for("process"), None);
    }
}
