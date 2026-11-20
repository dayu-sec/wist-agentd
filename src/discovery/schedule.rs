//! 触发规则：纯决策，不做任何 I/O。
//!
//! 与「采一次」分开的理由：规则（倒计时、重启归零、触发即重置、策略表覆盖周期）
//! 是要单测的部分，采集是平台相关的副作用。这里只回答两个问题：
//!
//! 1. 这一拍，某个探针到期了没有？
//! 2. 某个探针这一轮的周期是多少（策略表优先，内建默认兜底）？
//!
//! 规则口径见 `docs/design/agentd-architecture.md` §5.9。

use std::time::{Duration, Instant};

use super::policy::AppliedDiscoveryPolicy;

/// 每个探针一格「上次触发时刻」。
///
/// `None` = 从没跑过。运行时新建出来就是这个状态 —— 也就是「重启后倒计时为 0」：
/// 首轮全部到期，等价于一次全量刷新。计时只在内存，不落盘。
#[derive(Debug)]
pub(crate) struct ProbeSchedule {
    last_run_at: Vec<Option<Instant>>,
}

impl ProbeSchedule {
    pub(crate) fn new(slots: usize) -> Self {
        Self {
            last_run_at: vec![None; slots],
        }
    }

    /// 单槽位到期判定。
    ///
    /// `now` 由调用方给（规则内部不取时钟），测试才能把时间钉住。
    pub(crate) fn is_due(&self, index: usize, interval: Duration, now: Instant) -> bool {
        let Some(last) = self.last_run_at.get(index) else {
            return false;
        };
        match last {
            None => true,
            // `saturating`：时钟回退时判「未到期」，不 panic 也不把探针打成热循环。
            Some(last) => now.saturating_duration_since(*last) >= interval,
        }
    }

    /// 触发即重置：倒计时从 `at` 重新起算。
    pub(crate) fn mark_fired(&mut self, index: usize, at: Instant) {
        if let Some(slot) = self.last_run_at.get_mut(index) {
            *slot = Some(at);
        }
    }
}

/// 这一轮的周期：策略表优先（平台级取舍，盖过二进制里的内建默认值），
/// 表里没这个方向才回退内建值。
pub(crate) fn resolve_interval(
    builtin: Duration,
    policy: Option<&AppliedDiscoveryPolicy>,
    aspect: &str,
) -> Duration {
    policy
        .and_then(|policy| policy.interval_for(aspect))
        .unwrap_or(builtin)
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROCESS: Duration = Duration::from_secs(300);

    #[test]
    fn a_fresh_schedule_is_due_everywhere() {
        // 重启后倒计时为 0：首轮所有探针立即触发。
        let schedule = ProbeSchedule::new(3);
        let now = Instant::now();

        for index in 0..3 {
            assert!(
                schedule.is_due(index, PROCESS, now),
                "第 {index} 格必须到期"
            );
        }
    }

    #[test]
    fn nothing_is_due_before_the_interval_elapses() {
        let mut schedule = ProbeSchedule::new(1);
        let start = Instant::now();
        schedule.mark_fired(0, start);

        assert!(!schedule.is_due(0, PROCESS, start + Duration::from_millis(299_999)));
        assert!(schedule.is_due(0, PROCESS, start + PROCESS), "满周期即到期");
    }

    #[test]
    fn firing_resets_the_countdown_from_the_firing_instant() {
        let mut schedule = ProbeSchedule::new(1);
        let first = Instant::now();
        schedule.mark_fired(0, first);

        // 第二次触发（远在第一次之后）：下一次到期要从**第二次**起算。
        let second = first + Duration::from_secs(3000);
        schedule.mark_fired(0, second);

        assert!(!schedule.is_due(0, PROCESS, second + Duration::from_secs(299)));
        assert!(schedule.is_due(0, PROCESS, second + PROCESS));
    }

    #[test]
    fn a_clock_that_goes_backwards_does_not_make_a_probe_hot() {
        let mut schedule = ProbeSchedule::new(1);
        let start = Instant::now();
        schedule.mark_fired(0, start);

        assert!(
            !schedule.is_due(0, PROCESS, start - Duration::from_secs(10)),
            "时钟回退只能判「未到期」，否则探针会退化成每 tick 热循环"
        );
    }

    #[test]
    fn out_of_range_slots_are_never_due() {
        let schedule = ProbeSchedule::new(1);
        assert!(!schedule.is_due(9, PROCESS, Instant::now()));
    }

    #[test]
    fn without_a_policy_the_builtin_interval_is_used() {
        assert_eq!(resolve_interval(PROCESS, None, "process"), PROCESS);
    }
}
