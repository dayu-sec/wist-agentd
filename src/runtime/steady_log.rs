//! 稳态日志收敛：常驻主循环每 3s 就产出一份健康/指标快照，逐 tick 打印会持续写盘
//! （7 行/轮 × 2.88 万轮/天 ≈ 20 万行/天 ≈ 40 MB/天 ≈ 14 GB/年）。这里按「内容签名 + 心跳间隔」收敛：
//!
//! - 内容变化（状态迁移、失败计数变化、探针结果变化…）**立即**打印；
//! - 内容不变时只在超过心跳间隔后补一条，便于确认进程还活着；
//! - `WIST_AGENTD_LOG_HEARTBEAT_SECS=0` 关闭收敛（回到逐 tick 打印，用于联调）。
//!
//! 只收敛「周期性快照」这一类高频输出；失败、事件、状态迁移类日志始终逐条打印。

use std::sync::{LazyLock, Mutex};
use std::time::{Duration, Instant};

/// 默认心跳间隔：5 分钟补一条“没变化”的快照。
pub const DEFAULT_HEARTBEAT: Duration = Duration::from_secs(300);
/// 心跳间隔环境变量。
pub const HEARTBEAT_ENV: &str = "WIST_AGENTD_LOG_HEARTBEAT_SECS";

/// 按签名去重 + 周期性心跳的打印闸门。
#[derive(Debug)]
pub(crate) struct SteadyLogGate {
    last_signature: Option<String>,
    last_emit_at: Option<Instant>,
    heartbeat: Duration,
}

impl SteadyLogGate {
    pub(crate) fn new(heartbeat: Duration) -> Self {
        Self {
            last_signature: None,
            last_emit_at: None,
            heartbeat,
        }
    }

    /// 从 `WIST_AGENTD_LOG_HEARTBEAT_SECS` 构造（非法值回退默认，`0` 关闭收敛）。
    pub(crate) fn from_env() -> Self {
        Self::new(heartbeat_from_env())
    }

    /// 是否应该打印这条签名对应的快照。
    pub(crate) fn should_emit(&mut self, signature: &str, now: Instant) -> bool {
        if self.heartbeat.is_zero() {
            return true;
        }
        let changed = self.last_signature.as_deref() != Some(signature);
        let due = self
            .last_emit_at
            .is_none_or(|at| now.saturating_duration_since(at) >= self.heartbeat);
        if !changed && !due {
            return false;
        }
        self.last_signature = Some(signature.to_string());
        self.last_emit_at = Some(now);
        true
    }
}

/// 解析心跳间隔：`None`（未设置）或非法值 → 默认；`0` → 关闭收敛。
pub(crate) fn parse_heartbeat(raw: Option<&str>) -> Duration {
    match raw.map(str::trim) {
        None | Some("") => DEFAULT_HEARTBEAT,
        Some(text) => match text.parse::<u64>() {
            Ok(0) => Duration::ZERO,
            Ok(secs) => Duration::from_secs(secs),
            Err(_) => DEFAULT_HEARTBEAT,
        },
    }
}

fn heartbeat_from_env() -> Duration {
    let raw = std::env::var(HEARTBEAT_ENV).ok();
    parse_heartbeat(raw.as_deref())
}

// 健康快照与指标快照各自独立计数（两路输出的变化节奏不同）。
static HEALTH_GATE: LazyLock<Mutex<SteadyLogGate>> =
    LazyLock::new(|| Mutex::new(SteadyLogGate::from_env()));
static METRICS_GATE: LazyLock<Mutex<SteadyLogGate>> =
    LazyLock::new(|| Mutex::new(SteadyLogGate::from_env()));

/// 运行健康快照是否可以打印。
pub(crate) fn should_emit_health(signature: &str) -> bool {
    gate_allows(&HEALTH_GATE, signature)
}

/// 指标快照是否可以打印。
pub(crate) fn should_emit_metrics(signature: &str) -> bool {
    gate_allows(&METRICS_GATE, signature)
}

fn gate_allows(gate: &LazyLock<Mutex<SteadyLogGate>>, signature: &str) -> bool {
    // 锁中毒不致命：恢复内部值继续收敛，绝不因为日志问题中断主循环。
    let mut guard = gate.lock().unwrap_or_else(|err| err.into_inner());
    guard.should_emit(signature, Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn first_signature_is_always_emitted() {
        let mut gate = SteadyLogGate::new(Duration::from_secs(60));
        let now = Instant::now();
        assert!(gate.should_emit("a", now));
    }

    #[test]
    fn unchanged_signature_is_suppressed_until_heartbeat() {
        let mut gate = SteadyLogGate::new(Duration::from_secs(60));
        let start = Instant::now();
        assert!(gate.should_emit("a", start));
        assert!(!gate.should_emit("a", start + Duration::from_secs(59)));
        assert!(gate.should_emit("a", start + Duration::from_secs(60)));
        // 心跳打印后重新计时。
        assert!(!gate.should_emit("a", start + Duration::from_secs(61)));
    }

    #[test]
    fn changed_signature_is_emitted_immediately() {
        let mut gate = SteadyLogGate::new(Duration::from_secs(300));
        let start = Instant::now();
        assert!(gate.should_emit("a", start));
        assert!(gate.should_emit("b", start + Duration::from_millis(250)));
        // 变化之后回到新签名的静默期。
        assert!(!gate.should_emit("b", start + Duration::from_secs(1)));
    }

    #[test]
    fn zero_heartbeat_disables_suppression() {
        let mut gate = SteadyLogGate::new(Duration::ZERO);
        let start = Instant::now();
        assert!(gate.should_emit("a", start));
        assert!(gate.should_emit("a", start));
    }

    #[test]
    fn heartbeat_parsing_falls_back_to_default_for_missing_or_invalid_values() {
        assert_eq!(parse_heartbeat(None), DEFAULT_HEARTBEAT);
        assert_eq!(parse_heartbeat(Some("")), DEFAULT_HEARTBEAT);
        assert_eq!(parse_heartbeat(Some("abc")), DEFAULT_HEARTBEAT);
        assert_eq!(parse_heartbeat(Some("-1")), DEFAULT_HEARTBEAT);
        assert_eq!(parse_heartbeat(Some("300")), Duration::from_secs(300));
        assert_eq!(parse_heartbeat(Some(" 45 ")), Duration::from_secs(45));
        // 0 表示关闭收敛（仅联调）。
        assert_eq!(parse_heartbeat(Some("0")), Duration::ZERO);
    }
}
