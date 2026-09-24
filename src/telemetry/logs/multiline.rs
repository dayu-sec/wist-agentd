//! 行 → 记录的折叠：把**读法**翻成边界信号，算法本体在 `wist_shared::records`。
//!
//! 边界界定（"最后一条悬着""起点不发半条""到限封口"）是可复用的，**不在本仓**：
//! 见 `wist_shared::records`。这里只留两件本仓特有的事：
//!
//! 1. **把读法翻成信号**：[`delimiter_policy`]（`none` / `indented`；将来还会有 `anchor:<正则>`）；
//! 2. **管时序**：什么时候该到期封口 —— 那要接读取循环的节奏，所以在
//!    `files/multiline_support.rs` 里（空闲到点 / 轮转 / 截断 / 停机）。
//!
//! 为什么 `none` 不走界定器：一行一条**根本不用推断边界**，也就没有"最后一条悬着"
//! 那半拍到一秒的延迟、也不必存一份未封口状态。让它也过界定器只是白白给每条日志加上这些。

use wist_shared::records;

/// 单条记录的累积上限（行数 / 字节数，先到者胜）。
///
/// 取值依据实测：`/var/log/install.log` 上最长的一条多行记录 **190 行 / 9079 字节**，
/// 多行记录行数 p99 = 32 / p999 = 56。这里留了足够余量，同时给"永不结束的缩进块"一个上界 ——
/// 不给上界就等于把内存交给日志内容决定。
pub const MAX_RECORD_LINES: usize = 1000;
pub const MAX_RECORD_BYTES: usize = 1 << 20;

/// 折叠用的上限（给界定器）。
pub const FOLD_LIMITS: records::Limits = records::Limits {
    max_lines: MAX_RECORD_LINES,
    max_bytes: MAX_RECORD_BYTES,
};

/// 采集来源声明的**读法**（目录里 `[[units.sources]] multiline`）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MultilineMode {
    /// 一行一条（默认）。
    None,
    /// 行首缩进/制表符是上一条的续行。
    IndentedContinuation,
}

/// 界定器配置：起点状态 + 边界信号。
///
/// 抽成别名不只是为了少写几个字：它是"一种读法的两件套"，对调用方是一个概念。
pub type DelimiterPolicy = (records::Start, fn(&str) -> records::Boundary);

/// 这份读法对应的界定器配置。
///
/// `None` = **不需要**界定器（一行一条）。调用方据此分两条路，而不是给 `None` 造一个
/// 恒真的信号 —— 那样会把"不需要推断"伪装成"推断结果恰好是一行一条"。
pub fn delimiter_policy(mode: MultilineMode) -> Option<DelimiterPolicy> {
    match mode {
        MultilineMode::None => None,
        // 起点等第一个不缩进的行：从记录中间落地时，那一截没有头，不该被发出去。
        MultilineMode::IndentedContinuation => {
            Some((records::Start::WaitForStart, records::indented))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_read_modes_that_infer_boundaries_need_a_delimiter() {
        // 一行一条不需要界定器：给它造一个恒真的信号会把"不需要推断"伪装成"推断过了"。
        assert!(delimiter_policy(MultilineMode::None).is_none());

        let (start, signal) =
            delimiter_policy(MultilineMode::IndentedContinuation).expect("policy");
        assert_eq!(start, records::Start::WaitForStart);
        assert_eq!(signal("  frame\n"), records::Boundary::Neither);
        assert_eq!(signal("ERROR first\n"), records::Boundary::Starts);
    }
}
