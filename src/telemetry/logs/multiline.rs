//! 行 → 记录的折叠：把**读法**翻成边界信号，算法本体在 `wist_shared::records`。
//!
//! 边界界定（"最后一条悬着""起点不发半条""到限封口"）是可复用的，**不在本仓**：
//! 见 `wist_shared::records`。这里只留两件本仓特有的事：
//!
//! 1. **把读法翻成信号**：[`delimiter_policy`]（`none` / `indented` / `mysql_slow`）；
//! 2. **管时序**：什么时候该到期封口 —— 那要接读取循环的节奏，所以在
//!    `files/multiline_support.rs` 里（空闲到点 / 轮转 / 截断 / 停机）。
//!
//! `postgres_csv` 是个例外：它的边界取决于**跨行的引号状态**，不是“这一行长什么样”，
//! 所以它没有 [`records::Boundary`] 信号，走 `multiline_support.rs` 里的 CSV 状态机。
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
    /// MySQL slow log：`# Time:` 起块，下一条 `# Time:` 或空闲超时封口。
    MysqlSlow,
    /// PostgreSQL csvlog：一条记录是一行 CSV，**引号外**的换行才切。
    PostgresCsv,
}

impl MultilineMode {
    /// 目录 / 配置里的字符串 → 读法。认不出的返回 `None`（调用方按 `none` 处理并已在校验期拒过）。
    pub fn parse(mode: &str) -> Option<Self> {
        match mode {
            "none" => Some(Self::None),
            "indented" => Some(Self::IndentedContinuation),
            "mysql_slow" => Some(Self::MysqlSlow),
            "postgres_csv" => Some(Self::PostgresCsv),
            _ => None,
        }
    }

    /// 这种读法会不会折叠出**含换行**的正文（决定 TCP 分帧要不要升 `len`）。
    pub fn folds_records(self) -> bool {
        !matches!(self, Self::None)
    }
}

/// 界定器配置：起点状态 + 边界信号。
///
/// 抽成别名不只是为了少写几个字：它是"一种读法的两件套"，对调用方是一个概念。
pub type DelimiterPolicy = (records::Start, fn(&str) -> records::Boundary);

/// MySQL slow log 的边界信号：`# Time:` 开一条新记录。
///
/// slow log 的其余行（`# User@Host:` / `# Query_time:` / SQL 本身）都是续行；
/// 同一行里可能还带 `SET timestamp=…;` —— 位置无关，只看行首。
/// `#` 是 MySQL 的行注释符，SQL 正文里也可能出现一行以 `# Time:` 开头的注释；
/// 真正的头部后面紧跟时间戳，所以要求冒号后第一个非空字符是数字。
pub fn mysql_slow(line: &str) -> records::Boundary {
    let is_header = line
        .strip_prefix("# Time:")
        .map(str::trim_start)
        .is_some_and(|rest| rest.starts_with(|c: char| c.is_ascii_digit()));
    if is_header {
        records::Boundary::Starts
    } else {
        records::Boundary::Neither
    }
}

/// 这份读法对应的界定器配置。
///
/// `None` = **不需要**界定器（一行一条，或 csvlog 的跨行状态机）。
/// 调用方据此分两条路，而不是给 `None` 造一个恒真的信号 —— 那样会把"不需要推断"
/// 伪装成"推断结果恰好是一行一条"。
pub fn delimiter_policy(mode: MultilineMode) -> Option<DelimiterPolicy> {
    match mode {
        MultilineMode::None => None,
        // 起点等第一个不缩进的行：从记录中间落地时，那一截没有头，不该被发出去。
        MultilineMode::IndentedContinuation => {
            Some((records::Start::WaitForStart, records::indented))
        }
        // 与缩进同一取舍：落在一个块中间时，那一截没有 `# Time:` 头，不发半条。
        MultilineMode::MysqlSlow => Some((records::Start::WaitForStart, mysql_slow)),
        // csvlog 的边界要跨行状态（引号），不是"这一行长什么样"。
        MultilineMode::PostgresCsv => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn only_the_read_modes_that_infer_boundaries_need_a_delimiter() {
        // 一行一条不需要界定器：给它造一个恒真的信号会把"不需要推断"伪装成"推断过了"。
        assert!(delimiter_policy(MultilineMode::None).is_none());
        // csvlog 有边界，但不是逐行信号（引号状态跨行），所以也不走界定器。
        assert!(delimiter_policy(MultilineMode::PostgresCsv).is_none());

        let (start, signal) =
            delimiter_policy(MultilineMode::IndentedContinuation).expect("policy");
        assert_eq!(start, records::Start::WaitForStart);
        assert_eq!(signal("  frame\n"), records::Boundary::Neither);
        assert_eq!(signal("ERROR first\n"), records::Boundary::Starts);
    }

    #[test]
    fn the_slow_log_anchor_is_the_time_header() {
        let (start, signal) = delimiter_policy(MultilineMode::MysqlSlow).expect("policy");
        assert_eq!(start, records::Start::WaitForStart);
        assert_eq!(
            signal("# Time: 2026-10-24T01:02:03\n"),
            records::Boundary::Starts
        );
        assert_eq!(
            signal("# User@Host: app[app] @ localhost\n"),
            records::Boundary::Neither
        );
        assert_eq!(signal("SELECT 1;\n"), records::Boundary::Neither);
        // 只认行首：正文里出现 `# Time:` 不算新块。
        assert_eq!(
            signal("  # Time: not a header\n"),
            records::Boundary::Neither
        );
        // SQL 的 `#` 行注释也能以 `# Time:` 开头：真正的头部后面是时间戳。
        assert_eq!(
            signal("# Time: the report runs daily\n"),
            records::Boundary::Neither
        );
    }

    #[test]
    fn every_declared_mode_parses_and_round_trips_through_the_name() {
        for name in wist_contracts::work::MULTILINE_MODES {
            let mode = MultilineMode::parse(name).expect("vocabulary and parser must agree");
            assert_eq!(mode.folds_records(), *name != "none", "{name}");
        }
        assert!(MultilineMode::parse("guessed").is_none());
    }
}
