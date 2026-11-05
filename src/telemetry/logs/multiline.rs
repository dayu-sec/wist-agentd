//! 行 → 记录的折叠：把**读法**翻成边界信号，算法本体在 `wist_shared::records`。
//!
//! 边界界定（"最后一条悬着""起点不发半条""到限封口"）是可复用的，**不在本仓**：
//! 见 `wist_shared::records`。这里只留两件本仓特有的事：
//!
//! 1. **把读法翻成信号**：[`delimiter_policy`]（`indented` / `mysql_slow` / `container_cri`）；
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
    /// kubelet `/var/log/containers` 的 CRI 容器日志：按**应用自己的头部**切记录。
    ///
    /// 为什么不能用 CRI 的 `F`：`F` 只说“这一行写完了”，一次事务状态输出会被写成
    /// 很多条 `F` 行（`code: OK` / `msg: ""` / `}` …），按 `F` 切会把一条日志切成几十条。
    ContainerCri,
}

/// 读法词表：配置名 → 读法。
///
/// 词表只在这里写一遍，[`MultilineMode::parse`] 与测试都从它出发 —— 加一种读法只改一处，
/// 不会出现“解析认得、词表没有”的半边状态；与 `wist_contracts::work::MULTILINE_MODES`
/// 的一致性由测试守住。
const MODE_NAMES: &[(&str, MultilineMode)] = &[
    ("none", MultilineMode::None),
    ("indented", MultilineMode::IndentedContinuation),
    ("mysql_slow", MultilineMode::MysqlSlow),
    ("postgres_csv", MultilineMode::PostgresCsv),
    ("container_cri", MultilineMode::ContainerCri),
];

impl MultilineMode {
    /// 目录 / 配置里的字符串 → 读法。认不出的返回 `None`（调用方按 `none` 处理并已在校验期拒过）。
    pub fn parse(mode: &str) -> Option<Self> {
        MODE_NAMES
            .iter()
            .find(|(name, _)| *name == mode)
            .map(|(_, read_mode)| *read_mode)
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

/// CRI 容器日志的边界信号：**应用自己的头部**决定一条记录何时开始。
///
/// 行首 `2026-11-05T15:12:56.967547835+08:00 stderr F ` 是运行时加的封装头，先剥掉；
/// 正文仍原样上送（头部由数据面拆，见 `docker-container-logs.md` §5.1）。剥完只剩
/// 〔应用正文〕，四种开头开新条：
///
/// * glog：`I` / `W` / `E` / `F` + `mmdd` + 空格（`I1105 15:12:56.967547 …`）；
/// * 行首时间戳：`yyyy-mm-dd hh:mm` / `yyyy/mm/dd hh:mm`（issue 里的 `[INFO ]` 变体是它的子集，
///   也盖住了 Go 标准库与不带方括号的 log4j / Python）；
/// * Doris 的 `RuntimeLogger <时间戳> LEVEL …`；
/// * Docker 运行时节点上的 `{"log":…}`（见下）。
///
/// 其余一律算续行 —— 包括 Java 堆栈的 `at …` / `Caused by:`：它们属于当前条，不另起一条。
/// 堆栈正文里也常常长得像日期或带 `[ERROR]`，但都不在**行首**，所以不会被误切。
///
/// `{"log":…}` 是**另一种现场**：k8s + Docker（dockershim / cri-dockerd）时
/// `/var/log/containers/*.log` 指向的就是 docker 的 `json-file`，一行一条完整 JSON。
/// 不认它就会把整台机器的容器日志当成“没有头”全部丢掉 —— 一行一条正是它的事实形态，
/// 解包归数据面，与现状（`none`）一致。
pub fn container_cri(line: &str) -> records::Boundary {
    let payload = strip_cri_header(line).unwrap_or(line);
    if starts_container_record(payload) {
        records::Boundary::Starts
    } else {
        records::Boundary::Neither
    }
}

/// 剥掉 CRI 封装头 `<RFC3339 时间戳> <stdout|stderr> <F|P> `，返回应用正文。
///
/// 形状不对（不是 CRI 文本）就返回 `None`：调用方按原样子判断 —— 不硬剥一个不存在的头。
fn strip_cri_header(line: &str) -> Option<&str> {
    let mut rest = line;
    let timestamp = take_token(&mut rest)?;
    if !looks_like_timestamp(timestamp) {
        return None;
    }
    let stream = take_token(&mut rest)?;
    if stream != "stdout" && stream != "stderr" {
        return None;
    }
    // `F` = 这一行已写完，`P` = 还有后续（被截断的一行）。两者都是**行封装**，不是记录边界。
    let tag = take_token(&mut rest)?;
    if tag != "F" && tag != "P" {
        return None;
    }
    Some(rest)
}

/// 取行首第一段（到空格为止），并把它从 `rest` 里去掉。
fn take_token<'a>(rest: &mut &'a str) -> Option<&'a str> {
    let (token, tail) = rest.split_once(' ')?;
    *rest = tail;
    Some(token)
}

/// RFC3339 时间戳的**形状**校验（不解析时区，只看 `yyyy-mm-ddThh`）。
///
/// 不引日期库：这里只用来辨认 CRI 头，认错了也不会偷偷改正文。
fn looks_like_timestamp(token: &str) -> bool {
    let bytes = token.as_bytes();
    bytes.len() >= 20
        && bytes[..4].iter().all(u8::is_ascii_digit)
        && bytes[4] == b'-'
        && bytes[5..7].iter().all(u8::is_ascii_digit)
        && bytes[7] == b'-'
        && bytes[8..10].iter().all(u8::is_ascii_digit)
        && bytes[10] == b'T'
}

/// 应用正文是否开了新记录。
fn starts_container_record(payload: &str) -> bool {
    is_glog_header(payload)
        || has_timestamp_prefix(payload)
        || is_runtime_logger_header(payload)
        || payload.starts_with("{\"log\":")
}

/// glog：`I` / `W` / `E` / `F` + 日期 + 空格。
///
/// 日期认两种写法：glog 原生的 `mmdd`（`I1105 15:12:56…`）与 8 位的 `yyyymmdd`
/// （部分接入层会把它展开）。两者后面都必须跟空格，否则 `ERROR` 之类的正文也会命中。
fn is_glog_header(payload: &str) -> bool {
    let bytes = payload.as_bytes();
    let Some(level) = bytes.first() else {
        return false;
    };
    if !matches!(level, b'I' | b'W' | b'E' | b'F') {
        return false;
    }
    [4usize, 8].iter().any(|width| {
        let end = 1 + width;
        bytes.len() > end && bytes[1..end].iter().all(u8::is_ascii_digit) && bytes[end] == b' '
    })
}

/// `yyyy-mm-dd` / `yyyy/mm/dd` 开头的行，且后面紧跟时间（`hh:mm`）。
///
/// 这是 issue 第 2 条（`yyyy-mm-dd … [LEVEL]`）的**超集**：行首时间戳本身就是“应用自己的
/// 记录头”。为什么要放宽：容器里跑的不只有 Doris —— Go 标准库默认写
/// `2009/01/23 01:23:23 msg`、log4j 写 `2026-11-05 15:12:56,967 ERROR …`（不带方括号）。
/// 只认那几种方括号写法的话，这些容器的**每一行**都会因为“没有头”被丢掉，而且不报错。
///
/// 要求到 `hh:mm` 是为了收窄误判：正文里恰好以日期开头、但没有时间的行不算头。
fn has_timestamp_prefix(value: &str) -> bool {
    let bytes = value.as_bytes();
    if bytes.len() < 16 {
        return false;
    }
    let separator = bytes[4];
    if !(separator == b'-' || separator == b'/') || bytes[7] != separator {
        return false;
    }
    let digits = |range: std::ops::Range<usize>| bytes[range].iter().all(u8::is_ascii_digit);
    if !digits(0..4) || !digits(5..7) || !digits(8..10) {
        return false;
    }
    // 日期与时间之间是空格 / 制表符，或 ISO 的 `T`。
    let mut index = 10;
    if !matches!(bytes[index], b' ' | b'\t' | b'T') {
        return false;
    }
    index += 1;
    bytes.len() >= index + 5
        && digits(index..index + 2)
        && bytes[index + 2] == b':'
        && digits(index + 3..index + 5)
}

/// Doris `RuntimeLogger <时间戳> LEVEL …`。
fn is_runtime_logger_header(payload: &str) -> bool {
    let Some(rest) = payload.strip_prefix("RuntimeLogger ") else {
        return false;
    };
    has_timestamp_prefix(rest)
        && [" INFO", " WARN", " ERROR", " DEBUG"]
            .iter()
            .any(|level| rest.contains(level))
}

/// 这份读法对应的界定器配置。
///
/// `None` = **不需要**逐行界定器，两种原因不同但结论相同：
/// * [`MultilineMode::None`]：一行一条，根本不用推断边界；
/// * [`MultilineMode::PostgresCsv`]：边界取决于**跨行的引号状态**，不是“这一行长什么样”，
///   由 `multiline_support.rs` 的 CSV 状态机处理。
///
/// 调用方据此分两条路，而不是给 csvlog 造一个恒真的信号 —— 那样会把"不需要推断"
/// 伪装成"推断结果恰好是一行一条"。
pub fn delimiter_policy(mode: MultilineMode) -> Option<DelimiterPolicy> {
    // 走界定器的读法起点相同：等第一个带锚的行。从记录中间落地时，那一截没有头
    // （缩进续行没有起始行，slow log 没有 `# Time:`，CRI 落在堆栈中间），不发半条。
    let start = records::Start::WaitForStart;
    match mode {
        MultilineMode::IndentedContinuation => Some((start, records::indented)),
        MultilineMode::MysqlSlow => Some((start, mysql_slow)),
        MultilineMode::ContainerCri => Some((start, container_cri)),
        MultilineMode::None | MultilineMode::PostgresCsv => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_contract_mode_parses_to_its_own_read_mode() {
        let mut seen: Vec<MultilineMode> = Vec::new();
        for name in wist_contracts::work::MULTILINE_MODES {
            let mode = MultilineMode::parse(name).expect("vocabulary and parser must agree");
            // 两种读法不能撞到同一个名字上：否则一种读法会静默地顶掉另一种。
            assert!(!seen.contains(&mode), "{name} reuses another read mode");
            seen.push(mode);
            // 折叠出的正文含不含换行，与“是不是一行一条”是同一个问题。
            assert_eq!(mode.folds_records(), *name != "none", "{name}");
        }
        assert_eq!(seen.len(), wist_contracts::work::MULTILINE_MODES.len());
    }

    #[test]
    fn the_name_table_holds_exactly_the_contract_vocabulary() {
        // 校验期放行（契约词表）与运行期认得（解析表）必须是同一份：
        // 多出一个名字就是“配置能写但跑不起来”，少一个就是“配置写不了”。
        for (name, _) in MODE_NAMES {
            assert!(
                wist_contracts::work::MULTILINE_MODES.contains(name),
                "{name} is not in the contract vocabulary"
            );
        }
        let mut names: Vec<&str> = MODE_NAMES.iter().map(|(name, _)| *name).collect();
        names.sort_unstable();
        names.dedup();
        assert_eq!(names.len(), MODE_NAMES.len(), "table has duplicate names");
        assert_eq!(
            names.len(),
            wist_contracts::work::MULTILINE_MODES.len(),
            "table and vocabulary differ in size"
        );
    }

    #[test]
    fn unknown_names_are_not_guessed() {
        // 逐字比较：大小写 / 多余的空白都不认，猜错会把读法悄悄降级成 `none`。
        for unknown in [
            "",
            "None",
            "INDENTED",
            "indented ",
            " postgres_csv",
            "postgres-csv",
            "guessed",
        ] {
            assert_eq!(MultilineMode::parse(unknown), None, "{unknown:?}");
        }
    }

    #[test]
    fn only_the_single_line_read_mode_keeps_records_unfolded() {
        assert!(!MultilineMode::None.folds_records());
        for mode in [
            MultilineMode::IndentedContinuation,
            MultilineMode::MysqlSlow,
            MultilineMode::PostgresCsv,
            MultilineMode::ContainerCri,
        ] {
            assert!(mode.folds_records(), "{mode:?}");
        }
    }

    #[test]
    fn only_the_read_modes_that_infer_boundaries_need_a_delimiter() {
        // 一行一条不需要界定器：给它造一个恒真的信号会把"不需要推断"伪装成"推断过了"。
        // csvlog 有边界，但不是逐行信号（引号状态跨行），所以也不走界定器。
        for mode in [MultilineMode::None, MultilineMode::PostgresCsv] {
            assert!(delimiter_policy(mode).is_none(), "{mode:?}");
        }

        let (start, signal) =
            delimiter_policy(MultilineMode::IndentedContinuation).expect("policy");
        assert_eq!(start, records::Start::WaitForStart);
        assert_eq!(signal("  frame\n"), records::Boundary::Neither);
        assert_eq!(signal("ERROR first\n"), records::Boundary::Starts);

        // slow log 与缩进同一取舍：落在一个块中间时，那一截没有 `# Time:` 头，不发半条。
        // 下面两条用例同时把“配的是 `mysql_slow` 而不是 `indented`”钉住：
        // 缩进读法会把 `SELECT 1;` 当起始行，slow log 读法不会。
        let (start, signal) = delimiter_policy(MultilineMode::MysqlSlow).expect("policy");
        assert_eq!(start, records::Start::WaitForStart);
        assert_eq!(signal("SELECT 1;\n"), records::Boundary::Neither);
        assert_eq!(signal("# Time: 1\n"), records::Boundary::Starts);
    }

    #[test]
    fn the_slow_log_anchor_is_the_time_header() {
        // 经 `delimiter_policy` 取信号：保证“配给界定器的那一个”就是 slow log 的边界信号。
        let (_, signal) = delimiter_policy(MultilineMode::MysqlSlow).expect("policy");
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
    fn the_slow_log_header_needs_a_timestamp_after_the_colon() {
        // 冒号后第一个非空字符不是数字 ⇒ 不是块头（行注释 / 缺时间戳 / 缺空格都走这里）。
        for line in [
            "# Time:\n",
            "# Time: \t\n",
            "# Time: not a timestamp\n",
            "#Time: 2026-10-24\n",
            " # Time: 2026-10-24\n",
            "# Time: T2026-10-24\n",
            "",
        ] {
            assert_eq!(mysql_slow(line), records::Boundary::Neither, "{line:?}");
        }
        // 冒号后允许多个空白；行尾没有换行（末行）也要认。
        for line in [
            "# Time: 2026-10-24T01:02:03\n",
            "# Time:   42\n",
            "# Time:\t42\n",
            "# Time:0",
        ] {
            assert_eq!(mysql_slow(line), records::Boundary::Starts, "{line:?}");
        }
    }

    /// 带 CRI 封装头的一行（现场形态：`<ts> stderr F <正文>`）。
    fn cri(payload: &str) -> String {
        format!("2026-11-05T15:12:56.967547835+08:00 stderr F {payload}\n")
    }

    /// 用真的界定器跑一遍，返回封口出的记录与未封口的那条。
    fn fold(lines: &[String]) -> (Vec<records::Record>, Option<records::Record>) {
        let mut delimiter = records::Delimiter::new(FOLD_LIMITS, records::Start::WaitForStart);
        let mut sealed = Vec::new();
        let mut offset = 0u64;
        for text in lines {
            let end = offset + text.len() as u64;
            if let Some(record) = delimiter.push(
                records::Line {
                    text,
                    start_offset: offset,
                    end_offset: end,
                },
                container_cri,
            ) {
                sealed.push(record);
            }
            offset = end;
        }
        (sealed, delimiter.into_pending())
    }

    #[test]
    fn the_issue_transaction_dump_is_one_record() {
        // 每一次 `F` 都是“这一行写完了”，不是“这条日志完了”：7 行仍然是一条记录。
        let lines = [
            cri(
                "RuntimeLogger 2026-11-05 15:12:56,967 INFO (Routine load task scheduler|40) getTxnResponse: status {",
            ),
            cri("  code: OK"),
            cri("  msg: empty"),
            cri("}"),
            cri("txn_info {"),
            cri("  db_id: 1793352857343"),
            cri("    }"),
        ];
        let (sealed, pending) = fold(&lines);
        assert!(sealed.is_empty(), "没有下一条的头，就不该封口");
        let pending = pending.expect("整块悬在未封口的那一条上");
        assert_eq!(pending.lines, 7);
        assert!(
            pending
                .body
                .starts_with("2026-11-05T15:12:56.967547835+08:00 stderr F RuntimeLogger"),
            "正文原样保留 CRI 头"
        );
        // 每一行都原样带着自己的 CRI 头（头部由数据面拆），但仍然是**同一条**记录。
        assert!(
            pending.body.contains("stderr F   code: OK\n"),
            "续行用换行连上，没被丢掉: {:?}",
            pending.body
        );
    }

    #[test]
    fn the_next_header_seals_the_previous_record() {
        let lines = [
            cri("RuntimeLogger 2026-11-05 15:12:56,967 INFO first"),
            cri("  code: OK"),
            cri("2026-11-05 15:12:56,968 [WARN ] wp-station heartbeat slow"),
            cri("  detail still warn"),
        ];
        let (sealed, pending) = fold(&lines);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].lines, 2, "第一行 + 一条续行");
        assert!(sealed[0].body.contains("code: OK"));
        assert_eq!(pending.expect("WARN 那条还悬着").lines, 2);
    }

    #[test]
    fn java_stack_lines_are_continuations_until_the_next_header() {
        let lines = [
            cri("2026-11-05 15:12:56,967 [ERROR] request failed"),
            cri("java.lang.IllegalStateException: boom"),
            cri("\tat com.acme.Foo.bar(Foo.java:10)"),
            cri("Caused by: java.io.IOException: disk"),
            cri("\t... 3 more"),
            cri("2026-11-05 15:12:57,001 [WARN ] next record"),
        ];
        let (sealed, pending) = fold(&lines);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].lines, 5, "ERROR + 堆栈四行");
        assert!(sealed[0].body.contains("Caused by: java.io.IOException"));
        assert_eq!(pending.expect("下一条已开头").lines, 1);
    }

    #[test]
    fn glog_and_timestamped_lines_open_records_with_or_without_the_cri_header() {
        for line in [
            // glog（`mmdd` 与 8 位日期两种写法）。
            "I1105 15:12:56.967547 12345 handler.go:42] ready",
            "W1105 15:12:56.967547 12345 handler.go:42] slow",
            "E1105 15:12:56.967547 12345 handler.go:42] failed",
            "F1105 15:12:56.967547 12345 handler.go:42] fatal",
            "E20261105 15:12:56.967547 12345 handler.go:42] failed",
            // issue 列的带方括号级别（时间戳是真正的头部）。
            "2026-11-05 15:12:56,967 [DEBUG] heart",
            "2026-11-05 15:12:56,967 [INFO ] heart",
            "2026-11-05 15:12:56,967 [WARN ] heart",
            "2026-11-05 15:12:56,967 [ERROR] heart",
            // 同样是“行首时间戳”，但没有方括号：Go 标准库 / log4j / Python 都这样写。
            "2026/11/05 10:00:00 go default logger",
            "2026-11-05 15:12:56,967 ERROR log4j without brackets",
            "2026-11-05 15:12:56.967 - root - WARNING - python",
            "2026-11-05T15:12:56.123456Z structured",
            // Doris。
            "RuntimeLogger 2026-11-05 15:12:56,967 INFO x",
            "RuntimeLogger 2026-11-05 15:12:56,967 WARN x",
            "RuntimeLogger 2026-11-05 15:12:56,967 ERROR x",
            "RuntimeLogger 2026-11-05 15:12:56,967 DEBUG x",
            // k8s + Docker 运行时：一行一条 JSON。
            "{\"log\":\"docker json line\\n\",\"stream\":\"stdout\",\"time\":\"2026-11-05T15:12:56Z\"}",
        ] {
            // 有封装头 / 无封装头都要认：剥头失败时按原样子判断。
            assert_eq!(container_cri(line), records::Boundary::Starts, "{line}");
            let wrapped = cri(line);
            assert_eq!(
                container_cri(&wrapped),
                records::Boundary::Starts,
                "{wrapped}"
            );
        }
    }

    #[test]
    fn lines_without_an_application_header_are_continuations() {
        for line in [
            "  code: OK",
            "}",
            "txn_info {",
            "\tat com.acme.Foo.bar(Foo.java:10)",
            "Caused by: java.io.IOException",
            "[CloudGlobalTransactionMgr.getTransactionState():2369] status {",
            // 日期不在行首就不算头。
            "code: OK at 2026-11-05 15:12:56",
            // 行首只有日期、没有到 `hh:mm` 的时间：不够当记录头。
            "2026-11-05 not a header",
            "2026-11-05",
            "2026-11-05 1x:00 nope",
            "20261105 15:12:56 no separators",
            // glog 形状缺 mmdd。
            "E 2026-11-05 failed",
            // RuntimeLogger 没带级别。
            "RuntimeLogger 2026-11-05 15:12:56,967 (scheduler|40) status {",
            // Docker JSON 的续行不是一条新记录（只有行首的 `{\"log\":` 才是）。
            "  \"stream\": \"stdout\"}",
        ] {
            assert_eq!(container_cri(line), records::Boundary::Neither, "{line}");
        }
    }

    #[test]
    fn landing_in_the_middle_of_a_stack_does_not_emit_a_half_record() {
        // 起点等第一个带锚的行：落在一段堆栈中间时，那几行没有头，不发半条。
        let lines = [
            cri("\tat com.acme.Foo.bar(Foo.java:10)"),
            cri("Caused by: java.io.IOException"),
            cri("2026-11-05 15:12:56,967 [ERROR] real record"),
        ];
        let (sealed, pending) = fold(&lines);
        assert!(sealed.is_empty());
        assert_eq!(pending.expect("从头开始的那条").lines, 1);
    }

    #[test]
    fn a_cri_partial_line_tag_is_judged_like_a_full_one() {
        // `P`（部分行）与 `F` 一样只是行封装，不是记录边界。
        assert_eq!(
            container_cri(
                "2026-11-05T15:12:56.967547835+08:00 stdout P 2026-11-05 15:12:56,967 [WARN ] half"
            ),
            records::Boundary::Starts
        );
        assert_eq!(
            container_cri("2026-11-05T15:12:56.967547835+08:00 stdout P e rest of the line"),
            records::Boundary::Neither
        );
        // 只有封装头、正文为空：不另起一条。
        assert_eq!(
            container_cri("2026-11-05T15:12:56.967547835+08:00 stdout F \n"),
            records::Boundary::Neither
        );
    }

    #[test]
    fn docker_json_lines_are_each_their_own_record() {
        // k8s + Docker：一行就是一条完整 JSON，不能拼。
        let lines = [
            "{\"log\":\"first\\n\",\"stream\":\"stdout\",\"time\":\"t\"}\n".to_string(),
            "{\"log\":\"second\\n\",\"stream\":\"stderr\",\"time\":\"t\"}\n".to_string(),
        ];
        let (sealed, pending) = fold(&lines);
        assert_eq!(sealed.len(), 1);
        assert_eq!(sealed[0].lines, 1, "上一条只有一行");
        assert_eq!(pending.expect("第二条还悬着").lines, 1);
    }

    #[test]
    fn an_unrecognized_header_means_the_lines_wait_for_a_real_one() {
        // 已知取舍：完全认不出头的容器不发半条（宁可丢，不可发假记录）。
        // 这条用例把取舍钉住：以后要改，得先把这个断言改掉。
        let lines = [
            cri("plain text without any header"),
            cri("2026-11-05 15:12:56,967 [ERROR] real record"),
        ];
        let (sealed, pending) = fold(&lines);
        assert!(sealed.is_empty());
        assert_eq!(pending.expect("只从真头开始").lines, 1);
    }

    #[test]
    fn the_fold_limits_are_the_declared_record_limits() {
        // 界定器拿到的上限必须与本身声明的常量同源，否则“到限封口”的边界会两份各说各话。
        assert_eq!(FOLD_LIMITS.max_lines, MAX_RECORD_LINES);
        assert_eq!(FOLD_LIMITS.max_bytes, MAX_RECORD_BYTES);
    }
}
