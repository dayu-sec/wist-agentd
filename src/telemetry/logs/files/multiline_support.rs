use std::path::Path;

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::records;

use crate::state_store::log_checkpoint_state::PendingMultilineState;
use crate::telemetry::logs::files::file_reader::RawFileLine;
use crate::telemetry::logs::gate::UplinkGate;
use crate::telemetry::logs::multiline::{FOLD_LIMITS, MultilineMode, delimiter_policy};

/// 空闲多久算"这条记录到头了"。
///
/// 为什么要有它：一条记录的边界要等**下一个**边界信号才确定，而低频文件上那个信号
/// 可能几个小时后才来 —— 不设这道到期判定，最后一条就永远发不出去（"采了但看不到"）。
const MULTILINE_IDLE_FLUSH_MS: i64 = 1000;

/// `postgres_csv` 的到期封口阈值（远宽于 1s）。
///
/// csvlog 的边界是**确定的**（引号外换行），所以正常情况下不需要推断；这里的超时只服务一个
/// 异常场景：**写到一半被截断**（postgres 崩溃 / 半条 write）会让引号奇偶永久失衡，
/// 之后的完整行永远“还在引号里”，被这一条 pending 一直吸收到上限。60s 后按到期处理：
/// 累积的那条残缺记录按 `Oversized` 封口（不下发），下一条新行重新起头。
/// 60s 远大于任何正常单条 csvlog 的写入间隔（postgres 一条日志一次 write）。
const CSV_IDLE_FLUSH_MS: i64 = 60_000;

/// 一次读批的折叠结果。
pub(super) struct FoldedRead {
    /// 本次可以上送的记录（已被闸门放行）。
    pub(super) records: Vec<TelemetryRecord>,
    /// 仍未封口的那条（若有），交给下一次读批 / 到期封口。
    pub(super) pending: Option<PendingMultilineState>,
    /// 本次按 `drop_if_contains` 丢掉的记录数（进自观测）。
    pub(super) dropped_noise: usize,
}

/// 只有未封口记录要交出去时的结果（到期 / 轮转 / 换源 / 停机）。
pub(super) struct Admitted {
    pub(super) records: Vec<TelemetryRecord>,
    pub(super) dropped_noise: usize,
}

/// 把这一批新读到的行折进记录里。
///
/// 记录出口**一律经 `gate`**：内容不全的在那里被挡下（不转发、不取号），
/// 这条规矩只有一处，别的调用点不用重复判断。
///
/// `drop_if_contains` 在**进闸门之前**求值：被丢的是**整条记录**（不是命中那一行），
/// 而且**不消耗 `seq`** —— 与闸门挡下同一条理由（取号不上报会让接收端报假的数据丢失）。
#[allow(clippy::too_many_arguments)]
pub(super) fn records_from_read(
    gate: &mut UplinkGate<'_>,
    mode: MultilineMode,
    drop_if_contains: &[String],
    observed_at: &str,
    source_path: &Path,
    lines: Vec<RawFileLine>,
    pending: Option<PendingMultilineState>,
    next_seq: &mut u64,
) -> FoldedRead {
    let path = source_path.display().to_string();

    // csvlog 的边界是**跨行状态**（引号），不是逐行信号：它有自己的折叠器。
    if mode == MultilineMode::PostgresCsv {
        let (folded, pending) = fold_csv(&path, lines, pending, observed_at);
        let (records, dropped_noise) =
            admit_with_noise_filter(gate, &path, folded, drop_if_contains, next_seq);
        return FoldedRead {
            records,
            pending,
            dropped_noise,
        };
    }

    // 未封口的那条只对**同一个文件**有效：来源变了（轮转过、或这个 input 指向了别的文件），
    // 上一条不该再吃新文件的行 —— 否则会把两个文件的内容粘成一条。
    // 正常路径上调用方已经先处理过换源（`flush_pending_if_source_changes` /
    // `rebind_pending_source_on_rotate`），这里是兜底。
    let previous = pending.filter(|state| state.source_path == path);

    let Some((start, signal)) = delimiter_policy(mode) else {
        // 一行一条：不推断边界，自然也没有未封口状态。
        //
        // 但手里若还留着上一条未封口的记录（这个来源的读法刚从 `indented` 改成 `none`），
        // 不能把它丢掉 —— 按到期封口交出去。读法变了不该变成"那条日志没了"。
        let mut folded: Vec<records::Record> = previous
            .map(|state| records::Record {
                completion: records::Completion::Deadline,
                ..state.record
            })
            .into_iter()
            .collect();
        folded.extend(lines.into_iter().map(record_from_line));
        let (records, dropped_noise) =
            admit_with_noise_filter(gate, &path, folded, drop_if_contains, next_seq);
        return FoldedRead {
            records,
            pending: None,
            dropped_noise,
        };
    };

    let had_lines = !lines.is_empty();
    let (resumed, resumed_at) = match previous {
        Some(state) => (Some(state.record), Some(state.last_updated_at)),
        None => (None, None),
    };
    let mut delimiter = match resumed {
        Some(record) => records::Delimiter::resume(FOLD_LIMITS, start, record),
        None => records::Delimiter::new(FOLD_LIMITS, start),
    };

    let mut folded = Vec::new();
    for line in lines {
        folded.extend(delimiter.push(
            records::Line {
                text: &line.text,
                start_offset: line.start_offset,
                end_offset: line.end_offset,
            },
            signal,
        ));
    }
    let (records, dropped_noise) =
        admit_with_noise_filter(gate, &path, folded, drop_if_contains, next_seq);

    let pending = delimiter
        .into_pending()
        .map(|record| PendingMultilineState {
            source_path: path,
            // 空闲计时**只在这一次真的喂进了行**时重置。否则手里那条永远显得"刚更新过"，
            // 到期封口再也等不到 —— 低频文件上就退回成"采了但一直看不到"。
            last_updated_at: match (had_lines, resumed_at) {
                (true, _) | (false, None) => observed_at.to_string(),
                (false, Some(at)) => at,
            },
            record,
        });
    FoldedRead {
        records,
        pending,
        dropped_noise,
    }
}

/// 外部封口：把未封口的那条交出去（轮转 / 截断 / 到期 / 停机）。
///
/// 这些条件来自**读取循环之外**，界定器看不到；封口原因由调用方知道，这里记成
/// `Deadline`（内容完整、边界是推断的）。
///
/// `postgres_csv` 例外：pending 只可能是**引号内**的半条 CSV（边界确定，完整的早就封了），
/// 所以按 `Oversized` 封口（闸门会挡下，不下发）；否则下游会收到“看上去完整、实际是半条”的 CSV 行。
pub(super) fn records_from_pending(
    mode: MultilineMode,
    gate: &mut UplinkGate<'_>,
    drop_if_contains: &[String],
    pending: Option<PendingMultilineState>,
    next_seq: &mut u64,
) -> Admitted {
    let Some(state) = pending else {
        return Admitted {
            records: Vec::new(),
            dropped_noise: 0,
        };
    };
    let completion = if mode == MultilineMode::PostgresCsv {
        records::Completion::Oversized
    } else {
        records::Completion::Deadline
    };
    let record = records::Record {
        completion,
        ..state.record
    };
    let (records, dropped_noise) = admit_with_noise_filter(
        gate,
        &state.source_path,
        vec![record],
        drop_if_contains,
        next_seq,
    );
    Admitted {
        records,
        dropped_noise,
    }
}

/// 手里那条属于别的来源 → 先按到期封口交出去，再接着读新来源。
pub(super) fn flush_pending_if_source_changes(
    mode: MultilineMode,
    gate: &mut UplinkGate<'_>,
    drop_if_contains: &[String],
    pending: &mut Option<PendingMultilineState>,
    next_source_path: &Path,
    next_seq: &mut u64,
) -> Admitted {
    if pending
        .as_ref()
        .is_some_and(|state| state.source_path != next_source_path.display().to_string())
    {
        return records_from_pending(mode, gate, drop_if_contains, pending.take(), next_seq);
    }
    Admitted {
        records: Vec::new(),
        dropped_noise: 0,
    }
}

/// 文件被轮转：手里那条跟着改名 —— 它属于**旧文件**，继续等着旧文件的尾巴读完。
pub(super) fn rebind_pending_source_on_rotate(
    pending: &mut Option<PendingMultilineState>,
    previous_source_path: &Path,
    rotated_path: &Path,
) {
    let previous_source_path = previous_source_path.display().to_string();
    let rotated_path = rotated_path.display().to_string();
    if let Some(state) = pending
        .as_mut()
        .filter(|state| state.source_path == previous_source_path)
    {
        state.source_path = rotated_path;
    }
}

/// 到期了没：手里那条多久没吃到新行了（`observed_at` 与上次喂进行的时间比）。
///
/// 不同读法的到期阈值不同：`PostgresCsv` 的边界是确定的，只在对"写到一半"做恢复时用超时
/// （见 [`CSV_IDLE_FLUSH_MS`]），所以它的阈值宽得多。
pub(super) fn pending_should_flush(
    mode: MultilineMode,
    pending: Option<&PendingMultilineState>,
    observed_at: &str,
) -> bool {
    let Some(pending) = pending else {
        return false;
    };
    let idle_ms = if mode == MultilineMode::PostgresCsv {
        CSV_IDLE_FLUSH_MS
    } else {
        MULTILINE_IDLE_FLUSH_MS
    };
    let Ok(last_updated_at) = time::OffsetDateTime::parse(
        &pending.last_updated_at,
        &time::format_description::well_known::Rfc3339,
    ) else {
        return true;
    };
    let Ok(observed_at) =
        time::OffsetDateTime::parse(observed_at, &time::format_description::well_known::Rfc3339)
    else {
        return true;
    };
    observed_at - last_updated_at >= time::Duration::milliseconds(idle_ms)
}

/// 一行就是一条记录（`none` 读法）。
fn record_from_line(line: RawFileLine) -> records::Record {
    records::Record {
        body: line.text,
        start_offset: line.start_offset,
        end_offset: line.end_offset,
        lines: 1,
        // 一行一条时边界是**天然确定**的，不需要推断。
        completion: records::Completion::Boundary,
    }
}

/// 进闸门前先剔掉“噪音记录”（整条命中任一子串即丢），返回放行的记录与丢弃数。
fn admit_with_noise_filter(
    gate: &mut UplinkGate<'_>,
    source_path: &str,
    folded: Vec<records::Record>,
    drop_if_contains: &[String],
    next_seq: &mut u64,
) -> (Vec<TelemetryRecord>, usize) {
    if drop_if_contains.is_empty() {
        return (gate.admit(source_path, folded, next_seq), 0);
    }
    let before = folded.len();
    let kept: Vec<records::Record> = folded
        .into_iter()
        .filter(|record| !is_noise(&record.body, drop_if_contains))
        .collect();
    let dropped = before - kept.len();
    (gate.admit(source_path, kept, next_seq), dropped)
}

fn is_noise(body: &str, needles: &[String]) -> bool {
    needles.iter().any(|needle| body.contains(needle.as_str()))
}

// ── postgres csvlog：引号状态跨行的记录边界 ──────────────────────────────

/// 正在攒的一条 CSV 记录（`in_quotes` 是攒到这一行为止的引号状态）。
struct CsvRecord {
    record: records::Record,
    in_quotes: bool,
}

impl CsvRecord {
    /// 从 checkpoint 里未封口的那条恢复：引号状态可以**重算**（正文就在手里），
    /// 不必把状态单独存盘 —— 少一份会跟正文漂移的真相。
    fn resume(record: records::Record) -> Self {
        let (_, in_quotes) = scan_csv(&record.body, false);
        Self { record, in_quotes }
    }

    fn begin(line: &RawFileLine) -> Self {
        Self {
            record: records::Record {
                body: String::new(),
                start_offset: line.start_offset,
                end_offset: line.start_offset,
                lines: 0,
                completion: records::Completion::Boundary,
            },
            in_quotes: false,
        }
    }
}

/// 扫一段 CSV 文本：返回（这段里出现了**引号外的换行**，扫完后的引号状态）。
///
/// 引号内的 `""` 是转义（不是收尾），所以要看两个字符 —— 只数引号个数会把
/// `He said ""hi""` 误判成“引号关了又开”。
fn scan_csv(text: &str, mut in_quotes: bool) -> (bool, bool) {
    let bytes = text.as_bytes();
    let mut ended = false;
    let mut index = 0;
    while index < bytes.len() {
        match bytes[index] {
            b'"' => {
                if in_quotes && bytes.get(index + 1) == Some(&b'"') {
                    index += 2;
                    continue;
                }
                in_quotes = !in_quotes;
            }
            b'\n' if !in_quotes => ended = true,
            _ => {}
        }
        index += 1;
    }
    (ended, in_quotes)
}

fn over_limit(record: &records::Record, text: &str) -> bool {
    record.lines + 1 > FOLD_LIMITS.max_lines
        || record.body.len() + text.len() > FOLD_LIMITS.max_bytes
}

/// csvlog 折叠：一条记录 = 一行 CSV，**引号外**的换行才封口。
fn fold_csv(
    path: &str,
    lines: Vec<RawFileLine>,
    pending: Option<PendingMultilineState>,
    observed_at: &str,
) -> (Vec<records::Record>, Option<PendingMultilineState>) {
    let previous = pending.filter(|state| state.source_path == *path);
    let resumed_at = previous.as_ref().map(|state| state.last_updated_at.clone());
    let mut current = previous.map(|state| CsvRecord::resume(state.record));
    let had_lines = !lines.is_empty();
    let mut sealed = Vec::new();
    // 超限的那条已经按 `Oversized` 封口：剩下的行属于同一条物理记录，等它结束再重新起头
    // （与 `records::Delimiter` 对超限块的处置同一语义：宁可丢，不发半条）。
    //
    // 已知边界：若这条超限记录跨读批，`discarding` 不落盘 —— 下一批的第一行会被当成新记录
    // 的起点。这与 `Start::Collect` 格式的固有代价同源（看不到记录头就无法知道自己在中间），
    // 而单条 csvlog 记录超过 1 MiB / 1000 行本身就是病态。
    let mut discarding = false;
    let mut discarding_in_quotes = false;

    for line in lines {
        // 读取器截断的长行**不带换行**（其余字节已被丢弃，见 `file_reader.rs`）：
        // 它不可能再构成完整记录。直接按 `Oversized` 封口（闸门会挡下），
        // 否则下一行的换行会被当成它的结尾 —— 两行粘成一条、第一行的尾巴也丢。
        if !line.text.ends_with('\n') {
            let mut record = match current.take() {
                Some(acc) => acc.record,
                None => CsvRecord::begin(&line).record,
            };
            record.body.push_str(&line.text);
            record.end_offset = line.end_offset;
            record.lines += 1;
            sealed.push(records::Record {
                completion: records::Completion::Oversized,
                ..record
            });
            discarding = false;
            discarding_in_quotes = false;
            continue;
        }
        if discarding {
            let (ended, in_quotes) = scan_csv(&line.text, discarding_in_quotes);
            discarding_in_quotes = in_quotes;
            discarding = !ended;
            continue;
        }
        if current
            .as_ref()
            .is_some_and(|acc| over_limit(&acc.record, &line.text))
        {
            let acc = current.take().expect("accumulating");
            sealed.push(records::Record {
                completion: records::Completion::Oversized,
                ..acc.record
            });
            let (ended, in_quotes) = scan_csv(&line.text, acc.in_quotes);
            discarding_in_quotes = in_quotes;
            discarding = !ended;
            continue;
        }

        let acc = current.get_or_insert_with(|| CsvRecord::begin(&line));
        acc.record.body.push_str(&line.text);
        acc.record.end_offset = line.end_offset;
        acc.record.lines += 1;
        let (ended, in_quotes) = scan_csv(&line.text, acc.in_quotes);
        acc.in_quotes = in_quotes;
        if ended {
            let acc = current.take().expect("accumulating");
            sealed.push(records::Record {
                completion: records::Completion::Boundary,
                ..acc.record
            });
        }
    }

    let pending = current.map(|acc| PendingMultilineState {
        source_path: path.to_string(),
        // 与多行读法同一口径：只有真喂了行才刷新“最后更新”，否则到期封口永远等不到。
        last_updated_at: match (had_lines, resumed_at) {
            (true, _) | (false, None) => observed_at.to_string(),
            (false, Some(at)) => at,
        },
        record: acc.record,
    });
    (sealed, pending)
}
