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

/// 一次读批的折叠结果。
pub(super) struct FoldedRead {
    /// 本次可以上送的记录（已被闸门放行）。
    pub(super) records: Vec<TelemetryRecord>,
    /// 仍未封口的那条（若有），交给下一次读批 / 到期封口。
    pub(super) pending: Option<PendingMultilineState>,
}

/// 把这一批新读到的行折进记录里。
///
/// 记录出口**一律经 `gate`**：内容不全的在那里被挡下（不转发、不取号），
/// 这条规矩只有一处，别的调用点不用重复判断。
pub(super) fn records_from_read(
    gate: &mut UplinkGate<'_>,
    mode: MultilineMode,
    observed_at: &str,
    source_path: &Path,
    lines: Vec<RawFileLine>,
    pending: Option<PendingMultilineState>,
    next_seq: &mut u64,
) -> FoldedRead {
    let path = source_path.display().to_string();
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
        return FoldedRead {
            records: gate.admit(&path, folded, next_seq),
            pending: None,
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
    let records = gate.admit(&path, folded, next_seq);

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
    FoldedRead { records, pending }
}

/// 外部封口：把未封口的那条交出去（轮转 / 截断 / 到期 / 停机）。
///
/// 这些条件来自**读取循环之外**，界定器看不到；封口原因由调用方知道，这里记成
/// `Deadline`（内容完整、边界是推断的）。
pub(super) fn records_from_pending(
    gate: &mut UplinkGate<'_>,
    pending: Option<PendingMultilineState>,
    next_seq: &mut u64,
) -> Vec<TelemetryRecord> {
    let Some(state) = pending else {
        return Vec::new();
    };
    let record = records::Record {
        completion: records::Completion::Deadline,
        ..state.record
    };
    gate.admit(&state.source_path, vec![record], next_seq)
}

/// 手里那条属于别的来源 → 先按到期封口交出去，再接着读新来源。
pub(super) fn flush_pending_if_source_changes(
    gate: &mut UplinkGate<'_>,
    pending: &mut Option<PendingMultilineState>,
    next_source_path: &Path,
    next_seq: &mut u64,
) -> Vec<TelemetryRecord> {
    if pending
        .as_ref()
        .is_some_and(|state| state.source_path != next_source_path.display().to_string())
    {
        return records_from_pending(gate, pending.take(), next_seq);
    }
    Vec::new()
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
pub(super) fn pending_should_flush(
    pending: Option<&PendingMultilineState>,
    observed_at: &str,
) -> bool {
    let Some(pending) = pending else {
        return false;
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
    observed_at - last_updated_at >= time::Duration::milliseconds(MULTILINE_IDLE_FLUSH_MS)
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
