//! Conversion from delimited records into structured telemetry records.

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::records::Record;

use super::InputOrigin;

pub fn parse_delimited_records(
    agent_id: &str,
    observed_at: &str,
    input_id: &str,
    source_path: &str,
    origin: &InputOrigin,
    records: Vec<Record>,
    next_seq: &mut u64,
) -> Vec<TelemetryRecord> {
    records
        .into_iter()
        .map(|record| {
            let seq = *next_seq;
            *next_seq += 1;
            TelemetryRecord::new_log(
                agent_id.to_string(),
                observed_at.to_string(),
                input_id.to_string(),
                source_path.to_string(),
                record.body,
                record.start_offset,
                record.end_offset,
                seq,
            )
            // 来源身份跟着记录走：它要进数据帧，否则两个面一起跑就分不出哪条是哪来的。
            .with_origin(origin.family.clone(), origin.unit.clone())
        })
        .collect()
}
