//! Conversion from delimited records into structured telemetry records.

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::records::Record;

pub fn parse_delimited_records(
    agent_id: &str,
    observed_at: &str,
    input_id: &str,
    source_path: &str,
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
        })
        .collect()
}
