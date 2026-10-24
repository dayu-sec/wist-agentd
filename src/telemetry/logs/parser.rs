//! Conversion from delimited records into structured telemetry records.

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::records::Record;

use super::InputOrigin;
use crate::telemetry::container_ref;

pub fn parse_delimited_records(
    agent_id: &str,
    observed_at: &str,
    input_id: &str,
    source_path: &str,
    origin: &InputOrigin,
    records: Vec<Record>,
    next_seq: &mut u64,
) -> Vec<TelemetryRecord> {
    // 容器身份按**文件**查一次（不是每条）：纯 Docker 主机的日志目录里，名字/镜像只在
    // 同目录的 `config.v2.json` 里，文件名只有容器 id。非容器路径返回 `None`（一次字符串扫描）。
    let container = container_ref::for_source_path(source_path);
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
            .with_container(container.clone())
        })
        .collect()
}
