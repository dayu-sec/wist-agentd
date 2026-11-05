//! Conversion from delimited records into structured telemetry records.

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::records::Record;

use super::InputOrigin;
use crate::telemetry::{container_ref, pod_log_ref};

/// 把一个读批的已界定记录转成上送记录。
///
/// 参数分三类：**谁**（`agent_id`）、**什么时候**（`observed_at`）、**从哪来**
/// （`input_id` + `node_name` + `source_path` + `origin`）。都是“本批共享”的上下文，
/// 拆成结构体只会把同一组值在调用点重复一遍（与 `records_from_read` 同一取舍）。
#[allow(clippy::too_many_arguments)]
pub fn parse_delimited_records(
    agent_id: &str,
    observed_at: &str,
    input_id: &str,
    node_name: &str,
    source_path: &str,
    origin: &InputOrigin,
    records: Vec<Record>,
    next_seq: &mut u64,
) -> Vec<TelemetryRecord> {
    // 身份按**文件**查一次（不是每条）：k8s 的身份在文件名 / pod 目录名里（外加一次
    // `readlink`），纯 Docker 主机的名字/镜像只在同目录的 `config.v2.json` 里。
    // 两条路径互斥：`/var/log/containers/*.log` 与 `<docker-root>/containers/<id>/*` 形状不同，
    // 前面先问 k8s 是因为它的判据更严（三段下划线 + 64 位十六进制 id）。
    let pod_log = pod_log_ref::for_source_path(source_path).map(|mut pod| {
        // 节点名是**本机**事实，路径里没有：由采集运行时注入。
        pod.node_name = node_name.to_string();
        pod
    });
    let container = if pod_log.is_some() {
        // k8s 来源的容器身份在 `pod_log.container` 里：同一条记录只留一份。
        None
    } else {
        container_ref::for_source_path(source_path)
    };
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
            .with_pod_log(pod_log.clone())
            .with_container(container.clone())
        })
        .collect()
}
