//! Metrics runtime scaffolding.

pub mod collection;
pub mod cpu;
/// Doris 指标采集（连 FE 的 MySQL 协议口，读 BE 视图）。
pub mod doris;
pub mod kafka;
pub mod kafka_auth;
pub mod kafka_groups;
/// 真 broker 验收（`dev/kafka-sasl`）：全部 `#[ignore]`，只在起了 broker 时才跑。
#[cfg(test)]
mod kafka_live;
/// MySQL / TiDB 指标采集（SQL 直采，只读）。
pub mod mysql;
/// PostgreSQL 指标采集（SQL 直采，只读；与 mysql 共用查询通道）。
pub mod postgres;
pub mod runtime;
pub mod samples;
pub mod scheduler;
pub mod self_obs;
pub mod spec;
pub mod target_view;
