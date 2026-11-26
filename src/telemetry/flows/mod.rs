//! 主机流记录（`FLOW:` 帧）：记录形状、窗口切分与能力探测。
//!
//! 采集器（tc/eBPF）尚未接线：本模块目前只被单测使用，接线时删掉下面这条 `allow`。
#![allow(dead_code)]
//!
//! 设计见 `docs/design/host-ebpf-flow-collection.md`。本模块**不**做采集，
//! 只负责把采集层交上来的累计量变成一条条窗口记录 —— 窗口边界、键归一与编码都在这里，
//! 是唯一构造点。
//!
//! 记录类型暂时留在 agentd：`record_schema` 已经表达契约，等数据面 `FLOW:` 的
//! WPL/OML 规则落地后再上提到 `wist-contracts`（那一步要跟 api/metrics/validate 一起发版）。

pub mod iface;
pub mod record;
pub mod support;
