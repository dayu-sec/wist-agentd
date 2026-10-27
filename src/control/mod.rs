//! 控制面：agent 注册（enrollment）与运行入口。

pub mod enrollment;
// 网关授权的工作（agentd 侧的应用视图与折算）。
mod runtime_entry;
// 数据面上送启用的拉取与应用（网关授予，agentd 侧生效）。
pub mod uplink;
// 原文快照上送周期（网关下发，可按机器不同；没下发时用本机 [discovery]）。
pub mod discovery_snapshot;
// 采集预检：网关让机器**自己**探一次路径（远程维护时不用人登录客户机）。
pub mod preflight;
// 日志源候选上报（agentd 解析 → 网关判定）。与预检同一姿态：**尽力而为**，
// 送不出去只进日志，不把发现 tick 弄成故障。
pub mod log_sources;
// L3 搜索范围（知识库 ∩ 网关 roots 的**交集**，由网关下发；本机无配置）。
// 拿不到 = 不搜索，行为与 L2b 一致。
pub mod source_search_policy;
pub mod work;

pub(crate) use runtime_entry::run;
