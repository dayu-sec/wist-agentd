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
pub mod work;

pub(crate) use runtime_entry::run;
