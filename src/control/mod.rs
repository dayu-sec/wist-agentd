//! 控制面：agent 注册（enrollment）与运行入口。

pub mod enrollment;
// 网关授权的工作（agentd 侧的应用视图与折算）。
mod runtime_entry;
// 数据面上送启用的拉取与应用（网关授予，agentd 侧生效）。
pub mod uplink;
pub mod work;

pub(crate) use runtime_entry::run;
