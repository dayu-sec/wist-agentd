//! 控制面：agent 注册（enrollment）与运行入口。

pub mod enrollment;
// 网关授权的工作（agentd 侧的应用视图与折算）。
mod runtime_entry;
pub mod work;

pub(crate) use runtime_entry::run;
