//! 控制面：agent 注册（enrollment）与运行入口。

pub mod enrollment;
mod runtime_entry;

pub(crate) use runtime_entry::run;
