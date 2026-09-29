//! Edge daemon skeleton.

pub mod bootstrap;
pub mod config;
pub mod control;
pub mod discovery;
pub(crate) mod doctor;
pub mod error;
pub mod exec;
pub(crate) mod fs_async;
pub mod reporting;
pub mod runtime;
pub mod service;
pub(crate) mod single_instance;
pub mod state_store;
pub(crate) mod telemetry;
/// 升级执行体（`wist-upgrader` 二进制的全部逻辑；见模块注释里的取向说明）。
pub mod upgrade;

pub use config::config_runtime;
pub use control::enrollment;
pub use exec::{
    execution_support, local_exec, planner_bridge, process_control, quarantine, recovery,
};
pub use reporting::{exporter, reporting_pipeline};
pub use runtime::{daemon, scheduler, self_observability};
pub use service::{ServicePlatform, ServiceScope, ServiceSpec};

/// 进程入口：返回值是**进程退出码**（`doctor` 有 FAIL 时为 1，其余命令为 0）。
pub async fn run() -> error::AgentdResult<i32> {
    control::run().await
}
