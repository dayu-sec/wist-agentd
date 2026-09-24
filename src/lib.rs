//! Edge daemon skeleton.

pub mod bootstrap;
pub mod config;
pub mod control;
pub mod discovery;
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

pub async fn run() -> error::AgentdResult<()> {
    control::run().await
}
