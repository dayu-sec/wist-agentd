//! Edge daemon skeleton.

pub mod bootstrap;
pub mod config;
pub mod control;
pub mod discovery;
pub(crate) mod doctor;
pub mod error;
pub mod exec;
pub(crate) mod fs_async;
pub(crate) mod investigate;
/// 账号与授权（谁能在本机登录、谁能提权）。
pub(crate) mod investigate_accounts;
pub(crate) mod investigate_disk;
/// 暴露面（谁在听）。只出证据，不做安全判定。
pub(crate) mod investigate_exposure;
pub(crate) mod investigate_load;
/// 持久化（重启后还有什么会自己跑起来）。
pub(crate) mod investigate_persistence;
/// 安全向题目共用的小工具（有界读取 / 覆盖三态 / 时间）。
pub(crate) mod investigate_probe;
/// 调查报告的出口脱敏与结构校验（策略：`investigation/redaction-policy.toml`）。
pub mod investigate_safety;
/// 遥测健康（我们瞎了多久）：源还在产出吗、积压送得出去吗。
pub(crate) mod investigate_telemetry;
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
pub use service::{ServicePlatform, ServiceSpec};

/// 进程入口：返回值是**进程退出码**（`doctor` 有 FAIL 时为 1，其余命令为 0）。
pub async fn run() -> error::AgentdResult<i32> {
    control::run().await
}
