//! 动作执行域：本地执行、子进程生命周期控制、隔离与恢复。

pub mod attestation;
pub mod execution_support;
pub mod local_exec;
pub mod opcode;
pub mod plan_review;
pub mod planner_bridge;
pub mod process_control;
pub mod quarantine;
pub mod recovery;
