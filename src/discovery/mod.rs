//! Discovery runtime skeleton.

pub mod cache;
pub mod cgroup;
// 云实例身份（元数据服务的 instance-id）：双来源（agentd / 云 API）归并的确定性键。
pub mod cloud_meta;
pub mod container;
// 数据库自探的公共层（MySQL / PostgreSQL / Doris 共用）：netns 视角的端口/地址、
// 运行时判据、凭据 key。
pub mod db_source;
pub mod endpoint;
pub mod host;
pub mod k8s;
// Kafka 集群自探：从进程证据 + broker 配置推出端点/协议/机制，作为候选上报。
// 只发现、不下发采集任务；授权与限流仍由采集面（网关 + 知识策略）决定。
pub mod kafka_source;
// 日志源定位（v1 只做 PostgreSQL）：从发现快照的进程证据推出日志目录，作为候选上报。
// 采不采、采哪个仍由网关判定（见 `wist-design/doc/design/edge/log-source-resolution.md`）。
pub mod log_source;
// MySQL / TiDB 实例自探：从进程证据 + my.cnf + 监听端口推出候选（只发现，不下发采集）。
pub mod mysql_source;
pub mod network;
// PostgreSQL 实例自探（证据 + SSLRequest 握手），运行时交给 db_source。
pub mod pg_source;
// Doris FE 自探（只找 FE：SHOW BACKENDS 是 FE 的命令）。
pub mod doris_source;
pub mod policy;
pub mod process;
pub mod runtime;
// 触发规则（倒计时 / 重启归零 / 策略表覆盖周期）：纯决策，不做 I/O，便于单测。
pub(crate) mod schedule;

use std::time::SystemTime;

use orion_error::{conversion::ToStructError, runtime::OperationContext};

use wist_contracts::discovery::{DiscoveredResource, DiscoveredTarget, DiscoveryOrigin};

pub use crate::error::{DiscoveryError, DiscoveryReason};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DiscoverySourceKind {
    LocalRuntime,
    Static,
    File,
    K8s,
}

impl DiscoverySourceKind {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::LocalRuntime => "local_runtime",
            Self::Static => "static",
            Self::File => "file",
            Self::K8s => "k8s",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct ProbeOutput {
    pub probe: String,
    pub source: DiscoverySourceKind,
    pub refreshed_at: String,
    pub origin: DiscoveryOrigin,
    pub resources: Vec<DiscoveredResource>,
    pub targets: Vec<DiscoveredTarget>,
    /// 本探针**看见了但读不了**的位置（空表 = 没有这种情况）。
    ///
    /// 为什么要它：`Ok` + 空列表本身有歧义 —— 既可能是「确实没有这个对象」，也可能是
    /// 「看不见」（权限不足 / 运行时不可达）。下游对这两者的结论**相反**（空集 vs 该采而采
    /// 不了），而只有探针自己知道是哪种。探针**失败**仍然走 `Err`（那会让上一份输出继续
    /// 生效）—— 这里说的是「探针跑通了，但有一部分世界没看到」。
    pub unobserved: Vec<UnobservedSource>,
}

/// 一条「看不见」的记录（见 [`ProbeOutput::unobserved`]）。
#[derive(Debug, Clone, PartialEq, Eq, ::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct UnobservedSource {
    /// **稳定的域键**（不是人话）：下游（指标记账 / 页面）按它把「看不见」挂到对应的
    /// 采集域上。目前只有 `container_runtime`。
    pub subject: String,
    /// 具体位置：运行时根目录 / socket 路径。
    pub location: String,
    /// 人看的原因（权限不足 / 连接失败 / 响应无法解析）。
    pub detail: String,
}

pub trait DiscoveryProbe {
    fn name(&self) -> &'static str;
    fn source(&self) -> DiscoverySourceKind;
    fn refresh_interval(&self) -> std::time::Duration;
    fn refresh(&self, now: SystemTime) -> Result<ProbeOutput, DiscoveryError>;
}

/// Structured context shared by every probe failure, so observability can
/// recover the originating probe and source from the [`DiscoveryError`].
pub(crate) fn probe_error_context(probe: &str, source: DiscoverySourceKind) -> OperationContext {
    OperationContext::doing("discover")
        .with_meta("probe", probe)
        .with_meta("source", source.as_str())
}

/// Build a [`DiscoveryError`] for a probe whose refresh failed.
pub(crate) fn probe_failed(
    probe: &str,
    source: DiscoverySourceKind,
    detail: impl Into<String>,
) -> DiscoveryError {
    DiscoveryReason::ProbeFailed
        .to_err()
        .with_detail(detail)
        .with_context(probe_error_context(probe, source))
}
