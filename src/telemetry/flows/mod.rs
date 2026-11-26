//! 主机流记录（`FLOW:` 帧）：记录形状、窗口切分、选卡与采集器入口。
//!
//! 设计见 `docs/design/host-ebpf-flow-collection.md`。分工：
//! - `record`：窗口/键/记录编码（平台无关，唯一构造点）；
//! - `iface`：观测哪张网卡（纯判定）；
//! - `support`：采不了的原因，映射到采集状态闭集；
//! - `linux`：tc/eBPF 采集器（Linux + 构建期有 clang 时才会编译进去）。
//!
//! 这里给出的 [`Collector`] 是**跨平台门面**：非 Linux 或没编进 BPF 对象时，
//! `start` 返回 `NotBuilt`，调用方据此如实上报，而不是假装能采。

pub mod iface;
pub mod record;
pub mod support;

#[cfg(all(target_os = "linux", have_flow_bpf))]
mod linux;

use iface::IfaceSnapshot;
use record::{FlowKey, WindowAgg};
use std::net::IpAddr;
use support::{FlowSupport, Unavailable};

/// 一次 flush 交出去的一条聚合（窗口墙钟由调用方换算）。
#[derive(Debug, Clone)]
pub(crate) struct FlushedFlow {
    pub ifindex: u32,
    pub key: FlowKey,
    pub window_bucket: u64,
    pub agg: WindowAgg,
}

/// 正在被观测的网卡（采集层快照，用于填记录上下文）。
#[derive(Debug, Clone)]
pub(crate) struct WatchedIface {
    pub name: String,
    pub ifindex: u32,
    pub mac: Option<String>,
    pub addrs: Vec<IpAddr>,
}

fn not_built() -> Unavailable {
    Unavailable::NotBuilt {
        platform: if cfg!(target_os = "linux") {
            "linux, built without clang".to_string()
        } else {
            std::env::consts::OS.to_string()
        },
    }
}

/// 本机能不能采流记录（只判内核/构建；权限与 qdisc 在 `Collector::start` 才暴露）。
pub(crate) fn probe() -> FlowSupport {
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    {
        return linux::probe();
    }
    #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
    {
        FlowSupport::Unavailable(not_built())
    }
}

/// 单调时钟的 60s 桶（与 BPF 侧 `bpf_ktime_get_ns()/60e9` 同一口径）。
///
/// 只用来算**桶差**：桶边界本身不对齐 UTC，墙钟归属由 [`record::window_from_bucket`] 换算。
pub(crate) fn monotonic_bucket() -> u64 {
    let mut now: libc::timespec = unsafe { std::mem::zeroed() };
    if unsafe { libc::clock_gettime(libc::CLOCK_MONOTONIC, &mut now) } != 0 {
        return 0;
    }
    let seconds = now.tv_sec.max(0) as u64;
    seconds / record::WINDOW_SECONDS
}

/// 采集器门面。
pub(crate) struct Collector {
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    inner: linux::Collector,
}

impl Collector {
    /// 在给定网卡上开始观测。
    ///
    /// 返回 `Err` 表示**采不了**（内核/权限/qdisc/加载失败），调用方必须如实上报。
    pub(crate) fn start(ifaces: &[&IfaceSnapshot]) -> Result<Self, Unavailable> {
        #[cfg(all(target_os = "linux", have_flow_bpf))]
        {
            return linux::Collector::start(ifaces).map(|inner| Self { inner });
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            let _ = ifaces;
            Err(not_built())
        }
    }

    pub(crate) fn watched(&self) -> &[WatchedIface] {
        #[cfg(all(target_os = "linux", have_flow_bpf))]
        {
            return self.inner.watched();
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            &[]
        }
    }

    /// flush 已经结束满 `FLUSH_LAG_WINDOWS` 个窗口的桶。
    pub(crate) fn flush(&mut self, now_bucket: u64) -> Vec<FlushedFlow> {
        #[cfg(all(target_os = "linux", have_flow_bpf))]
        {
            return self.inner.flush(now_bucket);
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            let _ = now_bucket;
            Vec::new()
        }
    }

    /// 上一轮 flush 之后落进已 flush 窗口的包数（迟到，不补发）。
    pub(crate) fn take_late_dropped(&mut self) -> u64 {
        #[cfg(all(target_os = "linux", have_flow_bpf))]
        {
            return self.inner.take_late_dropped();
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            0
        }
    }
}
