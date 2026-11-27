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

// 解码侧（协议号、方向、迟到判定、各类「采不了」原因）只在 Linux + 构建期编了 BPF 对象时
// 才被构造。其余平台（或没 clang 的构建）里这些项会显示为 dead_code —— 那是 cfg 的产物，
// 不是真的死代码。注意这条 **只在非采集平台生效**：Linux 构建照常报死代码。
#![cfg_attr(not(all(target_os = "linux", have_flow_bpf)), allow(dead_code))]

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

/// 一次 flush 的结果。
#[derive(Debug, Default)]
pub(crate) struct FlushBatch {
    pub flows: Vec<FlushedFlow>,
    /// 还有桶没取走（这一拍到了批量上限）：桶留在 BPF 表里，下一拍照着取。
    /// 不是丢数据，只是分拍 —— 见 [`record::plan_take`]。
    pub deferred: bool,
}

/// 正在被观测的网卡（采集层快照，用于填记录上下文）。
#[derive(Debug, Clone)]
pub(crate) struct WatchedIface {
    pub name: String,
    pub ifindex: u32,
    pub mac: Option<String>,
    pub addrs: Vec<IpAddr>,
}

/// 真机测试的**网卡互斥**。
///
/// 两个真机用例（采集层单测与 daemon 端到端）都会 attach 到同一张网卡：并行跑时 filter
/// 会叠加，计数与丢包判定不可解释，而且先挂的那个会把流量“抢”走 —— 结果是偶发挂死。
/// 这里用一把进程内锁把它们串起来，不依赖调用者记得传 `--test-threads=1`。
#[cfg(test)]
pub(crate) static REAL_NIC_TEST_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// 本构建没有采集器时的原因。
///
/// 只在「非 Linux 平台 / 构建时没有 clang」编译：Linux + 编进 BPF 对象时报的是内核/权限，
/// 轮不到这一条。
#[cfg(not(all(target_os = "linux", have_flow_bpf)))]
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
        linux::probe()
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

/// 本机网卡快照（采集层事实）。非 Linux / 没编进 BPF 对象时为空。
pub(crate) fn interfaces() -> Vec<IfaceSnapshot> {
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    {
        linux::interfaces()
    }
    #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
    {
        Vec::new()
    }
}

/// 运行内核版本（`uname -r`）。取不到就写 `unknown`（不猜、不伪造）。
pub(crate) fn kernel_release() -> String {
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    {
        linux::kernel_release().unwrap_or_else(|| "unknown".to_string())
    }
    #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
    {
        "unknown".to_string()
    }
}

/// 当前走哪条 attach 路径：`tcx`（≥6.6，内核自动摘）| `netlink`（<6.6，需自己清残留）
/// | `unavailable`（本构建没有采集器）。自观测（`state/flows/status.json`）用它。
pub(crate) fn attach_path() -> &'static str {
    #[cfg(all(target_os = "linux", have_flow_bpf))]
    {
        linux::attach_path()
    }
    #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
    {
        "unavailable"
    }
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
            linux::Collector::start(ifaces).map(|inner| Self { inner })
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
            self.inner.watched()
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            &[]
        }
    }

    /// flush 已经结束满 `FLUSH_LAG_WINDOWS` 个窗口的桶，最多 `max` 条（`0` = 不限）。
    pub(crate) fn flush(&mut self, now_bucket: u64, max: usize) -> FlushBatch {
        #[cfg(all(target_os = "linux", have_flow_bpf))]
        {
            self.inner.flush(now_bucket, max)
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            let _ = (now_bucket, max);
            FlushBatch::default()
        }
    }

    /// 把**所有**桶（含在途窗口）取出来，用于停采时的截断窗口。不限量：停采只有一次机会。
    pub(crate) fn flush_all(&mut self, now_bucket: u64) -> Vec<FlushedFlow> {
        #[cfg(all(target_os = "linux", have_flow_bpf))]
        {
            self.inner.flush_all(now_bucket)
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
            self.inner.take_late_dropped()
        }
        #[cfg(not(all(target_os = "linux", have_flow_bpf)))]
        {
            0
        }
    }
}
