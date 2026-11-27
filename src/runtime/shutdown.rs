//! 停机信号：SIGTERM / SIGINT → 让主循环**有序**停下。
//!
//! 为什么必须有：主机的 tc/eBPF attach 只在进程**正常退出**（析构函数跑得到）时才会被摘掉。
//! `systemctl stop` 发的是 SIGTERM，Rust 默认直接终止进程 —— 析构函数不跑，于是：
//!   * 在途窗口（还没 settle 的那一分钟）直接丢，连一条 `partial` 记录都没有；
//!   * 老内核（<6.6 的 netlink clsact filter）上，程序会**留在网卡上**继续被逐包执行。
//!
//! 这里只负责「告诉主循环该停了」，具体停什么（流记录 flush + 卸 filter、释放文件句柄）
//! 由主循环按自己的顺序做。

use std::time::Duration;

/// 停机信号。`new()` 之后用 [`ShutdownSignal::idle`] 替换主循环里的 `sleep`。
pub(crate) struct ShutdownSignal {
    #[cfg(unix)]
    terminate: Option<tokio::signal::unix::Signal>,
    #[cfg(unix)]
    interrupt: Option<tokio::signal::unix::Signal>,
    /// 一旦置位就不再复位：停机的决定不能被后面的 tick 翻回去。
    requested: bool,
}

impl ShutdownSignal {
    pub(crate) fn new() -> Self {
        #[cfg(unix)]
        {
            // 注册失败（极少：fd 用尽 / 非主线程）不是致命问题：退回“没有信号处理”，
            // 行为与改动前一致（进程被直接杀掉），但**不假装**自己支持优雅停机。
            let terminate = match tokio::signal::unix::signal(
                tokio::signal::unix::SignalKind::terminate(),
            ) {
                Ok(signal) => Some(signal),
                Err(err) => {
                    log::warn!(
                        "event=ShutdownSignalUnavailable signal=sigterm detail=\"{err}\"（停机时会直接退出，不 flush 在途窗口）"
                    );
                    None
                }
            };
            let interrupt =
                match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt()) {
                    Ok(signal) => Some(signal),
                    Err(err) => {
                        log::warn!(
                            "event=ShutdownSignalUnavailable signal=sigint detail=\"{err}\""
                        );
                        None
                    }
                };
            Self {
                terminate,
                interrupt,
                requested: false,
            }
        }
        #[cfg(not(unix))]
        {
            Self { requested: false }
        }
    }

    /// 是否已经收到过停机信号（测试用：主循环自己只靠 [`Self::idle`] 的返回值）。
    #[cfg(test)]
    pub(crate) fn requested(&self) -> bool {
        self.requested
    }

    /// 最多等 `dur`；返回**是否要停**。
    ///
    /// 信号来了立刻返回 `true`（不用等满一个 tick），主循环据此跳出并做停机收尾。
    pub(crate) async fn idle(&mut self, dur: Duration) -> bool {
        if self.requested {
            return true;
        }
        #[cfg(unix)]
        {
            let sleep = tokio::time::sleep(dur);
            tokio::pin!(sleep);
            tokio::select! {
                _ = &mut sleep => false,
                signal = recv(&mut self.terminate, &mut self.interrupt) => {
                    log::info!("event=AgentdShutdownRequested signal={signal}");
                    self.requested = true;
                    true
                }
            }
        }
        #[cfg(not(unix))]
        {
            tokio::time::sleep(dur).await;
            false
        }
    }
}

/// 等到任意一个信号；两个都没注册上就永远等下去（等于没有信号支持）。
#[cfg(unix)]
async fn recv(
    terminate: &mut Option<tokio::signal::unix::Signal>,
    interrupt: &mut Option<tokio::signal::unix::Signal>,
) -> &'static str {
    match (terminate.as_mut(), interrupt.as_mut()) {
        (Some(term), Some(int)) => tokio::select! {
            _ = term.recv() => "sigterm",
            _ = int.recv() => "sigint",
        },
        (Some(term), None) => {
            term.recv().await;
            "sigterm"
        }
        (None, Some(int)) => {
            int.recv().await;
            "sigint"
        }
        (None, None) => std::future::pending().await,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// 没收到信号时 `idle` 只是等满时间并返回 `false`（不能因为“注册了信号”就立刻停）。
    #[tokio::test(flavor = "current_thread")]
    async fn idle_times_out_when_nothing_arrives() {
        let mut shutdown = ShutdownSignal::new();
        assert!(!shutdown.requested());
        assert!(!shutdown.idle(Duration::from_millis(10)).await);
        assert!(!shutdown.requested());
    }

    /// 已经置位之后，`idle` 立刻返回 `true`（不再陪跑一个 tick）。
    #[tokio::test(flavor = "current_thread")]
    async fn idle_returns_immediately_once_requested() {
        let mut shutdown = ShutdownSignal::new();
        shutdown.requested = true;
        let started = std::time::Instant::now();
        assert!(shutdown.idle(Duration::from_secs(60)).await);
        assert!(started.elapsed() < Duration::from_secs(1));
    }
}
