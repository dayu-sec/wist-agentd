//! 采集能力探测的结果与它到采集状态（`AgentLocalCollection`）的映射。
//!
//! `collection-status.md` 的原因闭集里没有「本版没这个采集器」这一条，所以：
//! - 内核/构建不支持 → `unsupported`
//! - 缺能力（CAP_*）→ `permission`
//! - qdisc 装不上 / verifier 拒绝 → `run_failed`
//!
//! 三类必须分开：现场看到的文案不同，下一步动作也不同（换内核 / 给权限 / 调网络配置）。

/// 本机能不能采流记录。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum FlowSupport {
    Available,
    Unavailable(Unavailable),
}

impl FlowSupport {
    /// 能力探测的结论是「能采 / 不能采 + 为什么」，判定点全在 daemon 侧的
    /// `daemon_flows`：那里直接 match 两个变体（不能采时要拿整条原因进采集状态，不是只要一句话）。
    #[cfg(test)]
    pub(crate) const fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }
}

/// 采不了的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// 本构建没有采集器（非 Linux 平台，或构建时没有嵌入 BPF 对象）。
    ///
    /// 在「Linux + 编进 BPF」的构建里这个变体不会被构造 —— 但它是**另一个平台**上的
    /// 如实答案，不能为消警告而删。
    #[cfg_attr(all(target_os = "linux", have_flow_bpf), allow(dead_code))]
    NotBuilt { platform: String },
    /// 没有一张网卡符合观测条件（没有默认路由，或只有链路本地/回环地址）。
    ///
    /// 与 `KernelTooOld` 分开：这台机器本身是好的，缺的是**网络事实**（默认路由还没起来、
    /// 网卡还没拿到地址），等一会儿可能就自己好了 —— 所以映射到 `source_not_ready`，
    /// 而不是 `unsupported`。
    NoObservedInterface { detail: String },
    /// 内核低于基线（`gso_segs` / tc 能力缺失）。
    KernelTooOld { running: String, required: String },
    /// 缺 capability（`CAP_BPF` / `CAP_NET_ADMIN`）。
    PermissionDenied { capability: String },
    /// `clsact` 装不上或与既有 qdisc 冲突。
    QdiscConflict { ifname: String, detail: String },
    /// verifier 拒绝 / 对象加载失败。
    LoadFailed { detail: String },
}

impl Unavailable {
    /// 映射到 `collection-status.md` 的原因 `kind` 闭集。
    pub(crate) const fn reason_kind(&self) -> &'static str {
        match self {
            // 内核/构建不支持：能力层面没有，不是失败。
            Self::NotBuilt { .. } | Self::KernelTooOld { .. } => "unsupported",
            // 采集器本身没问题，缺的是本机网络事实（默认路由/地址）。
            Self::NoObservedInterface { .. } => "source_not_ready",
            Self::PermissionDenied { .. } => "permission",
            // 运行期失败：装不上 qdisc / 加载不了对象。
            Self::QdiscConflict { .. } | Self::LoadFailed { .. } => "run_failed",
        }
    }

    /// 上报时的 `subject`（谁的问题）。
    pub(crate) fn subject(&self) -> String {
        match self {
            Self::NotBuilt { platform } => platform.clone(),
            Self::KernelTooOld { running, .. } => running.clone(),
            Self::NoObservedInterface { .. } => "iface".to_string(),
            Self::PermissionDenied { capability } => capability.clone(),
            Self::QdiscConflict { ifname, .. } => format!("qdisc:{ifname}"),
            Self::LoadFailed { .. } => "bpf_load".to_string(),
        }
    }

    /// 面向现场的一句话（英文，与既有 `unsupported_reason` 的口径一致）。
    pub(crate) fn detail(&self) -> String {
        match self {
            Self::NotBuilt { platform } => format!(
                "HostFlow is not built for this agent ({platform}): the eBPF/tc collector \
                 ships Linux-only builds"
            ),
            Self::KernelTooOld { running, required } => format!(
                "HostFlow needs Linux kernel >= {required} with `gso_segs` \
                 (running: {running})"
            ),
            Self::NoObservedInterface { detail } => format!(
                "HostFlow found no NIC to observe: {detail} \
                 (needs a default route and a routable address; container/loopback NICs are skipped)"
            ),
            Self::PermissionDenied { capability } => {
                format!(
                    "HostFlow needs {capability} (agentd must run as root or hold the capability)"
                )
            }
            Self::QdiscConflict { ifname, detail } => {
                format!("HostFlow could not attach to {ifname} (clsact qdisc): {detail}")
            }
            Self::LoadFailed { detail } => {
                format!(
                    "HostFlow BPF object failed to load: {}",
                    truncate(detail, 240)
                )
            }
        }
    }
}

/// verifier 的日志可以很长：只留前 `max` 字节，且按字符边界切（日志里有中文路径）。
fn truncate(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_string();
    }
    let mut end = max;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…", &text[..end])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reasons_map_onto_the_closed_set() {
        assert_eq!(
            Unavailable::NotBuilt {
                platform: "macos".into()
            }
            .reason_kind(),
            "unsupported"
        );
        assert_eq!(
            Unavailable::KernelTooOld {
                running: "4.14".into(),
                required: "5.4".into()
            }
            .reason_kind(),
            "unsupported"
        );
        assert_eq!(
            Unavailable::PermissionDenied {
                capability: "cap_bpf".into()
            }
            .reason_kind(),
            "permission"
        );
        // 「这台机器还没有对外网卡」不是能力缺失，等网络起来就能自愈。
        assert_eq!(
            Unavailable::NoObservedInterface {
                detail: "no default route".into()
            }
            .reason_kind(),
            "source_not_ready"
        );
        assert_eq!(
            Unavailable::QdiscConflict {
                ifname: "eth0".into(),
                detail: "EBUSY".into()
            }
            .reason_kind(),
            "run_failed"
        );
        assert_eq!(
            Unavailable::LoadFailed {
                detail: "verifier: invalid".into()
            }
            .reason_kind(),
            "run_failed"
        );
    }

    #[test]
    fn subjects_let_the_field_say_what_to_fix() {
        assert_eq!(
            Unavailable::PermissionDenied {
                capability: "cap_bpf".into()
            }
            .subject(),
            "cap_bpf"
        );
        assert_eq!(
            Unavailable::QdiscConflict {
                ifname: "eth0".into(),
                detail: "EBUSY".into()
            }
            .subject(),
            "qdisc:eth0"
        );
        assert_eq!(
            Unavailable::KernelTooOld {
                running: "4.18.0".into(),
                required: "5.4".into()
            }
            .subject(),
            "4.18.0"
        );
    }

    #[test]
    fn detail_mentions_the_action_and_is_bounded() {
        let too_old = Unavailable::KernelTooOld {
            running: "4.14.0".into(),
            required: "5.4".into(),
        };
        let detail = too_old.detail();
        assert!(detail.contains("5.4"), "{detail}");
        assert!(detail.contains("4.14.0"), "{detail}");

        let long = "汉".repeat(400);
        let detail = Unavailable::LoadFailed { detail: long }.detail();
        assert!(detail.len() < 400, "verifier 日志要截断：{}", detail.len());
    }

    #[test]
    fn available_has_no_reason() {
        assert!(FlowSupport::Available.is_available());
        assert!(
            !FlowSupport::Unavailable(Unavailable::NotBuilt {
                platform: "macos".into()
            })
            .is_available()
        );
    }
}
