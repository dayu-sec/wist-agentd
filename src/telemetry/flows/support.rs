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
    pub(crate) const fn is_available(&self) -> bool {
        matches!(self, Self::Available)
    }

    /// 给 `unsupported` 原因用的一句话（`None` = 能采）。
    pub(crate) fn detail(&self) -> Option<String> {
        match self {
            Self::Available => None,
            Self::Unavailable(reason) => Some(reason.detail()),
        }
    }
}

/// 采不了的原因。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Unavailable {
    /// 本构建没有采集器（非 Linux 平台，或构建时没有嵌入 BPF 对象）。
    NotBuilt { platform: String },
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
        assert_eq!(FlowSupport::Available.detail(), None);
        assert!(
            !FlowSupport::Unavailable(Unavailable::NotBuilt {
                platform: "macos".into()
            })
            .is_available()
        );
    }
}
