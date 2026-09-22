//! Kubernetes discovery probe skeleton.

use orion_error::conversion::ToStructError;

use super::{DiscoveryError, DiscoveryProbe, DiscoveryReason, DiscoverySourceKind, ProbeOutput};

#[derive(::jumo_derive::Jumo)]
#[jumo(kind = "struct", domain = "Discovery", module = "Discovery.Probe")]
pub struct K8sDiscoveryProbe;

impl DiscoveryProbe for K8sDiscoveryProbe {
    fn name(&self) -> &'static str {
        "k8s"
    }

    fn source(&self) -> DiscoverySourceKind {
        DiscoverySourceKind::K8s
    }

    fn refresh_interval(&self) -> std::time::Duration {
        // 这是**内建默认值**：与策展数据 `jumo/model/content/aspect-policies.toml` 里的
        // `default_interval_seconds` 同值，只在拿不到平台下发的策略表（断网 / 网关未配表）时生效。
        // 拿得到表就由表盖过（见 `DiscoveryRuntime` 的到期判定）；改策展值不必改这里。

        std::time::Duration::from_secs(300)
    }

    fn refresh(&self, _now: std::time::SystemTime) -> Result<ProbeOutput, DiscoveryError> {
        Err(DiscoveryReason::NotImplemented
            .to_err()
            .with_detail("k8s discovery probe is not implemented")
            .with_context(super::probe_error_context(self.name(), self.source())))
    }
}
