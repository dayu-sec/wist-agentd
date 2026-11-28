//! 采集范围：**默认（也是现在的唯一行为）只留「一端是公网」的流量**。
//!
//! **出站和入站都在内** —— 判据是**对端**，不是方向：`src` / `dst` **任意一个是公网**就保留，
//! 两端都是内网（东西向）才丢。所以：
//!
//! | 场景 | `src` | `dst` | 结果 |
//! |---|---|---|---|
//! | 本机主动连公网 | 私网 | **公网** | 保留 |
//! | 公网回包 / 公网连进来 | **公网** | 私网 | 保留 |
//! | 本机有公网 IP，公网直连 | **公网** | **公网** | 保留 |
//! | 内网东西向（k8s / mesh / 同 VPC） | 私网 | 私网 | **丢弃**（计 `filtered`） |
//!
//! 只判 `dst` 会把入站整片丢掉（入站包的 `dst` 就是本机私网地址），而「谁在访问我」
//! 恰恰是最有价值的观测之一（暴露面分析的另一半）；入站连接数通常很少（只有开放端口），
//! 成本几乎不涨。这条取舍在 `linux.rs` 的真机用例里有专门一条断言钉着。
//!
//! 为什么默认只留涉公网：主机上真正有信息量的是「这台机器跟公网上谁通信」——暴露面、
//! 外联基线、C2/挖矿判定都要它；而东西向（内网互通，尤其 k8s / service mesh）在
//! **连接条数**上通常比对外多两个数量级，正好是聚合表容量与每拍扫描成本的大头。
//! 丢掉东西向不是省一点，是换一个量级（见设计 §10.2）。
//!
//! 真正的判定在 BPF 侧（`flow.bpf.c` 的 `v4_internal` / `v6_internal`）：
//! 那边必须逐包做，且不能查表。**两边的地址表必须一致** —— 改动时对照
//! `docs/design/host-ebpf-flow-collection.md` §10.2 的表格。
//!
//! 为什么**没有**配置项：规模化的部署里没人会去改每一台机器的 `agentd.toml`，
//! 本机开关加进去等于永远停在默认值（一个假的配置面）。真要让站点/主机改口径，
//! 只能走平台下发（现有 `discovery-policies:poll` 是最近的落点），那是单独的契约改动，
//! 见设计 §10.2 / §13 #9。

/// 采集范围。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub(crate) enum FlowScope {
    /// 只保留「一端是公网」的流量（`src` 或 `dst` 是公网；**出站、入站都留**）。
    /// **生产唯一路径。**
    #[default]
    Internet,
    /// 全采（含内网东西向）。成本随连接数线性上升。
    ///
    /// 目前只有真机用例走这条（它们发往私网地址，不切全采就测不到流）；
    /// 将来平台下发口径时才会在生产里出现。所以生产构建里它是"未构造"的。
    #[cfg_attr(not(test), allow(dead_code))]
    All,
}

impl FlowScope {
    /// 写进状态快照 / 诊断的稳定词。改动它等于改现场语义，别随手改。
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Internet => "internet",
            Self::All => "all",
        }
    }

    /// 写进 BPF 的 `scope_mode`：`0` = 全采（过滤器恒真），`1` = 只留涉公网。
    pub(crate) const fn bpf_mode(self) -> u32 {
        match self {
            Self::Internet => 1,
            Self::All => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_default_is_internet_only() {
        assert_eq!(FlowScope::default(), FlowScope::Internet);
        assert_eq!(FlowScope::default().as_str(), "internet");
    }

    #[test]
    fn bpf_mode_matches_the_program_contract() {
        // 0 = 不过滤（全采），1 = 只留涉公网。BPF 侧按 `if (mode == 0) return 0;` 分支。
        assert_eq!(FlowScope::All.bpf_mode(), 0);
        assert_eq!(FlowScope::Internet.bpf_mode(), 1);
    }

    #[test]
    fn the_wire_words_are_stable() {
        // 这两个词进了 `state/flows/status.json` 与 `diagnose` 输出，改它就是改现场语义。
        assert_eq!(FlowScope::Internet.as_str(), "internet");
        assert_eq!(FlowScope::All.as_str(), "all");
    }
}
