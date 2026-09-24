//! File-log ingestion runtime pieces for standalone replacement.

pub mod files;
pub mod gate;
pub mod multiline;
pub mod parser;

/// 一条日志输入的**来源身份**：属于哪个采集面、哪条目录单元。
///
/// 为什么要有它：正文规则还没写时，记录的 `category` 恒为泛化的 `agent.log`，
/// 于是「这条来自哪个面」在数据里**没有位置** —— 两个面（如 launchd 与 wifi）一起跑就分不出来。
/// 它从工作授权（`AppliedWorkGrant::log_inputs`）一路带到数据帧里。
///
/// **两个字段都可能是空串**：空 = 这条不是平台派活来的（本机运维手工配置的输入）。
/// 这本身就是有用的信息，所以不拿“未知”去填。
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct InputOrigin {
    pub family: String,
    pub unit: String,
}

impl InputOrigin {
    pub fn new(family: impl Into<String>, unit: impl Into<String>) -> Self {
        Self {
            family: family.into(),
            unit: unit.into(),
        }
    }
}
