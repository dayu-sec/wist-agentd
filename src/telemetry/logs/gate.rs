//! 上送闸门：**界定好的记录 → 上送记录**。
//!
//! 这是**唯一**决定"一条记录要不要上送"的地方。为什么要单独一处：这个决定同时牵动三件
//! 不能分家的事 ——（1）发不发、（2）要不要消耗 `seq`、（3）怎么让人知道没发。散在调用点
//! 迟早会不一致。
//!
//! ## 判据：封口方式（`records::Completion`）
//!
//! | 封口 | 处置 | 理由 |
//! | --- | --- | --- |
//! | `Boundary` | 放行 | 边界确定、内容完整 |
//! | `Deadline` | 放行 | 内容完整；边界是推断的，但下游没有可执行的动作 → 不逐帧传 |
//! | `Oversized` | **挡下** | 内容**不全**。发出去它长得像完整记录，会骗过下游解析 |
//!
//! 为什么不逐帧传封口方式：协议 §6 已经定了「**不往数据平面插 in-band 标记**」——
//! 帧承载的是记录本身，"这条是怎么被截的"不是记录的内容。
//!
//! ## 挡下为什么不消耗 `seq`
//!
//! `seq` 是**上送记录**的跨 hop 身份。按协议 §6，接收端把「洞口 − 已上报的丢弃区间」
//! 当**真丢失**；挡下若也取号却不上报，接收端就会凭空报一次数据丢失（假警报）。
//! 所以现在**不取号**：接收端看不到洞，不会误报。
//!
//! 代价说清：平台侧**看不到**这件事，只有 agentd 本机的诊断（见 [`Withheld::summary`]）。
//! 等 §6 的丢弃区间报告通道建起来，再把"取号 + 上报 `truncated:record_limit`"一起加上
//! —— 那一步只动本模块（调用方不用改），下面这条不变量由测试钉住。

use wist_contracts::telemetry_record::TelemetryRecord;
use wist_shared::records::{Completion, Record};

use crate::telemetry::logs::multiline::{MAX_RECORD_BYTES, MAX_RECORD_LINES};
use crate::telemetry::logs::parser::parse_delimited_records;

use super::InputOrigin;

/// 挡下的原因码（将来进丢弃区间报告时用它当 `reason`）。
pub const WITHHELD_REASON: &str = "truncated:record_limit";

/// 被挡下的记录：**内容不全**（超过累积上限被截）。按设计不转发。
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Withheld {
    pub records: usize,
    pub bytes: usize,
}

impl Withheld {
    pub fn is_empty(&self) -> bool {
        self.records == 0
    }

    /// 问题的**身份**（进 failure 的 `detail`，**参与去重**）：原因 + 撞的是哪个上限。
    ///
    /// 刻意**不含本次计数** —— 去重的是"问题"，不是"它这次多大"。带上计数会让一个持续
    /// 存在的病态块每 tick 换个签名、每 tick 打印一次，正好毁掉选这条通道的理由。
    /// 量在 [`Withheld::magnitude`]：它会变，所以**不参与去重**。
    pub fn detail(&self) -> String {
        format!("{WITHHELD_REASON} limit_lines={MAX_RECORD_LINES} limit_bytes={MAX_RECORD_BYTES}")
    }

    /// 这个问题的**量**（会变）：本次挡下几条、多少字节。
    pub fn magnitude(&self) -> String {
        format!("records={} bytes={}", self.records, self.bytes)
    }
}

/// 上送闸门：持有本次采集的公共上下文，按封口方式放行或挡下。
pub struct UplinkGate<'a> {
    agent_id: &'a str,
    observed_at: &'a str,
    input_id: &'a str,
    /// 这条输入的来源身份（面 + 目录单元）：随记录进帧。空 = 非派活来源。
    origin: InputOrigin,
    withheld: Withheld,
}

impl<'a> UplinkGate<'a> {
    pub fn new(
        agent_id: &'a str,
        observed_at: &'a str,
        input_id: &'a str,
        origin: InputOrigin,
    ) -> Self {
        Self {
            agent_id,
            observed_at,
            input_id,
            origin,
            withheld: Withheld::default(),
        }
    }

    /// 收下一批界定好的记录。
    ///
    /// 放行的转成上送记录并**消耗 `seq`**；挡下的只记账（不取号 —— 见模块说明）。
    /// `source_path` 逐次传入：同一个输入可能同时在读轮转后的旧文件与当前文件。
    pub fn admit(
        &mut self,
        source_path: &str,
        records: Vec<Record>,
        next_seq: &mut u64,
    ) -> Vec<TelemetryRecord> {
        let mut admitted = Vec::with_capacity(records.len());
        for record in records {
            if withholds(&record) {
                self.withheld.records += 1;
                self.withheld.bytes += record.body.len();
                continue;
            }
            admitted.push(record);
        }
        parse_delimited_records(
            self.agent_id,
            self.observed_at,
            self.input_id,
            source_path,
            &self.origin,
            admitted,
            next_seq,
        )
    }

    /// 本次挡下了什么（`records == 0` 表示没有）。
    pub fn withheld(&self) -> Withheld {
        self.withheld
    }
}

/// 判据只有一条：**内容不全的不发**。
///
/// 用穷举 `match` 而不是 `matches!`：这样 `Completion` 日后多一个变体时，**这里编译不过**，
/// 逼着人明确决定新变体该不该发 —— 而不是默默把它当成"完整"发出去。
fn withholds(record: &Record) -> bool {
    match record.completion {
        Completion::Oversized => true,
        Completion::Boundary | Completion::Deadline => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn record(body: &str, completion: Completion) -> Record {
        Record {
            body: body.to_string(),
            start_offset: 0,
            end_offset: body.len() as u64,
            lines: 1,
            completion,
        }
    }

    fn gate() -> UplinkGate<'static> {
        UplinkGate::new(
            "agent-1",
            "2026-09-23T00:00:00Z",
            "input-a",
            InputOrigin::default(),
        )
    }

    #[test]
    fn complete_records_are_admitted_and_take_a_seq() {
        for completion in [Completion::Boundary, Completion::Deadline] {
            let mut gate = gate();
            let mut seq = 10;
            let admitted = gate.admit(
                "/var/log/app.log",
                vec![record("one\n", completion), record("two\n", completion)],
                &mut seq,
            );
            assert_eq!(admitted.len(), 2, "{completion:?}");
            assert_eq!(admitted[0].seq, 10);
            assert_eq!(admitted[1].seq, 11);
            assert_eq!(seq, 12, "放行的记录消耗 seq");
            assert!(gate.withheld().is_empty());
            assert_eq!(admitted[0].body, "one\n");
            assert_eq!(admitted[0].source_path, "/var/log/app.log");
        }
    }

    #[test]
    fn an_incomplete_record_is_withheld_and_does_not_take_a_seq() {
        // 关键不变量：挡下**不取号** —— 否则接收端会看到一个"洞"，
        // 而按协议 §6，未上报的洞等于真丢失 → 凭空报一次数据丢失。
        let mut gate = gate();
        let mut seq = 10;
        let admitted = gate.admit(
            "/var/log/app.log",
            vec![
                record("good\n", Completion::Boundary),
                record("cut here\n", Completion::Oversized),
                record("also good\n", Completion::Boundary),
            ],
            &mut seq,
        );
        assert_eq!(admitted.len(), 2);
        assert_eq!(
            admitted.iter().map(|r| r.body.as_str()).collect::<Vec<_>>(),
            vec!["good\n", "also good\n"]
        );
        assert_eq!(admitted[0].seq, 10);
        assert_eq!(admitted[1].seq, 11, "被挡下的那条不占号");
        assert_eq!(seq, 12, "seq 只按放行条数前移");
        assert_eq!(
            gate.withheld(),
            Withheld {
                records: 1,
                bytes: "cut here\n".len()
            }
        );
    }

    #[test]
    fn nothing_to_admit_costs_nothing() {
        // 空批：不放行也不挡下，seq 一点都不动。
        let mut gate = gate();
        let mut seq = 7;
        assert!(gate.admit("/a.log", Vec::new(), &mut seq).is_empty());
        assert_eq!(seq, 7);
        assert!(gate.withheld().is_empty());
    }

    #[test]
    fn counts_accumulate_across_admits_on_the_same_gate() {
        // 闸门是**按采集批次**一个：轮转尾巴与当前文件可能各自挡下几条，计数要累加。
        let mut gate = gate();
        let mut seq = 0;
        gate.admit(
            "/a.log.1",
            vec![record("cut A\n", Completion::Oversized)],
            &mut seq,
        );
        gate.admit(
            "/a.log",
            vec![
                record("cut B\n", Completion::Oversized),
                record("ok\n", Completion::Boundary),
            ],
            &mut seq,
        );
        assert_eq!(
            gate.withheld(),
            Withheld {
                records: 2,
                bytes: "cut A\n".len() + "cut B\n".len()
            }
        );
        assert_eq!(seq, 1, "只有放行的那条取号");
    }

    #[test]
    fn a_batch_that_is_all_withheld_does_not_advance_the_sequence() {
        // 极端：整批都是内容不全的。接收端仍不该看到洞。
        let mut gate = gate();
        let mut seq = 42;
        let admitted = gate.admit(
            "/a.log",
            vec![
                record("cut A\n", Completion::Oversized),
                record("cut B\n", Completion::Oversized),
            ],
            &mut seq,
        );
        assert!(admitted.is_empty());
        assert_eq!(seq, 42);
        assert_eq!(gate.withheld().records, 2);
    }

    #[test]
    fn the_identity_is_stable_while_the_magnitude_moves() {
        // 去重按 `detail`（身份），量在 `magnitude`。这条契约很重要：
        // 把量放进身份，一个持续存在的病态块就会每 tick 换个签名、每 tick 打印一次
        // —— 正好毁掉"走 failure 通道蹭去重"这个选择。
        let small = Withheld {
            records: 1,
            bytes: 11_890,
        };
        let big = Withheld {
            records: 3,
            bytes: 9_000_000,
        };
        assert_eq!(small.detail(), big.detail(), "身份不许随量变");
        assert_ne!(small.magnitude(), big.magnitude(), "量得看得出变化");
        // 身份里带上撞的是哪个上限：读到它的人第一个问题就是"撞的哪一条"。
        assert!(
            small.detail().contains(WITHHELD_REASON),
            "{}",
            small.detail()
        );
        assert!(
            small
                .detail()
                .contains(&format!("limit_lines={MAX_RECORD_LINES}")),
            "{}",
            small.detail()
        );
        assert!(
            small
                .detail()
                .contains(&format!("limit_bytes={MAX_RECORD_BYTES}")),
            "{}",
            small.detail()
        );
        assert!(
            small.magnitude().contains("records=1"),
            "{}",
            small.magnitude()
        );
    }
}
