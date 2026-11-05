//! Kafka 消费组 lag / 状态采集。
//!
//! 链路（规范 §6）：`ListGroups` → `DescribeGroups` → `OffsetFetch` → `ListOffsets`。
//! 全部是只读 Admin 调用，不 produce / 不 consume。
//!
//! ## 为什么 lag 是 P0
//!
//! 分区数、ISR、容量都只能回答「集群本身健康吗」。消费停了（或消费者挂了）时，
//! 上述指标**全部正常**，只有 `kafka_consumergroup_lag` 会单调上升。它是 Kafka 侧
//! 唯一能反映「业务有没有在处理」的读数。
//!
//! ## 协调者与 leader
//!
//! - `ListGroups` 只返回**该 broker 自己协调**的组，所以要对每个 broker 各问一次；
//! - `DescribeGroups` / `OffsetFetch` 必须发给组协调者（即报出该组的那个 broker）；
//! - `ListOffsets` 必须发给**分区 leader**（`Metadata` 里拿），否则 broker 回
//!   `NOT_LEADER_OR_FOLLOWER`。
//!
//! ## lag 口径
//!
//! `lag = log_end_offset - committed_offset`，按 `(group, topic)` 求和：
//!
//! - 用 `ListOffsets(timestamp = -1)`（LEO）而不是 LSO：与 `kafka-consumer-groups.sh`
//!   一致，滞留在未提交事务里的消息也算积压；
//! - `committed_offset < 0`（`OffsetFetch` 的 -1 = 该分区没有提交位点）不计入；
//! - 负 lag（提交位点超过 LEO，retention 删掉了尾巴时会出现）按 0 处理 —— 上报负数
//!   会让「lag 总量」出现无法解释的洼地；
//! - **不伪造失败**：拿不到 LEO 的分区不进求和，同时留一条能定位的 warning。

use std::collections::{BTreeMap, BTreeSet};
use std::io;
use std::time::Duration;

use wist_contracts::discovery::StringKeyValue;

use super::kafka::{self, Broker, Metadata, Reader};
use super::kafka_auth::{self, Connection, SecurityConfig};
use super::runtime::MetricsLabeledFact;

/// 消费积压（`By` = 消息条数，单位 `1`）。
pub const FACT_LAG: &str = "kafka.consumergroup.lag";
/// 组状态（一热：取值进 `state` label，样本值恒 1）。
pub const FACT_STATE: &str = "kafka.consumergroup.state";

const API_KEY_LIST_OFFSETS: i16 = 2;
const API_KEY_OFFSET_FETCH: i16 = 9;
const API_KEY_DESCRIBE_GROUPS: i16 = 15;
const API_KEY_LIST_GROUPS: i16 = 16;

const CLIENT_ID: &str = "wist-agentd";

// 同一条连接上会连着发好几个请求，correlation id 只要互不相同即可（响应对得上就行）。
const CORRELATION_LIST_GROUPS: i32 = 31;
const CORRELATION_DESCRIBE_GROUPS: i32 = 32;
const CORRELATION_OFFSET_FETCH: i32 = 33;
const CORRELATION_LIST_OFFSETS: i32 = 34;

/// 消费组采集的基数上限与过滤口径（规范 §5）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct GroupPolicy {
    /// 白名单：非空时**只**发这些组（不看阈值 —— 配了就是想看）。
    pub allowlist: Vec<String>,
    /// 单轮最多查多少个组（超出按组名稳定截断，丢弃数进 warnings / 自观测）。
    pub max_groups: usize,
    /// 白名单为空时，只发总 lag 超过该阈值的组（避免给几百个空闲组各建一条序列）。
    pub lag_threshold: i64,
}

impl Default for GroupPolicy {
    fn default() -> Self {
        Self {
            allowlist: Vec::new(),
            max_groups: 200,
            lag_threshold: 1000,
        }
    }
}

/// 一轮消费组采集的产物。
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct GroupCollection {
    /// 带 `group` / `topic` label 的事实（`kafka.consumergroup.lag` / `.state`）。
    pub facts: Vec<MetricsLabeledFact>,
    /// 单个组 / 单个 broker 失败的原因。不影响其它组，也不让整轮失败。
    pub warnings: Vec<String>,
    /// 因 `max_groups` 截断而未采集的组数（不得静默丢弃）。
    pub dropped_groups: usize,
}

/// 逐组告警的**聚合器**。
///
/// 大集群里「所有组都没权限 / 协调者都在迁移」是常态故障：200 个组各打一行会在
/// 一轮里把日志刷满，真正有用的那行反而被挤掉（而且 `KafkaProbeWarning` 的闸门
/// 按「内容变化」判断，组集合一变就重打一整屏）。
///
/// 所以按**原因**聚合：单组保留原来的一句话，多组变成「N 个组（如 a, b, c…）…」。
#[derive(Default)]
struct GroupWarnings {
    /// 原因（不含组名）→ 受影响的组（按出现顺序、去重）。
    failures: BTreeMap<String, Vec<String>>,
    /// 分区级缺失的原因 → 受影响组与缺失分区总数。
    partitions: BTreeMap<&'static str, PartitionShortfall>,
}

#[derive(Default)]
struct PartitionShortfall {
    groups: Vec<String>,
    total: usize,
}

impl GroupWarnings {
    /// `reason` 里**不能**带组名（否则聚合失效）。
    fn failure(&mut self, reason: String, group: &str) {
        push_group(self.failures.entry(reason).or_default(), group);
    }

    fn partitions(&mut self, reason: &'static str, group: &str, count: usize) {
        let entry = self.partitions.entry(reason).or_default();
        push_group(&mut entry.groups, group);
        entry.total += count;
    }

    fn finish(self) -> Vec<String> {
        let mut lines = Vec::new();
        for (reason, groups) in self.failures {
            lines.push(format!("{} {reason}", group_subject(&groups)));
        }
        for (reason, shortfall) in self.partitions {
            if shortfall.groups.len() == 1 {
                lines.push(format!(
                    "组 {} 有 {} 个分区{reason}",
                    shortfall.groups[0], shortfall.total
                ));
            } else {
                lines.push(format!(
                    "{} 共 {} 个分区{reason}",
                    group_subject(&shortfall.groups),
                    shortfall.total
                ));
            }
        }
        lines
    }
}

fn push_group(groups: &mut Vec<String>, group: &str) {
    if !groups.iter().any(|existing| existing == group) {
        groups.push(group.to_string());
    }
}

/// 聚合行里最多列多少个组名（剩下的用 `…` 略去）。
const GROUP_SAMPLES: usize = 3;

fn group_subject(groups: &[String]) -> String {
    match groups.len() {
        1 => format!("组 {}", groups[0]),
        n if n <= GROUP_SAMPLES => format!("组 {}", groups.join(", ")),
        n => format!(
            "{n} 个组（如 {}…）",
            groups
                .iter()
                .take(GROUP_SAMPLES)
                .cloned()
                .collect::<Vec<_>>()
                .join(", ")
        ),
    }
}

/// 一轮消费组采集的整体预算（规范 §6：单次总体超时 20s）。
const GROUP_BUDGET: Duration = Duration::from_secs(20);

/// 一个组由哪个 broker 协调。
struct GroupRef {
    broker: i32,
    group_id: String,
}

/// 组提交的一个 `(topic, partition)` 位点。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Committed {
    pub topic: String,
    pub partition: i32,
    pub offset: i64,
}

/// `OffsetFetch` 的解析结果：可用位点 + 分区级失败数。
type CommittedReadings = (Vec<Committed>, usize);
/// `ListOffsets` 的解析结果：可用读数 + 分区级失败数。
type EndOffsetReadings = (Vec<((String, i32), i64)>, usize);
/// `(topic, partition) → log end offset`。
type EndOffsets = BTreeMap<(String, i32), i64>;

/// 采集一轮消费组指标。
///
/// 任何一层失败都只影响它自己：某个 broker 的 `ListGroups` 挂了 → 少它协调的那些组；
/// 某个组 `OffsetFetch` 没权限 → 少这个组的 lag，其余照常。
pub fn collect(
    metadata: &Metadata,
    security: &SecurityConfig<'_>,
    timeout: Duration,
    policy: &GroupPolicy,
) -> GroupCollection {
    let mut out = GroupCollection::default();
    if policy.max_groups == 0 {
        return out;
    }
    let brokers: BTreeMap<i32, &Broker> = metadata
        .brokers
        .iter()
        .map(|broker| (broker.node_id, broker))
        .collect();
    // 分区 → leader 只建一次：组数 × 分区数很容易上万，放在逐组循环里会反复 clone topic 名。
    let leaders: BTreeMap<(String, i32), i32> = metadata
        .partitions
        .iter()
        .map(|partition| {
            (
                (partition.topic.clone(), partition.partition),
                partition.leader,
            )
        })
        .collect();
    let mut links = Links::new(security, timeout);

    // 1. 发现：ListGroups 是 per-broker 的（各 broker 只报自己协调的组）。
    let mut discovered: Vec<GroupRef> = Vec::new();
    for broker in &metadata.brokers {
        let listed = {
            let Some(conn) = links.conn(broker) else {
                continue;
            };
            list_groups(conn)
        };
        match listed {
            Ok(groups) => {
                for (group_id, protocol_type) in groups {
                    // 老版本组可能没有 protocol_type；当 consumer 处理（比漏报更有用）。
                    if protocol_type.is_empty() || protocol_type == "consumer" {
                        discovered.push(GroupRef {
                            broker: broker.node_id,
                            group_id,
                        });
                    }
                }
            }
            Err(err) => out.warnings.push(format!(
                "broker {} ({}:{}) ListGroups 失败：{err}",
                broker.node_id, broker.host, broker.port
            )),
        }
    }

    // 2. 过滤 + 截断。
    //
    // 白名单是**明确要看**的组：先按它筛，再做 `max_groups` 截断。
    // 反过来（先截断再筛）会在「集群组数 > max_groups」时把白名单里的组随机丢掉 ——
    // 而这正是白名单存在的场景（大集群里只看几个关键组）。
    if !policy.allowlist.is_empty() {
        discovered.retain(|group| policy.allowlist.iter().any(|name| name == &group.group_id));
        // 白名单里的组名写错不能静默：现场只会看到「配了却没数据」。
        for name in &policy.allowlist {
            if !discovered.iter().any(|group| &group.group_id == name) {
                out.warnings.push(format!(
                    "白名单里的组 `{name}` 本轮未发现（拼写错？该组还没创建？或协调它的 broker 没连上）"
                ));
            }
        }
    }
    discovered.sort_by(|a, b| a.group_id.cmp(&b.group_id));
    discovered.dedup_by(|a, b| a.group_id == b.group_id);
    if discovered.len() > policy.max_groups {
        out.dropped_groups = discovered.len() - policy.max_groups;
        discovered.truncate(policy.max_groups);
    }

    // 3. 逐组：状态 + 提交位点 + LEO。
    //
    // 整体预算：规范 §6 要求单轮 < 20s。大集群（几百个组 × 每 leader 一次请求）很容易超，
    // 超了只停采集，不拖死探测线程（拖死会让拓扑面也停更）。
    //
    // LEO 是**分区级**读数，与组无关：一轮里所有组共用同一份快照。
    // 不缓存的话请求数是 `组数 × leader 数`（200 个组 × 30 个 leader = 6000 次）；
    // 缓存后是 `leader 数`，而且同一轮的 lag 之间可比（不同时刻的 LEO 会让
    // 「谁更落后」失真）。`unresolved` 记已确认拿不到的分区，避免每个组重试一次。
    let mut end_offsets: EndOffsets = BTreeMap::new();
    let mut unresolved: BTreeSet<(String, i32)> = BTreeSet::new();
    // 逐组告警先聚合，最后一次性拼成行（大集群里几百个组同一种故障只占一行）。
    let mut group_warnings = GroupWarnings::default();
    let deadline = std::time::Instant::now() + GROUP_BUDGET;
    for (index, group) in discovered.iter().enumerate() {
        if std::time::Instant::now() >= deadline {
            out.warnings.push(format!(
                "本轮消费组采集超过 {}s，后 {} 个组本轮未采（可调小 max_groups 或加大 lag_interval_ms）",
                GROUP_BUDGET.as_secs(),
                discovered.len() - index
            ));
            break;
        }
        let Some(broker) = brokers.get(&group.broker).copied() else {
            group_warnings.failure(
                format!(
                    "的协调者 broker {} 不在 metadata 里（组可能正在迁移）",
                    group.broker
                ),
                &group.group_id,
            );
            continue;
        };

        let described = {
            let Some(conn) = links.conn(broker) else {
                continue;
            };
            describe_group(conn, &group.group_id)
        };
        let state = match described {
            Ok(state) => state,
            Err(err) => {
                links.drop_conn(group.broker);
                group_warnings.failure(format!("DescribeGroups 失败：{err}"), &group.group_id);
                continue;
            }
        };
        // 状态是枚举一热：**所有查到的组**都发（受 max_groups 约束），
        // 不然「rebalancing 但还没积压」这种状态就永远看不见。
        out.facts.push(labeled(
            FACT_STATE,
            state,
            &[("group", group.group_id.as_str())],
        ));

        let fetched = {
            let Some(conn) = links.conn(broker) else {
                continue;
            };
            fetch_committed(conn, &group.group_id)
        };
        let (committed, offset_failures) = match fetched {
            Ok(result) => result,
            Err(err) => {
                links.drop_conn(group.broker);
                group_warnings.failure(format!("OffsetFetch 失败：{err}"), &group.group_id);
                continue;
            }
        };
        if offset_failures > 0 {
            group_warnings.partitions(
                "位点读取失败（lag 会偏低）",
                &group.group_id,
                offset_failures,
            );
        }
        if committed.is_empty() {
            continue;
        }

        let needed: Vec<Committed> = committed
            .iter()
            .filter(|entry| {
                let key = (entry.topic.clone(), entry.partition);
                !end_offsets.contains_key(&key) && !unresolved.contains(&key)
            })
            .cloned()
            .collect();
        if !needed.is_empty() {
            let fetched = collect_end_offsets(&mut links, &brokers, &leaders, &needed);
            for entry in &needed {
                let key = (entry.topic.clone(), entry.partition);
                match fetched.get(&key) {
                    Some(offset) => {
                        end_offsets.insert(key, *offset);
                    }
                    // leader 不在 metadata / 分区级错误 / 请求失败：记下来，本轮不再试。
                    None => {
                        unresolved.insert(key);
                    }
                }
            }
        }

        let mut missing = 0usize;
        for entry in &committed {
            if !end_offsets.contains_key(&(entry.topic.clone(), entry.partition)) {
                missing += 1;
            }
        }
        if missing > 0 {
            group_warnings.partitions(
                "拿不到 log end offset（lag 会偏低）",
                &group.group_id,
                missing,
            );
        }

        let mut per_topic: BTreeMap<&str, i64> = BTreeMap::new();
        for entry in &committed {
            let Some(end) = end_offsets.get(&(entry.topic.clone(), entry.partition)) else {
                continue;
            };
            // 负 lag 按 0：见模块注释。
            let lag = (end - entry.offset).max(0);
            *per_topic.entry(entry.topic.as_str()).or_insert(0) += lag;
        }

        // 白名单非空 → 只看白名单；为空 → 只看超过阈值的组（规范 §5）。
        let emit = if policy.allowlist.is_empty() {
            let total: i64 = per_topic.values().copied().sum();
            total > policy.lag_threshold
        } else {
            policy
                .allowlist
                .iter()
                .any(|candidate| candidate == &group.group_id)
        };
        if !emit {
            continue;
        }
        for (topic, lag) in per_topic {
            out.facts.push(labeled(
                FACT_LAG,
                &lag.to_string(),
                &[("group", group.group_id.as_str()), ("topic", topic)],
            ));
        }
    }

    out.facts.sort_by(|a, b| {
        a.key
            .cmp(&b.key)
            .then_with(|| label_of(a, "group").cmp(label_of(b, "group")))
            .then_with(|| label_of(a, "topic").cmp(label_of(b, "topic")))
    });
    out.warnings.extend(group_warnings.finish());
    out.warnings.extend(links.warnings);
    out
}

fn label_of<'a>(fact: &'a MetricsLabeledFact, key: &str) -> &'a str {
    fact.labels
        .iter()
        .find(|label| label.key == key)
        .map(|label| label.value.as_str())
        .unwrap_or("")
}

fn labeled(key: &str, value: &str, labels: &[(&str, &str)]) -> MetricsLabeledFact {
    MetricsLabeledFact {
        key: key.to_string(),
        value: value.to_string(),
        labels: labels
            .iter()
            .map(|(label, value)| StringKeyValue::new(*label, *value))
            .collect(),
    }
}

/// 逐 broker 复用的连接池 + 告警去重。
///
/// 一个组至少有 2 次调用（DescribeGroups / OffsetFetch）+ 每个 leader 1 次，
/// 每组都重连一次会把「ApiVersions + SASL」的成本放大几十倍。
struct Links<'a> {
    security: &'a SecurityConfig<'a>,
    timeout: Duration,
    conns: BTreeMap<i32, Connection>,
    /// 连不上的 broker：同轮不再重试（超时是链式放大的大头）。
    dead: BTreeSet<i32>,
    warned: BTreeSet<String>,
    warnings: Vec<String>,
}

impl<'a> Links<'a> {
    fn new(security: &'a SecurityConfig<'a>, timeout: Duration) -> Self {
        Self {
            security,
            timeout,
            conns: BTreeMap::new(),
            dead: BTreeSet::new(),
            warned: BTreeSet::new(),
            warnings: Vec::new(),
        }
    }

    fn conn(&mut self, broker: &Broker) -> Option<&mut Connection> {
        let node_id = broker.node_id;
        if self.dead.contains(&node_id) {
            return None;
        }
        if !self.conns.contains_key(&node_id) {
            let addr = format!("{}:{}", broker.host, broker.port);
            match kafka_auth::connect(&addr, self.security, self.timeout) {
                Ok(conn) => {
                    self.conns.insert(node_id, conn);
                }
                Err(err) => {
                    self.dead.insert(node_id);
                    self.warnings
                        .push(format!("broker {node_id} ({addr}) 连接失败：{err}"));
                    return None;
                }
            }
        }
        self.conns.get_mut(&node_id)
    }

    /// 同一个 API 在多家 broker 上不可用时，只留一条（版本协商是集群级的）。
    fn warn_once(&mut self, key: &str, message: String) {
        if self.warned.insert(key.to_string()) {
            self.warnings.push(message);
        }
    }

    /// 请求失败后丢弃这条连接。
    ///
    /// broker 遇到解析不了 / 不允许的请求会直接关闭连接，而这条连接是**缓存**的：
    /// 不丢它，后面每个组都会在一条死连接上失败，一个报文错误就变成「全部组都没有数据」。
    fn drop_conn(&mut self, node_id: i32) {
        self.conns.remove(&node_id);
    }
}

/// 每个 leader broker 一次 `ListOffsets`，把 `(topic, partition) → LEO` 收齐。
///
/// 只返回**拿到了的**读数：缺席的分区由调用方记入 `unresolved`（本轮不再重试），
/// 并反映为「lag 偏低」的告警 —— 不能把缺席当成 0。
fn collect_end_offsets(
    links: &mut Links<'_>,
    brokers: &BTreeMap<i32, &Broker>,
    leaders: &BTreeMap<(String, i32), i32>,
    committed: &[Committed],
) -> EndOffsets {
    // 只查组真正提交过位点的分区：metadata 里可能有上千个分区，全查是浪费。
    let mut by_broker: BTreeMap<i32, Vec<(String, i32)>> = BTreeMap::new();
    for entry in committed {
        // 分区不在 metadata 里（已删除）或没有 leader（离线）：拿不到是事实，不是错误。
        if let Some(leader) = leaders.get(&(entry.topic.clone(), entry.partition))
            && *leader >= 0
        {
            by_broker
                .entry(*leader)
                .or_default()
                .push((entry.topic.clone(), entry.partition));
        }
    }

    let mut out = BTreeMap::new();
    for (node_id, requested) in by_broker {
        let Some(broker) = brokers.get(&node_id).copied() else {
            links.warn_once(
                &format!("leader-missing-{node_id}"),
                format!("分区 leader broker {node_id} 不在 metadata 里，本轮这些分区的 lag 偏低"),
            );
            continue;
        };
        let fetched = {
            let Some(conn) = links.conn(broker) else {
                continue;
            };
            list_offsets(conn, &requested)
        };
        match fetched {
            Ok((offsets, _failed)) => {
                // 分区级 error_code（元数据过期 / NOT_LEADER / 无权限）不在 `offsets` 里；
                // 调用方会把它归入 unresolved，并计入「lag 偏低」。
                out.extend(offsets);
            }
            Err(err) => {
                links.drop_conn(node_id);
                links.warn_once(
                    &format!("list-offsets-{node_id}"),
                    format!(
                        "broker {node_id} ({}:{}) ListOffsets 失败：{err}",
                        broker.host, broker.port
                    ),
                );
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 请求编码（全部使用协商出的 non-flexible 版本）
// ---------------------------------------------------------------------------

fn frame(body: Vec<u8>) -> Vec<u8> {
    let mut frame = Vec::with_capacity(body.len() + 4);
    frame.extend_from_slice(&(body.len() as i32).to_be_bytes());
    frame.extend_from_slice(&body);
    frame
}

/// 请求头（v1）：api_key / version / correlation_id / client_id。
fn header(api_key: i16, version: i16, correlation_id: i32, client_id: &str) -> Vec<u8> {
    let mut body = Vec::with_capacity(10 + client_id.len());
    body.extend_from_slice(&api_key.to_be_bytes());
    body.extend_from_slice(&version.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    body
}

fn push_string(body: &mut Vec<u8>, value: &str) {
    body.extend_from_slice(&(value.len() as i16).to_be_bytes());
    body.extend_from_slice(value.as_bytes());
}

/// `ListGroups` v0-v2：请求体为空（v3+ 才有 `states_filter`，且是 flexible）。
pub fn encode_list_groups_request(correlation_id: i32, client_id: &str, version: i16) -> Vec<u8> {
    frame(header(
        API_KEY_LIST_GROUPS,
        version,
        correlation_id,
        client_id,
    ))
}

/// `DescribeGroups` v0-v4：`groups: [string]`（v3+ 还有一个 `include_authorized_operations`）。
pub fn encode_describe_groups_request(
    correlation_id: i32,
    client_id: &str,
    version: i16,
    groups: &[&str],
) -> Vec<u8> {
    let mut body = header(API_KEY_DESCRIBE_GROUPS, version, correlation_id, client_id);
    body.extend_from_slice(&(groups.len() as i32).to_be_bytes());
    for group in groups {
        push_string(&mut body, group);
    }
    if version >= 3 {
        // 漏了这个 bool，broker 解析请求时会因「字节不够」直接断开连接。
        body.push(0); // include_authorized_operations = false
    }
    frame(body)
}

/// `OffsetFetch` v2-v5：`topics = null`（= 该组提交过的全部分区）。
pub fn encode_offset_fetch_request(
    correlation_id: i32,
    client_id: &str,
    version: i16,
    group_id: &str,
) -> Vec<u8> {
    let mut body = header(API_KEY_OFFSET_FETCH, version, correlation_id, client_id);
    push_string(&mut body, group_id);
    body.extend_from_slice(&(-1i32).to_be_bytes());
    frame(body)
}

/// `ListOffsets` v1-v5：`timestamp = -1` 取 log end offset。
pub fn encode_list_offsets_request(
    correlation_id: i32,
    client_id: &str,
    version: i16,
    partitions: &[(String, i32)],
) -> Vec<u8> {
    let mut by_topic: BTreeMap<&str, Vec<i32>> = BTreeMap::new();
    for (topic, partition) in partitions {
        by_topic.entry(topic.as_str()).or_default().push(*partition);
    }

    let mut body = header(API_KEY_LIST_OFFSETS, version, correlation_id, client_id);
    body.extend_from_slice(&(-1i32).to_be_bytes()); // replica_id = -1（普通客户端）
    if version >= 2 {
        body.push(0); // isolation_level = READ_UNCOMMITTED（与 kafka-consumer-groups 一致）
    }
    body.extend_from_slice(&(by_topic.len() as i32).to_be_bytes());
    for (topic, mut partitions) in by_topic {
        // 分区号排序：同一个中间态每轮请求字节一致，报文可以拿来对比。
        partitions.sort_unstable();
        push_string(&mut body, topic);
        body.extend_from_slice(&(partitions.len() as i32).to_be_bytes());
        for partition in partitions {
            body.extend_from_slice(&partition.to_be_bytes());
            if version >= 4 {
                body.extend_from_slice(&(-1i32).to_be_bytes()); // current_leader_epoch = 未知
            }
            body.extend_from_slice(&(-1i64).to_be_bytes()); // timestamp = -1 → LEO
        }
    }
    frame(body)
}

// ---------------------------------------------------------------------------
// 响应解析
// ---------------------------------------------------------------------------

fn correlation(reader: &mut Reader<'_>, expected: i32) -> io::Result<()> {
    let got = reader.i32()?;
    if got != expected {
        return Err(kafka::invalid(format!(
            "unexpected correlation id {got} (expected {expected})"
        )));
    }
    Ok(())
}

/// `ListGroups` v0-v2 响应：`(v1+) throttle` / `error_code` / `groups[{group_id, protocol_type}]`。
pub fn parse_list_groups(
    response: &[u8],
    correlation_id: i32,
    version: i16,
) -> io::Result<Vec<(String, String)>> {
    let mut reader = Reader::new(response);
    correlation(&mut reader, correlation_id)?;
    if version >= 1 {
        let _throttle = reader.i32()?;
    }
    let error_code = reader.i16()?;
    if error_code != 0 {
        return Err(kafka::invalid(format!(
            "ListGroups error_code {error_code}"
        )));
    }
    let len = reader.array_len()?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let group_id = reader.string()?;
        let protocol_type = reader.string()?;
        out.push((group_id, protocol_type));
    }
    Ok(out)
}

/// `DescribeGroups` v0-v4 响应：只读到 `group_state`（后面是 members，lag 用不上）。
pub fn parse_describe_groups(
    response: &[u8],
    correlation_id: i32,
    version: i16,
) -> io::Result<Vec<(String, String, i16)>> {
    let mut reader = Reader::new(response);
    correlation(&mut reader, correlation_id)?;
    if version >= 1 {
        let _throttle = reader.i32()?;
    }
    let len = reader.array_len()?;
    let mut out = Vec::with_capacity(len);
    for _ in 0..len {
        let error_code = reader.i16()?;
        let group_id = reader.string()?;
        let state = reader.string()?;
        out.push((group_id, state, error_code));
    }
    Ok(out)
}

/// `OffsetFetch` v2-v5 响应：`(v3+) throttle` / `topics[{name, partitions[…]}]` / 顶层 `error_code`。
///
/// 返回 `(可用位点, 分区级失败数)`：后者包含 `error_code != 0` 的分区，
/// 它会让 lag 偏低，必须让上层能说清楚。
pub fn parse_offset_fetch(
    response: &[u8],
    correlation_id: i32,
    version: i16,
) -> io::Result<CommittedReadings> {
    let mut reader = Reader::new(response);
    correlation(&mut reader, correlation_id)?;
    if version >= 3 {
        let _throttle = reader.i32()?;
    }
    let topics = reader.array_len()?;
    let mut out = Vec::new();
    let mut failed = 0usize;
    for _ in 0..topics {
        let topic = reader.string()?;
        let partitions = reader.array_len()?;
        for _ in 0..partitions {
            let partition = reader.i32()?;
            let offset = reader.i64()?;
            if version >= 5 {
                let _leader_epoch = reader.i32()?;
            }
            let _metadata = reader.string()?;
            let error_code = reader.i16()?;
            if error_code != 0 {
                failed += 1;
            } else if offset >= 0 {
                // -1 = 该分区没有提交位点：不算失败，也不进求和
                // （算进去会得到「整个 topic 都是积压」的假象）。
                out.push(Committed {
                    topic: topic.clone(),
                    partition,
                    offset,
                });
            }
        }
    }
    // v2-v7 有顶层 error_code（组级：NOT_COORDINATOR / GROUP_AUTHORIZATION_FAILED…）。
    if (2..=7).contains(&version) {
        let error_code = reader.i16()?;
        if error_code != 0 {
            return Err(kafka::invalid(format!(
                "OffsetFetch 顶层 error_code {error_code}（组不存在 / 无权限 / 协调者已迁移）"
            )));
        }
    }
    Ok((out, failed))
}

/// `ListOffsets` v1-v5 响应：`(v2+) throttle` / `topics[{name, partitions[{index, error, ts, offset}]}]`。
///
/// 返回 `(可用读数, 分区级失败数)`：`error_code != 0`（`NOT_LEADER` / 元数据过期 /
/// 无权限）的分区不能静默丢掉 —— 丢掉就是「lag 看起来正常」，而那正是我们要预警的事。
pub fn parse_list_offsets(
    response: &[u8],
    correlation_id: i32,
    version: i16,
) -> io::Result<EndOffsetReadings> {
    let mut reader = Reader::new(response);
    correlation(&mut reader, correlation_id)?;
    if version >= 2 {
        let _throttle = reader.i32()?;
    }
    let topics = reader.array_len()?;
    let mut out = Vec::new();
    let mut failed = 0usize;
    for _ in 0..topics {
        let topic = reader.string()?;
        let partitions = reader.array_len()?;
        for _ in 0..partitions {
            let partition = reader.i32()?;
            let error_code = reader.i16()?;
            let _timestamp = reader.i64()?;
            let offset = reader.i64()?;
            if version >= 4 {
                let _leader_epoch = reader.i32()?;
            }
            if error_code != 0 || offset < 0 {
                failed += 1;
            } else {
                out.push(((topic.clone(), partition), offset));
            }
        }
    }
    Ok((out, failed))
}

/// 组状态 → 指标 label 取值（规范 §5：`stable` / `rebalancing` / `dead` / `empty`）。
pub fn group_state(raw: &str) -> &'static str {
    match raw {
        "Stable" => "stable",
        "Empty" => "empty",
        "Dead" => "dead",
        "PreparingRebalance" | "CompletingRebalance" => "rebalancing",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// 单次调用（用协商出的版本发请求 + 解析）
// ---------------------------------------------------------------------------

fn unavailable(name: &str, reason: String) -> io::Error {
    kafka::invalid(format!("broker 不支持 {name}：{reason}"))
}

fn list_groups(conn: &mut Connection) -> io::Result<Vec<(String, String)>> {
    let Some(version) = conn.versions.list_groups.version else {
        return Err(unavailable(
            "ListGroups",
            conn.versions.list_groups.unavailable_reason("ListGroups"),
        ));
    };
    let payload = encode_list_groups_request(CORRELATION_LIST_GROUPS, CLIENT_ID, version);
    let response = kafka_auth::exchange(&mut *conn.stream, &payload)?;
    parse_list_groups(&response, CORRELATION_LIST_GROUPS, version)
}

fn describe_group(conn: &mut Connection, group_id: &str) -> io::Result<&'static str> {
    let Some(version) = conn.versions.describe_groups.version else {
        return Err(unavailable(
            "DescribeGroups",
            conn.versions
                .describe_groups
                .unavailable_reason("DescribeGroups"),
        ));
    };
    let payload = encode_describe_groups_request(
        CORRELATION_DESCRIBE_GROUPS,
        CLIENT_ID,
        version,
        &[group_id],
    );
    let response = kafka_auth::exchange(&mut *conn.stream, &payload)?;
    let groups = parse_describe_groups(&response, CORRELATION_DESCRIBE_GROUPS, version)?;
    let (returned, state, error_code) = groups
        .into_iter()
        .next()
        .ok_or_else(|| kafka::invalid("DescribeGroups 没有返回这个组".to_string()))?;
    if returned != group_id {
        // 回的是别的组：拿它的状态会张冠李戴，宁可报错。
        // 这里**不写请求的组名**（warning 行首已经带了），否则每组的错误文本都不同，
        // 按原因聚合会失效（几百个组就又是几百行）。
        return Err(kafka::invalid(format!(
            "DescribeGroups 返回的组是 {returned}（不是请求的组）"
        )));
    }
    if error_code != 0 {
        return Err(kafka::invalid(format!(
            "DescribeGroups error_code {error_code}（组不存在 / 无权限）"
        )));
    }
    Ok(group_state(&state))
}

fn fetch_committed(conn: &mut Connection, group_id: &str) -> io::Result<CommittedReadings> {
    let Some(version) = conn.versions.offset_fetch.version else {
        return Err(unavailable(
            "OffsetFetch",
            conn.versions.offset_fetch.unavailable_reason("OffsetFetch"),
        ));
    };
    let payload =
        encode_offset_fetch_request(CORRELATION_OFFSET_FETCH, CLIENT_ID, version, group_id);
    let response = kafka_auth::exchange(&mut *conn.stream, &payload)?;
    parse_offset_fetch(&response, CORRELATION_OFFSET_FETCH, version)
}

fn list_offsets(
    conn: &mut Connection,
    partitions: &[(String, i32)],
) -> io::Result<EndOffsetReadings> {
    let Some(version) = conn.versions.list_offsets.version else {
        return Err(unavailable(
            "ListOffsets",
            conn.versions.list_offsets.unavailable_reason("ListOffsets"),
        ));
    };
    let payload =
        encode_list_offsets_request(CORRELATION_LIST_OFFSETS, CLIENT_ID, version, partitions);
    let response = kafka_auth::exchange(&mut *conn.stream, &payload)?;
    parse_list_offsets(&response, CORRELATION_LIST_OFFSETS, version)
}

#[cfg(test)]
mod tests;
