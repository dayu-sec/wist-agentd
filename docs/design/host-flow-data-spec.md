# 主机流记录上行格式（`wist.host_flow/v1`）

本文定义 **agentd → 数据面** 这条链路上"一条流记录长什么样、怎么装在帧里"。
实现方（数据面 WPL/OML、平台解析、网关看板）只应依赖本文与
[`host-ebpf-flow-collection.md`](./host-ebpf-flow-collection.md) §6 的字段表。

两份文档的分工（**改字段时两处一起改**）：

| 文档 | 负责 |
|---|---|
| 本文 | 线上**字节格式**：分帧、帧标记、信封、正文编码规则、出现规则、闭集、幂等键、校验清单 |
| [设计文档](./host-ebpf-flow-collection.md) | **为什么是这些字段/为什么没有那些字段**、采集语义、覆盖与缺口、非目标 |

字段类型定义只有一处：`wist_contracts::host_flow::HostFlowRecord`（`wist-contracts`）。
agentd 只负责构造与序列化，不重建形状。

---

## 0. 版本与兼容

| 项 | 规则 |
|---|---|
| 版本闸门 | 正文自带 `record_schema = "wist.host_flow/v1"`。**加字段 / 改语义 = 升 `v2`**，不悄悄改 v1 |
| 未知键 | 正文是 `deny_unknown_fields` 的：多一个键就是契约被改了（或拼错），消费端应当**当场失败**，而不是继续读 |
| 信封 | 信封是**加性**的：新键必须是可选且"为空时不出现"，否则旧读取方（`deny_unknown_fields`）会整份拒收 |
| 消费者 | 数据面只按帧标记分派 + 保留 `body` 原文，不建模；富化与判定在平台（设计文档 §4） |

## 1. 范围

- **产出**：`wist-agentd` 的 tc/eBPF 采集器（Linux，root）。非 Linux / 未编入 BPF 对象时为 `unsupported`，不产帧。
- **一条记录** = 一个 60s 窗口内、某一方向、一个五元组（+ ICMP type/code）的聚合量。
- **不含**：进程/socket 归属、原始报文、云侧身份（VPC/ENI/instance）、放行/拒绝判定（`action`）。

## 2. 线上帧

### 2.1 分帧：`len`

上送链路（TCP）**固定**用长度前缀分帧，配置里的 `line` 只兼容旧配置并在启动时提示一次
（`SinkIdentity::resolve`）。

```text
<十进制字节数><一个空格><帧字节>
```

- 长度是**帧的字节数**（UTF-8 编码后），**不含**长度前缀自身，也不含任何换行；
- 接收端按长度切帧；半帧（连接中途断掉）长度凑不齐，天然可丢弃；
- **不写 `\n`**：不要按行切。`line` 分帧（`{帧}\n`）只用于测试与旧配置兼容。

### 2.2 帧 = 信封 + 标记 + 正文

```text
{信封 JSON} FLOW: {正文 JSON}
```

- 标记是 **7 个 ASCII 字节**：`空格` `F` `L` `O` `W` `:` `空格` —— 两侧各一个空格，不可省、不可换成制表符；
- 信封与正文**字节原样拼接**，中间除标记外无任何字符；
- 一条记录一帧，正文内部不含换行（紧凑 JSON）；
- 正文不转义、不 base64：数据面可以直接 `json(...)` 解，也可以只保留原文；
- **只有数据面 TCP sink 承载**：本地 `file` 输出静默跳过（`file` 只承载日志），
  此时采集器不启动并在 `collection-status` 里报 `target_not_ready`（授权了但没处送，必须可见）。

### 2.3 信封

流记录复用 agent 级数据帧信封（`wist_contracts::telemetry_record::DataFrame`）。
流记录**只会出现这四个键**（其余可选键为空即不出现）：

| 键 | 类型 | 值 |
|---|---|---|
| `schema` | string | 固定 `"v1"` |
| `agent` | string | `agent_id`（与正文 `collector_instance_id` 同源） |
| `ts` | string | **上送时刻**，RFC 3339 UTC；带非零亚秒时按纳秒精度输出小数（如 `2026-11-28T04:16:42.123456789Z`）。**不是**窗口时间 |
| `seq` | number | agent 级全局单调序号（uint64），见 §2.4 |

> `ts` 只回答"什么时候发的"；窗口时间看正文 `start` / `end`。按 `ts` 做窗口聚合是错的。

### 2.4 `seq` 语义

- **agent 级全局**：与 ` LOGRAW: ` / ` METRICS: ` / ` OBSFACT: ` 等共用同一个计数器
  （`state/logs/seq.json`），所以 `(agent, seq)` 跨帧类型唯一；
- 取号 → **先持久化高水位** → 再发送：崩溃只浪费号，**绝不回退撞号**；
- 消费端用 `(agent, seq)` 去重/查缺；缺口可能来自崩溃（正常，见上）或投递失败（一条记录只发一次，不重发）。

### 2.5 同批发送与顺序

- 一拍最多上送 **4096** 条（`MAX_FLOWS_PER_FLUSH`），其余桶留在 BPF 表里下一拍照着取（最老的先走）；
- 同一批内按 flush 顺序发送，`seq` 单调递增；**跨窗口不保证全局有序**（并发窗口可在同一拍一起 flush）；
- 平台按正文 `start` 归窗，不要依赖到达顺序。

## 3. 正文编码规则

这些规则是**契约的一部分**（不是实现细节），改它们等于改 `record_schema`：

| 项 | 规则 | 理由 / 反例 |
|---|---|---|
| JSON 形态 | 紧凑（无多余空白）、键名 `snake_case`、UTF-8 | 数据面按原文保留，体积敏感 |
| 全部键 | 只允许设计文档 §6 列出的键 | `deny_unknown_fields` |
| **数值 vs 字符串** | 计数/时间/端口号之外的量一律 JSON number；**只有** `protocol` / `srcport` / `dstport` / `icmp_type` / `icmp_code` 是字符串 | 与云侧词表一致，下游不必为"有的源是数字有的是字符串"写两次转换 |
| **缺失 vs 0** | 取不到就用**键不出现**表达，**绝不**写 `null`，也不写 0 冒充 | `wire_bytes` 缺失 ≠ 0 字节；`partial` 缺失 ≠ 未截断为假 |
| 可选布尔 | 只在为 `true` 时出现（`port_unavailable`、`partial`），**从不出现 `false`** | 出现 `false` 会让"缺失"与"明确不成立"混淆 |
| 数组 | `local_addrs` 恒出现，可为 `[]`，绝不为 `null` | 空数组表示"这张网卡当时没有可路由地址" |
| IP 文本 | v4 点分十进制；v6 用 RFC 5952 压缩小写（`fd00::14`，不是 `FD00:0:0::14`） | 幂等键里含地址字符串，格式不一致 = 同一会话两条记录 |
| 端口 | 十进制、无前导零；ICMP 或取不到时为 `"0"` | 与云侧口径一致 |
| 时间 | Unix **秒**（整数，无毫秒）；窗口是**半开区间** `[start, end)` | `end - start == window_seconds` |
| 窗口对齐 | `start` 对齐 UTC 整分（`start % 60 == 0`） | 桶换算见设计文档 §7.3；`partial` 时长度变短但仍整分对齐 |
| 协议号 | IANA 数字的**十进制字符串**：`"6"` TCP / `"17"` UDP / `"1"` ICMP / `"58"` ICMPv6 | 只采这四种，其它协议不产记录 |

## 4. 字段出现规则

字段清单与含义见设计文档 §6。这里只补"什么时候出现"这张表（实现时必须逐条成立）：

| 字段 | 何时出现 |
|---|---|
| 全部除下表之外 | **恒出现** |
| `host_name` | 只有拿到主机名时 |
| `if_mac` | 只有读得到网卡 MAC 时 |
| `icmp_type` / `icmp_code` | **仅** `protocol ∈ {"1","58"}`；TCP/UDP 不出现这两个键 |
| `port_unavailable` | 分片 / v6 扩展头导致端口取不到时（值为 `true`）；此时端口为 `"0"` |
| `wire_bytes` | **当前恒不出现**：基线内核（5.4+）没有 `skb->wire_len`，不估算、不伪造精度 |
| `skb_count` / `gso_skb_count` | 当前恒出现（诊断用）；契约上可选 |
| `partial` / `partial_reason` | 窗口被提前截断时成对出现；`partial_reason` ∈ §5 的闭集 |

## 5. 闭集常量

任何一项新增都是契约变更；消费端对未知值应当**忽略该维度**而不是崩溃。

| 字段 | 取值 | 含义 |
|---|---|---|
| `record_schema` | `wist.host_flow/v1` | 记录版本 |
| `source` | `host_ebpf` | 观测来源（主机侧 eBPF）。下游据此与云侧流日志**择一**使用，不相加 |
| `coverage` | `host_partial` | 主机视角有缺口（见 §7.1） |
| `capture` | `tc_egress` / `tc_ingress` | hook 位置；与 `direction` 一一对应 |
| `direction` | `in` / `out` | **相对被观测网卡**；用云侧词表，不是 `ingress`/`egress` |
| `protocol` | `6` / `17` / `1` / `58` | IANA 协议号 |
| `wire_bytes_source` | `wire_len` / `unavailable` | `wire_bytes` 的来源；当前恒为 `unavailable` |
| `partial_reason` | `agent_start` / `paused` / `interface_changed` / `shutdown` / `clock_changed` | 窗口为什么被截断 |

## 6. 幂等键

平台侧去重与 upsert 的唯一键：

```text
(collector_instance_id, ifname, direction, protocol,
 srcaddr, srcport, dstaddr, dstport, icmp_type, icmp_code, start)
```

- **不含** `seq`（`seq` 是传输层的去重/查缺键，重发同一条记录时 `seq` 会变、业务键不会）；
- **不含** `end` / `window_seconds`（它们由 `start` + 是否 `partial` 决定）；
- 含 **`icmp_type`/`icmp_code`**：echo 与 unreachable 相加没有意义，不同类型不能落进同一条记录；
- 含 `ifname` **与** `ifindex` 中的 `ifname`：接口重建后 `ifindex` 可能复用，用 `ifname` 更稳；
  记录里仍带 `ifindex` 供现场对账。

## 7. 采集口径对数据的影响（读数据的人必须知道）

### 7.1 只含「一端是公网」的流量（0.46.0+）

| 场景 | `src` | `dst` | 是否上送 |
|---|---|---|---|
| 本机主动连公网 | 私网 | 公网 | 是 |
| 公网连进来 / 公网回包 | 公网 | 私网 | 是 |
| 本机有公网 IP，公网直连 | 公网 | 公网 | 是 |
| 内网东西向（k8s / service mesh / 同 VPC） | 私网 | 私网 | **否**（设计如此，不是丢数据） |

由此：

- 一台只跑东西向的机器会**持续零记录**，这是 `success`，不是故障；
- 与云侧 VPC 流日志对账时，**先按对端是否为公网过滤云侧记录**再比；
- 本机被口径丢弃的包数只进本机诊断（`state/flows/status.json` 的 `filtered`，
  以及 `agentd diagnose` 的 `flows.status`），**不上行**。

### 7.2 `coverage = host_partial` 覆盖的两类缺口

1. **看不到**在到达网卡之前就被云侧策略丢弃的流量（主机侧无从观测）；
2. **按口径不采**东西向（§7.1）。

两者都在"记录缺失"里，但原因不同：前者要归因到云侧策略，后者是设计口径。

### 7.3 缺口字段怎么读

| 字段 | 读法 |
|---|---|
| `truncated=true` | 本窗口聚合表被 LRU 淘汰过，量偏小 —— 这一窗**不能**当完整数据 |
| `dropped>0` | 本窗口有事件没计入（表满 / 读表竞态 / 迟到落进已 flush 窗口）；**不补发** |
| `partial=true` + `partial_reason` | 窗口被截断（重启 / 暂停 / 换网卡 / 关机 / 墙钟跳变），`window_seconds` 是实际秒数 |
| 零记录 | 窗口内没有符合口径的流量 —— 正常态 |

## 8. 完整示例

### 8.1 TCP 出向（一条记录 + 真实分帧）

线上字节（`len` 分帧，长度是帧字节数；为可读这里断行，实际是一整段字节）：

```text
718 {"schema":"v1","agent":"agent-host-d97e23da6111","ts":"2026-11-28T04:16:42Z","seq":100231} FLOW: {"record_schema":"wist.host_flow/v1","source":"host_ebpf","coverage":"host_partial","capture":"tc_egress","collector_instance_id":"agent-host-d97e23da6111","host_id":"host-d97e23da6111","host_name":"vm-web-01","kernel":"5.15.0-91-generic","ifname":"eth0","ifindex":2,"if_mac":"52:54:00:aa:bb:cc","local_addrs":["10.118.0.14"],"direction":"out","protocol":"6","srcaddr":"10.118.0.14","dstaddr":"88.214.25.121","srcport":"50123","dstport":"443","start":1789470120,"end":1789470180,"window_seconds":60,"packets":13,"bytes":1460,"wire_bytes_source":"unavailable","skb_count":4,"gso_skb_count":1,"truncated":false,"dropped":0}
```

要点：`ts` 是上送时刻（`04:16:42`），窗口是 `1789470120`（整分对齐）；
`protocol`/`srcport`/`dstport` 是字符串；`wire_bytes` 整键不出现；`partial` 不出现（= 未截断）。

### 8.2 ICMP（正文，省略信封）

```json
{"record_schema":"wist.host_flow/v1","source":"host_ebpf","coverage":"host_partial","capture":"tc_egress","collector_instance_id":"agent-host-d97e23da6111","host_id":"host-d97e23da6111","kernel":"5.15.0-91-generic","ifname":"eth0","ifindex":2,"local_addrs":["10.118.0.14"],"direction":"out","protocol":"1","srcaddr":"10.118.0.14","dstaddr":"10.118.0.1","srcport":"0","dstport":"0","icmp_type":"8","icmp_code":"0","start":1789470120,"end":1789470180,"window_seconds":60,"packets":3,"bytes":252,"wire_bytes_source":"unavailable","skb_count":3,"gso_skb_count":0,"truncated":false,"dropped":0}
```

### 8.3 被截断的窗口（暂停后恢复，正文，省略信封）

```json
{"record_schema":"wist.host_flow/v1","source":"host_ebpf","coverage":"host_partial","capture":"tc_ingress","collector_instance_id":"agent-host-d97e23da6111","host_id":"host-d97e23da6111","kernel":"5.15.0-91-generic","ifname":"eth0","ifindex":2,"local_addrs":["10.118.0.14"],"direction":"in","protocol":"17","srcaddr":"88.214.25.121","dstaddr":"10.118.0.14","srcport":"443","dstport":"51000","start":1789470120,"end":1789470145,"window_seconds":25,"packets":7,"bytes":980,"wire_bytes_source":"unavailable","truncated":false,"dropped":0,"partial":true,"partial_reason":"paused"}
```

## 9. 校验清单（实现方断言）

数据面 / 平台解析落地时，这些应当有测试或断言，而不是靠 review：

- [ ] 帧能被 `<len><空格>` 切出来，且 `len == 帧字节数`；
- [ ] 帧里恰好一处 ` FLOW: `（两侧各一空格），信封只含 `schema`/`agent`/`ts`/`seq`；
- [ ] 正文能反序列化成 `HostFlowRecord`（`deny_unknown_fields` 生效：多键即失败）；
- [ ] 未知的 `partial_reason` / `capture` / `coverage` 不让解析崩溃；
- [ ] 幂等键（§6）重复 upsert 不产生两条；
- [ ] `end - start == window_seconds`，且 `start % 60 == 0`；
- [ ] 端口为 `"0"` 时：要么 `protocol ∈ {1,58}`，要么 `port_unavailable=true`；
- [ ] `wire_bytes` 不出现时 `wire_bytes_source == "unavailable"`；
- [ ] 拒绝类视图在只有主机来源时显示"不覆盖"，不是 0（设计文档 §3 硬规则 2）。

## 10. 下一步（未定）

- `coverage` 目前表达不了"东西向按口径不采"（§7.2 第 2 类）。计划随 `wist-contracts`
  下一版新增取值（如 `host_public_peer`）并同步四侧渲染 —— 见设计文档 §13 #12；
- 采集范围若要按站点/主机下发，走平台策略通道（设计文档 §13 #10），届时**记录格式不变**，
  只是"哪些流量会进来"变了。
