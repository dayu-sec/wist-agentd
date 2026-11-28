# 主机流记录（eBPF）采集设计

> 状态：**slice 1（以及 slice 2 的 ICMP/IPv6/VLAN/接口切换）已在 agentd 落地** ——
> 采集器在 `src/telemetry/flows/`，daemon 接线在 `src/runtime/daemon_flows.rs`
> （授权 → 能力探测 → 启停 → 窗口上送 → 采集状态）。
> **数据面（warp-parse 的 `FLOW:` WPL + `agent-flows` sink）尚未实现**，
> 所以按 §16 的顺序，**先上数据面再放开 agentd**。
> §12 的真机探针实验完成前，§6/§8 中标注「待实测」的条目不得当作已定结论。
> 对应 issue：`dayu-sec/wist-agentd#50`。

## 1. 目的与范围

在**未订阅云侧 VPC 流日志**的环境里，补齐"这台主机和哪些地址/端口发生过 TCP/UDP（以及 ICMP）通信、在哪个时间窗、哪个方向、多大量级"。

本能力是**主机视角的补充来源**，不是云流日志的等价替代：

- 观测点在主机网卡，看不到在到达网卡之前就被云侧策略丢弃的流量；
- 计数受内核 GSO/GRO 影响，**不与云侧逐包相同**；
- 不给出安全组/NACL 的放行或拒绝结论。

**首版范围**

- 协议：TCP / UDP / ICMP / ICMPv6（IPv4 + IPv6）；
- 只观测**对外网卡**，排除 loopback 与容器虚拟接口；
- 只覆盖主机协议栈实际能看到的收发流量；
- 只定义数据契约、覆盖边界与验收口径，不约束实现方式（§9 的选型是实现建议）。

**非目标**见 §14。

## 2. 已锁定的决策

| # | 决策 | 结论 |
|---|---|---|
| D1 | 云侧身份字段由谁填 | **平台富化**。agentd 不发 `account-id` / `vpc-id` / `subnet-id` / `interface-id` / `instance-id` / `region-id` / `az-id` / `cross-region`，也不发 `needs_enrichment` |
| D2 | `direction` 取值 | **`in` / `out`**，与云侧词表一致；"相对被观测网卡"这层语义写在文档里，不进字段 |
| D3 | 协议范围 | **`6` / `17` / `1` / `58`**，含 IPv4 与 IPv6 |
| D4 | 传输层帧标记 | **` FLOW: `**（详见 §5 的命名判据与禁用词） |
| D5 | 上行链路 | 复用既有 TCP sink / `DataFrame` 信封 / spool / framing，**不新开链路** |
| D6 | 实现技术栈 | **aya（用户态纯 Rust）+ C 编写的 BPF 程序**，**不使用 CO-RE**（§9） |
| D7 | 聚合位置 | **BPF map 内聚合**，key 带 `window_id`；用户态按窗口扫表（§9.3） |

## 3. 与云流日志的关系

| 维度 | 云侧流日志 | 本能力 |
|---|---|---|
| 观测点 | 云网络（ENI 前后由厂商定义） | 主机网卡（tc hook） |
| 被云策略提前丢弃的流量 | 可能可见（REJECT 记录） | **不可见**，且**不得补** |
| 地址 | 厂商口径（可能含 NAT 后公网地址） | hook 上见到的地址（egress/in 语义待实测，见 §12） |
| 身份字段 | 权威 | 不产出，由平台 join |
| 计数口径 | 厂商逐包或窗口口径 | 受 GSO/GRO 影响 |
| **采集范围** | 默认含 VPC 内东西向（可选过滤） | **只含一端是公网的流量**（东西向不采，§10.2） |

由此产生两条硬规则：

1. **不合并计算**。下游必须按 `(host_id, ifname, direction, 时间窗)` 择一使用，不能把主机记录加到云侧记录上。
2. **"不覆盖"不等于 0**。只有主机来源时，拒绝类视图必须显示"不覆盖"，不得显示 0。这条要写进下游渲染断言，而不只是文档。

再加一条**范围差异**（§10.2）：本能力**只采一端是公网的流量**，东西向默认不采。所以：

3. 拿云侧流日志对账时，必须**先按对端是否为公网过滤云侧记录**再比；直接把两份总量相减，
   差额几乎全是"东西向本来就不采"，会把设计口径当成数据丢失去查。

## 4. 契约分三层

| 层 | 谁产出 | 负责什么 | 不负责什么 |
|---|---|---|---|
| ① agentd 上行帧 | `wist-agentd` | 观测事实 + 平台 join 键（`agent_id`/`host_id`/`collector_instance_id`/`ifname`/MAC/`local_addrs`） | 任何推断、任何云侧身份、任何策略判决 |
| ② WPL/OML 解析产物 | 数据面（warp-parse） | 形状与类型归一（数值↔字符串、缺省值、字段命名对齐云 schema） | 不做富化、不做跨源合并、不做判定 |
| ③ 平台记录 | 网关 / `wist-atlas` | 云侧身份富化、跨源择一、证据层建模（`EpRes`/`DepObs`） | 不改写观测事实 |

约束：

- **`HostFlowRecord` 定义在 `wist-contracts`**（`wist_contracts::host_flow`，0.16 起），agentd 只负责构造与序列化、
  不重建（与 `OBSFACT` 同一纪律：谁构造契约对象只应有一处 —— agentd 侧是 `record::record_from_window`）。
- 第 ① 层出现"推断字段"即视为设计错误。`needs_enrichment` 属于第 ③ 层。
- `wist-atlas` 侧按 `doc/architecture/network-modeling-analysis.md` §10 处理：流记录是 **runtime evidence**，先落地为观测证据，不得直接 materialize 成 network inventory。

## 5. 传输层：` FLOW:` 帧

### 5.1 形状

```text
{"schema":"v1","agent":"<agent_id>","ts":"<RFC3339>","seq":<n>} FLOW: <HostFlowRecord JSON>
```

- 信封仍只有 `schema` / `agent` / `ts` / `seq`（`src/telemetry/warp_parse.rs`：来源细节不进帧）；
- **一条记录一帧**，正文是单行 JSON。分帧沿用既有策略：`alpha` 起 TCP 上送**固定 `len`**（`SinkIdentity::resolve` 不看配置，配置里的 `line` 仅兼容旧配置并提示一次），`FLOW` 帧不需要任何额外处理；
- `seq` 复用 agent 级全局计数器（`state/logs/seq.json`，指标帧已经在用），保证 `(agent, seq)` 的去重/查缺跨帧类型一致；
- `file` sink **静默跳过**（与 `OBSFACT`/`DSNAP`/`IVSREP` 一致），不得把流记录写进 `wist-records.ndjson`。

### 5.2 为什么必须新开标记

现有标记：` LOGRAW: ` / ` METRICS: ` / ` OBSFACT: ` / ` DSNAP: ` / ` IVSREP: `。仓库已把判据写死：

- `src/telemetry/warp_parse.rs`（`build_investigation_frame` 注释）：*"为什么单开一个标记而不是复用 `OBSFACT`：两者的消费者与保留策略不同……混在一个标记里，数据面只能用同一条 sink 规则"*；
- 同文件测试断言：*"不许蹭别的帧标记：数据面按标记分 sink"*。

逐项排除：

| 标记 | 为什么不能复用 |
|---|---|
| `LOGRAW` | 正文定义为"原文、不转义"，走各采集面 WPL + `raw_log` 兜底；流记录会变成"日志"，抽不出五元组、占日志保留期。且 `TelemetryRecord` 带 offset/checkpoint 语义，流是生成的、无 checkpoint |
| `METRICS` | 正文是 VM 单样本 `{metric:{…},values,timestamps}`，进指标存储；流记录是事件，字段模型不重叠 |
| `OBSFACT`/`DSNAP`/`IVSREP` | 消费者已绑定（网关 / atlas / 网关），且保留期语义不同 |

### 5.3 命名判据与禁用词

帧标记命名的是**载荷形态**，不是资源主题，也不能编码来源或实现：

- 可用：`FLOW`（本决定）、`FLOWS`（贴合 `METRICS` 复数风格）、`FLOWREC`（最无歧义但冗长）；
- **禁用**：`TRAFFIC`（量纲词，与 `METRICS` 的接口吞吐撞语义）、`NETFLOW`/`IPFIX`（协议名）、`NFLOG`（netfilter 真实设施名）、`CONN`/`SESSION`（UDP 无连接，且 `SESSION` 撞 `LoginSession` 采集面）、`PKT`（暗示逐包）、`HOSTFLOW`/`EBPFFLOW`（把来源/实现编进标记）；
- 来源与实现只进正文：`source=host_ebpf`、`capture=tc_egress|tc_ingress`。

## 6. 记录契约：`HostFlowRecord` v1

`record_schema = "wist.host_flow/v1"`。类型在 agentd 侧是强类型 JSON（数值就是数值），**第二层负责归一**成与云侧一致的字符串表示。

### 6.1 身份与来源

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `record_schema` | string | 是 | 固定 `wist.host_flow/v1` |
| `source` | string | 是 | 固定 `host_ebpf` |
| `coverage` | string | 是 | 固定 `host_partial` |
| `capture` | string | 是 | `tc_egress` / `tc_ingress` |
| `collector_instance_id` | string | 是 | agent 本地稳定的采集实例标识（重启不变） |
| `host_id` | string | 是 | 与 `OBSFACT` 同一 `host_id`，平台 join 键 |
| `host_name` | string | 否 | 仅留痕 |
| `kernel` | string | 是 | `uname -r`，现场排障用 |

### 6.2 观测点

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `ifname` | string | 是 | 被观测网卡名 |
| `ifindex` | uint32 | 是 | 防 ifindex 复用导致跨接口误合并 |
| `if_mac` | string | 否 | 识别接口重建 |
| `local_addrs` | string[] | 是 | 窗口开始时该网卡的 v4/v6 地址快照 |

### 6.3 五元组与方向

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `direction` | string | 是 | `in` / `out`（相对被观测网卡） |
| `protocol` | string | 是 | `6`/`17`/`1`/`58` |
| `srcaddr` | string | 是 | v6 用 RFC 5952 压缩文本 |
| `dstaddr` | string | 是 | 同上 |
| `srcport` | string | 是 | 十进制；ICMP 或取不到时为 `"0"` |
| `dstport` | string | 是 | 同上 |
| `icmp_type` | string | 否 | **仅** `protocol ∈ {1,58}` 出现；TCP/UDP 不出现该键 |
| `icmp_code` | string | 否 | 同上 |
| `port_unavailable` | bool | 否 | 分片/扩展头导致端口取不到；此时端口为 `"0"` |

### 6.4 窗口与量

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `start` / `end` | uint64 | 是 | Unix 秒；**半开区间** `[start, end)` |
| `window_seconds` | uint32 | 是 | 正常 60；`partial` 时为实际秒数 |
| `packets` | uint64 | 是 | Σ `gso_segs`，估算的 L3 报文数（§8） |
| `bytes` | uint64 | 是 | Σ `skb->len`，L3 字节，**不含 L2** |
| `wire_bytes` | uint64 | 否 | Σ `wire_len`（5.14+）；取不到则整键不出现 |
| `wire_bytes_source` | string | 是 | `wire_len` / `unavailable` |
| `skb_count` | uint64 | 否 | 实际观察到的 skb 数（GSO/GRO 诊断） |
| `gso_skb_count` | uint64 | 否 | 其中 `gso_segs > 1` 的 skb 数 |

### 6.5 覆盖与缺口

| 字段 | 类型 | 必填 | 说明 |
|---|---|---|---|
| `truncated` | bool | 是 | 本窗口发生过聚合表上限淘汰 |
| `dropped` | uint32 | 是 | 本窗口未能计入的事件数（表满、读表竞态、迟到落在已 flush 窗口） |
| `partial` | bool | 否 | 窗口被截断 |
| `partial_reason` | string | 条件 | `agent_start` / `paused` / `interface_changed` / `shutdown` / `clock_changed`；`partial=true` 时必填 |

### 6.6 明确不出现的字段

`account-id`、`action`、`az-id`、`cross-region`、`instance-id`、`interface-id`、`log-status`、`region-id`、`subnet-id`、`version`、`needs_enrichment`。

> 尤其 `action`：主机侧无力判断云侧放行/拒绝，留空。若下游 `action` 枚举只有 `ACCEPT/REJECT`，**不要**塞 `observed` 进去——那会把非法状态写进数据。`observed` 的语义由 `source`/`coverage` 表达。

### 6.7 示例

```json
{"schema":"v1","agent":"agent-host-d97e23da6111","ts":"2026-11-26T04:16:42Z","seq":100231} FLOW: {"record_schema":"wist.host_flow/v1","source":"host_ebpf","coverage":"host_partial","capture":"tc_egress","collector_instance_id":"agent-host-d97e23da6111","host_id":"host-d97e23da6111","host_name":"vm-web-01","kernel":"5.15.0-91-generic","ifname":"eth0","ifindex":2,"if_mac":"52:54:00:aa:bb:cc","local_addrs":["10.118.0.14"],"direction":"out","protocol":"6","srcaddr":"10.118.0.14","dstaddr":"88.214.25.121","srcport":"50123","dstport":"443","start":1789469760,"end":1789469820,"window_seconds":60,"packets":13,"bytes":1460,"wire_bytes_source":"unavailable","skb_count":4,"gso_skb_count":1,"truncated":false,"dropped":0}
```

## 7. 采集语义

### 7.1 观测点

tc clsact 的 egress 与 ingress 两个 hook，分别对应 `direction=out` / `in`。

- egress 的理论位置在 netfilter POSTROUTING **之后**（即看到 SNAT 后的源地址）；
- ingress 的理论位置在 PREROUTING **之前**（即看到 DNAT 前的目的地址）。

> **两条都待实测确认**（§12 Q1）。确认前不得对外承诺"五元组与云侧必然对齐"。

不采用 XDP 作为首版 ingress 观测点：需要驱动支持，且与 tc 的观测面不一致会引入两套解释。

### 7.2 网卡选择

判定"对外网卡"：

1. 默认路由出口所在接口；
2. 且持有 global unicast / ULA 地址（至少一个）；
3. 排除 `lo`、`veth*`、`docker*`、`br-*`、`cni*`、`flannel*`、`cali*` 等虚拟接口；
4. **bond 记 bond 接口本身，不记 slave**；vlan 子接口首版不观测（记在父接口）。

授权**只认 `HostFlow:auto`**（空等同 `auto`）：观测哪张网卡是**本机事实**，平台指定不出来。
写死接口名会被如实报成 `unsupported`（`reason.subject = flow`），而不是静默不采。多网卡时每条记录都带 `ifname`/`ifindex`，不做跨接口合并。

### 7.3 窗口

- 固定 **60s**，UTC 整分对齐：`start = floor(now/60)*60`，`end = start+60`；
- 半开区间 `[start, end)`，按包到达 hook 的时刻归窗；
- **只有窗口内有字节才发记录**。零流量窗口不发（空闲长连接每窗发 `bytes=0` 会爆量；"长连接持续产出"的口径即"有流量的窗口持续产出"）；
- flush 延迟 1 个窗口：只 flush `window_id <= current_window - 2` 的桶，给迟到包留收敛时间；
- 迟到包落进已 flush 的旧窗口 → 该桶被重建 → 用户态读到 `window_id < flush_horizon` 的桶时，计入当前窗口的 `dropped` 并删除，**不再补发**（避免同一幂等键出现两条记录）；
- 每拍最多上送 4096 条（其余桶留在表里下拍继续，见 §11）；
- **墙钟跳变**（NTP 步进 / 手改时间）：窗口归属靠「单调桶差 + 当前墙钟」换算，墙钟一跳映射就断。
  判据是「拿上一拍锚点外推的墙钟」与真实墙钟相差 ≥ 半个窗口；命中后按**旧锚点外推的时间**
  给这些桶归窗（它们确实是那一刻采的；按新墙钟重算会撞已发的幂等键），并标
  `partial_reason=clock_changed`，下一窗重新锚定。

### 7.4 聚合键与幂等键

聚合键（BPF map key，含 `window_id`）：

```text
(ifindex, direction, protocol, srcaddr, srcport, dstaddr, dstport,
 icmp_type, icmp_code, window_id)
```

下游幂等键（去掉 `window_id`，换成 `window_start`）：

```text
(collector_instance_id, ifname, direction, protocol,
 srcaddr, srcport, dstaddr, dstport, icmp_type, icmp_code, start)
```

`icmp_type`/`icmp_code` 进 key 的原因：echo 与 unreachable 相加没有意义，不同类型不能混进同一条记录。

### 7.5 协议细节

| 情况 | 处理 |
|---|---|
| ICMP / ICMPv6 | `srcport`/`dstport` = `"0"`，输出 `icmp_type`/`icmp_code`。端口口径（0 vs echo identifier）见 §12 Q2，待实测对齐云侧 |
| ICMPv6 ND（type 133–137）/ MLD | **不采**，BPF 侧直接丢弃并计入 `dropped`。v6 主机上这是持续噪音 |
| 链路本地 / 组播（`fe80::/10`、`ff00::/8`、`224.0.0.0/4`、`255.255.255.255`） | **不采** |
| IPv6 分片/扩展头导致端口取不到 | 端口 `"0"` + `port_unavailable=true`。不做重组 |
| 非首片（TCP/UDP） | 同上，`port_unavailable=true` |

### 7.6 上限与截断

- 聚合表用 `LRU_HASH`，容量写进配置并有硬上限；
- 达到上限时按 LRU 淘汰，并置该窗口 `truncated=true`；
- 被淘汰桶里已累计的字节丢失，计入 `dropped`。**不采样**：采样会让量级不可解释，宁可截断并明示。

## 8. 统计口径

| 量 | 取法 | 受什么影响 |
|---|---|---|
| `bytes` | Σ `skb->len`（L3，不含 L2） | 出方向 GSO 超级包只含一份 L3 头 → 比线缆字节**少**（差 `(segs-1) × L3 头 + 每段 L2 头`）；入方向 GRO 合并后同理 |
| `packets` | Σ `gso_segs`（非 GSO 包为 1） | 出方向接近线缆报文数；入方向 GRO 合并后仍按段数还原，但重传/乱序与线缆不完全等价 |
| `wire_bytes` | Σ `skb->wire_len` | 仅 5.14+ 可用；这是最接近"线缆字节"的量 |
| `skb_count` / `gso_skb_count` | 计数 | 诊断用：`skb_count ≪ packets` 说明 GSO/GRO 比例高 |

明确声明（写进面向用户的文档）：

- `bytes` 是 **L3** 字节，不是线缆字节；
- `packets` 是**估算的 L3 报文数**，不是"逐包相同"；
- 与云侧对比时，优先与云侧同为 L3 口径的量比；口径不明时只比**窗口级总量与方向**，且允许固定比例的偏差，不做逐条比较。

## 9. 实现建议

### 9.1 选型

| 方案 | 用户态依赖 | 构建依赖 | 判定 |
|---|---|---|---|
| **aya + C BPF** | 无（纯 Rust，静态 musl 可链接） | clang | ✅ 采用 |
| aya + Rust BPF（`aya-ebpf`） | 无 | **nightly + `bpf-linker`** + LLVM | 🟡 语言统一，但多一条会漂移的工具链 |
| `libbpf-rs` | `libelf`/`zlib`（大概率动态） | clang + libbpf + libclang | ❌ 与静态 musl 制品冲突 |

约束来源：`release.yml` 出 `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl` 静态制品，stable 工具链，`musl-gcc` 链接；升级靠 agent 自行替换二进制。任何运行时 `.so` 依赖都出局。

`bpf-linker` 跟随 nightly 漂移，长期维护成本高于钉死一个 clang 版本，因此选 C 写 BPF。

### 9.2 不使用 CO-RE

流记录所需的字段，`struct __sk_buff` 已直接暴露，无需读内核结构体：

| 需要什么 | 来源 | 版本（待实测确认） |
|---|---|---|
| L3 字节数 | `skb->len` | 一直有 |
| GSO 段数 | `skb->gso_segs` | 4.18+ |
| 线缆字节 | `skb->wire_len` | 5.14+ |
| 五元组 | 直接读包头（`bpf_skb_load_bytes`） | 一直有 |
| 入接口 | `skb->ingress_ifindex` / attach 时绑定 | 一直有 |

收益：不写 `vmlinux.h`、不用 `preserve_access_index`、**不要求目标内核有 `CONFIG_DEBUG_INFO_BTF`**，verifier 也更友好。

### 9.3 BPF 侧

- 只用 `tc` 程序（clsact egress/ingress），不用 XDP、不用 kprobe；
- 聚合在 `BPF_MAP_TYPE_LRU_HASH` 里完成，**不逐包发 ringbuf**（高连接数主机上逐包事件会直接压垮用户态）；
- key 含 `window_id`，value 是 `{packets, bytes, wire_bytes, skb_count, gso_skb_count, dropped}` 的累加器；
- 用一个 `ARRAY` map 或 `.rodata` 存放 `window_seconds` 等常量；
- 用户态每 tick 遍历 map：`window_id < flush_horizon` 的桶 → 编码成记录 → 删除；删除后若桶被重建（迟到包）→ 计入 `dropped`。

### 9.4 用户态

- 新增 `write_flow(envelope, body)` / `build_flow_frame` / `carries_flow_frames()`，形状照 `write_fact`/`build_fact_frame`；
- `HostFlowRecord` 的构造在 agentd 侧唯一一处；
- `seq` 从 `state/logs/seq.json` 取号；
- 采集未授权 / 内核不支持 / 加载失败 → 走 `unsupported` 上报，不静默。

### 9.5 制品与 CI

- BPF `.o` 用 `include_bytes_aligned!` 嵌入 → **制品仍是 3 个二进制**，打包脚本不变；
- BPF 对象随 agent 版本走，不单独发版。

**已落地（GitHub Actions）**：

| 位置 | 做什么 | 为什么 |
|---|---|---|
| `build-and-test.yml`（ubuntu 矩阵项） | 装 `dev/ci/flow-clang.txt` 里的 clang + `CLANG=<它>` | 不装的话 `have_flow_bpf` 不置位，`telemetry/flows/linux.rs` 与 `flow.bpf.c` **根本不参与编译**，回归只能靠真机 |
| 同上，build/test 步骤 | `WIST_REQUIRE_FLOW_BPF=1` | 缺 clang = **构建失败**（`build.rs` panic），而不是出一个“全机队报 unsupported”的包 |
| `release.yml`（linux 矩阵项） | 同上 + `<clang> --version` | 版本钉死；镜像升级丢包会**装包失败**，比静默出制品容易发现 |
| `release.yml` | 制品断言 `strings <bin> \| grep -qx flow_egress/flow_ingress/flow_map` | 双保险：从成品里找只可能来自 BPF 对象的符号 |
| `build-and-test.yml` 的 `flow-ebpf` 作业 | 以 root 跑 `#[ignore]` 的真机用例（attach / 真流量 / 停采 flush），**TCX 与 netlink 两条路径都跑** | 单测盖不到 verifier 与 tc；环境不满足时用例打印 `skip:` → 作业输出 `warning`，不假绿 |

### 维护：换 runner 镜像时改哪里

clang 的版本只有**一个**权威来源：`dev/ci/flow-clang.txt`（单行，无注释 —— 被 `$(cat)` 直接当包名与可执行名用）。
两个工作流里所有 `apt-get install` / `CLANG=` / 版本打印都从它读，**不用改任何 YAML**。

镜像升级套餐名不再叫 `clang-18` 时（如 ubuntu-26.04），按这个顺序动：

1. 改 `dev/ci/flow-clang.txt` 一行；
2. 本地跑一次 `cargo test --lib flows`（带 `CLANG=<新版本>`）确认 `flow.bpf.c` 在新版 clang 下仍能编、且真机用例能过；
3. 同步更新本节表格里的版本描述（“ubuntu-24.04 仓库里的 18”这类文字）。

> 为什么不把 clang 版本写进 `Cargo.toml` / 环境变量默认值：它是**构建机**的属性，不是产品配置；
> 写进单一文本文件是为了让“改一处”这件事不靠人记住 grep 结果。

macOS 构建（`aarch64-apple-darwin`）不参与：`aya` 只是 linux 依赖，`build.rs` 看到 target_os != linux 直接返回，
所以同一个 build/test 步骤两个平台共用（macOS 上 `CLANG` / `WIST_REQUIRE_FLOW_BPF` 无意义也不报错）。
x86_64 与 aarch64 均为小端，**一个 `.o` 两架构共用**。

> 本地开发不受 `WIST_REQUIRE_FLOW_BPF` 影响（默认仍是“没 clang 就报 unsupported”）：
> 那个开关只该出现在 CI/发布机的环境里。

### 9.6 测试形态

| 层 | 怎么做 |
|---|---|
| CI | 编译 BPF 对象 + 用户态单测：窗口切分、聚合键、编码、截断/丢弃计数、`partial` 语义 |
| 真机 | crate 内的 `#[ignore]` 用例：`cargo test --release --lib -- --ignored`，`WIST_FLOW_TC=tcx\|netlink` 两条 attach 路径都要跑。覆盖加载、双方向、ICMP、IPv6/QinQ、长连接跨窗、超限截断，以及 **`internet` 口径的三种地址形状**（内网→内网丢 / 本机→公网留 / 公网→本机留）。CI 由 `.github/workflows/build-and-test.yml` 的 flow job 驱动（netlink 跑在 veth + netns 里，绕开 runner 上 `pref 1` 的过滤器）；环境采不到时用例 skip，不假绿 |
| **已知缺口** | **真实 ingress hook 没有被端到端覆盖**：`internet` 用例里的入站形状是 AF_PACKET 注入帧造的，验的是「判据对 `src`/`dst` 对称」，不是「ingress 看到的地址」。要补得用 veth 对（CI 已经为 netlink 建了一个）+ 从对端真发包 |
| 契约 | 帧形状单测（`FLOW:` 标记、信封不含正文、不得出现其他标记） |

## 10. 权限、内核基线、部署

| 项 | 结论 |
|---|---|
| 对外承诺的内核基线 | **5.4+ LTS**（RHEL8 / Ubuntu 20.04 起）。4.18–5.3 未验证，实测通过后再放开；低于基线一律报 `unsupported` |
| 不再需要 `ringbuf` | 改用 map 聚合后基线由"5.8（ringbuf）"降到"4.18（`gso_segs`）"，对外仍保守承诺 5.4+ |
| 权限 | 5.8+ 用 `CAP_BPF` + `CAP_NET_ADMIN`（可选 `CAP_PERFMON`）；更低内核退化为 `CAP_SYS_ADMIN`。首版 agentd 本身是 root systemd 服务，直接以 root 运行即可 |
| `clsact` qdisc | 需要 `CAP_NET_ADMIN` |
| 容器部署 | **首版不支持**（需 hostNetwork + 高权限），避免做未验证的承诺 |
| 降级 | 不满足基线 / 无权限 / qdisc 装不上 → **不采集并如实上报**（映射到 `collection-status.md` 的 `blocked` + `unsupported`/`permission`），不得退化成 conntrack 或 `ss` 轮询（口径不同，会制造不可解释的差异） |

### 10.1 两条 attach 路径的覆盖差异（重要）

| | TCX（内核 ≥ 6.6） | netlink `tc filter`（< 6.6 的兜底） |
|---|---|---|
| 载体 | BPF link | `clsact` 上的 `SchedClassifier` filter |
| 异常退出 | 进程死 fd 关，内核自动摘 | 会把 prog 与 map 钉在内核里（所以挂前按程序名清残留） |
| **与别人的 tc 过滤器共存** | 不受影响 | **受限**：`tc filter` 按 `pref` 升序执行，先返回非 `PIPE` 的那个终止整条链 |

netlink 路径挂在自己的 `pref`（不给别人抢位置），因此**只要这台机器上已有更小 `pref` 的
`direct-action` 过滤器（很多 CNI / 安全 agent / 云厂商镜像会装），我们的 filter 就永远不会
被调用** —— 此时采集器会报“在采”，但一条流也不会出现。

实测例子：GitHub 的 `ubuntu-24.04` runner 在 `eth0` 上自带 `pref 1` 的
`tc_egress_traffic` / `tc_ingress_traffic`，我们挂的 `pref 49152` 被完全遮蔽；同一台
机器改走 TCX 就能采到。

因此：

- **能用 TCX 就用 TCX**（6.6+ 默认），现网 6.6+ 的机器不受这条限制影响；
- 老内核上要确认这张网卡的 clsact 上没有比我们更早的 `direct-action` 过滤器
  （`tc -d filter show dev <if> egress`）；
- **已知短板**：运行期还不会自动识别这种“被遮蔽”状态（没有计数器能证明“本该有包却没进来”），
  只能靠现场对账（对比云侧流日志或 `ss`/`nstat`）发现。彻底解决要自己 dump tc 过滤器做 pref 比对，
  属于后续项（§15 slice 3）。

### 10.2 采集范围过滤：只留「一端是公网」的流量

**一句话**：只保留「**一端是公网**」的流量，两端都是内网的（东西向）在聚合**之前**就地丢弃，
只计一个 `filtered` 计数器。**当前行为固定如此，没有开关。**

**出站与入站都在内** —— 判据是**对端**，不是方向：

| 场景 | `src` | `dst` | 结果 |
|---|---|---|---|
| 本机主动连公网 | 私网 | **公网** | 保留 |
| 公网回包 / 公网连进来（入站） | **公网** | 私网 | **保留** |
| 本机有公网 IP，公网直连 | **公网** | **公网** | 保留 |
| 内网东西向（k8s / service mesh / 同 VPC） | 私网 | 私网 | 丢弃（计 `filtered`） |

入站必须留：一来「谁在访问我」就是暴露面分析的另一半；二来入站连接数通常很少
（只有开放端口），成本几乎不涨；只判 `dst` 会把入站**整片丢掉**（入站包的 `dst` 是本机私网地址），
这是实现时最容易犯、而且不报错就静默发生的错。真机用例里有一条专门断言钉着它（§9.6）。

为什么不给开关：规模化部署里没人会去改每一台机器的 `agentd.toml`，本机开关加进去等于
永远停在默认值 —— 那是个假配置面，还让「配了却没生效」变成一种新的现场故障。
真要按站点/主机改口径，只能走**平台下发**（最近的落点是现有 `discovery-policies:poll`），
那是一条单独的契约改动（contracts + 网关 + 管理面），见 §13 #9。
所以本轮只交付「默认口径正确」，不交付旋钮。

理由：主机上真正有信息量的是「这台机器跟公网上谁通信」——暴露面、外联基线、C2 / 挖矿判定都要它；
而东西向（内网互通，尤其 k8s / service mesh）在**连接条数**上通常比对外多两个数量级，
正好是聚合表容量、每拍扫描、上行带宽、下游存储的大头。丢掉东西向不是省一点，是换一个量级。

| 项 | 口径 |
|---|---|
| 判据 | **对端**而不是方向：`src` / `dst` **任意一个是公网**就保留（上表） |
| 判定位置 | BPF `account()` 开头、**`window_id` 赋值之前**：东西向的包根本不进聚合表，也就不会被每拍扫到、不会挤掉涉公网的流（LRU 按写入顺序淘汰，这个顺序是效果的全部） |
| 配置面 | **无**。内置 agentd 不提供 `[telemetry.flows]` / 环境变量之类的本机旋钮（理由见上）；`FlowScope` 枚举与 `scope_mode` map 保留，是为了将来下发时不用再改 BPF 契约 |
| 可见性 | 被过滤的包数进 `state/flows/status.json` 的 `counters.filtered`，`diagnose` 的 `flows.status` 里同时打出 `scope=` 与 `filtered=` |

内置内网段（**BPF 常量比较，不查表**；判定全在 BPF，Rust 侧 `scope.rs` 只负责把模式写进 map）：

| 族 | 视为「内网 / 保留」的段 |
|---|---|
| v4 | `0/8`、`10/8`、`127/8`、`169.254/16`、`172.16/12`、`192.168/16`、`100.64/10`（CGNAT，云上常见）、`224/4`（组播）+ `240/4`（保留，含 `255.255.255.255`） |
| v6 | `::/8`（含 `::`、`::1`；**`::ffff:a.b.c.d` 解包看内嵌 v4**）、`fc00::/7`（ULA）、`fe80::/10`（链路本地）、`ff00::/8`（组播） |

漏判方向是**多采**（把站点私有的公网段当成公网），不是丢数据 —— 这是刻意选的失败方向。
唯一例外是已废弃的 `::a.b.c.d` 写法会被当成内网（Linux 不产生这种地址，不值得在逐包路径上多比 9 个字节）。
站点自定义内网段（LPM trie，例如 VPC 使用公网地址段）属于后续项。

实施细节：

- 模式经单条目 ARRAY map（`scope_mode`）在 **attach 之前**写进 BPF，同一份对象给所有站点用，不为每个站点重编；
- 写不进去时**按全采跑并 warn 一次**（宁可多采，不少采），不静默改成另一种口径；
- 过滤后的流**区分不了「主动连出」与「回包」**（没有 TCP flags）；`instigated_by` / `tcp_flags` 留给 `wist.host_flow/v2`。
  `internet` 范围下保留「任一端是公网」，所以回包方向仍在，语义上仍然是「对端」口径而不是「我发起的连接」。

## 11. 失败模式与自观测

失败分类**不新开通道**，复用既有 `AgentLocalCollection`（见 [`collection-status.md`](./collection-status.md)）的 `prerequisites` / `result` / `reasons[{kind, subject, detail}]`：

| 现场 | prerequisites | result | reasons |
|---|---|---|---|
| 内核低于基线 | `blocked` | `cancelled` | `{kind:"unsupported", subject:"kernel", detail:"<uname -r> < 5.4"}` |
| 缺 CAP / 非 root | `blocked` | `cancelled` | `{kind:"permission", subject:"cap_bpf"}` / `cap_net_admin` |
| clsact 装不上或与既有 qdisc 冲突 | `ready` | `failure` | `{kind:"run_failed", subject:"qdisc:eth0", detail:…}` |
| verifier 拒绝 | `ready` | `failure` | `{kind:"run_failed", subject:"bpf_load", detail:<截断的 verifier 日志>}` |
| 聚合表持续淘汰 | `ready` | `partial` | `{kind:"truncated", subject:"flow_map"}` |
| 未授权 / 工作暂停 / 上送关闸 | —— | `cancelled` | `{kind:"paused"}` / `{kind:"standby"}` |

分层要求：

- 记录里的 `truncated` 是**窗口级事实**（这一窗丢了），`collection-status` 里的 `truncated` 原因是**状态级判断**（整体持续被截断）。两者都要，不能互相替代。
- **没有记录 ≠ 故障**：窗口内无流量是正常态（`success`）。故障只能由 `prerequisites/result` 表达，不能靠"记录变少"推断。
- 心跳：窗口内零记录也上报一次采集状态（与 `FLOW` 帧分开），用于区分"没流量"与"采集中断"。
- 计数器进自观测：`map_full_drops`、`late_bucket_drops`、`load_failures`、`interface_changes`、
  `filtered`（被 §10.2 的采集范围丢掉的包数 —— 开着 `internet` 却一条流都没有时，
  它回答「是被过滤了」还是「真的没流量」）。
  **已落地**：落在 `state/flows/status.json`（节流 30s，失败面变化时立刻写），
  由 `agentd diagnose` 的 `flows.status` 项输出。**不进** v1 状态报文 ——
  那个报文是 `deny_unknown_fields` 的，加字段会让旧读取方整份拒收（见 §16.4）。
- 采集中断期间的窗口**不补**（没有数据可补），由采集状态 + `dropped` 共同表达。
- **零记录 ≠ 故障**，且默认口径下多了一个正当理由：**流量全被范围过滤了**（§10.2）。
  一台只跑内网东西向的机器会持续 `sent=0`，这是 `success`，不是 `partial`。
  证据链：`state/flows/status.json` 的 `filtered` 计数器 + `diagnose flows.status` 的
  `sent=0 但 filtered>0` 提示。范围过滤**不进** `reasons` —— 它不是故障，
  塞进去会让管理面常态化报异常。

**安全红线**：只创建/使用自己的 clsact，卸载时只删自己加的 filter；异常退出也要清理。把主机网络搞坏是本功能最不可接受的失败模式，作为实现验收项，不是"注意事项"。

落地补充（与代码同步）：

- **停机**：主循环收到 SIGTERM/SIGINT 时先按 `partial_reason=shutdown` 把在途窗口发出去，再卸 filter；关闸发不出去也要卸（留下的 filter 会一直逐包执行）。
- **崩溃残留**：≥6.6 用 TCX（BPF link，进程一死内核自动摘）；<6.6 是 netlink clsact filter，
  所以那条路在挂之前先 `clsact`（不存在则建）+ **按程序名**清掉自己的残留
  （只会匹配 `flow_egress`/`flow_ingress`，别人的 filter 不碰；不用固定 priority/handle ——
  那种坐标一旦撞上第三方就会误删）。
- **clsact 建了不删**：空 qdisc 没有开销，而删它可能连带删掉别人后来挂上的 filter。
- **批量上限**：一拍最多上送 4096 条记录，其余桶**留在 BPF 表里**下拍继续（最老的先走）；
  停采那一次不限量（采集器马上要 drop，分批等于丢）。
- **上下文丢失**：窗口结束时网卡已消失 → 那条记录组不出来（没有 `ifname`），丢弃并计
  `incomplete_data`（软问题），不静默丢。
- **现场可见**：`agentd diagnose` 的 `flows.status` 一项直接回答「采没采、为什么没采、丢了多少」
  （数据源是本机 `state/flows/status.json`，不绕控制面）。原因码与处理方向写在那项的 hint 里。

## 12. 必须先做的真机探针实验

在一台**同时开启云侧流日志**的对照主机上跑最小探针（只打印，不做聚合与上报），回答 4 个问题：

| # | 问题 | 影响 |
|---|---|---|
| Q1 | tc egress 看到的是 SNAT 前还是后的源地址？ingress 看到的是 DNAT 前还是后的目的地址？ | 决定 §7.1 的语义与验收能否对齐五元组；对不上就要加 `pre_nat_*` 字段或改字段语义 |
| Q2 | 云侧 ICMP 记录的 `srcport`/`dstport` 填 `0` 还是 echo identifier？是否有 type/code 列？ | 决定 §7.5 的端口口径与 `icmp_*` 字段是否保留 |
| Q3 | 云侧同一条长流多次上报时，`bytes`/`packets` 是**窗口增量**还是**累计值**？ | 决定是否需要额外的累计字段；issue 验收第 3 条卡在这 |
| Q4 | 目标发行版的内核版本、`gso_segs`/`wire_len` 可用性、clsact 能否加载、所需 CAP | 决定 §10 的基线是否成立 |

测法：一个 tc 探针，把 `ifindex`、`skb->len`、`gso_segs`、`wire_len`、hook 前后地址各打一行；与同一窗口的云侧导出按五元组 join 比对。产物：`probe.log` + 云侧导出 CSV + 对照表。

## 13. 待决策清单

| # | 问题 | 建议 | 阻塞 |
|---|---|---|---|
| 1 | 采集层 source kind 名与 target 语法 | `HostFlow`；target **只认空或 `auto`**（首版不支持固定单接口） | 四侧同源 |
| 2 | 归到哪个 `CollectionFamily` | **新开 `HostFlow`**，不塞进 `NetworkFirewall`（那面的语义是"拦了什么、策略变没变"） | 知识库版本、模板、web 文案 |
| 3 | 窗口长度是否可下发 | 首版固定 60s；后续再开放目录覆盖 | 契约（`window_seconds` 已能表达） |
| 4 | 聚合表容量与 LRU 上限默认值 | 等 Q4/量级数据 | 背压 |
| 5 | 能力协商机制 | **不往 v1 报文加字段**（`deny_unknown_fields`），新增"数据面能力表"端点；拿不到就默认不发 | 协议层 |
| 6 | `wire_bytes` 是否参与验收对比 | 不参与；验收用 `bytes`（同为 L3 口径） | 验收 |
| 7 | 数据面 sink 名与保留期 | `agent-flows`，保留期独立于 `agent-logs` | 数据面 |
| 8 | 拒绝类视图"不覆盖"的渲染 | 写成下游断言，不只是文档 | atlas / web |
| 9 | 采集范围（只留涉公网 vs 全采）怎么定、要不要开关 | **已定**：行为固定为「只留一端是公网的流量」（§10.2）。**不做本机配置** —— 规模化下没人会改每台的 `agentd.toml`，本机旋钮等于假配置面 | 已实现 |
| 10 | 采集范围要不要能按站点/主机下发 | 后续项：走**平台下发**（最近落点是 `discovery-policies:poll`），需 contracts + 网关 + 管理面配套；`FlowScope` / `scope_mode` map 已预留 | 契约变更 |
| 11 | 站点自定义内网段（VPC 用公网段） | 后续项：BPF 侧改用 LPM trie；本轮只认标准段（漏判方向是多采） | 选型 / 配置面 |
| 12 | 记录里的 `coverage` 怎么表达「东西向按口径不采」 | 现在只有 `host_partial`（语义是「看不到云侧策略提前丢的」），表达不了**故意的**范围缺口。下一班 contracts 火车新增一个取值（如 `host_public_peer`）并同步四侧渲染 | contracts + atlas/web 文案 |

## 14. 非目标

- 不补齐云侧安全组/NACL 的拒绝记录；
- 不与云流日志逐条一致，也不要求下游合并计算；
- 不采原始报文（payload）、不做抓包；
- 不做进程/socket 归属（pid/comm/uid）；
- 不观测 loopback 与容器/CNI 虚拟接口；
- 不做 ICMPv6 ND/MLD、链路本地与组播；
- 不做 NAT 前后双份地址（v1 只记 hook 上见到的地址）；
- 不涉及主机侧其他数据源、平台展示改造或部署配置。

## 15. 落地清单

**slice 1（Linux，TCP/UDP/IPv4）**

- `wist-contracts`：`HostFlowRecord`；source kind 词表加入 `HostFlow`；`is_executable_source` 认它；单测（词表、记录编解码）；
- agentd：BPF 程序 + 聚合 + flush + `write_flow` + `carries_flow_frames()`；三类 `unsupported` 分类；自观测计数器；`file` sink 跳过；
- 数据面：`FLOW:` 的 WPL 分支 + `agent-flows` sink；
- 真机验收：`cargo test --all -- --ignored`（`telemetry::flows` 与 `runtime::daemon_flows` 里的真机用例），
  TCX 与 netlink 两条 attach 路径各跑一遍（`WIST_FLOW_TC=tcx|netlink`）。

**slice 2（ICMP / IPv6 / 边界）**

- ICMP type/code 与端口口径（依 Q2 结果）；
- IPv6 地址、扩展头/分片、ND/MLD 过滤；
- 接口变化（ENI 热插拔、ifindex 复用）切窗与 `partial_reason=interface_changed`。

**slice 3（能力与运维）**

- 四侧同源：网关 `content.rs` 校验、web `agentWorkStatus.ts` 判据与文案；
- 知识库：`HostFlow` family + 单元 `active` + `catalog_version` 单独抬；
- 能力协商与降级重发；
- **netlink 路径的“被遮蔽”自检**（§10.1）：dump 同 hook 上的 tc 过滤器，若存在更小 `pref`
  的 `direct-action` 过滤器，就把这一面报成 `unsupported`/`run_failed`，而不是“在采但一条流都没有”；
- 容器部署（若需要）。

## 16. 上线顺序与兼容

1. **数据面先支持 ` FLOW: `**（WPL + sink），再放开 agentd 发帧；
2. 旧数据面收到未知标记会进 `raw_log` 兜底或掉 miss → **静默丢**，所以顺序不能反；
3. 旧 agentd 不认识 `HostFlow` kind → 必须如实报 `unsupported`，不能当无事发生（照 `log-source-exporters.md` §4 的降级规则）；
4. 能力协商**不往既有 v1 报文加字段**：`deny_unknown_fields` 会让旧读取方整份拒收。用新端点或新版本号承载"对端是否支持 `FLOW`"。

## 17. 验收口径

在同时开启云流日志的对照主机上：

- [ ] 分别产生入站/出站的 TCP、UDP，各含一条跨多个窗口的长连接；ICMP ping 一组（slice 2）；
- [ ] 五元组、方向、被观测网卡、时间窗可与云侧记录对齐；**无法对齐的逐条归因**（NAT、策略丢弃、口径差异），而不是笼统计入误差；
- [ ] 完整测试区间内核对总量与窗口切分；
- [ ] 云侧 `REJECT`、`NODATA`、采集起止边界、loopback/容器流量**单独列出**，不计入"流量误差"；
- [ ] ICMP 单独验收：不与 TCP/UDP 的五元组对齐标准混用；
- [ ] 仅存在主机来源时，云侧拒绝类视图显示"不覆盖"，不是 0；
- [ ] **不把"逐条相同""字段 1:1 等价"作为通过条件**；
- [ ] 关停/重启/暂停各一次，确认 `partial` 标记正确、无同一幂等键的重复记录。

## 18. 相关文档

- [`log-source-exporters.md`](./log-source-exporters.md)：source kind 词表与四侧同源、降级规则
- [`collection-status.md`](./collection-status.md)：采集状态（`AgentLocalCollection`）——本能力的失败分类映射到这里
- [`linux-security-audit-log-sources.md`](./linux-security-audit-log-sources.md)：Linux 采集面清单（`NetworkFirewall` 的边界）
- [`macos-agent-uplink-to-warp-parse.md`](./macos-agent-uplink-to-warp-parse.md)：上行帧与数据面接入
- [`metrics-data-spec.md`](./metrics-data-spec.md)：信封、`seq`、投递语义的既有约定
- [`agentd-service-deployment.md`](./agentd-service-deployment.md)：以 root systemd 服务运行的部署形态
- `src/telemetry/warp_parse.rs`：帧标记与 sink 路由的既有实现
- `wist-contracts/src/work.rs`：`EXECUTABLE_SOURCE_KINDS` / `is_executable_source`
- `wist-atlas` `doc/architecture/network-modeling-analysis.md`：流记录作为 runtime evidence 的定位
