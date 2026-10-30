# 流量镜像与 Suricata `eve.json` 采集方案

> 状态：**设计（待评审）**。规模相关的两个数（tick 预算、spool 上限）要在真机上量过再定。
> 本文只覆盖「流量怎么到检测点 → Suricata 怎么写 → agentd 怎么采 → 数据面怎么收」这条链路。

相关文档：

- [`log-file-input-spec.md`](./log-file-input-spec.md)：文件输入（tail / checkpoint / rotate / 文件族）
- [`agent-config-schema.md`](./agent-config-schema.md)：`[telemetry.logs]` 配置段
- [`self-observability.md`](./self-observability.md)：采集自观测（`telemetry input failed …` / `work-state paused`）
- `wist-knowledge/catalog.toml`：采集面 / 单元 / `match` 事实门
- `wist-contracts/src/work.rs`：`is_executable_source` / `LogsCapabilities`

---

## 1. 结论（先看这段）

1. **`wist-agentd` 今天就能采 `/var/log/suricata/eve.json`**，不需要新读法：
   `eve.json` 是**一行一条 JSON**，正好是文件输入器的默认形态（`multiline = none`），
   目标是一条**显式绝对路径**，`is_executable_source("FileGlob", "/var/log/suricata/eve.json")` 为真。
2. **不能在 agentd 里解析 JSON**（D1「只搬原文」）。归类/抽字段在数据面（wparse 的 WPL/OML），
   目录里 `rule_ref` 为空只代表「解析未就绪」，不影响采集。
3. **真正的缺口不是「能不能采」，是「跟不跟得上」**：agentd 原本每 tick（3s）对每条输入只读
   **一个批次**（上限 `max_lines_per_tick = 4096` 行 / `max_read_bytes_per_tick = 4 MiB`），
   即约 **1365 行/秒** 的硬上限。IDS 传感器是常态 5k~50k EPS，**差一个数量级**。
   **已落地（§5.4）**：tick 内改为带时间片的追平，上限由磁盘 / 出口决定，
   `catchup_slice_ms` / `catchup_budget_ms` 可调（`0` = 关回旧行为）。
4. **镜像配在 agentd 之外**（交换机 SPAN / TAP / ERSPAN / 主机 `tc`/OVS）。agentd 不做镜像：
   它是常驻采集控制器，不是网络配置执行器；把「改网卡」放进常驻循环，一次误配就把自己的
   控制面链路一起断掉。确实要自动化，走**一次性 ActionPlan**（§7）。
5. **控制面几乎不用改代码**：新增一个采集面 + 一个单元（数据），网关的可执行判定、web 的
   「可采/未接」、agentd 的 `log_inputs()` 全部按既有判据直接放行（§6）。

一句话：**采集能力已经在，要做的是「接线 + 提吞吐 + 把 Suricata 的写盘形态钉死」。**

---

## 2. 责任边界（四段）

| 段 | 负责者 | 产出 | 不属于本方案 |
|---|---|---|---|
| ① 流量镜像 | 网络设备 / 主机网络配置 | 目标网卡上有全量副本流量 | agentd 常驻配镜 |
| ② 检测与落盘 | Suricata | `/var/log/suricata/eve.json`（JSON Lines） | agentd 跑 IDS 引擎 |
| ③ 采集与上送 | **wist-agentd** | `TelemetryRecord` → spool → 数据面 | agentd 解析 eve 字段 |
| ④ 解析与归类 | 数据面（wparse） | 结构化事件 / 告警 / 资产关联 | — |

**agentd 明确不做**：

- 不配镜像（`tc` / `ovs` / 交换机）、不装 Suricata、不启停 Suricata —— 这些是运维变更，不是采集。
- 不解析 JSON、不拆 `event_type`、不按 `alert` 分流 —— 与 `audit.log`「不按 `type=` 丢行」同一条纪律。
- 不在同一台机器上再抓一份包（见 §11）。

---

## 3. 数据流

```text
      ┌──────────┐  SPAN/TAP/ERSPAN  ┌──────────────────┐
      │ 被观测网 │ ────────────────▶ │ mirror 网卡 (嗅探)│
      └──────────┘                   └────────┬─────────┘
                                              │ AF_PACKET / PF_RING
                                     ┌────────▼─────────┐
                                     │     Suricata     │
                                     └────────┬─────────┘
                                              │ 追加写（一行一条 JSON）
                                     ┌────────▼──────────────────┐
                                     │ /var/log/suricata/eve.json│
                                     └────────┬──────────────────┘
                                              │ tail（inode 跟踪 + checkpoint）
                         ┌────────────────────▼─────────────────────┐
                         │ wist-agentd（FileInputProcessor）        │
                         │  body = 原始行；offset/seq 由 agentd 补   │
                         └────────────────────┬─────────────────────┘
                                              │ TelemetryRecord → spool → uplink
                         ┌────────────────────▼─────────────────────┐
                         │ 数据面（wparse）：WPL/OML 解析、归类      │
                         └──────────────────────────────────────────┘
```

记录上带的字段（`wist-contracts::telemetry_record::TelemetryRecord`）：

| 字段 | 取值 | 用途 |
|---|---|---|
| `body` | **原始整行**（逐字，不裁剪不重排） | 数据面解析的唯一输入 |
| `source_path` | `/var/log/suricata/eve.json` | 来源定位 |
| `input_id` | `work-TrafficInspection-linux-suricata-eve` | 按输入排障 |
| `file_offset` / `file_offset_end` | 该行在文件中的字节区间 | 精确定位 / 对账 |
| `seq` | per-agent 全局单调 | 去重、断链判断（at-least-once） |
| `family` / `unit` | `TrafficInspection` / `linux-suricata-eve` | 采集面归属 |
| `observed_at` | **agentd 读到它的时刻** | 与 body 内 `timestamp` 相减 = 采集滞后 |

> 事件时间用 **body 里的 `timestamp`**（Suricata 写的）；`observed_at` 只表示「什么时候采到的」。
> 不要拿 `observed_at` 当事件时间 —— 重启回补、spool 重放都会让它偏后。

---

## 4. 采集形态：先钉死 Suricata 怎么写

### 4.0 路径形态：指定 / 搜索 / 输入 是三个不同的东西

「目标路径怎么写」在这个系统里有三条通道，**不能混用**：

| 通道 | 在哪个轴 | 谁写 | 产物 | 采集期行为 |
|---|---|---|---|---|
| **指定**（显式绝对路径） | 采集来源（`sources.target`） | 策展（知识库） | 一条 `FileGlob` 来源 | `FileInputProcessor`：单文件 + inode 轮转跟踪 |
| **搜索**（单层 glob / 目录） | 采集来源（`sources.target`） | 策展（知识库） | 一条 `FileGlob` 来源 | `FileFamilyProcessor`：文件族，新文件从 head |
| **候选发现 / 受限搜索** | **发现**（`search_roots`） | 知识库 ∩ 网关授权 | **候选**（上报给网关） | **不采**：采不采由网关判定 |
| **输入**（本机配置） | `[telemetry.logs.file_inputs]` | 本机 root | 一条本机输入 | 同上，但 `InputOrigin` 为空 = 手工配置 |

四条纪律：

1. **「搜索」不等于「自己找着采」**。真正的搜索是 `src/discovery/log_source/`：读
   `/proc` 证据（命令行 / 环境 / 配置 / 打开的 fd）推候选，最后一层才在
   **网关下发的 roots 交集**里有限搜索（roots ≤ 8、深度 ≤ 4、条目 ≤ 2000、≤ 2s，**不跟符号链接**）。
   产出是**候选**，经网关 `roots` 校验与优先级裁决后才会变成采集单元的 `target`。
   为什么不给 agentd 配置项：搜索等于允许一个 root 进程**枚举**客户机目录，这件事不该由
   主机上的一个文件决定（`control/source_search_policy.rs` 开头写的就是这句）。
2. **glob 展开不是运行时发现**，它是一段**写死的 pattern**：`*` 不跨目录、`**` 拒绝、
   `max_files = 512`、`max_new_files_per_tick = 32`、`rescan_interval = 15s`。
   pattern 写错的后果是「多采/少采」，不是「自适应」。
3. **本机 `file_inputs` 与平台派活是两条独立输入**：`run_tick` 先跑本机配置，再跑
   `work.log_inputs()`。同一个路径两边都写 = **同一个文件被读两遍**（`input_id` 不同、
   `seq` 都取号），下游看到的是重复记录。本机配置只能用于「平台没派这个面」的联调/兜底。
4. **路径是知识，不是偏好**。`source_path` 进数据帧、进历史、进对账，换一种写法就是换
   一类数据。所以它跟采集面一起版本化（知识库），不由页面手填。

### 4.1 Suricata 的四种写盘形态

同一个 `eve.json` 路径，Suricata 有四种写法，**只有前三种能被「一条显式路径」正确跟踪**。
采集形态由写盘形态决定，所以这一节是部署契约，不是建议。

| Suricata 配置 | 落盘形态 | agentd 该写什么 | 后果 |
|---|---|---|---|
| `filename: eve.json`（默认） | 单文件，持续追加 | `/var/log/suricata/eve.json` | ✅ 推荐 |
| `filename: eve.json` + 外部 logrotate（`create`/rename） | 改名 + 新建同名文件 | 同上 | ✅ 按 inode 跟到改名后的文件，尾巴读完再跟新文件 |
| `filename: eve.json` + `rotate-interval: day` | 同上（间隔内单文件） | 同上 | ✅ 同 logrotate |
| `filename: eve-%Y-%m-%d.json`（strftime） | **每个周期换新文件名**，不 rename | `/var/log/suricata/eve-*.json` | ⚠️ 必须用 glob；新文件从 head 读（W1），归档要 `exclude_globs` |
| `threaded: on` | **每个输出线程一个文件**（`eve.7.json`） | `/var/log/suricata/eve.*.json` | ⚠️ 必须用 glob；「多个文件的合集才是完整事件流」 |
| 两个 eve-log 实例（`eve-ips.json` + `eve-nsm.json`） | 两个独立文件 | 配置**两条** input | ✅ 推荐按用途拆分（告警量小、NSM 量大） |

**红线**：

- **不要用 `eve.json*` 这种通配去表达「单文件 + 轮转产物」**。轮转产物是历史，不是采集对象；
  通配会把 `eve.json.1`、`eve.json.2.gz` 一起纳入。单文件场景一律写**显式路径**。
- **`**` 永远不支持**（采集端不给递归上限）。`eve-*.json` 是一层目录内的单层 glob，合法。
- **logrotate 必须 `delaycompress`**（或干脆 `compress` + `delaycompress`）。原因见 §5.5：
  轮转后 agentd 靠 **inode** 找到被改名的旧文件把尾巴读完；一旦当场压成 `.gz`（inode 变了），
  这段尾巴就永久丢了。

---

## 5. agentd 侧

### 5.1 两种接法（不要同时用）

| 部署 | 写法 | 说明 |
|---|---|---|
| **平台下发（managed）** | 目录里的单元（§6），网关派活 | 推荐；机器换人配不用改 |
| **单机（managed + 本机配置）** | `[[telemetry.logs.file_inputs]]` | 仅用于「平台还没派这个面」的联调 / 兜底 |

> ⚠️ **同一个路径不要两边都写**。本机 `file_inputs` 与 `work.log_inputs()` 是两条独立输入
> （`run_tick` 两段各跑一遍），同一个文件会被读两遍、各取一套 `seq` —— 下游看到重复记录，
> 而且两边的 checkpoint 互不相干。

```toml
# /etc/wist-agentd/agentd.toml（单机联调用；平台下发时不需要写）
[[telemetry.logs.file_inputs]]
input_id = "suricata-eve"
path = "/var/log/suricata/eve.json"
# 默认就是 tail：只采新增。要回放历史是**一次性运维动作**，显式写 head。
# startup_position = "tail"
multiline_mode = "none"     # 一行一条 JSON

# 噪音减法（可选）：例如只在告警面采集时丢掉 stats 事件
# drop_if_contains = ['"event_type":"stats"']
```

> **`standalone` 模式不采集**（`[control_plane] enabled = false` 时整段 telemetry 停用）。
> 想「纯本地采集」，今天没有这条路 —— 必须是 `managed`（有网关）。这条限制先写在最前面，
> 免得现场按 standalone 装了却发现没数据。

### 5.2 读法（不需要新增任何模式）

- `multiline_mode = "none"`：一物理行一条记录。`eve.json` 每条事件**压成一行**，天然满足。
- `startup_position = "tail"`：授权派活不重放历史（`work.rs` 里是硬编码 `tail`）。
- 文件族（只有 §4 的 strftime / threaded 形态才需要）：运行中**新发现**的文件从 **head** 读
  —— 停机期间新建的 `eve-2026-10-30.json` 不会整段丢。
- 轮转：显式路径按 inode 跟踪，改名后读完尾巴再跟新主文件；truncate 检测到长度回退后从 0 读。
- checkpoint 落 `state/`，重启续读；**空 tick 不重写**（整目录 512 文件的全量状态每 3s 落盘是写放大）。

### 5.3 不解析（D1）

`eve.json` 的字段（`event_type` / `alert.signature` / `flow.bytes_toserver`…）**不进 agentd**。
理由与 `audit.log` 一致：

- 采集端解析 = 在边缘维护第二套规则，规则一改就要发 agentd 版本；
- `rule_ref` 是**解析就绪度**，不是采集闸门。目录里 `rule_ref = ""` 的单元照样能派下去采，
  记录只会归到泛化的 `agent.log` 下，等数据面规则补齐再翻成实体。

数据面需要的是：`body` 逐字 + `input_id`/`unit` 归属 + `seq`/offset 定位。这四样今天都有。

### 5.4 吞吐：这是本方案唯一的硬缺口

**现状**（`src/runtime/daemon.rs:86` + `src/runtime/daemon_telemetry.rs`）：
主循环 `TICK_INTERVAL = 3s`；每条 input 每 tick 调**一次** `process_once_async`，
而一次读最多 `max_lines_per_tick` 行 / `max_read_bytes_per_tick` 字节。

| 上限 | 默认值 | 折算 |
|---|---|---|
| `max_lines_per_tick` | 4096 行 | **≈ 1365 行/秒** |
| `max_read_bytes_per_tick` | 4 MiB | **≈ 1.33 MiB/秒** |

对照：20k EPS × 800 B/行 ≈ **16 MB/s**。差 **12 倍**。表现是 checkpoint 永远追不上文件尾，
spool 一路涨到 `spool_max_bytes`，然后 `pause` —— 「采了但一直在滞后」，比采不到更难查。

**方案 A（配置，立刻可用）**：把两个预算抬到传感器档位。

```toml
[telemetry.logs]
max_lines_per_tick = 65536          # ≈ 21.8k 行/秒
max_read_bytes_per_tick = 67108864  # 64 MiB ≈ 21.3 MiB/秒
```

代价：单 tick 变长，采集段占用主循环更久。控制面（工作授权 / 上送授权）排在采集**之前**，
不会被饿死；但发现 / 指标会顺延。**这只是把天花板抬起来，不是随负载自适应。**

**方案 B（代码，P1，已落地）**：把「每 tick 一批」改成**带时间片的追平**。

```text
tick:
  deadline = now + catchup_budget_ms        # 整轮采集段总预算（硬上限）
  for input in inputs:
    slice_end = min(now + catchup_slice_ms, deadline)
    loop:
      outcome = process_once_async()        # 仍是一批
      if outcome.read_lines == 0: break     # 已追平 / 文件为空
      if 出口写失败 or spool 暂停: break
      if now >= slice_end: break            # 让位给下一条 input
```

已实现的落点：

| 位置 | 改动 |
|---|---|
| `src/runtime/daemon_telemetry.rs` | `CatchupBudget`（片 + 硬预算）+ 每条输入的追平循环 |
| `src/telemetry/logs/files/{file,state_support}.rs` | `ProcessOutcome.read_lines`：本批真正读进来的行数（多行折叠 / 噪音丢弃 / 未封口块下都不能用记录数代替） |
| `src/runtime/daemon_telemetry.rs` | `InputTickReports`：多批的失败/计数**累加后拍末只报一次**（否则同一问题一拍打 N 次，毁掉按签名去重） |
| `src/config/agent_config.rs` | `catchup_slice_ms`（默认 400）/ `catchup_budget_ms`（默认 1800；`0` = 关闭追平） |

语义要点：

- 有效吞吐由**磁盘 + 出口**决定，不再由 tick 周期决定；
- 每输入一个**让位粒度**，一个疯长的 `eve.json` 不会把其它面饿死；
- **全局预算是硬上限**：片写得比它长也不会被放大（采集段不能吃掉整拍）；
- 判据是「**读到行**」而不是「产出记录」：`drop_if_contains` 全丢、多行未封口、
  `records_processed == 0` 都不等于「追平了」；
- 出问题就停：spool 暂停 / 出口写失败时不再继续追（继续读只会把 spool 堆得更高）。

代价（已知、有界）：追平会在同一拍里多次读状态 / 写 checkpoint，状态文件越大写放大越明显
（`eve.json` 这类单文件输入可以忽略；512 文件的文件族请把片调小）。**不碰** checkpoint / 轮转 / 多行语义。
验收：`daemon_run_once_catches_up_across_multiple_read_batches` /
`catchup_can_be_disabled_and_checkpoint_resumes_across_ticks`（`tests/local_exec/daemon_file_input.rs`）。

### 5.5 大行截断：JSON 行被截断 = 下游坏行

现状（`file_reader.rs`）：超过 `max_line_bytes`（默认 **1 MiB**）的行**截断后提交**，
计入 `truncated_lines`。对纯文本日志这是「丢一点尾巴」，对 **JSON Lines 就是产出一条永远解析不了的记录**。

三种处置，按推荐顺序：

1. **把 Suricata 侧管住**（零代码）：`alert` 不开 `payload` / `packet` / `http-body`；
   `tls.extended` 的证书链是最容易把行撑大的（几 KB～几十 KB，仍远小于 1 MiB）。
   只要不开 payload dump，1 MiB 足够。
2. **抬 `max_line_bytes`**（配置）：e.g. 4 MiB。代价是大行占内存与 spool 体积。
3. **给「超长行」加 `drop` 策略**（P1，代码）：`multiline` 是**格式**，`drop_if_contains` 是**内容**，
   都不适合表达「超长就丢」。要加就得新增一条**能力轴**
   （`WorkSpecSource.oversize` + `LogsCapabilities.oversize` + 网关裁源 + web 判据 + 知识库开单元），
   成本与 `drop_if_contains` 当年那批相当。**建议先做 1+2，把 3 放到有第二个 JSON 源的时候。**

无论走哪条，**`truncated_lines` 必须能在自观测里看见** —— 已落地：
`TelemetryFailureKind::TruncatedLine` 以 `warn` 级输出
`telemetry line truncated input_id=… path=… detail=… magnitude=lines=N`，按签名去重。
否则「下游为什么有坏 JSON」永远查不到源头。

### 5.6 spool 与磁盘

- 默认 `spool_max_bytes = 256 MiB`，`spool_over_limit = "pause"`（暂停采集 + 告警，**不丢**）。
- 定容公式：`spool_max_bytes ≥ 峰值速率 × 最长可容忍断链时长`。
  例：10 MB/s 采到 1 小时断链 → ≥ 36 GiB。**256 MiB 只够 IDS 断 25 秒。**
- `pause` 的语义是「停下读」，checkpoint 不推进；**这要求文件在恢复前不被删掉**。
  所以 logrotate 的保留策略（`rotate N` / `maxage`）必须覆盖「最长断链 + 追赶时间」，
  否则 spool 恢复时被轮转删除的那几段就是永久缺口（agentd 只能如实报 `MissingInput`）。
- spool 与 `eve.json` 放**不同卷**：采集盘写满会同时打崩 IDS 与 agentd。
- 写放大：每条记录进 spool + 进出口各一次，按 2~3× 峰值速率算磁盘 IO。

### 5.7 权限

- 系统级部署的 agentd 是 **root**（systemd unit），读 `/var/log/suricata/eve.json` 无障碍；
  目录里的单元写 `requires_privilege = "root"`，缺权限时如实进 `unsupported`，不静默少采。
- Suricata 侧建议 `filemode: 0640`（属主 suricata、属组 suricata）。不要 `0600`：
  那样只有非-root 的调试路径会踩坑。
- 开发机前台跑（非 root）：把用户加进 suricata 组，或临时放宽到 `0644`（仅联调）。
- SELinux enforcing 的机器若拒绝读取，按 `semanage fcontext -a -t var_log_t '/var/log/suricata(/.*)?'` 处理。

---

## 6. 控制面落点（五侧，其中三侧只是数据）

### 6.1 知识库（`wist-knowledge`）

**要不要新开面？开。** 判据不是「这是不是一个新数据源」（采集面不管能不能采），而是三件事：

| 判据 | `NetworkFirewall` 现状 | IDS 事件 | 结论 |
|---|---|---|---|
| 数据形态与消费者 | nft / iptables **规则快照**，KB 级一次 | alert / flow / NSM 事件流，GB/天 | 不同 |
| 容量与保留期 | 快照，无积压风险 | 本方案里唯一有 `pause` / spool 风险的面 | 差一个量级 |
| 旧面消费者会被迫学新格式 | 会（快照解析 vs 事件解析） | — | 应该拆 |

而且 `id` **只增不改名**、直接进数据帧与历史数据 —— 现在加是一行 TOML + 词表，
以后想从 `NetworkFirewall` 里拆出来就是破坏性变更。

新增一个采集面（**只增不改名**，`catalog_version` 单独抬一次）：

```toml
[[families]]
id = "TrafficInspection"
platforms = ["linux"]
name_zh = "流量检测"
name_en = "Traffic inspection"
summary_zh = "网络流量镜像点的入侵检测事件（Suricata eve.json）。"
summary_en = "IDS events from a mirrored traffic sensor (Suricata eve.json)."

[[units]]
unit_id = "linux-suricata-eve"
family = "TrafficInspection"
capability = "collect_logs"
platform = "linux"
# 事实门：文件在才采。没装 Suricata 的机器不该被派这一面。
match = "path_exists:/var/log/suricata/eve.json"
rule_ref = ""            # 解析未就绪：原文照进，归类等数据面规则
requires_privilege = "root"
# 显式绝对路径 = 今天所有 agentd 都能执行的形态，可以直接 active。
status = "active"

[[units.sources]]
kind = "FileGlob"
target = "/var/log/suricata/eve.json"
multiline = "none"
```

要点：

- `match` 用 **`path_exists`**（`;` 是 AND、`|` 是 OR、`any:` 前缀可包多条件）。
  不用 `installed:suricata`：容器化 / 静态编译装法的机器会判成「没装」，而文件才是真前置条件。
  网关的路径探测白名单是**从目录里的 `path_exists` 推导**的（`agent_ops.rs`），加了条件就自动探。
- 若采用 §4 的 strftime / threaded 形态，`target` 换成 `/var/log/suricata/eve-*.json`
  （或 `eve.*.json`），并加 `exclude_globs = ["/var/log/suricata/*.gz"]`。
- 采集范围拆分建议（**单元层，不是面层**）：告警与 NSM 拆成两个单元
  （`eve-ips.json` / `eve-nsm.json` 两条 input、两个 `unit_id`），因为两者的量级、保留期、
  下游规则完全不同；合成一条会让「告警掉数据」淹没在 flow 日志里。
  两者仍属同一个面 —— 它们回答的是同一个问题：「这台机器看到了什么网络事件」。
- **不开 `search_roots`**：那个字段是给「服务装在非标准目录、进程证据也说不清」的兜底（目前只有
  `linux-db-service` 预留）。Suricata 的输出路径由它自己的 yaml 决定，**是已知的**；
  开搜索只是把 root 枚举面变大、换不到覆盖。真遇到非标准安装，先用 `path_exists` 加一个候选，
  或在本机 `file_inputs` 里覆盖（§5.1 的重复采集警告仍适用）。
- **模型侧同批改**：`wist-design/jumo/model/static/control/module/agent/content/families.mju`
  的面词表要加上同一个 `TrafficInspection`（CI 会校目录与模型的一致性）。

### 6.1.1 一个面够不够：MVP 就一个，不要提前拆

MVP 的形状是 **1 面 : 1 单元 : 1 来源**：

```text
TrafficInspection                      ← 面：数据归属（进帧 family）
  └─ linux-suricata-eve                ← 单元：可派活粒度（进帧 unit）
       └─ FileGlob /var/log/suricata/eve.json   ← 来源：真读什么
```

对应的 `input_id` 是 `work-TrafficInspection-linux-suricata-eve`（`work-{family}-{unit}`），
它就是 checkpoint 文件名与排障粒度。**面不是越细越好**：每个面都会出现在词表、覆盖度、
包组合、web 页面和下游规则里，空面也是成本。

**什么时候必须开第二个面**（而不是在一个面里加单元）：三个维度**同时**反向时。

| 维度 | 告警（alert/anomaly/drop） | 流量元数据（flow/dns/http/tls） |
|---|---|---|
| 语义 | 「打中了哪条规则」 | 「网里跑了什么」 |
| 容量 / 保留 | 小、秒级、要长留 | 大、分钟级可、短留可 |
| 下游消费者 | 告警处置 / 工单 | 资产画像 / 行为基线 |

所以：

- **现在只开一个 `TrafficInspection`。**（§12 决策 1：先 alert+stats）
- **将来真要开 `flow` 时，开第二个面（如 `TrafficFlow`），不要塞进 `TrafficInspection`。**
  因为两者容量反向，挤在一个面里会让「这一面的保留期/容量」无法同时成立。
- **加面是追加式的、安全的**（新 id、新单元，不动旧数据）；**拆面是破坏性的**
  （已采数据的 `family` 改不了，只能双写/回溯）。所以判断标准是：
  **等 `flow` 真的开了、量真的量过了，再按数据拆**；今天不预拆。

命名上也别叫 `TrafficCollection` / `流量采集`：`family` 描述的是**数据是什么**，
不是我们做了什么动作。`采集` 是所有面共有的动作，放进 id 只会让后面每个面都长成 `XCollection`。

### 6.2 包 / 模板（`packs.toml` / `templates.toml`）—— 已落地

- **已加** Feature 包 `linux-ids`，`unit_refs = ["linux-suricata-eve"]`，
  **不塞进** `linux-base`：基线包是「每台 Linux 都要采的面」，IDS 传感器是少数机器。
- **挂在哪几个模板**：机器类别是**闭集**（`MacDaily / MacDev / LinuxHost / LinuxCompute / LinuxData`），
  加一个 `LinuxSensor` 要同时动模型与网关。所以 `linux-ids` 挂到**三个 Linux 模板**上
  （`linux-compute` / `linux-data` / `linux-host`），靠单元的 `path_exists` 事实门收敛：
  没装 Suricata 的机器只是不展开这个面（预检里一条 `fact_not_collected`）。
  包在模板里**不等于**可以派 —— 真正的闸门始终是单元的 `match`。

### 6.3 契约 / 网关 / web

| 侧 | 需要改吗 | 依据 |
|---|---|---|
| `wist-contracts` | **不用** | `is_executable_source("FileGlob", "/var/…/eve.json")` 已为真；`LogsCapabilities.file_inputs` 已上报 `absolute-path` |
| `wist-gateway` | **不用** | 单元至少一条可执行来源即 `active`，`validate_unit` 直接放行；`path_exists` 探测白名单从目录推导 |
| `wist-gateway-web` | **不用** | `isExecutableSource()` 对绝对路径恒真，「可采」灯自动亮 |

也就是说：**只有知识库是内容改动，agentd 侧是配置 + 吞吐改造。** 这一点决定了本方案可以很短地上线。

---

## 7. 镜像侧（不在 agentd 内）

### 7.1 四种手段

| 手段 | 位置 | 适用 | 代价 |
|---|---|---|---|
| 交换机 SPAN（端口镜像） | 交换机 | 通用；一个口做目的口 | 需要网络变更；注意镜像方向（ingress/egress/both） |
| 网络 TAP | 链路中间 | 高保真、不丢包 | 硬件；需要断链窗口 |
| ERSPAN | 交换机 → 主机 GRE | 跨机房把流量送到分析机 | 封装开销、MTU、GRE 配置 |
| 主机 `tc` / OVS mirror | 主机 | 单机自检、k8s 节点 | 只看到经过**这台主机**的流量；桥/网关位才有价值 |

`tc` 最小形态（**示例，不是 agentd 会执行的东西**）：

```bash
tc qdisc add dev eth0 handle ffff: ingress
tc filter add dev eth0 parent ffff: protocol all u32 \
   match u32 0 0 action mirred egress mirror dev mirror0
```

Suricata 侧把 `af-packet.interface` 指到 `mirror0`（或 `pcap` 模式读该口）。

### 7.2 为什么不做进 agentd

1. **故障归因**：「没有告警」到底是镜像断了、Suricata 挂了、还是采集停了？
   混进同一个组件，就没有第三方可以对照。分开后各段的健康信号是独立的。
2. **风险等级不同**：改网卡是一步到位的断网风险；采集是只读的。常驻循环里不该有前者。
3. **红线**：agentd 不允许「无具名约束的任意命令」（`log-source-exporters.md` §7）。
   镜像参数（接口名、方向、目标口）是**现场可变**的，做成具名 opcode 也需要白名单拆分，
   收益远小于成本。
4. **生命周期不同**：镜像是「装一次、验一次、很少改」；采集是「每 3 秒都在跑」。

### 7.3 如果确实要自动化

走**一次性 ActionPlan**（`src/exec/` + `wist-exec`），不做常驻：

- 具名 opcode（如 `net.mirror.apply` / `net.mirror.clear`），参数窄校验（接口名白名单、方向枚举）；
- **幂等**：先查后改，已是目标状态直接返回 `no_op`；
- **超时 + 自动回滚**（`clear` 原语必须存在，且回滚路径不依赖本次新增的配置）；
- **前置守卫**：目标口不能在 agentd 自己的控制面路径上（否则一次误配就失联）；
- 结果进执行结果上报，不进采集自观测。

这台机器上的**只读健康信号**仍由 agentd 提供（不需要新能力）：
`eve.json` 是否存在（`MissingInput`）、是否还在增长（记录流是否停滞）、`work-state paused`。

---

## 8. Suricata 侧最小配置（部署契约）

```yaml
outputs:
  - eve-log:
      enabled: yes
      filetype: regular
      filename: eve.json          # 固定名（不要 strftime，否则要改采集为 glob）
      #threaded: off              # 一定保持 off：开了就是每线程一个文件
      #buffer-size: 0             # 默认 0 = 同步写；非 0 会有「写了但没落盘」的窗口
      filemode: 0640              # 0640 而不是 0600
      types:
        - alert
        # - flow                  # 量最大的一项；先确认容量再开
        # - stats
        # - dns / http / tls ...  # 按需
```

四个开关的后果（写在这里，避免上线后被当成 agentd 的 bug）：

| 开关 | 若打开 | 后果 |
|---|---|---|
| `threaded: on` | 文件名变成 `eve.N.json` | 单路径采不到；必须整族 glob |
| `filename` 含 `%` | 每周期换名 | 同上；且「当前文件」概念消失，延迟取决于轮转对齐 |
| `buffer-size > 0` | 数据滞留内存 | 需配 `heartbeat.output-flush-interval`（1~60s）才有限度；采集端看到的延迟 = 刷盘延迟 |
| `alert.payload: yes` | 事件带上负载 | 行变大（`payload-buffer-size` 默认 4kb），且**敏感数据进入全链路** |

logrotate（若用外部轮转）：

```text
/var/log/suricata/eve.json {
    daily
    rotate 7
    missingok
    notifempty
    copytruncate   # ← 不推荐
    # create 0640 suricata suricata   ← 推荐
    delaycompress  # ← 必须：让 agentd 先把改名后的尾巴读完
    compress
}
```

`copytruncate` 的坑：copy 与 truncate 之间的写入会丢；agentd 当时**还没读完的那段尾巴**也随
这次 truncate 一起消失（同 inode 的长度回退只会让它从 0 重读，不会去追那份副本）。
重命名式轮转 + inode 跟踪才是完整语义。

---

## 9. 验收（真机，逐条可判定）

| # | 场景 | 命令 / 动作 | 判定 |
|---|---|---|---|
| 1 | 端到端 | `echo '{"event_type":"test","n":1}' >> /var/log/suricata/eve.json` | 数据面收到 `body` **逐字相同**、`source_path` 正确、`seq` 连续 |
| 2 | 轮转不丢 | `mv eve.json eve.json.1 && touch eve.json` | 改名文件尾部被读完，再跟新文件；无重复、无缺口（按 offset 对账） |
| 3 | 截断 | `truncate -s 0 eve.json` | 从 0 重读，不重复 |
| 4 | 追赶 | 生成 10 万行再启动 | 一段时间后 `file_offset` 追上 `stat -c %s`（方案 A/B 的差别在这里看） |
| 5 | 断链 | 停数据面 5 分钟 | spool 增长；恢复后按 `seq` 连续补发；`pause` 只在超限时出现 |
| 6 | 大行 | 写入 2 MiB 单行 | 截断可见（`truncated` 计数上自观测），下游知道这是坏行 |
| 7 | 权限 | `sudo -u nobody` 跑 `wist-agentd diagnose` | `telemetry.inputs` 明确 FAIL「不可读」，而不是「没有数据」 |
| 8 | 幂等 | 重启 agentd | 不重放历史（checkpoint 续读），`seq` 不跳号 |
| 9 | 事实门 | 在没有该文件的机器上派 `linux-ids` | 单元被 `match` 裁掉，不产生 `MissingInput` 噪音 |

第 4 条是本方案的验收分水岭：**能不能追上文件尾**。建议在真机上直接量：
`eve.json` 每小时增长量 ÷ 3600 = 需要的最低字节速率，与 §5.4 的实际上限比。

---

## 10. 落地批次

| 批次 | 内容 | 代码量 | 依赖 |
|---|---|---|---|
| **P0 接线**（1 天级） | 知识库新增面/单元/包 + `catalog_version` 抬版；Suricata 配置与 logrotate 契约；文档 | 无数值代码 | 无 |
| **P0 调参**（现场） | `max_lines_per_tick` / `max_read_bytes_per_tick` / `max_line_bytes` / `spool_max_bytes` / spool 卷 | 无 | 峰值速率实测 |
| **P1 吞吐**（✅ 已落地） | tick 内带时间片追平（方案 B）+ `read_lines` 进度位 + 失败拍末聚合 + 单测 | 中 | P0 实测数据 |
| **P1 可观测**（✅ 已落地） | `truncated_lines` → `telemetry line truncated`；`diagnose` 新增 `telemetry.inputs`（输入存在/可读，glob 只看固定前缀目录，匹配为空不算错） | 小 | 无 |
| **P2 超长行策略** | `oversize = truncate｜drop` 四侧同源 | 中 | 出现第二个 JSON 源时再做 |
| **P2 镜像自动化** | 一次性 ActionPlan 具名 opcode（apply/clear/回滚） | 中 | 真有「批量开镜」需求时再做 |

---

## 11. 不在本方案

- **agentd 自己抓包**（AF_PACKET → pcap → 上送）。Suricata 已经做了解码、流重组、规则匹配；
  在采集端再抓一份只增加 100% 的 I/O 与特权面，且 pcap 的格式/切分/清理是一整套新状态机。
  如果将来真需要「原始包留证」，正确形态是**新的 source kind**（`PacketCapture`）+
  独立的 spool 与保留策略，不是塞进 file input。
- **agentd 解析 eve 字段**（D1）。
- **Suricata 的安装 / 升级 / 规则更新**：属于发布与配置管理，走制品与 `wist-exec` 动作，不走采集面。
- **多传感器汇聚 / 去重**：数据面职责（按 `agent_id + input_id + seq` 或 `community_id`）。

---

## 12. 待决策点

1. **采集范围**：只采 `alert` + `stats`，还是也采 `flow` / `dns` / `http` / `tls`？
   `flow` 通常占 eve.json 的 80%+，直接决定 §5.4 / §5.6 的容量结论。**建议先 alert+stats，量过再开 flow。**
2. **机器类别**：新增 `LinuxSensor` 类，还是把 `linux-ids` 挂到现有 Linux 模板上靠 `match` 收敛？
   **已定（后者）**：类别是闭集，加一个要同时改模型与网关；`linux-ids` 已挂到三个 Linux 模板，
   闸门是单元的 `path_exists`。将来传感器多了再单独立类。
3. **`max_line_bytes` 与 payload**：确认 Suricata 侧**永久关闭** payload dump 吗？
   关 → 1 MiB 够用；不关 → 建议 4 MiB，并考虑 P2 的 `drop` 策略。
4. **轮转方式**：Suricata 内部 `rotate-interval` + 固定名，还是外部 logrotate？
   两者都能被显式路径跟踪；**建议外部 logrotate（`create` + `delaycompress`）**，
   因为可调保留期、可按大小切、可压缩，且不改 Suricata 的重启语义。
5. **是否拆两个 eve-log 实例**（`eve-ips.json` / `eve-nsm.json`）？
   **建议拆**：告警面与 NSM 面的容量、保留、下游规则是三件不同的事。
6. **P1 时间片取值**：`PER_INPUT_SLICE` 与 `TICK_TELEMETRY_BUDGET` 需要真机标定
   （建议起点 400ms / tick 的 60%），不在设计阶段拍死。
