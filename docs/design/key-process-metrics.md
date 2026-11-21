# 关键进程指标：采集面授权与匹配语义

> 状态：**已实现（契约 / 网关 / 前端 / agentd / 知识库）**；端到端验收待做。
>
> 实现落点：
> - 契约：`wist-contracts` **0.12.0**（已发布）—— `CollectionSourceKind::KeyProcessMetrics`、
>   `parse_key_process_target()`；
> - 网关：`app::content::is_collectable_source` 认这个来源（`target` 须是可解析的签名列表）；
> - agentd：`control::work::key_process_grant()` + `telemetry::metrics::key_process`
>   （签名匹配、分组、代表选择、上限）。
>
> 决策记录（2026-11-21，评审已定）：
> 1. 代表进程 = **同组内 PID 最小**（worker 在 master 之后 fork，PID 更大）；
> 2. **macOS 第一版不支持**（缺 `service.unit`），能力上报如实声明；
> 3. atlas 只存**实体**（谁在这台机器上、属于哪个服务）；`process_state` /
>    `memory_rss_kib` 这类**最新读数不入库**，查询时去 VictoriaMetrics 取；
> 4. **裸跑长驻进程要覆盖** → 引入 `cmdline:` 签名，但只用于匹配、永不落盘。
>
> 前置依赖：**无**。指标的唯一落点是 VictoriaMetrics，关键进程面做完即可被查询；
> atlas 不再需要 telemetry 管道（见 §12 第 0 步）。
>
> 相关：[metrics-inventory.md](./metrics-inventory.md)、[metrics-collection-runtime.md](./metrics-collection-runtime.md)、
> [metrics-data-spec.md](./metrics-data-spec.md) §10。

## 1. 问题

0.35.0 停掉了逐进程指标采集（当时的 `src/telemetry/metrics/target_view.rs` 里有一个
`PROCESS_METRICS_COLLECTION_ENABLED = false`，0.36 已删除，见 §12.1），理由有三条，其中两条至今成立：

1. `CollectionSourceKind`（`wist-contracts/src/work.rs:292`）里**没有进程类来源** ——
   没有任何工作能授权它；
2. 上送只有 3 条随机样本：`SAMPLE_LIMIT = 3`（`src/telemetry/metrics/runtime.rs:393`）
   把 950 个目标截成 3 条，其余记 `dropped_targets`；而这 3 条是候选顺序前 3 个
   （≈ PID 最小那几个），既无代表性也无法解释；
3. 没有消费方（当时的判断）。

但「**关键进程**的指标」是一个真实需求，与「全部进程的指标」完全不同：

- 运维要回答的是「那个服务还活着吗、吃多少内存、什么时候起的」；
- 950 个进程全采 = 950 × 约 5 条 fact ≈ 4750 条序列/批，每 3s 一批，基数不可接受；
- 关键进程的数量是**服务个数**量级（几十），有界、可解释、稳定。

**结论：把"关键进程"做成一个采集面，用「选」而不是「截断」。**

## 2. 不变量

1. **用户只做选择，不做编写。** 现场看到的是一个勾选项（「Kafka 关键进程指标」），
   不需要知道 `unit:` / `exe:` / `port:` / `cmdline:` 是什么，也不需要知道 kafka 的 exe 其实是 `java`。
2. **匹配面是策展知识。** 「kafka 长什么样」写进知识库、走审定与版本，不进 agentd、
   不进用户视野。判据改了就重新发知识包，不发 agentd。
3. **目标只来自本机。** 与四个外部系统来源（`KafkaCluster` / `MysqlInstance` /
   `PostgresInstance` / `DorisCluster`）同一条纪律：授权只说「采不采」，
   不指定主机上的具体进程/地址。签名是本机信号的描述，不是远端地址。
4. **未知签名前缀必须拒。** 整份 spec 判 `unsupported`，不允许"看不懂就跳过"——
   那会让一个配错的授权变成静默无数据。
5. **`matched = 0` 必须可见。** 授权了但一个进程都没匹配到，要出现在采集记账里，
   不能空转。
6. **上限先于功能。** 一个签名可能命中多个进程，必须有上限与确定性的代表规则，
   否则又退化成"任取一个"。
7. **cmdline 只能用来匹配。** 它不进行任何持久化结构、不发现快照、不上送、不进诊断包
   （理由见 §9）。

## 3. 分层职责

| 层 | 谁维护 | 内容 |
|---|---|---|
| 用户 / 管理面 | 现场 | 勾一个采集单元：`Kafka 关键进程指标` |
| 知识库（策展） | 平台 | 单元 → 签名的映射；`match` 表达式决定该单元只在可能有它的机器上出现 |
| 契约 | 平台 | `KeyProcessMetrics` 种类 + target 语法 + 未知前缀拒绝 |
| agentd | 本机 | 机械匹配签名、选代表进程、上限、`matched`/`dropped` 记账 |

**agentd 不认识 "kafka" 这个词。** 它只解析结构化签名并比对本机事实，一行"猜名字"的逻辑都不需要。

## 4. 授权形态：采集面 + 单元

与 `linux-host-metrics`（`wist-knowledge/catalog.toml`）完全同构：

```toml
[[families]]
id = "ProcessMetrics"
platforms = ["linux"]
name_zh = "关键进程指标"
summary_zh = "按策展签名选出的关键进程的运行指标（每服务一个代表进程）。"

[[units]]
unit_id = "linux-keyproc-kafka"
family = "ProcessMetrics"
capability = "collect_metrics"
platform = "linux"
# 只在装过 kafka 的机器上露出来：不给所有人看一个永远匹配不到的选项。
# 只用**有探针**的条件（`installed:` 目前恒为“无法判定”，写它等于永不展开）。
match = "any:path_exists:/etc/kafka|path_exists:/opt/kafka|port:9092"
rule_ref = "agent_uplink"          # 指标帧仍由 agent_uplink 承接，同 host-metrics
# 带 `port:` 要读别的用户的 fd / netns（见 §9.4）。
requires_privilege = "root"
min_agentd_version = "0.36.0"     # `KeyProcessMetrics` 从这一版才有
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "15s"                 # 周期只有这一处（§“为什么是两条 source”）

[[units.sources]]
kind = "KeyProcessMetrics"
target = "unit:kafka|port:9092|exe:kafka"
```

裸跑进程（手工起的、没有 systemd 单元的长驻服务）：

```toml
[[units]]
unit_id = "linux-keyproc-app-jar"
family = "ProcessMetrics"
capability = "collect_metrics"
platform = "linux"
match = "path_exists:/opt/app"
rule_ref = "agent_uplink"
# 只靠 `cmdline:` 不需要提权：`/proc/<pid>/cmdline` 是 0444（实测 `nobody` 也读得到）。
# 带 `port:` 才需要 root（要读别人的 fd / netns），见 §9.4。
requires_privilege = "none"
status = "active"

[[units.sources]]
kind = "MetricInterval"
target = "30s"

[[units.sources]]
kind = "KeyProcessMetrics"
target = "cmdline:app.jar"
```

### 为什么是两条 source

`WorkSpec::metric_interval_seconds()`（`wist-contracts/src/work.rs:561`）只认
`kind == "MetricInterval"`。**周期与"采什么"分开声明**，这样：

- 不用改那段已有的取最密间隔逻辑；
- 一个单元可以带多条 `KeyProcessMetrics`，周期仍然只有一处。

## 5. target 语法

```text
target  := signature ( "|" signature )*
signature := prefix ":" value
prefix  := "unit" | "exe" | "port" | "cmdline"
value   := 非空、不含 "|" 与空白的字符串
```

**语义是「或」**：任一签名命中即算这个单元采到了。

| 前缀 | 匹配的本机事实 | 取值来源 | Linux | macOS |
|---|---|---|---|---|
| `unit` | systemd 单元名包含 `value`（大小写不敏感子串） | `service.unit`（cgroup，`src/discovery/process.rs:163`） | ✅ | ❌ 恒为 `None` |
| `exe` | 可执行名 basename 等于 `value`（大小写不敏感） | `process.executable.name`（`exe → argv[0] → comm`，`src/discovery/process.rs:225-233`） | ✅ | ✅ |
| `port` | 该进程持有 `value` 端口的监听 socket | endpoint / `db_source` 的端口反查 | ✅ | ✅ |
| `cmdline` | `argv` 里**有且仅有一个 token 与 `value` 完全相等** | `/proc/<pid>/cmdline`（**只在内存里读，不落盘**，见 §9） | ✅ | ❌ v1 不支持 |

**`cmdline` 用"token 完全相等"而不是子串**，两个理由：

- 子串会误命中：`-Dkafka` 这类参数、路径里恰好含 `kafka` 的无关进程都会中；
- 完全相等可评审：`cmdline:app.jar` 与 `cmdline:kafka.Kafka` 各自只指向一种启动形态，
  漏了就在知识库里补一条，而不是把匹配放宽成"大概像"。

**注意值是 token 原文，不做 basename 归约**：`java -jar /opt/app/app.jar` 要写
`cmdline:/opt/app/app.jar`，写 `cmdline:app.jar` **不会命中**。理由同上：argv 里大量 token 是路径
（classpath / 配置路径），basename 相等会让 `cmdline:kafka` 把 `-cp /opt/kafka` 也当成命中。
路径无关的写 `unit:` / `exe:`；机器特有的路径走 §10 的现场覆盖，不进知识库。

**校验规则（硬性）**：

- 未知前缀、空 target、空 value、值里含空白或 `|` → **整份 spec 判 `unsupported`**；
- 与既有纪律一致：`is_executable_source` / `accepts_target` 那一层就把不合法的挡掉
  （`wist-contracts/src/work.rs:583`），不留给运行期"尽力理解"。

**为什么不做"裸词自动回退"**（`target = "kafka"` 然后依次试 unit → exe → port）：
回退链是隐式知识，配错时无法解释"为什么没采到"，也无法评审。显式写死前缀后，
"某台机器上采不到"可以精确指到是哪条签名没命中。

## 6. 跨平台差异

| 能力 | Linux | macOS | 说明 |
|---|---|---|---|
| `service.unit` | 有（systemd cgroup） | **没有**（`service_unit: None`） | 要补需采 launchd label（`launchctl list`） |
| `container.id` | 有 | 没有 | 本设计未用，作为将来的补充签名 |
| `process.executable.name` | 有（`/proc/<pid>/exe` 全路径） | 有（`ps comm` 全路径） | 0.35.0 起两端同口径，见 CHANGELOG |
| 端口反查 | 有 | 有 | 复用 endpoint 探针的既有实现 |
| `cmdline` | 有（`/proc/<pid>/cmdline`） | 无（`ps -axo command=` 会给，但 v1 不做） | — |

**决策：第一版只开 `platforms = ["linux"]`。**

macOS 缺 `service.unit`，用 `exe:` 认不出 Homebrew 启动脚本（`kafka-server-start` 的 exe 是 shell）
和 launchd 拉起的 JVM；`cmdline` 侧也没有实现。宁可在能力上报里如实说"只有 Linux 有这个面"，
也不要给出一个在 macOS 上大概率采不到的面。

补 launchd label 是将来让 `unit:` 在 macOS 成立的自然路径，但不在本次范围。

## 7. 代表进程与上限

一个签名命中多个进程是常态（nginx 1 master + N worker、kafka 多 JVM、容器内多进程）。

### 7.1 分组

先按**归属**分组，再在组内选代表：

| 组键 | 取值 | 说明 |
|---|---|---|
| `service.unit` | 有则用 | `kafka@0.service` / `kafka@1.service` 是两个实例，各选一个代表，不能合并 |
| `container.id` | unit 为空时用 | 容器内进程各自成组 |
| 命中的那条签名（`sig:<prefix>:<value>`） | 都没有时用 | 裸跑进程按“哪条签名命中”分组 |

**为什么兜底不是“整个命中集合算一组”**（设计初稿的写法）：两个互不相干的关键进程
（`cmdline:app.jar` 与 `cmdline:worker.py`）会被合成一个组，最后只报一个代表 —— 少报且没法解释。

### 7.2 组内选 PID 最小

**决策：同组内取 PID 最小的那个。**

依据：worker 是在 master/父进程**之后** fork 的，PID 必然更大 ——
所以"PID 最小"在同一组里就是控制进程本身，正是"最能代表这个服务"的那个。
这比"RSS 最大"稳：RSS 会随负载抖动，跨拍换人；PID 不会。

三个边界要写清：

- **PID 回收不构成误认**：进程身份用的是启动令牌（`ps_lstart:` / `linux_proc_start:`），
  不是 PID；PID 被回收给新进程时，令牌跟着变，代表进程换人是**正确**的（确实是新实例）。
- **master 重启 → 代表换人**：同上，这是真实变化，不是抖动。
- **PID 回绕**（`pid_max` 耗尽后从头分配）：理论上能让子进程 PID 小于父进程，
  概率极低且只在超长 uptime 的机器上出现。**不为此增加复杂度**，也不做特殊处理。

## 8. 可观测性

采集记账沿用现有三分类，口径写清：

| 情形 | 记账 |
|---|---|
| 采到了 | `succeeded`（按组计，一组一个代表） |
| 匹配到了但读取失败（进程刚退出等） | `failed` + `last_error` |
| 组数超上限被裁掉 | 只进日志（`event=KeyProcessDropped`）+ 采集结果的 `dropped_targets` 仍为 0（目标压根没成为目标） |
| **签名一条都没命中** | 面的采集结果报 `target_not_ready`，明细就是 `no process matched <签名>`（另有一行 `event=KeyProcessNoMatch` 日志） |

最后一行是硬要求：现场最常见的困惑是"授权了、但没数据"，必须能立刻区分
「没装」「签名配错」「agent 不支持这个前缀」。

链路：选目标在**发现拍**（要读 `/proc/<pid>/cmdline`），采集记账在**指标 tick**，
两者之间只有 `metrics_target_view.json` 一个通道 —— 所以原因写进视图的
`process_selection_error`，由指标 tick 带到 idle 的 process outcome 上，
`collection_health` 再把它报成 `target_not_ready`。

**上限**：契约里有 `CapabilityLimits.max_metrics_targets`
（`wist-contracts/src/capability_report.rs:136`），但它**今天仍没有任何代码读它**。

**当前实现用的是内建常量**：`key_process::KEY_PROCESS_TARGET_LIMIT = 50`
（量级 = 常见服务数）。下发通道没接，所以"按下发上限裁"还没生效 ——
要接的话在 `select_key_process_candidates` 的 `limit` 参数那一处换成读取能力上报的值。

**按组裁掉的量只进日志**（`event=KeyProcessDropped groups=… dropped=… limit=…`），
不重复计入采集结果的 `dropped_targets`：后者的语义是"有这个目标但没给样本"，
而这里压根没成为目标。两者混在一起就是 0.35.0 那个让人看不懂的 `dropped=947`。

## 9. 裸跑长驻进程：`cmdline:` 签名

有些关键服务既没有 systemd 单元、也不一定占着知名端口（手工起的 `java -jar`、
`python app.py`、带自定义端口的内部服务）。`unit:` / `exe:` / `port:` 都可能落空，
只能用启动命令行来认。

### 9.1 做法

- **只在发现拍（300s）匹配**，不在 3s 的指标 tick 上做。发现拍本来就在遍历 `/proc`，
  多读一次 `cmdline` 的成本是"每 300 秒 950 次小文件读"，可接受；放在指标 tick
  就是"每 3 秒 950 次"，不可接受。
- **匹配完只保留结论**：命中的候选只写 `pid + 命中签名 + 归属`，
  `cmdline` 原文读完就丢。
- 指标 tick 仍然只查那张进程表（`sys_proc::snapshot()`），与现在一致。

### 9.2 为什么必须"读完就丢"

`cmdline` **经常带凭据**：`--password=...`、`--ssl.keystore.password=...`、
JDBC URL 里的口令。一旦让它进入任何持久化结构，就等于：

- 本地 `state/discovery/*.json`、`planner_candidates` 里躺着明文口令；
- 诊断包（`investigate`、`diagnose` 收集物）带出去；
- 上送链路里出现口令。

所以这是**硬约束**（§2 第 7 条）：`cmdline` 是匹配输入，不是采集内容。
落盘/上送的候选只含派生结论。

### 9.3 代价与收窄

950 个进程各读一次 `cmdline`，其中绝大多数与签名无关。两个可选的收窄手段
（实现时按实测决定，不写死）：

- 只对**存活超过 N 分钟**的进程读（短命进程不可能是"关键进程"，且 `start_token`
  已经给出启动时刻，不需要额外成本）；
- 签名集合为空时整段跳过（没授权 `cmdline:` 就不读）。

### 9.4 权限

`/proc/<pid>/cmdline` 是 **0444 世界可读**，实测非 root 用户（`nobody`）也能读别的用户的
进程命令行，所以**单纯用 `cmdline:` 签名不需要提权**。

两类例外：

- 单元里同时用了 `port:` → 需要 root（要读别的用户的 fd / netns，与数据库自探同一类原因）；
- 内核挂了 `hidepid=2` 的机器 → 非 root 看不到别人的 `/proc/PID` 目录本身，那时 `cmdline:` 也需 root。

所以 `requires_privilege` 由**该单元用了哪些签名**决定，而不是一律写 `root`：
只 `cmdline:` / `exe:` → `none`；含 `port:` → `root`。网关按此做派单闸门。

## 10. 不在清单里的进程

与 `DatabaseService` 的既有做法一致（`catalog.toml` 注释：「装在别处仍然靠管理面的人工覆盖」）：

- **常见进程** → 提新单元进知识库，走审定，`catalog_version` +1；
- **现场特殊** → 管理面人工覆盖，只对那一台机器生效。

**不提供"随便填个进程名"的自由输入框**：那等于把契约退化成任意字符串，
采不到时无人能解释，也无人能评审。

## 11. 决策记录与剩余待定

### 已定（2026-11-21）

| # | 问题 | 结论 |
|---|---|---|
| 1 | 代表进程：RSS 最大 vs PID 最小 | **PID 最小**（worker 在 master 之后 fork，PID 更大）；按 `service.unit` / `container.id` 分组，组内选代表 |
| 2 | macOS 第一版 | **不支持**，`platforms = ["linux"]`，能力上报如实声明 |
| 3 | atlas 的 `ProcessRuntimeState` | **只存实体**；`process_state` / `memory_rss_kib` 等最新读数**不入库**，查询时去 VM 取。原先的 `atlas.in.telemetry.v1` 管道因此**不需要**建立 |
| 4 | 裸跑长驻进程 | **要覆盖**，用 `cmdline:` 签名；只匹配、不落盘；只在发现拍做 |

### 仍待定

1. **`cmdline:` 的收窄阈值**（§9.3 的 N 分钟）——按实测定，不先写死。
2. **macOS 补不补 launchd label**——不在本次范围，但它是 `unit:` 在 macOS 成立的前提。
3. **`container.id` 要不要单独成签名**（`container:`）——容器化服务目前靠 `port:` / `cmdline:` 覆盖，
   将来若"每个容器一个代表"成为需求，再单独立前缀。

## 12. 落地顺序

### 12.1 本仓（关键进程面）

| # | 步骤 | 状态 |
|---|---|---|
| 1 | 契约：`CollectionSourceKind::KeyProcessMetrics` + 语法校验 + 用例 | ✅ `wist-contracts 0.12.0` 已发布 |
| 2 | 网关：`is_collectable_source` 认这个来源 | ✅ 已实现 |
| 3 | 前端：`isExecutableSource` 同步（否则页面把可采面标成“未接”） | ✅ 已实现 |
| 4 | agentd：`key_process_grant()` + 四种签名匹配 + 分组/代表/上限 | ✅ 已实现 |
| 5 | agentd：`no match` 进面的采集结果（`target_not_ready` + 具体签名） | ✅ 已实现 |
| 6 | 知识库：`ProcessMetrics` 面 + 4 个单元（kafka / nginx / redis / postgres） | ✅ 已加单元、包与模板（`catalog_version = 24`） |
| 7 | 端到端验收（真机授权 → 指标落 VM → atlas 查询时 join） | ⬜ 未做（atlas 侧 §12.2 并行） |

> 依赖关系已变：contracts 0.12 要求**整条链**（metrics / api / validate）一起升版发布，
> 否则树里会同时存在两份 contracts、跨边界类型对不上。当前开发态用本地 `path` 依赖，
> 发布时按该顺序逐仓升版。

### 12.2 atlas 侧（清掉"最新读数入库"）

与 12.1 **并行**，不互相阻塞：

| # | 动作 | 位置 | 备注 |
|---|---|---|---|
| a | 域模型删 `ProcessRuntimeState.process_state` / `memory_rss_kib` | `crates/atlas-domain/src/runtime.rs:154` | 连带 PG 列、`sql.rs` 的 upsert |
| b | 删 `atlas.in.telemetry.v1` 的 process 分支（ingest + materialize） | `crates/atlas-api/src/ingest.rs`、`service/materialize/telemetry.rs:61-62` | 该管道本来就没有生产者 |
| c | 按内存聚合/排序的视图改成时序聚合 | `crates/atlas-api/src/query/helpers.rs`（`total_n`） | **这一步最容易低估**：跨源分页/排序必须先取全量，改成 PromQL 聚合才成立 |
| d | 定“谁去 VM 查” | atlas API / BFF / 前端 | **已定 A**，见 §12.3 |
| e | 清 `atlas-sync` 与 `scripts/replay_pg_jsonl.py` 的相关过滤 | `crates/atlas-sync/src/lib.rs:301`、`scripts/` | — |
| f | 加 `metric_instance` 列（§12.3.1 的 join 键） | domain + storage + materialize | 与删字段同一次迁移 |
| g | VM 客户端 + 两种查询形态 + 降级（§12.3.2 / §12.3.3） | atlas-api | 方案 A 的主体 |

### 12.3 查询时谁来 join（已定：方案 A）

**定案：atlas 的列表接口在服务端 join**。前端无感，分页与排序留在服务端。

#### 12.3.1 join 键（必须先落这一条）

两边的键今天**不一致**，直接拼会得到永久为空且不报错的 join：

| | 值 | 出处 |
|---|---|---|
| VM `instance`（进程域） | `host-1:proc:linux_proc_start:123` | `stable_instance`，`src/telemetry/metrics/samples.rs:409` |
| atlas `external_ref` | `host-1:pid:42:linux_proc_start:123` | `materialize/process.rs:100` |

差在 `proc:<identity>` vs `pid:<pid>:<identity>`。

**做法：atlas 域模型加一列 `metric_instance`，值 = `{machine_id}:proc:{identity}`，
与 `stable_instance` 同一条构造规则。** 原料 atlas 已有（`ProcessRuntimeCandidate` 的
`machine_id` / `identity`），不需要采集侧改。

这条串是**跨仓契约**：两端必须逐字节一致。已写进
[`metrics-data-spec.md`](./metrics-data-spec.md) **§3.1.1**（含“编码变更 = 破坏性变更”的纪律），
后续任何改动按那里执行。

#### 12.3.2 两种查询形态

| 列表场景 | 做法 | 请求量 |
|---|---|---|
| 默认（按名字/pid 排） | 先从 atlas 取一页实体，再用该页的 `metric_instance` **一次**批量查 VM（`instance=~"a\|b\|c"` + `last_over_time`） | 2 次 |
| **按内存排序/聚合** | 必须**先问 VM**：`topk(N, max by (instance) (process_memory_rss_bytes))`，再拿结果回 atlas 取实体 | 2 次 |

第二种不能反过来做：从 atlas 取一页再排序，得到的是「这一页里的最大值」，不是全局最大值。

#### 12.3.3 降级与超时

- **实体是权威，读数是装饰**：VM 不可达 / 超时 → 列表照常返回实体，读数字段留空，
  **不报错、不阻塞**；
- 单次 VM 请求 ≤ 2s，失败不重试（列表接口重试只会放大延迟）；
- 读数可短 TTL 缓存（建议 5~10s，与采集周期同量级），不引长期缓存。

## 13. 验收

- 授权一个单元、本机确有该进程 → 每周期报**恰好一个**代表进程的序列，`succeeded=1`；
- 一个 unit 下有 master + 8 worker → 只报 master（PID 最小），`succeeded=1`、其余不计入 dropped
  （同组非代表进程不是"被丢弃的目标"）；
- `kafka@0` / `kafka@1` 两个实例 → 各报一个代表，`succeeded=2`；
- 撤授权 → 下一周期序列消失，候选文件被清掉（与 0.35.0 行为一致）；
- 授权了但本机没有 → 面的采集结果报 `target_not_ready`，明细指明是哪条签名没命中
  （不是 `dropped`：`dropped_targets` 只表示"有这个目标但没给样本"）；
- `target = "bogus:kafka"` → 整份 spec `unsupported`，**不**进入采集；
- 签名命中 200 个进程 / 12 个归属组、上限 50 → **按组**算：12 组全留（`succeeded=12`），
  代表进程跨拍不跳；组数超 50 时按组键字典序截断，`dropped` 只进日志；
  进程样本**不再**受 `SAMPLE_LIMIT = 3` 限制（每个代表进程都要有序列）；
- 同一台机器连续 10 个周期，代表进程的 `resource_ref` **不跳变**；
- `cmdline:` 用例：`cmdline:/opt/app/app.jar` 命中 `java -jar /opt/app/app.jar`；
  `cmdline:app.jar` **不**命中（token 原文才比），且 `state/discovery/*.json` 与
  `planner_candidates` 里**搜不到**命令行原文。
- 端到端（与 atlas 侧 12.2 一起验）：VictoriaMetrics 里能查到该进程的
  `process_memory_rss_bytes{agent,instance}`，且 atlas 的进程列表**不含**内存/状态字段。
