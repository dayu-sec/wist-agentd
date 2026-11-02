# 指标数据规范（v1 草案）

> 规范性用语：**必须**（MUST）、**不得**（MUST NOT）、**应当**（SHOULD）、**可以**（MAY）。
> 命名体系：Prometheus 形态线名 + OTel 语义映射（§2.1）。
> 版本：**v1**。v1 内指标名、label 键、单位不得变更；加性变更不升版本；破坏性变更按 §0.1 执行。
> `wist-metrics` 的 `spec` 模块是本规范的机器可读副本；两者不一致时以本文为准并要求同步。

## 0. 版本与兼容规则

### 0.1 破坏性变更

改名、删名、改单位、改值类型、改 label 键、缩窄 label 值域均为破坏性变更，**必须**按序执行：新名入注册表并标旧名 `deprecated` → 双写 ≥ 2 个采集周期且 ≥ 7 天（两套数值必须一致）→ 消费方切换完成后删除旧名。

理由：序列名是时间序列的连接键，直接改名等于让同一物理量在时间轴上断成两条；双写是唯一能让看板与告警平滑迁移的方式。

指标名与 label 的切换**必须**在同一个双写窗口内完成：两者同属查询面，分两次改会让消费方付两次迁移成本，也会让双写期的「名字 ↔ label」组合出现四种形态。

### 0.2 加性变更

新增 `app` / `disk_role` / `state` / `outcome` 等枚举值、放宽数值范围，为加性变更，不升版本。

### 0.3 注册表唯一性

指标名、单位、值类型、label 键**只能**在注册表（§10）定义一次。采集实现**不得**自行生成指标名——采集侧只产 `fact_key`，名由注册表决定。

---

## 1. 目的与范围

本规范定义边缘指标从采集到入库的数据契约：指标叫什么、单位是什么、值怎么表示、身份怎么表达、时间取哪一刻、丢了怎么算。目标是让采集端、传输链、存储与消费端各自独立演进，而数据契约保持稳定。

数据流：发现快照 → 采集候选 → 采集侧产出 `fact` → 注册表映射为样本 → uplink 帧 → 存储 → 查询。采集侧只产 `fact`，指标名、单位、类型由注册表决定。

**范围**

- 主机指标（`system_*`）、进程/容器指标（`process_*` / `container_*`）、agent 自观测指标（`agent_*`）；
- uplink 指标帧的正文、VM JSON line、本地落盘文件（若启用）。

**非目标**

- 存储的保留策略、分片、告警规则、看板口径；
- 日志帧、事实帧、调查帧的契约；
- 采集调度周期（由工作授权决定，见 §7.6）。

---

## 2. 命名规范

### 2.1 命名体系

**线上指标名使用 Prometheus 形态（下划线分隔 + 单位后缀）；语义与单位沿用 OpenTelemetry 语义约定，记入注册表 `semconv_ref` 列。**

理由：

1. 线上名的唯一消费者是查询语言：只有合法裸名才能进 `rate` / 告警 / 录制规则 / 自动补全。
2. 存储是 name + labels 模型，没有 OTel 的直方图与资源属性；以点号名为 canonical 只会形成「文档与数据两套名字」。
3. 单位后缀把单位变成静态不变量，可与注册表 `unit` 双向校验。
4. 上游 OTel 约定仍在演进，线名不应随其改名而断裂。

若将来需要 OTLP 出口，由注册表生成 OTel 名即可，线名不变。

### 2.2 语法

```text
name    = ns "_" subject { "_" field } [ unit_suffix ] [ "_total" ]
ns      = "system" | "process" | "container" | "agent"      // 可扩展，须先入规范
segment = 1*( %x61-7A / %x30-39 )                          // [a-z0-9]，首字符必须是字母
```

- 全小写；分隔符只有 `_`；**不得**出现 `.` / `-` / `:` / 空格 / 驼峰；**不得**以 `_` 开头或结尾；**不得**出现连续 `__`。
- 首段是命名空间，表示**数据主体**：`system`（主机）、`process`（进程）、`container`（容器）、`agent`（agent 自身）。
- 第二段起描述「对象 + 字段」，用名词而不是动词，也不写实现：**不得**出现 `procfs` / `ps` / `sysinfo` / `gather` / `scrape`。
- **窗口**用独立指标名（`system_load_average_1m` / `_5m` / `_15m`）：不同窗口是同时存在的三条曲线，与 `node_load1` 一类主流口径一致。
- **磁盘角色**用 `disk_role` label（`system_disk_usage_ratio{disk_role="data"}`）：角色是同一量的分组维度，用 label 才能聚合与过滤。
- 名字**不得**编码聚合方式（`_max` / `_avg` / `_p99`）；聚合属于查询表达式。

### 2.3 单位后缀

| 单位类别 | 后缀 | 例 |
|---|---|---|
| 字节 | `_bytes` | `system_memory_total_bytes` |
| 秒 | `_seconds` | `agent_admin_latency_seconds` |
| 无量纲比例（0–1） | `_ratio` | `system_filesystem_usage_ratio` |
| 无量纲计数/编号/版本 | 无后缀 | `agent_cpu_cores`、`container_pid` |
| 累计计数器 | `_total`（在单位后缀之后） | `agent_uplink_metrics_failed_total` |

单位后缀集合封闭，新增单位必须同时新增后缀规则。毫秒、百分比、页、KiBy **不得**出现在名字里（见 §5）。

窗口后缀（`_1m` / `_5m` / `_15m`）不属于单位后缀：它是同一物理量的时间窗标识，与单位正交。

### 2.4 label 命名

snake_case，闭集（§3 给出值域与准入规则）。**不得**出现 `_ref` / `_id` 之类实现味后缀：label 名表达语义角色，不表达数据结构的拼装方式。

主流（node_exporter / kube-state-metrics / OTel 语义约定）已有**同名同义**的 label **必须**直接采用；自造名只允许在主流无对应概念时使用。

---

## 3. 指标身份

一条序列由「指标名 + label 集合」唯一确定，身份公式：

```text
(name, agent, instance, 按需 label)
```

| label | 必需 | 值域 | 语义 | 主流依据 |
|---|---|---|---|---|
| `agent` | 必须 | agent_id | 采集者身份；跨实例、跨升级不变 | 自造（无歧义；`instance` 已被被采对象占用） |
| `instance` | 目标类指标（`process` / `container`）与主机指标必须 | §3.1 | 被监控对象的**稳定身份** | Prometheus 的「被采对象」位 |
| `disk_role` | 按需 | `system` / `data` | 磁盘角色 | 自造（主流无对应，值域闭集） |
| `mountpoint` | 按需 | 绝对路径 | 文件系统挂载点 | node_exporter / OTel |
| `fstype` | 按需 | 文件系统类型；空则不写 | 文件系统类型 | node_exporter |
| `state` | 按需 | 闭集（§4.3） | 状态类指标的一热维度 | node_exporter |
| `cpu` | 按需 | 逻辑核编号（`0`、`1`…） | CPU 分核维度 | node_exporter |
| `mode` | 按需 | `user` / `system` / `idle` / `iowait` / `nice` / `irq` / `softirq` / `steal` | CPU 时间分类 | node_exporter |
| `target_kind` | 按需 | `host` / `process` / `container` | 计数类指标的统计对象 | 自造（主流无对应，值域闭集） |
| `outcome` | 按需 | `succeeded` / `partial` / `failed` / `dropped` | 采集结果 | 自造（主流无对应，值域闭集） |
| `device` | 按需 | 内核设备名（如 `sda` / `nvme0n1`） | 块设备 I/O 维度 | node_exporter |
| `namespace` / `pod` / `container` | 预留 | k8s 原始值 | 容器身份维度 | kube-state-metrics |

### 3.1 `instance` 的取值

```text
主机      →  <host_resource_id>                       例: host-1
进程      →  <host_resource_id>:proc:<identity>       例: host-1:proc:/usr/sbin/nginx@1690000000
容器      →  <host_resource_id>:ctr:<container_id>    例: host-1:ctr:3f9a2b
agent 自身 →  不适用（自观测指标没有 instance）
```

- `identity` 是「可执行文件 + 启动时间」或等价的稳定标识；**不得**含 PID。PID 会被回收，同一个 PID 在不同时刻属于不同进程。
- 容器用容器 id，不用容器名：名字可复用，id 在一个容器生命周期内稳定。
- 主机用资源 id，不用主机名：主机名会改，资源 id 不变。

主机与 `agent` 通常一一对应，但仍保留 `instance`：agent 重新注册会变，主机不变。

### 3.2 label 准入规则

1. 主流有**同名同义** → 直接采用（`mountpoint` / `fstype` / `state` / `device` / `instance`）。
2. 主流有**同名异义** → 禁用（`resource` 在 kube-state-metrics 指 cpu/memory；`node` 指节点；`target` 是抓取目标概念）。
3. 主流无对应 → 可以自造，但必须同时满足：值域闭集、不与主流同名、不冗余。

### 3.3 规则

1. **唯一性**：同一批次内，`(name, agent, instance, 按需 label)` 必须唯一。重复即为缺陷。
2. **白名单**：label 键集合封闭；采集实现**不得**注入未登记的 label。未登记 label 必须被丢弃并记为自观测事件。
3. **禁止高基数**：时间戳、错误文本、命令行、动态路径、PID 数值**不得**作为 label。PID 只能作为指标值（`process_pid` / `container_pid`）。
4. **保留名**：`__name__` 为存储保留键，任何 label **不得**与之冲突；`job` 属采集编排层，本规范不使用。
5. `agent` 自观测指标（`agent_*`）**不带** `instance`：它们描述 agent 进程自身，没有外部对象。
6. 目标类指标的 `instance` **必须**是稳定身份：同一对象在连续批次、agent 重启前后取值一致。

### 3.4 选择类 label

用途：把「一组机器 / 一组对象」一次选出来，服务查询与告警的范围。与身份无关。

| 键 | 必需 | 语义 | 取值 |
|---|---|---|---|
| `app` | 必须 | 用途标识：软件名或基础设施职能 | 小写、无版本，由控制面登记（`kafka` / `mysql` / `gateway` / `bastion`） |
| `env` | 必须 | 环境 | 闭集：`prod` / `staging` / `dev` / `test` |
| `cluster` | 必须 | 部署单元；单机部署取该单元标识（可与机器名相同） | 不含环境与应用名 |
| `role` | 可选 | 部署期确定的**主**角色 | 词表见下 |
| `shard` | 场景 | 分片/池序号 | 短标识；仅分片系统 |
| `tier` | 场景 | 存储层 | `hot` / `warm` / `cold`；仅分层存储 |
| `region` / `zone` | 场景 | 机房 | 短标识 |

`role` 词表（可扩展，扩展须按 `app` 登记）：`broker` / `controller` / `primary` / `replica` / `coordinator` / `data` / `ingest` / `proxy` / `worker`。

规则：

1. **能由其他字段唯一推导的维度不设**：域已由名字首段承载，不再用 label 重复；`cluster` 在单机取值与机器名相同时仍是登记事实，不属于重复。
2. **跨域选择例外**：`app` 在 `<app>_*` 域指标上与名字首段重合，但它的作用是**跨域选择**（一次选出同一台机器的 `system_*`、`process_*`、`kafka_*`），名字做不到——因此保留，不属于冗余。
3. **取值来源**：`app` / `env` / `cluster` 由控制面下发。`app` 在主机指标上表示**机器用途**，在进程/容器指标上表示**目标自身用途**（发现层识别），两者可以不同；`env` / `cluster` 一律继承 agent。
4. **禁止动态**：选举结果（leader/follower）、切换后的实际主从、版本、归属团队均**不得**进入选择类 label。动态角色用 one-hot 指标（§4.3），版本用 `*_info` 指标，归属放控制面注册表。
5. **单值限制**：一机多用途无法用选择类 label 表达；此时机器级选择不可用，改用进程/容器口径。
6. **每 app 登记允许键集**：`shard` 只允许出现在分片系统、`tier` 只允许出现在分层存储；未登记的键组合校验失败。
7. **数量上限**：一条序列上同时出现的选择类 label 不得超过 6 对。
8. **不使用 `job`**：Prometheus 里 `job` 标识抓取任务，推送模型没有对应物；用途与归属由 `app` / `cluster` 表达。

```toml
[metrics.labels]
app     = "kafka"
env     = "prod"
cluster = "orders"
role    = "broker"
```

```promql
# 一次选出该部署单元下的全部机器，每台一行：整机 CPU 利用率
1 - avg by (agent) (
  rate(system_cpu_seconds_total{app="kafka", env="prod", cluster="orders", mode="idle"}[5m])
)
```

### 3.5 键集合结论

- **必选 3**：`app` / `env` / `cluster`——任何机器都能给出，任何查询与告警都要先限定；缺失会让不同环境、不同部署单元静默混进同一聚合。
- **按需 4**：`role` / `shard` / `tier` / `region` + `zone`——只登记部署期确定、数月不变的信息。
- **不进 label 的五类**：动态状态与选举结果（→ one-hot 指标）、版本（→ `*_info`）、归属（→ 控制面）、分片内副本序号（→ `instance`）、一机多用途（→ 进程/容器口径）。
- **判据**：可由其他字段唯一推导 → 不设；变更会断档 → 不入 label；非单值 → 用指标。
- **边界与治理**：主机口径只适用于专用机器；取值由控制面下发，按 `app` 登记允许键集（§13）。

---

## 4. 值类型与数值表示

### 4.1 类型闭集

| 类型 | 语义 | 线上表示 |
|---|---|---|
| `gauge_i64` | 可上可下的整数 | JSON 整数 |
| `gauge_f64` | 可上可下的实数 | JSON 浮点 |
| `counter_i64` | 单调不减的累计量 | JSON 整数 |
| `counter_f64` | 单调不减的累计实数 | JSON 浮点 |

**`counter` 存的是累计量**（内核或进程启动以来的总量，如 CPU 秒、字节数），**不是**本周期内的增量。周期增量与比例一律由查询层的 `rate` / `increase` 派生，采集侧**不得**预先求差。理由：预求差把采集周期写死进数据（周期抖动、丢批、重放都会算错），而累计量的任意窗口都可重算，丢失批次也不丢信息。

```promql
# 累计量 → 每个核的使用率（0–1），与采集周期无关
rate(system_cpu_seconds_total{agent="a-7f2", cpu="0", mode="user"}[5m])
```

**指标通道不承载字符串值**：状态、模式、枚举一律转为数值（一热 label，见 §4.3）或计数指标——存储只收数值，字符串会在链路上被静默丢弃。

### 4.2 数值规则

- 数字**不加引号**；整数不写成 `1.0`；**不得**输出 `NaN` / `±Inf`。
- 布尔量用 `0` / `1`。
- 解析失败**不得**降级为字符串：样本丢弃并记 `event=MetricValueInvalid`——混型会让下游无法稳定解析。
- `gauge_i64` 表达精确整数（字节、核数、PID）；超过 `2^53` 的量若用浮点会丢精度，必须用 `gauge_i64`。

### 4.3 枚举量

状态类量用**一热 label**，只发当前值：

```text
process_state{state="running"} 1
```

- 每个目标每条 `state` 只发当前状态的一条序列，值为 `1`；
- `state` 值域必须是注册表登记的闭集（进程：`running` / `sleeping` / `disk_sleep` / `stopped` / `zombie` / `dead` / `idle` / `unknown`）；
- 未识别的状态值映射为 `unknown`，**不得**新增未登记取值。
- **可叠加的角色**不用 `state` label（它只能表达单值），改为每个角色一条布尔指标：`es_node_role_is_master 1`、`kafka_node_role_is_controller 1`。理由：一个节点可以同时承担多个角色，`state` 单值会让其中一部分丢失。

理由：一热 label 让「某状态的目标数」可以直接用 `count by (state)` 得到，同时避免引入字符串样本。

---

## 5. 单位

### 5.1 单位闭集

| 单位 | 含义 | 名字后缀 | 约束 |
|---|---|---|---|
| `By` | 字节，基单位 | `_bytes` | 非负整数 |
| `s` | 秒，基单位 | `_seconds` | 非负 |
| `1` | 无量纲（计数、核数、版本号、负载） | 无 | 整数或实数 |
| `1`（比例） | 0–1 的比例 | `_ratio` | `0 ≤ v ≤ 1` |

**禁止**作为存储单位：`KiBy` / `MiBy` / `%` / `ms` / `pages` / `state`。

### 5.2 规则

1. **只用基单位**：容量一律 `By`（采集侧完成 `KiB×1024`、页×页大小的换算），时长一律 `s`（展示层再换算 ms）。
2. **比例只用 0–1**：`0.9` 表示 90%，`percent` 只属于展示层——跨指标计算不需要随机 ÷100，也不会出现 0–1 与 0–100 混用。
3. **同名同单位**：同一指标名在所有平台、所有采集路径下只有一个单位。跨平台差异（页/字节、不同文件系统类型）必须在采集侧换算完毕。
4. **单位不进 label**：单位由名字后缀承载；样本**不得**携带 `unit` label——单位进入序列身份会让同名不同单位裂成两条序列，单位修正也会断档。
5. **单位与后缀双向校验**：注册表 `unit` 与名字后缀必须互相印证（§12 门禁）。
6. **ratio 必须声明分母**：任何 `*_ratio` 指标必须在注册表备注分母口径（整机容量 / 单核 / cgroup 配额）；**不得**同时落库同一物量的比例与累计量，比例在查询层由累计量派生（窗口选择见 §9.1）。

```promql
# 整机 CPU 利用率：累计秒 → 比例，分母由核数隐含（avg 就是除以核数）
1 - avg by (agent) (rate(system_cpu_seconds_total{mode="idle"}[5m]))
```

---

## 6. 时间语义

| 时间点 | 定义 | 用途 |
|---|---|---|
| 采集完成时刻 | provider 本轮采集结束的时刻（UTC，毫秒精度） | **样本时间** |
| 帧 `ts` | 帧发出的时刻（RFC3339，UTC） | 传输元数据，排查延迟 |
| 信封 `seq` | 该 agent 全局单调递增序号 | 缺口检测、去重 |

规则：

1. **样本时间 = 采集完成时刻**。VM `timestamps`（epoch ms）与样本 `collected_at`（RFC3339）必须表示同一时刻、同一批次共用一个时间戳。
2. 帧 `ts` **不得**被当作样本时间；消费方对齐曲线时只用样本时间。
3. 重发/补发（若启用）**必须**沿用原采集时刻，**不得**用重发时刻。
4. 去重键是 `(agent, seq)`；批次内序号**不得**作为去重键（进程重启后归零）。
5. 同一 agent 的 `seq` 必须单调递增、不得回退；到达顺序不做要求。
6. 时钟不可信时以 agent 本地时钟为准，接受偏差；消费方按样本时间排序，不按到达顺序。

理由：把发送时刻当样本时间会在网络抖动、重连、补发时把曲线整体右移，而这恰好发生在最需要看清趋势的故障窗口。

---

## 7. 采集语义

### 7.1 作用域

- **主机级指标**：每 agent 每批次**只发一次**，`instance` 指向该 agent 的主机资源。
- **目标级指标**：每个目标一组，`instance` 指向该目标。
- 主机级指标**不得**按目标数量复制：复制会产生数值相同、身份不同的多条序列，既浪费存储又会让「按 instance 去重」的查询失真。

### 7.2 基数与选样

1. 每批次每个采集域的目标采样上限必须显式登记在 capability 的 `limits` 中（`max_targets_per_domain`），不得是隐含常量。
2. 超出上限的目标**必须**计入 `agent_collect_targets{target_kind,outcome="dropped"}`，不得静默丢弃。
3. 选样规则必须**确定性**：按 `instance` 字典序；**不得**依赖遍历顺序或哈希顺序。
4. 上限值以「目标数 × 每目标序列数」后的总序列数不超过单 agent 预算为准，预算随容量测试更新。

理由：静默截断无法从数据侧发现（「一千个进程、图里只有三个」），确定性选样保证跨批次可比。

### 7.3 失败与部分成功

| outcome | 含义 | 是否发样本 |
|---|---|---|
| `succeeded` | 目标全部字段采集成功 | 发 |
| `partial` | 目标部分字段采集成功 | 只发成功字段 |
| `failed` | 目标无可信读数 | **不发** |
| `dropped` | 超出采样上限未采 | 不发 |

- 失败目标**不得**发送任何样本，也**不得**用 0、上次值或默认值填充。
- 失败与部分成功必须计入 `agent_collect_targets{target_kind,outcome}`。
- 批次级状态取最差：有任一 `failed` 即批次 `partial`；全部 `failed` 即批次 `failed`。

理由：旧值与新鲜值无法区分，会把故障伪装成正常；缺失本身可识别，补 0 则会伪造 0 读数。

### 7.4 平台归一

| 量 | 归一输出 | 采集侧必须完成 |
|---|---|---|
| 进程/容器内存 | `*_memory_rss_bytes`（`By`） | 页数 × 页大小；`ps -o rss` 的 KiB × 1024 |
| 进程状态 | `*_state{state}` 一热 | 状态字符 → 闭集枚举 |
| 主机容量 | `system_filesystem_*{mountpoint,fstype}` | 只保留本地真实文件系统；虚拟/网络/临时挂载排除 |
| 磁盘角色 | `system_disk_*{disk_role}` | 根文件系统 = `system`；其余本地块设备汇总 = `data`，同一设备的多挂载点只计一次 |
| 可用量 | `*_available_bytes` | 必须夹取到 `[0, total]` |

- `available` 必须满足 `available ≤ total`；违反时夹取并记一次自观测事件。
- 文件系统挂载点过滤规则属于采集实现，但**不得**改变指标语义（同一 `mountpoint` 在不同平台含义一致）。

### 7.5 覆盖完整性

每个采集域（`system` / `process` / `container` / `agent`）产出的 `fact_key` 必须三选一，并在注册表或 ignore 表登记：

1. 映射成指标；
2. 明确忽略（ignore 表必须写理由，如 `process.executable.name`：身份信息，属发现域而非指标域）；
3. 从采集侧删除。

未登记的 fact **不得**上送，且首次出现时**必须**记一条自观测事件（`event=MetricFactUnmapped`）。

理由：不登记就无法区分「这个量不重要」与「忘了加注册表」，后者会让新采集能力永远不可见。

### 7.6 触发与周期

- 采集与上送的周期由工作授权的 `MetricInterval` 决定；没有指标工作即不采集、不上送。
- 每批次产出一份采集快照，上送内容由该快照规范化得到。
- 无有效样本时**整批跳过**，不发空帧。
- 目标视图缺失时**可以**沿用上一次缓存的采集快照，但必须让该批次在自观测中可见（`used_cached_snapshot=true`）。

---

## 8. 传输与投递

### 8.1 帧格式

```text
{"schema":"v1","agent":"<agent_id>","ts":"<RFC3339>","seq":<n>} METRICS: {"metric":{"__name__":"system_filesystem_usage_ratio","agent":"<agent_id>","instance":"host-1","mountpoint":"/data","fstype":"xfs"},"values":[0.88],"timestamps":[1767225600000]}
```

- **一条样本一帧**；`metric.__name__` 是指标名，其余字段是 label。
- `values` / `timestamps` 为数组是存储协议要求，长度恒为 1。
- 分帧（`line` / `len`）与日志帧同规则；一帧必须是完整行。
- 指标帧与日志帧共用同一连接与同一 agent 级全局 `seq`；取号后先持久化高水位再发送，保证跨重启不回退。

### 8.2 投递保证

- **至多一次**：指标不进入持久化补偿队列。发送失败时该批次丢弃，下个周期重新采集。
- 失败**必须**计入 `agent_uplink_metrics_failed_total`（`counter_i64`）。
- 消费方**必须**容忍时间缺口，不得把「缺一批」当作故障。

理由：指标可重采，重传预算应留给不可重采的信号；前提是失败可观测。

### 8.3 本地落盘（若启用）

本地落盘文件**必须**与线格式同构（同样的 `metric` / `values` / `timestamps` 结构，同样的 label 集合）。**不得**存在第二套字段定义。

理由：两套格式必然漂移；同构后本地文件可直接用于离线回放与线上核对。

---

## 9. 消费约定

1. **按精确名查询**：`system_memory_available_bytes{agent="..."}`；不得依赖正则匹配名字。
2. **不依赖 label 顺序**，不依赖同一批次样本在时间上完全对齐。
3. **缺失即缺失**：图表与告警**不得**补 0 或前向填充。
4. **比例换算属于展示层**：`*_ratio × 100` 得到百分比；存储层不做 0–100 转换。
5. **单位不在 label 中**，查询方从名字后缀判定单位。
6. **身份过滤用 `instance`**；PID 不进 label，需要 PID 时读 `process_pid` / `container_pid`。
7. 新增消费方**必须**只使用 §10 注册表内的名字与 label。
8. **按机器看趋势用 `by (agent)`**；按用途/环境/部署单元圈定范围用 `app` / `env` / `cluster`；不得用正则匹配 `agent`。
9. 选择类 label 的值变更会断开历史，看板**不得**把它当可变维度（如按归属团队过滤）；归属类信息从控制面注册表 join。

### 9.1 派生量与查询窗口

累计量（`counter`）的派生值全部在查询层算，公式只由**样本时间戳**决定，与采集间隔无关：

```text
单核口径  ρ₁ = ΔC / ΔT          // 单位「核」，多线程可 > 1
整机口径  ρN = ρ₁ / N           // 0–1，N 取 agent_cpu_cores 或主机核数
查询形式  ρ₁ = rate(<name>[W])  // W 为窗口，不是采集间隔
```

**窗口必须 ≥ 4 × 采集间隔**（Prometheus 对 `rate()` 的建议；低于 2× 会直接算不出值）：

| 采集间隔 | `[30s]` 内的点数 | 最小窗口（4×） | 建议窗口 |
|---|---|---|---|
| 15s | 2（不满足 4×，丢一批就空） | 60s | 1m–2m |
| 5s | 6 | 20s | 30s–1m |
| 60s | 0–1（**失效**） | 4m | 5m–10m |

例：`rate(process_cpu_seconds_total{instance="…"}[30s])` 在 15s 采集下只有两个点，应当写成 `[2m]`；采集改为 5s 后同一个 `[30s]` 自然变成 6 个点，公式与看板都无需修改。

连带规则：

1. **采集间隔变更只影响分辨率**，不影响派生公式与历史可比性——这是存 `counter` 而非存比例的直接收益。
2. **告警的 `rate` 窗口与 `for` 时长必须一起复核**：间隔变短后同样时长内的点数变多，噪声更容易触发。
3. **不得因为间隔变短改用 `irate`**：它只吃最后两个点（等于一个采集间隔的窗口），只适合排障瞬时观察，不适合告警与趋势。
4. **计数器粒度给窗口定下限**：`/proc` 的 jiffies 为 10ms，5s 窗口有 500 个 tick（误差 0.2%），1s 窗口只剩 100 个 tick，量化误差开始可见。
5. **本地计算的短窗口不能小于采集间隔**：本地 ρ₁ 用实测 `ΔT` 作分母，但 `ΔT ≥ 采集间隔`；要 3s 占用率就必须 ≤ 3s 采样，与查询层窗口无关。

---

## 10. 指标注册表

> 注册表是 `(采集域, fact_key) → (name, type, unit, labels)` 的唯一映射。`semconv_ref` 仅供理解与未来导出，不影响线名。
>
> 四条登记规则：
>
> 1. **fact 值必须已处于注册表声明的单位**：KiB→By、页×页大小、0–100→0–1 的换算在采集侧完成，注册表不做数值变换。
> 2. **常量 label**（如 `disk_role=system`）由规范化层写入；**动态 label**（如 `mountpoint`）取自采集事实。
> 3. **枚举类 fact**（如 `process.state`）的取值写入 `state` label，样本值恒为 `1`（§4.3）。
> 4. **选择类 label**（§3.4）由代理层统一附加到该 agent 的全部序列，注册表不逐行声明；主机指标的 `app` 为机器用途，进程/容器指标的 `app` 为目标用途。

### 10.1 主机（域 `system`）

| fact_key | 指标名 | 类型 | 单位 | 常量 label | 动态 label | semconv_ref |
|---|---|---|---|---|---|---|
| `host.loadavg.1m` | `system_load_average_1m` | gauge_f64 | 1 | — | — | `system.cpu.load_average.1m` |
| `host.loadavg.5m` | `system_load_average_5m` | gauge_f64 | 1 | — | — | `system.cpu.load_average.5m` |
| `host.loadavg.15m` | `system_load_average_15m` | gauge_f64 | 1 | — | — | `system.cpu.load_average.15m` |
| `host.uptime.seconds` | `system_uptime_seconds` | gauge_f64 | s | — | — | `system.uptime` |
| `host.cpu.seconds` | `system_cpu_seconds_total` | counter_f64 | s | — | `cpu`,`mode` | `system.cpu.time` |
| `host.memory.total_bytes` | `system_memory_total_bytes` | gauge_i64 | By | — | — | `system.memory.limit` |
| `host.memory.available_bytes` | `system_memory_available_bytes` | gauge_i64 | By | — | — | `system.memory.usage`（state=free，近似） |
| `host.memory.usage_ratio` | `system_memory_usage_ratio` | gauge_f64 | 1 | — | — | `system.memory.utilization` |
| `host.memory.swap_total_bytes` | `system_memory_swap_total_bytes` | gauge_i64 | By | — | — | `system.paging.limit` |
| `host.memory.swap_free_bytes` | `system_memory_swap_free_bytes` | gauge_i64 | By | — | — | `system.paging.usage`（state=free，近似） |
| `host.disk.system.usage_ratio` | `system_disk_usage_ratio` | gauge_f64 | 1 | `disk_role=system` | — | — |
| `host.disk.system.total_bytes` | `system_disk_total_bytes` | gauge_i64 | By | `disk_role=system` | — | — |
| `host.disk.system.available_bytes` | `system_disk_available_bytes` | gauge_i64 | By | `disk_role=system` | — | — |
| `host.disk.data.usage_ratio` | `system_disk_usage_ratio` | gauge_f64 | 1 | `disk_role=data` | — | — |
| `host.disk.data.total_bytes` | `system_disk_total_bytes` | gauge_i64 | By | `disk_role=data` | — | — |
| `host.disk.data.available_bytes` | `system_disk_available_bytes` | gauge_i64 | By | `disk_role=data` | — | — |
| `host.disk.data.mounts` | `system_disk_mounts` | gauge_i64 | 1 | `disk_role=data` | — | — |
| `host.disk.read_bytes` | `system_disk_read_bytes_total` | counter_i64 | By | — | `device` | `system.disk.io`（direction=read） |
| `host.disk.written_bytes` | `system_disk_written_bytes_total` | counter_i64 | By | — | `device` | `system.disk.io`（direction=write） |
| `host.disk.reads` | `system_disk_reads_total` | counter_i64 | 1 | — | `device` | `system.disk.operations`（direction=read） |
| `host.disk.writes` | `system_disk_writes_total` | counter_i64 | 1 | — | `device` | `system.disk.operations`（direction=write） |
| `host.disk.io_time_seconds` | `system_disk_io_time_seconds_total` | counter_f64 | s | — | `device` | `system.disk.io_time` |
| `host.filesystem.usage_ratio` | `system_filesystem_usage_ratio` | gauge_f64 | 1 | — | `mountpoint`,`fstype` | `system.filesystem.utilization` |
| `host.filesystem.total_bytes` | `system_filesystem_total_bytes` | gauge_i64 | By | — | `mountpoint`,`fstype` | — |
| `host.filesystem.available_bytes` | `system_filesystem_available_bytes` | gauge_i64 | By | — | `mountpoint`,`fstype` | `system.filesystem.usage`（state=free，近似） |
| `host.filesystem.inodes` | `system_filesystem_inodes` | gauge_i64 | 1 | — | `mountpoint`,`fstype` | — |
| `host.filesystem.inodes_free` | `system_filesystem_inodes_free` | gauge_i64 | 1 | — | `mountpoint`,`fstype` | — |

- `disk_role=system` 的磁盘序列**必须**存在；`disk_role=data` 仅在存在数据盘时出现。
- `system_disk_*{disk_role}` 是角色汇总，`system_filesystem_*{mountpoint}` 是逐挂载点明细；两者对同一角色必须一致。
- **CPU**：核数不上报，由 `count by (agent) (system_cpu_seconds_total{mode="idle"})` 派生；利用率在查询层算（§5.2 规则 6）。
- **内存**：`system_memory_usage_ratio` 与 `available` 同批采集，保证互不矛盾；swap 只报总量与剩余，使用率在查询层算。
- **磁盘**：容量（total / available / usage）按挂载点表达，供 `mountpoint` 下钻；`device` 维度只承载 I/O 计数，不重复报容量；`disk_role` 保留为角色汇总的快速视图。
- **inodes**：使用率在查询层派生 `1 - inodes_free / inodes`；inode 总数命名为 `system_filesystem_inodes`（**不带** `_total`，避免与计数器后缀混淆）。

### 10.2 进程（域 `process`）

| fact_key | 指标名 | 类型 | 单位 | 常量 label | 动态 label | semconv_ref |
|---|---|---|---|---|---|---|
| `process.memory.rss_bytes` | `process_memory_rss_bytes` | gauge_i64 | By | — | — | `process.memory.usage` |
| `process.cpu.seconds` | `process_cpu_seconds_total` | counter_f64 | s | — | — | `process.cpu.time` |
| `process.state` | `process_state` | gauge_i64 | 1 | — | `state` | — |
| `process.pid` | `process_pid` | gauge_i64 | 1 | — | — | — |

### 10.3 容器（域 `container`）

| fact_key | 指标名 | 类型 | 单位 | 常量 label | 动态 label | semconv_ref |
|---|---|---|---|---|---|---|
| `process.memory.rss_bytes` | `container_memory_rss_bytes` | gauge_i64 | By | — | — | `container.memory.usage` |
| `process.cpu.seconds` | `container_cpu_seconds_total` | counter_f64 | s | — | — | `container.cpu.time` |
| `process.state` | `container_state` | gauge_i64 | 1 | — | `state` | — |
| `container.pid` | `container_pid` | gauge_i64 | 1 | — | — | — |

### 10.4 agent 自观测（域 `agent`，无 fact_key，由 agent 运行时直接产出）

| 指标名 | 类型 | 单位 | 动态 label | 语义 |
|---|---|---|---|---|
| `agent_memory_bytes` | gauge_i64 | By | — | agent 进程常驻内存 |
| `agent_cpu_ratio` | gauge_f64 | 1 | — | 单核口径（1.0 = 占满一个核；分母声明） |
| `agent_cpu_cores` | gauge_i64 | 1 | — | 逻辑核数，用于把单核口径换算成整机占比 |
| `agent_admin_latency_seconds` | gauge_f64 | s | — | 管理面交互延迟 |
| `agent_discovery_policy_version` | gauge_i64 | 1 | — | 已生效的发现策略版本 |
| `agent_collect_targets` | gauge_i64 | 1 | `target_kind`,`outcome` | 本批次各结果的目标计数 |
| `agent_uplink_metrics_failed_total` | counter_i64 | 1 | — | 指标上送失败累计次数 |

### 10.5 ignore 表（登记但不产出指标）

| fact_key | 理由 |
|---|---|
| `process.executable.name` | 身份信息，属发现域 |
| `process.identity` | 身份信息，用于 `instance` 取值 |
| `container.runtime` / `cgroup.path` / `k8s.*` | 身份信息，属发现域；k8s 身份经 `namespace` / `pod` / `container` label 表达 |
| `host.name` | 身份信息，由 `agent` / `instance` 承载 |

---

## 11. 决策记录

| 编号 | 议题 | 决定 | 理由 |
|---|---|---|---|
| D1 | 命名体系 | Prometheus 形态为线名，OTel 约定作 `semconv_ref` | 详见 §2.1 |
| D2 | 单位口径 | 只用基单位；比例 0–1 | 跳过隐式 ÷100 与 ×1024，避开口径不一 |
| D3 | 字符串样本 | 通道只收数值；枚举转 label | 字符串会被链路静默丢弃 |
| D4 | `unit` label | 不发 | 单位由名字后缀承载，重复且易断档 |
| D5 | 内存单位 | 统一 `_bytes` | 页大小不确定，`pages` 无法跨机比较 |
| D6 | 失败目标 | 不发样本，只记 `outcome` | 旧值/0 与新鲜值不可区分 |
| D7 | 采样上限 | 显式登记 + `dropped` 记账 + 确定性选样 | 静默截断无法从数据侧发现 |
| D8 | 主机级指标 | 每 agent 每批只发一次 | 重复序列会污染按 `instance` 的查询 |
| D9 | 身份位 | 只用 `instance`；PID 降为指标值 | PID 会被回收，不能作身份 |
| D10 | 补偿队列 | 指标不进；至多一次 + 失败计数 | 指标可重采，重传预算留给不可重采的信号 |
| D11 | 本地落盘 | 与线格式同构 | 两套格式必然漂移 |
| D12 | label 键命名 | 只用主流权威名；不与主流同名异义 | 避免误读，避免无信息位的重复 |
| D13 | 覆盖完整性 | 每个 fact 必须登记 | 否则「不重要」与「漏登记」无法区分 |
| D14 | 选择类 label | `app` / `env` / `cluster` 必选，其余按需；≤ 6 对；动态状态与版本不进 label | 缺失会让环境/部署单元混进同一聚合；会变的维度一改就断档 |
| D15 | CPU 表示 | 只存累计秒，比例在查询层派生 | 比例必须带分母口径，落库即固化 |

---

## 12. 扩展规程与校验门禁

### 12.1 新增一个指标的步骤

1. 先查 OTel 语义约定是否有对应条目，有则记 `semconv_ref`；
2. 在注册表加一行：`fact_key` / `name` / `type` / `unit` / 常量 label / 动态 label / `semconv_ref`；`fact_key` 必须单位中立（不得带 `_kb` / `_pages` / `_percent`），且其值必须已经是注册表声明的单位；
3. 需要新 label 时，先改 §3 的闭集，再改注册表；
4. 需要新单位时，先改 §5 的闭集与 §2.3 的后缀规则；
5. 采集侧只增加 `fact_key` 产出，不得生成指标名；
6. 更新 §10 表与本文相关章节。

### 12.2 校验门禁（规范要求，须由测试固化）

| 门禁 | 规则 |
|---|---|
| 名字语法 | 匹配 §2.2 文法；无 `.` / `-` / `:` / 连续 `__` / 首尾 `_` |
| 命名空间 | 名字第一段 ∈ 命名空间闭集；label **不得**重复表达域（由名字首段承载） |
| 单位后缀 | §2.3 的映射双向成立：`unit=By` ⇔ 名字以 `_bytes` 结尾，`unit=s` ⇔ 以 `_seconds` 结尾，比例 ⇔ `_ratio`；计数器允许在单位后缀后再接 `_total`；窗口后缀（`_1m`/`_5m`/`_15m`）不参与判定 |
| fact 契约 | `fact_key` 单位中立；fact 值的单位等于注册表 `unit`；常量 label 与注册表声明一致 |
| 单位闭集 | `unit` ∈ {`By`,`s`,`1`}；比例指标的取值范围必须是 `[0,1]` |
| 类型闭集 | `type` ∈ {`gauge_i64`,`gauge_f64`,`counter_i64`,`counter_f64`} |
| 数值 | 不得出现字符串值；不得出现 `NaN` / `±Inf`；容量类非负；`available ≤ total` |
| 注册表唯一性 | `(采集域, fact_key)` 唯一；`name` 全局唯一 |
| label 白名单 | 样本 label 键 ⊆ §3 闭集；未登记键必须被丢弃并记事件 |
| 身份唯一性 | 同一批次内 `(name, agent, instance, 按需 label)` 无重复 |
| 身份稳定性 | 目标类指标的 `instance` 不得含 PID；进程/容器身份必须由稳定标识构成，连续批次取值不变 |
| 选择类 label | 键 ⊆ §3.4 闭集；`app` / `env` / `cluster` 必须存在；每 app 的允许键集校验通过（`shard` / `tier` 不得出现在未登记的系统上） |
| 选择类取值 | 值小写、无空格；`env` ∈ 闭集；值不得编码其他维度（不含环境名、应用名）；不得含动态状态、版本、归属、IP/PID |
| 覆盖完整性 | 每个采集域的 fact 产出集合 ⊆ 注册表 ∪ ignore 表 |
| 投递可观测 | 每批次失败必须反映在 `agent_uplink_metrics_failed_total` |

---

## 13. 常见系统的选择类取值

以下为「每 `app` 登记允许键集与 `role` 词表」的基准表。新增系统时照此登记，不得自创键。

| 系统 | `app` | `cluster` 表示 | `role`（仅静态） | 额外键 | 不进 label、用指标表达 |
|---|---|---|---|---|---|
| 业务 API / 微服务 | 服务名（`api` / `orders`） | 部署单元 | — | — | 实例健康 |
| 定时任务 worker | `worker` | 部署单元 | — | — | 队列深度、失败数 |
| 接入层（Nginx/HAProxy/网关） | `gateway` / `nginx` | 部署单元 | `proxy` | — | VIP 主备状态 |
| Kafka（KRaft） | `kafka` | 集群 | `broker` / `controller` | — | controller 选举、ISR |
| RabbitMQ | `rabbitmq` | 集群 | — | — | queue master |
| Redis Cluster | `redis` | 集群 | **不写**（主从随时切换） | `shard` | 主从关系 |
| Redis Sentinel | `redis` | 集群 | `sentinel` | — | 当前主节点 |
| MySQL 主从 | `mysql` | 集群 | 静态部署才写 `primary` / `replica` | — | 只读状态 |
| MySQL MGR | `mysql` | 集群 | **不写**（角色随选举变） | — | 成员状态、primary 标记 |
| PostgreSQL（Patroni） | `postgres` | 集群 | **不写** | — | primary/standby 标记 |
| MongoDB 副本集 | `mongodb` | 副本集 | `arbiter` | — | primary/secondary |
| MongoDB 分片 | `mongodb` | 集群 | `mongos` / `config` | `shard` | 分片均衡状态 |
| Elasticsearch | `elasticsearch` | 集群 | 主角色（多角色用 one-hot 指标） | `tier` | master 选举 |
| ZooKeeper / etcd | `zookeeper` / `etcd` | 集群 | `observer` / `learner` | — | leader |
| ClickHouse | `clickhouse` | 集群 | `keeper` | `shard` | 副本同步状态 |
| TiDB | `tidb` | 集群 | `tidb` / `tikv` / `pd`（按 app 扩展） | — | PD leader |
| MinIO / 对象存储 | `minio` | 集群 | — | — | 盘与池状态 |
| k8s 节点 | `kubernetes` | 集群 | `worker` / `control-plane` | `zone` | — |
| 跳板机 / 备份机等 | `bastion` / `backup` | 部署单元 | — | — | — |

补充约定：

1. **分片内副本序号**（ClickHouse replica、MongoDB member index）不新增键，用 `instance` 区分。
2. **多角色节点**（KRaft 同机 broker+controller、ES master+data）的 `role` 只写主角色，其余角色用 one-hot 指标（`*_role_is_* 1`）。
3. **主机口径只适用于专用机器**；混跑机器上主机级选择不可用，按进程/容器口径选（指标的 `app` 取目标自身用途）。
4. 上表未列的系统，先在此表登记再接入：没有登记表的 `app` 不得上送指标。
