# 指标选择类 label 的下发与刷新

> 配套规范：[`metrics-data-spec.md`](./metrics-data-spec.md) §3.4（选择类 label）、§10（注册表）。
> 本文只回答：**label 的值从哪来、agent 怎么拿、怎么手工刷新**。

## 1. 目标

1. agent 的指标序列带上 `env` / `cluster`（以及可推断时的 `app` / `role`）。
2. 值由**控制面（网关）**统一给，不在每台机器上手写，不存在 `agentd.toml`。
3. 运维可以在网关上一台或一批地手工调整，改完尽快生效、无需重装与重启。
4. 所有需要的“知识/期望状态”都能被一个手工刷新命令覆盖，排障时不靠等节流过期。

## 2. 来源与优先级

三个来源都在网关侧，按**键**合并：

| 层 | 维护者 | 典型键 | 说明 |
|---|---|---|---|
| 部署默认 | 网关配置文件 | `env`、`cluster` | 一个部署一套，启动时校验 |
| 自动推断 | 网关（事实入库后） | `app`（`role` 暂不推断） | 白名单证据 + 注册表命中；判不出留空 |
| 每 agent 手工覆盖 | 网关管理接口 / 页面 | 任意合法键 | 例外处理 |

优先级（逐键）：**手工 > 推断 > 部署默认**；三者都没有 → **不发**该 label，不猜、不补默认。

`env` / `cluster` **不由事实推断**：事实里没有部署单元。`app` 的证据必须来自白名单，
可执行名 / 端口 / cmdline 只能作发现证据，不得直接作为取值（规范 §3.4）。

### 2.1 推断（P2）

| 项 | 口径 |
|---|---|
| 证据来源 | `service_units`（systemd 单元，含 `@实例`）、`container_names`（k8s 下即 pod spec 的容器名）。两者随事实摘要上送，**进内容摘要**（`fact-v4`） |
| 取值闭集 | 注册表 `wist-knowledge/metrics-app-registry.toml`（网关 `[metrics] registry_file`） |
| `app` | 证据命中**唯一**一个已登记的 app → 写；零个 → 留空；≥2 个（混跑）→ 留空并记事件 |
| `role` | 在命中的证据串里按 `-` `_` `.` `@` 切词，命中该 app 登记的 role 才写；两个不同角色词 → 有歧义，不写 |
| 单元模板 | `kafka@broker-1` 按模板名 `kafka` 命中 app；报出去的实例名里的 `broker` 用来定 role |
| 注册表变更 | 按文件 mtime 缓存，**改完即生效**（补登记不必重启网关）；读坏沿用上一份 |
| 采集缺口 | macOS 的 launchd label 需要 `launchctl` 子进程，本阶段不采 → macOS 上 `app` 留空 |

为什么 `role` 词表是闭集而不是「每 app 自由扩展」：`role` 会出现在查询与告警表达式里，
让一份策展文件引入任意词等于让 `{role=…}` 静默分裂。新增角色 = 改规范 + 改实现（一次发布），
登记表只决定某个 app 允许哪几个已有的词。

## 2.2 合并与降级（网关侧）

- 逐键合并，优先级 **手工 > 推断 > 部署默认**；三层都没有的键**不发**。
- **推断出的 `role` / `shard` / `tier` 依附于推断出的 `app`**：`app` 一旦被部署默认或手工覆盖
  取代，这几个键就一起撤掉 —— 否则会写出 `{app="redis", role="broker"}` 这种语义错的值
  （那个角色只在 kafka 的登记表里成立）。
- **永不下发非法值集**：agent 对选择类 label 是**整包拒收**的，一份坏响应只会让它保留旧缓存
  （现场表现为「改了标签但指标没变」）。所以网关在下发前自检，非法时按阶梯降级：
  1) 三层全量；2) 丢掉推断层（唯一「可缺」的一层）；3) 下发空表。每一级都记
  `MetricsLabelsEffectiveInvalid`，便于追「为什么某个 label 没出现」。
- `sources` 逐键标注来源（`default` / `inferred` / `manual`），只用于展示与排障，不参与取值。

### 已知偏差（待 P3 —— [issue #2](https://github.com/dayu-sec/wist-gateway-stack/issues/2)）

选择层当前贴在**该 agent 的全部序列**上（含 `process_*` / `container_*`）。规范 §3.4 规则 3 要求
进程/容器指标上的 `app` 表示**目标自身**用途；要按目标贴标，需要把证据按 cgroup / 容器归属
下沉到 target 层。在那之前，主机口径的 `app` 对进程/容器序列同样生效 —— 查询时若关心
「某个进程是不是 kafka」，请用进程/容器口径的 `instance`，不要依赖 `app`。
范围与验收标准见 [issue #2](https://github.com/dayu-sec/wist-gateway-stack/issues/2)。

## 3. 接口

### 3.1 agent 拉取

```http
POST /api/v1/agent/metrics-labels:poll      # mTLS，身份取客户端证书
{"api_version":"v1","kind":"poll_agent_metrics_labels",
 "agent_id":"…","instance_id":"…","requested_at":"…"}

200 {"api_version":"v1","kind":"agent_metrics_labels","agent_id":"…","revision":7,
     "labels":{"env":"prod","cluster":"kafka-prod","app":"kafka"},
     "sources":{"env":"default","cluster":"default","app":"manual"},"updated_at":"…"}
200 {…"revision":0,"labels":{},"sources":{}}   # 当前无可用值（合法，不是错误）
```

**为什么是 `POST` + `:poll` 而不是 `GET`**：与 agent 面其余拉取端点（`work:poll` /
`uplink:poll` / `discovery-policies:poll`）同一形状 —— 身份（`agent_id`）在**请求体**里，
不进出 URL（不落访问日志、不落代理日志）；`:poll` 明确它是幂等拉取而不是一次汇报。

- `revision` 是网关侧该 agent 这份值的版本（手工覆盖每次写入 +1）。agent 在
  **版本变化或内容变化**时替换缓存 —— 只比版本会让「改了部署默认、各 agent 没有手工覆盖
  （版本仍是 0）」这种变更永远推不下去。
- 响应非法（键不在闭集、值不合法、`env` 越界、合并后 > 6 对）→ **整包拒绝**，保留旧缓存并告警。

### 3.2 管理面

```http
GET    /api/v1/admin/agents/{agent_id}/metrics-labels   # 生效值 + 每键来源
PUT    /api/v1/admin/agents/{agent_id}/metrics-labels   # 设置手工覆盖（只传要改的键）
DELETE /api/v1/admin/agents/{agent_id}/metrics-labels   # 清除手工覆盖
```

- `PUT` 写前校验，非法直接 400；成功后 `revision += 1` 并给该 agent 排一条
  `refresh`（`what=["metrics-labels"]`）命令，下一次状态上报即送达（≤3s）。
- 每 agent 的手工覆盖可单独清除，清除后回落到推断 / 部署默认。
- **手工补发刷新（P4）**：

```http
POST /api/v1/admin/agents/{agent_id}/refresh
{"what":["metrics-labels"]}
200 {"command_id":"…","agent_id":"…","kind":"refresh","requested_at":"…"}   # 与 fact-refresh 同形状
```

  - **复用通用 `refresh` 命令面，不为 label 单开端点**（`command_kind::REFRESH` + `RefreshParams`）：
    agent 能刷新的来源是一个闭集（`refresh_what::ALL`），运维在命令台账里读到的值必须能直接抄回
    CLI 的 `--only`；再开一个 `metrics-labels:refresh` 就成了第二套词。
  - `what` 必填，每项必须在 `refresh_what::ALL` 内；空表报 400 —— 不能让一个请求"什么都不说
    就刷一堆"。
  - 与写入路径的关系：`PUT` / `DELETE` **已经自动**排刷新，这个端点只是"重发一次"，用于
    "改了但 agent 没拿到"的排障，不是正常生效路径。

## 4. agent 侧

- **不写配置文件**：拉到的值只存运行时状态 `state/metrics/labels.json`
  （`{revision, labels, sources, fetched_at}`）；删掉该文件等于回到“无选择类 label”。
- 拉取时机：启动（首拍）、周期（5 min）、手工刷新。失败保留缓存；无缓存 → 指标不带 label。
- 缓存文件被写坏 / 值越界 → 当作「没有缓存」（不带着越界值贴标），下一次拉取自动重建。
- 合并与上限在网关侧完成；agent 只做合法性复核，不做业务推断。
- 可观测：`metrics-labels show` 打印生效值与来源；**生效值**变了才打一行 `MetricsLabelsApplied`，
  不逐 tick 刷。版本号只作留痕：管理员把同一个值再写一次会让 `revision` +1，但序列没变，
  因此不记为变更。
- 缓存每次成功拉取都落盘（哪怕值没变）：它同时回答「上次成功拉取是哪一刻」；
  只在变更时写会让 `show` 的 `fetched_at` 停在上一次变更上，现场会以为「根本没在拉」。
- 未入网 / 未配控制面**不算失败**（没有可拉的东西），只有「配置齐全但请求失败」才记 `failed`。

## 5. 手工刷新

```bash
wist-agentd refresh --all                    # facts, policies, work, metrics-labels
wist-agentd refresh --only policies,work,facts,metrics-labels
wist-agentd refresh --only uplink            # 只能显式指定
wist-agentd refresh --only credentials       # 排障：立刻尝试续期
wist-agentd refresh --all --wait 30          # 等结果（默认 15s，最长 120s）
wist-agentd metrics-labels show|refresh|clear-cache
```

范围**必须显式给**（`--all` 或 `--only`）：一次刷四个来源代价不小，手滑敲一个 `refresh`
不该悄悄触发它。

覆盖范围：

| kind | 对应接口 | 说明 |
|---|---|---|
| `facts` | 重采 + 重报事实 | 现有 `refresh-facts` |
| `policies` | `/api/v1/agent/discovery-policies:poll` | 发现策略 |
| `work` | `/api/v1/agent/work:poll` | 工作授权 |
| `metrics-labels` | `/api/v1/agent/metrics-labels` | 选择类 label |
| `credentials` | `/api/v1/agent/credentials:renew` | 排障用，不进 `--all` |
| `uplink` | `/api/v1/agent/uplink:poll` | **不进 `--all`**：直接影响“发不发、发到哪” |

不纳入：`discovery-snapshot`、`source-search-policy`（跟随各自节奏）、`enroll`（身份，用 `enroll --force`）、
各上传接口与安装期接口。

实现：命令走现有的本地命令队列（`state_store::commands`），守护进程收到后把对应来源的
节流计时器清零（或置强制位），**本拍**的常规拉取立即执行一遍；拉取逻辑只有一处，
命令只负责说「这一次别等节流」。每个来源独立记 `updated` / `unchanged` / `failed`
到命令台账的一行 `detail`（如 `work=unchanged policies=updated`），**只要有来源失败就整体
`failed`** —— 点了四项只成三项不叫刷新成功。

`metrics-labels clear-cache` 只删本机缓存文件；**运行中的守护进程内存里那份要到重启或下一次
拉取才变**（下一次拉取会重新写回同一份值），所以它的用途是「让下次启动从干净状态开始」。

### 5.1 从网页触发（P4）

同一套词表也要能从管理面用，否则运维只能在 agentd 那台机器上敲 CLI：

- **入口位置**：主机 → 指标标签页的「重新下发」，固定发 `what=["metrics-labels"]`。
- **错误口径**：400 显示稳定原因码（`unknown_refresh_source` / `empty_refresh_what`）；
  429 走既有的限流倒计时；未知 agent 404 与读写接口一致。
- **不做的**：`uplink` / `credentials` 不给页面入口 —— 它们直接影响「发不发、发到哪」与凭据，
  误点代价比少一个按钮大；两者只留 CLI。
- **不做「等 ack」轮询**：命令台账页已经能看结果，标签页轮询只会多一份状态源。

## 6. 生效与断档

选择类 label 的值变化会**断开序列**（规范 §3.4 / §9）。因此：

1. 只放部署期稳定的值；变更要集中、一次性做。
2. 手工覆盖是例外手段，不作为日常开关。
3. 变更后历史不回填：新旧值在时间轴上自然分段。

## 7. 迁移：`[metrics.labels]` 废弃

agentd 配置中的 `[metrics.labels]` **停止生效**，但保留解析一个版本，避免旧配置启动失败：

- 加载时不再校验、不再用于样本；
- 非空时启动告警一次：`[metrics.labels] 已废弃：选择类 label 改由网关下发`；
- 下一版删除该结构体与文档段。

## 8. 分阶段

| 阶段 | 内容 | 依赖 |
|---|---|---|
| P1 | 网关接口 + 部署默认（`env`/`cluster`）+ 手工覆盖；agent 拉取 / 缓存 / 三个子命令；`refresh` 命令面；`[metrics.labels]` 废弃 | 无 |
| P2 | 注册表 + `app` / `role` 推断（**已完成**：systemd 单元 / 容器名）；launchd label 与容器镜像名待补 | agentd 发现层 |
| P3 | 管理页面：单机逐键编辑（`/agents/:agentId/labels`）(**已完成**) | 网关前端 |
| P4 | 手工刷新入口：`POST /api/v1/admin/agents/{id}/refresh` + 标签页「重新下发」（见 §10）(**已完成**) | 网关 + 前端 |
| P5 | 批量编辑 / 批量下发（一组机器一次改同一个键） | 网关前端 |

P1 期间 `app` 留空是符合规范的（`{app=""}` 可查）。P2 起 `app` 由注册表推断；
**macOS 与未登记的系统仍然留空** —— 那不是缺陷，是「判不出就不写」。

## 9. 验收

1. 新装机器：`agentd.toml` 中**没有**任何 `[metrics]` 段；
2. 带旧 `[metrics.labels]` 的配置能启动，且指标不带这些 label（有告警）；
3. `wist-agentd metrics-labels show` 能看到 `env` / `cluster` 与来源；
4. 网关 `PUT` 一台机器的 `app` 后，≤10s 内该机器的指标出现新值；
5. `wist-agentd refresh --all` 在台账里逐项列出 `updated/unchanged/failed`；
6. VM：`count by (env, cluster)` 与 `{app="…"}` 可查；
7. 网关不可用重启 agent：使用缓存标签；清缓存后重启 → 不带标签，不猜。
8. Linux 上跑 `kafka@broker-1.service`：`metrics-labels show` 能看到 `app=kafka`、
   `role=broker`，来源均为 `inferred`；
9. 同一台机器同时跑 kafka 与 postgres（都已登记）：`app` 留空，`env` / `cluster` 照常；
10. 在注册表里补登记一个新的 unit 名后，**不重启网关**，5 分钟内该机器的 `app` 出现；
11. 标签页点「重新下发」后，命令台账出现一条 `refresh` / `["metrics-labels"]`，≤3s 该 agent 重新拉取；
12. `POST …/refresh` 带 `what:[]` 或 `what:["bogus"]` → 400，且**不排任何命令**。

## 10. P4 任务清单（手工刷新入口）

目标：把已经存在的 `refresh` 命令面接到管理面与页面上，**不新增第二套刷新语义**。

### 10.1 先确认的边界

| 问题 | 结论 | 理由 |
|---|---|---|
| 是否为 label 单开 `metrics-labels:refresh`？ | 否 | 一个闭集、一套词；台账里的值要能直接抄回 `--only` |
| 是否允许 `what: []`？ | 否（400） | 空表会被 agent 当"无效参数"，而页面会把它渲染成"刷新成功" |
| 是否让页面等 ack？ | 否 | 台账页已有结果；两处状态源必然漂移 |
| 是否给 `uplink` / `credentials` 入口？ | 否 | 直接影响发送目标与凭据，误点代价大 |

### 10.2 wist-gateway

- [x] `POST /api/v1/admin/agents/{agent_id}/refresh`，body `{"what":["metrics-labels"]}`
- [x] 鉴权与 429 沿用 `require_admin_bearer`；未知 agent → 404（与 metrics-labels 三接口一致）
- [x] 校验：`what` 非空、逐项 ∈ `refresh_what::ALL`；失败给稳定原因码（`empty_refresh_what` /
      `unknown_refresh_source`）
- [x] 排 `kind = command_kind::REFRESH`，`params = serde_json(RefreshParams{ what })`
- [x] 响应与 `fact-refresh` 同形状（命令回执），便于前端复用现有渲染
- [x] 测试：正常排单 / 空表 400 且未排单 / 未知来源 400 / 未知 agent 404 / 连按两次 = 两条命令
- [x] `wist-design/doc/design/foundation/api-seam-inventory.md` 补这条 seam

实现补充（清单里没写死、落地时定下的两条）：

- **入队是追加语义，不按 kind 覆盖**：本端点的 kind 恒为 `refresh`，但 `params.what` 可以不同；
  沿用 `replace_pending_same_kind = true` 会让「先刷 policies 再刷 metrics-labels」静默丢掉前者。
  同一个 `what` 连点两次就是两条命令（agent 侧重复刷新幂等）。
- **失败渲染**：`400` 在页面上显示 `ApiError.code` 原文（`empty_refresh_what` /
  `unknown_refresh_source`），不翻成泛化的“请求不合法”。

### 10.3 wist-gateway-web

- [x] `src/api/admin.ts`：`dispatchAgentRefresh(agentId, what)` + 归一化（缺 `command_id` 即抛错）
- [x] `src/hooks`：`useAgentRefresh(agentId)`；成功后只回填提示，不轮询
- [x] 标签页生效表旁「重新下发」：固定 `what=["metrics-labels"]`，成功后提示「已排队，≤3s 送达」
- [x] 失败：400 显示原因码，429 走 `RateLimitNotice`
- [x] 测试：contract（路径 / 方法 / body / 400 原因码 / 429 退避）

### 10.4 验收

见 §9 第 11、12 条；另外确认命令台账里这一条与 CLI `refresh --only metrics-labels`
产生的是**同一种命令**（kind 与 params 逐字一致）。
