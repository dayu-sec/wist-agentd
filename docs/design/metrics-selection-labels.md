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

`env` / `cluster` **不由事实推断**：事实里没有部署单元。`app` 的证据必须来自白名单
（k8s label、容器镜像名、systemd / launchd unit），可执行名 / 端口 / cmdline 只能作发现证据，
不得直接作为取值（规范 §3.4）。

## 3. 接口

### 3.1 agent 拉取

```http
GET /api/v1/agent/metrics-labels        # mTLS，身份取客户端证书
200 {"revision":7,"labels":{"env":"prod","cluster":"kafka-prod","app":"kafka"},
     "sources":{"env":"default","cluster":"default","app":"manual"},"updated_at":"…"}
200 {"revision":0,"labels":{},"sources":{},"updated_at":"…"}   # 当前无可用值
```

- `revision` 单调递增；agent 只在 revision 变大时替换缓存。
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

## 4. agent 侧

- **不写配置文件**：拉到的值只存运行时状态 `state/metrics/labels.json`
  （`{revision, labels, sources, fetched_at}`）；删掉该文件等于回到“无选择类 label”。
- 拉取时机：启动、周期（约 5 min）、手工刷新。失败保留缓存；无缓存 → 指标不带 label。
- 合并与上限在网关侧完成；agent 只做合法性复核，不做业务推断。
- 可观测：`metrics-labels show` 打印生效值与来源；变更（revision 或内容变化）打一行日志，不逐 tick 刷。

## 5. 手工刷新

```bash
wist-agentd refresh --all
wist-agentd refresh --only policies,work,facts,metrics-labels
wist-agentd refresh --only uplink            # 只能显式指定
wist-agentd metrics-labels show|refresh|clear-cache
```

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

实现：命令走现有的本地命令队列（`state_store::commands`），守护进程收到后清零对应来源的节流计时器，
下一 tick 强制拉取；每个来源独立记 `updated` / `unchanged` / `failed(reason)` 到命令台账。
整次刷新有最小间隔（10s）防连点。

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
| P2 | 事实补 `systemd_unit` / `launchd_label` / `container_image` / `k8s.*`；注册表；`app` / `role` 推断 | agentd 发现层 |
| P3 | 批量编辑 / 管理页面 | 网关前端 |

P1 期间 `app` 留空是符合规范的（`{app=""}` 可查）。

## 9. 验收

1. 新装机器：`agentd.toml` 中**没有**任何 `[metrics]` 段；
2. 带旧 `[metrics.labels]` 的配置能启动，且指标不带这些 label（有告警）；
3. `wist-agentd metrics-labels show` 能看到 `env` / `cluster` 与来源；
4. 网关 `PUT` 一台机器的 `app` 后，≤10s 内该机器的指标出现新值；
5. `wist-agentd refresh --all` 在台账里逐项列出 `updated/unchanged/failed`；
6. VM：`count by (env, cluster)` 与 `{app="…"}` 可查；
7. 网关不可用重启 agent：使用缓存标签；清缓存后重启 → 不带标签，不猜。
