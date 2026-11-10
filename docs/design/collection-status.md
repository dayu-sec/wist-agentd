# 采集状态（`AgentLocalCollection`）

> 回答一个问题：**这个采集面到底采成没采成**。
>
> 线上字段：`local.standing[].collection`，由 agentd 本机观测后随工作视图上报。
> 状态是**多字段、正变的**：前置条件、执行结果、原因分开表达，不折叠成单一 `status`。

## 1. 字段

| 字段 | 闭集 | 定义 |
|---|---|---|
| `prerequisites` | `ready` / `blocked` | 前置条件是否具备：工具、依赖、来源、目标 |
| `result` | `success` / `partial` / `failure` / `cancelled` / `pending` | 执行结果 |
| `reasons` | `[{kind, subject, detail}]` | 为什么不是成功；不参与状态判定 |
| `observed_at` | 时间 | 得出该结论的时刻 |

### `prerequisites`

| 取值 | 含义 |
|---|---|
| `ready` | 所需工具 / 依赖 / 来源 / 目标都已具备 |
| `blocked` | 至少一个必备条件缺失；具体原因看 `reasons` |

### `result`

| 取值 | 含义 |
|---|---|
| `success` | 尝试过的单元全部成功，且没有软缺陷 |
| `partial` | 有内容采到，但部分单元失败 / 被阻塞，或有软缺陷（截断、指标部分失败） |
| `failure` | 尝试过但全部失败，或结构性错误（参数解析失败 / 零单元） |
| `cancelled` | **未执行**：工作暂停、上送关闸，或前置条件不满足 |
| `pending` | 还没有可判定的观测（首轮未完成）；不是错误，也不是取消 |

### 原因 `kind`（闭集）

`missing_tool` / `missing_dependency` / `source_not_ready` / `target_not_ready` /
`permission` / `missing_input` / `run_failed` / `unsupported` / `truncated` /
`invalid_spec` / `no_units` / `no_content` / `incomplete_data` / `paused` /
`standby` / `metric_partial`

## 2. 判定顺序（agentd `CollectionHealth::assess`）

1. 数据面上送关闸 → `result=cancelled`，`reasons=[standby]`
2. 工作 `status != active` → `result=cancelled`，`reasons=[paused]`
3. 工作参数无法解析 → `result=failure`，`reasons=[invalid_spec]`
4. `active` 但零单元 → `result=failure`，`reasons=[no_units]`
5. 汇总本 tick 证据：
   - **硬失败**：文件不存在 / 权限不足 / 未支持单元 / 导出器**运行**失败 / 指标域全部失败；
   - **阻塞**：导出器工具缺失（`blocked`）、指标目标未就绪（`blocked` + `pending`）；
   - **软问题**：行截断、记录不完整、指标 tick 级失败、指标部分目标失败；
   - **健康信号**：成功采集的任务 / 正常跑完的导出器 / 成功的指标域。
6. 折叠：
   - 有硬失败：还有健康 → `partial`；没有 → `failure`
   - 无硬失败、缺工具：还有健康 → `partial`；没有 → `cancelled`
   - 无硬失败、目标未就绪：还有健康 → `partial`；没有 → `pending`
   - 只有软问题：还有健康 → `partial`；没有 → `pending`
   - 有健康 → `success`；否则 `pending`

判定**每 tick 全量重算**，失败修好后会自然恢复（不靠人工清状态）。

## 3. 什么**不是**错误

| 现象 | 字段组合 | 说明 |
|---|---|---|
| 工作暂停 / 上送关闸 | `cancelled` + reason `paused`/`standby` | 本就不该采 |
| 日志文件很安静 | `success` | 没有失败 ≠ 没有新数据 |
| 过滤 / 降噪命中 | `success` | 主动不采 |
| 行被截断 / 记录不完整 | `partial` + reason `truncated`/`incomplete_data` | 软缺陷，不判 failure |
| **导出器工具未安装**（如 `smartctl`） | `prerequisites=blocked`、`result=cancelled`、reason `missing_tool` | 装上即自动恢复 |
| 发现层目标未产出 | `prerequisites=blocked`、`result=pending`、reason `target_not_ready` | 等自动条件 |
| 首轮还没跑完 | `result=pending` | 还没有可判定的观测 |

`smartctl` 的完整形态：

```json
{
  "prerequisites": "blocked",
  "result": "cancelled",
  "reasons": [
    {"kind": "missing_tool", "subject": "smartctl",
     "detail": "工具缺失：/usr/sbin/smartctl（装上后自动恢复）"}
  ],
  "observed_at": "2026-11-10T00:00:00Z"
}
```

## 4. 页面如何组合

| `prerequisites` | `result` | 展示 |
|---|---|---|
| `ready` | `success` | 采集正常 |
| `ready` | `partial` | 部分失败 |
| `ready` | `failure` | 采集失败 |
| `ready` | `cancelled` | 未采集（暂停 / 待命） |
| `ready` | `pending` | 尚未观测 |
| `blocked` | `cancelled` | **待就绪（缺工具）** |
| `blocked` | `pending` | 待就绪（等目标 / 首轮） |
| `blocked` | `partial` / `success` | 有内容在采 **+ 待就绪项** |

原因列表（`reasons`）原样展示，不再从一段 `detail` 里猜。

## 5. 兼容与迁移

- 旧字段 `status` / `detail` 仍由 agentd 输出（由新字段派生），供未升级的网关 / 中心 / 页面使用；
  新消费方**以 `result` 为准**。
- 旧 agentd 只报 `status` / `detail` 时，新字段为空 —— 新消费方回退到旧字段。
- 新 agentd 的输出含新字段，**旧网关**（`deny_unknown_fields`）会拒收整份上报：
  升级顺序必须是 **gateway（含 center）→ agentd**。
- 兼容字段在消费方全部升级后删除。

## 6. 与其他状态的区别

| 概念 | 区别 |
|---|---|
| 工作状态（`active` / `paused`） | 回答「**该不该**采」 |
| 确认版本（`acknowledged_version`） | 回答「工作**收到没**」 |
| 采集状态（本文） | 回答「**到底采成没采成、为什么**」 |
| `agent_*` 自观测 | agent 进程自身的健康，不替代采集状态 |

## 7. 演进约定

新增取值是一次**跨仓契约变更**：

1. `wist-contracts` 的 `collection_prerequisites` / `collection_result` /
   `collection_reason_kind` 加常量并纳入 `ALL`；
2. `wist-agentd` 的判定逻辑与测试；
3. `wist-gateway` 透传 + 契约测试；
4. `wist-gateway-web` / `wist-center-web` 的 label / tone / 统计；
5. 同步本文与契约注释。

只在 agentd 单侧新增取值 = 页面显示原始字符串、统计漏计，属于故障。
