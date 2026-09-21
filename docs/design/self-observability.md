# warp-insight Self-Observability 设计

## 1. 文档目的

本文档定义 `warp-insight` 自身的可观测性设计，重点覆盖：

- `wist-agentd`
- `wist-exec`
- `wist-upgrader`

目标是让边缘代理自身也具备可诊断、可验收、可压测的观测能力。

相关文档：

- [`agentd-architecture.md`](agentd-architecture.md)

---

## 2. 核心结论

`warp-insight` 必须把自观测视为一等能力，而不是上线后再补的辅助项。

第一版自观测的落点集中在 `wist-agentd` 的文本日志，分三类输出：

- 周期性快照：`health …`、`metrics_runtime …`、`discovery_probe …`（`src/runtime/self_observability.rs`）
- 状态变化事件：`event=DiscoveryRefreshed` / `event=DiscoveryRefreshFailed` / `event=MetricsRuntimeUpdated` / `event=MetricsRuntimeFailed`
- 工作状态通知：`telemetry work-state paused|resumed`，并随 `AgentStatusReport.work_state_changes` 上报控制面

一句话说：

- 没有 self-observability，就很难验证 `warp-insight` 是否真的轻、稳、可恢复

---

## 3. 设计原则

### 3.1 自观测必须分层

建议分成：

- process-level
- module-level
- workflow-level

### 3.2 自观测不能反过来拖垮 agent

第一版必须控制：

- 自身日志量
- 周期性快照的输出频率（`steady_log` 按「内容签名 + 心跳间隔」收敛，见 §5.2）

### 3.3 自观测优先服务工程验收

第一版重点不是“大而全”，而是能回答：

- agent 现在健康吗
- 为什么拒绝了一个计划
- queue/running/reporting 当前是什么状态
- metrics 数据面是否过载

---

## 4. 观测对象分层

### 4.1 `wist-agentd`

重点观测（对应 `RuntimeHealthSnapshot`，见 `src/runtime/self_observability.rs`）：

- daemon 生命周期：启动日志 `wist-agentd {version} starting: …`
- 运行健康 `health …`：`state` / `queue` / `running` / `reporting` / `paused_inputs` / `discovery_readiness` / `discovery_cached_loaded` / `discovery_used_cached` / `discovery_resources` / `discovery_targets` / `discovery_failures` / `discovery_last_success_at` / `updated_at`
- 发现探针 `discovery_probe …`：`source` / `probe` / `phase` / `status` / `resources` / `targets` / `error`
- 指标健康 `metrics_runtime …`：`target_view_loaded` / `used_cached_snapshot` / `total_targets` / `host_targets` / `process_targets` / `container_targets` / `attempted_targets` / `succeeded_targets` / `failed_targets` / `failures` / `last_error` / `updated_at`
- 状态变化事件：`event=DiscoveryRefreshed` / `event=DiscoveryRefreshFailed` / `event=MetricsRuntimeUpdated` / `event=MetricsRuntimeFailed`
- 工作状态通知：`telemetry work-state paused|resumed`

### 4.2 `wist-exec`

重点观测：

- 进程启动和退出
- step 执行统计
- stdout/stderr 摘要
- 失败、取消、超时原因

### 4.3 `wist-upgrader`

重点观测：

- 升级准备
- 校验
- 切换
- 回滚

---

## 5. Self Logs

### 5.1 输出分类

实际输出按四类：

- 周期性快照：`health …`、`metrics_runtime …`、`discovery_probe …`
- 状态变化事件：`event=DiscoveryRefreshed`、`event=DiscoveryRefreshFailed`、`event=MetricsRuntimeUpdated`、`event=MetricsRuntimeFailed`
- 工作状态通知：`telemetry work-state paused …` / `telemetry work-state resumed …`
- 失败与告警：telemetry 输入失败（`telemetry input missing|failed|output invalid …`）、指标上送失败（`wist-agentd metrics uplink failed: …`）、状态上报失败（`wist-agentd status report failed: …`）、凭证续期失败（`wist-agentd credential renewal failed …`）

### 5.2 稳态收敛

常驻主循环每 tick 都会产出一份健康/指标快照，逐 tick 打印会持续写盘。`src/runtime/steady_log.rs` 按「内容签名 + 心跳间隔」收敛：

- 签名变化（状态迁移、失败计数变化、探针结果变化）立即打印
- 签名不变时只按心跳间隔补一条（默认 300s，`WIST_AGENTD_LOG_HEARTBEAT_SECS` 可调，`0` 关闭收敛）
- 只收敛周期性快照；事件、工作状态通知、失败类日志始终逐条打印

### 5.3 日志约束

第一版必须避免：

- 高频全量 debug 默认打开
- 把大 payload 原样打进日志
- 把敏感 secret 写入日志

---

## 6. Batch A 验收依赖

`Batch A` metrics 数据面是否达标，强依赖 self-observability。

至少需要依靠自观测输出判断：

- scrape 是否稳定
- 样本是否被丢弃
- target 是否持续失效
- memory / cpu 是否逼近上限

也就是说：

- self-observability 不是附属功能
- 它是 metrics 数据面验收前提

---

## 7. 第一版限制

第一版不建议：

- 做复杂 tracing 链路
- 做高频全事件持久化
- 做过深的 profiling 系统

第一版先把：

- 周期性快照（`health` / `metrics_runtime` / `discovery_probe`）
- 状态变化事件与工作状态通知

做稳定即可。

---

## 8. 当前决定

当前阶段固定以下结论：

- `warp-insight` 自身必须具备自观测能力
- `wist-agentd` 的 queue / running / reporting / paused 必须有对应的 health 快照字段
- metrics 数据面验收必须依赖 self-observability 输出（health 快照字段 + 文本日志）
- 自观测要受控，不能反过来拖重 agent
