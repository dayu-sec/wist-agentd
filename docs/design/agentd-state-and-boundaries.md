# wist-agentd 本地状态与边界设计

## 1. 文档目的

本文档把 `wist-agentd` 的两件关键前置设计固定下来：

- 本地状态模型
- 状态边界（写入归属、并发互斥）；模块划分见 [`agentd-architecture.md`](agentd-architecture.md)

它直接服务于：

- `M3 Edge Runtime Skeleton`
- `M5 Controlled Action MVP`

相关文档：

- [`agentd-architecture.md`](agentd-architecture.md)
- [`agentd-failure-handling.md`](agentd-failure-handling.md)
- [`agentd-exec-protocol.md`](agentd-exec-protocol.md)
- [`log-file-state-schema.md`](log-file-state-schema.md)

---

## 2. 核心结论

`wist-agentd` 的实现必须建立在下面三个原则上：

1. 本地状态必须分层
2. 每类状态必须有唯一写入者（本地状态统一经由 `state_store` 落盘）
3. 并发必须显式互斥

一句话说：

- 不允许多个模块抢写同一个状态对象
- 不允许模块之间通过共享写文件协作（只能通过返回对象）
- `scheduler` 每轮只处理一个队列项（`src/runtime/scheduler.rs` 的 `drain_next_with_report_async`）
- action 执行固定单并发，upgrade 与 action 全互斥

---

## 3. 本地状态分层

`wist-agentd` 第一版建议把本地状态分成两大类：

- execution / control state
- telemetry runtime state

其中 execution / control state 再分成五层：

- `agent_runtime_state`
- `execution_queue_state`
- `execution_state`
- `report_state`
- `history_state`

文件日志输入的 checkpoint state 属于 telemetry runtime state，独立定义在：

- [`log-file-state-schema.md`](log-file-state-schema.md)

### 3.1 `agent_runtime_state`

表示 daemon 自身运行态。

主要内容：

- agent 版本
- instance id
- 当前全局模式

例如：

- `normal`
- `degraded`
- `protect`
- `upgrade_in_progress`

### 3.2 `execution_queue_state`

表示等待本地调度的 execution 队列。

这里的 `execution_queue` 专指：

- 已通过本地校验
- 尚未拉起 `wist-exec`
- 正在等待 `scheduler` 调度

它不是：

- 数据面的 buffer / spool
- 网络消息队列
- metrics / logs / traces 事件队列

主要内容：

- 待执行 execution 列表
- `action_id + plan_digest` 去重索引
- 优先级
- 入队时间
- 是否可取消

### 3.3 `execution_state`

表示单个 execution 的运行时状态。

主要内容：

- 当前状态
- 当前 step
- `plan_digest`
- 子进程 pid
- workdir
- deadline
- cancel 标记

### 3.4 `report_state`

表示结果上报状态。

主要内容：

- 是否已形成最终结果
- 结果摘要 / 签名
- 是否已成功回传中心
- 最近一次上报时间
- 最近一次上报失败原因

### 3.5 `history_state`

表示历史归档。

主要内容：

- 最近已执行 `action_id + plan_digest` 索引

第一版不要求长周期历史都在本地保留，但要有最小归档能力。

---

## 4. 本地目录与对象模型

建议 `wist-agentd` 采用如下目录：

```text
<agent_root>/
  run/
    actions/<execution_id>/
  state/
    agent_runtime.json
    execution_queue.json
    running/
      <execution_id>.json
    reporting/
      <execution_id>.json
    history/
    logs/
      file_inputs/
        <input_id>/
          checkpoints.json
  log/
```

### 4.1 `agent_runtime.json`

保存 daemon 自身状态。

建议字段：

- `agent_id`
- `instance_id`
- `version`
- `mode`
- `updated_at`

### 4.2 `execution_queue.json`

保存等待调度的 execution 队列。

建议字段：

- `items[]`

每个 `item` 建议包括：

- `execution_id`
- `action_id`
- `request_id`
- `priority`
- `queued_at`
- `deadline_at`

### 4.3 `running/<execution_id>.json`

保存运行中 execution 的控制视图。

建议字段：

- `execution_id`
- `action_id`
- `state`
- `workdir`
- `pid?`
- `started_at`
- `deadline_at?`
- `cancel_requested_at?`
- `kill_requested_at?`
- `updated_at`

### 4.4 `reporting/<execution_id>.json`

保存待上报或上报中的结果视图。

建议字段：

- `execution_id`
- `action_id`
- `final_state`
- `result_path`
- `report_attempt`
- `last_report_at?`
- `last_report_error?`

### 4.5 `logs/file_inputs/<input_id>/checkpoints.json`

保存文件日志输入的 checkpoint state。

这类状态：

- 不属于 `execution_queue`
- 不属于 `running` / `reporting`
- 不由 `scheduler` 持有

其 schema 独立定义在：

- [`log-file-state-schema.md`](log-file-state-schema.md)

---

## 5. 哪些状态必须落盘

第一版建议明确区分：

### 5.1 必须落盘

- `agent_runtime.json`
- `execution_queue.json`
- `running/<execution_id>.json`
- `reporting/<execution_id>.json`
- `logs/file_inputs/<input_id>/checkpoints.json`
- `run/actions/<execution_id>/plan.json`
- `run/actions/<execution_id>/runtime.json`
- `run/actions/<execution_id>/state.json`
- `run/actions/<execution_id>/result.json`

### 5.2 可以只保存在内存

- 临时调度索引
- 进程句柄对象
- 短生命周期 debounce 状态
- 非关键统计缓存

原则是：

- crash 后必须能恢复的状态，就落盘
- crash 后可以重算的状态，就只放内存

---

## 6. crash 恢复最小算法

`wist-agentd` 启动时至少执行以下恢复步骤：

1. 读取 `execution_queue.json`
2. 扫描 `state/running/*.json`
3. 扫描 `state/reporting/*.json`
4. 扫描 `run/actions/*`
5. 对每个 running execution 检查：
   - 对应 pid 是否仍存活
   - workdir 是否存在
   - `result.json` 是否已存在
6. 形成恢复结论：
   - 若结果已存在，转入 reporting
   - 若进程不存在且无结果，标记为 `failed`
   - 若进程仍存在，重新纳入 running 监控

第一版不要求复杂断点续跑，但必须做到：

- 不重复 spawn 同一 execution
- 不丢失已完成结果
- 不把孤儿执行永久留在 running 状态

---

## 7. 并发与互斥边界

建议 `scheduler` 持有以下调度约束：

- 固定单并发 action 执行槽

第一版建议最保守策略：

- action 执行固定为单并发
- upgrade 与 action 全互斥

这样可以显著降低本地状态复杂度。

---

## 8. 当前决定

当前阶段固定以下结论：

- `wist-agentd` 的本地状态必须分层
- `execution_queue` / `running` / `reporting` / `history` 必须分开
- 每类状态必须有唯一写入模块
- 模块之间通过返回对象协作，不通过共享写文件协作
