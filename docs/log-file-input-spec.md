# warp-insight 文件日志输入设计

## 1. 文档目的

本文档定义 `wist-agentd` 对日志文件的常驻读取能力。

这里的“文件日志输入”特指：

- `wist-agentd` 作为数据面常驻组件持续监控和读取文本日志文件
- 将文件新增内容转换为统一 telemetry record
- 进入统一 `record -> buffer/spool -> export` 主线

本文档不讨论：

- 远程动作里的 `file.tail` / `file.read_range`
- `syslog` / `journald` / `winlog` 等非文件输入
- `warp-parse` 内部 receiver 的实现细节

---

## 2. 核心结论

第一版固定以下结论：

- 文件日志读取是 `wist-agentd` 的一等数据面能力，不是远程动作替代方案
- 第一版必须明确对标 `Fluent Bit tail input`
- 对标对象是能力边界和工程行为，不是把 `warp-insight` 定义成 Fluent Bit 封装层
- 第一版必须覆盖（下列各项在当前实现中均有落点，真实流水线见 §5.1）：
  - 启动读头/读尾策略（`startup_position = head | tail`）
  - `commit point`、本地 checkpoint 持久化与 crash 恢复
  - 文件 rotate / truncate 处理
  - per-`agent` 全局 `seq` 取号与去重（见 §10.1.1）
  - 长行截断提交 + 计数、多行拼装、buffer/spool 背压
  - record 来源字段注入（`input_id` / `source_path` / `file_offset` / `file_offset_end`）与 `seq` 取号（见 §10.1）
- 该清单**不包含**以下机制（代码中无落点，不作为已实现能力）：
  - resource 绑定与资源引用（`resource_refs`）注入
    （契约 `TelemetryRecord` 固定为 `schema_version / agent_id / observed_at / input_id / source_path / body / file_offset / file_offset_end / seq` 九个字段，无资源引用字段）
  - glob/路径匹配与排除，以及新发现文件的起始位置策略
    （契约 `LogFileInputSection` 只有 `input_id / path / startup_position / multiline_mode`，是**单个显式路径**，无 `path_patterns` / `exclude_path_patterns`）
  - `file watcher` 与轮询 fallback
    （`src/` 下无 `inotify` / `native_notify` 相关代码；读取由主循环 tick 逐轮驱动，
    见 `src/runtime/daemon_telemetry.rs` 中逐 input 的 `process_once_async`）
- 第一版不要求完全复刻 Fluent Bit 的全部历史兼容行为

一句话说：

- `wist-agentd` 需要做一个可对标 `Fluent Bit tail` 的文件日志输入器
- 但输出目标不是 Fluent Bit tag/chunk 模型，而是 `warp-insight` 的统一 record / buffer 模型

实施阶段边界固定为：

- `M4` 实现其受控子集，用于先验证 `standalone` 替代切片
- `M4` 的实现边界收敛为：
  - 显式单路径输入（`input_id` + `path`），而不是通用 `path_patterns[]` 发现模型
  - 最小 `parser / multiline / checkpoint / rotate / truncate / restart recovery` 链路
  - 最小 `buffer / spool -> warp-parse / file output` 主线
- 本文档旧版本中的通用能力描述（discovery、watcher 策略、完整调度、保护模式与自观测扩展）没有代码落点，不作为已实现能力引用

---

## 3. 对标基线

### 3.1 参考对象

当前对标基线采用 Fluent Bit 官方 `Tail` 输入文档：

- `https://docs.fluentbit.io/manual/pipeline/inputs/tail`

按当前官方文档，Fluent Bit `tail` 已覆盖以下关键能力：

- `path` / `exclude_path`
- `read_from_head`
- `read_newly_discovered_files_from_head`
- `db` / `db.sync` / `db.compare_filename`
- `rotate_wait`
- `inotify_watcher`
- `buffer_chunk_size` / `buffer_max_size`
- `mem_buf_limit`
- `skip_long_lines` / `skip_empty_lines`
- `parser`
- `multiline.parser`
- `path_key` / `offset_key`
- `ignore_older`

### 3.2 对标口径

对标时要明确：

- 目标是达到同类成熟日志文件输入器应有的能力下限
- 不是要求配置名、内部状态文件格式、输出结构与 Fluent Bit 完全一致
- `warp-insight` 可以用更适合自身架构的对象模型替代 Fluent Bit 的 plugin/tag/chunk 习惯

### 3.3 我们应优于 Fluent Bit 的地方

第一版设计应明确争取在以下方面优于 Fluent Bit：

- `commit point`、checkpoint 与本地 spool / buffer 的关系更清晰
- record 自带来源定位字段（`source_path` / `file_offset` / `file_offset_end`）与归属字段 `input_id`，不依赖后置 filter 拼装
- 交付语义显式：per-`agent` 全局 `seq` + at-least-once（见 §10.1.1）
- spool 超限是显式的「暂停采集 + 工作状态通知」状态，而不是静默丢弃
- `standalone` / `managed` 模式下行为一致

---

## 4. 边界定义

### 4.1 它负责什么

文件日志输入负责：

- 读取配置指定的目标文件（`file_inputs[].path`，单个显式路径）
- 持续读取新增内容
- 进行按行切分
- 执行 parser / multiline 预处理
- 填充 record 来源字段（`input_id` / `source_path` / `file_offset` / `file_offset_end`）与 `seq`
- 把结果写入统一 telemetry pipeline
- 管理本地 checkpoint

### 4.2 它不负责什么

文件日志输入不负责：

- 远程文件内容读取
- 控制平面计划下发
- 复杂语义解析与 AI 推理
- 中心侧审计归档
- 取代 `warp-parse` 进行大规模规则解析

### 4.3 与 `file.tail` 的关系

必须明确区分：

- `logs.file_inputs[]`：
  常驻数据面输入
- `file.tail`：
  远程动作 opcode，用于临时诊断读取

两者都可能读取同一路径，但职责完全不同。

---

## 5. 运行模型

### 5.1 总体流水线

文件日志输入的流水线（由 daemon 的 telemetry tick 逐 input 轮询驱动，入口为 `src/runtime/daemon_telemetry.rs:167` 的 `FileInputProcessor::process_once_async`）固定为：

```text
按配置路径打开 -> 判定续读位置（resume / truncate / rotate）
-> 增量读取（预算内、长行截断）-> 按行切分 -> 多行拼装
-> 解析为 telemetry record -> 挂载来源字段与 seq
-> 入队本地 telemetry buffer/spool -> 到达 commit point -> 推进 checkpoint
```

各阶段对应的真实模块：

- 续读位置判定（`startup_position` / truncate / rename-rotate）：`src/telemetry/logs/files/file_watcher.rs` 的 `decide_resume_async`
- 增量读取与按行切分（`max_read_bytes_per_tick` / `max_lines_per_tick` / `max_line_bytes`）：`src/telemetry/logs/files/file_reader.rs` 的 `read_from_offset_async`
- 多行拼装：`src/telemetry/logs/multiline.rs`、`src/telemetry/logs/files/multiline_support.rs`
- 解析为 record（分配 `seq`）：`src/telemetry/logs/parser.rs` 的 `parse_folded_lines`
- buffer/spool 与 `commit point`：`src/telemetry/logs/files/delivery_support.rs`、`src/telemetry/buffer.rs`、`src/telemetry/spool.rs`
- checkpoint / `seq` 推进：`src/telemetry/logs/files/checkpoint_support.rs`、`src/state_store/log_checkpoints.rs`、`src/state_store/log_seq_state.rs`

驱动方式是**轮询 tick**：每个 tick 对每个 input 调用一次 `process_once_async`；不存在事件驱动 `watcher`、多路径 `discover` 与扫描调度阶段。

### 5.2 读取模型

每个被跟踪文件应维护独立 reader 状态：

- 当前 `file identity`
- 当前 `read offset`
- 最近读取时间
- 当前行缓冲
- multiline 暂存状态

读取语义固定为：

- 只读取追加内容
- 默认按 `\n` 切分
- 对未完成尾行不提交，留待下次读取补齐（行边界结算见 §6.5）

---

## 6. 配置骨架

第一版在 `AgentConfig.telemetry.logs`（契约 `LogsSection` / `LogFileInputSection`）下固定如下结构：

```text
LogsSection {                          # [telemetry.logs]，全局配置（非 per-input）
  file_inputs[]?                       # 或 file_inputs_file 指向外置清单（二选一）
  file_inputs_file?
  in_memory_buffer_bytes?
  max_line_bytes?
  max_read_bytes_per_tick?
  max_lines_per_tick?
  spool_max_bytes?
  spool_over_limit?                    # 当前仅 "pause"
  spool_dir?
  output {                             # kind = "file" | "tcp"
    kind
    file { path }
    tcp { addr, port, framing }
  }
}
```

```text
LogFileInputSection {                  # [[telemetry.logs.file_inputs]]
  input_id                             # 必填，唯一
  path                                 # 必填，单个显式路径
  startup_position?                    # "head"（默认）| "tail"
  multiline_mode?                      # "none"（默认）| "indented"
}
```

实施阶段约束：

- `M4` 实现只要求其中的受控子集：
  - `input_id`
  - `path`（单路径目标字段）
  - 最小 `startup_position`
  - 最小 `multiline_mode`

字段归属：

- 归 `LogFileInputSection`（per-input）：`input_id`、`path`、`startup_position`、`multiline_mode`
- 归 `LogsSection`（**全局**）：`in_memory_buffer_bytes`、`max_line_bytes`、`max_read_bytes_per_tick`、`max_lines_per_tick`、`spool_max_bytes`、`spool_over_limit`、`spool_dir`、`file_inputs_file`、`output`

字段说明：

- `startup_position`
  - `head`
  - `tail`

### 6.1 `parser`

不存在独立的 `parser` 配置项（契约里没有该字段）。解析阶段固定：
`src/telemetry/logs/parser.rs` 的 `parse_folded_lines` 把行直接映射为 `TelemetryRecord`
（不做结构化字段提取）。

### 6.2 `multiline`

配置项是 `LogFileInputSection.multiline_mode`（**不是** `multiline` 子结构），取值固定为：

- `none`（默认）
- `indented`

两个值由校验层限制（`wist-validate`：非 `none` / `indented` 返回 `invalid_log_multiline_mode`）。

### 6.3 长行保护（`max_line_bytes`）

**v1 决策（长行保护）**：超长行采用「**截断提交 + 计数**」——

- `max_line_bytes`（`[telemetry.logs]` 全局字段，默认 1 MiB）：单行超过上限时按上限截断后作为一条记录提交，不阻塞读取、不丢后续行；
- 每次截断计入 `truncated_lines` 计数（精确语义见 §6.5）；
- 目的：避免“无换行大文件”把内存拖垮或让读取永久不推进。

> 精确边界语义（行边界结算、恰等于上限不截断、EOF 截断提交、分块回放等）见 §6.5。

### 6.4 spool 超限（`spool_max_bytes` / `spool_over_limit`）

**v1 决策（spool 超限）**：spool（落盘待发队列，见 `src/telemetry/spool.rs`）必须有上限；
超限时「**暂停采集 + 工作状态通知**」——保完整、不丢数据：

```text
[telemetry.logs]               # 全局字段，不属于单个 input
spool_max_bytes?               # 全局 spool 上限（字节）
spool_over_limit = "pause"     # 当前仅 pause
```

超限（`pause`）语义：

1. 停止读取新行与 checkpoint 推进（已读未发数据留在 spool，源文件继续增长，恢复后从 checkpoint 续读）；
2. spool 保持不动，继续按 tick 回放；回放到清空后**自动恢复**采集；
3. 进入/退出该状态各产生一次**工作状态通知**（work-state notification，非告警/非失败）并**上报**：
   本地记 stderr（`src/runtime/daemon_runtime_state.rs:42-53`），开控制面时随 `AgentStatusReport.work_state_changes` 上报（`src/runtime/daemon.rs:226-233`）；
4. 若期间源文件被系统轮转/清理掉，属于系统侧行为，agent 不保证该部分（见 §11）。

### 6.5 边界语义与实现一致性（v1 实现，已由 5 轮 review 固化）

本节把 §6.3 / §6.4 的意图收敛成**可测试的精确语义**，与
`telemetry/logs/files/{file_reader,file}.rs`、`telemetry/spool.rs` 的实现一致。

**读取预算（`max_read_bytes_per_tick` / `max_lines_per_tick`）**

- 预算与行数只在**行边界**结算：`line_consumed == 0` 时才可能因预算停读；
- **行内不因预算中断**——单行可能超过 `max_read_bytes_per_tick`，但绝不会被切成两半；
  否则「行长 > 预算且跨多个缓冲块」会让每轮从行首重读、`committed_end_offset` 永不前进（已修，见下表）；
- 停读点保证下次从**行首**续读（`committed_end_offset` 落在行边界）。

**截断（`max_line_bytes`）**

- 只提交**完整行**；文件尾部的半行不提交（下次继续）；
- 单行**恰等于** `max_line_bytes`：不截断；**超出**即截断提交（保留前 `max_line_bytes`），
  跳过该行剩余到行尾后原子提交，并计入 `truncated_lines`；
- 截断行的 `end_offset` 指向**真实行尾**（checkpoint 不会卡住）；到 EOF 无换行时也提交截断行；
- `ReadLimits` 对上限做 `max(1)` 夹取，避免 0 预算导致零推进。

**背压 / 暂停（`spool_max_bytes` / `spool_over_limit`）**

- 触发：回放（replay）失败**且** `spool_bytes >= spool_max_bytes`（含恰好相等）；
- **回放优先**：只要 sink 能回放成功，即使 spool 已超限也先回放清空，不进入暂停；
- 暂停/恢复是**工作状态变化（work-state notification）**，不是告警、不是失败；
  命名不能用 “告警”。进入与退出（恢复）是同一类通知的两个事件：`paused` / `resumed`；
- 暂停期间：不读源、不推进 checkpoint、`spool` 保持不变；回放至清空后**自动恢复**；
- **应上报**：进入/退出各产生一次工作状态通知并上报（不能只落本地日志）；
  接收方与通道见 [`development-plan.md`](./development-plan.md) §W1「待办（follow-up）」。
- `drop_oldest` 已从校验收敛掉：**v1 仅接受 `pause`**（保完整优先），按 input 优先级丢弃留待后续。

**配置校验**

- `spool_over_limit = pause`（仅此一值），否则 `invalid_logs_spool_over_limit`；
- `max_line_bytes` / `max_read_bytes_per_tick` / `max_lines_per_tick` / `spool_max_bytes`
  必须 > 0，否则分别返回 `invalid_logs_max_line_bytes` / `invalid_logs_max_read_bytes_per_tick` /
  `invalid_logs_max_lines_per_tick` / `invalid_logs_spool_max_bytes`（避免 0 值造成永久暂停或零预算）。

**review 固化的缺陷与修复（与用例对应）**

| # | 问题 | 类型 | 修复 | 测试 |
|---|---|---|---|---|
| 1 | 行长 > 预算且跨缓冲块时每轮从行首重读、永不推进 | 缺陷 | 预算只在行边界结算 | `long_line_larger_than_read_budget_still_completes`、`line_over_read_budget_is_delivered_without_loss` |
| 2 | （无新缺陷）分块/预算在 Processor 层行为 | 验证 | — | `chunked_read_by_max_lines_advances_checkpoint_each_tick_without_loss`、`resumes_from_line_start_after_byte_budget_stop` |
| 3 | （无新缺陷）截断边界语义 | 验证 | — | `line_exactly_at_max_line_bytes_is_not_truncated`、`line_one_byte_over_max_line_bytes_is_truncated_and_counted`、`truncated_line_without_trailing_newline_is_committed_at_eof`、`multiple_truncated_lines_are_each_counted`、`truncated_long_line_with_small_budget_still_completes`、`read_limits_clamp_zero_to_one_and_still_make_progress` |
| 4 | （无新缺陷）背压边界（相等即暂停、健康即回放） | 验证 | — | `spool_exactly_at_limit_pauses`、`spool_over_limit_with_healthy_sink_replays_without_pausing` |
| 5 | 上限为 `0` 被接受 → 永久暂停 / 零预算 | 健壮性 | 上限非零校验 | `config_with_zero_{spool_max_bytes,max_line_bytes,max_read_bytes_per_tick,max_lines_per_tick}_is_rejected`、`config_with_drop_oldest_spool_over_limit_is_rejected` |

> 表中「工作状态通知的上报」已落地、`drop_oldest` 已收敛为仅 `pause`，见
> [`development-plan.md`](./development-plan.md) §W1「待办（follow-up）」。

---

## 7. 本地状态与 checkpoint

字段级 schema 独立定义在：

- [`log-file-state-schema.md`](./log-file-state-schema.md)

本节只保留与运行语义直接相关的结论。

### 7.1 状态文件位置

第一版建议每个文件日志输入在本地维护：

- `state/logs/file_inputs/<id>/checkpoints.json`

### 7.2 `commit point` 与 checkpoint 推进规则

checkpoint 不能在“刚读到文件内容”时立即推进。

建议固定为：

- 读取内容并形成 record
- record 已成功进入本地 telemetry buffer
- 若启用了 spool，则以 durable spool 接纳成功为 `commit point`
- 若未启用 spool，则以 input 认可的本地 buffer 安全接纳点作为 `commit point`
- 之后再推进 checkpoint

**序号（`seq`）持久化**：`next_seq` 为 **per-`agent` 全局**计数器，存独立文件 `state/logs/seq.json`；每个 input 提交 checkpoint **前**把当时的全局值原子写回该文件（前移一位，见 §10.1.1），重启后从该文件续号，全局不回退。

这样可以保证：

- 正常运行与优雅退出时尽量不丢数据
- 异常崩溃时提供 at-least-once
- 允许小范围重复，不允许静默跳过

### 7.3 crash 恢复语义

第一版建议固定：

- 恢复时优先使用 checkpoint 中的最近已提交 `checkpoint offset`
- 如果 crash 发生在“已读取但未提交 checkpoint”窗口，允许重复少量记录
- 不允许因为 crash 把未持久化确认的数据视为已成功消费

---

## 8. rotate / truncate 语义

### 8.1 rotate

第一版必须支持最常见的 rename-rotate 场景：

1. 原路径文件被 rename 到新路径
2. 新文件在原路径重新创建
3. reader 继续读取旧文件剩余尾部
4. 同时开始跟踪新文件

### 8.2 truncate

第一版必须识别 truncate / copytruncate 这类场景。

建议规则：

- 同一 `file_id` 下，如果当前文件大小小于已提交 `checkpoint offset`
- 视为发生 truncate
- 将 `read offset` 重置到 `0`

### 8.3 inode 复用

inode 复用是 `file reader` / `tail reader` 的高风险边界。

第一版建议：

- 必要时结合 `fingerprint`
- 当身份判断不可靠时，宁可保守重读少量内容，也不要静默跳过

---

## 9. 多行日志

第一版必须把 multiline 作为一等能力，而不是后期补丁。

原因很直接：

- Java / Python / Go stacktrace 很常见
- Docker / CRI 容器日志天然存在拆分与重组需求
- 没有 multiline，文件日志输入很难达到 Fluent Bit 同等级可用性

### 9.1 第一版最小模式

当前实现只支持 `multiline_mode` 的两个取值（见 §6.2）：

- `none`（默认，不拼装）
- `indented`

### 9.2 flush 规则

组装/收尾规则按当前实现固定（没有 `flush_timeout_ms` / `max_lines` / `max_bytes` 这三个配置项）：

- 组装形状：只有 `multiline_mode = indented` 会挂起状态；续行判定是行首为空格或制表符
  （`src/telemetry/logs/multiline.rs:101-103`），挂起状态存于 checkpoint 的 `pending_multiline`
  （`source_path / body / start_offset / end_offset / last_updated_at`）。
- 收尾触发条件（四类）：
  1. 读到一条**非续行开头**的行：立刻收尾上一条（`multiline.rs:57-91`，不依赖超时）；
  2. **固定 1s idle flush**：本 tick 没有读到新行且 `observed_at - last_updated_at >= 1000ms`
     时收尾（`MULTILINE_IDLE_FLUSH_MS = 1000`，`src/telemetry/logs/files/multiline_support.rs:12`、
     同文件 `:98-112`，调用点 `src/telemetry/logs/files/file.rs:313-323`）；
  3. 源路径变化：挂起状态的 `source_path` 与当前源不一致时收尾（`multiline_support.rs:60-81`，调用点 `file.rs:275-284`）；
  4. 识别到 rotate / truncate：直接收尾挂起内容（`file.rs:266-273`）。
- `multiline_mode = none` 时不存在组装：每条已提交行直接成为一条 record（`multiline.rs:40-50`）。
- 文件尾部半行、长行截断等边界由读取阶段（`file_reader.rs`）决定，多行组装层不另行截断；
  当前也没有 `truncated` / `multiline_flush_reason` 这类多行诊断字段。

### 9.3 与 parser 的顺序

第一版固定顺序（与 §5.1 一致）：

- 先按 `multiline_mode` 做必要的拼装（`src/telemetry/logs/multiline.rs`）
- 再映射为统一 record（`src/telemetry/logs/parser.rs`），该步不做结构化字段解析
- 最后注入来源字段与 `seq`

不要让 parser 和 multiline 形成循环依赖。

---

## 10. 统一 record 与去重

### 10.1 record 字段

文件日志输入不定义自己的输出对象，直接产出契约
`wist_contracts::telemetry_record::TelemetryRecord`
（`wist-contracts-0.1.2/src/telemetry_record.rs`）；唯一构造点是
`src/telemetry/logs/parser.rs` 的 `parse_folded_lines`（只调用 `TelemetryRecord::new_log(...)`）。

record 字段固定为 9 个，不做扩展：

- `schema_version`
- `agent_id`
- `observed_at`
- `input_id`（记录所属 input，spool/路由用，不进帧）
- `source_path`
- `body`
- `file_offset`
- `file_offset_end`
- `seq`（per-`agent` 全局单调递增 `u64`，去重/缺口键，见 §10.1.1）

字段来源与语义：

- `input_id` 取配置 `LogFileInputSection.input_id`；`source_path` 取配置的显式 `path`；
- `file_offset` / `file_offset_end` 是解析前的行边界偏移（截断行的 `file_offset_end` 指向真实行尾，见 §6.5）；
- `observed_at` 为读取时刻；`body` 为原文（multiline 时为拼装后的正文）。

record **没有** `source_type`，也没有 `source.file_id` / `source.device_id` / `source.inode`
这类来源子结构，更没有 `resource_refs` 之类的资源引用字段。
文件身份信息（`file_id` / `device_id` / `inode` / `fingerprint`）只落在**本地 checkpoint**
（`src/state_store/log_checkpoint_state.rs` 的 `TrackedFileCheckpoint`），用于 rotate/truncate
判定与续读位置；这些字段**不进 record**，也不随数据帧上送
（帧信封只有 `schema` / `agent` / `ts` / `seq`，见 §10.1.1）。

### 10.1.1 `seq` 与去重规则

**为什么不用 offset 单键**：truncate 后 offset 会复用、文件被替换但路径不变，旧键会把新数据误判为重复，故用 `seq` 作为唯一去重/缺口键。

**`seq` 定义**：

- 粒度：`per agent`（全局）；形态：`u64` 单调递增；
- 分配：记录生成时取号；`next_seq` 为 agent 级全局计数器，存独立文件 `state/logs/seq.json`，提交 checkpoint 前原子写（前移一位）；崩溃重读沿用同一 `seq`，误删单个 checkpoint 不回退号源；
- 重启：从 state 续号，只要求**不回退**（不要求连续）。

**上送帧**：在信封中新增 `seq`（与 `agent` 等通用字段并列），原文仍在 `RAW:` 之后。帧信号无关，不携带 `input`/文件路径/偏移等来源字段。

**下游去重（数据面规则）**：

1. 主键 `(agent_id, seq)` → 命中即丢弃。

> 不引入位置/世代辅助判据：崩溃窗口内「已 spool、未提交」的记录重读时沿用**同一个** `seq`，`seq` 去重已能覆盖崩溃窗口重复，无需 `(file_id, offset)` 位置判据。

**缺口检测**：同 `agent_id` 内 `seq` 不连续即为可疑丢行，由下游按需处理。

### 10.2 与 Fluent Bit 的差异

这里不要求照搬 Fluent Bit 的 `tag` / `tag_regex`：Fluent Bit 用 tag 做路由，而
`wist-agentd` 的 record 没有 tag 字段，归属信息由 `input_id` 承载
（契约注：`input_id` 记录所属 input，spool/路由用，不进帧）。

record 的可读内容是 `body`（原文）加来源定位字段
（`source_path` / `file_offset` / `file_offset_end`）；当前没有从文件名 regex
提取字段再挂到 labels / attrs 的机制（见 §10.1）。

---

## 11. 资源预算与 backpressure

文件日志输入属于“不可反馈输入”。

这意味着：

- 无法像 HTTP / OTLP push 一样把背压直接传回上游
- 只能靠本地 queue、spool 和限额来吸收

### 11.1 第一版必须具备的保护手段

- 读取与内存上限（`max_read_bytes_per_tick` / `max_lines_per_tick` / `in_memory_buffer_bytes`，均为 `[telemetry.logs]` 全局字段）
- 全局 telemetry spool 上限（超限**暂停采集 + 工作状态通知**，不丢数据）
- 长行**截断提交 + 计数**（见 §6.3 `max_line_bytes`）

### 11.2 超限时的行为

当前只有一种超限行为（代码里没有 protect / degrade 模式，也没有 drop reason）：

1. 达到 `spool_max_bytes` 且回放失败时，**暂停该 input 采集并发工作状态通知**（保完整，不丢数据）；
   暂停期间不读源、不推进 checkpoint，回放成功（spool 清空）后自动恢复（见 §6.4 / §6.5）
2. `drop_oldest` 按 input 优先级丢弃为未来备选（当前校验只接受 `pause`，无落地代码）

---

## 12. 验收标准

### 12.1 `M4` 受控子集验收

`M4` 只按受控子集验收，不以完整通用 `file input` 为交付门：

1. 在 `control_plane.enabled = false` 时，能稳定读取一个显式配置的文件路径。
2. 能在 restart 后基于已提交 checkpoint 恢复，并满足 at-least-once。
3. 能正确处理 append、rename-rotate、truncate 与最小 multiline 基线。
4. 能把 `input_id`、`source_path`、`file_offset`、`file_offset_end` 与 `seq` 稳定挂入 `TelemetryRecord`。
5. 能通过 `warp-parse` 或本地 fallback 输出，验证至少一类 `standalone` 替代链路。
6. 单 input 只对应一个显式路径，且不提供事件驱动 watcher 与多路径发现（见 §5.1）。

---

## 13. 当前决定

当前阶段固定以下结论：

- 文件日志输入必须进入 `wist-agentd` 第一版 logs 设计范围
- 其目标是对标 Fluent Bit `tail`，不是依赖 Fluent Bit
- 配置、checkpoint、rotate、multiline、budget 必须一起设计，不能拆成零散补丁
- `file.tail` 不能替代常驻文件日志采集
- `M4` 先落受控单路径替代切片（单 `input_id` + 单 `path`，轮询 tick 驱动，见 §5.1）
- **长行策略**固定为“截断提交 + 计数”（`max_line_bytes`，默认 1 MiB，见 §6.3）
- **spool 有上限，超限策略**固定为“暂停采集 + 工作状态通知”（保完整，见 §6.4/§11）；`drop_oldest` 为未来备选（v1 校验只接受 `pause`）
- **交付语义**为 at-least-once（可能重复、不丢）：spool 接纳成功即推进 checkpoint；去重采用 per-`agent` 全局
  `seq`（`next_seq` 存独立文件、先于 checkpoint 前移原子写）+ 下游组合键去重（见 §10.1.1）
- **源日志默认不清理**（只读采集）：轮转/清理交给系统或中心策略；agent 自身的 spool 与本地输出必须有界并轮转
