# warp-insight 文件日志输入状态 Schema 草案

## 1. 文档目的

本文档定义 `wist-agentd` 文件日志输入的本地状态 schema。

这里的状态专指：

- `file input` 的 checkpoint state
- `file identity` 到 `checkpoint offset` 的持久化映射
- crash 恢复、rotate、truncate 判断所需的最小本地状态

本文档不讨论：

- `execution_queue` / `running` / `reporting` 这类远程执行状态
- `wist-exec` workdir 状态
- parser / multiline 的运行时内存对象细节

相关文档：

- [`agentd-state-schema.md`](agentd-state-schema.md)
- [`agentd-state-and-boundaries.md`](agentd-state-and-boundaries.md)
- [`./log-file-input-spec.md`](./log-file-input-spec.md)

---

## 2. 核心结论

第一版固定以下结论：

- 文件日志输入状态应独立于 execution 状态树
- 文件日志输入状态的唯一持久化目标是支撑 checkpoint 恢复，而不是复刻完整 runtime 内存对象
- `checkpoint offset` 只能在越过 `commit point` 后推进
- `file_id` 是 `file identity` 的持久化表示，不等于当前 `path`
- 第一版每个 `file input` 维护一份 `checkpoints.json`

---

## 3. 目录位置

建议目录结构：

```text
<agent_root>/
  state/
    logs/
      file_inputs/
        <input_id>/
          checkpoints.json
```

说明：

- `execution_queue` 等控制状态仍保留在 `state/` 根下
- 文件日志输入状态单独放入 `state/logs/`，避免与 execution 状态混写

---

## 4. 状态对象

### 4.1 `checkpoints.json`

```text
LogCheckpointState {
  schema_version
  input_id
  updated_at
  next_seq
  pending_multiline?
  files[]
}
```

字段说明（结构体定义见 `src/state_store/log_checkpoint_state.rs:6-34`）：

- `schema_version`
  第一版固定为 `v1`
- `input_id`
  对应 `logs.file_inputs[].input_id`（入口字段名，契约见 `wist-contracts-0.1.2/src/agent_config.rs:277`）
- `updated_at`
  本次状态文件成功落盘时间
- `next_seq`
  【已废弃，仅兼容】历史遗留的 per-input 序号字段；因为结构体带 `#[serde(deny_unknown_fields)]`，
  保留它才能读出旧 `checkpoints.json`，当前不再读写
  （`src/state_store/log_checkpoint_state.rs:13-17`）
- `pending_multiline?`
  未闭合的多行组快照（`indented` 模式下跨 tick 保留的组），无则为空且不落盘
  （`skip_serializing_if = "Option::is_none"`，`src/state_store/log_checkpoint_state.rs:18-19`）
- `files[]`
  当前仍保留 checkpoint 的文件状态集合

全局 `seq` 高水位**不属本 schema 管辖**：它已从 per-input checkpoint 迁到独立文件
`state/logs/seq.json`（内容 `{"next_seq": N}`），与各 input 的 checkpoint 解耦
（`src/state_store/log_seq_state.rs:13-28`）。

### 4.2 `TrackedFileCheckpoint`

```text
TrackedFileCheckpoint {
  file_id
  path
  device_id?
  inode?
  fingerprint?
  checkpoint_offset
  checkpoint_probe?
  last_size?
  last_read_at?
  last_commit_point_at?
  rotated_from_path?
}
```

字段说明（结构体定义见 `src/state_store/log_checkpoint_state.rs:47-62`）：

- `file_id`
  `file identity` 的持久化字段
- `path`
  最近一次确认的当前路径
- `device_id` / `inode`
  Unix-like 平台上的首选身份来源
- `fingerprint`
  inode 不可靠或需额外校验时使用
- `checkpoint_offset`
  最近一次已提交的文件读取进度
- `checkpoint_probe`
  `checkpoint_offset` 前最多 16 字节（`CHECKPOINT_PROBE_BYTES`）的十六进制内容指纹，
  用于 copytruncate / 同前缀重写判定：若该位置前的字节与它不一致，则按 truncate 从 `0` 重读
  （`src/telemetry/logs/files/file_reader.rs:10`、`264-282`；`src/telemetry/logs/files/file_watcher.rs:53-64`、`129-142`）；
  `checkpoint_offset = 0` 或探测失败时为空
- `last_size`
  最近一次观测到的文件大小
- `last_read_at`
  最近一次 reader 实际读取到内容的时间
- `last_commit_point_at`
  最近一次越过 `commit point` 的时间
- `rotated_from_path`
  当前文件由哪个旧路径 rotate 而来；无则为空

本结构带 `#[serde(deny_unknown_fields)]`：`file_id` / `path` / `checkpoint_offset` 必填，
其余均为 `Option<T>`，缺失即为 `None`（serde 对 `Option` 字段缺失的处理）；多出未知键会被拒绝
（`src/state_store/log_checkpoint_state.rs:47-62`）。

---

## 5. `file_id` 与 `file identity`

第一版建议：

- `file_id` 不是自由字符串语义名，而是 `file identity` 的稳定持久化结果
- Linux / Unix 优先基于 `device_id + inode`
- 当 inode 不可靠时，退化为 `canonical_path + fingerprint`

工程约束：

- `path` 改变不等于 `file identity` 改变
- `file identity` 改变时必须重新判断 rotate / truncate / 新文件接管

---

## 6. checkpoint 推进规则

### 6.1 `read offset`

`read offset` 属于 runtime 内存态，不要求直接持久化到 state file。

第一版建议：

- 运行中可维护 `read offset`
- 但持久化文件中只保存 `checkpoint_offset`

### 6.2 `commit point`

第一版建议把以下条件作为 `commit point`：

- record 已完成必要 parse / normalize / resource binding
- record 已成功进入本地 telemetry buffer
- 若启用了 durable spool，则必须成功进入 spool

只有在越过 `commit point` 后，才允许推进 `checkpoint_offset`。

### 6.3 推进步骤

建议固定为：

1. `file reader` 读取新增内容
2. 形成 record
3. record 进入本地 telemetry buffer / spool
4. 达到 `commit point`
5. 更新 `checkpoint_offset`
6. 原子落盘 `checkpoints.json`

---

## 7. rotate / truncate 规则

### 7.1 rotate

当发生 rename-rotate 时：

- 旧文件的 `file identity` 保持不变
- 原路径上的新文件形成新的 `file identity`
- 旧文件继续读尾
- checkpoint 继续绑定到各自的 `file_id`

### 7.2 truncate

当满足以下条件时建议判定为 truncate：

- 同一 `file_id`
- 当前文件大小小于 `checkpoint_offset`

处理建议：

- 将 runtime `read offset` 重置到 `0`
- 后续从 `0` 重新建立新的 `checkpoint_offset`

---

## 8. 文件更新策略

`checkpoints.json` 建议沿用 `agentd-state-schema.md` 的统一规则：

- 先写临时文件
- `fsync`
- 原子 `rename`

第一版额外建议：

- 单次落盘应覆盖整个 `checkpoints.json`
- 不在同目录下维护增量 patch 文件

---

## 9. 最小示例

```json
{
  "schema_version": "v1",
  "input_id": "nginx_access",
  "updated_at": "2026-04-12T10:00:00Z",
  "files": [
    {
      "file_id": "dev:2049:ino:912345",
      "path": "/var/log/nginx/access.log",
      "device_id": 2049,
      "inode": 912345,
      "checkpoint_offset": 1839201,
      "last_size": 1839201,
      "last_read_at": "2026-04-12T09:59:58Z",
      "last_commit_point_at": "2026-04-12T09:59:58Z"
    }
  ]
}
```

---

## 10. 当前决定

当前阶段固定以下结论：

- 文件日志输入状态单独建模，不并入 execution state
- `checkpoint_offset` 是持久化真值，`read offset` 是运行时内存态
- `commit point` 是 checkpoint 推进的前置条件
- `file_id` 用于持久化 `file identity`
