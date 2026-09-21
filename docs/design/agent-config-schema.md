# warp-insight Agent 配置 Schema 草案

## 1. 文档目的

本文档定义 `wist-agentd` 的本地总配置骨架。

目标是把当前分散的配置讨论收敛成一份统一结构，覆盖：

- daemon 基础配置
- control plane 连接
- 本地路径
- execution 限制
- logs inputs

相关文档：

- [`log-file-input-spec.md`](./log-file-input-spec.md)
- [`agentd-architecture.md`](agentd-architecture.md)
- [`agentd-state-schema.md`](agentd-state-schema.md)

---

## 2. 顶层结构

```text
AgentConfig {
  schema_version
  agent
  control_plane
  paths
  execution
  telemetry
  discovery
}
```

第一版固定：

- `schema_version = "v1"`

---

## 3. `agent`

```text
AgentSection {
  agent_id?
  environment_id?
  instance_name?
}
```

说明：

- `agent_id` 可为空，由首次注册后固化

---

## 4. `control_plane`

```text
ControlPlaneSection {
  enabled
  endpoint?
  enrollment_token?
  credential_request?
  credential_id?
  bearer_token?
  credential_expires_at?
  tls_mode?
  trust_bundle?
  auth_mode?
}
```

第一版建议：

- `enabled = false` 表示 `standalone` 模式
- `enabled = true` 表示 `managed` 模式
- 当 `enabled = false` 时，`endpoint / tls_mode / auth_mode` 可为空
- 当 `enabled = true` 时，`endpoint` 为必填

也就是说：

- 是否连接中心节点，必须是显式配置
- 没有中心节点不是异常态，而是一种受支持运行模式

凭据相关字段说明（本仓实现口径，契约定义见 `wist-contracts-0.1.2/src/agent_config.rs:87-110`）：

- `enrollment_token`
  一次性注册 token；属于契约字段，但本仓**安装/注册路径不把它写进配置**：
  `service install --enrollment-token <token>` / `enroll --token <token>` 只在命令行传一次，
  注册完成后若配置文件里还有该键会被就地剔除（`src/control/enrollment.rs:101-105`、`598-619`；
  模板注释见 `src/config/config_runtime_support.rs:56-59`）
- `credential_request`
  请求的凭据类型；注册请求缺省填 `none`（`src/control/enrollment.rs:196-205`），
  续期请求缺省填 `bearer`（`src/control/enrollment.rs:322-331`），一般不手写
- `credential_id` / `bearer_token` / `credential_expires_at`
  长期凭据，由注册/续期结果写入：启动时从 `state` 注入配置（`src/control/enrollment.rs:157-192`），
  注册或续期成功时也直接写回（`src/control/enrollment.rs:493-519`）
- `auth_mode`
  有 bearer 凭据时运行时写成 `bearer`（`src/control/enrollment.rs:184`）；
  遗留的 `auth_mode = "enrollment_token"` 视为陈旧行，注册完成后一并剔除（`src/control/enrollment.rs:598-627`）
- `tls_mode`
  取值 `https` / `verify`（校验证书，`trust_bundle` 为 PEM 时加入 root store）、`none`（关闭校验，仅实验）、
  `http`（明文）；缺省按 `endpoint` 前缀推断（`src/control/enrollment.rs:369-402`）
- `trust_bundle`
  PEM 格式的信任材料，仅 `https` / `verify` 模式下生效（`src/control/enrollment.rs:379-390`）

---

## 5. `paths`

```text
PathsSection {
  root_dir
  run_dir
  state_dir
  log_dir
}
```

这些路径要与：

- `agentd-exec-protocol.md`
- `agentd-state-schema.md`

保持一致。

---

## 6. `execution`

```text
ExecutionSection {
  max_running_actions
  cancel_grace_ms
  default_stdout_limit_bytes
  default_stderr_limit_bytes
}
```

字段说明（契约定义见 `wist-contracts-0.1.2/src/agent_config.rs:136-158`）：

- `max_running_actions`
  并发 action 数；契约默认 `1`，但**当前只允许 `1`**：写成 `0` 报 `invalid_max_running_actions`，
  写成其它值报 `unsupported_max_running_actions`（`wist-validate-0.1.2/src/config.rs:28-33`）；
  默认模板不显式写该键，取契约默认值与校验一致
- `cancel_grace_ms` / `default_stdout_limit_bytes` / `default_stderr_limit_bytes`
  契约默认 `5000` / `1048576` / `1048576`，均要求 > 0

第一版建议：

- 字段存在（`max_running_actions`）但当前只允许 `1`
- 因此不暴露用户可调并发数
- action 执行固定为单并发

---

## 7. `telemetry.logs`

```text
LogsSection {
  file_inputs[]?
  file_inputs_file?
  in_memory_buffer_bytes
  max_line_bytes
  max_read_bytes_per_tick
  max_lines_per_tick
  spool_max_bytes
  spool_over_limit
  spool_dir
  output
}
```

字段说明（契约定义与默认值见 `wist-contracts-0.1.2/src/agent_config.rs:167-215`）：

- `file_inputs[]?`
  内联采集清单，默认空数组
- `file_inputs_file?`
  采集任务清单外置文件；路径相对本配置文件解析（`src/config/config_runtime.rs:104-105`），
  与内联 `[[telemetry.logs.file_inputs]]` 二选一，同时出现会被拒绝（`src/config/config_runtime.rs:110-114`）
- `in_memory_buffer_bytes`
  内存缓冲上限（字节），默认 `1048576`（1 MiB）；默认模板显式写该键（`src/config/config_runtime_support.rs:20`）
- `max_line_bytes`
  单行最大字节数：超过即截断提交并计数，默认 `1048576`（1 MiB）
- `max_read_bytes_per_tick`
  单次 tick 最多读取的字节数（大文件回放分块），默认 `4194304`（4 MiB）
- `max_lines_per_tick`
  单次 tick 最多读取的行数（大文件回放分块），默认 `4096`
- `spool_max_bytes`
  落盘待发队列（spool）上限（字节），默认 `268435456`（256 MiB）
- `spool_over_limit`
  超限行为，默认 `pause`；当前校验只接受 `pause`（`drop_oldest` 尚未接收）
- `spool_dir`
  spool 目录，默认 `state/spool/logs`；相对路径相对 `paths.root_dir` 解析（`src/config/config_runtime_support.rs:285-287`）
- `output`
  输出目标，默认 `kind = "file"`

第一版建议：

- 先固定 `telemetry.logs.file_inputs[]`
- 其字段结构直接复用：
  - [`./log-file-input-spec.md`](./log-file-input-spec.md)
- `M4` 口径为显式单路径输入（`input_id` + `path`，轮询 tick 驱动）
- `syslog` / `journald` / 其他 logs receiver 后续再补

### 7.1 `file_inputs[]` 元素

```text
LogFileInputSection {
  input_id
  path
  startup_position?
  multiline_mode?
}
```

字段说明（契约定义见 `wist-contracts-0.1.2/src/agent_config.rs:274-283`、`377-383`）：

- `input_id`
  采集任务标识，必填非空，同一配置内不可重复（重复报 `duplicate_log_input_id`）
- `path`
  目标文件路径，必填非空；相对路径相对 `paths.root_dir` 解析（`src/config/config_runtime_support.rs:292-301`）
- `startup_position?`
  首次观测该文件（尚无 checkpoint）时的起点，省略时默认 `head`：
  - `head`：从文件头开始，回放已有内容
  - `tail`：从文件当前长度开始，只收新增行
  映射见 `src/runtime/daemon_telemetry_support.rs:107-112`、`src/telemetry/logs/files/file_watcher.rs:28-38`
- `multiline_mode?`
  多行折叠模式，省略时默认 `none`：
  - `none`：一行一条记录
  - `indented`：以空格或 Tab 开头的行并入上一条，形成一条多行记录；未闭合的组跨 tick 保留在
    `pending_multiline` 状态里，下个 tick 遇到非缩进行时提交（`src/telemetry/logs/multiline.rs:57-103`）

两个字段省略时走契约默认值；非法取值被校验拒绝（`invalid_log_startup_position` / `invalid_log_multiline_mode`，
`wist-validate-0.1.2/src/config.rs:103-109`）。

### 7.2 `output`

```text
LogsOutputSection {
  kind
  file {
    path
  }
  tcp {
    addr
    port
    framing
  }
}
```

字段说明（契约定义与默认值见 `wist-contracts-0.1.2/src/agent_config.rs:217-272`）：

- `kind`
  输出类型：`file`（默认）/ `tcp`，其他值报 `invalid_logs_output_kind`
- `file.path`
  `kind = "file"` 时的输出文件，契约默认 `log/wist-records.ndjson`；默认模板不显式写它，
  由运行时按数据落点解析（`src/config/config_runtime_support.rs:244-253`）
- `tcp.addr` / `tcp.port`
  `kind = "tcp"` 时的目标地址与端口，默认 `127.0.0.1` / `9000`
- `tcp.framing`
  TCP 分帧方式：`line`（默认）/ `len`，其他值报 `invalid_logs_output_tcp_framing`

---

## 8. `discovery`

```text
DiscoverySection {
  host_enabled
  network_enabled
  endpoint_enabled
  process_enabled
  container_enabled
}
```

字段说明（契约定义见 `wist-contracts-0.1.2/src/agent_config.rs:49-74`）：

- `host_enabled`：host 发现，段内省略时默认 `true`
- `network_enabled`：network 发现，段内省略时默认 `true`
- `endpoint_enabled`：endpoint 发现，段内省略时默认 `true`
- `process_enabled`：process 发现，段内省略时默认 `false`
- `container_enabled`：container 发现（高基数），段内省略时默认 `false`

整段 `[discovery]` 不写时走 `DiscoverySection::default()`：host / network / endpoint / process 为 `true`、container 为 `false`。
默认模板把五个键都显式写出（`src/config/config_runtime_support.rs:33-40`）。
五个开关不能全为 `false`，否则报 `missing_discovery_probe`（`wist-validate-0.1.2/src/config.rs:43-51`）。

---

## 9. 当前决定

当前阶段固定以下结论：

- `wist-agentd` 需要一份统一总配置
- logs 配置作为 `telemetry` 段的子段（`telemetry.logs`）挂入
- execution / paths / control_plane 作为第一版必需配置段
