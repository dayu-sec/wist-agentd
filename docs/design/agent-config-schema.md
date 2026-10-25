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
  log
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
- 当 `enabled = false` 时，数据面（`[telemetry.logs]` / `[discovery]`）整体不生效：不采集、不缓冲、不上送，也不产生 spool

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

> **`standalone` 下整段不生效**（`[control_plane] enabled = false`）：不读 `file_inputs` / `file_inputs_file`，
> 不落 spool，`output` 的 `tcp` / `file` 两种都不写。配置里保留这些键不报错，但运行时忽略。

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
  exclude_globs?
  filters?
  drop_if_contains?
}
```

字段说明（类型定义已迁入本仓：`src/config/agent_config.rs`）：

- `input_id`
  采集任务标识，必填非空，同一配置内不可重复（重复报 `duplicate_log_input_id`）
- `path`
  采集目标：**绝对路径**。三种形态行为不同（见 [`./log-file-input-spec.md`](./log-file-input-spec.md) §2.1）：
  - 显式单文件（`/var/log/auth.log`）→ 单文件读取器，行为与 W1 前一致；
  - 单层 glob（`/var/log/containers/*.log`）→ 文件族读取器（`*` 不跨目录，`**` 被拒）；
  - 目录（`/var/log/postgresql`）→ 文件族读取器（目录下**直接子文件**）。
  相对路径相对 `paths.root_dir` 解析（`src/config/config_runtime_support.rs:292-301`）
- `startup_position?`
  首次观测该文件（尚无 checkpoint）时的起点，省略时默认 **`tail`**：
  - `tail`：从文件当前长度开始，只收新增行（**默认**，不重放历史）
  - `head`：从文件头开始，回放已有内容（要看历史才显式写）
  映射见 `src/runtime/daemon_telemetry_support.rs:107-112`、`src/telemetry/logs/files/file_watcher.rs:28-38`。
  文件族里**运行中/重启后新出现**的文件不看它，一律从 head 读（D10）。
- `multiline_mode?`
  多行折叠模式，省略时默认 `none`：
  - `none`：一行一条记录
  - `indented`：以空格或 Tab 开头的行并入上一条，形成一条多行记录；未闭合的组跨 tick 保留在
    `pending_multiline` 状态里，下个 tick 遇到非缩进行时提交（`src/telemetry/logs/multiline.rs`）。
    文件族下**每个文件各持一份**未闭合块（`TrackedFileCheckpoint.pending_multiline`）。
  - `mysql_slow`（W4）：MySQL slow log，`# Time:` 起块，下一条 `# Time:` 或空闲超时封口。
  - `postgres_csv`（W4）：PostgreSQL csvlog，**引号外**的换行才切记录（引号状态跨行，
    未封口块跨读批时从正文重算）。
- `exclude_globs?`
  只对文件族目标有意义：从匹配集里剔掉的**绝对路径** glob（按展开后的完整路径匹配），为空则不输出。
  典型用法：`path = "/var/log/containers/*.log"` + `exclude_globs = ["/var/log/containers/*_kube-system_*.log"]`。
  写在非文件族目标上不报错（无匹配集可剔），但相对路径会被校验拒绝（`invalid_log_input_exclude_glob`）。
- `filters?`（W2）
  容器选源的结构化过滤器：`namespace_in` / `pod_not_in`（精确名字，不是 pattern）。在**发现阶段**
  求值（展开 glob、剔完 `exclude_globs` 之后），读取器不参与；只允许用在 `/var/log/containers` 下，
  否则报 `invalid_log_input_container_filters`。
- `drop_if_contains?`（W4）
  含这些**精确子串**的记录**整条**丢弃（空 = 不丢）。不进闸门、**不消耗 `seq`**（取号不上报会让
  接收端报假的数据丢失），丢弃数进自观测（`telemetry noise dropped …`，`info`、按签名去重）。
  形状校验与网关共用（`validate_drop_if_contains`：限条数 / 长度、拒空串 / 首尾空白 / 控制字符 /
  重复），不合法报 `invalid_log_input_drop_if_contains`。

前两个字段省略时走契约默认值；非法取值被校验拒绝（`invalid_log_startup_position` / `invalid_log_multiline_mode`，
`src/config/validate.rs`）。

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
- `container_enabled`：container 发现（运行时 task 目录 + `/proc/<pid>/cgroup` 归属），段内省略时默认 `true`

整段 `[discovery]` 不写时走 `DiscoverySection::default()`：host / network / endpoint / process / container 均为 `true`。

> `container_enabled` 自 0.9.11 起默认开。早期版本生成的配置里它被写死为 `false`：
> 只要那份配置还带着旧模板的单行注释（说明没人动过这一段），加载时会**一次性**改写为
> `true` 并落盘；手写 `false`（无那行注释）的配置不动 —— 那是明确的选择。
默认模板把五个键都显式写出（`src/config/config_runtime_support.rs:33-40`）。
五个开关不能全为 `false`，否则报 `missing_discovery_probe`（`wist-validate-0.1.2/src/config.rs:43-51`）。

> **`standalone` 下 discovery 不运行**：五个开关即使为 `true` 也不启动探针（与「不采、不缓、不发」同一口径）。
> 配置校验仍按上面规则执行，不因运行模式改变。

---

## 9. `log`

本进程**运行日志**（级别 / 格式 / 落点 / 轮转）。与 `telemetry.logs`（**被采集的日志**）不同：
后者是 agentd 采集上送的"原料"，这里描述的是 agentd **自己**往哪里、以什么格式、记到什么级别。

```text
LogSection {
  level        # 可选，过滤器指令，如 "info" / "wist_agentd=debug,wist_shared=warn"
  format       # "text"（缺省） | "json"
  file         # 可选，写文件（追加、自动建父目录、写满轮转）；缺省写 stderr
  max_bytes    # 可选，单文件上限（字节），缺省 64 MiB
  keep_files   # 可选，保留分卷个数，缺省 4
  max_seconds  # 可选，分卷保留时长（秒）；旧名 max_age_seconds 仍接受
}
```

约定（与全库其它 wist 组件**同名同义**，见共享 crate `wist-log` 与 `wist-agentd`
`docs/design/logging-output.md`）：

- 优先级：`RUST_LOG` > `[log].level` > `info`。
- 缺省写 **stderr**：系统级部署交给 journald；容器里交给容器 runtime 收（**不要**在容器里给 `file`）。
- 给了 `file` 才写文件，并在**进程内**按 `max_bytes` / `keep_files` / `max_seconds` 轮转；
  自己轮转就**别**再挂 logrotate。
- `format = "json"` 时每行带 `level` 字段，便于采集端按级别筛。

缺省值（整段不写）：`format = "text"`、写 stderr、级别 `info`。本段**直接内嵌**共享 crate 的
单类型 `wist_log::LogSection`（同名同义、单一事实来源），在 daemon 启动早期交给 `wist_log::init`。

---

## 10. 当前决定

当前阶段固定以下结论：

- `wist-agentd` 需要一份统一总配置
- logs 配置作为 `telemetry` 段的子段（`telemetry.logs`）挂入
- execution / paths / control_plane 作为第一版必需配置段
