# 定时导出器（`Exporter` 采集来源）设计

> 状态：**设计（待评审）**。落地前先定 §9 的待决策点。
> 本文只覆盖 **`Exporter` 这一批能力**。「通配/目录型 + 运行中新发现文件的起始位置」是另一批，见 §10。

## 1. 目的与范围

目录词表里 `Exporter` 早就是**合法 kind**，但两侧的「可执行」判定都不认它，于是带 `Exporter` 的单元**派不出去**：

- 契约：`wist-contracts/src/work.rs` 的 `EXECUTABLE_SOURCE_KINDS = ["FileGlob", "MetricInterval"]`，`is_executable_source()` 对 `Exporter` 恒 `false`；
- agentd：`src/control/work.rs::log_inputs()` 只折算 `is_executable_source` 为真的来源；其余进 `unsupported_units()`（"`Exporter` … agentd 现在接不了"）；
- 网关：`src/app/content.rs::validate_unit()` 拒绝「`active` 但没有任何可执行来源」的单元；
- web：`src/components/agentWorkStatus.ts::isExecutableSource()` 同步判据（页面「可采/未接」）。

受害的面（当前只能停留在 `draft`）：

| 平台 | 面 | 单元 | 阻塞来源 |
|---|---|---|---|
| macOS | `PrivacyTcc` | `mac-privacy-tcc` | `Exporter sqlite-snapshot(TCC.db)` |
| macOS | `PrivilegeExecution` | `mac-privilege-exec` | `Exporter praudit(/var/audit)` |
| macOS | `LoginSession` | `mac-login-session` | `Exporter last,lastb` |
| Linux | `ServiceLifecycle` | `linux-service-lifecycle` | `Exporter journalctl-unit` |
| Linux | `NetworkFirewall` | `linux-network-firewall` | `Exporter nft-ruleset` / `iptables-save` |
| Linux | `RebootPower` | `linux-reboot-power` | `Exporter journalctl-shutdown` / `last-reboot` |
| Linux | `StorageHealth` | `linux-storage-health` | `Exporter smartctl`（+ 通配 `fsck*`，另批） |
| Linux | `CrashPanic` | `linux-crash-panic` | `Exporter dmesg:panic`（+ 通配 coredump，另批） |
| Linux | `ComputeWorkload` | `linux-compute-workload` | `Exporter dmesg:nvidia-xid`（+ 通配，另批） |
| Linux | `PrivilegeExecution` | `linux-privilege-exec` | `Exporter auditd-execve` |

设计稿 §8 已给出方向：「非追加型文本（journald / `last` / `smartctl` / `auditd` / `nft`）→ **周期导出成文本**」。本文把它落成一条**具名导出器**能力。

## 2. 不变量（不可破）

1. **采集就绪度与解析就绪度仍分开**：导出器只解决「采得到」，归类/抽字段仍看单元 `rule_ref`。带 `Exporter` 的单元 `rule_ref` 可以为空。
2. **「可执行」判定两侧同源**：网关与 agentd 必须 import **同一个** `wist_contracts::work::is_executable_source()`（现状已经是这样，别在某一侧复写一份）。
3. **具名，不是任意命令**：`target` 是**协议层词表里的导出器 ID**，不是自由命令串。
4. **不外泄提权面**：导出器的子进程只能经既有 `src/exec/`（`wist-exec` + `ActionPlan`）这一条出口，不在 export 模块里裸起 `Command::new`。

## 3. `target` 语法与 ID 表

目录里已用的 `target` 写法不统一（`journalctl-unit`、`dmesg:panic`、`smartctl`、`praudit(/var/audit)`、`sqlite-snapshot(TCC.db)`、`last,lastb`）。本设计**归一**为：

```
target = "<id>"                 # 无参
       | "<id>:<arg>"           # 冒号参数（简单标量，如 dmesg:panic）
```

- `id` 必须命中 §4 的注册表；`arg` 是**声明式的窄选项**（如 `dmesg` 的过滤键），**不是**命令行片段 —— 实现侧各自解释，绝不拼进 shell。
- 括号写法（`praudit(...)` / `sqlite-snapshot(...)`）在落地该平台时收敛为 `<id>:<arg>`；归一前旧写法一律按**未知 ID** 处理（= 不可执行），不静默猜。

已知 target → 归一 ID：

| 目录里的 target | 归一 ID | 平台 | 说明 |
|---|---|---|---|
| `journalctl-unit` | `journalctl-unit` | linux | `journalctl -o json --since` 按 unit |
| `journalctl-shutdown` | `journalctl-shutdown` | linux | shutdown/reboot 记录 |
| `last-reboot` | `last-reboot` | linux | `last -x reboot shutdown` |
| `nft-ruleset` | `nft-ruleset` | linux | `nft list ruleset` 快照 |
| `iptables-save` | `iptables-save` | linux | `iptables-save` 快照 |
| `smartctl` | `smartctl` | linux | `smartctl -a` 逐盘 |
| `dmesg:panic` | `dmesg` + `arg=panic` | linux | 内核 `panic`/`Oops`/`BUG:` |
| `dmesg:nvidia-xid` | `dmesg` + `arg=nvidia-xid` | linux | `NVRM`/`Xid` |
| `auditd-execve` | `auditd-execve` | linux | audit 日志里的 execve |
| `last,lastb` | `last` | macos | `last`/`lastb` 会话 |
| `praudit(/var/audit)` | `praudit` + `arg=/var/audit` | macos | OpenBSM 审计链 |
| `sqlite-snapshot(TCC.db)` | `sqlite-snapshot` + `arg=TCC.db` | macos | SQLite 快照 |

## 4. 「已知导出器 ID」放哪、怎么演进

`is_executable_source("Exporter", target)` 需要同时知道「ID 是否已知」。判定不能散在网关里，否则又出现两份真相。方案：

- 在 **`wist-contracts`** 定义 `EXPORTER_IDS`（协议层词表，与 `EXECUTABLE_SOURCE_KINDS` 并列）：
  ```rust
  pub const EXPORTER_IDS: &[&str] = &["journalctl-unit", "journalctl-shutdown", ...];
  pub fn is_known_exporter(target: &str) -> bool { /* 取冒号前的 id，查表 */ }
  ```
- `is_executable_source()` 对 `Exporter` 改为 `is_known_exporter(target)`。
- **四侧同源**：contracts（词表+判定）→ 网关（`content.rs` 校验、`EXECUTABLE_SOURCE_KINDS`）→ agentd（`log_inputs`/执行）→ web（`agentWorkStatus.ts` 的判据与文案）。
- **降级规则**：旧 agentd 收到**未知 ID**（新网关发的）→ 按既有 `unsupported` 如实上报，不当无事发生；旧网关遇到新 ID → 判定不可执行、`active` 被拦。
- 一次能力新增 = 四侧一起改 + 知识库把对应单元开 `active`（**知识库版本单独抬**）。

## 5. agentd 执行模型

**调度（随授权）**

- 每份 `active` 的常驻工作里，把 `Exporter` 来源折算成**导出任务**：`exporter_runs()`（与 `log_inputs()` 并列，走同一份 `AppliedWorkGrant`）。
- 每个 ID 有**默认周期**（写在 ID 表旁，如 `journalctl-unit` 5m、`nft-ruleset` 30m、`smartctl` 1h、`last-reboot` 6h）。周期是**导出器属性**，不是单元字段（首版不做目录覆盖，见 §9）。
- 同一 tick 内按各自 `last_run + period` 判定该不该跑；跨 restart 用本地状态记 `last_run`（`state/exporters/<input_id>.json`）。

**执行**

- 复用 `src/exec/`：把一次导出表达成 `ActionPlan`（`constraints.max_total_duration_ms` 当超时、stdout/stderr 上限沿用），经 `wist-exec run` 起子进程（`src/exec/local_exec.rs::execute_async`）。
- **无 shell、无 argv 拼接**：每个 ID 的实现体给出**固定 argv**（二进制走绝对路径或受控 `PATH` 白名单）。
- 退出码非 0 / 超时 / 二进制缺失 → 记 `unsupported` 或自观测事件，**不静默**。

**输出 → 记录**

- 一次导出 = 一批 `TelemetryRecord`（`src/telemetry/warp_parse.rs` 的记录通道）：
  - `source_path` = 归一 target（如 `exporter:nft-ruleset`，明确这不是真实文件路径）；
  - `family` / `unit` 来自授权（与日志帧同一套）；
  - `body` = 导出的文本（逐行 or 整块，见 §9）；
  - `file_offset` / `file_offset_end` = 该次快照内的字节位（快照型无「历史游标」，语义仅作定位）；
  - `seq` = 全局序号（与日志/事实共用）。
- **不走 checkpoint**：快照型没有「上次读到哪」，重启不补历史。

## 6. 权限

- `requires_privilege = root` 的导出器（`smartctl`、`nft-ruleset`、`iptables-save`、部分 `journalctl`、`auditd-execve`、`dmesg`）由 agentd 直接以 root 运行（agentd 本身是 system service，见 `agentd-service-deployment.md`）。
- `requires_privilege` 仍由**授权**下发（`WorkSpecUnit`），导出器实现据此决定是否需要提权失败时如实报「缺权限」。

## 7. 安全边界（设计红线）

- 无 shell（`sh -c` 一律禁止）、无用户可控字符串拼接进 argv；
- 命令来自**注册表常量**，不来自目录/网关的可变字段（`arg` 只做窄解析）；
- 固定超时 + stdout/stderr 上限（复用 `src/exec/` 既有约束）；
- 洁净环境变量；不继承登录 shell 的 `PATH`。

## 8. 落地清单（slice 1）

**协议层**
- `wist-contracts`：`EXPORTER_IDS` + `is_known_exporter()`；`is_executable_source()` 认 `Exporter`；单测（已知/未知 ID、`id:arg` 解析）。

**agentd**
- 新模块 `src/telemetry/logs/exporters/`（或 `src/telemetry/exporters/`）：ID → 实现体注册表 + 调度 + 输出→记录；
- `AppliedWorkGrant::exporter_runs()` + 周期状态；`summary()` 增加 `exporters=` 计数；
- 复用 `src/exec/` 起子进程；失败入自观测；
- 单测：未知 ID 报 unsupported、周期折算、退出码非 0、超时。

**网关**
- `src/app/content.rs`：`active` 单元的 `Exporter` 来源现可算「可执行」；ID 未知仍拦（`EXECUTABLE_SOURCE_KINDS` 与 `is_known_exporter` 收敛）；
- 真实数据测试：断言受影响的面（linux `ServiceLifecycle` 等）在装载后 `collect_ready`。

**web**
- `src/components/agentWorkStatus.ts`：`isExecutableSource()` 与文案同步；契约测试同步。

**知识库**
- 无需改内容结构（`target` 已是这些 ID）；只需在能力落地后把对应单元 `status = draft → active`，并抬 `catalog_version`（**单独一次 knowledge 版本**）。

**slice 1 的 ID 子集**（先解 LinuxHost/Compute 与 Linux 侧）：
`journalctl-unit`、`journalctl-shutdown`、`last-reboot`、`nft-ruleset`、`iptables-save`、`smartctl`、`dmesg`（`panic`/`nvidia-xid` 两种 `arg`）、`auditd-execve`。

**slice 2**（macOS 侧）：`praudit`、`sqlite-snapshot`、`last`。

## 9. 待决策点

1. **输出 → 记录**：直接发 `TelemetryRecord`（本文默认，快照型、无 checkpoint）**还是**导出器落一个派生文本文件、复用既有 file input（设计稿 §8B 的写法，好处是 offset/轮转/spool 全复用，代价是多一套派生文件的轮转/清理）？
2. **周期从哪来**：ID 表里写死默认周期（本文默认）**还是**给目录加字段让策展可调？
3. **`target` 语法**：现在就归一到 `id:arg`（并同步改目录/mac 侧），还是先只解析、旧写法逐步收敛？
4. **macOS 同批还是分批**：`praudit` / `sqlite-snapshot` 是否纳入 slice 1（安全/合规面更大）。
5. **`dmesg` 的 `arg` 语义**：`panic` / `nvidia-xid` 是**同 ID 不同 arg**（本文默认）还是拆成 `dmesg-panic` / `dmesg-nvidia-xid` 两个 ID？

## 10. 不在本批（另开）

- **通配/目录型 + 运行中新发现文件起始位置**（`discovered_file_position`）：解锁 `crash-panic`（coredump）、`database-service`、`backup-job`、`network-service`、`compute-workload` 的通配部分、`storage-health` 的 `fsck*`。这批是**文件输入发现**能力，与 Exporter 正交，单独出稿。

## 11. 相关文档

- [`log-file-input-spec.md`](./log-file-input-spec.md)：文件输入（tail/checkpoint/rotate）规格
- [`linux-security-audit-log-sources.md`](./linux-security-audit-log-sources.md) §8：接入分级（A 现成 / B 需定时导出器）
- [`macos-security-audit-log-sources.md`](./macos-security-audit-log-sources.md)：macOS 源清单
- `wist-contracts/src/work.rs`：`EXECUTABLE_SOURCE_KINDS` / `is_executable_source` / `WorkSpecSource`
- `wist-knowledge/catalog.toml`：`Exporter` 目标 ID 的现状
