# wist-agentd macOS / Linux 后台长期运行方案（设计说明）

本文说明**为什么**这样让 `wist-agentd` 长期后台运行。具体命令、安装位置表、升级步骤、排障表在
[安装与使用手册](../usage/agentd-install-and-usage.md)，本文不重复。

- 相关代码：[`src/service/`](../../src/service)、[`src/single_instance.rs`](../../src/single_instance.rs)、
  [`src/runtime/steady_log.rs`](../../src/runtime/steady_log.rs)
- 相关文档：[agentd-architecture.md](./agentd-architecture.md)、[agentd-failure-handling.md](./agentd-failure-handling.md)

---

## 1. 目标与非目标

| 目标 | 落地手段 |
| --- | --- |
| 关掉终端、退出登录后仍运行 | 交给 OS 服务管理器（Linux systemd / upstart、macOS launchd）托管 |
| 开机自启 | systemd `enable`；upstart `start on runlevel [2345]`；launchd `RunAtLoad` + `LaunchDaemons` |
| 崩溃自动拉起 | systemd `Restart=always`；upstart `respawn limit unlimited`；launchd `KeepAlive` |
| 长期运行不撑爆磁盘 | 稳态日志收敛 + journald / newsyslog 轮转 |
| 长期运行不出现重复实例 | state 目录 `flock` 单实例锁（进程退出即自动释放） |
| 配置 / 数据 / 日志分离 | 配置在 `/etc/wist-agentd`，数据（含采集输出 `data/`）落 `/var/lib/wist-agentd`，日志落 `/var/log/wist-agentd`（FHS） |
| 可升级、可回滚 | 原地替换二进制 + 重启服务；执行中的计划由 crash recovery 承接 |
| 验收可重复 | `dev/verify-system-install.sh`（需 root 的一次性验收机）自动断言定义/自启/running/落点/采集输出/拉起/单实例 |

**非目标（本方案不做）**：

- 不做 `fork` / `double-fork` daemonize。前台运行是服务管理器的前提，也避免了“谁持有 PID”的歧义。
- 不代替 `dev/start.sh`。`dev/` 仍是**开发机联调**脚本（`&` + `disown` + pidfile）；
  生产常驻一律走 `service install`。
- 不创建专用系统账号、不装 root helper。需要提权采集（audit / TCC / 统一日志）时，
  按 [macos-agent-uplink-to-warp-parse.md](./macos-agent-uplink-to-warp-parse.md) 的 root helper 方案另议。

## 2. 总体设计

```mermaid
flowchart TD
    subgraph OS["OS 服务管理器"]
        S["systemd (Linux)<br/>Restart=always"]
        U["upstart (CentOS/RHEL 6)<br/>respawn limit unlimited"]
        L["launchd (macOS)<br/>KeepAlive"]
    end
    S --> A["wist-agentd (前台常驻)<br/>--config-dir &lt;绝对路径&gt;"]
    U --> A
    L --> A
    A --> E["wist-exec (同目录 sibling)"]
    A --> ST["state/ 单实例 flock + 执行状态"]
    A --> LG["日志：/var/log/wist-agentd<br/>（systemd：journald）"]
```

三条硬约束：

1. **前台运行**：`ExecStart` / `ProgramArguments` 直接指向 `wist-agentd`，不加 daemonize 参数。
2. **配置目录必须绝对**：服务启动时 CWD 不确定，`--config-dir` 在安装时即被解析成绝对路径写进定义文件；
   配置文件内的 `[paths]` 相对路径一律相对**配置文件所在目录**解析（`resolve_paths`）。
3. **`wist-exec` 与 `wist-agentd` 同目录**：守护进程优先按“可执行文件同目录 sibling”解析执行器；
   安装时会检查并告警，也可用 `WARP_INSIGHT_EXEC_BIN` 覆盖。

### 两种安装方式与设计的关系

安装方式只影响“**由谁发起、放哪里、以谁运行**”，机制完全共用：

| | 开发环境安装（手册 §2） | 通过 Wist-Gateway 安装（手册 §3，TODO） |
| --- | --- | --- |
| 发起方 | 工程师手工执行 | 控制面下发安装指令（含 endpoint + 一次性 token） |
| 目录落点 | 全部就地（配置/数据/日志在同一个目录） | 配置 `/etc`、数据 `/var/lib`、日志 `/var/log`（第 5 节） |
| 运行身份 | 当前用户（不装服务，前台直跑） | root（系统级 systemd / upstart / launchd） |
| 注册 | 可选；`enroll --token` 一次性传入 | `service install --enrollment-token`，token 不落盘 |
| 日志采集 | 随进程（stderr 或 `[log].file`） | journald / `/var/log/wist-agentd` |

共用机制：`service install`（渲染 + 落盘 + 激活）、命令行一次性注册、路径推导、flock 单实例。
网关安装只是把这一串手工步骤搬进安装脚本，因此 agent 侧的能力已就位（见手册 §3.2）。

## 3. 关键取舍

**为什么不自带 daemonize。** 常驻托管有两条路：自己 `fork` 脱离终端（传统 daemon），或前台运行交给
supervisor。后者让“谁在管、怎么重启、日志去哪”都有唯一答案，也避免了 `fork` 之后 PID/日志/信号
处理的常见坑；`dev/start.sh` 那种 `&` + `disown` 只是开发机权宜。

**为什么用 flock 而不是 pidfile 判重复。** pidfile 有“stale 文件要清理、PID 被复用误判”的问题；
`flock` 挂在打开的文件描述符上，进程退出（含 `kill -9`）即由内核释放，覆盖 `start.sh`、`--foreground`、
直接运行二进制、supervisor 拉起等所有入口。副作用是“服务管理器重启期间若前任未退出，新进程会快速失败”，
这正是 `RestartSec` / `RestartSteps`（systemd）与 `ThrottleInterval`（launchd）要限流的原因。

**为什么不用 `StartLimitBurst` 限流。** 它配 `Restart=always` 的语义是“限流窗口内失败 N 次 → 标记
`failed` → **永久放弃拉起**，必须人工 `reset-failed`”。它只能防“配置写坏”这类不可恢复的快速失败，
而真正高频的是磁盘满、网络未就绪这类**可恢复的外部故障**——故障期间连 journald 都可能写不了盘，
等人来 `reset-failed` 就是无限期躺死（现场：盘满 8 天无服务）。所以 systemd 侧改成
`StartLimitIntervalSec=0` + 指数退避（`RestartSteps` / `RestartMaxDelaySec`），与 macOS 的
“一直重试”语义对齐。

**为什么支持 upstart（CentOS 6 / RHEL 6）。** 静态 musl 制品能在 kernel 2.6.32 上跑（采测：发现、指标、
上送链路全通），但 RHEL 6 的 PID 1 是 upstart 0.6.5，没有 systemd。如果 `service install` 写死 systemd，
这类主机就只能手写 init 脚本，网关 `install.sh` 也会在 `systemctl` 那一步失败。因此平台改为**按运行态判定**：
有 `systemctl` 走 systemd，否则 `/etc/init` + `initctl` 走 upstart，两者都没有时退回旧行为（写 unit）。

与 systemd 的语义对齐有两个坑：（1）upstart 的 `start` 在已 running 时是 no-op（报
`Job is already running`），所以 `--force` 重装不能只 `start`，激活序列必须是
`reload-configuration` + `stop` + `start`；（2）upstart 没有指数退避，也不能靠 `respawn limit`
限流（那是“失败 N 次就放弃”，与上面的设计取舍相反），所以用 `post-stop exec sleep 5`
固定间隔压重启风暴，代价是 `stop` 也等 5 秒。

另一个必须记住的兼容细节：RHEL 6 的 upstart 0.6.5 **不认** `kill signal` / `kill timeout`，写了会让整份 job
被丢弃（`/var/log/messages`: `Unknown stanza`，`initctl`: `Unknown job`），所以渲染器不输出这两个 stanza。

`agentd.env` 在 upstart 侧不能照搬 systemd 的“加载环境文件”写法：job 里 `. agentd.env` 是 **shell** 语义，
文件里一行 `FOO=$(...)` 就会以 root 执行；而 systemd 的 `EnvironmentFile` 是**数据**语义。两边语义不一致
比不支持更危险（同一份文件在一个平台安全、另一个平台成后门），所以 job 里自己按 `KEY=VALUE` 解析。

**为什么 `service install` 只做两件事。** 渲染定义 → 落盘（+ 建 launchd 日志目录），服务管理器调用
单独一步、可 `--no-activate` 跳过。这样：单测只覆盖“可确定的部分”（文本与文件），发行包/配置管理
工具可以只取 `service print --for` 的产物自己分发，不需要在安装机上执行二进制。

**为什么主循环是 3s（`TICK_INTERVAL`）。** 每轮都要重算派生状态并扫描 `state/`，tick 周期直接决定
采集与上报的时效。**它不等于稳态磁盘动作频率**：派生文件的落盘都按「内容/结构变了才写」收敛
（0.35.1，见第 7 节第 1 条），空闲拍一次都不写。换来的是“采样延迟”而不是“吞吐”——`drain` 每轮只
处理一个队列项且等它跑完，该值不是执行吞吐上限。

边界：更快的 tick 只增加写盘次数，换不到可感知的收益（file 输入本就是秒级时效）；慢于 5s 才开始拖
采集延迟。判断依据是“负载是否真有亚秒级时效要求”——采集（file tail）没有，将来的近实时场景单独议。
副作用见第 7 节第 6 条。

**为什么日志必须收敛。** 见第 4 节：不收敛的话，磁盘会被固定频率的输出吃满。

## 4. 日志：为什么必须收敛

常驻主循环周期 3s（`src/runtime/daemon.rs` 的 `TICK_INTERVAL`），每轮产出健康快照与指标快照。若逐轮打印：

- 健康快照：`health` + `metrics_runtime` + 每个 discovery probe 一行（默认 4 个探针）= 6 行/轮
- 指标快照：`event=MetricsRuntimeUpdated` 1 行/轮

即 **≈2.3 行/秒 ≈ 20 万行/天**（按 200B/行 ≈ 40 MB/天 ≈ 14 GB/年）——与“有没有变化”无关的固定频率写入，
时间一长仍必须靠日志轮转兜底。因此 `src/runtime/steady_log.rs` 对这两路**周期快照**做“签名去重 + 心跳”：

| 行为 | 说明 |
| --- | --- |
| 内容变化 | 立即打印（状态迁移、队列/running/reporting 变化、探针状态/计数变化、指标失败等） |
| 内容不变 | 每 `WIST_AGENTD_LOG_HEARTBEAT_SECS`（默认 300s）补一条心跳 |
| `=0` | 关闭收敛（回到逐轮打印），仅用于联调 |
| 其他日志 | 失败、事件、状态迁移通知（`DiscoveryRefreshFailed`、`telemetry_*`、`MetricsRuntimeFailed` 等）**始终逐条打印** |

签名刻意排除每轮都变的 `updated_at`，但保留探针/指标的**计数**（resources / targets / attempted 等）——
它们是真实变化，不该被静默丢掉。代价是“输出量与变化量成正比”：实测（macOS，约 900 进程的开发机，30s）
58 行 ≈ 1.9 行/秒；空闲主机上基本只剩心跳（默认 5 分钟一条）。**所以仍需系统侧轮转兜底**
（配置见手册 §7.1）。

## 5. 配置 / 数据 / 日志分离（FHS）

系统级部署下，三类内容分开放，**不需要运维写 `[paths]`**：

| 类别 | 位置 | 理由 |
| --- | --- | --- |
| 配置 `agentd.toml` + `tasks/` | `/etc/wist-agentd/` | 属于“管理员输入”，可能被配置管理工具接管、甚至只读挂载 |
| 数据 `run/`（`wist-exec` 工作目录） | `/var/lib/wist-agentd/run/` | 运行期数据，不是配置；放 `/run` 会在重启后被清空，反而多一种失败态 |
| 数据 `state/`（队列、running/reporting/history、checkpoint、spool） | `/var/lib/wist-agentd/state/` | 持久状态，重启/升级不能丢 |
| 数据：**采集输出**（file sink 默认） | `/var/lib/wist-agentd/data/wist-records.ndjson` | 采集结果是数据（要入库/上送的东西），不是 agent 的运行日志 |
| 日志 `log_dir` | `/var/log/wist-agentd/` | 日志天经地义在 `/var/log` |
| 服务自身 stdout/stderr | journald（Linux）/ `/var/log/wist-agentd/agentd.{out,err}`（macOS 系统级） | 交给 init 系统自带的日志通道 |
| 致命退出（`run()` 返回 Err） | 额外写 `/dev/kmsg`（Linux） | journald 自己也落盘：磁盘满时那一次启动失败会无痕；kmsg 不占盘（见 `src/kmsg.rs`） |

实现方式（`config_runtime_support::apply_path_defaults`）：只**填充 `[paths]` 中未声明的键**（及未声明的
采集输出路径），规则是“配置目录在 `/etc/wist-agentd` 下 → 数据（run/state/spool + 采集输出 `data/`）落
`/var/lib/wist-agentd`、日志落 `/var/log/wist-agentd`；其它位置 → 配置/数据/日志全部就地”。
选择“路径推导”而不是“新增配置项或安装参数”的原因：

- 没有任何新增开关，`service install` 与直接运行两种入口得到同一套布局；
- 显式声明优先，不会静默改写运维已经写定的路径（在 `/opt` 等非标准位置部署时运维可自行声明）；
- 判断依据（配置文件在哪）与运维看到的完全一致，不需要额外解释“为什么数据在另一个目录”。

开发机 / 自定义配置目录走“就地一整套”，所以**非 root 开发不会碰到 `/etc`、`/var/lib`、`/var/log`**；
`init-config` 的输出与 `service status` 的 `root_dir/run_dir/state_dir/log_dir` 都会把真实落点直接展示出来。

## 6. 服务定义里固化了什么

`service install` 写出的定义包含以下取舍（渲染文本可用 `wist-agentd service print` 查看）：

| 项 | systemd | launchd | 原因 |
| --- | --- | --- | --- |
| 前台运行 | `Type=simple` | `ProgramArguments` 直指二进制 | 见第 3 节 |
| 退出即拉起 | `Restart=always` + `RestartSec=5` | `KeepAlive` + `ThrottleInterval=10` | 常驻进程不应退出；限流避免失败重启风暴 |
| 重启风暴兜底 | `StartLimitIntervalSec=0` + `RestartSteps=5` + `RestartMaxDelaySec=60` | `ThrottleInterval` | 退避 5s→60s 后封顶，**永不放弃**：可恢复的外部故障解除后自己回来；systemd < 254 忽略后两项，退化成固定 5s 重试 |
| 停止语义 | `KillSignal=SIGTERM` + `TimeoutStopSec=30` + `KillMode=control-group` | `ExitTimeOut=30` | 停止时连 `wist-exec` 子进程一起收走；未完成执行交由 crash recovery。升级器不受此回收：它另立瞬态 unit（见架构 §11.2）|
| 环境变量 | `EnvironmentFile=-<config>/agentd.env`（可缺失） | 仅显式 `PATH` | 放长期环境变量；注册 token 走命令行，不落盘 |
| 日志 | `StandardOutput/Error=journal` | `StandardOut/ErrorPath` 落 `/var/log/wist-agentd/` | journald 自带回收；launchd 需 newsyslog |
| 权限 | `NoNewPrivileges=true`、`LimitNOFILE=65536` | 运行在 root（LaunchDaemon） | 只禁提权、不降权：agent 仍要以 root 读受限日志路径 |
| 自启 | `WantedBy=multi-user.target` | plist 位于 `LaunchDaemons` | 系统级开机起 |

### 模板变更怎么落到存量机器

**升级只换二进制，定义文件不会自动重写。** 这不是遗漏而是分层：`service install` 是一个原语（写定义 + 激活），
“清 start limit 的 failed 态”是现场处置步骤，把这类步骤固化进安装路径会让 `failed` 态这个现场证据被静默清掉，
也把一次性运维动作变成永久契约。所以 0.33 及更早落盘的 unit（带 `StartLimitBurst`）的退场方式是
**文档化的一次性迁移**（`reset-failed` → `service install --force`，见使用手册 §2.2），而不是产品在安装/升级时
自动改 `/etc`。

如果将来“定义变更”变成常态需求，再考虑在升级器里增加一步“用新件 `service install --force --no-activate` 重渲染 +
`daemon-reload`”（注意：跑升级的升级器是旧镜像，只能调用新装的 agentd 来渲染）；在那之前不为一次事故建一条
自动修改系统配置的长久通道。

### 重新安装必须重建进程

`service install --force`（升级二进制 / 改配置后重跑）不是“只重写文件”，它必须让新进程按新定义、新二进制跑起来：

| 平台 | 加载序列 | 为什么这样 |
| --- | --- | --- |
| systemd | `daemon-reload` → `enable` → `restart` | `enable --now` 在**已 active** 的 unit 上等价于 `start`（no-op），会留着旧进程跑旧二进制；`restart` 在首次安装（尚未启动）时也会把服务拉起来，因此两种情形都对 |
| launchd | `bootout`（失败可忽略）→ `bootstrap` → `enable` | `bootout` + `bootstrap` 天然杀掉旧进程、按新 plist 重建 |

`bootstrap` 在 `bootout` 之后少量重试（上限 5 次 / 300ms）：`bootout` 返回不等于旧进程已退出，紧跟其后的加载会拿到
`Bootstrap failed: 5: Input/output error` 这类瞬时错误。重试只在**失败**时发生，成功不会引入额外等待。

## 7. 已知限制与后续优化

1. **稳态每 3s 已经没有写盘**（0.35.1）。四处都按「没变就不碰磁盘」收敛：

   - `state/export/*.jsonl` 的**发现**导出 → 按 discovery revision 跳过（文件被删会重写）；
   - `metrics_runtime_snapshot.json` → 结构性变化（目标集合 / 状态 / 错误）立即写，只有数值抖动
     才按 60s 节流；
   - `export/metrics.jsonl` → 跟着快照落盘的那一拍导，也降到 ≤1/60s；
   - `agent_runtime.json` → 只在文件缺失时补一份（`updated_at` 没有读者）。

   上送与本地导出都用内存快照，不依赖这些文件的新鲜度。
2. **环境变量只在 Linux systemd 下可注入**：launchd 没有 `EnvironmentFile` 等价物（plist 只显式补
   `PATH`），macOS 需要长期环境变量时只能手工维护 plist；`agentd.env` 仅用于 Linux systemd。
3. **root 采集能力**：audit / TCC / 统一日志仍需 root helper，见第 1 节“非目标”。
4. **定义里没有 `User=` / `Group=` 降权项**：需要非 root 运行时，安装后手工编辑 unit，
   或后续给 `service install` 增加 `--run-as`。
5. **连续执行之间有固定空档（3s 取舍的副作用）**：`scheduler::drain_next_async` 每轮只处理一个队列项、
   且等它跑完才返回，循环末尾又固定 sleep 一个 tick。因此队列繁忙时两个执行之间最多插 3s 空档。
   当前 `src/` 内没有 `submit_local_plan` 的调用方（等网关接入），所以现在没有实际吞吐影响；
   负载上来后可按“该 tick 真的派发了任务就不 sleep”优化。
