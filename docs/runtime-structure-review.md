# agentd 运行时结构评审：卡点 / 资源占用 / 异步化

> 审查对象：`wist-agentd` alpha 分支（0.28.1）
> 方法：按三条链路分别读代码 —— ① 指标采集 ② 日志采集 ③ 控制面/上报。
> 行号基于当前提交，随代码演进可能漂移，定位时以函数名为准。
>
> **一句话结论**：单线程运行时（`current_thread`）上跑一条**串行主循环**，
> 而主循环里混进了「网络等待 + 磁盘 fsync + 同步进程扫描」；
> 同时多个**跨 tick 状态被每 tick 重建**（HTTP client、TCP sink、证书、机器画像），
> 导致稳态开销和故障半径都被放大。

---

## 一、问题总览

| # | 问题 | 类别 | 影响 | 优先级 |
|---|---|---|---|---|
| 1 | 每个控制面请求新建 `reqwest::Client`（无连接池、每次 TLS 握手 + 解析证书） | 资源 | 每 3s 一次握手 + 2 次 PEM/X.509 解析 | **P0** |
| 2 | TCP sink 每 tick 重建 → 连接不复用、**指数退避跨不过 tick** | 卡点 | 断网时 3s 节奏被拉成 8s；健康时也每 tick 重连 | **P0** |
| 3 | `process_metrics_tick` 同步读 + 同步写（含 fsync），从 async 主循环调用 | 卡点/资源 | 每 3s 一次全量落盘，内容未变也写 | **P0** |
| 4 | 控制面 13 个串行 `await` 排在采集之前 | 卡点 | 网关黑洞时单轮可达 ~80s，采集被拖 | P1 |
| 5 | 上行写压在采集关键路径上（connect 5s + write 15s） | 卡点 | 一次坏上行拖死整机所有上报 | P1 |
| 6 | 自探只有**一个**槽位，四域共用、后到覆盖先到 | 卡点 | 某些域的目标集合可能长期不刷新 | P1 |
| 7 | 采集线程 permit 不回收 + 无 watchdog | 卡点 | 8 个挂死作业 = 全部采集停摆，仅一行 warn | P1 |
| 8 | SQL 每轮新建连接（无池），会话 `SET` 无超时 | 资源/卡点 | 每轮 TCP+TLS+认证；两处可永不返回 | P1 |
| 9 | 日志每 tick 对每个文件 3~5 次 `open` | 资源 | 512 文件 × 每秒 = 数千 syscall/tick | P2 |
| 10 | 追平循环**每批**重读整份 checkpoint 并 fsync | 资源 | 每批 4 次 fsync，吞吐被 fsync 钉住 | P2 |
| 11 | spool 回放「全量读 + 成功才删」 | 卡点 | 断网恢复时每拍整份重发，CPU/IO/带宽放大器 | P2 |
| 12 | 无界增长：`inflight_investigations` 无上限、`pending_command_acks` 只在成功时清 | 资源 | 控制面长期不可达时堆积 | P2 |
| 13 | 主循环 `?` 直接把 tick 错误冒成进程退出 | 健壮性 | 一次 ENOSPC 重启掉整条链路 + 丢内存 grant | P2 |

---

## 二、运行时结构

```
┌─ main: #[tokio::main(flavor = "current_thread")] ──────────────────────┐
│                                                                        │
│  run_forever_async (daemon.rs:1834)                                    │
│  loop {                                                                │
│    1  取本机命令（本地文件）                                            │
│    2  收调查结果 → 建 TCP sink 发送                                     │
│    3  命令队列（probe 命令直接 await 网络）                             │
│    4  凭据续期（1h）                                                    │
│    5  metrics labels（5min）                                            │
│    6  发现策略表（5min）                                                │
│    7  L3 搜索范围（5min）                                               │
│    8  uplink grant（30s）                                               │
│    9  快照策略（30s）                                                   │
│   10  work grant + ack + result（30s）                                  │
│   11  ★ 采集 tick（同步发现探针 + sink 连接 + 写 spec）                  │
│   12  ★ 状态上报（每轮）                                                │
│   13  sleep(3s)                                                        │
│  }                                                                     │
│                                                                        │
│  采集线程（独立 std::thread + 8 permit）                                │
│    scan → host → kafka → mysql → doris → pg   （贪心抢 permit）          │
└────────────────────────────────────────────────────────────────────────┘
```

**结构性问题**：第 1–12 步全是串行 `await`。任何一步慢，后面的采集和下一次心跳都等；
而第 13 步是 `sleep(3s)` 而非 `interval` 补正，所以「3s 一拍」在弱网下不成立。

---

## 三、卡点（按严重度）

### 3.1 【P0】TCP sink 每 tick 重建 → 退避机制实际失效

`build_telemetry_sink` 在每轮 tick 重新构造（`daemon.rs:2655`），`TcpRecordSink` 的
`stream` / `next_attempt_at` / `backoff` 随实例丢弃（`warp_parse.rs:274-302`）。

- 健康链路：每 3s 一次 TCP 连接（`warp_parse.rs:328`）；
- 断网：`TCP_BACKOFF_INITIAL..MAX = 1s..30s` 的指数退避**跨不过 tick**，
  每个 tick 都重新连一次，5s 连接超时（`:249`）把 3s 节奏拉成 8s。

**改法**：把 sink 放进 `run_forever_async` 的跨 tick 状态（和 `discovery_runtime` 一样），
让退避与连接真正生效。

### 3.2 【P0】`process_metrics_tick` 在 async 主循环里做同步 IO

`daemon_metrics.rs:150-191`：每 tick
`read_json(target_view)` → `build_runtime_snapshot_live`（**同步扫描主机进程**）
→ `runtime::store`（**pretty JSON + tmp + fsync + rename + 目录 fsync**）。
内容没变也照写，且主循环本来就有 `target_view` 这份数据。

**改法**：
1. 改成 `fs_async` 版本；
2. 写盘前比较内容签名，未变则跳过；
3. `build_runtime_snapshot_live` 移到采集线程。

### 3.3 【P1】控制面 13 个串行 await 排在采集之前

`daemon.rs:2004-2590`。5 分钟整点那一轮，续期 + labels + 策略 + 搜索 + uplink +
快照 + work 同时到期，叠加可到 **~80s**（其中续期重试 3×10s）。

**改法**（两步走）：
- 先 `join!` 并发第 5–9 步（互不依赖），把「5 个 5s」压成「5s」；
- 彻底做法：整段搬进后台 task，主循环只读 `watch` 快照。

### 3.4 【P1】上行写压在采集关键路径

`daemon.rs:2741` 串行 await `process_telemetry_inputs` →
`TcpRecordSink::write_payload`（`warp_parse.rs:356-388`），最坏 5s + 15s = **20s**。
`CatchupBudget` 只在两批之间判时间，不覆盖一次 sink 写。

**改法**：采集侧只产出记录（spool 已兜底），发送交给独立 task + 有界 channel；
即便暂不重构，也要给 sink 写包一层 `timeout(2s)` —— 写失败落 spool 的路径已经现成
（`delivery_support.rs:74-88`）。

### 3.5 【P1】自探只有一个槽位，四域后到覆盖先到

`scheduler.rs:163-164` 是 `pending_scan: Option<_>` + `scan_inflight: bool`；
`request_scan` 直接赋值（`scheduler.rs:215-219`）。同一 tick 里 Kafka→MySQL→PG→Doris
依次投递（`daemon.rs:2275/2306/2338`），**排最后的 Doris 恒赢**，前三个本轮目标集合直接丢，
而它们的 `last_*_scan` 已被置 now，要等 300s 才重投。

另外 `scan_inflight` 没有 `started_at`，`log_stalled` 不覆盖扫描（`scheduler.rs:476-533`）：
一个卡死的扫描会让**所有域**永久无法重扫，且零日志。

**改法**：按域拆 4 个槽位 + 每槽 `started_at` 并入 `log_stalled`。

### 3.6 【P1】采集完成不回收 permit

`scheduler.rs:14-15` 明确「阻塞作业不可取消」，`log_stalled` 只 warn 一次。
8 个挂死的 Kafka/主机作业能让全部采集停摆，唯一信号是一行日志。

### 3.7 【P2】日志链路的三个放大器

| 位置 | 现象 |
|---|---|
| `files/file.rs:910/945/962/1043` + `checkpoint_support.rs:126` | 同一文件每 tick **3~5 次 open** + 1~2 次 canonicalize |
| `files/file.rs:652, 706-711, 1214` | 追平循环**每批**整份读回 + 写 seq + 写 checkpoints，每批 4 次 fsync |
| `spool.rs:88-125` | 回放「全量读 + 成功才删」，失败则下一拍从第 1 条重放 |

---

## 四、资源占用

### 4.1 稳态「每 3s 重复做慢变量」

| 每 tick 做的事 | 位置 | 本可以 |
|---|---|---|
| `Client::builder()...build()` + TLS 握手 | `enrollment.rs:630-689` | 复用 `OnceLock<Client>` |
| 读证书 PEM + 解私钥 + X.509 解析（×2） | `enrollment.rs:674-676, 698-732` + `daemon.rs:342-362` | 60s TTL 或按 mtime 失效 |
| `getifaddrs` 枚举网卡 + `/etc/machine-id` | `daemon.rs:510` → `enrollment.rs:343-368` | 5min TTL |
| 写 `state/export/*.jsonl`（十几个 fsync） | `daemon.rs:2856` → `reporting/exporter.rs:253-298` | 内容未变跳过 |
| 写 metrics runtime snapshot（fsync） | `daemon_metrics.rs:158` | 内容未变跳过 |

### 4.2 内存 churn（不是泄漏）

- `host.outcomes.clone()`（`scheduler.rs:728`）→ 每 result 的 targets 全量 clone + `BTreeSet` 去重（`collection.rs:266-270`）→ snapshot → samples 再拷；
- 每次 `request_scan` 收 `snapshot.cloned()`（macOS 实测 ~800KB），一 tick 四个域投 4 份、3 份被覆盖丢弃；
- 日志侧每 tick `runtime.log_state.clone()` 整棵树（含 pending 正文，单条上限 1 MiB）。

### 4.3 无界或口径不一致

| 项 | 位置 | 说明 |
|---|---|---|
| `inflight_investigations: Vec` | `daemon.rs:1948` | 无并发上限，每条 spawn 一份 `AgentConfig::clone`，可跑 300s |
| `pending_command_acks` | `daemon.rs:2565-2569` | **只在上报成功时清**，控制面长期不可达就堆积 |
| `pending_work_state_changes` | `daemon.rs:2531-2536` | 发送前 `mem::take`，失败**静默丢弃**（与 acks 口径不一致） |
| spool `.bad` 隔离文件 | `spool.rs:175-182` | 只增不减，无轮转 |

### 4.4 干净的地方

- 采集线程内部没有把 `std::sync::Mutex` guard 跨 `.await` 持有；
- 阻塞作业统一丢进 `spawn_blocking`（`collection.rs:94`）；
- multiline 有界（1000 行 / 1 MiB，`multiline.rs:22-30`）；
- spool 上限 256 MiB/输入，超限暂停读源而不丢数据（`file.rs:602-618`）。

---

## 五、异步化机会（按 ROI）

| # | 改法 | 收益 |
|---|---|---|
| 1 | 共享 `reqwest::Client` + 证书/画像 TTL | **稳态 CPU/IO 降一个数量级**，改动面极小 |
| 2 | sink 跨 tick 复用 | 退避生效；健康链路不再每 3s 重连 |
| 3 | `process_metrics_tick` 异步化 + 未变不写 | 干掉每 3s 的 fsync 和同步扫描 |
| 4 | 控制面拉取后台化（`watch` 快照） | 主循环只剩采集，弱网不再拖采集 |
| 5 | 上行独立 task + 有界 channel | 出口故障只影响出口 |
| 6 | `interval` + `MissedTickBehavior::Delay` 替代尾部 `sleep` | 3s 变 deadline，不再「拍 + 耗时」 |
| 7 | 日志每文件一次 open + `buffered(4~8)` 并发读 | 少 2/3 open，延迟叠加 |
| 8 | 追平循环内不落盘，一轮提交一次 | fsync 降一个数量级 |
| 9 | spool 断点续传（记已确认前缀） | 断网恢复不再整份重放 |
| 10 | 本地动作 / 导出器 spawn 出去 | 消除分钟级主循环停顿 |

---

## 六、建议路线

### 第一批（P0，改动小、收益最大，可单独发版）

1. **共享 HTTP client**：`OnceLock<reqwest::Client>`，仅在凭据轮换时重建；
   证书状态 60s TTL、机器画像 5min TTL；
2. **sink 跨 tick 复用**：把 `TcpRecordSink` 挪进 `run_forever_async` 的状态；
3. **`process_metrics_tick` 异步化 + 内容签名跳过写盘**。

预期：稳态每秒 syscall / TLS 握手 / fsync 数量降一个数量级；断网时节奏不再被打散。

#### 落地状态（0.28.2）

| # | 状态 | 落点 |
|---|---|---|
| 1 | ✅ 大部分 | `enrollment_http_client` 按 key 缓存 `Client`；`local_certificate_status` 60s TTL（按证书 + 续签台账 mtime 失效）。**机器画像 5min TTL 未做** → 见待改项 B1 |
| 2 | ✅ | `TelemetrySinkSlot`（身份 = 输出类别 + 目标 + 分帧）挂在 `run_forever_async` 上；一次性路径仍每次新建。**附带：连接上开 TCP keepalive**（见下“复用引入的新风险”） |
| 3 | ✅ | `process_metrics_tick` → `spawn_blocking`；`store_unless_unchanged` 按排除 `generated_at` 的内容签名跳过写盘 |

对应的钉子用例（每个都做过“去掉修复就变红”的核对）：

| 用例 | 钉住什么 |
|---|---|
| `the_client_cache_key_covers_every_input_that_shapes_the_client` | key 少一项就是“证书轮换后永远拿旧证书握手” |
| `sink_identity_folds_framing_into_the_reuse_key` | 分帧必须是身份的一部分，否则升级不重建 |
| `the_sink_slot_reuses_one_connection_across_ticks` | 两拍两帧必须落在**一条**连接上 |
| `the_sink_slot_keeps_the_backoff_window_across_ticks` | 退避状态必须活过一拍（复用只是手段，退避才是目的） |
| `the_sink_slot_rebuilds_when_the_target_changes` | 换目标必须新建连接 |
| `a_connected_uplink_socket_has_tcp_keepalive_enabled` | 长连接必须开 keepalive |
| `unchanged_content_is_not_rewritten_even_though_generated_at_moves` | 内容未变不落盘 |
| `a_change_confined_to_outcomes_is_still_written` | 签名要盖住 outcomes，不能只看计数 |
| `a_vanished_snapshot_file_is_written_again` | 文件被删后不能因签名相同而永久不写 |

**未做（有意）**：sink 写外再套 `timeout(2s)`。它会取消到任意字节上，线上留下半帧——
接收端在 EOF 时会把残行当成完整记录；现有的「无进展 5s + 总时长 15s + 后台收尾」正是为此设计。

**复用引入的新风险（已处理）**：连接以前每 3 秒重建，永远“新”；现在能活几小时。
一条被 NAT / 防火墙 / 对端重启静默弄死的连接，本端**第一次写仍会成功**（数据进了对端内核
缓冲，甚至是被 RST 的哑连接），要等下一次写才 EPIPE。对策是 `enable_keepalive`
（空闲 60s、探测间隔 15s）：kernel 在分钟级把死连接判掉，写随即失败 → 落 spool 重放。

### 第二批（P1，结构性）

4. 控制面拉取后台化（先 `join!`，再 `watch` 快照）；
5. 上行独立 task + 有界 channel（并给 sink 写加 `timeout`）；
6. 自探按域拆槽 + `started_at` watchdog；
7. SQL 换 `Pool`（`max_connections=1~2`），把 `SET SESSION` / `set_config` 包进超时，
   超时后显式 `close().await`。

### 第三批（P2，性能细节）

8. 日志一次 open + 并发读 + 一轮一次落盘；
9. spool 断点续传 + 回放限速；
10. 导出器按内容变化写；
11. `inflight_investigations` 加并发上限；`pending_command_acks` 加上限 + 失败保留策略对齐；
12. tick 的 `Err` 降级为记日志（不要杀进程）。

---

## 七、怎么观测这些指标（验证改动的效益）

现有自观测（`runtime/self_observability.rs`）之外，建议补三个可以直接量化的信号：

| 信号 | 采集方式 | 期望 |
|---|---|---|
| 每 tick 主循环耗时 | 主循环入口/出口 `Instant` 差，打点到 `state/self/*.json` | p99 < 500ms |
| 每 tick fsync 次数 | 统计 `fs_async::write_json_atomic_async` 调用 | 稳态趋近 0（未变不写） |
| 控制面请求耗时 / TLS 握手次数 | 复用 client 后握手次数应≈连接数而非请求数 | 每 5min 一次量级 |

---

## 八、待改项（backlog）

> 这是本文件唯一的工作清单：**做完一项就在该行标上 ✅ 并补上落点 + 钉子用例**，
> 不要另开清单（两份清单必然漂）。P0 已全部落地，下面剩下的都是 P1 / P2。

### 发布前必办（否则会发错包）

| # | 项 | 说明 |
|---|---|---|
| R1 | ✅ **已完成** —— 删掉 `[patch.crates-io] wist-contracts = { path = "../wist-contracts" }` | 已验证前提：crates.io 上的 `wist-contracts 0.10.4` 源码里确有 `pub collection: Option<AgentLocalCollection>`（`local_work.rs:91`）。依赖下限已从 `0.10.3` 提到 `0.10.4`（写 `0.10.3` 时最小版本解析会挑到编译不过的版本）。核对方式：`Cargo.lock` 已指向 `registry+...crates.io-index` 带 checksum，`cargo clean -p wist-contracts && cargo build` 能纯从 registry 重编通过 |
| R2 | ✅ **已完成（已自动化）** —— 发布产物静态链接受 CI 自证 | `release.yml` 的打包步骤现在逐个检查三件产物，不是 `statically linked` / `static-pie linked` 就当场拒发。首放（v0.29.0-beta）就抓到了判据写窄：x86_64-musl 产物是 `static-pie linked`（Rust 默认开 PIE），而 aarch64-musl 是 `statically linked`。本地 zigbuild 产物与 CI musl-gcc 产物形态不同，所以“本地验过”不能代替这道闸 |

### P1（结构性；不改就会在弱网 / 大机器上成瓶颈）

| # | 项 | 为什么 / 切入点 |
|---|---|---|
| B1 | 机器画像 `5min` TTL | `getifaddrs` 枚举网卡 + 读 `/etc/machine-id` 仍然每 3 秒一次（评审 4.1）；与已做的 client / 证书缓存同一套写法 |
| B2 | 控制面 13 个串行 `await` | 先 `join!` 并发互不依赖的 5–9 步，把“5 个 5s”压成“5s”；彻底做法是整段搬进后台 task，主循环只读 `watch` 快照（评审 3.3） |
| B3 | 上行退出采集关键路径 | 采集侧只产出记录（spool 已兜底），发送交给独立 task + 有界 channel（评审 3.4）。**注意**：不要用 `timeout(2s)` 包住 sink 写，那会造半帧 |
| B4 | 自探拆槽 + watchdog | `pending_scan: Option<_>` 四域共用、后到覆盖先到，排最后的 Doris 恒赢；且 `scan_inflight` 没有 `started_at`、`log_stalled` 不覆盖扫描——卡死即所有域永久无法重扫且零日志（评审 3.5） |
| B5 | 采集 permit 不回收 | 8 个挂死的 Kafka / 主机作业就能让全部采集停摆，唯一信号是一行 warn（评审 3.6） |
| B6 | SQL 连接池 + 超时 | 每轮新建连接（无池）；会话 `SET` / `set_config` 无超时，两处可永不返回（评审 3.7 / 4.1） |
| B7 | `process_metrics_tick` 加超时 | 现在已不在主循环线程上，但**仍会拖住这一拍**：`ps` / 进程扫描卡死时 await 不返回。加 `tokio::time::timeout` + 超时后报一次 `RuntimeSnapshotLoad` 失败 |

### P2（性能细节 / 健壮性）

| # | 项 | 为什么 |
|---|---|---|
| B8 | 日志每文件 3~5 次 `open` | `file.rs:910/945/962/1043` + `checkpoint_support.rs:126`：512 文件 × 每秒 = 数千 syscall/tick |
| B9 | 追平循环每批重读 + fsync | `file.rs:652/706-711/1214`：每批 4 次 fsync，吞吐被 fsync 钉住 |
| B10 | spool 断点续传 | 现在「全量读 + 成功才删」，断网恢复时每拍整份重发 |
| B11 | 导出器按内容变化写 | `state/export/*.jsonl` 十几个 fsync / 拍 |
| B12 | 无界增长三处 | `inflight_investigations` 无上限；`pending_command_acks` 只在成功时清（对端长期不可达就堆）；`pending_work_state_changes` 失败**静默丢弃**（与 acks 口径不一致） |
| B13 | tick 的 `Err` 降级 | 主循环 `?` 会把一次 `ENOSPC` 变成进程退出 + 丢内存里的 grant |
| B14 | 自观测补三个量 | 每 tick 主循环耗时 / fsync 次数 / TLS 握手次数（详见第七节）；没这三个数，“优化有没有效”只能拍脑袋 |

### 已接受的取舍（不是待办，是“想过了，就这样”）

| 取舍 | 理由 |
|---|---|
| client 缓存 key 用**证书 mtime + 长度**，不用内容 hash | 判定“换没换”不该需要解析 X.509（那正是要省的成本）。代价：同一秒内、且长度不变的轮换会漏掉——证书轮换是罕见的人为事件，可用重启兼容 |
| 磁盘快照的 `generated_at` 表示「内容最后一次真变化」 | 上送用的是**内存**快照，时间戳天然新鲜；写进文件的那个只用于“这是个多旧的结论” |
| sink 写不套 `timeout(2s)` | 会取消在任意字节上 → 线上半帧 → 接收端把残行当记录 |
| keepalive 不设重试次数 | `with_retries` 在非 Linux 上被默默忽略；各平台默认值够用 |
| Doris 探针用户名写死 `wist-probe` | 已实测默认权限可用、不需要 GRANT；改成配置项没有需求驱动 |

## 附录：关键行号索引

| 主题 | 位置 |
|---|---|
| 主循环 | `src/runtime/daemon.rs:1834`（`run_forever_async`）、`:2008`（`loop`） |
| 状态上报 | `daemon.rs:461-569`（`report_status_to_control_plane`） |
| 命令队列 | `daemon.rs:1343`（`handle_command_queue`） |
| 采集调度 | `src/telemetry/metrics/scheduler.rs:163-164`（槽位）、`:1141-1210`（permit 贪心）、`:476-533`（`log_stalled`） |
| 指标 tick | `src/runtime/daemon_metrics.rs:150-191` |
| TCP sink | `src/telemetry/warp_parse.rs:249-302`（超时与退避）、`:356-388`（写） |
| HTTP client | `src/control/enrollment.rs:630-689` |
| spool | `src/telemetry/spool.rs:88-125`（回放）、`:175-182`（`.bad`） |
| 日志文件 | `src/telemetry/logs/files/file.rs:652, 706-711, 910-1043` |
