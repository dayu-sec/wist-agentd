# 一次性调查（`investigate`）

> 状态：已实现（`wist-agentd` 0.11.0-alpha）。代码：`src/investigate.rs`（题目无关的模型、
> 渲染与命令入口）、`src/investigate_disk.rs`（`disk` 题）。
>
> 关联：[`self-observability.md`](./self-observability.md)（`diagnose` 做什么）、
> [`../usage/README.md`](../usage/README.md) §2.7（日志吃满磁盘的现场处置）、
> **跨仓**：[`investigation-surfaces.md`](../../../../wist-design/doc/design/center/investigation-surfaces.md)
> （调查面的词表 / 三道闸 / 网关授权；本仓只实现执行侧）。

## 1. 要解决的问题

`diagnose` 回答的是「**agentd 自己**为什么不对」：配置、身份、服务、控制面连通、上送。
它的检查项是**固定**的，判定是红/绿。

现场还有另一类问句，`diagnose` 天然答不了：

> 「这台机器磁盘满了，**是哪几大文件、多大了**？」

这类问题的答案不是布尔值，而是**证据表**（路径 + 字节数 + 占比），而且题目随现场变
（磁盘、内存、连接、进程……）。所以它需要另一种工具：**一次性、按题目、给证据**。

三条边界是刻意的：

| | 常驻采集（`telemetry` / `metrics`） | 诊断（`diagnose`） | 调查（`investigate`） |
| --- | --- | --- | --- |
| 时机 | 周期性，3s tick | 一次性 | 一次性 |
| 范围 | 固定面，全量快照 | 固定检查项 | 按题目/参数，可窄可宽 |
| 输出 | 指标 / 事实 | 红绿检查 + 提示 | 证据表（路径 + 体量） |
| 谁来跑 | 守护进程 | 人 / 脚本 / AI | 人 / 脚本 / AI / **网关命令** |

调查**不替代**指标：指标告诉你「/ 96%」，调查告诉你「/var/lib/docker 里那 12 个容器层占了 60 GiB」。

## 2. 两条入口，一份实现

```
                       ┌──────────────────────────────┐
  wist-agentd          │                              │
  investigate disk ───►│  investigate::execute(req)   │──► Report { findings[] }
  --path /var          │        │                     │
  --top 10             │        ├─ investigate_disk::investigate
                       │        └─ investigate_load::investigate
  AgentCommand         │                              │
  kind="investigate" ─►│                              │
  params={...}         └──────────────────────────────┘
```

* **CLI**：`wist-agentd investigate [topic] [--path …] [--json]`，`execute` 在本地跑完直接打印。
* **网关命令**：搭在既有的**一次性命令**通道上（`AgentStatusAck.commands` → `AgentCommand`，
  结果随 `AgentStatusReport.command_acks` 回传，见 `wist-design` 的 `api-seam-inventory.md`）。
  执行完把完整报告落到 `state/investigations/<topic>.json`，ack 的 `detail` 里给结论摘要 + 报告路径。

两条入口共用 `investigate::execute`，所以**「人在机器上跑出来的」与「网关拿到的」不会两套口径**
（与 `diagnose` 复用守护进程判定同一条理由）。

`kind` 取 `"investigate"`（`investigate::COMMAND_KIND`）。这是一个**新 kind**，不是复用
`refresh_facts`：旧 agentd 会如实回 `unsupported` —— 调查本来就该在「这台机器还没升级」时明确
失败，而不是假装查过。等网关侧接上后，这个常量应挪进 `wist_api::status::command_kind`（词表的家）。

`params` 是 JSON 文本，宽容解析（与采集预检同一条理由：网关版本会错位）：

```json
{ "topic": "disk", "path": "/var", "top": 10, "min_size": 8388608, "depth": 16, "max_seconds": 5 }
```

| 字段 | 缺省 | 约束 |
| --- | --- | --- |
| `topic` | `disk` | 只认词表里的值（`disk` / `load`）；**不认识就 `failed`**（不猜题目去扫盘） |
| `path` | 由题目挑 | 必须是**绝对路径**（相对路径取决于进程 cwd，换一种启动方式就翻面） |
| `top` | 10 | 夹到 1..=50 |
| `min_size` | 0 | 字节数 |
| `depth` | 16 | 夹到 1..=64 |
| `max_seconds` | 5 | 夹到 1..=30 |

未知字段忽略、类型不对的字段忽略、空 `params` = 默认磁盘调查。

## 3. `disk` 题给出什么

七节，顺序即「先看结论 → 再定位根因 → 再确认是不是我们自己 → 再解释对不上的部分」：

| 节 id | 内容 | 判定 |
| --- | --- | --- |
| `disk.filesystems` | 每个本地文件系统的已用/总量/可用 + **inode** 占比 | 空间或 inode ≥85% → WARN，≥95% → FAIL |
| `disk.largest_dirs` | **递归累计**最大的目录（任意深度）+ **热点下钻链** + **没扫完的一级目录** | 证据（不加判定） |
| `disk.top_dirs` | 扫描根下**一级目录**的合计与占比（粗粒度对账）；总数取**枚举全量**，没扫完的行逐行标注 | 证据（不加判定） |
| `disk.top_files` | 最大的 N 个文件（路径 + 体量 + 占比） | 证据（不加判定） |
| `disk.agent_dirs` | agent 自己的落点（root/state/log/run）各多大 | ≥1 GiB → WARN，≥10 GiB → FAIL |
| `disk.unattributed` | `df` 已用 − 扫描合计的**差量**（快照/保留块/已删除仍打开） | 扫描完成且差量 ≥5% 且 ≥512 MiB → WARN |
| `disk.scan` | 扫了多少、是否被预算截断、哪些目录读不了 | 被截断或有不可读 → WARN |

几条判据的理由：

* **为什么先看目录而不是文件**：**最大的文件不一定是根因**。现场最常见的形态是一堆中小文件
  堆在一个深层目录里（容器层、会话目录、百万小文件写满 inode），单个文件都不大。所以这里用
  经典的两步：
  1. **自底向上累计**（`du` 的做法）：每个文件把字节加到它所有祖先目录上，得到每个目录的
     递归体量；硬链接按 inode 只算一次（否则容器层会凭空多出一倍）。
  2. **逐层下钻**（`du -h --max-depth=1 | sort -h | tail -1` 重复做）：从扫描根开始，每层选
     占父级 ≥60% 的子目录，直到不再集中 —— 得到一条**热点路径**，直接告诉你“到底哪一层
     在长”。同体量的祖先目录不进列表（它们不提供新信息）。
* **inode 单独算**：inode 用满时盘上还有空间，但**建不了新文件** —— 也是「磁盘 full」。
  只看容量百分比会漏掉，而处置完全不同（删大文件没用，要清**数量**大的小文件）。
* **失败阈值 95%**：到 95% 基本已经在掉功能（日志写不进、临时文件建不了、数据库可能停写）。
* **agent 自己单独一节**：这些主机上「盘是谁写满的」最常见的答案就是我们自己（日志没轮转、
  spool 积压）。不先把这一项摆出来，运维会去翻半天别的目录。
* **未归因单独一节**：`df` 说满、`du` 却找不出来是经典事故（文件删了但进程还开着、快照、
  文件系统保留块、或者数据在另一个挂载点）。Linux 下会顺带扫 `/proc/<pid>/fd` 里
  “已删除但仍打开”的文件并给出合计；不给这块钱，人会以为“工具坏了”。
* **扫描边界单独一节**：「没有大文件」与「没扫到」是两回事。不把 `truncated` / `unreadable`
  说出来，上面那张「最大的文件」表会被当成本机的全部真相 —— 这是现场最容易踩的坑。
* **预算怎么花，决定了报告可不可信**：先花极小的代价把扫描根的**一级子目录列全**（这层只有
  几十条），再让这些一级目录**轮流**花剩下的预算（每个一级目录各自持有一个可续游标，
  每轮最多 4096 条）。理由来自现场：一台 macOS 上 `/Applications` 有 14 万条，深度优先
  一路走到底会把 200k 条目上限吃干，同级的 `/Users`（真正占了 200 GiB、里面 `~/.Trash` 就有
  150 GiB）连名字都没进报告，`disk.top_dirs` 只写了「共 3 个一级目录」——看起来像扫全了，
  实际上答案根本不在表里。轮流分配之后：
  * `disk.top_dirs` 的一级目录总数**总是完整的**；
  * 没扫完的目录**逐行标注**（`没扫完，实际更大`）并汇总到 `incomplete_dirs`；
  * 每条「没扫完」都配一条可直接复制的重扫命令（`--path <目录>`）。

  「没扫完」不是免责声明，而是**下一步该跑什么**：报告必须能自己指向下一条命令。
* **“没出现”有三种，不能混成一种**（同一个错误的三个变体）：
  * **没扫完**（预算不够）→ `incomplete_dirs`，处置 = 重扫 `--path`；
  * **读不了**（权限，如 macOS 的 `.Spotlight-V100`、`.DocumentRevisions-V100`）→
    `unreadable_dirs`，处置 = 以 root 重跑；它们在表里占一行且显式写 `—`（不是 `0 B`），
    因为“真的空”与“没看见”是两件事；
  * **深度到顶**（`--depth` 上限）→ `depth_limited` 计数，处置 = 加大 `--depth`；
    它不让状态变成 WARN（否则每台机器都永远 WARN），但 `disk.scan` 的标题会写成
    「扫描完成（部分目录深度到顶）」，正文明说数字是下界。

扫描根的选择：显式 `--path` 优先；否则取**占用率最高**的文件系统挂载点。理由：盘满的现场常常
是数据盘（`/data`、`/var/lib/docker` 单独挂）先报警，扫 `/` 只会在系统盘上浪费时间。

## 4. `load` 题给出什么

「负载 80」只是一条**排队长度**：同样 80，可能是 16 核跑满，也可能 CPU 闲着而一堆进程卡在磁盘上。
所以本题把「先分流 → 再点名」固定下来，八节：

| 节 id | 内容 | 判定 |
| --- | --- | --- |
| `load.summary` | 1/5/15 分钟负载 + 核数 + **每核负载** + 运行队列 / CPU 压力（Linux） | 每核 ≥ 1.0 → WARN，≥ 2.0 → FAIL |
| `load.cpu` | 总体与**每核**占用；Linux 还给 user/system/iowait/idle 去向 | 总体 ≥85% → WARN、≥95% → FAIL；**单个核打满也是 WARN**（单线程瓶颈） |
| `load.top_services` | 按**服务**聚合的 CPU/RSS（cgroup 归属 + 累加） | 服务 ≥1 核 → WARN，≥3 核 → FAIL |
| `load.top_processes` | 按 CPU 排的进程（pid + 名称 + RSS + 状态 + 运行时长） | 证据（不加判定） |
| `load.memory` | 物理内存与 swap | 内存 ≥85% → WARN、≥95% → FAIL；swap ≥50% → WARN |
| `load.io` | iowait / PSI io 压力 / **不可中断睡眠（D）进程数** | iowait ≥20% 或 D 状态 ≥3 且负载 > 核数 → WARN |
| `load.agent_processes` | agent 自己（agentd/exec/upgrader）的 CPU 与 RSS | CPU ≥1 核 → WARN、≥3 核 → FAIL；RSS ≥1 GiB → WARN、≥4 GiB → FAIL |
| `load.sample` | 采样窗口、进程数、平台能力（cgroup/iowait/PSI） | 进程数为 0 或窗口 < 300ms → WARN |

几条判据的理由：

* **为什么判据是每核负载**：负载不分平台都只是 runnable + uninterruptible 的**数量**，
  拿它跟核数比才有意义。`load 8` 在 32 核上是闲的，在 4 核上已经过载。
* **为什么必须有一节是「服务」**：磁盘题的教训是「最大的文件不是根因，目录才是」；CPU 一模一样 ——
  nginx/gunicorn/JVM/容器里的服务都是**多进程多 worker**，每个子进程单看都不大（8 个 worker × 12%
  在进程榜里一个都不显眼），加起来才是一个核。只给进程榜，现场会得出“没人忙”的错误结论。
* **服务归属从哪来**：Linux 读 `/proc/<pid>/cgroup` —— `system.slice/xxx.service`、
  `docker-<id>.scope`、`kubepods…/pod<uid>`，这才是“服务”的权威身份（进程名会重名，容器里处处是 `java`）。
  其它平台只能按**可执行名**聚合，渲染层会明说「同一服务的多个可执行文件可能被拆开」——
  不把局限写出来，那张表会被当成完整答案。
* **精确累计**：Linux 读 cgroup 的 `cpu.stat`（`usage_usec`）两次差值，得到**不依赖进程采样**的
  每服务 CPU；它包含「窗口内起落、采样时已经没了」的进程，这种服务在表里会出现（`进程数 = 0`，
  备注写「窗口内已退出」）。读不到（权限/非 Linux）就退回“进程采样加总”，并在正文标注。
* **为什么单列「不可中断睡眠」**：**负载高但 CPU 空闲**的头号原因是进程卡在磁盘/网络存储上
  （`D` 状态：杀不掉、也不吃 CPU）。只看 CPU 排行会得出“没有谁在忙”，然后去扩容 CPU —— 那不是根因。
  本节的 hint 会把下一步指向 `investigate disk`（是谁在写）而不是 CPU 扩容。
* **为什么单个核打满也要报**：总占用 20% 而某线程 100%，是“负载不高但服务慢”最常见的形态；
  判定放 WARN 而不是 FAIL（机器还活着），hint 直接点「单线程瓶颈、加核没用」。
* **为什么采样必须说窗口**：CPU% 是**两次刷新之间的增量**（sysinfo 需要 ≥200ms）。
  窗口 1s～3s（`--max-seconds` 可拉长到 3s）：1s 里周期性批处理/GC 的尖峰经常刚好躲过，
  多等 2s 是值得的。报告里写明 `window=…ms elapsed=…ms`；窗口异常短时本节判 WARN。
* **分母是“真实经过时间”，不是“想等多久”**：机器越忙 `sleep` 越容易超时，
  而那种机器恰好就是调查对象。用 `window` 当分母会把每个服务的 CPU 都算高，
  且是**同时抬高所有行**——看起来像“整机负载高”，实际只是分母错了。所以计时从基准读完开始，
  取 `Instant::elapsed()`；`window` 只用于报告和对账。
* **`/proc/stat` 只加前 8 项**：`guest` / `guest_nice` 已经含在 `user` / `nice` 里，
  再加一遍会让分母虚高、`load.cpu` 的时间去向全部偏低（跑虚拟机的机器上尤其明显）。
* **为什么 swap 要单独说**：swap 在用 = 已经在换页，延迟会抖、OOM killer 随时可能动手；
  而 macOS 的 swap 是动态的，`sysinfo` 常报 0 —— 这时只能写「读不到」，不能写「未启用」（那是没证据的断言）。
* **为什么先排除 agent 自己**：调查/采集本身也吃 CPU；不先把这一项摆出来，运维会去翻半天别的进程。

**脱敏**：`argv` 里经常有数据库密码、令牌、证书路径，所以报告**只给进程名**，
需要看完整命令行时由人对着 pid 自己 `ps`（hint 里给确切命令）。这条与
[`investigation-surfaces.md`](../../../../wist-design/doc/design/center/investigation-surfaces.md) §2.2 一致。

## 5. 扫描必须有界（三条「不」+ 三重上限）

调查是**在生产机上**跑的，不能变成新的故障源：

1. **不跟随符号链接**（`symlink_metadata`）：`/var/lib/docker/...` 里链接成环是常态，跟进去就是
   无限循环；链接本身也不计体量（目标可能不在本机）。
2. **不跨文件系统**：用 `st_dev` 判定。扫 `/` 时不能把 `/data`、`/proc`、`/sys`、网络盘一起算进来
   —— 既慢又错（「谁占了 **这个** 盘」才是问题）。跳过的条目数在 `disk.scan` 里如实报。
3. **三重上限**：条目 3M / 时长 `max_seconds`（默认 120s，上限 300s）/ 深度 `depth`（默认 16）。
   任一触顶 → `truncated=true`（深度到顶只记 `depth_limited`，见 §3），
   并把「扫描未完成，可能还漏了更大的」写进正文，**不猜**。
   触顶时预算按**一级目录轮流**分配（而非深度优先吃到底），并把没扫完的目录点名 ——
   见 §3「预算怎么花」。

   > 为什么条目上限从 200k 提到 3M：旧值在 5.9s 就撞上了，`--max-seconds` 再大也**无效**
   > （现场那台 macOS 的 `/Users` 有 200 万条，最大的目录永远扫不到）。条目上限改由
   > “目录 arena + 目录数封顶”来保证内存，而不是把条目数钉死：
   > 旧实现每个目录要 3~4 份完整路径（实测 ~1.4 KB/目录，200k 条就吃掉 66 MB），
   > 现在只存一份路径 + id 互指（~100B/目录，同样 200k 条只用 28 MB）。
   >
   > 默认预算从 5s 提到 **120s** 也是同一个原因：调查是**一次性、只读、人工触发**的，
   > 而真实机器的“哪个目录最大”就是需要一分多钟；扫完会提前结束，小盘上依旧毫秒级。

4. **体量口径 = 盘上实际占用**（`st_blocks * 512`），**不是** `len()`。
   稀疏文件（VM 磁盘镜像、容器层、数据库预分配文件）的 `len()` 可能是实际占用的几十倍：
   现场实测一个 OrbStack 镜像 `len()` = **927 GiB**、实际只占 **63 GiB** —— 用 `len()` 会让报告
   凭空多出 800 多 GiB（**超过整盘容量**），并把真正的元凶（104 GiB 的源码目录）挤出榜单。
   这也是 `du` 的口径：盘满了看的是“占了多少盘”。

另外：

* 同步目录遍历放在 `spawn_blocking` 里跑 —— 守护进程跑在单线程 tokio 运行时上，遍历留在
  async 线程里会把 3s 的状态上报一起拖住。所以「网关下发一次调查」最多晚一个 tick，而不是卡死守护循环。
* agent 落点那节每个目录单独给 **1s** 预算：它只是「顺带排除自己」，不该抢走主扫描预算；
  超了标「至少这么多（遍历未完成）」。
* 互相包含的目录（开发机布局里 `root` 包着 `state`/`log`）会合并成一行并标出角色，
  避免同一批字节算两遍。

## 6. 输出契约

**文本**（默认，TTY 上色）：与 `diagnose` 同一版式 —— `[OK]/[WARN]/[FAIL]` + 标题 + 正文 +
缩进的证据行 + `→` 提示 + 最后一行 `结论:`。`NO_COLOR` / 重定向 → 纯文本。

**JSON**（`--json`，与落盘报告同一份）：

```json
{
  "command": "investigate",
  "topic": "disk",
  "report_schema": "wist.investigation.disk/v1",
  "version": "0.18.0",
  "observed_at": "2026-10-30T09:50:33Z",
  "boot_id": "0f5d1f2e-9c4a-4a55-9b1e-6d2c3f7a8b10",
  "boot_time": "2026-10-28T03:12:41Z",
  "judged": true,
  "findings": [
    {
      "id": "disk.filesystems",
      "status": "fail",
      "title": "磁盘即将写满",
      "detail": "本机 2 个本地文件系统；最紧张的是 /data（96.8% 已用）",
      "hint": "…",
      "rows": [{ "label": "/data", "value": "96.8% 已用", "note": "…" }]
    }
  ],
  "summary": { "ok": 2, "warn": 1, "fail": 1, "unknown": 0, "overall": "fail" },
  "verdict": "2 项正常 / 1 项警告 / 1 项失败；首要问题：磁盘即将写满"
}
```

`finding.id` 是**稳定标识**，脚本/AI 按 id 取用；`rows` 是证据（`label` 路径、`value` 体量、
`note` 占比/设备/inode）；`report_schema` 是**带版本的契约 id**，网关按它选渲染/落库规则。
`boot_id` / `boot_time` 是**时间线锚点**：报告要与采集流拼到同一次开机上（见 §11.4），
读不到时省略。

**退出码**：有 FAIL → 1，其余 0（与 `diagnose` 同一条门禁语义）。

### 6.1 命令回传：ack 走控制面，报告走数据面

网关下发的一次性调查有**两条回程**，刻意分工：

| | 通道 | 内容 | 干什么 |
| --- | --- | --- | --- |
| ack | 控制面（`AgentStatusReport.command_acks`） | ≤600 字结论 + 报告去哪了 | 告诉管理面「查清了 / 没查成」 |
| 报告 | **数据面**（` IVSREP: ` 帧） | 完整证据（带 `command_id`） | 落库、回看、进 Atlas |

为什么报告不塞进 ack：状态上报是 3s 一次的控制报文，塞一张表会把整条控制面撑成批量通道；
而**数据面本来就有一条通道**（`LOGREC` / `METRICS` / `OBSFACT` / `DSNAP` 同一批帧），
它就是为「agent → 平台的结构化记录」建的。

帧形状（与事实/快照帧同构）：

```
{"schema":"v1","agent":"<agent_id>","ts":"<RFC3339>","seq":<n>} IVSREP: <Report JSON + command_id>
```

几条规矩：

* **`command_id` 是唯一关联键**：报告与 ack 走两条路，网关靠它 join（迟到/乱序都要容忍）。
* **闸跟事实帧一致**：只有 `kind = tcp` 能承载；**待命（`enabled = false`）也发** —— 调查是诊断
  元数据，不是主机内容。`kind = file` 时静默跳过，ack 里写「报告只在本机」。
* **`seq` 与日志/指标/事实共用一个空间**（`(agent, seq)` 是数据面的去重键）。先落高水位再发。
* **单帧有上限**（`MAX_UPLINK_BODY_BYTES` = 64 KiB），超了**逐级退化**：
  ① 去掉 `rows` 并标 `rows_omitted`；② 再去 `hint`、把 `detail` 截到 240 字（`title`/`status`/`verdict`
  始终保留 —— 那是结论本身）。**绝不发半条 JSON**（行分帧下截断的 JSON 会被当成丢失的记录）。
* **不重试、不进 spool**：报告是**一次提问的证据**，压在 spool 里过一会儿再送到没有意义；
  发失败就把原因写进 ack，人可以直接看本机那份。
* **回传失败不改变 outcome**：调查做成了就是 `succeeded`，通道问题单独写在 `detail`。

ack 的 `detail` 三句：`<结论摘要>` + `报告已回传（IVSREP，seq=n）| 无数据面上送通道…| 报告回传失败：…`
+ `完整报告：<path>`，整体截到 900 字（结论段本身再按 600 字截 —— ack 是状态上报里的短文本）。

完整报告另落 `state/investigations/<topic>.json`（**每个题目只留最新一份**，不会长）
—— 盘满时中心可能收不到帧，运维 SSH 上来还能读到它。**落盘失败不当作失败**：盘满正是要查的时候，
报告还在内存里，能回传就够了。

### 6.2 出口脱敏（策略即代码）

报告会进数据面 sink（可再分发到 Atlas / 外部），所以**掩码在 agentd 做**，不指望网关或前端事后清洗。
规则不是散在代码里，而是一份可评审、可校验的策略：

| 落点 | 作用 |
| --- | --- |
| `investigation/redaction-policy.toml` | 单一事实来源：字段白名单 + “永不回传”值规则（私钥、口令哈希、连接串口令、云/平台 token、`authorized_keys` 正文） |
| `src/investigate_safety.rs` | 编译并执行策略：`Row::new` / `Finding::new` 产出时脱敏，`Report::to_json` 整体兜底；`scan()` 检查结构（字段白名单 / 题目登记 / `finding.id` 前缀） |
| `tests/investigation_redaction_policy.rs` | CI 闸门：样本必须被声明的规则命中、普通证据不得误伤、真实形状的报告必须零违规 |

两条规矩：

* **整值替换**为 `[redacted:<rule>]`，不做部分打码（半个 token 也是 token），并保留命中的规则名；
* **具体规则在前、泛化规则在后**（`cred.env_assignment` 放最后，否则 `aws_secret_access_key = …` 会被它抢先命中）。

新题必须做两件事（缺一不可）：在策略里登记 `<topic>.` 前缀；往 `tests/fixtures/investigation/` 加一份该题的
`good-report-*.json`。前者保证“加题时有人看过输出”，后者保证“结构白名单不会误伤正常报告”。

策略是 `include_str!` 内嵌的，改完必须重新编译；CI 里有一条用例专门比对内嵌副本与仓库文件是否一致。

## 7. 怎么加一道新题目

1. 在 `investigate::TOPICS` 加常量（如 `mem`），在 `execute` 的 `match` 里加分支；
2. 新文件 `src/investigate_<topic>.rs`，导出
   `fn investigate(&InvestigateRequest, Option<&AgentConfig>) -> Result<Vec<Finding>, String>`；
3. 复用 `Finding::ok/warn/fail`（`id` 用 `<topic>.<section>`）与 `Row`；
4. 新的 `params` 字段加进 `InvestigateRequest::from_params`（宽容解析 + 夹紧）；
5. 在 `investigation/redaction-policy.toml` 的 `[topics]` 登记 `<topic>.` 前缀，并加一份
   `tests/fixtures/investigation/good-report-<topic>.json`（见 §6.2）。

**只加一行代码不算加完** —— 题目是**跨仓的词表**，漏一处现场就是“页面上看不见”或“一下发就失败”：

* `wist-gateway/src/api/investigations.rs` 的 `TOPICS`（网关自己的词表，不共用 agentd 的常量）；
* `wist-gateway-web` 里两处 `TOPICS` 与题目文案（授权页、调查页）；
* `wist-design` 的 `investigation-surfaces.md` §5 清单（敏感度/成本/特权）；
* 本仓 `investigation/redaction-policy.toml` 的 `[topics]` 与 `tests/fixtures/investigation/`（§6.2）；
* 本仓 README 与 `docs/usage/agentd-install-and-usage.md` 的用法示例。

**不要把题目做成通用命令执行器**：调查是**只读**的。需要改机器时走 `ActionPlan`（`wist-exec`）。

## 8. 升级与兼容

* **agentd 侧**：新命令 kind 加性与只读；不开 `managed` 也能用 CLI（`standalone` 下同样可用，
  因为它不依赖采集链路）。
* **网关侧**：需要能下发 `kind="investigate"`（回执里的 `commands[]` 是开放字符串，报文形状不用改）。
  在网关支持之前，这个能力只能在本机用 CLI 触发。
* **数据面也要认这个帧**：` IVSREP: ` 需要 `wp-rules` 的 WPL/OML 与 sink 分组（`business.d/agent_ivsrep.toml`）
  就位。没就位时记录**不会静默丢失**，而是落进兑底 sink `gateway-logs` —— 位置错了，能看见。
  在这之前，ack 摘要与本机报告仍然可用。
* **旧 agentd** 收到 `investigate` 会回 `unsupported` 并写明「尚未实现」，不会静默。

### 8.1 调查面与授权（跨仓，本仓只负责“能跑”与“跑得安全”）

“哪些题允许在**哪台机器**上跑”不是本仓说了算 —— 它是一道独立的授权轴，设计在
[`investigation-surfaces.md`](../../../../wist-design/doc/design/center/investigation-surfaces.md)。
本仓承担其中两条硬约束：

* **只读**：调查面永远不改机器（要改走 `ActionPlan` / `wist-exec`）；
* **有界**：每个题必须声明预算，超限如实标 `truncated`，不接受网关“放宽预算”的参数。

以及一条向网关提供的声明：

* **上报能力**：状态上报里的 `investigation_capabilities`（`{surfaces, privileged}`）**从实现处取**
  ——`surfaces` 就是 `TOPICS`、`privileged` 就是 `geteuid() == 0`，不另写一份名单（否则新增一道题
  时上报与实现会静默漂移，网关会把新题当成“这台机器不会”）。
* 网关侧对应地：**入队前**校验能力（不认识回 `409 investigation_unsupported`），并把
  `requested_by`（`admin:<token 指纹>`）写进命令台账 —— 调查读的是客户机上的路径/文件名，
  一次按需读取必须能回答“这是谁点的”。
  另两道网关侧闸（与能力闸正交、都在入队前）：**按面授权** `[investigations] allowed_topics`
  （被关掉的面回 `403 investigation_not_allowed`）与**配额** `max_per_agent_per_hour`
  （超了回 `429 investigation_quota_exceeded`）；报告的可见保留期是 `report_retention_days`
  （只过滤、不删文件）。本仓**不**参与这三件事：agentd 只保证“能跑、有界”，
  机器上能读什么、能读几次是控制面的策略。

## 9. 没做（留给后续）

* 其余题目（内存 / 连接 / 进程 / 日志增长速率）。
* 调查**历史**（只留最新一份；要对比「昨天 vs 今天」得另做归档）。
* 网关侧的展示与「从这里一键派调查」入口（本设计只覆盖 agentd）。
* 大目录的增量扫描（现在是每次从头遍历；对「刚才查过」的场景没有缓存）。

## 10. 安全向三题（`accounts` / `persistence` / `exposure`）

先只做 Linux：三题都要读 `/etc`、`/proc`、`/etc/systemd`；macOS 的用户库（DirectoryService）、
launchd 域与 `netstat` 走的是另一套“只读查询命令白名单”，不在这版里假装支持。
`capabilities()` 因此**按平台过滤**：macOS 上只报 `disk` / `load`，不会把答不了的题报上去。

### 10.1 为什么是这三题

它们回答的是**属性**（一次枚举就是全集），不是**行为**（要连续观测才准）。
出站流量因此明确**不做**：`NetworkFlow` 那类数据源在观测层就有结构性缺口
（短连接、`NOTRACK`、offload、netns），放进采集面会用“零丢失”的措辞包装一份残缺数据。

| 题 | 一句话 | 主要来源 |
| --- | --- | --- |
| `accounts` | 谁能在本机登录、谁能提权 | `/etc/passwd`、`/etc/shadow`、`/etc/sudoers{,.d}`、`~/.ssh/authorized_keys`、`sshd_config`（含 `Include`） |
| `persistence` | 重启后还有什么会自己跑 | `/etc/systemd/system/*.wants`、cron/at、`ld.so.preload`、`rc.local`、`profile.d` |
| `exposure` | 谁在听、绑在哪 | `/proc/net/{tcp,tcp6,udp,udp6}` + `/proc/<pid>/fd` |

### 10.2 三条契约（跨题，且对所有题成立）

| 字段 | 作用 | 为什么不能省 |
| --- | --- | --- |
| `Status::Unknown` | 整节“无法判定” | 非 root 读不到 `/etc/shadow` 时，显示 `OK` 等于说“这台机器很安全”——安全题的假阴性 |
| `finding.coverage` | `checked` / `denied` / `skipped` | 让“端口可见但属主不可见”这种**半可见**能被表达出来 |
| `report.judged` | 这一题做不做安全判定 | `exposure` 只列事实；若不标 `false`，`verdict` 会输出“全部正常” |
| `report.limits` | 能力边界（人话，各节并集） | 前端不能把“只快照 / 未覆盖容器 netns”渲染成结论 |

`unknown` **不让退出码变非零**（缺权限不该把 CI 变红），它只影响 verdict 与页面。
`overall` 的优先级：`Fail > Warn > Unknown > Ok`。

### 10.3 各题节与判定

**`accounts`**：`uids`（uid 0 别名 → FAIL；系统账号带登录 shell → WARN）、
`passwords`（空口令且可登录 → FAIL；只分类 `none/locked/set`，**哈希永不回传**）、
`sudoers`（非 root 的 `NOPASSWD: ALL` → WARN；别名不展开要写进 limits）、
`keys`（符号链接 / 近 7 天新增 → WARN；只给类型与条数）、
`ssh`（`PermitEmptyPasswords yes` → FAIL；`PermitRootLogin yes` → WARN）。

`sshd_config` 按 sshd_config(5) 的**首个取值生效**求值，`Include` 在原位置展开，`Match` 之后不求值。
这一点极容易写反（大多数配置是后者覆盖），代码与单测都钉住了它。

**`persistence`**：`units`（本地/非包管理单元优先列；enable 状态 = `.wants` 符号链接，
不调 `systemctl`）、`scheduled`（cron/at；只报程序与是否“下载并执行”）、
`hooks`（`ld.so.preload` 非空 → FAIL）、`recent`（近 7 天新增汇总）。

**`exposure`**：`listeners`（`bind_scope` 分 `all` / `specific` / `loopback`）。
它是 `EVIDENCE_ONLY_TOPICS` 里唯一的题：`0.0.0.0` 是好是坏取决于拓扑与漏洞，主机答不了。

### 10.4 只读与预算

* 不 exec：不跑 `systemctl` / `sshd -T` / `ss` / `netstat` / `dscl`；不碰网络；不写盘。
* 单文件读上限（`authorized_keys` 1 MiB / 200 条）、`Include` 递归深度、
  `/proc/<pid>/fd` 扫描 20 万条上限。
* 出口仍走 §6.2 的脱敏策略；三题都已在 `investigation/redaction-policy.toml` 登记，
  并各有一份 `tests/fixtures/investigation/good-report-*.json`。
* 真机验收：`sudo dev/verify-investigate-security.sh`（root + non-root 两轮；
  macOS 上可用 OrbStack 的 Docker 跑，命令见 README）。它验单测证明不了的三件事：
  “非 root → `unknown` 而不是 `ok`”、`ld.so.preload` 真的会 FAIL、报告里搜不到 `$6$`。

## 11. 遥测健康（`telemetry-health`）：我们瞎了多久

前面几题回答“这台机器有什么”，这一题回答“**我们的眼睛还在不在**”。
`accounts` / `persistence` 在最坏的情况下也照样能给出漂亮报告 —— 越漂亮越危险，
因为它掩盖了“这 6 小时一条日志都没采到”。

两平台都实现（判据全部来自 agentd 自己的状态文件，不依赖 `/proc` 或系统命令）。

### 11.1 三节

| 节 | 证据 | 判定 |
| --- | --- | --- |
| `telemetry.sources` | 每个配置输入：源路径在不在、有没有 checkpoint、最近一次**提交**多久前、积压未读字节 | 静默 ≥ 15 分钟 → WARN；≥ 24 小时 → FAIL；无 checkpoint / 读不到 → UNKNOWN |
| `telemetry.backlog` | 每个输入的 spool 文件大小与最后写入时间 | 有积压 → WARN；到 `spool_max_bytes` → FAIL（运行时会把该输入 `pause`） |
| `telemetry.pipeline` | 输出闸门（`[telemetry.logs.output] enabled/kind`）、全局 `seq` 高水位（`state/logs/seq.json`）的写入时间 | 输出关闭 → WARN；从未产出 → UNKNOWN |

为什么静默分两档：15 分钟是“该看一眼”，24 小时是“这个源基本不会再有数据了”。
只有一档阈值时，要么天天误报（低流量源），要么在真正的停摆上保持沉默。

### 11.2 数据来源与口径

* checkpoint：`state/logs/file_inputs/<input_id>/checkpoints.json`，取 `files[].last_commit_point_at`
  的最大值。**宽容解析**（只认用到的字段）：真实结构体是 `deny_unknown_fields`，
  但调查工具不该因为状态里多了一个键就整节失效。
* spool：与采集器**同一个函数**算路径（`daemon_telemetry::spool_path_for`），
  调查按另一套路径去猜，只会得到“报告说没积压、采集其实在 pause”。
* `seq.json` 只在确实处理过记录时推进（`ran_any`），所以它的写入时间≈“最后一次见到任何记录”。
* 只对**字面路径**做存在性检查；glob / 目录按 `is_family_target` 交给 checkpoint 判断，不展开匹配。

### 11.3 不做什么

* 不读日志正文：只看 checkpoint / spool / seq 的元数据。
* checkpoint 单文件读取上限 16 MiB：超过就明确报 `unknown`，不把内存吃光（JSON 要整份解析，“读一半”没意义）。
* 不 exec、不连网络、不写盘；控制面连通性仍归 `diagnose`。
* “静默”不等于“采集坏了”：报告给的是**时长**，结论仍需结合业务（低流量源本来就安静）。
* 不是证据型题目：`judged = true`。静默是采集面的故障，不是“好坏取决于拓扑”的事实。

已在 `investigation/redaction-policy.toml` 登记（`[topics."telemetry-health"] id_prefixes = ["telemetry."]`），
样本：`tests/fixtures/investigation/good-report-telemetry.json`。

### 11.4 报告头的时间线锚点

`to_json` / 数据面 `IVSREP` 正文多了两个字段：

| 字段 | 来源 | 为什么 |
| --- | --- | --- |
| `boot_id` | Linux `/proc/sys/kernel/random/boot_id`；其它平台省略 | 报告要和采集流拼**同一次开机**的时间线：重启前的事件不该和重启后的报告混在一起 |
| `boot_time` | `sysinfo::System::boot_time()` | 只有 `observed_at` 时，时钟被改过就再也对不上 |

两者都可能缺失（非 Linux / 读不到）—— 缺失时如实省略，不编一个数。
