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
  --top 10             │        └─ investigate_disk::investigate
                       │                              │
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
| `topic` | `disk` | 只认词表里的值；**不认识就 `failed`**（不猜题目去扫盘） |
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

## 4. 扫描必须有界（三条「不」+ 三重上限）

调查是**在生产机上**跑的，不能变成新的故障源：

1. **不跟随符号链接**（`symlink_metadata`）：`/var/lib/docker/...` 里链接成环是常态，跟进去就是
   无限循环；链接本身也不计体量（目标可能不在本机）。
2. **不跨文件系统**：用 `st_dev` 判定。扫 `/` 时不能把 `/data`、`/proc`、`/sys`、网络盘一起算进来
   —— 既慢又错（「谁占了 **这个** 盘」才是问题）。跳过的条目数在 `disk.scan` 里如实报。
3. **三重上限**：条目 200k / 时长 `max_seconds`（默认 5s，上限 30s）/ 深度 `depth`（默认 16）。
   任一触顶 → `truncated=true`（深度到顶只记 `depth_limited`，见 §3），
   并把「扫描未完成，可能还漏了更大的」写进正文，**不猜**。
   触顶时预算按**一级目录轮流**分配（而非深度优先吃到底），并把没扫完的目录点名 ——
   见 §3「预算怎么花」。实测：macOS 扫 `/System/Volumes/Data`（910 GiB 已用）默认参数下
   只能归因 ~83 GiB，但报告会明确说 `/Users`、`/private` 没扫完（另外 3 个系统目录读不了），
   并给出各自的 `--path` 重扫命令；按提示单独扫 `/Users`（30s）即可看到 `~/.Trash` 占 151.9 GiB。

另外：

* 同步目录遍历放在 `spawn_blocking` 里跑 —— 守护进程跑在单线程 tokio 运行时上，遍历留在
  async 线程里会把 3s 的状态上报一起拖住。所以「网关下发一次调查」最多晚一个 tick，而不是卡死守护循环。
* agent 落点那节每个目录单独给 **1s** 预算：它只是「顺带排除自己」，不该抢走主扫描预算；
  超了标「至少这么多（遍历未完成）」。
* 互相包含的目录（开发机布局里 `root` 包着 `state`/`log`）会合并成一行并标出角色，
  避免同一批字节算两遍。

## 5. 输出契约

**文本**（默认，TTY 上色）：与 `diagnose` 同一版式 —— `[OK]/[WARN]/[FAIL]` + 标题 + 正文 +
缩进的证据行 + `→` 提示 + 最后一行 `结论:`。`NO_COLOR` / 重定向 → 纯文本。

**JSON**（`--json`，与落盘报告同一份）：

```json
{
  "command": "investigate",
  "topic": "disk",
  "report_schema": "wist.investigation.disk/v1",
  "version": "0.11.0-alpha",
  "observed_at": "2026-10-30T09:50:33Z",
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
  "summary": { "ok": 2, "warn": 1, "fail": 1, "overall": "fail" },
  "verdict": "2 项正常 / 1 项警告 / 1 项失败；首要问题：磁盘即将写满"
}
```

`finding.id` 是**稳定标识**，脚本/AI 按 id 取用；`rows` 是证据（`label` 路径、`value` 体量、
`note` 占比/设备/inode）；`report_schema` 是**带版本的契约 id**，网关按它选渲染/落库规则。

**退出码**：有 FAIL → 1，其余 0（与 `diagnose` 同一条门禁语义）。

### 5.1 命令回传：ack 走控制面，报告走数据面

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

## 6. 怎么加一道新题目

1. 在 `investigate::TOPICS` 加常量（如 `mem`），在 `execute` 的 `match` 里加分支；
2. 新文件 `src/investigate_<topic>.rs`，导出
   `fn investigate(&InvestigateRequest, Option<&AgentConfig>) -> Result<Vec<Finding>, String>`；
3. 复用 `Finding::ok/warn/fail`（`id` 用 `<topic>.<section>`）与 `Row`；
4. 新的 `params` 字段加进 `InvestigateRequest::from_params`（宽容解析 + 夹紧）。

**不要把题目做成通用命令执行器**：调查是**只读**的。需要改机器时走 `ActionPlan`（`wist-exec`）。

## 7. 升级与兼容

* **agentd 侧**：新命令 kind 加性与只读；不开 `managed` 也能用 CLI（`standalone` 下同样可用，
  因为它不依赖采集链路）。
* **网关侧**：需要能下发 `kind="investigate"`（回执里的 `commands[]` 是开放字符串，报文形状不用改）。
  在网关支持之前，这个能力只能在本机用 CLI 触发。
* **数据面也要认这个帧**：` IVSREP: ` 需要 `wp-rules` 的 WPL/OML 与 sink 分组（`business.d/agent_ivsrep.toml`）
  就位。没就位时记录**不会静默丢失**，而是落进兑底 sink `gateway-logs` —— 位置错了，能看见。
  在这之前，ack 摘要与本机报告仍然可用。
* **旧 agentd** 收到 `investigate` 会回 `unsupported` 并写明「尚未实现」，不会静默。

### 7.1 调查面与授权（跨仓，本仓只负责“能跑”与“跑得安全”）

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

## 8. 没做（留给后续）

* 其余题目（内存/连接/进程/日志增长速率）。
* 调查**历史**（只留最新一份；要对比「昨天 vs 今天」得另做归档）。
* 网关侧的展示与「从这里一键派调查」入口（本设计只覆盖 agentd）。
* 大目录的增量扫描（现在是每次从头遍历；对「刚才查过」的场景没有缓存）。
