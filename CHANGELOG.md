# 更新日志

本文件记录 `wist-agentd` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

## [0.13.1-alpha] - 2026-10-31

### 修复（“没出现”有三种，不能混成一种）

对 0.13.0 的实现做了 5 轮 review，找到同一类错误的另外两个变体 —— 都是「目录不出现 → 被当成它不存在」：

- **整目录读不了的一级目录不再消失**（权限，如 macOS 的 `.Spotlight-V100` /
  `.DocumentRevisions-V100` / `.fseventsd`）：以前它们不贡献字节，就从 `disk.top_dirs` 里整条
  不见了，看起来像“本机只有这几个目录”。现在：
  - 新增 `unreadable_dirs`（整个目录打不开的一级目录），`disk.top_dirs` 里给它们补一行，
    值写 `—`（**不是 `0 B`**），备注「读不了（需要 root），这里不是 0」；
  - `disk.largest_dirs` / `disk.top_dirs` / `disk.unattributed` 的正文会写
    「**N 个一级目录读不了**（…）—— 它们一个字节也没计入，需 root」；
  - `disk.scan` 的正文多一项 `unreadable_top_dirs=N`，hint 点名具体目录。
- **`--depth` 到顶不再静默**：深度到顶的目录里的内容**不会被计入**，但以前 `truncated=false`，
  那些数字会被当成完整值。现在计数器 `depth_limited`：`disk.scan` 正文多一项
  `depth_limited=N`，标题写成「扫描完成（部分目录深度到顶）」，hint 说明
  「体量/占比都是下界，要更全就把 `--depth` 加大」。
  （不把状态刷成 WARN：默认 `depth=16` 几乎每台机器都有到顶目录，那会让 WARN 变成噪声。）
- **“读不了”不再说成“没有”**：扫描根读不了、或目录全读不了时，`disk.top_dirs` /
  `disk.largest_dirs` 的标题从「没有子目录（只有文件）」改成「读不了（权限）」，正文引导 `sudo`。
- 「没扫完」的文案统一为「表里是已扫到的下界，实际更大」（原文案“它们实际只会更大”缺主语）。

### 测试（+9）

`src/investigate_disk.rs`：

- `resuming_a_cursor_never_counts_a_file_twice`：预算被切成 5+ 片时，字节数必须等于
  `文件数 × 单文件大小`（守住可续游标不重读）；
- `a_scan_with_enough_budget_reports_nothing_unfinished`：反例守卫，别让「没扫完」变成常驻噪音；
- `walk_counts_directories_it_stopped_descending_at_the_depth_cap`：`depth_limited` 必须有值，
  且深度外的体量不能凭空出现；
- `walk_names_a_top_level_directory_it_cannot_open`（unix，root 下跳过）：`chmod 000` 的一级
  目录必须进 `unreadable_dirs`，且不能把其它目录的扫描带崩；
- `top_dirs_renders_an_unreadable_directory_instead_of_dropping_it`：读不了的目录必须有行、
  备注写读不了；
- `unfinished_and_unreadable_directories_are_reported_apart`：两种处置（重扫 vs 要 root）分开说；
- `the_incomplete_hint_lists_a_bounded_number_of_rescan_commands`：hint 最多列
  `INCOMPLETE_DIRS_SHOWN` 条命令，总数在正文里说；
- `the_scan_section_says_when_depth_stopped_the_walk`：`depth_limited` 进正文 + 标题 + hint；
- `unattributed_points_at_the_directories_it_could_not_read`：差量解释里点名读不了的目录。

实测（926 GiB 的 macOS）：默认参数下 `disk.top_dirs` 现在写
「共 18 个一级目录」，4 个没扫完 + 3 个读不了全部点名；`disk.scan` 带
`incomplete_top_dirs=4 unreadable_top_dirs=3 depth_limited=41`。

### 兼容性

报告 schema 仍为 `wist.investigation.disk/v1`（只增字段与文案）；网关/web 无需变更。

## [0.13.0-alpha] - 2026-10-31

### 修复（磁盘调查：先「一级目录列全」，再均匀花预算）

现场报告（926 GiB 的 macOS）暴露的问题：`/Applications` 有 14 万条，深度优先一路走到底
把 200k 条目上限吃干，同级的 `/Users`（真正占了 200 GiB，`~/.Trash` 就 151 GiB）连名字都
没进报告，`disk.top_dirs` 只写了「共 3 个一级目录」——**看起来像扫全了，答案却不在表里**。

- **预算改成「一级目录轮流分配」**：先用极小代价枚举根下一级目录全集（这一层不计预算），
  再让各一级目录各持一个**可续游标**轮流花剩余预算（每轮每目录最多 4096 条），
  先扫完的目录会把额度让出来。巨型目录不再能把同级目录饿死。
- **`disk.top_dirs` 的「共 N 个一级目录」现在总是真的**（取枚举全量，不再是被截断后的条数）。
- **没扫完的一级目录点名**：报告新增 `incomplete_dirs`（路径 + 已扫到的字节，按体量降序），
  `disk.top_dirs` / `disk.largest_dirs` / `disk.unattributed` 都会写「N 个一级目录没扫完（/Users、…），
  它们实际只会更大」，对应的行标注 `没扫完，实际更大`。
- **每条「没扫完」都配一条可直接复制的重扫命令**
  （`wist-agentd investigate disk --path <目录> --max-seconds 60`）。
  「没扫完」不是免责声明，而是**下一步该跑什么**。
- **时限按条目复查**（每 512 条）：只在目录边界查，一个巨型目录会一路超时跑下去。
- **平台化的大头提示**：磁盘紧张时按平台给出常见元凶 ——
  macOS：`~/.Trash`、`~/Library/Caches`、`~/Library/Containers`、`~/Library/Developer`、`/private/var/folders`；
  Linux：`/var/log`、`/var/lib/docker`、`/var/lib/containerd`、`/var/cache`、`/home/*/.cache`。
- `disk.scan` 的正文多一项 `incomplete_top_dirs=N`，hint 改为引导「单独扫某个目录」
  （`--depth` 不再是瓶颈，条目/时长才是）。

实测（同一台机器）：默认参数下归因从 25 GiB 提升到 ~83 GiB，且指向的目录是对的；
按提示单独扫 `/Users`（30s）后，`~/.Trash` 151.9 GiB（占扫描总量 70.2%）立刻成为热点。

### 兼容性

报告 schema 仍为 `wist.investigation.disk/v1`（本次只增字段与文案，不改结构）；
网关/web 无需变更。

## [0.12.0-alpha] - 2026-10-30

### 新增（磁盘调查：先找「哪个目录」，再找文件）

- **`disk.largest_dirs`**：**递归累计**最大的目录（任意深度）+ **热点下钻链**。
  为什么：**最大的文件不一定是根因**。现场最常见的是「一堆中小文件堆在一个深层目录里」
  （容器层、会话目录、百万小文件写满 inode），单个文件都不大，一级目录只会告诉你“/var 很大”。
  - 自底向上累计（`du` 的做法）：每个文件把字节加到所有祖先目录，硬链接按 inode **只算一次**；
  - 逐层下钻（`du -h --max-depth=1 | sort -h | tail -1` 重复做）：每层选占父级 ≥60% 的子目录，
    直到不再集中 —— 得到 `热点路径：/ → /var (100%) → /var/lib (78.9%) → … → /app`；
  - 同体量的祖先目录不进列表（只会把同一串数字重复四遍）；链末端主要由某个文件撑时直接点名。
- **`disk.unattributed`**：`df` 已用 − 扫描合计的**差量**摊到明面上（扫描根就是挂载点时才报）。
  Linux 下顺带扫 `/proc/<pid>/fd`，给出「已删除但仍被打开」的文件数与合计
  （`df` 满而 `du` 找不到的头号原因）；非 Linux 只给方向提示。
- ack 摘要的“证据节”改为优先取 `disk.largest_dirs`（目录才是根因，文件是落地动作）。

## [0.11.0-alpha] - 2026-10-30

### 新增（一次性调查：磁盘满了，到底是哪几大文件）

- **`wist-agentd investigate [disk]`**：只读、有界的一次性调查，给**证据表**而不是红绿检查。
  磁盘题固定五节：文件系统占用（含 **inode**）→ 一级目录合计 → 最大的文件 → **agent 自己占多少**
  → 扫描完成度。有 FAIL 退出码非零（与 `diagnose` 同一条门禁语义）。
  - 默认扫描根 = 占用率最高的文件系统挂载点（数据盘先报警时不用手写 `--path`）；
  - 选项：`--path` / `--top` / `--min-size` / `--depth` / `--max-seconds` / `--json`；
  - 扫描**不跟随符号链接、不跨文件系统**，条目 200k / 时长 5s / 深度 16 三重上限；
    触顶如实标 `truncated`，「最大的文件」不会被当成本机全部真相；
  - 不需要守护进程在跑、读不到配置也能用（只少一节 `disk.agent_dirs`）。
- **网关一次性命令 `kind = investigate`**：搭在既有的命令通道上（`AgentStatusAck.commands` →
  `command_acks`）。执行完 ack 回结论摘要；**完整报告走数据面回传**：新增 ` IVSREP: ` 帧
  （与 `LOGREC`/`METRICS`/`OBSFACT`/`DSNAP` 同一套信封与 `seq` 空间），正文带 `command_id`
  （数据面报告与控制面 ack 的唯一关联键）与 `report_schema`（`wist.investigation.<topic>/v1`）。
  `outcome` 只表达「调查做成了没有」（磁盘紧张是结论，不是命令失败）；回传失败不改 outcome，
  只写在 `detail` 里。`params` 为 JSON：`{topic, path, top, min_size, depth, max_seconds}`，
  宽容解析、夹紧区间；**题目不认识就回 `failed`**，不猜一个题目去扫盘。
- 回传的几条规矩：只有 `kind = tcp` 能承载（待命也发 —— 调查是诊断元数据，不是主机内容）；
  单帧上限 64 KiB，超了**逐级退化**（去 `rows` → 去 `hint` + 截 `detail`，结论始终保留），
  **不发半条 JSON**；不重试、不进 spool（证据迟到就没意义）；本地另留一份 `state/investigations/<topic>.json`。
- ack 的 `detail` 摘要**不绑定题目**：优先取 `*.top_files`，其次 `*.top_dirs`，再退到第一个带证据表的节。
  写死 `disk.top_files` 会让新增第二道题时摘要静默只剩结论、没有任何证据（而且不会报错）。
- 设计取舍见 [`docs/design/agentd-investigation.md`](docs/design/agentd-investigation.md)；
  调查面的词表与网关授权见跨仓
  [`investigation-surfaces.md`](../wist-design/doc/design/center/investigation-surfaces.md)。
- ⚠ **升级顺序：网关先于 agentd**。`AgentStatusReport` 是 `deny_unknown_fields` 的，0.11.0 起每次
  状态上报都带 `investigation_capabilities` —— 发给 0.26.x 网关会被整条拒掉（agent 看上去会“掉线”）。
  `compat.json` 的 `requires.wist-gateway` 因此从 `>=0.26.0` 提到 **`>=0.27.0`**；
  旧 agentd 在 0.27 网关上照常工作，只是调查菜单一直置灰。

### 新增（采集追平：让 agentd 跟得上高吞吐日志源）

- **`[telemetry.logs] catchup_slice_ms`（默认 400）/ `catchup_budget_ms`（默认 1800）**：
  一轮 tick 里对同一条输入**反复读多批**，直到追平或时间片用完；任一为 `0` = 关闭（回到
  「每 tick 一批」）。
  - 为什么：`max_lines_per_tick` / `max_read_bytes_per_tick` 只是**一批**的上限，而主循环 3s 一拍 ——
    单输入上限就是 `4096 行 / 3s ≈ 1365 行/秒`。Suricata 的 `eve.json`、高频应用日志会因此
    永远滞后：checkpoint 追不上文件尾，spool 涨满后 `pause`（「采了但一直在滞后」比采不到更难查）。
  - 每条输入一个**让位粒度**（片），整轮另有一个**硬预算**（3s 拍的 60%）= 采集段不能吃掉整拍。
  - 追的判据是「本批**读到了行**」而不是「产出记录」：多行折叠 / `drop_if_contains` /
    未封口块都会让记录数为 0，但文件确实在前进。
- **超长行截断进自观测**：`telemetry line truncated input_id=… path=… detail=… magnitude=lines=N`
  （`warn`，按签名去重）。对 JSON Lines（如 `eve.json`）截断 = 产出一条下游永远解析不了的记录，
  必须能在源头看见，否则「下游为什么有坏 JSON」查不到。

### 新增（诊断：采集输入能不能读）

- **`diagnose` 新增 `telemetry.inputs`**：逐个检查本机配置 + 已生效工作折算出的日志目标，
  只读不采：显式单文件真开一次（不读内容），glob / 目录只看**固定前缀目录**；
  匹配为空**不算失败**（运行时也不把“没匹配”当错误）。采集未运行（待命 / standalone）
  时报「待启用」，不制造假失败。
  为什么：路径写错 / 权限不足 / 被采程序没启动，现象全是「平台上看不到数据」，
  而以前的 diagnose **完全不看输入**，现场只能猜。

### 变更（内部）

- `ProcessOutcome.read_lines`：本批真正读进来的行数，追平循环的唯一进度信号
  （不能用 `records_processed`：多行折叠 / 噪音丢弃 / 未封口块下它会是 0）。
- tick 内的失败/计数改为**每条输入聚合后拍末只报一次**：追平会让同一输入一拍跑多批，
  每批各推一条会让同一个问题一拍打 N 次，毁掉既有的按签名去重。

- 文件系统枚举收敛到 `telemetry::metrics::runtime::local_filesystems`：指标 `host.filesystem.*`
  与 `investigate disk` **共用同一套过滤与去重规则**（bind mount / APFS 辅助卷不会两处口径不一）。
- `doctor::Status` 增加 `Ord`（`Ok < Warn < Fail`），调查复用同一套状态词表，不再另起一套。

### 升级注意

- 新增的 `investigate` 命令 kind 对旧 agentd **不兼容是有意的**：本机 CLI 新能力需要升级二进制；
  网关下发调查要求 agentd ≥ 0.11.0（旧版本会回 `unsupported`，不会静默）。其余行为不变。
- 数据面（warp-parse）需要新增 `IVSREP:` 的 WPL/OML 与 sink 分组（`business.d/agent_ivsrep.toml`）
  才能把报告入库；在那之前记录会落兑底 sink `gateway-logs`（可见但错位，不会丢）。
  **顺序建议：先发数据面规则包，再开网关侧调查入口**（agentd 先升也不会有副作用：没下发过
  `investigate` 命令就不会发帧）。

## [0.10.3-alpha] - 2026-10-29

### 变更（发版带上升级兼容声明）

- 新增仓根 `compat.json`：`requires: { "wist-gateway": ">=0.26.0" }`，**故意不给**
  `compat_mode` / `coexists_with` —— 旧网关的 `deny_unknown_fields` 会拒收新 agentd 的上报，
  混合态真的不行，就该硬拦，把“先升网关”这个顺序钉住。
- `dev/package-agentd.sh` 与发布流水线都会把它打进包内（仓根缺件则拒绝发布）。

## [0.10.2-alpha] - 2026-10-28

### 修复（上送不再产生截断帧）

- 数据面（wparse）不再收到「半条 JSON 帧」：agentd 写停住时会把已经写到线上的那条记录**补完再断连接**，
  而不是直接断开——现象就是 miss 里出现 `{"schema":"v1",...` 这类截断报文（issue #34）。
- 上送变慢不再被误判成链路坏了（超时看的是「一段时间里没有任何进展」，不是「整次写超过 5 秒」）；
  「对端一直滴数据」也拖不住 agent 的主循环。

## [0.10.1-alpha] - 2026-10-27

### 修复（macOS 上的存储健康）

- `smartctl` 导出器不再写死 `/usr/sbin/smartctl`：按顺序探测
  `/usr/sbin` → `/opt/homebrew/sbin`（Apple Silicon）→ `/usr/local/sbin`（Intel），取第一个**可执行**的。
  三个都没有时仍保留第一个候选，由既有的「工具缺失」预检如实上报（不静默）。
- 与知识库 0.7.0 配套：macOS 开发机（MacDev）的 StorageHealth 面现在能真的跑起来。

## [0.10.0-alpha] - 2026-10-27

### 新增（日志源动态定位：库装在 `/data/db/...` 也能采到）

- **本机推导数据库日志目录**：从进程证据（`-D` / `PGDATA` / `--log-error` / `my.cnf` /
  `redis.conf` / `mongod.conf` / 正在打开的日志文件）推出 PostgreSQL、MySQL、Redis、MongoDB
  的日志目录，作为**候选**随事实摘要同拍上报（`POST /api/v1/agent/log-sources`）。
  采不采仍由网关判定，agent 不自作主张。
- **容器里的实例**：容器视角的路径经 `/proc/<pid>/root` + `realpath` 变成**宿主可见**路径；
  命名卷、可写层、bind mount 三种形态都能定位。
- **多实例**：同一机器上 5432 / 5433 两个实例各自一条（按端口作身份，重启不丢）。
- **受限搜索（L3，默认关）**：前几层证据都落不了地时，在**控制面下发**的 roots 下有界查找
  （标记：`PG_VERSION` / `ibdata1` / `dump.rdb` / `WiredTiger` 或日志文件名）。
  上限：roots ≤ 8、深度 ≤ 4、2000 条目、总时长 2s；不跟随符号链接；只读目录名，不读文件内容。
- **`agentd diagnose` 新增 `discovery.log_sources`**：现场跑一次解析（与守护进程同一条路），
  直接报「看到了几个实例、定位到几个、当前搜索范围」，专治「我配了 `-D`，为什么页面上没变」。

### 变更（配置）

- `[discovery]` 新增 `source_resolve`（默认开：只读 `/proc`，常数成本）。
- **搜索范围不在本机配置里**：由网关下发（知识库 `search_roots` ∩ `allowed_source_roots`），
  落 `state/source_search_policy.json`（重启后仍生效）；拿不到就不搜索。主机侧改不了范围。

### 升级注意

- 需要的网关端点（`/api/v1/agent/log-sources`、`/source-search-policy:poll`）需要
  **网关 ≥ 0.23.0-alpha**；旧网关下这两个能力静默不可用，**其它行为不变**（404 不告警）。

## [0.9.13-alpha] - 2026-10-26

### 修复（探针：看不到 ≠ 不存在）

- 路径探测从**两态**改成**三态**：存在 / 确认不存在（`NotFound`）/ **探不了**（权限、IO 等）。
  以前 `Path::exists()` 把所有错误压成 `false`，于是「没权限」会伪装成「没有这个目录」——
  网关只能报「本机没有」，人就会去改采集配置而不是查权限。
- 探不了的路径**不再计入「已探过」**：网关据此给出「无法判定」（要查权限 / 再探一次），
  而不是「确认没有」。原始错误（`permission denied` 等）会带到回传里。

### 新增（配合网关的采集预检）

- 识别命令 `refresh_facts` 的 `params` = `{"scope":"paths","paths":[…]}`：
  只探这几条路径并回传到 `POST /api/v1/agent/collection-preflight`，**不做整轮重采**
  （探十几条路径是纯读、毫秒级，所以不受重采的 60s 节流限制）。
- 不认这个 `params` 的旧网关不受影响（它们不会发）；旧 agentd 收到也不受影响（忽略 params，
  退化成整轮重采，结论照样出得来）。
- 回传失败（网关不可达 / 未入网）会**大声失败**：命令记 `failed` + 原因，不静默成功。

## [0.9.12-alpha] - 2026-10-26

### 新增（通用的一次性命令通道）

- **统一入口**：网关下发的命令（状态回执 `AgentStatusAck.commands`）与本机 `refresh-facts` CLI
  共用一份**命令台账**（`state/command_history.json`）和一条执行路径。新增一种命令只需加一个
  `kind` 分支，不再新增通道 / 去重 / 结果格式。
- 每条命令带 `command_id`：已处理过的（网关重发、重启后重发）只补结果，不再执行；结果在下一次
  状态上报的 `command_acks` 里回传（`succeeded` / `failed` / `no_uplink` / `throttled` / `stale` /
  `unsupported`），上报成功才清。
- 首个命令 `refresh_facts`：强制拉一次发现策略 → **全量重采**所有探针 → **绕过事实摘要的 5 分钟
  节流**立即上报。本机入口 `wist-agentd refresh-facts`（`--wait <secs>` / `--no-wait`）。
- 单台最小间隔 60s（`WIST_AGENTD_FACT_REFRESH_SECS` 可覆盖）；命令超过 10 分钟才拿到则判 `stale`。
- 本机请求文件是**单槽**的：已有一条未被拾取的请求时，新的 `refresh-facts` 不覆盖它，
  而是等**先到的那条**的台账结果（覆盖会丢掉前一条的 `command_id`，等它的人会白白超时）。
- 按需全量重采时，**单个探针失败沿用上次成功输出**（并在 detail 里列出失败项），避免紧接着的重报把
  「没采到」写成「采到了空的」；同时修正全量刷新后 `last_run_at` 被写成 `None`、导致下一轮又全刷一遍的问题。
- 日志：`CommandAccepted` / `CommandHandled` / `CommandDuplicate` / `FactRefreshCompleted`；
  请求/台账读不出或写不回时另有 `CommandRequestUnreadable` / `CommandHistoryUnreadable` /
  `CommandHistoryStoreFailed`（都是 warn，不影响下一轮）。

### 升级提示（命令通道）

- 依赖 `wist-api` 的 `AgentCommand` / `AgentCommandAck`（`AgentStatusAck.commands` /
  `AgentStatusReport.command_acks`）。**网关必须先升级**：旧网关的 `AgentStatusReport` 是
  `deny_unknown_fields`，收到带 `command_acks` 的报文会整份 400。没有结果时 agentd 不发该字段，
  所以本机 `refresh-facts` 这条路径可以先上。

### 变更（原文快照默认开启，默认 1 小时一帧）

- `[discovery] snapshot_uplink_enabled` 默认从 **关** 改为 **开**：资产清单（进程 / 端口 / 容器明细）
  只有原文快照里有，默认关等于中心看不到资产。**升级后旧配置（没有这个键）会开始上报**；
  显式写了 `false` 的保持不变。
- `snapshot_uplink_interval_seconds` 默认从 `300` 改为 `3600`（1 小时）。实测一台 117 资源的机器
  一帧约 114 KB：1 小时一帧 ≈ 2.7 MB/天，5 分钟一帧 ≈ 33 MB/天。
  周期是**本机配置**，不同机器可以不同（关键主机 300~900，容器密集的 1800~3600）；低于 60s 仍夹到 60s。
- 新建配置模板直接写出这两项（而不是注释掉），让「发不发、多久发」一眼可见。

### 新增（可观测性：不再「静默不发」）

- **周期改由控制面下发**（`agent/discovery-snapshot:poll`，管理面 web 按机器设）：
  优先级 **单机覆盖 > 全局设置 > 本机 `[discovery]`**。网关没有设置时回 `204`，继续用本机配置 ——
  本机配置仍是离线 / 旧网关 / 未入网时唯一的来源。旧网关没有这个端点（404）同样静默回落，
  不会每 30s 刷一行 failed。
- 网关**撤销**设置时会把已下发的值清掉并回落本机配置（否则会一直沿用旧周期）。
- 启动行 `event=DiscoverySnapshotUplinkConfigured ... source=local_config` 说明本机值；
  控制面值到达/变化时另打 `event=DiscoverySnapshotPolicyApplied/ Cleared`。

- 启动时打一行 `event=DiscoverySnapshotUplinkConfigured enabled=... interval_seconds=...`：
  关闭时明说关闭及后果。此前「配置里没有这个键 → 默认关」在日志里**一行都没有**，
  现场表现为「采集一切正常、数据面一帧都没有」。
- `diagnose` 新增 `discovery.snapshot_uplink` 检查，四种状态都报：
  已关闭（warn，附开启方法）/ 已开启但输出不是已启用的 tcp（warn，说明开关开了也不发）/ 已生效（ok，
  报实际周期与 `source`）。来源是 `control_plane` 时提示会**明确说改本机 toml 无效**。
  此前诊断里**没有任何发现/快照项**，所以故障时它报「全部正常」。

### 备注

- 失败语义不变：到点就发，失败只 warn 一行，等下一个整周期（不做秒级重试，也不堆积 spool）。
- 数据面 `agent-dsnap.jsonl` 仍无内置轮转：默认 1 小时后写入量降为原来的 1/12，
  但长期运行仍需按大小/天轮转（数据面侧配置，不在本仓）。

## [0.9.11-alpha] - 2026-10-25

### 变更（容器采集默认开启）

- 容器发现从「按需打开」改为**默认开启**：Linux 上会采集运行时里的容器，以及每个进程
  属于哪个容器。升级后不用改配置就生效，容器资产不会再因为少一行配置而缺一层。
- **老配置自动迁移**：早期版本生成的配置把 `container_enabled` 写死为 `false`。
  只要这份配置还带着旧模板的说明行（说明这一段没人动过），升级后首次启动会自动改写为
  `true`，并在日志里留一条 warn；手写过 `false` 的配置不动 —— 那是明确的选择。
- 确实不需要容器的部署，显式写 `container_enabled = false`。
- 非 root 运行的 agent 读不到运行时目录（`/run/containerd`）时不再让探针失败：
  只是看不到容器，不应该把探针健康度永久标红。

### 说明

- 需要 `service install` 换二进制并重启守护进程后才生效。容器只会在 Linux 上出现；
  macOS 的容器跑在虚拟机里，宿主看不到归属。

## [0.9.10-alpha] - 2026-10-25

### 新增（进程标注所属容器）

- 采集到的进程会带上「它跑在哪个容器里」。中心侧据此把进程归到对应容器下 ——
  以前只有正在监听端口的进程能被归位，批处理任务、sidecar 这类不监听端口的进程
  只能游离在外。
- 只对宿主上能观察到的容器生效。macOS 的容器跑在虚拟机里，宿主看不到归属，
  这类进程不带该信息（不会写成空值）。

### 说明

- 需要 `service install` 换二进制并重启守护进程后才生效。

## [0.9.9-alpha] - 2026-10-25

### 新增（macOS 监听端口采集）

- **macOS 上也能知道「这台机器对谁开了什么口」了**。endpoint probe 之前只在 Linux 有实现，
  macOS 一直报「一个端口都没开」，中心侧的服务列表因此为空。现在会列出本机所有监听中的
  TCP / UDP 地址，并带上持有它的进程（pid + 可执行路径）。
  - 每条记录包含协议、绑定地址、端口。`0.0.0.0`（对外）与 `127.0.0.1`（仅本机）
    能区分开 —— 这两者是完全不同的暴露面。
  - 只看正在监听的 socket，已建立的连接不计入。
  - 同一进程重复绑同一端口只报一次。
- 本机实测 60 个监听端点（`wparse` 1514、`wist-gateway` 3000、`wist-atlas` 8080、
  Postgres 55437 …），端口 / 绑定地址 / 进程均正确。

### 说明

- 需要 `service install` 换二进制并重启守护进程后才生效。

## [0.9.8-alpha] - 2026-10-25

### 新增（发现快照原文上送）

- **完整发现快照可以作为 `DSNAP:` 帧周期上送到数据面**，消费者是中心侧资产目录（`wist-atlas`），
  不是网关。与事实摘要**分开标记、分开周期**：摘要走网关（10~30 KB），原文快照走 atlas
  （一台几百 KB），互不挤占。
  - 默认**关**（`[discovery] snapshot_uplink_enabled`）—— 几百 KB 的上送不该因升级自动打开。
  - 周期 `snapshot_uplink_interval_seconds` 默认 300s；**低于 60s 会被夹到 60s**，一块全量
    快照不能因手滑配置打到秒级。
  - 只在 `[telemetry.logs.output] kind = "tcp"` 且输出启用时生效。开了开关但输出不是 tcp 时，
    启动后打一行 `event=DiscoverySnapshotUplinkInactive` 说明原因 —— 这个组合以前是**完全静默**的。
  - 与日志 / 指标 / 事实共用一条连接与同一个 `seq` 号源。号先落盘再发送：发送失败会留一个
    **可见的空洞**，因为退号会让同一个号被两帧复用，下游按 `(agent, seq)` 去重时会误删。

### 说明

- 配置模板里的新增键是**注释掉的**：旧版本 agentd 的配置是 `deny_unknown_fields`，
  把新键写进旧 agent 读的模板会启动即拒。
- 快照里目前只有 `host.id` / `host.name`，没有 `os.*` / `host.arch`；中心侧主机资产卡片的
  系统信息暂时为空，属于下一步的采集项。

## [0.9.7-alpha] - 2026-10-25

### 新增（选源过滤的自观测）

- **`filters` 真的剔了哪些文件，现在看得见**：每轮通过已有的 failure 通道报一行
  `telemetry selection filtered … magnitude=excluded=N identity_unknown=M`（打 `info`，
  与 `noise dropped` 同一档：配置的正常结果、但必须可对账）。
  - `excluded`：被 `filters` 剔掉的**现存文件数**（`exclude_globs` 不算）；
  - `identity_unknown`：其中因为**读不到容器身份**（`config.v2.json` 缺失 / 坏 / 非 json-file）
    而作判定的条数 —— 这是“排除式静默 no-op”“包含式一条不收”的唯一线索。
  - 量进 `magnitude`、不进签名：持续生效的过滤器只报一次，不会每 tick 刷屏。
- 验收脚本的两个 name 过滤 phase 同时断言这条日志（含 `identity_unknown=1`）。

## [0.9.6-alpha] - 2026-10-24

### 修复

- **本机配置里的容器过滤器校验按维度拆分**。以前“有任一 `filters` 非空就必须在
  `/var/log/containers` 下”，而 M1.5 的 `name_in` / `name_not_in` 也支持纯 Docker 载体：
  同一份配置在网关派活里能用、写进 `[[telemetry.logs.file_inputs]]` 或任务清单却启动即拒。
  现在与网关同一条口径：k8s 维限 `/var/log/containers`；name 维只要求是容器日志来源的形状
  （共用 `wist_contracts::work::is_container_log_target`，接受目录形态）。

### 测试

- 验收脚本新增两个 phase：`name_in` 只采指定容器、身份读不到的不收；`name_not_in` 剔掉
  指定容器、身份读不到的**保留**（共用同一份三容器 fixture，钉住这个不对称语义）。
- 补形状断言：空容器段（`a_b_-d.log`）不算 k8s 命名；四段以上容器名完整吃掉剩余部分。

### 依赖

- `wist-contracts` 0.9.8。

## [0.9.5-alpha] - 2026-10-24

### 新增（M1.5：容器名过滤）

- **`filters.name_in` / `filters.name_not_in` 在采集端生效**：两种容器载体共用一个语义，
  名字来源不同 —— k8s 取文件名第三段（`<pod>_<ns>_<container>-<id>.log`），Docker 读同目录
  `config.v2.json` 的 `Name`（与帧字段 `container.name` 同源，因此不会出现“过滤用一个名字、
  上报另一个名字”）。
- **取不到身份时的三态刻意不对称**：包含式（`name_in`）要求“证明确实是它”，读不到就不命中；
  排除式（`name_not_in`）不能因为读不到配置就把日志全丢了，保留。
- `namespace_in` / `pod_not_in` 仍只对 k8s 命名有效；只用这两维时，非 k8s 命名的候选一律不收
  （与旧行为一致）。

### 依赖

- `wist-contracts` 0.9.7（新增两个过滤维度与能力轴 `filters:name_in` / `filters:name_not_in`；
  `CONTAINER_FILTERS` 扩到 4 维，能力上报自动带上）。

## [0.9.4-alpha] - 2026-10-24

### 新增（M1：容器身份）

- **纯 Docker 主机的容器日志记录带上 `container { name, image, id }`**：从日志同目录的
  `config.v2.json` 读（`Name` 去前导 `/`、`Config.Image`），**只读元数据、不碰正文**。
  k8s 侧这个信息编码在文件名里，Docker 侧文件名只有容器 id —— 不带它，数据面只能看到
  一串十六进制，分不出哪个是业务 / 网关 / 数据库容器。
- 识别靠**路径形状**（`<root>/containers/<id>/<file>`），不写死 `/var/lib/docker`：
  改过 `data-root` 的现场照样能认。配置缺失 / 坏 JSON / 容器创建中 → `None`（下一轮重试），
  不会把半个身份发出去；按 `(mtime, size)` 缓存，容器重建自然失效。
- 取开销：每轮每**文件**问一次（不是每条记录），非容器路径只是一次字符串扫描。

### 依赖

- `wist-contracts` 0.9.6（`ContainerRef` + 帧字段）。

## [0.9.3-alpha] - 2026-10-24

### 变更

- **策略表收编改用契约提供的唯一转换**：`DiscoveryAspectPolicySet::from(returned)`
  （wist-api 0.9.2）取代手写的 `::new(..)` 重建。那处重建正是 0.9.2 那个白名单丢失 bug 的源头；
  现在转换实现在两侧都**穷尽解构**，以后无论哪边加字段，编译器会直接报错，而不是静默丢掉。

## [0.9.2-alpha] - 2026-10-24

### 修复

- **网关下发的探测白名单被丢掉，导致按路径判定的面永远授不了权**：agentd 收到策略表后
  用 `DiscoveryAspectPolicySet::new(..)` 重建了一份，而那个构造器把 `probe_paths` 置空，
  且**漏了**链上 `.with_probe_paths(returned.probe_paths)`。后果：agentd 从不探测任何路径，
  事实摘要里的 `probed_paths` / `present_paths` 恒为空；网关侧的 `path_exists:` 条件只能判成
  「无法判定」——`linux-db-service`（csvlog / slow log）与 `linux-container-stdout` 因此
  **永远授不了权**，`POST /api/v1/admin/agents/<id>/work` 回
  `work_conflict: no unit selected for DatabaseService: linux-db-service=fact_not_collected`。
  升级到本版并重启 agentd 即可：下一轮策略拉取（≤5 分钟）后开始探测，事实重报后就能授权。
- 补上回归位：`fetch_discovery_policies` 的用例现在断言白名单**完整带过来**
  （以前假响应里根本没有 `probe_paths`，所以这个 bug 静默了很久）。

## [0.9.1-alpha] - 2026-10-24

### 新增

- **能力上报补全（G1 / G3）**：`logs_capabilities` 增 `filters`（`namespace_in` /
  `pod_not_in`）与 `drop_if_contains`（`substring`），从契约常量派生。网关据此在派活时
  判断旧机队能不能承接对应的来源。
- **噪音行丢弃（W4）**：输入配置 / 目录单元支持 `drop_if_contains` —— 整条记录命中任一
  精确子串就丢，**不消耗 `seq`**（与闸门挡下同一条理由：取号不上报会让接收端报假丢失）。
  丢弃数进自观测（`telemetry noise dropped …`，`info` 级、按签名去重）。
- **两种记录边界读法（W4）**：
  - `mysql_slow`：`# Time:` 起块（要求冒号后是时间戳，避开 SQL 的 `#` 行注释），
    下一条 `# Time:` 或空闲超时封口；
  - `postgres_csv`：引号状态跨行的 CSV 状态机，**引号外**的换行才切记录；
    未封口的块跨读批时从 pending 正文重算引号状态（不另存一份会漂的状态）；
    读取器截断的长行按 `Oversized` 挡下（不会把下一行粘进来）；
    长空闲（60s）才按 `Oversized` 回收“写到一半”的记录（否则一条截断记录会永久吸收后续行）。
- 配置校验的读法词表改为直接取契约 `MULTILINE_MODES`。
- **真机验收脚本**：`dev/verify-log-acceptance.sh`（配合 CI 的 `log-acceptance` job）。
  单测证明的是「给定行 → 给定记录」，证明不了轮转 / symlink / inode、checkpoint 跨进程
  续读、噪音不取号这几类**只有真文件系统 + 真进程**才暴露的行为。脚本用临时目录自造
  fixture（不需要 root），断言全是逐字比对与计数：记录集合、`[file_offset, file_offset_end)`
  与来源字节一致、marker 恰好一次、`seq` 严格递增、自观测 `records=N` 对账。

### 变更

- `ProcessOutcome` 新增 `dropped_noise`：采集批次里被噪音过滤掉的条数。
- `NoiseDropped` 不计入 `TelemetryTick::is_active()`：持续丢 cron 噪音的空闲机器不该永远显示 `Active`。
- **事实采集跟上 `fact-v3`**：进程标识改取 `/proc/<pid>/exe` 的**完整路径**
  （内核线程 / 僵尸整条跳过，读不到 `exe` 时退回 argv、再退回 `comm`）；监听端口只报稳定
  服务端口。两者都是为了让内容摘要稳定 —— 15 字符短名会撞名、临时端口会随无关进程换号，
  都会让幂等键失效。

### 升级提示

- **依赖 `wist-contracts` 0.9.5**（本版用到 `filters` / `drop_if_contains` 两个新能力轴）。
  contracts 发布后再 `cargo update -p wist-contracts` 刷新 `Cargo.lock`。
- 与本版配套的网关是 **0.20.1**：`WorkSpecSource` 是 `deny_unknown_fields` 的，低于它的网关
  解析不了 `drop_if_contains`（整份目录加载失败），也不会把 `filters` 纳入能力裁剪。

## [0.9.0-alpha] - 2026-10-23

### 新增

- **一条输入可以盯一个文件族（W2 收口）**：容器日志的结构化选源 `filters`（`namespace_in` /
  `pod_not_in`）在**发现阶段**求值（展开 → 剔 `exclude_globs` → 剔 filters），
  读取器（tail / checkpoint / 轮转 / 预算）一行未改。
- **内核日志改走 journald（W3）**：新导出器 `journalctl-kernel`（`journalctl -k -p 4 -o json`，
  周期 60s）。游标续读，重启不重放；`--show-cursor` 不可靠，改用 JSON 里的 `__CURSOR`。
  journal 被 vacuum 时 journalctl **不报错**（实测 systemd 255 / 259）而是静默重读，
  所以带游标超时会清游标退回有界的 `--since`，不会永久卡死。
- **状态上报带日志能力清单（D7）**：`logs_capabilities`（`file_inputs` / `multiline_modes` /
  `exporters`），从契约常量派生。网关据此不再把「这台机器接不了的来源」派下来。

### 变更

- 上送失败时不推进游标（至少一次）：宁可下一轮重读，不把没送达的一段永久跳过。

### 升级提示

- **依赖 `wist-contracts` 0.9.4 / `wist-api` 0.9.1**。
- ⚠ **先升级网关再升级本版**：`AgentStatusReport` 是 `deny_unknown_fields` 的，
  旧网关收到 `logs_capabilities` 会**整份拒收**，本版会一直报 400。
- 新增导出器 `journalctl-kernel`：需要本机有 `/usr/bin/journalctl`（非 systemd 主机不派这个面）。

## [0.8.0-alpha] - 2026-10-22

### 新增

- **文件族输入（W1）：一条输入可以盯一个 glob 或一个目录**。`path` 为绝对路径时按形态分流：
  显式单文件走既有单文件读取器（行为逐字不变），单层 glob（`/var/log/containers/*.log`）
  与目录走新的 `FileFamilyProcessor`。`*` 不跨目录、`**` 不支持、`~` 不展开。
- **`exclude_globs`**（`LogFileInputSection`，默认空）：从文件族匹配集里剔掉绝对路径 glob，
  按展开后的完整路径匹配。容器日志的选源就是 `*.log` + 排除平台自身的 pod。
- **`exclude_globs` 从工作参数透传**：网关派活的单元里声明的排除项会原样进入本机采集任务。
- **起始位置（写死）**：input 首次扫描用 `startup_position`（默认 tail）；运行中/重启后
  **新发现**的文件从 head 读（停机期间的日志不整段丢）；已跟踪的文件按 checkpoint 续读。
- **symlink 轮转**：发现时持久化 `real_path`（`/var/log/containers/*.log` 是 symlink，
  轮转发生在 `/var/log/pods/...`）；排空与找回轮转文件都在真实路径上进行。
- **每文件独立的多行块**：`pending_multiline` 下移到 `TrackedFileCheckpoint`，
  旧 checkpoint 的 input 级块在首轮自动迁到对应文件（多文件交错不会再把两个块粘错）。
- 保护：`max_files` 512（跟踪上限）、`max_new_files` 32/轮、目录重扫 15s（与 3s tick 解耦）、
  单轮读取预算跨文件递减（预算耗尽时后面的文件留到下一轮，且不落 offset=0 的 checkpoint）。
- **触顶上报**：匹配数超过 `max_files` 时新增失败类 `CapacityExceeded`（`refused/tracked`
  进 `magnitude`，按稳定签名去重）—— 否则「这台机器的某个容器为什么没数据」只能靠猜。

### 变更

- **`FileGlob` 来源的「可执行」判据放宽**（随 `wist-contracts` 0.9.1）：绝对路径 + 单层通配
  现在会被折算成采集任务；`**` / `~` / 相对路径仍进 `unsupported_units`，文案改为
  「not a collectable absolute path」。`**` 也在本机配置这一层被 `unsupported_target()`
  拒成「目标形态不支持」（而不是让文件族每轮抛一次 IO 错误）。
- 目录目标不再被当作「采集失败」：无匹配是正常空集合（目录不可读才报错）。
- **checkpoint 只在真的变了时重写**：位置没推进、集合没变、也没扫描的 tick 不落盘
  （512 个文件的全量状态每 3s 重写一次是数 GB/天的写放大）。

### 修复

- 文件在轮转/删除后找不到旧文件时，手里的未封口多行块现在会按到期封口交出去，
  不再既不发也不清（此前会一直挂在 checkpoint 里）。
- **一个路径只保留一条 checkpoint**：同一路径换了 inode（轮转但旧文件已不在、或停机期间被替换）
  时旧条目让位 —— 否则 `checkpoint_for_path` 只取第一条，新文件永远读不到。
- **单文件读失败不拖垮整族**：其余文件照常交付并提交 checkpoint，错误在本轮末尾上报。
- **扫描失败不推进扫描时钟**：目录不可读时每轮都重试并报错，而不是 15s 才报一次、
  中间那些 tick 看着「一切正常」。
- **同一真实文件只读一次**：目录里同时有 symlink 与其目标文件时按 `realpath` 去重。
- 轮转 / 截断后起点确定为 0 时，即使本轮预算已耗尽也会留下 offset=0 的 checkpoint，
  否则下一轮会把新文件当「新出现的文件」从 head 读，这中间写入的内容整段丢。
- 旧状态里迁移不上文件的 input 级未封口块，改为按到期封口交出去（此前会随迁移静默消失）。

### 升级提示

- **依赖 `wist-contracts` 0.9.1**（`is_glob_path` / `is_file_target` / `WorkSpecSource.exclude_globs`）。
  发布顺序：先发 contracts，再发本仓；本地同期开发时用 `Cargo.toml` 末尾的
  `[patch.crates-io]`（注释块）指向 `../wist-contracts`。
- 旧网关不会派 glob 来源，因此升级本仓本身不改变现有采集行为。
- **降级**：本版 checkpoint 新增 `last_scan_ms` / `real_path` / 每文件的 `pending_multiline`，
  旧版 agentd 的 `LogCheckpointState` 是 `deny_unknown_fields` 的 —— 它会把整份状态读成
  「读不动」，打一条 `LogCheckpointUnreadable` 警告后按 `startup_position` 重新定位。
  `tail` 下不重放也不丢；**glob/目录输入在旧版会被报成 unsupported**（旧版不认这种形态）。
- 本版工作参数会带 `exclude_globs`（仅当单元声明了排除项）：旧版 agentd 的
  `WorkSpecSource` 同样 `deny_unknown_fields`，会把**整份 spec** 判为解析失败。所以目录里带
  排除项的单元必须等机队升级后再翻 `active`（见设计文档 D7）。

## [0.7.0-alpha] - 2026-10-19

### 新增

- **`diagnose` 新增控制面证书主机名检查**：`network.tls_cert` 只读地开一次 TLS 握手，读取网关
  叶证书的 `subject` / `SAN` 并与 endpoint 主机名比对（支持 DNS、通配符与 IP SAN）。
  主机名不匹配时直接 FAIL 并给出重签提示，不再只表现为一句 `transport error`（换域名、
  共享 `identity/` 被另一条部署路径重签、反代 SNI 不对都会命中）。
  取不到证书时**不额外报项**（避免把“网关要求客户端证书”误报成故障），真正结论仍由
  `network.control_plane` 给出。

## [0.6.0-alpha] - 2026-10-19

### 新增

- **主机磁盘容量按挂载点采集**：新增 `host.filesystem.{usage_percent,total_kb,available_kb}`，
  带 `mount` / `fstype` 标签，规范化成 `system.filesystem.{usage,total,available}`。
  - Linux 排除引导/运行期/虚拟/网络挂载；macOS 计入 Data 卷与本地 `/Volumes/*`，
    排除其它 `/System/Volumes/*` 与网络卷。
  - 同一文件系统被 bind mount 到多个路径时只报一次；旧 `host.disk.*` 保留兼容。
- 指标样本 / VM line 支持 `labels`，数据面可按 `mount` / `fstype` 透传。

### 变更（依赖）

- 对齐 `wist-metrics 0.5`；发布顺序：先发 `wist-metrics 0.5.0`，再发本版。

### 文档

- 明确 `standalone`（`control_plane.enabled = false`）不采集、不缓冲、不上送；
  file input 与 discovery 只在 `managed` 下运行。

## [0.5.0] - 2026-10-18

### 新增

- **路径存在性事实（`path_exists` 的采集端）**：网关把发现策略里 `path_exists:<绝对路径>`
  条件推导出的路径白名单（`DiscoveryAspectPolicySet.probe_paths`）随策略下发；agentd 在压缩事实摘要时
  逐条探测（`build_summary(snapshot, probe_paths)`），并把「探测过」与「存在」分开上报
  （`probed_paths` / `present_paths`）。这样采集目录里的 `match = "path_exists:…"` 才能区分
  **无法判定**（没探测过）、**不存在**（探测过但不在）与**存在**。
  - 只探**绝对路径**：相对路径的结果取决于进程 cwd，同一台机器换个启动方式就会翻面，不当事实。
  - 内容摘要随契约升级到 `fact-v2`（`probed_paths` / `present_paths` 参与摘要计算）。

### 变更（依赖）

- 对齐 `wist-contracts` / `wist-api` **0.9**、`wist-validate` **0.6**、`wist-metrics` **0.4**。
  **升级顺序**：本版会多报两个字段，旧网关（`deny_unknown_fields`）会拒整份事实上报 ——
  必须**先升网关**（≥ 0.14.0），再升 agentd。

## [0.4.0-alpha] - 2026-10-15

### 变更（不兼容）

- **移除 `--user` 用户级作用域**：`wist-agentd` 只保留系统级托管（Linux systemd 系统 unit /
  macOS `LaunchDaemons`）。`service` 子命令不再有任何作用域旗标（系统级为默认且唯一）；
  升级器 `wist-upgrader` 的 `--scope system|user` 选项一并删除，systemd 重启不再带 `--user`，launchd 固定
  用 `system/<label>` 域。`--config-dir` 与“非 `/etc/wist-agentd` 配置目录 → 数据/日志就地”的开发机行为保留。
- **`dev/install-local.sh` 不再接受 `WIST_AGENTD_SCOPE`**：一律系统级安装，落点固定
  `/usr/local/bin`（二进制）+ `/etc/wist-agentd`（配置）。
- **升级注意**：旧的 `--user` 用户级安装需先重装为系统级 —— 否则升级重启会指向不存在的 system 服务。

## [0.3.2-alpha] - 2026-10-14

### 变更

- **制品推送到 COS 时自带 sha256**：上传的每个对象带自定义元数据 `x-cos-meta-artifact-sha256`
  （COS 只存 MD5 ETag，GitHub 资产摘要过不来）；可用 `coscli stat`（HEAD）读回。`x-cos-meta-`
  是 COS 对自定义元数据的强制前缀。

## [0.3.1-alpha] - 2026-10-13

### 变更

- **发布时可选把制品推送到腾讯云 COS**：打 tag 时新增 `upload-cos` job，把各平台 tarball 上传到
  `cos://<桶>/wist-agentd/<tag>/` 与 `.../latest/`（未配置 `COS_BUCKET` 时自动跳过，不影响发布）。

## [0.3.0-alpha] - 2026-10-11

### 新增

- **接入统一日志**（共享 crate `wist-log`）：daemon 启动早期按配置的 `[log]` 段初始化，级别 / 格式
  （`text` | `json`）/ 落点（缺省 stderr；可选文件 + 进程内轮转）与全栈同名同义。
  daemon 运行诊断从 `eprintln!` 改为 `log::{info,warn,error}!`（CLI 输出 `version` / `init-config` /
  `wist-exec` / `wist-upgrader` 仍走 stdout）。

### 变更（不兼容）

- **`AgentConfig` 新增顶层 `[log]` 段**（直接内嵌 `wist_log::LogSection`，与 gateway / center 同口径）。
- **依赖升到** `wist-contracts 0.8` / `wist-api 0.8` / `wist-metrics 0.3` / `wist-validate 0.5` /
  `wist-log 0.1`。`AgentConfig` 与配置校验（`config::agent_config` / `config::validate`）现由本仓承载
  —— `wist-contracts` 删了 `agent_config`、`wist-validate` 删了 `config`。

## [0.2.3-alpha] - 2026-10-09

### 变更

- **对齐 `orion-error` 0.9**：依赖由 `0.8` 升到 `0.9`（`OperationContext` 变纯数据、Drop 日志交给
  `AutoLogGuard`）。本仓只用 `to_err` / `source_err` / builder，无行为变更。

## [0.2.2-alpha] - 2026-10-09

### 变更

- **对齐生态版本**：依赖升到 `wist-contracts 0.7` / `wist-api 0.7` / `wist-validate 0.4` /
  `wist-metrics 0.2` / `wist-shared 0.2`（0.4–0.7 期间 seam 报文迁入 `wist-api`）。无行为变更。

## [0.2.1-alpha] - 2026-10-08

### 变更

- **Linux 制品改为静态 musl**：发布矩阵从 `x86_64-unknown-linux-gnu` / `aarch64-unknown-linux-gnu`
  收敛为 `x86_64-unknown-linux-musl` / `aarch64-unknown-linux-musl`（macOS 仍 `aarch64-apple-darwin`），
  构建时装 `musl-tools` 并把 C 依赖（`ring` 等）的 `CC`/链接器指向 `musl-gcc`，产出**静态链接**二进制
  （`file` → `statically linked`，`ldd` → `not a dynamic executable`），glibc 与 musl（Alpine）主机上都能跑。
  制品名相应变为 `<repo>-<version>-<triple>.tar.gz` 的 musl 形态，满足控制中心「三平台、不出现 glibc」的平台集。
  **包内三件套**（`wist-agentd` / `wist-exec` / `wist-upgrader`）与安装脚本口径不变；仅发布产物形态变更。

## [0.2.0-alpha] - 2026-10-07

### 新增

- **机器名兜底到系统主机名**：`HOSTNAME` / `COMPUTERNAME` / `/etc/hostname` 都拿不到时（macOS 的常态）
  改用 `gethostname()` —— 此前会退化成占位名 `local-host`，导致管理面上**所有 macOS 机器同名**。

### 变更

- **机器画像与事实摘要只带有信息量的网卡地址**：在采集侧就滤掉 IPv6 链路本地（`fe80::/10`）、
  回环与 IPv4 自分配（`169.254.0.0/16`）—— 多网卡主机不再把十几条噪声地址带上管理面 / 中心。
- 机器名优先级（`HOSTNAME → COMPUTERNAME → /etc/hostname → gethostname`）收成**一份共享实现**
  （发现探针 / 机器画像 / 实例名三处共用），不再各自复制、各自退化。

## [0.1.34-alpha] - 2026-10-06

### 变更

- **依赖换到底座 crate `wist-artifact`**：升级取包 / 摘要校验 / 版本比较原先经 `wist-release` 拿 ——
  那是**发布域** crate（包身份解析 + 发布计划），被管端不该依赖控制面的域 crate：它只需要
  「拿下来 / 核摘要 / 判方向」。换到底座之后，agentd 的依赖树里**不再有 `wist-release`，也不再
  有 `flate2` / `tar`**（那两个只在身份解析那层用），发布域升版也不会再牵着 agent 走。
  **行为不变**（错误码 `package_unavailable` / `package_too_large` / `digest_invalid` /
  `digest_mismatch` 与「只前进、降级需显式声明」的规则逐条保持原样）。
- **`reqwest` 0.13.1 → 0.13.5，并去掉 `webpki-roots`**：它不是 reqwest 0.13 的 feature（只是可选依赖
  的隐式 feature，reqwest 源码也不引用），0.13.5 已把它去掉 —— 留着会把本仓**钉死在 0.13.1**，任何
  forward 更新都解析失败。0.13 里 TLS 根由 `rustls`（系统根）决定。

## [0.1.33-alpha] - 2026-10-06

### 变更

- **升级取包与摘要校验收进共享 crate `wist-release` 0.2**：本仓原先自带一份「读来源（本机路径 / 
  mTLS 请求）+ 大小上限 + sha256 + `sha256:` 前缀口径 + 版本比较」，与网关缓存、中心发布那两份是同口径的
  **第三、四份**实现。现在统一走 `wist-release`，**行为不变**（错误码
  `package_unavailable` / `package_too_large` / `digest_invalid` / `digest_mismatch`
  与「只前进、降级需显式声明」的拒绝规则逐条保持原样）。
  - 本机路径分支**刻意不构造 HTTP client**：联调 / 离线演练常在还没有已签发身份的机器上跑；
    一旦那里要求 client，「能读本地文件」就会变成读不了。
  - 生产代码不再直依赖 `sha2`（摘要改由 `wist-release` 算，与中心 / 网关同一个实现）；
    `sha2` 只留在 dev-dependencies —— e2e 需要一个**独立于被测实现**算出来的摘要夹具。

## [0.1.32-alpha] - 2026-10-06

### 变更

- 依赖跟随：`wist-api` `0.5` → **`0.6`**（seam 模块名统一：`gateway` 拆成
  `action_plan` / `action_result` / `facts` / `discovery_policies`；`agent_status` / `agent_uplink`
  改名为 `status` / `uplink`）、`wist-validate` `0.2.2` → **`0.3`**（后者也是跟随 `wist-api 0.6`）。
  **线上 JSON 与行为不变**，本仓只改 `use` / 类型路径。

## [0.1.31-alpha] - 2026-10-06

### 变更

- 依赖跟随：`wist-api` `0.4` → **`0.5`**（非破坏：`gateway` / `work` / `agent_uplink` 规范成 `v1` 子模块，
  报文路径经 `pub use v1::*` 不变）、`wist-validate` `0.2.1` → **`0.2.2`**（后者也是跟随 `wist-api 0.5`）。
  无行为变化。

## [0.1.30-alpha] - 2026-10-05

### 变更

- **`work` / `agent_uplink` 的 seam 报文改用 `wist-api`**（`wist-api::work` / `wist-api::agent_uplink`）；
  **领域 / 状态类仍在 `wist-contracts`**。**线上 JSON 不变**。
- 依赖：`wist-api` 0.4、`wist-validate` 0.2.1。

## [0.1.29-alpha] - 2026-10-05

### 变更

- **agent 面其余 seam 报文改用 `wist-api::gateway`**：`ReportActionResult` / `ReportAgentFactSummary` /
  `PollDiscoveryPolicies` / `DiscoveryPoliciesReturned` 等由 `wist-api` 提供
  （`wist_contracts::gateway` 已整体移出）。**线上 JSON 不变**。
- 依赖跟进：`wist-validate` 0.2（其校验输入类型也随迁）、`wist-api` 0.3。

## [0.1.28-alpha] - 2026-10-05

### 变更

- **`agent/status` 报文改用独立 seam crate `wist-api` 0.2**：上报体 `AgentStatusReport`（及
  `AgentWorkState(Change)` / `AgentCertificateStatus` / `AgentCredentialRenewal`）由
  `wist_api::agent_status` 提供（`wist_contracts::gateway` 里的对应报文已移出）。**线上 JSON 不变**。

## [0.1.27-alpha] - 2026-10-05

### 变更

- **对齐 `wist-contracts` 0.3**：agent 注册/续期（`agent/enroll`、`agent/credentials:renew`）的报文
  改由独立 seam crate **`wist-api` 0.1** 提供（`wist_contracts::enrollment` 里的报文已移出）；
  **线上 JSON 不变**，纯依赖归位。契约里被多条 seam 复用的领域类型（`HostProfile` /
  `CredentialBundle` 等）仍在 `wist-contracts`。
- 依赖链一并跟进：`wist-validate` 0.1.5、`wist-metrics` 0.1.6（均已切 `wist-contracts` 0.3）。

## [0.1.26-alpha] - 2026-10-05

### 变更

- **对齐 `wist-contracts` 0.2**：由 0.1 升至 0.2，与 `wist-gateway` / `wist-center` 统一边缘契约版本；
  一并跟进依赖链（`wist-validate` 0.1.4 / `wist-metrics` 0.1.5 也已切到 `wist-contracts` 0.2）。
  agentd 用到的契约类型（`enrollment` / `work` / `gateway` / `action_*` / `discovery` 等）在 0.2.0 中未变
  —— 0.2.0 的破坏点集中在网关↔中心注册/凭据（`gateway_control`），agentd 不消费。

## [0.1.25-alpha] - 2026-10-05

### 变更

- **排障文档路径更新**：网关开发态 home 从 `~/.wist-gateway` 迁到 `<栈根>/dev/configs/gateway`
  （对称发布态 `configs/gateway`）；FAQ 里的 admin token / TLS 证书路径同步更新。

## [0.1.24] - 2026-10-03

### 新增

- **状态上报带上机器画像**（机器名 / `node_id` / `machine_id` / 网卡地址）：此前凭客户端证书首触
  注册的机器在管理面只有一个 ID，认不出是哪台；现在由每次状态上报补齐，管理面可显示主机名与 IP。
  依赖 `wist-contracts` 0.1.14。

### 修复

- 注册时上报的 `ip_addresses` 以前恒为空表（写死），现在如实填本机网卡地址。

## [0.1.23] - 2026-10-03

### 修复

- **升级其实成功了、控制面却显示失败**：此前 Linux 上服务重启会把升级器一并终止，于是升级结果再也报不回去 —— 控制面看到的是「升级器 60s 没有心跳，判定已死（步骤 restart）；机器可能停在中间态」，而机器其实已经换好并跑起来了。现在升级结果能被如实上报。

### 新增

- **`wist-agentd diagnose` 增加「升级」检查项**：直接读本机升级记录与心跳，报出最近一次升级的成败 / 进度，以及「升级器已失联（判定已死）」这类结论 —— 不再出现「控制面显示失败、本机诊断全绿」的对不上。

## [0.1.22] - 2026-10-03

### 变更

- **导出器先预检工具、再执行**：导出器工具（如 `smartctl` / `ausearch`）缺失时，agentd 不再靠
  「进程启动失败」表达，而是**跑前判存在**（且要可执行）—— 缺失的**记进本地状态**
  （`state/exporters.json` 的 `missing`）并打一行清晰的 `tool missing`；工具装上后**自动恢复**
  （缺失期间不推进周期，装上即跑）。
- **`wist-agentd diagnose` 展示缺的导出器工具**：新增检查项「导出器工具缺失」，把记在案的
  缺件（`id（路径）`）连同处置提示一起报出来 —— 缺件是一类**部署缺口**，不该只藏在日志里。

### 说明

- 采集语义不变：缺件只让**对应面**今天采不到，不影响其它面；`diagnose` 里没有缺件记录时
  不出现该检查项。

## [0.1.21] - 2026-10-03

### 新增

- **定时导出器（`Exporter` 来源）落地**：采集内容目录里那些「不是 tail 一个文件」的来源
  （journald、`last`、`smartctl`、`nft` / `iptables-save`、`dmesg`、`auditd`）现在能采了。agentd 按
  **授权**把它们折算成**周期任务**：到点跑一条**固定命令**（无 shell、无参数拼接、有超时），
  输出按行变成记录上送，`source_path` 记为 `exporter:<target>`。
- 导出器上次运行时刻落本地 `state/exporters.json`（跨重启保留，重启不重跑快照）。
- 失败（二进制缺失 / 退出非 0 / 超时）如实打到自观测，不静默。

### 说明

- 「能不能采」的判据与网关是**同一个**（`wist-contracts::work::is_executable_source`）：只有
  **已知导出器 ID** 才算可采，未知 ID 仍如实报 `unsupported`。
- 首版导出器：`journalctl-unit` / `journalctl-shutdown` / `last-reboot` / `nft-ruleset` /
  `iptables-save` / `smartctl` / `dmesg`（`panic` / `nvidia-xid`）/ `auditd-execve`。
  命令路径与开关按通用发行版写，**建议在目标机核对**；`smartctl` 首版只枚举磁盘。

## [0.1.20] - 2026-10-02

### 修复

- **官方 Release 的安装包缺件，经网关下发的安装脚本会当场中止**
  （`agent package is missing wist-upgrader`）：「三件必须一起换」是硬要求（升级器正是去换 agentd
  自己的那个进程，版本错配就失去“同版本”前提），而 release 工作流只打了 `wist-agentd` 与 `wist-exec`
  —— 于是**每个官方 Release 都是漏件制品**，从网关上装不下来（开发环境自己打的包是好的，所以一直没暴露）。
  现在三件一起打，并补上两道漏件校验（**打前**查可执行、**打后**查包内），与开发环境打包脚本同口径：
  再漏件会在 CI 当场失败，而不是把残包发出去。
- 包内一层目录改成与包同名（原来是 `artifacts/`）：与开发环境打的包一致，`tar tzf` 看着也不再像临时目录。

## [0.1.19] - 2026-10-01

### 修复

- **凭据被网关拒绝后，不再必须人工重启才能恢复**：被拒（吊销 / 证书身份对不上）之后 agentd 会
  停止一切常规上报，而那个状态以前只存在内存里 —— 网关侧改好了（解除拒绝名单、重新登记），
  这台机器仍然一直静默，且排障时看不出来（本机诊断工具自己探一遍是通的，页面上也只是“离线”）。
  现在这类状态会**落盘保留**、按固定间隔**自己重试**，网关一恢复接受就自动回到常规上报；
  机器重启后也能接着认账并自愈。重试不会刷日志（只在进入与恢复各留一行）。

### 变更

- **`diagnose` 新增「凭据终态」检查**：处在终态时报 FAIL，并给出 code、进入时间、已重试次数与
  处理办法；网关换了拒绝理由时会跟着更新，不再照旧理由给错建议。
- **`diagnose` 对「待命（不上送）」的说明改准确**：以前它总是归因为「网关侧没有上送地址」，
  而实际原因可能是这台没有派工、或上送开关没开；现在并列两种可能，并指出去管理面的哪两处补齐
  （原来那句话会把运维往错的方向引）。

## [0.1.18] - 2026-09-30

### 变更

- **与控制面通信只凭客户端证书（mTLS）**：状态上报 / 派活 / 数据面 / 发现策略 / 续期 / 升级取包都不再
  发送业务 bearer 凭据；配置与本地状态里也不再保存 bearer token。
- **注册与续期必须带 CSR**：拿不到本地密钥就不再注册（mTLS 是唯一凭据路径）。
- `diagnose` 的凭据/证书两项语义更新：无客户端证书不再是「正常（未启用 mTLS）」，而是 **WARN**，
  并提示用一次性 token 重新注册。

### 修复

- **续期换发的新证书现在会落盘**：此前续期只换了服务端记录，本机仍在用旧证书。
- **没有客户端证书时不再无限重试续期**：改为明确记「需重装」（带一次性 token 重新注册），
  不再每轮静默失败。
- 控制面明确拒绝（如被拒名单）时的处置提示与实际原因码保持一致。

## [0.1.17] - 2026-09-29

### 修复

- **`diagnose` 不再误报「未入网 / 旧网关」**：bearer 凭据**从不写进 `agentd.toml`、只落 state**，
  daemon 启动时会把它注入内存配置；`diagnose` 以前只读 toml，于是控制面探测会「没凭据就不发请求」
  并假报无下发。现在它做同一步注入 —— 你看到的是**真实结论**（401 就报 401，并带上网关的原因码）。
- **`diagnose --offline` 不再丢掉本地能得出的结论**：生效上送输出 / spool 积压 / 本地工作视图照常报。
- `paths.writable` 不再创建目录（回到最近已存在祖先探写）；IPv6 端点（`https://[::1]:3000`）
  不再被误判为坏地址。

### 变更

- **凭据被网关明确拒绝时进入终态**：`unknown_credential`（库里没有这条凭据）/ `certificate_revoked`
  （被拒名单）/ `credential_mismatch` 等，agentd 不再每 3 秒空转重试，而是打出一行
  `event=AgentAuthTerminal code=… source=…` 并按 code 告诉运维**该做什么**；凭据**过期**等可自愈的情况不误停。
- `diagnose` 在凭据一项打出 `credential_id`，一眼即可与网关库对照（判断「库里到底有没有这条」）。
- 被拒详情（控制面探测 / 上送）里带上网关的稳定原因码。

## [0.1.16] - 2026-09-29

### 新增

- **自我诊断 `wist-agentd diagnose`**：一屏回答「这台机器现在有什么问题」。只读地按
  「配置 → 身份 → 安装/服务 → 控制面连通 → 数据面（上送） → 本地工作」逐项自检，每项给出
  `[OK]/[WARN]/[FAIL]` 与**下一步怎么做**；网络按 DNS → TCP → TLS/HTTP/鉴权**分层报错**，
  直接指出「端口不对」「证书不受信」这类常见原因。
- `diagnose --json`：机器可读（`checks[].id/status/hint` + `summary`），供脚本与自动化消费；
  `diagnose --offline`：跳过网络探测，只查本机配置/身份/服务/落点。
- **有 FAIL 时退出码非零**：可直接当门禁（`wist-agentd diagnose || 处理`）。

### 变更

- `[OK]/[WARN]/[FAIL]` 在终端上按状态着色（绿/黄/红），一眼扫到 FAIL；重定向与 `--json`
  恒为纯文本，并支持 `NO_COLOR` / `CLICOLOR_FORCE`。
- 诊断复用守护进程同款判定（生效上送目标、控制面探测），不会「工具说一套、进程做一套」；
  全程只读，不改配置、不建目录（唯一副作用是 `paths.writable` 临时建/删一个探针文件）。

## [0.1.3]

### 新增

- **后台服务托管**：`service print | install | uninstall | status` 渲染并安装 systemd unit 或 launchd plist，
  随后加载并启动服务；`--no-activate` 只落盘定义并打印需要手动执行的加载命令。
- **命令行一次性注册**：`enroll --token <t>` / `enroll --token-stdin`，以及
  `service install --enrollment-token <t>`（先注册后装服务，token 被拒时不会留下半成品服务）。token 不写入配置、
  不落盘；重复注册是幂等空操作。
- 新增 `init-config [--stdout]`、`version`、`help` 子命令。
- file sink 不再要求显式声明路径：未声明的采集输出默认落到 `<数据根>/data/wist-records.ndjson`。
- `dev/verify-system-install.sh`：服务托管真机验收脚本（服务定义、开机自启、running、目录落点、采集输出、
  崩溃拉起、单实例），失败时保留现场并自动 dump 诊断。
- 新增文档：`docs/agentd-install-and-usage.md`（按安装方式组织的安装与使用手册）、
  `docs/agentd-service-deployment.md`（后台长期运行方案设计说明）。

### 变更

- 常驻/自启/拉起交给 OS 服务管理器；daemon 自身**只前台运行**（不自带 daemonize），单实例由 `flock` 保证。
- 默认配置目录：`/etc/wist-agentd`。配置目录在 `/etc/wist-agentd`
  下时，数据落 `/var/lib/wist-agentd`、日志落 `/var/log/wist-agentd`；其它位置则配置/数据/日志全部就地，因此非 root
  开发不会碰到 `/etc`、`/var/lib`、`/var/log`。只填充**未声明**的 `[paths]` 键——显式声明优先。
- `service install --force` 会**重建服务进程**：systemd 走 `daemon-reload` + `enable` + `restart`，launchd 走
  `bootout` + `bootstrap` + `enable`。其中"重建进程"这一步失败时会少量重试，以吸收服务管理器异步拆除的窗口；
  幂等步骤不重试。
- 主循环周期由 250ms 改为 3s（`TICK_INTERVAL`）。
- 稳态周期快照按"内容签名 + 心跳"收敛（`WIST_AGENTD_LOG_HEARTBEAT_SECS`，默认 300s，`0` 关闭收敛），
  内容不变的快照不再刷满磁盘。
- `service status` 额外输出运行/状态/日志目录、单实例锁状态，以及压成一行的配置错误。
- 文档：清除了仓库拆分前的旧路径引用，以及从未落地的机制描述。

### 修复

- systemd 定义对参数做转义，二进制与配置路径含空格、`%`、`$` 也能正确传递。
- systemd 上重装现在会重启服务，替换二进制或改动定义后能真正生效（`enable --now` 对已 active 的 unit 是 no-op）。
- 非 root 用户运行 `service status` 时，能探测 root 属主的单实例锁。
- 验收脚本某一步失败时保留现场并打印诊断，而不是在第一条失败命令上提前退出。

### 移除

- `control::capability_report` 及其 schema 文档：该 builder 没有任何调用方，且 `wist-contracts` 里没有任何消息
  承载 `CapabilityReport`，这份能力声明从未被发送出去。
- `docs/agentd-events.md`：其中描述的进程内事件对象在代码里不存在。

## [0.1.2-alpha] - 2026-09-14

### 变更

- 采用 `wist-contracts` 0.1.2 的 `AgentStatusReport` 命名。

## [0.1.1-alpha] - 2026-09-14

### 新增

- 首个独立发布：tag 触发构建 `x86_64-unknown-linux-gnu`、`aarch64-unknown-linux-gnu`、
  `aarch64-apple-darwin` 三个平台的产物，并接入 CI（build / test / clippy）与 `version.txt`。
- `wist-exec` 与守护进程同 crate 构建、一起发布。

### 变更

- 仓库从 `warp-insight` 拆出，`warp-agentd` 更名为 `wist-agentd`；适配 `wist-contracts` 的类型与 wire 值重命名。
- 升级 CI 依赖的 action 版本。

### 修复

- macOS 上指标上送的 TCP 读取更稳健。
- `endpoint_linux` 的 IPv6 `/proc` 地址用例；模块迁移、未使用 import 与 `reqwest` feature 问题。
- 拆分后 `test_exec_bin` 的 workspace 根定位。
