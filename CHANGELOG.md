# 更新日志

本文件记录 `wist-agentd` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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
