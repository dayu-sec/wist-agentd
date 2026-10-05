# 更新日志

本文件记录 `wist-agentd` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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

- **后台服务托管**：`service print | install | uninstall | status` 为 `--system`（默认）与 `--user` 渲染并安装
  systemd unit 或 launchd plist，随后加载并启动服务；`--no-activate` 只落盘定义并打印需要手动执行的加载命令。
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
- 默认配置目录：`--system` 为 `/etc/wist-agentd`，`--user` 为 `~/.wist-agentd`。配置目录在 `/etc/wist-agentd`
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
