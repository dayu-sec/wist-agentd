# 更新日志

本文件记录 `wist-agentd` 的所有重要变更。格式遵循 [Keep a Changelog](https://keepachangelog.com/en/1.1.0/)，
版本号遵循[语义化版本](https://semver.org/lang/zh-CN/)。

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
