# wist-agentd 使用帮助（常见问题处理）

出问题先翻这里；安装/配置/命令全量参考 [agentd-install-and-usage.md](./agentd-install-and-usage.md)，
设计取舍 [../design/agentd-service-deployment.md](../design/agentd-service-deployment.md)。
文中 `wist-agentd` 指本机那份二进制。

## 0. 三条自检

```bash
wist-agentd service status --system               # 用户级：--user；只读
tail -50 /var/log/wist-agentd/agentd.err          # macOS；用户级 ~/Library/Logs/wist-agentd/
journalctl -u wist-agentd -n 50                   # Linux；用户级加 --user
launchctl print system/com.dayu-sec.wist-agentd   # macOS 平台侧
systemctl status wist-agentd                      # Linux 平台侧
```

| `service status` 字段 | 含义 |
| --- | --- |
| `scope` | system / user |
| `definition_present` | 定义在不在；`false` = 没托管（前台/`start.sh` 跑的，或已 uninstall） |
| `running` | 单实例锁是否被持有（= 真在跑），比 pidfile 可靠 |
| `bin=` / `exec_bin=` | 都该 `(present)`；缺 `wist-exec` 会让执行类任务全失败 |
| `config=` | 真正在读的那份 `agentd.toml` |
| `root_dir` / `run_dir` / `state_dir` / `log_dir` | 解析后的绝对落点 |
| `logs=` / `check=` | 看日志 / 看平台状态的命令 |

`definition_present=true` + `running=false` → 定义了没跑起来；反过来 → 有人手工在跑（§3.3）。

## 1. 谁在托管它

| 运行方式 | 自启 / 崩溃拉起 | 停止 |
| --- | --- | --- |
| 托管 `--system` | ✓ 开机起 | `systemctl stop` / `launchctl bootout system/…`（§1.2） |
| 托管 `--user` | ✓ 登录起 | 同上；macOS 域换 `gui/$(id -u)`，systemd 加 `--user` |
| `sysrun/start.sh` | ✗ | `sysrun/stop.sh`（日志 `~/.wist-agentd/log/agentd.out`） |
| 前台 | ✗ | Ctrl-C |

四者共用同一 state 目录，靠 `<state_dir>/.agentd.lock` 的 `flock` 互斥：**同时只能一个实例**，
换方式前先停旧的（§2.2）。

### 1.1 作用域：macOS `gui/501` / Linux `systemctl --user`

macOS 用域名 `<类型>/<uid>`：`system`（LaunchDaemon，`/Library/LaunchDaemons/`，`--system`）、
`gui/<uid>`（LaunchAgent，`~/Library/LaunchAgents/`，`--user`）、`user/<uid>`（无图形会话，SSH）。

`501` 是 UID（`id -u`）：0–500 留给系统账号，人类账号从 501 起，换机器会变 → 用 `gui/$(id -u)`。
`sudo` 下 uid=0，install.sh 因此走 `--system`（域是 `system`，没有 `gui/0`）。

Linux 无域名，就是 `/etc/systemd/system/wist-agentd.service`（系统级）与
`~/.config/systemd/user/wist-agentd.service`（用户级）。两个坑：

- `systemctl --user` 需该用户有 user manager：无人登录的机器 / 容器 / 纯 SSH 会话常常没有，报
  `Failed to connect to bus`（`sudo -i` 里也踩）→ 用 `--system`。
- 用户级随会话结束而停；要常驻：`sudo loginctl enable-linger <user>`
  （查 `loginctl show-user <user> -p Linger`）。

### 1.2 平台命令

```bash
# macOS：用户级把 system/ 换成 gui/$(id -u)/
launchctl print system/com.dayu-sec.wist-agentd        # 状态
launchctl kickstart -k system/com.dayu-sec.wist-agentd # 重启（定义不动）
launchctl bootout system/com.dayu-sec.wist-agentd      # 停止（下次登录/重启会回来）

# Linux：用户级每行加 --user
systemctl status wist-agentd
systemctl restart wist-agentd
systemctl stop wist-agentd
systemctl disable --now wist-agentd     # 持久停用（重启也不回来）
systemctl reset-failed wist-agentd      # 清 failed（§2.2）
journalctl -u wist-agentd -f
```

`launchctl load/unload` 已废弃 → `bootstrap`/`bootout`；Linux 不必手工 `daemon-reload`，
`service install --force` 会做。

## 2. 常见问题

### 2.1 kill 完又自己回来

托管必然拉起：launchd `KeepAlive`（`ThrottleInterval=10`）、systemd `Restart=always`（`RestartSec=5`）。

| 目标 | macOS | Linux |
| --- | --- | --- |
| 停一会儿 | `launchctl bootout gui/$(id -u)/…` | `systemctl stop wist-agentd` |
| 停且不再自启 | 加 `launchctl disable gui/$(id -u)/…`（恢复 `enable`） | `systemctl disable --now wist-agentd`（恢复 `enable --now`） |
| 彻底卸载 | `service uninstall --user` / `--system` | 同左 |
| 只重启 | `launchctl kickstart -k …` | `systemctl restart wist-agentd` |

- 只停不 disable：macOS 的 plist 还在 → 下次图形登录重新加载；Linux 的 unit 仍 enabled → **重启机器**会再起。
- 停止是优雅的：`ExitTimeOut=30` / `TimeoutStopSec=30`（先 SIGTERM，30s 后 SIGKILL）。Linux
  `KillMode=control-group` 会连 `wist-exec` 一起收走，未完成的执行由下次启动的 crash recovery 重排。
- `uninstall` 不删配置、state、日志（保留 agent 身份，便于复装）。
- 谁拉起来的：macOS `launchctl blame gui/$(id -u)/com.dayu-sec.wist-agentd`；
  Linux `systemctl show wist-agentd -p NRestarts`。

### 2.2 日志刷 another wist-agentd instance is already running

同一 state 目录有两个实例（多为手工前台/`start.sh` 那份没停）。表现：`running=true` 且平台侧另有进程，
或托管那份反复起了就退。

```bash
pgrep -fl wist-agentd          # 有几个、各读哪份配置
sysrun/stop.sh                 # 停掉手工那份
wist-agentd service status --user | grep running=
```

**Linux 专有**：`StartLimitIntervalSec=60` / `StartLimitBurst=10` → 60 秒内失败 10 次即标记 `failed` 并
**放弃自动拉起**（`start request repeated too quickly`）；launchd 只会按 `ThrottleInterval` 一直重试。
修掉根因后：`sudo systemctl reset-failed wist-agentd && sudo systemctl start wist-agentd`

⚠️ 别删 `.agentd.lock`：文件在但无人持锁是正常的（内核在进程退出时释放），删了会让两个实例都以为自己是唯一实例。

### 2.3 网关看不到这台主机

网关侧 `last_seen_at` 不推进，agentd 日志反复 `status report failed: error sending request for url (https://…)`。
**`Connection refused`（网关没起）与 `CertificateUnknown`（证书被拒）在 agentd 侧是同一句报错**，要两侧对着看：

| 步骤 | 命令 / 位置 | 结论 |
| --- | --- | --- |
| ① 网关可达？ | `curl -sk -o /dev/null -w '%{http_code}\n' https://<网关>/api/v1/agent/install/x86/install.sh` | `200` = 网关在、TLS 可达；否则查网络/DNS/端口 |
| ② 网关拒证？ | 网关日志 grep `CertificateUnknown` / `failed TLS handshake` | 有 → §2.4 |
| ③ 凭据有效？ | 下行一行式看 `credential_status` / `credential_expires_at` | revoked/过期 → §3.2 |
| ④ 本地在跑？ | `service status` 的 `running=` | `false` → §2.2 |

```bash
# admin token 在网关配置 ~/.wist-gateway/wist-gateway.toml 的 admin_api_token
curl -sk -H "Authorization: Bearer <token>" https://<网关>/api/v1/admin/agents \
  | python3 -c "import sys,json; [print(a['agent_id'],a['status'],a['last_seen_at'],a['credential_status']) for a in json.load(sys.stdin)['agents']]"
```

`last_seen_at` 在推进（十几秒到几十秒一次）＝上报正常。

⚠️ 别用 `curl --cacert` 的成败下结论：curl 比 agent 用的 rustls 宽松，证书形态不对时也可能测得过。
判据只有网关日志的握手告警，或 §2.4 的 rustls 测试。

### 2.4 网关换证书后全部 agent 掉线

agent 的信任锚（`agentd.toml` 的 `control_plane.trust_bundle`）是**安装那一刻**拿的，网关换证书或换证书
形态后即失效：网关日志刷 `failed TLS handshake … CertificateUnknown`，agent 侧即 §2.3 的报错。

**重跑安装**（重写 `agentd.toml`、带上新锚；直接粘管理面给的安装命令，含证书指纹）：

```bash
curl -fsSLk --pinnedpubkey "sha256//<网关证书指纹>" \
  "https://<网关>/api/v1/agent/install/<arch>/install.sh" -o s && sh s
```

⚠️ `dev/re-enroll.sh` 只重写 `enrollment_token`，**不刷新 `trust_bundle`**，换证书后跑它无效。

验证证书是不是合法叶证书（在 wist-gateway 仓库跑，与 agent 同源校验器）：

```bash
cargo test --offline --lib -- --ignored rustls_accepts_gateway_certificate --nocapture
# 默认 ~/.wist-gateway/state/admin-tls.crt.pem；可用 WIST_GATEWAY_TLS_CERT / WIST_GATEWAY_TLS_SERVER_NAME 覆盖
```

`rustls ACCEPTS` 才算过；`REJECTS … CaUsedAsEndEntity` = 证书带 `CA:TRUE` 却当叶证书用，须重新生成
（dev 栈的 `dev/start-gateway.sh` 会自动重生成）。

### 2.5 安装脚本报错（摘要不符 / 缺 token）

**`agent package sha256 mismatch`**：下载物与网关记录的摘要不一致（脚本已中止，不覆盖本地安装）。成因都在
网关侧：① "安装包来源地址"与摘要不是同一份制品（如地址指向发布 tarball，摘要来自本地开发二进制）；
② 换了来源地址但摘要没更新。处理：管理面"安装包来源"页把**摘要留空保存一次**（网关按实际缓存回填），
再重新生成安装命令。自查：`shasum -a 256 /tmp/wist-agentd-downloaded` 对比页面显示的 `package_sha256`。

**`Enrollment token:` / `missing WIST_ENROLLMENT_TOKEN`**：命令里的 token 没传进去（只复制了 curl 那段、
没带 `export …ENROLLMENT_TOKEN=<token>`）。脚本认 `WIST_ENROLLMENT_TOKEN` 与旧的
`WARP_INSIGHT_ENROLLMENT_TOKEN` 两个名字，粘上 `export` 那行或在提示符处输入即可。

- ⚠️ 脚本从 **`/dev/tty`** 读提示，`echo <token> | sh install.sh` 这类管道无效；CM/CI 请设环境变量。
- ⚠️ 别把 token 手工写进 `agentd.toml`：注册成功后会自动清掉，手工留着等于长期落盘。

### 2.6 macOS：换二进制后进程起不来，报 Killed: 9

`cp` 覆盖**正在运行**的二进制会把这个路径改坏：老进程还活着，但之后任何 `exec` 它的进程都被内核 SIGKILL。
正确做法（`install.sh` 已这么做）——先写新文件再改名，rename 不动老 inode：

```bash
cp -f wist-agentd.new /usr/local/bin/wist-agentd.new
chmod 0755 /usr/local/bin/wist-agentd.new
mv -f /usr/local/bin/wist-agentd.new /usr/local/bin/wist-agentd
```

已踩：重写一遍二进制（换新 inode），再 `service install --force`。

### 2.7 日志吃满磁盘

- macOS：launchd 不轮转文件，配 `/etc/newsyslog.d/wist-agentd.conf`；Linux：journald，额度看
  `/etc/systemd/journald.conf` 的 `SystemMaxUse`，或 `sudo journalctl --vacuum-size=500M`。
- 稳态输出已收敛（变化才打印 + 默认 5 分钟心跳）；调大 `WIST_AGENTD_LOG_HEARTBEAT_SECS`
  （默认 `300`，`0` = 逐轮打印，仅联调）。
- 采集输出 `wist-records.ndjson` 是数据，不受收敛影响，由下游或 logrotate 管。

### 2.8 采集与落点

**采不到 `/var/log/xxx`**：要系统级安装（root）；macOS 可能还需 Full Disk Access，Linux 看 SELinux / AppArmor
（`dmesg | grep -i denied`、`ausearch -m avc`）。只支持可追加的单个文本文件，见
[../design/log-file-input-spec.md](../design/log-file-input-spec.md)。

**落点**（系统级都要 root；`--user` / 开发机安装则全在配置目录 `~/.wist-agentd/` 下）：

```
/etc/wist-agentd/       配置与 tasks
/var/lib/wist-agentd/   数据：run/ state/ data/（采集输出在 data/wist-records.ndjson）
/var/log/wist-agentd/   服务日志（仅 macOS；Linux 进 journald）
```

**确认在跑哪份配置 / 哪个版本**：

```bash
wist-agentd version
wist-agentd service status --system | grep -E 'config=|bin='
tail -1 /var/log/wist-agentd/agentd.err      # macOS 启动行；Linux：journalctl -u wist-agentd -n 1
# 启动行形如 wist-agentd 0.1.3 starting: config=… mode=managed run_dir=… state_dir=… log_dir=…
```

### 2.9 升级被拒：`artifact_invalid`（制品与这台机器不匹配）

升级**拒绝把机器变成混合版本**，所以在换件之前就会失败，页面上写的是 `artifact_invalid`。两种情形：

- **制品不完整**（tarball 漏打了某个件）：自己用 `bash sysrun/package-agentd.sh` 重打一份，
  它以「三件齐全」为前提，打完还会自己演练一遍；
- **裸包盖在三件套机器上**：网关内置的默认包只有 `wist-agentd`，而机器上已经有
  `wist-exec` / `wist-upgrader` —— 升级只装不删，那两件会留在旧版本。去网关「设置」页把
  「安装包来源地址」指到一份三件齐全的制品。

（摘要校验拦不住这两种：网关按它自己缓存的那份字节算摘要，漏打包的包自己跟自己对得上。）

## 3. 标准操作

### 3.1 升级二进制

A（推荐）：重跑安装命令（校摘要 → 换二进制 → 重写配置 → 重建服务进程）。
B（离线/手工）：先换二进制，再重建。

```bash
# 前提：新版本已解到当前目录（wist-agentd.new / wist-exec.new / wist-upgrader.new）
for b in wist-agentd wist-exec wist-upgrader; do
  cp -f $b.new /usr/local/bin/$b.new
  chmod 0755 /usr/local/bin/$b.new
  mv -f /usr/local/bin/$b.new /usr/local/bin/$b
done
wist-agentd service install --force --system --bin /usr/local/bin/wist-agentd --config-dir /etc/wist-agentd
wist-agentd version
```

- 三个二进制一起换（版本错配会让执行类任务失败，而升级器本身就是去换 agentd 自己的那个件）；
  `service install --force` 只管定义与进程，不拷贝二进制。
- 别用 `systemctl enable --now` 代替 restart（在已 active 的 unit 上是 no-op，会留旧进程跑旧二进制）。
- 回滚：换回旧二进制 + 重建服务进程；state 是 schema 化 JSON，不丢 checkpoint。
- 全升级链路（取包 → 校验 → 换件 → 重启 → 失败回滚）可在本机一键验：`bash sysrun/verify-upgrade.sh`
- 发布制品（tarball）自己打：`bash sysrun/package-agentd.sh` —— 三个件必须同版本、必须一起进包；
  脚本打完会自己演练一遍（把包喂给升级器走一遍取包/验摘要/解包/验证）。
  用法：把它作为网关「设置」页的**安装包来源地址**（绝对路径或 https 链接都行，网关会下载到
  自己的缓存并按缓存那份字节算摘要，摘要不用手抄）。

C（开发机：就是用**本机刚编出来的**二进制）：`sysrun/install-local.sh` [--dry-run|--rollback]

```bash
sysrun/install-local.sh            # 取 target/release → 备份 → 换上 → 重启服务 → 验证
sysrun/install-local.sh --dry-run  # 只打印将执行的命令
sysrun/install-local.sh --rollback # 换回最近一次备份
```

- 把上面 A/B 的手工步骤（构建、备份、换 inode、重启、验证）封成一条命令，并补上 A/B 没做的两步：
  **换前备份**（回滚不再依赖“手边还留着旧包”）与**换后按 sha256 核对**。
- 以**普通用户**运行（它自己为需要 root 的步骤提权）：整个脚本以 root 跑会让 `cargo build` 把 `target/` 变成 root 属主。
- 它不下载、不写配置、不碰注册与凭据 —— 升级前后 enrollment 与 state 不变。
- 默认 `WIST_AGENTD_SCOPE=system`；`user` 作用域同理（装 `~/bin` + `~/.wist-agentd`）。

### 3.2 换网关地址 / 重新注册

| 只变了 | 做法 |
| --- | --- |
| 网关地址 / 证书 | 重跑安装（重写 `endpoint` 与 `trust_bundle`），见 §2.4 |
| 一次性注册 token（凭据失效/被吊销） | `wist-agentd enroll --token <token>` 后重启服务 |
| 网关重装、本机身份作废 | 删 `state/agent_runtime.json` 后重跑安装（重新注册、换发凭据） |

`enroll` 幂等：已注册直接返回 `already enrolled`。

### 3.3 手工跑 → 托管

```bash
sysrun/stop.sh                       # 必须先停，见 §2.2
wist-agentd service install --user --bin ~/bin/wist-agentd --config-dir ~/.wist-agentd
wist-agentd service status --user | grep -E 'definition_present|running='
```

服务自身日志：macOS `~/Library/Logs/wist-agentd/agentd.err`，Linux `journalctl --user -u wist-agentd`；
业务输出仍在配置目录 `log/`、`data/`。Linux 用户级记得 `loginctl enable-linger`（§1.1）。

### 3.4 卸载 / 重装

```bash
wist-agentd service uninstall --system      # 停止 + 删定义（用户级 --user）
# 按需清理（保留则重装后仍是同一 agent 身份）：
#   /etc/wist-agentd/  /var/lib/wist-agentd/  /var/log/wist-agentd/（仅 macOS）
```

干净重装：再删 `state/agent_runtime.json` 与配置目录，然后重跑安装命令。

### 3.5 给服务设环境变量

服务由 launchd/systemd 拉起，不继承终端环境。

| 平台 | 做法 |
| --- | --- |
| Linux | 写 `<配置目录>/agentd.env`（定义里是 `EnvironmentFile=-…`，一行一个 `KEY=VALUE`）后 `systemctl restart`；系统级即 `/etc/wist-agentd/agentd.env` |
| macOS | 无等价文件（只注入固定 `PATH`）：改 plist 的 `EnvironmentVariables`。注意 `service install --force` 按 bin/config 重渲染，会覆盖手工改动 |

常用项：`WIST_AGENTD_LOG_HEARTBEAT_SECS=600`（§2.7）。

### 3.6 报障要带什么

1. `wist-agentd service status`（`--system`/`--user`）全文；
2. `launchctl print …` / `systemctl cat wist-agentd` + `systemctl status`；
3. 服务日志尾部 200 行（`tail -200 …/agentd.err` 或 `journalctl -u wist-agentd -n 200`）；
4. `wist-agentd version` 与启动行；网关侧同时段日志（`failed TLS handshake` / `CertificateUnknown`）。

⚠️ 先脱敏：`agentd.toml` 的 `enrollment_token`、`state/agent_runtime.json` 的 `bearer_token` 不外发
（给 `agent_id` / `credential_id` / `credential_expires_at` 够定位）。

## 4. 别这么做

| ❌ | 为什么 |
| --- | --- |
| `kill -9` 当停止服务 | 托管必然拉起；停止只有 bootout / `systemctl stop` |
| 换证书后只跑 `re-enroll.sh` | 不刷新 `trust_bundle`，仍拒收（§2.4） |
| 手工删 `.agentd.lock` | 文件在 ≠ 有人持锁；删了会同时出现两个"唯一实例" |
| 同机跑"托管 + 手工"两份 | 抢同一 state 目录的锁，托管那份反复退出（§2.2） |
| macOS 用 `cp` 覆盖二进制 | 路径被改坏，之后 exec 一律 SIGKILL（§2.6） |
| 改完 plist/unit 直接重启 | 定义没重写：用 `service install --force` |
| 把一次性 token 写进 `agentd.toml` | 注册后本会清掉，手工留着等于长期落盘 |
| `/etc` 下装却不用 sudo | 配置/数据/日志三处都要 root |
| Linux 无人登录机器用 `--user` | `systemctl --user` 连不上 bus；改 `--system`（§1.1） |
| Linux 崩溃循环后只 `restart` | 已被 start-limit 拒掉：先 `systemctl reset-failed`（§2.2） |
