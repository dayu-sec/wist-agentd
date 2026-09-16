# wist-agentd 安装与使用手册

面向部署/运维人员的操作手册。文档按**安装方式**组织：

| 安装方式 | 适用 | 状态 |
| --- | --- | --- |
| [方式一：开发环境安装](#2-方式一开发环境安装) | 开发/联调；本地构建、免 sudo、配置数据日志就地 | 可用 |
| [方式二：通过 Wist-Gateway 安装](#3-方式二通过-wist-gateway-安装todo) | 生产主机；由控制面下发安装与注册 | **TODO**（网关侧待补齐，含过渡做法） |

之后的 [配置](#4-配置) / [运行方式](#5-运行方式) / [命令参考](#6-service-命令参考) / [日常运维](#7-日常运维) /
[验收](#8-验收清单) / [排障](#9-排障) 对两种方式通用。

> 想理解“为什么这样设计”（为什么不自带 daemonize、日志为什么要收敛、为什么 `/etc` 只放配置）→ 看
> [agentd-service-deployment.md](./agentd-service-deployment.md)。

- 相关代码：[`src/service/`](../src/service)（服务定义与安装）、[`src/control/runtime_entry.rs`](../src/control/runtime_entry.rs)（CLI）、[`src/control/enrollment.rs`](../src/control/enrollment.rs)（注册）

---

## 1. 前置条件

| 项 | 要求 |
| --- | --- |
| 操作系统 | Linux（systemd）、macOS（launchd）；常驻托管仅这两个平台支持 |
| 运行时依赖 | 无外部运行时依赖；`wist-agentd` 与 `wist-exec` 一起发布且**必须同目录** |
| 源码构建 | Rust 1.85+（edition 2024） |
| 权限 | 读 `/var/log/**`、执行下发的 `ActionPlan`、写入自己的 state 目录。系统级安装通常以 **root** 运行 |
| 目录 | 配置目录与 `run/state/log` 可写（落点由 `[paths]` 决定，见 §4.3） |
| 控制面 | 需要注册时为 `control_plane.endpoint` 准备地址与**一次性 token**（token 不落盘，见 §4.5） |

> `wist-exec` 必须与 `wist-agentd` 同目录：守护进程按“可执行文件同目录 sibling”查找执行器，找不到才回退 `PATH`；
> 可用 `WARP_INSIGHT_EXEC_BIN` 显式覆盖。

## 2. 方式一：开发环境安装

目标：在一台开发机上从源码构建、**不需要 sudo** 地跑起来（前台或用户级常驻），配置、数据、日志全部就地。

### 2.1 构建与放置

```bash
git clone <repo> && cd wist-agentd
cargo build --release                     # 产出 target/release/{wist-agentd,wist-exec}
```

两个二进制必须同目录。开发时可直接用 `./target/release/...`；想固定路径（可选）：

```bash
install -m 0755 target/release/wist-agentd target/release/wist-exec ~/bin/   # 无需 sudo
```

**不要**把 `target/debug/wist-agentd` 写进服务定义：先装到固定路径，再用 `--bin` 指向它。

### 2.2 初始化配置

```bash
./target/release/wist-agentd init-config --config-dir ./dev-conf
```

关键点：**配置目录不在 `/etc` 下时，数据与日志就地**（不会碰 `/etc`、`/var/lib`、`/var/log`）：

```
./dev-conf/
  agentd.toml            # 配置（可 gitignore）
  tasks/*.toml           # 可选：外置采集清单
  agentd.env             # 可选：长期环境变量（systemd --user 会读）
  run/ state/            # 数据
  data/                  # 采集输出（默认 data/wist-records.ndjson）
  log/                   # 日志
```

> 反过来不行：把开发配置放到 `/etc/wist-agentd` 再以普通用户跑——那样数据会去 `/var/lib/wist-agentd`，
> 普通用户写不进去（要这样跑就在配置里显式写 `root_dir = "<你可写的目录>"`）。

### 2.3 跑起来

```bash
# 前台直跑（Ctrl-C 退出；第一行会打印实际使用的配置与目录）
./target/release/wist-agentd --config-dir ./dev-conf

# 仓库自带的开发机后台脚本（& + disown + pidfile，无自启/无崩溃拉起）
cd sysrun && ./start.sh && ./stop.sh

# 需要“登录即起 + 崩溃拉起”时，装成用户级常驻（仍不需要 sudo）
./target/release/wist-agentd service install --user \
    --bin "$PWD/target/release/wist-agentd" --config-dir ./dev-conf
```

联调小抄：

```bash
WIST_AGENTD_LOG_HEARTBEAT_SECS=0 ./target/release/wist-agentd --config-dir ./dev-conf   # 逐轮全量日志
WIST_AGENTD_RUN_ONCE=1 ./target/release/wist-agentd --config-dir ./dev-conf             # 只跑一轮后退出
./target/release/wist-agentd service status --user --config-dir ./dev-conf              # 只读自检
```

用户级常驻的日志：systemd 看 `journalctl --user -u wist-agentd -f`；launchd 看 `~/Library/Logs/wist-agentd/agentd.err`。

## 3. 方式二：通过 Wist-Gateway 安装（TODO）

目标：生产主机上的安装与注册由 **Wist-Gateway（控制面）** 发起，运维不手工拼命令——网关给出安装指令
（含 `endpoint` 与**一次性注册 token**），agent 完成注册后以系统级常驻方式受管。

### 3.1 目标流程

1. 网关侧生成主机/环境对应的一次性 token；
2. 运维在目标主机执行网关给出的安装指令（脚本或单条命令），大体形如：

   ```bash
   # 目标形态（示意，尚未实现）
   curl -fsSL https://<gateway>/install.sh | sudo sh -s -- --enrollment-token <token>
   ```

3. 安装脚本负责：放二进制 → 初始化配置（写 `endpoint`）→ `service install --system --enrollment-token <token>`
   → 校验 `service status`；
4. 注册结果（`agent_id`、凭据）落 state，网关侧能看到该主机上线。

### 3.2 当前已经具备（agent 侧）

| 能力 | 命令/机制 | 状态 |
| --- | --- | --- |
| 一次性 token 注册，不落盘 | `wist-agentd enroll --token <token>`（或 `--token-stdin`） | ✅ 已实现 |
| 装服务时一并注册（失败不留半成品） | `service install --system --enrollment-token <token>` | ✅ 已实现 |
| 系统级常驻 + 自启 + 崩溃拉起 | `service install --system`（systemd / launchd） | ✅ 已实现 |
| 配置 / 数据（含采集输出）/ 日志分离 | `[paths]` 与采集输出的默认推导 | ✅ 已实现 |
| 幂等注册、重复执行安全 | 已注册时直接返回 `already enrolled` | ✅ 已实现 |
| 安装脚本 / 包管理 / 网关下发 | `install.sh`、deb/rpm、网关 UI 生成安装指令 | ❌ TODO |

### 3.3 TODO（网关可用前先用“手工过渡做法”）

- [ ] 网关侧：主机授权、一次性 token 生成/回收、安装指令（脚本或包）生成；
- [ ] 安装脚本：下载 + 校验（哈希/签名）、放二进制、`init-config`、`service install --enrollment-token`、自检；
- [ ] 发行形态：deb/rpm/brew 或 tarball（含 systemd unit / launchd plist 的模板，`service print --for <platform>` 已能输出）；
- [ ] 升级通道：网关下发新版本 + 校验 + 重启（当前手工替换二进制，见 §7.3）；
- [ ] 批量/无人值守：`--no-activate` + CM 分发定义文件的编排方式。

### 3.4 过渡做法：手工系统级安装（网关可用前）

等价于“安装脚本会做的事”，逐步执行：

**Linux（systemd）**

```bash
sudo install -m 0755 target/release/wist-agentd target/release/wist-exec /usr/local/bin/
sudo wist-agentd init-config --config-dir /etc/wist-agentd
sudo vi /etc/wist-agentd/agentd.toml          # 填 [control_plane] endpoint；[paths] 不用写（§4.3）
sudo wist-agentd service install --system --enrollment-token <token>
wist-agentd service status --system
systemctl status wist-agentd && journalctl -u wist-agentd -f
```

**macOS（launchd LaunchDaemon）**

```bash
sudo install -m 0755 target/release/wist-agentd target/release/wist-exec /usr/local/bin/
sudo wist-agentd init-config --config-dir /etc/wist-agentd
sudo vi /etc/wist-agentd/agentd.toml
sudo wist-agentd service install --system --enrollment-token <token>
wist-agentd service status --system
launchctl print system/com.dayu-sec.wist-agentd
```

装完的服务自身日志：Linux 进 journald，macOS 进 `/var/log/wist-agentd/agentd.{out,err}`（轮转见 §7.1）。

这套手工步骤的一键版本（含目录落点、崩溃拉起、单实例断言）见 §8 的 `sysrun/verify-system-install.sh`。

## 4. 配置

### 4.1 生成配置

```bash
wist-agentd init-config --config-dir /etc/wist-agentd   # 系统级（需要 sudo）
wist-agentd init-config --config-dir ~/.wist-agentd     # 用户级
wist-agentd init-config                                 # 不给 --config-dir → /etc/wist-agentd
wist-agentd init-config --stdout                        # 只看默认模板，不落盘
```

已存在则不会覆盖，只提示。`--config-dir` 的规则只有两条：**绝对路径原样用，相对路径相对当前工作目录**；
不给就是系统默认目录 `/etc/wist-agentd`（非 root 会得到权限错误，请显式指定或用 `--user`）。

### 4.2 配置目录布局

```
<config-dir>/                        # 配置类（唯一可能放在 /etc 的东西）
  agentd.toml                        # 主配置（可以由 init-config 生成）
  tasks/*.toml                       # 可选：外置的日志采集清单（file_inputs_file 引用）
  agentd.env                         # 可选（仅 Linux systemd）：EnvironmentFile，放长期环境变量
```

`tasks/` 不是 `[paths]` 项，它和 `agentd.toml` 同级，**跟着配置文件走**（相对配置文件所在目录解析）。

### 4.3 配置 / 数据 / 日志默认落点

**放哪里不用手写 `[paths]`**：agentd 按配置目录的位置自动分三类落点。

| 类别 | `/etc/wist-agentd`（系统级部署） | 其它位置（开发机 / `--user`） |
| --- | --- | --- |
| 配置（`agentd.toml`、`tasks/`、`agentd.env`） | `/etc/wist-agentd/` | `<配置目录>/` |
| 数据：运行/状态（`run/`、`state/`） | `/var/lib/wist-agentd/` | `<配置目录>/` |
| 数据：**采集输出**（file sink 默认） | `/var/lib/wist-agentd/data/wist-records.ndjson` | `<配置目录>/data/wist-records.ndjson` |
| 日志（`log_dir`） | **`/var/log/wist-agentd/`** | `<配置目录>/log/` |

规则细节：

- 只填充 `[paths]` 中**未声明**的键（以及未声明的采集输出路径）：显式写的值一律以你为准，不会被静默改写；
- 相对路径相对**配置文件所在目录**解析，绝对路径原样使用；
- **采集输出算数据**（不属于日志）：未声明时跟数据根目录走，即 `<root_dir>/data/`；要指定就写 `[telemetry.logs.output.file] path = "..."`；
- 想把日志放回数据目录：显式写 `log_dir = "log"`；想另行指定：用绝对路径（可带 `${ENV}`）；
- 配置不在 `/etc` 下但想分离数据：显式写 `root_dir = "/var/lib/wist-agentd"`。

系统级部署的默认布局：

```
/etc/wist-agentd/
  agentd.toml                     # 配置（唯一必放的东西）
  tasks/apps.toml                 # 有外置采集清单时：它是配置，跟 agentd.toml 走
  agentd.env                      # 仅 Linux systemd：EnvironmentFile（长期环境变量）

/var/lib/wist-agentd/            # 数据
  run/                            # wist-exec 工作目录
  state/                          # 执行队列、running/reporting/history、checkpoint、
                                  # discovery/metrics 缓存、export/、planner/、spool/logs/
  data/wist-records.ndjson        # 采集输出（file sink 默认）

/var/log/wist-agentd/            # 日志（log_dir）
  agentd.out / agentd.err         # 仅 macOS：launchd 捕获的服务 stdout/stderr
```

Linux 下 agent 自身的运维日志走 journald（`journalctl -u wist-agentd`，存储默认 `/var/log/journal`，自带回收）。

> `/etc/wist-agentd` 需可写（不要挂只读）：目录里没有 `agentd.toml` 时，守护进程会生成一份默认配置。

`init-config` 会把这个提示直接打在输出里：

```
initialized config directory /etc/wist-agentd and wrote config file /etc/wist-agentd/agentd.toml
config dir /etc/wist-agentd is the system location: data (run/state/spool + collected output data/)
defaults to /var/lib/wist-agentd, logs to /var/log/wist-agentd (declare [paths] to override)
```

### 4.4 建议配置（可选微调）

```toml
[agent]
# instance_name = "host-01"           # 留空则自动生成

[control_plane]
enabled = true                        # false = standalone（不连控制面）
endpoint = "https://10.0.1.1"
# enrollment_token 不走配置，见 §4.5（命令行传入）

# [paths] 一般不用写：默认规则见 §4.3。需要时显式覆盖：
# [paths]
# root_dir = "/var/lib/wist-agentd"   # 数据基准（run/state/spool/data 都在它下面）
# log_dir  = "/var/log/wist-agentd"
```

### 4.5 注册 token（一次性，不落盘）

enrollment token 只在注册时用一次，注册成功后即无用（换来的长期凭据在 state 里），所以**不存文件**，
在安装/注册命令里传一次即可：

```bash
# 装服务时一并注册（推荐）
sudo wist-agentd service install --system --enrollment-token <token>

# 或者单独补注册（服务已装好、只想注册）
sudo wist-agentd enroll --token <token>
# 多用户机器别让 token 进 argv/shell history：
echo <token> | sudo wist-agentd enroll --token-stdin
```

行为约定：

- token 只在内存里用一次，**不写任何文件**；`agentd.toml` 一字不改；
- 只有换来的凭据落 `state/agent_runtime.json`（0600）；
- 幂等：已注册后再调（哪怕换个 token）直接返回 `already enrolled (state identity)`，不发请求；
- `service install` 先注册后装服务：注册失败就不写服务定义，不会留下“启动即报错”的半成品；
- 手头暂时没有 token（如让别人代装）：`service install --no-activate` 先落定义，之后补 `enroll`，
  再 `systemctl start wist-agentd` / `launchctl kickstart -k ...`。

### 4.6 环境变量

| 变量 | 作用 | 默认 |
| --- | --- | --- |
| `WARP_INSIGHT_EXEC_BIN` | 覆盖 `wist-exec` 路径 | 同目录 sibling → `PATH` |
| `WIST_AGENTD_LOG_HEARTBEAT_SECS` | 稳态快照心跳间隔（秒）；`0` = 逐轮打印（仅联调） | `300` |
| `WIST_AGENTD_RUN_ONCE` | `1` = 只跑一轮调度就退出（自检用） | 未设置 |

## 5. 运行方式

| 方式 | 开机自启 | 崩溃拉起 | 日志 | 适用 |
| --- | --- | --- | --- | --- |
| 5.1 前台 | ✗ | ✗ | 终端 | 联调 |
| 5.2 `sysrun/start.sh` | ✗ | ✗ | `~/.wist-agentd/log/agentd.out` | 开发机挂着跑 |
| 5.3 `service install --user` | ✓（登录起） | ✓ | journald `--user` / `~/Library/Logs/wist-agentd` | 用户级常驻（开发机/个人机） |
| 5.3 `service install --system` | ✓（开机起） | ✓ | journald / `/var/log/wist-agentd` | **生产常驻** |

> 单实例由 `state/.agentd.lock` 的 `flock` 保证：同一 state 目录下第二个进程会以
> `another wist-agentd instance is already running` 退出（崩溃/kill -9 后锁自动释放，无需手工清理）。
> 切换运行方式前，先停掉旧方式启动的实例。

### 5.1 前台运行

```bash
wist-agentd --config-dir ~/.wist-agentd
```

启动第一行会输出运行上下文，可用来确认版本与路径：

```
wist-agentd 0.1.2 starting: config=/Users/me/.wist-agentd/agentd.toml mode=managed run_dir=... state_dir=... log_dir=...
```

`Ctrl-C` 退出。想看逐轮全量日志：`WIST_AGENTD_LOG_HEARTBEAT_SECS=0 wist-agentd --config-dir ~/.wist-agentd`。

### 5.2 开发机后台（`sysrun/start.sh`）

```bash
cd wist-agentd/sysrun
./start.sh               # 后台 + disown，pid/log 落 ~/.wist-agentd/log/
./start.sh --foreground  # 前台，看日志
./stop.sh
```

可用 `WIST_AGENTD_BIN` / `WIST_AGENTD_CONFIG_DIR` / `WIST_AGENTD_HOME` 覆盖默认路径。该脚本**没有**自启与
崩溃拉起，仅用于开发机。

### 5.3 常驻托管（`service install`）

**macOS — 用户级**（不需要 sudo，登录即起）

```bash
wist-agentd service print   --user --bin ~/bin/wist-agentd          # 先看要装成什么样，不落盘
wist-agentd service install --user --bin ~/bin/wist-agentd          # config-dir 默认 ~/.wist-agentd
wist-agentd service status  --user
launchctl print gui/$(id -u)/com.dayu-sec.wist-agentd
tail -f ~/Library/Logs/wist-agentd/agentd.err
```

**macOS — 系统级**（LaunchDaemon，以 root 运行；读 `/var/log` 受限路径需要）

```bash
sudo wist-agentd init-config --config-dir /etc/wist-agentd
sudo vi /etc/wist-agentd/agentd.toml
sudo wist-agentd service install --system --bin /usr/local/bin/wist-agentd --enrollment-token <token>
wist-agentd service status --system
```

**Linux — 系统级**（systemd）

```bash
sudo wist-agentd init-config --config-dir /etc/wist-agentd
sudo vi /etc/wist-agentd/agentd.toml                                # [paths] 不用写（见 §4.3）
sudo wist-agentd service install --system --bin /usr/local/bin/wist-agentd --enrollment-token <token>
systemctl status wist-agentd
journalctl -u wist-agentd -f
```

**Linux — 用户级**（`systemd --user`）

```bash
wist-agentd init-config --config-dir ~/.wist-agentd
wist-agentd service install --user --bin ~/bin/wist-agentd --enrollment-token <token>
sudo loginctl enable-linger "$USER"      # 不开机登录也要跑
systemctl --user status wist-agentd
journalctl --user -u wist-agentd -f
```

只想写定义文件、自己手动加载（配置管理/发行包场景）：加 `--no-activate`，命令会打印出需要执行的
`systemctl` / `launchctl` 命令。

## 6. `service` 命令参考

```
wist-agentd service print     [--system|--user] [--bin <path>] [--config-dir <path>] [--for <systemd|launchd>]
wist-agentd service install   [--system|--user] [--bin <path>] [--config-dir <path>] [--force] [--no-activate] [--enrollment-token <token>]
wist-agentd service uninstall [--system|--user] [--bin <path>] [--config-dir <path>]
wist-agentd service status    [--system|--user] [--bin <path>] [--config-dir <path>]
wist-agentd enroll            [--token <token> | --token-stdin] [--config-dir <path>]
```

| 参数 | 说明 |
| --- | --- |
| `print` | 只把服务定义（systemd unit / launchd plist）渲染到 stdout，**不读也不写系统** |
| `install` | 写定义文件（launchd 还会创建日志目录），默认随后加载并启动服务 |
| `uninstall` | 先停止并取消托管，再删除定义文件（不删配置/状态目录） |
| `status` | 只读自检：定义、二进制、`wist-exec`、配置、state 目录、**单实例锁**、日志入口 |
| `enroll` | 用一次性 token 注册（`--token` 或 `--token-stdin`）；不落盘、幂等 |
| `--system` | 系统级（**默认**）：`/etc` 路径、root 所有、开机自启 |
| `--user` | 用户级：`systemd --user` / launchd LaunchAgent，以当前用户身份运行 |
| `--bin <path>` | 写入定义里的 `wist-agentd` 路径；默认取当前可执行文件 |
| `--config-dir <path>` | 写入定义里的配置目录；不传时按作用域取默认值（见下表） |
| `--force` | 覆盖已存在的定义（仅 `install`）。**会重建服务进程**，因此升级二进制或改配置后必须用它才能生效 |
| `--no-activate` | 只落盘定义，并打印需要手动执行的加载命令（仅 `install`） |
| `--enrollment-token <token>` | 安装前先用该一次性 token 注册（token 不落盘；注册失败则不写服务定义）（仅 `install`） |
| `--for <systemd\|launchd>` | 为**另一个平台**渲染定义（仅 `print`；例：在 macOS 上生成 Linux 的 unit 交给发行包） |

### 6.1 安装位置

| 作用域 | 平台 | 服务定义 | 默认配置目录 | 数据默认落点（含采集输出） | 日志 |
| --- | --- | --- | --- | --- | --- |
| `--system` | Linux | `/etc/systemd/system/wist-agentd.service` | `/etc/wist-agentd` | `/var/lib/wist-agentd`（采集输出 `/var/lib/wist-agentd/data/wist-records.ndjson`） | `log_dir=/var/log/wist-agentd` + journald（服务自身） |
| `--system` | macOS | `/Library/LaunchDaemons/com.dayu-sec.wist-agentd.plist` | `/etc/wist-agentd` | `/var/lib/wist-agentd`（同上） | `/var/log/wist-agentd/agentd.{out,err}` |
| `--user` | Linux | `~/.config/systemd/user/wist-agentd.service` | `~/.wist-agentd` | 同配置目录 | 同配置目录 + `journalctl --user` |
| `--user` | macOS | `~/Library/LaunchAgents/com.dayu-sec.wist-agentd.plist` | `~/.wist-agentd` | 同配置目录 | 同配置目录 + `~/Library/Logs/wist-agentd/agentd.err` |

落点由配置目录推导（见 §4.3）；`[paths]` 里显式声明的键（含显式指定的采集输出路径）优先。

`install` / `uninstall` / `status` 只针对**本机平台**（定义路径固定）；只有 `print` 支持 `--for` 跨平台渲染。

### 6.2 `status` 输出字段

```
platform=launchd                 # 本机服务管理器
scope=user                       # 作用域
definition=/Users/me/Library/LaunchAgents/com.dayu-sec.wist-agentd.plist
definition_present=true          # 定义文件是否存在
bin=/Users/me/bin/wist-agentd (present)
exec_bin=/Users/me/bin/wist-exec (present)     # 不同目录/缺失会导致启动失败
config=/Users/me/.wist-agentd/agentd.toml (present)
root_dir=/Users/me/.wist-agentd                # 配置解析出的数据落点（系统级安装会是 /var/lib/wist-agentd）
run_dir=/Users/me/.wist-agentd/run
state_dir=/Users/me/.wist-agentd/state
log_dir=/Users/me/.wist-agentd/log
running=true                     # state/.agentd.lock 是否被持有（= 是否真有实例在跑）
logs=tail -f ~/Library/Logs/wist-agentd/agentd.err
check=launchctl print gui/501/com.dayu-sec.wist-agentd
```

`root_dir / run_dir / state_dir / log_dir` 是**配置经解析后的真实绝对路径**（含“/etc → /var/lib”的推导），
配置读不到时全部显示 `-`，`running` 则退化为 `unknown`。

`running` 由 `flock` 探测得出，比 pidfile 可靠：文件存在但无人持锁 = 上次非正常退出留下的空文件，
无需手工清理。

## 7. 日常运维

### 7.1 状态与日志

```bash
wist-agentd version                       # 已部署版本
wist-agentd service status --system       # 只读自检（含真实数据/日志落点）
```

| 平台 | 服务状态 | 日志 |
| --- | --- | --- |
| Linux | `systemctl status wist-agentd` | 服务自身：`journalctl -u wist-agentd -f`；采集输出：`tail -f /var/lib/wist-agentd/data/wist-records.ndjson` |
| macOS | `launchctl print system/com.dayu-sec.wist-agentd` | 服务自身：`tail -f /var/log/wist-agentd/agentd.err`；采集输出：`tail -f /var/lib/wist-agentd/data/wist-records.ndjson` |

日志量说明：常驻循环每 3s 产出的健康/指标快照被收敛为“变化才打印 + 默认 5 分钟一条心跳”。
系统侧轮转兜底：

- Linux：服务自身走 journald（按 `SystemMaxUse` 回收）；采集输出由 logrotate 或上游消费端自行管理。
- macOS：launchd **不会**轮转文件，加 `/etc/newsyslog.d/wist-agentd.conf`：

  ```
  /var/log/wist-agentd/agentd.out   root:wheel  644  7  10240  *  J
  /var/log/wist-agentd/agentd.err   root:wheel  644  7  10240  *  J
  ```

  验证：`sudo newsyslog -nv`（dry-run）。

### 7.2 启动 / 停止 / 重启

| 动作 | Linux | macOS |
| --- | --- | --- |
| 启动 | `systemctl start wist-agentd` | `launchctl kickstart -k system/com.dayu-sec.wist-agentd` |
| 停止 | `systemctl stop wist-agentd` | `launchctl bootout system/com.dayu-sec.wist-agentd` |
| 重启 | `systemctl restart wist-agentd` | `launchctl kickstart -k system/com.dayu-sec.wist-agentd` |
| 是否自启 | `systemctl is-enabled wist-agentd` | plist 在 `LaunchDaemons`/`LaunchAgents` 即自启（`RunAtLoad`） |

用户级同理，命令加 `--user`（systemd）或把 `system/` 换成 `gui/$(id -u)/`（launchd）。

### 7.3 升级与回滚

两个二进制**同时**替换，避免版本错配。推荐直接用 `service install --force` 一并完成「重写定义 + 重建服务进程」：

```bash
sudo install -m 0755 wist-agentd.new /usr/local/bin/wist-agentd
sudo install -m 0755 wist-exec.new   /usr/local/bin/wist-exec
sudo wist-agentd service install --system --force   # Linux: enable + restart；macOS: bootout + bootstrap
wist-agentd version                                  # 核对版本
```

手工等价动作（想自己控制时机时）：

| 动作 | Linux | macOS |
| --- | --- | --- |
| 停止 | `sudo systemctl stop wist-agentd` | `sudo launchctl bootout system/com.dayu-sec.wist-agentd` |
| 启动 | `sudo systemctl start wist-agentd` | `sudo launchctl bootstrap system /Library/LaunchDaemons/com.dayu-sec.wist-agentd.plist` |

- **别用 `systemctl enable --now` 代替 restart**：它在已 active 的 unit 上是 no-op，会让旧进程继续跑旧二进制；
- 执行中的 `ActionPlan` 会在停止时被一并收走（systemd `KillMode=control-group`），未完成的执行由下次启动的
  crash recovery 转成 reporting，不会丢结果上报；
- 回滚：把旧二进制换回并按上表重启。state 是 schema 化 JSON，升级/回退不丢 checkpoint；但不要回退到读不懂新
  schema 的更早版本（损坏的状态会被隔离，不会再执行）。

### 7.4 卸载

```bash
# 停止 + 删除服务定义（系统级需要 sudo）
sudo wist-agentd service uninstall --system    # 用户级：wist-agentd service uninstall --user

# 其余目录按需人工清理（保留数据以便排查/复装）
#   /etc/wist-agentd/        配置与 tasks
#   /var/lib/wist-agentd/    数据：run/ state/ data/
#   /var/log/wist-agentd/    日志：agentd.{out,err}（macOS 系统级）
#   （--user / 开发机安装则全在配置目录下）
```

`uninstall` 只删服务定义，**不会**删除配置、state、日志，这是有意的。

## 8. 验收清单

一键验收（需要 root 的**一次性验收机**，会自动安装→断言→清理）：

```bash
cargo build --release
sudo sysrun/verify-system-install.sh                 # 定义/自启/running/目录落点/采集输出/崩溃拉起/单实例
sudo sysrun/verify-system-install.sh --keep          # 保留安装；重启后：
sudo sysrun/verify-system-install.sh --after-reboot  # 复检“自启 + 仍在跑”
sudo sysrun/verify-system-install.sh --cleanup       # 清理它装的东西
# 非 root 只看将执行的命令：WIST_VERIFY_DRY_RUN=1 sysrun/verify-system-install.sh
```

脚本会轮询等服务/目录/锁就绪（launchd、systemd 都是异步拉起进程），**有 FAIL 时保留现场**并自动 dump
诊断（`service status`、`systemctl cat`/`launchctl print`、日志尾部、目录列表、前台直跑输出）。

手工验收（逐条对照，两种方式通用）：

**Linux**

1. `systemctl is-enabled wist-agentd` = `enabled`；
2. `systemctl status wist-agentd` = `active (running)`，`journalctl -u wist-agentd -n 20` 里有启动行
   （`wist-agentd <version> starting: config=... mode=...`）；
3. `sudo kill -9 $(systemctl show -p MainPID --value wist-agentd)` → 5 秒内被拉起（`RestartSec=5`）；
4. `sudo reboot` 后进程自动回来；
5. `journalctl -u wist-agentd --since '10 min ago' | wc -l` 明显低于逐轮打印量级（≈2.3 行/秒）；空闲主机
   应接近心跳频率；
6. 手动再起一个实例（`wist-agentd --config-dir /etc/wist-agentd`）应以 `already running` 退出，
   且不影响正在运行的实例。

**macOS**

1. `launchctl print system/com.dayu-sec.wist-agentd` 有输出且 `state = running`；
2. `sudo kill -9 <pid>` → 10 秒内被拉起（`ThrottleInterval`）；
3. 重启后自动回来；
4. `/var/log/wist-agentd/agentd.err` 与 `/var/lib/wist-agentd/data/wist-records.ndjson` 有内容，
   `sudo newsyslog -nv` 能看到轮转条目；
5. 同 Linux 第 6 条的单实例验收。

## 9. 排障

| 现象 | 原因 / 处理 |
| --- | --- |
| `another wist-agentd instance is already running (lock file: ...)` | 同一 state 目录已有实例。用 `wist-agentd service status --system`（或 `--user`，看 `running=`）或 `lsof <state>/.agentd.lock` 确认；换运行方式前先停旧实例 |
| 服务启动即退出，报 `no enrollment token available` | 还没注册。`wist-agentd enroll --token <token>`（或 `echo <token> \| wist-agentd enroll --token-stdin`）补注册后重启服务 |
| 服务启动即退出，报 `wist-exec was not found ...` | `wist-exec` 不在同目录、或不在 `PATH`、或没有可执行位。`install -m 0755` 两个一起放，或用 `WARP_INSIGHT_EXEC_BIN` 指定 |
| `install` 提示 `warning: config dir ... does not exist` | 首次启动会自动写默认 `agentd.toml`。建议先 `init-config` 并审阅后再启动 |
| `service install` 报权限错误 | 系统级安装需要 root：写 `/etc/systemd/system/` 或 `/Library/LaunchDaemons/` 会 `Permission denied`。用 `sudo`，或改 `--user` |
| `service install` 报 `launchctl bootstrap` 失败 | 用户级需要已登录的 GUI 会话（domain `gui/<uid>`）；无人登录的后台机请用 `--system` |
| 采不到 `/var/log/xxx` | 权限不足：系统级安装（root）或给二进制授予 Full Disk Access；失败会体现为输入读取失败/暂停 |
| `service install` 提示定义已存在 | 加 `--force` 覆盖；先 `wist-agentd service print` 对比差异 |
| 磁盘被日志吃满 | 调大 `WIST_AGENTD_LOG_HEARTBEAT_SECS`（默认 300s），并确认 macOS 已配 newsyslog / Linux 用 journald |
| 配置或数据写不进去（`Permission denied`） | 系统级部署要 root：配置 `/etc/wist-agentd`、数据 `/var/lib/wist-agentd`、日志 `/var/log/wist-agentd`。非 root 开发请把配置放到非 `/etc` 路径（数据/日志就地，见 §2），或用 `--user` |
| 不确定数据写到哪了 | 看启动行的 `run_dir= / state_dir= / log_dir=`（解析后的绝对路径），或 `wist-agentd service status` 的 `root_dir/run_dir/state_dir/log_dir` |
| 想确认跑的是哪份配置/版本 | 启动行 `wist-agentd <version> starting: config=... mode=...`；`wist-agentd service status` 看 `config=` |

## 10. 相关文档

- [agentd-service-deployment.md](./agentd-service-deployment.md) — 设计说明（服务托管取舍、配置/数据/日志分离理由、日志收敛原理、已知限制）
- [agent-config-schema.md](./agent-config-schema.md) — `agentd.toml` 全量字段
- [agentd-architecture.md](./agentd-architecture.md) — 模块边界与运行模型
- [agentd-failure-handling.md](./agentd-failure-handling.md) — 崩溃恢复与失败隔离
- [log-file-input-spec.md](./log-file-input-spec.md) — 日志文件采集（tail/checkpoint/轮转）
