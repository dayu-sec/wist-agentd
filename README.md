# wist-agentd

Edge daemon (controller) for the **wist** agent runtime.

[![CI](https://github.com/dayu-sec/wist-agentd/actions/workflows/build-and-test.yml/badge.svg)](https://github.com/dayu-sec/wist-agentd/actions/workflows/build-and-test.yml)
[![codecov](https://codecov.io/gh/dayu-sec/wist-agentd/branch/main/graph/badge.svg)](https://codecov.io/gh/dayu-sec/wist-agentd)
[![dependency status](https://deps.rs/repo/github/dayu-sec/wist-agentd/status.svg)](https://deps.rs/repo/github/dayu-sec/wist-agentd)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

`wist-agentd` is a long-running agent that runs on each managed host. It is the **controller**,
not the executor: it receives `ActionPlan`s from a control plane, validates and queues them
locally, then spawns and supervises the bundled [`wist-exec`](src/bin/wist-exec) binary to
actually run each plan. Alongside that, it discovers local resources, tails log files, samples
host/process metrics, and reports status, health, and execution results back upstream.

## 中文

`wist-agentd` 是运行在每台被管主机上的常驻 Agent 守护进程，定位是**控制器**而非执行器：它从控制面接收 `ActionPlan`，在本地校验并排队，然后拉起并监督内置的 [`wist-exec`](src/bin/wist-exec) 二进制去真正执行每个计划。同时，它还会发现本地资源、tail 日志文件、采集主机/进程指标，并把状态、健康度与执行结果上报给上游。

### 功能

- **ActionPlan 执行控制** — 本地队列、并发上限、超时 / 取消 / 强杀、失败执行隔离、崩溃恢复。
- **内置执行器** — `wist-exec` 与守护进程同 crate 构建，二者始终一起发布、一起版本化。
- **本地资源发现** — 主机、网络、端点、进程、容器探针。
- **日志采集** — 文件 tail + checkpoint 持久化、spool、背压。
- **指标采样** — 主机与进程运行时指标。
- **注册（Enrollment）** — 向控制面注册并轮换凭据。
- **上报与自观测** — 聚合执行结果，输出健康/状态快照。
- **运行模式** — `standalone`（无控制面）与 `managed`。

### 组件关系

| 组件            | 职责                                             |
| --------------- | ------------------------------------------------ |
| `wist-agentd`   | 边缘控制器（本 crate 的守护进程二进制）。           |
| `wist-exec`     | 执行器子进程（内置 `[[bin]]`）。                  |

守护进程与执行器通过本地文件协议通信：守护进程准备好工作目录（`plan.json` / `runtime.json`），拉起 `wist-exec`，再读回状态与结果文件。详见 [`docs/agentd-exec-protocol.md`](docs/agentd-exec-protocol.md)。

### 运行模式

`agentd` 自身**只前台运行**，常驻/自启/崩溃拉起交给 OS 服务管理器。**[安装与使用手册](docs/agentd-install-and-usage.md)**
按安装方式组织：**方式一 开发环境安装**（本地构建、免 sudo、数据日志就地）、**方式二 通过 Wist-Gateway 安装**
（控制面下发，TODO）；配置/运行方式/命令参考/升级/验收/排障两者通用。设计取舍见
[后台长期运行方案](docs/agentd-service-deployment.md)。

```bash
# 长期后台运行（Linux systemd / macOS launchd；Linux 需 sudo，macOS 可加 --user）
# 注册 token 一次性传入、不落盘（先注册再装服务，注册失败不会留下半成品服务）
sudo wist-agentd service install --system --enrollment-token <token>

# 已经装好但还没注册，可以单独补注册：
sudo wist-agentd enroll --token <token>          # 或 echo <token> | sudo wist-agentd enroll --token-stdin

# 只看不装：把 unit / plist 渲染到 stdout
wist-agentd service print --system

# 自检：定义 / 二进制 / 配置 / 单实例锁 / 数据与日志落点
wist-agentd service status --system
```

开发机联调：[`sysrun/start.sh`](sysrun/start.sh)（`&` + `disown`，非生产）。

### 快速开始

```bash
cargo run -- init-config --config-dir ./wist-agentd
cargo run -- --config-dir ./wist-agentd
```

或使用编译出的二进制并指定配置目录：

```bash
wist-agentd --config-dir /etc/wist-agentd
```

### 配置

由配置目录下的 `agentd.toml` 驱动，主要段：`[agent]`（实例名/身份）、`[control_plane]`（网关端点、TLS 模式、注册 token）、`[telemetry.logs]`（日志输入、缓冲、spool、输出）、`[paths]`（root / run / state / log 目录）。

`[paths]` 不用手写：配置位于 `/etc/wist-agentd`（系统级部署）时 `/etc` 只放配置，数据（`run/state/spool`
与采集输出 `data/`）自动落到 `/var/lib/wist-agentd`、日志落到 `/var/log/wist-agentd`；开发机或 `--user`
安装则配置/数据/日志全部就地放在配置目录下。显式声明的键优先。

## Features

- **ActionPlan execution control** — local queue, concurrency limits, timeout / cancel /
  force-kill, quarantine of failed executions, and crash recovery.
- **Bundled executor** — `wist-exec` is built from the same crate, so the daemon and its
  executor always ship and version together.
- **Local resource discovery** — host, network, endpoint, process, and container probes.
- **Log collection** — file tailing with checkpoint persistence, spooling, and backpressure.
- **Metrics sampling** — host and process runtime metrics.
- **Enrollment** — registers with the control plane and rotates credentials.
- **Reporting & self-observability** — aggregates execution results and emits health/state
  snapshots.
- **Run modes** — `standalone` (no control plane) and `managed`.

## How the pieces fit

| Component     | Role                                          |
| ------------- | --------------------------------------------- |
| `wist-agentd` | Edge controller (this crate's daemon binary). |
| `wist-exec`   | Executor child process (bundled `[[bin]]`).   |

The daemon and executor speak a local, file-based protocol: the daemon prepares a work
directory (`plan.json` / `runtime.json`), spawns `wist-exec`, and reads back the status and
result files. See [`docs/agentd-exec-protocol.md`](docs/agentd-exec-protocol.md) for details.

## Requirements

- Rust **1.85+** (edition 2024)
- Linux or macOS (uses `libc` and `sysinfo`)

## Building

```bash
cargo build --release
```

This produces two binaries in `target/release/`:

- `wist-agentd` — the daemon
- `wist-exec` — the bundled executor

## Quick start

Generate a default config, then run the daemon:

```bash
cargo run -- init-config --config-dir ./wist-agentd
cargo run -- --config-dir ./wist-agentd
```

Or use the built binary with an explicit config directory:

```bash
wist-agentd --config-dir /etc/wist-agentd
```

## Command-line

```
Usage:
  wist-agentd [--config-dir <path>]
  wist-agentd help
  wist-agentd version
  wist-agentd init-config [--stdout] [--config-dir <path>]
  wist-agentd service <print|install|uninstall|status> [--system|--user] [--bin <path>] [--force] [--no-activate] [--config-dir <path>]
  wist-agentd service print --for <systemd|launchd>   (render for another platform)
  wist-agentd enroll [--token <token> | --token-stdin] [--config-dir <path>]

Commands:
  help                 Show this help message.
  version              Print the daemon version.
  init-config          Initialize config directory wist-agentd/ and write agentd.toml.
  init-config --stdout Print the default config template to stdout.
  service print        Print the systemd unit / launchd plist without touching the system.
  service install      Write the service definition and (unless --no-activate) load and start it.
  service uninstall    Stop the service and remove its definition.
  service status       Show definition / binary / config / lock / log status.
  enroll               Enroll with a one-time token; the token is never written to disk.

Service options (Linux uses systemd, macOS uses launchd):
  --system             Install for the whole host (default; /etc paths, root-owned).
  --user               Install for the current user (systemd --user / launchd LaunchAgent).
  --bin <path>         Installed path of the wist-agentd binary (default: current executable).
  --for <platform>     Only with `service print`: render systemd or launchd output.
  --force              Overwrite an existing service definition.
  --no-activate        Only write the definition; print the commands to load it yourself.
  --enrollment-token <token>  Only with `service install`: enroll first (token not persisted).

Enroll options:
  --token <token>      One-time enrollment token (visible in argv/ps for the run).
  --token-stdin        Read the token from stdin instead (recommended on shared hosts).

Options:
  --config-dir <path>  Use the specified config directory. Relative paths are resolved from the current working directory.
                       Default: /etc/wist-agentd.
```

## Long-running deployment

`wist-agentd` runs in the foreground by design; keeping it alive across logouts, crashes,
and reboots is delegated to the OS service manager:

- **Linux** — systemd unit at `/etc/systemd/system/wist-agentd.service` (or
  `~/.config/systemd/user/` with `--user`), `Restart=always`, logs to journald.
- **macOS** — launchd plist at `/Library/LaunchDaemons/com.dayu-sec.wist-agentd.plist` (or
  `~/Library/LaunchAgents/` with `--user`), `KeepAlive`, logs to `/var/log/wist-agentd/`
  (`~/Library/Logs/wist-agentd/` with `--user`, where a non-root daemon cannot write `/var/log`).

See [`docs/agentd-install-and-usage.md`](docs/agentd-install-and-usage.md) for the install and
operations manual — organized by install path: **dev environment install** (local, no sudo) and
**install via Wist-Gateway** (control-plane driven, TODO), followed by configuration, run modes,
the `service` command reference, upgrades, acceptance checks and troubleshooting. See
[`docs/agentd-service-deployment.md`](docs/agentd-service-deployment.md) for the design rationale. Duplicate instances are rejected by the flock in the state directory, and the
periodic health/metrics snapshots are collapsed to change-only output plus a heartbeat
(`WIST_AGENTD_LOG_HEARTBEAT_SECS`, default 300s) so a long-running daemon cannot fill the disk.

## Configuration

`wist-agentd` is configured by an `agentd.toml` file in the config directory. The main
sections:

- `[agent]` — instance name / identity.
- `[control_plane]` — gateway endpoint, TLS mode, and enrollment token.
- `[telemetry.logs]` — log file inputs, buffer, spool, and output sink.
- `[paths]` — root / run / state / log directories. Defaults follow the config location: a config in
  `/etc/wist-agentd` (system install) keeps only configuration there, puts data (`run/state/spool` and
  the collected output `data/wist-records.ndjson`) under `/var/lib/wist-agentd` and logs under
  `/var/log/wist-agentd`; elsewhere (dev box, `--user`) config, data and logs stay together next to
  the config file. Any key you declare explicitly wins.

Ready-to-run examples live under [`examples/`](examples):

- [`examples/macos-p0-agentd.toml`](examples/macos-p0-agentd.toml) — macOS P0 log collection.
- [`examples/local-p0-agentd.toml`](examples/local-p0-agentd.toml) — local verification run.

## Environment variables

- `WARP_INSIGHT_EXEC_BIN` — override the path to the `wist-exec` binary. By default it resolves
  to the sibling binary next to the `wist-agentd` executable, then `wist-exec` on `PATH`.
- `WIST_AGENTD_LOG_HEARTBEAT_SECS` — heartbeat (seconds) for the steady-state health/metrics
  lines; `0` disables collapsing and prints every tick (debugging only). Default `300`.
- `WIST_AGENTD_RUN_ONCE=1` — run a single scheduler tick and exit (used by tests/ops checks).

## Repository layout

```
src/
  bin/wist-exec/    # bundled executor binary
  bootstrap/        # runtime directory initialization
  config/           # config loading and env expansion
  control/          # daemon entry, enrollment, capability report
  discovery/        # host / network / endpoint / process / container probes
  exec/             # execution controller, process control, quarantine, recovery
  reporting/        # result aggregation and upstream reporting
  runtime/          # daemon loop, scheduler, self-observability
  service/          # systemd / launchd definitions, install & status
  state_store/      # on-disk state (queue, running, reporting, history, checkpoints)
  telemetry/        # log file tailing and metrics sampling
examples/           # example agentd.toml configs
docs/               # design documentation
```

## Documentation

- [`docs/agentd-install-and-usage.md`](docs/agentd-install-and-usage.md) — install & operations
  manual (how to install, configure, run, upgrade, troubleshoot).
- [`docs/agentd-service-deployment.md`](docs/agentd-service-deployment.md) — long-running
  service design rationale (systemd / launchd).
- [`docs/agentd-architecture.md`](docs/agentd-architecture.md) — module boundaries and state model.
- [`docs/agentd-exec-protocol.md`](docs/agentd-exec-protocol.md) — the `wist-exec` local protocol.
- [`docs/agent-config-schema.md`](docs/agent-config-schema.md) — the `agentd.toml` schema.

## License

[Apache-2.0](LICENSE)
