# wist-agentd

Edge daemon (controller) for the **wist** agent runtime.

[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)
[![MSRV](https://img.shields.io/badge/rustc-1.85+-orange.svg)](#)

`wist-agentd` is a long-running agent that runs on each managed host. It is the **controller**,
not the executor: it receives `ActionPlan`s from a control plane, validates and queues them
locally, then spawns and supervises the bundled [`wist-exec`](src/bin/wist-exec) binary to
actually run each plan. Alongside that, it discovers local resources, tails log files, samples
host/process metrics, and reports status, health, and execution results back upstream.

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
  wist-agentd init-config [--stdout] [--config-dir <path>]

Commands:
  help                 Show this help message.
  init-config          Initialize config directory wist-agentd/ and write agentd.toml.
  init-config --stdout Print the default config template to stdout.

Options:
  --config-dir <path>  Use the specified config directory. Relative paths are resolved
                       from the current working directory.
```

## Configuration

`wist-agentd` is configured by an `agentd.toml` file in the config directory. The main
sections:

- `[agent]` — instance name / identity.
- `[control_plane]` — gateway endpoint, TLS mode, and enrollment token.
- `[telemetry.logs]` — log file inputs, buffer, spool, and output sink.
- `[paths]` — root / run / state / log directories.

Ready-to-run examples live under [`examples/`](examples):

- [`examples/macos-p0-agentd.toml`](examples/macos-p0-agentd.toml) — macOS P0 log collection.
- [`examples/local-p0-agentd.toml`](examples/local-p0-agentd.toml) — local verification run.

## Environment variables

- `WARP_INSIGHT_EXEC_BIN` — override the path to the `wist-exec` binary. By default it resolves
  to the sibling binary next to the `wist-agentd` executable, then `wist-exec` on `PATH`.

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
  state_store/      # on-disk state (queue, running, reporting, history, checkpoints)
  telemetry/        # log file tailing and metrics sampling
examples/           # example agentd.toml configs
docs/               # design documentation
```

## Related crates

- [`wist-contracts`](../wist-contracts) — shared contract and schema types.
- [`wist-shared`](../wist-shared) — shared helpers (fs, ids, paths, time).
- [`wist-metrics`](../wist-metrics) — metrics runtime model.
- [`wist-validate`](../wist-validate) — static validators.

## Documentation

- [`docs/agentd-architecture.md`](docs/agentd-architecture.md) — module boundaries and state model.
- [`docs/agentd-exec-protocol.md`](docs/agentd-exec-protocol.md) — the `wist-exec` local protocol.
- [`docs/agent-config-schema.md`](docs/agent-config-schema.md) — the `agentd.toml` schema.

## License

[Apache-2.0](LICENSE)
