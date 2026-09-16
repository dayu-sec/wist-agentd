# wist-agentd 设计文档

wist-agentd（edge daemon）实现时最重要的设计文档。

> **位置约定**：agentd 专属设计文档在本目录维护（crate 就近阅读入口），不在其他位置维护副本。

## 阅读顺序建议

0. [development-plan.md](./development-plan.md) — 开发计划（当前差距 → 批次落地 → 验收标准）
1. [agentd-install-and-usage.md](./agentd-install-and-usage.md) — **安装与使用手册**（两种安装方式：开发环境 / 通过 Wist-Gateway（TODO）；配置、运行方式、命令参考、运维、验收、排障）
2. [agentd-architecture.md](./agentd-architecture.md) — daemon 总体架构与边界
3. [agentd-state-and-boundaries.md](./agentd-state-and-boundaries.md) — 状态与边界
4. [agentd-state-schema.md](./agentd-state-schema.md) — 本地状态 schema
5. [agentd-failure-handling.md](./agentd-failure-handling.md) — 故障处理
6. [agentd-exec-protocol.md](./agentd-exec-protocol.md) — 本地执行协议（配合 `src/exec/`）
7. [agent-config-schema.md](./agent-config-schema.md) — 配置 schema（配合 `src/config/`）
8. [self-observability.md](./self-observability.md) — 自观测（配合 `src/runtime/self_observability.rs`）
9. [agentd-service-deployment.md](./agentd-service-deployment.md) — 后台长期运行方案（设计说明；配合 `src/service/`）

## 日志 / telemetry 采集（配合 `src/telemetry/logs/files/`）

- [log-file-input-spec.md](./log-file-input-spec.md) — 文件日志输入规格（checkpoint/tail/rotate）
- [log-file-state-schema.md](./log-file-state-schema.md) — 文件日志 checkpoint 状态 schema
- [macos-agent-uplink-to-warp-parse.md](./macos-agent-uplink-to-warp-parse.md) — macOS P0 采集端到端方案
- [macos-security-audit-log-sources.md](./macos-security-audit-log-sources.md) — macOS 安全/审计日志源清单

## 模块对照（src 目录化后）

| 域 | 相关文档 |
|---|---|
| `src/bootstrap` | agentd-state-and-boundaries |
| `src/config` | agent-config-schema |
| `src/exec` | agentd-exec-protocol、agentd-failure-handling |
| `src/runtime` | agentd-architecture、self-observability |
| `src/service` | agentd-install-and-usage、agentd-service-deployment |
| `src/telemetry` | log-file-input-spec、log-file-state-schema、macos-* |
