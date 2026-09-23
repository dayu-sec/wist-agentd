# wist-agentd 设计文档

wist-agentd（edge daemon）实现时最重要的设计文档。

> **位置约定**：agentd 专属设计文档在本目录维护（crate 就近阅读入口），不在其他位置维护副本。

## 阅读顺序建议

0. [development-plan.md](./development-plan.md) — 开发计划（当前差距 → 批次落地 → 验收标准）
1. [agentd-architecture.md](./agentd-architecture.md) — daemon 总体架构与边界
2. [agentd-state-and-boundaries.md](./agentd-state-and-boundaries.md) — 状态与边界
3. [agentd-state-schema.md](./agentd-state-schema.md) — 本地状态 schema
4. [agentd-failure-handling.md](./agentd-failure-handling.md) — 故障处理
5. [agentd-exec-protocol.md](./agentd-exec-protocol.md) — 本地执行协议（配合 `src/exec/`）
6. [agent-config-schema.md](./agent-config-schema.md) — 配置 schema（配合 `src/config/`）
7. [self-observability.md](./self-observability.md) — 自观测（配合 `src/runtime/self_observability.rs`）
8. [agentd-service-deployment.md](./agentd-service-deployment.md) — 后台长期运行方案（设计说明；配合 `src/service/`）

> 面向运维的安装/使用/排障手册不在本目录，在 [`../usage/`](../usage/README.md)：
> [agentd-install-and-usage.md](../usage/agentd-install-and-usage.md)（安装与使用手册）、
> [README.md](../usage/README.md)（使用帮助：常见问题处理）。

## 日志 / telemetry 采集（配合 `src/telemetry/logs/files/`）

- [log-file-input-spec.md](./log-file-input-spec.md) — 文件日志输入规格（checkpoint/tail/rotate）
- [log-file-state-schema.md](./log-file-state-schema.md) — 文件日志 checkpoint 状态 schema
- [macos-agent-uplink-to-warp-parse.md](./macos-agent-uplink-to-warp-parse.md) — macOS P0 采集端到端方案
- [macos-security-audit-log-sources.md](./macos-security-audit-log-sources.md) — macOS 安全/审计日志源清单
- [linux-security-audit-log-sources.md](./linux-security-audit-log-sources.md) — Linux 采集源清单（计算/数据服务器；**未核对**，规则/样本为零）

## 模块对照（src 目录化后）

| 域 | 相关文档 |
|---|---|
| `src/bootstrap` | agentd-state-and-boundaries |
| `src/config` | agent-config-schema |
| `src/exec` | agentd-exec-protocol、agentd-failure-handling |
| `src/runtime` | agentd-architecture、self-observability |
| `src/service` | agentd-service-deployment（设计）＋ `../usage/agentd-install-and-usage`（安装/运维） |
| `src/telemetry` | log-file-input-spec、log-file-state-schema、macos-*、linux-* |
