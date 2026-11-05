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
9. [agentd-investigation.md](./agentd-investigation.md) — 一次性调查 `investigate`（题目模型 / 磁盘证据 / 扫描边界 / 命令 seam；配合 `src/investigate*.rs`）
10. [metrics-data-spec.md](./metrics-data-spec.md) — 指标数据规范（草案；配合 `src/telemetry/metrics/`）

> 面向运维的安装/使用/排障手册不在本目录，在 [`../usage/`](../usage/README.md)：
> [agentd-install-and-usage.md](../usage/agentd-install-and-usage.md)（安装与使用手册）、
> [README.md](../usage/README.md)（使用帮助：常见问题处理）。

## 指标采集（配合 `src/telemetry/metrics/`）

- [metrics-collection-runtime.md](./metrics-collection-runtime.md) — **采集运行时**：统一调度 + `enum Collector` + async/blocking 双执行器（**P0/P0.5 已落地**：主机三域 + Kafka；**P1 已落地**：MySQL / TiDB）
- [mysql-metrics.md](./mysql-metrics.md) — MySQL / TiDB 指标采集：P0 指标子集 / `sqlx` 连接与凭据 / 自探证据层与握手 / 失败表现
- [pg-metrics.md](./pg-metrics.md) — PostgreSQL 指标采集：与 MySQL 共用运行时与凭据规则，只换了 SQL / 握手 / 指标
- [doris-metrics.md](./doris-metrics.md) — Doris 指标采集（P0：BE 存活/容量/tablet）：只从本机 FE 读 `SHOW BACKENDS`，能力边界与凭据
- [metrics-data-spec.md](./metrics-data-spec.md) — 指标数据规范（v1 草案：命名/单位/类型/身份/选择类 label/主机身份 info 指标（`system_host_info`）/常见系统取值/投递语义与决策记录）
- [kafka-sasl-implementation.md](./kafka-sasl-implementation.md) — Kafka 探针的 SASL/TLS 实现交接（协议顺序 / SCRAM 步骤 / 测试清单）
- [metrics-selection-labels.md](./metrics-selection-labels.md) — 选择类 label 的下发与刷新（网关三层来源 / agent 拉取与缓存 / 手工刷新命令面 / 管理面补发入口 P4）
- [metrics-spec-rollout.md](./metrics-spec-rollout.md) — 上述规范的落地计划（工作包 / 分支策略 / 切换策略 / 验收）

## 日志 / telemetry 采集（配合 `src/telemetry/logs/files/`）

- [log-file-input-spec.md](./log-file-input-spec.md) — 文件日志输入规格（checkpoint/tail/rotate）
- [log-source-exporters.md](./log-source-exporters.md) — 定时导出器（`Exporter` 采集来源）设计（journald/smartctl/nft/dmesg…）
- [log-file-state-schema.md](./log-file-state-schema.md) — 文件日志 checkpoint 状态 schema
- [suricata-eve-collection.md](./suricata-eve-collection.md) — 流量镜像与 Suricata `eve.json` 采集（形态/吞吐/容量/控制面落点）
- [macos-agent-uplink-to-warp-parse.md](./macos-agent-uplink-to-warp-parse.md) — macOS P0 采集端到端方案
- [macos-security-audit-log-sources.md](./macos-security-audit-log-sources.md) — macOS 安全/审计日志源清单
- [linux-security-audit-log-sources.md](./linux-security-audit-log-sources.md) — Linux 采集源清单（计算/数据服务器；**未核对**，规则/样本为零）

## 模块对照（src 目录化后）

| 域 | 相关文档 |
|---|---|
| `src/bootstrap` | agentd-state-and-boundaries |
| `src/config` | agent-config-schema |
| `src/exec` | agentd-exec-protocol、agentd-failure-handling |
| `src/investigate*` | agentd-investigation |
| `src/runtime` | agentd-architecture、self-observability |
| `src/service` | agentd-service-deployment（设计）＋ `../usage/agentd-install-and-usage`（安装/运维） |
| `src/telemetry` | metrics-data-spec、log-file-input-spec、log-file-state-schema、macos-*、linux-* |
