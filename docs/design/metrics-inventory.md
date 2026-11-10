# 指标采集清单（当前实现）

> 用途：一眼看清 agentd **现在**采什么、多久采一次、带哪些 label、什么情况下不出值。
>
> **规范性定义只维护两处**：[`metrics-data-spec.md`](./metrics-data-spec.md) §10（主机 / 进程 / 容器 / agent 自观测）
> 与 `wist-metrics` 的 `METRIC_SPECS`（含 Kafka / MySQL / PG / Doris）。本文是**运行态快照**，
> 新增或改名时请同步这三处，避免文档与注册表漂移。
>
> 对应版本：`wist-agentd 0.31.1-alpha` / `wist-metrics 0.18.0`。

## 1. 采集与上送

| 项 | 当前值 |
|---|---|
| 主机三域采集周期 | **3s**（`scheduler::HOST_ROUND_INTERVAL`） |
| 指标上送周期 | 由网关 `collect_metrics` 授权下发，缺省 **15s**（`DEFAULT_METRICS_UPLINK_SECONDS`） |
| 样本时间 | 本轮采集完成时刻（UTC，毫秒）；不是发送时刻 |
| 序列身份 | `(name, agent, instance)` + 按需 label；选择类 label（`env` / `cluster` / …）由控制面下发 |
| `tenant_id` | **不由 agentd 写入**；下游按业务单元附加 |
| 前提 | 发现层产出采集目标 + 指标采集授权 + 上送通道启用；缺一不产生指标帧 |

每个上送步取最近一轮采集结果；`system_cpu_usage_ratio` 的值本身是最近 **60s** 窗口的派生量。

## 2. 主机域（`system_*`）

### 2.1 CPU / 负载

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `system_cpu_seconds_total` | counter_f64 | s | `cpu`,`mode` | 逐核逐 mode 的累计秒（`user` / `nice` / `system` / `idle` / `iowait` / `irq` / `softirq` / `steal`）；权威源 |
| `system_cpu_usage_ratio` | gauge_f64 | 1 | — | **整机**使用率 0–1：`1 - idle 增量 / (经过时间 × 核数)`，60s 窗口 |
| `system_load_average_1m` | gauge_f64 | 1 | — | 1 分钟负载 |
| `system_load_average_5m` | gauge_f64 | 1 | — | 5 分钟负载 |
| `system_load_average_15m` | gauge_f64 | 1 | — | 15 分钟负载 |

### 2.2 内存

| 指标 | 类型 | 单位 | 说明 |
|---|---|---|---|
| `system_memory_total_bytes` | gauge_i64 | By | 物理内存总量 |
| `system_memory_available_bytes` | gauge_i64 | By | 可用内存 |
| `system_memory_usage_ratio` | gauge_f64 | 1 | 使用率 0–1 |
| `system_memory_swap_total_bytes` | gauge_i64 | By | **仅在配置了 swap 时上报** |
| `system_memory_swap_free_bytes` | gauge_i64 | By | 同上 |

### 2.3 磁盘容量（角色汇总）

| 指标 | 类型 | 单位 | 常量 label | 说明 |
|---|---|---|---|---|
| `system_disk_usage_ratio` | gauge_f64 | 1 | `disk_role`（`system` / `data`） | 角色汇总使用率 |
| `system_disk_total_bytes` | gauge_i64 | By | 同上 | 角色汇总容量 |
| `system_disk_available_bytes` | gauge_i64 | By | 同上 | 角色汇总可用量 |
| `system_disk_mounts` | gauge_i64 | 1 | `disk_role=data` | 数据盘挂载点数 |

- Linux：`system` = 根文件系统 `/`；`data` = 其余本地块设备挂载点（同一设备 bind mount 只算一次）。
- macOS / 其它 Unix：只报主盘（macOS 优先 Data 卷，回落 `/`）为 `system`，不产生 `data` 系列。

### 2.4 块设备 I/O

| 指标 | 类型 | 单位 | label |
|---|---|---|---|
| `system_disk_read_bytes_total` | counter_i64 | By | `device` |
| `system_disk_written_bytes_total` | counter_i64 | By | `device` |
| `system_disk_reads_total` | counter_i64 | 1 | `device` |
| `system_disk_writes_total` | counter_i64 | 1 | `device` |
| `system_disk_io_time_seconds_total` | counter_f64 | s | `device` |

### 2.5 文件系统（逐挂载点）

| 指标 | 类型 | 单位 | label |
|---|---|---|---|
| `system_filesystem_usage_ratio` | gauge_f64 | 1 | `mountpoint`,`fstype` |
| `system_filesystem_total_bytes` | gauge_i64 | By | `mountpoint`,`fstype` |
| `system_filesystem_available_bytes` | gauge_i64 | By | `mountpoint`,`fstype` |
| `system_filesystem_inodes` | gauge_i64 | 1 | `mountpoint`,`fstype` |
| `system_filesystem_inodes_free` | gauge_i64 | 1 | `mountpoint`,`fstype` |

网络 / 伪文件系统（`nfs` / `fuse*` / `proc` / `sysfs` / `cgroup*` 等）被过滤，不进序列；inode 数拿不到时
只缺这两条，不补 0。

### 2.6 身份与运行时长

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `system_uptime_seconds` | gauge_f64 | s | — | 开机时长 |
| `system_host_info` | gauge_i64 | 1 | `host_name`,`host_ip`,`os`,`arch`,`kernel` | 值恒为 1；主机可读身份**只**在这条序列上 |

### 2.7 条件与边界

- **不补 0**：拿不到的读数直接不发（swap 未配置、inode 不可用、数据盘不存在都属此类）。
- `system_cpu_usage_ratio` 需要窗口内至少两个采样点；以下情况**不出值**：
  首轮、idle 计数器回退（重启 / 热插拔）、核数变化、读数非法。
- 内存总量未知时不发 `system_memory_usage_ratio`（避免伪造「很空」）。
- 主机身份（`host_name` / `host_ip` / `os` / `arch` / `kernel`）**不得**出现在测量序列上，
  否则改名 / 换 IP / 升级内核会把历史切断。

## 3. agent 自观测（`agent_*`）

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `agent_memory_bytes` | gauge_i64 | By | — | agent 进程常驻内存 |
| `agent_cpu_ratio` | gauge_f64 | 1 | — | **agent 进程自身** CPU，单核口径（`1.0` = 占满一个核，可 > 1） |
| `agent_cpu_cores` | gauge_i64 | 1 | — | 逻辑核数（把单核口径换算成整机占比的分母） |
| `agent_admin_latency_seconds` | gauge_f64 | s | — | 最近一次成功的管理面交互耗时 |
| `agent_discovery_policy_version` | gauge_i64 | 1 | — | 已生效的发现策略版本（阶标，不进趋势） |
| `agent_uplink_metrics_failed_total` | counter_i64 | 1 | — | 指标上送失败累计（进程生命周期内） |
| `agent_collect_targets` | gauge_i64 | 1 | `target_kind`,`outcome` | 每批按目标类型 × 结果的目标数（`dropped` 也记账） |

`agent_*` 的 `instance` 与主机指标一致（host resource id），可直接与 `system_host_info` 关联。
这**不改变**测量对象：它们仍然描述 agent 自己。

### 3.1 `agent_cpu_ratio` 与 `system_cpu_usage_ratio` 的区别

| | `agent_cpu_ratio` | `system_cpu_usage_ratio` |
|---|---|---|
| 测量对象 | **agent 进程自身** | **主机整机** |
| 数据源 | `/proc/self/stat`（Linux）/ `getrusage(RUSAGE_SELF)`（macOS） | `/proc/stat` 各核 idle（Linux）/ `host_processor_info`（macOS） |
| 口径 | 单核比例，可 > 1 | 0–1 的整机比例 |
| 窗口 | 相邻两次读数的间隔 | 60s 滑动窗口 |

```promql
# agent 进程占整机的比例（0–1）
agent_cpu_ratio / agent_cpu_cores

# 主机整机使用率（0–1）——不要用 agent_cpu_ratio 代替
system_cpu_usage_ratio
```

## 4. 进程与容器

### 4.1 进程（`process_*`，`collection_kind=process_metrics`）

身份：`instance = <host>:proc:<identity>`（可执行文件 + 启动时间，**不含 PID**）。

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `process_memory_rss_bytes` | gauge_i64 | By | — | 常驻内存 |
| `process_cpu_seconds_total` | counter_f64 | s | — | 进程累计 CPU 秒 |
| `process_state` | gauge_i64 | 1 | `state` | 一热：状态进 label，值恒为 1 |
| `process_pid` | gauge_i64 | 1 | — | 当前 PID（只作值，不作 label） |

### 4.2 容器（`container_*`，`collection_kind=container_metrics`）

身份：`instance = <host>:ctr:<container_id>`（cgroup 口径）。

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `container_memory_rss_bytes` | gauge_i64 | By | — | 容器内存 |
| `container_cpu_seconds_total` | counter_f64 | s | — | 容器累计 CPU 秒 |
| `container_state` | gauge_i64 | 1 | `state` | 一热：状态进 label，值恒为 1 |
| `container_pid` | gauge_i64 | 1 | — | 主进程 PID（只作值） |

## 5. Kafka（`kafka_*`，`collection_kind=kafka_broker_metrics`）

- **身份**：broker 级 `instance = kafka:<cluster>:<node_id>`；集群级 `instance = kafka:<cluster>`（离线分区、消费组读数）。
- **周期**：拓扑 / 分区 / 容量 / 组状态 **30s**（`[kafka] interval_ms`）；消费组 lag **60s**（`lag_interval_ms`，单独节奏）；单次超时 5s。
- **前提**：Kafka 集群自探命中 + 采集授权 + 凭据（`secrets/kafka/<key>/`，SCRAM/TLS 见 [`kafka-sasl-implementation.md`](./kafka-sasl-implementation.md)）。
- **上限**：单轮最多 `max_groups`（默认 200）个消费组；`lag_group_allowlist` 非空时忽略阈值、只采名单内的组。

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `kafka_broker_up` | gauge_i64 | 1 | — | broker 可达 |
| `kafka_broker_role_is_controller` | gauge_i64 | 1 | — | 是否 controller |
| `kafka_partition_count` | gauge_i64 | 1 | — | 分区数 |
| `kafka_partition_under_replicated` | gauge_i64 | 1 | — | 副本不足的分区数 |
| `kafka_partition_offline` | gauge_i64 | 1 | — | 离线分区数（集群级） |
| `kafka_log_dir_size_bytes` | gauge_i64 | By | — | 全部 log dir 合计大小 |
| `kafka_log_dir_usable_bytes` | gauge_i64 | By | — | 可用空间；仅 `DescribeLogDirs v4` 才有，老 broker 少这一条 |
| `kafka_consumergroup_lag` | gauge_i64 | 1 | `group`,`topic` | 消费积压（按 topic 求和） |
| `kafka_consumergroup_state` | gauge_i64 | 1 | `group`,`state` | 一热：`stable` / `rebalancing` / `empty` / `dead`，值恒为 1 |

> 组名与 topic 是业务标识，只做 label；拿不到容量的 broker **不发** `kafka_log_dir_size_bytes`（不补 0，0 会被当成「磁盘空」）。

## 6. MySQL / TiDB（`mysql_*`，`collection_kind=mysql_metrics`）

- **身份**：`instance = mysql:<host>:<port>`（容器场景用凭据 key，重启换 IP 不断档）。
- **周期**：30s（`[mysql] interval_ms`）；单轮总超时 5s。
- **凭据**：只读账号 `wist-probe`，密码 `secrets/mysql/<key>/password`；有 `ca.pem` 时升级为 `VerifyCa`，否则 `Preferred`。
- **约定**：读不到的键记 warning 并跳过；不是副本就不出 `mysql_replication_*`（TiDB / 单机 MySQL 走这条路）。

| 指标 | 类型 | 单位 | 说明 |
|---|---|---|---|
| `mysql_up` | gauge_i64 | 1 | 实例可达 |
| `mysql_uptime_seconds` | gauge_i64 | s | 运行时长 |
| `mysql_connections_current` | gauge_i64 | 1 | 当前连接数 |
| `mysql_connections_max` | gauge_i64 | 1 | 连接数上限 |
| `mysql_threads_running` | gauge_i64 | 1 | 正在运行的线程 |
| `mysql_queries_total` | counter_i64 | 1 | 累计查询数 |
| `mysql_slow_queries_total` | counter_i64 | 1 | 累计慢查询 |
| `mysql_aborted_connects_total` | counter_i64 | 1 | 累计异常连接 |
| `mysql_received_bytes_total` | counter_i64 | By | 累计接收字节 |
| `mysql_sent_bytes_total` | counter_i64 | By | 累计发送字节 |
| `mysql_innodb_buffer_pool_pages` | gauge_i64 | 1 | buffer pool 页数 |
| `mysql_innodb_buffer_pool_pages_free` | gauge_i64 | 1 | buffer pool 空闲页数 |
| `mysql_innodb_buffer_pool_size_bytes` | gauge_i64 | By | buffer pool 大小 |
| `mysql_replication_lag_seconds` | gauge_f64 | s | 复制延迟（仅副本） |
| `mysql_replication_running` | gauge_i64 | 1 | 复制线程是否运行（仅副本） |

## 7. PostgreSQL（`pg_*`，`collection_kind=pg_metrics`）

- **身份**：`instance = postgres:<host>:<port>`。
- **周期**：30s（与 MySQL 共用 `[postgres] interval_ms`）；单轮总超时 5s。
- **凭据 / 约定**：与 MySQL 同形；不是副本不出 `pg_replication_*`。

| 指标 | 类型 | 单位 | 说明 |
|---|---|---|---|
| `pg_up` | gauge_i64 | 1 | 实例可达 |
| `pg_uptime_seconds` | gauge_i64 | s | 运行时长 |
| `pg_connections_current` | gauge_i64 | 1 | 当前连接数 |
| `pg_connections_max` | gauge_i64 | 1 | 连接数上限 |
| `pg_xact_commit_total` | counter_i64 | 1 | 累计提交事务 |
| `pg_xact_rollback_total` | counter_i64 | 1 | 累计回滚事务 |
| `pg_deadlocks_total` | counter_i64 | 1 | 累计死锁 |
| `pg_temp_bytes_total` | counter_i64 | By | 累计临时文件字节 |
| `pg_disk_read_bytes_total` | counter_i64 | By | 累计读盘字节 |
| `pg_cache_hit_bytes_total` | counter_i64 | By | 累计命中缓存字节 |
| `pg_database_size_bytes` | gauge_i64 | By | 数据库大小 |
| `pg_replication_lag_seconds` | gauge_f64 | s | 复制延迟（仅副本） |
| `pg_replication_running` | gauge_i64 | 1 | 复制线程是否运行（仅副本） |

## 8. Doris（`doris_*`，`collection_kind=doris_metrics`）

- **身份**：`instance = doris:<host>:<port>`（FE）；读数按 **BE** 拆开，`be` label = `ip:heartbeat_port`。
- **周期**：30s（`[doris] interval_ms`，与 `[postgres]` 同形）；单轮总超时 5s。
- **查询**：只从本机 FE 读 `SHOW BACKENDS`（不依赖审计日志、不读 compaction 明细）。
- **边界**：BE 掉线时该 BE 的序列**消失**，不补 0；只看集群合计会把「一台写满、其余空闲」看成整体有余量。

| 指标 | 类型 | 单位 | label | 说明 |
|---|---|---|---|---|
| `doris_be_up` | gauge_i64 | 1 | `be` | BE 存活 |
| `doris_be_capacity_bytes` | gauge_i64 | By | `be` | BE 容量 |
| `doris_be_available_bytes` | gauge_i64 | By | `be` | BE 可用空间 |
| `doris_be_tablets` | gauge_i64 | 1 | `be` | BE 上的 tablet 数 |

## 9. 常用查询

```promql
# 主机 CPU 使用率（0–1）
system_cpu_usage_ratio

# 主机 CPU 使用率 + 主机名 / IP
system_cpu_usage_ratio
  * on(agent, instance) group_left(host_name, host_ip) system_host_info

# 逐核 user 时间（rate）
rate(system_cpu_seconds_total{mode="user"}[5m])

# 内存使用率
system_memory_usage_ratio

# 最紧张的挂载点
topk(1, system_filesystem_usage_ratio)

# agent 进程的 CPU（单核口径）
agent_cpu_ratio

# Kafka：消费积压 TopN（按组 + topic）
topk(10, kafka_consumergroup_lag)

# Kafka：副本不足分区总数
sum(kafka_partition_under_replicated)

# MySQL / PG：复制延迟最差的副本
topk(3, mysql_replication_lag_seconds or pg_replication_lag_seconds)

# Doris：按 BE 看剩余空间
doris_be_available_bytes
```

## 10. 维护约定

1. 新增 / 改名 / 改单位：先改 `wist-metrics::METRIC_SPECS`，再改 [`metrics-data-spec.md`](./metrics-data-spec.md) §10，
   最后同步本文；按 §0.1 的破坏性变更流程走。
2. 本文不引入新的口径描述；有冲突时以 `metrics-data-spec.md` 与注册表为准。
3. 条件上报（不补 0、窗口不足不出值、副本才有 replication_*）属于实现语义，改动时同步 §2.7、§6、§7、§8。
