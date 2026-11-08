# 采集能力评估报告

> 数据快照：2026-11-08 · 网关 `0.40.11` / stack `0.10.12` / agentd `0.30.0` / 知识包 `0.10.0-alpha`（`catalog_version=23`，`purpose_version=5`）
> 数据来源：`GET /api/v1/admin/content`（网关实际装载的内容目录）+ `wist-agentd probe` 实测

## 一、结论

- **采集面 22 个**：全部在词表内、都有采集单元（4 个已废弃的指标旧面已于 2026-11-08 从词表与网关闭集删除）。
- **采集单元 40 个**：`active` **29 个**（可派活）、`draft` **11 个**（网关不派）；其中 macOS
  数据库指标三个单元（`mac-postgres-metrics` / `mac-mysql-metrics` / `mac-doris-metrics`）为本轮新增。
- **每个面真的采成没采成，现在有信号**：agentd 每 tick 重算并随状态心跳上报
  `AgentLocalStandingWork.collection`（`ok` / `degraded` / `failed` / `unknown` / `paused`），
  管理面「Agent 工作」卡片并列展示，摘要区单独统计「采集异常」。口径见
  [`collection-families.md` §3.2](https://github.com/dayu-sec/wist-design)。
- **能力层与授权层是两件事**：agentd 侧探针是否可用（`executable`）由代码决定；能不能派下去（`collect_ready`）由知识库单元的 `status` 决定。两者不一致时，现场表现为「配好了却没有任何指标」。
- **本轮实测（真实服务）**：PostgreSQL **11 facts / 69ms**、MySQL **13 facts / 113ms**、
  Kafka **9 facts / 3ms**、Doris **4 facts / 3ms** —— **四个域全部能出数**。
  Doris 首轮暴露了一个真实缺陷（见 4.3），已修复并补 5 条保护用例。
## 二、采集面总览

| 面 | 平台 | 单元数 | active | draft | 对外状态 |
| --- | --- | ---: | ---: | ---: | --- |
| BackupJob | linux | 1 | 0 | 1 | 未就绪 |
| ComputeWorkload | linux | 1 | 0 | 1 | 未就绪 |
| ContainerWorkload | linux | 2 | 2 | 0 | 可用 |
| CrashPanic | 全平台 | 2 | 1 | 1 | 可用 |
| DatabaseMetrics | linux, macos | 6 | 6 | 0 | 可用 |
| DatabaseService | linux, macos | 2 | 2 | 0 | 可用 |
| DevToolchain | macos | 1 | 0 | 1 | 未就绪 |

| GatekeeperQuarantine | macos | 1 | 0 | 1 | 未就绪 |
| HostMetrics | 全平台 | 2 | 2 | 0 | 可用 |

| KernelSystem | linux | 1 | 1 | 0 | 可用 |
| LoginSession | 全平台 | 2 | 1 | 1 | 可用 |
| MessageQueueMetrics | linux | 1 | 1 | 0 | 可用 |
| MiscSystem | 全平台 | 2 | 0 | 2 | 未就绪 |

| NetworkFirewall | 全平台 | 2 | 2 | 0 | 可用 |
| NetworkService | linux | 1 | 0 | 1 | 未就绪 |

| PrivacyTcc | macos | 1 | 0 | 1 | 未就绪 |
| PrivilegeExecution | 全平台 | 3 | 2 | 1 | 可用 |
| RebootPower | 全平台 | 2 | 2 | 0 | 可用 |
| ServiceLifecycle | 全平台 | 2 | 2 | 0 | 可用 |
| SoftwareChange | 全平台 | 2 | 2 | 0 | 可用 |
| StorageHealth | linux, macos | 2 | 2 | 0 | 可用 |
| TrafficInspection | linux | 1 | 1 | 0 | 可用 |

## 三、采集单元就绪矩阵

| 单元 | 面 | 平台 | 能力 | status | agentd 可执行 | 来源类型 |
| --- | --- | --- | --- | --- | --- | --- |
| `linux-backup-job` | BackupJob | linux | collect_logs | **draft** | 是 | FileGlob, FileGlob |
| `linux-compute-workload` | ComputeWorkload | linux | collect_logs | **draft** | 是 | FileGlob, Exporter |
| `linux-container-stdout` | ContainerWorkload | linux | collect_logs | **active** | 是 | FileGlob |
| `linux-docker-container-stdout` | ContainerWorkload | linux | collect_logs | **active** | 是 | FileGlob |
| `linux-crash-panic` | CrashPanic | linux | collect_logs | **active** | 是 | FileGlob, FileGlob, Exporter |
| `mac-crash-panic` | CrashPanic | macos | collect_logs | **draft** | 是 | FileGlob, FileGlob |
| `linux-doris-metrics` | DatabaseMetrics | linux | collect_metrics | **active** | 是 | DorisCluster |
| `linux-mysql-metrics` | DatabaseMetrics | linux | collect_metrics | **active** | 是 | MysqlInstance |
| `linux-postgres-metrics` | DatabaseMetrics | linux | collect_metrics | **active** | 是 | PostgresInstance |
| `mac-postgres-metrics` | DatabaseMetrics | macos | collect_metrics | **active** | 是 | PostgresInstance |
| `mac-mysql-metrics` | DatabaseMetrics | macos | collect_metrics | **active** | 是 | MysqlInstance |
| `mac-doris-metrics` | DatabaseMetrics | macos | collect_metrics | **active** | 是 | DorisCluster |
| `linux-db-service` | DatabaseService | linux | collect_logs | **active** | 是 | FileGlob, FileGlob, FileGlob, FileGlob, FileGlob, FileGlob, FileGlob, FileGlob |
| `mac-db-service` | DatabaseService | macos | collect_logs | **active** | 是 | FileGlob, FileGlob, FileGlob, FileGlob, FileGlob, FileGlob, FileGlob, FileGlob |
| `mac-dev-toolchain` | DevToolchain | macos | collect_logs | **draft** | 否 | FileGlob, FileGlob |
| `mac-gatekeeper` | GatekeeperQuarantine | macos | collect_logs | **draft** | 否 | UnifiedLogPredicate |
| `linux-host-metrics` | HostMetrics | linux | collect_metrics | **active** | 是 | MetricInterval |
| `mac-host-metrics` | HostMetrics | macos | collect_metrics | **active** | 是 | MetricInterval |
| `linux-kernel-system` | KernelSystem | linux | collect_logs | **active** | 是 | Exporter |
| `linux-auth-session` | LoginSession | linux | collect_logs | **active** | 是 | FileGlob, FileGlob |
| `mac-login-session` | LoginSession | macos | collect_logs | **draft** | 否 | Exporter |
| `linux-kafka-metrics` | MessageQueueMetrics | linux | collect_metrics | **active** | 是 | KafkaCluster |
| `linux-misc-system` | MiscSystem | linux | collect_logs | **draft** | 是 | FileGlob, FileGlob |
| `mac-misc-system` | MiscSystem | macos | collect_logs | **draft** | 是 | FileGlob, FileGlob, FileGlob |
| `linux-network-firewall` | NetworkFirewall | linux | collect_logs | **active** | 是 | Exporter, Exporter |
| `mac-network-wifi` | NetworkFirewall | macos | collect_logs | **active** | 是 | FileGlob, UnifiedLogPredicate |
| `linux-network-service` | NetworkService | linux | collect_logs | **draft** | 是 | FileGlob, FileGlob |
| `mac-privacy-tcc` | PrivacyTcc | macos | collect_logs | **draft** | 否 | Exporter |
| `linux-audit-log` | PrivilegeExecution | linux | collect_logs | **active** | 是 | FileGlob |
| `linux-sudo-log` | PrivilegeExecution | linux | collect_logs | **active** | 是 | FileGlob |
| `mac-privilege-exec` | PrivilegeExecution | macos | collect_logs | **draft** | 否 | Exporter |
| `linux-reboot-power` | RebootPower | linux | collect_logs | **active** | 是 | Exporter, Exporter |
| `mac-reboot-power` | RebootPower | macos | collect_logs | **active** | 是 | FileGlob |
| `linux-service-lifecycle` | ServiceLifecycle | linux | collect_logs | **active** | 是 | Exporter |
| `mac-launchd-service` | ServiceLifecycle | macos | collect_logs | **active** | 是 | FileGlob |
| `linux-software-change` | SoftwareChange | linux | collect_logs | **active** | 是 | FileGlob, FileGlob, FileGlob, FileGlob |
| `mac-software-change` | SoftwareChange | macos | collect_logs | **active** | 是 | FileGlob |
| `linux-storage-health` | StorageHealth | linux | collect_logs | **active** | 是 | Exporter, FileGlob |
| `mac-storage-health` | StorageHealth | macos | collect_logs | **active** | 是 | Exporter, FileGlob |
| `linux-suricata-eve` | TrafficInspection | linux | collect_logs | **active** | 是 | FileGlob |

## 四、能力验证记录

验证环境：`dev-int-warpaxis-02`（Ubuntu / x86_64，k8s 单节点），
用 `wist-agentd probe` 直接对**真实服务**跑（不启守护进程、不进授权链路）。

| 域 | 结果 | 耗时 | facts | 备注 |
| --- | --- | ---: | ---: | --- |
| PostgreSQL | ✅ | 69ms | 11 | 建只读账号 + `pg_read_all_stats` |
| Kafka | ✅ | 3ms | 9 | PLAINTEXT，**不需要凭据** |
| Doris | ⚠️→✅ | 3ms | 4 | 首轮 facts=0，修复后通过（见 4.3）|
| MySQL | ✅ | 113ms | 13 | MySQL 8.0.32，`PROCESS` + `REPLICATION CLIENT` |
| TiDB | 未验证 | — | — | 走同一个 `MysqlInstance` 来源，协议兼容（未实测）|

### 4.1 PostgreSQL（✅ 11 facts）

```
probe pg_metrics  mode=explicit  73ms
  summary  targets=1 succeeded=1 failed=0 facts=11（已注册 11 / 未注册 0）

[1/1] pg_metrics postgres:127.0.0.1:55999  status=succeeded  69ms
        pg.up                       1          -> pg_up
        pg.uptime.seconds           13         -> pg_uptime_seconds
        pg.connections.max          100        -> pg_connections_max
        pg.connections.current      6          -> pg_connections_current
        pg.xact.commit.total        8          -> pg_xact_commit_total
        pg.xact.rollback.total      0          -> pg_xact_rollback_total
        pg.deadlocks.total          0          -> pg_deadlocks_total
        pg.temp.bytes.total         0          -> pg_temp_bytes_total
        pg.database.size_bytes      7699479    -> pg_database_size_bytes
        pg.disk.read_bytes.total    1417216    -> pg_disk_read_bytes_total
        pg.cache.hit_bytes.total    26918912   -> pg_cache_hit_bytes_total
```

前置动作（与生产一致）：

```sql
CREATE ROLE "wist-probe" LOGIN PASSWORD '<password>';
GRANT CONNECT ON DATABASE postgres TO "wist-probe";
GRANT pg_read_all_stats TO "wist-probe";   -- 读其他会话的 pg_stat_activity
```

### 4.2 Kafka（✅ 9 facts）

```
probe kafka_broker_metrics  mode=explicit  3ms
  summary  targets=1 succeeded=2 failed=0 facts=9（已注册 9 / 未注册 0）

[1/1] kafka_broker_metrics kafka:127.0.0.1:30001  status=succeeded  3ms
        kafka.broker.up                  1    -> kafka_broker_up
        kafka.broker.is_controller       1    -> kafka_broker_role_is_controller
        kafka.partition.count            57   -> kafka_partition_count
        kafka.partition.under_replicated 0    -> kafka_partition_under_replicated
        kafka.partition.offline          0    -> kafka_partition_offline
        kafka.log_dir.size_bytes         3626 -> kafka_log_dir_size_bytes
        kafka.log_dir.usable_bytes       1053117272064 -> kafka_log_dir_usable_bytes
        kafka.consumergroup.state  stable  -> kafka_consumergroup_state {group=asset-ingest-group}
        kafka.consumergroup.state  stable  -> kafka_consumergroup_state {group=log-audit-service-consumer}
```

- 集群：单 broker（`kafka-controller-0`），**PLAINTEXT**，57 分区，2 个消费组；
- **不需要凭据**：PLAINTEXT 下探针不带 SASL 身份（报告里 `credential ...（缺失）` 是预期）；
  只有 `SASL_*` 协议才需要 `/etc/wist-agentd/secrets/kafka/probe`。

### 4.3 Doris（⚠️ 发现缺陷 → 修复后 ✅ 4 facts）

- 集群：**Doris 4.1.0-rc03**，1 FE + 1 BE（728 tablets / ≈1 TB）；
- 首轮 probe：`status=succeeded` 但 **`facts=0`**，只有两条 warning：

  ```
  warning  SHOW BACKENDS 的行缺少 IP/HeartbeatPort
  warning  1 / 1 台 BE 未存活
  ```

- **根因**：Doris 4.x 把 `SHOW BACKENDS` 的 `IP` 列改名成 `Host`（2.x 是 `IP`），
  探针 `be_label()` 只读 `IP` → **每一行都被跳过**，BE 计数为 0，于是又派生出「未存活」。
- **修复**（`src/telemetry/metrics/doris.rs`）：先读 `Host`，回落 `IP`；补两条用例
  （Doris 4 列名被接受、两列并存时以 `Host` 为准）。全量测试 1492 项通过。
- 修复后：

```
probe doris_metrics  mode=explicit  3ms
  summary  targets=1 succeeded=1 failed=0 facts=4（已注册 4 / 未注册 0）

[1/1] doris_metrics doris:127.0.0.1:31166  status=succeeded  3ms
        doris.be.up                1     -> doris_be_up
        doris.be.capacity_bytes    1098974756864 -> doris_be_capacity_bytes
        doris.be.available_bytes   1053137792139 -> doris_be_available_bytes
        doris.be.tablets           728   -> doris_be_tablets
        {be=doriscluster-helm-be-0.doriscluster-helm-be-internal.default.svc.cluster.local:9050}
```

- **权限实测**：只 `CREATE USER`（不做任何 `GRANT`）即可执行 `SHOW BACKENDS`。
  该账号实际权限只有默认的 `internal.information_schema: Select_priv` / `internal.mysql: Select_priv` /
  `Usage_priv` —— **Doris 4.x 不需要 ADMIN_PRIV**。（2.x/3.x 可能仍需实例级特权，按版本确认。）

### 4.4 MySQL（✅ 13 facts）

```
probe mysql_metrics  mode=explicit  113ms
  summary  targets=1 succeeded=1 failed=0 facts=13（已注册 13 / 未注册 0）

[1/1] mysql_metrics mysql:10.244.154.250:3306  status=succeeded  113ms
        mysql.up                                 1          -> mysql_up
        mysql.uptime.seconds                     4607278    -> mysql_uptime_seconds
        mysql.connections.current                31         -> mysql_connections_current
        mysql.connections.max                    151        -> mysql_connections_max
        mysql.threads.running                    2          -> mysql_threads_running
        mysql.queries.total                      63333876   -> mysql_queries_total
        mysql.slow_queries.total                 0          -> mysql_slow_queries_total
        mysql.aborted_connects.total             14         -> mysql_aborted_connects_total
        mysql.bytes_received.total               11115137897 -> mysql_received_bytes_total
        mysql.bytes_sent.total                   16565983458 -> mysql_sent_bytes_total
        mysql.innodb.buffer_pool.page_count      8192       -> mysql_innodb_buffer_pool_pages
        mysql.innodb.buffer_pool.page_free_count 6518       -> mysql_innodb_buffer_pool_pages_free
        mysql.innodb.buffer_pool.size_bytes      134217728  -> mysql_innodb_buffer_pool_size_bytes
```

- 实例：**MySQL 8.0.32**（`apollo-mysql-0`，k8s 内 3306）；
- 授权（实测够用）：

  ```sql
  CREATE USER 'wist-probe'@'%' IDENTIFIED BY '<password>';
  GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'wist-probe'@'%';
  ```

  - `PROCESS` → `SHOW GLOBAL STATUS` / `SHOW GLOBAL VARIABLES`
  - `REPLICATION CLIENT` → `SHOW REPLICA STATUS`
- TiDB 走同一个 `MysqlInstance` 来源（协议兼容），但**本轮未实测**。


### 4.5 macOS 自探（结构验证，待真库验收）

macOS 与 Linux 走**同一条链**（进程 → argv → 配置证据 → 监听端口 → 握手），只换事实来源：

| 层 | Linux | macOS |
| --- | --- | --- |
| 进程 | `/proc` 扫描 | `ps -axo pid=,comm=`（已有） |
| 端口归属 | `/proc/<pid>/net/tcp` + fd 反查 | libproc（`PROC_PIDLISTFDS` + `PROC_PIDFDSOCKETINFO`） |
| argv | `/proc/<pid>/cmdline` | `sysctl(KERN_PROCARGS2)` |
| 配置证据 | `/proc/<pid>/root/etc/my.cnf` | 真实路径（Homebrew 前缀） |
| netns | 真实判同/异 | 恒为同一个（没有 netns） |
| 容器里的库 | 自然覆盖（读的是容器自己的 netns） | Docker API 拿「容器 → 发布端口」→ 对发布端口握手 |
| 采集 / 上报 | TCP 客户端 + uplink | 同（零改动） |

已用两种测试钉住平台层：

- 纯函数：`KERN_PROCARGS2` 的 argc / exec_path / 对齐填充 / argv 边界（Linux CI 也跑）；
- 真机冒烟：自己绑的监听口必须被 libproc 看到；自己的 argv 必须被 sysctl 读回。

**边界**：

- **原生 / Homebrew 安装**：走进程自探（libproc + `KERN_PROCARGS2`）。
- **Docker / OrbStack 里的库**：容器在独立的 Linux VM 里，宿主看不到进程；容器探针改从
  Docker API（Unix socket）拿**容器名 + 发布端口**，数据库自探再对发布端口做协议握手。
  凭据口径是容器名（`secrets/<domain>/container-<name>/`），与 Linux 容器侧一致。
- 看不到的：没把端口发布到宿主的容器（`-p` 没写）、远端库（需要显式端点覆盖，待定）。

## 五、缺口分析

### 5.1 未就绪的单元（11 个）

| 面 | 未就绪单元 | 影响 |
| --- | --- | --- |
| BackupJob | `linux-backup-job` | 该面在采集授权页不可派 |
| ComputeWorkload | `linux-compute-workload` | 该面在采集授权页不可派 |
| CrashPanic | `mac-crash-panic` | 该面在采集授权页不可派 |
| DevToolchain | `mac-dev-toolchain` | 该面在采集授权页不可派 |
| GatekeeperQuarantine | `mac-gatekeeper` | 该面在采集授权页不可派 |
| LoginSession | `mac-login-session` | 该面在采集授权页不可派 |
| MiscSystem | `linux-misc-system`, `mac-misc-system` | 该面在采集授权页不可派 |
| NetworkService | `linux-network-service` | 该面在采集授权页不可派 |
| PrivacyTcc | `mac-privacy-tcc` | 该面在采集授权页不可派 |
| PrivilegeExecution | `mac-privilege-exec` | 该面在采集授权页不可派 |

### 5.2 两类缺口的区别

| 缺口 | 表现 | 修法 |
| --- | --- | --- |
| **授权层**（`status=draft`）| 探针能跑，但网关不派活；采集授权页显示「没有采集就绪的单元」| 知识库改 `active` → `catalog_version` +1 → 发包 → 录入并激活 |
| **能力层**（`executable=false`）| 即使改 active，agentd 也会回 `unsupported` | 需要 agentd 先实现该来源类型 |

本轮 37 个单元里 **`executable=false` 的有 0 个** —— 所有已定义单元 agentd 都能执行，所以剩下的都只是授权层缺口。

## 六、下一步

1. **数据库三件套已全部转 `active`**（知识包 `0.9.5-alpha`，`catalog_version=22`）：
   - ✅ PostgreSQL（已验，11 facts）
   - ✅ MySQL 8.0（已验，13 facts）；⬜ TiDB（未验，走同一个 `MysqlInstance` 来源）
   - ✅ Doris 4.1（已验，修复探针后 4 facts）
   - 剩余风险是**现场前置动作**（凭据 / 只读账号 / 权限）没做完 —— 这类失败会在
     「Agent 工作」卡片的「采集结果」里以 `degraded` / `failed` 报出来，不再静静没数据。
2. **现场前置动作**（在真正授权前完成，指南页已有）：
   - 投放凭据到 `/etc/wist-agentd/secrets/{postgres,mysql,doris}/<key>/password`；
   - 数据库侧建 `wist-probe` 只读账号（PG 需要 `pg_read_all_stats`；MySQL 需要 `PROCESS` + `REPLICATION CLIENT`；
     Doris 4.x 默认权限即可）。
3. **收敛 draft 面**：剩下 **11 个** draft 单元（见 5.1），建议按「有无现场需求」排期；
   长期不用的可从词表移除（确认无历史数据才可删，否则只能标 `deprecated`）。
4. **macOS 数据库指标真库验收**：本轮只做到「结构 + 平台层冒烟」，需要在有原生
   MySQL / PostgreSQL 的 Mac 上跑一次 `wist-agentd probe {mysql,pg}_metrics`，
   确认 facts / 耗时后再对外声张。Docker Desktop 里的库不属于这条链（见 4.5）。

## 附录 A：怎么复现本报告

```bash
# 1) 面/单元的实际装载状态（网关说了算，不看仓库）
curl -sk https://<gateway>/api/v1/admin/content \
  -H "Authorization: Bearer $ADMIN_TOKEN" | jq '.units[] | {unit_id, status, executable}'

# 2) 单域能力验证（不启服务、不进授权链路）
wist-agentd probe pg --addr <host:port> --password-file <path> --out /tmp/probe.json
wist-agentd probe mysql --addr <host:port> --password-file <path>
wist-agentd probe doris --addr <host:port> --password-file <path>
wist-agentd probe kafka --addr <host:port> --password-file <path> \
  --security-protocol SASL_SSL --username wist-probe --ca-file <path>
```

## 附录 B：凭据目录约定

| 域 | 凭据目录 | 用户名 | 文件 |
| --- | --- | --- | --- |
| PostgreSQL | `/etc/wist-agentd/secrets/postgres/<key>/` | `wist-probe` | `password`、可选 `ca.pem` |
| MySQL / TiDB | `/etc/wist-agentd/secrets/mysql/<key>/` | `wist-probe` | `password`、可选 `ca.pem` |
| Doris | `/etc/wist-agentd/secrets/doris/<key>/` | `wist-probe` | `password`、可选 `ca.pem` |
| Kafka | `/etc/wist-agentd/secrets/kafka/` | 固定 `wist-probe` | `probe`、可选 `ca.pem`（单实例域，无 `<key>`）|

`<key>` 规则：宿主机 `port-<port>`；容器 `container-<name>`；K8s `pod-<namespace>-<pod>`；其余回落 `addr-<host>-<port>`。
