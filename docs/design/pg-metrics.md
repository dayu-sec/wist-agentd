# PostgreSQL 指标采集（SQL 直采）

> 状态：**P0 已落地**（2026-11-05）。域 `pg_metrics` 已在 `wist-metrics 0.16.0` 注册。
> 运行时（host / docker-compose / k8s）与凭据 key 的规则见
> [mysql-metrics.md](./mysql-metrics.md) §3 —— 两个域**完全同一套**，本文只说 PG 自己的部分。

## 1. 与 MySQL 的关系

| 维度 | MySQL | PostgreSQL |
|---|---|---|
| 自探运行时（netns / 地址 / 凭据 key） | 共用 `discovery/db_source.rs` | 同上 |
| 传输 | `sqlx` mysql | `sqlx` postgres（同一个 crate、同一套 rustls） |
| 握手（"端口上真的是它吗"） | 读 Protocol 10 问候包 | 发 `SSLRequest`，收 `S` / `N` |
| 证据 | `[mysqld] port=` / `--port=` | `postgresql.conf port=` / `-p` |
| 查询通道 | `SqlTransport`（共用 trait） | 同上 |
| 凭据根目录 | `secrets/mysql/` | `secrets/postgres/` |

## 2. 采什么（P0 子集）

| 指标 | 事实键 | 类型 | 为什么在 P0 |
|---|---|---|---|
| `pg_up` | `pg.up` | gauge | 先知道库是活的 |
| `pg_uptime_seconds` | `pg.uptime.seconds` | gauge | 掉 0 = 刚重启，其它读数要重新解读 |
| `pg_connections_current` | `pg.connections.current` | gauge | 连接打满是「忽然全站慢」的头号原因 |
| `pg_connections_max` | `pg.connections.max` | gauge | 单看 current 判断不了余量 |
| `pg_database_size_bytes` | `pg.database.size_bytes` | gauge | 增长失控 / 归档没生效 |
| `pg_xact_commit_total` | `pg.xact.commit.total` | counter | TPS 分子 |
| `pg_xact_rollback_total` | `pg.xact.rollback.total` | counter | 回滚比例 = 业务在报错 |
| `pg_deadlocks_total` | `pg.deadlocks.total` | counter | 应用层并发写模式的直接证据 |
| `pg_temp_bytes_total` | `pg.temp.bytes.total` | counter | 临时文件暴涨 = 排序/哈希溢出，内存不足 |
| `pg_disk_read_bytes_total` | `pg.disk.read_bytes.total` | counter | 冷读突增 = 缓存失效或数据集变大 |
| `pg_cache_hit_bytes_total` | `pg.cache.hit_bytes.total` | counter | 与上一条配合算命中率 |
| `pg_replication_lag_seconds` | `pg.replication.lag_seconds` | gauge | 读写分离里唯一的「跟不跟得上」 |
| `pg_replication_running` | `pg.replication.running` | gauge | 延迟读数此时可能不可信 |

`blks_read` / `blks_hit` 是**块**计数，采集侧按 8 KiB 换算成字节上报：
消费方不需要知道 `BLCKSZ`，也不会因为哪天块大小变了而读到错量级。

**没进 P0 的**：`pg_stat_statements`（要装扩展）、锁等待细节、WAL 生成速率（要跨轮差分）、
autovacuum 进度（要 `pg_stat_progress_vacuum`，版本差异大）。

## 3. 怎么连

```
用户：wist-probe
密码：/etc/wist-agentd/secrets/postgres/<key>/password   （0400，属主 root）
CA  ：/etc/wist-agentd/secrets/postgres/<key>/ca.pem      （可选）
```

`<key>` 与 MySQL 同一套（`port-5432` / `pod-<ns>-<pg>` / `container-<name>` / `addr-<ip>-<port>`）。

只读账号与 `pg_hba.conf`：

```sql
CREATE ROLE wist_probe LOGIN PASSWORD '<随机密码>';
GRANT pg_monitor TO wist_probe;
-- pg_monitor 覆盖 pg_stat_* 与 pg_read_all_settings，不需要 superuser
```

```
# pg_hba.conf：host 上走近回环；容器 / k8s 走节点地址
host    all    wist_probe    127.0.0.1/32    scram-sha-256
host    all    wist_probe    10.0.0.0/8      scram-sha-256   # 按你的节点 / pod CIDR 收窄
```

> 容器 / k8s 下 agentd 从**宿主侧**连 pod IP，PG 看到的来源不是 `127.0.0.1`。
> 只写 `127.0.0.1/32` 会出现「密码对、还是连不上」——和 MySQL 那边是同一类坑。

## 4. 证据与握手

- 证据：`-D <datadir>/postgresql.conf` 的 `port =`（最权威）→ 常见发行版路径
  （`/etc/postgresql/*/main/postgresql.conf`、`/var/lib/pgsql/data/…`）→ 命令行 `-p` → 监听端口；
- 握手：发 `SSLRequest`（长度 8 + 魔数 80877103），收一个 `S`（支持 TLS）或 `N`（不支持）。
  两种都是 PG，其它响应直接判「不是」；
- 排除项：`pgbouncer` / `psql` / `pg_dump` / `pg_basebackup` / `pg_ctl` / `postgres_exporter`
  —— 它们说 PG 协议，采它们会把「池子的统计」当成「数据库的统计」。

## 5. 失败怎么表现

与 MySQL 同一张表（见 [mysql-metrics.md](./mysql-metrics.md) §5），PG 侧额外两条：

| 情况 | 表现 |
|---|---|
| 主库（不在恢复中） | **不出** `pg_replication_*`（不补 0） |
| 备库但还没回放过事务 | `pg_replication_running = 0`，**不出**延迟（NULL ≠ 0） |
| `pg_stat_database` 无权限 | 只丢事务/IO 那几条 + warning，其余照出 |

## 6. 测试

- 采集逻辑：假 `SqlTransport` 注入结果集，覆盖主库 / 备库 / 未回放 / 状态查询失败 /
  统计查询失败 / 缺列（`max_connections`）/ 密码文件缺失；
- 自探：假 `DbProc` + 假握手，覆盖 `-D` 配置端口、argv 端口、pod IP + pod key、pooler 排除、
  conf 解析（注释 / 引号）；
- **真库未跑**：本机没有 PostgreSQL，客户环境暂不可达；有开发库时补 `#[ignore]` live 用例。
