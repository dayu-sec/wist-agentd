# MySQL / TiDB 指标采集（SQL 直采）

> 状态：**P0 已落地**（2026-11-05）。域 `mysql_metrics` 已在 `wist-metrics 0.15.0` 注册。
> 调度与执行模型见 [metrics-collection-runtime.md](./metrics-collection-runtime.md)；
> 本文只讲 MySQL 这一域：采什么、怎么连、证据从哪来、失败怎么表现。

## 1. 一句话

agentd 以 root 跑在数据库机器上，**进程本身就是证据**：端口与凭据位置自己探出来，
采集由采集面授权（`collect_metrics` + `MysqlInstance/auto`）驱动，
用 `sqlx` 说 MySQL 协议跑三条只读 `SHOW`。不需要 exporter，不需要本机配置开关。

## 2. 采什么（P0 子集）

| 指标 | 事实键 | 类型 | 为什么在 P0 |
|---|---|---|---|
| `mysql_up` | `mysql.up` | gauge | 只看有没有数还不够，要先知道库是活的 |
| `mysql_uptime_seconds` | `mysql.uptime.seconds` | gauge | 掉 0 = 刚重启，别的读数都要重新解读 |
| `mysql_connections_current` | `mysql.connections.current` | gauge | 连接打满是现场最常见的「忽然全站慢」 |
| `mysql_connections_max` | `mysql.connections.max` | gauge | 单看 current 判断不了「还剩多少」 |
| `mysql_threads_running` | `mysql.threads.running` | gauge | 连接不多但这里打满 = 慢查询堆着 |
| `mysql_queries_total` | `mysql.queries.total` | counter | QPS 的分子（`Questions`） |
| `mysql_slow_queries_total` | `mysql.slow_queries.total` | counter | 慢查询在涨，但没人看日志 |
| `mysql_aborted_connects_total` | `mysql.aborted_connects.total` | counter | 认证/网络问题的最早信号 |
| `mysql_received_bytes_total` | `mysql.bytes_received.total` | counter | 流量突增/突降 |
| `mysql_sent_bytes_total` | `mysql.bytes_sent.total` | counter | 同上 |
| `mysql_innodb_buffer_pool_pages` | `mysql.innodb.buffer_pool.page_count` | gauge | 与下面一条配合看命中率 |
| `mysql_innodb_buffer_pool_pages_free` | `mysql.innodb.buffer_pool.page_free_count` | gauge | free 长期偏低 = 池子在抖 |
| `mysql_innodb_buffer_pool_size_bytes` | `mysql.innodb.buffer_pool.size_bytes` | gauge | 配置容量，解释上面两条的量级 |
| `mysql_replication_lag_seconds` | `mysql.replication.lag_seconds` | gauge | 读写分离里唯一的「跟不跟得上」 |
| `mysql_replication_running` | `mysql.replication.running` | gauge | 延迟读数此时可能不可信 |

**没进 P0 的**：`performance_schema` 系（等待事件、锁）、`exporter` 系的 per-schema 统计、
InnoDB 命中率（需要跨轮差分）、TiDB 的 region/GC 指标。理由：它们要么需要额外权限
（`performance_schema` 打开），要么需要跨轮状态，先不把复杂度引进来。

## 3. 怎么连

```
主机：127.0.0.1（端点只来自本机自探，不接受外部地址）
用户：wist-probe（固定，不是秘密）
密码：/etc/wist-agentd/secrets/mysql/port-<port>/password   （0400，属主 root）
CA  ：/etc/wist-agentd/secrets/mysql/port-<port>/ca.pem      （可选）
```

- `<port>` 就是自探出来的端口（`port-3306`）——**运维可以在 agentd 自探之前就把文件放好**，
  这是选择端口而不是哈希/实例 id 的唯一理由（决策记录见运行时文档 §12.1-5）；
- 有 `ca.pem` ⇒ `ssl_mode=VerifyCa`；没有 ⇒ `Preferred`（支持加密就加密、否则明文）。
  **配了 CA 不会静默降级**：要求校验但文件不在，直接算这一轮失败并说清楚；
- 连接后先跑 `SET SESSION max_execution_time = <timeout_ms>`（参数走 bind），
  为将来加 `SELECT` 留一道保险（`SHOW` 本身不受它约束）。

只读账号的最小权限：

```sql
CREATE USER 'wist-probe'@'127.0.0.1' IDENTIFIED BY '<随机密码>';
GRANT PROCESS, REPLICATION CLIENT ON *.* TO 'wist-probe'@'127.0.0.1';
-- PROCESS 足以读 SHOW GLOBAL STATUS / VARIABLES；REPLICATION CLIENT 用于 SHOW REPLICA STATUS
```

## 4. 证据层（自探）

`src/discovery/mysql_source.rs`，从强到弱：

1. **配置文件**：`--defaults-file=` 或 `/etc/my.cnf`、`/etc/mysql/my.cnf`、
   `.../mysql.conf.d/mysqld.cnf`、`.../mariadb.conf.d/50-server.cnf` 里的
   `[mysqld] port=` / `skip-networking`；
2. **命令行**：`--port=`、`--skip-networking`；
3. **监听端口**：该进程的 TCP 监听（只看得到「这里有个监听」）。

然后**每个候选端口实测一次握手**：连上后读第一个字节，必须是 MySQL 经典协议的
`protocol_version = 10`。

> 为什么非要做握手：一个 `mysqld` 通常同时监听 3306（经典协议）与 33060（X 协议）。
> TCP 能连不等于能用 SQL 采；把 X 协议端口当 MySQL 采会**每轮都失败一次**，
> 而这在指标上看起来和「库挂了」一模一样。

红线：`[mysqld]` 段只读 `port` / `skip-networking` / `socket`，任何含 `password` /
`user` 的键一律不读、不报、不进日志。

## 5. 失败怎么表现

| 情况 | `attempted` / `failed` | 日志 | 指标 |
|---|---|---|---|
| 没投放密码文件 | 1 / 1 | 本轮 `last_error`（"未投放凭据"） | 没有样本 |
| 连接被拒 / 密码错 | 1 / 1 | `last_error` 带原始原因 | 没有样本 |
| 连接或查询超时 | 1 / 1 | `last_error` 带超时毫秒 | 没有样本 |
| `SHOW GLOBAL STATUS` 失败 | 1 / 1 | 同连接失败 | 没有样本 |
| `SHOW GLOBAL VARIABLES` 失败 | 1 / 0 | warning（只影响两项指标） | 其余照出 |
| 某状态键不存在 | 1 / 0 | warning（"Status 缺少 X"） | **不补 0**，该键无样本 |
| 不是副本 / 版本不支持 | 1 / 0 | 只 debug | 不出 `mysql_replication_*` |
| 复制延迟为 NULL | 1 / 0 | warning | 只出 `running`，不出 `lag` |

多通道复制（MySQL 8 `FOR CHANNEL`）：lag 取**最大值**、`running` 要求**全部通道**正常。
平均值会把「一个通道断了几小时」抹平。

## 6. 测试

- 单测（不需要真库）：`src/telemetry/metrics/mysql.rs` 用假 `SqlTransport` 注入结果集，
  覆盖正常 / 缺键 / 非数字 / 非副本 / 不支持语句 / 破复制 / 多通道 / 密码文件缺失；
- 自探单测：假 `MysqlProc` + 假 `Handshake`，覆盖 X 协议端口被握手筛掉、argv/config 证据优先级、
  `skip-networking`、客户端进程排除、同端口去重；
- 调度：`scheduler.rs` 覆盖排轮 / 在飞不重复排轮 / 撤授权即停 / 晚到的扫描结果被丢弃；
- **真库**：本轮未跑（客户环境 `10.168.1.145` 不可达）。开发库可用时补一条
  `#[ignore]` 的 live 用例，环境变量指向本地 MySQL。

## 7. 已知边界

- 只采**本机**实例（决策 §12.1-4）：远端库采集需要单独的授权与 SSRF 设计，不在本轮；
- TiDB 的 `SHOW REPLICA STATUS` 不支持（报语法错）：按「不是副本」处理，不打 warning；
- 连接每轮新建、用完即关：没有连接池常驻。理由是 30s 一轮、一次三条 `SHOW`，
  池化带来的收益（省一次握手）远小于它带来的状态管理成本；
- 慢查询只数**条数**（`Slow_queries` 计数器），不采具体 SQL：那是审计/日志域的活。
