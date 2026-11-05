# Kafka 自探（实现说明）

> 目标：**机器侧零配置**。端点、协议、机制由 agentd 自己探出来，供**本机**使用：
> 采集时决定连哪里、用什么协议，`doctor` 里给人看。
>
> **发现结果不上报、不进网关**。授权走既有采集面（工作授权），凭据由人在机器上按
> 「接入 Kafka」页面给的命令投放。没有任何 Kafka 专属的网关接口。
>
> 状态：agentd 侧已落地 —— 自探（`discovery/kafka_source.rs`）+ 授权驱动的启停
> （`telemetry/metrics/kafka.rs::reconcile`）。

## 1. 为什么自探

让运维为每台机器写 `bootstrap_servers` / `security_protocol` 不可行（也没人做）。
agentd 以 root 跑在 broker 机器上，**进程本身就是证据** —— 与
`discovery/log_source.rs` 定位数据库日志目录同构。

由此定死采集范围：**只采 agentd 所在节点上自探得到的 broker**。agentd 跑在独立监控机上
采远端集群不在支持范围（端点必须自探，网关给地址等于开一个 SSRF 口子）。

## 2. 证据层（从强到弱）

| 层 | 读什么 | 产出 | confidence |
|---|---|---|---|
| 1 | `server.properties`（argv 的 `-Dkafka.config.file` / `kafka-server-start.sh <path>` / 发行版默认路径） | listeners、advertised、协议映射、SASL 机制、node.id | 90 |
| 2 | 容器环境变量 `KAFKA_CFG_*`（Bitnami 镜像） | 同上 | 80 |
| 3 | 该进程的监听端口（发现快照） | 端口 + 协议 `unknown` | 30 |

容器里的进程走 `/proc/<pid>/root<path>` 读配置。

**红线**：只读白名单键（`listeners` / `advertised.listeners` /
`listener.security.protocol.map` / `sasl.enabled.mechanisms` / `node.id` / `broker.id` 等）；
`ssl.keystore.password`、`sasl.jaas.config`、任何 `*.password` **不读、不报、不进日志**。
有两条用例钉住这一点（含"序列化结果里不能出现密码串"）。

**排除项**：ZooKeeper、kafka-exporter、Kafka Connect（同样带 `kafka` 字样，但不是 broker）。

## 3. 端点假设与可达性

每个监听器产生最多三条假设，**每条都实测**：

- 明文监听器：直接发 `ApiVersions`（一次连接同时证明「TCP 通」与「这确实是 Kafka」）；
- TLS / SASL 监听器：只做 TCP 连接（不带凭据不可能握手），**不降级成明文重试**；
- 单次封顶 300ms，每集群最多 6 个端点。

排序：广告地址且握手成功 > 其它握手成功 > 能连 > 连不上；不可达的**也保留**
（它解释了"为什么这个集群没采到"）。

## 4. 这些结果去了哪里

| 用途 | 路径 |
|---|---|
| 采集时用哪个端点/协议 | `scheduler::request_scan`（主循环投递）→ 采集线程解析 → `scheduler::finish_scan` |
| 现场诊断 | `wist-agentd doctor` 的 `discovery.kafka` 检查（与守护进程同一解析路径） |
| 网关 | **没有**：不上报、不存储、不新增接口 |

授权仍然走既有采集面：网关派一份工作，unit 的 `capability = collect_metrics`、
`source = {kind: "KafkaCluster", target: "auto"}` —— 意思是「允许在本机采集 Kafka」，
具体连哪由 agent 自己发现。

凭据（仅 SASL）由人按「接入 Kafka」页面上的命令投放：建只读主体 + ACL + Secret，
agentd 从固定路径读文件。**密码不经过平台。**

## 5. 成本与边界

| 项 | 上限 |
|---|---|
| 每轮最多检查的 broker 进程 | 8（先按 `java` / `kafka` 粗筛再读 argv） |
| 每集群端点 | 6（各 300ms 封顶，明文只连一次） |
| `cmdline` / `environ` 读取 | 4 KiB |
| `server.properties` 读取 | 64 KiB |
| 触发时机 | 有采集授权时：快照 revision 变化或每 5 分钟一次；诊断时手动 |

只有本机**真的发现 broker** 时才会发生网络探测，普通主机这一项是零网络成本。

**扫描不在 3s 主循环里跑**：主循环只判断「需不需要重算」并把快照投递到采集线程
（`scheduler::request_scan`）；解析 `/proc` 与有界 TCP 探测都在那个线程上完成。
极限情况（8 个 broker 进程 × 6 个端点 × 300ms）也不超过十几秒，而主循环一次都不会等。
扫描带代号（epoch）：撤授权或又投递了新扫描时，晚一步回来的旧结果会被丢弃——
否则撤销授权后一个迟到的扫描会把集群又加回去。

## 6. 配置

只有一个逃生开关，默认开：

```toml
[discovery]
kafka_discovery = true
```

关掉 = 不自动发现（也就采不到，因为端点只来自自探）。**没有** `[kafka]` 端点/协议配置。

`[kafka]` 段里只剩调优旋钮（周期 / 超时 / 组基数上限 / 阈值 / 白名单）。旧版的
`enabled` / `bootstrap_servers` / `security_protocol` / `sasl_*` / `username` /
`password_file` / `tls_ca_file` **能加载但不生效**（也不能把 agentd 拦在启动前）；
启动日志会以 `event=KafkaProbeConfigIgnored` 点名哪些键被忽略 —— 否则就是一处配置两处真相。

## 7. 下一步

1. ~~agentd：授权驱动的启停~~ —— **已完成**：授权来自采集面
   （`collect_metrics` + `KafkaCluster/auto`），端点来自自探，撤授权即停。
   自探扫描走 `request_scan` / `finish_scan`（在采集线程执行，不占主循环）。
2. ~~Web：`接入 → Kafka` 页面只放**帮助代码**~~ —— **已完成**：页面分三段
   ① 采集面授权（工作单元片段，`KafkaCluster/auto`）；② Kafka 侧授权与凭据投放
   （建主体 / 最小 ACL 集 / Secret 或主机文件 / DaemonSet 挂载，密码在浏览器生成、
   只显示一次）；③ 常见失败判读。全部是可复制的命令，**不调用任何 Kafka 专属后端接口**。
   帮助代码的拼装逻辑在 `wist-gateway-web/src/lib/kafkaAccess.ts`，由
   `tests/kafka-access-help.test.ts` 钉住字面契约（principal / secret key / 路径 / ACL 资源）。
3. 需要的话再加本机自检：`wist-agentd doctor` 里把凭据文件状态一并显示
   （现在只报自探结果：端点、协议、可达性）。

## 8. 与采集面的接法（已实现）

工作单元（网关派发）：

```json
{"unit_id":"kafka-broker","capability":"collect_metrics","rule_ref":"kafka-broker",
 "sources":[{"kind":"KafkaCluster","target":"auto"},
            {"kind":"MetricInterval","target":"30s"}]}
```

- `target` 只认 `auto`（空串等同）；写具体地址会被报成 `unsupported`（端点必须自探）。
- agentd 的生效逻辑：
  - 有授权 → 按自探结果 reconcile 出要采的集群（新出现的立即采一轮）；
  - 自探没有可达端点 → 不采，打一条 `event=KafkaProbeNoEndpoint`（一次，不刷屏）；
  - 撤授权 / 暂停 → 下个 tick 内停采，序列从快照里消失；
  - `MetricInterval` 决定拓扑面周期；`[kafka] lag_interval_ms` 决定组面周期。
- 凭据只剩一个约定路径：`/etc/wist-agentd/secrets/kafka/probe`（SASL），
  `.../ca.pem`（私有 CA，可选）。用户名固定 `wist-probe`，机制 `auto`。

> `KafkaCluster` 这个 source kind 目前定义在 agentd（`control/work.rs`）——
> 改 `wist-contracts` 需要连带 `wist-api` / `wist-metrics` / `wist-validate` 一起切
> path 发版。等网关开始派发这种单元时，再把它收进 contracts，两边同口径。
