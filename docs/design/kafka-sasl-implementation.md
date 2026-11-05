# Kafka SASL/TLS 接入实现说明（交接文档）

> 规格见 `wist-design/doc/design/telemetry/kafka-broker-metrics-spec.md`。
> 本文只写「怎么把它实现掉」：模块边界、协议顺序、算法步骤、测试清单。
>
> 状态：**配置、校验、握手与消费组链路都已落地** —— `[kafka]` 现在只剩调优旋钮
> （`lag_group_allowlist` / `max_groups` / `lag_threshold` / `lag_interval_ms` / `interval_ms` /
> `timeout_ms`）由 `config/validate.rs` 把关；`bootstrap_servers` / `security_protocol` /
> `sasl_mechanism` / `username` / `password_file` / `tls_ca_file` 是**兼容字段**：能加载、
> 只在写了时做形式校验，但**不参与采集**（端点/协议来自自探，凭据来自固定路径），
> 启动时以 `event=KafkaProbeConfigIgnored` 点名。握手在
> `src/telemetry/metrics/kafka_auth.rs`，消费组在 `kafka_groups.rs`
> （`kafka.rs` 只调 `connect()` / `exchange()` / `collect()`）。
>
> ⚠ **启停不靠本机配置**：采集由采集面授权（`collect_metrics` + `KafkaCluster/auto`）驱动，
> 端点/协议由本机自探（见 `kafka-self-discovery.md`）；`[kafka]` 只剩调优旋钮，
> `enabled` 已不再决定采集。

## 1. 目标

让 `src/telemetry/metrics/kafka.rs` 的探针支持四种协议与三种机制：

| `security_protocol` | TLS | SASL |
|---|---|---|
| `PLAINTEXT` | — | — |
| `SSL` | ✅ | — |
| `SASL_PLAINTEXT` | — | ✅ |
| `SASL_SSL` | ✅ | ✅ |

`sasl_mechanism`：`auto` / `SCRAM-SHA-512` / `SCRAM-SHA-256` / `PLAIN`。

**`auto` 只在 broker 声明的机制列表里挑**，优先级 `SCRAM-SHA-512 > SCRAM-SHA-256 > PLAIN`；
列表为空或都不匹配时，报「broker 启用了 X/Y/Z」而不是「认证失败」。

## 2. 依赖（已加入 `Cargo.toml`）

```toml
hmac = "0.12"
pbkdf2 = { version = "0.12", default-features = false, features = ["hmac"] }
rustls-pemfile = "2"
```

`sha2` 原本只在 `[dev-dependencies]`（e2e 摘要夹具），已挪到 `[dependencies]`（SCRAM 运行时要用）；
`base64`、`rustls`、`rustls-platform-verifier`、`tokio-rustls` 已在 lock 中，其中后两者已是直接依赖。

## 3. 模块结构

新增 `src/telemetry/metrics/kafka_auth.rs`，`kafka.rs` 只调用它的入口：

```rust
pub struct SecurityConfig<'a> {
    pub protocol: &'a str,        // PLAINTEXT | SSL | SASL_PLAINTEXT | SASL_SSL
    pub mechanism: &'a str,       // auto | SCRAM-SHA-512 | SCRAM-SHA-256 | PLAIN
    pub username: Option<&'a str>,
    pub password_file: Option<&'a str>,
    pub tls_ca_file: Option<&'a str>,
}

/// 建立一条已认证的流，并先问清 broker 支持的协议版本。
pub fn connect(addr: &str, cfg: &SecurityConfig<'_>, timeout: Duration)
    -> io::Result<Connection>;

pub struct Connection {
    pub versions: ApiVersions,   // metadata / describe_log_dirs 各用哪个版本
    pub stream: Box<dyn ReadWrite>,
}
```

`fetch_metadata` / `fetch_log_dir_totals` 改成走 `connect()`，并按 `versions` 编码/解析
（仍然「连不上只影响该 broker，不出样本、不补 0」）。

消费组链路单独放在 `kafka_groups.rs`，只对外暴露：

```rust
pub struct GroupPolicy { allowlist, max_groups, lag_threshold }
pub struct GroupCollection { facts, warnings, dropped_groups }
pub fn collect(metadata: &Metadata, security: &SecurityConfig<'_>,
               timeout: Duration, policy: &GroupPolicy) -> GroupCollection;
```

`kafka.rs::probe_once` 把 `GroupCollection.facts` 挂到集群级 target 的 `labeled_facts` 上
（`instance = kafka:<cluster_key>`，组名 / topic 只做 label），并按 `lag_interval_ms`
决定本轮要不要真去采（两轮之间沿用上一轮的组读数，避免序列忽有忽无）。

## 4. 协议顺序

```text
TCP connect
  └─ (SSL | SASL_SSL)   TLS 握手
        rustls ClientConnection + StreamOwned<_, TcpStream>
        根证书：tls_ca_file 给了就用它（rustls-pemfile 读 PEM），否则 platform verifier
        ServerName 用 bootstrap 的 host（IP 也能构造，但优先 hostname）
  └─ ApiVersions (api 18, v0)       ← **认证之前**（Kafka 允许未认证连接发它）
        Metadata        → 取交集上限，我们只解 v1/v2（v2 带 cluster_id）
        DescribeLogDirs → 取交集上限，我们只解 v0-v4（v2 起 flexible，v4 才有 usable_bytes）
        ListGroups / DescribeGroups / OffsetFetch / ListOffsets → 各取非 flexible 的最高版
        没有交集就报「broker 是 vX-vY，探针只支持 vA-vB」，不猜
  └─ (SASL_*)           SaslHandshake (api 17, v1)
        request: mechanism
        response: error_code + mechanisms[]
        —— `auto` 在这里选机制；选不到就报列表
  └─ (SASL_*)           SaslAuthenticate (api 36, v0)
        request: auth_bytes
        response: error_code + error_message + auth_bytes
        —— SCRAM 要往返两次（client-first / client-final）
```

要点：

- **SASL 请求本身也走 Kafka 请求头**（api_key / api_version / correlation_id / client_id），
  不是裸字节。
- **版本一律协商出来**，不再写死：Kafka 4.0 已移除 `DescribeLogDirs v0`（基线 v1）与
  `Fetch v0-v3` 等；`Metadata` 仍是 `v0-13`。协商让同一份探针同时能连 0.10 与 4.x。
- `SaslAuthenticate` 用 **v0**（Kafka 1.0+，4.0 也没抬基线）。更老的 broker 用裸帧，
  V1 不支持，直接报版本不足。
- `error_message` 要原样进日志（它是 broker 给的原因），但**不得**包含密码。
- 认证失败时**不要把 auth_bytes 打进日志**（SCRAM 的 client-final 含 proof）。

## 5. SCRAM 步骤（RFC 5802）

```text
client-first  = "n,,n=<user>,r=<client-nonce>"
server-first  = "r=<client-nonce+server-nonce>,s=<salt-b64>,i=<iterations>"

salted        = PBKDF2-HMAC-SHA256/512(password, salt, iterations)
client_key    = HMAC(salted, "Client Key")
stored_key    = SHA(client_key)
auth_message  = client_first_bare + "," + server_first + "," + client_final_without_proof
client_sig    = HMAC(stored_key, auth_message)
proof         = client_key XOR client_sig
client-final  = "c=biws,r=<nonce>,p=<b64(proof)>"

server_key    = HMAC(salted, "Server Key")
server_sig    = HMAC(server_key, auth_message)
server-final  = "v=<b64(server_sig)>"   ← 必须校验；不等就是中间人/密码错
```

- nonce 用 16–24 字节随机（`getrandom` 或 `/dev/urandom`），base64 后作为 client-nonce。
- `c=biws` 是 base64("n,,")，表示「没有 channel binding」——我们不支持 channel binding。
- `m=` 扩展指令出现时必须拒绝（RFC 5802 §5.1）。

`PLAIN`：`auth_bytes = "\0" + username + "\0" + password`（注意开头那个 NUL）。

## 6. 凭据读取

```text
password_file：只要求 agentd 可读。读不到 → 报路径 + errno，不发样本、不重试风暴。
              **不校验权限**（0600 是运维约定，不是我们的接口）。
              **不自动生成密码**、不降级到无认证。
读到的内容去掉行尾的 \r\n 后使用；读完即丢弃，不留全局缓存。
```

`tls_ca_file` 可选：给了就覆盖系统根；文件读不到要在**启动时**就报错（配置校验只查路径非空，
实际读取放在第一次建连，错误信息里带上路径）。

## 7. 错误语义（与现有探针一致）

| 情况 | 行为 |
|---|---|
| TLS 失败（证书/主机名） | 本轮该 bootstrap 失败；错误带「验证失败的关键词」，便于区分「网络不通」 |
| SASL 机制不被 broker 支持 | 报 broker 的机制列表；**不**自动跨机制重试 |
| 密码错 | 报 `error_message`，不带 auth_bytes |
| `password_file` 读不到 | 报路径 + errno；不进入握手 |
| 单个 broker 失败 | 只缺该 broker 的样本，不影响其它 broker 与其它采集域 |

## 8. 测试清单（全部离线，不需要 broker）

1. `PLAIN` 载荷字节精确比对（含开头 NUL）。
2. SCRAM `client-first` / `client-final` 结构断言：给定固定 nonce + 固定 server-first
   → 输出可复现；`proof` 长度 = hash 长度。
3. SCRAM 解析：合法 server-first / 缺 `r` / 缺 `s` / 迭代数为 0 / 含 `m=` → 后者必须拒绝。
4. `server-final` 校验：`v=` 不匹配必须失败。
5. 机制选择：`auto` + `[SCRAM-SHA-512, PLAIN]` → 选 512；`[PLAIN]` → 选 PLAIN；
   空列表 → 报错且消息里含「broker 启用了」。
6. 密码读取：文件不存在 → 错误含路径；文件含 `\r\n` → 去掉后使用。
7. 回归：`PLAINTEXT` 路径不受影响（现有 9 条 kafka 测试全绿）。
8. 端到端（仍是本地假 broker，不需要真集群）：`PLAINTEXT` / `PLAIN` / `SCRAM-SHA-256` /
   `SSL` + `tls_ca_file` / 证书主机名不匹配 / `auto` 换机制重连 / 错密码 / `v=` 不匹配 /
   超大帧 —— 覆盖 wire 格式、连接复用与错误文案（`kafka_auth.rs` 的 `mod tests`）。

## 9. 验收

1. 三种机制各自能连上对应的测试集群（`SASL_SSL` 为主）；
2. 错密码 / 错机制 / 错 CA 三种失败，日志能一眼区分；
3. 认证失败时日志与诊断包里**搜不到密码**；
4. `security_protocol = "SSL"` 且不给 CA、系统根可用时，能连公有 CA 签发的集群。

**怎么跑（真 broker，按需手动，不进 CI）**：

用例在 `src/telemetry/metrics/kafka_live.rs`（全部 `#[ignore]`），指向哪个 broker 就验哪个：

```bash
# A. 已有集群（研发 / 测试环境）：不需要发布 agentd、不需要 Docker
WIST_KAFKA_LIVE=1 WIST_KAFKA_LIVE_BOOTSTRAP=kafka-dev.intra:9093 \
WIST_KAFKA_LIVE_PROTOCOL=SASL_SSL WIST_KAFKA_LIVE_MECHANISMS=SCRAM-SHA-512 \
WIST_KAFKA_LIVE_USER=wist-probe WIST_KAFKA_LIVE_PASSWORD='***' \
WIST_KAFKA_LIVE_CA_FILE=/etc/pki/kafka/ca.pem \
  cargo test --lib telemetry::metrics::kafka_live -- --ignored --test-threads=1 --nocapture

# B. 没有现成集群：起一个容器（两条 listener、三种机制）
dev/kafka-sasl/run.sh
```

验的是「真实现能不能接受我们手写的报文」（`Metadata v1` / `DescribeLogDirs v0` /
`SaslHandshake v1` / `SaslAuthenticate v0` + SCRAM）与 **advertised 地址可达性**
（探针的第二条连接靠它）。字段布局以 Kafka 3.9 的
`clients/src/main/resources/common/message/*.json` 为准；本地夹具不含 TLS，指向真集群时
可带 `CA_FILE`。

第 4 条（公有 CA）得用云上集群验；多 broker 下线、ACL 降级、大集群超时预算要上真实环境（§12）。

**镜像钉 Kafka 3.9.x**：只是为了让夹具可重现。真正的兼容性靠协商：
`DescribeLogDirs v0` 在 4.0 被移除（基线 v1，布局相同），`Metadata` 仍是 `v0-13`，
`SaslHandshake`/`SaslAuthenticate` 也没抬基线 —— 所以连 4.x 时协商会自动选 `DescribeLogDirs v1`。
要验证 4.x，把 `WIST_KAFKA_IMAGE` 指到 4.x 镜像跑同一组用例即可。

## 10. 明确不做

- **GSSAPI / Kerberos**：需要 keytab 与 SASL/GSSAPI 实现，不在本阶段；配置校验会直接拒绝这个机制名。
- **多轮 SASL 之外的自定义回调**（自定义 `SaslClientProvider` 之类）。
- **凭证托管**：网关不下发、不存储 Kafka 密码（见规格 §7）。

## 11. 消费组 lag / 状态（V2，已落地）

模块：`src/telemetry/metrics/kafka_groups.rs`（`kafka.rs` 只调 `collect()` 并把结果挂到集群级 target）。

### 11.1 链路与版本

```text
每个 broker:  ListGroups   (api 16, v0-v2)
                     ↓ 只保留 protocol_type ∈ {"consumer", ""}
每个组:      DescribeGroups (api 15, v0-v4)   → group_state
             OffsetFetch    (api  9, v2-v5)   → 提交位点（topics = null = 全部）
每个分区 leader: ListOffsets  (api  2, v1-v5)   → log end offset（timestamp = -1）
```

- 全部选**非 flexible 的最高版本**（flexible 分别从 v6/v6/v5/v3 开始），报文是简单大端布局；
  版本一律来自 `ApiVersions` 协商，不写死。
- `ListGroups` 是 per-broker 的（各 broker 只报自己协调的组），必须每个 broker 问一次；
  `DescribeGroups` / `OffsetFetch` 必须发给**组协调者**；`ListOffsets` 必须发给**分区 leader**。
- 连接按 broker 缓存（`Links`），一组的“Describe + OffsetFetch + 每 leader 一次 ListOffsets”
  共用连接；请求失败就丢掉这条缓存连接，否则一个报文错误会让后续每个组都死在死连接上。

### 11.2 lag 口径

```text
lag(group, topic) = Σ_partition max(0, log_end_offset - committed_offset)
```

- 用 LEO（`ListOffsets` timestamp = -1、`isolation_level = 0`），与 `kafka-consumer-groups.sh` 一致；
- `committed_offset < 0`（该分区没提交过）不计入；
- 负 lag（retention 删掉尾巴后会出现）按 0：上报负数会让「总积压」出现无法解释的洼地；
- 拿不到 LEO 的分区不进求和，并留一条「组 X 有 N 个分区拿不到 log end offset（lag 会偏低）」。

### 11.3 基数与过滤（规格 §5）

- `lag_group_allowlist` 非空 → **先按白名单筛选**，再应用 `max_groups` 上限（反过来的话，大集群里
  白名单里的组会被随机截掉 —— 而那正是白名单存在的场景）；只看白名单，不看阈值；
- 白名单为空 → 只发总 lag **> `lag_threshold`**（默认 1000）的组；
- 单轮最多查 `max_groups`（默认 200），超出**按组名稳定截断**并把丢弃数写进 warnings。
  （规格写的是「按 lag 降序取前 N」，但排序需要先把 N 个组的 lag 都算出来，成本正好是
  我们要限流的部分；按组名截断至少保证每轮截断的是同一批组，序列不会来回跳。）
- 白名单里的组名写错 / 还没创建时，会留一条 warning（否则现场只看到「配了却没数据」）。
- 阈值模式先按**组的合计 lag** 过阈，过阈后该组的所有 topic 都发（含 lag=0 的）——
  宁可多几条序列，也不要「知道这个组积压了，但看不出来到底堵在哪条 topic」。
- 组状态**不受阈值影响**：否则「rebalancing 但还没积压」的组会隐身。
- `kafka_consumergroup_lag` 的 label 是 `group` + `topic`；`kafka_consumergroup_state` 是一热
  （`state` label 承载取值，样本值恒 1），两者都挂在 `instance = kafka:<cluster_key>` 上。

### 11.4 真机验出来的两个坑（已有回归用例）

1. `DescribeGroups v3+` 请求末尾还有 `include_authorized_operations: bool`。漏掉它 broker
   解析请求时直接断开连接（假 broker 的解析器宽松，只有真机才能暴露）。
2. **连接失败后不能继续复用缓存连接**：broker 遇到解析不了的请求会关连接，
   不丢缓存就会变成「一个报文错误 → 全部组没有数据」。

夹具层面的同类坑：macOS/BSD 上 `accept()` 出来的 socket 会继承监听器的 `O_NONBLOCK`，
假 broker 里必须显式 `set_nonblocking(false)`，否则 `read_exact` 立刻返回 `WouldBlock`。

### 11.6 一轮的请求预算与复用（2026-11-05 review 补强）

- **LEO 是分区级读数，一轮只取一次**：
  `ListOffsets` 的结果按 `(topic, partition)` 缓存在**本轮**（`collect` 内部），所有组共用。
  请求数从 `组数 × leader 数` 降到 `leader 数`（200 组 / 30 leader：6000 → 30），
  而且同一轮里各组的 lag 用的是**同一时刻**的 LEO，「谁更落后」才有可比性。
  本轮已确认拿不到的分区（leader 不在 metadata / 分区级 error / 请求失败）记进
  `unresolved`，不会每个组再重试一次。
- **容量面有自己的总预算**（`capacity_budget`，默认 10s）：
  单个 broker 失败只影响它自己，但「不可达 broker 数 × 单次超时（默认 5s）」是串行叠加的，
  不封顶就会把同一轮的 lag 面一起饿死（所以组面现在也排在容量面**之前**）。
  超预算 → 少采尾部 broker 的容量 + 一条 warning，拓扑 / ISR / lag 不受影响。
- **目录级 `error_code` 不再静默**：`DescribeLogDirs` 单个 log dir 返回错误时，它不贡献容量；
  部分目录失败 → 合计照常但带 `failed_dirs` 计数（→ warning）；**全部目录都失败** → 整条容量读数
  报错（**不发 0**：0 会被读成「磁盘空」，与「一点都没读到」方向相反）。
- **`attempted_targets` 与 `succeeded_targets` 同口径**：都数**目标**（每 broker 一个 +
  一个集群级），不再用 bootstrap 地址数（否则 3 broker 的集群会出现 `attempted=1 / succeeded=4`，
  self-observability 那行自相矛盾）。

### 11.7 日志

单个组 / 单个 broker 的失败只进 `warnings`（不影响整轮）：

- `broker N (addr) ListGroups 失败：…`
- `组 X DescribeGroups 失败：…` / `组 X OffsetFetch 失败：…`
- `broker N (addr) ListOffsets 失败：…`（同轮同 API 只留一条）
- `组 X 有 N 个分区拿不到 log end offset（lag 会偏低）` —— 分区级 `error_code`（NOT_LEADER /
  元数据过期）与连不上 leader 都算在这里
- `组 X 有 N 个分区位点读取失败（lag 会偏低）` —— `OffsetFetch` 的分区级 error
- `本轮消费组采集超过 20s，后 N 个组本轮未采（…）`
- `消费组数超过 max_groups=…，本轮丢弃 N 个`
- `容量面超过预算 10000ms：后 N 个 broker 本轮不采（拓扑与 lag 不受影响）`
- `broker N (addr) 有 M 个 log dir 返回错误码（容量读数偏低）`
- `broker N (addr) DescribeLogDirs 失败：…`（含「N 个日志目录全部返回错误码」）

**逐组告警按原因聚合**（`GroupWarnings`）：大集群里「所有组都没权限 / 协调者都在迁移」
是常态故障，200 个组各一行会把日志刷满，而 `KafkaProbeWarning` 的闸门是按「内容变化」
判断的——组集合一变就重打一整屏。现在同一种原因只占一行：

- 单个组：`组 orders DescribeGroups 失败：error_code 15（组不存在 / 无权限）`（与原先一致）；
- 多个组（≤3）：`组 a, b, c OffsetFetch 失败：…`；
- 多个组（>3）：`62 个组（如 a, b, c…） DescribeGroups 失败：…`；
- 分区级缺失：`32 个组（如 a, b, c…） 共 183 个分区拿不到 log end offset（lag 会偏低）`。

所以告警文案里**不带组名**（组名已经给了，且在行首）；拿不到组名的错误
（比如 `DescribeGroups 返回的组是 X`）也要写成与请求组无关的形式，否则聚合失效。

探测线程按「warnings 内容变化」打日志（`event=KafkaProbeWarning`），不会 30s 一条地刷屏。
