# Kafka 真 broker 验收（§9）

用例在 `src/telemetry/metrics/kafka_live.rs`，全部 `#[ignore]`。**默认不跑**，指到哪个 broker
就验哪个 —— 两种入口：

## A. 指向已有集群（研发 / 测试环境，推荐）

不需要 Docker、**不需要发布 agentd**。在能连到 broker 的机器上：

```bash
WIST_KAFKA_LIVE=1 \
WIST_KAFKA_LIVE_BOOTSTRAP=kafka-dev.intra:9093 \
WIST_KAFKA_LIVE_PROTOCOL=SASL_SSL \
WIST_KAFKA_LIVE_MECHANISMS=SCRAM-SHA-512 \
WIST_KAFKA_LIVE_USER=wist-probe \
WIST_KAFKA_LIVE_PASSWORD='***' \
WIST_KAFKA_LIVE_CA_FILE=/etc/pki/kafka/ca.pem \
  cargo test --lib telemetry::metrics::kafka_live -- --ignored --test-threads=1 --nocapture
```

| 变量 | 说明 |
|---|---|
| `WIST_KAFKA_LIVE_BOOTSTRAP` | `host:port`，随便挑一个能连的 broker |
| `WIST_KAFKA_LIVE_PROTOCOL` | `PLAINTEXT` / `SSL` / `SASL_PLAINTEXT` / `SASL_SSL`（默认 `PLAINTEXT`） |
| `WIST_KAFKA_LIVE_MECHANISMS` | 逗号分隔，SASL 必填（`PLAIN` / `SCRAM-SHA-256` / `SCRAM-SHA-512`） |
| `WIST_KAFKA_LIVE_USER` / `_PASSWORD` | SASL 必填；密码只落到本机临时文件（0600），不进日志 |
| `WIST_KAFKA_LIVE_CA_FILE` | `SSL` / `SASL_SSL` 可选；不给就走系统根 |

跑之前先看集群侧三件事，能省一轮来回：

- **版本**：`kafka-broker-api-versions.sh --bootstrap-server … | head`。探针会先发
  `ApiVersions` 再选版本（Metadata v1/v2、DescribeLogDirs v0/v1），所以 0.10 → 4.x 都能连；
  只有在双方区间**没有交集**时才会报「broker 是 vX-vY，探针只支持 vA-vB」。
- **advertised 地址**：探针的第二条连接（`DescribeLogDirs`）按 metadata 里的
  `host:port` 去连。集群如果只广告了 k8s 内部 DNS、而你在集群外跑，这一步会失败 ——
  用例会把失败的 broker 和原因逐条列出来。
- **权限**：探测用户至少要能 `DescribeLogDirs`（否则容量读数缺失，用例会列出 broker）。

## B. 本地起一个（没有现成集群时）

```bash
dev/kafka-sasl/run.sh            # 起 → 测 → 收拾
dev/kafka-sasl/run.sh --keep     # 留着，自己再连
```

一个容器、两条 listener（`SASL_PLAINTEXT:9092` / `PLAINTEXT:9093`）、三种机制、
KRaft 单节点。首次要拉镜像（~600MB），之后每次十几秒。**不进 CI**。

## 它值什么

真 broker 才能证的两件事：

1. 手写的 `Metadata v1` / `DescribeLogDirs v0` / `SaslHandshake v1` / `SaslAuthenticate v0`
   报文与 SCRAM 的 challenge/response，真实 Kafka 能接受（字段布局以 Kafka 3.9 的
   `clients/src/main/resources/common/message/*.json` 为准；假 broker 是照同一份理解写的，
   所以**它发现不了布局本身的错**——`Metadata v1` 少读 rack、`DescribeLogDirs v0` 少读
   throttle 两个 bug 就是这么漏过去的）；
2. advertised 地址从这台机器到底通不通。

**它不验什么**：TLS 证书链（离线用例已在真 rustls 服务端 + 真 CA 上覆盖）、多 broker
下线行为、ACL 降级、大集群超时预算 —— 那些要靠真实环境按 §9/§12 验收。
