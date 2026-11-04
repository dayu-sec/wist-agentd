# Kafka SASL/TLS 接入实现说明（交接文档）

> 规格见 `wist-design/doc/design/telemetry/kafka-broker-metrics-spec.md`。
> 本文只写「怎么把它实现掉」：模块边界、协议顺序、算法步骤、测试清单。
>
> 状态：**配置与校验已落地**（`[kafka]` 的 `security_protocol` / `sasl_mechanism` /
> `username` / `password_file` / `tls_ca_file`），**握手尚未实现** —— 当前只能连 `PLAINTEXT`。

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

`sha2` 已在 `[dev-dependencies]`，需要挪到 `[dependencies]`（SCRAM 运行时要用）；
`base64`、`rustls`、`rustls-platform-verifier`、`tokio-rustls` 已在 lock 中。

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

/// 建立一条已认证的流；失败时返回「能说明下一步」的错误。
pub fn connect(addr: &str, cfg: &SecurityConfig<'_>, timeout: Duration)
    -> io::Result<Box<dyn ReadWrite>>;
```

`fetch_metadata` / `fetch_log_dir_total` 改成走 `connect()`，其余逻辑不变
（仍然「连不上只影响该 broker，不出样本、不补 0」）。

## 4. 协议顺序

```text
TCP connect
  └─ (SSL | SASL_SSL)   TLS 握手
        rustls ClientConnection + StreamOwned<_, TcpStream>
        根证书：tls_ca_file 给了就用它（rustls-pemfile 读 PEM），否则 platform verifier
        ServerName 用 bootstrap 的 host（IP 也能构造，但优先 hostname）
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
- `SaslAuthenticate` 用 **v0**（Kafka 1.0+）。更老的 broker 用裸帧，V1 不支持，直接报版本不足。
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

## 9. 验收

1. 三种机制各自能连上对应的测试集群（`SASL_SSL` 为主）；
2. 错密码 / 错机制 / 错 CA 三种失败，日志能一眼区分；
3. 认证失败时日志与诊断包里**搜不到密码**；
4. `security_protocol = "SSL"` 且不给 CA、系统根可用时，能连公有 CA 签发的集群。

## 10. 明确不做

- **GSSAPI / Kerberos**：需要 keytab 与 SASL/GSSAPI 实现，不在本阶段；配置校验会直接拒绝这个机制名。
- **多轮 SASL 之外的自定义回调**（自定义 `SaslClientProvider` 之类）。
- **凭证托管**：网关不下发、不存储 Kafka 密码（见规格 §7）。
