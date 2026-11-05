//! Kafka 连接层：TCP → TLS → SASL，交出一条「已经能直接用」的流。
//!
//! 上层 `kafka.rs` 只关心报文（`Metadata` / `DescribeLogDirs`），这里负责四件事：
//! 建 TCP、TLS 握手、SASL 机制协商、SASL 认证（SCRAM / PLAIN）。
//!
//! 设计见 `docs/design/kafka-sasl-implementation.md`。边界：
//!
//! - 只做 `SCRAM-SHA-256` / `SCRAM-SHA-512` / `PLAIN`；`auto` 只从 broker 回的机制
//!   列表里挑（512 > 256 > PLAIN），**不猜、不跨机制重试**；
//! - 不支持 channel binding（`c=biws`），不做 GSSAPI；
//! - 密码只从文件读、读完即用即丢；**日志与错误里绝不出现密码或 auth_bytes**
//!   （SCRAM 的 client-final 里有 proof，泄露它等于泄露口令的派生物）。

use std::collections::BTreeMap;
use std::fs;
use std::io::{self, BufReader, Read, Write};
use std::net::{SocketAddr, TcpStream, ToSocketAddrs};
use std::sync::Arc;
use std::time::Duration;

use base64::Engine as _;
use base64::engine::general_purpose::STANDARD as BASE64;
use hmac::{Hmac, Mac};
use rustls::pki_types::ServerName;
use rustls::{ClientConfig, ClientConnection, RootCertStore, StreamOwned};
use sha2::{Digest, Sha256, Sha512};

use super::kafka::{Reader, invalid};

/// 一帧响应的上限：与 `kafka.rs` 的 `round_trip` 同一条纪律（畸形长度不许吃掉内存）。
const MAX_RESPONSE_BYTES: i32 = 64 * 1024 * 1024;

/// SASL 帧里的 `client_id`。
///
/// `connect()` 的入参只有地址与安全配置（见设计文档 §3），握手用的 client_id 就固定成
/// 进程名 —— broker 侧看到的是同一个客户端，和业务请求的 client_id 不必强求一致。
const SASL_CLIENT_ID: &str = "wist-agentd";

const API_KEY_SASL_HANDSHAKE: i16 = 17;
/// v1：Kafka 1.0+ 的 `SaslAuthenticate` 就绪版本。更老的 broker 走裸帧，不支持。
const API_VERSION_SASL_HANDSHAKE: i16 = 1;
const API_KEY_SASL_AUTHENTICATE: i16 = 36;
const API_VERSION_SASL_AUTHENTICATE: i16 = 0;

/// `ApiVersions`：连上就发它，先问清 broker 到底支持哪些版本。
const API_KEY_API_VERSIONS: i16 = 18;
/// 必须用 v0：还不知道对方支持什么版本时，这是唯一能保证被接受的。
const API_VERSION_API_VERSIONS: i16 = 0;
const API_KEY_METADATA: i16 = 3;
const API_KEY_DESCRIBE_LOG_DIRS: i16 = 35;
const API_KEY_LIST_OFFSETS: i16 = 2;
const API_KEY_OFFSET_FETCH: i16 = 9;
const API_KEY_DESCRIBE_GROUPS: i16 = 15;
const API_KEY_LIST_GROUPS: i16 = 16;

/// 本探针能解析的 Metadata 版本区间。
///
/// v1 有 rack（0.10+），v2 多一个 `cluster_id`（0.10.1+）；v3/v4 多 throttle、
/// v5 多 `offline_replicas`、v9 起是 flexible 版本。只做到 v2：再往上要改布局，
/// 而 v1/v2 在所有仍被支持的 broker（包括 4.x，其 `validVersions` 仍是 `0-13`）上都可用。
const METADATA_VERSIONS: (i16, i16) = (1, 2);
/// 消费组 lag 相关三件套：都用 non-flexible 的最高版（flexible 从 v6/v6/v5 才开始）。
const LIST_OFFSETS_VERSIONS: (i16, i16) = (1, 5);
const OFFSET_FETCH_VERSIONS: (i16, i16) = (2, 5);
const DESCRIBE_GROUPS_VERSIONS: (i16, i16) = (0, 4);
const LIST_GROUPS_VERSIONS: (i16, i16) = (0, 2);

/// 本探针能解析的 `DescribeLogDirs` 版本区间。
///
/// v0 已在 Kafka 4.0 被移除（基线 v1），而 **v0 与 v1 的响应布局完全一样**
/// （v1 只是改了限流时机），所以同一个解析器能服务两者；v2 起是 flexible，v4 才有总量。
const DESCRIBE_LOG_DIRS_VERSIONS: (i16, i16) = (0, 4);

const CORRELATION_HANDSHAKE: i32 = 21;
const CORRELATION_AUTH_FIRST: i32 = 22;
const CORRELATION_AUTH_FINAL: i32 = 23;
const CORRELATION_API_VERSIONS: i32 = 20;

/// SCRAM 迭代次数的上限：broker 若声明一个天文数字，PBKDF2 会把探针线程挂死。
/// （Kafka 默认 4096，翻到百万级已经远超现实配置。）
const MAX_SCRAM_ITERATIONS: u32 = 2_000_000;

/// 已认证的双向流。明文 TCP 与 TLS 都包成它，上层不需要区分。
pub trait ReadWrite: Read + Write {}

impl<T: Read + Write> ReadWrite for T {}

/// 安全参数（来自 `[kafka]` 段，按借用视图传进来，避免每轮探测都克隆字符串）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SecurityConfig<'a> {
    /// `PLAINTEXT` | `SSL` | `SASL_PLAINTEXT` | `SASL_SSL`。
    pub protocol: &'a str,
    /// `auto` | `SCRAM-SHA-512` | `SCRAM-SHA-256` | `PLAIN`。
    pub mechanism: &'a str,
    pub username: Option<&'a str>,
    pub password_file: Option<&'a str>,
    pub tls_ca_file: Option<&'a str>,
}

/// `SecurityConfig` 的持有版：由守护进程从配置里拷一份交给采集线程。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct OwnedSecurityConfig {
    pub protocol: String,
    pub mechanism: String,
    pub username: Option<String>,
    pub password_file: Option<String>,
    pub tls_ca_file: Option<String>,
}

impl Default for OwnedSecurityConfig {
    fn default() -> Self {
        Self {
            // 与 `KafkaSection` 的默认值保持一致：不加安全参数就是明文。
            protocol: "PLAINTEXT".to_string(),
            mechanism: "auto".to_string(),
            username: None,
            password_file: None,
            tls_ca_file: None,
        }
    }
}

impl OwnedSecurityConfig {
    pub fn borrowed(&self) -> SecurityConfig<'_> {
        SecurityConfig {
            protocol: &self.protocol,
            mechanism: &self.mechanism,
            username: self.username.as_deref(),
            password_file: self.password_file.as_deref(),
            tls_ca_file: self.tls_ca_file.as_deref(),
        }
    }
}

/// 一个 API 的协商结果。
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub struct ApiVersion {
    /// 双方都支持的版本；`None` = 这个能力用不了（没声明 / 区间不相交）。
    pub version: Option<i16>,
    /// broker 声明的区间，报错时用。
    pub range: Option<(i16, i16)>,
}

impl ApiVersion {
    fn negotiate(name: &str, range: Option<(i16, i16)>, ours: (i16, i16)) -> Self {
        Self {
            version: range.and_then(|broker| pick_version(name, broker, ours).ok()),
            range,
        }
    }

    /// 能力用不了时给一句能直接进日志的话（哪个 API、双方区间）。
    pub fn unavailable_reason(&self, name: &str) -> String {
        match self.range {
            Some((min, max)) => {
                format!("broker 的 {name} 版本区间是 v{min}-v{max}，与本探针支持的区间没有交集")
            }
            None => format!("broker 没有声明 {name}"),
        }
    }
}

/// 协商出来的版本（后续每个请求按它编码/解析）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ApiVersions {
    /// 双方都支持的 Metadata 版本（必然可用，否则整条链路没意义）。
    pub metadata: i16,
    pub describe_log_dirs: ApiVersion,
    pub list_offsets: ApiVersion,
    pub offset_fetch: ApiVersion,
    pub describe_groups: ApiVersion,
    pub list_groups: ApiVersion,
}

/// 一条已经建好、并且完成版本协商（以及 SASL 认证）的连接。
pub struct Connection {
    pub versions: ApiVersions,
    pub stream: Box<dyn ReadWrite>,
}

/// 建立一条已认证的流，并先问清 broker 支持哪些协议版本。
///
/// 顺序是 TCP →（TLS）→ **ApiVersions** →（SASL）：ApiVersions 必须在认证前问
/// （Kafka 允许未认证连接发它，这也是所有官方客户端的行为），否则一旦 broker 抬了
/// 最低认证版本，我们就永远问不到了。
///
/// 地址解析出的每个地址都会试一遍，与 `kafka.rs` 原来的 `round_trip` 一致。
pub fn connect(addr: &str, cfg: &SecurityConfig<'_>, timeout: Duration) -> io::Result<Connection> {
    let protocol = Protocol::parse(cfg.protocol)?;
    // 凭据在**建连之前**读：读不到就别进握手（错误里有路径，运维能直接改）。
    let credentials = if protocol.sasl() {
        Some(Credentials::load(cfg)?)
    } else {
        None
    };
    // `auto` 先不带结论：第一跳用首选机制试探，broker 回的列表才是权威。
    let mut mechanism = if protocol.sasl() && !cfg.mechanism.eq_ignore_ascii_case("auto") {
        Some(Mechanism::parse(cfg.mechanism)?)
    } else {
        None
    };

    let mut last: Option<io::Error> = None;
    // 正常情况只跑一轮。第二轮只在 `auto` 的机制协商要求换机制时发生 ——
    // broker 在握手失败后会关连接，换机制只能重开 TCP，不能在同一条流上重试。
    let mut switched = false;
    loop {
        let peers = addr
            .to_socket_addrs()
            .map_err(|err| invalid(format!("cannot resolve {addr}: {err}")))?;
        let mut switch_to = None;
        for peer in peers {
            match attempt(
                peer,
                addr,
                protocol,
                cfg,
                credentials.as_ref(),
                mechanism,
                timeout,
            ) {
                Ok(Attempt::Connected(stream)) => return Ok(stream),
                Ok(Attempt::Switch(resolved)) => {
                    // 机制是集群级的：一个 broker 这么说，别的也一样，直接从头来。
                    switch_to = Some(resolved);
                    break;
                }
                Err(err) => {
                    last = Some(match last {
                        Some(current) => prefer_error(current, err),
                        None => err,
                    })
                }
            }
        }
        // 一轮全失败（或根本没解析出地址）：如实回报，**不要**再试一次 ——
        // 重连只会把第一条真实错误（认证 / TLS）盖成 ECONNREFUSED。
        let Some(resolved) = switch_to else {
            return Err(last.unwrap_or_else(|| invalid(format!("cannot resolve {addr}"))));
        };
        if switched {
            return Err(invalid(
                "SASL 机制协商没有收敛：broker 连续两次要求换机制".to_string(),
            ));
        }
        switched = true;
        mechanism = Some(resolved);
    }
}

/// 一个域名解析出多个地址时，优先报「更说明问题」的那条错。
///
/// 双栈（`localhost` → `::1` + `127.0.0.1`）很常见：某个族根本没有监听，另一族却是
/// 证书/认证不对。报 `Connection refused` 会把真因埋掉，而 §7 要求这两种一眼能区分。
fn prefer_error(current: io::Error, candidate: io::Error) -> io::Error {
    if severity(&candidate) > severity(&current) {
        candidate
    } else {
        current
    }
}

/// `0` = 连接层失败（换个地址可能就好了），`1` = 已经连上但握手/认证不对。
fn severity(err: &io::Error) -> u8 {
    match err.kind() {
        io::ErrorKind::ConnectionRefused
        | io::ErrorKind::ConnectionReset
        | io::ErrorKind::ConnectionAborted
        | io::ErrorKind::NotConnected
        | io::ErrorKind::TimedOut => 0,
        _ => 1,
    }
}

/// 发一帧、读一帧（Kafka 传输格式：4 字节大端长度 + 载荷）。
///
/// 放在这里而不是 `kafka.rs`：TLS 之后读写的也是这个帧格式，两边共用一份边界检查。
pub fn exchange(stream: &mut dyn ReadWrite, payload: &[u8]) -> io::Result<Vec<u8>> {
    stream.write_all(payload)?;
    stream.flush()?;

    let mut size = [0u8; 4];
    stream.read_exact(&mut size).map_err(|err| {
        invalid(format!(
            "Kafka 响应头读取失败（连接可能已被 broker 关闭）：{err}"
        ))
    })?;
    let len = i32::from_be_bytes(size);
    if !(0..=MAX_RESPONSE_BYTES).contains(&len) {
        return Err(invalid(format!("invalid response size {len}")));
    }
    let mut body = vec![0u8; len as usize];
    stream
        .read_exact(&mut body)
        .map_err(|err| invalid(format!("Kafka 响应体读取失败（声明 {len} 字节）：{err}")))?;
    Ok(body)
}

// ---------------------------------------------------------------------------
// 版本协商（ApiVersions）
// ---------------------------------------------------------------------------

/// 问一次 `ApiVersions` v0，挑出双方都能用的版本。
fn negotiate_versions(stream: &mut dyn ReadWrite) -> io::Result<ApiVersions> {
    let request = encode_api_versions_request(CORRELATION_API_VERSIONS, SASL_CLIENT_ID);
    let response = exchange(stream, &request)?;
    let supported = parse_api_versions(&response, CORRELATION_API_VERSIONS)?;

    let metadata_range = supported
        .get(&API_KEY_METADATA)
        .copied()
        .ok_or_else(|| invalid("broker 没有声明 Metadata（Kafka < 0.8？）".to_string()))?;
    let metadata = pick_version("Metadata", metadata_range, METADATA_VERSIONS)?;

    Ok(ApiVersions {
        metadata,
        // 下面这些面都允许退化：用不了就少一类读数，不影响拓扑/ISR/离线分区。
        // 原因交给上层打 warning（比默默不发好得多）。
        describe_log_dirs: ApiVersion::negotiate(
            "DescribeLogDirs",
            supported.get(&API_KEY_DESCRIBE_LOG_DIRS).copied(),
            DESCRIBE_LOG_DIRS_VERSIONS,
        ),
        list_offsets: ApiVersion::negotiate(
            "ListOffsets",
            supported.get(&API_KEY_LIST_OFFSETS).copied(),
            LIST_OFFSETS_VERSIONS,
        ),
        offset_fetch: ApiVersion::negotiate(
            "OffsetFetch",
            supported.get(&API_KEY_OFFSET_FETCH).copied(),
            OFFSET_FETCH_VERSIONS,
        ),
        describe_groups: ApiVersion::negotiate(
            "DescribeGroups",
            supported.get(&API_KEY_DESCRIBE_GROUPS).copied(),
            DESCRIBE_GROUPS_VERSIONS,
        ),
        list_groups: ApiVersion::negotiate(
            "ListGroups",
            supported.get(&API_KEY_LIST_GROUPS).copied(),
            LIST_GROUPS_VERSIONS,
        ),
    })
}

/// 取双方区间的交集上限；没有交集就报「谁该升级」。
fn pick_version(name: &str, broker: (i16, i16), ours: (i16, i16)) -> io::Result<i16> {
    let (broker_min, broker_max) = broker;
    let (our_min, our_max) = ours;
    if broker_min > our_max || broker_max < our_min {
        return Err(invalid(format!(
            "broker 声明的 {name} 版本区间是 v{broker_min}-v{broker_max}，本探针只支持 v{our_min}-v{our_max}：\
             升级 broker 或探针（KIP-896 之后旧版本会被移除）"
        )));
    }
    Ok(broker_max.min(our_max))
}

/// 解析 `ApiVersions` v0 响应 → `api_key → (min, max)`。
fn parse_api_versions(
    response: &[u8],
    correlation_id: i32,
) -> io::Result<BTreeMap<i16, (i16, i16)>> {
    let mut reader = Reader::new(response);
    let got = reader.i32()?;
    if got != correlation_id {
        return Err(invalid(format!("unexpected correlation id {got}")));
    }
    let error_code = reader.i16()?;
    if error_code != 0 {
        // 说清是「版本」问题而不是「认证/网络」问题：现场第一步就要能分流。
        return Err(invalid(format!(
            "broker 拒绝 ApiVersions v0（error_code {error_code}，35 = UNSUPPORTED_VERSION）：\
             需要 Kafka 0.10+，或中间代理不支持这个 API"
        )));
    }
    let count = reader.array_len()?;
    let mut supported = BTreeMap::new();
    for _ in 0..count {
        let api_key = reader.i16()?;
        let min_version = reader.i16()?;
        let max_version = reader.i16()?;
        supported.insert(api_key, (min_version, max_version));
    }
    Ok(supported)
}

fn encode_api_versions_request(correlation_id: i32, client_id: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_API_VERSIONS.to_be_bytes());
    body.extend_from_slice(&API_VERSION_API_VERSIONS.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    // v0 请求体没有额外字段。
    frame(body)
}

// ---------------------------------------------------------------------------
// 传输层：协议 → (TLS, SASL)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Protocol {
    Plaintext,
    Tls,
    SaslPlaintext,
    SaslTls,
}

impl Protocol {
    fn parse(raw: &str) -> io::Result<Self> {
        match raw {
            "PLAINTEXT" => Ok(Self::Plaintext),
            "SSL" => Ok(Self::Tls),
            "SASL_PLAINTEXT" => Ok(Self::SaslPlaintext),
            "SASL_SSL" => Ok(Self::SaslTls),
            other => Err(invalid(format!(
                "unsupported security_protocol `{other}`（只支持 PLAINTEXT / SSL / SASL_PLAINTEXT / SASL_SSL）"
            ))),
        }
    }

    fn tls(self) -> bool {
        matches!(self, Self::Tls | Self::SaslTls)
    }

    fn sasl(self) -> bool {
        matches!(self, Self::SaslPlaintext | Self::SaslTls)
    }
}

/// 一次地址尝试的结果。
enum Attempt {
    Connected(Connection),
    /// broker 的机制列表说明该换一个机制：必须从 TCP 重来。
    Switch(Mechanism),
}

/// 一次地址尝试：TCP →（TLS）→ ApiVersions →（SASL）。
fn attempt(
    peer: SocketAddr,
    addr: &str,
    protocol: Protocol,
    cfg: &SecurityConfig<'_>,
    credentials: Option<&Credentials>,
    mechanism: Option<Mechanism>,
    timeout: Duration,
) -> io::Result<Attempt> {
    let tcp = TcpStream::connect_timeout(&peer, timeout)?;
    tcp.set_read_timeout(Some(timeout))?;
    tcp.set_write_timeout(Some(timeout))?;

    let mut stream: Box<dyn ReadWrite> = if protocol.tls() {
        Box::new(tls_handshake(tcp, addr, cfg.tls_ca_file)?)
    } else {
        Box::new(tcp)
    };

    let versions = negotiate_versions(&mut *stream)?;

    let Some(credentials) = credentials else {
        return Ok(Attempt::Connected(Connection { versions, stream }));
    };
    match sasl_login(&mut *stream, cfg, credentials, mechanism)? {
        SaslOutcome::Authenticated => Ok(Attempt::Connected(Connection { versions, stream })),
        SaslOutcome::Switch(resolved) => Ok(Attempt::Switch(resolved)),
    }
}

// ---------------------------------------------------------------------------
// TLS
// ---------------------------------------------------------------------------

fn tls_handshake(
    tcp: TcpStream,
    addr: &str,
    ca_file: Option<&str>,
) -> io::Result<StreamOwned<ClientConnection, TcpStream>> {
    let config = tls_config(ca_file)?;
    let host = host_of(addr);
    let server_name = ServerName::try_from(host.to_string())
        .map_err(|err| invalid(format!("TLS 主机名 `{host}` 不能用于证书校验：{err}")))?;
    let conn = ClientConnection::new(config, server_name)
        .map_err(|err| invalid(format!("{addr}: TLS 初始化失败：{err}")))?;

    let mut stream = StreamOwned::new(conn, tcp);
    // `StreamOwned` 是惰性的：握手要自己推，推完才算「连上了」。
    while stream.conn.is_handshaking() {
        if let Err(err) = stream.conn.complete_io(&mut stream.sock) {
            let reason = classify_tls_error(&err);
            return Err(invalid(format!("{addr}: {reason}")));
        }
    }
    Ok(stream)
}

/// 把 rustls 的错误分成「验证失败」与「握手失败」：现场的这两种情况处理方式完全不同
/// （改 CA / 改地址），错误文本必须能一眼区分。
fn classify_tls_error(err: &io::Error) -> String {
    match err
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
    {
        Some(rustls::Error::InvalidCertificate(reason)) => {
            format!("TLS 证书验证失败（{reason:?}）：{err}")
        }
        Some(other) => format!("TLS 握手失败：{other}"),
        None => format!("TLS 握手失败：{err}"),
    }
}

fn tls_config(ca_file: Option<&str>) -> io::Result<Arc<ClientConfig>> {
    install_crypto_provider();
    match ca_file {
        // 给了 CA 就**只用它**：运维显式指定信任锚时，回落到系统根等于放宽信任面。
        Some(path) => {
            let pem = fs::read(path)
                .map_err(|err| invalid(format!("读取 tls_ca_file `{path}` 失败：{err}")))?;
            let mut roots = RootCertStore::empty();
            let mut added = 0usize;
            for cert in rustls_pemfile::certs(&mut BufReader::new(pem.as_slice())) {
                let cert =
                    cert.map_err(|err| invalid(format!("解析 tls_ca_file `{path}` 失败：{err}")))?;
                roots.add(cert).map_err(|err| {
                    invalid(format!("tls_ca_file `{path}` 里的证书不能当根：{err}"))
                })?;
                added += 1;
            }
            if added == 0 {
                return Err(invalid(format!("tls_ca_file `{path}` 里没有 PEM 证书")));
            }
            Ok(Arc::new(
                ClientConfig::builder()
                    .with_root_certificates(roots)
                    .with_no_client_auth(),
            ))
        }
        None => {
            use rustls_platform_verifier::ConfigVerifierExt;
            let config = ClientConfig::with_platform_verifier().map_err(|err| {
                invalid(format!("系统根证书不可用（可显式配 tls_ca_file）：{err}"))
            })?;
            Ok(Arc::new(config))
        }
    }
}

fn install_crypto_provider() {
    if rustls::crypto::CryptoProvider::get_default().is_some() {
        return;
    }
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
}

/// 从 `host:port` / `[v6]:port` 里取主机名：证书校验用的是**配置里的名字**，
/// 不是解析出来的 IP（解析到 IP 反而会让主机名校验失效）。
fn host_of(addr: &str) -> &str {
    let host = addr
        .rsplit_once(':')
        .map(|(host, _port)| host)
        .unwrap_or(addr);
    host.strip_prefix('[')
        .and_then(|inner| inner.strip_suffix(']'))
        .unwrap_or(host)
}

// ---------------------------------------------------------------------------
// 凭据
// ---------------------------------------------------------------------------

struct Credentials {
    username: String,
    password: String,
}

impl std::fmt::Debug for Credentials {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // 密码永远不进 Debug 输出：任何一处 `{:?}` 都不该成为泄露路径。
        f.debug_struct("Credentials")
            .field("username", &self.username)
            .field("password", &"<redacted>")
            .finish()
    }
}

impl Credentials {
    fn load(cfg: &SecurityConfig<'_>) -> io::Result<Self> {
        // 用户名去首尾空白（配置里多一个空格几乎总是手误），密码不动（空格有意义）。
        let username = cfg.username.unwrap_or_default().trim();
        if username.is_empty() {
            return Err(invalid("SASL 需要 username".to_string()));
        }
        let path = cfg.password_file.unwrap_or_default().trim();
        if path.is_empty() {
            return Err(invalid("SASL 需要 password_file".to_string()));
        }
        Ok(Self {
            username: username.to_string(),
            password: read_password(path)?,
        })
    }
}

/// 密码文件的上限：正常密码几十字节，超过这个数一定是路径指错了（比如指到 `/dev/zero`）。
const MAX_PASSWORD_BYTES: u64 = 64 * 1024;

/// 读密码文件：只要求可读（`0600` 是运维约定，不是我们的接口），
/// 去掉行尾 `\r\n` 后使用，读完即丢弃。
fn read_password(path: &str) -> io::Result<String> {
    let file = fs::File::open(path)
        .map_err(|err| invalid(format!("读取 SASL password_file `{path}` 失败：{err}")))?;
    let mut raw = Vec::new();
    file.take(MAX_PASSWORD_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|err| invalid(format!("读取 SASL password_file `{path}` 失败：{err}")))?;
    if raw.len() as u64 > MAX_PASSWORD_BYTES {
        return Err(invalid(format!(
            "SASL password_file `{path}` 超过 {MAX_PASSWORD_BYTES} 字节（路径是不是指错了）"
        )));
    }
    let text = String::from_utf8(raw)
        .map_err(|_| invalid(format!("SASL password_file `{path}` 不是 UTF-8")))?;
    // 只去行尾换行：密码里的空格是有意义的。
    Ok(text.trim_end_matches(['\r', '\n']).to_string())
}

// ---------------------------------------------------------------------------
// SASL
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Mechanism {
    ScramSha512,
    ScramSha256,
    Plain,
}

impl Mechanism {
    fn as_str(self) -> &'static str {
        match self {
            Self::ScramSha512 => "SCRAM-SHA-512",
            Self::ScramSha256 => "SCRAM-SHA-256",
            Self::Plain => "PLAIN",
        }
    }

    fn parse(raw: &str) -> io::Result<Self> {
        match raw {
            "SCRAM-SHA-512" => Ok(Self::ScramSha512),
            "SCRAM-SHA-256" => Ok(Self::ScramSha256),
            "PLAIN" => Ok(Self::Plain),
            other => Err(invalid(format!(
                "unsupported sasl_mechanism `{other}`（只支持 auto / SCRAM-SHA-512 / SCRAM-SHA-256 / PLAIN）"
            ))),
        }
    }

    fn hash(self) -> Option<ScramHash> {
        match self {
            Self::ScramSha512 => Some(ScramHash::Sha512),
            Self::ScramSha256 => Some(ScramHash::Sha256),
            Self::Plain => None,
        }
    }
}

/// `auto` 的优先级：只从 broker 声明的列表里挑，挑不到就报列表。
fn select_mechanism(requested: &str, offered: &[String]) -> io::Result<Mechanism> {
    let is_offered = |name: &str| offered.iter().any(|item| item.eq_ignore_ascii_case(name));

    let resolved = if requested.eq_ignore_ascii_case("auto") {
        [
            Mechanism::ScramSha512,
            Mechanism::ScramSha256,
            Mechanism::Plain,
        ]
        .into_iter()
        .find(|candidate| is_offered(candidate.as_str()))
    } else {
        // 显式选的机制 broker 不支持时**不跨机制重试**：换机制重试等于拿密码去猜。
        let explicit = Mechanism::parse(requested)?;
        is_offered(explicit.as_str()).then_some(explicit)
    };

    resolved.ok_or_else(|| {
        invalid(format!(
            "SASL 机制 `{requested}` 不被 broker 接受；broker 启用了 {}",
            describe_mechanisms(offered)
        ))
    })
}

fn describe_mechanisms(offered: &[String]) -> String {
    if offered.is_empty() {
        // 空列表通常是 listener 没开 SASL，把它说清楚，别让人以为是密码错。
        "（没声明任何 SASL 机制；检查 listener 的 sasl.enabled.mechanisms）".to_string()
    } else {
        offered.join(" / ")
    }
}

/// broker 回的错误码就三种可能（Kafka 协议 §SaslHandshake），翻成人话。
fn describe_sasl_error(code: i16) -> &'static str {
    match code {
        33 => "UNSUPPORTED_SASL_MECHANISM：broker 没启用这个机制",
        34 => "ILLEGAL_SASL_STATE：listener 的 SASL 状态不对（通常没配 sasl.enabled.mechanisms）",
        35 => "UNSUPPORTED_VERSION：broker 太老，SaslHandshake v1 需要 Kafka 1.0+",
        _ => "未知错误码",
    }
}

enum SaslOutcome {
    Authenticated,
    /// 机制协商要求换一个（`auto` 专用），调用方必须重开连接。
    Switch(Mechanism),
}

fn sasl_login(
    stream: &mut dyn ReadWrite,
    cfg: &SecurityConfig<'_>,
    credentials: &Credentials,
    mechanism: Option<Mechanism>,
) -> io::Result<SaslOutcome> {
    // `auto` 没有先验知识，先用最强机制试探；broker 的列表才作数。
    let probe = mechanism.unwrap_or(Mechanism::ScramSha512);
    let handshake = sasl_handshake(stream, probe)?;

    let resolved = match select_mechanism(cfg.mechanism, &handshake.mechanisms) {
        Ok(resolved) => resolved,
        Err(err) if handshake.error_code == 0 => return Err(err),
        Err(err) => {
            return Err(invalid(format!(
                "{err}；SaslHandshake error_code {}（{}）",
                handshake.error_code,
                describe_sasl_error(handshake.error_code)
            )));
        }
    };

    if handshake.error_code != 0 {
        // 机制在 broker 的列表里、握手却还是失败：问题在 listener 状态或 broker 版本，
        // 换机制解决不了 —— 直接报原因，不再重连。
        if resolved == probe {
            return Err(invalid(format!(
                "SaslHandshake 被 broker 拒绝（error_code {}：{}）；broker 启用了 {}",
                handshake.error_code,
                describe_sasl_error(handshake.error_code),
                describe_mechanisms(&handshake.mechanisms)
            )));
        }
        return Ok(SaslOutcome::Switch(resolved));
    }

    if resolved != probe {
        return Ok(SaslOutcome::Switch(resolved));
    }

    match resolved.hash() {
        Some(hash) => authenticate_scram(stream, hash, credentials)?,
        None => {
            let payload = plain_payload(&credentials.username, &credentials.password)?;
            // PLAIN 的应答里没有 auth_bytes；错误已经由 `sasl_step` 转成可读原因。
            let _ = sasl_step(stream, CORRELATION_AUTH_FIRST, &payload)?;
        }
    }
    Ok(SaslOutcome::Authenticated)
}

struct SaslHandshakeResponse {
    error_code: i16,
    mechanisms: Vec<String>,
}

fn sasl_handshake(
    stream: &mut dyn ReadWrite,
    mechanism: Mechanism,
) -> io::Result<SaslHandshakeResponse> {
    let request =
        encode_sasl_handshake_request(CORRELATION_HANDSHAKE, SASL_CLIENT_ID, mechanism.as_str());
    let response = exchange(stream, &request)?;

    let mut reader = Reader::new(&response);
    let correlation_id = reader.i32()?;
    if correlation_id != CORRELATION_HANDSHAKE {
        return Err(invalid(format!(
            "unexpected correlation id {correlation_id}"
        )));
    }
    let error_code = reader.i16()?;
    let count = reader.array_len()?;
    let mut mechanisms = Vec::with_capacity(count);
    for _ in 0..count {
        mechanisms.push(reader.string()?);
    }
    Ok(SaslHandshakeResponse {
        error_code,
        mechanisms,
    })
}

/// 一次 `SaslAuthenticate` 往返，返回 broker 回的 auth_bytes。
fn sasl_step(
    stream: &mut dyn ReadWrite,
    correlation_id: i32,
    auth_bytes: &[u8],
) -> io::Result<Vec<u8>> {
    let request = encode_sasl_authenticate_request(correlation_id, SASL_CLIENT_ID, auth_bytes);
    let response = exchange(stream, &request)?;

    let mut reader = Reader::new(&response);
    let got = reader.i32()?;
    if got != correlation_id {
        return Err(invalid(format!("unexpected correlation id {got}")));
    }
    let error_code = reader.i16()?;
    // 先处理错误码再解 `error_message`：broker 的拒绝原因是这条路径上最有信息量的东西，
    // 不能被一个畸形字符串盖掉。
    if error_code != 0 {
        let message = reader.string().unwrap_or_default();
        let reason = if message.trim().is_empty() {
            "<broker 没有给 error_message>"
        } else {
            message.trim()
        };
        // **不带** auth_bytes（SCRAM client-final 里有 proof）。
        return Err(invalid(format!(
            "Kafka SASL 认证失败（error_code {error_code}）：{reason}"
        )));
    }
    let _error_message = reader.string()?;
    let bytes = reader.bytes()?;
    Ok(bytes)
}

/// SASL/PLAIN：`authzid \0 authcid \0 password`，authzid 留空 —— 开头必须有一个 NUL。
fn plain_payload(username: &str, password: &str) -> io::Result<Vec<u8>> {
    // PLAIN 用 NUL 当分隔符：凭据里再出现 NUL 会让服务端切错位，只能当配置错拒掉。
    if username.contains('\0') || password.contains('\0') {
        return Err(invalid(
            "SASL/PLAIN 的 username / password 不能包含 NUL 字节".to_string(),
        ));
    }
    let mut payload = Vec::with_capacity(username.len() + password.len() + 2);
    payload.push(0);
    payload.extend_from_slice(username.as_bytes());
    payload.push(0);
    payload.extend_from_slice(password.as_bytes());
    Ok(payload)
}

// ---------------------------------------------------------------------------
// SCRAM（RFC 5802 / RFC 7677）
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ScramHash {
    Sha256,
    Sha512,
}

impl ScramHash {
    fn len(self) -> usize {
        match self {
            Self::Sha256 => 32,
            Self::Sha512 => 64,
        }
    }

    fn digest(self, data: &[u8]) -> Vec<u8> {
        match self {
            Self::Sha256 => Sha256::digest(data).to_vec(),
            Self::Sha512 => Sha512::digest(data).to_vec(),
        }
    }

    fn hmac(self, key: &[u8], data: &[u8]) -> Vec<u8> {
        // HMAC 接受任意长度密钥，这里的 `expect` 只会在实现写错时触发。
        match self {
            Self::Sha256 => {
                let mut mac =
                    Hmac::<Sha256>::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
            Self::Sha512 => {
                let mut mac =
                    Hmac::<Sha512>::new_from_slice(key).expect("HMAC accepts any key length");
                mac.update(data);
                mac.finalize().into_bytes().to_vec()
            }
        }
    }

    fn pbkdf2(self, password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0u8; self.len()];
        match self {
            Self::Sha256 => pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out),
            Self::Sha512 => pbkdf2::pbkdf2_hmac::<Sha512>(password, salt, iterations, &mut out),
        }
        out
    }
}

/// `client-first`：`n,,n=<user>,r=<nonce>`；返回值是 `(整条消息, 去掉 gs2 头的 bare)`。
///
/// `bare` 必须原样拼进 `auth_message` —— 少一个字节 proof 就对不上。
fn scram_client_first(username: &str, nonce: &str) -> (String, String) {
    let bare = format!("n={},r={}", saslname(username), nonce);
    (format!("n,,{bare}"), bare)
}

/// RFC 5802 §5.1 的 saslname 转义：用户名里的 `,` / `=` 会破坏属性分隔。
fn saslname(username: &str) -> String {
    username.replace('=', "=3D").replace(',', "=2C")
}

#[derive(Debug)]
struct ServerFirst {
    /// broker 的原文：`auth_message` 必须逐字节用回它（含未知扩展指令）。
    raw: String,
    nonce: String,
    salt: Vec<u8>,
    iterations: u32,
}

fn parse_server_first(message: &str, client_nonce: &str) -> io::Result<ServerFirst> {
    let mut nonce = None;
    let mut salt = None;
    let mut iterations = None;

    for attribute in message.split(',') {
        let (name, value) = attribute
            .split_once('=')
            .ok_or_else(|| invalid(format!("SCRAM server-first 里的 `{attribute}` 缺少 `=`")))?;
        match name {
            // RFC 5802 §5.1：看不懂的**必需**扩展只能拒绝，不能忽略。
            "m" => {
                return Err(invalid(
                    "SCRAM server-first 要求了 `m=` 扩展（本实现不支持 channel binding）"
                        .to_string(),
                ));
            }
            "r" => nonce = Some(value),
            "s" => {
                salt = Some(BASE64.decode(value).map_err(|err| {
                    invalid(format!("SCRAM server-first 的 `s=` 不是 base64：{err}"))
                })?)
            }
            "i" => {
                let parsed = value.parse::<u32>().map_err(|_| {
                    invalid(format!("SCRAM server-first 的 `i=` 不是整数：`{value}`"))
                })?;
                iterations = Some(parsed);
            }
            // 其余扩展指令 RFC 允许忽略。
            _ => {}
        }
    }

    let nonce = nonce.ok_or_else(|| invalid("SCRAM server-first 缺少 `r=`".to_string()))?;
    let salt = salt.ok_or_else(|| invalid("SCRAM server-first 缺少 `s=`".to_string()))?;
    let iterations =
        iterations.ok_or_else(|| invalid("SCRAM server-first 缺少 `i=`".to_string()))?;

    if !nonce.starts_with(client_nonce) {
        return Err(invalid(
            "SCRAM server-first 的 nonce 不是以 client-nonce 开头（可能被中间人改写）".to_string(),
        ));
    }
    if iterations == 0 {
        return Err(invalid("SCRAM server-first 的迭代次数为 0".to_string()));
    }
    if iterations > MAX_SCRAM_ITERATIONS {
        return Err(invalid(format!(
            "SCRAM server-first 的迭代次数 {iterations} 超出上限 {MAX_SCRAM_ITERATIONS}（拒绝把探针线程算死）"
        )));
    }

    Ok(ServerFirst {
        raw: message.to_string(),
        nonce: nonce.to_string(),
        salt,
        iterations,
    })
}

struct ClientFinal {
    /// 发给 broker 的整条消息（含 `p=`）。
    message: String,
    /// 期望的 server 签名：`server-final` 的 `v=` 必须逐字节等于它。
    server_signature: Vec<u8>,
}

fn build_client_final(
    hash: ScramHash,
    credentials: &Credentials,
    client_first_bare: &str,
    server_first: &ServerFirst,
) -> ClientFinal {
    let salted = hash.pbkdf2(
        credentials.password.as_bytes(),
        &server_first.salt,
        server_first.iterations,
    );
    let client_key = hash.hmac(&salted, b"Client Key");
    let stored_key = hash.digest(&client_key);

    let without_proof = format!("c=biws,r={}", server_first.nonce);
    let auth_message = format!("{client_first_bare},{},{without_proof}", server_first.raw);

    let client_signature = hash.hmac(&stored_key, auth_message.as_bytes());
    let proof = xor(&client_key, &client_signature);
    let message = format!("{without_proof},p={}", BASE64.encode(&proof));

    let server_key = hash.hmac(&salted, b"Server Key");
    let server_signature = hash.hmac(&server_key, auth_message.as_bytes());

    ClientFinal {
        message,
        server_signature,
    }
}

fn xor(left: &[u8], right: &[u8]) -> Vec<u8> {
    left.iter().zip(right).map(|(a, b)| a ^ b).collect()
}

fn authenticate_scram(
    stream: &mut dyn ReadWrite,
    hash: ScramHash,
    credentials: &Credentials,
) -> io::Result<()> {
    let client_nonce = client_nonce()?;
    let (client_first, client_first_bare) =
        scram_client_first(&credentials.username, &client_nonce);

    let server_first_raw = sasl_step(stream, CORRELATION_AUTH_FIRST, client_first.as_bytes())?;
    let server_first_raw = String::from_utf8(server_first_raw)
        .map_err(|err| invalid(format!("SCRAM server-first 不是 UTF-8：{err}")))?;
    let server_first = parse_server_first(&server_first_raw, &client_nonce)?;

    let client_final = build_client_final(hash, credentials, &client_first_bare, &server_first);
    let server_final = sasl_step(
        stream,
        CORRELATION_AUTH_FINAL,
        client_final.message.as_bytes(),
    )?;
    verify_server_final(&server_final, &client_final.server_signature)
}

fn verify_server_final(response: &[u8], expected: &[u8]) -> io::Result<()> {
    let text = std::str::from_utf8(response)
        .map_err(|err| invalid(format!("SCRAM server-final 不是 UTF-8：{err}")))?;

    let mut signature = None;
    for attribute in text.split(',') {
        let (name, value) = attribute
            .split_once('=')
            .ok_or_else(|| invalid(format!("SCRAM server-final 里的 `{attribute}` 缺少 `=`")))?;
        match name {
            "e" => {
                return Err(invalid(format!("SCRAM 服务端拒绝认证：`{value}`")));
            }
            "v" => {
                signature = Some(BASE64.decode(value).map_err(|err| {
                    invalid(format!("SCRAM server-final 的 `v=` 不是 base64：{err}"))
                })?)
            }
            _ => {}
        }
    }

    let Some(signature) = signature else {
        return Err(invalid("SCRAM server-final 缺少 `v=`".to_string()));
    };
    if !constant_time_eq(&signature, expected) {
        return Err(invalid(
            "SCRAM server-final 的 `v=` 与服务端签名不一致（密码错或中间人在场）".to_string(),
        ));
    }
    Ok(())
}

/// 比较签名不做短路：签名长度固定，但常量时间比较是这一层的默认姿势。
fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let mut diff = 0u8;
    for (a, b) in left.iter().zip(right) {
        diff |= a ^ b;
    }
    diff == 0
}

fn client_nonce() -> io::Result<String> {
    let mut raw = [0u8; 24];
    // 不引随机数 crate：系统熵源就是它。读不到宁可报错，也不要用时间戳凑一个。
    let mut source = fs::File::open("/dev/urandom")
        .map_err(|err| invalid(format!("读取 /dev/urandom 失败：{err}")))?;
    source
        .read_exact(&mut raw)
        .map_err(|err| invalid(format!("读取 /dev/urandom 失败：{err}")))?;
    Ok(BASE64.encode(raw))
}

// ---------------------------------------------------------------------------
// 请求编码（SASL 自己的两条 API，也走 Kafka 请求头）
// ---------------------------------------------------------------------------

fn encode_sasl_handshake_request(correlation_id: i32, client_id: &str, mechanism: &str) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_SASL_HANDSHAKE.to_be_bytes());
    body.extend_from_slice(&API_VERSION_SASL_HANDSHAKE.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    body.extend_from_slice(&(mechanism.len() as i16).to_be_bytes());
    body.extend_from_slice(mechanism.as_bytes());
    frame(body)
}

fn encode_sasl_authenticate_request(
    correlation_id: i32,
    client_id: &str,
    auth_bytes: &[u8],
) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&API_KEY_SASL_AUTHENTICATE.to_be_bytes());
    body.extend_from_slice(&API_VERSION_SASL_AUTHENTICATE.to_be_bytes());
    body.extend_from_slice(&correlation_id.to_be_bytes());
    body.extend_from_slice(&(client_id.len() as i16).to_be_bytes());
    body.extend_from_slice(client_id.as_bytes());
    body.extend_from_slice(&(auth_bytes.len() as i32).to_be_bytes());
    body.extend_from_slice(auth_bytes);
    frame(body)
}

fn frame(body: Vec<u8>) -> Vec<u8> {
    let mut framed = Vec::with_capacity(body.len() + 4);
    framed.extend_from_slice(&(body.len() as i32).to_be_bytes());
    framed.extend_from_slice(&body);
    framed
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io;
    use std::net::{TcpListener, TcpStream};
    use std::path::PathBuf;
    use std::sync::Arc;
    use std::time::{Duration, Instant};

    use hmac::{Hmac, Mac};
    use rustls::pki_types::PrivateKeyDer;
    use rustls::{ServerConfig, ServerConnection};
    use sha2::{Digest, Sha256};

    use crate::telemetry::metrics::kafka;

    fn credentials(username: &str, password: &str) -> Credentials {
        Credentials {
            username: username.to_string(),
            password: password.to_string(),
        }
    }

    fn server_first(nonce_suffix: &str, iterations: u32) -> ServerFirst {
        parse_server_first(
            &format!("r=client{nonce_suffix},s=c2FsdA==,i={iterations}"),
            "client",
        )
        .expect("parse server-first")
    }

    fn temp_file(name: &str, content: &[u8]) -> PathBuf {
        let path =
            std::env::temp_dir().join(format!("wist-kafka-auth-{}-{name}", std::process::id()));
        std::fs::write(&path, content).expect("write temp file");
        path
    }

    #[test]
    fn security_protocol_is_a_closed_set() {
        assert!(Protocol::parse("SASL_SSL").expect("ssl+sasl").tls());
        assert!(Protocol::parse("SASL_SSL").expect("ssl+sasl").sasl());
        assert!(Protocol::parse("SSL").expect("ssl").tls());
        assert!(!Protocol::parse("SSL").expect("ssl").sasl());
        assert!(Protocol::parse("SASL_PLAINTEXT").expect("sasl").sasl());
        assert!(!Protocol::parse("PLAINTEXT").expect("plain").tls());
        assert!(Protocol::parse("SSL_SASL").is_err(), "写反了要立刻报");
    }

    #[test]
    fn plain_payload_keeps_the_leading_nul() {
        // PLAIN 的三段是 `authzid \0 authcid \0 password`；authzid 留空 → 开头是 NUL。
        assert_eq!(
            plain_payload("probe", "s3cr3t").expect("payload"),
            b"\0probe\0s3cr3t".to_vec()
        );
        // 凭据里带 NUL 会把三段切错位，只能当配置错拒掉。
        assert!(plain_payload("pro\0be", "pw").is_err());
        assert!(plain_payload("probe", "p\0w").is_err());
    }

    #[test]
    fn scram_sha256_matches_the_rfc7677_vector() {
        // RFC 7677 §3 的完整往返：固定 nonce 就必须给出同一串字节。
        let (client_first, client_first_bare) = scram_client_first("user", "rOprNGfwEbeRWgbNEkqO");
        assert_eq!(client_first, "n,,n=user,r=rOprNGfwEbeRWgbNEkqO");

        let server_first_message = "r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
                                    s=W22ZaJ0SNY7soEsUEjb6gQ==,i=4096";
        let parsed = parse_server_first(server_first_message, "rOprNGfwEbeRWgbNEkqO")
            .expect("parse server-first");

        let client_final = build_client_final(
            ScramHash::Sha256,
            &credentials("user", "pencil"),
            &client_first_bare,
            &parsed,
        );
        assert_eq!(
            client_final.message,
            "c=biws,r=rOprNGfwEbeRWgbNEkqO%hvYDpWUa2RaTCAfuxFIlj)hNlF$k0,\
             p=dHzbZapWIk4jUhN+Ute9ytag9zjfMHgsqmmiz7AndVQ="
        );

        // 服务端签名能对上 = 密码对、中间没人在场。
        verify_server_final(
            b"v=6rriTRBi23WpRR/wtup+mMhUZUn/dB5nLTJRsjl95G4=",
            &client_final.server_signature,
        )
        .expect("server signature");
    }

    #[test]
    fn scram_proof_and_signature_are_hash_sized() {
        let parsed = server_first("srv", 4096);
        for (hash, size) in [(ScramHash::Sha256, 32), (ScramHash::Sha512, 64)] {
            let final_message = build_client_final(
                hash,
                &credentials("probe", "pencil"),
                "n=probe,r=client",
                &parsed,
            );
            let proof = final_message
                .message
                .rsplit_once("p=")
                .expect("proof attribute")
                .1;
            assert_eq!(BASE64.decode(proof).expect("base64 proof").len(), size);
            assert_eq!(final_message.server_signature.len(), size);
            assert!(final_message.message.starts_with("c=biws,r=clientsrv,p="));
        }
    }

    #[test]
    fn scram_server_first_rejects_malformed_input() {
        let nonce = "client";
        assert!(
            parse_server_first("s=c2FsdA==,i=4096", nonce).is_err(),
            "缺 r="
        );
        assert!(
            parse_server_first("r=clientsrv,i=4096", nonce).is_err(),
            "缺 s="
        );
        assert!(
            parse_server_first("r=clientsrv,s=c2FsdA==,i=0", nonce).is_err(),
            "迭代数为 0"
        );
        assert!(
            parse_server_first("r=clientsrv,s=c2FsdA==,i=abc", nonce).is_err(),
            "迭代数不是整数"
        );
        let err = parse_server_first("m=bind,r=clientsrv,s=c2FsdA==,i=4096", nonce)
            .expect_err("m= 必须拒绝");
        assert!(err.to_string().contains("m="), "{err}");
        assert!(
            parse_server_first("r=other,s=c2FsdA==,i=4096", nonce).is_err(),
            "nonce 不以 client-nonce 开头"
        );
    }

    #[test]
    fn server_final_signature_mismatch_fails() {
        let expected = vec![7u8; 32];
        let matching = format!("v={}", BASE64.encode(&expected));
        verify_server_final(matching.as_bytes(), &expected).expect("签名一致");

        let mismatch = format!("v={}", BASE64.encode([0u8; 32]));
        assert!(
            verify_server_final(mismatch.as_bytes(), &expected).is_err(),
            "v= 不匹配必须失败"
        );
        assert!(verify_server_final(b"", &expected).is_err(), "缺 v=");
        assert!(
            verify_server_final(b"e=other-error", &expected).is_err(),
            "服务端报错要原样失败"
        );
    }

    #[test]
    fn auto_picks_the_strongest_mechanism_the_broker_offers() {
        let offered = vec!["PLAIN".to_string(), "SCRAM-SHA-512".to_string()];
        assert_eq!(
            select_mechanism("auto", &offered).expect("pick"),
            Mechanism::ScramSha512
        );

        let plain_only = vec!["PLAIN".to_string()];
        assert_eq!(
            select_mechanism("auto", &plain_only).expect("pick"),
            Mechanism::Plain
        );

        let err = select_mechanism("auto", &[]).expect_err("空列表不能猜");
        assert!(err.to_string().contains("broker 启用了"), "{err}");

        let err = select_mechanism("SCRAM-SHA-256", &offered).expect_err("broker 不支持");
        assert!(err.to_string().contains("SCRAM-SHA-256"), "{err}");
        assert!(
            err.to_string().contains("SCRAM-SHA-512"),
            "错误里要带 broker 的列表：{err}"
        );
    }

    #[test]
    fn password_file_is_read_trimmed_and_reported_by_path() {
        let missing = "/nonexistent/wist-agentd/kafka-password";
        let err = read_password(missing).expect_err("文件不存在");
        assert!(err.to_string().contains(missing), "错误里要有路径：{err}");

        let path = temp_file("crlf", b"s3cr3t\r\n");
        let password = read_password(path.to_str().expect("utf8 path")).expect("read");
        std::fs::remove_file(&path).ok();
        assert_eq!(password, "s3cr3t", "只去行尾换行");
    }

    #[test]
    fn oversized_password_file_is_rejected() {
        // `password_file` 指到 `/dev/zero` 之类的东西时，不能把采集线程读爆。
        let path = temp_file("huge-password", &vec![b'x'; 64 * 1024 + 1]);
        let err = read_password(path.to_str().expect("utf8 path")).expect_err("过大");
        std::fs::remove_file(&path).ok();
        assert!(err.to_string().contains("超过"), "{err}");
    }

    #[test]
    fn credentials_require_both_username_and_password_file() {
        let dir = temp_file("empty-config", b"x");
        let path = dir.to_str().expect("utf8 path").to_string();
        let err = Credentials::load(&SecurityConfig {
            protocol: "SASL_SSL",
            mechanism: "auto",
            username: None,
            password_file: Some(&path),
            tls_ca_file: None,
        })
        .expect_err("缺 username");
        assert!(err.to_string().contains("username"), "{err}");

        let err = Credentials::load(&SecurityConfig {
            protocol: "SASL_SSL",
            mechanism: "auto",
            username: Some("probe"),
            password_file: None,
            tls_ca_file: None,
        })
        .expect_err("缺 password_file");
        assert!(err.to_string().contains("password_file"), "{err}");

        std::fs::remove_file(&path).ok();
    }

    #[test]
    fn saslname_escapes_separators() {
        assert_eq!(saslname("plain"), "plain");
        assert_eq!(saslname("a=b,c"), "a=3Db=2Cc");
    }

    #[test]
    fn client_nonce_is_random_and_scram_safe() {
        let first = client_nonce().expect("nonce");
        let second = client_nonce().expect("nonce");
        assert_ne!(first, second, "每次都要重新取随机数");
        assert_eq!(first.len(), 32, "24 字节 base64 后是 32 个字符");
        assert!(!first.contains(','), "SCRAM 用逗号分隔属性，nonce 里不能有");
        assert!(
            first.chars().all(|c| ('!'..='~').contains(&c)),
            "nonce 必须是 RFC 5802 的 printable：{first}"
        );
    }

    #[test]
    fn host_of_keeps_the_configured_name_for_certificate_checks() {
        assert_eq!(host_of("kafka-0.internal:9093"), "kafka-0.internal");
        assert_eq!(host_of("10.0.0.1:9092"), "10.0.0.1");
        assert_eq!(host_of("[::1]:9093"), "::1", "IPv6 的方括号要剥掉");
    }

    #[test]
    fn scram_rejects_a_runaway_iteration_count() {
        let err = parse_server_first("r=clientsrv,s=c2FsdA==,i=4000000", "client")
            .expect_err("迭代数不能把探针线程算死");
        assert!(err.to_string().contains("迭代次数"), "{err}");
    }

    #[test]
    fn scram_tolerates_unknown_attributes() {
        let parsed = parse_server_first("x=ignored,r=clientsrv,s=c2FsdA==,i=4096", "client")
            .expect("未知扩展指令按 RFC 忽略");
        assert_eq!(parsed.iterations, 4096);
        assert_eq!(parsed.nonce, "clientsrv");

        let expected = vec![3u8; 32];
        let with_extra = format!("v={},x=ignored", BASE64.encode(&expected));
        verify_server_final(with_extra.as_bytes(), &expected).expect("未知属性不影响 v= 校验");
    }

    #[test]
    fn username_is_trimmed_but_the_password_is_kept_verbatim() {
        let path = temp_file("spaces", b" pa ss \r\n");
        let file = path.to_str().expect("utf8 path").to_string();
        let credentials = Credentials::load(&SecurityConfig {
            protocol: "SASL_SSL",
            mechanism: "auto",
            username: Some("  probe  "),
            password_file: Some(&file),
            tls_ca_file: None,
        })
        .expect("load");
        std::fs::remove_file(&path).ok();
        assert_eq!(credentials.username, "probe", "用户名去首尾空白");
        assert_eq!(credentials.password, " pa ss ", "密码里的空格有语义");
    }

    #[test]
    fn credentials_debug_never_prints_the_password() {
        let rendered = format!("{:?}", credentials("probe", "s3cr3t"));
        assert!(rendered.contains("probe"), "{rendered}");
        assert!(
            !rendered.contains("s3cr3t"),
            "Debug 输出里不能有密码：{rendered}"
        );
        assert!(rendered.contains("redacted"), "{rendered}");
    }

    #[test]
    fn tls_ca_file_errors_name_the_path() {
        let missing = "/nonexistent/wist-agentd/ca.pem";
        let err = tls_config(Some(missing)).expect_err("文件不存在");
        assert!(err.to_string().contains(missing), "{err}");

        let empty = temp_file("empty-ca", b"not a pem\n");
        let path = empty.to_str().expect("utf8 path").to_string();
        let err = tls_config(Some(&path)).expect_err("没有证书");
        std::fs::remove_file(&empty).ok();
        assert!(err.to_string().contains("没有 PEM 证书"), "{err}");
    }

    // -----------------------------------------------------------------------
    // 假 broker：把「建连 → 握手 → 报文」整条链跑一遍，不需要真集群
    // -----------------------------------------------------------------------

    /// 测试自己的报文游标：**不复用被测的 `Reader`**，否则编码/解码可以一起错。
    struct Cursor<'a> {
        buf: &'a [u8],
        pos: usize,
    }

    impl<'a> Cursor<'a> {
        fn new(buf: &'a [u8]) -> Self {
            Self { buf, pos: 0 }
        }

        fn take(&mut self, len: usize) -> &'a [u8] {
            let end = self.pos + len;
            assert!(end <= self.buf.len(), "夹具里的报文被截断了");
            let slice = &self.buf[self.pos..end];
            self.pos = end;
            slice
        }

        fn i16(&mut self) -> i16 {
            let bytes = self.take(2);
            i16::from_be_bytes([bytes[0], bytes[1]])
        }

        fn i32(&mut self) -> i32 {
            let bytes = self.take(4);
            i32::from_be_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
        }

        fn string(&mut self) -> String {
            let len = self.i16();
            assert!(len >= 0, "夹具不处理 null 字符串");
            String::from_utf8(self.take(len as usize).to_vec()).expect("utf8")
        }

        fn bytes(&mut self) -> Vec<u8> {
            let len = self.i32();
            assert!(len >= 0, "夹具不处理 null bytes");
            self.take(len as usize).to_vec()
        }

        fn rest(&self) -> &'a [u8] {
            &self.buf[self.pos..]
        }
    }

    fn read_frame(stream: &mut dyn ReadWrite) -> io::Result<Vec<u8>> {
        let mut size = [0u8; 4];
        stream.read_exact(&mut size)?;
        let len = i32::from_be_bytes(size);
        let mut body = vec![0u8; len as usize];
        stream.read_exact(&mut body)?;
        Ok(body)
    }

    fn write_frame(stream: &mut dyn ReadWrite, body: &[u8]) -> io::Result<()> {
        stream.write_all(&(body.len() as i32).to_be_bytes())?;
        stream.write_all(body)?;
        stream.flush()
    }

    struct Request {
        api_key: i16,
        api_version: i16,
        correlation_id: i32,
        client_id: String,
        payload: Vec<u8>,
    }

    fn read_request(stream: &mut dyn ReadWrite) -> io::Result<Request> {
        let body = read_frame(stream)?;
        let mut cursor = Cursor::new(&body);
        Ok(Request {
            api_key: cursor.i16(),
            api_version: cursor.i16(),
            correlation_id: cursor.i32(),
            client_id: cursor.string(),
            payload: cursor.rest().to_vec(),
        })
    }

    /// 客户端连上就会发 `ApiVersions`（在认证之前），假 broker 必须先答它。
    ///
    /// 版本区间照真实 broker：Metadata v0-v2、DescribeLogDirs v0-v1（v0 在 4.0 被移除）、
    /// SaslHandshake v0-v1、SaslAuthenticate v0-v2。
    fn answer_api_versions(
        stream: &mut dyn ReadWrite,
        log_dirs: Option<(i16, i16)>,
    ) -> io::Result<()> {
        let request = read_request(stream)?;
        assert_eq!(request.api_key, 18, "第一条必须是 ApiVersions");
        assert_eq!(request.api_version, 0);
        let mut apis: Vec<(i16, i16, i16)> = vec![(18, 0, 4), (3, 0, 2)];
        if let Some((min, max)) = log_dirs {
            apis.push((35, min, max));
        }
        apis.push((17, 0, 1));
        apis.push((36, 0, 2));

        let mut body = Vec::new();
        body.extend_from_slice(&request.correlation_id.to_be_bytes());
        body.extend_from_slice(&0i16.to_be_bytes()); // error_code
        body.extend_from_slice(&(apis.len() as i32).to_be_bytes());
        for (api_key, min, max) in apis {
            body.extend_from_slice(&api_key.to_be_bytes());
            body.extend_from_slice(&min.to_be_bytes());
            body.extend_from_slice(&max.to_be_bytes());
        }
        write_frame(stream, &body)
    }

    fn push_string(out: &mut Vec<u8>, value: &str) {
        out.extend_from_slice(&(value.len() as i16).to_be_bytes());
        out.extend_from_slice(value.as_bytes());
    }

    /// `SaslHandshake` 请求体里的机制名（`auto` 试探的就是它）。
    fn mechanism_of(payload: &[u8]) -> String {
        Cursor::new(payload).string()
    }

    /// `SaslAuthenticate` 请求体里的 auth_bytes。
    fn auth_bytes_of(payload: &[u8]) -> Vec<u8> {
        Cursor::new(payload).bytes()
    }

    fn sasl_handshake_response(
        correlation_id: i32,
        error_code: i16,
        mechanisms: &[&str],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&error_code.to_be_bytes());
        body.extend_from_slice(&(mechanisms.len() as i32).to_be_bytes());
        for mechanism in mechanisms {
            push_string(&mut body, mechanism);
        }
        body
    }

    fn sasl_authenticate_response(
        correlation_id: i32,
        error_code: i16,
        message: &str,
        auth_bytes: &[u8],
    ) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&error_code.to_be_bytes());
        push_string(&mut body, message);
        body.extend_from_slice(&(auth_bytes.len() as i32).to_be_bytes());
        body.extend_from_slice(auth_bytes);
        body
    }

    /// 最小可用的 `Metadata` **v2** 响应：一个 broker、一个空 topic。
    ///
    /// 字段顺序严格按 `MetadataResponse.json`：broker 带 **rack**（v1 起，nullable），
    /// v2 再多一个 `cluster_id`（客户端协商到的就是这个版本）。
    fn metadata_response(correlation_id: i32) -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&correlation_id.to_be_bytes());
        body.extend_from_slice(&1i32.to_be_bytes()); // brokers
        body.extend_from_slice(&1i32.to_be_bytes()); // node_id
        push_string(&mut body, "127.0.0.1");
        body.extend_from_slice(&9092i32.to_be_bytes());
        body.extend_from_slice(&(-1i16).to_be_bytes()); // rack = null
        body.extend_from_slice(&9i16.to_be_bytes()); // cluster_id
        body.extend_from_slice(b"test-live");
        body.extend_from_slice(&1i32.to_be_bytes()); // controller_id
        body.extend_from_slice(&1i32.to_be_bytes()); // topics
        body.extend_from_slice(&0i16.to_be_bytes()); // topic error_code
        push_string(&mut body, "t");
        body.push(0); // is_internal
        body.extend_from_slice(&0i32.to_be_bytes()); // partitions
        body
    }

    struct FakeBroker {
        port: u16,
        handle: std::thread::JoinHandle<Vec<io::Result<()>>>,
    }

    impl FakeBroker {
        /// 依次接 `connections` 条连接（`auto` 换机制时会建两次）。
        fn spawn<F>(connections: usize, tls: Option<Arc<ServerConfig>>, handler: F) -> Self
        where
            F: Fn(usize, &mut dyn ReadWrite) -> io::Result<()> + Send + Sync + 'static,
        {
            let listener = TcpListener::bind("127.0.0.1:0").expect("bind");
            let port = listener.local_addr().expect("local addr").port();
            listener.set_nonblocking(true).expect("nonblocking");
            let handle = std::thread::spawn(move || {
                let deadline = Instant::now() + Duration::from_secs(5);
                let mut log = Vec::new();
                for index in 0..connections {
                    let tcp = loop {
                        match listener.accept() {
                            Ok((tcp, _)) => break tcp,
                            Err(err) if err.kind() == io::ErrorKind::WouldBlock => {
                                if Instant::now() >= deadline {
                                    log.push(Err(io::Error::new(
                                        io::ErrorKind::TimedOut,
                                        "假 broker 等不到客户端（连接数不足）",
                                    )));
                                    return log;
                                }
                                std::thread::sleep(Duration::from_millis(5));
                            }
                            Err(err) => {
                                log.push(Err(err));
                                return log;
                            }
                        }
                    };
                    tcp.set_nonblocking(false).expect("blocking");
                    tcp.set_read_timeout(Some(Duration::from_secs(5))).ok();
                    tcp.set_write_timeout(Some(Duration::from_secs(5))).ok();

                    let result = match tls.as_ref() {
                        None => {
                            let mut stream = tcp;
                            handler(index, &mut stream)
                        }
                        Some(config) => match serve_tls(config.clone(), tcp) {
                            Ok(mut stream) => handler(index, &mut stream),
                            Err(err) => Err(err),
                        },
                    };
                    log.push(result);
                }
                log
            });
            Self { port, handle }
        }

        fn addr(&self) -> String {
            format!("127.0.0.1:{}", self.port)
        }

        fn host_addr(&self, host: &str) -> String {
            format!("{host}:{}", self.port)
        }

        fn finish(self) -> Vec<io::Result<()>> {
            match self.handle.join() {
                Ok(log) => log,
                Err(_) => panic!("假 broker 线程 panic（多半是夹具里的断言失败）"),
            }
        }
    }

    fn serve_tls(
        config: Arc<ServerConfig>,
        tcp: TcpStream,
    ) -> io::Result<StreamOwned<ServerConnection, TcpStream>> {
        let conn = ServerConnection::new(config)
            .map_err(|err| io::Error::new(io::ErrorKind::InvalidData, err.to_string()))?;
        let mut stream = StreamOwned::new(conn, tcp);
        while stream.conn.is_handshaking() {
            stream.conn.complete_io(&mut stream.sock)?;
        }
        Ok(stream)
    }

    fn plaintext() -> SecurityConfig<'static> {
        SecurityConfig {
            protocol: "PLAINTEXT",
            mechanism: "auto",
            username: None,
            password_file: None,
            tls_ca_file: None,
        }
    }

    /// 自签证书 + 服务端配置；返回 `(server config, 证书 PEM)`。
    fn tls_broker(san: &str) -> (Arc<ServerConfig>, String) {
        install_crypto_provider();
        let certified = rcgen::generate_simple_self_signed(vec![san.to_string()]).expect("证书");
        let key = PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
        let config = ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certified.cert.der().clone()], key)
            .expect("服务端 TLS 配置");
        (Arc::new(config), certified.cert.pem())
    }

    fn hmac_sha256(key: &[u8], data: &[u8]) -> Vec<u8> {
        let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("hmac");
        mac.update(data);
        mac.finalize().into_bytes().to_vec()
    }

    fn sha256(data: &[u8]) -> Vec<u8> {
        Sha256::digest(data).to_vec()
    }

    fn salted_password(password: &[u8], salt: &[u8], iterations: u32) -> Vec<u8> {
        let mut out = vec![0u8; 32];
        pbkdf2::pbkdf2_hmac::<Sha256>(password, salt, iterations, &mut out);
        out
    }

    fn scram_auth_message(client_first: &str, client_final: &str, server_first: &str) -> String {
        let bare = client_first
            .strip_prefix("n,,")
            .expect("client-first 必须以 gs2 头 n,, 开头");
        let without_proof = client_final
            .rsplit_once(",p=")
            .expect("client-final 必须带 p=")
            .0;
        format!("{bare},{server_first},{without_proof}")
    }

    /// 服务端独立验一遍 proof（RFC 5802 §3）。
    fn scram_proof_is_valid(
        password: &str,
        salt: &[u8],
        iterations: u32,
        client_first: &str,
        client_final: &str,
        server_first: &str,
    ) -> bool {
        let auth_message = scram_auth_message(client_first, client_final, server_first);
        let salted = salted_password(password.as_bytes(), salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        let stored_key = sha256(&client_key);
        let signature = hmac_sha256(&stored_key, auth_message.as_bytes());
        let expected: Vec<u8> = client_key
            .iter()
            .zip(&signature)
            .map(|(a, b)| a ^ b)
            .collect();
        let proof = client_final
            .rsplit_once(",p=")
            .map(|(_, value)| BASE64.decode(value).expect("proof 是 base64"))
            .expect("proof");
        expected == proof
    }

    fn scram_server_signature(
        password: &str,
        salt: &[u8],
        iterations: u32,
        client_first: &str,
        client_final: &str,
        server_first: &str,
    ) -> Vec<u8> {
        let auth_message = scram_auth_message(client_first, client_final, server_first);
        let salted = salted_password(password.as_bytes(), salt, iterations);
        let server_key = hmac_sha256(&salted, b"Server Key");
        hmac_sha256(&server_key, auth_message.as_bytes())
    }

    struct ScramExchange {
        correlation_id: i32,
        client_first: String,
        client_final: String,
        server_first: String,
    }

    /// 走完 SCRAM 的握手与 client-first/client-final，返回最后一步要回的关联号。
    fn serve_scram(
        stream: &mut dyn ReadWrite,
        password: &str,
        salt: &[u8],
        iterations: u32,
    ) -> io::Result<ScramExchange> {
        answer_api_versions(stream, Some((0, 1)))?;
        let handshake = read_request(stream)?;
        assert_eq!(handshake.api_key, 17, "第一条必须是 SaslHandshake");
        assert_eq!(handshake.api_version, 1);
        assert_eq!(mechanism_of(&handshake.payload), "SCRAM-SHA-256");
        write_frame(
            stream,
            &sasl_handshake_response(handshake.correlation_id, 0, &["SCRAM-SHA-256"]),
        )?;

        let first = read_request(stream)?;
        assert_eq!(first.api_key, 36, "第二条必须是 SaslAuthenticate");
        assert_eq!(first.api_version, 0);
        let client_first =
            String::from_utf8(auth_bytes_of(&first.payload)).expect("client-first 是 ASCII");
        assert!(
            client_first.starts_with("n,,n=user,r="),
            "client-first 格式：{client_first}"
        );
        let client_nonce = client_first
            .rsplit_once(",r=")
            .expect("client-first 里有 r=")
            .1
            .to_string();
        let server_first = format!(
            "r={client_nonce}SRV,s={},i={iterations}",
            BASE64.encode(salt)
        );
        write_frame(
            stream,
            &sasl_authenticate_response(first.correlation_id, 0, "", server_first.as_bytes()),
        )?;

        let final_ = read_request(stream)?;
        assert_eq!(final_.api_key, 36, "第三条必须是 SaslAuthenticate");
        let client_final =
            String::from_utf8(auth_bytes_of(&final_.payload)).expect("client-final 是 ASCII");
        assert!(
            client_final.starts_with(&format!("c=biws,r={client_nonce}SRV,p=")),
            "client-final 格式：{client_final}"
        );
        assert!(
            scram_proof_is_valid(
                password,
                salt,
                iterations,
                &client_first,
                &client_final,
                &server_first
            ),
            "服务端算出来的 proof 和客户端发的不一致"
        );

        Ok(ScramExchange {
            correlation_id: final_.correlation_id,
            client_first,
            client_final,
            server_first,
        })
    }

    /// 版本协商：取交集上限，没交集就报「谁该升级」。
    #[test]
    fn version_negotiation_picks_the_intersection() {
        // 常见 broker：全区间
        assert_eq!(
            pick_version("Metadata", (0, 12), METADATA_VERSIONS).expect("pick"),
            2,
            "我们最高只解到 v2，不能盲目跟到 v12"
        );
        // 0.10.0：只有 v0/v1
        assert_eq!(
            pick_version("Metadata", (0, 1), METADATA_VERSIONS).expect("pick"),
            1
        );
        // Kafka 3.x 的 DescribeLogDirs：v0-v4 → 取 v4（唯一带 `usable_bytes` 的版本）
        assert_eq!(
            pick_version("DescribeLogDirs", (1, 4), DESCRIBE_LOG_DIRS_VERSIONS).expect("pick"),
            4
        );
        // 只支持到 v1 的老 broker：退回 v1（v0 与 v1 的响应布局一样）
        assert_eq!(
            pick_version("DescribeLogDirs", (0, 1), DESCRIBE_LOG_DIRS_VERSIONS).expect("pick"),
            1
        );
        let err = pick_version("DescribeLogDirs", (5, 7), DESCRIBE_LOG_DIRS_VERSIONS)
            .expect_err("没有交集");
        assert!(err.to_string().contains("v5-v7"), "{err}");
        assert!(err.to_string().contains("v0-v4"), "{err}");
    }

    /// broker 拒绝 ApiVersions 时，错误要说清是**版本**问题而不是认证/网络。
    #[test]
    fn api_versions_error_is_reported_as_a_version_problem() {
        let mut body = Vec::new();
        body.extend_from_slice(&20i32.to_be_bytes());
        body.extend_from_slice(&35i16.to_be_bytes()); // UNSUPPORTED_VERSION
        body.extend_from_slice(&0i32.to_be_bytes());

        let err = parse_api_versions(&body, 20).expect_err("要报错");
        assert!(err.to_string().contains("ApiVersions"), "{err}");
        assert!(err.to_string().contains("0.10"), "{err}");
    }

    /// broker 没声明 `DescribeLogDirs`（或区间不相交）：只退化容量面，不拖死拓扑。
    #[test]
    fn negotiate_degrades_the_capacity_face_only() {
        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, None)?;
            Ok(())
        });
        let config = SecurityConfig {
            protocol: "PLAINTEXT",
            mechanism: "auto",
            username: None,
            password_file: None,
            tls_ca_file: None,
        };
        let connection = connect(&broker.addr(), &config, Duration::from_secs(5)).expect("connect");
        assert_eq!(connection.versions.metadata, 2);
        assert!(
            connection.versions.describe_log_dirs.version.is_none(),
            "没声明就不能假装有"
        );
        assert!(connection.versions.describe_log_dirs.range.is_none());
        assert!(
            connection.versions.list_groups.version.is_none(),
            "消费组面同样要退化"
        );
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }

        // 声明了但区间不相交：同样只退化，但把区间留下来给上层报错用。
        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((5, 7)))?;
            Ok(())
        });
        let connection = connect(&broker.addr(), &config, Duration::from_secs(5)).expect("connect");
        assert!(connection.versions.describe_log_dirs.version.is_none());
        assert_eq!(connection.versions.describe_log_dirs.range, Some((5, 7)));
        assert!(
            connection
                .versions
                .describe_log_dirs
                .unavailable_reason("DescribeLogDirs")
                .contains("v5-v7"),
            "退化原因要能直接进日志"
        );
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn plaintext_connection_carries_a_metadata_request() {
        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let request = read_request(stream)?;
            assert_eq!(request.api_key, 3, "Metadata");
            assert_eq!(request.api_version, 2, "协商后应选 v2");
            assert_eq!(request.client_id, "wist-agentd");
            assert_eq!(
                request.payload,
                (-1i32).to_be_bytes().to_vec(),
                "topics = null（全部）"
            );
            write_frame(stream, &metadata_response(request.correlation_id))
        });

        let metadata = kafka::fetch_metadata(
            &broker.addr(),
            &plaintext(),
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect("明文链路要能走通");
        assert_eq!(metadata.brokers.len(), 1);
        assert_eq!(metadata.controller_id, 1);
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn plain_authentication_sends_the_documented_payload() {
        let password_file = temp_file("plain-password", b"s3cr3t\r\n");
        let password_path = password_file.to_str().expect("utf8 path").to_string();

        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let handshake = read_request(stream)?;
            assert_eq!(handshake.api_key, 17);
            assert_eq!(handshake.api_version, 1, "SaslHandshake v1");
            assert_eq!(mechanism_of(&handshake.payload), "PLAIN");
            write_frame(
                stream,
                &sasl_handshake_response(handshake.correlation_id, 0, &["PLAIN"]),
            )?;

            let authenticate = read_request(stream)?;
            assert_eq!(authenticate.api_key, 36);
            assert_eq!(authenticate.api_version, 0, "SaslAuthenticate v0");
            assert_eq!(
                auth_bytes_of(&authenticate.payload),
                b"\0probe\0s3cr3t".to_vec(),
                "PLAIN 载荷：\\0 + user + \\0 + password（行尾换行已去掉）"
            );
            write_frame(
                stream,
                &sasl_authenticate_response(authenticate.correlation_id, 0, "", &[]),
            )?;

            let metadata = read_request(stream)?;
            assert_eq!(metadata.api_key, 3, "认证通过后同一条连接发 Metadata");
            write_frame(stream, &metadata_response(metadata.correlation_id))
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "PLAIN",
            username: Some("probe"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let metadata = kafka::fetch_metadata(
            &broker.addr(),
            &config,
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect("PLAIN 认证要能走通");
        std::fs::remove_file(&password_file).ok();
        assert_eq!(metadata.brokers.len(), 1);
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn password_rejection_surfaces_the_broker_message_without_the_password() {
        let password_file = temp_file("rejected-password", b"s3cr3t");
        let password_path = password_file.to_str().expect("utf8 path").to_string();

        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let handshake = read_request(stream)?;
            write_frame(
                stream,
                &sasl_handshake_response(handshake.correlation_id, 0, &["PLAIN"]),
            )?;
            let authenticate = read_request(stream)?;
            write_frame(
                stream,
                &sasl_authenticate_response(
                    authenticate.correlation_id,
                    58,
                    "Authentication failed: credentials rejected",
                    &[],
                ),
            )
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "PLAIN",
            username: Some("probe"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let err = kafka::fetch_metadata(
            &broker.addr(),
            &config,
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect_err("密码错要失败");
        std::fs::remove_file(&password_file).ok();

        let message = err.to_string();
        assert!(message.contains("credentials rejected"), "{message}");
        assert!(message.contains("58"), "错误里要有 error_code：{message}");
        assert!(
            !message.contains("s3cr3t"),
            "错误和日志里绝不能出现密码：{message}"
        );
        assert!(
            !message.contains("\u{0}probe"),
            "也不能把 auth_bytes（PLAIN 明文载荷）打出来：{message}"
        );
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn auto_reconnects_once_when_the_broker_rejects_the_probe_mechanism() {
        let password_file = temp_file("auto-switch-password", b"pw");
        let password_path = password_file.to_str().expect("utf8 path").to_string();

        let broker = FakeBroker::spawn(2, None, |index, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let handshake = read_request(stream)?;
            assert_eq!(handshake.api_key, 17);
            if index == 0 {
                assert_eq!(
                    mechanism_of(&handshake.payload),
                    "SCRAM-SHA-512",
                    "auto 先试探最强的那个"
                );
                // 33 = UNSUPPORTED_SASL_MECHANISM；broker 顺带给出自己的列表。
                write_frame(
                    stream,
                    &sasl_handshake_response(handshake.correlation_id, 33, &["PLAIN"]),
                )?;
                return Ok(());
            }
            assert_eq!(
                mechanism_of(&handshake.payload),
                "PLAIN",
                "第二跳必须换成 broker 支持的机制"
            );
            write_frame(
                stream,
                &sasl_handshake_response(handshake.correlation_id, 0, &["PLAIN"]),
            )?;
            let authenticate = read_request(stream)?;
            write_frame(
                stream,
                &sasl_authenticate_response(authenticate.correlation_id, 0, "", &[]),
            )?;
            let metadata = read_request(stream)?;
            write_frame(stream, &metadata_response(metadata.correlation_id))
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "auto",
            username: Some("probe"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let metadata = kafka::fetch_metadata(
            &broker.addr(),
            &config,
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect("auto 应该自己收敛到 PLAIN");
        std::fs::remove_file(&password_file).ok();
        assert_eq!(metadata.brokers.len(), 1);
        let log = broker.finish();
        assert_eq!(log.len(), 2, "被拒后必须重开连接，而不是在同一条流上重试");
        for result in log {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn explicit_mechanism_missing_from_the_broker_list_is_a_hard_error() {
        let password_file = temp_file("explicit-password", b"pw");
        let password_path = password_file.to_str().expect("utf8 path").to_string();

        // 只接一条连接：显式机制不支持时**不跨机制重试**。
        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let handshake = read_request(stream)?;
            write_frame(
                stream,
                &sasl_handshake_response(handshake.correlation_id, 33, &["SCRAM-SHA-256"]),
            )
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "SCRAM-SHA-512",
            username: Some("probe"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let err = connect(&broker.addr(), &config, Duration::from_secs(5))
            .err()
            .expect("broker 不支持就必须失败");
        std::fs::remove_file(&password_file).ok();

        let message = err.to_string();
        assert!(message.contains("SCRAM-SHA-512"), "{message}");
        assert!(
            message.contains("SCRAM-SHA-256"),
            "要报 broker 的列表：{message}"
        );
        assert!(message.contains("broker 启用了"), "{message}");
        let log = broker.finish();
        assert_eq!(log.len(), 1, "不能偷偷换机制重试");
    }

    #[test]
    fn sasl_handshake_version_rejection_says_the_broker_is_too_old() {
        let password_file = temp_file("old-broker-password", b"pw");
        let password_path = password_file.to_str().expect("utf8 path").to_string();

        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let handshake = read_request(stream)?;
            // 35 = UNSUPPORTED_VERSION：老 broker 不认 SaslHandshake v1。
            write_frame(
                stream,
                &sasl_handshake_response(handshake.correlation_id, 35, &[]),
            )
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "PLAIN",
            username: Some("probe"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let err = connect(&broker.addr(), &config, Duration::from_secs(5))
            .err()
            .expect("版本不足要报错");
        std::fs::remove_file(&password_file).ok();
        let message = err.to_string();
        assert!(message.contains("1.0+"), "要说清是 broker 太老：{message}");
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn scram_sha256_end_to_end_validates_the_broker_signature() {
        let password = "pencil";
        let password_file = temp_file("scram-password", password.as_bytes());
        let password_path = password_file.to_str().expect("utf8 path").to_string();
        let salt = b"0123456789abcdef".to_vec();
        let iterations = 4096u32;

        let broker = FakeBroker::spawn(1, None, move |_, stream| {
            let exchange = serve_scram(stream, password, &salt, iterations)?;
            let signature = scram_server_signature(
                password,
                &salt,
                iterations,
                &exchange.client_first,
                &exchange.client_final,
                &exchange.server_first,
            );
            let server_final = format!("v={}", BASE64.encode(&signature));
            write_frame(
                stream,
                &sasl_authenticate_response(
                    exchange.correlation_id,
                    0,
                    "",
                    server_final.as_bytes(),
                ),
            )?;

            let metadata = read_request(stream)?;
            assert_eq!(metadata.api_key, 3);
            write_frame(stream, &metadata_response(metadata.correlation_id))
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "SCRAM-SHA-256",
            username: Some("user"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let metadata = kafka::fetch_metadata(
            &broker.addr(),
            &config,
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect("SCRAM-SHA-256 要能走通");
        std::fs::remove_file(&password_file).ok();
        assert_eq!(metadata.brokers.len(), 1);
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn scram_rejects_a_broker_signature_it_did_not_expect() {
        let password = "pencil";
        let password_file = temp_file("scram-bad-signature", password.as_bytes());
        let password_path = password_file.to_str().expect("utf8 path").to_string();
        let salt = b"0123456789abcdef".to_vec();

        let broker = FakeBroker::spawn(1, None, move |_, stream| {
            let exchange = serve_scram(stream, password, &salt, 4096)?;
            // 冒充 broker：签名给一个长度对但内容错的。
            let forged = format!("v={}", BASE64.encode([0u8; 32]));
            write_frame(
                stream,
                &sasl_authenticate_response(exchange.correlation_id, 0, "", forged.as_bytes()),
            )
        });

        let config = SecurityConfig {
            protocol: "SASL_PLAINTEXT",
            mechanism: "SCRAM-SHA-256",
            username: Some("user"),
            password_file: Some(&password_path),
            tls_ca_file: None,
        };
        let err = kafka::fetch_metadata(
            &broker.addr(),
            &config,
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect_err("服务端签名不对必须失败");
        std::fs::remove_file(&password_file).ok();
        let message = err.to_string();
        assert!(message.contains("server-final"), "{message}");
        assert!(!message.contains(password), "错误里不能有密码：{message}");
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn tls_with_an_explicit_ca_accepts_the_broker() {
        let (tls, ca_pem) = tls_broker("localhost");
        let ca_file = temp_file("good-ca", ca_pem.as_bytes());
        let ca_path = ca_file.to_str().expect("utf8 path").to_string();

        let broker = FakeBroker::spawn(1, Some(tls), |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let request = read_request(stream)?;
            assert_eq!(request.api_key, 3);
            write_frame(stream, &metadata_response(request.correlation_id))
        });

        let config = SecurityConfig {
            protocol: "SSL",
            mechanism: "auto",
            username: None,
            password_file: None,
            tls_ca_file: Some(&ca_path),
        };
        let metadata = kafka::fetch_metadata(
            &broker.host_addr("localhost"),
            &config,
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect("显式 CA 要能验过自签证书");
        std::fs::remove_file(&ca_file).ok();
        assert_eq!(metadata.brokers.len(), 1);
        for result in broker.finish() {
            result.expect("假 broker 没有报错");
        }
    }

    #[test]
    fn tls_hostname_mismatch_is_reported_as_a_verification_failure() {
        let (tls, ca_pem) = tls_broker("localhost");
        let ca_file = temp_file("mismatch-ca", ca_pem.as_bytes());
        let ca_path = ca_file.to_str().expect("utf8 path").to_string();

        // 证书只签了 localhost，这里按 IP 连 —— 必须因为主机名不匹配失败。
        let broker = FakeBroker::spawn(1, Some(tls), |_, _| Ok(()));
        let config = SecurityConfig {
            protocol: "SSL",
            mechanism: "auto",
            username: None,
            password_file: None,
            tls_ca_file: Some(&ca_path),
        };
        let err = connect(&broker.addr(), &config, Duration::from_secs(5))
            .err()
            .expect("主机名不匹配必须失败");
        std::fs::remove_file(&ca_file).ok();

        let message = err.to_string();
        assert!(
            message.contains("证书验证失败"),
            "要能和「网络不通」区分开：{message}"
        );
        let _ = broker.finish();
    }

    #[test]
    fn tls_without_a_ca_does_not_trust_a_self_signed_broker() {
        let (tls, _ca_pem) = tls_broker("localhost");
        let broker = FakeBroker::spawn(1, Some(tls), |_, _| Ok(()));
        let config = SecurityConfig {
            protocol: "SSL",
            mechanism: "auto",
            username: None,
            password_file: None,
            tls_ca_file: None,
        };
        let err = connect(
            &broker.host_addr("localhost"),
            &config,
            Duration::from_secs(5),
        )
        .err()
        .expect("系统根不该信任自签证书");
        let message = err.to_string();
        assert!(
            message.contains("证书验证失败") || message.contains("系统根证书不可用"),
            "失败原因要说清是 TLS 信任问题：{message}"
        );
        let _ = broker.finish();
    }

    #[test]
    fn oversized_frame_is_rejected_without_allocating() {
        let broker = FakeBroker::spawn(1, None, |_, stream| {
            answer_api_versions(stream, Some((0, 1)))?;
            let _ = read_frame(stream)?;
            stream.write_all(&i32::MAX.to_be_bytes())?;
            stream.flush()
        });
        let err = kafka::fetch_metadata(
            &broker.addr(),
            &plaintext(),
            "wist-agentd",
            Duration::from_secs(5),
        )
        .expect_err("超大帧必须拒绝");
        assert!(err.to_string().contains("invalid response size"), "{err}");
        let _ = broker.finish();
    }

    #[test]
    fn bad_protocol_and_mechanism_fail_before_any_connection() {
        let err = connect(
            "127.0.0.1:1",
            &SecurityConfig {
                protocol: "SSL_SASL",
                ..plaintext()
            },
            Duration::from_millis(200),
        )
        .err()
        .expect("协议名写错");
        assert!(err.to_string().contains("security_protocol"), "{err}");

        let password_file = temp_file("bad-mechanism", b"pw");
        let password_path = password_file.to_str().expect("utf8 path").to_string();
        let err = connect(
            "127.0.0.1:1",
            &SecurityConfig {
                protocol: "SASL_SSL",
                mechanism: "GSSAPI",
                username: Some("probe"),
                password_file: Some(&password_path),
                tls_ca_file: None,
            },
            Duration::from_millis(200),
        )
        .err()
        .expect("机制名写错");
        std::fs::remove_file(&password_file).ok();
        assert!(err.to_string().contains("sasl_mechanism"), "{err}");
    }

    #[test]
    fn tls_failures_outrank_connection_refusals_across_addresses() {
        // 双栈名（`localhost` → `::1` + `127.0.0.1`）很常见：一个族没监听，另一个族
        // 证书/认证不对。报「拒绝连接」会把真因埋掉。
        let refused = || io::Error::new(io::ErrorKind::ConnectionRefused, "refused");
        let tls = || invalid("TLS 证书验证失败（NotValidForName）".to_string());

        let error = prefer_error(refused(), tls());
        assert!(error.to_string().contains("证书验证失败"), "{error}");
        let error = prefer_error(tls(), refused());
        assert!(
            error.to_string().contains("证书验证失败"),
            "顺序不能影响结论：{error}"
        );
        // 都是连接层失败时保留第一条（先解析出来的那个地址）。
        let error = prefer_error(
            refused(),
            io::Error::new(io::ErrorKind::TimedOut, "timeout"),
        );
        assert!(error.to_string().contains("refused"), "{error}");
    }

    #[test]
    fn owned_security_config_defaults_to_plaintext() {
        let owned = OwnedSecurityConfig::default();
        let borrowed = owned.borrowed();
        assert_eq!(borrowed.protocol, "PLAINTEXT", "默认不能偷偷上 TLS/SASL");
        assert_eq!(borrowed.mechanism, "auto");
        assert!(borrowed.username.is_none());
        assert!(borrowed.password_file.is_none());
        assert!(borrowed.tls_ca_file.is_none());
    }
}
