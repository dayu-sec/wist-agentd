//! MySQL / TiDB 指标采集：SQL 直采，只读。
//!
//! 与 Kafka 的差异只有传输层：这里没有自己的协议实现，用 `sqlx` 说 MySQL 协议；
//! **采集逻辑本身**（查什么、缺什么怎么办）与传输分开，单测用假 transport 注入。
//!
//! 目标身份：`mysql:<host>:<port>`。凭据只走固定路径
//! `<MYSQL_SECRET_ROOT>/port-<port>/password`（用户名固定 [`MYSQL_PROBE_USERNAME`]），
//! 目录规则见设计文档 §12.1-5。
//!
//! 三条不变量：
//! - **不伪造 0**：读不到的键记 warning 并跳过，不补 0（「没有样本」≠「值是 0」）；
//! - 不是副本就不出 `mysql.replication_*`（TiDB / 单机 MySQL 都走这条路）；
//! - 整轮失败时 `attempted = 1 / failed = 1`，`targets` 为空。

use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::time::Duration;

use wist_contracts::discovery::StringKeyValue;

use super::collection::ProbeResult;
use super::runtime::MetricsCollectionTargetSample;

/// 采集域：与 `wist_metrics::spec` 里 `mysql_metrics` 对应。
pub const COLLECTION_KIND: &str = "mysql_metrics";

/// 只读账号名：不是秘密，固定约定（与 Kafka 探针一致）。
pub const MYSQL_PROBE_USERNAME: &str = "wist-probe";

/// 凭据根目录（Secret / 配置文件挂载点）。
pub const MYSQL_SECRET_ROOT: &str = "/etc/wist-agentd/secrets/mysql";

/// 单轮默认超时：连接 + 三条 `SHOW` 都是毫秒级，超这个数说明库忙或网络不通。
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// 一轮 `SHOW` 里最多保留多少条事实（防止异常版本回一个天量 `SHOW STATUS`）。
const MAX_FACTS: usize = 64;

/// 凭据目录：`<root>/<key>`。
///
/// key 的取值按运行时（决策见设计文档 §12.1-5）：
/// - host：`port-3306`
/// - k8s：`pod-<namespace>-<pod>`
/// - docker / compose：`container-<name>`
/// - 容器身份拿不到：`addr-<ip>-<port>`
///
/// 为什么容器不能用端口：一个节点上多个 pod 都是 3306，用端口会互相覆盖凭据；
/// 而名字（pod / 容器名）是运维**在投放凭据之前就能知道**的东西。
pub fn secret_dir_for_key(key: &str) -> String {
    format!("{MYSQL_SECRET_ROOT}/{key}")
}

/// host 的 key 形态：一条 agent 上一个 3306。
pub fn secret_dir_for_port(port: u16) -> String {
    secret_dir_for_key(&format!("port-{port}"))
}

pub fn password_file_for_port(port: u16) -> String {
    format!("{}/password", secret_dir_for_port(port))
}

/// 可选的自签 CA：存在就用它校验（`VerifyCa`），不存在就走 `Preferred`。
pub fn password_file_for_key(key: &str) -> String {
    format!("{}/password", secret_dir_for_key(key))
}

pub fn ca_file_for_key(key: &str) -> String {
    format!("{}/ca.pem", secret_dir_for_key(key))
}

/// TLS 策略。
///
/// 默认 `Preferred`：库支持加密就加密、不支持就明文（本机 / 内网采集是常态）。
/// 有 `ca.pem` 时升级到 `VerifyCa` —— 此时不再允许回落到明文，否则「配了 CA」
/// 反而给人一个虚假的安全感。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Preferred,
    VerifyCa,
}

/// 一个待采的 MySQL 实例。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysqlProbeConfig {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub interval: Duration,
    pub tls: TlsMode,
    /// 密码文件路径（内容按行 trim 后使用）。
    pub password_file: String,
    /// `VerifyCa` 时必填。
    pub ca_file: Option<String>,
    /// 凭据目录名（`port-3306` / `pod-...`），也用于日志。
    pub credential_key: String,
    /// 指标 `instance`：host 用 `<host>:<port>`，容器用凭据 key（重启换 IP 不断档）。
    instance_id: String,
}

impl MysqlProbeConfig {
    pub fn new(host: impl Into<String>, port: u16, timeout_ms: u64, interval_ms: u64) -> Self {
        let host = host.into();
        Self {
            tls: TlsMode::Preferred,
            password_file: password_file_for_port(port),
            ca_file: None,
            credential_key: format!("port-{port}"),
            instance_id: format!("{}:{host}:{port}", COLLECTION_KIND_PREFIX),
            port,
            host,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            interval: Duration::from_millis(interval_ms.max(1)),
        }
    }

    /// 按自探结果设置凭据目录与容器身份。
    pub fn with_identity(mut self, credential_key: &str, instance_id: String) -> Self {
        self.credential_key = credential_key.to_string();
        self.password_file = password_file_for_key(credential_key);
        self.ca_file = None;
        self.instance_id = instance_id;
        self
    }

    /// 实例身份：host 是 `mysql:<host>:<port>`，容器是 `mysql:<credential_key>`。
    pub fn instance(&self) -> String {
        self.instance_id.clone()
    }
}

/// `instance` 的首段（避免与 [`COLLECTION_KIND`] 的拼写漂移）。
const COLLECTION_KIND_PREFIX: &str = "mysql";

/// 把自探结果翻译成采集配置（每个实例一条）。
///
/// - 端点：本机 `127.0.0.1:<port>`（端点**只来自自探**，不接受外部地址）；
/// - 凭据：`secrets/mysql/port-<port>/password`；`ca.pem` 存在就升级到 `VerifyCa`
///   （不静默降级：配了 CA 却回落到明文等于假安全）。
///
/// 没有快照 / 没有通过握手的实例 → 空列表（调用方据此停采，而不是猜端口）。
pub fn targets_from_discovery(
    snapshot: Option<&wist_contracts::discovery::DiscoverySnapshot>,
    settings: &MysqlTargetSettings,
) -> Vec<MysqlProbeConfig> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    targets_from_instances(
        crate::discovery::mysql_source::resolve_from_snapshot(snapshot),
        settings,
    )
}

/// 纯映射部分（与发现解耦，单测不需要真 `/proc`）。
pub fn targets_from_instances(
    instances: Vec<crate::discovery::mysql_source::MysqlInstanceEntry>,
    settings: &MysqlTargetSettings,
) -> Vec<MysqlProbeConfig> {
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    for instance in instances {
        // 实例身份去重：容器看名字（同一 pod 换 IP 仍是一条），host 看地址+端口。
        if !seen.insert(instance.instance()) {
            continue;
        }
        let mut config = MysqlProbeConfig::new(
            &instance.host,
            instance.port,
            settings.timeout.as_millis() as u64,
            settings.interval.as_millis() as u64,
        )
        .with_identity(&instance.credential_key, instance.instance());
        let ca = ca_file_for_key(&instance.credential_key);
        if std::path::Path::new(&ca).is_file() {
            config.tls = TlsMode::VerifyCa;
            config.ca_file = Some(ca);
        }
        log::debug!(
            "event=MysqlTargetResolved target=\"{}\" addr=\"{}:{}\" credential=\"{}\" evidence={} confidence={}",
            config.instance(),
            instance.host,
            instance.port,
            instance.credential_key,
            instance.evidence,
            instance.confidence
        );
        out.push(config);
    }
    out
}

/// 自探结果的调优参数（来自工作授权的周期）。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct MysqlTargetSettings {
    pub timeout: Duration,
    pub interval: Duration,
}

impl Default for MysqlTargetSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            interval: Duration::from_secs(30),
        }
    }
}

// ---------------------------------------------------------------------------
// 查询层（可注入，单测不需要真库）
// ---------------------------------------------------------------------------

/// 一行结果：列名 → 文本值。NULL 不出现在 map 里（与「不存在」同义，都不补 0）。
pub type Row = BTreeMap<String, String>;

type BoxFuture<'a, T> = Pin<Box<dyn Future<Output = T> + Send + 'a>>;

/// 只读查询通道。
///
/// 刻意只暴露「执行一条静态 SQL」：采集逻辑就三条 `SHOW`，不需要事务、参数绑定
/// 或连接池管理，接口越窄，假实现越好写、真实现越不容易跑偏。
pub trait SqlTransport: Send {
    fn query(&mut self, sql: &'static str) -> BoxFuture<'_, Result<Vec<Row>, String>>;
}

const STATUS_SQL: &str = "SHOW GLOBAL STATUS";
const VARIABLES_SQL: &str = "SHOW GLOBAL VARIABLES";
/// MySQL 8.0.22+ 用 REPLICA 术语，老版本只有 SLAVE；TiDB 两条都不支持。
const REPLICA_SQL: [&str; 2] = ["SHOW REPLICA STATUS", "SHOW SLAVE STATUS"];

/// 采集一轮（传输可注入）。
pub(super) async fn collect_with(
    transport: &mut dyn SqlTransport,
    config: &MysqlProbeConfig,
) -> ProbeResult {
    let mut warnings = Vec::new();

    let status = match transport.query(STATUS_SQL).await {
        Ok(rows) => into_map(rows),
        Err(err) => {
            // `SHOW GLOBAL STATUS` 失败 = 这一轮什么都拿不到：整轮算失败。
            return ProbeResult {
                targets: Vec::new(),
                attempted: 1,
                failed: 1,
                last_error: Some(format!("{STATUS_SQL} 失败：{err}")),
                warnings,
            };
        }
    };
    let variables = match transport.query(VARIABLES_SQL).await {
        Ok(rows) => into_map(rows),
        Err(err) => {
            // 变量只是补充（上限 / buffer pool 容量），不该拖垮整轮。
            warnings.push(format!("{VARIABLES_SQL} 失败：{err}（相关指标本轮缺失）"));
            BTreeMap::new()
        }
    };

    let mut facts = Facts::default();
    facts.push("mysql.up", "1");
    facts.int(&status, "Status", "Uptime", "mysql.uptime.seconds");
    facts.int(
        &status,
        "Status",
        "Threads_connected",
        "mysql.connections.current",
    );
    facts.int(
        &variables,
        "Variable",
        "max_connections",
        "mysql.connections.max",
    );
    facts.int(
        &status,
        "Status",
        "Threads_running",
        "mysql.threads.running",
    );
    facts.int(&status, "Status", "Questions", "mysql.queries.total");
    facts.int(
        &status,
        "Status",
        "Slow_queries",
        "mysql.slow_queries.total",
    );
    facts.int(
        &status,
        "Status",
        "Aborted_connects",
        "mysql.aborted_connects.total",
    );
    facts.int(
        &status,
        "Status",
        "Bytes_received",
        "mysql.bytes_received.total",
    );
    facts.int(&status, "Status", "Bytes_sent", "mysql.bytes_sent.total");
    facts.int(
        &status,
        "Status",
        "Innodb_buffer_pool_pages_total",
        "mysql.innodb.buffer_pool.page_count",
    );
    facts.int(
        &status,
        "Status",
        "Innodb_buffer_pool_pages_free",
        "mysql.innodb.buffer_pool.page_free_count",
    );
    facts.int(
        &variables,
        "Variable",
        "innodb_buffer_pool_size",
        "mysql.innodb.buffer_pool.size_bytes",
    );

    collect_replication(transport, &mut facts).await;

    warnings.extend(facts.warnings);
    ProbeResult {
        targets: vec![sample(config, facts.facts)],
        attempted: 1,
        failed: 0,
        last_error: None,
        warnings,
    }
}

/// 复制面：没有副本（或版本不支持这条语句）就**什么都不出**。
///
/// 多通道复制（MySQL 8 的 `FOR CHANNEL`）一次返回多行：lag 取**最大值**、
/// running 要求**全部**通道都在跑 —— 部分通道断了就是断了，平均值会把故障抹平。
async fn collect_replication(transport: &mut dyn SqlTransport, facts: &mut Facts) {
    let mut last_error = None;
    for sql in REPLICA_SQL {
        match transport.query(sql).await {
            Ok(rows) if rows.is_empty() => {
                // 不是副本：静默（每轮都打一行 warning 会把日志刷满，而这是正常状态）。
                log::debug!("event=MysqlNotAReplica statement=\"{sql}\"");
                return;
            }
            Ok(rows) => {
                if rows.len() > 1 {
                    facts.warnings.push(format!(
                        "复制有 {} 个通道：延迟取最大值、运行状态要求全部正常",
                        rows.len()
                    ));
                }
                replication_facts(&rows, facts);
                return;
            }
            Err(err) => last_error = Some(err),
        }
    }
    let detail = last_error.unwrap_or_else(|| "未知错误".to_string());
    if is_unsupported(&detail) {
        // TiDB / 老版本没有这条语句：不是故障，也不需要每轮提醒。
        log::debug!("event=MysqlReplicationStatusUnsupported detail=\"{detail}\"");
    } else {
        facts.warnings.push(format!(
            "复制状态不可读：{detail}（延迟与运行状态本轮缺失）"
        ));
    }
}

fn replication_facts(rows: &[Row], facts: &mut Facts) {
    let mut running = true;
    let mut lag: Option<f64> = None;
    for row in rows {
        let io = row
            .get("Replica_IO_Running")
            .or_else(|| row.get("Slave_IO_Running"));
        let sql = row
            .get("Replica_SQL_Running")
            .or_else(|| row.get("Slave_SQL_Running"));
        running &= matches!(io.map(String::as_str), Some("Yes"))
            && matches!(sql.map(String::as_str), Some("Yes"));

        let raw = row
            .get("Seconds_Behind_Source")
            .or_else(|| row.get("Seconds_Behind_Master"));
        match raw.map(|value| value.trim()) {
            Some(value) if !value.is_empty() && !value.eq_ignore_ascii_case("null") => {
                match value.parse::<f64>() {
                    Ok(seconds) => lag = Some(lag.map_or(seconds, |prev: f64| prev.max(seconds))),
                    Err(_) => facts.warnings.push(format!("复制延迟不是数字：{value}")),
                }
            }
            _ => facts
                .warnings
                .push("复制延迟为 NULL（SQL 线程可能已停）：本轮不出延迟".to_string()),
        }
    }
    facts.push("mysql.replication.running", if running { "1" } else { "0" });
    if let Some(seconds) = lag {
        facts.push("mysql.replication.lag_seconds", &seconds.to_string());
    }
}

/// 版本不支持这条语句（TiDB 的 1105、老版本 1064）——按「没有副本」处理。
fn is_unsupported(detail: &str) -> bool {
    let lowered = detail.to_ascii_lowercase();
    lowered.contains("error in your sql syntax")
        || lowered.contains("unknown command")
        || lowered.contains("not supported")
}

fn into_map(rows: Vec<Row>) -> BTreeMap<String, String> {
    // `SHOW GLOBAL STATUS` / `VARIABLES` 是两列的表：`Variable_name` 与 `Value`。
    // **按列名取**，不按顺序取：`Row` 是 `BTreeMap`，迭代顺序是键排序，不是列顺序。
    rows.into_iter()
        .filter_map(|row| {
            let name = row.get("Variable_name")?.clone();
            let value = row.get("Value")?.clone();
            Some((name, value))
        })
        .collect()
}

/// 事实收集器：缺键只记 warning，不补 0。
#[derive(Default)]
struct Facts {
    facts: Vec<StringKeyValue>,
    warnings: Vec<String>,
    seen_keys: BTreeSet<String>,
}

impl Facts {
    fn push(&mut self, key: &str, value: &str) {
        if self.facts.len() >= MAX_FACTS {
            return;
        }
        if !self.seen_keys.insert(key.to_string()) {
            return;
        }
        self.facts.push(StringKeyValue::new(key, value.to_string()));
    }

    /// 从 `SHOW` 结果里取一个整数事实。
    fn int(&mut self, table: &BTreeMap<String, String>, source: &str, name: &str, key: &str) {
        match table.get(name) {
            Some(raw) => match raw.trim().parse::<i64>() {
                Ok(value) => self.push(key, &value.to_string()),
                Err(_) => self
                    .warnings
                    .push(format!("{source}.{name} 不是整数：{raw}")),
            },
            None => self.warnings.push(format!("{source} 缺少 {name}")),
        }
    }
}

fn sample(config: &MysqlProbeConfig, facts: Vec<StringKeyValue>) -> MetricsCollectionTargetSample {
    let instance = config.instance();
    MetricsCollectionTargetSample {
        candidate_id: instance.clone(),
        target_ref: instance.clone(),
        status: "succeeded".to_string(),
        last_error: None,
        resource_ref: instance,
        execution_hints: Vec::new(),
        runtime_facts: facts,
        labeled_facts: Vec::new(),
    }
}

// ---------------------------------------------------------------------------
// 真传输：sqlx
// ---------------------------------------------------------------------------

use sqlx::Connection as _;

/// 一轮采集：读密码 → 连接 → 三条 `SHOW` → 结果。
///
/// 连接失败也算**尝试过**（`attempted = 1 / failed = 1`）：现场只看得到「没数据」时，
/// 必须能区分「没授权」和「连不上 / 密码错」。
pub(super) async fn probe_once(config: &MysqlProbeConfig) -> ProbeResult {
    let password = match tokio::fs::read_to_string(&config.password_file).await {
        Ok(text) => text.trim().to_string(),
        Err(err) => {
            return failed(format!(
                "读不到密码文件 {}：{err}（该实例未投放凭据）",
                config.password_file
            ));
        }
    };

    let mut options = sqlx::mysql::MySqlConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .username(MYSQL_PROBE_USERNAME)
        .password(&password)
        // 采集只读几条 `SHOW`：不要语句缓存，省掉每个连接的首轮 round-trip。
        .statement_cache_capacity(0);
    options = match (config.tls, config.ca_file.as_deref()) {
        (TlsMode::VerifyCa, Some(ca)) => options
            .ssl_mode(sqlx::mysql::MySqlSslMode::VerifyCa)
            .ssl_ca(std::path::Path::new(ca)),
        // 配了 `VerifyCa` 却没有 CA 文件：不静默降级，按失败报出来（配置错误要说清楚）。
        (TlsMode::VerifyCa, None) => {
            return failed(format!(
                "实例 {} 要求校验服务端证书，但没有配置 ca.pem",
                config.instance()
            ));
        }
        (TlsMode::Preferred, _) => options.ssl_mode(sqlx::mysql::MySqlSslMode::Preferred),
    };

    let connect = sqlx::MySqlConnection::connect_with(&options);
    let mut conn = match tokio::time::timeout(config.timeout, connect).await {
        Ok(Ok(conn)) => conn,
        Ok(Err(err)) => return failed(format!("连接 {} 失败：{err}", config.addr())),
        Err(_) => {
            return failed(format!(
                "连接 {} 超时（{}ms）",
                config.addr(),
                config.timeout.as_millis()
            ));
        }
    };

    // 兜底：只读账号 + 会话级执行上限（`SHOW` 不受它约束，但将来加 SELECT 时有效）。
    // 参数走 bind：sqlx 0.9 不接受动态拼出来的 SQL 字符串。
    let guard_ms = config.timeout.as_millis() as u64;
    if let Err(err) = sqlx::query("SET SESSION max_execution_time = ?")
        .bind(guard_ms)
        .execute(&mut conn)
        .await
    {
        log::debug!("event=MysqlSessionGuardIgnored detail=\"{err}\"");
    }

    let mut transport = SqlxTransport { conn };
    let result = tokio::time::timeout(config.timeout, collect_with(&mut transport, config)).await;
    match result {
        Ok(result) => result,
        Err(_) => failed(format!(
            "采集 {} 超时（{}ms）",
            config.addr(),
            config.timeout.as_millis()
        )),
    }
}

impl MysqlProbeConfig {
    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

fn failed(error: String) -> ProbeResult {
    ProbeResult {
        targets: Vec::new(),
        attempted: 1,
        failed: 1,
        last_error: Some(error),
        warnings: Vec::new(),
    }
}

struct SqlxTransport {
    conn: sqlx::mysql::MySqlConnection,
}

impl SqlTransport for SqlxTransport {
    fn query(&mut self, sql: &'static str) -> BoxFuture<'_, Result<Vec<Row>, String>> {
        Box::pin(async move {
            let rows = sqlx::query(sql)
                .fetch_all(&mut self.conn)
                .await
                .map_err(|err| err.to_string())?;
            Ok(rows.iter().map(to_row).collect())
        })
    }
}

fn to_row(row: &sqlx::mysql::MySqlRow) -> Row {
    use sqlx::{Column, Row as _};
    let mut out = Row::new();
    for (index, column) in row.columns().iter().enumerate() {
        // `SHOW` 的列类型随版本而变（字符串 / 无符号整数 / NULL），按「谁解析得动就用谁」
        // 逐个试：NULL 在第一次就得到 `None`，不会误判。
        if let Some(value) = cell(row, index) {
            out.insert(column.name().to_string(), value);
        }
    }
    out
}

fn cell(row: &sqlx::mysql::MySqlRow, index: usize) -> Option<String> {
    use sqlx::Row as _;
    if let Ok(value) = row.try_get::<Option<String>, _>(index) {
        return value;
    }
    if let Ok(value) = row.try_get::<Option<i64>, _>(index) {
        return value.map(|value| value.to_string());
    }
    if let Ok(value) = row.try_get::<Option<u64>, _>(index) {
        return value.map(|value| value.to_string());
    }
    if let Ok(value) = row.try_get::<Option<f64>, _>(index) {
        return value.map(|value| value.to_string());
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Default)]
    struct Fake {
        answers: std::sync::Mutex<BTreeMap<&'static str, Result<Vec<Row>, String>>>,
        asked: std::sync::Mutex<Vec<&'static str>>,
    }

    impl Fake {
        fn with(mut self, sql: &'static str, answer: Result<Vec<Row>, String>) -> Self {
            self.answers.get_mut().unwrap().insert(sql, answer);
            self
        }
    }

    impl SqlTransport for Fake {
        fn query(&mut self, sql: &'static str) -> BoxFuture<'_, Result<Vec<Row>, String>> {
            Box::pin(async move {
                self.asked.lock().unwrap().push(sql);
                self.answers
                    .lock()
                    .unwrap()
                    .get(sql)
                    .cloned()
                    .unwrap_or(Ok(Vec::new()))
            })
        }
    }

    fn row(pairs: &[(&str, &str)]) -> Row {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn status(pairs: &[(&str, &str)]) -> Result<Vec<Row>, String> {
        Ok(pairs
            .iter()
            .map(|(name, value)| row(&[("Variable_name", name), ("Value", value)]))
            .collect())
    }

    fn config() -> MysqlProbeConfig {
        MysqlProbeConfig::new("127.0.0.1", 3306, 1_000, 30_000)
    }

    fn fact_value<'a>(result: &'a ProbeResult, key: &str) -> Option<&'a str> {
        result.targets[0]
            .runtime_facts
            .iter()
            .find(|fact| fact.key == key)
            .map(|fact| fact.value.as_str())
    }

    fn healthy_status() -> Result<Vec<Row>, String> {
        status(&[
            ("Uptime", "12345"),
            ("Threads_connected", "12"),
            ("Threads_running", "3"),
            ("Questions", "9000"),
            ("Slow_queries", "7"),
            ("Aborted_connects", "2"),
            ("Bytes_received", "1000"),
            ("Bytes_sent", "2000"),
            ("Innodb_buffer_pool_pages_total", "8192"),
            ("Innodb_buffer_pool_pages_free", "1024"),
        ])
    }

    fn healthy_variables() -> Result<Vec<Row>, String> {
        status(&[
            ("max_connections", "151"),
            ("innodb_buffer_pool_size", "134217728"),
        ])
    }

    fn healthy_replica() -> Result<Vec<Row>, String> {
        Ok(vec![row(&[
            ("Replica_IO_Running", "Yes"),
            ("Replica_SQL_Running", "Yes"),
            ("Seconds_Behind_Source", "5"),
        ])])
    }

    #[tokio::test]
    async fn maps_a_healthy_instance_to_the_documented_facts() {
        let mut transport = Fake::default()
            .with(STATUS_SQL, healthy_status())
            .with(VARIABLES_SQL, healthy_variables())
            .with(REPLICA_SQL[0], healthy_replica());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 0);
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
        assert_eq!(result.targets.len(), 1);
        assert_eq!(result.targets[0].resource_ref, "mysql:127.0.0.1:3306");

        for (key, expected) in [
            ("mysql.up", "1"),
            ("mysql.uptime.seconds", "12345"),
            ("mysql.connections.current", "12"),
            ("mysql.connections.max", "151"),
            ("mysql.threads.running", "3"),
            ("mysql.queries.total", "9000"),
            ("mysql.slow_queries.total", "7"),
            ("mysql.aborted_connects.total", "2"),
            ("mysql.bytes_received.total", "1000"),
            ("mysql.bytes_sent.total", "2000"),
            ("mysql.innodb.buffer_pool.page_count", "8192"),
            ("mysql.innodb.buffer_pool.page_free_count", "1024"),
            ("mysql.innodb.buffer_pool.size_bytes", "134217728"),
            ("mysql.replication.running", "1"),
            ("mysql.replication.lag_seconds", "5"),
        ] {
            assert_eq!(fact_value(&result, key), Some(expected), "fact `{key}`");
        }
    }

    #[tokio::test]
    async fn a_failed_status_query_fails_the_whole_round() {
        let mut transport = Fake::default().with(STATUS_SQL, Err("denied".to_string()));

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.attempted, 1, "尝试过就要记账");
        assert_eq!(result.failed, 1);
        assert!(result.targets.is_empty(), "连不上不造样本");
        assert!(result.last_error.unwrap().contains("denied"));
    }

    #[tokio::test]
    async fn a_failed_variables_query_only_drops_those_facts() {
        let mut transport = Fake::default()
            .with(STATUS_SQL, healthy_status())
            .with(VARIABLES_SQL, Err("timeout".to_string()));

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 0, "变量是补充信息，不拖垮整轮");
        assert_eq!(fact_value(&result, "mysql.connections.max"), None);
        assert_eq!(fact_value(&result, "mysql.connections.current"), Some("12"));
        assert!(
            result.warnings.iter().any(|w| w.contains("timeout")),
            "缺失原因要留痕：{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn a_standalone_server_emits_no_replication_facts() {
        let mut transport = Fake::default()
            .with(STATUS_SQL, healthy_status())
            .with(VARIABLES_SQL, healthy_variables());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "mysql.replication.running"), None);
        assert_eq!(fact_value(&result, "mysql.replication.lag_seconds"), None);
        assert!(
            result.warnings.is_empty(),
            "「不是副本」是正常状态，不该报 warning：{:?}",
            result.warnings
        );
        assert_eq!(fact_value(&result, "mysql.up"), Some("1"), "但库本身是活的");
    }

    #[tokio::test]
    async fn an_unsupported_replica_statement_is_not_a_warning() {
        // TiDB：两条语句都不认，返回语法错误 —— 按「不是副本」处理。
        let mut transport = Fake::default()
            .with(STATUS_SQL, healthy_status())
            .with(VARIABLES_SQL, healthy_variables())
            .with(
                REPLICA_SQL[0],
                Err("You have an error in your SQL syntax".to_string()),
            )
            .with(
                REPLICA_SQL[1],
                Err("You have an error in your SQL syntax".to_string()),
            );

        let result = collect_with(&mut transport, &config()).await;

        assert!(
            result.warnings.is_empty(),
            "版本不支持不该每轮刷日志：{:?}",
            result.warnings
        );
        assert_eq!(fact_value(&result, "mysql.replication.running"), None);
    }

    #[tokio::test]
    async fn a_broken_replication_keeps_running_zero_and_drops_the_lag() {
        let mut transport = Fake::default()
            .with(STATUS_SQL, healthy_status())
            .with(VARIABLES_SQL, healthy_variables())
            .with(
                REPLICA_SQL[0],
                Ok(vec![row(&[
                    ("Replica_IO_Running", "Connecting"),
                    ("Replica_SQL_Running", "Yes"),
                    ("Seconds_Behind_Source", ""),
                ])]),
            );

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "mysql.replication.running"), Some("0"));
        assert_eq!(
            fact_value(&result, "mysql.replication.lag_seconds"),
            None,
            "延迟为 NULL 时不出样本（不伪造 0）"
        );
        assert!(
            result.warnings.iter().any(|w| w.contains("NULL")),
            "{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn multiple_channels_take_the_worst_lag_and_require_all_running() {
        let mut transport = Fake::default()
            .with(STATUS_SQL, healthy_status())
            .with(VARIABLES_SQL, healthy_variables())
            .with(
                REPLICA_SQL[0],
                Ok(vec![
                    row(&[
                        ("Replica_IO_Running", "Yes"),
                        ("Replica_SQL_Running", "Yes"),
                        ("Seconds_Behind_Source", "3"),
                    ]),
                    row(&[
                        ("Replica_IO_Running", "Yes"),
                        ("Replica_SQL_Running", "No"),
                        ("Seconds_Behind_Source", "40"),
                    ]),
                ]),
            );

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "mysql.replication.running"), Some("0"));
        assert_eq!(
            fact_value(&result, "mysql.replication.lag_seconds"),
            Some("40")
        );
        assert!(result.warnings.iter().any(|w| w.contains("通道")));
    }

    #[tokio::test]
    async fn a_missing_status_key_is_reported_not_zeroed() {
        let mut transport = Fake::default()
            .with(STATUS_SQL, status(&[("Uptime", "10")]))
            .with(VARIABLES_SQL, healthy_variables());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "mysql.uptime.seconds"), Some("10"));
        assert_eq!(
            fact_value(&result, "mysql.threads.running"),
            None,
            "缺键不补 0"
        );
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("Threads_running")),
            "{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn a_non_numeric_status_value_is_reported_and_skipped() {
        let mut transport = Fake::default()
            .with(
                STATUS_SQL,
                status(&[("Uptime", "ten"), ("Threads_running", "3")]),
            )
            .with(VARIABLES_SQL, healthy_variables());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "mysql.uptime.seconds"), None);
        assert!(
            result.warnings.iter().any(|w| w.contains("不是整数")),
            "{:?}",
            result.warnings
        );
    }

    #[test]
    fn credential_paths_follow_the_port_key_rule() {
        assert_eq!(
            secret_dir_for_port(3306),
            "/etc/wist-agentd/secrets/mysql/port-3306"
        );
        assert_eq!(
            password_file_for_port(3307),
            "/etc/wist-agentd/secrets/mysql/port-3307/password"
        );
        assert_eq!(
            ca_file_for_key("port-3306"),
            "/etc/wist-agentd/secrets/mysql/port-3306/ca.pem"
        );
        assert_eq!(config().instance(), "mysql:127.0.0.1:3306");
    }

    #[tokio::test]
    async fn a_missing_password_file_is_a_failed_round_not_an_empty_one() {
        let mut config = config();
        config.password_file = "/nonexistent/wist-agentd/password".to_string();

        let result = probe_once(&config).await;

        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 1);
        assert!(result.targets.is_empty());
        let error = result.last_error.unwrap();
        assert!(error.contains("未投放凭据"), "{error}");
    }

    #[test]
    fn discovered_instances_become_loopback_targets() {
        use crate::discovery::mysql_source::{InstanceScope, MysqlInstanceEntry};

        let settings = MysqlTargetSettings::default();
        let entry = |port: u16, evidence: &str| MysqlInstanceEntry {
            source_ref: format!("port:{port}"),
            host: "127.0.0.1".to_string(),
            port,
            credential_key: format!("port-{port}"),
            scope: InstanceScope::Host,
            evidence: evidence.to_string(),
            detail: String::new(),
            confidence: 50,
        };
        let targets = targets_from_instances(
            vec![
                entry(3999, "config"),
                entry(3999, "listening_port"),
                entry(3998, "argv"),
            ],
            &settings,
        );

        assert_eq!(targets.len(), 2, "同一实例只留一条");
        let target = targets
            .iter()
            .find(|target| target.port == 3998)
            .expect("3998");
        assert_eq!(target.instance(), "mysql:127.0.0.1:3998");
        assert_eq!(target.host, "127.0.0.1", "host 实例走近回环");
        assert_eq!(
            target.password_file,
            "/etc/wist-agentd/secrets/mysql/port-3998/password"
        );
        assert_eq!(target.tls, TlsMode::Preferred, "没有 ca.pem 就允许回落明文");
        assert_eq!(target.timeout, settings.timeout);
    }

    #[test]
    fn a_container_instance_uses_its_name_as_identity_and_credential() {
        use crate::discovery::mysql_source::{InstanceScope, MysqlInstanceEntry};

        let targets = targets_from_instances(
            vec![MysqlInstanceEntry {
                source_ref: "port:3306".to_string(),
                host: "10.244.1.5".to_string(),
                port: 3306,
                credential_key: "pod-prod-mysql-0".to_string(),
                scope: InstanceScope::Container,
                evidence: "config".to_string(),
                detail: String::new(),
                confidence: 90,
            }],
            &MysqlTargetSettings::default(),
        );

        assert_eq!(targets.len(), 1);
        assert_eq!(
            targets[0].instance(),
            "mysql:pod-prod-mysql-0",
            "容器身份用名字：pod 重建换 IP 也不会断成两条序列"
        );
        assert_eq!(targets[0].host, "10.244.1.5", "连接走 pod IP");
        assert_eq!(
            targets[0].password_file,
            "/etc/wist-agentd/secrets/mysql/pod-prod-mysql-0/password"
        );
    }
}
