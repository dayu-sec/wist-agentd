//! PostgreSQL 指标采集：SQL 直采，只读。
//!
//! 与 [`super::mysql`] 共用查询通道与事实收集器（[`super::mysql::SqlTransport`]），
//! 差别只在 SQL 与指标映射：PG 没有 `SHOW GLOBAL STATUS`，读数来自
//! `pg_stat_activity` / `pg_stat_database` / `pg_settings` / 恢复状态函数。
//!
//! 目标身份：`postgres:<host>:<port>`（host 实例）或 `postgres:<凭据 key>`
//! （容器，pod 重建换 IP 不断档）。凭据与 MySQL 同一套规则，只是根目录换成
//! `secrets/postgres/`。
//!
//! 三条不变量与 MySQL 一致：**不伪造 0**、不是备库就不出复制序列、整轮失败记
//! `attempted = 1 / failed = 1`。

use std::collections::BTreeMap;
use std::time::Duration;

use wist_contracts::discovery::StringKeyValue;

use super::collection::ProbeResult;
use super::mysql::{BoxFuture, Facts, Row, SqlTransport};
use super::runtime::MetricsCollectionTargetSample;

/// 采集域：与 `wist_metrics::spec` 里 `pg_metrics` 对应。
pub const COLLECTION_KIND: &str = "pg_metrics";

/// 只读账号名：与其它探针一致。
pub const PG_PROBE_USERNAME: &str = "wist-probe";

/// 凭据根目录（Secret / 配置文件挂载点）。
pub const PG_SECRET_ROOT: &str = "/etc/wist-agentd/secrets/postgres";

const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// PostgreSQL 的块大小（`blks_read` / `blks_hit` 的单位），换算成字节上报。
const PG_BLOCK_BYTES: i64 = 8192;

pub fn secret_dir_for_key(key: &str) -> String {
    format!("{PG_SECRET_ROOT}/{key}")
}

pub fn password_file_for_key(key: &str) -> String {
    format!("{}/password", secret_dir_for_key(key))
}

pub fn ca_file_for_key(key: &str) -> String {
    format!("{}/ca.pem", secret_dir_for_key(key))
}

/// TLS 策略（与 MySQL 同义）。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsMode {
    Prefer,
    VerifyCa,
}

/// 一个待采的 PostgreSQL 实例。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgProbeConfig {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub interval: Duration,
    pub tls: TlsMode,
    pub password_file: String,
    pub ca_file: Option<String>,
    pub credential_key: String,
    instance_id: String,
}

impl PgProbeConfig {
    pub fn new(host: impl Into<String>, port: u16, timeout_ms: u64, interval_ms: u64) -> Self {
        let host = host.into();
        let key = format!("port-{port}");
        Self {
            tls: TlsMode::Prefer,
            password_file: password_file_for_key(&key),
            ca_file: None,
            credential_key: key,
            instance_id: format!("postgres:{host}:{port}"),
            port,
            host,
            timeout: Duration::from_millis(timeout_ms.max(1)),
            interval: Duration::from_millis(interval_ms.max(1)),
        }
    }

    pub fn with_identity(mut self, credential_key: &str, instance_id: String) -> Self {
        self.credential_key = credential_key.to_string();
        self.password_file = password_file_for_key(credential_key);
        self.ca_file = None;
        self.instance_id = instance_id;
        self
    }

    pub fn instance(&self) -> String {
        self.instance_id.clone()
    }

    fn addr(&self) -> String {
        format!("{}:{}", self.host, self.port)
    }
}

/// 自探结果的调优参数。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct PgTargetSettings {
    pub timeout: Duration,
    pub interval: Duration,
}

impl Default for PgTargetSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_millis(DEFAULT_TIMEOUT_MS),
            interval: Duration::from_secs(30),
        }
    }
}

/// 把自探结果翻译成采集配置。
pub fn targets_from_discovery(
    snapshot: Option<&wist_contracts::discovery::DiscoverySnapshot>,
    settings: &PgTargetSettings,
) -> Vec<PgProbeConfig> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    targets_from_instances(
        crate::discovery::pg_source::resolve_from_snapshot(snapshot),
        settings,
    )
}

pub fn targets_from_instances(
    instances: Vec<crate::discovery::pg_source::PgInstanceEntry>,
    settings: &PgTargetSettings,
) -> Vec<PgProbeConfig> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for instance in instances {
        if !seen.insert(instance.instance()) {
            continue;
        }
        let mut config = PgProbeConfig::new(
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
            "event=PgTargetResolved target=\"{}\" addr=\"{}\" credential=\"{}\" evidence={} confidence={}",
            config.instance(),
            config.addr(),
            instance.credential_key,
            instance.evidence,
            instance.confidence
        );
        out.push(config);
    }
    out
}

// ---------------------------------------------------------------------------
// 查询
// ---------------------------------------------------------------------------

/// 一台实例一轮要跑的三条查询。刻意都用 `pg_stat_*`，不依赖任何扩展。
const SERVER_SQL: &str = "SELECT extract(epoch from now() - pg_postmaster_start_time())::bigint AS uptime, \
     current_setting('max_connections') AS max_connections, pg_is_in_recovery() AS in_recovery";
const ACTIVITY_SQL: &str = "SELECT count(*) AS connections FROM pg_stat_activity";
const DATABASE_SQL: &str = "SELECT xact_commit, xact_rollback, deadlocks, temp_bytes, blks_read, blks_hit, \
     pg_database_size(current_database()) AS size_bytes \
     FROM pg_stat_database WHERE datname = current_database()";
const REPLICA_SQL: &str =
    "SELECT extract(epoch from now() - pg_last_xact_replay_timestamp()) AS lag_seconds";

pub(super) async fn collect_with(
    transport: &mut dyn SqlTransport,
    config: &PgProbeConfig,
) -> ProbeResult {
    let mut warnings = Vec::new();

    let server = match transport.query(SERVER_SQL).await {
        Ok(rows) => first_row(rows),
        Err(err) => {
            return ProbeResult {
                targets: Vec::new(),
                attempted: 1,
                failed: 1,
                last_error: Some(format!("状态查询失败：{err}")),
                warnings,
            };
        }
    };
    let Some(server) = server else {
        return ProbeResult {
            targets: Vec::new(),
            attempted: 1,
            failed: 1,
            last_error: Some("状态查询没有返回行".to_string()),
            warnings,
        };
    };

    let activity = match transport.query(ACTIVITY_SQL).await {
        Ok(rows) => first_row(rows).unwrap_or_default(),
        Err(err) => {
            warnings.push(format!("pg_stat_activity 不可读：{err}（连接数本轮缺失）"));
            Row::new()
        }
    };
    let database = match transport.query(DATABASE_SQL).await {
        Ok(rows) => first_row(rows).unwrap_or_default(),
        Err(err) => {
            warnings.push(format!(
                "pg_stat_database 不可读：{err}（事务与 IO 指标本轮缺失）"
            ));
            Row::new()
        }
    };

    let mut facts = Facts::default();
    facts.push("pg.up", "1");
    int_fact(&mut facts, &server, "uptime", "pg.uptime.seconds");
    int_fact(&mut facts, &server, "max_connections", "pg.connections.max");
    int_fact(
        &mut facts,
        &activity,
        "connections",
        "pg.connections.current",
    );
    int_fact(&mut facts, &database, "xact_commit", "pg.xact.commit.total");
    int_fact(
        &mut facts,
        &database,
        "xact_rollback",
        "pg.xact.rollback.total",
    );
    int_fact(&mut facts, &database, "deadlocks", "pg.deadlocks.total");
    int_fact(&mut facts, &database, "temp_bytes", "pg.temp.bytes.total");
    int_fact(
        &mut facts,
        &database,
        "size_bytes",
        "pg.database.size_bytes",
    );
    // 块计数换算成字节：消费方不需要知道 `BLCKSZ`。
    bytes_from_blocks(
        &mut facts,
        &database,
        "blks_read",
        "pg.disk.read_bytes.total",
    );
    bytes_from_blocks(
        &mut facts,
        &database,
        "blks_hit",
        "pg.cache.hit_bytes.total",
    );

    // 复制：只在备库上有意义。主库不出这两条（不补 0）。
    let in_recovery = match server.get("in_recovery") {
        Some(value) => value.eq_ignore_ascii_case("true") || value.trim() == "1",
        None => {
            // 缺这一列时绝不能默认「主库」了事：那会让备库的复制断掉静默消失。
            warnings.push("状态查询缺少 in_recovery：本轮不出复制指标".to_string());
            false
        }
    };
    if in_recovery {
        match transport.query(REPLICA_SQL).await {
            Ok(rows) => match first_row(rows).and_then(|row| row.get("lag_seconds").cloned()) {
                Some(lag) if !lag.trim().is_empty() => {
                    facts.push("pg.replication.running", "1");
                    facts.push("pg.replication.lag_seconds", lag.trim());
                }
                _ => {
                    // 备库但还没有可用的回放位点：如实说「在恢复、但没有延迟读数」。
                    facts.push("pg.replication.running", "0");
                    warnings.push("备库尚未回放过事务：本轮不出复制延迟".to_string());
                }
            },
            Err(err) => {
                facts.push("pg.replication.running", "0");
                warnings.push(format!("复制状态不可读：{err}"));
            }
        }
    }

    warnings.extend(facts.warnings);
    ProbeResult {
        targets: vec![sample(config, facts.facts)],
        attempted: 1,
        failed: 0,
        last_error: None,
        warnings,
    }
}

fn first_row(rows: Vec<Row>) -> Option<Row> {
    rows.into_iter().next()
}

fn int_fact(facts: &mut Facts, row: &Row, column: &str, fact_key: &str) {
    let Some(raw) = row.get(column) else {
        facts.warnings.push(format!("查询结果缺少 {column}"));
        return;
    };
    match raw.trim().parse::<i64>() {
        Ok(value) => facts.push(fact_key, &value.to_string()),
        Err(_) => facts.warnings.push(format!("{column} 不是整数：{raw}")),
    }
}

fn bytes_from_blocks(facts: &mut Facts, row: &Row, column: &str, fact_key: &str) {
    let Some(raw) = row.get(column) else {
        facts.warnings.push(format!("查询结果缺少 {column}"));
        return;
    };
    match raw.trim().parse::<i64>() {
        Ok(blocks) => facts.push(
            fact_key,
            &(blocks.saturating_mul(PG_BLOCK_BYTES)).to_string(),
        ),
        Err(_) => facts.warnings.push(format!("{column} 不是整数：{raw}")),
    }
}

fn sample(config: &PgProbeConfig, facts: Vec<StringKeyValue>) -> MetricsCollectionTargetSample {
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

pub(super) async fn probe_once(config: &PgProbeConfig) -> ProbeResult {
    let password = match tokio::fs::read_to_string(&config.password_file).await {
        Ok(text) => text.trim().to_string(),
        Err(err) => {
            return failed(format!(
                "读不到密码文件 {}：{err}（该实例未投放凭据）",
                config.password_file
            ));
        }
    };

    let mut options = sqlx::postgres::PgConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .username(PG_PROBE_USERNAME)
        .password(&password)
        .application_name("wist-agentd");
    options = match (config.tls, config.ca_file.as_deref()) {
        (TlsMode::VerifyCa, Some(ca)) => options
            .ssl_mode(sqlx::postgres::PgSslMode::VerifyCa)
            .ssl_root_cert(std::path::Path::new(ca)),
        (TlsMode::VerifyCa, None) => {
            return failed(format!(
                "实例 {} 要求校验服务端证书，但没有配置 ca.pem",
                config.instance()
            ));
        }
        (TlsMode::Prefer, _) => options.ssl_mode(sqlx::postgres::PgSslMode::Prefer),
    };

    let connect = sqlx::PgConnection::connect_with(&options);
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

    // 会话级超时：`SET` 不接受绑定参数，用 `set_config`。
    if let Err(err) = sqlx::query("SELECT set_config('statement_timeout', $1, false)")
        .bind(format!("{}ms", config.timeout.as_millis()))
        .execute(&mut conn)
        .await
    {
        log::debug!("event=PgSessionGuardIgnored detail=\"{err}\"");
    }

    let mut transport = PgTransport { conn };
    match tokio::time::timeout(config.timeout, collect_with(&mut transport, config)).await {
        Ok(result) => result,
        Err(_) => failed(format!(
            "采集 {} 超时（{}ms）",
            config.addr(),
            config.timeout.as_millis()
        )),
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

struct PgTransport {
    conn: sqlx::PgConnection,
}

impl SqlTransport for PgTransport {
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

fn to_row(row: &sqlx::postgres::PgRow) -> Row {
    use sqlx::{Column, Row as _};
    let mut out = BTreeMap::new();
    for (index, column) in row.columns().iter().enumerate() {
        if let Some(value) = cell(row, index) {
            out.insert(column.name().to_string(), value);
        }
    }
    out
}

/// PG 的列类型随版本/查询而变（bigint / numeric / bool / text），按「谁解析得动用谁」。
fn cell(row: &sqlx::postgres::PgRow, index: usize) -> Option<String> {
    use sqlx::Row as _;
    if let Ok(value) = row.try_get::<Option<String>, _>(index) {
        return value;
    }
    if let Ok(value) = row.try_get::<Option<i64>, _>(index) {
        return value.map(|value| value.to_string());
    }
    if let Ok(value) = row.try_get::<Option<f64>, _>(index) {
        return value.map(|value| value.to_string());
    }
    if let Ok(value) = row.try_get::<Option<bool>, _>(index) {
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

    fn config() -> PgProbeConfig {
        PgProbeConfig::new("127.0.0.1", 5432, 1_000, 30_000)
    }

    fn fact_value<'a>(result: &'a ProbeResult, key: &str) -> Option<&'a str> {
        result.targets[0]
            .runtime_facts
            .iter()
            .find(|fact| fact.key == key)
            .map(|fact| fact.value.as_str())
    }

    fn primary() -> (Result<Vec<Row>, String>, Result<Vec<Row>, String>) {
        (
            Ok(vec![row(&[
                ("uptime", "3600"),
                ("max_connections", "100"),
                ("in_recovery", "false"),
            ])]),
            Ok(vec![row(&[("connections", "7")])]),
        )
    }

    fn database() -> Result<Vec<Row>, String> {
        Ok(vec![row(&[
            ("xact_commit", "1000"),
            ("xact_rollback", "3"),
            ("deadlocks", "1"),
            ("temp_bytes", "4096"),
            ("blks_read", "10"),
            ("blks_hit", "90"),
            ("size_bytes", "8192"),
        ])])
    }

    #[tokio::test]
    async fn maps_a_primary_to_the_documented_facts() {
        let (server, activity) = primary();
        let mut transport = Fake::default()
            .with(SERVER_SQL, server)
            .with(ACTIVITY_SQL, activity)
            .with(DATABASE_SQL, database());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 0);
        assert_eq!(result.targets[0].resource_ref, "postgres:127.0.0.1:5432");
        for (key, expected) in [
            ("pg.up", "1"),
            ("pg.uptime.seconds", "3600"),
            ("pg.connections.max", "100"),
            ("pg.connections.current", "7"),
            ("pg.xact.commit.total", "1000"),
            ("pg.xact.rollback.total", "3"),
            ("pg.deadlocks.total", "1"),
            ("pg.temp.bytes.total", "4096"),
            ("pg.disk.read_bytes.total", "81920"),
            ("pg.cache.hit_bytes.total", "737280"),
            ("pg.database.size_bytes", "8192"),
        ] {
            assert_eq!(fact_value(&result, key), Some(expected), "fact `{key}`");
        }
        assert_eq!(
            fact_value(&result, "pg.replication.running"),
            None,
            "主库不出复制序列"
        );
        assert!(result.warnings.is_empty(), "{:?}", result.warnings);
    }

    #[tokio::test]
    async fn every_emitted_fact_has_a_metric_spec() {
        let (server, activity) = primary();
        let mut primary_transport = Fake::default()
            .with(SERVER_SQL, server)
            .with(ACTIVITY_SQL, activity)
            .with(DATABASE_SQL, database());
        let mut replica_transport = Fake::default()
            .with(
                SERVER_SQL,
                Ok(vec![row(&[
                    ("uptime", "10"),
                    ("max_connections", "100"),
                    ("in_recovery", "true"),
                ])]),
            )
            .with(ACTIVITY_SQL, Ok(vec![row(&[("connections", "1")])]))
            .with(DATABASE_SQL, database())
            .with(REPLICA_SQL, Ok(vec![row(&[("lag_seconds", "2.5")])]));

        for (tag, transport) in [
            ("primary", &mut primary_transport),
            ("replica", &mut replica_transport),
        ] {
            let result = collect_with(transport, &config()).await;
            assert_eq!(result.failed, 0, "{tag}");
            for fact in &result.targets[0].runtime_facts {
                let spec = wist_metrics::spec::find_metric_spec(COLLECTION_KIND, &fact.key)
                    .unwrap_or_else(|| panic!("{tag}: fact `{}` 没有指标声明", fact.key));
                assert!(
                    spec.name.starts_with("pg_"),
                    "`{}` 必须落在 pg 命名空间",
                    spec.name
                );
            }
        }
    }

    #[tokio::test]
    async fn a_replica_reports_lag_and_running() {
        let mut transport = Fake::default()
            .with(
                SERVER_SQL,
                Ok(vec![row(&[
                    ("uptime", "10"),
                    ("max_connections", "100"),
                    ("in_recovery", "true"),
                ])]),
            )
            .with(ACTIVITY_SQL, Ok(vec![row(&[("connections", "1")])]))
            .with(DATABASE_SQL, database())
            .with(REPLICA_SQL, Ok(vec![row(&[("lag_seconds", "4.5")])]));

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "pg.replication.running"), Some("1"));
        assert_eq!(
            fact_value(&result, "pg.replication.lag_seconds"),
            Some("4.5")
        );
    }

    #[tokio::test]
    async fn a_replica_without_a_replay_point_does_not_fake_zero_lag() {
        let mut transport = Fake::default()
            .with(
                SERVER_SQL,
                Ok(vec![row(&[
                    ("uptime", "10"),
                    ("max_connections", "100"),
                    ("in_recovery", "true"),
                ])]),
            )
            .with(ACTIVITY_SQL, Ok(vec![row(&[("connections", "1")])]))
            .with(DATABASE_SQL, database())
            .with(REPLICA_SQL, Ok(vec![row(&[("lag_seconds", "")])]));

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "pg.replication.running"), Some("0"));
        assert_eq!(fact_value(&result, "pg.replication.lag_seconds"), None);
        assert!(result.warnings.iter().any(|w| w.contains("回放")));
    }

    #[tokio::test]
    async fn a_failed_status_query_fails_the_whole_round() {
        let mut transport = Fake::default().with(SERVER_SQL, Err("denied".to_string()));

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.attempted, 1);
        assert_eq!(result.failed, 1);
        assert!(result.targets.is_empty());
        assert!(result.last_error.unwrap().contains("denied"));
    }

    #[tokio::test]
    async fn a_failed_stats_query_only_drops_those_facts() {
        let (server, activity) = primary();
        let mut transport = Fake::default()
            .with(SERVER_SQL, server)
            .with(ACTIVITY_SQL, activity)
            .with(DATABASE_SQL, Err("permission denied".to_string()));

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 0);
        assert_eq!(fact_value(&result, "pg.uptime.seconds"), Some("3600"));
        assert_eq!(fact_value(&result, "pg.xact.commit.total"), None);
        assert!(
            result.warnings.iter().any(|w| w.contains("permission")),
            "{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn a_missing_in_recovery_column_is_reported() {
        let mut transport = Fake::default()
            .with(
                SERVER_SQL,
                Ok(vec![row(&[("uptime", "10"), ("max_connections", "100")])]),
            )
            .with(ACTIVITY_SQL, Ok(vec![row(&[("connections", "1")])]))
            .with(DATABASE_SQL, database());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "pg.replication.running"), None);
        assert!(
            result.warnings.iter().any(|w| w.contains("in_recovery")),
            "{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn a_missing_column_is_reported_not_zeroed() {
        let mut transport = Fake::default()
            .with(
                SERVER_SQL,
                Ok(vec![row(&[("uptime", "10"), ("in_recovery", "false")])]),
            )
            .with(ACTIVITY_SQL, Ok(vec![row(&[("connections", "1")])]))
            .with(DATABASE_SQL, database());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(fact_value(&result, "pg.connections.max"), None);
        assert!(
            result
                .warnings
                .iter()
                .any(|w| w.contains("max_connections"))
        );
    }

    #[tokio::test]
    async fn verify_ca_without_a_ca_file_fails_fast_instead_of_downgrading() {
        let mut config = config();
        config.tls = TlsMode::VerifyCa;
        config.ca_file = None;
        let path = std::env::temp_dir().join(format!(
            "wist-agentd-pg-test-{}.password",
            std::process::id()
        ));
        std::fs::write(&path, "secret\n").expect("write");
        config.password_file = path.to_string_lossy().to_string();

        let result = probe_once(&config).await;

        assert_eq!(result.failed, 1);
        assert!(
            result.last_error.unwrap().contains("没有配置 ca.pem"),
            "不能静默降级到明文"
        );
    }

    #[tokio::test]
    async fn a_missing_password_file_is_a_failed_round() {
        let mut config = config();
        config.password_file = "/nonexistent/wist-agentd/pg-password".to_string();

        let result = probe_once(&config).await;

        assert_eq!(result.failed, 1);
        assert!(result.last_error.unwrap().contains("未投放凭据"));
    }

    #[test]
    fn credential_paths_follow_the_key_rule() {
        assert_eq!(
            password_file_for_key("port-5432"),
            "/etc/wist-agentd/secrets/postgres/port-5432/password"
        );
        assert_eq!(
            ca_file_for_key("pod-data-pg-0"),
            "/etc/wist-agentd/secrets/postgres/pod-data-pg-0/ca.pem"
        );
        assert_eq!(config().instance(), "postgres:127.0.0.1:5432");
    }
}
