//! Doris 指标采集（P0）：连 FE 的 MySQL 协议口，读 BE 视图。
//!
//! P0 范围按决策 §12.1-7：**BE 存活 / 容量 / 可用空间 / tablet**，
//! 只用 `SHOW BACKENDS`，不依赖审计日志、不读 compaction 明细。
//!
//! 为什么按 BE 拆序列：一台 FE 管多台 BE，只报合计会把「一台写满、其余空闲」
//! 看成「整体还有 60%」。BE 掉线时该 BE 的序列应当消失（不补 0）。
//!
//! 传输复用 `sqlx` 的 MySQL 驱动（FE 就是说 MySQL 协议），查询通道与 MySQL 域同一个 trait。

use std::collections::BTreeMap;
use std::time::Duration;

use wist_contracts::discovery::StringKeyValue;

use super::collection::ProbeResult;
use super::mysql::{BoxFuture, Row, SqlTransport};
use super::runtime::{MetricsCollectionTargetSample, MetricsLabeledFact};

pub const COLLECTION_KIND: &str = "doris_metrics";
/// FE 上通常只读；沿用同一套探针账号约定。
pub const DORIS_PROBE_USERNAME: &str = "wist-probe";
pub const DORIS_SECRET_ROOT: &str = "/etc/wist-agentd/secrets/doris";

const SHOW_BACKENDS_SQL: &str = "SHOW BACKENDS";

pub fn password_file_for_key(key: &str) -> String {
    format!("{DORIS_SECRET_ROOT}/{key}/password")
}

pub fn ca_file_for_key(key: &str) -> String {
    format!("{DORIS_SECRET_ROOT}/{key}/ca.pem")
}

/// 一个待采的 FE。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DorisProbeConfig {
    pub host: String,
    pub port: u16,
    pub timeout: Duration,
    pub interval: Duration,
    pub password_file: String,
    pub ca_file: Option<String>,
    pub credential_key: String,
    instance_id: String,
}

impl DorisProbeConfig {
    pub fn new(host: impl Into<String>, port: u16, timeout_ms: u64, interval_ms: u64) -> Self {
        let host = host.into();
        let key = format!("port-{port}");
        Self {
            password_file: password_file_for_key(&key),
            ca_file: None,
            credential_key: key,
            instance_id: format!("doris:{host}:{port}"),
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

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DorisTargetSettings {
    pub timeout: Duration,
    pub interval: Duration,
}

impl Default for DorisTargetSettings {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(5),
            interval: Duration::from_secs(30),
        }
    }
}

pub fn targets_from_discovery(
    snapshot: Option<&wist_contracts::discovery::DiscoverySnapshot>,
    settings: &DorisTargetSettings,
) -> Vec<DorisProbeConfig> {
    let Some(snapshot) = snapshot else {
        return Vec::new();
    };
    targets_from_instances(
        crate::discovery::doris_source::resolve_from_snapshot(snapshot),
        settings,
    )
}

pub fn targets_from_instances(
    instances: Vec<crate::discovery::doris_source::DorisInstanceEntry>,
    settings: &DorisTargetSettings,
) -> Vec<DorisProbeConfig> {
    let mut seen = std::collections::BTreeSet::new();
    let mut out = Vec::new();
    for instance in instances {
        if !seen.insert(instance.instance()) {
            continue;
        }
        let mut config = DorisProbeConfig::new(
            &instance.host,
            instance.port,
            settings.timeout.as_millis() as u64,
            settings.interval.as_millis() as u64,
        )
        .with_identity(&instance.credential_key, instance.instance());
        let ca = ca_file_for_key(&instance.credential_key);
        if std::path::Path::new(&ca).is_file() {
            config.ca_file = Some(ca);
        }
        out.push(config);
    }
    out
}

/// 采一轮（查询通道可注入）。
pub(super) async fn collect_with(
    transport: &mut dyn SqlTransport,
    config: &DorisProbeConfig,
) -> ProbeResult {
    let mut warnings = Vec::new();
    let rows = match transport.query(SHOW_BACKENDS_SQL).await {
        Ok(rows) => rows,
        Err(err) => {
            return ProbeResult {
                targets: Vec::new(),
                attempted: 1,
                failed: 1,
                last_error: Some(format!("{SHOW_BACKENDS_SQL} 失败：{err}")),
                warnings,
            };
        }
    };
    if rows.is_empty() {
        return ProbeResult {
            targets: Vec::new(),
            attempted: 1,
            failed: 1,
            last_error: Some("SHOW BACKENDS 没有返回任何 BE（集群未就绪或账号无权限）".to_string()),
            warnings,
        };
    }

    let mut labeled: Vec<MetricsLabeledFact> = Vec::new();
    let mut alive = 0usize;
    for row in &rows {
        let Some(be) = be_label(row) else {
            warnings.push("SHOW BACKENDS 的行缺少 IP/HeartbeatPort".to_string());
            continue;
        };
        // 缺 `Alive` 不等于「掉线」：那只是这条行没读全，不能凭空发一个 0。
        let Some(alive_raw) = row.get("Alive") else {
            warnings.push(format!("BE {be} 的行缺少 Alive，本轮跳过"));
            continue;
        };
        let up = alive_raw.eq_ignore_ascii_case("true") || alive_raw.trim() == "1";
        if up {
            alive += 1;
        }
        push_labeled(&mut labeled, "doris.be.up", if up { "1" } else { "0" }, &be);
        // 掉线的 BE 只报 up=0，不报容量（那会拿到上一轮/0，等于伪造）。
        if !up {
            continue;
        }
        for (column, fact_key) in [
            ("TotalCapacity", "doris.be.capacity_bytes"),
            ("AvailCapacity", "doris.be.available_bytes"),
        ] {
            match row.get(column).and_then(|raw| parse_size(raw)) {
                Some(bytes) => push_labeled(&mut labeled, fact_key, &bytes.to_string(), &be),
                None => warnings.push(format!(
                    "BE {be} 的 {column} 读不出字节数：{:?}",
                    row.get(column)
                )),
            }
        }
        match row
            .get("TabletNum")
            .and_then(|raw| raw.trim().parse::<i64>().ok())
        {
            Some(count) => push_labeled(&mut labeled, "doris.be.tablets", &count.to_string(), &be),
            None => warnings.push(format!("BE {be} 的 TabletNum 不是整数")),
        }
    }

    if alive < rows.len() {
        warnings.push(format!(
            "{} / {} 台 BE 未存活",
            rows.len() - alive,
            rows.len()
        ));
    }

    ProbeResult {
        targets: vec![sample(config, labeled)],
        attempted: 1,
        failed: 0,
        last_error: None,
        warnings,
    }
}

fn be_label(row: &Row) -> Option<String> {
    // 列名在 Doris 版本间不一致：2.x 是 `IP`，**4.x 起改成 `Host`**（4.1 实测）。
    // 只认一个会让**每一行**都被跳过 —— 现象是 probe 报 success 但 `facts` 为 0，
    // 只附一条「行缺少 IP/HeartbeatPort」的 warning，很容易被当成集群问题。
    let host = row.get("Host").or_else(|| row.get("IP"))?.trim();
    if host.is_empty() {
        return None;
    }
    match row.get("HeartbeatPort").map(|port| port.trim()) {
        Some(port) if !port.is_empty() => Some(format!("{host}:{port}")),
        _ => Some(host.to_string()),
    }
}

fn push_labeled(out: &mut Vec<MetricsLabeledFact>, key: &str, value: &str, be: &str) {
    out.push(MetricsLabeledFact {
        key: key.to_string(),
        value: value.to_string(),
        labels: vec![StringKeyValue::new("be", be.to_string())],
    });
}

/// `SHOW BACKENDS` 的容量列是**带单位的人类可读串**（`1.000 TB` / `512.000 GB`）。
///
/// 解析失败就丢这条（记 warning），不猜。
fn parse_size(raw: &str) -> Option<i64> {
    let raw = raw.trim();
    if raw.is_empty() {
        return None;
    }
    if let Ok(bytes) = raw.parse::<i64>() {
        return Some(bytes);
    }
    let (number, unit) = raw.split_once(char::is_whitespace)?;
    let value: f64 = number.trim().parse().ok()?;
    let factor = match unit.trim().to_ascii_uppercase().as_str() {
        "B" => 1.0,
        "KB" => 1024.0,
        "MB" => 1024.0 * 1024.0,
        "GB" => 1024.0 * 1024.0 * 1024.0,
        "TB" => 1024.0 * 1024.0 * 1024.0 * 1024.0,
        "PB" => 1024.0 * 1024.0 * 1024.0 * 1024.0 * 1024.0,
        _ => return None,
    };
    Some((value * factor) as i64)
}

fn sample(
    config: &DorisProbeConfig,
    labeled: Vec<MetricsLabeledFact>,
) -> MetricsCollectionTargetSample {
    let instance = config.instance();
    MetricsCollectionTargetSample {
        candidate_id: instance.clone(),
        target_ref: instance.clone(),
        status: "succeeded".to_string(),
        last_error: None,
        resource_ref: instance,
        execution_hints: Vec::new(),
        // Doris 的读数全部按 BE 打 label，没有「整条实例一个值」的事实。
        runtime_facts: Vec::new(),
        labeled_facts: labeled,
    }
}

// ---------------------------------------------------------------------------
// 真传输：sqlx（MySQL 协议）
// ---------------------------------------------------------------------------

use sqlx::Connection as _;

pub(super) async fn probe_once(config: &DorisProbeConfig) -> ProbeResult {
    let password = match tokio::fs::read_to_string(&config.password_file).await {
        Ok(text) => text.trim().to_string(),
        Err(err) => {
            return failed(format!(
                "读不到密码文件 {}：{err}（该 FE 未投放凭据）",
                config.password_file
            ));
        }
    };

    let mut options = sqlx::mysql::MySqlConnectOptions::new()
        .host(&config.host)
        .port(config.port)
        .username(DORIS_PROBE_USERNAME)
        .password(&password)
        .statement_cache_capacity(0);
    if let Some(ca) = config.ca_file.as_deref() {
        options = options
            .ssl_mode(sqlx::mysql::MySqlSslMode::VerifyCa)
            .ssl_ca(std::path::Path::new(ca));
    } else {
        options = options.ssl_mode(sqlx::mysql::MySqlSslMode::Preferred);
    }

    let connect = sqlx::MySqlConnection::connect_with(&options);
    let conn = match tokio::time::timeout(config.timeout, connect).await {
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

    let mut transport = DorisTransport { conn };
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

struct DorisTransport {
    conn: sqlx::MySqlConnection,
}

impl SqlTransport for DorisTransport {
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
    let mut out = BTreeMap::new();
    for (index, column) in row.columns().iter().enumerate() {
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

    struct Fake {
        rows: std::sync::Mutex<Result<Vec<Row>, String>>,
    }

    impl Fake {
        fn with(rows: Vec<Row>) -> Self {
            Self {
                rows: std::sync::Mutex::new(Ok(rows)),
            }
        }
        fn failing(err: &str) -> Self {
            Self {
                rows: std::sync::Mutex::new(Err(err.to_string())),
            }
        }
    }

    impl SqlTransport for Fake {
        fn query(&mut self, _sql: &'static str) -> BoxFuture<'_, Result<Vec<Row>, String>> {
            Box::pin(async move { self.rows.lock().unwrap().clone() })
        }
    }

    fn row(pairs: &[(&str, &str)]) -> Row {
        pairs
            .iter()
            .map(|(key, value)| (key.to_string(), value.to_string()))
            .collect()
    }

    fn config() -> DorisProbeConfig {
        DorisProbeConfig::new("127.0.0.1", 9030, 1_000, 30_000)
    }

    fn labeled<'a>(result: &'a ProbeResult, key: &str, be: &str) -> Option<&'a str> {
        result.targets[0]
            .labeled_facts
            .iter()
            .find(|fact| fact.key == key && fact.labels.iter().any(|label| label.value == be))
            .map(|fact| fact.value.as_str())
    }

    fn two_backends() -> Vec<Row> {
        vec![
            row(&[
                ("IP", "10.0.0.1"),
                ("HeartbeatPort", "9050"),
                ("Alive", "true"),
                ("TotalCapacity", "1.000 TB"),
                ("AvailCapacity", "512.000 GB"),
                ("TabletNum", "120"),
            ]),
            row(&[
                ("IP", "10.0.0.2"),
                ("HeartbeatPort", "9050"),
                ("Alive", "false"),
                ("TotalCapacity", "1.000 TB"),
                ("AvailCapacity", "900.000 GB"),
                ("TabletNum", "3"),
            ]),
        ]
    }

    /// Doris 4.x 把 `IP` 列改叫 `Host`（4.1 实测）。只认旧名会**一行都读不出来**：
    /// probe 仍是 `success`、`facts=0`，只附一条 warning —— 现场很容易误判成「集群没就绪」。
    #[tokio::test]
    async fn host_column_from_doris_4_is_accepted() {
        let mut transport = Fake::with(vec![row(&[
            ("Host", "10.0.0.9"),
            ("HeartbeatPort", "9050"),
            ("Alive", "true"),
            ("TotalCapacity", "1.000 TB"),
            ("AvailCapacity", "512.000 GB"),
            ("TabletNum", "42"),
        ])]);

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 0);
        assert_eq!(labeled(&result, "doris.be.up", "10.0.0.9:9050"), Some("1"));
        assert_eq!(
            labeled(&result, "doris.be.tablets", "10.0.0.9:9050"),
            Some("42")
        );
        assert!(
            result.warnings.is_empty(),
            "新列名不该再报「缺少 IP/HeartbeatPort」：{:?}",
            result.warnings
        );
    }

    /// 两列同时存在（某些代理/改造版会两列都给）：以 `Host` 为准，不重复出两条。
    #[tokio::test]
    async fn host_wins_when_both_columns_exist() {
        let mut transport = Fake::with(vec![row(&[
            ("Host", "10.0.0.9"),
            ("IP", "10.9.9.9"),
            ("HeartbeatPort", "9050"),
            ("Alive", "true"),
            ("TotalCapacity", "1.000 TB"),
            ("AvailCapacity", "512.000 GB"),
            ("TabletNum", "7"),
        ])]);

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(labeled(&result, "doris.be.up", "10.0.0.9:9050"), Some("1"));
        assert_eq!(labeled(&result, "doris.be.up", "10.9.9.9:9050"), None);
    }

    #[tokio::test]
    async fn backends_are_reported_per_be() {
        let mut transport = Fake::with(two_backends());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 0);
        assert_eq!(result.targets[0].resource_ref, "doris:127.0.0.1:9030");
        assert_eq!(labeled(&result, "doris.be.up", "10.0.0.1:9050"), Some("1"));
        assert_eq!(labeled(&result, "doris.be.up", "10.0.0.2:9050"), Some("0"));
        assert_eq!(
            labeled(&result, "doris.be.capacity_bytes", "10.0.0.1:9050"),
            Some("1099511627776"),
            "1 TB = 1024^4"
        );
        assert_eq!(
            labeled(&result, "doris.be.available_bytes", "10.0.0.1:9050"),
            Some("549755813888")
        );
        assert_eq!(
            labeled(&result, "doris.be.tablets", "10.0.0.1:9050"),
            Some("120")
        );
        assert!(
            result.warnings.iter().any(|w| w.contains("1 / 2")),
            "掉线要留痕：{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn a_missing_alive_column_is_skipped_instead_of_zeroed() {
        let mut transport = Fake::with(vec![row(&[
            ("IP", "10.0.0.3"),
            ("HeartbeatPort", "9050"),
            ("TotalCapacity", "1.000 TB"),
        ])]);

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 0);
        assert_eq!(
            labeled(&result, "doris.be.up", "10.0.0.3:9050"),
            None,
            "缺 Alive 不能当成掉线（那就是伪造 0）"
        );
        assert!(
            result.warnings.iter().any(|w| w.contains("缺少 Alive")),
            "{:?}",
            result.warnings
        );
    }

    #[tokio::test]
    async fn alive_accepts_the_forms_doris_uses() {
        for alive in ["true", "TRUE", "1"] {
            let mut transport = Fake::with(vec![row(&[
                ("IP", "10.0.0.4"),
                ("HeartbeatPort", "9050"),
                ("Alive", alive),
                ("TotalCapacity", "1.000 TB"),
                ("AvailCapacity", "1.000 TB"),
                ("TabletNum", "1"),
            ])]);
            let result = collect_with(&mut transport, &config()).await;
            assert_eq!(
                labeled(&result, "doris.be.up", "10.0.0.4:9050"),
                Some("1"),
                "Alive={alive} 应当算存活"
            );
        }
    }

    #[tokio::test]
    async fn every_labeled_fact_has_a_metric_spec_and_matching_labels() {
        let mut transport = Fake::with(two_backends());

        let result = collect_with(&mut transport, &config()).await;

        assert!(
            !result.targets[0].labeled_facts.is_empty(),
            "场景没产出事实"
        );
        for fact in &result.targets[0].labeled_facts {
            let spec = wist_metrics::spec::find_metric_spec(COLLECTION_KIND, &fact.key)
                .unwrap_or_else(|| panic!("fact `{}` 没有指标声明", fact.key));
            assert!(
                spec.name.starts_with("doris_"),
                "`{}` 必须落在 doris 命名空间",
                spec.name
            );
            // label 与声明必须一一对应：多一个上游丢弃维度，少一个所有 BE 会叠成一条线。
            let mut declared: Vec<&str> = spec.dynamic_labels.to_vec();
            let mut produced: Vec<&str> =
                fact.labels.iter().map(|label| label.key.as_str()).collect();
            declared.sort_unstable();
            produced.sort_unstable();
            assert_eq!(produced, declared, "`{}` 的 label 与声明不一致", spec.name);
        }
    }

    #[tokio::test]
    async fn a_dead_backend_reports_only_up_zero() {
        let mut transport = Fake::with(two_backends());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(
            labeled(&result, "doris.be.capacity_bytes", "10.0.0.2:9050"),
            None,
            "掉线的 BE 不报容量（不伪造）"
        );
        assert_eq!(labeled(&result, "doris.be.tablets", "10.0.0.2:9050"), None);
    }

    #[tokio::test]
    async fn an_empty_backend_list_is_a_failed_round() {
        let mut transport = Fake::with(Vec::new());

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 1);
        assert!(result.targets.is_empty());
    }

    #[tokio::test]
    async fn a_failed_query_fails_the_round() {
        let mut transport = Fake::failing("denied");

        let result = collect_with(&mut transport, &config()).await;

        assert_eq!(result.failed, 1);
        assert!(result.last_error.unwrap().contains("denied"));
    }

    #[test]
    fn sizes_are_parsed_with_units() {
        assert_eq!(parse_size("1024"), Some(1024));
        assert_eq!(parse_size("1.000 TB"), Some(1099511627776));
        assert_eq!(parse_size("512.000 GB"), Some(549755813888));
        assert_eq!(parse_size("2 KB"), Some(2048));
        assert_eq!(parse_size("garbage"), None);
        assert_eq!(parse_size(""), None);
    }
}
