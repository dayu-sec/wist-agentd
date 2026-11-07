//! 真 PostgreSQL 验收：指向**任意一台** PG，默认不跑。
//!
//! 单测只证明「SQL 结果长这样时映射对不对」，证明不了「真驱动 + 真服务端能不能连上、
//! 返回的列名与类型是不是我们以为的那些」（`deadlocks` 在低版本叫 `deadlocks`、
//! `blks_read` 的类型、`pg_is_in_recovery()` 的文本形态都算）。
//!
//! ```text
//! WIST_PG_LIVE=1
//! WIST_PG_LIVE_ADDR=127.0.0.1:55439                    # host:port
//! WIST_PG_LIVE_PASSWORD_FILE=/tmp/wist-pg-live/password # 内容就是 wist-probe 的密码，0600
//! ```
//!
//! ```bash
//! cargo test --lib telemetry::metrics::postgres_live -- --ignored --test-threads=1 --nocapture
//! ```
//!
//! 现场准备（只读账号，与 `docs/design/pg-metrics.md` §3 一致）：
//!
//! ```sql
//! CREATE ROLE "wist-probe" LOGIN PASSWORD '<随机密码>';
//! GRANT pg_monitor TO "wist-probe";
//! ```
//!
//! 为什么放在 lib 里而不是 `tests/`：`telemetry` 是 `pub(crate)`，集成测试拿不到
//! `probe_once` 与真实的 `sqlx` 传输层。

use super::collection::ProbeResult;
use super::postgres::{PgProbeConfig, TlsMode, probe_once};
use crate::discovery::pg_source::{Handshake, TcpHandshake};

const TIMEOUT_MS: u64 = 10_000;

struct LiveEnv {
    config: PgProbeConfig,
    addr: String,
}

/// 环境变量没给全就返回 `None`：这些用例在普通 `cargo test` 里必须静默跳过。
fn live_env() -> Option<LiveEnv> {
    if std::env::var("WIST_PG_LIVE").ok().as_deref() != Some("1") {
        return None;
    }
    let addr = std::env::var("WIST_PG_LIVE_ADDR").ok()?;
    let password_file = std::env::var("WIST_PG_LIVE_PASSWORD_FILE").ok()?;
    let (host, port) = addr.rsplit_once(':')?;
    let port: u16 = port.parse().ok()?;

    let mut config = PgProbeConfig::new(host, port, TIMEOUT_MS, 30_000);
    config.password_file = password_file;
    config.tls = TlsMode::Prefer;
    Some(LiveEnv { config, addr })
}

fn fact_value<'a>(result: &'a ProbeResult, key: &str) -> Option<&'a str> {
    result
        .targets
        .first()?
        .runtime_facts
        .iter()
        .find(|fact| fact.key == key)
        .map(|fact| fact.value.as_str())
}

fn int_fact(result: &ProbeResult, key: &str) -> i64 {
    let raw = fact_value(result, key).unwrap_or_else(|| panic!("缺少 fact `{key}`"));
    raw.trim()
        .parse()
        .unwrap_or_else(|_| panic!("fact `{key}` 不是整数：{raw}"))
}

#[tokio::test]
#[ignore = "需要真 PostgreSQL：WIST_PG_LIVE=1 + ADDR + PASSWORD_FILE"]
async fn a_real_primary_reports_the_documented_facts() {
    let Some(live) = live_env() else {
        eprintln!("skip: WIST_PG_LIVE / WIST_PG_LIVE_ADDR / WIST_PG_LIVE_PASSWORD_FILE 未设置");
        return;
    };

    let result = probe_once(&live.config).await;

    assert_eq!(
        (result.attempted, result.failed),
        (1, 0),
        "真库采集失败：{:?} / warnings={:?}",
        result.last_error,
        result.warnings
    );
    let sample = result
        .targets
        .first()
        .unwrap_or_else(|| panic!("成功但没有任何样本：{:?}", result.warnings));
    assert_eq!(sample.status, "succeeded");
    assert_eq!(sample.resource_ref, live.config.instance());

    // 把真库采到的指标原样打出来：这是「本地能不能采 PG」最直接的证据。
    eprintln!("--- {} 实采指标 ---", live.config.instance());
    for fact in &sample.runtime_facts {
        eprintln!("    {:<32} {}", fact.key, fact.value);
    }
    if !result.warnings.is_empty() {
        eprintln!("    warnings: {:?}", result.warnings);
    }

    // 每条序列都得有真值，不能是「字段在、值是空」。
    assert_eq!(fact_value(&result, "pg.up"), Some("1"));
    assert!(int_fact(&result, "pg.uptime.seconds") >= 0);
    assert!(int_fact(&result, "pg.connections.max") > 0);
    assert!(int_fact(&result, "pg.connections.current") >= 1);
    assert!(int_fact(&result, "pg.database.size_bytes") > 0);
    assert!(int_fact(&result, "pg.xact.commit.total") > 0);
    for counter in [
        "pg.xact.rollback.total",
        "pg.deadlocks.total",
        "pg.temp.bytes.total",
        "pg.disk.read_bytes.total",
        "pg.cache.hit_bytes.total",
    ] {
        assert!(
            int_fact(&result, counter) >= 0,
            "counter `{counter}` 不该是负数"
        );
    }

    // 主库不出复制序列（不补 0）：这是 pg-metrics.md §5 的硬要求。
    assert_eq!(
        fact_value(&result, "pg.replication.running"),
        None,
        "主库不该出 pg.replication.*；warnings={:?}",
        result.warnings
    );
    assert_eq!(fact_value(&result, "pg.replication.lag_seconds"), None);
}

#[tokio::test]
#[ignore = "需要真 PostgreSQL：WIST_PG_LIVE=1 + ADDR + PASSWORD_FILE"]
async fn a_wrong_password_fails_the_round_without_faking_zeroes() {
    let Some(mut live) = live_env() else {
        eprintln!("skip: 环境变量未设置");
        return;
    };
    live.config.password_file = "/nonexistent/wist-agentd/secret".to_string();

    let result = probe_once(&live.config).await;

    assert_eq!((result.attempted, result.failed), (1, 1));
    assert!(
        result.targets.is_empty(),
        "失败时必须没有样本（补 0 会被读成「库很空」）"
    );
    let error = result.last_error.unwrap_or_default();
    assert!(
        error.contains("密码文件"),
        "错误应该点名凭据缺失，实际是：{error}"
    );
}

#[tokio::test]
#[ignore = "需要真 PostgreSQL：WIST_PG_LIVE=1 + ADDR + PASSWORD_FILE"]
async fn the_ssl_request_fingerprint_recognizes_a_real_server() {
    let Some(live) = live_env() else {
        eprintln!("skip: 环境变量未设置");
        return;
    };

    // 自探判据：SSLRequest 收到 'S' / 'N' 才算 PG。这条与采集是两条独立链路。
    assert!(
        TcpHandshake.postgres_greeting(&live.addr),
        "{} 不是 PG 指纹（SSLRequest 没有回 S/N）",
        live.addr
    );

    // 反证：往一个没人监听的端口上打，必须是「不是 PG」而不是 panic。
    let closed = {
        let mut parts = live.addr.rsplit(':');
        let port: u16 = parts.next().and_then(|p| p.parse().ok()).unwrap_or(1);
        format!("127.0.0.1:{}", port.saturating_add(1))
    };
    assert!(!TcpHandshake.postgres_greeting(&closed));
}
