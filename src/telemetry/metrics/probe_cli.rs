//! `wist-agentd probe`：对**一个地址或本机自探结果**跑一轮采集，并把结果写成诊断文件。
//!
//! 与守护进程的关系：这条命令**不启服务、不进授权链路、不读 `state/work.json`**，
//! 是给「装服务之前先看看能不能采到」用的。所以它允许显式 `--addr` ——
//! 那条「端点只来自自探」的硬约束管的是**工作单元**（网关下发的授权），
//! 不是本机运维手工跑的一次性探针。
//!
//! 输出分两路：
//!
//! - stdout：人读摘要（每个目标的成败、耗时、逐条 fact，以及它对应的指标名）；
//! - 文件：一份 JSON（`--out` 指定，默认当前目录 `probe-<域>-<UTC>.json`），
//!   出问题可以直接把它发出来诊断。**密码从不读进内存，也不进报告**。
//!
//! 与 `diagnose` 的分工：`diagnose` 看「这台机器作为 agent 的状态」（身份 / 服务 / 上送）；
//! `probe` 只看「这个采集域还能不能出数」。所以 `probe` 不需要注册、不需要配置目录。

use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use orion_error::conversion::ToStructError;
use serde::Serialize;
use time::OffsetDateTime;
use time::format_description::well_known::Rfc3339;

use super::collection::ProbeResult;
use super::{doris, kafka, mysql, postgres};
use crate::error::{AgentdReason, AgentdResult};

/// 单次请求的默认超时（与各域默认值一致）。
const DEFAULT_TIMEOUT_MS: u64 = 5_000;

/// `probe` 支持的采集域。
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum ProbeDomain {
    Postgres,
    Mysql,
    Doris,
    Kafka,
}

impl ProbeDomain {
    /// 别名按运维口语收：`pg` / `postgres` / `postgresql` 都是同一个域。
    pub(crate) fn parse(text: &str) -> Option<Self> {
        match text.trim().to_ascii_lowercase().as_str() {
            "pg" | "postgres" | "postgresql" => Some(Self::Postgres),
            "mysql" | "tidb" => Some(Self::Mysql),
            "doris" => Some(Self::Doris),
            "kafka" => Some(Self::Kafka),
            _ => None,
        }
    }

    pub(crate) fn supported() -> &'static str {
        "pg | mysql | doris | kafka"
    }

    /// 文件名里用的短名（也用于 stderr/stdout 提示）。
    fn label(self) -> &'static str {
        match self {
            Self::Postgres => "pg",
            Self::Mysql => "mysql",
            Self::Doris => "doris",
            Self::Kafka => "kafka",
        }
    }

    /// 与 `wist-metrics` 注册表里的采集域同名。
    fn collection_kind(self) -> &'static str {
        match self {
            Self::Postgres => postgres::COLLECTION_KIND,
            Self::Mysql => mysql::COLLECTION_KIND,
            Self::Doris => doris::COLLECTION_KIND,
            Self::Kafka => kafka::COLLECTION_KIND,
        }
    }

    fn default_port(self) -> u16 {
        match self {
            Self::Postgres => 5432,
            Self::Mysql => 3306,
            Self::Doris => 9030,
            Self::Kafka => 9092,
        }
    }

    /// 凭据根目录（与守护进程约定同一套，见各域设计文档 §3）。
    pub(crate) fn secrets_root(self) -> &'static str {
        match self {
            Self::Postgres => postgres::PG_SECRET_ROOT,
            Self::Mysql => mysql::MYSQL_SECRET_ROOT,
            Self::Doris => doris::DORIS_SECRET_ROOT,
            // Kafka 是单实例域：密码文件是 `secrets/kafka/probe`，没有 `<key>` 这一层。
            Self::Kafka => kafka::KAFKA_SECRET_DIR,
        }
    }

    fn ca_path(self, key: &str) -> String {
        if self == Self::Kafka {
            return format!("{}/ca.pem", self.secrets_root());
        }
        format!("{}/{key}/ca.pem", self.secrets_root())
    }
}

/// 一次 `probe` 的请求。
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct ProbeRequest {
    pub domain: ProbeDomain,
    /// `None` = 走本机自探（Linux 专有）。
    pub addr: Option<String>,
    /// `None` = 用约定路径 `<secrets>/<key>/password`。
    pub password_file: Option<PathBuf>,
    /// `None` = 当前目录 `probe-<域>-<UTC>.json`。
    pub out: Option<PathBuf>,
    pub timeout_ms: u64,
    pub json: bool,
    /// 只看自探候选，不采集（不需要凭据）。
    pub list: bool,
    /// 四个域一起跑（自探或列候选）；不能与 `--addr` 同用。
    pub all: bool,
    /// Kafka：`PLAINTEXT` / `SSL` / `SASL_PLAINTEXT` / `SASL_SSL`。
    pub security_protocol: Option<String>,
    /// Kafka：SASL 用户名（密码仍走文件）。
    pub username: Option<String>,
    /// Kafka：私有 CA（不给则用系统根）。
    pub ca_file: Option<PathBuf>,
    /// Kafka：只发这些消费组（逗号分隔），空 = 按阈值过滤。
    pub group_allowlist: Vec<String>,
    /// Kafka：单轮最多查多少个组。
    pub max_groups: Option<usize>,
    /// Kafka：白名单为空时只发总 lag 超过该值的组。
    pub lag_threshold: Option<i64>,
}

impl ProbeRequest {
    pub(crate) fn new(domain: ProbeDomain) -> Self {
        Self {
            domain,
            addr: None,
            password_file: None,
            out: None,
            timeout_ms: DEFAULT_TIMEOUT_MS,
            json: false,
            list: false,
            all: false,
            security_protocol: None,
            username: None,
            ca_file: None,
            group_allowlist: Vec::new(),
            max_groups: None,
            lag_threshold: None,
        }
    }
}

// ---------------------------------------------------------------------------
// 目标
// ---------------------------------------------------------------------------

enum TargetConfig {
    Pg(postgres::PgProbeConfig),
    Mysql(mysql::MysqlProbeConfig),
    Doris(doris::DorisProbeConfig),
    Kafka(kafka::KafkaProbeConfig),
}

impl TargetConfig {
    fn domain(&self) -> ProbeDomain {
        match self {
            Self::Pg(_) => ProbeDomain::Postgres,
            Self::Mysql(_) => ProbeDomain::Mysql,
            Self::Doris(_) => ProbeDomain::Doris,
            Self::Kafka(_) => ProbeDomain::Kafka,
        }
    }

    fn instance(&self) -> String {
        match self {
            Self::Pg(config) => config.instance(),
            Self::Mysql(config) => config.instance(),
            Self::Doris(config) => config.instance(),
            Self::Kafka(config) => format!(
                "kafka:{}",
                config
                    .bootstrap_servers
                    .first()
                    .cloned()
                    .unwrap_or_else(|| "unknown".to_string())
            ),
        }
    }

    fn addr(&self) -> String {
        match self {
            Self::Pg(config) => format!("{}:{}", config.host, config.port),
            Self::Mysql(config) => format!("{}:{}", config.host, config.port),
            Self::Doris(config) => format!("{}:{}", config.host, config.port),
            Self::Kafka(config) => config.bootstrap_servers.join(","),
        }
    }

    fn credential_key(&self) -> &str {
        match self {
            Self::Pg(config) => &config.credential_key,
            Self::Mysql(config) => &config.credential_key,
            Self::Doris(config) => &config.credential_key,
            // Kafka 是单实例域，密码固定 `secrets/kafka/probe`，没有 key 这一层。
            Self::Kafka(_) => "probe",
        }
    }

    fn password_file(&self) -> &str {
        match self {
            Self::Pg(config) => &config.password_file,
            Self::Mysql(config) => &config.password_file,
            Self::Doris(config) => &config.password_file,
            Self::Kafka(config) => config.security.password_file.as_deref().unwrap_or(""),
        }
    }

    async fn probe(&self) -> ProbeResult {
        match self {
            Self::Pg(config) => postgres::probe_once(config).await,
            Self::Mysql(config) => mysql::probe_once(config).await,
            Self::Doris(config) => doris::probe_once(config).await,
            // Kafka 采集器是**阻塞**的（手写协议 + 同步 TLS），且需要一份组缓存：
            // 放进 blocking 池里跑，不要堵在异步执行器上。
            Self::Kafka(config) => {
                let config = config.clone();
                match tokio::task::spawn_blocking(move || {
                    let mut groups = kafka::GroupCache::default();
                    kafka::probe_once(&config, &mut groups)
                })
                .await
                {
                    Ok(result) => result,
                    Err(err) => ProbeResult {
                        targets: Vec::new(),
                        attempted: 1,
                        failed: 1,
                        last_error: Some(format!("Kafka 采集任务失败：{err}")),
                        warnings: Vec::new(),
                    },
                }
            }
        }
    }
}

/// 解析 `host:port`；省略端口时用该域的默认端口。IPv6 用方括号形式（`[::1]:5432`）。
pub(crate) fn parse_addr(text: &str, default_port: u16) -> Result<(String, u16), String> {
    let text = text.trim();
    if text.is_empty() {
        return Err("地址是空的".to_string());
    }
    let (host, port) = if let Some(rest) = text.strip_prefix('[') {
        let Some((host, tail)) = rest.split_once(']') else {
            return Err(format!("IPv6 地址缺少 `]`：{text}"));
        };
        match tail.strip_prefix(':') {
            Some(port) => (host.to_string(), Some(port)),
            None if tail.is_empty() => (host.to_string(), None),
            None => return Err(format!("地址端口格式不对：{text}")),
        }
    } else {
        // 裸 IPv6（多个冒号）不猜：`::1:5432` 分不清哪一段是端口。
        if text.matches(':').count() > 1 {
            return Err(format!(
                "IPv6 地址请用方括号写成 [addr]:port（现在：{text}）"
            ));
        }
        match text.split_once(':') {
            Some((host, port)) => (host.to_string(), Some(port)),
            None => (text.to_string(), None),
        }
    };
    if host.is_empty() {
        return Err(format!("地址缺少主机部分：{text}"));
    }
    let port = match port {
        Some(raw) => raw
            .parse::<u16>()
            .map_err(|_| format!("端口不是 0-65535 的整数：{raw}"))?,
        None => default_port,
    };
    Ok((host, port))
}

fn explicit_target(
    domain: ProbeDomain,
    host: &str,
    port: u16,
    request: &ProbeRequest,
) -> TargetConfig {
    let timeout = request.timeout_ms;
    let interval = 30_000;
    match domain {
        ProbeDomain::Postgres => {
            let mut config = postgres::PgProbeConfig::new(host, port, timeout, interval);
            if let Some(path) = &request.password_file {
                config.password_file = path.display().to_string();
            }
            let ca = domain.ca_path(&config.credential_key);
            if Path::new(&ca).is_file() {
                config.tls = postgres::TlsMode::VerifyCa;
                config.ca_file = Some(ca);
            }
            TargetConfig::Pg(config)
        }
        ProbeDomain::Mysql => {
            let mut config = mysql::MysqlProbeConfig::new(host, port, timeout, interval);
            if let Some(path) = &request.password_file {
                config.password_file = path.display().to_string();
            }
            let ca = domain.ca_path(&config.credential_key);
            if Path::new(&ca).is_file() {
                config.tls = mysql::TlsMode::VerifyCa;
                config.ca_file = Some(ca);
            }
            TargetConfig::Mysql(config)
        }
        ProbeDomain::Doris => {
            let mut config = doris::DorisProbeConfig::new(host, port, timeout, interval);
            if let Some(path) = &request.password_file {
                config.password_file = path.display().to_string();
            }
            let ca = domain.ca_path(&config.credential_key);
            if Path::new(&ca).is_file() {
                config.ca_file = Some(ca);
            }
            TargetConfig::Doris(config)
        }
        ProbeDomain::Kafka => {
            let mut config = kafka::KafkaProbeConfig::new(
                vec![format!("{host}:{port}")],
                "wist-agentd-probe".to_string(),
                timeout,
                interval,
            );
            config.security.protocol = request
                .security_protocol
                .clone()
                .unwrap_or_else(|| "PLAINTEXT".to_string());
            config.security.username = request.username.clone();
            config.security.password_file = Some(
                request
                    .password_file
                    .as_ref()
                    .map(|path| path.display().to_string())
                    .unwrap_or_else(|| format!("{}/probe", kafka::KAFKA_SECRET_DIR)),
            );
            if let Some(ca) = &request.ca_file {
                config.security.tls_ca_file = Some(ca.display().to_string());
            }
            apply_group_policy(&mut config, request);
            TargetConfig::Kafka(config)
        }
    }
}

fn apply_group_policy(config: &mut kafka::KafkaProbeConfig, request: &ProbeRequest) {
    if !request.group_allowlist.is_empty() {
        config.groups.allowlist = request.group_allowlist.clone();
    }
    if let Some(max_groups) = request.max_groups {
        config.groups.max_groups = max_groups;
    }
    if let Some(lag_threshold) = request.lag_threshold {
        config.groups.lag_threshold = lag_threshold;
    }
}

/// 本机自探 → 采集目标。自探读 `/proc`，在非 Linux 上永远是空列表（报告里会说明）。
fn discovered_targets(domain: ProbeDomain, request: &ProbeRequest) -> Vec<TargetConfig> {
    let timeout_ms = request.timeout_ms;
    let timeout = Duration::from_millis(timeout_ms.max(1));
    let interval = Duration::from_secs(30);
    match domain {
        ProbeDomain::Postgres => postgres::targets_from_instances(
            crate::discovery::pg_source::resolve_live(),
            &postgres::PgTargetSettings { timeout, interval },
        )
        .into_iter()
        .map(TargetConfig::Pg)
        .collect(),
        ProbeDomain::Mysql => mysql::targets_from_instances(
            crate::discovery::mysql_source::resolve_live(),
            &mysql::MysqlTargetSettings { timeout, interval },
        )
        .into_iter()
        .map(TargetConfig::Mysql)
        .collect(),
        ProbeDomain::Doris => doris::targets_from_instances(
            crate::discovery::doris_source::resolve_live(),
            &doris::DorisTargetSettings { timeout, interval },
        )
        .into_iter()
        .map(TargetConfig::Doris)
        .collect(),
        ProbeDomain::Kafka => crate::discovery::kafka_source::resolve_live()
            .into_iter()
            .filter_map(|cluster| {
                // 优先用实测可达的端点；一条都不通时也保留（错误会如实报）。
                let mut addrs: Vec<String> = cluster
                    .endpoints
                    .iter()
                    .filter(|endpoint| endpoint.reachable)
                    .map(|endpoint| endpoint.addr.clone())
                    .collect();
                if addrs.is_empty() {
                    addrs = cluster
                        .endpoints
                        .iter()
                        .map(|endpoint| endpoint.addr.clone())
                        .collect();
                }
                if addrs.is_empty() {
                    return None;
                }
                let protocol = cluster
                    .endpoints
                    .iter()
                    .find(|endpoint| endpoint.kafka_api)
                    .or_else(|| cluster.endpoints.first())
                    .map(|endpoint| endpoint.protocol.clone())
                    .filter(|protocol| protocol != "unknown")
                    .unwrap_or_else(|| "PLAINTEXT".to_string());
                let mut config = kafka::KafkaProbeConfig::new(
                    addrs,
                    "wist-agentd-probe".to_string(),
                    timeout_ms,
                    30_000,
                );
                config.security.protocol = protocol;
                config.security.password_file = Some(format!("{}/probe", kafka::KAFKA_SECRET_DIR));
                apply_group_policy(&mut config, request);
                Some(TargetConfig::Kafka(config))
            })
            .collect(),
    }
}

fn resolve_targets(domain: ProbeDomain, request: &ProbeRequest) -> AgentdResult<Vec<TargetConfig>> {
    match &request.addr {
        Some(addr) => {
            let (host, port) = parse_addr(addr, domain.default_port())
                .map_err(|detail| AgentdReason::InvalidArgs.to_err().with_detail(detail))?;
            Ok(vec![explicit_target(domain, &host, port, request)])
        }
        None => Ok(discovered_targets(domain, request)),
    }
}

/// `--all` 时的域顺序：先本机库，再 broker（Kafka 最贵）。
const ALL_DOMAINS: [ProbeDomain; 4] = [
    ProbeDomain::Postgres,
    ProbeDomain::Mysql,
    ProbeDomain::Doris,
    ProbeDomain::Kafka,
];

fn request_domains(request: &ProbeRequest) -> Vec<ProbeDomain> {
    if request.all {
        ALL_DOMAINS.to_vec()
    } else {
        vec![request.domain]
    }
}

// ---------------------------------------------------------------------------
// 报告
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct Report {
    tool: &'static str,
    version: &'static str,
    /// `--all` 时是 `all`，否则是对应的 `*_metrics`。
    domain: &'static str,
    mode: &'static str,
    generated_at: String,
    duration_ms: u64,
    /// 没有目标时的原因（自探为空 / 非 Linux），给人看的一句话。
    #[serde(skip_serializing_if = "Option::is_none")]
    note: Option<String>,
    summary: Summary,
    /// `--list` 模式下的自探候选（不采集）。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    candidates: Vec<CandidateReport>,
    targets: Vec<TargetReport>,
}

#[derive(Debug, Default, Serialize)]
struct Summary {
    targets: usize,
    /// `--list` 列出的自探候选数。
    candidates: usize,
    succeeded: usize,
    failed: usize,
    facts: usize,
    /// 能在 `wist-metrics` 注册表里查到的指标数。
    registered_facts: usize,
    /// 采到了但没声明（规范化层会丢弃）—— 非 0 就说明 agentd 与 wist-metrics 版本不匹配。
    unregistered_facts: usize,
}

#[derive(Debug, Serialize)]
struct CandidateReport {
    domain: &'static str,
    instance: String,
    addr: String,
    credential_key: String,
    evidence: String,
    confidence: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    detail: Option<String>,
}

#[derive(Debug, Serialize)]
struct TargetReport {
    domain: &'static str,
    instance: String,
    addr: String,
    source: &'static str,
    credential_key: String,
    password_file: String,
    /// 只报「文件在不在」，内容永不进报告。
    password_file_present: bool,
    status: &'static str,
    duration_ms: u64,
    attempted: usize,
    succeeded: usize,
    failed: usize,
    #[serde(skip_serializing_if = "Option::is_none")]
    last_error: Option<String>,
    warnings: Vec<String>,
    facts: Vec<FactReport>,
}

#[derive(Debug, Serialize)]
struct FactReport {
    fact: String,
    value: String,
    /// 在 `wist-metrics` 注册表里查到的指标名；`None` = 采到了但没声明（会被规范化层丢掉）。
    #[serde(skip_serializing_if = "Option::is_none")]
    metric: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    unit: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    value_type: Option<String>,
    /// `key=value` 形式的动态 label（Kafka 的 `group` / `topic` 等）。
    #[serde(skip_serializing_if = "Vec::is_empty")]
    labels: Vec<String>,
}

struct TargetRun<'a> {
    target: &'a TargetConfig,
    result: ProbeResult,
    elapsed: Duration,
    source: &'static str,
}

fn status_of(result: &ProbeResult, succeeded: usize) -> &'static str {
    if result.failed == 0 {
        "succeeded"
    } else if succeeded > 0 {
        "partial"
    } else {
        "failed"
    }
}

fn fact_reports(domain: ProbeDomain, result: &ProbeResult) -> Vec<FactReport> {
    let kind = domain.collection_kind();
    let push = |key: &str, value: &str, labels: Vec<String>| {
        let spec = wist_metrics::spec::find_metric_spec(kind, key);
        FactReport {
            fact: key.to_string(),
            value: value.to_string(),
            metric: spec.map(|spec| spec.name.to_string()),
            unit: spec.map(|spec| spec.unit.to_string()),
            value_type: spec.map(|spec| spec.value_type.to_string()),
            labels,
        }
    };

    let mut out = Vec::new();
    for sample in &result.targets {
        for fact in &sample.runtime_facts {
            out.push(push(&fact.key, &fact.value, Vec::new()));
        }
        // Kafka 的组读数（lag / state）挂在 `labeled_facts` 上，label 是组名与 topic：
        // 诊断时最需要的正是这两维，不能只看 runtime_facts。
        for fact in &sample.labeled_facts {
            let labels = fact
                .labels
                .iter()
                .map(|label| format!("{}={}", label.key, label.value))
                .collect();
            out.push(push(&fact.key, &fact.value, labels));
        }
    }
    out
}

fn mode_of(request: &ProbeRequest) -> &'static str {
    if request.list {
        "list"
    } else if request.addr.is_some() {
        "explicit"
    } else {
        "discovery"
    }
}

fn domain_label(request: &ProbeRequest) -> &'static str {
    if request.all {
        "all"
    } else {
        request.domain.collection_kind()
    }
}

fn build_report(
    request: &ProbeRequest,
    generated_at: OffsetDateTime,
    total: Duration,
    runs: &[TargetRun<'_>],
    candidates: Vec<CandidateReport>,
    note: Option<String>,
) -> Report {
    let targets: Vec<TargetReport> = runs
        .iter()
        .map(|run| {
            let succeeded = run.result.attempted.saturating_sub(run.result.failed);
            TargetReport {
                domain: run.target.domain().collection_kind(),
                instance: run.target.instance(),
                addr: run.target.addr(),
                source: run.source,
                credential_key: run.target.credential_key().to_string(),
                password_file: run.target.password_file().to_string(),
                password_file_present: !run.target.password_file().is_empty()
                    && Path::new(run.target.password_file()).is_file(),
                status: status_of(&run.result, succeeded),
                duration_ms: run.elapsed.as_millis() as u64,
                attempted: run.result.attempted,
                succeeded,
                failed: run.result.failed,
                last_error: run.result.last_error.clone(),
                warnings: run.result.warnings.clone(),
                facts: fact_reports(run.target.domain(), &run.result),
            }
        })
        .collect();

    let mut summary = Summary {
        targets: targets.len(),
        candidates: candidates.len(),
        ..Summary::default()
    };
    for target in &targets {
        summary.succeeded += target.succeeded;
        summary.failed += target.failed;
        summary.facts += target.facts.len();
        let registered = target
            .facts
            .iter()
            .filter(|fact| fact.metric.is_some())
            .count();
        summary.registered_facts += registered;
        summary.unregistered_facts += target.facts.len() - registered;
    }

    Report {
        tool: "wist-agentd",
        version: env!("CARGO_PKG_VERSION"),
        domain: domain_label(request),
        mode: mode_of(request),
        generated_at: generated_at
            .format(&Rfc3339)
            .unwrap_or_else(|_| "unknown".to_string()),
        duration_ms: total.as_millis() as u64,
        note,
        summary,
        candidates,
        targets,
    }
}

/// 报告文件名：`probe-<域>-<UTC 紧凑时间>.json`。
fn report_path(request: &ProbeRequest, generated_at: OffsetDateTime) -> PathBuf {
    let stamp = format!(
        "{:04}{:02}{:02}T{:02}{:02}{:02}Z",
        generated_at.year(),
        u8::from(generated_at.month()),
        generated_at.day(),
        generated_at.hour(),
        generated_at.minute(),
        generated_at.second()
    );
    let file = format!(
        "probe-{}-{stamp}.json",
        if request.all {
            "all"
        } else {
            request.domain.label()
        }
    );
    match &request.out {
        Some(path) if path.is_dir() || path.to_string_lossy().ends_with('/') => path.join(file),
        Some(path) => path.clone(),
        None => PathBuf::from(file),
    }
}

fn write_report(report: &Report, path: &Path) -> AgentdResult<()> {
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|err| {
            AgentdReason::system_error()
                .to_err()
                .with_detail(format!("创建报告目录 {} 失败：{err}", parent.display()))
        })?;
    }
    let json = serde_json::to_string_pretty(report).map_err(|err| {
        AgentdReason::system_error()
            .to_err()
            .with_detail(format!("序列化报告失败：{err}"))
    })?;
    std::fs::write(path, json + "\n").map_err(|err| {
        AgentdReason::system_error()
            .to_err()
            .with_detail(format!("写报告 {} 失败：{err}", path.display()))
    })
}

fn print_human(report: &Report, path: &Path) {
    println!(
        "probe {}  mode={}  {}ms  报告：{}",
        report.domain,
        report.mode,
        report.duration_ms,
        path.display()
    );
    println!(
        "  summary  targets={} succeeded={} failed={} facts={}（已注册 {} / 未注册 {}） candidates={}",
        report.summary.targets,
        report.summary.succeeded,
        report.summary.failed,
        report.summary.facts,
        report.summary.registered_facts,
        report.summary.unregistered_facts,
        report.summary.candidates
    );
    if let Some(note) = &report.note {
        println!("  {note}");
    }
    if !report.candidates.is_empty() {
        println!("\n自探候选：");
        for candidate in &report.candidates {
            println!(
                "  [{}] {}  ({})  key={}  evidence={} confidence={}",
                candidate.domain,
                candidate.instance,
                candidate.addr,
                candidate.credential_key,
                candidate.evidence,
                candidate.confidence
            );
            if let Some(detail) = &candidate.detail
                && !detail.is_empty()
            {
                println!("        {detail}");
            }
        }
    }
    for (index, target) in report.targets.iter().enumerate() {
        println!(
            "\n[{}/{}] {} {}  ({})  status={}  {}ms",
            index + 1,
            report.targets.len(),
            target.domain,
            target.instance,
            target.addr,
            target.status,
            target.duration_ms
        );
        println!(
            "      credential  {}（{}）",
            target.password_file,
            if target.password_file_present {
                "已投放"
            } else {
                "缺失"
            }
        );
        if let Some(error) = &target.last_error {
            println!("      error       {error}");
        }
        for warning in &target.warnings {
            println!("      warning     {warning}");
        }
        if target.facts.is_empty() {
            println!("      facts       （无）");
        } else {
            println!("      facts       {}", target.facts.len());
            for fact in &target.facts {
                let labels = if fact.labels.is_empty() {
                    String::new()
                } else {
                    format!(" {{{}}}", fact.labels.join(","))
                };
                match (&fact.metric, &fact.unit, &fact.value_type) {
                    (Some(metric), Some(unit), Some(value_type)) => println!(
                        "        {:<30} {:<14} -> {metric} ({value_type}, {unit}){labels}",
                        fact.fact, fact.value
                    ),
                    _ => println!(
                        "        {:<30} {:<14} -> 指标未注册（会被规范化层丢弃）{labels}",
                        fact.fact, fact.value
                    ),
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// 自探候选
// ---------------------------------------------------------------------------

/// `--list`：只跑自探并列出候选，不采集、不需要凭据。
fn collect_candidates(domains: &[ProbeDomain], _timeout_ms: u64) -> Vec<CandidateReport> {
    let mut out = Vec::new();
    for domain in domains {
        match domain {
            ProbeDomain::Postgres => {
                for entry in crate::discovery::pg_source::resolve_live() {
                    out.push(CandidateReport {
                        domain: domain.collection_kind(),
                        instance: entry.instance(),
                        addr: format!("{}:{}", entry.host, entry.port),
                        credential_key: entry.credential_key.clone(),
                        evidence: entry.evidence.clone(),
                        confidence: entry.confidence,
                        detail: Some(entry.detail.clone()),
                    });
                }
            }
            ProbeDomain::Mysql => {
                for entry in crate::discovery::mysql_source::resolve_live() {
                    out.push(CandidateReport {
                        domain: domain.collection_kind(),
                        instance: entry.instance(),
                        addr: format!("{}:{}", entry.host, entry.port),
                        credential_key: entry.credential_key.clone(),
                        evidence: entry.evidence.clone(),
                        confidence: entry.confidence,
                        detail: Some(entry.detail.clone()),
                    });
                }
            }
            ProbeDomain::Doris => {
                for entry in crate::discovery::doris_source::resolve_live() {
                    out.push(CandidateReport {
                        domain: domain.collection_kind(),
                        instance: entry.instance(),
                        addr: format!("{}:{}", entry.host, entry.port),
                        credential_key: entry.credential_key.clone(),
                        evidence: entry.evidence.clone(),
                        confidence: entry.confidence,
                        detail: Some(entry.detail.clone()),
                    });
                }
            }
            ProbeDomain::Kafka => {
                for cluster in crate::discovery::kafka_source::resolve_live() {
                    for endpoint in &cluster.endpoints {
                        out.push(CandidateReport {
                            domain: domain.collection_kind(),
                            instance: cluster.source_ref.clone(),
                            addr: endpoint.addr.clone(),
                            credential_key: "probe".to_string(),
                            evidence: cluster.evidence.clone(),
                            confidence: cluster.confidence,
                            detail: Some(format!(
                                "protocol={} reachable={} kafka_api={}",
                                endpoint.protocol, endpoint.reachable, endpoint.kafka_api
                            )),
                        });
                    }
                }
            }
        }
    }
    out
}

// ---------------------------------------------------------------------------
// 入口
// ---------------------------------------------------------------------------

pub(crate) async fn run(request: ProbeRequest) -> AgentdResult<i32> {
    let started = Instant::now();
    let generated_at = OffsetDateTime::now_utc();
    let domains = request_domains(&request);

    // `--list`：只看自探能看到什么，不碰任何凭据。
    if request.list {
        let candidates = collect_candidates(&domains, request.timeout_ms);
        let note = if candidates.is_empty() {
            Some(format!(
                "自探没有找到候选（{}）：自探只认 /proc 里的进程证据，本机没有在跑的实例就不会有；\
                 非 Linux 平台永远为空。",
                domains
                    .iter()
                    .map(|domain| domain.label())
                    .collect::<Vec<_>>()
                    .join("/")
            ))
        } else {
            None
        };
        let report = build_report(
            &request,
            generated_at,
            started.elapsed(),
            &[],
            candidates,
            note,
        );
        let path = report_path(&request, generated_at);
        write_report(&report, &path)?;
        emit(&request, &report, &path);
        return Ok(exit_code(&report));
    }

    let source = if request.addr.is_some() {
        "explicit"
    } else {
        "discovery"
    };

    let mut targets = Vec::new();
    for domain in &domains {
        targets.extend(resolve_targets(*domain, &request)?);
    }

    let note = if targets.is_empty() {
        Some(format!(
            "自探没有找到候选（{}）：自探只认 /proc 里的进程证据（本机没有在跑的实例就不会有候选；\
             非 Linux 平台永远是空）。先用 --addr <host:port> 指定一台验采集，或用 --list 看候选。",
            domains
                .iter()
                .map(|domain| domain.label())
                .collect::<Vec<_>>()
                .join("/")
        ))
    } else {
        None
    };

    let mut runs = Vec::with_capacity(targets.len());
    for target in &targets {
        let begin = Instant::now();
        let result = target.probe().await;
        runs.push(TargetRun {
            target,
            result,
            elapsed: begin.elapsed(),
            source,
        });
    }

    let report = build_report(
        &request,
        generated_at,
        started.elapsed(),
        &runs,
        Vec::new(),
        note,
    );
    let path = report_path(&request, generated_at);
    write_report(&report, &path)?;
    emit(&request, &report, &path);

    Ok(exit_code(&report))
}

fn emit(request: &ProbeRequest, report: &Report, path: &Path) {
    if request.json {
        println!(
            "{}",
            serde_json::to_string_pretty(report).unwrap_or_else(|_| "{}".to_string())
        );
    } else {
        print_human(report, path);
    }
}

/// 退出码：0 = 全部成功（`--list` 时为「至少有一个候选」）；
/// 1 = 采集失败；2 = 没有候选 / 没找到目标。
fn exit_code(report: &Report) -> i32 {
    if report.mode == "list" {
        return if report.candidates.is_empty() { 2 } else { 0 };
    }
    if report.targets.is_empty() {
        return 2;
    }
    let failed: usize = report.targets.iter().map(|target| target.failed).sum();
    if failed == 0 { 0 } else { 1 }
}

#[cfg(test)]
mod tests {
    use super::*;
    use wist_contracts::discovery::StringKeyValue;

    fn sample(facts: &[(&str, &str)]) -> ProbeResult {
        ProbeResult {
            targets: vec![
                crate::telemetry::metrics::runtime::MetricsCollectionTargetSample {
                    candidate_id: "postgres:127.0.0.1:5432".to_string(),
                    target_ref: "postgres:127.0.0.1:5432".to_string(),
                    status: "succeeded".to_string(),
                    last_error: None,
                    resource_ref: "postgres:127.0.0.1:5432".to_string(),
                    execution_hints: Vec::new(),
                    runtime_facts: facts
                        .iter()
                        .map(|(key, value)| StringKeyValue::new(*key, *value))
                        .collect(),
                    labeled_facts: Vec::new(),
                },
            ],
            attempted: 1,
            failed: 0,
            last_error: None,
            warnings: Vec::new(),
        }
    }

    #[test]
    fn domains_have_operator_aliases() {
        for text in ["pg", "postgres", "PostgreSQL", " pg "] {
            assert_eq!(
                ProbeDomain::parse(text),
                Some(ProbeDomain::Postgres),
                "{text}"
            );
        }
        assert_eq!(ProbeDomain::parse("tidb"), Some(ProbeDomain::Mysql));
        assert_eq!(ProbeDomain::parse("doris"), Some(ProbeDomain::Doris));
        assert_eq!(ProbeDomain::parse("kafka"), Some(ProbeDomain::Kafka));
        assert_eq!(ProbeDomain::parse("elasticsearch"), None);
    }

    #[test]
    fn kafka_targets_use_the_single_instance_credential_convention() {
        let request = ProbeRequest::new(ProbeDomain::Kafka);
        let target = explicit_target(ProbeDomain::Kafka, "10.0.0.9", 9094, &request);

        assert_eq!(target.domain(), ProbeDomain::Kafka);
        assert_eq!(target.credential_key(), "probe");
        assert_eq!(target.addr(), "10.0.0.9:9094");
        assert_eq!(
            target.password_file(),
            "/etc/wist-agentd/secrets/kafka/probe"
        );
        assert_eq!(ProbeDomain::Kafka.default_port(), 9092);
    }

    #[test]
    fn summary_counts_registered_and_unregistered_facts() {
        let request = ProbeRequest {
            addr: Some("127.0.0.1:5432".to_string()),
            ..ProbeRequest::new(ProbeDomain::Postgres)
        };
        let report = report_for(
            &request,
            sample(&[("pg.up", "1"), ("pg.not.registered", "9")]),
        );

        assert_eq!(report.summary.targets, 1);
        assert_eq!(report.summary.succeeded, 1);
        assert_eq!(report.summary.failed, 0);
        assert_eq!(report.summary.facts, 2);
        assert_eq!(report.summary.registered_facts, 1);
        assert_eq!(report.summary.unregistered_facts, 1);
        assert_eq!(report.targets[0].domain, "pg_metrics");
    }

    #[test]
    fn labeled_facts_from_kafka_keep_their_group_and_topic() {
        let request = ProbeRequest {
            addr: Some("10.0.0.9:9094".to_string()),
            ..ProbeRequest::new(ProbeDomain::Kafka)
        };
        let mut result = sample(&[]);
        result.targets[0].labeled_facts = vec![
            wist_metrics::provider::MetricsLabeledFact {
                key: "kafka.consumergroup.lag".to_string(),
                value: "17".to_string(),
                labels: vec![
                    wist_contracts::discovery::StringKeyValue::new("group", "g1"),
                    wist_contracts::discovery::StringKeyValue::new("topic", "t1"),
                ],
            },
            wist_metrics::provider::MetricsLabeledFact {
                key: "kafka.not.registered".to_string(),
                value: "1".to_string(),
                labels: Vec::new(),
            },
        ];
        let report = report_for(&request, result);

        let fact = &report.targets[0].facts[0];
        assert_eq!(fact.value, "17");
        assert_eq!(fact.labels, vec!["group=g1", "topic=t1"]);
        assert_eq!(report.summary.registered_facts, 1);
        assert_eq!(report.summary.unregistered_facts, 1);
    }

    #[test]
    fn list_mode_exits_zero_only_with_candidates() {
        let request = ProbeRequest {
            list: true,
            ..ProbeRequest::new(ProbeDomain::Postgres)
        };

        let with_candidate = build_report(
            &request,
            OffsetDateTime::now_utc(),
            Duration::from_millis(2),
            &[],
            vec![CandidateReport {
                domain: "pg_metrics",
                instance: "postgres:10.0.0.1:5432".to_string(),
                addr: "10.0.0.1:5432".to_string(),
                credential_key: "port-5432".to_string(),
                evidence: "config".to_string(),
                confidence: 90,
                detail: None,
            }],
            None,
        );
        assert_eq!(with_candidate.mode, "list");
        assert_eq!(with_candidate.summary.candidates, 1);
        assert_eq!(exit_code(&with_candidate), 0);

        let empty = build_report(
            &request,
            OffsetDateTime::now_utc(),
            Duration::ZERO,
            &[],
            Vec::new(),
            Some("没找到".to_string()),
        );
        assert_eq!(exit_code(&empty), 2);
    }

    #[test]
    fn addr_parsing_handles_omitted_port_ipv4_and_bracketed_ipv6() {
        assert_eq!(
            parse_addr("127.0.0.1:55439", 5432).unwrap(),
            ("127.0.0.1".to_string(), 55439)
        );
        assert_eq!(
            parse_addr("db.internal", 5432).unwrap(),
            ("db.internal".to_string(), 5432)
        );
        assert_eq!(
            parse_addr("[::1]:5432", 5432).unwrap(),
            ("::1".to_string(), 5432)
        );
        assert_eq!(
            parse_addr("[::1]", 5432).unwrap(),
            ("::1".to_string(), 5432)
        );
        assert!(parse_addr("::1:5432", 5432).is_err());
        assert!(parse_addr("host:notaport", 5432).is_err());
        assert!(parse_addr("", 5432).is_err());
    }

    #[test]
    fn report_maps_facts_to_registered_metrics_and_never_carries_the_secret() {
        let request = ProbeRequest {
            addr: Some("127.0.0.1:5432".to_string()),
            password_file: Some(PathBuf::from("/nonexistent/secret")),
            ..ProbeRequest::new(ProbeDomain::Postgres)
        };
        let target = explicit_target(ProbeDomain::Postgres, "127.0.0.1", 5432, &request);
        let run = TargetRun {
            target: &target,
            result: sample(&[("pg.up", "1"), ("pg.not.registered", "9")]),
            elapsed: Duration::from_millis(7),
            source: "explicit",
        };

        let report = build_report(
            &request,
            OffsetDateTime::now_utc(),
            Duration::from_millis(7),
            &[run],
            Vec::new(),
            None,
        );
        let json = serde_json::to_string(&report).unwrap();

        assert!(json.contains("\"metric\":\"pg_up\""), "{json}");
        assert!(json.contains("pg.not.registered"), "{json}");
        assert!(!json.contains("\"metric\":\"pg_not"), "{json}");
        assert!(json.contains("\"password_file_present\":false"), "{json}");
        assert_eq!(report.targets[0].status, "succeeded");
        assert_eq!(report.targets[0].succeeded, 1);
    }

    #[test]
    fn report_path_follows_out_directory_or_explicit_file() {
        let generated = OffsetDateTime::now_utc();
        let base = ProbeRequest::new(ProbeDomain::Mysql);

        let default = report_path(&base, generated);
        assert!(default.to_string_lossy().starts_with("probe-mysql-"));
        assert!(default.to_string_lossy().ends_with(".json"));

        let dir = PathBuf::from("/tmp/probe-out/");
        let in_dir = report_path(
            &ProbeRequest {
                out: Some(dir),
                ..base.clone()
            },
            generated,
        );
        assert!(
            in_dir
                .to_string_lossy()
                .starts_with("/tmp/probe-out/probe-mysql-")
        );

        let file = PathBuf::from("/tmp/explicit.json");
        let explicit = report_path(
            &ProbeRequest {
                out: Some(file.clone()),
                ..base
            },
            generated,
        );
        assert_eq!(explicit, file);
    }

    fn report_for(request: &ProbeRequest, result: ProbeResult) -> Report {
        let target = explicit_target(
            request.domain,
            "127.0.0.1",
            request.domain.default_port(),
            request,
        );
        let run = TargetRun {
            target: &target,
            result,
            elapsed: Duration::from_millis(3),
            source: "explicit",
        };
        build_report(
            request,
            OffsetDateTime::now_utc(),
            Duration::from_millis(3),
            &[run],
            Vec::new(),
            None,
        )
    }

    #[test]
    fn exit_code_is_zero_only_when_every_target_succeeded() {
        let request = ProbeRequest::new(ProbeDomain::Postgres);

        let succeeded = report_for(&request, sample(&[("pg.up", "1")]));
        assert_eq!(exit_code(&succeeded), 0);

        let mut failed = sample(&[]);
        failed.attempted = 1;
        failed.failed = 1;
        failed.last_error = Some("连接失败".to_string());
        assert_eq!(exit_code(&report_for(&request, failed)), 1);

        // 自探没找到候选（空报告）也必须非 0：命令就是回答「能不能采到」。
        let empty = build_report(
            &request,
            OffsetDateTime::now_utc(),
            Duration::ZERO,
            &[],
            Vec::new(),
            Some("没找到".to_string()),
        );
        assert_eq!(exit_code(&empty), 2, "没候选是 2，不是 1");
    }

    #[test]
    fn a_failed_round_reports_no_facts() {
        let request = ProbeRequest::new(ProbeDomain::Mysql);
        let mut failed = sample(&[]);
        failed.attempted = 1;
        failed.failed = 1;
        failed.last_error = Some("读不到密码文件".to_string());

        let report = report_for(&request, failed);

        assert_eq!(report.targets[0].status, "failed");
        assert_eq!(
            (report.targets[0].attempted, report.targets[0].failed),
            (1, 1)
        );
        assert!(
            report.targets[0].facts.is_empty(),
            "失败不能留下任何事实/样本"
        );
    }

    #[test]
    fn the_password_file_contents_never_reach_the_report() {
        let dir = std::env::temp_dir().join(format!("wist-probe-secret-{}", std::process::id()));
        std::fs::create_dir_all(&dir).expect("temp dir");
        let password_file = dir.join("password");
        std::fs::write(&password_file, "SuperSecret-2026").expect("write secret");

        let request = ProbeRequest {
            addr: Some("127.0.0.1:5432".to_string()),
            password_file: Some(password_file.clone()),
            ..ProbeRequest::new(ProbeDomain::Postgres)
        };
        let report = report_for(&request, sample(&[("pg.up", "1")]));
        let json = serde_json::to_string(&report).expect("json");

        assert!(!json.contains("SuperSecret-2026"), "报告里不能出现密码内容");
        assert!(json.contains("\"password_file_present\":true"), "{json}");
        assert!(json.contains(&password_file.display().to_string()));

        let _ = std::fs::remove_dir_all(&dir);
    }
}
