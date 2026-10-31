//! 调查报告的**出口脱敏**与**结构校验**（“永不回传清单”的可执行版本）。
//!
//! 为什么要有这个模块：`disk` / `load` 之所以安全，是因为它们**结构上**没有 argv、没有文件正文
//! （枚举类型里根本没有那个字段）。但安全向的题（`accounts` / `secrets` / `data-exposure` …）
//! 会接触到口令哈希、私钥路径、`pg_hba.conf` 的认证方式、连接串。只靠“写代码时记得别带上”
//! 是一条迟早会断的防线，所以把规则抽成**可校验的策略**：
//!
//! * 策略：`investigation/redaction-policy.toml`（单一事实来源，带注释、可评审）；
//! * 运行时：`Row::new` / `Finding::new` 在产出处脱敏，`Report::to_json` 再整体过一遍；
//! * CI：本模块单测 + [`tests/investigation_redaction_policy.rs`] 用 fixtures 钉住行为。
//!
//! 两条设计取舍：
//!
//! 1. **整值替换，不做部分打码**。`password=hunter2` 打成 `password=***` 在“值就是证据”的
//!    场景里仍会泄露长度/前缀；替换成 `[redacted:cred.env_assignment]` 既不留残片，也告诉读的人
//!    **是哪条规则**命中的 —— 这比一句“已脱敏”有用。
//! 2. **只报不问、只脱不删**。校验失败不改变报告内容（脱敏已在前一步做了），它只把问题说清楚；
//!    结构问题交给 CI 与评审，运行时不因为结构不对就丢弃一份证据。

use std::borrow::Cow;
use std::collections::BTreeMap;
use std::sync::LazyLock;

use regex::Regex;
use serde::Deserialize;
use serde_json::{Map, Value};

/// 内嵌的策略文本（与 `investigation/redaction-policy.toml` 同一份文件）。
pub const POLICY_TOML: &str = include_str!("../investigation/redaction-policy.toml");

/// 一次策略违规。
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Violation {
    /// JSON 路径，如 `$.findings[2].rows[0].value`。
    pub path: String,
    /// 规则 id，如 `cred.env_assignment` / `schema.unknown_key`。
    pub rule: String,
    /// 人话原因（来自策略，或结构检查的固定文案）。
    pub reason: String,
}

impl Violation {
    fn new(path: impl Into<String>, rule: &str, reason: impl Into<String>) -> Self {
        Self {
            path: path.into(),
            rule: rule.to_string(),
            reason: reason.into(),
        }
    }
}

/// 编译后的策略。字段对外只读，便于网关/工具复用同一份判断。
pub struct Policy {
    pub version: u32,
    pub schema_prefix: String,
    pub envelope: Envelope,
    /// 题目 → 允许的 `finding.id` 前缀。
    pub topics: BTreeMap<String, Vec<String>>,
    value_rules: Vec<Rule>,
    key_rules: Vec<Rule>,
}

/// 报告信封的字段白名单。
pub struct Envelope {
    pub top_keys: Vec<String>,
    pub finding_keys: Vec<String>,
    pub row_keys: Vec<String>,
    pub summary_keys: Vec<String>,
    report_schema: Regex,
}

struct Rule {
    id: String,
    reason: String,
    regex: Regex,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct PolicyFile {
    version: u32,
    #[serde(default)]
    #[allow(dead_code)]
    description: String,
    schema_prefix: String,
    envelope: EnvelopeFile,
    topics: BTreeMap<String, TopicFile>,
    #[serde(default)]
    forbidden_key_names: Vec<RuleFile>,
    #[serde(default)]
    value_rules: Vec<RuleFile>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvelopeFile {
    top_keys: Vec<String>,
    finding_keys: Vec<String>,
    row_keys: Vec<String>,
    summary_keys: Vec<String>,
    report_schema_pattern: String,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TopicFile {
    id_prefixes: Vec<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct RuleFile {
    id: String,
    pattern: String,
    reason: String,
}

/// 全局策略（进程内只解析一次）。
pub fn policy() -> &'static Policy {
    static POLICY: LazyLock<Policy> = LazyLock::new(|| {
        Policy::from_toml(POLICY_TOML).unwrap_or_else(|err| {
            panic!("内嵌的调查报告脱敏策略不合法（investigation/redaction-policy.toml）: {err}")
        })
    });
    &POLICY
}

impl Policy {
    fn from_toml(text: &str) -> Result<Self, String> {
        let file: PolicyFile = toml::from_str(text).map_err(|err| format!("解析失败: {err}"))?;
        if file.version != 1 {
            return Err(format!("不支持的策略版本 {}（本实现只认 1）", file.version));
        }
        if file.topics.is_empty() {
            return Err("topics 不能为空".to_string());
        }
        let mut seen: BTreeMap<String, ()> = BTreeMap::new();
        let mut compile = |rule: &RuleFile, kind: &str| -> Result<Rule, String> {
            if seen.insert(rule.id.clone(), ()).is_some() {
                return Err(format!("规则 id 重复: {}", rule.id));
            }
            let regex = Regex::new(&rule.pattern)
                .map_err(|err| format!("{kind} `{}` 的正则不合法: {err}", rule.id))?;
            Ok(Rule {
                id: rule.id.clone(),
                reason: rule.reason.clone(),
                regex,
            })
        };
        let mut value_rules = Vec::with_capacity(file.value_rules.len());
        for rule in &file.value_rules {
            value_rules.push(compile(rule, "value_rules")?);
        }
        let mut key_rules = Vec::with_capacity(file.forbidden_key_names.len());
        for rule in &file.forbidden_key_names {
            key_rules.push(compile(rule, "forbidden_key_names")?);
        }
        let mut topics = BTreeMap::new();
        for (topic, spec) in file.topics {
            if spec.id_prefixes.is_empty() {
                return Err(format!("题目 `{topic}` 没有声明 id_prefixes"));
            }
            topics.insert(topic, spec.id_prefixes);
        }
        let report_schema = Regex::new(&file.envelope.report_schema_pattern)
            .map_err(|err| format!("envelope.report_schema_pattern 不合法: {err}"))?;
        Ok(Self {
            version: file.version,
            schema_prefix: file.schema_prefix,
            envelope: Envelope {
                top_keys: file.envelope.top_keys,
                finding_keys: file.envelope.finding_keys,
                row_keys: file.envelope.row_keys,
                summary_keys: file.envelope.summary_keys,
                report_schema,
            },
            topics,
            value_rules,
            key_rules,
        })
    }

    fn value_rule(&self, text: &str) -> Option<&Rule> {
        self.value_rules
            .iter()
            .find(|rule| rule.regex.is_match(text))
    }

    fn key_rule(&self, key: &str) -> Option<&Rule> {
        self.key_rules.iter().find(|rule| rule.regex.is_match(key))
    }

    /// 策略里的值规则 id（给测试与文档用）。
    pub fn value_rule_ids(&self) -> Vec<&str> {
        self.value_rules
            .iter()
            .map(|rule| rule.id.as_str())
            .collect()
    }

    /// 策略里的键名规则 id。
    pub fn key_rule_ids(&self) -> Vec<&str> {
        self.key_rules.iter().map(|rule| rule.id.as_str()).collect()
    }
}

/// 对一个字符串值脱敏。命中时返回 `[redacted:<rule>]`，否则原样返回（不额外分配）。
pub fn sanitize_text(text: &str) -> Cow<'_, str> {
    match policy().value_rule(text) {
        Some(rule) => Cow::Owned(format!("[redacted:{}]", rule.id)),
        None => Cow::Borrowed(text),
    }
}

/// [`sanitize_text`] 的 `String` 版本（避免 `Cow` 在所有调用点扩散）。
pub fn sanitize_owned(text: String) -> String {
    match sanitize_text(&text) {
        Cow::Borrowed(_) => text,
        Cow::Owned(masked) => masked,
    }
}

/// 递归脱敏整个 JSON 值。返回被替换的字段数。
///
/// 除了字符串值，也处理**键名**：命中 `forbidden_key_names` 的键，其值整体替换。
pub fn sanitize_value(value: &mut Value) -> usize {
    let policy = policy();
    let mut masked = 0;
    walk_sanitize(value, policy, &mut masked);
    masked
}

fn walk_sanitize(value: &mut Value, policy: &Policy, masked: &mut usize) {
    match value {
        Value::String(text) => {
            if let Some(rule) = policy.value_rule(text) {
                *text = format!("[redacted:{}]", rule.id);
                *masked += 1;
            }
        }
        Value::Array(items) => {
            for item in items {
                walk_sanitize(item, policy, masked);
            }
        }
        Value::Object(map) => {
            for (key, child) in map.iter_mut() {
                if let Some(rule) = policy.key_rule(key) {
                    *child = Value::String(format!("[redacted:{}]", rule.id));
                    *masked += 1;
                    continue;
                }
                walk_sanitize(child, policy, masked);
            }
        }
        _ => {}
    }
}

/// 校验一份报告：结构（字段白名单 / 题目登记 / id 前缀）+ 值规则。
///
/// 返回空 = 合规。**脱敏之后**调用它，得到的就是“出口上不该有任何东西”的证明。
pub fn scan(value: &Value) -> Vec<Violation> {
    let policy = policy();
    let mut out = Vec::new();
    let Some(report) = value.as_object() else {
        out.push(Violation::new(
            "$",
            "shape.not_object",
            "报告顶层必须是 JSON 对象",
        ));
        return out;
    };

    check_keys(report, &policy.envelope.top_keys, "$", &mut out);
    for key in ["topic", "report_schema", "findings"] {
        if !report.contains_key(key) {
            out.push(Violation::new(
                format!("$.{key}"),
                "shape.missing_key",
                format!("缺少必需字段 `{key}`"),
            ));
        }
    }

    if let Some(schema) = report.get("report_schema").and_then(Value::as_str) {
        if !policy.envelope.report_schema.is_match(schema) {
            out.push(Violation::new(
                "$.report_schema",
                "schema.report_schema",
                format!("`{schema}` 不符合 `wist.investigation.<topic>/v<N>`"),
            ));
        } else if !schema.starts_with(&format!("{}.", policy.schema_prefix)) {
            out.push(Violation::new(
                "$.report_schema",
                "schema.prefix",
                format!("`{schema}` 不以 `{}` 开头", policy.schema_prefix),
            ));
        }
    }

    let topic = report
        .get("topic")
        .and_then(Value::as_str)
        .unwrap_or_default();
    let prefixes = policy.topics.get(topic);
    if prefixes.is_none() {
        out.push(Violation::new(
            "$.topic",
            "schema.unknown_topic",
            format!("题目 `{topic}` 未在脱敏策略登记（新增题目必须登记 id 前缀）"),
        ));
    }

    match report.get("findings") {
        Some(Value::Array(findings)) => {
            for (index, finding) in findings.iter().enumerate() {
                let path = format!("$.findings[{index}]");
                let Some(finding) = finding.as_object() else {
                    out.push(Violation::new(
                        path,
                        "shape.finding_not_object",
                        "findings 的元素必须是对象",
                    ));
                    continue;
                };
                check_keys(finding, &policy.envelope.finding_keys, &path, &mut out);
                let id_allowed = match (finding.get("id").and_then(Value::as_str), prefixes) {
                    (Some(id), Some(prefixes)) => prefixes
                        .iter()
                        .any(|prefix| id.starts_with(prefix.as_str())),
                    // 题目未登记或没写 id：前者已单独报过，后者不在这里重复。
                    _ => true,
                };
                if !id_allowed {
                    let id = finding
                        .get("id")
                        .and_then(Value::as_str)
                        .unwrap_or_default();
                    out.push(Violation::new(
                        format!("{path}.id"),
                        "schema.id_prefix",
                        format!("`{id}` 不属于题目 `{topic}` 允许的前缀 {prefixes:?}"),
                    ));
                }
                if let Some(rows) = finding.get("rows").and_then(Value::as_array) {
                    for (row_index, row) in rows.iter().enumerate() {
                        let row_path = format!("{path}.rows[{row_index}]");
                        match row.as_object() {
                            Some(row) => {
                                check_keys(row, &policy.envelope.row_keys, &row_path, &mut out);
                            }
                            None => out.push(Violation::new(
                                row_path,
                                "shape.row_not_object",
                                "rows 的元素必须是对象",
                            )),
                        }
                    }
                }
            }
        }
        Some(_) => out.push(Violation::new(
            "$.findings",
            "shape.findings_not_array",
            "findings 必须是数组",
        )),
        None => {}
    }

    if let Some(summary) = report.get("summary").and_then(Value::as_object) {
        check_keys(
            summary,
            &policy.envelope.summary_keys,
            "$.summary",
            &mut out,
        );
    }

    scan_values(value, "$", policy, &mut out);
    out
}

fn check_keys(map: &Map<String, Value>, allowed: &[String], path: &str, out: &mut Vec<Violation>) {
    for key in map.keys() {
        if !allowed.iter().any(|allowed| allowed == key) {
            out.push(Violation::new(
                format!("{path}.{key}"),
                "schema.unknown_key",
                format!("字段 `{key}` 不在白名单（允许：{}）", allowed.join(", ")),
            ));
        }
    }
}

fn scan_values(value: &Value, path: &str, policy: &Policy, out: &mut Vec<Violation>) {
    match value {
        Value::String(text) => {
            if let Some(rule) = policy.value_rule(text) {
                out.push(Violation::new(path, &rule.id, rule.reason.clone()));
            }
        }
        Value::Array(items) => {
            for (index, item) in items.iter().enumerate() {
                scan_values(item, &format!("{path}[{index}]"), policy, out);
            }
        }
        Value::Object(map) => {
            for (key, child) in map {
                let child_path = format!("{path}.{key}");
                if let Some(rule) = policy.key_rule(key) {
                    out.push(Violation::new(
                        child_path.as_str(),
                        &rule.id,
                        rule.reason.clone(),
                    ));
                }
                scan_values(child, &child_path, policy, out);
            }
        }
        _ => {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn policy_is_valid() {
        assert_eq!(policy().version, 1);
        assert!(!policy().topics.is_empty());
    }

    /// 词表与策略必须同步：新增题目却忘了登记前缀，这里立刻挂。
    #[test]
    fn topics_cover_registry() {
        for topic in crate::investigate::TOPICS {
            assert!(
                policy().topics.contains_key(*topic),
                "题目 `{topic}` 未在 investigation/redaction-policy.toml 登记 id 前缀"
            );
        }
    }

    #[test]
    fn masks_private_key() {
        let text = "-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNzaC1rZXk=\n";
        assert_eq!(sanitize_text(text), "[redacted:pem.private_key]");
    }

    #[test]
    fn masks_connection_string_password() {
        assert_eq!(
            sanitize_text("postgres://app:s3cr3t@db.internal:5432/prod"),
            "[redacted:cred.uri_password]"
        );
    }

    #[test]
    fn masks_cli_flag_and_env_assignment() {
        assert_eq!(
            sanitize_text("wist-agentd --token=abc123"),
            "[redacted:cred.flag]"
        );
        assert_eq!(
            sanitize_text("DB_PASSWORD=hunter2"),
            "[redacted:cred.env_assignment]"
        );
    }

    /// 误伤是这套机制最贵的失败方式：普通证据必须原样通过。
    #[test]
    fn ordinary_evidence_is_untouched() {
        for text in [
            "/var/lib/docker/overlay2",
            "/home/dev/.aws/credentials",
            "占比 62.3%",
            "nginx: worker process",
            "2026-10-31T08:00:00Z",
            "disk.top_files",
            "deleted bin: /usr/bin/sshd (deleted)",
            "ssh: 允许 root 登录",
            "inode 用量 12%",
        ] {
            assert_eq!(sanitize_text(text), text, "不应命中任何规则: {text}");
        }
    }

    #[test]
    fn sanitize_walks_nested_values_without_touching_clean_ones() {
        let mut value = json!({
            "topic": "disk",
            "rows": [
                { "label": "/", "value": "88.0%", "note": "ext4" },
                { "label": "db", "value": "postgres://u:p@h/db", "note": "" }
            ],
            "nested": { "api_key": "anything" }
        });
        assert_eq!(sanitize_value(&mut value), 2);
        assert_eq!(value["rows"][0]["value"], "88.0%");
        assert_eq!(value["rows"][1]["value"], "[redacted:cred.uri_password]");
        assert_eq!(value["nested"]["api_key"], "[redacted:key.credential]");
    }

    #[test]
    fn scan_reports_structure_and_value_problems() {
        let value = json!({
            "topic": "software",
            "report_schema": "wist.investigation.software/v1",
            "findings": [
                { "id": "disk.top_files", "status": "ok", "title": "t", "detail": "d", "hint": null, "rows": [] }
            ],
            "surprise": true,
            "verdict": "postgres://u:p@h/db"
        });
        let violations = scan(&value);
        let rules: Vec<&str> = violations.iter().map(|v| v.rule.as_str()).collect();
        assert!(rules.contains(&"schema.unknown_topic"), "{rules:?}");
        assert!(rules.contains(&"schema.unknown_key"), "{rules:?}");
        assert!(rules.contains(&"cred.uri_password"), "{rules:?}");
    }

    /// `limits` 是新增的报告字段，也是**人话字符串**：它同样要过脱敏。
    #[test]
    fn sanitizer_covers_the_limits_array() {
        let mut value = json!({
            "topic": "accounts",
            "report_schema": "wist.investigation.accounts/v1",
            "judged": true,
            "limits": ["见 postgres://app:s3cr3t@db/prod"],
            "findings": [],
            "summary": { "ok": 0, "warn": 0, "fail": 0, "unknown": 0, "overall": "ok" },
            "verdict": "0 项正常"
        });
        assert_eq!(sanitize_value(&mut value), 1);
        assert_eq!(value["limits"][0], "[redacted:cred.uri_password]");
        assert!(scan(&value).is_empty());
    }

    #[test]
    fn sanitize_then_scan_is_clean() {
        let mut value = json!({
            "topic": "disk",
            "report_schema": "wist.investigation.disk/v1",
            "findings": [
                {
                    "id": "disk.top_files",
                    "status": "ok",
                    "title": "t",
                    "detail": "-----BEGIN RSA PRIVATE KEY-----",
                    "hint": null,
                    "rows": [
                        { "label": "a", "value": "AKIAIOSFODNN7EXAMPLE", "note": "" }
                    ]
                }
            ],
            "summary": { "ok": 1, "warn": 0, "fail": 0, "overall": "ok" },
            "verdict": "全部正常"
        });
        assert_eq!(sanitize_value(&mut value), 2);
        assert_eq!(scan(&value), Vec::new());
    }
}
