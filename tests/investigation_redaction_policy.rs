//! 「永不回传清单」的 CI 闸门：策略即代码。
//!
//! 这组用例守的不是某个函数的实现，而是**一条出口承诺**：
//! 调查报告（`IVSREP` 帧、`state/investigations/*.json`、`--json`）里不会出现
//! 口令哈希、私钥、连接串口令、云/平台 token、`authorized_keys` 正文。
//!
//! 三个来源：
//! * 策略文件本身：`investigation/redaction-policy.toml`（与内嵌副本必须一致）；
//! * 取证样本：`tests/fixtures/investigation/redaction-cases.json`（该脱的脱、不该动的没动）；
//! * **每个题一份真实形状的报告**：`good-report-*.json`（结构白名单不能把正常报告判成违规）。
//!
//! 新增调查题时，除了在策略里登记 `id` 前缀，还必须往这里加一份 `good-report-<topic>.json`
//! —— 否则“新题的报告结构是否会误伤”这件事没有任何证据。

use std::fs;
use std::path::PathBuf;

use serde::Deserialize;
use serde_json::Value;
use wist_agentd::investigate_safety::{POLICY_TOML, sanitize_text, sanitize_value, scan};

fn read(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|err| panic!("读取 {path:?} 失败: {err}"))
}

#[derive(Deserialize)]
struct Cases {
    leaks: Vec<Leak>,
    clean: Vec<String>,
}

#[derive(Deserialize)]
struct Leak {
    rule: String,
    text: String,
}

fn cases() -> Cases {
    serde_json::from_str(&read("tests/fixtures/investigation/redaction-cases.json"))
        .expect("redaction-cases.json 必须可解析")
}

/// 每个题目一份“真实形状”的报告。加题不加样本 = 这里少一份证据。
fn good_reports() -> Vec<(String, Value)> {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/investigation");
    let mut files: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|err| panic!("读取 {dir:?} 失败: {err}"))
        .flatten()
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .map(|name| {
                    let name = name.to_string_lossy();
                    name.starts_with("good-report-") && name.ends_with(".json")
                })
                .unwrap_or(false)
        })
        .collect();
    files.sort();
    assert!(
        files.len() >= 3,
        "至少要覆盖 disk / accounts / exposure 三份报告形状"
    );
    files
        .into_iter()
        .map(|path| {
            let text =
                fs::read_to_string(&path).unwrap_or_else(|err| panic!("读取 {path:?} 失败: {err}"));
            let value: Value = serde_json::from_str(&text)
                .unwrap_or_else(|err| panic!("{path:?} 不是合法 JSON: {err}"));
            (path.display().to_string(), value)
        })
        .collect()
}

fn disk_report() -> Value {
    good_reports()
        .into_iter()
        .find(|(name, _)| name.contains("good-report-disk"))
        .map(|(_, value)| value)
        .expect("必须存在 good-report-disk.json")
}

#[test]
fn embedded_policy_matches_the_file() {
    assert_eq!(
        read("investigation/redaction-policy.toml"),
        POLICY_TOML,
        "内嵌策略与仓库里的文件不一致（改了文件没重新编译，或反过来）"
    );
}

#[test]
fn every_leak_is_masked_by_the_declared_rule() {
    for case in cases().leaks {
        let masked = sanitize_text(&case.text);
        let expected = format!("[redacted:{}]", case.rule);
        assert_eq!(
            masked.as_ref(),
            expected.as_str(),
            "样本未被 `{}` 命中（或先被别的规则命中）: {:?}",
            case.rule,
            case.text
        );
    }
}

/// 误伤是这套机制最贵的失败方式：普通证据必须原样通过。
#[test]
fn clean_evidence_passes_through_untouched() {
    for text in cases().clean {
        assert_eq!(sanitize_text(&text).as_ref(), text.as_str(), "误伤: {text}");
    }
}

/// 每个题目的真实报告形状都必须零违规：字段白名单（`judged` / `limits` / `coverage` /
/// `summary.unknown`）与题目 id 前缀都在这里被钉住。
#[test]
fn real_shaped_reports_are_clean() {
    for (name, report) in good_reports() {
        let violations = scan(&report);
        assert!(violations.is_empty(), "{name} 被判违规: {violations:?}");
    }
}

#[test]
fn sanitize_makes_a_leaky_report_pass_scan() {
    let mut report = disk_report();
    report["verdict"] = Value::String("postgres://app:s3cr3t@db.internal/prod".to_string());
    report["findings"][0]["detail"] = Value::String("-----BEGIN RSA PRIVATE KEY-----".to_string());

    assert_eq!(sanitize_value(&mut report), 2);
    let violations = scan(&report);
    assert!(violations.is_empty(), "脱敏后不应再有违规: {violations:?}");
}

/// 没登记的新题目必须被拒 —— 这条守的是“加题时必须有人看过这题的输出”。
#[test]
fn unregistered_topic_is_rejected() {
    let mut report = disk_report();
    report["topic"] = Value::String("software".to_string());
    report["report_schema"] = Value::String("wist.investigation.software/v1".to_string());

    let rules: Vec<String> = scan(&report).into_iter().map(|v| v.rule).collect();
    assert!(
        rules.iter().any(|rule| rule == "schema.unknown_topic"),
        "未登记的题目必须被判违规: {rules:?}"
    );
}

/// `finding.id` 必须落在题目前缀里：防止 A 题的报告混进 B 题的结论。
#[test]
fn foreign_finding_id_is_rejected() {
    let mut report = disk_report();
    report["findings"][0]["id"] = Value::String("load.cpu".to_string());

    let rules: Vec<String> = scan(&report).into_iter().map(|v| v.rule).collect();
    assert!(
        rules.iter().any(|rule| rule == "schema.id_prefix"),
        "跨题目的 finding id 必须被判违规: {rules:?}"
    );
}
