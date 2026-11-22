//! `config.inspect`：配置文件**结构体检**。只回结构，**不回值**。
//!
//! 为什么不回值：配置文件里十有八九有口令 / token / 私钥。一个 R1 调用就能把整台机器的
//! 凭据搬到中心，等于给「只读」开了个后门。要看具体值请用 `file.read_range`
//! （同样受 `allow.paths` 约束，而且显式带 `offset` / `length`）。
//!
//! 它回答三个问题：
//!
//! 1. 这个文件能不能按指定格式解析；不能的话，错在**第几行第几列**；
//! 2. 结构规模：顶层键有哪些、叶子多少个、根是什么类型；
//! 3. 指定的键路径**在不在**，以及它的**类型**（仍然不回值）。
//!
//! 解析错误**只报 `kind` / `line` / `column`**：TOML 的错误文本会把出错那一行的原文
//! 带出来，原样回传就绕过了「不回值」的承诺。
//!
//! 边界：`selector` 是**点分路径**（`server.tls.enabled`、`actions.0.name`），
//! 键名里本身带 `.` 的无法寻址 —— 这是这个契约的已知限制，不猜。

use std::collections::BTreeMap;
use std::io::Read;
use std::path::Path;

use serde::Deserialize;
use serde_json::{Value, json};
use wist_contracts::action_plan::RiskLevel;

use crate::exec::opcode::file::{open_regular, resolve_allowed};
use crate::exec::opcode::{OpBudget, OpError, OpInput, OpOutput, OpSpec, codes, parse_args};

const SCHEMA: &str = "wist.opcode.config_inspect/v1";
/// 配置文件不应该有这么大；再大就不像配置了。
const MAX_CONFIG_BYTES: u64 = 1024 * 1024;
const MAX_SELECTORS: usize = 32;
const MAX_SELECTOR_CHARS: usize = 200;
const MAX_TOP_KEYS: usize = 100;

pub const INSPECT_SPEC: OpSpec = OpSpec {
    id: "config.inspect",
    risk: RiskLevel::R1,
    platforms: &["linux", "macos"],
    budget: OpBudget::new(3_000, 1, 0),
    handler: inspect,
};

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct InspectArgs {
    path: String,
    /// `auto`（默认）/ `toml` / `json` / `env`。
    #[serde(default)]
    format: Option<String>,
    /// 点分键路径；只回答「在不在 + 什么类型」。
    #[serde(default)]
    selectors: Option<Vec<String>>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) enum Format {
    Json,
    Toml,
    Env,
}

impl Format {
    pub(super) fn id(self) -> &'static str {
        match self {
            Self::Json => "json",
            Self::Toml => "toml",
            Self::Env => "env",
        }
    }

    pub(super) fn parse(value: &str) -> Result<Self, OpError> {
        match value {
            "json" => Ok(Self::Json),
            "toml" => Ok(Self::Toml),
            "env" => Ok(Self::Env),
            other => Err(OpError::new(
                codes::INVALID_ARGS,
                format!("format 只能是 auto | toml | json | env，收到 `{other}`"),
            )),
        }
    }
}

/// 中性结构树：**只留类型与键名**，不留任何标量值。
#[derive(Debug)]
pub(super) enum Node {
    Scalar(&'static str),
    Array(Vec<Node>),
    Object(BTreeMap<String, Node>),
}

impl Node {
    fn type_name(&self) -> &'static str {
        match self {
            Self::Scalar(name) => name,
            Self::Array(_) => "array",
            Self::Object(_) => "table",
        }
    }

    fn root_name(&self) -> &'static str {
        match self {
            Self::Scalar(_) => "scalar",
            Self::Array(_) => "array",
            Self::Object(_) => "object",
        }
    }

    fn leaf_count(&self) -> usize {
        match self {
            Self::Scalar(_) => 1,
            Self::Array(items) => items.iter().map(Self::leaf_count).sum(),
            Self::Object(map) => map.values().map(Self::leaf_count).sum(),
        }
    }

    /// 点分路径查找：对象按键名、数组按数字下标。
    fn lookup(&self, selector: &str) -> Option<&Node> {
        let mut current = self;
        for segment in selector.split('.') {
            current = match current {
                Self::Object(map) => map.get(segment)?,
                Self::Array(items) => items.get(segment.parse::<usize>().ok()?)?,
                Self::Scalar(_) => return None,
            };
        }
        Some(current)
    }
}

#[derive(Debug)]
pub(super) enum ParseFailure {
    Syntax {
        line: Option<usize>,
        column: Option<usize>,
    },
    NotUtf8,
    TooLarge,
}

impl ParseFailure {
    /// 人读的说明。**只包含行列与类别**，不回放原文（原文可能就是口令）。
    pub(super) fn describe(&self) -> String {
        match self {
            Self::Syntax {
                line: Some(line),
                column: Some(column),
            } => format!("第 {line} 行第 {column} 列解析失败"),
            Self::Syntax { line, column } => {
                format!("解析失败（line={line:?}, column={column:?}）")
            }
            Self::NotUtf8 => "内容不是合法 UTF-8".to_string(),
            Self::TooLarge => format!("文件超过 {MAX_CONFIG_BYTES} 字节"),
        }
    }

    fn to_json(&self) -> Value {
        match self {
            Self::Syntax { line, column } => {
                json!({ "kind": "syntax", "line": line, "column": column })
            }
            Self::NotUtf8 => json!({ "kind": "not_utf8" }),
            Self::TooLarge => json!({ "kind": "too_large", "limit_bytes": MAX_CONFIG_BYTES }),
        }
    }
}

/// 字节偏移 → (行, 列)，1 基。TOML 只给 span，不给行列。
fn line_col(text: &str, offset: usize) -> (usize, usize) {
    let mut line = 1usize;
    let mut column = 1usize;
    for (index, ch) in text.char_indices() {
        if index >= offset {
            break;
        }
        if ch == '\n' {
            line += 1;
            column = 1;
        } else {
            column += 1;
        }
    }
    (line, column)
}

fn from_json(value: &serde_json::Value) -> Node {
    match value {
        serde_json::Value::Null => Node::Scalar("null"),
        serde_json::Value::Bool(_) => Node::Scalar("boolean"),
        serde_json::Value::Number(number) => {
            if number.is_f64() {
                Node::Scalar("float")
            } else {
                Node::Scalar("integer")
            }
        }
        serde_json::Value::String(_) => Node::Scalar("string"),
        serde_json::Value::Array(items) => Node::Array(items.iter().map(from_json).collect()),
        serde_json::Value::Object(map) => Node::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), from_json(value)))
                .collect(),
        ),
    }
}

fn from_toml(value: &toml::Value) -> Node {
    match value {
        toml::Value::String(_) => Node::Scalar("string"),
        toml::Value::Integer(_) => Node::Scalar("integer"),
        toml::Value::Float(_) => Node::Scalar("float"),
        toml::Value::Boolean(_) => Node::Scalar("boolean"),
        toml::Value::Datetime(_) => Node::Scalar("datetime"),
        toml::Value::Array(items) => Node::Array(items.iter().map(from_toml).collect()),
        toml::Value::Table(map) => Node::Object(
            map.iter()
                .map(|(key, value)| (key.clone(), from_toml(value)))
                .collect(),
        ),
    }
}

/// `KEY=VALUE` 行（支持 `export ` 前缀与 `#` 注释）。值一律是字符串。
fn parse_env(text: &str) -> Result<Node, ParseFailure> {
    let mut map: BTreeMap<String, Node> = BTreeMap::new();
    for (index, raw) in text.lines().enumerate() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let line = line.strip_prefix("export ").unwrap_or(line).trim();
        let Some((key, _value)) = line.split_once('=') else {
            return Err(ParseFailure::Syntax {
                line: Some(index + 1),
                column: None,
            });
        };
        let key = key.trim();
        if key.is_empty() || key.chars().any(char::is_whitespace) {
            return Err(ParseFailure::Syntax {
                line: Some(index + 1),
                column: None,
            });
        }
        map.insert(key.to_string(), Node::Scalar("string"));
    }
    Ok(Node::Object(map))
}

pub(super) fn parse_as(format: Format, text: &str) -> Result<Node, ParseFailure> {
    match format {
        Format::Json => serde_json::from_str::<serde_json::Value>(text)
            .map(|value| from_json(&value))
            .map_err(|err| ParseFailure::Syntax {
                line: Some(err.line()),
                column: Some(err.column()),
            }),
        Format::Toml => toml::from_str::<toml::Value>(text)
            .map(|value| from_toml(&value))
            .map_err(|err| {
                let (line, column) = err
                    .span()
                    .map(|span| line_col(text, span.start))
                    .map(|(line, column)| (Some(line), Some(column)))
                    .unwrap_or((None, None));
                ParseFailure::Syntax { line, column }
            }),
        Format::Env => parse_env(text),
    }
}

/// 扩展名 → 已知格式。认不出就是 `None`（**不猜**：`nginx.conf` 不是 toml）。
pub(super) fn format_from_extension(path: &Path) -> Option<Format> {
    match path
        .extension()
        .map(|ext| ext.to_string_lossy().to_ascii_lowercase())
        .as_deref()
    {
        Some("json") => Some(Format::Json),
        Some("toml") => Some(Format::Toml),
        Some("env") => Some(Format::Env),
        _ => None,
    }
}

/// `auto`：先看扩展名，再按 json → toml → env 依次试。
///
/// 返回第一个能解析的格式；都不行就返回候选里的第一个（附上它的错误），
/// **不**把三次错误混在一起报。
fn detect_and_parse(path: &Path, text: &str) -> (Format, Result<Node, ParseFailure>) {
    let mut candidates: Vec<Format> = Vec::new();
    if let Some(format) = format_from_extension(path) {
        candidates.push(format);
    }
    for format in [Format::Json, Format::Toml, Format::Env] {
        if !candidates.contains(&format) {
            candidates.push(format);
        }
    }

    let mut first_error: Option<(Format, ParseFailure)> = None;
    for format in candidates {
        match parse_as(format, text) {
            Ok(node) => return (format, Ok(node)),
            Err(failure) => {
                if first_error.is_none() {
                    first_error = Some((format, failure));
                }
            }
        }
    }
    match first_error {
        Some((format, failure)) => (format, Err(failure)),
        // 候选最少有三个，走不到这里；保底也给一个可解释的错误。
        None => (
            Format::Json,
            Err(ParseFailure::Syntax {
                line: None,
                column: None,
            }),
        ),
    }
}

fn validate_selectors(selectors: Option<Vec<String>>) -> Result<Vec<String>, OpError> {
    let selectors = selectors.unwrap_or_default();
    if selectors.len() > MAX_SELECTORS {
        return Err(OpError::new(
            codes::INVALID_ARGS,
            format!("selectors 最多 {MAX_SELECTORS} 条"),
        ));
    }
    for selector in &selectors {
        if selector.trim().is_empty() {
            return Err(OpError::new(codes::INVALID_ARGS, "selector 不能为空"));
        }
        if selector.chars().count() > MAX_SELECTOR_CHARS {
            return Err(OpError::new(
                codes::INVALID_ARGS,
                format!("selector 超过 {MAX_SELECTOR_CHARS} 个字符"),
            ));
        }
        if selector.split('.').any(str::is_empty) {
            return Err(OpError::new(
                codes::INVALID_ARGS,
                format!("selector `{selector}` 有空段（形如 `server.tls.enabled`）"),
            ));
        }
    }
    Ok(selectors)
}

fn inspect(input: &OpInput<'_>) -> Result<OpOutput, OpError> {
    let args: InspectArgs = parse_args(input.args)?;
    let selectors = validate_selectors(args.selectors)?;
    let requested = args.format.as_deref().unwrap_or("auto");
    let explicit = if requested == "auto" {
        None
    } else {
        Some(Format::parse(requested)?)
    };

    let path = resolve_allowed(&args.path, input.allow_paths)?;
    let (file, metadata) = open_regular(&path)?;
    let size = metadata.len();

    let mut raw = Vec::new();
    file.take(MAX_CONFIG_BYTES + 1)
        .read_to_end(&mut raw)
        .map_err(|err| OpError::new(codes::OP_FAILED, format!("读取失败：{err}")))?;

    let (format, parsed) = if raw.len() as u64 > MAX_CONFIG_BYTES {
        (
            explicit.unwrap_or(Format::Json),
            Err(ParseFailure::TooLarge),
        )
    } else {
        match String::from_utf8(raw) {
            Err(_) => (explicit.unwrap_or(Format::Json), Err(ParseFailure::NotUtf8)),
            Ok(text) => match explicit {
                Some(format) => (format, parse_as(format, &text)),
                None => detect_and_parse(&path, &text),
            },
        }
    };

    let (ok, error, tree) = match parsed {
        Ok(node) => (true, Value::Null, Some(node)),
        Err(failure) => (false, failure.to_json(), None),
    };

    let top_level_keys = match tree.as_ref() {
        Some(Node::Object(map)) => {
            let mut keys: Vec<&String> = map.keys().collect();
            keys.truncate(MAX_TOP_KEYS);
            keys.into_iter().cloned().collect::<Vec<_>>()
        }
        _ => Vec::new(),
    };
    let selected: Vec<Value> = selectors
        .iter()
        .map(
            |selector| match tree.as_ref().and_then(|node| node.lookup(selector)) {
                Some(node) => json!({
                    "selector": selector,
                    "found": true,
                    "value_type": node.type_name(),
                }),
                None => json!({ "selector": selector, "found": false, "value_type": null }),
            },
        )
        .collect();

    Ok(OpOutput {
        value: json!({
            "schema": SCHEMA,
            "path": args.path,
            "canonical": path.display().to_string(),
            "size_bytes": size,
            "format_requested": requested,
            "format_detected": format.id(),
            "parsed": ok,
            "error": error,
            "root": tree.as_ref().map(Node::root_name),
            "top_level_keys": top_level_keys,
            "top_level_keys_truncated": tree
                .as_ref()
                .and_then(|node| match node {
                    Node::Object(map) => Some(map.len() > MAX_TOP_KEYS),
                    _ => None,
                })
                .unwrap_or(false),
            "leaf_count": tree.as_ref().map(Node::leaf_count),
            "selected": selected,
            "notes": [
                "不回传配置值：要取值请用 file.read_range（同样受 allow.paths 约束）",
                "selector 是点分路径；键名本身含 `.` 的无法寻址",
            ],
        }),
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::PathBuf;
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_dir(name: &str) -> PathBuf {
        let suffix = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let dir = std::env::temp_dir().join(format!("wist-config-opcode-{name}-{suffix}"));
        fs::create_dir_all(&dir).expect("create temp dir");
        dir
    }

    fn input<'a>(args: &'a serde_json::Value, allow: &'a [String]) -> OpInput<'a> {
        OpInput {
            args,
            requested_by: "tester",
            config: None,
            allow_paths: allow,
            budget: INSPECT_SPEC.budget,
            step_timeout_ms: 60_000,
            backups: None,
        }
    }

    /// 结果里**任何地方**都不许出现这些值。
    fn assert_no_values(value: &Value, secrets: &[&str]) {
        let text = serde_json::to_string(value).expect("serialize");
        for secret in secrets {
            assert!(
                !text.contains(secret),
                "结果里出现了配置值 {secret:?}：{text}"
            );
        }
    }

    #[test]
    fn a_json_config_reports_structure_and_selector_types_only() {
        let dir = temp_dir("json");
        let file = dir.join("app.json");
        fs::write(
            &file,
            r#"{"server": {"port": 8080, "host": "0.0.0.0"}, "token": "hunter2-secret", "flags": [true, false]}"#,
        )
        .expect("write");
        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({
            "path": file.display().to_string(),
            "selectors": ["server.port", "flags.1", "token", "nope.deep"],
        });

        let out = inspect(&input(&args, &allow)).expect("inspect");
        let value = &out.value;
        assert_eq!(value["format_detected"], "json");
        assert_eq!(value["parsed"], true);
        assert!(value["error"].is_null());
        assert_eq!(value["root"], "object");
        assert_eq!(
            value["top_level_keys"],
            serde_json::json!(["flags", "server", "token"])
        );
        // server.port / server.host / token / flags.0 / flags.1 = 5 个叶子
        assert_eq!(value["leaf_count"], 5);

        let selected = value["selected"].as_array().expect("selected");
        assert_eq!(selected[0]["selector"], "server.port");
        assert_eq!(selected[0]["found"], true);
        assert_eq!(selected[0]["value_type"], "integer");
        assert_eq!(selected[1]["value_type"], "boolean");
        assert_eq!(selected[2]["value_type"], "string");
        assert_eq!(selected[3]["found"], false);
        assert!(selected[3]["value_type"].is_null());

        assert_no_values(value, &["hunter2-secret", "8080", "0.0.0.0"]);
    }

    #[test]
    fn a_toml_config_is_detected_and_parsed() {
        let dir = temp_dir("toml");
        let file = dir.join("app.toml");
        fs::write(
            &file,
            "[server]\nport = 8080\n\n[server.tls]\nenabled = true\n\n[[workers]]\nname = \"w1\"\n",
        )
        .expect("write");
        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({
            "path": file.display().to_string(),
            "selectors": ["server.tls.enabled", "workers.0.name", "workers.1.name"],
        });

        let out = inspect(&input(&args, &allow)).expect("inspect");
        let value = &out.value;
        assert_eq!(value["format_detected"], "toml");
        assert_eq!(value["parsed"], true);
        assert_eq!(
            value["top_level_keys"],
            serde_json::json!(["server", "workers"])
        );
        let selected = value["selected"].as_array().expect("selected");
        assert_eq!(selected[0]["value_type"], "boolean");
        assert_eq!(selected[1]["value_type"], "string");
        assert_eq!(selected[2]["found"], false);
        assert_no_values(value, &["8080", "w1"]);
    }

    #[test]
    fn a_syntax_error_gives_line_and_column_without_the_offending_line() {
        let dir = temp_dir("syntax");
        let file = dir.join("broken.toml");
        fs::write(&file, "[server\npassword = \"hunter2-secret\"\n").expect("write");
        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({ "path": file.display().to_string(), "format": "toml" });

        let out = inspect(&input(&args, &allow)).expect("inspect");
        let value = &out.value;
        assert_eq!(value["parsed"], false);
        assert_eq!(value["error"]["kind"], "syntax");
        assert!(value["error"]["line"].as_u64().is_some(), "{value}");
        assert!(value["top_level_keys"].as_array().expect("keys").is_empty());
        assert!(value["leaf_count"].is_null());
        assert_no_values(value, &["hunter2-secret", "password"]);
    }

    #[test]
    fn env_files_report_keys_as_string_leaves() {
        let dir = temp_dir("env");
        let file = dir.join("app.env");
        fs::write(
            &file,
            "# comment\n\nDB_PASSWORD=hunter2-secret\nexport PORT=8080\n",
        )
        .expect("write");
        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({
            "path": file.display().to_string(),
            "selectors": ["DB_PASSWORD"],
        });

        let out = inspect(&input(&args, &allow)).expect("inspect");
        let value = &out.value;
        assert_eq!(value["format_detected"], "env");
        assert_eq!(value["parsed"], true);
        assert_eq!(
            value["top_level_keys"],
            serde_json::json!(["DB_PASSWORD", "PORT"])
        );
        assert_eq!(value["leaf_count"], 2);
        assert_eq!(value["selected"][0]["value_type"], "string");
        assert_no_values(value, &["hunter2-secret", "8080"]);
    }

    #[test]
    fn an_env_line_without_equals_is_a_syntax_error_with_a_line_number() {
        let dir = temp_dir("env-broken");
        let file = dir.join("broken.env");
        fs::write(&file, "OK=1\nthis is not a pair\n").expect("write");
        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({ "path": file.display().to_string(), "format": "env" });

        let out = inspect(&input(&args, &allow)).expect("inspect");
        assert_eq!(out.value["parsed"], false);
        assert_eq!(out.value["error"]["kind"], "syntax");
        assert_eq!(out.value["error"]["line"], 2);
    }

    #[test]
    fn an_unparseable_auto_file_reports_the_first_candidate_error() {
        let dir = temp_dir("auto-broken");
        let file = dir.join("weird.conf");
        fs::write(&file, "not json, not toml, not env\n").expect("write");
        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({ "path": file.display().to_string() });

        let out = inspect(&input(&args, &allow)).expect("inspect");
        assert_eq!(out.value["parsed"], false);
        assert_eq!(out.value["format_requested"], "auto");
        assert_eq!(out.value["error"]["kind"], "syntax");
        // auto 会试三种；失败时报第一种（json）的行列，不混着报。
        assert_eq!(out.value["format_detected"], "json");
    }

    #[test]
    fn oversized_and_non_utf8_files_are_classified_not_parsed() {
        let dir = temp_dir("bad-input");
        let allow = vec![dir.display().to_string()];

        let big = dir.join("big.toml");
        fs::write(&big, vec![b'a'; (MAX_CONFIG_BYTES + 10) as usize]).expect("write big");
        let args = serde_json::json!({ "path": big.display().to_string() });
        let out = inspect(&input(&args, &allow)).expect("inspect");
        assert_eq!(out.value["parsed"], false);
        assert_eq!(out.value["error"]["kind"], "too_large");

        let binary = dir.join("bin.toml");
        fs::write(&binary, [0xff, 0xfe, 0x00]).expect("write binary");
        let args = serde_json::json!({ "path": binary.display().to_string() });
        let out = inspect(&input(&args, &allow)).expect("inspect");
        assert_eq!(out.value["parsed"], false);
        assert_eq!(out.value["error"]["kind"], "not_utf8");
    }

    #[test]
    fn allow_list_format_and_selectors_are_all_closed_sets() {
        let dir = temp_dir("validation");
        let file = dir.join("a.json");
        fs::write(&file, "{}").expect("write");
        let path = file.display().to_string();

        // 没有白名单：一律拒。
        let args = serde_json::json!({ "path": path });
        let err = inspect(&input(&args, &[])).expect_err("no allow");
        assert_eq!(err.code, codes::PATH_NOT_ALLOWED);

        let allow = vec![dir.display().to_string()];
        let args = serde_json::json!({ "path": path, "format": "yaml" });
        let err = inspect(&input(&args, &allow)).expect_err("bad format");
        assert_eq!(err.code, codes::INVALID_ARGS);

        for bad in [serde_json::json!([""]), serde_json::json!(["a..b"])] {
            let args = serde_json::json!({ "path": path, "selectors": bad });
            let err = inspect(&input(&args, &allow)).expect_err("bad selector");
            assert_eq!(err.code, codes::INVALID_ARGS);
        }

        let args = serde_json::json!({ "path": dir.display().to_string() });
        let err = inspect(&input(&args, &allow)).expect_err("directory");
        assert_eq!(err.code, codes::INVALID_ARGS);
    }

    #[test]
    fn op_metadata_is_a_read_only_r1() {
        assert_eq!(INSPECT_SPEC.risk, RiskLevel::R1);
        assert_eq!(INSPECT_SPEC.id, "config.inspect");
    }
}
