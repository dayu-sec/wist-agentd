//! Agent 配置的接线级校验测试：fixture 反序列化 → `validate_config`。
//!
//! 配置类型（`config::agent_config`）与校验入口（`config::validate`）都住在
//! 本 crate，因此这组用例随之从 `wist-validate` 一并归位。

use std::fs;
use std::path::PathBuf;

use wist_agentd::config::agent_config::{
    AgentConfig, AgentSection, ControlPlaneSection, DiscoverySection, ExecutionSection,
    LogFileInputSection, LogsFileOutputSection, LogsOutputSection, LogsSection,
    LogsTcpOutputSection, PathsSection, TelemetrySection,
};
use wist_agentd::config::validate::validate_config;

fn fixture_text(relative: &str) -> String {
    let path = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures")
        .join(relative);
    fs::read_to_string(path).expect("read fixture")
}

fn config_fixture(relative: &str) -> AgentConfig {
    toml::from_str(&fixture_text(relative)).expect("deserialize config fixture")
}

#[test]
fn config_valid_fixture_passes() {
    let fixture = config_fixture("contracts/config/valid/standalone.toml");

    validate_config(&fixture).expect("valid config");
}

#[test]
fn config_invalid_fixture_fails() {
    let fixture = config_fixture("contracts/config/invalid/managed-missing-endpoint.toml");

    let err = validate_config(&fixture).expect_err("invalid config");
    assert_eq!(err.code, "missing_control_plane_endpoint");
}

/// 契约收口（2026-09-30）：`control_plane` 不再有 `bearer_token` 字段 ——
/// 带它的配置应当**解不出来**（`deny_unknown_fields`），而不是静默忽略。
#[test]
fn control_plane_with_a_legacy_bearer_token_is_rejected() {
    let text = r#"
schema_version = "v1"

[agent]
environment_id = "prod"
instance_name = "instance-001"

[control_plane]
enabled = false
endpoint = "https://control.local"
bearer_token = "wic_legacy"

[paths]
root_dir = "/tmp/root"
run_dir = "run"
state_dir = "state"
log_dir = "log"

[execution]
max_running_actions = 1
cancel_grace_ms = 5000
default_stdout_limit_bytes = 1048576
default_stderr_limit_bytes = 1048576

[telemetry.logs]
spool_dir = "state/spool/logs"

[telemetry.logs.output]
kind = "file"

[telemetry.logs.output.file]
path = "log/out.ndjson"
"#;

    let decoded = toml::from_str::<AgentConfig>(text);
    assert!(
        decoded.is_err(),
        "带 bearer_token 的旧配置必须被拒（字段已删）"
    );
}

#[test]
fn config_with_more_than_one_running_action_is_rejected() {
    let fixture = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-001".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-001".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: "/tmp/root".to_string(),
            run_dir: "/tmp/root/run".to_string(),
            state_dir: "/tmp/root/state".to_string(),
            log_dir: "/tmp/root/log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 2,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1024,
            default_stderr_limit_bytes: 1024,
        },
    );

    let err = validate_config(&fixture).expect_err("config should be rejected");
    assert_eq!(err.code, "unsupported_max_running_actions");
}

#[test]
fn config_with_all_discovery_probes_disabled_is_rejected() {
    let mut fixture = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-001".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-001".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: "/tmp/root".to_string(),
            run_dir: "/tmp/root/run".to_string(),
            state_dir: "/tmp/root/state".to_string(),
            log_dir: "/tmp/root/log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1024,
            default_stderr_limit_bytes: 1024,
        },
    );
    fixture.discovery = DiscoverySection {
        host_enabled: false,
        network_enabled: false,
        endpoint_enabled: false,
        process_enabled: false,
        container_enabled: false,
        snapshot_uplink_enabled: false,
        snapshot_uplink_interval_seconds: 300,
    };

    let err = validate_config(&fixture).expect_err("config should be rejected");
    assert_eq!(err.code, "missing_discovery_probe");
}

#[test]
fn config_with_duplicate_log_input_ids_is_rejected() {
    let fixture = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-001".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-001".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: "/tmp/root".to_string(),
            run_dir: "/tmp/root/run".to_string(),
            state_dir: "/tmp/root/state".to_string(),
            log_dir: "/tmp/root/log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1024,
            default_stderr_limit_bytes: 1024,
        },
    )
    .with_telemetry(TelemetrySection {
        logs: LogsSection {
            file_inputs: vec![
                LogFileInputSection {
                    input_id: "app".to_string(),
                    path: "/tmp/root/app.log".to_string(),
                    startup_position: "head".to_string(),
                    multiline_mode: "none".to_string(),
                    exclude_globs: Vec::new(),
                    filters: Default::default(),
                    drop_if_contains: Vec::new(),
                },
                LogFileInputSection {
                    input_id: "app".to_string(),
                    path: "/tmp/root/other.log".to_string(),
                    startup_position: "head".to_string(),
                    multiline_mode: "none".to_string(),
                    exclude_globs: Vec::new(),
                    filters: Default::default(),
                    drop_if_contains: Vec::new(),
                },
            ],
            file_inputs_file: None,
            max_line_bytes: 1_048_576,
            max_read_bytes_per_tick: 4_194_304,
            max_lines_per_tick: 4096,
            spool_max_bytes: 268_435_456,
            spool_over_limit: "pause".to_string(),
            in_memory_buffer_bytes: 1024,
            spool_dir: "/tmp/root/state/spool/logs".to_string(),
            output: LogsOutputSection {
                kind: "file".to_string(),
                file: LogsFileOutputSection {
                    path: "/tmp/root/log/records.ndjson".to_string(),
                },
                ..LogsOutputSection::default()
            },
        },
    });

    let err = validate_config(&fixture).expect_err("config should be rejected");
    assert_eq!(err.code, "duplicate_log_input_id");
}

#[test]
fn config_with_invalid_log_startup_position_is_rejected() {
    let fixture = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-001".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-001".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: "/tmp/root".to_string(),
            run_dir: "/tmp/root/run".to_string(),
            state_dir: "/tmp/root/state".to_string(),
            log_dir: "/tmp/root/log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1024,
            default_stderr_limit_bytes: 1024,
        },
    )
    .with_telemetry(TelemetrySection {
        logs: LogsSection {
            file_inputs: vec![LogFileInputSection {
                input_id: "app".to_string(),
                path: "/tmp/root/app.log".to_string(),
                startup_position: "middle".to_string(),
                multiline_mode: "none".to_string(),
                exclude_globs: Vec::new(),
                filters: Default::default(),
                drop_if_contains: Vec::new(),
            }],
            file_inputs_file: None,
            max_line_bytes: 1_048_576,
            max_read_bytes_per_tick: 4_194_304,
            max_lines_per_tick: 4096,
            spool_max_bytes: 268_435_456,
            spool_over_limit: "pause".to_string(),
            in_memory_buffer_bytes: 1024,
            spool_dir: "/tmp/root/state/spool/logs".to_string(),
            output: LogsOutputSection {
                kind: "file".to_string(),
                file: LogsFileOutputSection {
                    path: "/tmp/root/log/records.ndjson".to_string(),
                },
                ..LogsOutputSection::default()
            },
        },
    });

    let err = validate_config(&fixture).expect_err("config should be rejected");
    assert_eq!(err.code, "invalid_log_startup_position");
}

#[test]
fn config_with_invalid_log_spool_over_limit_is_rejected() {
    let fixture = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-001".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-001".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: "/tmp/root".to_string(),
            run_dir: "/tmp/root/run".to_string(),
            state_dir: "/tmp/root/state".to_string(),
            log_dir: "/tmp/root/log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1024,
            default_stderr_limit_bytes: 1024,
        },
    )
    .with_telemetry(TelemetrySection {
        logs: LogsSection {
            file_inputs: vec![LogFileInputSection {
                input_id: "app".to_string(),
                path: "/tmp/root/app.log".to_string(),
                startup_position: "head".to_string(),
                multiline_mode: "none".to_string(),
                exclude_globs: Vec::new(),
                filters: Default::default(),
                drop_if_contains: Vec::new(),
            }],
            file_inputs_file: None,
            max_line_bytes: 1_048_576,
            max_read_bytes_per_tick: 4_194_304,
            max_lines_per_tick: 4096,
            spool_max_bytes: 268_435_456,
            spool_over_limit: "grow".to_string(),
            in_memory_buffer_bytes: 1024,
            spool_dir: "/tmp/root/state/spool/logs".to_string(),
            output: LogsOutputSection {
                kind: "file".to_string(),
                file: LogsFileOutputSection {
                    path: "/tmp/root/log/records.ndjson".to_string(),
                },
                ..LogsOutputSection::default()
            },
        },
    });

    let err = validate_config(&fixture).expect_err("config should be rejected");
    assert_eq!(err.code, "invalid_logs_spool_over_limit");
}

#[test]
fn config_with_drop_oldest_spool_over_limit_is_rejected() {
    let mut fixture = config_fixture("contracts/config/valid/standalone.toml");
    fixture.telemetry.logs.spool_over_limit = "drop_oldest".to_string();

    let err = validate_config(&fixture).expect_err("drop_oldest should be rejected");
    assert_eq!(err.code, "invalid_logs_spool_over_limit");
}

#[test]
fn config_with_zero_spool_max_bytes_is_rejected() {
    let mut fixture = config_fixture("contracts/config/valid/standalone.toml");
    fixture.telemetry.logs.spool_max_bytes = 0;

    let err = validate_config(&fixture).expect_err("zero spool_max_bytes should be rejected");
    assert_eq!(err.code, "invalid_logs_spool_max_bytes");
}

#[test]
fn config_with_zero_max_line_bytes_is_rejected() {
    let mut fixture = config_fixture("contracts/config/valid/standalone.toml");
    fixture.telemetry.logs.max_line_bytes = 0;

    let err = validate_config(&fixture).expect_err("zero max_line_bytes should be rejected");
    assert_eq!(err.code, "invalid_logs_max_line_bytes");
}

#[test]
fn config_with_zero_max_read_bytes_per_tick_is_rejected() {
    let mut fixture = config_fixture("contracts/config/valid/standalone.toml");
    fixture.telemetry.logs.max_read_bytes_per_tick = 0;

    let err =
        validate_config(&fixture).expect_err("zero max_read_bytes_per_tick should be rejected");
    assert_eq!(err.code, "invalid_logs_max_read_bytes_per_tick");
}

#[test]
fn config_with_zero_max_lines_per_tick_is_rejected() {
    let mut fixture = config_fixture("contracts/config/valid/standalone.toml");
    fixture.telemetry.logs.max_lines_per_tick = 0;

    let err = validate_config(&fixture).expect_err("zero max_lines_per_tick should be rejected");
    assert_eq!(err.code, "invalid_logs_max_lines_per_tick");
}

#[test]
fn config_with_invalid_tcp_output_framing_is_rejected() {
    let fixture = AgentConfig::new(
        AgentSection {
            agent_id: Some("agent-001".to_string()),
            environment_id: Some("prod".to_string()),
            instance_name: Some("instance-001".to_string()),
        },
        ControlPlaneSection {
            enabled: false,
            endpoint: None,
            enrollment_token: None,
            credential_request: None,
            credential_id: None,
            credential_expires_at: None,
            tls_mode: None,
            trust_bundle: None,
            auth_mode: None,
        },
        PathsSection {
            root_dir: "/tmp/root".to_string(),
            run_dir: "/tmp/root/run".to_string(),
            state_dir: "/tmp/root/state".to_string(),
            log_dir: "/tmp/root/log".to_string(),
        },
        ExecutionSection {
            max_running_actions: 1,
            cancel_grace_ms: 5_000,
            default_stdout_limit_bytes: 1024,
            default_stderr_limit_bytes: 1024,
        },
    )
    .with_telemetry(TelemetrySection {
        logs: LogsSection {
            file_inputs: vec![LogFileInputSection {
                input_id: "app".to_string(),
                path: "/tmp/root/app.log".to_string(),
                startup_position: "head".to_string(),
                multiline_mode: "none".to_string(),
                exclude_globs: Vec::new(),
                filters: Default::default(),
                drop_if_contains: Vec::new(),
            }],
            file_inputs_file: None,
            max_line_bytes: 1_048_576,
            max_read_bytes_per_tick: 4_194_304,
            max_lines_per_tick: 4096,
            spool_max_bytes: 268_435_456,
            spool_over_limit: "pause".to_string(),
            in_memory_buffer_bytes: 1024,
            spool_dir: "/tmp/root/state/spool/logs".to_string(),
            output: LogsOutputSection {
                kind: "tcp".to_string(),
                tcp: LogsTcpOutputSection {
                    addr: "127.0.0.1".to_string(),
                    port: 9000,
                    framing: "auto".to_string(),
                },
                ..LogsOutputSection::default()
            },
        },
    });

    let err = validate_config(&fixture).expect_err("config should be rejected");
    assert_eq!(err.code, "invalid_logs_output_tcp_framing");
}

/// 容器过滤器（W2）的接线校验：**名字是精确值、且只许用在容器选源根下**。
///
/// 与网关装载期同一口径：本机直配的输入写错了同样会「一个都匹配不上」，
/// 与其在运行时静默空载，不如在配置校验阶段就拒绝。
fn container_input(
    path: &str,
    filters: wist_contracts::work::ContainerFilters,
) -> LogFileInputSection {
    LogFileInputSection {
        input_id: "containers".to_string(),
        path: path.to_string(),
        startup_position: "head".to_string(),
        multiline_mode: "none".to_string(),
        exclude_globs: Vec::new(),
        filters,
        drop_if_contains: Vec::new(),
    }
}

fn config_with_input(input: LogFileInputSection) -> AgentConfig {
    let mut fixture = config_fixture("contracts/config/valid/standalone.toml");
    fixture.telemetry.logs.file_inputs = vec![input];
    fixture
}

#[test]
fn container_filters_are_accepted_under_the_container_root() {
    let config = config_with_input(container_input(
        "/var/log/containers/*.log",
        wist_contracts::work::ContainerFilters {
            namespace_in: vec!["prod".to_string()],
            pod_not_in: vec!["debug-pod".to_string()],
            ..Default::default()
        },
    ));
    validate_config(&config).expect("container filters with a container source");
}

#[test]
fn container_filters_are_rejected_off_the_container_root() {
    let config = config_with_input(container_input(
        "/var/log/postgresql/*.log",
        wist_contracts::work::ContainerFilters {
            namespace_in: vec!["prod".to_string()],
            pod_not_in: Vec::new(),
            ..Default::default()
        },
    ));
    let err = validate_config(&config).expect_err("filters off the container root");
    assert_eq!(err.code, "invalid_log_input_container_filters");
}

#[test]
fn container_name_filters_are_accepted_on_docker_sources() {
    // name 维度不靠 k8s 文件名：纯 Docker 载体（名字在 `config.v2.json`）也必须能通过
    // 本机配置校验。以前“有任一 filters 就必须在 /var/log/containers 下”会让同一份配置
    // 在网关派活可用、搬到本机配置却被拒。
    for path in [
        "/var/lib/docker/containers/*/*-json.log*",
        "/var/lib/docker/containers",
        "/var/log/containers",
    ] {
        let config = config_with_input(container_input(
            path,
            wist_contracts::work::ContainerFilters {
                name_in: vec!["mysql".to_string()],
                name_not_in: vec!["fluent-bit".to_string()],
                ..Default::default()
            },
        ));
        validate_config(&config).unwrap_or_else(|err| panic!("{path}: {}", err.code));
    }

    // 非容器路径仍然拒（过滤器写在别处只会“一个都匹配不上”）。
    let config = config_with_input(container_input(
        "/var/log/mysql/slow.log",
        wist_contracts::work::ContainerFilters {
            name_in: vec!["mysql".to_string()],
            ..Default::default()
        },
    ));
    let err = validate_config(&config).expect_err("name filters off a container source");
    assert_eq!(err.code, "invalid_log_input_container_filters");

    // k8s 维度写在 Docker 根目录上仍然拒（那里没有 pod/namespace 语义）。
    let config = config_with_input(container_input(
        "/var/lib/docker/containers/*/*-json.log*",
        wist_contracts::work::ContainerFilters {
            namespace_in: vec!["prod".to_string()],
            ..Default::default()
        },
    ));
    let err = validate_config(&config).expect_err("k8s dimension on a docker source");
    assert_eq!(err.code, "invalid_log_input_container_filters");
}

#[test]
fn container_filters_reject_pattern_values() {
    // 过滤器存的是**精确名字**：`prod*` 永远匹配不上（那是 pattern 的写法）。
    let config = config_with_input(container_input(
        "/var/log/containers/*.log",
        wist_contracts::work::ContainerFilters {
            namespace_in: vec!["prod*".to_string()],
            pod_not_in: Vec::new(),
            ..Default::default()
        },
    ));
    let err = validate_config(&config).expect_err("wildcard filter value");
    assert_eq!(err.code, "invalid_log_input_container_filters");
}
