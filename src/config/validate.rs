//! Config validation entrypoints.

use std::collections::HashSet;

use wist_contracts::SCHEMA_VERSION_V1;

use crate::config::agent_config::{AgentConfig, LogsSection};
use wist_validate::{ValidationError, require_non_empty};

pub fn validate_config(contract: &AgentConfig) -> Result<(), ValidationError> {
    if contract.schema_version != SCHEMA_VERSION_V1 {
        return Err(ValidationError::new("invalid_schema_version"));
    }
    if contract.control_plane.enabled {
        let endpoint = contract
            .control_plane
            .endpoint
            .as_deref()
            .unwrap_or_default();
        require_non_empty(endpoint, "missing_control_plane_endpoint")?;
    }

    require_non_empty(&contract.paths.root_dir, "missing_root_dir")?;
    require_non_empty(&contract.paths.run_dir, "missing_run_dir")?;
    require_non_empty(&contract.paths.state_dir, "missing_state_dir")?;
    require_non_empty(&contract.paths.log_dir, "missing_log_dir")?;

    if contract.execution.max_running_actions == 0 {
        return Err(ValidationError::new("invalid_max_running_actions"));
    }
    if contract.execution.max_running_actions != 1 {
        return Err(ValidationError::new("unsupported_max_running_actions"));
    }
    if contract.execution.cancel_grace_ms == 0 {
        return Err(ValidationError::new("invalid_cancel_grace_ms"));
    }
    if contract.execution.default_stdout_limit_bytes == 0 {
        return Err(ValidationError::new("invalid_stdout_limit"));
    }
    if contract.execution.default_stderr_limit_bytes == 0 {
        return Err(ValidationError::new("invalid_stderr_limit"));
    }
    if !contract.discovery.host_enabled
        && !contract.discovery.network_enabled
        && !contract.discovery.endpoint_enabled
        && !contract.discovery.process_enabled
        && !contract.discovery.container_enabled
    {
        return Err(ValidationError::new("missing_discovery_probe"));
    }

    validate_logs_section(&contract.telemetry.logs)?;

    Ok(())
}

fn validate_logs_section(logs: &LogsSection) -> Result<(), ValidationError> {
    if logs.in_memory_buffer_bytes == 0 {
        return Err(ValidationError::new("invalid_logs_buffer_bytes"));
    }
    require_non_empty(&logs.spool_dir, "missing_logs_spool_dir")?;
    require_non_empty(&logs.output.kind, "missing_logs_output_kind")?;
    match logs.output.kind.as_str() {
        "file" => {
            require_non_empty(&logs.output.file.path, "missing_logs_output_file_path")?;
        }
        "tcp" => {
            require_non_empty(&logs.output.tcp.addr, "missing_logs_output_tcp_addr")?;
            if logs.output.tcp.port == 0 {
                return Err(ValidationError::new("invalid_logs_output_tcp_port"));
            }
            match logs.output.tcp.framing.as_str() {
                "line" | "len" => {}
                _ => return Err(ValidationError::new("invalid_logs_output_tcp_framing")),
            }
        }
        _ => return Err(ValidationError::new("invalid_logs_output_kind")),
    }
    match logs.spool_over_limit.as_str() {
        "pause" => {}
        _ => return Err(ValidationError::new("invalid_logs_spool_over_limit")),
    }
    for (value, code) in [
        (logs.max_line_bytes, "invalid_logs_max_line_bytes"),
        (
            logs.max_read_bytes_per_tick,
            "invalid_logs_max_read_bytes_per_tick",
        ),
        (logs.max_lines_per_tick, "invalid_logs_max_lines_per_tick"),
        (logs.spool_max_bytes, "invalid_logs_spool_max_bytes"),
    ] {
        if value == 0 {
            return Err(ValidationError::new(code));
        }
    }
    let mut input_ids = HashSet::new();
    for input in &logs.file_inputs {
        require_non_empty(&input.input_id, "missing_log_input_id")?;
        require_non_empty(&input.path, "missing_log_input_path")?;
        if !input_ids.insert(input.input_id.as_str()) {
            return Err(ValidationError::new("duplicate_log_input_id"));
        }
        match input.startup_position.as_str() {
            "head" | "tail" => {}
            _ => return Err(ValidationError::new("invalid_log_startup_position")),
        }
        // 读法词表直接取契约（与网关装载期、目录同源）：新增一种读法不该在三处各加一次。
        if !wist_contracts::work::MULTILINE_MODES.contains(&input.multiline_mode.as_str()) {
            return Err(ValidationError::new("invalid_log_multiline_mode"));
        }
        // 排除项是绝对路径 glob：相对路径的结果取决于进程 cwd，同一台机器换一种启动方式
        // 就少采一个文件，那不是配置。
        for exclude in &input.exclude_globs {
            if !exclude.starts_with('/') {
                return Err(ValidationError::new("invalid_log_input_exclude_glob"));
            }
        }
        // 容器过滤器是**精确名字**：空串 / 空白 / 通配符都永远匹配不上，当面拒掉。
        // （这里只能给 code，不带 detail —— `ValidationError` 就是这个形状；
        //   填错的具体原因在网关装载目录时会带着单元 id 报出来。）
        input
            .filters
            .validate()
            .map_err(|_| ValidationError::new("invalid_log_input_container_filters"))?;
        if !input.filters.is_empty() {
            // 维度决定目标形态（与网关装载期同一条口径，本机直配也拦一道）：
            //   * `namespace_in` / `pod_not_in` 靠文件名 `<pod>_<ns>_<container>-<id>.log`
            //     求值 → 只能在 k8s 的 `/var/log/containers` 下；
            //   * `name_in` / `name_not_in` 也支持纯 Docker（名字来自同目录
            //     `config.v2.json`）→ 只要求是容器日志来源的形状（不写死 data-root）。
            // 两者分开判：以前“有任一 filters 就必须在 k8s 根下”会让同一份配置
            // 在网关派活可用、搬到本机配置却被拒。
            let k8s_shape =
                !input.filters.namespace_in.is_empty() || !input.filters.pod_not_in.is_empty();
            let name_shape =
                !input.filters.name_in.is_empty() || !input.filters.name_not_in.is_empty();
            if k8s_shape {
                let root = wist_contracts::work::CONTAINER_LOG_ROOT;
                let under_root = input.path == root || input.path.starts_with(&format!("{root}/"));
                if !under_root {
                    return Err(ValidationError::new("invalid_log_input_container_filters"));
                }
            }
            if name_shape && !wist_contracts::work::is_container_log_target(&input.path) {
                return Err(ValidationError::new("invalid_log_input_container_filters"));
            }
        }
        // 噪音行丢弃：与网关装载期共用同一份形状校验（精确子串、限条数 / 长度）。
        wist_contracts::work::validate_drop_if_contains(&input.drop_if_contains)
            .map_err(|_| ValidationError::new("invalid_log_input_drop_if_contains"))?;
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use crate::config::agent_config::{
        AgentSection, ControlPlaneSection, DiscoverySection, ExecutionSection, LogFileInputSection,
        LogsFileOutputSection, LogsOutputSection, LogsTcpOutputSection, PathsSection,
        TelemetrySection,
    };

    use super::*;

    /// 校验用例：期望错误码 + 对合法样本的破坏性修改。
    type Case<T> = (&'static str, fn(&mut T));

    fn base_config() -> AgentConfig {
        AgentConfig::new(
            AgentSection {
                agent_id: Some("agent-001".to_string()),
                environment_id: Some("prod".to_string()),
                instance_name: Some("instance-001".to_string()),
            },
            ControlPlaneSection {
                enabled: false,
                ..ControlPlaneSection::default()
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
    }

    fn valid_logs() -> LogsSection {
        LogsSection {
            file_inputs: vec![LogFileInputSection {
                input_id: "app".to_string(),
                path: "/tmp/root/app.log".to_string(),
                startup_position: "tail".to_string(),
                multiline_mode: "none".to_string(),
                exclude_globs: Vec::new(),
                filters: Default::default(),
                drop_if_contains: Vec::new(),
            }],
            file_inputs_file: None,
            in_memory_buffer_bytes: 1024,
            max_line_bytes: 1024,
            max_read_bytes_per_tick: 4096,
            max_lines_per_tick: 10,
            spool_max_bytes: 100_000,
            spool_over_limit: "pause".to_string(),
            spool_dir: "/tmp/root/state/spool".to_string(),
            output: LogsOutputSection {
                enabled: true,
                kind: "file".to_string(),
                file: LogsFileOutputSection {
                    path: "/tmp/root/log/records.ndjson".to_string(),
                },
                tcp: LogsTcpOutputSection::default(),
            },
        }
    }

    fn assert_code(result: Result<(), ValidationError>, expected: &'static str) {
        let err = result.expect_err("expected a validation error");
        assert_eq!(err.code, expected);
    }

    #[test]
    fn a_default_config_passes() {
        validate_config(&base_config()).expect("valid default config");
    }

    #[test]
    fn a_config_with_explicit_logs_passes() {
        let config = base_config().with_telemetry(TelemetrySection { logs: valid_logs() });
        validate_config(&config).expect("valid explicit logs config");
    }

    #[test]
    fn schema_version_error_has_stable_code() {
        let mut config = base_config();
        config.schema_version = "v2".to_string();
        assert_code(validate_config(&config), "invalid_schema_version");
    }

    #[test]
    fn enabled_control_plane_requires_endpoint() {
        let mut config = base_config();
        config.control_plane.enabled = true;
        assert_code(validate_config(&config), "missing_control_plane_endpoint");

        let mut config = base_config();
        config.control_plane.enabled = true;
        config.control_plane.endpoint = Some("  ".to_string());
        assert_code(validate_config(&config), "missing_control_plane_endpoint");

        let mut config = base_config();
        config.control_plane.enabled = true;
        config.control_plane.endpoint = Some("https://gw.example".to_string());
        validate_config(&config).expect("enabled control plane with endpoint");
    }

    #[test]
    fn blank_paths_are_rejected() {
        let cases: &[Case<PathsSection>] = &[
            ("missing_root_dir", |paths| paths.root_dir = " ".to_string()),
            ("missing_run_dir", |paths| paths.run_dir = String::new()),
            ("missing_state_dir", |paths| {
                paths.state_dir = "\t".to_string()
            }),
            ("missing_log_dir", |paths| paths.log_dir = String::new()),
        ];
        for &(expected, mutate) in cases {
            let mut config = base_config();
            mutate(&mut config.paths);
            assert_code(validate_config(&config), expected);
        }
    }

    #[test]
    fn execution_concurrency_limit_only_accepts_one() {
        let mut config = base_config();
        config.execution.max_running_actions = 0;
        assert_code(validate_config(&config), "invalid_max_running_actions");

        for value in [2, 3, u32::MAX] {
            let mut config = base_config();
            config.execution.max_running_actions = value;
            assert_code(validate_config(&config), "unsupported_max_running_actions");
        }
    }

    #[test]
    fn execution_timeout_and_limit_errors_have_stable_codes() {
        let cases: &[Case<ExecutionSection>] = &[
            ("invalid_cancel_grace_ms", |exec| exec.cancel_grace_ms = 0),
            ("invalid_stdout_limit", |exec| {
                exec.default_stdout_limit_bytes = 0
            }),
            ("invalid_stderr_limit", |exec| {
                exec.default_stderr_limit_bytes = 0
            }),
        ];
        for &(expected, mutate) in cases {
            let mut config = base_config();
            mutate(&mut config.execution);
            assert_code(validate_config(&config), expected);
        }
    }

    #[test]
    fn config_with_all_discovery_probes_disabled_is_rejected() {
        let mut config = base_config();
        config.discovery = DiscoverySection {
            host_enabled: false,
            network_enabled: false,
            endpoint_enabled: false,
            process_enabled: false,
            container_enabled: false,
        };
        assert_code(validate_config(&config), "missing_discovery_probe");
    }

    #[test]
    fn any_single_discovery_probe_is_enough() {
        let enable: &[fn(&mut DiscoverySection)] = &[
            |d| d.host_enabled = true,
            |d| d.network_enabled = true,
            |d| d.endpoint_enabled = true,
            |d| d.process_enabled = true,
            |d| d.container_enabled = true,
        ];
        for &set_enabled in enable {
            let mut discovery = DiscoverySection {
                host_enabled: false,
                network_enabled: false,
                endpoint_enabled: false,
                process_enabled: false,
                container_enabled: false,
            };
            set_enabled(&mut discovery);
            let mut config = base_config();
            config.discovery = discovery;
            validate_config(&config).expect("one enabled probe is enough");
        }
    }

    #[test]
    fn logs_buffer_and_spool_errors_have_stable_codes() {
        let cases: &[Case<LogsSection>] = &[
            ("invalid_logs_buffer_bytes", |logs| {
                logs.in_memory_buffer_bytes = 0
            }),
            ("missing_logs_spool_dir", |logs| {
                logs.spool_dir = " ".to_string()
            }),
            ("invalid_logs_output_kind", |logs| {
                logs.output.kind = "kafka".to_string()
            }),
            ("missing_logs_output_kind", |logs| {
                logs.output.kind = String::new()
            }),
            ("missing_logs_output_file_path", |logs| {
                logs.output.file.path = " ".to_string()
            }),
            ("invalid_logs_spool_over_limit", |logs| {
                logs.spool_over_limit = "drop_oldest".to_string()
            }),
            ("invalid_logs_max_line_bytes", |logs| {
                logs.max_line_bytes = 0
            }),
            ("invalid_logs_max_read_bytes_per_tick", |logs| {
                logs.max_read_bytes_per_tick = 0
            }),
            ("invalid_logs_max_lines_per_tick", |logs| {
                logs.max_lines_per_tick = 0
            }),
            ("invalid_logs_spool_max_bytes", |logs| {
                logs.spool_max_bytes = 0
            }),
        ];
        for &(expected, mutate) in cases {
            let mut logs = valid_logs();
            mutate(&mut logs);
            let config = base_config().with_telemetry(TelemetrySection { logs });
            assert_code(validate_config(&config), expected);
        }
    }

    #[test]
    fn tcp_output_errors_have_stable_codes() {
        let tcp_logs = || {
            let mut logs = valid_logs();
            logs.output.kind = "tcp".to_string();
            logs
        };

        let mut logs = tcp_logs();
        logs.output.tcp.addr = " ".to_string();
        let config = base_config().with_telemetry(TelemetrySection { logs });
        assert_code(validate_config(&config), "missing_logs_output_tcp_addr");

        let mut logs = tcp_logs();
        logs.output.tcp.port = 0;
        let config = base_config().with_telemetry(TelemetrySection { logs });
        assert_code(validate_config(&config), "invalid_logs_output_tcp_port");

        let mut logs = tcp_logs();
        logs.output.tcp.framing = "auto".to_string();
        let config = base_config().with_telemetry(TelemetrySection { logs });
        assert_code(validate_config(&config), "invalid_logs_output_tcp_framing");

        for framing in ["line", "len"] {
            let mut logs = tcp_logs();
            logs.output.tcp.framing = framing.to_string();
            let config = base_config().with_telemetry(TelemetrySection { logs });
            validate_config(&config).expect("known tcp framing");
        }
    }

    #[test]
    fn file_input_errors_have_stable_codes() {
        let with_inputs = |mutate: fn(&mut LogFileInputSection)| {
            let mut logs = valid_logs();
            mutate(&mut logs.file_inputs[0]);
            base_config().with_telemetry(TelemetrySection { logs })
        };

        assert_code(
            validate_config(&with_inputs(|input| input.input_id = " ".to_string())),
            "missing_log_input_id",
        );
        assert_code(
            validate_config(&with_inputs(|input| input.path = String::new())),
            "missing_log_input_path",
        );
        assert_code(
            validate_config(&with_inputs(|input| {
                input.startup_position = "middle".to_string()
            })),
            "invalid_log_startup_position",
        );
        assert_code(
            validate_config(&with_inputs(|input| {
                input.multiline_mode = "weird".to_string()
            })),
            "invalid_log_multiline_mode",
        );
        assert_code(
            validate_config(&with_inputs(|input| {
                input.exclude_globs = vec!["relative/*.log".to_string()]
            })),
            "invalid_log_input_exclude_glob",
        );
        assert_code(
            validate_config(&with_inputs(|input| {
                input.drop_if_contains = vec![" padded ".to_string()]
            })),
            "invalid_log_input_drop_if_contains",
        );
    }

    #[test]
    fn a_file_family_input_accepts_globs_and_absolute_excludes() {
        let mut logs = valid_logs();
        logs.file_inputs[0].path = "/var/log/containers/*.log".to_string();
        logs.file_inputs[0].exclude_globs =
            vec!["/var/log/containers/*_kube-system_*.log".to_string()];
        let config = base_config().with_telemetry(TelemetrySection { logs });
        validate_config(&config).expect("glob input with excludes");
    }

    #[test]
    fn known_file_input_modes_are_accepted() {
        for startup_position in ["head", "tail"] {
            for multiline_mode in wist_contracts::work::MULTILINE_MODES {
                let mut logs = valid_logs();
                logs.file_inputs[0].startup_position = startup_position.to_string();
                logs.file_inputs[0].multiline_mode = (*multiline_mode).to_string();
                let config = base_config().with_telemetry(TelemetrySection { logs });
                validate_config(&config).expect("known input modes");
            }
        }
    }

    #[test]
    fn noise_needles_are_accepted_when_they_are_exact_substrings() {
        let mut logs = valid_logs();
        logs.file_inputs[0].drop_if_contains = vec![
            "pam_unix(cron:session)".to_string(),
            "systemd-logind".to_string(),
        ];
        let config = base_config().with_telemetry(TelemetrySection { logs });
        validate_config(&config).expect("exact substrings");
    }

    #[test]
    fn duplicate_log_input_ids_are_rejected() {
        let mut logs = valid_logs();
        let mut duplicate = logs.file_inputs[0].clone();
        duplicate.path = "/tmp/root/other.log".to_string();
        logs.file_inputs.push(duplicate);
        let config = base_config().with_telemetry(TelemetrySection { logs });
        assert_code(validate_config(&config), "duplicate_log_input_id");
    }
}
