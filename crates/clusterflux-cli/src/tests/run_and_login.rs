use super::*;
use clusterflux_protocol::CoordinatorResponse;

#[test]
fn cli_error_classifier_distinguishes_mvp_failure_categories() {
    for (message, category, exit_code) in [
            (
                "login required before running this command",
                "authentication",
                20,
            ),
            (
                "CLI session credential has expired; run clusterflux login --browser again",
                "authentication",
                20,
            ),
            (
                "CLI session credential has been revoked",
                "authentication",
                20,
            ),
            ("unauthorized tenant action", "authorization", 21),
            (
                "quota unavailable: resource limit exceeded for api_calls",
                "quota",
                22,
            ),
            ("policy denied native command execution", "policy", 23),
            (
                "scheduler placement failed: no capable node for placement: project mismatch",
                "capability",
                24,
            ),
            (
                "scheduler placement failed: no capable node for placement: source snapshot unavailable and direct connectivity unavailable",
                "connectivity",
                25,
            ),
            (
                "failed to connect to coordinator: connection refused",
                "connectivity",
                25,
            ),
            (
                "missing environment envs/linux/Containerfile",
                "environment",
                26,
            ),
            ("task exited with status 101 after panic", "program", 27),
            (
                "project already has active virtual process vp-current",
                "active_process",
                28,
            ),
        ] {
            let summary = cli_error_summary(message);
            assert_eq!(summary["category"], category, "{message}");
            assert_eq!(summary["stable_exit_code"], exit_code, "{message}");
            assert_eq!(summary["safe_failure"], true);
            assert_eq!(summary["process_exit_code_applied"], false);
            assert!(summary["next_actions"].as_array().unwrap().len() >= 2);
            if category == "quota" {
                assert_eq!(summary["resource_category"], "api_calls");
                assert_eq!(summary["community_tier_language"], true);
                assert_eq!(summary["community_tier_label"], "community tier");
                assert_eq!(summary["sensitive_abuse_heuristics_exposed"], false);
                let rendered = human_report(&json!({
                    "command": "run",
                    "machine_error": summary,
                }));
                assert!(rendered.contains("quota tier: community tier"));
                let forbidden_tier = ["free", "tier"].join(" ");
                assert!(!rendered.to_ascii_lowercase().contains(&forbidden_tier));
            }
        }
}

#[test]
fn command_report_exit_code_marks_command_failures_only() {
    let run_start = run_start_summary(&CoordinatorResponse::error(
        "test-run-start",
        "quota unavailable: resource limit exceeded for api_calls",
    ));
    let mut report = json!({
        "command": "run",
        "status": run_start["status"].clone(),
        "run_start": run_start,
    });

    assert_eq!(apply_command_report_exit_code(&mut report), Some(22));
    assert_eq!(
        report["run_start"]["machine_error"]["process_exit_code_applied"],
        true
    );

    let mut task_list = json!({
        "command": "task list",
        "tasks": [{
            "task": "compile",
            "state": "failed",
            "machine_error": cli_error_summary_for_category("program", "task exited with status 1"),
        }],
    });
    assert_eq!(apply_command_report_exit_code(&mut task_list), None);
    assert_eq!(
        task_list["tasks"][0]["machine_error"]["process_exit_code_applied"],
        false
    );
}

#[test]
fn top_level_version_is_available() {
    let command = Cli::command();
    assert_eq!(command.get_name(), "clusterflux");
    assert!(command.get_version().is_some());
}

#[test]
fn run_defaults_to_current_project_without_inventing_an_entrypoint() {
    let Cli {
        command: Commands::Run(args),
    } = parse(&["clusterflux", "run"])
    else {
        panic!("wrong command");
    };
    let plan = run_plan(args, PathBuf::from("/repo"), CliSession::Anonymous).unwrap();

    assert_eq!(plan.project, PathBuf::from("/repo"));
    assert_eq!(plan.requested_entrypoint, None);
    assert_eq!(plan.coordinator, CoordinatorSelection::LocalOnly);
    assert_eq!(plan.hosted_coordinator_endpoint, None);
    assert_eq!(plan.session, CliSession::Anonymous);
}

#[test]
fn non_interactive_run_without_session_requires_explicit_auth_or_local() {
    let Cli {
        command: Commands::Run(args),
    } = parse(&["clusterflux", "run", "--non-interactive", "--json"])
    else {
        panic!("wrong command");
    };
    let report = run_report(args, PathBuf::from("/repo"), CliSession::Anonymous).unwrap();

    assert_eq!(report["command"], "run");
    assert_eq!(report["status"], "authentication_required");
    assert_eq!(report["non_interactive"], true);
    assert_eq!(report["browser_opened"], false);
    assert_eq!(report["external_website_required"], false);
    assert_eq!(report["machine_error"]["category"], "authentication");
    assert_eq!(report["machine_error"]["stable_exit_code"], 20);
    assert_eq!(report["machine_error"]["browser_opened"], false);
    let next_actions = report["machine_error"]["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(next_actions.contains(&"clusterflux login --browser"));
    assert!(next_actions.contains(&"set CLUSTERFLUX_AGENT_PRIVATE_KEY for automation"));
    assert!(next_actions.contains(&"pass --local to run against local services"));
}

#[test]
fn run_project_and_named_entry_are_respected() {
    let Cli {
        command: Commands::Run(args),
    } = parse(&["clusterflux", "run", "test", "--project", "/other"])
    else {
        panic!("wrong command");
    };
    let plan = run_plan(args, PathBuf::from("/repo"), CliSession::HumanSession).unwrap();

    assert_eq!(plan.project, PathBuf::from("/other"));
    assert_eq!(plan.requested_entrypoint.as_deref(), Some("test"));
    assert_eq!(plan.coordinator, CoordinatorSelection::Hosted);
    assert_eq!(
        plan.hosted_coordinator_endpoint.as_deref(),
        Some(DEFAULT_HOSTED_COORDINATOR_ENDPOINT)
    );
    assert_eq!(plan.session, CliSession::HumanSession);
}

#[test]
fn node_attach_detects_and_accepts_capability_overrides() {
    let Cli {
        command: Commands::Node {
            command: NodeCommands::Attach(args),
        },
    } = parse(&[
        "clusterflux",
        "node",
        "attach",
        "--cap",
        "artifact-transfer",
    ])
    else {
        panic!("wrong command");
    };
    let plan = attach_plan_with_capabilities(args, test_linux_container_node_capabilities());

    assert!(plan
        .capabilities
        .capabilities
        .contains(&Capability::ArtifactTransfer));
    assert!(!plan.capabilities.arch.is_empty());
    assert!(plan.detection.auto_detected);
    assert_eq!(plan.detection.os, plan.capabilities.os);
    assert_eq!(plan.detection.arch, plan.capabilities.arch);
    assert_eq!(plan.detection.command_backend, "container-command");
    assert!(plan.detection.command_backend_available);
    assert!(plan.detection.manual_capability_overrides_allowed);
    assert_eq!(
        plan.detection.manual_capability_overrides,
        vec!["artifact-transfer".to_owned()]
    );
    assert!(plan
        .detection
        .recognized_capability_overrides
        .contains(&Capability::ArtifactTransfer));
    assert!(plan.detection.unrecognized_capability_overrides.is_empty());
    assert!(!plan.detection.os_arch_capabilities_require_manual_flags);
    assert!(plan
        .detection
        .source_provider_backends
        .iter()
        .any(|provider| provider.provider == "filesystem" && provider.detected));
}

#[test]
fn node_attach_discloses_container_and_sensitive_capability_grants() {
    let Cli {
        command: Commands::Node {
            command: NodeCommands::Attach(args),
        },
    } = parse(&[
        "clusterflux",
        "node",
        "attach",
        "--cap",
        "network",
        "--cap",
        "host-filesystem",
        "--cap",
        "secrets",
    ])
    else {
        panic!("wrong command");
    };
    let plan = attach_plan_with_capabilities(args, test_linux_container_node_capabilities());
    let grants = plan
        .grant_disclosures
        .iter()
        .map(|disclosure| disclosure.grant.as_str())
        .collect::<Vec<_>>();

    assert!(grants.contains(&"container_command_execution"));
    assert!(grants.contains(&"source_access"));
    assert!(grants.contains(&"network_access"));
    assert!(grants.contains(&"host_filesystem_access"));
    assert!(grants.contains(&"secret_access"));
    assert!(plan
        .grant_disclosures
        .iter()
        .all(|disclosure| disclosure.coordinator_policy_limited));

    let rendered = human_report(&json!({
        "command": "node attach",
        "node": plan.node,
        "grant_disclosures": plan.grant_disclosures,
    }));
    assert!(rendered.contains("grant container_command_execution"));
    assert!(rendered.contains("grant network_access"));
    assert!(rendered.contains("policy-limited"));
}

#[test]
fn agents_can_select_hosted_with_public_key_identity() {
    let args = RunArgs {
        entry: None,
        project: None,
        coordinator: None,
        local: false,
        non_interactive: true,
        json: false,
    };
    let plan = run_plan(
        args,
        PathBuf::from("/repo"),
        CliSession::AgentPublicKey {
            agent: "agent-ci".to_owned(),
            public_key: "agent-key".to_owned(),
            public_key_fingerprint: Digest::sha256("agent-key"),
            private_key: None,
            browser_interaction_required: false,
        },
    )
    .unwrap();

    assert_eq!(plan.coordinator, CoordinatorSelection::Hosted);
    assert_eq!(
        plan.hosted_coordinator_endpoint.as_deref(),
        Some(DEFAULT_HOSTED_COORDINATOR_ENDPOINT)
    );
    assert_eq!(
        plan.session,
        CliSession::AgentPublicKey {
            agent: "agent-ci".to_owned(),
            public_key: "agent-key".to_owned(),
            public_key_fingerprint: Digest::sha256("agent-key"),
            private_key: None,
            browser_interaction_required: false,
        }
    );
}

#[test]
fn agent_environment_auth_requires_matching_private_key_possession() {
    let public_only = agent_session_from_keys(
        "agent-ci".to_owned(),
        Some("ed25519:claimed-public-key".to_owned()),
        None,
    )
    .unwrap_err();
    assert!(public_only.to_string().contains("cannot authenticate"));

    let private_key = "ed25519:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    let public_key =
        clusterflux_core::agent_ed25519_public_key_from_private_key(private_key).unwrap();
    let session = agent_session_from_keys(
        "agent-ci".to_owned(),
        Some(public_key.clone()),
        Some(private_key.to_owned()),
    )
    .unwrap()
    .unwrap();
    assert_eq!(
        session,
        CliSession::AgentPublicKey {
            agent: "agent-ci".to_owned(),
            public_key: public_key.clone(),
            public_key_fingerprint: Digest::sha256(public_key),
            private_key: Some(private_key.to_owned()),
            browser_interaction_required: false,
        }
    );

    let mismatched = agent_session_from_keys(
        "agent-ci".to_owned(),
        Some("ed25519:different-public-key".to_owned()),
        Some(private_key.to_owned()),
    )
    .unwrap_err();
    assert!(mismatched.to_string().contains("does not match"));
}

#[test]
fn run_with_agent_public_key_sends_attributable_workflow_actor() {
    let temp = tempfile::tempdir().unwrap();
    write_runnable_wasm_project(temp.path());
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "tenant-live".to_owned(),
            project: "project-live".to_owned(),
            user: "user-live".to_owned(),
            coordinator: None,
        },
    )
    .unwrap();

    let private_key = "ed25519:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
    let public_key =
        clusterflux_core::agent_ed25519_public_key_from_private_key(private_key).unwrap();
    let fingerprint = Digest::sha256(&public_key);
    let expected_fingerprint = fingerprint.to_string();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"start_process""#));
        assert!(line.contains(r#""tenant":"tenant-live""#));
        assert!(line.contains(r#""project":"project-live""#));
        assert!(line.contains(r#""actor_agent":"agent-ci""#));
        assert!(line.contains(&format!(
            r#""agent_public_key_fingerprint":"{expected_fingerprint}""#
        )));
        assert!(line.contains(r#""agent_signature""#));
        assert!(line.contains(r#""nonce":"agent-signature-"#));
        assert!(line.contains(r#""signature":"ed25519:"#));
        assert!(!line.contains(r#""actor_user""#));
        let launch_attempt = launch_attempt_from_wire(&line);
        stream
                .write_all(
                    format!(
                        r#"{{"type":"process_started","process":"vp-current","launch_attempt":"{launch_attempt}","epoch":7,"actor":{{"kind":"agent","user":"user-live","agent":"agent-ci","credential_kind":"PublicKey","public_key_fingerprint":"{expected_fingerprint}","authenticated_without_browser":true,"scopes":["project:read","project:run"]}},"charged_spawns":1}}"#
                    )
                    .as_bytes(),
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
        let mut launch_line = String::new();
        reader.read_line(&mut launch_line).unwrap();
        assert!(launch_line.contains(r#""type":"launch_task""#));
        assert!(launch_line.contains(r#""tenant":"tenant-live""#));
        assert!(launch_line.contains(r#""project":"project-live""#));
        assert!(launch_line.contains(r#""process":"vp-current""#));
        let launch: Value = serde_json::from_str(&launch_line).unwrap();
        let task_definition = launch["payload"]["task_spec"]["task_definition"]
            .as_str()
            .expect("launch must use the selected entrypoint name");
        assert_eq!(task_definition, "build");
        assert_eq!(
            launch["payload"]["task_spec"]["task_instance"],
            "ti:vp-current:main"
        );
        assert_eq!(
            launch["payload"]["task_spec"]["failure_policy"],
            "fail_fast"
        );
        assert!(launch_line.contains(r#""required_capabilities":[]"#));
        assert!(launch_line.contains(r#""wasm_module_base64":""#));
        assert!(launch_line.contains(r#""kind":"coordinator_node_wasm""#));
        assert!(launch_line.contains(r#""export":"clusterflux_entry_v1_"#));
        assert!(!launch_line.contains(r#""command":""#));
        assert!(launch_line.contains(r#""actor_agent":"agent-ci""#));
        assert!(launch_line.contains(&format!(
            r#""agent_public_key_fingerprint":"{expected_fingerprint}""#
        )));
        assert!(launch_line.contains(r#""agent_signature""#));
        assert!(launch_line.contains(r#""nonce":"agent-signature-"#));
        assert!(launch_line.contains(r#""signature":"ed25519:"#));
        assert!(!launch_line.contains(r#""actor_user""#));
        stream
            .write_all(
                serde_json::to_string(&json!({
                    "type": "main_launched",
                    "process": "vp-current",
                    "task_definition": task_definition,
                    "task_instance": "ti:vp-current:main",
                    "actor": {
                        "kind": "agent",
                        "user": "user-live",
                        "agent": "agent-ci",
                        "credential_kind": "PublicKey",
                        "public_key_fingerprint": expected_fingerprint,
                        "authenticated_without_browser": true,
                        "scopes": ["project:read", "project:run"],
                    },
                    "state": "running",
                }))
                .unwrap()
                .as_bytes(),
            )
            .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let report = run_report(
        RunArgs {
            entry: Some("build".to_owned()),
            project: Some(temp.path().to_path_buf()),
            coordinator: Some(format!("clusterflux+tcp://{addr}")),
            local: false,
            non_interactive: true,
            json: false,
        },
        PathBuf::from("/unused"),
        CliSession::AgentPublicKey {
            agent: "agent-ci".to_owned(),
            public_key,
            public_key_fingerprint: fingerprint,
            private_key: Some(private_key.to_owned()),
            browser_interaction_required: false,
        },
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["status"], "main_launched");
    assert_eq!(report["workflow_actor"]["kind"], "agent");
    assert_eq!(report["workflow_actor"]["agent"], "agent-ci");
    assert_eq!(
        report["workflow_actor"]["authenticated_without_browser"],
        true
    );
    assert_eq!(report["run_start"]["actor"]["kind"], "agent");
    assert_eq!(report["task_launch"]["type"], "main_launched");
    assert_eq!(report["task_launch"]["state"], "running");
    assert_eq!(report["task_launch"]["actor"]["agent"], "agent-ci");
}

#[test]
fn run_with_human_session_derives_workflow_scope_from_authenticated_envelope() {
    let temp = tempfile::tempdir().unwrap();
    write_runnable_wasm_project(temp.path());
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "spoofed-tenant".to_owned(),
            project: "spoofed-project".to_owned(),
            user: "spoofed-user".to_owned(),
            coordinator: None,
        },
    )
    .unwrap();
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: addr.clone(),
            tenant: "tenant-session".to_owned(),
            project: "project-session".to_owned(),
            user: "user-session".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("run-session-secret".to_owned()),
            token_expiry_posture: "unknown_coordinator_session".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        for (expected_operation, response) in [
            (
                "start_process",
                br#"{"type":"process_started","process":"vp-current","epoch":7,"actor":{"kind":"user","user":"user-session","agent":null,"credential_kind":"CliDeviceSession","public_key_fingerprint":null,"authenticated_without_browser":false,"scopes":["project:read","project:run"]},"charged_spawns":1}"#.as_slice(),
            ),
            (
                "launch_task",
                br#"{"type":"main_launched","process":"vp-current","task_definition":"entry-build","task_instance":"ti:vp-current:main","actor":{"kind":"user","user":"user-session","agent":null,"credential_kind":"CliDeviceSession","public_key_fingerprint":null,"authenticated_without_browser":false,"scopes":["project:read","project:run"]},"state":"running"}"#.as_slice(),
            ),
        ] {
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let wire: Value = serde_json::from_str(&line).unwrap();
            assert_eq!(wire["type"], "coordinator_request");
            assert_eq!(wire["operation"], "authenticated");
            assert_eq!(wire["authentication"]["kind"], "cli_session");
            assert_eq!(wire["payload"]["type"], "authenticated");
            assert_eq!(wire["payload"]["session_secret"], "run-session-secret");
            assert_eq!(wire["payload"]["request"]["type"], expected_operation);
            assert!(wire["payload"]["request"].get("tenant").is_none());
            assert!(wire["payload"]["request"].get("project").is_none());
            assert!(wire["payload"]["request"].get("actor_user").is_none());
            if expected_operation == "start_process" {
                let launch_attempt = launch_attempt_from_wire(&line);
                stream
                    .write_all(
                        serde_json::to_string(&json!({
                            "type": "process_started",
                            "process": "vp-current",
                            "launch_attempt": launch_attempt,
                            "epoch": 7,
                            "actor": {
                                "kind": "user",
                                "user": "user-session",
                                "agent": null,
                                "credential_kind": "CliDeviceSession",
                                "public_key_fingerprint": null,
                                "authenticated_without_browser": false,
                                "scopes": ["project:read", "project:run"]
                            },
                            "charged_spawns": 1,
                        }))
                        .unwrap()
                        .as_bytes(),
                    )
                    .unwrap();
            } else {
                stream.write_all(response).unwrap();
            }
            stream.write_all(b"\n").unwrap();
        }
    });

    let report = run_report(
        RunArgs {
            entry: Some("build".to_owned()),
            project: Some(temp.path().to_path_buf()),
            coordinator: None,
            local: false,
            non_interactive: true,
            json: false,
        },
        PathBuf::from("/unused"),
        CliSession::HumanSession,
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["status"], "main_launched");
    assert_eq!(report["workflow_actor"]["user"], "user-session");
    assert_eq!(report["task_launch"]["state"], "running");
    assert_eq!(report["task_launch"]["actor"]["user"], "user-session");
}

#[test]
fn run_local_flag_overrides_logged_in_hosted_selection() {
    let Cli {
        command: Commands::Run(args),
    } = parse(&["clusterflux", "run", "--local"])
    else {
        panic!("wrong command");
    };
    let plan = run_plan(args, PathBuf::from("/repo"), CliSession::HumanSession).unwrap();

    assert_eq!(plan.coordinator, CoordinatorSelection::LocalOnly);
    assert_eq!(plan.hosted_coordinator_endpoint, None);
}

#[test]
fn run_contacts_configured_coordinator_and_reports_active_process_conflicts() {
    let temp = tempfile::tempdir().unwrap();
    write_runnable_wasm_project(temp.path());
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "tenant-live".to_owned(),
            project: "project-live".to_owned(),
            user: "user-live".to_owned(),
            coordinator: None,
        },
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for (index, response) in [
                r#"{"type":"process_started","process":"vp-current","epoch":7,"actor":{"kind":"user","user":"user-live","agent":null,"credential_kind":"BrowserSession","public_key_fingerprint":null,"authenticated_without_browser":false,"scopes":["project:read","project:run"]},"charged_spawns":1}"#,
                r#"{"type":"error","message":"coordinator request failed: unauthorized coordinator action: project already has active virtual process vp-current; attach to or restart it, request cooperative cancellation, abort it, or use another Coordinator Project"}"#,
            ]
            .into_iter()
            .enumerate()
            {
                let (mut stream, _) = listener.accept().unwrap();
                let mut reader = BufReader::new(stream.try_clone().unwrap());
                let mut line = String::new();
                reader.read_line(&mut line).unwrap();
                assert!(line.contains(r#""type":"start_process""#));
                assert!(line.contains(r#""tenant":"tenant-live""#));
                assert!(line.contains(r#""project":"project-live""#));
                assert!(line.contains(r#""process":"vp-current""#));
                assert!(line.contains(r#""restart":false"#));
                let response = if index == 0 {
                    let launch_attempt = launch_attempt_from_wire(&line);
                    serde_json::to_string(&json!({
                        "type": "process_started",
                        "process": "vp-current",
                        "launch_attempt": launch_attempt,
                        "epoch": 7,
                        "actor": test_workflow_actor(
                            "user",
                            Some("user-live"),
                            None,
                            "BrowserSession",
                            false,
                        ),
                        "charged_spawns": 1,
                    }))
                    .unwrap()
                } else {
                    canonical_error_response(&line, response).to_string()
                };
                stream.write_all(response.as_bytes()).unwrap();
                stream.write_all(b"\n").unwrap();
                if index == 0 {
                    let mut launch_line = String::new();
                    reader.read_line(&mut launch_line).unwrap();
                    assert!(launch_line.contains(r#""type":"launch_task""#));
                    assert!(launch_line.contains(r#""tenant":"tenant-live""#));
                    assert!(launch_line.contains(r#""project":"project-live""#));
                    assert!(launch_line.contains(r#""process":"vp-current""#));
                    let launch: Value = serde_json::from_str(&launch_line).unwrap();
                    let task_definition = launch["payload"]["task_spec"]["task_definition"]
                        .as_str()
                        .expect("launch must use the selected entrypoint name");
                    assert_eq!(task_definition, "build");
                    assert_eq!(
                        launch["payload"]["task_spec"]["task_instance"],
                        "ti:vp-current:main"
                    );
                    assert!(launch_line.contains(r#""actor_user":"user-live""#));
                    assert!(launch_line.contains(r#""required_capabilities":[]"#));
                    assert!(launch_line.contains(r#""wasm_module_base64":""#));
                    assert!(launch_line.contains(r#""kind":"coordinator_node_wasm""#));
                    assert!(launch_line.contains(r#""export":"clusterflux_entry_v1_"#));
                    assert!(!launch_line.contains(r#""command":""#));
                    assert!(!launch_line.contains("--manifest-path"));
                    stream
                        .write_all(
                            serde_json::to_string(&json!({
                                "type": "main_launched",
                                "process": "vp-current",
                                "task_definition": task_definition,
                                "task_instance": "ti:vp-current:main",
                                "actor": test_workflow_actor(
                                    "user",
                                    Some("user-live"),
                                    None,
                                    "BrowserSession",
                                    false,
                                ),
                                "state": "running",
                            }))
                            .unwrap()
                            .as_bytes(),
                        )
                        .unwrap();
                    stream.write_all(b"\n").unwrap();
                }
            }
    });

    let started = run_report(
        RunArgs {
            entry: Some("build".to_owned()),
            project: Some(temp.path().to_path_buf()),
            coordinator: Some(format!("clusterflux+tcp://{addr}")),
            local: false,
            non_interactive: false,
            json: false,
        },
        PathBuf::from("/unused"),
        CliSession::Anonymous,
    )
    .unwrap();
    let blocked = run_report(
        RunArgs {
            entry: Some("test".to_owned()),
            project: Some(temp.path().to_path_buf()),
            coordinator: Some(format!("clusterflux+tcp://{addr}")),
            local: false,
            non_interactive: false,
            json: false,
        },
        PathBuf::from("/unused"),
        CliSession::Anonymous,
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(started["status"], "main_launched");
    assert_eq!(started["entry"], "build");
    assert_eq!(started["tenant"], "tenant-live");
    assert_eq!(started["project"], "project-live");
    assert_eq!(started["process"], "vp-current");
    assert_eq!(started["run_start"]["restart"], false);
    assert_eq!(started["run_start"]["single_active_process_boundary"], true);
    assert_eq!(started["task_launch"]["type"], "main_launched");
    assert_eq!(started["task_launch"]["state"], "running");

    assert_eq!(blocked["status"], "blocked_active_process");
    assert_eq!(blocked["entry"], "test");
    assert_eq!(
        blocked["run_start"]["category"],
        "active_process_already_running"
    );
    assert_eq!(blocked["run_start"]["error_category"], "active_process");
    assert_eq!(blocked["run_start"]["stable_exit_code"], 28);
    assert_eq!(
        blocked["run_start"]["machine_error"]["category"],
        "active_process"
    );
    assert_eq!(
        blocked["run_start"]["machine_error"]["stable_exit_code"],
        28
    );
    assert_eq!(blocked["run_start"]["safe_failure"], true);
    assert!(blocked["run_start"]["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action == "clusterflux process restart --yes"));
}

#[test]
fn run_rejection_reports_machine_readable_error_category() {
    let rejected = run_start_summary(&CoordinatorResponse::error(
        "test-run-rejection",
        "quota unavailable: resource limit exceeded for api_calls",
    ));

    assert_eq!(rejected["status"], "coordinator_rejected");
    assert_eq!(rejected["error_category"], "quota");
    assert_eq!(rejected["stable_exit_code"], 22);
    assert_eq!(rejected["machine_error"]["category"], "quota");
    assert_eq!(rejected["machine_error"]["resource_category"], "api_calls");
    assert_eq!(rejected["machine_error"]["community_tier_language"], true);
    assert_eq!(
        rejected["machine_error"]["sensitive_abuse_heuristics_exposed"],
        false
    );
    assert!(rejected["machine_error"]["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action == "clusterflux quota status"));
}

#[test]
fn local_only_run_executes_ephemeral_local_services() {
    let Cli {
        command: Commands::Run(args),
    } = parse(&["clusterflux", "run", "--local"])
    else {
        panic!("wrong command");
    };
    let plan = run_plan(args, PathBuf::from("/repo"), CliSession::Anonymous).unwrap();

    assert!(should_execute_local_node(&plan));
}

#[test]
fn login_defaults_to_the_server_owned_browser_flow() {
    let Cli {
        command: Commands::Login(args),
    } = parse(&["clusterflux", "login"])
    else {
        panic!("wrong command");
    };
    let plan = login_plan(args);

    assert_eq!(plan.coordinator, DEFAULT_HOSTED_COORDINATOR_ENDPOINT);
    let LoginFlowPlan::Browser(flow) = plan.human_flow;
    assert_eq!(flow.authorization_url, None);
    assert!(flow.server_owns_state);
    assert!(flow.server_owns_nonce);
    assert!(flow.pkce_required);
    assert!(flow.hosted_callback);
    assert!(!flow.cli_receives_provider_authorization_code);
    assert!(!flow.cli_submits_identity_claims);
}

#[test]
fn browser_login_flow_is_available_for_humans() {
    let Cli {
        command: Commands::Login(args),
    } = parse(&["clusterflux", "login", "--browser"])
    else {
        panic!("wrong command");
    };
    let plan = login_plan(args);

    let LoginFlowPlan::Browser(flow) = plan.human_flow;
    assert_eq!(flow.authorization_url, None);
    assert!(flow.server_owns_state);
    assert!(flow.server_owns_nonce);
    assert!(flow.pkce_required);
    assert!(flow.hosted_callback);
    assert!(!flow.cli_receives_provider_authorization_code);
    assert!(!flow.cli_submits_identity_claims);
}

#[test]
fn login_inherits_the_current_project_scope() {
    let temp = tempfile::tempdir().unwrap();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "workspace-tenant".to_owned(),
            project: "workspace-project".to_owned(),
            user: "workspace-user".to_owned(),
            coordinator: Some("https://workspace.example:9443".to_owned()),
        },
    )
    .unwrap();
    let Cli {
        command: Commands::Login(args),
    } = parse(&["clusterflux", "login", "--browser"])
    else {
        panic!("wrong command");
    };

    let args = login_args_for_project(args, temp.path()).unwrap();

    assert_eq!(args.project, "workspace-project");
    assert_eq!(args.coordinator, "https://workspace.example:9443");
}

#[test]
fn auth_status_reports_a_session_that_does_not_match_the_current_project() {
    let temp = tempfile::tempdir().unwrap();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "workspace-tenant".to_owned(),
            project: "workspace-project".to_owned(),
            user: "workspace-user".to_owned(),
            coordinator: Some("https://workspace.example:9443".to_owned()),
        },
    )
    .unwrap();
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: "https://workspace.example:9443".to_owned(),
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            user: "other-user".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("other-session".to_owned()),
            token_expiry_posture: "expires_at".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
    let Cli {
        command: Commands::Auth {
            command: AuthCommands::Status(args),
        },
    } = parse(&["clusterflux", "auth", "status"])
    else {
        panic!("wrong command");
    };

    let report = auth_status_report(args, temp.path().to_path_buf()).unwrap();

    assert_eq!(report["session_matches_current_project"], false);
    assert_eq!(
        report["coordinator_account_status"]["reason"],
        "stored CLI session does not match the current project"
    );
    assert_eq!(
        report["coordinator_account_status"]["authenticated_for_current_project"],
        false
    );
}

#[test]
fn browser_login_non_interactive_fails_before_opening_browser() {
    let Cli {
        command: Commands::Login(args),
    } = parse(&["clusterflux", "login", "--browser", "--non-interactive"])
    else {
        panic!("wrong command");
    };
    let report = non_interactive_browser_login_report(&args);

    assert_eq!(report["command"], "login");
    assert_eq!(report["status"], "authentication_required");
    assert_eq!(report["non_interactive"], true);
    assert_eq!(report["browser_requested"], true);
    assert_eq!(report["browser_opened"], false);
    assert_eq!(report["machine_error"]["category"], "authentication");
    assert_eq!(report["machine_error"]["stable_exit_code"], 20);
    assert_eq!(report["machine_error"]["browser_opened"], false);
    let next_actions = report["machine_error"]["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .filter_map(Value::as_str)
        .collect::<Vec<_>>();
    assert!(next_actions.contains(&"rerun without --non-interactive to open the browser"));
    assert!(next_actions.contains(&"use CLUSTERFLUX_AGENT_PRIVATE_KEY for automation"));
}

#[test]
fn browser_login_completion_detects_raw_provider_token_fields() {
    assert!(contains_provider_token_field(&json!({
        "session": {
            "access_token": "secret"
        }
    })));
    assert!(!contains_provider_token_field(&json!({
        "session": {
            "cli_session_credential_kind": "CliDeviceSession",
            "oidc_token_exchange": {
                "received_access_token": true,
                "received_id_token": true
            }
        }
    })));
}

#[test]
fn stored_browser_login_session_omits_provider_token_values() {
    let stored = stored_cli_session_from_login_response(
        "https://coord.example.test",
        &json!({
            "session": {
                "tenant": "tenant-live",
                "project": "project-live",
                "user": "user-live",
                "cli_session_credential_kind": "CliDeviceSession",
                "cli_session_secret": "clusterflux-cli-session-secret",
                "expires_at": "2026-07-04T00:00:00Z",
                "access_token": "provider-secret",
                "id_token": "provider-id-token",
                "provider_tokens_sent_to_nodes": false
            }
        }),
        true,
        false,
    )
    .unwrap();
    let serialized = serde_json::to_string(&stored).unwrap();

    assert_eq!(stored.kind, "human");
    assert_eq!(stored.coordinator, "https://coord.example.test");
    assert_eq!(stored.tenant, "tenant-live");
    assert_eq!(stored.project, "project-live");
    assert_eq!(stored.user, "user-live");
    assert_eq!(
        stored.session_secret.as_deref(),
        Some("clusterflux-cli-session-secret")
    );
    assert_eq!(stored.token_expiry_posture, "expires_at");
    assert!(stored.provider_tokens_exposed_to_cli);
    assert!(!stored.provider_tokens_sent_to_nodes);
    assert!(!serialized.contains("provider-secret"));
    assert!(!serialized.contains("provider-id-token"));
    assert!(!serialized.contains("access_token"));
    assert!(!serialized.contains("id_token"));
}

#[test]
fn stored_browser_login_session_accepts_hosted_epoch_expiry() {
    let stored = stored_cli_session_from_login_response(
        "https://hosted.example.test",
        &json!({
            "session": {
                "tenant": "tenant-live",
                "project": "project-live",
                "user": "user-live",
                "cli_session_credential_kind": "CliDeviceSession",
                "cli_session_secret": "clusterflux-cli-session-secret",
                "expires_at_epoch_seconds": 1_800_000_000_u64,
                "provider_tokens_sent_to_nodes": false
            }
        }),
        false,
        false,
    )
    .unwrap();

    assert_eq!(stored.token_expiry_posture, "expires_at");
    assert_eq!(stored.expires_at.as_deref(), Some("1800000000"));
}

#[test]
fn agent_enroll_uses_public_key_without_browser_each_run() {
    let Cli {
        command: Commands::Agent {
            command: AgentCommands::Enroll(args),
        },
    } = parse(&[
        "clusterflux",
        "agent",
        "enroll",
        "--public-key",
        "agent-key",
    ])
    else {
        panic!("wrong command");
    };
    let plan = agent_enrollment_plan(args);

    assert!(!plan.browser_interaction_required_each_run);
    assert!(plan.public_key_fingerprint.as_str().starts_with("sha256:"));
}
