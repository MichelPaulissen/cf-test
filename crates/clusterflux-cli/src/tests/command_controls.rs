use super::*;

#[test]
fn cli_first_mvp_command_surface_parses() {
    for args in [
        &["clusterflux", "doctor"][..],
        &["clusterflux", "auth", "status"],
        &[
            "clusterflux",
            "auth",
            "status",
            "--require-valid-for",
            "30m",
        ],
        &["clusterflux", "logout", "--yes"],
        &["clusterflux", "auth", "logout", "--yes"],
        &["clusterflux", "login", "--browser", "--non-interactive"],
        &[
            "clusterflux",
            "key",
            "add",
            "--agent",
            "agent",
            "--public-key",
            "key",
        ],
        &["clusterflux", "key", "list"],
        &["clusterflux", "key", "revoke", "--agent", "agent", "--yes"],
        &["clusterflux", "project", "init", "--yes"],
        &["clusterflux", "project", "status"],
        &["clusterflux", "project", "list"],
        &["clusterflux", "project", "select", "project"],
        &["clusterflux", "inspect"],
        &["clusterflux", "build"],
        &["clusterflux", "run", "--non-interactive"],
        &["clusterflux", "runs", "retry", "run-1"],
        &[
            "clusterflux",
            "runs",
            "trigger",
            "--repository",
            "github:owner/repository",
            "--ref",
            "refs/heads/main",
        ],
        &["clusterflux", "runs", "diagnose", "run-1"],
        &["clusterflux", "webhook", "deliveries"],
        &["clusterflux", "node", "enroll"],
        &["clusterflux", "node", "list"],
        &["clusterflux", "node", "status"],
        &["clusterflux", "node", "doctor", "--node", "node"],
        &[
            "clusterflux",
            "node",
            "doctor",
            "--full",
            "--environment",
            "windows-node-build",
        ],
        &["clusterflux", "node", "revoke", "--node", "node", "--yes"],
        &["clusterflux", "process", "list"],
        &["clusterflux", "process", "status"],
        &["clusterflux", "process", "restart", "--yes"],
        &["clusterflux", "process", "cancel", "--yes"],
        &["clusterflux", "process", "abort", "--yes"],
        &["clusterflux", "task", "list"],
        &["clusterflux", "task", "restart", "compile-linux", "--yes"],
        &["clusterflux", "logs"],
        &["clusterflux", "artifact", "list"],
        &["clusterflux", "artifact", "download", "artifact"],
        &[
            "clusterflux",
            "artifact",
            "export",
            "artifact",
            "--to",
            "/tmp/out",
        ],
        &["clusterflux", "dap", "--plan"],
        &["clusterflux", "debug", "attach"],
        &["clusterflux", "quota", "status"],
        &["clusterflux", "admin", "status"],
        &["clusterflux", "admin", "bootstrap", "--yes"],
        &[
            "clusterflux",
            "admin",
            "revoke-node",
            "--node",
            "node",
            "--yes",
        ],
        &["clusterflux", "admin", "stop-process", "--yes"],
        &["clusterflux", "admin", "suspend-tenant", "--yes"],
    ] {
        let _ = parse(args);
    }
}

#[test]
fn node_doctor_environment_requires_the_full_runtime_probe() {
    let error = Cli::try_parse_from([
        "clusterflux",
        "node",
        "doctor",
        "--environment",
        "windows-node-build",
    ])
    .unwrap_err()
    .to_string();
    assert!(error.contains("--full"));
}

#[test]
fn cli_has_no_direct_hosted_account_creation_command() {
    for args in [
        &["clusterflux", "signup"][..],
        &["clusterflux", "account", "create"],
        &["clusterflux", "login", "--create-account"],
    ] {
        let error = Cli::try_parse_from(args).unwrap_err().to_string();
        assert!(
            error.contains("unrecognized subcommand") || error.contains("unexpected argument"),
            "expected no direct account creation command for {args:?}, got {error}"
        );
    }

    let mut command = Cli::command();
    let help = command.render_help().to_string();
    assert!(help.contains("Hosted account creation happens in the browser login flow."));
    assert!(!help.contains("clusterflux signup"));
    assert!(!help.contains("account create"));
}

#[test]
fn admin_bootstrap_reports_self_hosted_cli_only_path() {
    let temp = tempfile::tempdir().unwrap();
    let report = admin_bootstrap_report(
        AdminBootstrapArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "team".to_owned(),
                project: "self-hosted".to_owned(),
                user: "admin".to_owned(),
                json: false,
            },
            name: "Self Hosted".to_owned(),
            yes: true,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();

    assert_eq!(report["command"], "admin bootstrap");
    assert_eq!(report["mode"], "self_hosted_local");
    assert_eq!(report["external_website_required"], false);
    assert_eq!(report["self_hosted_cli_only"], true);
    assert_eq!(report["project_config_written"], true);
    assert_eq!(report["project_init"]["command"], "project init");
    assert_eq!(report["project_init"]["external_website_required"], false);
    assert_eq!(
        report["project_init"]["project_config"]["project"],
        "self-hosted"
    );
    assert_eq!(
        report["admin_surfaces"]["node"],
        "clusterflux node enroll/list/status/revoke"
    );
    let steps = report["bootstrap_sequence"].as_array().unwrap();
    for expected in [
        "start_self_hosted_coordinator",
        "create_or_link_project",
        "create_node_enrollment_grant",
        "attach_worker_node",
        "run_process",
        "inspect_status_logs_artifacts",
        "revoke_access",
    ] {
        assert!(
            steps.iter().any(|step| step["step"] == expected),
            "missing bootstrap step {expected}"
        );
    }
    assert!(steps.iter().all(|step| {
        !step
            .get("external_website_required")
            .and_then(Value::as_bool)
            .unwrap_or(false)
    }));
    assert!(steps.iter().any(|step| step
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("")
        .contains("clusterflux node enroll")));
    assert!(steps.iter().any(|step| step
        .get("command")
        .and_then(Value::as_str)
        .unwrap_or("")
        .contains("clusterflux admin revoke-node")));
}

#[test]
fn top_level_help_exposes_primary_workflow_without_auth() {
    let mut command = Cli::command();
    let help = command.render_help().to_string();

    for expected in [
        "Primary workflow:",
        "clusterflux login --browser",
        "clusterflux project init",
        "clusterflux node enroll",
        "clusterflux node attach",
        "clusterflux-node --worker",
        "clusterflux run [entry] --project <path>",
        "Clusterflux: Launch Virtual Process",
        "clusterflux dap",
        "clusterflux process status",
        "task list",
        "logs",
        "artifact list",
        "--json",
        "Hosted account creation happens in the browser login flow.",
    ] {
        assert!(help.contains(expected), "help output missing {expected}");
    }
}

#[test]
fn top_level_logout_alias_removes_only_cli_session_state() {
    let temp = tempfile::tempdir().unwrap();
    let session_file = session_config_file(temp.path());
    fs::create_dir_all(session_file.parent().unwrap()).unwrap();
    fs::write(&session_file, br#"{"kind":"human","token":"local"}"#).unwrap();

    let unconfirmed = logout_report(
        AuthLogoutArgs {
            yes: false,
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
        "logout",
    )
    .unwrap();

    assert_eq!(unconfirmed["status"], "confirmation_required");
    assert_eq!(unconfirmed["coordinator_request_sent"], false);
    assert_eq!(unconfirmed["machine_error"]["category"], "policy");
    assert!(session_file.exists());

    let report = logout_report(
        AuthLogoutArgs {
            yes: true,
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
        "logout",
    )
    .unwrap();

    assert_eq!(report["command"], "logout");
    assert_eq!(report["requires_confirmation"], false);
    assert_eq!(report["removed_cli_session_file"], true);
    assert_eq!(report["node_credentials_untouched"], true);
    assert!(!session_file.exists());
}

#[test]
fn logout_revokes_stored_cli_session_on_coordinator_before_local_removal() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: addr.clone(),
            tenant: "tenant-session".to_owned(),
            project: "project-session".to_owned(),
            user: "user-session".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("logout-cli-session-secret".to_owned()),
            token_expiry_posture: "unknown_coordinator_session".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
    let session_file = session_config_file(temp.path());
    assert!(session_file.exists());

    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"authenticated""#));
        assert!(line.contains(r#""session_secret":"logout-cli-session-secret""#));
        assert!(line.contains(r#""type":"revoke_cli_session""#));
        assert!(!line.contains(r#""actor_user":"user-session""#));
        stream
            .write_all(
                br#"{"type":"cli_session_revoked","tenant":"tenant-session","project":"project-session","actor":"user-session"}"#,
            )
            .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let report = logout_report(
        AuthLogoutArgs {
            yes: true,
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
        "logout",
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["removed_cli_session_file"], true);
    assert_eq!(report["server_session_revocation"]["attempted"], true);
    assert_eq!(report["server_session_revocation"]["revoked"], true);
    assert_eq!(
        report["server_session_revocation"]["coordinator_response_type"],
        "cli_session_revoked"
    );
    assert!(!session_file.exists());
}

#[test]
fn mutating_commands_require_yes_before_side_effects() {
    let temp = tempfile::tempdir().unwrap();
    let scope = CliScopeArgs {
        coordinator: Some("127.0.0.1:9".to_owned()),
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        user: "user".to_owned(),
        json: false,
    };
    let reports = [
        key_revoke_report(KeyRevokeArgs {
            scope: scope.clone(),
            agent: "agent-ci".to_owned(),
            yes: false,
        })
        .unwrap(),
        node_revoke_report(
            NodeRevokeArgs {
                scope: scope.clone(),
                node: "node-a".to_owned(),
                yes: false,
            },
            temp.path().to_path_buf(),
        )
        .unwrap(),
        process_restart_report(ProcessRestartArgs {
            scope: scope.clone(),
            process: "vp".to_owned(),
            yes: false,
        })
        .unwrap(),
        process_cancel_report(ProcessCancelArgs {
            scope: scope.clone(),
            process: "vp".to_owned(),
            node: None,
            task: None,
            yes: false,
        })
        .unwrap(),
        task_restart_report(TaskRestartArgs {
            scope: scope.clone(),
            task: "compile-linux".to_owned(),
            process: "vp".to_owned(),
            yes: false,
        })
        .unwrap(),
        admin_suspend_tenant_report(AdminSuspendTenantArgs {
            scope,
            target_tenant: Some("tenant".to_owned()),
            admin_token: None,
            yes: false,
        })
        .unwrap(),
    ];

    for report in reports {
        assert_eq!(report["status"], "confirmation_required");
        assert_eq!(report["requires_confirmation"], true);
        assert_eq!(report["coordinator_request_sent"], false);
        assert_eq!(report["safe_failure"], true);
        assert_eq!(report["machine_error"]["category"], "policy");
        assert_eq!(report["machine_error"]["confirmation_required"], true);
        assert!(report["next_actions"]
            .as_array()
            .unwrap()
            .iter()
            .any(|action| action.as_str().unwrap_or_default().contains("--yes")));
    }
}

#[test]
fn cli_first_json_mode_parses_for_primary_commands() {
    for args in [
        &["clusterflux", "doctor", "--json"][..],
        &["clusterflux", "login", "--json"],
        &[
            "clusterflux",
            "login",
            "--browser",
            "--non-interactive",
            "--json",
        ],
        &["clusterflux", "logout", "--yes", "--json"],
        &["clusterflux", "auth", "status", "--json"],
        &[
            "clusterflux",
            "agent",
            "enroll",
            "--public-key",
            "key",
            "--json",
        ],
        &[
            "clusterflux",
            "key",
            "add",
            "--agent",
            "agent",
            "--public-key",
            "key",
            "--json",
        ],
        &["clusterflux", "project", "init", "--yes", "--json"],
        &["clusterflux", "inspect", "--json"],
        &["clusterflux", "build", "--json"],
        &["clusterflux", "bundle", "inspect", "--json"],
        &["clusterflux", "run", "--json"],
        &["clusterflux", "run", "--non-interactive", "--json"],
        &["clusterflux", "node", "attach", "--json"],
        &["clusterflux", "node", "enroll", "--json"],
        &["clusterflux", "process", "status", "--json"],
        &["clusterflux", "task", "list", "--json"],
        &["clusterflux", "logs", "--json"],
        &["clusterflux", "artifact", "list", "--json"],
        &["clusterflux", "artifact", "download", "artifact", "--json"],
        &[
            "clusterflux",
            "artifact",
            "export",
            "artifact",
            "--to",
            "/tmp/out",
            "--json",
        ],
        &["clusterflux", "dap", "--plan", "--json"],
        &["clusterflux", "debug", "attach", "--json"],
        &["clusterflux", "quota", "status", "--json"],
        &["clusterflux", "admin", "status", "--json"],
    ] {
        let _ = parse(args);
    }
}

#[test]
fn key_lifecycle_reports_project_scoped_agent_credentials() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let add_response = concat!(
            r#"{"type":"agent_public_key","actor":"user","record":{"tenant":"tenant","project":"project","user":"user","agent":"agent-ci","public_key":"agent-key-v1","public_key_fingerprint":"sha256:agent-v1","version":1,"revoked":false,"scopes":["project:read","project:run"],"human_account_creation_privilege":false,"browser_interaction_required_each_run":false}}"#
        );
        let list_response = concat!(
            r#"{"type":"agent_public_keys","actor":"user","records":[{"tenant":"tenant","project":"project","user":"user","agent":"agent-ci","public_key":"agent-key-v1","public_key_fingerprint":"sha256:agent-v1","version":1,"revoked":false,"scopes":["project:read","project:run"],"human_account_creation_privilege":false,"browser_interaction_required_each_run":false}]}"#
        );
        let revoke_response = concat!(
            r#"{"type":"agent_public_key","actor":"user","record":{"tenant":"tenant","project":"project","user":"user","agent":"agent-ci","public_key":"agent-key-v1","public_key_fingerprint":"sha256:agent-v1","version":1,"revoked":true,"scopes":["project:read","project:run"],"human_account_creation_privilege":false,"browser_interaction_required_each_run":false}}"#
        );
        for (expected, response) in [
            ("register_agent_public_key", add_response),
            ("list_agent_public_keys", list_response),
            ("revoke_agent_public_key", revoke_response),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(&format!(r#""type":"{expected}""#)));
            assert!(line.contains(r#""tenant":"tenant""#));
            assert!(line.contains(r#""project":"project""#));
            assert!(line.contains(r#""user":"user""#));
            if expected != "list_agent_public_keys" {
                assert!(line.contains(r#""agent":"agent-ci""#));
            }
            if expected == "register_agent_public_key" {
                assert!(line.contains(r#""public_key":"agent-key-v1""#));
            }
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    });
    let scope = CliScopeArgs {
        coordinator: Some(addr),
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        user: "user".to_owned(),
        json: false,
    };

    let added = key_add_report(KeyAddArgs {
        scope: scope.clone(),
        agent: "agent-ci".to_owned(),
        public_key: "agent-key-v1".to_owned(),
    })
    .unwrap();
    let listed = key_list_report(KeyListArgs {
        scope: scope.clone(),
    })
    .unwrap();
    let revoked = key_revoke_report(KeyRevokeArgs {
        scope,
        agent: "agent-ci".to_owned(),
        yes: true,
    })
    .unwrap();
    server.join().unwrap();

    assert_eq!(added["command"], "key add");
    assert_eq!(added["agent"], "agent-ci");
    assert_eq!(added["credential_scope"]["actions"][0], "project:read");
    assert_eq!(
        added["credential_scope"]["human_account_creation_privilege"],
        false
    );
    assert_eq!(added["browser_interaction_required_each_run"], false);
    assert_eq!(added["attribution"]["registered_by_user"], "user");
    assert_eq!(listed["records"].as_array().unwrap().len(), 1);
    assert_eq!(listed["credential_scope"]["listed_for_user"], "user");
    assert_eq!(revoked["revoked"], true);
    assert_eq!(revoked["attribution"]["revoked_by_user"], "user");
}

#[test]
fn key_lifecycle_uses_coordinator_bound_client_session_without_claimed_scope() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let stored_session = StoredCliSession {
        kind: "human".to_owned(),
        coordinator: addr.clone(),
        tenant: "tenant-session".to_owned(),
        project: "project-session".to_owned(),
        user: "user-session".to_owned(),
        cli_session_credential_kind: "CliDeviceSession".to_owned(),
        session_secret: Some("key-session-secret".to_owned()),
        token_expiry_posture: "unknown_coordinator_session".to_owned(),
        expires_at: None,
        provider_tokens_exposed_to_cli: false,
        provider_tokens_sent_to_nodes: false,
        created_at_unix_seconds: 1,
    };
    let server = std::thread::spawn(move || {
        for (expected, response) in [
            (
                "register_agent_public_key",
                br#"{"type":"agent_public_key","actor":"user-session","record":{"tenant":"tenant-session","project":"project-session","user":"user-session","agent":"agent-ci","public_key":"agent-key-v1","public_key_fingerprint":"sha256:agent-v1","version":1,"revoked":false,"scopes":["project:read","project:run"],"human_account_creation_privilege":false,"browser_interaction_required_each_run":false}}"#.as_slice(),
            ),
            (
                "list_agent_public_keys",
                br#"{"type":"agent_public_keys","actor":"user-session","records":[]}"#.as_slice(),
            ),
            (
                "revoke_agent_public_key",
                br#"{"type":"agent_public_key","actor":"user-session","record":{"tenant":"tenant-session","project":"project-session","user":"user-session","agent":"agent-ci","public_key":"agent-key-v1","public_key_fingerprint":"sha256:agent-v1","version":1,"revoked":true,"scopes":["project:read","project:run"],"human_account_creation_privilege":false,"browser_interaction_required_each_run":false}}"#.as_slice(),
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let wire: Value = serde_json::from_str(&line).unwrap();
            let payload = &wire["payload"];
            assert_eq!(payload["type"], "authenticated");
            assert_eq!(payload["session_secret"], "key-session-secret");
            assert_eq!(payload["request"]["type"], expected);
            assert!(payload["request"].get("tenant").is_none());
            assert!(payload["request"].get("project").is_none());
            assert!(payload["request"].get("user").is_none());
            stream.write_all(response).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    });
    let ignored_scope = CliScopeArgs {
        coordinator: None,
        tenant: "ignored-tenant".to_owned(),
        project: "ignored-project".to_owned(),
        user: "ignored-user".to_owned(),
        json: false,
    };

    let added = key_add_report_with_session(
        KeyAddArgs {
            scope: ignored_scope.clone(),
            agent: "agent-ci".to_owned(),
            public_key: "agent-key-v1".to_owned(),
        },
        Some(&stored_session),
    )
    .unwrap();
    let listed = key_list_report_with_session(
        KeyListArgs {
            scope: ignored_scope.clone(),
        },
        Some(&stored_session),
    )
    .unwrap();
    let revoked = key_revoke_report_with_session(
        KeyRevokeArgs {
            scope: ignored_scope,
            agent: "agent-ci".to_owned(),
            yes: true,
        },
        Some(&stored_session),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(added["tenant"], "tenant-session");
    assert_eq!(added["project"], "project-session");
    assert_eq!(added["user"], "user-session");
    assert_eq!(listed["tenant"], "tenant-session");
    assert_eq!(revoked["user"], "user-session");
}

#[test]
fn client_session_secret_is_never_sent_to_a_different_coordinator() {
    let stored_session = StoredCliSession {
        kind: "human".to_owned(),
        coordinator: "https://trusted.example:9443".to_owned(),
        tenant: "tenant-session".to_owned(),
        project: "project-session".to_owned(),
        user: "user-session".to_owned(),
        cli_session_credential_kind: "CliDeviceSession".to_owned(),
        session_secret: Some("must-not-leak".to_owned()),
        token_expiry_posture: "unknown_coordinator_session".to_owned(),
        expires_at: None,
        provider_tokens_exposed_to_cli: false,
        provider_tokens_sent_to_nodes: false,
        created_at_unix_seconds: 1,
    };
    let authenticated = crate::client::authenticated_or_local_trusted_request(
        "https://trusted.example:9443",
        Some(&stored_session),
        clusterflux_protocol::CoordinatorRequest::ListProjects {
            tenant: "tenant-session".to_owned(),
            actor_user: "user-session".to_owned(),
        },
    )
    .unwrap();
    let untrusted = crate::client::authenticated_or_local_trusted_request(
        "https://attacker.example:9443",
        Some(&stored_session),
        clusterflux_protocol::CoordinatorRequest::ListProjects {
            tenant: "tenant-session".to_owned(),
            actor_user: "user-session".to_owned(),
        },
    );

    let authenticated = serde_json::to_value(authenticated).unwrap();
    assert_eq!(authenticated["type"], "authenticated");
    assert_eq!(authenticated["session_secret"], "must-not-leak");
    let error = untrusted.unwrap_err().to_string();
    assert!(error.contains("no authenticated CLI session matches coordinator"));
    assert!(!error.contains("must-not-leak"));
}

#[test]
fn node_revoke_reports_scoped_credential_revocation() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"revoke_node_credential""#));
        assert!(line.contains(r#""tenant":"tenant""#));
        assert!(line.contains(r#""project":"project""#));
        assert!(line.contains(r#""actor_user":"user""#));
        assert!(line.contains(r#""node":"node-a""#));
        stream
                .write_all(
                    br#"{"type":"node_credential_revoked","node":"node-a","tenant":"tenant","project":"project","actor":"user","descriptor_removed":true,"queued_assignments_removed":2}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let temp = tempfile::tempdir().unwrap();
    let revoked = node_revoke_report(
        NodeRevokeArgs {
            scope: CliScopeArgs {
                coordinator: Some(addr),
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
            node: "node-a".to_owned(),
            yes: true,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(revoked["command"], "node revoke");
    assert_eq!(revoked["node"], "node-a");
    assert_eq!(revoked["credential_revoked"], true);
    assert_eq!(revoked["descriptor_removed"], true);
    assert_eq!(revoked["queued_assignments_removed"], 2);
    assert_eq!(revoked["node_credentials_separate_from_user_session"], true);
}

#[test]
fn admin_status_and_suspend_use_public_coordinator_api() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for (expected, response) in [
            (
                "admin_status",
                r#"{"type":"admin_status","tenant":"tenant","actor":"admin","suspended":false,"safe_default":"read_only"}"#,
            ),
            (
                "suspend_tenant",
                r#"{"type":"tenant_suspended","tenant":"tenant","actor":"admin","policy":{"tenant":"tenant","name":"tenant:suspended","digest":"sha256:suspension"}}"#,
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(&format!(r#""type":"{expected}""#)));
            assert!(
                line.contains(r#""tenant":"admin-tenant""#)
                    || line.contains(r#""tenant":"tenant""#)
            );
            assert!(line.contains(r#""actor_user":"admin""#));
            assert!(!line.contains(r#""admin_token""#));
            let wire: Value = serde_json::from_str(&line).unwrap();
            let payload = &wire["payload"];
            let tenant = payload["tenant"].as_str().unwrap();
            let actor_user = payload["actor_user"].as_str().unwrap();
            let target_tenant = payload["target_tenant"].as_str().unwrap_or(tenant);
            let admin_nonce = payload["admin_nonce"].as_str().unwrap();
            let issued_at_epoch_seconds = payload["issued_at_epoch_seconds"].as_u64().unwrap();
            assert_eq!(
                payload["admin_proof"],
                clusterflux_core::admin_request_proof(
                    "admin-token",
                    expected,
                    tenant,
                    actor_user,
                    target_tenant,
                    admin_nonce,
                    issued_at_epoch_seconds,
                )
                .to_string()
            );
            if expected == "suspend_tenant" {
                assert!(line.contains(r#""target_tenant":"tenant""#));
            }
            stream.write_all(response.as_bytes()).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    });
    let scope = CliScopeArgs {
        coordinator: Some(addr),
        tenant: "admin-tenant".to_owned(),
        project: "project".to_owned(),
        user: "admin".to_owned(),
        json: false,
    };

    let status = admin_status_report(AdminStatusArgs {
        scope: scope.clone(),
        admin_token: Some("admin-token".to_owned()),
    })
    .unwrap();
    let suspended = admin_suspend_tenant_report(AdminSuspendTenantArgs {
        scope,
        target_tenant: Some("tenant".to_owned()),
        admin_token: Some("admin-token".to_owned()),
        yes: true,
    })
    .unwrap();
    server.join().unwrap();

    assert_eq!(status["command"], "admin status");
    assert_eq!(status["safe_default"], "read_only");
    assert_eq!(status["external_website_required"], false);
    assert_eq!(status["suspended"], false);
    assert_eq!(suspended["command"], "admin suspend-tenant");
    assert_eq!(suspended["tenant"], "tenant");
    assert_eq!(suspended["actor_tenant"], "admin-tenant");
    assert_eq!(suspended["suspended"], true);
    assert_eq!(suspended["external_website_required"], false);
}

#[test]
fn admin_commands_require_explicit_admin_token_for_coordinator_requests() {
    let error = admin_status_report(AdminStatusArgs {
        scope: CliScopeArgs {
            coordinator: Some("127.0.0.1:9".to_owned()),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "admin".to_owned(),
            json: false,
        },
        admin_token: None,
    })
    .unwrap_err();

    assert!(error.to_string().contains("--admin-token"));
}

#[test]
fn debug_attach_reports_public_authorization() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"debug_attach""#));
        assert!(line.contains(r#""tenant":"tenant""#));
        assert!(line.contains(r#""project":"project""#));
        assert!(line.contains(r#""actor_user":"user""#));
        assert!(line.contains(r#""process":"vp""#));
        stream
                .write_all(
                    br#"{"type":"debug_attach","process":"vp","actor":"user","authorization":{"allowed":true,"reason":"debug attach authorized for project"},"audit_event":{"tenant":"tenant","project":"project","process":"vp","task":null,"actor":"user","operation":"debug_attach","allowed":true,"reason":"debug attach authorized for project","charged_debug_read_bytes":1024,"used_debug_read_bytes":1024},"charged_debug_read_bytes":1024,"used_debug_read_bytes":1024}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let report = debug_attach_report_with_dap(
        DebugAttachArgs {
            scope: CliScopeArgs {
                coordinator: Some(addr),
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
            process: "vp".to_owned(),
        },
        "/tmp/clusterflux-debug-dap-test".to_owned(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["command"], "debug attach");
    assert_eq!(report["process"], "vp");
    assert_eq!(report["authorized"], true);
    assert_eq!(
        report["authorization"]["reason"],
        "debug attach authorized for project"
    );
    assert_eq!(report["audit_event"]["operation"], "debug_attach");
    assert_eq!(report["charged_debug_read_bytes"], 1024);
    assert_eq!(report["used_debug_read_bytes"], 1024);
    assert_eq!(report["debug_reads_quota_limited"], true);
    assert_eq!(report["external_website_required"], false);
}

#[test]
fn user_control_commands_use_authenticated_envelope_with_stored_cli_session() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for (expected, response) in [
            (
                "list_processes",
                br#"{"type":"process_statuses","processes":[{"process":"vp","state":"running","main_task_definition":null,"main_task_instance":null,"main_state":null,"main_wait_state":null,"main_debug_epoch":null,"connected_nodes":[],"coordinator_epoch":42}],"actor":"user-session"}"#.as_slice(),
            ),
            (
                "list_task_events",
                br#"{"type":"task_events","events":[]}"#.as_slice(),
            ),
            (
                "list_processes",
                br#"{"type":"process_statuses","processes":[{"process":"vp","state":"running","main_task_definition":null,"main_task_instance":null,"main_state":null,"main_wait_state":null,"main_debug_epoch":null,"connected_nodes":[],"coordinator_epoch":42}],"actor":"user-session"}"#.as_slice(),
            ),
            (
                "start_process",
                br#"{"type":"process_started","process":"vp","epoch":42,"actor":{"kind":"user","user":"user-session","agent":null,"credential_kind":"CliDeviceSession","public_key_fingerprint":null,"authenticated_without_browser":false,"scopes":["project:read","project:run"]},"charged_spawns":1}"#.as_slice(),
            ),
            (
                "cancel_process",
                br#"{"type":"process_cancellation_requested","process":"vp","cancelled_tasks":[],"affected_nodes":[]}"#.as_slice(),
            ),
            (
                "abort_process",
                br#"{"type":"process_aborted","process":"vp","aborted_tasks":[],"affected_nodes":[]}"#.as_slice(),
            ),
            (
                "restart_task",
                br#"{"type":"task_restart","process":"vp","task":"task-a","restarted_task_instance":null,"restarted_attempt_id":null,"actor":"user-session","accepted":false,"clean_boundary_available":false,"active_task":false,"completed_event_observed":false,"requires_whole_process_restart":true,"message":"restart requires checkpoint","charged_debug_read_bytes":1024,"used_debug_read_bytes":1024,"audit_event":{"tenant":"tenant-session","project":"project-session","process":"vp","task":"task-a","actor":"user-session","operation":"restart_task","allowed":true,"reason":"restart requires checkpoint","charged_debug_read_bytes":1024,"used_debug_read_bytes":1024}}"#.as_slice(),
            ),
            (
                "list_task_events",
                br#"{"type":"task_events","events":[{"tenant":"tenant-session","project":"project-session","process":"vp","node":"node-a","executor":"node","task_definition":"definition-task-a","task":"task-a","terminal_state":"completed","status_code":0,"stdout_bytes":9,"stderr_bytes":0,"stdout_tail":"compiled\n","stderr_tail":"","stdout_truncated":false,"stderr_truncated":false,"artifact_path":null,"artifact_digest":null,"artifact_size_bytes":null,"result":null}]}"#.as_slice(),
            ),
            (
                "list_task_events",
                br#"{"type":"task_events","events":[{"tenant":"tenant-session","project":"project-session","process":"vp","node":"node-a","executor":"node","task_definition":"definition-task-a","task":"task-a","terminal_state":"completed","status_code":0,"stdout_bytes":0,"stderr_bytes":0,"stdout_tail":"","stderr_tail":"","stdout_truncated":false,"stderr_truncated":false,"artifact_path":"/vfs/artifacts/app.txt","artifact_digest":"sha256:app","artifact_size_bytes":3,"result":null}]}"#.as_slice(),
            ),
            (
                "create_artifact_download_link",
                br#"{"type":"artifact_download_link","link":{"artifact":"app.txt","artifact_digest":"sha256:app","artifact_size_bytes":3,"source":{"RetainedNode":"node-a"},"url_path":"/artifacts/tenant-session/project-session/vp/app.txt","scoped_token_digest":"sha256:token","expires_at_epoch_seconds":60,"tenant":"tenant-session","project":"project-session","process":"vp","actor":{"User":"user-session"},"max_bytes":2048,"policy_context_digest":"sha256:policy"}}"#.as_slice(),
            ),
            (
                "debug_attach",
                br#"{"type":"debug_attach","process":"vp","actor":"user-session","authorization":{"allowed":true,"reason":"debug attach authorized for project"},"audit_event":{"tenant":"tenant-session","project":"project-session","process":"vp","task":null,"actor":"user-session","operation":"debug_attach","allowed":true,"reason":"debug attach authorized for project","charged_debug_read_bytes":1024,"used_debug_read_bytes":1024},"charged_debug_read_bytes":1024,"used_debug_read_bytes":1024}"#.as_slice(),
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(r#""type":"coordinator_request""#));
            assert!(line.contains(r#""type":"authenticated""#));
            assert!(line.contains(r#""session_secret":"control-cli-session-secret""#));
            assert!(line.contains(&format!(r#""type":"{expected}""#)));
            assert!(!line.contains("ignored-tenant"));
            assert!(!line.contains("ignored-project"));
            assert!(!line.contains("ignored-user"));
            stream.write_all(response).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    });
    let session = StoredCliSession {
        kind: "human".to_owned(),
        coordinator: addr.clone(),
        tenant: "tenant-session".to_owned(),
        project: "project-session".to_owned(),
        user: "user-session".to_owned(),
        cli_session_credential_kind: "CliDeviceSession".to_owned(),
        session_secret: Some("control-cli-session-secret".to_owned()),
        token_expiry_posture: "unknown_coordinator_session".to_owned(),
        expires_at: None,
        provider_tokens_exposed_to_cli: false,
        provider_tokens_sent_to_nodes: false,
        created_at_unix_seconds: 1,
    };
    let scope = CliScopeArgs {
        coordinator: None,
        tenant: "ignored-tenant".to_owned(),
        project: "ignored-project".to_owned(),
        user: "ignored-user".to_owned(),
        json: false,
    };
    let coordinator_scope = CliScopeArgs {
        coordinator: Some(addr),
        ..scope.clone()
    };

    process_status_report_with_session(
        ProcessStatusArgs {
            scope: scope.clone(),
            process: "vp".to_owned(),
        },
        Some(&session),
    )
    .unwrap();
    process_list_report_with_session(
        ProcessListArgs {
            scope: scope.clone(),
        },
        Some(&session),
    )
    .unwrap();
    process_restart_report_with_session(
        ProcessRestartArgs {
            scope: scope.clone(),
            process: "vp".to_owned(),
            yes: true,
        },
        Some(&session),
    )
    .unwrap();
    process_cancel_report_with_session(
        ProcessCancelArgs {
            scope: scope.clone(),
            process: "vp".to_owned(),
            node: None,
            task: None,
            yes: true,
        },
        Some(&session),
    )
    .unwrap();
    process_abort_report_with_session(
        ProcessAbortArgs {
            scope: scope.clone(),
            process: "vp".to_owned(),
            yes: true,
        },
        Some(&session),
    )
    .unwrap();
    task_restart_report_with_session(
        TaskRestartArgs {
            scope: coordinator_scope.clone(),
            task: "task-a".to_owned(),
            process: "vp".to_owned(),
            yes: true,
        },
        Some(&session),
    )
    .unwrap();
    let logs = logs_report_with_session(
        LogsArgs {
            scope: scope.clone(),
            process: Some("vp".to_owned()),
            task: Some("task-a".to_owned()),
        },
        Some(&session),
    )
    .unwrap();
    let artifacts = artifact_list_report_with_session(
        ArtifactListArgs {
            scope: scope.clone(),
            process: Some("vp".to_owned()),
        },
        Some(&session),
    )
    .unwrap();
    let download = artifact_download_report_with_session(
        ArtifactDownloadArgs {
            scope,
            artifact: "app.txt".to_owned(),
            to: None,
            max_bytes: 2048,
        },
        Some(&session),
    )
    .unwrap();
    assert_eq!(logs["log_entries"][0]["stdout_tail"], "compiled\n");
    assert_eq!(artifacts["artifacts"][0]["artifact"], "app.txt");
    assert_eq!(download["coordinator"], session.coordinator);
    debug_attach_report_with_dap_and_session(
        DebugAttachArgs {
            scope: coordinator_scope,
            process: "vp".to_owned(),
        },
        "/tmp/clusterflux-debug-dap-test".to_owned(),
        Some(&session),
    )
    .unwrap();
    server.join().unwrap();
}

#[test]
fn json_line_session_preserves_typed_coordinator_errors() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let server = std::thread::spawn(move || {
        let (stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut request = String::new();
        reader.read_line(&mut request).unwrap();
        let request: Value = serde_json::from_str(&request).unwrap();
        let request_id = request["request_id"].as_str().unwrap();
        let response = json!({
            "type": "error",
            "code": "session_expired",
            "category": "authentication",
            "message": "wording is not part of the contract",
            "retryable": false,
            "request_id": request_id
        });
        writeln!(&stream, "{response}").unwrap();
    });

    let mut session =
        crate::client::JsonLineSession::connect(&format!("clusterflux+tcp://{address}")).unwrap();
    let error = session
        .request(clusterflux_protocol::CoordinatorRequest::Ping)
        .unwrap_err();
    let api_error = error
        .downcast_ref::<clusterflux_core::ApiError>()
        .expect("typed API error must survive the CLI transport boundary");
    assert_eq!(
        api_error.code,
        clusterflux_core::ApiErrorCode::SessionExpired
    );
    assert_eq!(api_error.message, "wording is not part of the contract");
    server.join().unwrap();
}
