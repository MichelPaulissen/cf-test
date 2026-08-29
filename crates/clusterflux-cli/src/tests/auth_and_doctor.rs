use super::*;

#[test]
fn hosted_coordinator_remains_a_real_https_control_endpoint() {
    assert_eq!(
        control_endpoint_identity(DEFAULT_HOSTED_COORDINATOR_ENDPOINT).unwrap(),
        "https://clusterflux.lesstuff.com/api/v1/control"
    );
    assert_eq!(
        control_endpoint_identity("https://clusterflux.lesstuff.com/api/v1/control").unwrap(),
        "https://clusterflux.lesstuff.com/api/v1/control"
    );
    assert!(control_endpoint_identity("http://operator.example.test").is_err());
    assert_eq!(
        control_endpoint_identity("127.0.0.1:7999").unwrap(),
        "clusterflux+tcp://127.0.0.1:7999"
    );
}

#[test]
fn doctor_reports_unchecked_coordinator_reachability_without_config() {
    let temp = tempfile::tempdir().unwrap();
    let report = doctor::doctor_report_with_capabilities(
        DoctorArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
        test_linux_container_node_capabilities(),
    )
    .unwrap();

    assert_eq!(report["command"], "doctor");
    assert!(report["coordinator"].is_null());
    assert_eq!(report["coordinator_reachability"]["checked"], false);
    assert_eq!(
        report["coordinator_reachability"]["status"],
        "not_configured"
    );
    assert!(matches!(
        report["node_readiness_summary"]["status"].as_str(),
        Some("ready_to_attach") | Some("local_dependencies_missing") | Some("limited_capabilities")
    ));
    assert_eq!(
        report["node_readiness_summary"]["explicit_attach_required"],
        true
    );
    assert_eq!(
        report["node_readiness_summary"]["command_execution_capability"],
        true
    );
    assert!(report["node_readiness_summary"]["missing_local_dependencies"].is_array());
    assert!(
        report["node_readiness_summary"]["next_actions"]
            .as_array()
            .unwrap()
            .len()
            >= 2
    );
}

#[test]
fn doctor_pings_configured_coordinator() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        let request: serde_json::Value = serde_json::from_str(&line).unwrap();
        assert_eq!(request["type"], "coordinator_request");
        assert_eq!(request["protocol_version"], 1);
        assert_eq!(request["request_id"], "doctor-1");
        assert_eq!(request["operation"], "ping");
        assert_eq!(request["authentication"]["kind"], "none");
        assert_eq!(request["payload"]["type"], "ping");
        stream
            .write_all(b"{\"type\":\"pong\",\"epoch\":42}\n")
            .unwrap();
    });

    let temp = tempfile::tempdir().unwrap();
    let report = doctor_report(
        DoctorArgs {
            scope: CliScopeArgs {
                coordinator: Some(addr.clone()),
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["coordinator"], addr);
    assert_eq!(report["coordinator_reachability"]["checked"], true);
    assert_eq!(report["coordinator_reachability"]["status"], "reachable");
    assert_eq!(
        report["coordinator_reachability"]["response"]["type"],
        "pong"
    );
    assert_eq!(report["coordinator_reachability"]["response"]["epoch"], 42);
}

#[test]
fn auth_status_reads_stored_cli_session_without_provider_tokens() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"authenticated""#));
        assert!(line.contains(r#""session_secret":"clusterflux-cli-session-secret""#));
        assert!(line.contains(r#""type":"auth_status""#));
        assert!(!line.contains(r#""actor_user":"user-session""#));
        stream
                .write_all(
                    br#"{"type":"auth_status","tenant":"tenant-session","project":"project-session","actor":"user-session","authenticated":true,"account_status":"active","suspended":false,"disabled":false,"deleted":false,"manual_review":false,"sanitized_reason":null,"next_actions":[],"sensitive_moderation_details_exposed":false,"signup_failure_details_exposed":false}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: addr.clone(),
            tenant: "tenant-session".to_owned(),
            project: "project-session".to_owned(),
            user: "user-session".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("clusterflux-cli-session-secret".to_owned()),
            token_expiry_posture: "expires_at".to_owned(),
            expires_at: Some("2026-07-04T00:00:00Z".to_owned()),
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();

    let report = auth_status_report(
        AuthStatusArgs {
            require_valid_for: None,
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["active_coordinator"], addr);
    assert_eq!(report["principal"], "user-session");
    assert_eq!(report["tenant"], "tenant-session");
    assert_eq!(report["project"], "project-session");
    assert_eq!(report["session"]["kind"], "human");
    assert_eq!(report["session"]["source"], "session_file");
    assert_eq!(report["session"]["authenticated"], true);
    assert_eq!(
        report["session"]["cli_session_credential_kind"],
        "CliDeviceSession"
    );
    assert_eq!(
        report["coordinator_account_status"]["used_cli_session_credential"],
        true
    );
    assert_eq!(report["session"]["token_expiry_posture"], "expires_at");
    assert_eq!(report["session"]["provider_tokens_exposed_to_cli"], false);
    assert_eq!(report["session"]["provider_tokens_exposed_to_nodes"], false);
    assert_eq!(report["coordinator_account_status"]["checked"], true);
    assert_eq!(
        report["coordinator_account_status"]["account_status"],
        "active"
    );
    assert_eq!(
        report["coordinator_account_status"]["sensitive_moderation_details_exposed"],
        false
    );
}

#[test]
fn auth_status_requires_enough_confirmed_session_validity() {
    for (remaining, expected) in [(120_u64, true), (30_u64, false)] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            stream.write_all(br#"{"type":"auth_status","tenant":"tenant-session","project":"project-session","actor":"user-session","authenticated":true,"account_status":"active","suspended":false,"disabled":false,"deleted":false,"manual_review":false,"sanitized_reason":null,"next_actions":[],"sensitive_moderation_details_exposed":false,"signup_failure_details_exposed":false}"#).unwrap();
            stream.write_all(b"\n").unwrap();
        });
        write_cli_session(
            temp.path(),
            &StoredCliSession {
                kind: "human".to_owned(),
                coordinator: addr,
                tenant: "tenant-session".to_owned(),
                project: "project-session".to_owned(),
                user: "user-session".to_owned(),
                cli_session_credential_kind: "CliDeviceSession".to_owned(),
                session_secret: Some("session-secret".to_owned()),
                token_expiry_posture: "expires_at".to_owned(),
                expires_at: Some(
                    crate::tools::unix_timestamp_seconds()
                        .saturating_add(remaining)
                        .to_string(),
                ),
                provider_tokens_exposed_to_cli: false,
                provider_tokens_sent_to_nodes: false,
                created_at_unix_seconds: 1,
            },
        )
        .unwrap();
        let report = auth_status_report(
            AuthStatusArgs {
                require_valid_for: Some(std::time::Duration::from_secs(60)),
                scope: CliScopeArgs {
                    coordinator: None,
                    tenant: "tenant".to_owned(),
                    project: "project".to_owned(),
                    user: "user".to_owned(),
                    json: false,
                },
            },
            temp.path().to_path_buf(),
        )
        .unwrap();
        server.join().unwrap();
        assert_eq!(report["valid_for_requirement_met"], expected);
        assert_eq!(report["required_valid_for_seconds"], 60);
        assert_eq!(report["machine_error"].is_null(), expected);
        if !expected {
            assert_eq!(report["machine_error"]["category"], "authentication");
            assert_eq!(report["guidance"]["recommended"]["command"][1], "login");
        }
    }
}

#[test]
fn auth_status_reports_expired_or_revoked_cli_session_as_login_required() {
    for message in [
        "unauthorized coordinator action: CLI session credential has expired; run clusterflux login --browser again",
        "unauthorized coordinator action: CLI session credential has been revoked",
    ] {
        let temp = tempfile::tempdir().unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap().to_string();
        let server_message = message.to_owned();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(r#""type":"authenticated""#));
            assert!(line.contains(r#""session_secret":"stale-cli-session-secret""#));
            assert!(line.contains(r#""type":"auth_status""#));
            writeln!(
                stream,
                "{}",
                canonical_error_response(&line, &server_message)
            )
            .unwrap();
        });
        write_cli_session(
            temp.path(),
            &StoredCliSession {
                kind: "human".to_owned(),
                coordinator: addr.clone(),
                tenant: "tenant-session".to_owned(),
                project: "project-session".to_owned(),
                user: "user-session".to_owned(),
                cli_session_credential_kind: "CliDeviceSession".to_owned(),
                session_secret: Some("stale-cli-session-secret".to_owned()),
                token_expiry_posture: "expires_at".to_owned(),
                expires_at: Some("2026-07-04T00:00:00Z".to_owned()),
                provider_tokens_exposed_to_cli: false,
                provider_tokens_sent_to_nodes: false,
                created_at_unix_seconds: 1,
            },
        )
        .unwrap();

        let report = auth_status_report(
            AuthStatusArgs {
                require_valid_for: None,
                scope: CliScopeArgs {
                    coordinator: None,
                    tenant: "tenant".to_owned(),
                    project: "project".to_owned(),
                    user: "user".to_owned(),
                    json: false,
                },
            },
            temp.path().to_path_buf(),
        )
        .unwrap();
        server.join().unwrap();

        assert_eq!(report["coordinator_account_status"]["checked"], true);
        assert_eq!(report["coordinator_account_status"]["reachable"], true);
        assert_eq!(
            report["coordinator_account_status"]["machine_error"]["category"],
            "authentication"
        );
        assert_eq!(report["machine_error"]["category"], "authentication");
        let mut exit_report = report.clone();
        assert_eq!(
            crate::output::apply_command_report_exit_code(&mut exit_report),
            Some(20)
        );
        assert_eq!(
            exit_report["machine_error"]["process_exit_code_applied"],
            true
        );
        assert!(
            report["coordinator_account_status"]["next_actions"]
                .as_array()
                .unwrap()
                .iter()
                .any(|action| action == "clusterflux login --browser")
        );
    }
}

#[test]
fn auth_status_queries_coordinator_account_state_without_sensitive_moderation_details() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"auth_status""#));
        assert!(line.contains(r#""tenant":"tenant-live""#));
        assert!(line.contains(r#""project":"project-live""#));
        assert!(line.contains(r#""actor_user":"user-live""#));
        stream
                .write_all(
                    br#"{"type":"auth_status","tenant":"tenant-live","project":"project-live","actor":"user-live","authenticated":true,"account_status":"suspended","suspended":true,"disabled":false,"deleted":false,"manual_review":false,"sanitized_reason":"account or tenant is suspended by hosted policy","next_actions":["contact the hosted operator"],"sensitive_moderation_details_exposed":false,"signup_failure_details_exposed":false,"abuse_score":99,"moderation_notes":"sensitive moderation note"}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let temp = tempfile::tempdir().unwrap();
    let report = auth_status_report(
        AuthStatusArgs {
            require_valid_for: None,
            scope: CliScopeArgs {
                coordinator: Some(addr),
                tenant: "tenant-live".to_owned(),
                project: "project-live".to_owned(),
                user: "user-live".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["command"], "auth status");
    assert_eq!(report["coordinator_account_status"]["checked"], true);
    assert_eq!(report["coordinator_account_status"]["reachable"], true);
    assert_eq!(
        report["coordinator_account_status"]["source"],
        "public_coordinator_api"
    );
    assert_eq!(
        report["coordinator_account_status"]["account_status"],
        "suspended"
    );
    assert_eq!(report["coordinator_account_status"]["suspended"], true);
    assert_eq!(report["coordinator_account_status"]["disabled"], false);
    assert_eq!(
        report["coordinator_account_status"]["sanitized_reason"],
        "account or tenant is suspended by hosted policy"
    );
    assert_eq!(
        report["coordinator_account_status"]["sensitive_moderation_details_exposed"],
        false
    );
    assert_eq!(
        report["coordinator_account_status"]["signup_failure_details_exposed"],
        false
    );
    assert_eq!(
        report["coordinator_account_status"]["coordinator_response_type"],
        "auth_status"
    );
    assert_eq!(
        report["coordinator_account_status"]["coordinator_session_requests"],
        1
    );
    let serialized = serde_json::to_string(&report).unwrap();
    assert!(!serialized.contains("abuse_score"));
    assert!(!serialized.contains("moderation_notes"));
    assert!(!serialized.contains("sensitive moderation note"));

    let rendered = human_report(&report);
    assert!(rendered.contains("account status: suspended"));
    assert!(rendered.contains("account suspended: true"));
    assert!(rendered.contains("sensitive moderation details exposed: false"));
    assert!(!rendered.contains("sensitive moderation note"));
}

#[test]
fn auth_status_reports_disabled_deleted_and_manual_review_safely() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for (tenant, status, reason, flags) in [
            (
                "tenant-disabled",
                "disabled",
                "account or tenant is disabled by hosted policy",
                (false, true, false, false),
            ),
            (
                "tenant-deleted",
                "deleted",
                "account or tenant is no longer active",
                (false, false, true, false),
            ),
            (
                "tenant-review",
                "manual_review",
                "account or tenant is pending hosted review",
                (false, false, false, true),
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(r#""type":"auth_status""#));
            assert!(line.contains(&format!(r#""tenant":"{tenant}""#)));
            let (suspended, disabled, deleted, manual_review) = flags;
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "auth_status",
                    "tenant": tenant,
                    "project": "project-live",
                    "actor": "user-live",
                    "authenticated": true,
                    "account_status": status,
                    "suspended": suspended,
                    "disabled": disabled,
                    "deleted": deleted,
                    "manual_review": manual_review,
                    "sanitized_reason": reason,
                    "next_actions": ["contact the hosted operator"],
                    "sensitive_moderation_details_exposed": false,
                    "signup_failure_details_exposed": false,
                    "abuse_score": 99,
                    "moderation_notes": "sensitive moderation note",
                    "signup_policy_trace": "sensitive signup trace",
                })
            )
            .unwrap();
        }
    });

    for (tenant, status, rendered_marker) in [
        ("tenant-disabled", "disabled", "account disabled: true"),
        ("tenant-deleted", "deleted", "account deleted: true"),
        (
            "tenant-review",
            "manual_review",
            "account manual review: true",
        ),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let report = auth_status_report(
            AuthStatusArgs {
                require_valid_for: None,
                scope: CliScopeArgs {
                    coordinator: Some(addr.clone()),
                    tenant: tenant.to_owned(),
                    project: "project-live".to_owned(),
                    user: "user-live".to_owned(),
                    json: false,
                },
            },
            temp.path().to_path_buf(),
        )
        .unwrap();
        assert_eq!(
            report["coordinator_account_status"]["account_status"],
            status
        );
        assert_eq!(
            report["coordinator_account_status"]["account_state_known"],
            true
        );
        assert_eq!(
            report["coordinator_account_status"]["sensitive_moderation_details_exposed"],
            false
        );
        assert_eq!(
            report["coordinator_account_status"]["signup_failure_details_exposed"],
            false
        );
        let serialized = serde_json::to_string(&report).unwrap();
        assert!(!serialized.contains("abuse_score"));
        assert!(!serialized.contains("moderation_notes"));
        assert!(!serialized.contains("signup_policy_trace"));
        assert!(!serialized.contains("sensitive moderation note"));
        let rendered = human_report(&report);
        assert!(rendered.contains(&format!("account status: {status}")));
        assert!(rendered.contains(rendered_marker));
        assert!(!rendered.contains("sensitive moderation note"));
    }
    server.join().unwrap();
}
