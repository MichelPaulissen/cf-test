use super::*;
use clusterflux_protocol::CoordinatorResponse;

#[test]
fn human_report_is_text_not_json() {
    let report = json!({
        "command": "doctor",
        "status": "ok",
        "coordinator": "127.0.0.1:9443",
        "next_actions": ["clusterflux login --browser", "clusterflux project init"],
    });
    let human = human_report(&report);

    assert!(!human.trim_start().starts_with('{'));
    assert!(human.contains("Clusterflux doctor"));
    assert!(human.contains("status: ok"));
    assert!(human.contains("coordinator: 127.0.0.1:9443"));
    assert!(human.contains("clusterflux login --browser"));
}

#[test]
fn human_node_status_matches_web_drain_reasons_without_network_internals() {
    let report = json!({
        "command": "node status",
        "node": "worker-a",
        "response": {
            "type": "node_summaries",
            "nodes": [{
                "id": "worker-a",
                "online": false,
                "drain": {
                    "state": "draining",
                    "running_task_count": 1,
                    "queued_task_count": 2,
                    "active_transfer_count": 1,
                    "retained_bytes": 4096,
                    "soft_drain_deadline_epoch_seconds": 120,
                    "hard_drain_deadline_epoch_seconds": 180,
                    "hard_deadline_reached": false,
                    "blockers": [{
                        "summary": "Only copy retained for running task task-a",
                        "endpoint_id": "must-not-be-rendered",
                        "relay_urls": ["https://must-not-be-rendered.invalid"]
                    }]
                }
            }]
        }
    });
    let human = human_report(&report);
    assert!(human
        .contains("drain: draining; 1 running, 2 queued, 1 transfer(s), 4096 retained byte(s)"));
    assert!(human.contains("blocker: Only copy retained for running task task-a"));
    assert!(human.contains("soft drain deadline: 120"));
    assert!(human.contains("hard drain deadline: 180"));
    assert!(!human.contains("must-not-be-rendered"));
}

#[test]
fn project_init_select_and_status_use_local_project_config() {
    let temp = tempfile::tempdir().unwrap();

    let init = project_init_report(
        ProjectInitArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "ignored".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
            new_project: "project-a".to_owned(),
            name: "Project A".to_owned(),
            yes: true,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    assert_eq!(init["command"], "project init");
    assert_eq!(init["source"], "local_project_config");
    assert_eq!(init["project_config_written"], true);
    assert_eq!(
        init["current_directory_link"]["config_format"],
        "clusterflux_project_config_v1"
    );
    assert_eq!(
        init["current_directory_link"]["links_current_directory"],
        true
    );
    assert_eq!(
        init["current_directory_link"]["writes_current_directory_only"],
        true
    );
    assert_eq!(init["safe_defaults"]["project"], "project-a");
    assert_eq!(init["safe_defaults"]["tenant"], "tenant");
    assert_eq!(init["safe_defaults"]["browser_interaction_required"], false);
    assert_eq!(init["coordinator_create_before_local_write"], false);
    let rendered = human_report(&init);
    assert!(rendered.contains("current directory linked: true"));
    assert!(rendered.contains("current directory config:"));

    let config = read_project_config(temp.path()).unwrap().unwrap();
    assert_eq!(config.project, "project-a");
    assert_eq!(config.tenant, "tenant");

    let selected = project_select_report(
        ProjectSelectArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "tenant".to_owned(),
                project: "ignored".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
            selected_project: "project-b".to_owned(),
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    assert_eq!(selected["command"], "project select");
    assert_eq!(
        read_project_config(temp.path()).unwrap().unwrap().project,
        "project-b"
    );

    let status = project_status_report(
        ProjectStatusArgs {
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
    assert_eq!(status["command"], "project status");
    assert_eq!(status["project_identity"]["project"], "project-b");
    assert_eq!(status["project_identity"]["tenant"], "tenant");
    assert_eq!(status["active_process"], "unknown_without_coordinator");
    assert_eq!(status["attached_nodes"]["checked"], false);
}

#[test]
fn project_init_uses_public_create_before_writing_local_config() {
    let temp_success = tempfile::tempdir().unwrap();
    let temp_rejected = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for index in 0..2 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(r#""type":"create_project""#));
            assert!(line.contains(r#""tenant":"tenant-live""#));
            assert!(line.contains(r#""actor_user":"user-live""#));
            match index {
                0 => {
                    assert!(line.contains(r#""project":"project-created""#));
                    stream
                            .write_all(
                                br#"{"type":"project_created","project":{"id":"project-created","tenant":"tenant-live","name":"Created Project"},"actor":"user-live"}"#,
                            )
                            .unwrap();
                }
                1 => {
                    assert!(line.contains(r#""project":"foreign-project""#));
                    write!(
                        stream,
                        "{}",
                        canonical_error_response(
                            &line,
                            "project id is outside the signed-in tenant scope"
                        )
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            stream.write_all(b"\n").unwrap();
        }
    });

    let scope = CliScopeArgs {
        coordinator: Some(addr),
        tenant: "tenant-live".to_owned(),
        project: "ignored".to_owned(),
        user: "user-live".to_owned(),
        json: false,
    };
    let created = project_init_report(
        ProjectInitArgs {
            scope: scope.clone(),
            new_project: "project-created".to_owned(),
            name: "Created Project".to_owned(),
            yes: true,
        },
        temp_success.path().to_path_buf(),
    )
    .unwrap();

    assert_eq!(created["command"], "project init");
    assert_eq!(created["source"], "public_coordinator_api");
    assert_eq!(created["coordinator_create_before_local_write"], true);
    assert_eq!(
        created["project_config_write_after_coordinator_acceptance"],
        true
    );
    assert_eq!(created["coordinator_session_requests"], 1);
    assert_eq!(
        created["created_or_linked_project"]["id"],
        "project-created"
    );
    assert_eq!(
        created["current_directory_link"]["links_current_directory"],
        true
    );
    assert_eq!(
        created["safe_defaults"]["browser_interaction_required"],
        false
    );
    assert_eq!(created["external_website_required"], false);
    assert_eq!(
        read_project_config(temp_success.path())
            .unwrap()
            .unwrap()
            .project,
        "project-created"
    );

    let rejected = project_init_report(
        ProjectInitArgs {
            scope,
            new_project: "foreign-project".to_owned(),
            name: "Foreign Project".to_owned(),
            yes: true,
        },
        temp_rejected.path().to_path_buf(),
    )
    .unwrap_err();
    server.join().unwrap();

    assert!(rejected.to_string().contains("tenant scope"));
    assert!(read_project_config(temp_rejected.path()).unwrap().is_none());
}

#[test]
fn project_list_and_select_use_public_api_without_website() {
    let temp = tempfile::tempdir().unwrap();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "tenant-live".to_owned(),
            project: "project-original".to_owned(),
            user: "user-live".to_owned(),
            coordinator: None,
        },
    )
    .unwrap();

    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for index in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(r#""tenant":"tenant-live""#));
            assert!(line.contains(r#""actor_user":"user-live""#));
            match index {
                0 => {
                    assert!(line.contains(r#""type":"list_projects""#));
                    stream
                            .write_all(
                                br#"{"type":"projects","projects":[{"id":"project-a","tenant":"tenant-live","name":"Project A"}],"actor":"user-live"}"#,
                            )
                            .unwrap();
                }
                1 => {
                    assert!(line.contains(r#""type":"select_project""#));
                    assert!(line.contains(r#""project":"project-a""#));
                    stream
                            .write_all(
                                br#"{"type":"project_selected","project":{"id":"project-a","tenant":"tenant-live","name":"Project A"},"actor":"user-live"}"#,
                            )
                            .unwrap();
                }
                2 => {
                    assert!(line.contains(r#""type":"select_project""#));
                    assert!(line.contains(r#""project":"project-b""#));
                    write!(
                        stream,
                        "{}",
                        canonical_error_response(
                            &line,
                            "project is outside the signed-in tenant scope"
                        )
                    )
                    .unwrap();
                }
                _ => unreachable!(),
            }
            stream.write_all(b"\n").unwrap();
        }
    });

    let scope = CliScopeArgs {
        coordinator: Some(addr),
        tenant: "tenant-live".to_owned(),
        project: "project".to_owned(),
        user: "user-live".to_owned(),
        json: false,
    };
    let list = project_list_report(
        ProjectListArgs {
            scope: scope.clone(),
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    assert_eq!(list["command"], "project list");
    assert_eq!(list["source"], "public_coordinator_api");
    assert_eq!(list["project_count"], 1);
    assert_eq!(list["projects"][0]["id"], "project-a");
    assert_eq!(list["external_website_required"], false);
    assert_eq!(list["coordinator_session_requests"], 1);

    let selected = project_select_report(
        ProjectSelectArgs {
            scope: scope.clone(),
            selected_project: "project-a".to_owned(),
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    assert_eq!(selected["command"], "project select");
    assert_eq!(selected["source"], "public_coordinator_api");
    assert_eq!(selected["selected_project"]["id"], "project-a");
    assert_eq!(selected["project_config_written"], true);
    assert_eq!(selected["external_website_required"], false);
    assert_eq!(
        read_project_config(temp.path()).unwrap().unwrap().project,
        "project-a"
    );

    let rejected = project_select_report(
        ProjectSelectArgs {
            scope,
            selected_project: "project-b".to_owned(),
        },
        temp.path().to_path_buf(),
    )
    .unwrap_err();
    server.join().unwrap();

    assert!(rejected.to_string().contains("tenant scope"));
    assert_eq!(
        read_project_config(temp.path()).unwrap().unwrap().project,
        "project-a"
    );
}

#[test]
fn project_list_uses_authenticated_envelope_with_stored_cli_session() {
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
            session_secret: Some("project-list-session-secret".to_owned()),
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
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"authenticated""#));
        assert!(line.contains(r#""session_secret":"project-list-session-secret""#));
        assert!(line.contains(r#""type":"list_projects""#));
        assert!(!line.contains(r#""actor_user":"user-session""#));
        stream
                .write_all(
                    br#"{"type":"projects","projects":[{"id":"project-session","tenant":"tenant-session","name":"Session Project"}],"actor":"user-session"}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let report = project_list_report(
        ProjectListArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "ignored-tenant".to_owned(),
                project: "ignored-project".to_owned(),
                user: "ignored-user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["source"], "public_coordinator_api");
    assert_eq!(report["tenant"], "tenant-session");
    assert_eq!(report["user"], "user-session");
    assert_eq!(report["projects"][0]["id"], "project-session");
}

#[test]
fn project_select_updates_the_authoritative_stored_session_scope() {
    let temp = tempfile::tempdir().unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    write_cli_session(
        temp.path(),
        &StoredCliSession {
            kind: "human".to_owned(),
            coordinator: addr.clone(),
            tenant: "tenant-session".to_owned(),
            project: "project-one".to_owned(),
            user: "user-session".to_owned(),
            cli_session_credential_kind: "CliDeviceSession".to_owned(),
            session_secret: Some("project-select-session-secret".to_owned()),
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
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""session_secret":"project-select-session-secret""#));
        assert!(line.contains(r#""type":"select_project""#));
        assert!(line.contains(r#""project":"project-two""#));
        stream
            .write_all(
                br#"{"type":"project_selected","project":{"id":"project-two","tenant":"tenant-session","name":"Project Two"},"actor":"user-session"}"#,
            )
            .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    project_select_report(
        ProjectSelectArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "ignored-tenant".to_owned(),
                project: "ignored-project".to_owned(),
                user: "ignored-user".to_owned(),
                json: false,
            },
            selected_project: "project-two".to_owned(),
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(
        read_cli_session(temp.path()).unwrap().unwrap().project,
        "project-two"
    );
    assert_eq!(
        read_project_config(temp.path()).unwrap().unwrap().project,
        "project-two"
    );
}

#[test]
fn project_status_queries_public_coordinator_state() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.contains("\"type\":\"list_node_descriptors\"") {
                assert!(line.contains("\"project\":\"project-live\""));
                write!(
                    stream,
                    "{}",
                    json!({
                        "type": "node_descriptors",
                        "descriptors": [test_node_descriptor(
                            "node-a",
                            "tenant-live",
                            "project-live",
                            true,
                        )],
                        "actor": "user",
                    })
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            } else if line.contains("\"type\":\"list_task_events\"") {
                assert!(line.contains("\"project\":\"project-live\""));
                write!(
                    stream,
                    "{}",
                    json!({
                        "type": "task_events",
                        "events": [test_task_completion_event(
                            "tenant-live",
                            "project-live",
                            "vp-live",
                            "node-a",
                            "task-a",
                        )],
                    })
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            } else if line.contains("\"type\":\"list_processes\"") {
                assert!(line.contains("\"project\":\"project-live\""));
                stream
                    .write_all(
                        br#"{"type":"process_statuses","processes":[{"process":"vp-live","state":"running","main_task_definition":null,"main_task_instance":null,"main_state":null,"main_wait_state":null,"main_debug_epoch":null,"connected_nodes":[],"coordinator_epoch":42}],"actor":"user"}"#,
                    )
                    .unwrap();
                stream.write_all(b"\n").unwrap();
            } else {
                panic!("unexpected coordinator request: {line}");
            }
        }
    });

    let temp = tempfile::tempdir().unwrap();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "tenant-live".to_owned(),
            project: "project-live".to_owned(),
            user: "user".to_owned(),
            coordinator: Some(addr.clone()),
        },
    )
    .unwrap();

    let status = project_status_report(
        ProjectStatusArgs {
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

    assert_eq!(status["coordinator"], addr);
    assert_eq!(status["project_identity"]["project"], "project-live");
    assert_eq!(status["attached_nodes"]["checked"], true);
    assert_eq!(status["attached_nodes"]["count"], 1);
    assert_eq!(status["attached_nodes"]["online"], 1);
    assert_eq!(status["active_process"], "vp-live");
    assert_eq!(
        status["quota_posture"]["current_usage"]["observed_task_events"],
        1
    );
}

#[test]
fn project_status_uses_authenticated_client_session_for_nodes_and_events() {
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
            session_secret: Some("status-session-secret".to_owned()),
            token_expiry_posture: "unknown_coordinator_session".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            let wire: Value = serde_json::from_str(&line).unwrap();
            let payload = &wire["payload"];
            assert_eq!(payload["type"], "authenticated");
            assert_eq!(payload["session_secret"], "status-session-secret");
            assert!(payload["request"].get("tenant").is_none());
            assert!(payload["request"].get("project").is_none());
            assert!(payload["request"].get("actor_user").is_none());
            match payload["request"]["type"].as_str().unwrap() {
                "list_node_descriptors" => write!(
                    stream,
                    "{}",
                    json!({
                        "type": "node_descriptors",
                        "descriptors": [test_node_descriptor(
                            "node-session",
                            "tenant-session",
                            "project-session",
                            true,
                        )],
                        "actor": "user-session",
                    })
                )
                .unwrap(),
                "list_task_events" => write!(
                    stream,
                    "{}",
                    json!({
                        "type": "task_events",
                        "events": [test_task_completion_event(
                            "tenant-session",
                            "project-session",
                            "vp-session",
                            "node-session",
                            "task-session",
                        )],
                    })
                )
                .unwrap(),
                "list_processes" => stream
                    .write_all(
                        br#"{"type":"process_statuses","processes":[{"process":"vp-session","state":"running","main_task_definition":null,"main_task_instance":null,"main_state":null,"main_wait_state":null,"main_debug_epoch":null,"connected_nodes":[],"coordinator_epoch":42}],"actor":"user-session"}"#,
                    )
                    .unwrap(),
                operation => panic!("unexpected coordinator operation: {operation}"),
            }
            stream.write_all(b"\n").unwrap();
        }
    });

    let status = project_status_report(
        ProjectStatusArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "ignored-tenant".to_owned(),
                project: "ignored-project".to_owned(),
                user: "ignored-user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(status["coordinator"], addr);
    assert_eq!(status["project_identity"]["tenant"], "tenant-session");
    assert_eq!(status["project_identity"]["project"], "project-session");
    assert_eq!(status["project_identity"]["user"], "user-session");
    assert_eq!(status["attached_nodes"]["count"], 1);
    assert_eq!(status["active_process"], "vp-session");
}

#[test]
fn quota_status_uses_project_config_and_generic_public_limits() {
    let temp = tempfile::tempdir().unwrap();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "tenant-quota".to_owned(),
            project: "project-quota".to_owned(),
            user: "user".to_owned(),
            coordinator: None,
        },
    )
    .unwrap();

    let status = quota_status_report(
        QuotaStatusArgs {
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

    assert_eq!(status["command"], "quota status");
    assert_eq!(status["tenant"], "tenant-quota");
    assert_eq!(status["project"], "project-quota");
    assert_eq!(status["current_usage"]["attached_nodes"], 0);
    assert_eq!(status["limits"]["configured"], false);
    assert_eq!(status["quota_configuration_source"], "unavailable_offline");
    assert!(status["quota_tier"].is_null());
    let rendered = human_report(&status);
    assert!(!rendered.contains("quota tier:"));
    let forbidden_tier = ["free", "tier"].join(" ");
    assert!(!rendered.to_ascii_lowercase().contains(&forbidden_tier));
    assert_eq!(
        status["next_blocked_action"]["action"],
        "node_work_requires_online_attached_node"
    );
    assert_eq!(
        status["next_blocked_action"]["machine_error"]["category"],
        "capability"
    );
    assert_eq!(
        status["next_blocked_action"]["machine_error"]["stable_exit_code"],
        24
    );
}

#[test]
fn quota_status_queries_public_coordinator_usage() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        for _ in 0..3 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.contains("\"type\":\"list_node_descriptors\"") {
                assert!(line.contains("\"tenant\":\"tenant-live\""));
                write!(
                    stream,
                    "{}",
                    json!({
                        "type": "node_descriptors",
                        "descriptors": [
                            test_node_descriptor(
                                "node-a",
                                "tenant-live",
                                "project-live",
                                true,
                            ),
                            test_node_descriptor(
                                "node-b",
                                "tenant-live",
                                "project-live",
                                false,
                            ),
                        ],
                        "actor": "user",
                    })
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            } else if line.contains("\"type\":\"list_task_events\"") {
                assert!(line.contains("\"project\":\"project-live\""));
                write!(
                    stream,
                    "{}",
                    json!({
                        "type": "task_events",
                        "events": [
                            test_task_completion_event(
                                "tenant-live",
                                "project-live",
                                "vp-live",
                                "node-a",
                                "task-a",
                            ),
                            test_task_completion_event(
                                "tenant-live",
                                "project-live",
                                "vp-live",
                                "node-b",
                                "task-b",
                            ),
                        ],
                    })
                )
                .unwrap();
                stream.write_all(b"\n").unwrap();
            } else if line.contains("\"type\":\"quota_status\"") {
                stream
                    .write_all(
                        br#"{"type":"quota_status","tenant":"tenant-live","project":"project-live","actor":"user","policy_label":"community tier","limits":{"limits":{"Spawn":64}},"window_seconds":{"Spawn":60},"usage":{"Spawn":2},"window_started_epoch_seconds":{"Spawn":120},"projects_current":1,"projects_maximum":1,"node_identities_current":2,"node_identities_maximum":4,"active_processes_current":0,"active_processes_maximum":1}"#,
                    )
                    .unwrap();
                stream.write_all(b"\n").unwrap();
            } else {
                panic!("unexpected coordinator request: {line}");
            }
        }
    });

    let temp = tempfile::tempdir().unwrap();
    write_project_config(
        temp.path(),
        &ProjectConfig {
            tenant: "tenant-live".to_owned(),
            project: "project-live".to_owned(),
            user: "user".to_owned(),
            coordinator: Some(addr.clone()),
        },
    )
    .unwrap();

    let status = quota_status_report(
        QuotaStatusArgs {
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

    assert_eq!(status["coordinator"], addr);
    assert_eq!(status["current_usage"]["attached_nodes"], 2);
    assert_eq!(status["current_usage"]["online_nodes"], 1);
    assert_eq!(status["current_usage"]["observed_task_events"], 2);
    assert_eq!(status["current_usage"]["scoped_resource_usage"]["Spawn"], 2);
    assert_eq!(status["current_usage"]["projects"], 1);
    assert_eq!(status["current_usage"]["node_identities"], 2);
    assert_eq!(status["current_usage"]["active_processes"], 0);
    assert_eq!(
        status["limits"],
        json!({ "Spawn": 64, "projects": 1, "node_identities": 4, "active_processes": 1 })
    );
    assert_eq!(status["window_seconds"]["Spawn"], 60);
    assert_eq!(status["quota_configuration_source"], "coordinator");
    assert_eq!(status["quota_tier"], "community tier");
    assert!(status["next_blocked_action"].is_null());
    assert_eq!(status["task_events"]["response"]["type"], "task_events");
}

#[test]
fn process_task_log_and_artifact_reports_summarize_task_events() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let response = concat!(
            r#"{"type":"task_events","events":["#,
            r#"{"tenant":"tenant","project":"project","process":"vp","node":"node-a","executor":"node","task_definition":"definition-task-a","task":"task-a","placement":{"node":"node-a","score":120,"reasons":["warm environment cache","source snapshot already local"]},"terminal_state":"completed","status_code":0,"stdout_bytes":12,"stderr_bytes":0,"stdout_tail":"ok","stderr_tail":"","stdout_truncated":false,"stderr_truncated":false,"artifact_path":"/vfs/artifacts/app.txt","artifact_digest":"sha256:artifact","artifact_size_bytes":12,"result":null},"#,
            r#"{"tenant":"tenant","project":"project","process":"vp","node":"node-b","executor":"node","task_definition":"definition-task-b","task":"task-b","terminal_state":"failed","status_code":1,"stdout_bytes":0,"stderr_bytes":7,"stdout_tail":"","stderr_tail":"boom","stdout_truncated":false,"stderr_truncated":false,"artifact_path":null,"artifact_digest":null,"artifact_size_bytes":null,"result":null},"#,
            r#"{"tenant":"tenant","project":"project","process":"vp","node":"node-c","executor":"node","task_definition":"definition-task-c","task":"task-c","terminal_state":"failed","status_code":1,"stdout_bytes":0,"stderr_bytes":71,"stdout_tail":"","stderr_tail":"source snapshot unavailable and direct connectivity unavailable","stdout_truncated":false,"stderr_truncated":false,"artifact_path":null,"artifact_digest":null,"artifact_size_bytes":null,"result":null}"#,
            r#"]}"#
        );
        for _ in 0..5 {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            if line.contains("\"type\":\"list_processes\"") {
                stream
                    .write_all(
                        br#"{"type":"process_statuses","processes":[{"process":"vp","state":"running","main_task_definition":null,"main_task_instance":null,"main_state":null,"main_wait_state":null,"main_debug_epoch":null,"connected_nodes":[],"coordinator_epoch":42}],"actor":"user"}"#,
                    )
                    .unwrap();
            } else {
                assert!(line.contains("\"type\":\"list_task_events\""));
                assert!(line.contains("\"process\":\"vp\""));
                stream.write_all(response.as_bytes()).unwrap();
            }
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

    let process = process_status_report(ProcessStatusArgs {
        scope: scope.clone(),
        process: "vp".to_owned(),
    })
    .unwrap();
    let tasks = task_list_report(TaskListArgs {
        scope: scope.clone(),
        process: Some("vp".to_owned()),
    })
    .unwrap();
    let logs = logs_report(LogsArgs {
        scope: scope.clone(),
        process: Some("vp".to_owned()),
        task: Some("task-a".to_owned()),
    })
    .unwrap();
    let artifacts = artifact_list_report(ArtifactListArgs {
        scope,
        process: Some("vp".to_owned()),
    })
    .unwrap();
    server.join().unwrap();

    assert_eq!(process["state"], "running");
    assert_eq!(process["current_task_count"], 3);
    assert_eq!(
        process["current_tasks"][0]["node_placement"]["node"],
        "node-a"
    );
    assert_eq!(
        process["current_tasks"][0]["node_placement"]["reasons"][0],
        "warm environment cache"
    );
    assert_eq!(tasks["tasks"][0]["node_placement"]["score"], 120);
    let rendered_tasks = human_report(&tasks);
    assert!(rendered_tasks.contains("placement task-a: node-a"));
    assert!(rendered_tasks.contains("source snapshot already local"));
    assert_eq!(tasks["tasks"][1]["failure_reason"], "boom");
    assert_eq!(tasks["tasks"][1]["machine_error"]["category"], "program");
    assert_eq!(tasks["tasks"][1]["machine_error"]["stable_exit_code"], 27);
    assert_eq!(
        tasks["tasks"][2]["locality_failure"]["affected_data"],
        "source_snapshot"
    );
    assert_eq!(
        tasks["tasks"][2]["locality_failure"]["coordinator_bulk_relay_used"],
        false
    );
    assert_eq!(
        tasks["tasks"][2]["machine_error"]["category"],
        "connectivity"
    );
    assert_eq!(tasks["tasks"][2]["machine_error"]["stable_exit_code"], 25);
    assert_eq!(tasks["tasks"][2]["machine_error"]["locality_failure"], true);
    assert!(tasks["tasks"][2]["machine_error"]["next_actions"]
        .as_array()
        .unwrap()
        .iter()
        .any(|action| action == "rerun source preparation on an attached node"));
    assert!(rendered_tasks.contains("locality task-c: source_snapshot"));
    assert!(rendered_tasks.contains("do not rely on coordinator bulk source relay"));
    assert_eq!(logs["log_entries"].as_array().unwrap().len(), 1);
    assert_eq!(logs["log_entries"][0]["task"], "task-a");
    assert_eq!(logs["log_entries"][0]["stdout_tail"], "ok");
    assert_eq!(artifacts["artifacts"].as_array().unwrap().len(), 1);
    assert_eq!(artifacts["artifacts"][0]["artifact"], "app.txt");
    assert_eq!(artifacts["artifacts"][0]["size_bytes"], 12);
    assert_eq!(artifacts["artifacts"][0]["known_locations"][0], "node-a");
    assert_eq!(artifacts["default_durable_store_assumed"], false);
}

#[test]
fn log_and_task_reports_redact_secret_like_values() {
    let events = json!({
        "response": {
            "type": "task_events",
            "events": [{
                "tenant": "tenant",
                "project": "project",
                "process": "vp",
                "node": "node-a",
                "task": "task-secret",
                "terminal_state": "failed",
                "status_code": 1,
                "stdout_bytes": 128,
                "stderr_bytes": 64,
                "stdout_tail": "upload token=abc123 Authorization: Bearer bearer-secret",
                "stderr_tail": "failed password=hunter2 access_token=provider-secret",
                "stdout_truncated": true,
                "stderr_truncated": false
            }]
        }
    });

    let entries = log_entries(Some(&events), Some("task-secret"));
    let entry = &entries.as_array().unwrap()[0];
    assert_eq!(
        entry["stdout_tail"],
        "upload token=[redacted] Authorization: Bearer [redacted]"
    );
    assert_eq!(
        entry["stderr_tail"],
        "failed password=[redacted] access_token=[redacted]"
    );
    assert_eq!(entry["stdout_bytes"], 128);
    assert_eq!(entry["stdout_truncated"], true);
    assert_eq!(entry["secret_like_values_redacted"], true);
    assert_eq!(entry["redacted_fields"][0], "stdout_tail");
    assert_eq!(entry["redacted_fields"][1], "stderr_tail");

    let tasks = task_summaries(Some(&events));
    let task = &tasks.as_array().unwrap()[0];
    assert_eq!(
        task["failure_reason"],
        "failed password=[redacted] access_token=[redacted]"
    );
    assert_eq!(
        task["machine_error"]["message"],
        "failed password=[redacted] access_token=[redacted]"
    );
    assert!(!serde_json::to_string(&entries)
        .unwrap()
        .contains("provider-secret"));
    assert!(!serde_json::to_string(&tasks).unwrap().contains("hunter2"));
}

#[test]
fn artifact_cli_never_requests_coordinator_carried_bytes() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"create_artifact_download_link""#));
        stream
            .write_all(
                br#"{"type":"artifact_download_link","link":{"artifact":"app.txt","artifact_digest":"sha256:8e4c2e339a4a879ce6b1e89da60d5bc8a32d3c84dec737b56eb0e79d45e4432c","artifact_size_bytes":9,"source":{"RetainedNode":"node-a"},"url_path":"/artifacts/tenant/project/vp/app.txt","scoped_token_digest":"sha256:download-token","expires_at_epoch_seconds":60,"tenant":"tenant","project":"project","process":"vp","actor":{"User":"user"},"max_bytes":2048,"policy_context_digest":"sha256:policy"}}"#,
            )
            .unwrap();
        stream.write_all(b"\n").unwrap();

        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"export_artifact_to_node""#));
        assert!(line.contains(r#""receiver_node":"node-b""#));
        stream
            .write_all(
                br#"{"type":"artifact_export","transfer":null,"receiver_node":"node-b","artifact_size_bytes":9,"already_present":true}"#,
            )
            .unwrap();
        stream.write_all(b"\n").unwrap();
    });
    let scope = CliScopeArgs {
        coordinator: Some(addr),
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        user: "user".to_owned(),
        json: false,
    };
    let temp = tempfile::tempdir().unwrap();
    let local_path = temp.path().join("app.txt");
    let download = artifact_download_report(ArtifactDownloadArgs {
        scope: scope.clone(),
        artifact: "app.txt".to_owned(),
        to: Some(local_path.clone()),
        max_bytes: 2048,
    })
    .unwrap();
    assert_eq!(
        download["local_download"]["status"],
        "direct_node_export_required"
    );
    assert_eq!(
        download["local_download"]["local_bytes_written_by_cli"],
        false
    );
    assert!(!local_path.exists());

    let export = artifact_export_report(ArtifactExportArgs {
        scope,
        artifact: "app.txt".to_owned(),
        to: Some(local_path),
        receiver_node: "node-b".to_owned(),
    })
    .unwrap();
    assert_eq!(export["export_plan"]["status"], "already_present");
    assert_eq!(
        export["export_plan"]["local_export_status"],
        "node_transfer_submitted"
    );
    assert_eq!(export["export_plan"]["local_bytes_written_by_cli"], false);
    assert_eq!(export["response"]["transfer"], Value::Null);
    server.join().unwrap();
}

#[test]
fn artifact_failure_reports_apply_stable_exit_codes() {
    let download_error = CoordinatorResponse::error(
        "test-artifact-download",
        "artifact download unauthorized for project",
    );
    let mut download = json!({
        "command": "artifact download",
        "download_session": artifact_download_session_summary(&download_error),
    });
    assert_eq!(apply_command_report_exit_code(&mut download), Some(21));
    assert_eq!(
        download["download_session"]["machine_error"]["category"],
        "authorization"
    );
    assert_eq!(
        download["download_session"]["machine_error"]["process_exit_code_applied"],
        true
    );

    let export_error = CoordinatorResponse::error(
        "test-artifact-export",
        "direct connectivity unavailable for artifact export",
    );
    let mut export = json!({
        "command": "artifact export",
        "export_plan": artifact_export_plan_summary(
            &export_error,
            Some(Path::new("dist/app.txt")),
        ),
    });
    assert_eq!(apply_command_report_exit_code(&mut export), Some(25));
    assert_eq!(
        export["export_plan"]["machine_error"]["category"],
        "connectivity"
    );
    assert_eq!(
        export["export_plan"]["machine_error"]["process_exit_code_applied"],
        true
    );
}

#[test]
fn process_restart_cancel_and_abort_reports_expose_control_boundaries() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let restart_response = r#"{"type":"process_started","process":"vp","epoch":42,"actor":{"kind":"user","user":"user","agent":null,"credential_kind":"BrowserSession","public_key_fingerprint":null,"authenticated_without_browser":false,"scopes":["project:read","project:run"]},"charged_spawns":1}"#;
        let cancel_response = r#"{"type":"process_cancellation_requested","process":"vp","cancelled_tasks":[{"process":"vp","task":"compile-linux","node":"node-a"},{"process":"vp","task":"link-linux","node":"node-b"}],"affected_nodes":["node-a","node-b"]}"#;
        let abort_response =
            r#"{"type":"process_aborted","process":"vp","aborted_tasks":[],"affected_nodes":[]}"#;
        for expected in ["start_process", "cancel_process", "abort_process"] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(&format!(r#""type":"{expected}""#)));
            assert!(line.contains(r#""tenant":"tenant""#));
            assert!(line.contains(r#""project":"project""#));
            assert!(line.contains(r#""process":"vp""#));
            if expected == "start_process" {
                stream.write_all(restart_response.as_bytes()).unwrap();
            } else if expected == "cancel_process" {
                assert!(line.contains(r#""actor_user":"user""#));
                stream.write_all(cancel_response.as_bytes()).unwrap();
            } else {
                assert!(line.contains(r#""actor_user":"user""#));
                stream.write_all(abort_response.as_bytes()).unwrap();
            }
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

    let restart = process_restart_report(ProcessRestartArgs {
        scope: scope.clone(),
        process: "vp".to_owned(),
        yes: true,
    })
    .unwrap();
    let cancel = process_cancel_report(ProcessCancelArgs {
        scope: scope.clone(),
        process: "vp".to_owned(),
        node: None,
        task: None,
        yes: true,
    })
    .unwrap();
    let abort = process_abort_report_with_session(
        ProcessAbortArgs {
            scope,
            process: "vp".to_owned(),
            yes: true,
        },
        None,
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(restart["restart_request"]["status"], "process_started");
    assert_eq!(
        restart["restart_request"]["operation"],
        "restart_virtual_process"
    );
    assert_eq!(restart["restart_request"]["accepted"], true);
    assert_eq!(restart["restart_request"]["process"], "vp");
    assert_eq!(restart["restart_request"]["coordinator_epoch"], 42);
    assert_eq!(restart["restart_request"]["requires_confirmation"], false);
    assert_eq!(restart["restart_request"]["website_required"], false);

    assert_eq!(
        cancel["cancel_request"]["status"],
        "process_cancellation_requested"
    );
    assert_eq!(
        cancel["cancel_request"]["operation"],
        "cancel_virtual_process"
    );
    assert_eq!(cancel["cancel_request"]["accepted"], true);
    assert_eq!(cancel["cancel_request"]["process"], "vp");
    assert_eq!(cancel["cancel_request"]["cancelled_task_count"], 2);
    assert_eq!(
        cancel["cancel_request"]["cancelled_tasks"][0]["task"],
        "compile-linux"
    );
    assert_eq!(cancel["cancel_request"]["affected_nodes"][1], "node-b");
    assert_eq!(cancel["cancel_request"]["requires_confirmation"], false);
    assert_eq!(cancel["cancel_request"]["website_required"], false);
    assert_eq!(
        cancel["cancel_request"]["whole_process_cancel_available"],
        true
    );
    assert_eq!(
        cancel["cancel_request"]["node_must_poll_task_control"],
        true
    );
    assert_eq!(cancel["cancel_request"]["new_task_launches_blocked"], true);
    assert_eq!(abort["status"], "aborted");
    assert_eq!(abort["abort_request"]["accepted"], true);
    assert_eq!(abort["abort_request"]["forced"], true);
    assert_eq!(abort["abort_request"]["cooperative"], false);
    assert_eq!(abort["abort_request"]["process_slot_released"], true);
}

#[test]
fn task_restart_reports_clean_boundary_requirements() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"restart_task""#));
        assert!(line.contains(r#""tenant":"tenant""#));
        assert!(line.contains(r#""project":"project""#));
        assert!(line.contains(r#""actor_user":"user""#));
        assert!(line.contains(r#""process":"vp""#));
        assert!(line.contains(r#""task":"compile-linux""#));
        stream
                .write_all(
                    br#"{"type":"task_restart","process":"vp","task":"compile-linux","restarted_task_instance":null,"restarted_attempt_id":null,"actor":"user","accepted":false,"clean_boundary_available":false,"active_task":true,"completed_event_observed":false,"requires_whole_process_restart":true,"message":"selected task is still active; clean task restart requires a captured checkpoint boundary","audit_event":{"tenant":"tenant","project":"project","process":"vp","task":"compile-linux","actor":"user","operation":"restart_task","allowed":true,"reason":"selected task is still active; clean task restart requires a captured checkpoint boundary","charged_debug_read_bytes":1024,"used_debug_read_bytes":1024},"charged_debug_read_bytes":1024,"used_debug_read_bytes":1024}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let report = task_restart_report(TaskRestartArgs {
        scope: CliScopeArgs {
            coordinator: Some(addr),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            user: "user".to_owned(),
            json: false,
        },
        task: "compile-linux".to_owned(),
        process: "vp".to_owned(),
        yes: true,
    })
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["command"], "task restart");
    assert_eq!(
        report["restart_request"]["operation"],
        "restart_selected_task"
    );
    assert_eq!(report["restart_request"]["accepted"], false);
    assert_eq!(report["restart_request"]["clean_boundary_available"], false);
    assert_eq!(
        report["restart_request"]["requires_whole_process_restart"],
        true
    );
    assert_eq!(report["restart_request"]["active_task"], true);
    assert_eq!(
        report["restart_request"]["audit_event"]["operation"],
        "restart_task"
    );
    assert_eq!(report["restart_request"]["charged_debug_read_bytes"], 1024);
    assert_eq!(report["restart_request"]["used_debug_read_bytes"], 1024);
    assert_eq!(report["restart_request"]["debug_reads_quota_limited"], true);
    assert_eq!(report["restart_request"]["website_required"], false);
    assert_eq!(report["coordinator_session_requests"], 1);
}

#[test]
fn build_command_reuses_bundle_inspection_without_full_repo_upload() {
    let temp = tempfile::tempdir().unwrap();
    let fixture = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .join("examples/hello-build");
    let project = temp.path().join("project");
    for relative in [
        ".clusterflux/Cargo.toml",
        ".clusterflux/main.rs",
        ".clusterflux/unused.rs",
        "envs/linux/Containerfile",
        "fixture/hello-clusterflux.c",
    ] {
        let destination = project.join(relative);
        fs::create_dir_all(destination.parent().unwrap()).unwrap();
        fs::copy(fixture.join(relative), destination).unwrap();
    }
    let manifest_path = project.join(".clusterflux/Cargo.toml");
    let sdk_path = fixture
        .join("../../crates/clusterflux-sdk")
        .canonicalize()
        .unwrap();
    let manifest = fs::read_to_string(&manifest_path).unwrap().replace(
        "path = \"../../../crates/clusterflux-sdk\"",
        &format!(
            "path = {}",
            serde_json::to_string(&sdk_path.to_string_lossy()).unwrap()
        ),
    );
    fs::write(manifest_path, manifest).unwrap();
    let output = temp.path().join("bundle");

    let report = build_report(
        BuildArgs {
            project: Some(project),
            entry: None,
            source_provider: Some("filesystem".to_owned()),
            disabled_source_providers: Vec::new(),
            output: Some(output.clone()),
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();

    assert_eq!(report["command"], "build");
    assert_eq!(report["content_addressed"], true);
    assert_eq!(report["contains_full_repository_upload"], false);
    assert_eq!(report["bundle_artifact"]["task_descriptor_count"], 2);
    assert_eq!(report["bundle_artifact"]["entrypoint_count"], 1);
    assert!(output.join("module.wasm").is_file());
    assert!(output.join("manifest.json").is_file());
    assert!(output.join("task-descriptors.json").is_file());
    assert!(output.join("source-snapshot.json").is_file());
    let manifest: Value =
        serde_json::from_slice(&fs::read(output.join("manifest.json")).unwrap()).unwrap();
    let persisted_source_snapshot: Value =
        serde_json::from_slice(&fs::read(output.join("source-snapshot.json")).unwrap()).unwrap();
    assert_eq!(report["source_snapshot"]["provider"], "filesystem");
    assert_eq!(report["source_snapshot"]["source_mode"], "filesystem_tree");
    assert!(report["source_snapshot"]["digest"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(manifest["source_snapshot"], report["source_snapshot"]);
    assert_eq!(persisted_source_snapshot, report["source_snapshot"]);
    assert_eq!(
        report["bundle_artifact"]["source_snapshot"],
        report["source_snapshot"]
    );
    assert_eq!(manifest["bundle_digest"], report["bundle_digest"]);
    assert_eq!(
        report["bundle_artifact"]["bundle_digest"],
        report["bundle_digest"]
    );
    assert_eq!(report["selected_entrypoint"]["name"], "build");
    assert_eq!(
        manifest["selected_entrypoint"],
        report["selected_entrypoint"]
    );
    assert_eq!(
        report["task_compatibility_metadata"]["task_abi"],
        report["bundle"]["metadata"]["task_metadata"]["task_abi"]
    );
    assert!(report["task_compatibility_metadata"]["descriptors"]
        .as_array()
        .is_some_and(|descriptors| descriptors.len() == 2));
    assert!(report["environment_digests"].is_array());
    let task_descriptors: Value =
        serde_json::from_slice(&fs::read(output.join("task-descriptors.json")).unwrap()).unwrap();
    assert!(task_descriptors
        .as_array()
        .unwrap()
        .iter()
        .any(|descriptor| {
            descriptor["name"] == "compile"
                && descriptor["argument_schema"] == "source : SourceSnapshot"
                && descriptor["result_schema"] == "Result < Artifact >"
                && descriptor["restart_compatibility_hash"]
                    .as_str()
                    .unwrap()
                    .starts_with("sha256:")
        }));
    assert!(report["bundle"]["metadata"]["identity"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert!(report["bundle"]["metadata"]["wasm_code"]
        .as_str()
        .unwrap()
        .starts_with("sha256:"));
    assert_eq!(
        report["bundle"]["metadata"]["task_metadata"]["default_entrypoint"],
        "build"
    );
    assert_eq!(
        report["bundle"]["metadata"]["task_metadata"]["authority"],
        "compiled_wasm_descriptors"
    );
    assert_eq!(
        report["bundle"]["metadata"]["task_metadata"]["boundary"],
        "shared_bundle_finalizer"
    );
    assert!(report["bundle"]["metadata"]["task_metadata"]["entrypoints"]
        .as_array()
        .unwrap()
        .iter()
        .any(|entrypoint| entrypoint == "build"));
    assert!(
        !report["bundle"]["metadata"]["task_metadata"]["entrypoints"]
            .as_array()
            .unwrap()
            .iter()
            .any(|entrypoint| entrypoint == "release")
    );
    assert_eq!(
        report["bundle"]["metadata"]["source_metadata"]["transfer_policy"]
            ["coordinator_receives_source_bytes_by_default"],
        false
    );
    assert_eq!(
        report["bundle"]["metadata"]["source_metadata"]["transfer_policy"]
            ["default_full_repo_tarball"],
        false
    );
    assert_eq!(
        report["bundle"]["metadata"]["debug_metadata"]["dap_virtual_process"],
        true
    );
    assert_eq!(
        report["bundle"]["metadata"]["large_input_policy"]["selected_inputs_are_content_digests"],
        true
    );
    assert_eq!(
        report["bundle"]["metadata"]["large_input_policy"]["selected_input_bytes_included"],
        false
    );
    assert_eq!(
        report["bundle"]["metadata"]["large_input_policy"]["full_repository_bytes_included"],
        false
    );
    assert_eq!(
        report["bundle"]["metadata"]["large_input_policy"]["silent_task_argument_serialization"],
        false
    );
    assert!(
        report["bundle"]["metadata"]["large_input_policy"]["supported_handle_types"]
            .as_array()
            .unwrap()
            .iter()
            .any(|handle| handle == "Artifact")
    );
    assert_eq!(
        report["bundle"]["metadata"]["restart_compatibility"]
            ["source_edits_can_restart_from_clean_task_boundary"],
        true
    );
    assert_eq!(
        report["bundle"]["metadata"]["restart_compatibility"]["requires_clean_checkpoint_boundary"],
        true
    );
    assert_eq!(
        report["bundle"]["metadata"]["restart_compatibility"]["compares_task_abi"],
        report["bundle"]["metadata"]["task_metadata"]["task_abi"]
    );
    assert_eq!(
        report["bundle"]["metadata"]["restart_compatibility"]
            ["incompatible_changes_require_whole_process_restart"],
        true
    );
    assert_eq!(report["status"], "built");
    assert_eq!(report["scheduled_work"], false);
}

#[test]
fn build_blocks_before_schedule_on_missing_environment_reference() {
    let temp = tempfile::tempdir().unwrap();
    write_constrained_workflow(
        temp.path(),
        "demo",
        "fn main() { let _target = env!(\"linux\"); }\n",
    );

    let report = build_report(
        BuildArgs {
            project: Some(temp.path().to_path_buf()),
            entry: None,
            source_provider: None,
            disabled_source_providers: Vec::new(),
            output: None,
            json: false,
        },
        PathBuf::from("/unused"),
    )
    .unwrap();

    assert_eq!(report["status"], "blocked_before_schedule");
    assert_eq!(report["scheduled_work"], false);
    assert_eq!(report["machine_error"]["category"], "environment");
    assert_eq!(report["diagnostics"][0]["code"], "missing_environment");
}

#[test]
fn node_enroll_reports_short_lived_public_api_grant() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let addr = listener.local_addr().unwrap().to_string();
    let server = std::thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let mut reader = BufReader::new(stream.try_clone().unwrap());
        let mut line = String::new();
        reader.read_line(&mut line).unwrap();
        assert!(line.contains(r#""type":"create_node_enrollment_grant""#));
        assert!(line.contains(r#""tenant":"tenant""#));
        assert!(line.contains(r#""project":"project""#));
        assert!(line.contains(r#""actor_user":"user""#));
        assert!(!line.contains(r#""grant":""#));
        assert!(!line.contains("now_epoch_seconds"));
        assert!(line.contains(r#""ttl_seconds":300"#));
        stream
                .write_all(
                    br#"{"type":"node_enrollment_grant_created","tenant":"tenant","project":"project","grant":"grant-live","scope":"node:attach","expires_at_epoch_seconds":300}"#,
                )
                .unwrap();
        stream.write_all(b"\n").unwrap();
    });

    let temp = tempfile::tempdir().unwrap();
    let report = node_enroll_report(
        NodeEnrollArgs {
            scope: CliScopeArgs {
                coordinator: Some(addr),
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                user: "user".to_owned(),
                json: false,
            },
            ttl_seconds: 300,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(report["command"], "node enroll");
    assert_eq!(report["status"], "created");
    assert_eq!(report["external_website_required"], false);
    assert_eq!(report["tenant"], "tenant");
    assert_eq!(report["project"], "project");
    assert_eq!(report["user"], "user");
    assert_eq!(report["enrollment_grant"]["grant"], "grant-live");
    assert_eq!(report["enrollment_grant"]["scope"], "node:attach");
    assert_eq!(report["enrollment_grant"]["ttl_seconds"], 300);
    assert_eq!(report["enrollment_grant"]["expires_at_epoch_seconds"], 300);
    assert_eq!(report["enrollment_grant"]["short_lived"], true);
    assert_eq!(
        report["enrollment_grant"]["exchange_for_persistent_node_identity"],
        true
    );
    assert_eq!(
        report["enrollment_grant"]["node_credentials_separate_from_user_session"],
        true
    );
    assert_eq!(report["coordinator_session_requests"], 1);
}

#[test]
fn node_commands_use_authenticated_envelope_with_stored_cli_session() {
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
            session_secret: Some("node-cli-session-secret".to_owned()),
            token_expiry_posture: "unknown_coordinator_session".to_owned(),
            expires_at: None,
            provider_tokens_exposed_to_cli: false,
            provider_tokens_sent_to_nodes: false,
            created_at_unix_seconds: 1,
        },
    )
    .unwrap();
    let server = std::thread::spawn(move || {
        for (request_type, response) in [
            (
                "create_node_enrollment_grant",
                br#"{"type":"node_enrollment_grant_created","tenant":"tenant-session","project":"project-session","grant":"grant-session","scope":"node:attach","expires_at_epoch_seconds":300}"#.as_slice(),
            ),
            (
                "list_node_summaries",
                br#"{"type":"node_summaries","nodes":[{"id":"node-session","display_name":"node-session","online":true,"stale":false,"last_seen_epoch_seconds":1,"capabilities":{"os":"Linux","arch":"x86_64","capabilities":[],"environment_backends":[],"source_providers":[]},"artifact_connectivity":{"endpoint_advertised":false,"recent_path":"unknown","recent_direct_failure":false,"relay_policy":"direct_required"}}],"next_cursor":null,"actor":"user-session"}"#.as_slice(),
            ),
            (
                "revoke_node_credential",
                br#"{"type":"node_credential_revoked","node":"node-session","tenant":"tenant-session","project":"project-session","actor":"user-session","descriptor_removed":true,"queued_assignments_removed":0}"#.as_slice(),
            ),
        ] {
            let (mut stream, _) = listener.accept().unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut line = String::new();
            reader.read_line(&mut line).unwrap();
            assert!(line.contains(r#""type":"authenticated""#));
            assert!(line.contains(r#""session_secret":"node-cli-session-secret""#));
            assert!(
                line.contains(&format!(r#""type":"{request_type}""#)),
                "expected request type {request_type}, got {line}"
            );
            assert!(!line.contains(r#""actor_user":"ignored-user""#));
            assert!(!line.contains(r#""tenant":"ignored-tenant""#));
            assert!(!line.contains(r#""project":"ignored-project""#));
            stream.write_all(response).unwrap();
            stream.write_all(b"\n").unwrap();
        }
    });

    let enrolled = node_enroll_report(
        NodeEnrollArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "ignored-tenant".to_owned(),
                project: "ignored-project".to_owned(),
                user: "ignored-user".to_owned(),
                json: false,
            },
            ttl_seconds: 300,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    let listed = node_list_report(
        NodeListArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "ignored-tenant".to_owned(),
                project: "ignored-project".to_owned(),
                user: "ignored-user".to_owned(),
                json: false,
            },
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    let revoked = node_revoke_report(
        NodeRevokeArgs {
            scope: CliScopeArgs {
                coordinator: None,
                tenant: "ignored-tenant".to_owned(),
                project: "ignored-project".to_owned(),
                user: "ignored-user".to_owned(),
                json: false,
            },
            node: "node-session".to_owned(),
            yes: true,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    server.join().unwrap();

    assert_eq!(enrolled["tenant"], "tenant-session");
    assert_eq!(enrolled["project"], "project-session");
    assert_eq!(enrolled["user"], "user-session");
    assert_eq!(listed["response"]["nodes"][0]["id"], "node-session");
    assert_eq!(revoked["credential_revoked"], true);
}

#[test]
fn node_enroll_and_process_commands_have_safe_plan_without_coordinator() {
    let scope = CliScopeArgs {
        coordinator: None,
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        user: "user".to_owned(),
        json: false,
    };
    let temp = tempfile::tempdir().unwrap();
    let enroll = node_enroll_report(
        NodeEnrollArgs {
            scope: scope.clone(),
            ttl_seconds: 60,
        },
        temp.path().to_path_buf(),
    )
    .unwrap();
    assert_eq!(enroll["status"], "requires_coordinator");
    assert_eq!(enroll["external_website_required"], false);
    assert_eq!(enroll["enrollment_grant"], serde_json::Value::Null);
    assert_eq!(enroll["requested_ttl_seconds"], 60);

    let cancel = process_cancel_report(ProcessCancelArgs {
        scope,
        process: "vp".to_owned(),
        node: None,
        task: None,
        yes: false,
    })
    .unwrap();
    assert_eq!(cancel["status"], "confirmation_required");
    assert_eq!(cancel["requires_confirmation"], true);
    assert_eq!(cancel["coordinator_request_sent"], false);
}
