use super::*;

#[test]
fn service_rejects_malformed_node_capability_report() {
    let mut service = CoordinatorService::new(1);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();

    let mut capabilities = linux_capabilities();
    capabilities
        .source_providers
        .insert("../checkout".to_owned());
    let error = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            capabilities,
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap_err();

    assert!(error.to_string().contains("source provider id"));
    assert!(service.node_registry.is_empty());
}

#[test]
fn signed_hostile_artifact_paths_return_errors_and_the_same_service_stays_healthy() {
    let mut service = CoordinatorService::new(27);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "hostile-path-process".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            process: "hostile-path-process".to_owned(),
            epoch: 27,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "hostile-path-process",
        "node",
        "metadata-task",
        "metadata-task",
        27,
    );

    let invalid_metadata = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportVfsMetadata {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "hostile-path-process".to_owned(),
            node: "node".to_owned(),
            task: "metadata-task".to_owned(),
            artifact_path: Some("/vfs/artifacts/bad artifact!".to_owned()),
            artifact_digest: Some(Digest::sha256("bad")),
            artifact_size_bytes: Some(3),
            large_bytes_uploaded: false,
        })
        .unwrap_err();
    assert!(
        invalid_metadata
            .to_string()
            .contains("invalid VFS artifact path"),
        "unexpected error: {invalid_metadata}"
    );

    let valid_metadata = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportVfsMetadata {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "hostile-path-process".to_owned(),
            node: "node".to_owned(),
            task: "metadata-task".to_owned(),
            artifact_path: Some("/vfs/artifacts/valid-artifact".to_owned()),
            artifact_digest: Some(Digest::sha256("valid")),
            artifact_size_bytes: Some(5),
            large_bytes_uploaded: false,
        })
        .unwrap();
    assert!(matches!(
        valid_metadata,
        CoordinatorResponse::VfsMetadataRecorded { .. }
    ));

    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "hostile-path-process",
        "node",
        "child",
        "child-instance",
        27,
    );
    let invalid_completion = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "hostile-path-process".to_owned(),
            node: "node".to_owned(),
            task: "child-instance".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/repeated//component".to_owned()),
            artifact_digest: Some(Digest::sha256("bad-completion")),
            artifact_size_bytes: Some(0),
            result: None,
        })
        .unwrap_err();
    assert!(
        invalid_completion
            .to_string()
            .contains("invalid VFS artifact path"),
        "unexpected error: {invalid_completion}"
    );

    let valid_completion = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "hostile-path-process".to_owned(),
            node: "node".to_owned(),
            task: "child-instance".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/valid-completion".to_owned()),
            artifact_digest: Some(Digest::sha256("valid-completion")),
            artifact_size_bytes: Some(0),
            result: None,
        })
        .unwrap();
    assert!(matches!(
        valid_completion,
        CoordinatorResponse::TaskRecorded { .. }
    ));
}

#[test]
fn service_rejects_task_completion_outside_node_scope() {
    let mut service = CoordinatorService::new(1);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            restart: false,
        })
        .unwrap();

    let error = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-linux".to_owned(),
            terminal_state: None,
            status_code: Some(0),
            stdout_bytes: 128,
            stderr_bytes: 64,
            stdout_tail: "foreign stdout".to_owned(),
            stderr_tail: "foreign stderr".to_owned(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/foreign.txt".to_owned()),
            artifact_digest: Some(Digest::sha256("foreign-artifact")),
            artifact_size_bytes: Some(128),
            result: None,
        })
        .unwrap_err();

    assert!(error.to_string().contains("not enrolled"));
    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("process".to_owned()),
        })
        .unwrap()
    else {
        panic!("expected task events");
    };
    assert!(events.is_empty());
}

#[test]
fn service_rejects_task_event_access_using_retained_process_scope() {
    let mut service = CoordinatorService::new(1);
    service.process_registry.record_scope(
        (
            TenantId::from("tenant-a"),
            ProjectId::from("project-a"),
            ProcessId::from("process"),
        ),
        MAX_TASK_EVENTS_TOTAL,
    );

    let error = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("process".to_owned()),
        })
        .unwrap_err();

    assert!(error
        .to_string()
        .contains("outside the virtual process tenant/project scope"));
}

#[test]
fn service_rejects_node_capability_report_outside_enrollment_scope() {
    let mut service = CoordinatorService::new(1);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();

    let error = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            node: "node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap_err();

    assert!(error.to_string().contains("not enrolled"));
    assert!(service.node_registry.is_empty());
}

#[test]
fn service_rejects_source_preparation_completion_outside_node_scope() {
    let mut service = CoordinatorService::new(1);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();

    let error = service
        .handle_signed_node_request_auto(CoordinatorRequest::CompleteSourcePreparation {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            node: "node".to_owned(),
            provider: SourceProviderKind::Filesystem,
            source_snapshot: Digest::sha256("foreign-source"),
        })
        .unwrap_err();

    assert!(error.to_string().contains("not enrolled"));
}

#[test]
fn service_rejects_unknown_node_heartbeat() {
    let mut service = CoordinatorService::new(1);

    let error = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "missing".to_owned(),
            node_signature: None,
        })
        .unwrap_err();

    assert!(error.to_string().contains("not enrolled"));
}

#[test]
fn service_requires_signed_node_heartbeat_from_enrolled_key() {
    let mut service = CoordinatorService::new(5);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();

    let unsigned = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: None,
        })
        .unwrap_err();
    assert!(unsigned.to_string().contains("signed proof"));

    let wrong_private_key = test_node_private_key("other-node");
    let wrong_signature = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(signed_node_heartbeat_with_private_key(
                "node",
                &wrong_private_key,
                "wrong-node-key",
            )),
        })
        .unwrap_err();
    assert!(wrong_signature.to_string().contains("signature"));

    let signed = signed_node_heartbeat("node", "fresh-node-heartbeat");
    let heartbeat = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(signed.clone()),
        })
        .unwrap();
    assert_eq!(
        heartbeat,
        CoordinatorResponse::NodeHeartbeat {
            node: NodeId::from("node"),
            epoch: 5,
        }
    );

    let replay = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(signed),
        })
        .unwrap_err();
    assert!(replay.to_string().contains("nonce"));
}

#[test]
fn service_rejects_raw_node_originated_requests_without_signed_envelope() {
    let mut service = CoordinatorService::new(5);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();

    let error = service
        .handle_request(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap_err();

    assert!(error.to_string().contains("signed_node envelope proof"));
}

#[test]
fn service_stream_accepts_multiple_requests_on_one_connection() {
    let (listener, addr) = bind_listener("127.0.0.1:0").unwrap();
    let server = std::thread::spawn(move || {
        let mut service = CoordinatorService::new(3);
        let (stream, _) = listener.accept().unwrap();
        service.handle_stream_local_trusted(stream).unwrap();
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());

    write_coordinator_wire_request(
        &mut stream,
        &CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        },
        "stream-1",
    );

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    assert!(matches!(
        serde_json::from_str::<CoordinatorResponse>(&line).unwrap(),
        CoordinatorResponse::NodeAttached { .. }
    ));

    write_coordinator_wire_request(
        &mut stream,
        &CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(signed_node_heartbeat("node", "stream-heartbeat")),
        },
        "stream-2",
    );

    line.clear();
    reader.read_line(&mut line).unwrap();
    assert_eq!(
        serde_json::from_str::<CoordinatorResponse>(&line).unwrap(),
        CoordinatorResponse::NodeHeartbeat {
            node: NodeId::from("node"),
            epoch: 3,
        }
    );

    stream.shutdown(std::net::Shutdown::Both).unwrap();
    server.join().unwrap();
}

#[test]
fn strict_service_stream_rejects_body_authority_and_accepts_cli_session() {
    let (listener, addr) = bind_listener("127.0.0.1:0").unwrap();
    let server = std::thread::spawn(move || {
        let mut service = CoordinatorService::new(3);
        service
            .issue_cli_session(
                TenantId::from("tenant"),
                ProjectId::from("project"),
                UserId::from("user"),
                "strict-stream-session",
                None,
            )
            .unwrap();
        let (stream, _) = listener.accept().unwrap();
        service.handle_stream(stream).unwrap();
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    write_coordinator_wire_request(
        &mut stream,
        &CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "victim-tenant".to_owned(),
            project: "victim-project".to_owned(),
            actor_user: Some("forged-user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-forged".to_owned(),
            restart: false,
        },
        "strict-stream-forged",
    );

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let CoordinatorResponse::Error { error } =
        serde_json::from_str::<CoordinatorResponse>(&line).unwrap()
    else {
        panic!("expected strict body-authority denial");
    };
    assert!(error
        .message
        .contains("request-body identity fields are not authority"));
    assert_eq!(error.request_id, "strict-stream-forged");
    assert_eq!(error.code, clusterflux_core::ApiErrorCode::Forbidden);

    write_coordinator_wire_request(
        &mut stream,
        &CoordinatorRequest::Authenticated {
            session_secret: "strict-stream-session".to_owned(),
            request: AuthenticatedCoordinatorRequest::StartProcess {
                launch_attempt: None,
                process: "vp-authenticated".to_owned(),
                restart: false,
            },
        },
        "strict-stream-authenticated",
    );

    line.clear();
    reader.read_line(&mut line).unwrap();
    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        process,
        actor,
        ..
    } = serde_json::from_str::<CoordinatorResponse>(&line).unwrap()
    else {
        panic!("expected authenticated strict process start");
    };
    assert_eq!(process, ProcessId::from("vp-authenticated"));
    assert_eq!(actor.user, Some(UserId::from("user")));

    stream.shutdown(std::net::Shutdown::Both).unwrap();
    server.join().unwrap();
}

#[test]
fn service_stream_rejects_invalid_versioned_envelope_metadata() {
    let (listener, addr) = bind_listener("127.0.0.1:0").unwrap();
    let server = std::thread::spawn(move || {
        let mut service = CoordinatorService::new(3);
        let (stream, _) = listener.accept().unwrap();
        service.handle_stream(stream).unwrap();
    });

    let mut stream = TcpStream::connect(addr).unwrap();
    let mut reader = BufReader::new(stream.try_clone().unwrap());
    let mut wire_request = serde_json::to_value(coordinator_wire_request(
        "bad-operation",
        CoordinatorRequest::Ping,
    ))
    .unwrap();
    wire_request["operation"] = serde_json::Value::String("attach_node".to_owned());
    serde_json::to_writer(&mut stream, &wire_request).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();

    let mut line = String::new();
    reader.read_line(&mut line).unwrap();
    let response = serde_json::from_str::<CoordinatorResponse>(&line).unwrap();
    let CoordinatorResponse::Error { error } = response else {
        panic!("expected invalid wire envelope response");
    };
    assert!(error
        .message
        .contains("operation attach_node does not match payload operation ping"));
    assert_eq!(error.request_id, "bad-operation");
    assert_eq!(error.code, clusterflux_core::ApiErrorCode::ValidationError);

    stream.shutdown(std::net::Shutdown::Both).unwrap();
    server.join().unwrap();
}

#[test]
fn coordinator_protocol_rejects_client_supplied_authority_fields() {
    for payload in [
        json!({
            "type": "create_node_enrollment_grant",
            "tenant": "tenant",
            "project": "project",
            "actor_user": "user",
            "grant": "attacker-chosen",
            "ttl_seconds": 60,
        }),
        json!({
            "type": "exchange_node_enrollment_grant",
            "tenant": "tenant",
            "project": "project",
            "node": "node",
            "public_key": "key",
            "enrollment_grant": "grant",
            "now_epoch_seconds": 0,
        }),
        json!({
            "type": "schedule_task",
            "tenant": "tenant",
            "project": "project",
            "environment": null,
            "environment_digest": null,
            "required_capabilities": [],
            "dependency_cache": null,
            "source_snapshot": null,
            "required_artifacts": [],
            "quota_available": true,
            "policy_allowed": true,
            "prefer_node": null,
        }),
        json!({
            "type": "create_artifact_download_link",
            "tenant": "tenant",
            "project": "project",
            "actor_user": "user",
            "artifact": "artifact",
            "max_bytes": 1,
            "token_nonce": "attacker-chosen",
            "ttl_seconds": 60,
        }),
    ] {
        let error = serde_json::from_value::<CoordinatorRequest>(payload).unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }
}

#[test]
fn coordinator_generates_and_bounds_node_enrollment_grants() {
    let mut service = CoordinatorService::new(7);
    service.set_server_time(100);

    let first = service
        .handle_request(CoordinatorRequest::CreateNodeEnrollmentGrant {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            ttl_seconds: u64::MAX,
        })
        .unwrap();
    let second = service
        .handle_request(CoordinatorRequest::CreateNodeEnrollmentGrant {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            ttl_seconds: u64::MAX,
        })
        .unwrap();

    let CoordinatorResponse::NodeEnrollmentGrantCreated {
        grant: first_grant,
        expires_at_epoch_seconds,
        ..
    } = first
    else {
        panic!("expected enrollment grant");
    };
    let CoordinatorResponse::NodeEnrollmentGrantCreated {
        grant: second_grant,
        ..
    } = second
    else {
        panic!("expected enrollment grant");
    };
    assert!(first_grant.starts_with("node_grant_"));
    assert_ne!(first_grant, second_grant);
    assert_eq!(expires_at_epoch_seconds, 100 + 15 * 60);
}

#[test]
fn web_process_summaries_are_scoped_paginated_and_retain_authoritative_terminal_state() {
    let mut service = CoordinatorService::new(7);
    for (tenant, project, user, secret) in [
        ("tenant-a", "project-a", "user-a", "session-a"),
        ("tenant-b", "project-b", "user-b", "session-b"),
    ] {
        service
            .issue_cli_session(
                TenantId::from(tenant),
                ProjectId::from(project),
                UserId::from(user),
                secret,
                None,
            )
            .unwrap();
    }
    service.set_server_time(100);
    service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::StartProcess {
                launch_attempt: None,
                process: "process-one".to_owned(),
                restart: false,
            },
        })
        .unwrap();

    let CoordinatorResponse::ProcessSummaries {
        processes,
        next_cursor,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: None,
                limit: 1,
            },
        })
        .unwrap()
    else {
        panic!("expected process summaries");
    };
    assert_eq!(processes.len(), 1);
    assert_eq!(processes[0].process, ProcessId::from("process-one"));
    assert_eq!(processes[0].lifecycle, ProcessLifecycleState::Active);
    assert_eq!(processes[0].activity, ProcessActivityState::Running);
    assert_eq!(processes[0].started_at_epoch_seconds, 100);
    assert!(next_cursor.is_none());

    let CoordinatorResponse::ProcessSummaries { processes, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-b".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: None,
                limit: 10,
            },
        })
        .unwrap()
    else {
        panic!("expected scoped process summaries");
    };
    assert!(processes.is_empty());

    service.set_server_time(120);
    service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::AbortProcess {
                process: "process-one".to_owned(),
                launch_attempt: None,
            },
        })
        .unwrap();
    let CoordinatorResponse::ProcessSummaries { processes, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: None,
                limit: 10,
            },
        })
        .unwrap()
    else {
        panic!("expected terminal process summary");
    };
    assert_eq!(
        processes[0].lifecycle,
        ProcessLifecycleState::RecentTerminal
    );
    assert_eq!(processes[0].activity, ProcessActivityState::Cancelled);
    assert_eq!(
        processes[0].final_result,
        Some(ProcessFinalResult::Cancelled)
    );
    assert_eq!(processes[0].ended_at_epoch_seconds, Some(120));

    service.set_server_time(130);
    service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::StartProcess {
                launch_attempt: None,
                process: "process-two".to_owned(),
                restart: false,
            },
        })
        .unwrap();
    let CoordinatorResponse::ProcessSummaries {
        processes,
        next_cursor: Some(cursor),
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: None,
                limit: 1,
            },
        })
        .unwrap()
    else {
        panic!("expected first process summary page");
    };
    assert_eq!(processes[0].process, ProcessId::from("process-two"));
    let CoordinatorResponse::ProcessSummaries {
        processes,
        next_cursor: None,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: Some(cursor),
                limit: 1,
            },
        })
        .unwrap()
    else {
        panic!("expected final process summary page");
    };
    assert_eq!(processes[0].process, ProcessId::from("process-one"));

    let oversized = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcessSummaries {
                cursor: None,
                limit: 101,
            },
        })
        .unwrap_err();
    assert!(oversized.to_string().contains("limit"));
    assert!(oversized.to_string().contains("100"));
}

#[test]
fn process_summary_eviction_releases_live_log_accounting_state() {
    let mut service = CoordinatorService::new(7);
    let tenant = TenantId::from("tenant-summary-bound");
    let project = ProjectId::from("project-summary-bound");
    let task = TaskInstanceId::from("task");

    for index in 0..MAX_RECENT_PROCESS_SUMMARIES_PER_PROJECT {
        let process = ProcessId::new(format!("process-{index:03}"));
        service.record_process_started(&tenant, &project, &process, index as u64);
        service.record_process_terminal(
            &tenant,
            &project,
            &process,
            ProcessFinalResult::Completed,
            index as u64 + 1,
        );
        let key = (
            tenant.clone(),
            project.clone(),
            process,
            task.clone(),
            "stdout".to_owned(),
        );
        service
            .recent_log_store
            .set_accounted_bytes(key.clone(), 10);
        service.recent_log_store.mark_source_truncated(key);
    }

    let evicted = ProcessId::from("process-000");
    service.record_process_started(&tenant, &project, &ProcessId::from("process-next"), 1_000);

    assert!(!service.process_registry.contains_summary(&(
        tenant.clone(),
        project.clone(),
        evicted.clone()
    )));
    assert!(!service
        .recent_log_store
        .has_accounted_process(&tenant, &project, &evicted));
    assert!(!service
        .recent_log_store
        .has_truncated_process(&tenant, &project, &evicted));
}

#[test]
fn web_node_summaries_are_scoped_paginated_and_hard_bounded() {
    let mut service = CoordinatorService::new(7);
    service
        .issue_cli_session(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            UserId::from("user"),
            "session",
            None,
        )
        .unwrap();
    for node in ["node-a", "node-b", "node-c"] {
        enroll_test_node(
            &mut service,
            "tenant",
            "project",
            node,
            &test_node_public_key(node),
        );
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }

    let CoordinatorResponse::NodeSummaries {
        nodes,
        next_cursor: Some(cursor),
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: None,
                limit: 2,
            },
        })
        .unwrap()
    else {
        panic!("expected first node-summary page");
    };
    assert_eq!(
        nodes
            .iter()
            .map(|node| node.id.as_str())
            .collect::<Vec<_>>(),
        ["node-a", "node-b"]
    );

    let CoordinatorResponse::NodeSummaries {
        nodes,
        next_cursor: None,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: Some(cursor),
                limit: 2,
            },
        })
        .unwrap()
    else {
        panic!("expected final node-summary page");
    };
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, NodeId::from("node-c"));

    let oversized = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: None,
                limit: 201,
            },
        })
        .unwrap_err();
    assert!(oversized.to_string().contains("limit"));
    assert!(oversized.to_string().contains("200"));
}

#[test]
fn durable_node_identity_quota_is_exact_visible_and_reclaimed_only_by_revocation() {
    let quota =
        CoordinatorQuotaConfiguration::unlimited().with_admission_limits(usize::MAX, 4, usize::MAX);
    let mut service = CoordinatorService::new_with_admin_token_database_url_and_quota(
        7,
        "test-admin-token",
        None,
        quota,
    )
    .unwrap();
    service
        .issue_cli_session(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            UserId::from("user"),
            "session",
            None,
        )
        .unwrap();

    for node in ["node-a", "node-b", "node-c", "node-d"] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                public_key: test_node_public_key(node),
            })
            .unwrap();
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            node: "other-node".to_owned(),
            public_key: test_node_public_key("other-node"),
        })
        .unwrap();

    // Runtime descriptors are intentionally not durable. Durable identities must
    // remain visible after the same loss of runtime state that occurs on restart.
    service.node_registry = NodeRegistry::default();
    let CoordinatorResponse::NodeSummaries { nodes, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: None,
                limit: 200,
            },
        })
        .unwrap()
    else {
        panic!("expected node summaries");
    };
    assert_eq!(nodes.len(), 4);
    assert!(nodes.iter().all(|node| {
        node.credential_state == "active"
            && node.runtime_state == "offline"
            && !node.online
            && node.stale
            && !node.capabilities_known
            && node.capabilities.os == Os::Other("unknown".to_owned())
    }));

    let CoordinatorResponse::QuotaStatus {
        node_identities_current,
        node_identities_maximum,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session".to_owned(),
            request: AuthenticatedCoordinatorRequest::QuotaStatus,
        })
        .unwrap()
    else {
        panic!("expected quota status");
    };
    assert_eq!((node_identities_current, node_identities_maximum), (4, 4));

    let error = service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node-e".to_owned(),
            public_key: test_node_public_key("node-e"),
        })
        .unwrap_err();
    let api_error = error.api_error("request-quota");
    assert_eq!(api_error.code, ApiErrorCode::QuotaExceeded);
    assert_eq!(api_error.resource.as_deref(), Some("node_identity"));
    assert_eq!(api_error.current, Some(4));
    assert_eq!(api_error.maximum, Some(4));
    assert_eq!(
        api_error.next_actions,
        vec![
            "clusterflux node list".to_owned(),
            "clusterflux node revoke <node-id> --yes".to_owned(),
        ]
    );

    service
        .handle_request(CoordinatorRequest::RevokeNodeCredential {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            node: "node-a".to_owned(),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node-e".to_owned(),
            public_key: test_node_public_key("node-e"),
        })
        .unwrap();
    assert_eq!(
        service
            .coordinator
            .node_identity_count_for_tenant(&TenantId::from("tenant")),
        4
    );
}

#[test]
fn web_artifact_queries_are_scoped_paginated_and_track_retention_availability() {
    let mut service = CoordinatorService::new(7);
    for (tenant, project, user, secret, node) in [
        ("tenant-a", "project-a", "user-a", "session-a", "node-a"),
        ("tenant-b", "project-b", "user-b", "session-b", "node-b"),
    ] {
        service
            .issue_cli_session(
                TenantId::from(tenant),
                ProjectId::from(project),
                UserId::from(user),
                secret,
                None,
            )
            .unwrap();
        enroll_test_node(
            &mut service,
            tenant,
            project,
            node,
            &test_node_public_key(node),
        );
    }
    service.set_server_time(100);
    for (tenant, project, node) in [
        ("tenant-a", "project-a", "node-a"),
        ("tenant-b", "project-b", "node-b"),
    ] {
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: tenant.to_owned(),
                project: project.to_owned(),
                node: node.to_owned(),
                capabilities: linux_capabilities(),
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: vec!["shared-artifact".to_owned()],
                online: false,
            })
            .unwrap();
    }
    let CoordinatorResponse::NodeSummaries { nodes, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: None,
                limit: 200,
            },
        })
        .unwrap()
    else {
        panic!("expected node summaries");
    };
    assert_eq!(nodes.len(), 1);
    assert_eq!(nodes[0].id, NodeId::from("node-a"));
    assert!(nodes[0].online);
    assert!(!nodes[0].stale);
    assert_eq!(nodes[0].last_seen_epoch_seconds, Some(100));
    assert_eq!(nodes[0].capabilities.os, Os::Linux);
    for (tenant, project, node, digest) in [
        ("tenant-a", "project-a", "node-a", "tenant-a-bytes"),
        ("tenant-b", "project-b", "node-b", "tenant-b-bytes"),
    ] {
        service.artifact_registry.flush_metadata(ArtifactFlush {
            id: ArtifactId::from("shared-artifact"),
            tenant: TenantId::from(tenant),
            project: ProjectId::from(project),
            process: ProcessId::from("process-one"),
            producer_task: TaskInstanceId::from("task-one"),
            retaining_node: NodeId::from(node),
            digest: Digest::sha256(digest),
            size: digest.len() as u64,
        });
    }
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: ArtifactId::from("second-artifact"),
        tenant: TenantId::from("tenant-a"),
        project: ProjectId::from("project-a"),
        process: ProcessId::from("process-two"),
        producer_task: TaskInstanceId::from("task-two"),
        retaining_node: NodeId::from("node-a"),
        digest: Digest::sha256("second"),
        size: 6,
    });

    let CoordinatorResponse::Artifacts {
        artifacts,
        next_cursor: Some(cursor),
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListArtifacts {
                process: None,
                cursor: None,
                limit: 1,
            },
        })
        .unwrap()
    else {
        panic!("expected first artifact page");
    };
    assert_eq!(artifacts.len(), 1);
    assert_eq!(artifacts[0].id, ArtifactId::from("second-artifact"));
    assert_eq!(artifacts[0].availability, ArtifactAvailability::Available);
    let CoordinatorResponse::Artifacts {
        artifacts,
        next_cursor: None,
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListArtifacts {
                process: None,
                cursor: Some(cursor),
                limit: 1,
            },
        })
        .unwrap()
    else {
        panic!("expected final artifact page");
    };
    assert_eq!(artifacts[0].id, ArtifactId::from("shared-artifact"));
    assert_eq!(artifacts[0].digest, Digest::sha256("tenant-a-bytes"));

    let cross_tenant = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::GetArtifact {
                artifact: "tenant-b-only".to_owned(),
            },
        })
        .unwrap_err();
    assert!(cross_tenant.to_string().contains("does not exist"));
    let CoordinatorResponse::Artifact { artifact } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-b".to_owned(),
            request: AuthenticatedCoordinatorRequest::GetArtifact {
                artifact: "shared-artifact".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected tenant-b artifact");
    };
    assert_eq!(artifact.digest, Digest::sha256("tenant-b-bytes"));

    service.set_server_time(131);
    let CoordinatorResponse::NodeSummaries { nodes, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListNodeSummaries {
                cursor: None,
                limit: 200,
            },
        })
        .unwrap()
    else {
        panic!("expected stale node summary");
    };
    assert!(!nodes[0].online);
    assert!(nodes[0].stale);
    assert_eq!(nodes[0].last_seen_epoch_seconds, Some(100));
    let CoordinatorResponse::Artifact { artifact } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::GetArtifact {
                artifact: "shared-artifact".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected offline artifact metadata");
    };
    assert_eq!(artifact.availability, ArtifactAvailability::NodeOffline);
    assert!(!artifact.downloadable_now);

    service
        .artifact_registry
        .sync_to_explicit_store(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            &ArtifactId::from("shared-artifact"),
            "store://tenant-a/shared-artifact",
        )
        .unwrap();
    let CoordinatorResponse::Artifact { artifact } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::GetArtifact {
                artifact: "shared-artifact".to_owned(),
            },
        })
        .unwrap()
    else {
        panic!("expected explicitly retained artifact metadata");
    };
    assert_eq!(artifact.availability, ArtifactAvailability::Available);
    assert_eq!(
        artifact.retention_state,
        ArtifactRetentionState::ExplicitStorage
    );
    assert!(artifact.downloadable_now);
}

#[test]
fn web_recent_logs_are_signed_scoped_cursor_safe_and_memory_bounded() {
    let mut service = CoordinatorService::new(7);
    for (tenant, project, user, secret, node, process) in [
        (
            "tenant-a",
            "project-a",
            "user-a",
            "session-a",
            "node-a",
            "process-shared",
        ),
        (
            "tenant-b",
            "project-b",
            "user-b",
            "session-b",
            "node-b",
            "process-b",
        ),
    ] {
        service
            .issue_cli_session(
                TenantId::from(tenant),
                ProjectId::from(project),
                UserId::from(user),
                secret,
                None,
            )
            .unwrap();
        enroll_test_node(
            &mut service,
            tenant,
            project,
            node,
            &test_node_public_key(node),
        );
        service
            .handle_request(CoordinatorRequest::Authenticated {
                session_secret: secret.to_owned(),
                request: AuthenticatedCoordinatorRequest::StartProcess {
                    launch_attempt: None,
                    process: process.to_owned(),
                    restart: false,
                },
            })
            .unwrap();
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
                tenant: tenant.to_owned(),
                project: project.to_owned(),
                node: node.to_owned(),
                process: process.to_owned(),
                epoch: 7,
            })
            .unwrap();
        register_test_task_assignment(
            &mut service,
            tenant,
            project,
            process,
            node,
            "task-one",
            "task-one",
            7,
        );
    }
    service.set_server_time(100);
    let first = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLogChunk {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            process: "process-shared".to_owned(),
            node: "node-a".to_owned(),
            task: "task-one".to_owned(),
            stream: TaskLogStream::Stdout,
            offset: 0,
            source_bytes: 5,
            text: "hello".to_owned(),
            truncated: false,
        })
        .unwrap();
    let CoordinatorResponse::TaskLogChunkRecorded {
        sequence: Some(first_sequence),
        next_offset: 5,
        ..
    } = first
    else {
        panic!("expected first live log sequence");
    };
    assert_eq!(
        service.quota.used_log_bytes(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            100,
        ),
        5,
        "live bytes must be charged when accepted"
    );
    let retry = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLogChunk {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            process: "process-shared".to_owned(),
            node: "node-a".to_owned(),
            task: "task-one".to_owned(),
            stream: TaskLogStream::Stdout,
            offset: 0,
            source_bytes: 5,
            text: "hello".to_owned(),
            truncated: false,
        })
        .unwrap();
    assert!(matches!(
        retry,
        CoordinatorResponse::TaskLogChunkRecorded { sequence: None, .. }
    ));
    assert_eq!(
        service.quota.used_log_bytes(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            100,
        ),
        5,
        "a retried chunk must not be charged twice"
    );
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLogChunk {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            process: "process-shared".to_owned(),
            node: "node-a".to_owned(),
            task: "task-one".to_owned(),
            stream: TaskLogStream::Stdout,
            offset: 8,
            source_bytes: 2,
            text: "ok".to_owned(),
            truncated: false,
        })
        .unwrap();
    assert_eq!(
        service.quota.used_log_bytes(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            100,
        ),
        10,
        "a gap and the delivered bytes must both count toward source-byte usage"
    );

    let CoordinatorResponse::RecentLogs {
        entries,
        next_sequence: Some(cursor),
        history_truncated: false,
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListRecentLogs {
                process: "process-shared".to_owned(),
                task: None,
                after_sequence: None,
                limit: 2,
            },
        })
        .unwrap()
    else {
        panic!("expected first recent-log page");
    };
    assert_eq!(entries.len(), 2);
    assert_eq!(entries[0].sequence, first_sequence);
    assert_eq!(entries[0].text, "hello");
    assert!(entries[1].text.contains("3 bytes"));
    assert!(entries[1].truncated);
    let CoordinatorResponse::RecentLogs { entries, .. } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListRecentLogs {
                process: "process-shared".to_owned(),
                task: None,
                after_sequence: Some(cursor),
                limit: 2,
            },
        })
        .unwrap()
    else {
        panic!("expected second recent-log page");
    };
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].text, "ok");

    service
        .handle_report_task_log(
            "tenant-a".to_owned(),
            "project-a".to_owned(),
            "process-shared".to_owned(),
            "node-a".to_owned(),
            "task-one".to_owned(),
            12,
            0,
            "hello???okZZ".to_owned(),
            String::new(),
            false,
            false,
            false,
        )
        .unwrap();
    assert_eq!(
        service.quota.used_log_bytes(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            100,
        ),
        12,
        "the final summary must charge only source bytes not already charged live"
    );
    assert_eq!(
        service
            .recent_log_store
            .entries_for_project(&TenantId::from("tenant-a"), &ProjectId::from("project-a"))
            .last()
            .unwrap()
            .text,
        "ZZ",
        "final-tail reconciliation must append only the nonduplicating suffix"
    );
    service
        .handle_report_task_log(
            "tenant-a".to_owned(),
            "project-a".to_owned(),
            "process-shared".to_owned(),
            "node-a".to_owned(),
            "task-one".to_owned(),
            12,
            0,
            "hello???okZZ".to_owned(),
            String::new(),
            false,
            false,
            false,
        )
        .unwrap();
    assert_eq!(
        service.quota.used_log_bytes(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            100,
        ),
        12,
        "replayed final accounting must be idempotent"
    );

    let marker = service
        .handle_report_task_log_chunk(
            "tenant-a".to_owned(),
            "project-a".to_owned(),
            "process-shared".to_owned(),
            "node-a".to_owned(),
            "task-one".to_owned(),
            TaskLogStream::Stdout,
            12,
            0,
            "[log output truncated at node capture limit]".to_owned(),
            true,
        )
        .unwrap();
    assert!(matches!(
        marker,
        CoordinatorResponse::TaskLogChunkRecorded {
            sequence: Some(_),
            next_offset: 12,
            ..
        }
    ));
    let repeated_marker = service
        .handle_report_task_log_chunk(
            "tenant-a".to_owned(),
            "project-a".to_owned(),
            "process-shared".to_owned(),
            "node-a".to_owned(),
            "task-one".to_owned(),
            TaskLogStream::Stdout,
            12,
            0,
            "[log output truncated at node capture limit]".to_owned(),
            true,
        )
        .unwrap();
    assert!(matches!(
        repeated_marker,
        CoordinatorResponse::TaskLogChunkRecorded {
            sequence: None,
            next_offset: 12,
            ..
        }
    ));

    let cross_tenant = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-b".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListRecentLogs {
                process: "process-shared".to_owned(),
                task: None,
                after_sequence: None,
                limit: 10,
            },
        })
        .unwrap_err();
    assert!(cross_tenant.to_string().contains("outside"));
    let oversized = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListRecentLogs {
                process: "process-shared".to_owned(),
                task: None,
                after_sequence: None,
                limit: 201,
            },
        })
        .unwrap_err();
    assert!(oversized.to_string().contains("limit"));
    assert!(oversized.to_string().contains("200"));

    service
        .handle_report_task_log_chunk(
            "tenant-b".to_owned(),
            "project-b".to_owned(),
            "process-b".to_owned(),
            "node-b".to_owned(),
            "task-b".to_owned(),
            TaskLogStream::Stderr,
            0,
            1,
            "b".to_owned(),
            false,
        )
        .unwrap();
    for offset in 10..310 {
        service
            .handle_report_task_log_chunk(
                "tenant-a".to_owned(),
                "project-a".to_owned(),
                "process-shared".to_owned(),
                "node-a".to_owned(),
                "task-one".to_owned(),
                TaskLogStream::Stdout,
                offset,
                1,
                "x".to_owned(),
                false,
            )
            .unwrap();
    }
    let tenant_a_logs = service
        .recent_log_store
        .entries_for_project(&TenantId::from("tenant-a"), &ProjectId::from("project-a"));
    assert!(tenant_a_logs.len() <= MAX_RECENT_LOG_ENTRIES_PER_PROCESS);
    let tenant_b_logs = service
        .recent_log_store
        .entries_for_project(&TenantId::from("tenant-b"), &ProjectId::from("project-b"));
    assert_eq!(tenant_b_logs.len(), 1);
    assert_eq!(tenant_b_logs[0].text, "b");
    let CoordinatorResponse::RecentLogs {
        entries,
        history_truncated,
        ..
    } = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: "session-a".to_owned(),
            request: AuthenticatedCoordinatorRequest::ListRecentLogs {
                process: "process-shared".to_owned(),
                task: None,
                after_sequence: None,
                limit: 200,
            },
        })
        .unwrap()
    else {
        panic!("expected bounded recent-log response");
    };
    assert_eq!(entries.len(), 200);
    assert!(history_truncated);
}

#[test]
fn restarted_worker_completion_preserves_live_log_accounting() {
    let mut service = CoordinatorService::new(41);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            process: "process".to_owned(),
            epoch: 41,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "task",
        "task",
        41,
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLogChunk {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "task".to_owned(),
            stream: TaskLogStream::Stderr,
            offset: 0,
            source_bytes: 5,
            text: "hello".to_owned(),
            truncated: false,
        })
        .unwrap();

    let completed = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "task".to_owned(),
            terminal_state: Some(TaskTerminalState::Cancelled),
            status_code: None,
            stdout_bytes: 0,
            stderr_bytes: 0,
            stdout_tail: String::new(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: None,
        })
        .unwrap();
    assert!(matches!(
        completed,
        CoordinatorResponse::TaskRecorded { .. }
    ));

    let event = service.task_registry.event_at(0).unwrap();
    assert_eq!(event.stderr_bytes, 5);
    assert!(event.stderr_truncated);
    assert_eq!(
        service
            .quota
            .used_log_bytes(&TenantId::from("tenant"), &ProjectId::from("project"), 41,),
        5,
        "completion must not double-charge bytes already accepted live"
    );
    let entries = service
        .recent_log_store
        .entries_for_project(&TenantId::from("tenant"), &ProjectId::from("project"));
    assert!(entries.iter().any(|entry| entry.text == "hello"));
    assert!(entries
        .iter()
        .any(|entry| entry.text.contains("unavailable or truncated") && entry.truncated));
}
