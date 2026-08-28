use super::*;

#[test]
fn service_attaches_node_starts_process_and_records_scoped_task_event() {
    let mut service = CoordinatorService::new(7);

    let attached = service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    assert!(matches!(attached, CoordinatorResponse::NodeAttached { .. }));

    let started = service
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
    assert_eq!(
        started,
        CoordinatorResponse::ProcessStarted {
            launch_attempt: None,
            process: ProcessId::from("process"),
            epoch: 7,
            actor: WorkflowActor {
                kind: "user".to_owned(),
                user: Some(UserId::from("user")),
                agent: None,
                credential_kind: CredentialKind::BrowserSession,
                public_key_fingerprint: None,
                authenticated_without_browser: false,
                scopes: vec!["project:read".to_owned(), "project:run".to_owned()],
            },
            charged_spawns: 1,
        }
    );

    let heartbeat = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(signed_node_heartbeat("node", "task-event-heartbeat")),
        })
        .unwrap();
    assert_eq!(
        heartbeat,
        CoordinatorResponse::NodeHeartbeat {
            node: NodeId::from("node"),
            epoch: 7,
        }
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            process: "process".to_owned(),
            epoch: 7,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "compile-linux",
        "compile-linux",
        7,
    );
    let recorded = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-linux".to_owned(),
            terminal_state: None,
            status_code: Some(0),
            stdout_bytes: 12,
            stderr_bytes: 0,
            stdout_tail: "build ok".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/app.txt".to_owned()),
            artifact_digest: Some(Digest::sha256("artifact")),
            artifact_size_bytes: Some(12),
            result: None,
        })
        .unwrap();

    assert_eq!(
        recorded,
        CoordinatorResponse::TaskRecorded {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("compile-linux"),
            events_recorded: 1
        }
    );
    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("process".to_owned()),
        })
        .unwrap()
    else {
        panic!("expected task events");
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].node, NodeId::from("node"));
    assert_eq!(events[0].stdout_tail, "build ok");
    assert_eq!(events[0].stderr_tail, "");
    assert!(!events[0].stdout_truncated);

    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "oversized",
        "oversized",
        7,
    );

    let oversized_tail = "x".repeat(MAX_TASK_LOG_TAIL_BYTES + 1);
    let oversized_log = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportTaskLog {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "oversized".to_owned(),
            stdout_bytes: oversized_tail.len() as u64,
            stderr_bytes: 0,
            stdout_tail: oversized_tail.clone(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            backpressured: false,
        })
        .unwrap_err();
    assert!(oversized_log.to_string().contains("stdout_tail"));

    let oversized_completion = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "oversized".to_owned(),
            terminal_state: None,
            status_code: Some(0),
            stdout_bytes: oversized_tail.len() as u64,
            stderr_bytes: 0,
            stdout_tail: oversized_tail,
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: None,
        })
        .unwrap_err();
    assert!(oversized_completion.to_string().contains("stdout_tail"));

    let cross_tenant = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "other".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("process".to_owned()),
        })
        .unwrap_err();
    assert!(cross_tenant
        .to_string()
        .contains("outside the virtual process tenant/project scope"));

    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("other-process".to_owned()),
        })
        .unwrap()
    else {
        panic!("expected task events");
    };
    assert!(events.is_empty());
}

#[test]
fn service_revokes_node_credentials_and_live_descriptors() {
    let mut service = CoordinatorService::new(7);

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            public_key: test_node_public_key("node"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: vec![],
            dependency_cache_digests: vec![],
            source_snapshots: vec![],
            artifact_locations: vec![],
            online: true,
        })
        .unwrap();

    let CoordinatorResponse::NodeCredentialRevoked {
        node,
        tenant,
        project,
        actor,
        descriptor_removed,
        queued_assignments_removed,
    } = service
        .handle_request(CoordinatorRequest::RevokeNodeCredential {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            node: "node".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected node credential revocation");
    };
    assert_eq!(node, NodeId::from("node"));
    assert_eq!(tenant, TenantId::from("tenant"));
    assert_eq!(project, ProjectId::from("project"));
    assert_eq!(actor, UserId::from("user"));
    assert!(descriptor_removed);
    assert_eq!(queued_assignments_removed, 0);

    let heartbeat = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node".to_owned(),
            node_signature: Some(signed_node_heartbeat("node", "revoked-heartbeat")),
        })
        .unwrap_err();
    assert!(heartbeat.to_string().contains("not enrolled"));

    let CoordinatorResponse::NodeDescriptors { descriptors, .. } = service
        .handle_request(CoordinatorRequest::ListNodeDescriptors {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected node descriptors");
    };
    assert!(descriptors.is_empty());
}

#[test]
fn duplicate_node_ids_are_isolated_across_identity_replay_liveness_and_revocation() {
    let mut service = CoordinatorService::new(19);
    let node = "shared-node";
    let private_a = test_node_private_key("tenant-a-shared-node");
    let private_b = test_node_private_key("tenant-b-shared-node");
    let private_c = test_node_private_key("tenant-a-other-project-shared-node");
    let public_a = node_ed25519_public_key_from_private_key(&private_a).unwrap();
    let public_b = node_ed25519_public_key_from_private_key(&private_b).unwrap();
    let public_c = node_ed25519_public_key_from_private_key(&private_c).unwrap();

    for (tenant, project, public_key) in [
        ("tenant-a", "project-a", public_a),
        ("tenant-b", "project-b", public_b),
        ("tenant-a", "project-c", public_c),
    ] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: tenant.to_owned(),
                project: project.to_owned(),
                node: node.to_owned(),
                public_key,
            })
            .unwrap();
    }
    assert_eq!(
        service
            .coordinator
            .node_identity_count_for_tenant(&TenantId::from("tenant-a")),
        2
    );
    assert_eq!(
        service
            .coordinator
            .node_identity_count_for_tenant(&TenantId::from("tenant-b")),
        1
    );

    for (index, (tenant, project, private_key)) in [
        ("tenant-a", "project-a", private_a.as_str()),
        ("tenant-b", "project-b", private_b.as_str()),
        ("tenant-a", "project-c", private_c.as_str()),
    ]
    .into_iter()
    .enumerate()
    {
        service.set_server_time(100 + index as u64);
        service
            .handle_request(CoordinatorRequest::NodeHeartbeat {
                tenant: tenant.to_owned(),
                project: project.to_owned(),
                node: node.to_owned(),
                node_signature: Some(signed_node_heartbeat_in_scope_with_private_key(
                    tenant,
                    project,
                    node,
                    private_key,
                    "same-nonce",
                )),
            })
            .unwrap();
        service
            .handle_request(signed_node_request_auto_with_private_key(
                CoordinatorRequest::ReportNodeCapabilities {
                    tenant: tenant.to_owned(),
                    project: project.to_owned(),
                    node: node.to_owned(),
                    capabilities: linux_capabilities(),
                    cached_environment_digests: vec![Digest::sha256(format!(
                        "cache-{tenant}-{project}"
                    ))],
                    dependency_cache_digests: Vec::new(),
                    source_snapshots: Vec::new(),
                    artifact_locations: Vec::new(),
                    online: true,
                },
                private_key,
            ))
            .unwrap();
    }

    let replay = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            node: node.to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope_with_private_key(
                "tenant-a",
                "project-a",
                node,
                &private_a,
                "same-nonce",
            )),
        })
        .unwrap_err();
    assert!(replay.to_string().contains("nonce"));

    let forged = service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            node: node.to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope_with_private_key(
                "tenant-b",
                "project-b",
                node,
                &private_a,
                "forged-cross-scope",
            )),
        })
        .unwrap_err();
    assert!(forged.to_string().contains("signature"));

    let scope_a = crate::NodeScopeKey::new(
        TenantId::from("tenant-a"),
        ProjectId::from("project-a"),
        NodeId::from(node),
    );
    let scope_b = crate::NodeScopeKey::new(
        TenantId::from("tenant-b"),
        ProjectId::from("project-b"),
        NodeId::from(node),
    );
    let scope_c = crate::NodeScopeKey::new(
        TenantId::from("tenant-a"),
        ProjectId::from("project-c"),
        NodeId::from(node),
    );
    assert!(service.node_registry.contains_node(&scope_a));
    assert!(service.node_registry.contains_node(&scope_b));
    assert!(service.node_registry.contains_node(&scope_c));
    assert_eq!(service.node_registry.last_seen(&scope_a), Some(100));
    assert_eq!(service.node_registry.last_seen(&scope_b), Some(101));
    assert_eq!(service.node_registry.last_seen(&scope_c), Some(102));
    assert!(service
        .replay_registry
        .contains_node(&scope_a, "same-nonce"));
    assert!(service
        .replay_registry
        .contains_node(&scope_b, "same-nonce"));
    assert!(service
        .replay_registry
        .contains_node(&scope_c, "same-nonce"));

    service
        .handle_request(CoordinatorRequest::RevokeNodeCredential {
            tenant: "tenant-a".to_owned(),
            project: "project-a".to_owned(),
            actor_user: "user-a".to_owned(),
            node: node.to_owned(),
        })
        .unwrap();
    assert!(service
        .coordinator
        .node_identity(
            &TenantId::from("tenant-a"),
            &ProjectId::from("project-a"),
            &NodeId::from(node),
        )
        .is_none());
    assert!(service
        .coordinator
        .node_identity(
            &TenantId::from("tenant-b"),
            &ProjectId::from("project-b"),
            &NodeId::from(node),
        )
        .is_some());
    assert!(!service.node_registry.contains_node(&scope_a));
    assert!(service.node_registry.contains_node(&scope_b));
    assert!(service.node_registry.contains_node(&scope_c));

    service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-b".to_owned(),
            project: "project-b".to_owned(),
            node: node.to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope_with_private_key(
                "tenant-b",
                "project-b",
                node,
                &private_b,
                "post-other-scope-revocation",
            )),
        })
        .expect("revoking tenant A's duplicate node must not affect tenant B");
}

#[test]
fn service_delivers_cancellation_to_connected_node_and_records_terminal_state() {
    let mut service = CoordinatorService::new(7);

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
            epoch: 7,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "compile-linux",
        "compile-linux",
        7,
    );

    let cancelled = service
        .handle_request(CoordinatorRequest::CancelTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-linux".to_owned(),
        })
        .unwrap();
    assert_eq!(
        cancelled,
        CoordinatorResponse::TaskCancellationRequested {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("compile-linux"),
            node: NodeId::from("node"),
        }
    );

    let control = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-linux".to_owned(),
            child_tasks: Vec::new(),
        })
        .unwrap();
    assert_eq!(
        control,
        CoordinatorResponse::TaskControl {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("compile-linux"),
            cancel_requested: true,
            abort_requested: false,
            child_joins: Vec::new(),
        }
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-linux".to_owned(),
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

    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("process".to_owned()),
        })
        .unwrap()
    else {
        panic!("expected task events");
    };
    assert_eq!(events[0].terminal_state, TaskTerminalState::Cancelled);

    let terminal_control = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-linux".to_owned(),
            child_tasks: Vec::new(),
        })
        .unwrap_err();
    assert!(terminal_control
        .to_string()
        .contains("assignment authority"));
}

#[test]
fn service_authorizes_debug_attach_through_public_api() {
    let mut service = CoordinatorService::new(7);
    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant".to_owned(),
            actor_user: "user".to_owned(),
            project: "project".to_owned(),
            name: "Demo".to_owned(),
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

    let CoordinatorResponse::DebugAttach {
        process,
        actor,
        authorization,
        audit_event,
        charged_debug_read_bytes,
        used_debug_read_bytes,
        ..
    } = service
        .handle_request(CoordinatorRequest::DebugAttach {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected debug attach authorization");
    };
    assert_eq!(process, ProcessId::from("process"));
    assert_eq!(actor, UserId::from("user"));
    assert!(authorization.allowed);
    assert_eq!(audit_event.operation, "debug_attach");
    assert_eq!(audit_event.actor, UserId::from("user"));
    assert!(audit_event.allowed);
    assert_eq!(charged_debug_read_bytes, DEBUG_CONTROL_READ_BYTES);
    assert_eq!(used_debug_read_bytes, DEBUG_CONTROL_READ_BYTES);

    let CoordinatorResponse::DebugAttach {
        authorization,
        audit_event,
        charged_debug_read_bytes,
        used_debug_read_bytes,
        ..
    } = service
        .handle_request(CoordinatorRequest::DebugAttach {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "other-user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected denied debug attach authorization");
    };
    assert!(!authorization.allowed);
    assert!(authorization.reason.contains("explicit project permission"));
    assert!(!audit_event.allowed);
    assert_eq!(audit_event.charged_debug_read_bytes, 0);
    assert_eq!(charged_debug_read_bytes, 0);
    assert_eq!(used_debug_read_bytes, DEBUG_CONTROL_READ_BYTES);

    let CoordinatorResponse::DebugAttach {
        authorization,
        audit_event,
        charged_debug_read_bytes,
        used_debug_read_bytes,
        ..
    } = service
        .handle_request(CoordinatorRequest::DebugAttach {
            tenant: "other-tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected cross-tenant debug attach denial");
    };
    assert!(!authorization.allowed);
    assert!(authorization.reason.contains("tenant or project"));
    assert!(!audit_event.allowed);
    assert_eq!(charged_debug_read_bytes, 0);
    assert_eq!(used_debug_read_bytes, 0);
    assert_eq!(service.debug_registry.audit_len(), 3);
}

#[test]
fn debug_epoch_commands_are_polled_by_signed_active_task_nodes() {
    let mut service = CoordinatorService::new(7);
    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant".to_owned(),
            actor_user: "user".to_owned(),
            project: "project".to_owned(),
            name: "Demo".to_owned(),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker".to_owned(),
            public_key: test_node_public_key("worker"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: vec![],
            dependency_cache_digests: vec![],
            source_snapshots: vec![],
            artifact_locations: vec![],
            online: true,
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "process",
                "compile-linux",
                7,
                [Capability::Command],
            ),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/out.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap();
    service.main_runtime.controls.insert(
        process_control_key(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &ProcessId::from("process"),
        ),
        super::main_runtime::CoordinatorMainControl {
            task_definition: clusterflux_core::TaskDefinitionId::from("completed-main"),
            task_instance: TaskInstanceId::from("ti:process:main"),
            abort: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            debug: std::sync::Arc::new(clusterflux_wasm_runtime::WasmDebugControl::default()),
            state: "completed".to_owned(),
            stopped_probe_symbol: None,
            handles: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            launch_id: 1,
        },
    );
    let CoordinatorResponse::DebugBreakpoints {
        revision,
        probe_symbols,
        hit_epoch,
        ..
    } = service
        .handle_request(CoordinatorRequest::SetDebugBreakpoints {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            revision: 1,
            probe_symbols: vec!["clusterflux.probe.compile_linux".to_owned()],
            probe_locations: vec![clusterflux_core::SourceLocation {
                source_path: ".clusterflux/tasks.rs".to_owned(),
                line: 42,
                column: Some(5),
                probe_id: "clusterflux.probe.compile_linux".to_owned(),
            }],
        })
        .unwrap()
    else {
        panic!("expected debug breakpoints response");
    };
    assert_eq!(revision, 1);
    assert_eq!(probe_symbols, ["clusterflux.probe.compile_linux"]);
    assert_eq!(hit_epoch, None);

    let CoordinatorResponse::DebugBreakpoints {
        revision,
        probe_symbols,
        ..
    } = service
        .handle_request(CoordinatorRequest::SetDebugBreakpoints {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            revision: 0,
            probe_symbols: vec!["clusterflux.probe.stale".to_owned()],
            probe_locations: Vec::new(),
        })
        .unwrap()
    else {
        panic!("expected stale breakpoint response");
    };
    assert_eq!(revision, 1);
    assert_eq!(probe_symbols, ["clusterflux.probe.compile_linux"]);

    let CoordinatorResponse::DebugProbeHit {
        breakpoint_matched,
        debug_epoch,
        probe_symbol,
        ..
    } = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportDebugProbeHit {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker".to_owned(),
            task: "compile-linux".to_owned(),
            probe_symbol: "clusterflux.probe.compile_linux".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected executing Wasm probe hit response");
    };
    assert!(breakpoint_matched);
    assert_eq!(debug_epoch, Some(1));
    assert_eq!(probe_symbol, "clusterflux.probe.compile_linux");

    let CoordinatorResponse::DebugBreakpoints {
        hit_epoch,
        hit_task,
        hit_probe_symbol,
        hit_source_location,
        ..
    } = service
        .handle_request(CoordinatorRequest::InspectDebugBreakpoints {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected breakpoint hit status");
    };
    assert_eq!(hit_epoch, Some(1));
    assert_eq!(hit_task, Some(TaskInstanceId::from("compile-linux")));
    assert_eq!(
        hit_probe_symbol.as_deref(),
        Some("clusterflux.probe.compile_linux")
    );
    assert_eq!(
        hit_source_location.unwrap().source_path,
        ".clusterflux/tasks.rs"
    );

    let CoordinatorResponse::DebugBreakpoints {
        revision,
        probe_symbols,
        hit_epoch,
        hit_task,
        hit_probe_symbol,
        ..
    } = service
        .handle_request(CoordinatorRequest::SetDebugBreakpoints {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            revision: 1,
            probe_symbols: vec!["clusterflux.probe.compile_linux".to_owned()],
            probe_locations: vec![clusterflux_core::SourceLocation {
                source_path: ".clusterflux/tasks.rs".to_owned(),
                line: 42,
                column: Some(5),
                probe_id: "clusterflux.probe.compile_linux".to_owned(),
            }],
        })
        .unwrap()
    else {
        panic!("expected idempotent breakpoint response");
    };
    assert_eq!(revision, 1);
    assert_eq!(probe_symbols, ["clusterflux.probe.compile_linux"]);
    assert_eq!(hit_epoch, Some(1));
    assert_eq!(hit_task, Some(TaskInstanceId::from("compile-linux")));
    assert_eq!(
        hit_probe_symbol.as_deref(),
        Some("clusterflux.probe.compile_linux")
    );

    let CoordinatorResponse::DebugCommand {
        epoch: Some(1),
        command: Some(command),
        ..
    } = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollDebugCommand {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker".to_owned(),
            task: "compile-linux".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected signed node poll to receive freeze command");
    };
    assert_eq!(command, "freeze");

    let CoordinatorResponse::DebugCommand {
        epoch: None,
        command: None,
        ..
    } = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollDebugCommand {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker".to_owned(),
            task: "compile-linux".to_owned(),
        })
        .unwrap()
    else {
        panic!("debug commands should be consumed after poll");
    };

    let CoordinatorResponse::DebugEpochStatus {
        fully_frozen,
        fully_resumed,
        acknowledgements,
        ..
    } = service
        .handle_request(CoordinatorRequest::InspectDebugEpoch {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            epoch: 1,
        })
        .unwrap()
    else {
        panic!("expected pending debug epoch status");
    };
    assert!(!fully_frozen);
    assert!(!fully_resumed);
    assert!(acknowledgements.is_empty());
    let early_resume = service
        .handle_request(CoordinatorRequest::ResumeDebugEpoch {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            epoch: 1,
        })
        .unwrap_err();
    assert!(early_resume
        .to_string()
        .contains("no settled frozen participant set"));

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportDebugState {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker".to_owned(),
            task: "compile-linux".to_owned(),
            epoch: 1,
            state: DebugAcknowledgementState::Frozen,
            current_source_location: Some(clusterflux_core::SourceLocation {
                source_path: ".clusterflux/tasks.rs".to_owned(),
                line: 17,
                column: Some(3),
                probe_id: "clusterflux.probe.compile_linux".to_owned(),
            }),
            stack_frames: vec!["compile_linux::wasm".to_owned()],
            local_values: vec![("wasm_local_0".to_owned(), "I32(41)".to_owned())],
            task_args: vec![("target".to_owned(), "linux".to_owned())],
            handles: vec![("artifact".to_owned(), "pending".to_owned())],
            command_status: Some("frozen at Wasm safepoint".to_owned()),
            recent_output: vec![],
            message: None,
        })
        .unwrap();
    let CoordinatorResponse::DebugEpochStatus {
        fully_frozen,
        fully_resumed,
        acknowledgements,
        ..
    } = service
        .handle_request(CoordinatorRequest::InspectDebugEpoch {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            epoch: 1,
        })
        .unwrap()
    else {
        panic!("expected frozen debug epoch status");
    };
    assert!(fully_frozen);
    assert!(!fully_resumed);
    assert_eq!(acknowledgements.len(), 1);
    assert_eq!(acknowledgements[0].state, DebugAcknowledgementState::Frozen);
    assert_eq!(
        acknowledgements[0]
            .current_source_location
            .as_ref()
            .map(|location| (location.source_path.as_str(), location.line)),
        Some((".clusterflux/tasks.rs", 17))
    );

    let CoordinatorResponse::DebugEpoch {
        epoch,
        command,
        affected_tasks,
        all_stop_requested,
        audit_event,
        ..
    } = service
        .handle_request(CoordinatorRequest::ResumeDebugEpoch {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            epoch: 1,
        })
        .unwrap()
    else {
        panic!("expected debug epoch resume response");
    };
    assert_eq!(epoch, 1);
    assert_eq!(command, "resume");
    assert!(!all_stop_requested);
    assert_eq!(affected_tasks.len(), 1);
    assert_eq!(audit_event.operation, "resume_debug_epoch");

    let CoordinatorResponse::DebugCommand {
        epoch: Some(1),
        command: Some(command),
        ..
    } = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollDebugCommand {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker".to_owned(),
            task: "compile-linux".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected signed node poll to receive resume command");
    };
    assert_eq!(command, "resume");

    let CoordinatorResponse::DebugEpochStatus { fully_resumed, .. } = service
        .handle_request(CoordinatorRequest::InspectDebugEpoch {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            epoch: 1,
        })
        .unwrap()
    else {
        panic!("expected pending resume status");
    };
    assert!(!fully_resumed);
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportDebugState {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker".to_owned(),
            task: "compile-linux".to_owned(),
            epoch: 1,
            state: DebugAcknowledgementState::Running,
            current_source_location: None,
            stack_frames: vec![],
            local_values: vec![],
            task_args: vec![],
            handles: vec![],
            command_status: Some("running".to_owned()),
            recent_output: vec![],
            message: None,
        })
        .unwrap();
    let CoordinatorResponse::DebugEpochStatus {
        fully_frozen,
        fully_resumed,
        ..
    } = service
        .handle_request(CoordinatorRequest::InspectDebugEpoch {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            epoch: 1,
        })
        .unwrap()
    else {
        panic!("expected resumed debug epoch status");
    };
    assert!(!fully_frozen);
    assert!(fully_resumed);
}

#[test]
fn service_reports_task_restart_boundary_through_public_api() {
    let mut service = CoordinatorService::new(7);
    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant".to_owned(),
            actor_user: "user".to_owned(),
            project: "project".to_owned(),
            name: "Demo".to_owned(),
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

    let denied = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "other-user".to_owned(),
            process: "process".to_owned(),
            task: "task".to_owned(),
            replacement_bundle: None,
        })
        .unwrap_err();
    assert!(denied.to_string().contains("task restart denied"));

    let CoordinatorResponse::TaskRestart {
        accepted,
        clean_boundary_available,
        active_task,
        completed_event_observed,
        requires_whole_process_restart,
        restarted_task_instance,
        message,
        audit_event,
        charged_debug_read_bytes,
        used_debug_read_bytes,
        ..
    } = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            task: "task".to_owned(),
            replacement_bundle: None,
        })
        .unwrap()
    else {
        panic!("expected task restart response");
    };
    assert!(!accepted);
    assert!(!clean_boundary_available);
    assert!(!active_task);
    assert!(!completed_event_observed);
    assert!(restarted_task_instance.is_none());
    assert!(requires_whole_process_restart);
    assert!(message.contains("not known"));
    assert_eq!(audit_event.operation, "restart_task");
    assert_eq!(audit_event.task, Some(TaskInstanceId::from("task")));
    assert!(audit_event.allowed);
    assert_eq!(charged_debug_read_bytes, DEBUG_CONTROL_READ_BYTES);
    assert_eq!(used_debug_read_bytes, DEBUG_CONTROL_READ_BYTES);

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            public_key: test_node_public_key("worker-linux"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "process",
                "task",
                7,
                [Capability::Command],
            ),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap();
    let Some(initial_assignment) =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "worker-linux")
    else {
        panic!("expected initial task assignment");
    };
    assert_eq!(initial_assignment.task, TaskInstanceId::from("task"));

    let CoordinatorResponse::TaskRestart {
        accepted,
        clean_boundary_available,
        active_task,
        completed_event_observed,
        requires_whole_process_restart,
        message,
        audit_event,
        used_debug_read_bytes,
        ..
    } = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            task: "task".to_owned(),
            replacement_bundle: None,
        })
        .unwrap()
    else {
        panic!("expected active task restart response");
    };
    assert!(!accepted);
    assert!(!clean_boundary_available);
    assert!(active_task);
    assert!(!completed_event_observed);
    assert!(requires_whole_process_restart);
    assert!(message.contains("still active"));
    assert_eq!(
        audit_event.charged_debug_read_bytes,
        DEBUG_CONTROL_READ_BYTES
    );
    assert_eq!(used_debug_read_bytes, DEBUG_CONTROL_READ_BYTES * 2);

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "worker-linux".to_owned(),
            task: "task".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
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

    let CoordinatorResponse::TaskRestart {
        accepted,
        clean_boundary_available,
        active_task,
        completed_event_observed,
        requires_whole_process_restart,
        restarted_task_instance,
        restarted_attempt_id,
        message,
        audit_event,
        used_debug_read_bytes,
        ..
    } = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
            task: "task".to_owned(),
            replacement_bundle: None,
        })
        .unwrap()
    else {
        panic!("expected completed task restart response");
    };
    assert!(accepted);
    assert!(clean_boundary_available);
    assert!(!active_task);
    assert!(completed_event_observed);
    assert!(!requires_whole_process_restart);
    let restarted_task_instance = restarted_task_instance.expect("restart returns logical id");
    let restarted_attempt_id = restarted_attempt_id.expect("restart returns a new attempt id");
    assert!(restarted_attempt_id.starts_with("ta_"));
    assert!(message.contains("from clean VFS entry boundary epoch 7"));
    let Some(restarted_assignment) =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "worker-linux")
    else {
        panic!("expected restarted task assignment");
    };
    assert_eq!(restarted_assignment.task, restarted_task_instance);
    assert_eq!(restarted_assignment.task, TaskInstanceId::from("task"));
    let mut expected_task_spec = initial_assignment.task_spec.clone();
    expected_task_spec.task_instance = restarted_task_instance;
    assert_eq!(restarted_assignment.task_spec, expected_task_spec);
    assert_eq!(
        restarted_assignment.wasm_module_base64,
        initial_assignment.wasm_module_base64
    );
    assert_eq!(
        audit_event.charged_debug_read_bytes,
        DEBUG_CONTROL_READ_BYTES
    );
    assert_eq!(used_debug_read_bytes, DEBUG_CONTROL_READ_BYTES * 3);
    assert_eq!(service.debug_registry.audit_len(), 4);
}
