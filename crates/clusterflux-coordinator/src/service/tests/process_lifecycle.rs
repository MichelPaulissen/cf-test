use super::*;

fn attach_live_process_worker(service: &mut CoordinatorService, node: &str) {
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

fn start_assignment_lifecycle_process(service: &mut CoordinatorService) {
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "assignment-process".to_owned(),
            restart: false,
        })
        .unwrap();
}

fn launch_assignment_lifecycle_task(service: &mut CoordinatorService) -> TaskAssignment {
    let response = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "assignment-process",
                "assignment-task",
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
            artifact_path: "/vfs/artifacts/assignment-task.bin".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap();
    let CoordinatorResponse::TaskLaunched { assignment, .. } = response else {
        panic!("expected task launch");
    };
    *assignment
}

fn poll_process_assignment(service: &mut CoordinatorService, node: &str) -> TaskAssignment {
    let response = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollNodeAssignment {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: node.to_owned(),
            accept_system_tasks: false,
            accept_process_tasks: true,
            active_assignment: None,
        })
        .unwrap();
    let CoordinatorResponse::NodeAssignment {
        assignment: Some(offer),
        cancel_assignment: None,
    } = response
    else {
        panic!("expected process assignment offer");
    };
    let clusterflux_protocol::NodeAssignmentWork::Task { assignment } = offer.work else {
        panic!("expected process task work");
    };
    *assignment
}

fn assignment_authority(assignment: &TaskAssignment) -> AssignmentAuthority {
    AssignmentAuthority {
        assignment_id: assignment.assignment_id.clone(),
        attempt_id: assignment.attempt_id.clone(),
        offer_epoch: assignment.offer_epoch,
    }
}

#[path = "process_lifecycle_terminal_idempotency.rs"]
mod terminal_idempotency;

#[test]
fn unacknowledged_process_offer_expires_and_is_safely_redelivered_with_a_new_fence() {
    let mut service = CoordinatorService::new(7);
    service.set_node_stale_after_seconds(60);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    start_assignment_lifecycle_process(&mut service);
    let launched = launch_assignment_lifecycle_task(&mut service);
    let first = poll_process_assignment(&mut service, "node-a");
    assert_eq!(first.assignment_id, launched.assignment_id);
    let stale_authority = assignment_authority(&first);

    attach_live_process_worker(&mut service, "node-b");
    service.set_server_time(131);
    let redelivered = poll_process_assignment(&mut service, "node-b");
    assert_eq!(redelivered.attempt_id, first.attempt_id);
    assert_ne!(redelivered.assignment_id, first.assignment_id);
    assert!(redelivered.offer_epoch > first.offer_epoch);

    let stale_ack = signed_node_request_auto_with_private_key_and_authority(
        CoordinatorRequest::AcknowledgeNodeAssignment {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node-a".to_owned(),
            assignment_id: first.assignment_id,
            lease_epoch: first.offer_epoch,
        },
        &test_node_private_key("node-a"),
        Some(stale_authority),
    );
    let stale_error = service
        .handle_request(stale_ack)
        .expect_err("an expired offer must not be acknowledged");
    assert!(matches!(
        stale_error,
        CoordinatorServiceError::StaleNodeAssignmentAcknowledgement
    ));
    let api_error = stale_error.api_error("stale-ack");
    assert_eq!(api_error.code, clusterflux_core::ApiErrorCode::Conflict);
    assert!(api_error.retryable);

    let fresh_authority = assignment_authority(&redelivered);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-b".to_owned(),
                assignment_id: redelivered.assignment_id,
                lease_epoch: redelivered.offer_epoch,
            },
            &test_node_private_key("node-b"),
            Some(fresh_authority),
        ))
        .unwrap();
}

#[test]
fn acknowledged_process_offer_expires_to_visible_node_offline_without_duplication() {
    let mut service = CoordinatorService::new(7);
    service.set_node_stale_after_seconds(60);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    start_assignment_lifecycle_process(&mut service);
    launch_assignment_lifecycle_task(&mut service);
    let assignment = poll_process_assignment(&mut service, "node-a");
    let authority = assignment_authority(&assignment);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-a".to_owned(),
                assignment_id: assignment.assignment_id.clone(),
                lease_epoch: assignment.offer_epoch,
            },
            &test_node_private_key("node-a"),
            Some(authority.clone()),
        ))
        .unwrap();
    attach_live_process_worker(&mut service, "node-b");

    service.set_server_time(281);
    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "assignment-process".to_owned(),
            task: "assignment-task".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected join result");
    };
    assert_eq!(join.state, TaskJoinState::Failed);
    assert!(join.remote_completion_observed);
    assert!(join.message.contains("node_offline"));

    let response = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollNodeAssignment {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node-b".to_owned(),
            accept_system_tasks: false,
            accept_process_tasks: true,
            active_assignment: None,
        })
        .unwrap();
    assert!(matches!(
        response,
        CoordinatorResponse::NodeAssignment {
            assignment: None,
            ..
        }
    ));

    let stale_completion = signed_node_request_auto_with_private_key_and_authority(
        CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "assignment-process".to_owned(),
            node: "node-a".to_owned(),
            task: "assignment-task".to_owned(),
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
        },
        &test_node_private_key("node-a"),
        Some(authority),
    );
    assert!(service.handle_request(stale_completion).is_err());
}

#[test]
fn revoked_node_does_not_poison_expired_assignment_reconciliation() {
    let mut service = CoordinatorService::new(7);
    service.set_node_stale_after_seconds(60);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    start_assignment_lifecycle_process(&mut service);
    launch_assignment_lifecycle_task(&mut service);
    let assignment = poll_process_assignment(&mut service, "node-a");
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-a".to_owned(),
                assignment_id: assignment.assignment_id.clone(),
                lease_epoch: assignment.offer_epoch,
            },
            &test_node_private_key("node-a"),
            Some(assignment_authority(&assignment)),
        ))
        .unwrap();

    service
        .handle_request(CoordinatorRequest::RevokeNodeCredential {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            node: "node-a".to_owned(),
        })
        .unwrap();

    service.set_server_time(281);
    assert!(matches!(
        service.handle_request(CoordinatorRequest::Ping).unwrap(),
        CoordinatorResponse::Pong { epoch: 7 }
    ));

    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "assignment-process".to_owned(),
            task: "assignment-task".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected join result");
    };
    assert_eq!(join.state, TaskJoinState::Failed);
    assert!(join.remote_completion_observed);
    assert!(join.message.contains("node_offline"));
    assert!(service
        .coordinator
        .durable_state()
        .active_assignments
        .is_empty());
}

#[test]
fn coordinator_restart_recovery_retires_acknowledged_process_authority() {
    let mut service = CoordinatorService::new(7);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    start_assignment_lifecycle_process(&mut service);
    launch_assignment_lifecycle_task(&mut service);
    let assignment = poll_process_assignment(&mut service, "node-a");
    let authority = assignment_authority(&assignment);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-a".to_owned(),
                assignment_id: assignment.assignment_id.clone(),
                lease_epoch: assignment.offer_epoch,
            },
            &test_node_private_key("node-a"),
            Some(authority.clone()),
        ))
        .unwrap();
    assert_eq!(
        service.coordinator.durable_state().active_assignments.len(),
        1
    );

    assert_eq!(
        service
            .reconcile_active_assignments_after_coordinator_restart()
            .unwrap(),
        1
    );
    assert!(service
        .coordinator
        .durable_state()
        .active_assignments
        .is_empty());
    assert!(
        !service
            .coordinator
            .durable_state()
            .terminal_assignment_history
            .iter()
            .find(|terminal| terminal.assignment_id == assignment.assignment_id)
            .unwrap()
            .replay_allowed
    );

    let stale_progress = signed_node_request_auto_with_private_key_and_authority(
        CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "assignment-process".to_owned(),
            node: "node-a".to_owned(),
            task: "assignment-task".to_owned(),
            child_tasks: Vec::new(),
        },
        &test_node_private_key("node-a"),
        Some(authority),
    );
    assert!(service.handle_request(stale_progress).is_err());
}

#[test]
fn reconnect_poll_renews_only_the_matching_process_assignment_fence() {
    let mut service = CoordinatorService::new(7);
    service.set_node_stale_after_seconds(600);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    start_assignment_lifecycle_process(&mut service);
    launch_assignment_lifecycle_task(&mut service);
    let assignment = poll_process_assignment(&mut service, "node-a");
    let authority = assignment_authority(&assignment);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-a".to_owned(),
                assignment_id: assignment.assignment_id.clone(),
                lease_epoch: assignment.offer_epoch,
            },
            &test_node_private_key("node-a"),
            Some(authority),
        ))
        .unwrap();

    service.set_server_time(250);
    let matching = clusterflux_protocol::ActiveNodeAssignment {
        assignment_id: assignment.assignment_id.clone(),
        attempt_id: assignment.attempt_id.clone(),
        lease_epoch: assignment.offer_epoch,
    };
    let response = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollNodeAssignment {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node-a".to_owned(),
            accept_system_tasks: false,
            accept_process_tasks: true,
            active_assignment: Some(matching.clone()),
        })
        .unwrap();
    assert_eq!(
        response,
        CoordinatorResponse::NodeAssignment {
            assignment: None,
            cancel_assignment: None,
        }
    );
    assert_eq!(
        service
            .coordinator
            .durable_state()
            .active_assignments
            .get(&assignment.assignment_id)
            .unwrap()
            .lease_expires_at,
        430
    );

    let stale = clusterflux_protocol::ActiveNodeAssignment {
        lease_epoch: assignment.offer_epoch.saturating_add(1),
        ..matching
    };
    let response = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollNodeAssignment {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "node-a".to_owned(),
            accept_system_tasks: false,
            accept_process_tasks: true,
            active_assignment: Some(stale.clone()),
        })
        .unwrap();
    assert_eq!(
        response,
        CoordinatorResponse::NodeAssignment {
            assignment: None,
            cancel_assignment: Some(stale),
        }
    );

    service.set_server_time(281);
    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "assignment-process".to_owned(),
            task: "assignment-task".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected join result");
    };
    assert_eq!(join.state, TaskJoinState::Pending);

    service.set_server_time(431);
    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "assignment-process".to_owned(),
            task: "assignment-task".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected join result");
    };
    assert_eq!(join.state, TaskJoinState::Failed);
}

#[test]
fn completion_winning_the_lease_expiry_boundary_remains_the_only_terminal_result() {
    let mut service = CoordinatorService::new(7);
    service.set_server_time(100);
    attach_live_process_worker(&mut service, "node-a");
    start_assignment_lifecycle_process(&mut service);
    launch_assignment_lifecycle_task(&mut service);
    let assignment = poll_process_assignment(&mut service, "node-a");
    let authority = assignment_authority(&assignment);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: "node-a".to_owned(),
                assignment_id: assignment.assignment_id,
                lease_epoch: assignment.offer_epoch,
            },
            &test_node_private_key("node-a"),
            Some(authority.clone()),
        ))
        .unwrap();

    service.set_server_time(280);
    service
        .handle_request(signed_node_request_auto_with_private_key_and_authority(
            CoordinatorRequest::TaskCompleted {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                process: "assignment-process".to_owned(),
                node: "node-a".to_owned(),
                task: "assignment-task".to_owned(),
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
            },
            &test_node_private_key("node-a"),
            Some(authority),
        ))
        .unwrap();

    service.set_server_time(281);
    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("assignment-process".to_owned()),
        })
        .unwrap()
    else {
        panic!("expected task events");
    };
    assert_eq!(events.len(), 1);
    assert_eq!(events[0].terminal_state, TaskTerminalState::Completed);
    assert!(service
        .coordinator
        .durable_state()
        .active_assignments
        .is_empty());
}

#[test]
fn service_cancels_whole_process_and_blocks_new_task_launches() {
    let mut service = CoordinatorService::new(7);
    for node in ["node-a", "node-b"] {
        let capabilities = if node == "node-a" {
            linux_capabilities()
        } else {
            windows_capabilities()
        };
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
                capabilities,
                cached_environment_digests: vec![],
                dependency_cache_digests: vec![],
                source_snapshots: vec![],
                artifact_locations: vec![],
                online: true,
            })
            .unwrap();
    }
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
    for node in ["node-a", "node-b"] {
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                process: "process".to_owned(),
                epoch: 7,
            })
            .unwrap();
    }

    for (task, required_capability, preferred_node) in [
        ("compile-linux", Capability::Containers, "node-a"),
        ("link-windows", Capability::WindowsCommandDev, "node-b"),
    ] {
        let response = service
            .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
                task_spec: test_task_spec(
                    "tenant",
                    "project",
                    "process",
                    task,
                    7,
                    [required_capability],
                ),
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: Some("user".to_owned()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                wait_for_node: false,
                artifact_path: format!("/vfs/artifacts/{task}.txt"),
                wasm_module_base64: test_wasm_module_base64(),
            })
            .unwrap();
        let CoordinatorResponse::TaskLaunched { assignment, .. } = response else {
            panic!("expected task launch");
        };
        assert_eq!(assignment.node, NodeId::from(preferred_node));
    }

    let CoordinatorResponse::ProcessCancellationRequested {
        process,
        cancelled_tasks,
        affected_nodes,
    } = service
        .handle_request(CoordinatorRequest::CancelProcess {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected process cancellation");
    };
    assert_eq!(process, ProcessId::from("process"));
    assert_eq!(cancelled_tasks.len(), 2);
    assert_eq!(
        affected_nodes,
        vec![NodeId::from("node-a"), NodeId::from("node-b")]
    );

    let control = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node-a".to_owned(),
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

    let blocked = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "process",
                "package-linux",
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
            artifact_path: "/vfs/artifacts/package-linux.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap_err();
    assert!(blocked
        .to_string()
        .contains("virtual process is cancelling"));

    service
        .handle_request(CoordinatorRequest::AbortProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap();
    let abort_control = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node-a".to_owned(),
            task: "compile-linux".to_owned(),
            child_tasks: Vec::new(),
        })
        .unwrap();
    assert_eq!(
        abort_control,
        CoordinatorResponse::TaskControl {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("compile-linux"),
            cancel_requested: false,
            abort_requested: true,
            child_joins: Vec::new(),
        }
    );
}

#[test]
fn service_rejects_second_active_process_unless_restarting_same_process() {
    let mut service = CoordinatorService::new(7);
    let started = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-a".to_owned(),
            restart: false,
        })
        .unwrap();
    assert!(matches!(
        started,
        CoordinatorResponse::ProcessStarted {
            launch_attempt: None,
            ..
        }
    ));

    let same_without_restart = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-a".to_owned(),
            restart: false,
        })
        .unwrap_err();
    assert!(same_without_restart
        .to_string()
        .contains("already has active virtual process"));

    let other_process = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-b".to_owned(),
            restart: true,
        })
        .unwrap_err();
    assert!(other_process
        .to_string()
        .contains("already has active virtual process"));

    let wrong_attempt_abort = service
        .handle_request(CoordinatorRequest::AbortProcess {
            launch_attempt: Some("attempt-b".to_owned()),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process-a".to_owned(),
        })
        .unwrap_err();
    assert!(wrong_attempt_abort
        .to_string()
        .contains("does not own process process-a"));
    assert!(service
        .coordinator
        .active_process(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &ProcessId::from("process-a")
        )
        .is_some());

    let retired_main_abort = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
    let process_key = process_control_key(
        &TenantId::from("tenant"),
        &ProjectId::from("project"),
        &ProcessId::from("process-a"),
    );
    service.main_runtime.controls.insert(
        process_key.clone(),
        super::main_runtime::CoordinatorMainControl {
            task_definition: clusterflux_core::TaskDefinitionId::from("build"),
            task_instance: TaskInstanceId::from("ti:process-a:main"),
            abort: std::sync::Arc::clone(&retired_main_abort),
            debug: std::sync::Arc::new(clusterflux_wasm_runtime::WasmDebugControl::default()),
            state: "running".to_owned(),
            stopped_probe_symbol: None,
            handles: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            launch_id: 1,
        },
    );
    let restarted = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: Some("attempt-a-restart".to_owned()),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-a".to_owned(),
            restart: true,
        })
        .unwrap();
    assert_eq!(
        restarted,
        CoordinatorResponse::ProcessStarted {
            launch_attempt: Some("attempt-a-restart".to_owned()),
            process: ProcessId::from("process-a"),
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
            charged_spawns: 2,
        }
    );
    assert!(retired_main_abort.load(std::sync::atomic::Ordering::Acquire));
    assert!(!service.main_runtime.controls.contains_key(&process_key));
}

#[test]
fn completed_main_waits_for_final_child_then_preserves_history_and_releases_the_slot() {
    let mut service = CoordinatorService::new(31);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("process-main-before-child");
    let child = TaskInstanceId::from("child-active");
    let process_key = process_control_key(&tenant, &project, &process);

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: "worker".to_owned(),
            public_key: test_node_public_key("worker"),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: process.to_string(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: "worker".to_owned(),
            process: process.to_string(),
            epoch: 31,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        tenant.as_str(),
        project.as_str(),
        process.as_str(),
        "worker",
        "child-definition",
        child.as_str(),
        31,
    );

    let main = TaskInstanceId::from("main-instance");
    service.main_runtime.controls.insert(
        process_key.clone(),
        super::main_runtime::CoordinatorMainControl {
            task_definition: TaskDefinitionId::from("build"),
            task_instance: main.clone(),
            abort: std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false)),
            debug: std::sync::Arc::new(clusterflux_wasm_runtime::WasmDebugControl::default()),
            state: "running".to_owned(),
            stopped_probe_symbol: None,
            handles: std::sync::Arc::new(std::sync::Mutex::new(std::collections::HashMap::new())),
            launch_id: 1,
        },
    );
    service.debug_registry.set_epoch(process_key.clone(), 9);

    service.record_coordinator_main_completion(
        super::main_runtime::MainScope {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task_definition: TaskDefinitionId::from("build"),
            task_instance: main,
            epoch: 31,
            launch_id: 1,
        },
        Ok(WasmTaskResult::completed(
            TaskInstanceId::from("main-instance"),
            TaskBoundaryValue::SmallJson(json!("main completed")),
        )),
    );

    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_some());
    assert!(service.debug_registry.contains_epoch(&process_key));
    assert!(service
        .task_registry
        .active_tasks()
        .any(|(_, _, retained_process, _, task)| {
            retained_process == &process && task == &child
        }));
    let blocked_next = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-too-early".to_owned(),
            restart: false,
        })
        .unwrap_err();
    assert!(blocked_next
        .to_string()
        .contains("already has active virtual process"));

    let artifact_bytes = b"child artifact survives terminal cleanup";
    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: tenant.to_string(),
            project: project.to_string(),
            process: process.to_string(),
            node: "worker".to_owned(),
            task: child.to_string(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: artifact_bytes.len() as u64,
            stderr_bytes: 0,
            stdout_tail: "child completed".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/child-output".to_owned()),
            artifact_digest: Some(Digest::sha256(artifact_bytes)),
            artifact_size_bytes: Some(artifact_bytes.len() as u64),
            result: Some(TaskBoundaryValue::SmallJson(json!("child completed"))),
        })
        .unwrap();

    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_none());
    assert!(!service.debug_registry.contains_epoch(&process_key));
    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: "user".to_owned(),
            process: Some(process.to_string()),
        })
        .unwrap()
    else {
        panic!("expected retained task events");
    };
    assert_eq!(events.len(), 2);
    assert!(events.iter().any(|event| {
        event.executor == TaskExecutor::CoordinatorMain
            && event.terminal_state == TaskTerminalState::Completed
    }));
    assert!(events.iter().any(|event| {
        event.task == child && event.artifact_digest == Some(Digest::sha256(artifact_bytes))
    }));
    let metadata = service
        .artifact_registry
        .metadata(&tenant, &project, &ArtifactId::from("child-output"))
        .expect("artifact metadata must survive terminal cleanup");
    assert_eq!(metadata.process, process);
    assert_eq!(metadata.digest, Digest::sha256(artifact_bytes));

    let next = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-after-cleanup".to_owned(),
            restart: false,
        })
        .unwrap();
    assert!(matches!(next, CoordinatorResponse::ProcessStarted { .. }));
}

#[test]
fn completed_main_terminal_matrix_retires_after_failed_or_cancelled_final_child() {
    for terminal_state in [TaskTerminalState::Failed, TaskTerminalState::Cancelled] {
        let mut service = service_with_completed_main_and_final_child(
            clusterflux_core::TaskFailurePolicy::FailFast,
        );
        complete_terminal_matrix_child(&mut service, terminal_state.clone());

        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("terminal-matrix");
        assert!(
            service
                .coordinator
                .active_process(&tenant, &project, &process)
                .is_none(),
            "{terminal_state:?} final child left the process slot active"
        );
        let process_key = process_control_key(&tenant, &project, &process);
        assert!(!service.debug_registry.contains_epoch(&process_key));
        assert!(!service.debug_registry.contains_breakpoint(&process_key));
        assert!(service
            .debug_registry
            .commands_are_outside_process(&tenant, &project, &process));
        assert!(!service
            .panel_registry
            .contains_snapshot(&super::keys::panel_stop_key(&tenant, &project, &process)));
        assert!(service.task_registry.active_tasks().all(
            |(task_tenant, task_project, task_process, _, _)| {
                task_tenant != &tenant || task_project != &project || task_process != &process
            }
        ));
        assert!(!service
            .main_runtime
            .controls
            .contains_key(&process_control_key(&tenant, &project, &process)));
        let join = service.task_join_result(
            tenant.clone(),
            project.clone(),
            process.clone(),
            TaskInstanceId::from("final-child"),
        );
        assert_eq!(
            join.state,
            match terminal_state {
                TaskTerminalState::Failed => TaskJoinState::Failed,
                TaskTerminalState::Cancelled => TaskJoinState::Cancelled,
                TaskTerminalState::Completed => unreachable!(),
            }
        );
        service
            .handle_request(CoordinatorRequest::StartProcess {
                launch_attempt: None,
                tenant: tenant.to_string(),
                project: project.to_string(),
                actor_user: None,
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: "next-after-terminal".to_owned(),
                restart: false,
            })
            .expect("the terminal outcome must release the one-process project slot");
    }
}

#[test]
fn completed_main_unpolled_final_assignment_completion_retires_process() {
    let mut service =
        service_with_completed_main_and_final_child(clusterflux_core::TaskFailurePolicy::FailFast);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("terminal-matrix");
    let node = NodeId::from("worker");
    let assignment_key = (tenant.clone(), project.clone(), node);
    assert_eq!(
        service
            .task_registry
            .assignments_for_node(&assignment_key)
            .count(),
        1
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: tenant.to_string(),
            project: project.to_string(),
            process: process.to_string(),
            node: "worker".to_owned(),
            task: "final-child".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 2,
            stderr_bytes: 0,
            stdout_tail: "42".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: Some(TaskBoundaryValue::SmallJson(json!(42))),
        })
        .unwrap();

    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_none());
    assert_eq!(
        service
            .task_registry
            .assignments_for_node(&assignment_key)
            .count(),
        0
    );
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "next-after-unpolled-completion".to_owned(),
            restart: false,
        })
        .expect("unpolled terminal completion must release the one-process slot");
}

#[test]
fn completed_main_retires_from_authoritative_state_after_event_history_rotates() {
    let mut service =
        service_with_completed_main_and_final_child(clusterflux_core::TaskFailurePolicy::FailFast);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("terminal-matrix");

    for index in 0..=MAX_TASK_EVENTS_PER_PROCESS {
        service.record_task_completion_event(TaskCompletionEvent {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            node: NodeId::from("worker"),
            executor: TaskExecutor::Node,
            task_definition: TaskDefinitionId::from("historical"),
            task: TaskInstanceId::new(format!("historical-{index}")),
            attempt_id: None,
            placement: None,
            terminal_state: TaskTerminalState::Completed,
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
        });
    }
    assert!(
        service.task_registry.events().all(|event| {
            event.process != process || event.executor != TaskExecutor::CoordinatorMain
        }),
        "the regression requires bounded history to have rotated the main event"
    );

    complete_terminal_matrix_child(&mut service, TaskTerminalState::Completed);

    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_none());
    let summary = service
        .process_registry
        .summary(&process_control_key(&tenant, &project, &process))
        .expect("the terminal process summary must remain authoritative");
    assert_eq!(summary.final_result, Some(ProcessFinalResult::Completed));
    assert_eq!(
        summary.main_terminal_state,
        Some(TaskTerminalState::Completed)
    );
}

#[test]
fn completed_main_await_operator_blocks_retirement_until_each_resolution() {
    for resolution in [
        TaskFailureResolution::AcceptFailure,
        TaskFailureResolution::Cancel,
    ] {
        let mut service = service_with_completed_main_and_final_child(
            clusterflux_core::TaskFailurePolicy::AwaitOperator,
        );
        complete_terminal_matrix_child(&mut service, TaskTerminalState::Failed);

        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("terminal-matrix");
        let process_key = process_control_key(&tenant, &project, &process);
        assert!(service
            .coordinator
            .active_process(&tenant, &project, &process)
            .is_some());
        assert!(service.debug_registry.contains_epoch(&process_key));
        assert!(service.debug_registry.contains_breakpoint(&process_key));
        assert!(service
            .panel_registry
            .contains_snapshot(&super::keys::panel_stop_key(&tenant, &project, &process)));
        let attempt = service
            .task_registry
            .current_attempt(&super::keys::task_restart_key(
                &tenant,
                &project,
                &process,
                &TaskInstanceId::from("final-child"),
            ))
            .unwrap();
        assert_eq!(attempt.state, TaskAttemptState::FailedAwaitingAction);

        service
            .handle_request(CoordinatorRequest::ResolveTaskFailure {
                tenant: tenant.to_string(),
                project: project.to_string(),
                actor_user: "user".to_owned(),
                process: process.to_string(),
                task: "final-child".to_owned(),
                resolution,
            })
            .unwrap();

        assert!(
            service
                .coordinator
                .active_process(&tenant, &project, &process)
                .is_none(),
            "{resolution:?} left the process slot active"
        );
        assert!(!service.debug_registry.contains_epoch(&process_key));
        assert!(!service.debug_registry.contains_breakpoint(&process_key));
        assert!(!service
            .panel_registry
            .contains_snapshot(&super::keys::panel_stop_key(&tenant, &project, &process)));
        assert!(service
            .debug_registry
            .commands_are_outside_process(&tenant, &project, &process));
        let join = service.task_join_result(
            tenant.clone(),
            project.clone(),
            process.clone(),
            TaskInstanceId::from("final-child"),
        );
        assert_eq!(
            join.state,
            match resolution {
                TaskFailureResolution::AcceptFailure => TaskJoinState::Failed,
                TaskFailureResolution::Cancel => TaskJoinState::Cancelled,
            }
        );
        service
            .handle_request(CoordinatorRequest::StartProcess {
                launch_attempt: None,
                tenant: tenant.to_string(),
                project: project.to_string(),
                actor_user: None,
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: "next-after-resolution".to_owned(),
                restart: false,
            })
            .expect("operator resolution must release the one-process project slot");
    }
}

#[test]
fn completed_main_failed_child_restarted_successfully_retires_with_successful_current_attempt() {
    let mut service = service_with_completed_main_and_final_child(
        clusterflux_core::TaskFailurePolicy::AwaitOperator,
    );
    complete_terminal_matrix_child(&mut service, TaskTerminalState::Failed);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("terminal-matrix");
    let task = TaskInstanceId::from("final-child");

    let CoordinatorResponse::TaskRestart { accepted, .. } = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: tenant.to_string(),
            project: project.to_string(),
            actor_user: "user".to_owned(),
            process: process.to_string(),
            task: task.to_string(),
            replacement_bundle: None,
        })
        .unwrap()
    else {
        panic!("expected task restart");
    };
    assert!(accepted);

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: tenant.to_string(),
            project: project.to_string(),
            process: process.to_string(),
            node: "worker".to_owned(),
            task: task.to_string(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 2,
            stderr_bytes: 0,
            stdout_tail: "ok".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: Some(TaskBoundaryValue::SmallJson(json!("ok"))),
        })
        .unwrap();

    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_none());
    let attempts = service
        .task_registry
        .attempt_history(&super::keys::task_restart_key(
            &tenant, &project, &process, &task,
        ))
        .unwrap();
    assert!(
        attempts
            .iter()
            .any(|attempt| !attempt.current
                && attempt.state == TaskAttemptState::FailedAwaitingAction)
    );
    assert!(attempts
        .iter()
        .any(|attempt| attempt.current && attempt.state == TaskAttemptState::Completed));
    assert_eq!(
        service
            .process_registry
            .summary(&process_control_key(&tenant, &project, &process))
            .and_then(|summary| summary.final_result.clone()),
        Some(ProcessFinalResult::Completed),
        "a successful current retry must override the superseded failed attempt"
    );
    assert_eq!(
        service
            .task_join_result(tenant, project, process, task)
            .state,
        TaskJoinState::Completed
    );
}

#[test]
fn completed_main_failed_child_does_not_abort_another_active_child() {
    let mut service =
        service_with_completed_main_and_final_child(clusterflux_core::TaskFailurePolicy::FailFast);
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "terminal-matrix",
        "worker",
        "other-child-definition",
        "other-child",
        83,
    );

    complete_terminal_matrix_child(&mut service, TaskTerminalState::Failed);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("terminal-matrix");
    let other_key = task_control_key(
        &tenant,
        &project,
        &process,
        &NodeId::from("worker"),
        &TaskInstanceId::from("other-child"),
    );
    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_some());
    assert!(service.task_registry.is_active(&other_key));
    assert!(!service.task_registry.is_aborted(&other_key));
    assert_eq!(
        service
            .task_join_result(
                tenant.clone(),
                project.clone(),
                process.clone(),
                TaskInstanceId::from("final-child"),
            )
            .state,
        TaskJoinState::Failed
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: tenant.to_string(),
            project: project.to_string(),
            process: process.to_string(),
            node: "worker".to_owned(),
            task: "other-child".to_owned(),
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

    assert!(service
        .coordinator
        .active_process(&tenant, &project, &process)
        .is_none());
    assert!(!service.task_registry.is_active(&other_key));
}

#[test]
fn quiescent_cooperative_cancel_releases_slot_immediately() {
    let mut service = CoordinatorService::new(17);
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-a".to_owned(),
            restart: false,
        })
        .unwrap();
    service.record_task_completion_event(TaskCompletionEvent {
        tenant: TenantId::from("tenant"),
        project: ProjectId::from("project"),
        process: ProcessId::from("process-a"),
        node: NodeId::from("node"),
        executor: TaskExecutor::Node,
        task_definition: clusterflux_core::TaskDefinitionId::from("old-task"),
        task: TaskInstanceId::from("ti:process-a:old"),
        attempt_id: None,
        placement: None,
        terminal_state: TaskTerminalState::Completed,
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
        result: Some(TaskBoundaryValue::SmallJson(json!("old"))),
    });
    service
        .record_debug_audit_event(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            ProcessId::from("process-a"),
            None,
            UserId::from("user"),
            "old_debug_event",
            false,
            "old process incarnation",
        )
        .unwrap();

    service
        .handle_request(CoordinatorRequest::CancelProcess {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process-a".to_owned(),
        })
        .unwrap();

    let CoordinatorResponse::ProcessStatuses { processes, .. } = service
        .handle_request(CoordinatorRequest::ListProcesses {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected live process statuses");
    };
    assert!(processes.is_empty());

    let started = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "process-a".to_owned(),
            restart: false,
        })
        .unwrap();
    assert!(matches!(
        started,
        CoordinatorResponse::ProcessStarted {
            launch_attempt: None,
            ..
        }
    ));
    assert!(service.task_registry.events().all(|event| {
        event.tenant != TenantId::from("tenant")
            || event.project != ProjectId::from("project")
            || event.process != ProcessId::from("process-a")
    }));
    assert!(service.debug_registry.audit_events().all(|event| {
        event.tenant != TenantId::from("tenant")
            || event.project != ProjectId::from("project")
            || event.process != ProcessId::from("process-a")
    }));
}

#[test]
fn aborted_process_accepts_signed_terminal_event_for_issued_task() {
    let mut service = CoordinatorService::new(17);
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
            epoch: 17,
        })
        .unwrap();
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "node",
        "compile",
        "compile-1",
        17,
    );

    let CoordinatorResponse::ProcessAborted { aborted_tasks, .. } = service
        .handle_request(CoordinatorRequest::AbortProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "process".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected process abort");
    };
    assert_eq!(aborted_tasks.len(), 1);

    let recorded = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "node".to_owned(),
            task: "compile-1".to_owned(),
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
    assert_eq!(
        recorded,
        CoordinatorResponse::TaskRecorded {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("compile-1"),
            events_recorded: 1,
        }
    );
    assert_eq!(
        service.task_registry.event_at(0).unwrap().task_definition,
        clusterflux_core::TaskDefinitionId::from("compile")
    );
    assert!(service.task_registry.checkpoints_are_empty());
}

#[test]
fn download_links_are_scoped_metadata_without_a_coordinator_byte_stream() {
    let mut service = CoordinatorService::new(7);
    service.set_server_time(10);
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
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: ArtifactId::from("app.txt"),
        tenant: TenantId::from("tenant"),
        project: ProjectId::from("project"),
        process: ProcessId::from("process"),
        producer_task: TaskInstanceId::from("producer"),
        retaining_node: NodeId::from("node"),
        digest: Digest::sha256(b"artifact bytes"),
        size: 14,
    });

    let CoordinatorResponse::ArtifactDownloadLink { link } = service
        .handle_request(CoordinatorRequest::CreateArtifactDownloadLink {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            artifact: "app.txt".to_owned(),
            max_bytes: 64,
            ttl_seconds: 60,
        })
        .unwrap()
    else {
        panic!("expected scoped artifact metadata link");
    };

    let cross_tenant = service
        .handle_request(CoordinatorRequest::CreateArtifactDownloadLink {
            tenant: "other-tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            artifact: "app.txt".to_owned(),
            max_bytes: 64,
            ttl_seconds: 60,
        })
        .unwrap_err();
    assert!(cross_tenant.to_string().contains("does not exist"));
    let cross_project = service
        .handle_request(CoordinatorRequest::CreateArtifactDownloadLink {
            tenant: "tenant".to_owned(),
            project: "other-project".to_owned(),
            actor_user: "user".to_owned(),
            artifact: "app.txt".to_owned(),
            max_bytes: 64,
            ttl_seconds: 60,
        })
        .unwrap_err();
    assert!(cross_project.to_string().contains("does not exist"));

    let cross_actor = service
        .handle_request(CoordinatorRequest::RevokeArtifactDownloadLink {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "other-user".to_owned(),
            artifact: "app.txt".to_owned(),
            token_digest: link.scoped_token_digest.clone(),
        })
        .unwrap_err();
    assert!(cross_actor.to_string().contains("token is invalid"));

    let CoordinatorResponse::ArtifactDownloadLinkRevoked { .. } = service
        .handle_request(CoordinatorRequest::RevokeArtifactDownloadLink {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            artifact: "app.txt".to_owned(),
            token_digest: link.scoped_token_digest.clone(),
        })
        .unwrap()
    else {
        panic!("expected metadata-link revocation");
    };
}

#[test]
fn windows_task_events_share_the_virtual_process_scope() {
    let mut service = CoordinatorService::new(7);
    service.record_task_completion_event(TaskCompletionEvent {
        tenant: TenantId::from("other-tenant"),
        project: ProjectId::from("other-project"),
        process: ProcessId::from("other-process"),
        node: NodeId::from("other-node"),
        executor: super::TaskExecutor::Node,
        task_definition: TaskDefinitionId::from("other-task"),
        task: TaskInstanceId::from("other-task"),
        attempt_id: None,
        placement: None,
        terminal_state: TaskTerminalState::Completed,
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
    });
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "windows-node".to_owned(),
            public_key: test_node_public_key("windows-node"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "windows-node".to_owned(),
            capabilities: windows_capabilities(),
            cached_environment_digests: vec![Digest::sha256("env-windows-command-dev")],
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
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
    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "process",
        "windows-node",
        "windows-command-dev",
        "windows-command-dev",
        7,
    );

    let recorded = service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "process".to_owned(),
            node: "windows-node".to_owned(),
            task: "windows-command-dev".to_owned(),
            terminal_state: None,
            status_code: Some(0),
            stdout_bytes: 24,
            stderr_bytes: 0,
            stdout_tail: "windows output".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/windows-output.txt".to_owned()),
            artifact_digest: Some(Digest::sha256("windows-artifact")),
            artifact_size_bytes: Some(24),
            result: None,
        })
        .unwrap();
    assert_eq!(
        recorded,
        CoordinatorResponse::TaskRecorded {
            process: ProcessId::from("process"),
            task: TaskInstanceId::from("windows-command-dev"),
            events_recorded: 1,
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
    assert_eq!(events[0].process, ProcessId::from("process"));
    assert_eq!(events[0].node, NodeId::from("windows-node"));
    assert_eq!(events[0].task, TaskInstanceId::from("windows-command-dev"));
    assert_eq!(
        events[0].artifact_path,
        Some(VfsPath::new("/vfs/artifacts/windows-output.txt").unwrap())
    );
}
