use super::*;

#[test]
fn service_schedules_task_across_reported_node_descriptors() {
    let mut service = CoordinatorService::new(7);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            node: "other-node".to_owned(),
            public_key: test_node_public_key("other-node"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            node: "other-node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    for node in ["cold-node", "warm-node"] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                public_key: test_node_public_key(node),
            })
            .unwrap();
    }

    let recorded = service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "cold-node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    assert_eq!(
        recorded,
        CoordinatorResponse::NodeCapabilitiesRecorded {
            node: NodeId::from("cold-node"),
            node_descriptors: 1,
        }
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "warm-node".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: vec![Digest::sha256("env")],
            dependency_cache_digests: vec![Digest::sha256("deps")],
            source_snapshots: vec![Digest::sha256("source")],
            artifact_locations: vec!["build-output".to_owned()],
            online: true,
        })
        .unwrap();

    let CoordinatorResponse::NodeDescriptors { descriptors, actor } = service
        .handle_request(CoordinatorRequest::ListNodeDescriptors {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "operator".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected node descriptor inspector state");
    };
    assert_eq!(actor, UserId::from("operator"));
    assert_eq!(descriptors.len(), 2);
    let warm = descriptors
        .iter()
        .find(|descriptor| descriptor.id == NodeId::from("warm-node"))
        .expect("warm node descriptor is visible to inspector state");
    assert!(warm
        .capabilities
        .capabilities
        .contains(&Capability::Command));
    assert!(warm.cached_environments.contains(&Digest::sha256("env")));
    assert!(warm.dependency_caches.contains(&Digest::sha256("deps")));
    assert!(warm.source_snapshots.contains(&Digest::sha256("source")));
    assert!(warm
        .artifact_locations
        .contains(&ArtifactId::from("build-output")));

    let CoordinatorResponse::TaskPlacement { placement } = service
        .handle_request(CoordinatorRequest::ScheduleTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            environment: Some(EnvironmentRequirements::linux_container()),
            environment_digest: Some(Digest::sha256("env")),
            required_capabilities: vec![Capability::Command],
            dependency_cache: Some(Digest::sha256("deps")),
            source_snapshot: Some(Digest::sha256("source")),
            required_artifacts: vec!["build-output".to_owned()],
            prefer_node: None,
        })
        .unwrap()
    else {
        panic!("expected task placement");
    };
    assert_eq!(placement.node, NodeId::from("warm-node"));
    assert!(placement
        .reasons
        .iter()
        .any(|reason| reason.contains("environment")));
    assert!(placement
        .reasons
        .iter()
        .any(|reason| reason.contains("source")));
    assert!(placement
        .reasons
        .iter()
        .any(|reason| reason.contains("dependency")));
    assert!(placement
        .reasons
        .iter()
        .any(|reason| reason.contains("artifact")));

    let error = service
        .handle_request(CoordinatorRequest::ScheduleTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            environment: None,
            environment_digest: None,
            required_capabilities: vec![Capability::WindowsCommandDev],
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: Vec::new(),
            prefer_node: None,
        })
        .unwrap_err();
    assert!(error.to_string().contains("WindowsCommandDev"));

    service.quota.set_workflow_limits(ResourceLimits {
        limits: BTreeMap::from([(LimitKind::Spawn, 0)]),
    });
    let quota_error = service
        .handle_request(CoordinatorRequest::ScheduleTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            environment: None,
            environment_digest: None,
            required_capabilities: vec![Capability::Command],
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: Vec::new(),
            prefer_node: None,
        })
        .unwrap_err();
    assert!(quota_error
        .to_string()
        .contains("quota unavailable for placement"));

    service.quota.set_workflow_limits(ResourceLimits {
        limits: BTreeMap::from([(LimitKind::Spawn, 10)]),
    });
    service.admission.workflow_placement_allowed = false;
    let policy_error = service
        .handle_request(CoordinatorRequest::ScheduleTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            environment: None,
            environment_digest: None,
            required_capabilities: vec![Capability::Command],
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: Vec::new(),
            prefer_node: None,
        })
        .unwrap_err();
    assert!(policy_error.to_string().contains("policy denied placement"));
}

#[test]
fn coordinator_side_task_launch_queues_worker_assignment() {
    let mut service = CoordinatorService::new(9);
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
            cached_environment_digests: vec![Digest::sha256("env")],
            dependency_cache_digests: vec![Digest::sha256("deps")],
            source_snapshots: vec![Digest::sha256("source")],
            artifact_locations: vec!["bootstrap-artifact".to_owned()],
            online: true,
        })
        .unwrap();
    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        epoch,
        ..
    } = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-control".to_owned(),
            restart: false,
        })
        .unwrap()
    else {
        panic!("expected coordinator-side process start");
    };
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker-linux".to_owned(),
            process: "vp-control".to_owned(),
            epoch,
        })
        .unwrap();
    service.artifact_registry.flush_metadata(ArtifactFlush {
        id: ArtifactId::from("bootstrap-artifact"),
        tenant: TenantId::from("tenant"),
        project: ProjectId::from("project"),
        process: ProcessId::from("vp-control"),
        producer_task: TaskInstanceId::from("bootstrap"),
        retaining_node: NodeId::from("worker-linux"),
        digest: Digest::sha256("bootstrap"),
        size: 9,
    });

    let submitted_task_spec = TaskSpec {
        tenant: TenantId::from("tenant"),
        project: ProjectId::from("project"),
        process: ProcessId::from("vp-control"),
        task_definition: clusterflux_core::TaskDefinitionId::from("compile-linux"),
        task_instance: clusterflux_core::TaskInstanceId::from("compile-linux-1"),
        dispatch: TaskDispatch::CoordinatorNodeWasm {
            export: Some("compile-linux".to_owned()),
            abi: WasmExportAbi::TaskV1,
        },
        environment_id: Some("linux".to_owned()),
        environment: None,
        environment_digest: Some(Digest::sha256("env")),
        required_capabilities: BTreeSet::from([Capability::Command]),
        dependency_cache: Some(Digest::sha256("deps")),
        source_snapshot: Some(Digest::sha256("source")),
        source_revision: None,
        required_artifacts: vec![ArtifactId::from("bootstrap-artifact")],
        args: vec![
            TaskBoundaryValue::SmallJson(serde_json::json!("test")),
            TaskBoundaryValue::SourceSnapshot(Digest::sha256("source")),
            TaskBoundaryValue::Artifact(ArtifactHandle {
                id: ArtifactId::from("bootstrap-artifact"),
                digest: Digest::sha256("bootstrap"),
                size_bytes: 9,
            }),
        ],
        requested_secrets: Vec::new(),
        vfs_epoch: epoch,
        failure_policy: Default::default(),
        bundle_digest: Some(Digest::sha256(TEST_WASM_MODULE)),
    };

    let CoordinatorResponse::TaskLaunched {
        process,
        task,
        placement,
        assignment,
        ..
    } = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: submitted_task_spec.clone(),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/dap-output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap()
    else {
        panic!("expected launched task");
    };
    assert_eq!(process, ProcessId::from("vp-control"));
    assert_eq!(task, TaskInstanceId::from("compile-linux-1"));
    assert_eq!(placement.node, NodeId::from("worker-linux"));
    assert!(placement
        .reasons
        .iter()
        .any(|reason| reason.contains("environment")));
    assert!(placement
        .reasons
        .iter()
        .any(|reason| reason.contains("source")));
    assert_eq!(assignment.node, NodeId::from("worker-linux"));
    assert_eq!(assignment.epoch, epoch);
    assert_eq!(
        assignment.task_spec.bundle_digest,
        Some(Digest::sha256(TEST_WASM_MODULE))
    );
    assert!(assignment.task_spec.product_mode_uses_remote_dispatch());
    assert_eq!(assignment.task_spec, submitted_task_spec);
    assert_eq!(
        assignment.task_spec.environment_id.as_deref(),
        Some("linux")
    );
    assert!(matches!(
        assignment.task_spec.dispatch,
        TaskDispatch::CoordinatorNodeWasm {
            export: Some(ref export),
            abi: WasmExportAbi::TaskV1,
        } if export == "compile-linux"
    ));
    assert_eq!(assignment.task_spec.vfs_epoch, epoch);
    assert_eq!(assignment.task_spec.args, submitted_task_spec.args);

    let assignment =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "worker-linux");
    let assignment = assignment.expect("worker should receive queued assignment");
    assert_eq!(assignment.process, ProcessId::from("vp-control"));
    assert_eq!(assignment.task, TaskInstanceId::from("compile-linux-1"));
    assert!(assignment.task_spec.product_mode_uses_remote_dispatch());
    assert_eq!(
        assignment.task_spec.bundle_digest,
        Some(Digest::sha256(TEST_WASM_MODULE))
    );
    assert_eq!(assignment.wasm_module_base64, test_wasm_module_base64());

    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp-control".to_owned(),
            task: "compile-linux-1".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected pending join result");
    };
    assert_eq!(join.state, TaskJoinState::Pending);
    assert!(!join.remote_completion_observed);

    let assignment =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "worker-linux");
    assert!(assignment.is_none());

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp-control".to_owned(),
            node: "worker-linux".to_owned(),
            task: "compile-linux-1".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 12,
            stderr_bytes: 0,
            stdout_tail: "ok".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: Some("/vfs/artifacts/dap-output.txt".to_owned()),
            artifact_digest: Some(Digest::sha256("artifact")),
            artifact_size_bytes: Some(12),
            result: Some(TaskBoundaryValue::Artifact(ArtifactHandle {
                id: ArtifactId::from("dap-output.txt"),
                digest: Digest::sha256("artifact"),
                size_bytes: 12,
            })),
        })
        .unwrap();
    let CoordinatorResponse::TaskEvents { events } = service
        .handle_request(CoordinatorRequest::ListTaskEvents {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: Some("vp-control".to_owned()),
        })
        .unwrap()
    else {
        panic!("expected task events");
    };
    let event_placement = events[0]
        .placement
        .as_ref()
        .expect("task event should retain launch placement explanation");
    assert_eq!(event_placement.node, NodeId::from("worker-linux"));
    assert_eq!(event_placement.reasons, placement.reasons);
    assert_eq!(
        events[0].result,
        Some(TaskBoundaryValue::Artifact(ArtifactHandle {
            id: ArtifactId::from("dap-output.txt"),
            digest: Digest::sha256("artifact"),
            size_bytes: 12,
        }))
    );

    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp-control".to_owned(),
            task: "compile-linux-1".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected completed join result");
    };
    assert_eq!(join.state, TaskJoinState::Completed);
    assert!(join.remote_completion_observed);
    assert_eq!(
        join.result,
        Some(TaskBoundaryValue::Artifact(ArtifactHandle {
            id: ArtifactId::from("dap-output.txt"),
            digest: Digest::sha256("artifact"),
            size_bytes: 12,
        }))
    );

    register_test_task_assignment(
        &mut service,
        "tenant",
        "project",
        "vp-control",
        "worker-linux",
        "wasm-add",
        "wasm-add",
        epoch,
    );
    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp-control".to_owned(),
            node: "worker-linux".to_owned(),
            task: "wasm-add".to_owned(),
            terminal_state: Some(TaskTerminalState::Completed),
            status_code: Some(0),
            stdout_bytes: 3,
            stderr_bytes: 0,
            stdout_tail: "42\n".to_owned(),
            stderr_tail: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: Some(TaskBoundaryValue::SmallJson(serde_json::json!(42))),
        })
        .unwrap();
    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp-control".to_owned(),
            task: "wasm-add".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected serialized join result");
    };
    assert_eq!(
        join.result,
        Some(TaskBoundaryValue::SmallJson(serde_json::json!(42)))
    );
}

#[test]
fn same_definition_instances_join_correctly_when_they_complete_in_reverse_order() {
    let mut service = CoordinatorService::new(41);
    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant".to_owned(),
            actor_user: "user".to_owned(),
            project: "project".to_owned(),
            name: "Duplicate instances".to_owned(),
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
            cached_environment_digests: Vec::new(),
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
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker".to_owned(),
            process: "vp".to_owned(),
            epoch: 41,
        })
        .unwrap();

    let restart_compatibility = Digest::sha256("compile-u32-to-u32-abi-v1");
    let (initial_module, initial_bundle_digest) =
        test_edited_task_bundle(&restart_compatibility, "initial-body");
    for (instance, argument) in [("compile-1", 1), ("compile-2", 2)] {
        let mut spec =
            test_task_spec_instance("tenant", "project", "vp", "compile", instance, 41, []);
        spec.args = vec![TaskBoundaryValue::SmallJson(serde_json::json!(argument))];
        spec.dispatch = TaskDispatch::CoordinatorNodeWasm {
            export: Some("compile_export".to_owned()),
            abi: WasmExportAbi::TaskV1,
        };
        spec.bundle_digest = Some(initial_bundle_digest.clone());
        let CoordinatorResponse::TaskLaunched {
            task, assignment, ..
        } = service
            .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: Some("user".to_owned()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                task_spec: spec,
                wait_for_node: false,
                artifact_path: format!("/vfs/artifacts/{instance}.json"),
                wasm_module_base64: initial_module.clone(),
            })
            .unwrap()
        else {
            panic!("expected launched task instance");
        };
        assert_eq!(task, TaskInstanceId::from(instance));
        assert_eq!(
            assignment.task_spec.task_definition,
            clusterflux_core::TaskDefinitionId::from("compile")
        );
        assert_eq!(
            assignment.task_spec.task_instance,
            clusterflux_core::TaskInstanceId::from(instance)
        );
    }
    for instance in ["compile-1", "compile-2"] {
        let Some(assignment) =
            poll_process_assignment_for_test(&mut service, "tenant", "project", "worker")
        else {
            panic!("expected queued task assignment");
        };
        assert_eq!(assignment.task, TaskInstanceId::from(instance));
    }

    service
        .handle_request(CoordinatorRequest::CancelTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp".to_owned(),
            node: "worker".to_owned(),
            task: "compile-1".to_owned(),
        })
        .unwrap();
    for (instance, expected_cancelled) in [("compile-1", true), ("compile-2", false)] {
        let CoordinatorResponse::TaskControl {
            cancel_requested,
            abort_requested,
            ..
        } = service
            .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                process: "vp".to_owned(),
                node: "worker".to_owned(),
                task: instance.to_owned(),
                child_tasks: Vec::new(),
            })
            .unwrap()
        else {
            panic!("expected task control response");
        };
        assert_eq!(cancel_requested, expected_cancelled);
        assert!(!abort_requested);
    }

    for (instance, result) in [("compile-2", 22), ("compile-1", 11)] {
        service
            .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                process: "vp".to_owned(),
                node: "worker".to_owned(),
                task: instance.to_owned(),
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
                result: Some(TaskBoundaryValue::SmallJson(serde_json::json!(result))),
            })
            .unwrap();
    }

    for (instance, expected) in [("compile-1", 11), ("compile-2", 22)] {
        let CoordinatorResponse::TaskJoined { join } = service
            .handle_request(CoordinatorRequest::JoinTask {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                actor_user: "user".to_owned(),
                process: "vp".to_owned(),
                task: instance.to_owned(),
            })
            .unwrap()
        else {
            panic!("expected task join");
        };
        assert_eq!(
            join.task_instance,
            clusterflux_core::TaskInstanceId::from(instance)
        );
        assert_eq!(
            join.result,
            Some(TaskBoundaryValue::SmallJson(serde_json::json!(expected)))
        );
    }

    let duplicate = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            task_spec: test_task_spec_instance(
                "tenant",
                "project",
                "vp",
                "compile",
                "compile-1",
                41,
                [],
            ),
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/duplicate.json".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap_err();
    assert!(duplicate.to_string().contains("fresh task-instance id"));

    let (replacement_module, replacement_bundle_digest) =
        test_edited_task_bundle(&restart_compatibility, "edited-body");
    assert_ne!(replacement_bundle_digest, initial_bundle_digest);
    let CoordinatorResponse::TaskRestart {
        accepted,
        restarted_task_instance,
        restarted_attempt_id,
        ..
    } = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp".to_owned(),
            task: "compile-1".to_owned(),
            replacement_bundle: Some(TaskReplacementBundle {
                bundle_digest: replacement_bundle_digest.clone(),
                wasm_module_base64: replacement_module.clone(),
                source_snapshot: None,
            }),
        })
        .unwrap()
    else {
        panic!("expected task restart response");
    };
    assert!(accepted);
    let restarted = restarted_task_instance.expect("restart returns the logical instance");
    let restarted_attempt_id = restarted_attempt_id.expect("restart creates a new attempt");
    assert!(restarted_attempt_id.starts_with("ta_"));
    assert_eq!(restarted, TaskInstanceId::from("compile-1"));
    assert_ne!(restarted, TaskInstanceId::from("compile-2"));
    let Some(restarted_assignment) =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "worker")
    else {
        panic!("expected restarted assignment");
    };
    assert_eq!(restarted_assignment.task, restarted);
    assert_eq!(
        restarted_assignment.task_spec.task_definition,
        clusterflux_core::TaskDefinitionId::from("compile")
    );
    assert_eq!(
        restarted_assignment.task_spec.args,
        vec![TaskBoundaryValue::SmallJson(serde_json::json!(1))]
    );
    assert_eq!(
        restarted_assignment.task_spec.bundle_digest,
        Some(replacement_bundle_digest)
    );
    assert_eq!(
        restarted_assignment.task_spec.dispatch,
        TaskDispatch::CoordinatorNodeWasm {
            export: Some("compile_export".to_owned()),
            abi: WasmExportAbi::TaskV1,
        }
    );
    assert_eq!(restarted_assignment.wasm_module_base64, replacement_module);

    let CoordinatorResponse::TaskSnapshots { snapshots } = service
        .handle_request(CoordinatorRequest::ListTaskSnapshots {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected task snapshots after restart");
    };
    let compile_one_attempts = snapshots
        .iter()
        .filter(|snapshot| snapshot.task == TaskInstanceId::from("compile-1"))
        .collect::<Vec<_>>();
    assert_eq!(compile_one_attempts.len(), 2);
    assert_eq!(compile_one_attempts[0].attempt_number, 2);
    assert!(compile_one_attempts[0].current);
    assert_eq!(compile_one_attempts[1].attempt_number, 1);
    assert!(!compile_one_attempts[1].current);

    let incompatible_compatibility = Digest::sha256("compile-changed-signature");
    let (incompatible_module, incompatible_bundle_digest) =
        test_edited_task_bundle(&incompatible_compatibility, "incompatible-body");
    let CoordinatorResponse::TaskRestart {
        accepted,
        requires_whole_process_restart,
        restarted_task_instance,
        message,
        ..
    } = service
        .handle_request(CoordinatorRequest::RestartTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp".to_owned(),
            task: "compile-2".to_owned(),
            replacement_bundle: Some(TaskReplacementBundle {
                bundle_digest: incompatible_bundle_digest,
                wasm_module_base64: incompatible_module,
                source_snapshot: None,
            }),
        })
        .unwrap()
    else {
        panic!("expected incompatible task restart response");
    };
    assert!(!accepted);
    assert!(requires_whole_process_restart);
    assert!(restarted_task_instance.is_none());
    assert!(message.contains("task ABI changed"));

    let CoordinatorResponse::TaskJoined { join } = service
        .handle_request(CoordinatorRequest::JoinTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp".to_owned(),
            task: "compile-2".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected unaffected sibling join");
    };
    assert_eq!(join.state, TaskJoinState::Completed);
    assert_eq!(
        join.result,
        Some(TaskBoundaryValue::SmallJson(serde_json::json!(22)))
    );
}

#[test]
fn long_lived_process_state_reaches_a_scoped_bounded_steady_state() {
    let mut service = CoordinatorService::new(73);
    service
        .handle_request(CoordinatorRequest::CreateProject {
            tenant: "tenant-soak".to_owned(),
            actor_user: "user-soak".to_owned(),
            project: "project-soak".to_owned(),
            name: "Bounded soak".to_owned(),
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant-soak".to_owned(),
            project: "project-soak".to_owned(),
            node: "worker-soak".to_owned(),
            public_key: test_node_public_key("worker-soak"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant-soak".to_owned(),
            project: "project-soak".to_owned(),
            node: "worker-soak".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant-soak".to_owned(),
            project: "project-soak".to_owned(),
            actor_user: Some("user-soak".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-soak".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant-soak".to_owned(),
            project: "project-soak".to_owned(),
            node: "worker-soak".to_owned(),
            process: "vp-soak".to_owned(),
            epoch: 73,
        })
        .unwrap();

    let event_waves = 4;
    for index in 0..super::MAX_TASK_EVENTS_PER_PROCESS * event_waves {
        let task = format!("soak-task-{index}");
        register_test_task_assignment(
            &mut service,
            "tenant-soak",
            "project-soak",
            "vp-soak",
            "worker-soak",
            "soak-task",
            &task,
            73,
        );
        service
            .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
                tenant: "tenant-soak".to_owned(),
                project: "project-soak".to_owned(),
                process: "vp-soak".to_owned(),
                node: "worker-soak".to_owned(),
                task,
                terminal_state: Some(TaskTerminalState::Completed),
                status_code: Some(0),
                stdout_bytes: 8,
                stderr_bytes: 0,
                stdout_tail: "soak-log".to_owned(),
                stderr_tail: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                artifact_path: None,
                artifact_digest: None,
                artifact_size_bytes: None,
                result: Some(TaskBoundaryValue::SmallJson(json!(index))),
            })
            .unwrap();
    }
    for index in 0..super::MAX_DEBUG_AUDIT_EVENTS_PER_PROCESS * 3 {
        service
            .record_debug_audit_event(
                TenantId::from("tenant-soak"),
                ProjectId::from("project-soak"),
                ProcessId::from("vp-soak"),
                None,
                UserId::from("user-soak"),
                "soak_inspect",
                true,
                format!("bounded audit {index}"),
            )
            .unwrap();
    }
    for _ in 0..128 {
        let _ = poll_process_assignment_for_test(
            &mut service,
            "tenant-soak",
            "project-soak",
            "worker-soak",
        );
    }

    for index in 0..2_000 {
        service.replay_registry.seed_node(
            crate::NodeScopeKey::new(
                TenantId::from("tenant-soak"),
                ProjectId::from("project-soak"),
                NodeId::from("worker-soak"),
            ),
            format!("expired-{index}"),
            0,
        );
    }
    service
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-soak".to_owned(),
            project: "project-soak".to_owned(),
            node: "worker-soak".to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope(
                "tenant-soak",
                "project-soak",
                "worker-soak",
                "post-expiry-prune",
            )),
        })
        .unwrap();

    for index in 0..3 {
        service.record_task_completion_event(TaskCompletionEvent {
            tenant: TenantId::from("tenant-other"),
            project: ProjectId::from("project-other"),
            process: ProcessId::from("vp-other"),
            node: NodeId::from("worker-other"),
            executor: TaskExecutor::Node,
            task_definition: clusterflux_core::TaskDefinitionId::from("other"),
            task: TaskInstanceId::new(format!("other-{index}")),
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

    let retained_soak_events = service
        .task_registry
        .events()
        .filter(|event| event.process == ProcessId::from("vp-soak"))
        .count();
    let retained_other_events = service
        .task_registry
        .events()
        .filter(|event| event.process == ProcessId::from("vp-other"))
        .count();
    let retained_soak_audit = service
        .debug_registry
        .audit_events()
        .filter(|event| event.process == ProcessId::from("vp-soak"))
        .count();
    let retained_soak_checkpoints = service
        .task_registry
        .checkpoint_count_for_process(&ProcessId::from("vp-soak"));
    let retained_soak_nonces = service
        .replay_registry
        .node_count(&crate::NodeScopeKey::new(
            TenantId::from("tenant-soak"),
            ProjectId::from("project-soak"),
            NodeId::from("worker-soak"),
        ));

    assert_eq!(retained_soak_events, super::MAX_TASK_EVENTS_PER_PROCESS);
    assert_eq!(retained_other_events, 3);
    assert_eq!(
        retained_soak_audit,
        super::MAX_DEBUG_AUDIT_EVENTS_PER_PROCESS
    );
    assert_eq!(
        retained_soak_checkpoints,
        super::MAX_RESTART_CHECKPOINTS_PER_PROCESS
    );
    assert!(retained_soak_nonces <= super::MAX_NODE_REPLAY_NONCES_PER_AUTHORITY);
    assert!(
        super::MAX_NODE_REPLAY_NONCES_PER_AUTHORITY
            >= super::NODE_SIGNATURE_WINDOW_SECONDS as usize * 2 * 1_000
                / clusterflux_core::MIN_SIGNED_NODE_POLL_INTERVAL_MS as usize
                + 64,
        "the bounded node replay window must sustain artifact and assignment polls at the protocol minimum with control-message headroom"
    );
    assert!(service
        .coordinator
        .active_process(
            &TenantId::from("tenant-soak"),
            &ProjectId::from("project-soak"),
            &ProcessId::from("vp-soak"),
        )
        .is_some());
}

#[test]
fn signed_active_wasm_task_can_spawn_and_join_child_in_its_process_only() {
    let mut service = CoordinatorService::new(12);
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
            cached_environment_digests: Vec::new(),
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
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp".to_owned(),
            restart: false,
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "worker".to_owned(),
            process: "vp".to_owned(),
            epoch: 12,
        })
        .unwrap();
    service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            task_spec: test_task_spec("tenant", "project", "vp", "parent", 12, []),
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/parent.json".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap();

    let child_request = CoordinatorRequest::LaunchChildTask {
        tenant: "tenant".to_owned(),
        project: "project".to_owned(),
        process: "vp".to_owned(),
        node: "worker".to_owned(),
        parent_task: "parent".to_owned(),
        task_spec: test_task_spec("tenant", "project", "vp", "child", 12, []),
        wait_for_node: false,
        artifact_path: "/vfs/artifacts/child.json".to_owned(),
        wasm_module_base64: test_wasm_module_base64(),
    };
    let unsigned = service.handle_request(child_request.clone()).unwrap_err();
    assert!(unsigned.to_string().contains("signed_node"));

    let CoordinatorResponse::TaskLaunched { actor, task, .. } = service
        .handle_signed_node_request_auto(child_request)
        .unwrap()
    else {
        panic!("expected signed child launch");
    };
    assert_eq!(task, TaskInstanceId::from("child"));
    assert_eq!(actor.kind, "task");
    assert_eq!(actor.credential_kind, CredentialKind::TaskCredential);
    assert!(actor.scopes.contains(&"process:spawn-child".to_owned()));

    let wrong_parent = service
        .handle_signed_node_request_auto(CoordinatorRequest::JoinChildTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp".to_owned(),
            node: "worker".to_owned(),
            parent_task: "not-active".to_owned(),
            task: "child".to_owned(),
        })
        .unwrap_err();
    assert!(wrong_parent.to_string().contains("assignment authority"));

    let CoordinatorResponse::TaskJoined { join } = service
        .handle_signed_node_request_auto(CoordinatorRequest::JoinChildTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp".to_owned(),
            node: "worker".to_owned(),
            parent_task: "parent".to_owned(),
            task: "child".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected signed child join");
    };
    assert_eq!(join.state, TaskJoinState::Pending);

    let CoordinatorResponse::TaskControl { child_joins, .. } = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp".to_owned(),
            node: "worker".to_owned(),
            task: "parent".to_owned(),
            child_tasks: vec!["child".to_owned()],
        })
        .unwrap()
    else {
        panic!("expected parent task control");
    };
    assert!(child_joins.is_empty());

    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp".to_owned(),
            node: "worker".to_owned(),
            task: "child".to_owned(),
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
            result: Some(TaskBoundaryValue::SmallJson(json!({"ok": true}))),
        })
        .unwrap();
    let CoordinatorResponse::TaskControl { child_joins, .. } = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollTaskControl {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "vp".to_owned(),
            node: "worker".to_owned(),
            task: "parent".to_owned(),
            child_tasks: vec!["child".to_owned()],
        })
        .unwrap()
    else {
        panic!("expected parent task control");
    };
    assert_eq!(child_joins.len(), 1);
    assert_eq!(child_joins[0].state, TaskJoinState::Completed);
}

#[test]
fn queued_named_environment_exposes_cache_miss_until_worker_is_ready() {
    let mut service = CoordinatorService::new(10);
    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "uncached-worker".to_owned(),
            public_key: test_node_public_key("uncached-worker"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "uncached-worker".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        epoch,
        ..
    } = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-environment".to_owned(),
            restart: false,
        })
        .unwrap()
    else {
        panic!("expected process start");
    };
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReconnectNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "uncached-worker".to_owned(),
            process: "vp-environment".to_owned(),
            epoch,
        })
        .unwrap();
    let mut task_spec = test_task_spec(
        "tenant",
        "project",
        "vp-environment",
        "compile-linux",
        epoch,
        [],
    );
    let environment_digest = Digest::sha256("missing-environment");
    task_spec.environment_id = Some("missing-environment".to_owned());
    task_spec.environment_digest = Some(environment_digest.clone());

    let CoordinatorResponse::TaskQueued { reason, .. } = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: true,
            artifact_path: "/vfs/artifacts/environment-output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap()
    else {
        panic!("expected task to wait for its exact environment cache");
    };

    assert!(reason.contains("named environment cache"));
    let CoordinatorResponse::ProcessStatuses { processes, .. } = service
        .handle_request(CoordinatorRequest::ListProcesses {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected process statuses");
    };
    assert_eq!(processes.len(), 1);
    assert_eq!(
        processes[0].main_wait_reason.as_deref(),
        Some(reason.as_str())
    );

    let CoordinatorResponse::TaskSnapshots { snapshots } = service
        .handle_request(CoordinatorRequest::ListTaskSnapshots {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
            process: "vp-environment".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected queued task snapshot");
    };
    assert_eq!(snapshots.len(), 1);
    assert_eq!(
        snapshots[0].waiting_reason.as_deref(),
        Some(reason.as_str())
    );

    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "uncached-worker".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: vec![environment_digest],
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
    let assignment =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "uncached-worker")
            .expect("prepared worker should receive the queued task");
    assert_eq!(assignment.task, TaskInstanceId::from("compile-linux"));

    let CoordinatorResponse::ProcessStatuses { processes, .. } = service
        .handle_request(CoordinatorRequest::ListProcesses {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: "user".to_owned(),
        })
        .unwrap()
    else {
        panic!("expected process statuses");
    };
    assert_eq!(processes[0].main_wait_reason, None);
}

#[test]
fn coordinator_side_task_launch_fails_cleanly_without_capable_worker() {
    let mut service = CoordinatorService::new(10);
    service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-control".to_owned(),
            restart: false,
        })
        .unwrap();

    let error = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "vp-control",
                "compile-linux",
                10,
                [Capability::Command],
            ),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: false,
            artifact_path: "/vfs/artifacts/dap-output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap_err();

    assert!(error.to_string().contains("no capable node"));
}

#[test]
fn coordinator_side_task_launch_can_wait_for_capable_worker() {
    let mut service = CoordinatorService::new(11);
    let CoordinatorResponse::ProcessStarted {
        epoch: other_epoch, ..
    } = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "other-vp-wait".to_owned(),
            restart: false,
        })
        .unwrap()
    else {
        panic!("expected unrelated process start");
    };
    let CoordinatorResponse::TaskQueued {
        queued_tasks: other_queued_tasks,
        ..
    } = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "other-tenant",
                "other-project",
                "other-vp-wait",
                "other-compile",
                other_epoch,
                [Capability::Command],
            ),
            tenant: "other-tenant".to_owned(),
            project: "other-project".to_owned(),
            actor_user: Some("other-user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: true,
            artifact_path: "/vfs/artifacts/other-wait-output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap()
    else {
        panic!("expected unrelated queued task launch");
    };
    assert_eq!(other_queued_tasks, 1);
    let CoordinatorResponse::ProcessStarted {
        launch_attempt: None,
        epoch,
        ..
    } = service
        .handle_request(CoordinatorRequest::StartProcess {
            launch_attempt: None,
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: None,
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            process: "vp-wait".to_owned(),
            restart: false,
        })
        .unwrap()
    else {
        panic!("expected process start");
    };

    let CoordinatorResponse::TaskQueued {
        process,
        task,
        reason,
        queued_tasks,
        charged_spawns,
        ..
    } = service
        .handle_authorized_test_task_launch(CoordinatorRequest::LaunchTask {
            task_spec: test_task_spec(
                "tenant",
                "project",
                "vp-wait",
                "compile-linux",
                epoch,
                [Capability::Command],
            ),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            actor_user: Some("user".to_owned()),
            actor_agent: None,
            agent_public_key_fingerprint: None,
            agent_signature: None,
            wait_for_node: true,
            artifact_path: "/vfs/artifacts/wait-output.txt".to_owned(),
            wasm_module_base64: test_wasm_module_base64(),
        })
        .unwrap()
    else {
        panic!("expected queued task launch");
    };
    assert_eq!(process, ProcessId::from("vp-wait"));
    assert_eq!(task, TaskInstanceId::from("compile-linux"));
    assert!(reason.contains("waiting for any capable node"));
    assert_eq!(queued_tasks, 1);
    assert_eq!(charged_spawns, 2);

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "late-worker".to_owned(),
            public_key: test_node_public_key("late-worker"),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "late-worker".to_owned(),
            capabilities: linux_capabilities(),
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();

    let assignment =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "late-worker");
    let assignment = assignment.expect("late worker should receive pending assignment");
    assert_eq!(assignment.process, ProcessId::from("vp-wait"));
    assert_eq!(assignment.task, TaskInstanceId::from("compile-linux"));
    assert_eq!(assignment.node, NodeId::from("late-worker"));
    assert_eq!(assignment.epoch, epoch);
    assert!(assignment.task_spec.product_mode_uses_remote_dispatch());
    assert_eq!(assignment.wasm_module_base64, test_wasm_module_base64());

    let assignment =
        poll_process_assignment_for_test(&mut service, "tenant", "project", "late-worker");
    assert!(assignment.is_none());
}
