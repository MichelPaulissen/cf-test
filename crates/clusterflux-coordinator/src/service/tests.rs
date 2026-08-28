use std::collections::{BTreeMap, BTreeSet};
use std::io::{BufRead, BufReader, Write};
use std::net::TcpStream;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{
    admin_request_proof, agent_ed25519_public_key_from_private_key,
    derive_ed25519_private_key_from_seed, node_ed25519_public_key_from_private_key,
    sign_agent_workflow_request, sign_node_assignment_operation_request,
    sign_node_assignment_request, sign_node_request, signed_request_payload_digest,
    AgentSignedRequest, AgentWorkflowScope, ArtifactFlush, ArtifactHandle, ArtifactId,
    ArtifactTransferState, AssignmentAuthority, Capability, ClusterfluxPathKind, Digest,
    EnvironmentBackend, EnvironmentRequirements, IrohEndpointAdvertisement, LimitKind,
    NodeAssignmentOperation, NodeCapabilities, NodeSignedRequest, Os, PanelState, ResourceLimits,
    SourceProviderKind, TaskBoundaryValue, TaskDefinitionId, TaskDispatch, TaskInstanceId,
    TaskJoinState, TaskSpec, VfsPath, WasmExportAbi, WasmTaskResult,
};
use clusterflux_protocol::coordinator_wire_request;
use serde_json::json;

use crate::{AssignmentKind, AssignmentState, FallibleDurableStore, TenantQuotaOverrideValues};

use super::keys::{process_control_key, task_control_key};
use super::*;

fn test_admin_request(
    token: &str,
    operation: &str,
    tenant: &str,
    actor_user: &str,
    target_tenant: &str,
    nonce: &str,
) -> (Digest, String, u64) {
    let issued_at_epoch_seconds = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default();
    (
        admin_request_proof(
            token,
            operation,
            tenant,
            actor_user,
            target_tenant,
            nonce,
            issued_at_epoch_seconds,
        ),
        nonce.to_owned(),
        issued_at_epoch_seconds,
    )
}

fn enroll_test_node(
    service: &mut CoordinatorService,
    tenant: &str,
    project: &str,
    node: &str,
    public_key: &str,
) {
    let response = service
        .handle_request(CoordinatorRequest::CreateNodeEnrollmentGrant {
            tenant: tenant.to_owned(),
            project: project.to_owned(),
            actor_user: "test-user".to_owned(),
            ttl_seconds: 900,
        })
        .unwrap();
    let CoordinatorResponse::NodeEnrollmentGrantCreated { grant, .. } = response else {
        panic!("expected node enrollment grant");
    };
    service
        .handle_request(CoordinatorRequest::ExchangeNodeEnrollmentGrant {
            tenant: tenant.to_owned(),
            project: project.to_owned(),
            node: node.to_owned(),
            public_key: public_key.to_owned(),
            enrollment_grant: grant,
        })
        .unwrap();
}

#[test]
fn runtime_service_uses_memory_only_when_database_url_is_absent() {
    let service = CoordinatorService::new_with_database_url(1, None).unwrap();
    assert_eq!(service.durable_store_kind(), "in_memory");

    let error = CoordinatorService::new_with_database_url(1, Some("not-a-postgres-url"))
        .err()
        .expect("an invalid configured DATABASE_URL must fail closed");
    assert!(error
        .to_string()
        .contains("durable coordinator state failed"));
}

#[test]
fn startup_configuration_rejects_zero_or_effectively_unbounded_limits() {
    assert!(CoordinatorServiceStartupConfiguration::default()
        .validate()
        .is_ok());
    assert!(CoordinatorServiceStartupConfiguration {
        node_stale_after_seconds: 0,
    }
    .validate()
    .is_err());
    assert!(CoordinatorServiceStartupConfiguration {
        node_stale_after_seconds: u64::MAX,
    }
    .validate()
    .is_err());

    let mut main = CoordinatorMainRuntimeConfiguration::default();
    assert_eq!(main.max_active_mains, MAX_COORDINATOR_MAINS);
    assert!(main.validate().is_ok());
    main.max_active_mains = MAX_COORDINATOR_MAINS + 1;
    assert!(main.validate().is_err());

    for invalid in [
        CoordinatorMainRuntimeConfiguration {
            nested_join_timeout_ms: u64::MAX,
            ..CoordinatorMainRuntimeConfiguration::default()
        },
        CoordinatorMainRuntimeConfiguration {
            max_wakeups_per_minute: u64::MAX,
            ..CoordinatorMainRuntimeConfiguration::default()
        },
        CoordinatorMainRuntimeConfiguration {
            max_output_bytes: usize::MAX,
            ..CoordinatorMainRuntimeConfiguration::default()
        },
        CoordinatorMainRuntimeConfiguration {
            max_state_bytes: usize::MAX,
            ..CoordinatorMainRuntimeConfiguration::default()
        },
    ] {
        assert!(invalid.validate().is_err());
    }
}

#[test]
fn postgres_persists_duplicate_scoped_node_ids_and_credentials_across_restart() {
    let Ok(database_url) = std::env::var("CLUSTERFLUX_TEST_POSTGRES_SERVICE") else {
        return;
    };
    let mut clean_store = crate::PostgresDurableStore::connect(&database_url).unwrap();
    clean_store
        .save_state(&crate::DurableState::default())
        .unwrap();

    let session_secret = "postgres-runtime-service-session";
    let mut first = CoordinatorService::new_with_database_url(41, Some(&database_url)).unwrap();
    assert_eq!(first.durable_store_kind(), "postgres");
    first
        .issue_cli_session(
            TenantId::from("tenant-pg"),
            ProjectId::from("project-pg"),
            UserId::from("user-pg"),
            session_secret,
            None,
        )
        .unwrap();
    enroll_test_node(
        &mut first,
        "tenant-pg",
        "project-pg",
        "node-pg",
        &test_node_public_key("node-pg"),
    );
    let duplicate_private_key = test_node_private_key("node-pg-other-scope");
    enroll_test_node(
        &mut first,
        "tenant-pg-other",
        "project-pg-other",
        "node-pg",
        &node_ed25519_public_key_from_private_key(&duplicate_private_key).unwrap(),
    );
    first
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: session_secret.to_owned(),
            request: AuthenticatedCoordinatorRequest::StartProcess {
                launch_attempt: None,
                process: "process-ephemeral".to_owned(),
                restart: false,
            },
        })
        .unwrap();
    drop(first);

    let mut restarted = CoordinatorService::new_with_database_url(42, Some(&database_url)).unwrap();
    assert_eq!(restarted.durable_store_kind(), "postgres");
    let auth = restarted
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: session_secret.to_owned(),
            request: AuthenticatedCoordinatorRequest::AuthStatus,
        })
        .unwrap();
    assert!(matches!(
        auth,
        CoordinatorResponse::AuthStatus {
            authenticated: true,
            ..
        }
    ));
    let heartbeat = restarted
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-pg".to_owned(),
            project: "project-pg".to_owned(),
            node: "node-pg".to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope(
                "tenant-pg",
                "project-pg",
                "node-pg",
                "postgres-restart-heartbeat",
            )),
        })
        .unwrap();
    assert!(matches!(
        heartbeat,
        CoordinatorResponse::NodeHeartbeat { epoch: 42, .. }
    ));
    let duplicate_heartbeat = restarted
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-pg-other".to_owned(),
            project: "project-pg-other".to_owned(),
            node: "node-pg".to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope_with_private_key(
                "tenant-pg-other",
                "project-pg-other",
                "node-pg",
                &duplicate_private_key,
                "postgres-restart-heartbeat",
            )),
        })
        .unwrap();
    assert!(matches!(
        duplicate_heartbeat,
        CoordinatorResponse::NodeHeartbeat { epoch: 42, .. }
    ));
    let CoordinatorResponse::ProcessStatuses { processes, .. } = restarted
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: session_secret.to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProcesses,
        })
        .unwrap()
    else {
        panic!("expected process list");
    };
    assert!(processes.is_empty());

    restarted
        .handle_request(CoordinatorRequest::RevokeNodeCredential {
            tenant: "tenant-pg".to_owned(),
            project: "project-pg".to_owned(),
            actor_user: "user-pg".to_owned(),
            node: "node-pg".to_owned(),
        })
        .unwrap();
    drop(restarted);

    let mut after_revocation =
        CoordinatorService::new_with_database_url(43, Some(&database_url)).unwrap();
    assert!(after_revocation
        .coordinator
        .node_identity(
            &TenantId::from("tenant-pg"),
            &ProjectId::from("project-pg"),
            &NodeId::from("node-pg"),
        )
        .is_none());
    assert!(after_revocation
        .coordinator
        .node_identity(
            &TenantId::from("tenant-pg-other"),
            &ProjectId::from("project-pg-other"),
            &NodeId::from("node-pg"),
        )
        .is_some());
    after_revocation
        .handle_request(CoordinatorRequest::NodeHeartbeat {
            tenant: "tenant-pg-other".to_owned(),
            project: "project-pg-other".to_owned(),
            node: "node-pg".to_owned(),
            node_signature: Some(signed_node_heartbeat_in_scope_with_private_key(
                "tenant-pg-other",
                "project-pg-other",
                "node-pg",
                &duplicate_private_key,
                "post-revocation-restart",
            )),
        })
        .expect("the duplicate node in the other scope must remain authenticated");
}

fn linux_capabilities() -> NodeCapabilities {
    NodeCapabilities {
        os: Os::Linux,
        arch: "x86_64".to_owned(),
        capabilities: BTreeSet::from([
            Capability::Command,
            Capability::Containers,
            Capability::RootlessPodman,
            Capability::VfsArtifacts,
        ]),
        environment_backends: BTreeSet::from([EnvironmentBackend::Container]),
        source_providers: BTreeSet::from(["filesystem".to_owned()]),
        work_policy: clusterflux_core::NodeWorkPolicy::Normal,
        system_bundles: Vec::new(),
    }
}

fn windows_capabilities() -> NodeCapabilities {
    NodeCapabilities {
        os: Os::Windows,
        arch: "x86_64".to_owned(),
        capabilities: BTreeSet::from([
            Capability::Command,
            Capability::WindowsCommandDev,
            Capability::VfsArtifacts,
        ]),
        environment_backends: BTreeSet::from([EnvironmentBackend::WindowsCommandDev]),
        source_providers: BTreeSet::from(["filesystem".to_owned()]),
        work_policy: clusterflux_core::NodeWorkPolicy::Normal,
        system_bundles: Vec::new(),
    }
}

fn assert_agent_workflow_actor(actor: &WorkflowActor, fingerprint: &Digest) {
    assert_eq!(actor.kind, "agent");
    assert_eq!(actor.user, Some(UserId::from("user")));
    assert_eq!(actor.agent, Some(AgentId::from("agent-ci")));
    assert_eq!(actor.credential_kind, CredentialKind::PublicKey);
    assert_eq!(actor.public_key_fingerprint.as_ref(), Some(fingerprint));
    assert!(actor.authenticated_without_browser);
    assert!(actor.scopes.iter().any(|scope| scope == "project:run"));
}

const TEST_AGENT_PRIVATE_KEY: &str = "ed25519:BwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwcHBwc=";
static TEST_NODE_REQUEST_NONCE: AtomicU64 = AtomicU64::new(1);
const TEST_WASM_MODULE: &[u8] = b"clusterflux-test-wasm-module";

fn test_wasm_module_base64() -> String {
    BASE64_STANDARD.encode(TEST_WASM_MODULE)
}

fn append_test_custom_section(module: &mut Vec<u8>, name: &str, data: &[u8]) {
    fn leb(mut value: usize, output: &mut Vec<u8>) {
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            output.push(byte);
            if value == 0 {
                break;
            }
        }
    }

    let mut payload = Vec::new();
    leb(name.len(), &mut payload);
    payload.extend_from_slice(name.as_bytes());
    payload.extend_from_slice(data);
    module.push(0);
    leb(payload.len(), module);
    module.extend_from_slice(&payload);
}

fn test_edited_task_bundle(compatibility: &Digest, edit_marker: &str) -> (String, Digest) {
    let descriptor = serde_json::to_vec(&serde_json::json!({
        "kind": "task",
        "name": "compile",
        "function": "compile",
        "export": "compile_export",
        "stable_id": Digest::sha256("compile-stable"),
        "argument_schema": "u32",
        "result_schema": "u32",
        "required_capabilities": [],
        "restart_compatibility_hash": compatibility,
        "abi_version": clusterflux_core::WASM_TASK_ABI_VERSION,
        "probe_symbol": "clusterflux.probe.compile",
    }))
    .unwrap();
    let mut module = b"\0asm\x01\0\0\0".to_vec();
    append_test_custom_section(&mut module, "clusterflux.tasks", &descriptor);
    append_test_custom_section(&mut module, "clusterflux.edit", edit_marker.as_bytes());
    let digest = Digest::sha256(&module);
    (BASE64_STANDARD.encode(module), digest)
}

fn test_task_spec(
    tenant: &str,
    project: &str,
    process: &str,
    task: &str,
    epoch: u64,
    required_capabilities: impl IntoIterator<Item = Capability>,
) -> TaskSpec {
    test_task_spec_instance(
        tenant,
        project,
        process,
        task,
        task,
        epoch,
        required_capabilities,
    )
}

fn test_task_spec_instance(
    tenant: &str,
    project: &str,
    process: &str,
    task_definition: &str,
    task_instance: &str,
    epoch: u64,
    required_capabilities: impl IntoIterator<Item = Capability>,
) -> TaskSpec {
    TaskSpec {
        tenant: TenantId::from(tenant),
        project: ProjectId::from(project),
        process: ProcessId::from(process),
        task_definition: clusterflux_core::TaskDefinitionId::from(task_definition),
        task_instance: clusterflux_core::TaskInstanceId::from(task_instance),
        dispatch: TaskDispatch::CoordinatorNodeWasm {
            export: Some(task_definition.to_owned()),
            abi: WasmExportAbi::TaskV1,
        },
        environment_id: None,
        environment: None,
        environment_digest: None,
        required_capabilities: required_capabilities.into_iter().collect(),
        dependency_cache: None,
        source_snapshot: None,
        source_revision: None,
        required_artifacts: Vec::new(),
        args: Vec::new(),
        requested_secrets: Vec::new(),
        vfs_epoch: epoch,
        failure_policy: Default::default(),
        bundle_digest: Some(Digest::sha256(TEST_WASM_MODULE)),
    }
}

trait AuthorizedTestTaskLaunch {
    fn handle_authorized_test_task_launch(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError>;
}

impl AuthorizedTestTaskLaunch for CoordinatorService {
    fn handle_authorized_test_task_launch(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let CoordinatorRequest::LaunchTask {
            task_spec,
            wait_for_node,
            artifact_path,
            wasm_module_base64,
            ..
        } = request
        else {
            panic!("authorized test task launch requires LaunchTask");
        };
        let tenant = task_spec.tenant.clone();
        let project = task_spec.project.clone();
        self.handle_launch_task_with_actor(
            tenant,
            project,
            WorkflowActor {
                kind: "task".to_owned(),
                user: None,
                agent: None,
                credential_kind: CredentialKind::TaskCredential,
                public_key_fingerprint: None,
                authenticated_without_browser: true,
                scopes: vec!["process:spawn-child".to_owned()],
            },
            task_spec,
            wait_for_node,
            artifact_path,
            wasm_module_base64,
        )
    }
}

fn register_test_task_assignment(
    service: &mut CoordinatorService,
    tenant: &str,
    project: &str,
    process: &str,
    node: &str,
    task_definition: &str,
    task_instance: &str,
    epoch: u64,
) {
    let task_spec = test_task_spec_instance(
        tenant,
        project,
        process,
        task_definition,
        task_instance,
        epoch,
        [],
    );
    let attempt_id = service
        .begin_task_attempt(
            &task_spec,
            Some(NodeId::from(node)),
            Some(&format!("/vfs/artifacts/{task_instance}.bin")),
            false,
        )
        .unwrap();
    let assignment = TaskAssignment {
        assignment_id: format!("assignment-{process}-{task_instance}"),
        attempt_id: attempt_id.clone(),
        offer_epoch: 1,
        offer_expires_at_epoch_seconds: u64::MAX,
        tenant: TenantId::from(tenant),
        project: ProjectId::from(project),
        process: ProcessId::from(process),
        task: TaskInstanceId::from(task_instance),
        node: NodeId::from(node),
        epoch,
        artifact_path: format!("/vfs/artifacts/{task_instance}.bin"),
        task_spec,
        wasm_module_base64: test_wasm_module_base64(),
    };
    service
        .capture_task_restart_checkpoint(&assignment)
        .unwrap();
    service
        .coordinator
        .durable_state_mut()
        .active_assignments
        .insert(
            assignment.assignment_id.clone(),
            crate::ActiveAssignmentRecord {
                assignment_id: assignment.assignment_id.clone(),
                kind: AssignmentKind::ProcessTask {
                    process: assignment.process.clone(),
                    task: assignment.task.clone(),
                },
                tenant: assignment.tenant.clone(),
                project: assignment.project.clone(),
                node: assignment.node.clone(),
                attempt_id,
                offer_epoch: assignment.offer_epoch,
                state: AssignmentState::Acknowledged,
                offered_at: 0,
                acknowledged_at: Some(0),
                lease_expires_at: u64::MAX,
                terminal_mutations: Default::default(),
            },
        );
    service
        .task_registry
        .activate(super::keys::task_control_key(
            &assignment.tenant,
            &assignment.project,
            &assignment.process,
            &assignment.node,
            &assignment.task,
        ));
}

fn service_with_completed_main_and_final_child(
    failure_policy: clusterflux_core::TaskFailurePolicy,
) -> CoordinatorService {
    let mut service = CoordinatorService::new(83);
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let process = ProcessId::from("terminal-matrix");
    let node = NodeId::from("worker");
    let task = TaskInstanceId::from("final-child");

    service
        .handle_request(CoordinatorRequest::AttachNode {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
            public_key: test_node_public_key(node.as_str()),
        })
        .unwrap();
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: tenant.to_string(),
            project: project.to_string(),
            node: node.to_string(),
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
            node: node.to_string(),
            process: process.to_string(),
            epoch: 83,
        })
        .unwrap();

    let mut task_spec = test_task_spec_instance(
        tenant.as_str(),
        project.as_str(),
        process.as_str(),
        "child-definition",
        task.as_str(),
        83,
        [],
    );
    task_spec.failure_policy = failure_policy;
    let mut assignment = TaskAssignment {
        assignment_id: "assignment-terminal-matrix-final-child".to_owned(),
        attempt_id: String::new(),
        offer_epoch: 1,
        offer_expires_at_epoch_seconds: u64::MAX,
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        task: task.clone(),
        node: node.clone(),
        epoch: 83,
        artifact_path: "/vfs/artifacts/final-child.bin".to_owned(),
        task_spec: task_spec.clone(),
        wasm_module_base64: test_wasm_module_base64(),
    };
    let attempt_id = service
        .begin_task_attempt(
            &task_spec,
            Some(node.clone()),
            Some(&assignment.artifact_path),
            false,
        )
        .unwrap();
    assignment.attempt_id = attempt_id.clone();
    service
        .capture_task_restart_checkpoint(&assignment)
        .unwrap();
    service
        .coordinator
        .durable_state_mut()
        .active_assignments
        .insert(
            assignment.assignment_id.clone(),
            crate::ActiveAssignmentRecord {
                assignment_id: assignment.assignment_id.clone(),
                kind: AssignmentKind::ProcessTask {
                    process: assignment.process.clone(),
                    task: assignment.task.clone(),
                },
                tenant: assignment.tenant.clone(),
                project: assignment.project.clone(),
                node: assignment.node.clone(),
                attempt_id,
                offer_epoch: assignment.offer_epoch,
                state: AssignmentState::Acknowledged,
                offered_at: 0,
                acknowledged_at: Some(0),
                lease_expires_at: u64::MAX,
                terminal_mutations: Default::default(),
            },
        );
    service
        .task_registry
        .activate(task_control_key(&tenant, &project, &process, &node, &task));
    service.task_registry.enqueue_assignment(assignment);
    service
        .debug_registry
        .set_epoch(process_control_key(&tenant, &project, &process), 11);
    service.debug_registry.set_breakpoint(
        process_control_key(&tenant, &project, &process),
        super::debug::DebugBreakpointPlan {
            actor: UserId::from("user"),
            revision: 1,
            probe_symbols: BTreeSet::from(["child-probe".to_owned()]),
            probe_locations: BTreeMap::new(),
            hit_epoch: None,
            hit_task: None,
            hit_probe_symbol: None,
        },
    );
    service.debug_registry.queue_command(
        task_control_key(&tenant, &project, &process, &node, &task),
        super::debug::DebugPendingCommand {
            epoch: 11,
            command: "continue".to_owned(),
        },
    );
    let panel_key = super::keys::panel_stop_key(&tenant, &project, &process);
    let panel_now = service.current_epoch_seconds().unwrap();
    service
        .panel_registry
        .store_snapshot(
            panel_key,
            PanelState {
                tenant: tenant.clone(),
                project: project.clone(),
                process: process.clone(),
                widgets: BTreeMap::new(),
                program_ui_events_enabled: false,
                control_plane_actions: Vec::new(),
            },
            true,
            panel_now,
        )
        .unwrap();
    service.record_task_completion_event(TaskCompletionEvent {
        tenant: tenant.clone(),
        project: project.clone(),
        process: process.clone(),
        node: NodeId::from("coordinator-main"),
        executor: TaskExecutor::CoordinatorMain,
        task_definition: TaskDefinitionId::from("build"),
        task: TaskInstanceId::from("main"),
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
        .coordinator
        .grant_project_debug(tenant, project, UserId::from("user"));
    service
}

fn complete_terminal_matrix_child(
    service: &mut CoordinatorService,
    terminal_state: TaskTerminalState,
) {
    service
        .handle_signed_node_request_auto(CoordinatorRequest::TaskCompleted {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            process: "terminal-matrix".to_owned(),
            node: "worker".to_owned(),
            task: "final-child".to_owned(),
            terminal_state: Some(terminal_state),
            status_code: Some(1),
            stdout_bytes: 0,
            stderr_bytes: 4,
            stdout_tail: String::new(),
            stderr_tail: "boom".to_owned(),
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: None,
        })
        .unwrap();
}

fn test_agent_public_key() -> String {
    agent_ed25519_public_key_from_private_key(TEST_AGENT_PRIVATE_KEY).unwrap()
}

fn signed_agent_workflow_request(
    request: &CoordinatorRequest,
    request_kind: &str,
    process: &str,
    task: Option<&str>,
    nonce: &str,
) -> AgentSignedRequest {
    let task = task.map(TaskInstanceId::from);
    let payload = serde_json::to_value(request).unwrap();
    let payload_digest = signed_request_payload_digest(&payload);
    sign_agent_workflow_request(
        TEST_AGENT_PRIVATE_KEY,
        AgentWorkflowScope {
            tenant: &TenantId::from("tenant"),
            project: &ProjectId::from("project"),
            agent: &AgentId::from("agent-ci"),
            request_kind,
            process: &ProcessId::from(process),
            task: task.as_ref(),
        },
        &payload_digest,
        nonce.to_owned(),
        unix_timestamp_seconds_for_tests(),
    )
    .unwrap()
}

fn with_signed_agent_workflow(
    mut request: CoordinatorRequest,
    request_kind: &str,
    process: &str,
    task: Option<&str>,
    nonce: &str,
) -> CoordinatorRequest {
    let signature = signed_agent_workflow_request(&request, request_kind, process, task, nonce);
    match &mut request {
        CoordinatorRequest::StartProcess {
            launch_attempt: None,
            agent_signature,
            ..
        }
        | CoordinatorRequest::LaunchTask {
            agent_signature, ..
        } => *agent_signature = Some(signature),
        _ => panic!("agent signing helper only accepts agent workflow requests"),
    }
    request
}

fn test_node_private_key(node: &str) -> String {
    derive_ed25519_private_key_from_seed(&format!("test-node-key:{node}"))
}

fn test_node_public_key(node: &str) -> String {
    node_ed25519_public_key_from_private_key(&test_node_private_key(node)).unwrap()
}

fn signed_node_heartbeat(node: &str, nonce: &str) -> NodeSignedRequest {
    signed_node_heartbeat_in_scope("tenant", "project", node, nonce)
}

fn signed_node_heartbeat_in_scope(
    tenant: &str,
    project: &str,
    node: &str,
    nonce: &str,
) -> NodeSignedRequest {
    let payload = json!({
        "type": "node_heartbeat",
        "tenant": tenant,
        "project": project,
        "node": node
    });
    signed_node_request_with_private_key(
        node,
        &test_node_private_key(node),
        "node_heartbeat",
        &signed_request_payload_digest(&payload),
        nonce,
    )
}

fn signed_node_heartbeat_with_private_key(
    node: &str,
    private_key: &str,
    nonce: &str,
) -> NodeSignedRequest {
    signed_node_heartbeat_in_scope_with_private_key("tenant", "project", node, private_key, nonce)
}

fn signed_node_heartbeat_in_scope_with_private_key(
    tenant: &str,
    project: &str,
    node: &str,
    private_key: &str,
    nonce: &str,
) -> NodeSignedRequest {
    let payload = json!({
        "type": "node_heartbeat",
        "tenant": tenant,
        "project": project,
        "node": node
    });
    signed_node_request_with_private_key(
        node,
        private_key,
        "node_heartbeat",
        &signed_request_payload_digest(&payload),
        nonce,
    )
}

fn signed_node_request_with_private_key(
    node: &str,
    private_key: &str,
    request_kind: &str,
    payload_digest: &Digest,
    nonce: &str,
) -> NodeSignedRequest {
    sign_node_request(
        private_key,
        &NodeId::from(node),
        request_kind,
        payload_digest,
        nonce.to_owned(),
        unix_timestamp_seconds_for_tests(),
    )
    .unwrap()
}

fn signed_node_request_auto(request: CoordinatorRequest) -> CoordinatorRequest {
    let node = match &request {
        CoordinatorRequest::ReportNodeCapabilities { node, .. }
        | CoordinatorRequest::GetArtifactDataPlanePolicy { node, .. }
        | CoordinatorRequest::PollNodeAssignment { node, .. }
        | CoordinatorRequest::AcknowledgeNodeAssignment { node, .. }
        | CoordinatorRequest::LaunchChildTask { node, .. }
        | CoordinatorRequest::JoinChildTask { node, .. }
        | CoordinatorRequest::CompleteSourcePreparation { node, .. }
        | CoordinatorRequest::ReconnectNode { node, .. }
        | CoordinatorRequest::PollTaskControl { node, .. }
        | CoordinatorRequest::PollDebugCommand { node, .. }
        | CoordinatorRequest::ReportDebugState { node, .. }
        | CoordinatorRequest::ReportDebugProbeHit { node, .. }
        | CoordinatorRequest::ReportTaskLog { node, .. }
        | CoordinatorRequest::ReportTaskLogChunk { node, .. }
        | CoordinatorRequest::ReportVfsMetadata { node, .. }
        | CoordinatorRequest::TaskCompleted { node, .. } => node.clone(),
        _ => panic!("test helper only signs node-originated requests"),
    };
    signed_node_request_auto_with_private_key(request, &test_node_private_key(&node))
}

fn signed_node_request_auto_with_private_key(
    request: CoordinatorRequest,
    private_key: &str,
) -> CoordinatorRequest {
    signed_node_request_auto_with_private_key_and_authority(request, private_key, None)
}

fn signed_node_request_auto_with_private_key_and_authority(
    request: CoordinatorRequest,
    private_key: &str,
    assignment_authority: Option<AssignmentAuthority>,
) -> CoordinatorRequest {
    let payload_digest = signed_request_payload_digest(&serde_json::to_value(&request).unwrap());
    let (node, request_kind) = match &request {
        CoordinatorRequest::ReportNodeCapabilities { node, .. } => {
            (node.clone(), "report_node_capabilities")
        }
        CoordinatorRequest::GetArtifactDataPlanePolicy { node, .. } => {
            (node.clone(), "get_artifact_data_plane_policy")
        }
        CoordinatorRequest::PollNodeAssignment { node, .. } => {
            (node.clone(), "poll_node_assignment")
        }
        CoordinatorRequest::AcknowledgeNodeAssignment { node, .. } => {
            (node.clone(), "acknowledge_node_assignment")
        }
        CoordinatorRequest::LaunchChildTask { node, .. } => (node.clone(), "launch_child_task"),
        CoordinatorRequest::JoinChildTask { node, .. } => (node.clone(), "join_child_task"),
        CoordinatorRequest::CompleteSourcePreparation { node, .. } => {
            (node.clone(), "complete_source_preparation")
        }
        CoordinatorRequest::ReconnectNode { node, .. } => (node.clone(), "reconnect_node"),
        CoordinatorRequest::PollTaskControl { node, .. } => (node.clone(), "poll_task_control"),
        CoordinatorRequest::PollDebugCommand { node, .. } => (node.clone(), "poll_debug_command"),
        CoordinatorRequest::ReportDebugState { node, .. } => (node.clone(), "report_debug_state"),
        CoordinatorRequest::ReportDebugProbeHit { node, .. } => {
            (node.clone(), "report_debug_probe_hit")
        }
        CoordinatorRequest::ReportTaskLog { node, .. } => (node.clone(), "report_task_log"),
        CoordinatorRequest::ReportTaskLogChunk { node, .. } => {
            (node.clone(), "report_task_log_chunk")
        }
        CoordinatorRequest::ReportVfsMetadata { node, .. } => (node.clone(), "report_vfs_metadata"),
        CoordinatorRequest::TaskCompleted { node, .. } => (node.clone(), "task_completed"),
        _ => panic!("test helper only signs node-originated requests"),
    };
    let nonce = TEST_NODE_REQUEST_NONCE
        .fetch_add(1, Ordering::Relaxed)
        .to_string();
    let nonce = format!("node-request-{nonce}");
    let issued_at_epoch_seconds = unix_timestamp_seconds_for_tests();
    let operation_id = matches!(
        &request,
        CoordinatorRequest::ReportVfsMetadata { .. } | CoordinatorRequest::TaskCompleted { .. }
    )
    .then(|| format!("test-operation-{nonce}"));
    let node_signature = if let Some(authority) = assignment_authority {
        if let Some(operation_id) = operation_id {
            sign_node_assignment_operation_request(
                private_key,
                &NodeId::from(node.as_str()),
                request_kind,
                &payload_digest,
                nonce,
                issued_at_epoch_seconds,
                NodeAssignmentOperation {
                    assignment_authority: authority,
                    operation_id,
                },
            )
            .unwrap()
        } else {
            sign_node_assignment_request(
                private_key,
                &NodeId::from(node.as_str()),
                request_kind,
                &payload_digest,
                nonce,
                issued_at_epoch_seconds,
                authority,
            )
            .unwrap()
        }
    } else {
        signed_node_request_with_private_key(
            &node,
            private_key,
            request_kind,
            &payload_digest,
            &nonce,
        )
    };
    CoordinatorRequest::SignedNode {
        node: node.clone(),
        node_signature,
        request: Box::new(request),
    }
}

fn signed_assignment_operation_for_test(
    request: CoordinatorRequest,
    node: &str,
    request_kind: &str,
    authority: AssignmentAuthority,
    operation_id: &str,
) -> CoordinatorRequest {
    let payload_digest = signed_request_payload_digest(&serde_json::to_value(&request).unwrap());
    let nonce = TEST_NODE_REQUEST_NONCE.fetch_add(1, Ordering::Relaxed);
    let node_signature = sign_node_assignment_operation_request(
        &test_node_private_key(node),
        &NodeId::from(node),
        request_kind,
        &payload_digest,
        format!("node-operation-request-{nonce}"),
        unix_timestamp_seconds_for_tests(),
        NodeAssignmentOperation {
            assignment_authority: authority,
            operation_id: operation_id.to_owned(),
        },
    )
    .unwrap();
    CoordinatorRequest::SignedNode {
        node: node.to_owned(),
        node_signature,
        request: Box::new(request),
    }
}

trait SignedNodeRequestTestExt {
    fn handle_signed_node_request_auto(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError>;
}

impl SignedNodeRequestTestExt for CoordinatorService {
    fn handle_signed_node_request_auto(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let assignment = match &request {
            CoordinatorRequest::AcknowledgeNodeAssignment { assignment_id, .. } => self
                .coordinator
                .durable_state()
                .active_assignments
                .get(assignment_id)
                .cloned(),
            CoordinatorRequest::LaunchChildTask {
                tenant,
                project,
                process,
                node,
                parent_task,
                ..
            }
            | CoordinatorRequest::JoinChildTask {
                tenant,
                project,
                process,
                node,
                parent_task,
                ..
            } => self
                .coordinator
                .durable_state()
                .active_assignments
                .values()
                .find(|active| {
                    active.tenant.as_str() == tenant
                        && active.project.as_str() == project
                        && active.node.as_str() == node
                        && matches!(
                            &active.kind,
                            AssignmentKind::ProcessTask { process: owned_process, task }
                                if owned_process.as_str() == process && task.as_str() == parent_task
                        )
                })
                .cloned(),
            CoordinatorRequest::PollTaskSecretGrant {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::PollTaskControl {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::PollDebugCommand {
                tenant,
                project,
                process,
                node,
                task,
            }
            | CoordinatorRequest::ReportDebugState {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::ReportDebugProbeHit {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::ReportTaskLog {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::ReportTaskLogChunk {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::ReportVfsMetadata {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::TaskCompleted {
                tenant,
                project,
                process,
                node,
                task,
                ..
            }
            | CoordinatorRequest::ReleaseArtifact {
                tenant,
                project,
                process,
                node,
                task,
                ..
            } => self
                .coordinator
                .durable_state()
                .active_assignments
                .values()
                .find(|active| {
                    active.tenant.as_str() == tenant
                        && active.project.as_str() == project
                        && active.node.as_str() == node
                        && matches!(
                            &active.kind,
                            AssignmentKind::ProcessTask { process: owned_process, task: owned_task }
                                if owned_process.as_str() == process && owned_task.as_str() == task
                        )
                })
                .cloned(),
            _ => None,
        };
        let authority = assignment.as_ref().map(|active| AssignmentAuthority {
            assignment_id: active.assignment_id.clone(),
            attempt_id: active.attempt_id.clone(),
            offer_epoch: active.offer_epoch,
        });
        if let (Some(active), Some(authority)) = (assignment, authority.as_ref()) {
            if active.state == AssignmentState::Offered {
                let key = (
                    active.tenant.clone(),
                    active.project.clone(),
                    active.node.clone(),
                );
                let now = self.current_epoch_seconds()?;
                self.task_registry.acknowledge_process_assignment(
                    self.coordinator.durable_state_mut(),
                    &key,
                    authority,
                    now,
                    180,
                );
            }
        }
        let node = match &request {
            CoordinatorRequest::ReportNodeCapabilities { node, .. }
            | CoordinatorRequest::GetArtifactDataPlanePolicy { node, .. }
            | CoordinatorRequest::PollNodeAssignment { node, .. }
            | CoordinatorRequest::AcknowledgeNodeAssignment { node, .. }
            | CoordinatorRequest::LaunchChildTask { node, .. }
            | CoordinatorRequest::JoinChildTask { node, .. }
            | CoordinatorRequest::CompleteSourcePreparation { node, .. }
            | CoordinatorRequest::ReconnectNode { node, .. }
            | CoordinatorRequest::PollTaskControl { node, .. }
            | CoordinatorRequest::PollDebugCommand { node, .. }
            | CoordinatorRequest::ReportDebugState { node, .. }
            | CoordinatorRequest::ReportDebugProbeHit { node, .. }
            | CoordinatorRequest::ReportTaskLog { node, .. }
            | CoordinatorRequest::ReportTaskLogChunk { node, .. }
            | CoordinatorRequest::ReportVfsMetadata { node, .. }
            | CoordinatorRequest::TaskCompleted { node, .. } => node,
            _ => return self.handle_request(signed_node_request_auto(request)),
        };
        let private_key = test_node_private_key(node);
        self.handle_request(signed_node_request_auto_with_private_key_and_authority(
            request,
            &private_key,
            authority,
        ))
    }
}

fn poll_process_assignment_for_test(
    service: &mut CoordinatorService,
    tenant: &str,
    project: &str,
    node: &str,
) -> Option<Box<TaskAssignment>> {
    let CoordinatorResponse::NodeAssignment { assignment, .. } = service
        .handle_signed_node_request_auto(CoordinatorRequest::PollNodeAssignment {
            tenant: tenant.to_owned(),
            project: project.to_owned(),
            node: node.to_owned(),
            accept_system_tasks: false,
            accept_process_tasks: true,
            active_assignment: None,
        })
        .expect("node assignment poll should succeed")
    else {
        panic!("expected node assignment response");
    };
    let offer = assignment?;
    service
        .handle_signed_node_request_auto(CoordinatorRequest::AcknowledgeNodeAssignment {
            tenant: tenant.to_owned(),
            project: project.to_owned(),
            node: node.to_owned(),
            assignment_id: offer.assignment_id.clone(),
            lease_epoch: offer.lease_epoch,
        })
        .expect("node assignment acknowledgement should succeed");
    match offer.work {
        clusterflux_protocol::NodeAssignmentWork::Task { assignment } => Some(assignment),
        clusterflux_protocol::NodeAssignmentWork::SystemTask { .. } => {
            panic!("process-only poll returned a system task")
        }
    }
}

fn unix_timestamp_seconds_for_tests() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}

fn write_coordinator_wire_request(
    stream: &mut TcpStream,
    request: &CoordinatorRequest,
    request_id: &str,
) {
    let wire_request = coordinator_wire_request(request_id, request.clone());
    serde_json::to_writer(&mut *stream, &wire_request).unwrap();
    stream.write_all(b"\n").unwrap();
    stream.flush().unwrap();
}

mod artifact_interchange;
mod auth_and_policy;
mod automation_mvp;
mod node_and_debug;
mod process_lifecycle;
mod scheduling;
mod validation_and_queries;
