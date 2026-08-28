use crate::{AutomatedRunStageRecord, NodeScopeKey};
use clusterflux_core::{
    AssignmentAuthority, AutomatedRunState, CommitTrigger, CompiledWorkflowBundle,
    CompilerIdentity, CompilerProfile, ForgeKind, RepositoryId, RepositoryRevision,
    TriggerEventKind, TriggerId, WorkflowCompilationRequest, WorkflowCompilationResult,
    WorkflowCompilerResourcePolicy, WorkflowSource, WorkflowSourceFile, WASM_TASK_ABI_VERSION,
};

use super::*;

const SESSION: &str = "automation-mvp-session";
const REPOSITORY_URL: &str = "https://github.com/clusterflux-example/cf-test.git";

fn offer_authority(offer: &clusterflux_protocol::NodeAssignmentOffer) -> AssignmentAuthority {
    AssignmentAuthority {
        assignment_id: offer.assignment_id.clone(),
        attempt_id: offer.attempt_id.clone(),
        offer_epoch: offer.lease_epoch,
    }
}

fn service_with_project() -> CoordinatorService {
    let mut service = CoordinatorService::new(1_000);
    service
        .issue_cli_session(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            UserId::from("operator"),
            SESSION,
            None,
        )
        .unwrap();
    service
}

fn system_bundle_capabilities() -> NodeCapabilities {
    let manifest = clusterflux_core::workflow_compiler_system_manifest();
    let mut capabilities = linux_capabilities();
    capabilities
        .system_bundles
        .push(clusterflux_core::SystemBundleCapability {
            bundle_id: manifest.bundle_id,
            bundle_digest: manifest.bundle_digest,
            sdk_abi_version: manifest.sdk_abi_version,
            wasm_target: manifest.wasm_target,
            rust_toolchain: manifest.rust_toolchain,
            environment_digest: manifest.environment_digest,
            sandbox: clusterflux_core::SystemTaskSandbox::RootlessPodman,
            max_source_bytes: clusterflux_core::MAX_WORKFLOW_SOURCE_BYTES,
            max_output_bytes: WorkflowCompilerResourcePolicy::default().max_output_bytes,
            max_concurrent_assignments: 1,
        });
    capabilities
}

fn attach_node_with_capabilities(
    service: &mut CoordinatorService,
    node: &str,
    capabilities: NodeCapabilities,
) {
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
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();
}

fn attach_system_bundle_node(service: &mut CoordinatorService, node: &str) {
    attach_node_with_capabilities(service, node, system_bundle_capabilities());
}

fn trigger(index: u64, commit_index: u64) -> CommitTrigger {
    CommitTrigger {
        trigger_id: TriggerId::new(format!("trigger-{index}")),
        forge: ForgeKind::GitHub,
        repository_id: RepositoryId::from("github:clusterflux-example/cf-test"),
        repository_url: REPOSITORY_URL.to_owned(),
        commit_sha: format!("{commit_index:040x}"),
        git_ref: "refs/heads/main".to_owned(),
        delivery_id: format!("delivery-{index}"),
        event_kind: TriggerEventKind::Push,
        actor: Some("octocat".to_owned()),
        trusted: true,
        received_at: 1_000 + index,
    }
}

#[test]
fn running_automation_surfaces_and_clears_process_waiting_reason() {
    let mut service = service_with_project();
    let accepted = accept(&mut service, "binding", trigger(90, 90));
    let process = ProcessId::from("process-waiting-environment");
    {
        let record = service
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&accepted.run.run_id)
            .unwrap();
        record.run.state = AutomatedRunState::Running;
        record.run.process_id = Some(process.clone());
        record.run.started_at = Some(1_090);
    }

    let reason = "required named environment cache sha256:deadbeef is unavailable";
    service.record_automated_process_waiting_reason(
        &TenantId::from("tenant"),
        &ProjectId::from("project"),
        &process,
        Some(reason),
    );
    assert_eq!(
        service
            .automated_run(&accepted.run.run_id)
            .unwrap()
            .run
            .waiting_reason
            .as_deref(),
        Some(reason)
    );

    service.record_automated_process_waiting_reason(
        &TenantId::from("tenant"),
        &ProjectId::from("project"),
        &process,
        None,
    );
    assert_eq!(
        service
            .automated_run(&accepted.run.run_id)
            .unwrap()
            .run
            .waiting_reason,
        None
    );
}

#[test]
fn failed_automated_process_retains_a_bounded_actionable_task_diagnostic() {
    let mut service = service_with_project();
    let accepted = accept(&mut service, "binding", trigger(91, 91));
    let process = ProcessId::from("process-failed-automation");
    {
        let record = service
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&accepted.run.run_id)
            .unwrap();
        record.run.state = AutomatedRunState::Running;
        record.run.process_id = Some(process.clone());
        record.run.started_at = Some(1_091);
    }
    service.record_task_completion_event(TaskCompletionEvent {
        tenant: TenantId::from("tenant"),
        project: ProjectId::from("project"),
        process: process.clone(),
        node: NodeId::from("release-node"),
        executor: TaskExecutor::Node,
        task_definition: TaskDefinitionId::from("test_public_repo"),
        task: TaskInstanceId::from("test-public-repo-1"),
        attempt_id: Some("attempt-1".to_owned()),
        placement: None,
        terminal_state: TaskTerminalState::Failed,
        status_code: Some(101),
        stdout_bytes: 0,
        stderr_bytes: 8_000,
        stdout_tail: String::new(),
        stderr_tail: format!("{}root cause: lane proof failed", "é".repeat(4_000)),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        artifact_digest: None,
        artifact_size_bytes: None,
        result: None,
    });

    service.record_process_terminal(
        &TenantId::from("tenant"),
        &ProjectId::from("project"),
        &process,
        ProcessFinalResult::Failed,
        1_100,
    );

    let run = &service.automated_run(&accepted.run.run_id).unwrap().run;
    assert_eq!(run.state, AutomatedRunState::Failed);
    assert_eq!(run.failure_code.as_deref(), Some("process_failed"));
    let message = run.failure_message.as_deref().unwrap();
    assert!(message.starts_with("Task test-public-repo-1 (test_public_repo) failed:"));
    assert!(message.ends_with("root cause: lane proof failed"));
    assert!(message.len() <= clusterflux_core::MAX_AUTOMATED_RUN_FAILURE_BYTES);
    run.validate().unwrap();
}

fn source_for(trigger: &CommitTrigger, commit_sha: &str) -> WorkflowSource {
    WorkflowSource::new(
        trigger.trigger_id.clone(),
        trigger.repository_id.clone(),
        commit_sha,
        vec![
            WorkflowSourceFile::new(
                ".clusterflux/Cargo.toml",
                0o100644,
                b"[package]\nname='automation-test'\nversion='0.0.0'\nedition='2024'\npublish=false\n[lib]\npath='main.rs'\ncrate-type=['cdylib']\n[dependencies]\nclusterflux={package='clusterflux-sdk',version='=0.2.0'}\n[workspace]\nresolver='3'\n"
                    .to_vec(),
            )
            .unwrap(),
            WorkflowSourceFile::new(
                ".clusterflux/main.rs",
                0o100644,
                b"pub fn main() {}\n".to_vec(),
            )
            .unwrap(),
        ],
    )
    .unwrap()
}

fn revision_for(trigger: &CommitTrigger) -> RepositoryRevision {
    RepositoryRevision {
        repository_id: trigger.repository_id.clone(),
        clone_url: trigger.repository_url.clone(),
        commit_sha: trigger.commit_sha.clone(),
        source_snapshot: Digest::sha256(format!("snapshot-{}", trigger.commit_sha)),
    }
}

fn compilation_request(
    run_id: clusterflux_core::RunId,
    source: WorkflowSource,
) -> WorkflowCompilationRequest {
    let manifest = clusterflux_core::workflow_compiler_system_manifest();
    WorkflowCompilationRequest {
        run_id,
        source,
        compiler_profile: clusterflux_core::workflow_compiler_profile_id(
            &manifest.environment_digest,
        ),
        compiler_image: manifest.environment_digest,
        compiler_sdk: manifest.sdk_digest,
        rust_toolchain: manifest.rust_toolchain,
        resource_policy: WorkflowCompilerResourcePolicy::default(),
    }
}

fn accept(
    service: &mut CoordinatorService,
    binding: &str,
    trigger: CommitTrigger,
) -> AutomatedRunStageRecord {
    service
        .accept_commit_trigger(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            binding.to_owned(),
            Digest::sha256(format!("body-{}", trigger.delivery_id)),
            trigger,
        )
        .unwrap()
}

#[test]
fn coordinator_restart_fails_running_automation_without_a_dead_process_link() {
    let mut service = service_with_project();
    let accepted = accept(&mut service, "binding", trigger(1, 1));
    let run_id = accepted.run.run_id.clone();
    {
        let record = service
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&run_id)
            .unwrap();
        record.run.state = AutomatedRunState::Running;
        record.run.process_id = Some(ProcessId::from("process-before-restart"));
        record.run.started_at = Some(1_001);
    }

    assert_eq!(
        service
            .reconcile_automated_runs_after_coordinator_restart()
            .unwrap(),
        1
    );
    let reconciled = service.automated_run(&run_id).unwrap();
    assert_eq!(reconciled.run.state, AutomatedRunState::Failed);
    assert_eq!(
        reconciled.run.failure_code.as_deref(),
        Some("coordinator_restart_interrupted_run")
    );
    assert!(reconciled.run.ended_at.is_some());
    assert!(reconciled.run.process_id.is_none());
}

#[test]
fn trigger_dedup_queue_pagination_and_cancellation_are_bounded_and_durable() {
    let mut service = service_with_project();
    let first_trigger = trigger(1, 1);
    let first_body = Digest::sha256(format!("body-{}", first_trigger.delivery_id));
    let first = accept(&mut service, "binding", first_trigger.clone());
    let duplicate = service
        .accept_commit_trigger(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "binding".to_owned(),
            first_body.clone(),
            first_trigger.clone(),
        )
        .unwrap();
    assert_eq!(duplicate.run.run_id, first.run.run_id);

    let mut same_commit_new_delivery = first_trigger.clone();
    same_commit_new_delivery.trigger_id = TriggerId::from("trigger-duplicate-commit");
    same_commit_new_delivery.delivery_id = "delivery-duplicate-commit".to_owned();
    let logical_duplicate = accept(&mut service, "binding", same_commit_new_delivery);
    assert_eq!(logical_duplicate.run.run_id, first.run.run_id);

    assert!(service
        .accept_commit_trigger(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "binding".to_owned(),
            Digest::sha256("changed-body"),
            first_trigger.clone(),
        )
        .unwrap_err()
        .to_string()
        .contains("different body"));

    let cancelled = service.cancel_automated_run(&first.run.run_id).unwrap();
    assert_eq!(cancelled.run.state, AutomatedRunState::Cancelled);
    let exact_source = source_for(&first_trigger, &first_trigger.commit_sha);
    let after_source = service
        .record_automated_run_source(
            &first.run.run_id,
            exact_source.clone(),
            revision_for(&first_trigger),
        )
        .unwrap();
    assert_eq!(after_source.run.state, AutomatedRunState::Cancelled);
    assert!(after_source.source.is_none());
    let after_enqueue = service
        .enqueue_workflow_compilation(compilation_request(first.run.run_id.clone(), exact_source))
        .unwrap();
    assert_eq!(after_enqueue.run.state, AutomatedRunState::Cancelled);
    let after_report = service
        .report_system_compile_for_test(WorkflowCompilationResult {
            assignment_id: "cancelled-assignment".to_owned(),
            attempt_id: "cancelled-attempt".to_owned(),
            lease_epoch: 1,
            run_id: first.run.run_id.clone(),
            node: NodeId::from("irrelevant-after-cancel"),
            bundle: None,
            compiler_transcript: "cancel won".to_owned(),
            failure_code: Some("compiler_failed".to_owned()),
            retryable: false,
        })
        .unwrap_err();
    assert!(after_report
        .to_string()
        .contains("retained assignment history"));

    for index in 2..=5 {
        let record = accept(&mut service, "binding", trigger(index, index));
        service.cancel_automated_run(&record.run.run_id).unwrap();
    }
    let (page_one, cursor) = service
        .automated_runs_page(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            None,
            2,
        )
        .unwrap();
    assert_eq!(page_one.len(), 2);
    let cursor = cursor.expect("more run history remains");
    let (page_two, _) = service
        .automated_runs_page(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            Some(&cursor),
            2,
        )
        .unwrap();
    assert_eq!(page_two.len(), 2);
    assert!(page_one
        .iter()
        .all(|left| page_two.iter().all(|right| left.run_id != right.run_id)));
    assert!(service
        .automated_runs_page(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            Some("expired-run-cursor"),
            2,
        )
        .is_err());

    let mut saturated = service_with_project();
    for index in 10..18 {
        accept(&mut saturated, "binding", trigger(index, index));
    }
    assert!(accept_commit_error(&mut saturated, trigger(18, 18)).contains("queue is full"));
}

#[test]
fn failed_or_cancelled_run_retry_creates_a_fresh_attempt_for_the_same_revision() {
    let mut service = service_with_project();
    let original_trigger = trigger(62, 62);
    let original = accept(&mut service, "binding", original_trigger.clone());
    service.cancel_automated_run(&original.run.run_id).unwrap();

    let retry = service.retry_automated_run(&original.run.run_id).unwrap();
    assert_ne!(retry.run.run_id, original.run.run_id);
    assert_ne!(
        retry.run.primary_trigger_id,
        original.run.primary_trigger_id
    );
    assert_eq!(retry.run.repository_id, original.run.repository_id);
    assert_eq!(retry.run.commit_sha, original.run.commit_sha);
    assert_eq!(retry.run.git_ref, original.run.git_ref);
    assert_eq!(retry.run.trusted, original.run.trusted);
    assert_eq!(retry.run.state, AutomatedRunState::Accepted);
    assert!(retry.run.process_id.is_none());
    assert!(retry.run.failure_code.is_none());
    assert!(retry.run.failure_message.is_none());

    let pending = service.pending_source_loads(8);
    assert!(pending
        .iter()
        .any(|record| record.trigger.trigger_id == retry.run.primary_trigger_id));
    assert!(service.retry_automated_run(&retry.run.run_id).is_err());

    let second_retry = service.retry_automated_run(&original.run.run_id).unwrap();
    assert_ne!(second_retry.run.run_id, retry.run.run_id);

    let duplicate = service
        .accept_commit_trigger(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "binding".to_owned(),
            Digest::sha256(format!("body-{}", original_trigger.delivery_id)),
            original_trigger,
        )
        .unwrap();
    assert_eq!(duplicate.run.run_id, original.run.run_id);
}

#[test]
fn retention_compaction_keeps_the_trigger_for_a_surviving_retry() {
    let mut service = service_with_project();
    let original_trigger = trigger(70, 70);
    let original = accept(&mut service, "binding", original_trigger.clone());
    service.cancel_automated_run(&original.run.run_id).unwrap();
    service
        .coordinator
        .durable_state_mut()
        .automated_runs
        .get_mut(&original.run.run_id)
        .unwrap()
        .run
        .created_at = 0;
    let retry = service.retry_automated_run(&original.run.run_id).unwrap();

    for index in 100..162 {
        let record = accept(&mut service, "binding", trigger(index, index));
        service.cancel_automated_run(&record.run.run_id).unwrap();
    }
    accept(&mut service, "binding", trigger(163, 163));

    assert!(service.automated_run(&original.run.run_id).is_none());
    assert!(service.automated_run(&retry.run.run_id).is_some());
    assert!(service
        .coordinator
        .durable_state()
        .accepted_commit_triggers
        .contains_key(&retry.run.primary_trigger_id));
    assert!(service
        .pending_source_loads(8)
        .iter()
        .any(|record| record.trigger.trigger_id == retry.run.primary_trigger_id));
}

#[test]
fn cancelled_system_assignment_is_revoked_through_normal_node_poll() {
    let mut service = service_with_project();
    let commit = trigger(9, 9);
    let accepted = accept(&mut service, "binding", commit.clone());
    let source = source_for(&commit, &commit.commit_sha);
    service
        .record_automated_run_source(&accepted.run.run_id, source.clone(), revision_for(&commit))
        .unwrap();
    service
        .enqueue_workflow_compilation(compilation_request(accepted.run.run_id.clone(), source))
        .unwrap();
    attach_system_bundle_node(&mut service, "ordinary-node");

    let CoordinatorResponse::NodeAssignment {
        assignment: Some(offer),
        cancel_assignment: None,
    } = service
        .handle_poll_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "ordinary-node".to_owned(),
            true,
            false,
            None,
        )
        .unwrap()
    else {
        panic!("ordinary node should receive system assignment");
    };
    service
        .handle_acknowledge_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "ordinary-node".to_owned(),
            offer.assignment_id.clone(),
            offer.lease_epoch,
            Some(offer_authority(&offer)),
        )
        .unwrap();

    service.cancel_automated_run(&accepted.run.run_id).unwrap();
    let active = clusterflux_protocol::ActiveNodeAssignment {
        assignment_id: offer.assignment_id,
        attempt_id: offer.attempt_id,
        lease_epoch: offer.lease_epoch,
    };
    let CoordinatorResponse::NodeAssignment {
        assignment: None,
        cancel_assignment: Some(cancelled),
    } = service
        .handle_poll_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "ordinary-node".to_owned(),
            false,
            false,
            Some(active.clone()),
        )
        .unwrap()
    else {
        panic!("cancelled system assignment should be revoked");
    };
    assert_eq!(cancelled, active);
}

#[test]
fn suspending_tenant_cancels_queued_and_active_automation_without_restarting_it() {
    let mut service = service_with_project();
    let queued_trigger = trigger(91, 91);
    let queued = accept(&mut service, "binding", queued_trigger);
    let compiling_trigger = trigger(92, 92);
    let compiling = accept(&mut service, "binding", compiling_trigger.clone());
    let source = source_for(&compiling_trigger, &compiling_trigger.commit_sha);
    service
        .record_automated_run_source(
            &compiling.run.run_id,
            source.clone(),
            revision_for(&compiling_trigger),
        )
        .unwrap();
    service
        .enqueue_workflow_compilation(compilation_request(compiling.run.run_id.clone(), source))
        .unwrap();
    attach_system_bundle_node(&mut service, "ordinary-node");
    let CoordinatorResponse::NodeAssignment {
        assignment: Some(offer),
        ..
    } = service
        .handle_poll_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "ordinary-node".to_owned(),
            true,
            false,
            None,
        )
        .unwrap()
    else {
        panic!("ordinary node should receive system assignment");
    };
    service
        .handle_acknowledge_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "ordinary-node".to_owned(),
            offer.assignment_id.clone(),
            offer.lease_epoch,
            Some(offer_authority(&offer)),
        )
        .unwrap();

    service
        .suspend_hosted_account(TenantId::from("tenant"), UserId::from("admin"), 1_100)
        .unwrap();
    for run in [&queued.run.run_id, &compiling.run.run_id] {
        assert_eq!(
            service.automated_run(run).unwrap().run.state,
            AutomatedRunState::Cancelled
        );
    }
    assert!(service.launchable_automated_runs(8).is_empty());

    let active = clusterflux_protocol::ActiveNodeAssignment {
        assignment_id: offer.assignment_id,
        attempt_id: offer.attempt_id,
        lease_epoch: offer.lease_epoch,
    };
    let CoordinatorResponse::NodeAssignment {
        assignment: None,
        cancel_assignment: Some(cancelled),
    } = service
        .handle_poll_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "ordinary-node".to_owned(),
            true,
            true,
            Some(active.clone()),
        )
        .unwrap()
    else {
        panic!("suspended tenant should only return cancellation for active work");
    };
    assert_eq!(cancelled, active);
}

#[test]
fn system_assignment_wait_reasons_are_actionable_and_compatible_node_resumes() {
    let mut service = service_with_project();
    let commit = trigger(19, 19);
    let accepted = accept(&mut service, "binding", commit.clone());
    let source = source_for(&commit, &commit.commit_sha);
    service
        .record_automated_run_source(&accepted.run.run_id, source.clone(), revision_for(&commit))
        .unwrap();
    let queued = service
        .enqueue_workflow_compilation(compilation_request(accepted.run.run_id.clone(), source))
        .unwrap();
    assert_eq!(
        queued.run.waiting_reason.as_deref(),
        Some("no_attached_compatible_node")
    );

    let mut disabled = system_bundle_capabilities();
    disabled.work_policy = clusterflux_core::NodeWorkPolicy::ExecutionOnly;
    attach_node_with_capabilities(&mut service, "execution-only", disabled);
    assert!(service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("execution-only"),
        )
        .unwrap()
        .is_none());
    assert_eq!(
        service
            .automated_run(&accepted.run.run_id)
            .unwrap()
            .run
            .waiting_reason
            .as_deref(),
        Some("node_policy_disables_workflow_compilation")
    );
    assert_eq!(service.operational_metrics().node_policy_rejections, 1);

    let mut mismatched = system_bundle_capabilities();
    mismatched.system_bundles[0].bundle_digest = Digest::sha256("older-release");
    attach_node_with_capabilities(&mut service, "older-node", mismatched);
    assert!(service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("older-node"),
        )
        .unwrap()
        .is_none());
    assert_eq!(
        service
            .automated_run(&accepted.run.run_id)
            .unwrap()
            .run
            .waiting_reason
            .as_deref(),
        Some("system_bundle_version_mismatch_or_unavailable")
    );
    let metrics = service.operational_metrics();
    assert_eq!(metrics.node_policy_rejections, 0);
    assert_eq!(metrics.system_bundle_mismatches, 1);

    attach_system_bundle_node(&mut service, "ordinary-compatible");
    let offer = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("ordinary-compatible"),
        )
        .unwrap();
    assert!(offer.is_some());
    assert_eq!(
        service
            .automated_run(&accepted.run.run_id)
            .unwrap()
            .run
            .waiting_reason,
        None
    );
}

fn accept_commit_error(service: &mut CoordinatorService, trigger: CommitTrigger) -> String {
    service
        .accept_commit_trigger(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            "binding".to_owned(),
            Digest::sha256(format!("body-{}", trigger.delivery_id)),
            trigger,
        )
        .unwrap_err()
        .to_string()
}

#[test]
fn source_identity_and_system_assignment_lease_ownership_fail_closed() {
    let mut service = service_with_project();
    let first_trigger = trigger(20, 20);
    let accepted = accept(&mut service, "binding", first_trigger.clone());
    let mismatched_source = source_for(&first_trigger, &format!("{:040x}", 21));
    assert!(service
        .record_automated_run_source(
            &accepted.run.run_id,
            mismatched_source,
            revision_for(&first_trigger),
        )
        .is_err());

    let source = source_for(&first_trigger, &first_trigger.commit_sha);
    service
        .record_automated_run_source(
            &accepted.run.run_id,
            source.clone(),
            revision_for(&first_trigger),
        )
        .unwrap();
    let queued = service
        .enqueue_workflow_compilation(compilation_request(
            accepted.run.run_id.clone(),
            source.clone(),
        ))
        .unwrap();
    assert_eq!(queued.run.state, AutomatedRunState::WaitingForCompilerNode);

    for node in ["system-node", "ordinary"] {
        service
            .handle_request(CoordinatorRequest::AttachNode {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                public_key: test_node_public_key(node),
            })
            .unwrap();
        let mut capabilities = linux_capabilities();
        if node == "system-node" {
            let manifest = clusterflux_core::workflow_compiler_system_manifest();
            capabilities
                .system_bundles
                .push(clusterflux_core::SystemBundleCapability {
                    bundle_id: manifest.bundle_id,
                    bundle_digest: manifest.bundle_digest,
                    sdk_abi_version: manifest.sdk_abi_version,
                    wasm_target: manifest.wasm_target,
                    rust_toolchain: manifest.rust_toolchain,
                    environment_digest: manifest.environment_digest,
                    sandbox: clusterflux_core::SystemTaskSandbox::RootlessPodman,
                    max_source_bytes: clusterflux_core::MAX_WORKFLOW_SOURCE_BYTES,
                    max_output_bytes: WorkflowCompilerResourcePolicy::default().max_output_bytes,
                    max_concurrent_assignments: 1,
                });
        }
        service
            .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
                tenant: "tenant".to_owned(),
                project: "project".to_owned(),
                node: node.to_owned(),
                capabilities,
                cached_environment_digests: Vec::new(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: Vec::new(),
                artifact_locations: Vec::new(),
                online: true,
            })
            .unwrap();
    }
    assert!(service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("ordinary"),
        )
        .unwrap()
        .is_none());
    let offer = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node"),
        )
        .unwrap()
        .expect("compiler receives the oldest work item");
    let leased = match &offer.work {
        clusterflux_protocol::NodeAssignmentWork::SystemTask { assignment } => {
            match &assignment.task {
                clusterflux_protocol::SystemTaskKind::CompileWorkflow { request } => request,
            }
        }
        _ => panic!("expected compiler work"),
    };
    assert_eq!(leased.run_id, accepted.run.run_id);
    let redelivered = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node"),
        )
        .unwrap()
        .expect("unacknowledged compiler offer is redelivered");
    assert_eq!(redelivered.assignment_id, offer.assignment_id);
    assert_eq!(redelivered.lease_epoch, offer.lease_epoch);
    service.server_time_override = Some(1_031);
    assert!(service
        .acknowledge_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node"),
            &offer.assignment_id,
            offer.lease_epoch,
            &offer_authority(&offer),
        )
        .unwrap());
    service.server_time_override = Some(1_041);
    let metrics = service.operational_metrics();
    assert_eq!(metrics.system_assignments_running, 1);
    assert_eq!(metrics.compile_duration_seconds, 10);
    assert!(service
        .acknowledge_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node"),
            &offer.assignment_id,
            offer.lease_epoch,
            &offer_authority(&offer),
        )
        .unwrap());

    let failed_result = |node: &str| WorkflowCompilationResult {
        assignment_id: offer.assignment_id.clone(),
        attempt_id: offer.attempt_id.clone(),
        lease_epoch: offer.lease_epoch,
        run_id: accepted.run.run_id.clone(),
        node: NodeId::from(node),
        bundle: None,
        compiler_transcript: "rustc rejected the workflow".to_owned(),
        failure_code: Some("compile_failed".to_owned()),
        retryable: false,
    };
    assert!(service
        .report_system_compile_for_test(failed_result("ordinary"))
        .is_err());
    let mut stale = failed_result("system-node");
    stale.lease_epoch = stale.lease_epoch.saturating_add(1);
    assert!(service.report_system_compile_for_test(stale).is_err());
    let system_result_request =
        |result: WorkflowCompilationResult| CoordinatorRequest::ReportSystemTask {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "system-node".to_owned(),
            result: clusterflux_protocol::SystemTaskResult {
                bundle_id: clusterflux_core::WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID.to_owned(),
                bundle_digest: clusterflux_core::workflow_compiler_system_bundle_digest(),
                result: clusterflux_protocol::SystemTaskOutput::CompileWorkflow {
                    result: Box::new(result),
                },
            },
        };
    let operation_id = format!("system-result-{}", offer.assignment_id);
    let request = system_result_request(failed_result("system-node"));
    let failed = service
        .handle_request(signed_assignment_operation_for_test(
            request.clone(),
            "system-node",
            "report_system_task",
            offer_authority(&offer),
            &operation_id,
        ))
        .unwrap();
    let CoordinatorResponse::SystemTaskRecorded { run } = failed else {
        panic!("expected recorded system-task failure");
    };
    assert_eq!(run.state, AutomatedRunState::Failed);
    let replay = service
        .handle_request(signed_assignment_operation_for_test(
            request,
            "system-node",
            "report_system_task",
            offer_authority(&offer),
            &operation_id,
        ))
        .unwrap();
    assert_eq!(
        replay,
        CoordinatorResponse::SystemTaskRecorded { run: run.clone() }
    );
    let mut conflicting = failed_result("system-node");
    conflicting.compiler_transcript = "different compiler result".to_owned();
    let conflict = service
        .handle_request(signed_assignment_operation_for_test(
            system_result_request(conflicting),
            "system-node",
            "report_system_task",
            offer_authority(&offer),
            &operation_id,
        ))
        .unwrap_err();
    assert!(matches!(
        conflict,
        CoordinatorServiceError::TerminalOperationConflict
    ));

    let trigger = trigger(21, 21);
    let accepted = accept(&mut service, "binding", trigger.clone());
    let source = source_for(&trigger, &trigger.commit_sha);
    service
        .record_automated_run_source(&accepted.run.run_id, source.clone(), revision_for(&trigger))
        .unwrap();
    service
        .enqueue_workflow_compilation(compilation_request(
            accepted.run.run_id.clone(),
            source.clone(),
        ))
        .unwrap();
    let offer = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node"),
        )
        .unwrap()
        .unwrap();
    service
        .acknowledge_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node"),
            &offer.assignment_id,
            offer.lease_epoch,
            &offer_authority(&offer),
        )
        .unwrap();
    let module = b"\0asm\x01\0\0\0";
    let execution_module_digest = Digest::sha256(module);
    let debug_sidecar_digest = Digest::sha256([]);
    let manifest_digest = source.manifest.digest.clone();
    let bundle_digest = Digest::from_parts([
        b"clusterflux-compiled-workflow:v2".as_slice(),
        execution_module_digest.as_str().as_bytes(),
        debug_sidecar_digest.as_str().as_bytes(),
        manifest_digest.as_str().as_bytes(),
        source.tree_digest.as_str().as_bytes(),
    ]);
    let system_manifest = clusterflux_core::workflow_compiler_system_manifest();
    assert!(service
        .report_system_compile_for_test(WorkflowCompilationResult {
            assignment_id: offer.assignment_id,
            attempt_id: offer.attempt_id,
            lease_epoch: offer.lease_epoch,
            run_id: accepted.run.run_id.clone(),
            node: NodeId::from("system-node"),
            bundle: Some(CompiledWorkflowBundle {
                module_base64: BASE64_STANDARD.encode(module),
                bundle_digest,
                execution_module_digest,
                manifest_digest,
                source_tree_digest: source.tree_digest,
                sdk_abi_version: WASM_TASK_ABI_VERSION + 1,
                default_entrypoint: "main".to_owned(),
                entrypoints: vec!["main".to_owned()],
                task_definitions: vec!["main".to_owned()],
                environment_names: Vec::new(),
                environments: Vec::new(),
                debug_metadata_base64: String::new(),
                debug_sidecar_digest,
                path_remapping: vec![("/workflow".to_owned(), ".clusterflux".to_owned())],
                compiler_identity: CompilerIdentity {
                    profile: CompilerProfile::HostedSandbox,
                    rustc_version: system_manifest.rust_toolchain.clone(),
                    rustc_commit: None,
                    target: "wasm32-unknown-unknown".to_owned(),
                    flags: vec![
                        "-Copt-level=1".to_owned(),
                        "-Cdebuginfo=2".to_owned(),
                        "-Cstrip=none".to_owned(),
                        "-Cpanic=abort".to_owned(),
                        "--remap-path-prefix=/workspace=.clusterflux".to_owned(),
                    ],
                    sdk_version: "0.2.0".to_owned(),
                    sdk_digest: system_manifest.sdk_digest,
                    trusted_dependencies: Vec::new(),
                    sandbox_image_digest: Some(system_manifest.environment_digest),
                },
                source_paths: vec![
                    ".clusterflux/Cargo.toml".to_owned(),
                    ".clusterflux/main.rs".to_owned(),
                ],
            }),
            compiler_transcript: String::new(),
            failure_code: None,
            retryable: false,
        })
        .unwrap_err()
        .to_string()
        .contains("unsupported"));
    let still_compiling = service.automated_run(&accepted.run.run_id).unwrap();
    assert_eq!(
        still_compiling.run.state,
        AutomatedRunState::CompilingWorkflow
    );
    assert!(still_compiling.compiled_bundle.is_none());
}

#[test]
fn system_assignment_loss_before_and_after_ack_is_fenced_and_retried() {
    let mut service = service_with_project();
    service.server_time_override = Some(1_000);
    let trigger = trigger(23, 23);
    let accepted = accept(&mut service, "binding", trigger.clone());
    let source = source_for(&trigger, &trigger.commit_sha);
    service
        .record_automated_run_source(&accepted.run.run_id, source.clone(), revision_for(&trigger))
        .unwrap();
    service
        .enqueue_workflow_compilation(compilation_request(accepted.run.run_id.clone(), source))
        .unwrap();
    attach_system_bundle_node(&mut service, "system-node-a");
    attach_system_bundle_node(&mut service, "system-node-b");

    let first = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-a"),
        )
        .unwrap()
        .unwrap();
    service.server_time_override = Some(1_031);
    let second = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-b"),
        )
        .unwrap()
        .expect("expired unacknowledged offer returns to pending");
    assert_ne!(first.assignment_id, second.assignment_id);
    assert!(second.lease_epoch > first.lease_epoch);
    assert!(service
        .acknowledge_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-b"),
            &second.assignment_id,
            second.lease_epoch,
            &offer_authority(&second),
        )
        .unwrap());
    assert!(service
        .report_system_compile_for_test(WorkflowCompilationResult {
            assignment_id: first.assignment_id,
            attempt_id: first.attempt_id,
            lease_epoch: first.lease_epoch,
            run_id: accepted.run.run_id.clone(),
            node: NodeId::from("system-node-a"),
            bundle: None,
            compiler_transcript: "stale".to_owned(),
            failure_code: Some("stale".to_owned()),
            retryable: true,
        })
        .is_err());

    service.server_time_override = Some(1_212);
    let third = service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-a"),
        )
        .unwrap()
        .expect("lost acknowledged assignment is retried after its bounded lease");
    assert!(third.lease_epoch > second.lease_epoch);
    assert_ne!(third.assignment_id, second.assignment_id);

    service.server_time_override = Some(1_243);
    service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-b"),
        )
        .unwrap()
        .expect("fourth bounded attempt");
    service.server_time_override = Some(1_274);
    service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-a"),
        )
        .unwrap()
        .expect("fifth bounded attempt");
    service.server_time_override = Some(1_305);
    assert!(service
        .poll_system_task_offer(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("system-node-b"),
        )
        .unwrap()
        .is_none());
    let exhausted = service.automated_run(&accepted.run.run_id).unwrap();
    assert_eq!(exhausted.run.state, AutomatedRunState::Failed);
    assert_eq!(
        exhausted.run.failure_code.as_deref(),
        Some("system_assignment_node_lost")
    );
}

#[test]
fn system_tasks_only_policy_refuses_runtime_secret_artifact_and_debug_authority() {
    let mut service = service_with_project();
    attach_system_bundle_node(&mut service, "system-only");
    let scope = NodeScopeKey::from_refs(
        &TenantId::from("tenant"),
        &ProjectId::from("project"),
        &NodeId::from("system-only"),
    );
    let mut capabilities = service
        .node_registry
        .descriptor(&scope)
        .unwrap()
        .capabilities
        .clone();
    capabilities.work_policy = clusterflux_core::NodeWorkPolicy::SystemTasksOnly;
    service
        .handle_signed_node_request_auto(CoordinatorRequest::ReportNodeCapabilities {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "system-only".to_owned(),
            capabilities,
            cached_environment_digests: Vec::new(),
            dependency_cache_digests: Vec::new(),
            source_snapshots: Vec::new(),
            artifact_locations: Vec::new(),
            online: true,
        })
        .unwrap();

    let response = service
        .handle_poll_node_assignment(
            "tenant".to_owned(),
            "project".to_owned(),
            "system-only".to_owned(),
            false,
            true,
            None,
        )
        .unwrap();
    assert!(matches!(
        response,
        CoordinatorResponse::NodeAssignment {
            assignment: None,
            ..
        }
    ));
    for request in [
        CoordinatorRequest::GetArtifactDataPlanePolicy {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "system-only".to_owned(),
        },
        CoordinatorRequest::PollDebugCommand {
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            node: "system-only".to_owned(),
            process: "process".to_owned(),
            task: "task".to_owned(),
        },
    ] {
        assert!(service
            .handle_signed_node_request_auto(request)
            .unwrap_err()
            .to_string()
            .contains("system-tasks-only node policy"));
    }
}

#[test]
fn project_secret_values_are_randomized_at_rest_and_absent_from_user_reads() {
    let mut service = service_with_project();
    service.enable_project_secrets_for_tests([7; 32]);
    let encoded = BASE64_STANDARD.encode(b"release-token-value");
    let short = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: SESSION.to_owned(),
            request: AuthenticatedCoordinatorRequest::SetProjectSecret {
                name: "TOO_SHORT".to_owned(),
                value_base64: BASE64_STANDARD.encode(b"short"),
            },
        })
        .unwrap_err();
    assert!(short.to_string().contains("16 through"));
    let set = || CoordinatorRequest::Authenticated {
        session_secret: SESSION.to_owned(),
        request: AuthenticatedCoordinatorRequest::SetProjectSecret {
            name: "GITHUB_TOKEN".to_owned(),
            value_base64: encoded.clone(),
        },
    };
    let response = service.handle_request(set()).unwrap();
    let response_json = serde_json::to_string(&response).unwrap();
    assert!(!response_json.contains(&encoded));
    assert!(!response_json.contains("release-token-value"));

    let key = (
        TenantId::from("tenant"),
        ProjectId::from("project"),
        "GITHUB_TOKEN".to_owned(),
    );
    let first = service
        .coordinator
        .durable_state()
        .encrypted_project_secrets
        .get(&key)
        .unwrap()
        .clone();
    assert_eq!(
        first.allowed_trusted_refs,
        ["refs/heads/main".to_owned(), "refs/tags/v*".to_owned(),]
    );
    assert_ne!(first.ciphertext_base64, encoded);
    service.handle_request(set()).unwrap();
    let second = service
        .coordinator
        .durable_state()
        .encrypted_project_secrets
        .get(&key)
        .unwrap();
    assert_ne!(first.nonce_base64, second.nonce_base64);
    assert_ne!(first.ciphertext_base64, second.ciphertext_base64);

    let listed = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: SESSION.to_owned(),
            request: AuthenticatedCoordinatorRequest::ListProjectSecrets,
        })
        .unwrap();
    let listed_json = serde_json::to_string(&listed).unwrap();
    assert!(listed_json.contains("GITHUB_TOKEN"));
    assert!(!listed_json.contains(&encoded));
    assert!(!listed_json.contains("release-token-value"));

    let revoked = service
        .handle_request(CoordinatorRequest::Authenticated {
            session_secret: SESSION.to_owned(),
            request: AuthenticatedCoordinatorRequest::RevokeProjectSecret {
                name: "GITHUB_TOKEN".to_owned(),
            },
        })
        .unwrap();
    assert!(serde_json::to_string(&revoked)
        .unwrap()
        .contains("revoked_at"));
}

#[test]
fn secret_authority_uses_explicit_request_and_capabilities_not_task_name() {
    let mut cache_task = test_task_spec_instance(
        "tenant",
        "project",
        "release",
        "cache_nix_package",
        "cache-nix",
        1,
        [
            Capability::Command,
            Capability::Network,
            Capability::Secrets,
        ],
    );
    cache_task
        .requested_secrets
        .push("cachix-auth-token".to_owned());

    assert!(
        super::super::secrets::task_declares_secret_materialization_authority(
            &cache_task,
            "cachix-auth-token"
        )
    );
    assert!(
        !super::super::secrets::task_declares_secret_materialization_authority(
            &cache_task,
            "github-release"
        )
    );

    for capability in [
        Capability::Command,
        Capability::Network,
        Capability::Secrets,
    ] {
        let mut incomplete_task = cache_task.clone();
        incomplete_task.required_capabilities.remove(&capability);
        assert!(
            !super::super::secrets::task_declares_secret_materialization_authority(
                &incomplete_task,
                "cachix-auth-token"
            )
        );
    }

    let legacy_refs = ["refs/heads/main".to_owned(), "refs/tags/v0.1.1".to_owned()];
    assert!(super::super::secrets::secret_ref_is_authorized(
        &legacy_refs,
        "refs/tags/v0.2.0"
    ));
    assert!(!super::super::secrets::secret_ref_is_authorized(
        &legacy_refs,
        "refs/tags/build-123456789abc"
    ));
    assert!(!super::super::secrets::secret_ref_is_authorized(
        &legacy_refs,
        "refs/tags/v0.2.0-rc.1"
    ));
}
