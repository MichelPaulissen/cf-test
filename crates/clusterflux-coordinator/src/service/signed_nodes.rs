use clusterflux_core::{
    AssignmentAuthority, NodeId, NodeSignedRequest, ProcessId, ProjectId, TaskInstanceId, TenantId,
};

use crate::{AssignmentKind, CoordinatorError, NodeScopeKey};

use super::task_registry::AssignmentMutationReplay;
use super::{CoordinatorRequest, CoordinatorResponse, CoordinatorService, CoordinatorServiceError};

impl CoordinatorService {
    pub(super) fn handle_signed_node_request(
        &mut self,
        signed_node: String,
        node_signature: NodeSignedRequest,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let request_kind = signed_node_request_kind(&request)?;
        let request_scope = signed_node_request_scope(&request)?;
        let assignment_authority = node_signature.assignment_authority.clone();
        let mutation_context = match &request {
            CoordinatorRequest::ReportSystemTask { result, .. } => {
                let clusterflux_protocol::SystemTaskOutput::CompileWorkflow { result } =
                    &result.result;
                Some((
                    ProcessId::from(result.run_id.as_str()),
                    TaskInstanceId::from("system-workflow-compiler"),
                    true,
                ))
            }
            CoordinatorRequest::ReportVfsMetadata { process, task, .. } => Some((
                ProcessId::new(process.clone()),
                TaskInstanceId::new(task.clone()),
                false,
            )),
            CoordinatorRequest::TaskCompleted { process, task, .. } => Some((
                ProcessId::new(process.clone()),
                TaskInstanceId::new(task.clone()),
                true,
            )),
            _ => None,
        };
        let operation_id = node_signature.operation_id.clone();
        let request_payload = serde_json::to_value(&request).map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "failed to canonicalize signed node request: {error}"
            ))
        })?;
        let payload_digest = clusterflux_core::signed_request_payload_digest(&request_payload);
        let signed_node = NodeId::try_new(signed_node).map_err(|error| {
            CoordinatorServiceError::Protocol(format!("invalid signed node identifier: {error}"))
        })?;
        if request_scope.node != signed_node {
            return Err(CoordinatorError::Unauthorized(
                "signed node request node does not match the wrapped request node".to_owned(),
            )
            .into());
        }
        self.authenticate_node_request(
            &request_scope,
            Some(node_signature),
            request_kind,
            &payload_digest,
        )?;
        if mutation_context.is_some() {
            let operation_id = operation_id.as_deref().ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    "terminal node mutation omitted its stable operation identifier".to_owned(),
                )
            })?;
            clusterflux_core::validate_opaque_token(operation_id, 128).map_err(|error| {
                CoordinatorServiceError::Protocol(format!(
                    "invalid terminal node operation identifier: {error}"
                ))
            })?;
        }
        if let (Some((process, task, _)), Some(operation_id), Some(authority)) = (
            mutation_context.as_ref(),
            operation_id.as_deref(),
            assignment_authority.as_ref(),
        ) {
            match super::TaskRegistry::assignment_mutation_replay(
                self.coordinator.durable_state(),
                &request_scope,
                authority,
                process,
                task,
                operation_id,
                &payload_digest,
            ) {
                AssignmentMutationReplay::Exact(response) => return Ok(*response),
                AssignmentMutationReplay::Conflict => {
                    return Err(CoordinatorServiceError::TerminalOperationConflict)
                }
                AssignmentMutationReplay::Missing => {}
            }
        }
        if self
            .node_registry
            .descriptor(&request_scope)
            .is_some_and(|descriptor| {
                descriptor.capabilities.work_policy
                    == clusterflux_core::NodeWorkPolicy::SystemTasksOnly
            })
            && !matches!(
                &request,
                CoordinatorRequest::ReportNodeCapabilities { .. }
                    | CoordinatorRequest::PollNodeAssignment { .. }
                    | CoordinatorRequest::AcknowledgeNodeAssignment { .. }
                    | CoordinatorRequest::ReportSystemTask { .. }
                    | CoordinatorRequest::BeginNodeDrain { .. }
                    | CoordinatorRequest::FinalizeNodeRelease { .. }
            )
        {
            return Err(CoordinatorError::Unauthorized(
                "system-tasks-only node policy forbids task, secret, artifact, source, and debug operations"
                    .to_owned(),
            )
            .into());
        }
        let terminal_process_authority = self.authorize_signed_assignment_request(
            &request_scope,
            &request,
            assignment_authority.as_ref(),
        )?;
        let response = match request {
            CoordinatorRequest::ReportNodeCapabilities {
                tenant,
                project,
                node,
                capabilities,
                cached_environment_digests,
                dependency_cache_digests,
                source_snapshots,
                artifact_locations,
                online,
            } => self.handle_report_node_capabilities(
                tenant,
                project,
                node,
                capabilities,
                cached_environment_digests,
                dependency_cache_digests,
                source_snapshots,
                artifact_locations,
                online,
            ),
            CoordinatorRequest::PollNodeAssignment {
                tenant,
                project,
                node,
                accept_system_tasks,
                accept_process_tasks,
                active_assignment,
            } => self.handle_poll_node_assignment(
                tenant,
                project,
                node,
                accept_system_tasks,
                accept_process_tasks,
                active_assignment,
            ),
            CoordinatorRequest::AcknowledgeNodeAssignment {
                tenant,
                project,
                node,
                assignment_id,
                lease_epoch,
            } => self.handle_acknowledge_node_assignment(
                tenant,
                project,
                node,
                assignment_id,
                lease_epoch,
                assignment_authority.clone(),
            ),
            CoordinatorRequest::ReportSystemTask {
                tenant,
                project,
                node,
                result,
            } => {
                let clusterflux_protocol::SystemTaskOutput::CompileWorkflow {
                    result: compilation,
                } = &result.result;
                if compilation.node.as_str() != node {
                    return Err(CoordinatorError::Unauthorized(
                        "system task result node differs from its signed request".to_owned(),
                    )
                    .into());
                }
                let record = self.report_system_task(result)?;
                if record.run.tenant.as_str() != tenant || record.run.project.as_str() != project {
                    return Err(CoordinatorError::Unauthorized(
                        "system task result is outside its signed scope".to_owned(),
                    )
                    .into());
                }
                Ok(CoordinatorResponse::SystemTaskRecorded { run: record.run })
            }
            CoordinatorRequest::PollTaskSecretGrant {
                tenant,
                project,
                node,
                process,
                task,
                secret_name,
            } => self.handle_poll_task_secret_grant(
                tenant,
                project,
                node,
                process,
                task,
                secret_name,
            ),
            CoordinatorRequest::GetArtifactDataPlanePolicy {
                tenant,
                project,
                node,
            } => self.handle_get_artifact_data_plane_policy(tenant, project, node),
            CoordinatorRequest::ReportIrohEndpointAdvertisement {
                tenant,
                project,
                node,
                advertisement,
            } => {
                self.handle_report_iroh_endpoint_advertisement(tenant, project, node, advertisement)
            }
            CoordinatorRequest::RequestArtifactInterchange {
                tenant,
                project,
                process,
                node,
                artifact,
                offset,
            } => self.handle_request_artifact_interchange(
                tenant, project, process, node, artifact, offset,
            ),
            CoordinatorRequest::PollArtifactProviderAssignment {
                tenant,
                project,
                node,
            } => self.handle_poll_artifact_provider_assignment(tenant, project, node),
            CoordinatorRequest::PollArtifactReceiverAssignment {
                tenant,
                project,
                node,
            } => self.handle_poll_artifact_receiver_assignment(tenant, project, node),
            CoordinatorRequest::AcknowledgeArtifactAssignment {
                tenant,
                project,
                node,
                transfer_id,
                role,
            } => self.handle_acknowledge_artifact_assignment(
                tenant,
                project,
                node,
                transfer_id,
                role,
            ),
            CoordinatorRequest::ReportArtifactInterchange {
                tenant,
                project,
                node,
                transfer_id,
                state,
                bytes_completed,
                path_kind,
                failure_code,
                verified_digest,
                verified_size,
            } => self.handle_report_artifact_interchange(
                tenant,
                project,
                node,
                transfer_id,
                state,
                bytes_completed,
                path_kind,
                failure_code,
                verified_digest,
                verified_size,
            ),
            CoordinatorRequest::ReleaseArtifact {
                tenant,
                project,
                process,
                node,
                task,
                artifact,
                digest,
                size_bytes,
            } => self.handle_release_artifact(
                tenant, project, process, node, task, artifact, digest, size_bytes,
            ),
            CoordinatorRequest::BeginNodeDrain {
                tenant,
                project,
                node,
                ephemeral,
                provider_deadline_epoch_seconds,
                soft_drain_deadline_epoch_seconds,
                hard_drain_deadline_epoch_seconds,
            } => self.handle_begin_node_drain(
                tenant,
                project,
                node,
                ephemeral,
                provider_deadline_epoch_seconds,
                soft_drain_deadline_epoch_seconds,
                hard_drain_deadline_epoch_seconds,
            ),
            CoordinatorRequest::FinalizeNodeRelease {
                tenant,
                project,
                node,
            } => self.handle_finalize_node_release(tenant, project, node),
            CoordinatorRequest::LaunchChildTask {
                tenant,
                project,
                process,
                node,
                parent_task,
                task_spec,
                wait_for_node,
                artifact_path,
                wasm_module_base64,
            } => self.handle_launch_child_task(
                tenant,
                project,
                process,
                node,
                parent_task,
                task_spec,
                wait_for_node,
                artifact_path,
                wasm_module_base64,
            ),
            CoordinatorRequest::JoinChildTask {
                tenant,
                project,
                process,
                node,
                parent_task,
                task,
            } => self.handle_join_child_task(tenant, project, process, node, parent_task, task),
            CoordinatorRequest::CompleteSourcePreparation {
                tenant,
                project,
                node,
                provider,
                source_snapshot,
            } => self.handle_complete_source_preparation(
                tenant,
                project,
                node,
                provider,
                source_snapshot,
            ),
            CoordinatorRequest::ReconnectNode {
                tenant,
                project,
                node,
                process,
                epoch,
            } => self.handle_reconnect_node(tenant, project, node, process, epoch),
            CoordinatorRequest::PollTaskControl {
                tenant,
                project,
                process,
                node,
                task,
                child_tasks,
            } => self.handle_poll_task_control(tenant, project, process, node, task, child_tasks),
            CoordinatorRequest::PollDebugCommand {
                tenant,
                project,
                process,
                node,
                task,
            } => self.handle_poll_debug_command(tenant, project, process, node, task),
            CoordinatorRequest::ReportDebugState {
                tenant,
                project,
                process,
                node,
                task,
                epoch,
                state,
                current_source_location,
                stack_frames,
                local_values,
                task_args,
                handles,
                command_status,
                recent_output,
                message,
            } => self.handle_report_debug_state(
                tenant,
                project,
                process,
                node,
                task,
                epoch,
                state,
                current_source_location,
                stack_frames,
                local_values,
                task_args,
                handles,
                command_status,
                recent_output,
                message,
            ),
            CoordinatorRequest::ReportDebugProbeHit {
                tenant,
                project,
                process,
                node,
                task,
                probe_symbol,
            } => self.handle_report_debug_probe_hit(
                tenant,
                project,
                process,
                node,
                task,
                probe_symbol,
            ),
            CoordinatorRequest::ReportTaskLog {
                tenant,
                project,
                process,
                node,
                task,
                stdout_bytes,
                stderr_bytes,
                stdout_tail,
                stderr_tail,
                stdout_truncated,
                stderr_truncated,
                backpressured,
            } => self.handle_report_task_log(
                tenant,
                project,
                process,
                node,
                task,
                stdout_bytes,
                stderr_bytes,
                stdout_tail,
                stderr_tail,
                stdout_truncated,
                stderr_truncated,
                backpressured,
            ),
            CoordinatorRequest::ReportTaskLogChunk {
                tenant,
                project,
                process,
                node,
                task,
                stream,
                offset,
                source_bytes,
                text,
                truncated,
            } => self.handle_report_task_log_chunk(
                tenant,
                project,
                process,
                node,
                task,
                stream,
                offset,
                source_bytes,
                text,
                truncated,
            ),
            CoordinatorRequest::ReportVfsMetadata {
                tenant,
                project,
                process,
                node,
                task,
                artifact_path,
                artifact_digest,
                artifact_size_bytes,
                large_bytes_uploaded,
            } => self.handle_report_vfs_metadata(
                tenant,
                project,
                process,
                node,
                task,
                artifact_path,
                artifact_digest,
                artifact_size_bytes,
                large_bytes_uploaded,
            ),
            CoordinatorRequest::TaskCompleted {
                tenant,
                project,
                process,
                node,
                task,
                terminal_state,
                status_code,
                stdout_bytes,
                stderr_bytes,
                stdout_tail,
                stderr_tail,
                stdout_truncated,
                stderr_truncated,
                artifact_path,
                artifact_digest,
                artifact_size_bytes,
                result,
            } => self.handle_task_completed(
                tenant,
                project,
                process,
                node,
                task,
                terminal_state,
                status_code,
                stdout_bytes,
                stderr_bytes,
                stdout_tail,
                stderr_tail,
                stdout_truncated,
                stderr_truncated,
                artifact_path,
                artifact_digest,
                artifact_size_bytes,
                result,
                super::TaskCompletionOrigin::SignedNode,
            ),
            _ => self.reject_unsigned_node_request(),
        };
        if let Ok(committed_response) = &response {
            if let (Some((process, task, terminal)), Some(operation_id), Some(authority)) = (
                mutation_context,
                operation_id,
                assignment_authority.as_ref(),
            ) {
                if !super::TaskRegistry::record_assignment_mutation(
                    self.coordinator.durable_state_mut(),
                    authority,
                    process,
                    task,
                    operation_id,
                    payload_digest,
                    committed_response,
                ) {
                    return Err(CoordinatorServiceError::Protocol(
                        "terminal node mutation could not be recorded against its active assignment"
                            .to_owned(),
                    ));
                }
                if terminal {
                    let now = self.current_epoch_seconds()?;
                    super::TaskRegistry::terminalize_active_assignment(
                        self.coordinator.durable_state_mut(),
                        authority,
                        now,
                        true,
                    );
                }
                self.persist_durable_state()?;
            } else if let Some(authority) = terminal_process_authority {
                let now = self.current_epoch_seconds()?;
                super::TaskRegistry::terminalize_active_assignment(
                    self.coordinator.durable_state_mut(),
                    &authority,
                    now,
                    true,
                );
                self.persist_durable_state()?;
            }
        }
        response
    }

    fn authorize_signed_assignment_request(
        &mut self,
        scope: &NodeScopeKey,
        request: &CoordinatorRequest,
        authority: Option<&AssignmentAuthority>,
    ) -> Result<Option<AssignmentAuthority>, CoordinatorServiceError> {
        let process_target = match request {
            CoordinatorRequest::PollTaskSecretGrant { process, task, .. }
            | CoordinatorRequest::PollTaskControl { process, task, .. }
            | CoordinatorRequest::PollDebugCommand { process, task, .. }
            | CoordinatorRequest::ReportDebugState { process, task, .. }
            | CoordinatorRequest::ReportDebugProbeHit { process, task, .. }
            | CoordinatorRequest::ReportTaskLog { process, task, .. }
            | CoordinatorRequest::ReportTaskLogChunk { process, task, .. }
            | CoordinatorRequest::ReportVfsMetadata { process, task, .. } => Some((
                ProcessId::new(process.clone()),
                Some(TaskInstanceId::new(task.clone())),
                false,
            )),
            CoordinatorRequest::TaskCompleted { process, task, .. } => Some((
                ProcessId::new(process.clone()),
                Some(TaskInstanceId::new(task.clone())),
                true,
            )),
            CoordinatorRequest::LaunchChildTask {
                process,
                parent_task,
                ..
            }
            | CoordinatorRequest::JoinChildTask {
                process,
                parent_task,
                ..
            } => Some((
                ProcessId::new(process.clone()),
                Some(TaskInstanceId::new(parent_task.clone())),
                false,
            )),
            CoordinatorRequest::ReleaseArtifact { process, task, .. } => Some((
                ProcessId::new(process.clone()),
                Some(TaskInstanceId::new(task.clone())),
                false,
            )),
            _ => None,
        };
        let Some((process, task, terminal)) = process_target else {
            return Ok(None);
        };
        let authority = authority.ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "assignment-owned node request omitted its signed assignment authority".to_owned(),
            )
        })?;
        let now = self.current_epoch_seconds()?;
        let active = super::TaskRegistry::active_assignment(
            self.coordinator.durable_state(),
            &authority.assignment_id,
        )
        .cloned()
        .ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "assignment-owned node request refers to stale or terminal authority".to_owned(),
            )
        })?;
        let AssignmentKind::ProcessTask {
            process: active_process,
            task: active_task,
        } = &active.kind
        else {
            return Err(CoordinatorError::Unauthorized(
                "process task request used system-assignment authority".to_owned(),
            )
            .into());
        };
        if active_process != &process || task.as_ref().is_some_and(|task| task != active_task) {
            return Err(CoordinatorError::Unauthorized(
                "assignment authority does not own the requested process task".to_owned(),
            )
            .into());
        }
        if !super::TaskRegistry::authorize_active_assignment(
            self.coordinator.durable_state_mut(),
            scope,
            authority,
            now,
            180,
        ) {
            return Err(CoordinatorError::Unauthorized(
                "assignment authority is stale, expired, or belongs to another node".to_owned(),
            )
            .into());
        }
        Ok(terminal.then(|| authority.clone()))
    }

    pub(super) fn reject_unsigned_node_request(
        &self,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        Err(CoordinatorError::Unauthorized(
            "node-originated request requires signed_node envelope proof".to_owned(),
        )
        .into())
    }
}

fn signed_node_request_kind(
    request: &CoordinatorRequest,
) -> Result<&'static str, CoordinatorServiceError> {
    match request {
        CoordinatorRequest::ReportNodeCapabilities { .. } => Ok("report_node_capabilities"),
        CoordinatorRequest::PollNodeAssignment { .. } => Ok("poll_node_assignment"),
        CoordinatorRequest::AcknowledgeNodeAssignment { .. } => Ok("acknowledge_node_assignment"),
        CoordinatorRequest::ReportSystemTask { .. } => Ok("report_system_task"),
        CoordinatorRequest::PollTaskSecretGrant { .. } => Ok("poll_task_secret_grant"),
        CoordinatorRequest::GetArtifactDataPlanePolicy { .. } => {
            Ok("get_artifact_data_plane_policy")
        }
        CoordinatorRequest::ReportIrohEndpointAdvertisement { .. } => {
            Ok("report_iroh_endpoint_advertisement")
        }
        CoordinatorRequest::RequestArtifactInterchange { .. } => Ok("request_artifact_interchange"),
        CoordinatorRequest::PollArtifactProviderAssignment { .. } => {
            Ok("poll_artifact_provider_assignment")
        }
        CoordinatorRequest::PollArtifactReceiverAssignment { .. } => {
            Ok("poll_artifact_receiver_assignment")
        }
        CoordinatorRequest::AcknowledgeArtifactAssignment { .. } => {
            Ok("acknowledge_artifact_assignment")
        }
        CoordinatorRequest::ReportArtifactInterchange { .. } => Ok("report_artifact_interchange"),
        CoordinatorRequest::ReleaseArtifact { .. } => Ok("release_artifact"),
        CoordinatorRequest::BeginNodeDrain { .. } => Ok("begin_node_drain"),
        CoordinatorRequest::FinalizeNodeRelease { .. } => Ok("finalize_node_release"),
        CoordinatorRequest::LaunchChildTask { .. } => Ok("launch_child_task"),
        CoordinatorRequest::JoinChildTask { .. } => Ok("join_child_task"),
        CoordinatorRequest::CompleteSourcePreparation { .. } => Ok("complete_source_preparation"),
        CoordinatorRequest::ReconnectNode { .. } => Ok("reconnect_node"),
        CoordinatorRequest::PollTaskControl { .. } => Ok("poll_task_control"),
        CoordinatorRequest::PollDebugCommand { .. } => Ok("poll_debug_command"),
        CoordinatorRequest::ReportDebugState { .. } => Ok("report_debug_state"),
        CoordinatorRequest::ReportDebugProbeHit { .. } => Ok("report_debug_probe_hit"),
        CoordinatorRequest::ReportTaskLog { .. } => Ok("report_task_log"),
        CoordinatorRequest::ReportTaskLogChunk { .. } => Ok("report_task_log_chunk"),
        CoordinatorRequest::ReportVfsMetadata { .. } => Ok("report_vfs_metadata"),
        CoordinatorRequest::TaskCompleted { .. } => Ok("task_completed"),
        _ => Err(CoordinatorError::Unauthorized(
            "signed_node envelope only accepts node-originated coordinator requests".to_owned(),
        )
        .into()),
    }
}

fn signed_node_request_scope(
    request: &CoordinatorRequest,
) -> Result<NodeScopeKey, CoordinatorServiceError> {
    match request {
        CoordinatorRequest::ReportNodeCapabilities {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportSystemTask {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::PollTaskSecretGrant {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::GetArtifactDataPlanePolicy {
            tenant,
            project,
            node,
        }
        | CoordinatorRequest::ReportIrohEndpointAdvertisement {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::RequestArtifactInterchange {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::PollArtifactProviderAssignment {
            tenant,
            project,
            node,
        }
        | CoordinatorRequest::PollArtifactReceiverAssignment {
            tenant,
            project,
            node,
        }
        | CoordinatorRequest::AcknowledgeArtifactAssignment {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportArtifactInterchange {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReleaseArtifact {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::BeginNodeDrain {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::FinalizeNodeRelease {
            tenant,
            project,
            node,
        }
        | CoordinatorRequest::PollNodeAssignment {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::AcknowledgeNodeAssignment {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::LaunchChildTask {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::JoinChildTask {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::CompleteSourcePreparation {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReconnectNode {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::PollTaskControl {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::PollDebugCommand {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportDebugState {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportDebugProbeHit {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportTaskLog {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportTaskLogChunk {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::ReportVfsMetadata {
            tenant,
            project,
            node,
            ..
        }
        | CoordinatorRequest::TaskCompleted {
            tenant,
            project,
            node,
            ..
        } => node_scope_from_strings(tenant, project, node),
        _ => Err(CoordinatorError::Unauthorized(
            "signed_node envelope only accepts node-originated coordinator requests".to_owned(),
        )
        .into()),
    }
}

fn node_scope_from_strings(
    tenant: &str,
    project: &str,
    node: &str,
) -> Result<NodeScopeKey, CoordinatorServiceError> {
    let tenant = TenantId::try_new(tenant.to_owned()).map_err(|error| {
        CoordinatorServiceError::Protocol(format!("invalid wrapped tenant identifier: {error}"))
    })?;
    let project = ProjectId::try_new(project.to_owned()).map_err(|error| {
        CoordinatorServiceError::Protocol(format!("invalid wrapped project identifier: {error}"))
    })?;
    let node = NodeId::try_new(node.to_owned()).map_err(|error| {
        CoordinatorServiceError::Protocol(format!("invalid wrapped node identifier: {error}"))
    })?;
    Ok(NodeScopeKey::new(tenant, project, node))
}
