use std::collections::BTreeMap;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{
    AgentSignedRequest, ArtifactId, CheckpointBoundary, CredentialKind, DefaultScheduler, Digest,
    NodeDescriptor, NodeId, Placement, PlacementError, PlacementRequest, ProcessId, ProjectId,
    Scheduler, TaskBoundaryValue, TaskCheckpoint, TaskDispatch, TaskInstanceId, TaskSpec, TenantId,
    VfsManifest, VfsObject, VfsPath, WasmTaskInvocation,
};

use crate::CoordinatorError;

use super::keys::{process_control_key, task_control_key, task_restart_key, TaskRestartKey};
use super::{
    CoordinatorResponse, CoordinatorService, CoordinatorServiceError, TaskAssignment, WorkflowActor,
};

use super::processes::*;
use super::protocol::{TaskAttemptSnapshot, TaskAttemptState};

fn select_task_placement(
    candidates: &[Placement],
    active_by_node: &BTreeMap<NodeId, usize>,
) -> Option<Placement> {
    candidates
        .iter()
        .min_by(|left, right| {
            right
                .score
                .cmp(&left.score)
                .then_with(|| {
                    active_by_node
                        .get(&left.node)
                        .copied()
                        .unwrap_or_default()
                        .cmp(&active_by_node.get(&right.node).copied().unwrap_or_default())
                })
                .then_with(|| left.node.cmp(&right.node))
        })
        .cloned()
}

impl CoordinatorService {
    pub(super) fn task_placement_source_snapshot(task_spec: &TaskSpec) -> Option<Digest> {
        if task_spec.source_revision.is_some() {
            return None;
        }
        task_spec.source_snapshot.clone()
    }

    fn place_workflow_task(
        &self,
        nodes: &[NodeDescriptor],
        request: &PlacementRequest,
    ) -> Result<Placement, PlacementError> {
        let candidates = nodes
            .iter()
            .filter_map(|node| {
                DefaultScheduler
                    .place(std::slice::from_ref(node), request)
                    .ok()
            })
            .collect::<Vec<_>>();
        if candidates.is_empty() {
            return DefaultScheduler.place(nodes, request);
        }
        let active_by_node = self
            .task_registry
            .active_tasks()
            .filter(|(tenant, project, _, _, _)| {
                tenant == &request.tenant && project == &request.project
            })
            .fold(BTreeMap::<NodeId, usize>::new(), |mut counts, key| {
                *counts.entry(key.3.clone()).or_default() += 1;
                counts
            });
        let mut selected = select_task_placement(&candidates, &active_by_node)
            .expect("one or more compatible task-placement candidates should remain");
        let selected_load = active_by_node
            .get(&selected.node)
            .copied()
            .unwrap_or_default();
        if candidates.iter().any(|candidate| {
            candidate.score == selected.score
                && active_by_node
                    .get(&candidate.node)
                    .copied()
                    .unwrap_or_default()
                    > selected_load
        }) {
            selected.reasons.push(format!(
                "least active equal-locality node ({selected_load} active assignment(s))"
            ));
        }
        Ok(selected)
    }

    pub(super) fn capture_task_restart_checkpoint(
        &mut self,
        assignment: &TaskAssignment,
    ) -> Result<(), CoordinatorServiceError> {
        let task_spec = &assignment.task_spec;
        let environment_digest = task_spec.environment_digest.clone().unwrap_or_else(|| {
            task_spec.environment.as_ref().map_or_else(
                || Digest::sha256("clusterflux.environment.unconstrained.v1"),
                |environment| {
                    Digest::sha256(
                        serde_json::to_vec(environment)
                            .expect("serializable environment requirements"),
                    )
                },
            )
        });
        let task_entrypoint = match &task_spec.dispatch {
            clusterflux_core::TaskDispatch::CoordinatorNodeWasm { export, .. } => export
                .clone()
                .or_else(|| assignment_task_descriptor(assignment)?.get("export")?.as_str().map(str::to_owned))
                .ok_or_else(|| {
                    CoordinatorServiceError::Protocol(format!(
                        "cannot capture restart checkpoint for task `{}`: bundle descriptor omitted its Wasm export",
                        task_spec.task_definition
                    ))
                })?,
        };
        let mut objects = BTreeMap::new();
        let mut checkpoint_artifacts = Vec::new();
        let mut missing_required_artifact = false;
        for artifact in &task_spec.required_artifacts {
            let Some(metadata) =
                self.artifact_registry
                    .metadata(&assignment.tenant, &assignment.project, artifact)
            else {
                missing_required_artifact = true;
                continue;
            };
            if metadata.retaining_nodes.is_empty() {
                missing_required_artifact = true;
                continue;
            }
            let path = VfsPath::new(format!("/vfs/artifacts/{artifact}"))
                .map_err(|error| CoordinatorServiceError::InvalidArtifactPath(error.to_string()))?;
            objects.insert(
                path.clone(),
                VfsObject {
                    path,
                    digest: metadata.digest.clone(),
                    size: metadata.size,
                    producer: metadata.producer_task.clone(),
                    node: metadata.producer_node.clone(),
                },
            );
            checkpoint_artifacts.push(artifact.clone());
        }
        let checkpoint = TaskCheckpoint {
            task: assignment.task.clone(),
            boundary: CheckpointBoundary {
                task_entrypoint,
                serialized_args: Digest::sha256(serde_json::to_vec(&task_spec.args)?),
                environment_digest,
                vfs_epoch: task_spec.vfs_epoch,
                task_abi: assignment_task_compatibility(assignment)
                    .unwrap_or(Digest::sha256(serde_json::to_vec(&task_spec.dispatch)?)),
            },
            vfs_manifest: VfsManifest {
                epoch: task_spec.vfs_epoch,
                producer: assignment.task.clone(),
                node: assignment.node.clone(),
                objects,
                large_bytes_uploaded: false,
            },
            depends_on_live_stack: false,
            depends_on_live_socket: false,
            depends_on_ephemeral_artifact_durability: missing_required_artifact,
        };
        let key = task_restart_key(
            &assignment.tenant,
            &assignment.project,
            &assignment.process,
            &assignment.task,
        );
        let removed = self.task_registry.store_checkpoint(
            key.clone(),
            TaskRestartCheckpoint {
                checkpoint,
                assignment: assignment.clone(),
            },
            super::MAX_RESTART_CHECKPOINTS_PER_PROCESS,
            super::MAX_RESTART_CHECKPOINTS_TOTAL,
        );
        for removed_key in removed {
            self.artifact_registry.release_restart_checkpoint_holds(
                &removed_key.0,
                &removed_key.1,
                &removed_key.2,
                &removed_key.3,
            );
        }
        let now = self.current_epoch_seconds()?;
        for artifact in checkpoint_artifacts {
            let _ = self.artifact_registry.add_hold(
                &assignment.tenant,
                &assignment.project,
                &artifact,
                clusterflux_core::ArtifactHoldReason::RestartCheckpoint {
                    process: assignment.process.clone(),
                    task: assignment.task.clone(),
                },
                now,
            );
        }
        Ok(())
    }

    pub(super) fn remove_task_restart_checkpoint(&mut self, key: &TaskRestartKey) -> bool {
        let removed = self.task_registry.remove_checkpoint(key);
        if removed {
            self.artifact_registry
                .release_restart_checkpoint_holds(&key.0, &key.1, &key.2, &key.3);
        }
        removed
    }

    pub(super) fn handle_schedule_task(
        &mut self,
        tenant: String,
        project: String,
        environment: Option<clusterflux_core::EnvironmentRequirements>,
        environment_digest: Option<Digest>,
        required_capabilities: Vec<clusterflux_core::Capability>,
        dependency_cache: Option<Digest>,
        source_snapshot: Option<Digest>,
        required_artifacts: Vec<String>,
        prefer_node: Option<String>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let request = PlacementRequest {
            tenant: tenant.clone(),
            project: project.clone(),
            environment,
            environment_digest,
            environment_cache_required: false,
            required_capabilities: required_capabilities.into_iter().collect(),
            dependency_cache,
            source_snapshot,
            required_artifacts: required_artifacts
                .into_iter()
                .map(ArtifactId::new)
                .collect(),
            quota_available: self
                .quota
                .can_charge_workflow_spawn(&tenant, &project, now_epoch_seconds)
                .is_ok(),
            policy_allowed: self.admission.workflow_placement_allowed,
            prefer_node: prefer_node.map(NodeId::new),
        };
        let nodes = self.live_node_descriptors();
        let placement = DefaultScheduler.place(&nodes, &request)?;
        Ok(CoordinatorResponse::TaskPlacement { placement })
    }

    pub(super) fn handle_launch_task(
        &mut self,
        tenant: String,
        project: String,
        actor_user: Option<String>,
        actor_agent: Option<String>,
        agent_public_key_fingerprint: Option<Digest>,
        agent_signature: Option<AgentSignedRequest>,
        request_payload_digest: Option<&Digest>,
        task_spec: TaskSpec,
        _wait_for_node: bool,
        _artifact_path: String,
        wasm_module_base64: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        task_spec
            .validate_boundary_authority()
            .map_err(CoordinatorServiceError::Protocol)?;
        if matches!(
            &task_spec.dispatch,
            TaskDispatch::CoordinatorNodeWasm {
                abi: clusterflux_core::WasmExportAbi::EntrypointV1,
                ..
            }
        ) {
            return self.handle_launch_coordinator_main(
                tenant,
                project,
                actor_user,
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature,
                request_payload_digest,
                task_spec,
                wasm_module_base64,
            );
        }
        Err(CoordinatorError::Unauthorized(
            "external callers may launch only EntrypointV1; TaskV1 requires an authenticated live parent runtime or validated restart"
                .to_owned(),
        )
        .into())
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_launch_child_task(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        parent_task: String,
        task_spec: TaskSpec,
        wait_for_node: bool,
        artifact_path: String,
        wasm_module_base64: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let parent_task = TaskInstanceId::new(parent_task);
        if task_spec.process != process {
            return Err(CoordinatorError::Unauthorized(
                "child task must remain in its parent virtual process".to_owned(),
            )
            .into());
        }
        if !matches!(
            task_spec.dispatch,
            TaskDispatch::CoordinatorNodeWasm {
                abi: clusterflux_core::WasmExportAbi::TaskV1,
                ..
            }
        ) {
            return Err(CoordinatorError::Unauthorized(
                "child task launch requires the TaskV1 ABI".to_owned(),
            )
            .into());
        }
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        let parent_key = task_control_key(&tenant, &project, &process, &node, &parent_task);
        if !self.task_registry.is_active(&parent_key) {
            return Err(CoordinatorError::Unauthorized(
                "child task launch requires a currently active parent task on the signed node"
                    .to_owned(),
            )
            .into());
        }
        let actor = WorkflowActor {
            kind: "task".to_owned(),
            user: None,
            agent: None,
            credential_kind: CredentialKind::TaskCredential,
            public_key_fingerprint: None,
            authenticated_without_browser: true,
            scopes: vec!["process:spawn-child".to_owned()],
        };
        self.handle_launch_task_with_actor(
            tenant,
            project,
            actor,
            task_spec,
            wait_for_node,
            artifact_path,
            wasm_module_base64,
        )
    }

    pub(super) fn handle_launch_task_with_actor(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        actor: WorkflowActor,
        task_spec: TaskSpec,
        wait_for_node: bool,
        artifact_path: String,
        wasm_module_base64: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        task_spec
            .validate_boundary_authority()
            .map_err(CoordinatorServiceError::Protocol)?;
        if task_spec.tenant != tenant || task_spec.project != project {
            return Err(CoordinatorError::Unauthorized(
                "task specification is outside the authenticated tenant/project scope".to_owned(),
            )
            .into());
        }
        if !task_spec.product_mode_uses_remote_dispatch() {
            return Err(CoordinatorError::Unauthorized(
                "task specification must use the Wasm coordinator/node dispatch ABI".to_owned(),
            )
            .into());
        }
        if task_spec
            .environment_id
            .as_deref()
            .is_some_and(|environment| environment.trim().is_empty() || environment.len() > 128)
        {
            return Err(CoordinatorError::Unauthorized(
                "task specification environment id is invalid".to_owned(),
            )
            .into());
        }
        let process = task_spec.process.clone();
        let task = task_spec.task_instance.clone();
        let active = self
            .coordinator
            .active_process(&tenant, &project, &process)
            .cloned()
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "task launch requires an active coordinator-side virtual process".to_owned(),
                )
            })?;
        debug_assert_eq!(active.tenant, tenant);
        debug_assert_eq!(active.project, project);
        if self
            .process_registry
            .is_cancelled(&process_control_key(&tenant, &project, &process))
        {
            return Err(CoordinatorError::Unauthorized(
                "task launch is blocked because the virtual process is cancelling".to_owned(),
            )
            .into());
        }
        if self.task_instance_exists(&tenant, &project, &process, &task) {
            return Err(CoordinatorServiceError::Protocol(format!(
                "task instance {task} already exists in virtual process {process}; every spawn must use a fresh task-instance id"
            )));
        }
        let in_flight = self
            .task_registry
            .in_flight_count(&tenant, &project, &process);
        if in_flight >= super::MAX_IN_FLIGHT_TASKS_PER_PROCESS {
            return Err(CoordinatorServiceError::Protocol(format!(
                "virtual process task limit of {} reached; join or cancel existing work before spawning more",
                super::MAX_IN_FLIGHT_TASKS_PER_PROCESS
            )));
        }
        if task_spec.vfs_epoch != active.coordinator_epoch {
            return Err(CoordinatorError::Unauthorized(format!(
                "task specification VFS epoch {} does not match active process epoch {}",
                task_spec.vfs_epoch, active.coordinator_epoch
            ))
            .into());
        }
        let bundle_digest = task_spec.bundle_digest.as_ref().ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "Wasm task specification is missing its bundle digest".to_owned(),
            )
        })?;
        if !bundle_digest.is_valid_sha256() {
            return Err(CoordinatorError::Unauthorized(
                "Wasm task specification has an invalid bundle digest".to_owned(),
            )
            .into());
        }
        let module = BASE64_STANDARD
            .decode(&wasm_module_base64)
            .map_err(|error| {
                CoordinatorServiceError::Protocol(format!(
                    "Wasm task module is not valid base64: {error}"
                ))
            })?;
        let actual_digest = Digest::sha256(&module);
        if &actual_digest != bundle_digest {
            return Err(CoordinatorError::Unauthorized(format!(
                "Wasm task module digest does not match bundle digest: expected {bundle_digest}, actual {actual_digest}"
            ))
            .into());
        }
        WasmTaskInvocation::new(
            task_spec.task_definition.clone(),
            task.clone(),
            task_spec.args.clone(),
        )
        .validate()
        .map_err(CoordinatorServiceError::Protocol)?;
        for artifact in &task_spec.required_artifacts {
            let metadata = self
                .artifact_registry
                .metadata(&tenant, &project, artifact)
                .ok_or_else(|| {
                    CoordinatorError::Unauthorized(format!(
                        "required artifact {artifact} is unavailable or has expired in this tenant/project scope"
                    ))
                })?;
            if metadata.retaining_nodes.is_empty() {
                return Err(CoordinatorError::Unauthorized(format!(
                    "required artifact {artifact} has no retaining node"
                ))
                .into());
            }
        }
        VfsPath::new(&artifact_path)
            .map_err(|error| CoordinatorServiceError::InvalidArtifactPath(error.to_string()))?;
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let trusted_secret_node = if task_spec.requested_secrets.is_empty() {
            None
        } else {
            Some(
                self.coordinator
                    .durable_state()
                    .trusted_secret_nodes
                    .get(&(tenant.clone(), project.clone()))
                    .cloned()
                    .ok_or_else(|| {
                        CoordinatorError::Unauthorized(
                            "task requests project secrets, but no trusted secret node is configured"
                                .to_owned(),
                        )
                    })?,
            )
        };
        self.quota
            .can_charge_workflow_spawn(&tenant, &project, now_epoch_seconds)?;
        let request = PlacementRequest {
            tenant: tenant.clone(),
            project: project.clone(),
            environment: task_spec.environment.clone(),
            environment_digest: task_spec.environment_digest.clone(),
            environment_cache_required: task_spec.environment_id.is_some()
                && (task_spec.environment.is_none() || task_spec.source_revision.is_some()),
            required_capabilities: task_spec.required_capabilities.clone(),
            dependency_cache: task_spec.dependency_cache.clone(),
            // An immutable repository revision can be materialized by a
            // SourceGit node. A snapshot-only local run cannot: keep its exact
            // digest as a hard placement constraint so an unrelated checkout
            // never claims the task merely because it has Git or Iroh.
            // A genuinely source-less child has no source placement constraint.
            // Source-using children carry their exact snapshot in the TaskSpec.
            source_snapshot: Self::task_placement_source_snapshot(&task_spec),
            required_artifacts: task_spec.required_artifacts.iter().cloned().collect(),
            quota_available: self
                .quota
                .can_charge_workflow_spawn(&tenant, &project, now_epoch_seconds)
                .is_ok(),
            policy_allowed: self.admission.workflow_placement_allowed,
            prefer_node: trusted_secret_node.clone(),
        };
        let mut nodes = self.live_node_descriptors();
        if let Some(trusted) = &trusted_secret_node {
            nodes.retain(|node| &node.id == trusted);
        }
        let placement = match self.place_workflow_task(&nodes, &request) {
            Ok(placement) => placement,
            Err(err) if wait_for_node => {
                let reason = if err.message.is_empty() {
                    "waiting for any capable node".to_owned()
                } else {
                    err.message
                };
                let reason = super::processes::bounded_waiting_reason(&reason);
                let charged_spawns =
                    self.quota
                        .charge_workflow_spawn(&tenant, &project, now_epoch_seconds)?;
                self.begin_task_attempt(&task_spec, None, Some(&artifact_path), true)?;
                let attempt_key = task_restart_key(
                    &task_spec.tenant,
                    &task_spec.project,
                    &task_spec.process,
                    &task_spec.task_instance,
                );
                self.task_registry
                    .update_current_attempt(&attempt_key, |attempt| {
                        attempt.command_state = Some("waiting_for_node".to_owned());
                        attempt.waiting_reason = Some(reason.clone());
                    });
                self.task_registry.push_pending_launch(PendingTaskLaunch {
                    tenant: tenant.clone(),
                    project: project.clone(),
                    process: process.clone(),
                    task: task.clone(),
                    request,
                    epoch: active.coordinator_epoch,
                    artifact_path,
                    task_spec,
                    wasm_module_base64,
                    offer_epoch: 1,
                    waiting_reason: reason.clone(),
                });
                self.record_automated_process_waiting_reason(
                    &tenant,
                    &project,
                    &process,
                    Some(&reason),
                );
                let queued_tasks = self
                    .task_registry
                    .queued_count_for_process(&tenant, &project, &process);
                return Ok(CoordinatorResponse::TaskQueued {
                    process,
                    task,
                    actor,
                    reason,
                    charged_spawns,
                    queued_tasks,
                });
            }
            Err(err) => return Err(err.into()),
        };
        let charged_spawns =
            self.quota
                .charge_workflow_spawn(&tenant, &project, now_epoch_seconds)?;
        let attempt_id = self.begin_task_attempt(
            &task_spec,
            Some(placement.node.clone()),
            Some(&artifact_path),
            true,
        )?;
        let owner_identity = format!(
            "process-task\0{}\0{}\0{}\0{}",
            tenant, project, process, task
        );
        let authority = super::TaskRegistry::offer_active_assignment(
            self.coordinator.durable_state_mut(),
            crate::AssignmentKind::ProcessTask {
                process: process.clone(),
                task: task.clone(),
            },
            tenant.clone(),
            project.clone(),
            placement.node.clone(),
            attempt_id.clone(),
            1,
            now_epoch_seconds,
            super::processes::NODE_ASSIGNMENT_OFFER_SECONDS,
            &owner_identity,
        );
        let assignment = TaskAssignment {
            assignment_id: authority.assignment_id,
            attempt_id,
            offer_epoch: authority.offer_epoch,
            offer_expires_at_epoch_seconds: now_epoch_seconds
                .saturating_add(super::processes::NODE_ASSIGNMENT_OFFER_SECONDS),
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task: task.clone(),
            node: placement.node.clone(),
            epoch: active.coordinator_epoch,
            artifact_path,
            task_spec,
            wasm_module_base64,
        };
        self.capture_task_restart_checkpoint(&assignment)?;
        let task_key = task_control_key(&tenant, &project, &process, &placement.node, &task);
        self.task_registry
            .set_placement(task_key.clone(), placement.clone());
        self.task_registry.activate(task_key);
        for artifact in &assignment.task_spec.required_artifacts {
            let _ = self.artifact_registry.add_hold(
                &assignment.tenant,
                &assignment.project,
                artifact,
                clusterflux_core::ArtifactHoldReason::ConsumerTask {
                    process: assignment.process.clone(),
                    task: assignment.task.clone(),
                },
                now_epoch_seconds,
            );
        }
        self.task_registry.enqueue_assignment(assignment.clone());
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::TaskLaunched {
            process,
            task,
            actor,
            placement,
            assignment: Box::new(assignment),
            charged_spawns,
        })
    }

    fn task_instance_exists(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task_instance: &clusterflux_core::TaskInstanceId,
    ) -> bool {
        self.task_registry
            .task_instance_exists(tenant, project, process, task_instance)
    }

    pub(super) fn begin_task_attempt(
        &mut self,
        task_spec: &TaskSpec,
        node: Option<NodeId>,
        artifact_path: Option<&str>,
        queued: bool,
    ) -> Result<String, CoordinatorServiceError> {
        let key = task_restart_key(
            &task_spec.tenant,
            &task_spec.project,
            &task_spec.process,
            &task_spec.task_instance,
        );
        let attempt_id = clusterflux_core::generate_opaque_token("ta")
            .map_err(CoordinatorServiceError::Protocol)?;
        let mut argument_summary = task_spec
            .args
            .iter()
            .map(|argument| {
                let mut value = serde_json::to_string(argument)
                    .unwrap_or_else(|_| "<invalid canonical argument>".to_owned());
                value.truncate(value.len().min(1024));
                value
            })
            .collect::<Vec<_>>();
        argument_summary.truncate(64);
        let mut handle_summary = task_spec
            .required_artifacts
            .iter()
            .map(|artifact| format!("artifact:{artifact}"))
            .collect::<Vec<_>>();
        for argument in &task_spec.args {
            if let TaskBoundaryValue::Structured(boundary) = argument {
                handle_summary.extend(boundary.handles.iter().map(|handle| format!("{handle:?}")));
            }
        }
        handle_summary.truncate(256);
        let snapshot = TaskAttemptSnapshot {
            process: task_spec.process.clone(),
            task: task_spec.task_instance.clone(),
            attempt_id: attempt_id.clone(),
            attempt_number: 0,
            task_definition: task_spec.task_definition.clone(),
            display_name: task_spec.task_definition.as_str().replace(['_', '-'], " "),
            state: if queued {
                TaskAttemptState::Queued
            } else {
                TaskAttemptState::Running
            },
            current: true,
            node,
            environment_id: task_spec.environment_id.clone(),
            environment_digest: task_spec.environment_digest.clone(),
            argument_summary,
            handle_summary,
            command_state: Some(if queued { "queued" } else { "running" }.to_owned()),
            waiting_reason: None,
            vfs_checkpoint: format!("vfs-epoch:{}", task_spec.vfs_epoch),
            probe_symbol: None,
            source_path: None,
            source_line: None,
            restart_compatible: true,
            failure_policy: task_spec.failure_policy,
            artifact_path: artifact_path.and_then(|path| VfsPath::new(path).ok()),
            artifact_digest: None,
            artifact_size_bytes: None,
            status_code: None,
            error: None,
        };
        self.task_registry
            .begin_attempt(key, snapshot, super::MAX_TASK_ATTEMPT_HISTORIES, 128)
            .map_err(|()| {
                CoordinatorServiceError::Protocol(
                    "task attempt history capacity is exhausted by active attempts".to_owned(),
                )
            })?;
        Ok(attempt_id)
    }

    pub(super) fn assign_task_attempt(&mut self, task_spec: &TaskSpec, node: NodeId) {
        let key = task_restart_key(
            &task_spec.tenant,
            &task_spec.project,
            &task_spec.process,
            &task_spec.task_instance,
        );
        self.task_registry.update_current_attempt(&key, |attempt| {
            attempt.node = Some(node);
            attempt.state = TaskAttemptState::Queued;
            attempt.command_state = Some("offered".to_owned());
            attempt.waiting_reason = None;
        });
    }
}

fn assignment_task_compatibility(assignment: &TaskAssignment) -> Option<Digest> {
    let descriptor = assignment_task_descriptor(assignment)?;
    serde_json::from_value(descriptor.get("restart_compatibility_hash")?.clone()).ok()
}

fn assignment_task_descriptor(assignment: &TaskAssignment) -> Option<serde_json::Value> {
    let module = BASE64_STANDARD
        .decode(&assignment.wasm_module_base64)
        .ok()?;
    let mut descriptors = super::main_runtime::task_descriptors(&module).ok()?;
    descriptors.remove(assignment.task_spec.task_definition.as_str())
}

#[cfg(test)]
mod placement_tests {
    use super::*;

    fn placement(node: &str, score: i64) -> Placement {
        Placement {
            node: NodeId::from(node),
            score,
            reasons: Vec::new(),
        }
    }

    #[test]
    fn equal_locality_prefers_the_least_active_node() {
        let candidates = vec![placement("busy", 40), placement("idle", 40)];
        let active = BTreeMap::from([(NodeId::from("busy"), 1)]);

        assert_eq!(
            select_task_placement(&candidates, &active)
                .expect("one placement")
                .node,
            NodeId::from("idle")
        );
    }

    #[test]
    fn locality_score_remains_stronger_than_load_balancing() {
        let candidates = vec![placement("warm", 50), placement("cold", 40)];
        let active = BTreeMap::from([(NodeId::from("warm"), 2)]);

        assert_eq!(
            select_task_placement(&candidates, &active)
                .expect("one placement")
                .node,
            NodeId::from("warm")
        );
    }
}
