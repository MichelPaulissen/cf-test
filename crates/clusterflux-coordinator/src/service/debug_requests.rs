use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{
    Actor, Capability, CredentialKind, Digest, EnvironmentResource, ProcessId, ProjectId,
    RestartDecision, RestartPolicy, RestartRequest, TaskDispatch, TaskInstanceId, TenantId, UserId,
    WasmExportAbi,
};

use crate::{CoordinatorError, CoordinatorServiceError};

use super::keys::task_restart_key;
use super::protocol::TaskFailureResolution;
use super::{
    AuthenticatedCoordinatorRequest, CoordinatorRequest, CoordinatorResponse, CoordinatorService,
    TaskReplacementBundle, TaskTerminalState, WorkflowActor,
};

impl CoordinatorService {
    pub(super) fn handle_debug_request(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        match request {
            CoordinatorRequest::DebugAttach {
                tenant,
                project,
                actor_user,
                process,
            } => self.handle_debug_attach(tenant, project, actor_user, process),
            CoordinatorRequest::SetDebugBreakpoints {
                tenant,
                project,
                actor_user,
                process,
                revision,
                probe_symbols,
                probe_locations,
            } => self.handle_set_debug_breakpoints(
                tenant,
                project,
                actor_user,
                process,
                revision,
                probe_symbols,
                probe_locations,
            ),
            CoordinatorRequest::InspectDebugBreakpoints {
                tenant,
                project,
                actor_user,
                process,
            } => self.handle_inspect_debug_breakpoints(tenant, project, actor_user, process),
            CoordinatorRequest::CreateDebugEpoch {
                tenant,
                project,
                actor_user,
                process,
                stopped_task,
                reason,
            } => self.handle_create_debug_epoch(
                tenant,
                project,
                actor_user,
                process,
                stopped_task,
                reason,
            ),
            CoordinatorRequest::ResumeDebugEpoch {
                tenant,
                project,
                actor_user,
                process,
                epoch,
            } => self.handle_resume_debug_epoch(tenant, project, actor_user, process, epoch),
            CoordinatorRequest::InspectDebugEpoch {
                tenant,
                project,
                actor_user,
                process,
                epoch,
            } => self.handle_inspect_debug_epoch(tenant, project, actor_user, process, epoch),
            _ => unreachable!("handle_debug_request only accepts debug coordinator requests"),
        }
    }

    pub(super) fn handle_authenticated_debug_request(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        actor: &UserId,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        match request {
            AuthenticatedCoordinatorRequest::DebugAttach { process } => self.handle_debug_attach(
                tenant.as_str().to_owned(),
                project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
            ),
            AuthenticatedCoordinatorRequest::SetDebugBreakpoints {
                process,
                revision,
                probe_symbols,
                probe_locations,
            } => self.handle_set_debug_breakpoints(
                tenant.as_str().to_owned(),
                project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                revision,
                probe_symbols,
                probe_locations,
            ),
            AuthenticatedCoordinatorRequest::InspectDebugBreakpoints { process } => self
                .handle_inspect_debug_breakpoints(
                    tenant.as_str().to_owned(),
                    project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    process,
                ),
            AuthenticatedCoordinatorRequest::CreateDebugEpoch {
                process,
                stopped_task,
                reason,
            } => self.handle_create_debug_epoch(
                tenant.as_str().to_owned(),
                project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                stopped_task,
                reason,
            ),
            AuthenticatedCoordinatorRequest::ResumeDebugEpoch { process, epoch } => self
                .handle_resume_debug_epoch(
                    tenant.as_str().to_owned(),
                    project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    process,
                    epoch,
                ),
            AuthenticatedCoordinatorRequest::InspectDebugEpoch { process, epoch } => self
                .handle_inspect_debug_epoch(
                    tenant.as_str().to_owned(),
                    project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    process,
                    epoch,
                ),
            _ => unreachable!(
                "handle_authenticated_debug_request only accepts debug coordinator requests"
            ),
        }
    }

    pub(super) fn handle_restart_task(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: String,
        replacement_bundle: Option<TaskReplacementBundle>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let task = TaskInstanceId::new(task);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        if !authorization.allowed {
            let _ = self.record_debug_audit_event(
                tenant,
                project,
                process,
                Some(task),
                actor,
                "restart_task",
                false,
                authorization.reason.clone(),
            )?;
            return Err(CoordinatorError::Unauthorized(format!(
                "task restart denied: {}",
                authorization.reason
            ))
            .into());
        }
        let active_key = self
            .task_registry
            .active_task_for_logical_task(&tenant, &project, &process, &task);
        let process_key = super::keys::process_control_key(&tenant, &project, &process);
        let active_main = self
            .main_runtime
            .controls
            .get(&process_key)
            .is_some_and(|control| {
                control.task_instance == task
                    && matches!(control.state.as_str(), "running" | "stopping")
            });
        let active_task = active_key.is_some() || active_main;
        let completed_event_observed = self
            .task_registry
            .last_event_for_task(&tenant, &project, &process, &task)
            .is_some();
        let checkpoint_key = task_restart_key(&tenant, &project, &process, &task);
        let checkpoint = self.task_registry.checkpoint(&checkpoint_key).cloned();
        let mut accepted = false;
        let mut restarted_task_instance = None;
        let mut restarted_attempt_id = None;
        let mut clean_boundary_available = false;
        let mut requires_whole_process_restart = true;
        let message = if active_main {
            "selected coordinator main is still active; restart the whole virtual process to rerun its capless entry boundary".to_owned()
        } else if active_task {
            "selected task is still active; wait for its terminal event or abort the whole virtual process before restarting from its clean entry boundary".to_owned()
        } else if !completed_event_observed {
            "selected task is not known in the active process; restart the whole virtual process or inspect task list".to_owned()
        } else if let Some(checkpoint) = checkpoint {
            let vfs_available = checkpoint.checkpoint.vfs_manifest.objects.iter().try_fold(
                true,
                |available, (path, object)| {
                    let artifact = super::keys::artifact_id_from_path(path).map_err(|error| {
                        CoordinatorServiceError::InvalidArtifactPath(error.to_string())
                    })?;
                    Ok::<_, CoordinatorServiceError>(
                        available
                            && self
                                .artifact_registry
                                .metadata(&tenant, &project, &artifact)
                                .is_some_and(|metadata| {
                                    metadata.digest == object.digest
                                        && metadata.size == object.size
                                        && !metadata.retaining_nodes.is_empty()
                                }),
                    )
                },
            )?;
            if !vfs_available {
                "selected task checkpoint references VFS artifacts that are no longer retained; restart the whole virtual process".to_owned()
            } else {
                let replacement = replacement_bundle
                    .as_ref()
                    .map(|bundle| {
                        validate_task_replacement(
                            bundle,
                            &checkpoint.assignment.task_spec.task_definition,
                            checkpoint.assignment.task_spec.environment_id.as_deref(),
                        )
                    })
                    .transpose()?;
                let request = RestartRequest {
                    task: task.clone(),
                    entrypoint: replacement.as_ref().map_or_else(
                        || checkpoint.checkpoint.boundary.task_entrypoint.clone(),
                        |replacement| replacement.export.clone(),
                    ),
                    serialized_args: checkpoint.checkpoint.boundary.serialized_args.clone(),
                    environment_digest: replacement.as_ref().map_or_else(
                        || checkpoint.checkpoint.boundary.environment_digest.clone(),
                        |replacement| replacement.environment_digest.clone(),
                    ),
                    task_abi: replacement.as_ref().map_or_else(
                        || checkpoint.checkpoint.boundary.task_abi.clone(),
                        |replacement| replacement.restart_compatibility.clone(),
                    ),
                    source_edited: replacement.is_some(),
                };
                match RestartPolicy.decide(&checkpoint.checkpoint, &request) {
                    RestartDecision::RestartTask { from_vfs_epoch, .. } => {
                        clean_boundary_available = true;
                        let mut assignment = checkpoint.assignment;
                        assignment.task = task.clone();
                        assignment.task_spec.task_instance = task.clone();
                        let next_attempt = self
                            .task_registry
                            .attempt_count(&checkpoint_key)
                            .saturating_add(1);
                        assignment.artifact_path = format!(
                            "/vfs/artifacts/{}-attempt-{next_attempt}-result.json",
                            task.as_str()
                        );
                        if let Some(replacement) = replacement {
                            if assignment.task_spec.source_snapshot.is_some() {
                                let replacement_source = replacement_bundle
                                    .as_ref()
                                    .and_then(|bundle| bundle.source_snapshot.clone())
                                    .ok_or_else(|| {
                                        CoordinatorServiceError::Protocol(
                                            "replacement task omitted the current SourceSnapshot for source-bound arguments"
                                                .to_owned(),
                                        )
                                    })?;
                                assignment
                                    .task_spec
                                    .rebind_source_snapshot(replacement_source)
                                    .map_err(|error| {
                                        CoordinatorServiceError::Protocol(format!(
                                            "replacement task SourceSnapshot is invalid: {error}"
                                        ))
                                    })?;
                            }
                            assignment.task_spec.dispatch = TaskDispatch::CoordinatorNodeWasm {
                                export: Some(replacement.export),
                                abi: WasmExportAbi::TaskV1,
                            };
                            assignment.task_spec.environment = replacement
                                .environment
                                .map(|environment| environment.requirements);
                            assignment.task_spec.environment_digest =
                                Some(replacement.environment_digest);
                            assignment.task_spec.required_capabilities =
                                replacement.required_capabilities;
                            assignment.task_spec.bundle_digest =
                                Some(replacement.bundle_digest.clone());
                            assignment.wasm_module_base64 = replacement.wasm_module_base64;
                        }
                        let restart_task_spec = assignment.task_spec.clone();
                        let restart_artifact_path = assignment.artifact_path.clone();
                        self.task_registry
                            .mark_restart_launch(checkpoint_key.clone());
                        let launch = self.handle_launch_task_with_actor(
                            tenant.clone(),
                            project.clone(),
                            WorkflowActor {
                                kind: "user".to_owned(),
                                user: Some(actor.clone()),
                                agent: None,
                                credential_kind: CredentialKind::CliDeviceSession,
                                public_key_fingerprint: None,
                                authenticated_without_browser: false,
                                scopes: vec!["process:restart-task".to_owned()],
                            },
                            assignment.task_spec,
                            true,
                            assignment.artifact_path,
                            assignment.wasm_module_base64,
                        );
                        self.task_registry.clear_restart_launch(&checkpoint_key);
                        let launch = launch?;
                        let queued = matches!(launch, CoordinatorResponse::TaskQueued { .. });
                        accepted = matches!(
                            &launch,
                            CoordinatorResponse::TaskLaunched { .. }
                                | CoordinatorResponse::TaskQueued { .. }
                        );
                        if accepted {
                            restarted_task_instance = Some(task.clone());
                            restarted_attempt_id = self
                                .task_registry
                                .last_attempt(&checkpoint_key)
                                .map(|attempt| attempt.attempt_id.clone());
                            if restarted_attempt_id.is_none() {
                                restarted_attempt_id = Some(self.begin_task_attempt(
                                    &restart_task_spec,
                                    None,
                                    Some(&restart_artifact_path),
                                    queued,
                                )?);
                            }
                        }
                        requires_whole_process_restart = !accepted;
                        format!(
                            "selected logical task {task} restarted as a new attempt from clean VFS entry boundary epoch {from_vfs_epoch}; unflushed task changes were discarded"
                        )
                    }
                    RestartDecision::RestartWholeVirtualProcess { message } => message,
                }
            }
        } else {
            "selected task has terminal metadata but no captured clean VFS entry boundary; restart the whole virtual process".to_owned()
        };
        let audit_event = self.record_debug_audit_event(
            tenant,
            project,
            process.clone(),
            Some(task.clone()),
            actor.clone(),
            "restart_task",
            true,
            &message,
        )?;
        Ok(CoordinatorResponse::TaskRestart {
            process,
            task,
            restarted_task_instance,
            restarted_attempt_id,
            actor,
            accepted,
            clean_boundary_available,
            active_task,
            completed_event_observed,
            requires_whole_process_restart,
            message,
            charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
            used_debug_read_bytes: audit_event.used_debug_read_bytes,
            audit_event,
        })
    }

    pub(super) fn handle_resolve_task_failure(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: String,
        resolution: TaskFailureResolution,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let task = TaskInstanceId::new(task);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        if !authorization.allowed {
            return Err(CoordinatorError::Unauthorized(format!(
                "task failure resolution denied: {}",
                authorization.reason
            ))
            .into());
        }
        let key = task_restart_key(&tenant, &project, &process, &task);
        let attempt_id = self
            .task_registry
            .resolve_failed_attempt(&key, resolution)
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    "task is not failed awaiting operator action".to_owned(),
                )
            })?;
        let mut event = self
            .task_registry
            .event_for_attempt(&tenant, &project, &process, &task, &attempt_id)
            .cloned()
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    "failed attempt terminal event is unavailable".to_owned(),
                )
            })?;
        if resolution == TaskFailureResolution::Cancel {
            event.terminal_state = TaskTerminalState::Cancelled;
            event.stderr_tail = "operator cancelled task after failure".to_owned();
        }
        self.record_task_completion_event(event.clone());
        self.notify_coordinator_main_waiters(&event);
        self.maybe_retire_terminal_process(&tenant, &project, &process)?;
        Ok(CoordinatorResponse::TaskFailureResolved {
            process,
            task,
            attempt_id,
            resolution,
        })
    }
}

struct ValidatedTaskReplacement {
    bundle_digest: Digest,
    wasm_module_base64: String,
    export: String,
    restart_compatibility: Digest,
    environment: Option<EnvironmentResource>,
    environment_digest: Digest,
    required_capabilities: BTreeSet<Capability>,
}

fn validate_task_replacement(
    replacement: &TaskReplacementBundle,
    task_definition: &clusterflux_core::TaskDefinitionId,
    environment_id: Option<&str>,
) -> Result<ValidatedTaskReplacement, CoordinatorServiceError> {
    let module = BASE64_STANDARD
        .decode(&replacement.wasm_module_base64)
        .map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "replacement task bundle is not valid base64: {error}"
            ))
        })?;
    let actual_digest = Digest::sha256(&module);
    if actual_digest != replacement.bundle_digest {
        return Err(CoordinatorServiceError::Protocol(format!(
            "replacement task bundle digest mismatch: expected {}, actual {actual_digest}",
            replacement.bundle_digest
        )));
    }
    let descriptors = super::main_runtime::task_descriptors(&module)?;
    let descriptor = descriptors.get(task_definition.as_str()).ok_or_else(|| {
        CoordinatorServiceError::Protocol(format!(
            "replacement bundle has no task definition `{task_definition}`"
        ))
    })?;
    if descriptor
        .get("abi_version")
        .and_then(serde_json::Value::as_u64)
        != Some(clusterflux_core::WASM_TASK_ABI_VERSION as u64)
    {
        return Err(CoordinatorServiceError::Protocol(format!(
            "replacement task `{task_definition}` uses an unsupported task ABI"
        )));
    }
    let export = descriptor
        .get("export")
        .and_then(serde_json::Value::as_str)
        .filter(|export| !export.is_empty())
        .ok_or_else(|| {
            CoordinatorServiceError::Protocol(format!(
                "replacement task `{task_definition}` omitted its export"
            ))
        })?
        .to_owned();
    let restart_compatibility = serde_json::from_value(
        descriptor
            .get("restart_compatibility_hash")
            .cloned()
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(format!(
                    "replacement task `{task_definition}` omitted restart compatibility metadata"
                ))
            })?,
    )?;
    let mut required_capabilities = descriptor
        .get("required_capabilities")
        .and_then(serde_json::Value::as_array)
        .into_iter()
        .flatten()
        .map(|capability| {
            super::main_runtime::capability_from_descriptor(capability.as_str().ok_or_else(
                || {
                    CoordinatorServiceError::Protocol(
                        "replacement task capability is not a string".to_owned(),
                    )
                },
            )?)
            .map_err(CoordinatorServiceError::Protocol)
        })
        .collect::<Result<BTreeSet<_>, _>>()?;
    let environment = environment_id
        .map(|environment_id| {
            super::main_runtime::bundle_environments(&module)?
                .remove(environment_id)
                .ok_or_else(|| {
                    CoordinatorServiceError::Protocol(format!(
                        "replacement bundle has no environment `{environment_id}`"
                    ))
                })
        })
        .transpose()?;
    if let Some(environment) = &environment {
        required_capabilities.extend(environment.requirements.capabilities.iter().cloned());
    }
    let environment_digest = environment.as_ref().map_or_else(
        || Digest::sha256("clusterflux.environment.unconstrained.v1"),
        |environment| environment.digest.clone(),
    );
    Ok(ValidatedTaskReplacement {
        bundle_digest: replacement.bundle_digest.clone(),
        wasm_module_base64: replacement.wasm_module_base64.clone(),
        export,
        restart_compatibility,
        environment,
        environment_digest,
        required_capabilities,
    })
}
