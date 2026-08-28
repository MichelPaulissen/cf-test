use std::collections::{BTreeSet, VecDeque};
use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{
    AgentId, AgentSignedRequest, AssignmentAuthority, CredentialKind, DefaultScheduler, Digest,
    NodeId, PlacementRequest, ProcessId, ProjectId, Scheduler, SourcePreparation, TaskCheckpoint,
    TaskInstanceId, TaskSpec, TenantId, UserId,
};
use clusterflux_protocol::{ActiveNodeAssignment, NodeAssignmentOffer, NodeAssignmentWork};

use crate::{AssignmentKind, CoordinatorError, NodeScopeKey};

use super::keys::{process_control_key, task_control_key};
use super::{
    CoordinatorResponse, CoordinatorService, CoordinatorServiceError, SourcePreparationDisposition,
    SourcePreparationStatus, TaskAssignment, TaskAttemptState, TaskCancellationTarget,
    VirtualProcessStatus, WorkflowActor,
};

pub(super) const NODE_ASSIGNMENT_OFFER_SECONDS: u64 = 30;

#[derive(Clone, Debug)]
pub(super) struct PendingTaskLaunch {
    pub(super) tenant: TenantId,
    pub(super) project: ProjectId,
    pub(super) process: ProcessId,
    pub(super) task: TaskInstanceId,
    pub(super) request: PlacementRequest,
    pub(super) epoch: u64,
    pub(super) artifact_path: String,
    pub(super) task_spec: TaskSpec,
    pub(super) wasm_module_base64: String,
    pub(super) offer_epoch: u64,
    pub(super) waiting_reason: String,
}

#[derive(Clone, Debug)]
pub(super) struct TaskRestartCheckpoint {
    pub(super) checkpoint: TaskCheckpoint,
    pub(super) assignment: TaskAssignment,
}

impl CoordinatorService {
    pub fn reconcile_active_assignments_after_coordinator_restart(
        &mut self,
    ) -> Result<usize, CoordinatorServiceError> {
        let authorities = self
            .coordinator
            .durable_state()
            .active_assignments
            .values()
            .map(|active| AssignmentAuthority {
                assignment_id: active.assignment_id.clone(),
                attempt_id: active.attempt_id.clone(),
                offer_epoch: active.offer_epoch,
            })
            .collect::<Vec<_>>();
        if authorities.is_empty() {
            return Ok(0);
        }
        let now = self.current_epoch_seconds()?;
        for authority in &authorities {
            super::TaskRegistry::terminalize_active_assignment(
                self.coordinator.durable_state_mut(),
                authority,
                now,
                false,
            );
        }
        self.persist_durable_state()?;
        Ok(authorities.len())
    }

    pub(super) fn reconcile_expired_process_assignments(
        &mut self,
    ) -> Result<usize, CoordinatorServiceError> {
        let now = self.current_epoch_seconds()?;
        let expired =
            super::TaskRegistry::expired_active_assignments(self.coordinator.durable_state(), now)
                .into_iter()
                .filter(|active| matches!(active.kind, AssignmentKind::ProcessTask { .. }))
                .collect::<Vec<_>>();
        if expired.is_empty() {
            return Ok(0);
        }
        let expired_count = expired.len();

        for active in expired {
            let AssignmentKind::ProcessTask { process, task } = &active.kind else {
                unreachable!();
            };
            let authority = AssignmentAuthority {
                assignment_id: active.assignment_id.clone(),
                attempt_id: active.attempt_id.clone(),
                offer_epoch: active.offer_epoch,
            };
            let checkpoint_key =
                super::keys::task_restart_key(&active.tenant, &active.project, process, task);
            let checkpoint = self.task_registry.checkpoint(&checkpoint_key).cloned();
            super::TaskRegistry::terminalize_active_assignment(
                self.coordinator.durable_state_mut(),
                &authority,
                now,
                false,
            );

            let Some(checkpoint) = checkpoint else {
                // Runtime task state is intentionally restart-ephemeral. Startup
                // reconciliation owns the process-level recovery in this case;
                // the durable assignment authority must still be retired here.
                continue;
            };
            let assignment = checkpoint.assignment;
            let task_key =
                task_control_key(&active.tenant, &active.project, process, &active.node, task);

            if active.acknowledged_at.is_none() && active.state == crate::AssignmentState::Offered {
                self.task_registry.finish_task(&task_key);
                if self
                    .coordinator
                    .active_process(&active.tenant, &active.project, process)
                    .is_none()
                    || self.process_registry.is_cancelled(&process_control_key(
                        &active.tenant,
                        &active.project,
                        process,
                    ))
                {
                    continue;
                }
                self.task_registry
                    .update_current_attempt(&checkpoint_key, |attempt| {
                        if attempt.attempt_id == active.attempt_id {
                            attempt.node = None;
                            attempt.state = TaskAttemptState::Queued;
                            attempt.command_state =
                                Some("offer_expired_redelivery_pending".to_owned());
                            attempt.waiting_reason = Some(
                                "assigned node stopped renewing its task lease; waiting for a compatible replacement"
                                    .to_owned(),
                            );
                        }
                    });
                let trusted_secret_node = (!assignment.task_spec.requested_secrets.is_empty())
                    .then(|| {
                        self.coordinator
                            .durable_state()
                            .trusted_secret_nodes
                            .get(&(active.tenant.clone(), active.project.clone()))
                            .cloned()
                    })
                    .flatten();
                let request = PlacementRequest {
                    tenant: active.tenant.clone(),
                    project: active.project.clone(),
                    environment: assignment.task_spec.environment.clone(),
                    environment_digest: assignment.task_spec.environment_digest.clone(),
                    environment_cache_required: assignment.task_spec.environment_id.is_some()
                        && (assignment.task_spec.environment.is_none()
                            || assignment.task_spec.source_revision.is_some()),
                    required_capabilities: assignment.task_spec.required_capabilities.clone(),
                    dependency_cache: assignment.task_spec.dependency_cache.clone(),
                    source_snapshot: Self::task_placement_source_snapshot(&assignment.task_spec),
                    required_artifacts: assignment
                        .task_spec
                        .required_artifacts
                        .iter()
                        .cloned()
                        .collect(),
                    quota_available: self
                        .quota
                        .can_charge_workflow_spawn(&active.tenant, &active.project, now)
                        .is_ok(),
                    policy_allowed: self.admission.workflow_placement_allowed,
                    prefer_node: trusted_secret_node,
                };
                self.task_registry.push_pending_launch(PendingTaskLaunch {
                    tenant: active.tenant,
                    project: active.project,
                    process: process.clone(),
                    task: task.clone(),
                    request,
                    epoch: assignment.epoch,
                    artifact_path: assignment.artifact_path,
                    task_spec: assignment.task_spec,
                    wasm_module_base64: assignment.wasm_module_base64,
                    offer_epoch: active.offer_epoch.saturating_add(1).max(1),
                    waiting_reason:
                        "assigned node stopped renewing its task lease; waiting for a compatible replacement"
                            .to_owned(),
                });
                continue;
            }

            self.handle_task_completed(
                active.tenant.to_string(),
                active.project.to_string(),
                process.to_string(),
                active.node.to_string(),
                task.to_string(),
                Some(super::TaskTerminalState::Failed),
                Some(1),
                0,
                0,
                String::new(),
                "node_offline: assigned node stopped renewing its task lease".to_owned(),
                false,
                false,
                None,
                None,
                None,
                None,
                super::TaskCompletionOrigin::ExpiredAssignment,
            )?;
        }
        self.persist_durable_state()?;
        Ok(expired_count)
    }

    pub(super) fn handle_poll_node_assignment(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        accept_system_tasks: bool,
        accept_process_tasks: bool,
        active_assignment: Option<ActiveNodeAssignment>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        self.coordinator
            .node_identity(&tenant, &project, &node)
            .ok_or(CoordinatorError::UnknownNode)?;
        if self.coordinator.tenant_suspended(&tenant) {
            return Ok(CoordinatorResponse::NodeAssignment {
                assignment: None,
                cancel_assignment: active_assignment,
            });
        }
        let scope = NodeScopeKey::from_refs(&tenant, &project, &node);
        let descriptor = self
            .node_registry
            .descriptor(&scope)
            .cloned()
            .ok_or_else(|| {
                CoordinatorError::Unauthorized("node has no capability report".to_owned())
            })?;
        let now = self.current_epoch_seconds()?;
        let active_assignment_authorized = match active_assignment.as_ref() {
            Some(active) => {
                self.active_node_assignment_is_authorized(&tenant, &project, &node, active, now)?
            }
            None => true,
        };
        let cancel_assignment = (!active_assignment_authorized)
            .then(|| active_assignment.clone())
            .flatten();
        if cancel_assignment.is_some() {
            return Ok(CoordinatorResponse::NodeAssignment {
                assignment: None,
                cancel_assignment,
            });
        }
        if active_assignment.is_some() && !accept_system_tasks {
            self.set_system_task_wait_reason(&tenant, &project, "all_eligible_nodes_at_capacity")?;
        }

        if accept_system_tasks && !descriptor.capabilities.system_bundles.is_empty() {
            if let Some(offer) = self.poll_system_task_offer(&tenant, &project, &node)? {
                return Ok(CoordinatorResponse::NodeAssignment {
                    assignment: Some(Box::new(offer)),
                    cancel_assignment: None,
                });
            }
        }

        if accept_process_tasks
            && descriptor.capabilities.work_policy
                != clusterflux_core::NodeWorkPolicy::SystemTasksOnly
        {
            let key = (tenant.clone(), project.clone(), node.clone());
            let mut assignment = self.task_registry.poll_assignment(&key);
            if assignment.is_none() && self.node_accepts_new_work(&scope) {
                assignment = self.assign_pending_task_to_node(&tenant, &project, &node)?;
                if let Some(new_assignment) = &assignment {
                    self.task_registry
                        .enqueue_assignment(new_assignment.clone());
                    self.persist_durable_state()?;
                }
            }
            if let Some(assignment) = assignment {
                let offer = NodeAssignmentOffer {
                    assignment_id: assignment.assignment_id.clone(),
                    attempt_id: assignment.attempt_id.clone(),
                    tenant,
                    project,
                    node,
                    lease_epoch: assignment.offer_epoch,
                    expires_at_epoch_seconds: assignment.offer_expires_at_epoch_seconds,
                    work: NodeAssignmentWork::Task {
                        assignment: Box::new(assignment),
                    },
                };
                return Ok(CoordinatorResponse::NodeAssignment {
                    assignment: Some(Box::new(offer)),
                    cancel_assignment: None,
                });
            }
        }
        Ok(CoordinatorResponse::NodeAssignment {
            assignment: None,
            cancel_assignment: None,
        })
    }

    pub(super) fn handle_acknowledge_node_assignment(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        assignment_id: String,
        lease_epoch: u64,
        signed_authority: Option<AssignmentAuthority>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        self.coordinator
            .node_identity(&tenant, &project, &node)
            .ok_or(CoordinatorError::UnknownNode)?;
        let key = (tenant.clone(), project.clone(), node.clone());
        let authority = signed_authority
            .filter(|authority| {
                authority.assignment_id == assignment_id && authority.offer_epoch == lease_epoch
            })
            .or_else(|| {
                super::TaskRegistry::active_assignment(
                    self.coordinator.durable_state(),
                    &assignment_id,
                )
                .filter(|active| active.offer_epoch == lease_epoch)
                .map(|active| AssignmentAuthority {
                    assignment_id: active.assignment_id.clone(),
                    attempt_id: active.attempt_id.clone(),
                    offer_epoch: active.offer_epoch,
                })
            })
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "node assignment acknowledgement omitted or mismatched its attempt authority"
                        .to_owned(),
                )
            })?;
        let now = self.current_epoch_seconds()?;
        let task_acknowledged = self.task_registry.acknowledge_process_assignment(
            self.coordinator.durable_state_mut(),
            &key,
            &authority,
            now,
            180,
        );
        if task_acknowledged {
            if let Some(active) = super::TaskRegistry::active_assignment(
                self.coordinator.durable_state(),
                &assignment_id,
            )
            .cloned()
            {
                if let AssignmentKind::ProcessTask { process, task } = active.kind {
                    self.task_registry.update_current_attempt(
                        &super::keys::task_restart_key(&tenant, &project, &process, &task),
                        |attempt| {
                            if attempt.attempt_id == authority.attempt_id {
                                attempt.state = TaskAttemptState::Running;
                                attempt.command_state = Some("running".to_owned());
                            }
                        },
                    );
                }
            }
            self.persist_durable_state()?;
        }
        if !task_acknowledged
            && !self.acknowledge_system_task_offer(
                &tenant,
                &project,
                &node,
                &assignment_id,
                lease_epoch,
                &authority,
            )?
        {
            return Err(CoordinatorServiceError::StaleNodeAssignmentAcknowledgement);
        }
        Ok(CoordinatorResponse::NodeAssignmentAcknowledged {
            assignment_id,
            lease_epoch,
        })
    }

    fn assign_pending_task_to_node(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
    ) -> Result<Option<TaskAssignment>, CoordinatorServiceError> {
        let Some(descriptor) = self
            .node_registry
            .descriptor(&NodeScopeKey::from_refs(tenant, project, node))
            .cloned()
        else {
            return Ok(None);
        };
        let mut remaining = VecDeque::new();
        let mut selected = None;

        let mut pending_launches = self.task_registry.take_pending_launches();
        while let Some(mut pending) = pending_launches.pop_front() {
            if selected.is_some() {
                remaining.push_back(pending);
                continue;
            }
            if &pending.tenant != tenant || &pending.project != project {
                remaining.push_back(pending);
                continue;
            }
            if self.process_registry.is_cancelled(&process_control_key(
                &pending.tenant,
                &pending.project,
                &pending.process,
            )) {
                continue;
            }
            let Some(active) = self.coordinator.active_process(
                &pending.tenant,
                &pending.project,
                &pending.process,
            ) else {
                continue;
            };
            if active.tenant != pending.tenant
                || active.project != pending.project
                || active.coordinator_epoch != pending.epoch
            {
                continue;
            }
            if !pending.task_spec.requested_secrets.is_empty()
                && self
                    .coordinator
                    .durable_state()
                    .trusted_secret_nodes
                    .get(&(pending.tenant.clone(), pending.project.clone()))
                    != Some(&descriptor.id)
            {
                remaining.push_back(pending);
                continue;
            }
            let placement =
                match DefaultScheduler.place(std::slice::from_ref(&descriptor), &pending.request) {
                    Ok(placement) => placement,
                    Err(error) => {
                        pending.waiting_reason = bounded_waiting_reason(&error.message);
                        let key = super::keys::task_restart_key(
                            &pending.tenant,
                            &pending.project,
                            &pending.process,
                            &pending.task,
                        );
                        self.task_registry.update_current_attempt(&key, |attempt| {
                            attempt.command_state = Some("waiting_for_node".to_owned());
                            attempt.waiting_reason = Some(pending.waiting_reason.clone());
                        });
                        remaining.push_back(pending);
                        continue;
                    }
                };
            self.assign_task_attempt(&pending.task_spec, placement.node.clone());
            let attempt_id = self
                .task_registry
                .current_attempt(&super::keys::task_restart_key(
                    &pending.tenant,
                    &pending.project,
                    &pending.process,
                    &pending.task,
                ))
                .expect("queued task has a current attempt")
                .attempt_id
                .clone();
            let now = self.current_epoch_seconds()?;
            let owner_identity = format!(
                "process-task\0{}\0{}\0{}\0{}",
                pending.tenant, pending.project, pending.process, pending.task
            );
            let authority = super::TaskRegistry::offer_active_assignment(
                self.coordinator.durable_state_mut(),
                AssignmentKind::ProcessTask {
                    process: pending.process.clone(),
                    task: pending.task.clone(),
                },
                pending.tenant.clone(),
                pending.project.clone(),
                placement.node.clone(),
                attempt_id.clone(),
                pending.offer_epoch,
                now,
                NODE_ASSIGNMENT_OFFER_SECONDS,
                &owner_identity,
            );
            let assignment = TaskAssignment {
                assignment_id: authority.assignment_id,
                attempt_id,
                offer_epoch: authority.offer_epoch,
                offer_expires_at_epoch_seconds: now.saturating_add(NODE_ASSIGNMENT_OFFER_SECONDS),
                tenant: pending.tenant.clone(),
                project: pending.project.clone(),
                process: pending.process.clone(),
                task: pending.task.clone(),
                node: placement.node.clone(),
                epoch: pending.epoch,
                artifact_path: pending.artifact_path,
                task_spec: pending.task_spec,
                wasm_module_base64: pending.wasm_module_base64,
            };
            self.capture_task_restart_checkpoint(&assignment)?;
            let task_key = task_control_key(
                &pending.tenant,
                &pending.project,
                &pending.process,
                &placement.node,
                &pending.task,
            );
            self.task_registry
                .set_placement(task_key.clone(), placement);
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
                    now,
                );
            }
            selected = Some(assignment);
        }

        let assigned_scope = selected.as_ref().map(|assignment| {
            (
                assignment.tenant.clone(),
                assignment.project.clone(),
                assignment.process.clone(),
            )
        });
        self.task_registry.restore_pending_launches(remaining);
        if let Some((tenant, project, process)) = assigned_scope {
            let remaining_reason = self
                .task_registry
                .pending_waiting_reason_for_process(&tenant, &project, &process)
                .map(str::to_owned);
            self.record_automated_process_waiting_reason(
                &tenant,
                &project,
                &process,
                remaining_reason.as_deref(),
            );
        }
        Ok(selected)
    }

    pub(super) fn handle_request_source_preparation(
        &mut self,
        tenant: String,
        project: String,
        provider: clusterflux_core::SourceProviderKind,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let preparation = SourcePreparation::node_task(tenant.clone(), project.clone(), provider);
        let request = PlacementRequest {
            tenant,
            project,
            environment: None,
            environment_digest: None,
            environment_cache_required: false,
            required_capabilities: preparation.required_capabilities.clone(),
            dependency_cache: None,
            source_snapshot: None,
            required_artifacts: Default::default(),
            quota_available: true,
            policy_allowed: true,
            prefer_node: None,
        };
        let nodes = self.live_node_descriptors();
        let disposition = match DefaultScheduler.place(&nodes, &request) {
            Ok(placement) => SourcePreparationDisposition::Assigned {
                node: placement.node,
            },
            Err(err) => SourcePreparationDisposition::Pending {
                reason: if err.message.is_empty() {
                    "waiting for any capable node to prepare source".to_owned()
                } else {
                    err.message
                },
            },
        };
        Ok(CoordinatorResponse::SourcePreparation {
            status: SourcePreparationStatus {
                preparation,
                disposition,
            },
        })
    }

    pub(super) fn handle_complete_source_preparation(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        provider: clusterflux_core::SourceProviderKind,
        source_snapshot: Digest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        let identity = self
            .coordinator
            .node_identity(&tenant, &project, &node)
            .ok_or(CoordinatorError::UnknownNode)?;
        debug_assert_eq!(identity.tenant, tenant);
        debug_assert_eq!(identity.project, project);
        match self.node_registry.record_source_snapshot(
            &NodeScopeKey::from_refs(&tenant, &project, &node),
            source_snapshot.clone(),
            super::MAX_NODE_REPORTED_OBJECTS_PER_KIND,
        ) {
            Ok(()) => {}
            Err(super::SourceSnapshotAdmissionError::MissingDescriptor) => {
                return Err(CoordinatorError::Unauthorized(
                    "source preparation completion requires a node capability report".to_owned(),
                )
                .into());
            }
            Err(super::SourceSnapshotAdmissionError::Capacity) => {
                return Err(CoordinatorServiceError::Protocol(format!(
                    "node source snapshot retention limit of {} reached; refresh the node capability report",
                    super::MAX_NODE_REPORTED_OBJECTS_PER_KIND
                )));
            }
        }
        Ok(CoordinatorResponse::SourcePreparationCompleted {
            node,
            provider,
            source_snapshot,
        })
    }

    pub(super) fn handle_start_process(
        &mut self,
        tenant: String,
        project: String,
        actor_user: Option<String>,
        actor_agent: Option<String>,
        agent_public_key_fingerprint: Option<Digest>,
        agent_signature: Option<AgentSignedRequest>,
        request_payload_digest: Option<&Digest>,
        process: String,
        launch_attempt: Option<String>,
        restart: bool,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        self.coordinator.ensure_tenant_active(&tenant)?;
        let actor = self.workflow_actor(
            &tenant,
            &project,
            actor_user,
            actor_agent,
            agent_public_key_fingerprint,
            agent_signature,
            request_payload_digest,
            "start_process",
            &process,
            None,
        )?;
        let replacing_existing = if let Some(active) = self
            .coordinator
            .active_process_for_project(&tenant, &project)
        {
            if active.id != process || !restart {
                return Err(CoordinatorError::Unauthorized(format!(
                    "project already has active virtual process {}; attach to or restart it, request cooperative cancellation, abort it, or use another Coordinator Project",
                    active.id
                ))
                .into());
            }
            true
        } else {
            false
        };
        if !replacing_existing {
            self.quota.ensure_process_admission(
                &tenant,
                self.coordinator.active_process_count_for_tenant(&tenant),
                self.coordinator
                    .tenant_quota_override(&tenant)
                    .map(|record| &record.values),
            )?;
        }
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let charged_spawns =
            self.quota
                .charge_workflow_spawn(&tenant, &project, now_epoch_seconds)?;
        if replacing_existing {
            self.main_runtime.interrupt_process(
                &tenant,
                &project,
                &process,
                "virtual process incarnation replaced",
            );
            self.main_runtime
                .controls
                .remove(&process_control_key(&tenant, &project, &process));
        }
        self.process_registry
            .clear_control(&process_control_key(&tenant, &project, &process));
        self.clear_debug_state_for_process(&tenant, &project, &process);
        self.clear_operator_panel_state(&tenant, &project, &process);
        self.task_registry
            .clear_process(&tenant, &project, &process);
        self.debug_registry
            .remove_audit_for_process(&tenant, &project, &process);
        let active = self.coordinator.start_process_for_launch_attempt(
            tenant.clone(),
            project.clone(),
            process.clone(),
            launch_attempt.map(clusterflux_core::LaunchAttemptId::new),
        );
        self.record_process_started(&tenant, &project, &process, now_epoch_seconds);
        Ok(CoordinatorResponse::ProcessStarted {
            process,
            launch_attempt: active
                .launch_attempt
                .as_ref()
                .map(|attempt| attempt.as_str().to_owned()),
            epoch: self.coordinator.coordinator_epoch(),
            actor,
            charged_spawns,
        })
    }

    pub(super) fn handle_reconnect_node(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        process: String,
        epoch: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        let process = ProcessId::new(process);
        self.coordinator
            .reconnect_node(&tenant, &project, &node, Some((&process, epoch)))?;
        Ok(CoordinatorResponse::NodeReconnected { node, process })
    }

    pub(super) fn handle_cancel_task(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        self.coordinator
            .authorize_node_for_process(&node, &tenant, &project, &process)?;
        let active = self
            .coordinator
            .active_process(&tenant, &project, &process)
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "task cancellation requires an active virtual process".to_owned(),
                )
            })?;
        if !active.connected_nodes.contains(&node) {
            return Err(CoordinatorError::Unauthorized(
                "task cancellation target node is not connected to the virtual process".to_owned(),
            )
            .into());
        }
        self.task_registry
            .request_cancel(task_control_key(&tenant, &project, &process, &node, &task));
        Ok(CoordinatorResponse::TaskCancellationRequested {
            process,
            task,
            node,
        })
    }

    pub(super) fn handle_cancel_process(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let _actor_user = actor_user;
        let active = self
            .coordinator
            .active_process(&tenant, &project, &process)
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "process cancellation requires an active virtual process".to_owned(),
                )
            })?;
        debug_assert_eq!(active.tenant, tenant);
        debug_assert_eq!(active.project, project);
        self.process_registry
            .request_cancel(process_control_key(&tenant, &project, &process));
        let now = self.current_epoch_seconds()?;
        self.cancel_artifact_interchanges_for_process(&tenant, &project, &process, now);
        self.main_runtime.interrupt_process(
            &tenant,
            &project,
            &process,
            "virtual process cancellation requested",
        );
        self.clear_debug_state_for_process(&tenant, &project, &process);
        self.task_registry
            .remove_pending_for_process(&tenant, &project, &process);
        let mut cancelled_tasks = Vec::new();
        let mut affected_nodes = BTreeSet::new();
        for (_, _, _, node, task) in self
            .task_registry
            .request_cancel_for_process(&tenant, &project, &process)
        {
            affected_nodes.insert(node.clone());
            cancelled_tasks.push(TaskCancellationTarget {
                process: process.clone(),
                task,
                node,
            });
        }
        let process_key = process_control_key(&tenant, &project, &process);
        if cancelled_tasks.is_empty() && !self.main_runtime.controls.contains_key(&process_key) {
            self.record_process_terminal(
                &tenant,
                &project,
                &process,
                super::ProcessFinalResult::Cancelled,
                now,
            );
            self.coordinator
                .abort_process(&tenant, &project, &process)?;
            self.clear_operator_panel_state(&tenant, &project, &process);
        }
        Ok(CoordinatorResponse::ProcessCancellationRequested {
            process,
            cancelled_tasks,
            affected_nodes: affected_nodes.into_iter().collect(),
        })
    }

    pub(super) fn handle_abort_process(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        launch_attempt: Option<String>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.handle_abort_process_with_reason(
            tenant,
            project,
            actor_user,
            process,
            launch_attempt,
            "virtual process aborted",
        )
    }

    pub(super) fn handle_abort_process_with_reason(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        launch_attempt: Option<String>,
        reason: &str,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let _actor_user = actor_user;
        let active = self
            .coordinator
            .active_process(&tenant, &project, &process)
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "process abort requires an active virtual process".to_owned(),
                )
            })?;
        debug_assert_eq!(active.tenant, tenant);
        debug_assert_eq!(active.project, project);
        let launch_attempt = launch_attempt.map(clusterflux_core::LaunchAttemptId::new);
        if let Some(expected) = launch_attempt.as_ref() {
            if active.launch_attempt.as_ref() != Some(expected) {
                return Err(CoordinatorError::Unauthorized(format!(
                    "launch rollback denied: attempt {} does not own process {}",
                    expected.as_str(),
                    process.as_str()
                ))
                .into());
            }
        }

        let process_key = process_control_key(&tenant, &project, &process);
        let now = self.current_epoch_seconds()?;
        self.cancel_artifact_interchanges_for_process(&tenant, &project, &process, now);
        self.process_registry.clear_cancel(&process_key);
        self.task_registry
            .clear_cancellations_for_process(&tenant, &project, &process);
        self.process_registry.request_abort(process_key);
        self.main_runtime
            .interrupt_process(&tenant, &project, &process, reason);
        self.main_runtime
            .controls
            .remove(&process_control_key(&tenant, &project, &process));
        self.clear_debug_state_for_process(&tenant, &project, &process);
        self.clear_operator_panel_state(&tenant, &project, &process);
        self.task_registry
            .remove_pending_for_process(&tenant, &project, &process);
        self.task_registry
            .remove_assignments_for_process(&tenant, &project, &process);
        let mut aborted_tasks = Vec::new();
        let mut affected_nodes = BTreeSet::new();
        for (_, _, _, node, task) in self
            .task_registry
            .request_abort_for_process(&tenant, &project, &process)
        {
            affected_nodes.insert(node.clone());
            aborted_tasks.push(TaskCancellationTarget {
                process: process.clone(),
                task,
                node,
            });
        }

        self.record_process_terminal(
            &tenant,
            &project,
            &process,
            super::ProcessFinalResult::Cancelled,
            now,
        );
        if let Some(launch_attempt) = launch_attempt.as_ref() {
            self.coordinator.abort_process_for_launch_attempt(
                &tenant,
                &project,
                &process,
                launch_attempt,
            )?;
        } else {
            self.coordinator
                .abort_process(&tenant, &project, &process)?;
        }
        let active_restart_tasks = aborted_tasks
            .iter()
            .map(|target| target.task.clone())
            .collect::<BTreeSet<_>>();
        self.task_registry.retain_process_checkpoints_for_tasks(
            &tenant,
            &project,
            &process,
            &active_restart_tasks,
        );
        if aborted_tasks.is_empty() {
            self.process_registry
                .clear_abort(&process_control_key(&tenant, &project, &process));
        }
        Ok(CoordinatorResponse::ProcessAborted {
            process,
            aborted_tasks,
            affected_nodes: affected_nodes.into_iter().collect(),
        })
    }

    pub(super) fn handle_list_processes(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let processes = self
            .coordinator
            .active_processes_for_project(&tenant, &project)
            .into_iter()
            .map(|active| {
                let process_key = process_control_key(&active.tenant, &active.project, &active.id);
                let main = self.main_runtime.controls.get(&process_key);
                let stored = self.process_registry.summary(&process_key);
                let stored_main_state = stored
                    .and_then(|summary| summary.main_terminal_state.as_ref())
                    .map(|state| match state {
                        super::TaskTerminalState::Completed => "completed",
                        super::TaskTerminalState::Failed => "failed",
                        super::TaskTerminalState::Cancelled => "cancelled",
                    });
                let state = if self.process_registry.is_cancelled(&process_key) {
                    "cancelling"
                } else {
                    "running"
                };
                let main_wait_state = main.and_then(|main| {
                    if main.state != "running" {
                        return None;
                    }
                    if self.task_registry.queued_count_for_process(
                        &active.tenant,
                        &active.project,
                        &active.id,
                    ) > 0
                    {
                        Some("waiting_for_node".to_owned())
                    } else if self.main_runtime.is_waiting_for_task(
                        &active.tenant,
                        &active.project,
                        &active.id,
                    ) {
                        Some("waiting_for_task".to_owned())
                    } else {
                        Some("executing".to_owned())
                    }
                });
                let main_wait_reason = self
                    .task_registry
                    .pending_waiting_reason_for_process(&active.tenant, &active.project, &active.id)
                    .map(str::to_owned);
                VirtualProcessStatus {
                    process: active.id,
                    state: state.to_owned(),
                    main_task_definition: main.map(|main| main.task_definition.clone()).or_else(
                        || stored.and_then(|summary| summary.main_task_definition.clone()),
                    ),
                    main_task_instance: main
                        .map(|main| main.task_instance.clone())
                        .or_else(|| stored.and_then(|summary| summary.main_task_instance.clone())),
                    main_state: main
                        .map(|main| main.state.clone())
                        .or_else(|| stored_main_state.map(str::to_owned)),
                    main_wait_state,
                    main_wait_reason,
                    main_debug_epoch: main.and_then(|main| main.debug.requested_epoch()),
                    connected_nodes: active.connected_nodes.into_iter().collect(),
                    coordinator_epoch: active.coordinator_epoch,
                }
            })
            .collect();
        Ok(CoordinatorResponse::ProcessStatuses { processes, actor })
    }

    pub(super) fn handle_poll_task_control(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        child_tasks: Vec<String>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        let task_key = task_control_key(&tenant, &project, &process, &node, &task);
        if !child_tasks.is_empty() && !self.task_registry.is_active(&task_key) {
            return Err(CoordinatorError::Unauthorized(
                "child join notifications require a currently active parent task on the signed node"
                    .to_owned(),
            )
            .into());
        }
        let cancel_requested = self.task_registry.is_cancelled(&task_key)
            || self
                .process_registry
                .is_cancelled(&process_control_key(&tenant, &project, &process));
        let abort_requested = self.task_registry.is_aborted(&task_key)
            || self
                .process_registry
                .is_aborted(&process_control_key(&tenant, &project, &process));
        let child_joins = child_tasks
            .into_iter()
            .map(TaskInstanceId::new)
            .map(|child| {
                self.task_join_result(tenant.clone(), project.clone(), process.clone(), child)
            })
            .filter(|join| join.state != clusterflux_core::TaskJoinState::Pending)
            .collect();
        Ok(CoordinatorResponse::TaskControl {
            process,
            task,
            cancel_requested,
            abort_requested,
            child_joins,
        })
    }

    pub(super) fn workflow_actor(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        actor_user: Option<String>,
        actor_agent: Option<String>,
        agent_public_key_fingerprint: Option<Digest>,
        agent_signature: Option<AgentSignedRequest>,
        request_payload_digest: Option<&Digest>,
        request_kind: &str,
        process: &ProcessId,
        task: Option<&TaskInstanceId>,
    ) -> Result<WorkflowActor, CoordinatorServiceError> {
        if let Some(agent) = actor_agent {
            let agent = AgentId::new(agent);
            let signature = agent_signature.ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "agent workflow dispatch requires a signed request proving private-key possession"
                        .to_owned(),
                )
            })?;
            let request_payload_digest = request_payload_digest.ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "agent workflow dispatch requires a canonical signed request payload"
                        .to_owned(),
                )
            })?;
            if signature.nonce.trim().is_empty() || signature.nonce.len() > 256 {
                return Err(CoordinatorError::Unauthorized(
                    "agent signed request nonce is missing or invalid".to_owned(),
                )
                .into());
            }
            let now_epoch_seconds = unix_timestamp_seconds();
            const AGENT_SIGNATURE_WINDOW_SECONDS: u64 = 300;
            if let Err(super::ReplayAdmissionError::Duplicate) = self.replay_registry.prepare_agent(
                tenant,
                project,
                &agent,
                &signature.nonce,
                now_epoch_seconds,
                AGENT_SIGNATURE_WINDOW_SECONDS,
            ) {
                return Err(CoordinatorError::Unauthorized(
                    "agent signed request nonce has already been used".to_owned(),
                )
                .into());
            }
            let canonical_scope = clusterflux_core::AgentWorkflowRequestScope::new(
                tenant.clone(),
                project.clone(),
                request_kind,
                process.clone(),
                task.cloned(),
            )
            .map_err(CoordinatorError::Unauthorized)?;
            let record = self.coordinator.authorize_agent_project_run(
                canonical_scope.for_agent(&agent),
                agent_public_key_fingerprint.as_ref(),
                request_payload_digest,
                &signature,
                now_epoch_seconds,
            )?;
            if let Err(super::ReplayAdmissionError::Capacity) = self.replay_registry.commit_agent(
                tenant.clone(),
                project.clone(),
                agent.clone(),
                signature.nonce.clone(),
                signature.issued_at_epoch_seconds,
                super::MAX_REPLAY_NONCES_PER_AUTHORITY,
            ) {
                return Err(CoordinatorError::Unauthorized(
                    "agent signed request replay window is full; retry after the bounded signature window advances"
                        .to_owned(),
                )
                .into());
            }
            return Ok(WorkflowActor {
                kind: "agent".to_owned(),
                user: Some(record.user),
                agent: Some(agent),
                credential_kind: CredentialKind::PublicKey,
                public_key_fingerprint: Some(record.public_key_fingerprint),
                authenticated_without_browser: true,
                scopes: record.scopes,
            });
        }

        let actor = UserId::new(actor_user.unwrap_or_else(|| "user".to_owned()));
        Ok(WorkflowActor {
            kind: "user".to_owned(),
            user: Some(actor),
            agent: None,
            credential_kind: CredentialKind::BrowserSession,
            public_key_fingerprint: None,
            authenticated_without_browser: false,
            scopes: vec!["project:read".to_owned(), "project:run".to_owned()],
        })
    }
}

pub(super) fn bounded_waiting_reason(reason: &str) -> String {
    let reason = if reason.trim().is_empty() {
        "waiting for any capable node"
    } else {
        reason
    };
    reason.chars().take(256).collect()
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
