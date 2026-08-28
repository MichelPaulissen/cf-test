use std::collections::BTreeSet;

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{
    descriptor_records, select_entrypoint, AssignmentAuthority, AutomatedRunRecord,
    AutomatedRunState, CommitTrigger, CompiledWorkflowBundle, Digest, NodeId, ProcessId, ProjectId,
    PublicationResult, RunId, TaskBoundaryValue, TaskDefinitionId, TaskDispatch, TaskFailurePolicy,
    TaskInstanceId, TaskSpec, TenantId, TriggerContext, TriggerId, WasmExportAbi,
    WorkflowCompilationRequest, WorkflowCompilationResult, WorkflowSource,
};
use clusterflux_protocol::{
    ActiveNodeAssignment, NodeAssignmentOffer, NodeAssignmentWork, SystemTaskAssignment,
    SystemTaskKind, SystemTaskOutput, SystemTaskOwner, SystemTaskResult, TaskExecutor,
    TaskTerminalState,
};

use crate::{
    AcceptedCommitTriggerRecord, AssignmentKind, AssignmentState, AutomatedRunStageRecord,
    CoordinatorError, NodeScopeKey, ProjectEnvironmentRecord,
};

use super::{CoordinatorResponse, CoordinatorService, CoordinatorServiceError, ProcessFinalResult};

const MAX_RUNS_PER_PROJECT: usize = 64;
const MAX_QUEUED_RUNS_PER_PROJECT: usize = 8;
const MAX_PENDING_COMPILATIONS_PER_PROJECT: usize = 8;
const SYSTEM_ASSIGNMENT_LEASE_SECONDS: u64 = 180;
const SYSTEM_ASSIGNMENT_OFFER_SECONDS: u64 = 30;
const MAX_SYSTEM_ASSIGNMENT_ATTEMPTS: u8 = 5;

impl CoordinatorService {
    pub fn automated_run_for_trigger_delivery(
        &self,
        binding_id: &str,
        delivery_id: &str,
    ) -> Option<RunId> {
        let trigger_id = self
            .coordinator
            .durable_state()
            .trigger_deliveries
            .get(&(binding_id.to_owned(), delivery_id.to_owned()))?;
        let trigger = self
            .coordinator
            .durable_state()
            .accepted_commit_triggers
            .get(trigger_id)?;
        let run_key = trigger.trigger.run_identity(&trigger.project);
        self.coordinator
            .durable_state()
            .automated_run_keys
            .get(&run_key)
            .cloned()
    }

    fn terminalize_system_assignment_for_run(&mut self, run_id: &RunId, now: u64) {
        let kind = AssignmentKind::WorkflowCompiler {
            run_id: run_id.clone(),
        };
        if let Some(active) =
            super::TaskRegistry::active_assignment_for_kind(self.coordinator.durable_state(), &kind)
                .cloned()
        {
            super::TaskRegistry::terminalize_active_assignment(
                self.coordinator.durable_state_mut(),
                &AssignmentAuthority {
                    assignment_id: active.assignment_id,
                    attempt_id: active.attempt_id,
                    offer_epoch: active.offer_epoch,
                },
                now,
                false,
            );
        }
    }

    pub fn reconcile_automated_runs_after_coordinator_restart(
        &mut self,
    ) -> Result<usize, CoordinatorServiceError> {
        let interrupted = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .filter(|(_, record)| record.run.state == AutomatedRunState::Running)
            .map(|(run_id, _)| run_id.clone())
            .collect::<Vec<_>>();
        if interrupted.is_empty() {
            return Ok(0);
        }

        let now = self.current_epoch_seconds()?;
        for run_id in &interrupted {
            self.terminalize_system_assignment_for_run(run_id, now);
            let record = self
                .coordinator
                .durable_state_mut()
                .automated_runs
                .get_mut(run_id)
                .expect("interrupted automated run still exists");
            record.run.state = AutomatedRunState::Failed;
            record.run.process_id = None;
            record.run.ended_at = Some(now);
            record.run.failure_code = Some("coordinator_restart_interrupted_run".to_owned());
            record.run.failure_message = Some(
                "The coordinator restarted while this automated process was running; retry the run after the coordinator is healthy."
                    .to_owned(),
            );
            record.run.waiting_reason = None;
            record.trigger_context = None;
            record.launch_attempt = None;
        }
        self.persist_durable_state()?;
        Ok(interrupted.len())
    }

    pub fn pending_source_loads(&self, limit: usize) -> Vec<AcceptedCommitTriggerRecord> {
        let mut pending = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| {
                record.source.is_none()
                    && matches!(
                        record.run.state,
                        AutomatedRunState::Accepted | AutomatedRunState::LoadingSource
                    )
            })
            .filter_map(|record| {
                self.coordinator
                    .durable_state()
                    .accepted_commit_triggers
                    .get(&record.run.primary_trigger_id)
                    .cloned()
                    .map(|trigger| (record.run.created_at, trigger))
            })
            .collect::<Vec<_>>();
        pending.sort_by_key(|item| item.0);
        pending
            .into_iter()
            .map(|(_, trigger)| trigger)
            .take(limit.min(8))
            .collect()
    }

    pub fn claim_source_load(
        &mut self,
        trigger_id: &TriggerId,
    ) -> Result<RunId, CoordinatorServiceError> {
        let run_id = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .find(|(_, record)| &record.run.primary_trigger_id == trigger_id)
            .map(|(run_id, _)| run_id.clone())
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown trigger run".to_owned()))?;
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&run_id)
            .expect("trigger run exists");
        if record.source.is_none() {
            record.run.state = AutomatedRunState::LoadingSource;
        }
        self.persist_durable_state()?;
        Ok(run_id)
    }

    pub fn launchable_automated_runs(&self, limit: usize) -> Vec<RunId> {
        let mut launchable = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .filter(|(_, record)| {
                record.compiled_bundle.is_some()
                    && matches!(
                        record.run.state,
                        AutomatedRunState::WaitingForProcessSlot | AutomatedRunState::Launching
                    )
            })
            .map(|(run_id, record)| (record.run.created_at, run_id.clone()))
            .collect::<Vec<_>>();
        launchable.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        launchable
            .into_iter()
            .map(|(_, run_id)| run_id)
            .take(limit.min(8))
            .collect()
    }

    pub fn automated_run_scope(&self, run_id: &RunId) -> Option<(TenantId, ProjectId)> {
        let record = self
            .coordinator
            .durable_state()
            .automated_runs
            .get(run_id)?;
        self.coordinator
            .durable_state()
            .accepted_commit_triggers
            .get(&record.run.primary_trigger_id)
            .map(|trigger| (trigger.tenant.clone(), trigger.project.clone()))
    }

    pub fn fail_automated_run_stage(
        &mut self,
        run_id: &RunId,
        code: &str,
        message: &str,
    ) -> Result<(), CoordinatorServiceError> {
        self.fail_automated_run(run_id, code, message)
    }

    pub fn accept_commit_trigger(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        binding_id: String,
        body_digest: Digest,
        trigger: CommitTrigger,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        trigger
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        if !body_digest.is_valid_sha256() {
            return Err(CoordinatorServiceError::Protocol(
                "webhook body digest is not a SHA-256 digest".to_owned(),
            ));
        }
        let configured_project = self.coordinator.project(&project).ok_or_else(|| {
            CoordinatorError::Unauthorized("trigger project does not exist".to_owned())
        })?;
        if configured_project.tenant != tenant {
            return Err(CoordinatorError::Unauthorized(
                "trigger project is outside the tenant scope".to_owned(),
            )
            .into());
        }

        let delivery_key = (binding_id.clone(), trigger.delivery_id.clone());
        if let Some(existing_id) = self
            .coordinator
            .durable_state()
            .trigger_deliveries
            .get(&delivery_key)
            .cloned()
        {
            let existing = self
                .coordinator
                .durable_state()
                .accepted_commit_triggers
                .get(&existing_id)
                .expect("delivery index references an accepted trigger");
            if existing.body_digest != body_digest {
                return Err(CoordinatorServiceError::Protocol(
                    "forge delivery ID was replayed with a different body".to_owned(),
                ));
            }
            let run_key = existing.trigger.run_identity(&existing.project);
            let run_id = self
                .coordinator
                .durable_state()
                .automated_run_keys
                .get(&run_key)
                .expect("accepted trigger references a durable run");
            return self
                .coordinator
                .durable_state()
                .automated_runs
                .get(run_id)
                .cloned()
                .ok_or_else(|| {
                    CoordinatorServiceError::Protocol(
                        "accepted trigger references a missing run".to_owned(),
                    )
                });
        }

        let run_key = trigger.run_identity(&project);
        if !self
            .coordinator
            .durable_state()
            .automated_run_keys
            .contains_key(&run_key)
        {
            let queued = self
                .coordinator
                .durable_state()
                .automated_runs
                .values()
                .filter(|record| {
                    record.run.tenant == tenant
                        && record.run.project == project
                        && !record.run.state.is_terminal()
                        && record.run.state != AutomatedRunState::Running
                })
                .count();
            if queued >= MAX_QUEUED_RUNS_PER_PROJECT {
                return Err(CoordinatorServiceError::Protocol(format!(
                    "project automated-run queue is full ({MAX_QUEUED_RUNS_PER_PROJECT})"
                )));
            }
            self.compact_automated_run_history(&tenant, &project)?;
            let project_run_count = self
                .coordinator
                .durable_state()
                .automated_runs
                .values()
                .filter(|record| record.run.tenant == tenant && record.run.project == project)
                .count();
            if project_run_count >= MAX_RUNS_PER_PROJECT {
                return Err(CoordinatorServiceError::Protocol(format!(
                    "project automated-run retention is full ({MAX_RUNS_PER_PROJECT})"
                )));
            }
        }

        let run_id = self
            .coordinator
            .durable_state()
            .automated_run_keys
            .get(&run_key)
            .cloned()
            .unwrap_or_else(|| run_id_from_key(&run_key));
        let now = trigger.received_at;
        let record = self
            .coordinator
            .durable_state()
            .automated_runs
            .get(&run_id)
            .cloned()
            .unwrap_or_else(|| AutomatedRunStageRecord {
                run: AutomatedRunRecord {
                    run_id: run_id.clone(),
                    primary_trigger_id: trigger.trigger_id.clone(),
                    tenant: tenant.clone(),
                    project: project.clone(),
                    repository_id: trigger.repository_id.clone(),
                    commit_sha: trigger.commit_sha.clone(),
                    git_ref: trigger.git_ref.clone(),
                    trusted: trigger.trusted,
                    workflow_tree_digest: None,
                    bundle_digest: None,
                    state: AutomatedRunState::Accepted,
                    process_id: None,
                    created_at: now,
                    started_at: None,
                    ended_at: None,
                    failure_code: None,
                    failure_message: None,
                    waiting_reason: None,
                    publication_tag: None,
                    publication_url: None,
                },
                run_key: run_key.clone(),
                source: None,
                revision_environments: Vec::new(),
                revision: None,
                compilation_request: None,
                assignment_retry: Default::default(),
                compiled_bundle: None,
                compiled_summary: None,
                trigger_context: None,
                launch_attempt: None,
            });
        let durable = self.coordinator.durable_state_mut();
        durable.trigger_deliveries.insert(
            (binding_id.clone(), trigger.delivery_id.clone()),
            trigger.trigger_id.clone(),
        );
        durable.accepted_commit_triggers.insert(
            trigger.trigger_id.clone(),
            AcceptedCommitTriggerRecord {
                tenant,
                project,
                binding_id,
                body_digest,
                trigger,
            },
        );
        durable.automated_run_keys.insert(run_key, run_id.clone());
        durable.automated_runs.insert(run_id, record.clone());
        self.persist_durable_state()?;
        Ok(record)
    }

    fn compact_automated_run_history(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> Result<(), CoordinatorServiceError> {
        let project_run_count = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| &record.run.tenant == tenant && &record.run.project == project)
            .count();
        if project_run_count < MAX_RUNS_PER_PROJECT {
            return Ok(());
        }
        let remove_count = project_run_count
            .saturating_add(1)
            .saturating_sub(MAX_RUNS_PER_PROJECT);
        let mut terminal = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .filter(|(_, record)| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.state.is_terminal()
            })
            .map(|(run_id, record)| {
                (
                    record.run.created_at,
                    run_id.clone(),
                    record.run_key.clone(),
                    record.run.primary_trigger_id.clone(),
                )
            })
            .collect::<Vec<_>>();
        terminal.sort_by(|left, right| left.0.cmp(&right.0).then_with(|| left.1.cmp(&right.1)));
        if terminal.len() < remove_count {
            return Ok(());
        }
        let terminal = terminal.into_iter().take(remove_count).collect::<Vec<_>>();
        let removed_runs = terminal
            .iter()
            .map(|(_, run_id, _, _)| run_id.clone())
            .collect::<BTreeSet<_>>();
        let removed_keys = terminal
            .iter()
            .map(|(_, _, run_key, _)| run_key.clone())
            .collect::<BTreeSet<_>>();
        let removed_primary_triggers = terminal
            .iter()
            .map(|(_, _, _, trigger_id)| trigger_id.clone())
            .collect::<BTreeSet<_>>();
        let surviving_primary_triggers = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .filter(|(run_id, _)| !removed_runs.contains(*run_id))
            .map(|(_, record)| record.run.primary_trigger_id.clone())
            .collect::<BTreeSet<_>>();
        let removed_triggers = self
            .coordinator
            .durable_state()
            .accepted_commit_triggers
            .iter()
            .filter(|(trigger_id, record)| {
                removed_primary_triggers.contains(*trigger_id)
                    || (&record.tenant == tenant
                        && &record.project == project
                        && removed_keys.contains(&record.trigger.run_identity(project))
                        && !surviving_primary_triggers.contains(*trigger_id))
            })
            .map(|(trigger_id, _)| trigger_id.clone())
            .collect::<BTreeSet<_>>();
        let durable = self.coordinator.durable_state_mut();
        durable
            .automated_runs
            .retain(|run_id, _| !removed_runs.contains(run_id));
        durable
            .automated_run_keys
            .retain(|run_key, _| !removed_keys.contains(run_key));
        durable
            .accepted_commit_triggers
            .retain(|trigger_id, _| !removed_triggers.contains(trigger_id));
        durable
            .trigger_deliveries
            .retain(|_, trigger_id| !removed_triggers.contains(trigger_id));
        self.persist_durable_state()
    }

    pub fn record_automated_run_source(
        &mut self,
        run_id: &RunId,
        source: WorkflowSource,
        revision: clusterflux_core::RepositoryRevision,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        source
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        revision
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(run_id)
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        if record.run.state.is_terminal() {
            return Ok(record.clone());
        }
        if source.trigger_id != record.run.primary_trigger_id
            || source.repository_id != record.run.repository_id
            || source.commit_sha != record.run.commit_sha
            || revision.repository_id != record.run.repository_id
            || revision.commit_sha != record.run.commit_sha
        {
            return Err(CoordinatorError::Unauthorized(
                "workflow source or repository revision does not match its run".to_owned(),
            )
            .into());
        }
        if let Some(existing) = &record.source {
            if existing != &source || record.revision.as_ref() != Some(&revision) {
                return Err(CoordinatorServiceError::Protocol(
                    "automated run source was retried with different content".to_owned(),
                ));
            }
            return Ok(record.clone());
        }
        record.run.workflow_tree_digest = Some(source.tree_digest.clone());
        record.revision_environments = source.environments.clone();
        record.run.state = AutomatedRunState::LoadingSource;
        record.source = Some(source);
        record.revision = Some(revision);
        let response = record.clone();
        self.persist_durable_state()?;
        Ok(response)
    }

    pub fn enqueue_workflow_compilation(
        &mut self,
        request: WorkflowCompilationRequest,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        request
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        let run_id = request.run_id.clone();
        let (tenant, project) = self
            .coordinator
            .durable_state()
            .automated_runs
            .get(&run_id)
            .map(|record| (record.run.tenant.clone(), record.run.project.clone()))
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        let pending = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| {
                record.run.tenant == tenant
                    && record.run.project == project
                    && matches!(
                        record.run.state,
                        AutomatedRunState::WaitingForCompilerNode
                            | AutomatedRunState::CompilingWorkflow
                    )
                    && record.compiled_bundle.is_none()
                    && record.compiled_summary.is_none()
            })
            .count();
        if pending >= MAX_PENDING_COMPILATIONS_PER_PROJECT {
            return Err(CoordinatorServiceError::Protocol(format!(
                "project compiler queue is full ({MAX_PENDING_COMPILATIONS_PER_PROJECT})"
            )));
        }
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&run_id)
            .expect("run existence checked above");
        if record.run.state.is_terminal() {
            return Ok(record.clone());
        }
        if let Some(existing) = &record.compilation_request {
            if existing != &request {
                return Err(CoordinatorServiceError::Protocol(
                    "compiler stage was retried with a different request".to_owned(),
                ));
            }
            return Ok(record.clone());
        }
        if record.source.as_ref() != Some(&request.source) {
            return Err(CoordinatorError::Unauthorized(
                "compiler request does not contain the run's exact loaded source".to_owned(),
            )
            .into());
        }
        record.compilation_request = Some(request);
        // The request now owns the exact-revision source. Do not persist a
        // second copy alongside it while compilation is active.
        record.source = None;
        record.run.state = AutomatedRunState::WaitingForCompilerNode;
        record.run.waiting_reason = Some("no_attached_compatible_node".to_owned());
        let response = record.clone();
        self.persist_durable_state()?;
        Ok(response)
    }

    pub(super) fn set_system_task_wait_reason(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        reason: &str,
    ) -> Result<(), CoordinatorServiceError> {
        let mut changed = false;
        for record in self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .values_mut()
        {
            if record.run.tenant == *tenant
                && record.run.project == *project
                && record.run.state == AutomatedRunState::WaitingForCompilerNode
                && record.run.waiting_reason.as_deref() != Some(reason)
            {
                record.run.waiting_reason = Some(reason.to_owned());
                changed = true;
            }
        }
        if changed {
            self.persist_durable_state()?;
        }
        Ok(())
    }

    pub(super) fn poll_system_task_offer(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
    ) -> Result<Option<NodeAssignmentOffer>, CoordinatorServiceError> {
        let scope = NodeScopeKey::from_refs(tenant, project, node);
        self.coordinator
            .node_identity(tenant, project, node)
            .ok_or(CoordinatorError::UnknownNode)?;
        let descriptor = self
            .node_registry
            .descriptor(&scope)
            .cloned()
            .ok_or_else(|| {
                CoordinatorError::Unauthorized("node has no capability report".to_owned())
            })?;
        let release_manifest = clusterflux_core::workflow_compiler_system_manifest();
        if descriptor.capabilities.work_policy == clusterflux_core::NodeWorkPolicy::ExecutionOnly
            || descriptor.capabilities.os != clusterflux_core::Os::Linux
            || descriptor.capabilities.arch != release_manifest.supported_arch
            || !descriptor
                .capabilities
                .environment_backends
                .contains(&clusterflux_core::EnvironmentBackend::Container)
            || !descriptor
                .capabilities
                .capabilities
                .contains(&clusterflux_core::Capability::RootlessPodman)
        {
            let reason = if descriptor.capabilities.work_policy
                == clusterflux_core::NodeWorkPolicy::ExecutionOnly
            {
                "node_policy_disables_workflow_compilation"
            } else {
                "no_compatible_linux_container_backend"
            };
            self.set_system_task_wait_reason(tenant, project, reason)?;
            return Ok(None);
        }
        let system_bundle = descriptor
            .capabilities
            .system_bundles
            .iter()
            .find(|bundle| {
                bundle.bundle_id == release_manifest.bundle_id
                    && bundle.bundle_digest == release_manifest.bundle_digest
                    && bundle.environment_digest == release_manifest.environment_digest
                    && bundle.sdk_abi_version == release_manifest.sdk_abi_version
                    && bundle.wasm_target == release_manifest.wasm_target
            })
            .cloned();
        let Some(system_bundle) = system_bundle else {
            self.set_system_task_wait_reason(
                tenant,
                project,
                "system_bundle_version_mismatch_or_unavailable",
            )?;
            return Ok(None);
        };
        let now = self.current_epoch_seconds()?;
        let expired =
            super::TaskRegistry::expired_active_assignments(self.coordinator.durable_state(), now)
                .into_iter()
                .filter(|active| matches!(active.kind, AssignmentKind::WorkflowCompiler { .. }))
                .collect::<Vec<_>>();
        for active in expired {
            let authority = AssignmentAuthority {
                assignment_id: active.assignment_id.clone(),
                attempt_id: active.attempt_id.clone(),
                offer_epoch: active.offer_epoch,
            };
            super::TaskRegistry::terminalize_active_assignment(
                self.coordinator.durable_state_mut(),
                &authority,
                now,
                false,
            );
        }
        let exhausted = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .find(|(_, record)| {
                record.run.tenant == *tenant
                    && record.run.project == *project
                    && record.assignment_retry.attempts >= MAX_SYSTEM_ASSIGNMENT_ATTEMPTS
                    && super::TaskRegistry::active_assignment_for_kind(
                        self.coordinator.durable_state(),
                        &AssignmentKind::WorkflowCompiler {
                            run_id: record.run.run_id.clone(),
                        },
                    )
                    .is_none()
                    && matches!(
                        record.run.state,
                        AutomatedRunState::WaitingForCompilerNode
                            | AutomatedRunState::CompilingWorkflow
                    )
            })
            .map(|(run_id, _)| run_id.clone());
        if let Some(run_id) = exhausted {
            self.terminalize_system_assignment_for_run(&run_id, now);
            let record = self
                .coordinator
                .durable_state_mut()
                .automated_runs
                .get_mut(&run_id)
                .expect("exhausted compiler run exists");
            record.run.state = AutomatedRunState::Failed;
            record.run.ended_at = Some(now);
            record.run.failure_code = Some("system_assignment_node_lost".to_owned());
            record.run.failure_message = Some(format!(
                "workflow compilation exhausted {MAX_SYSTEM_ASSIGNMENT_ATTEMPTS} bounded node attempts"
            ));
            record.compilation_request = None;
            self.persist_durable_state()?;
        }
        let selected = self
            .coordinator
            .durable_state()
            .automated_runs
            .iter()
            .filter(|(_, record)| {
                record.run.tenant == *tenant
                    && record.run.project == *project
                    && matches!(
                        record.run.state,
                        AutomatedRunState::WaitingForCompilerNode
                            | AutomatedRunState::CompilingWorkflow
                    )
                    && record.compilation_request.is_some()
                    && record.compilation_request.as_ref().is_some_and(|request| {
                        request.compiler_profile
                            == clusterflux_core::workflow_compiler_profile_id(
                                &system_bundle.environment_digest,
                            )
                            && request.compiler_image == release_manifest.environment_digest
                            && request.compiler_sdk == release_manifest.sdk_digest
                            && request.rust_toolchain == release_manifest.rust_toolchain
                            && system_bundle.rust_toolchain == request.rust_toolchain
                            && request.source.total_bytes() <= system_bundle.max_source_bytes
                            && request.resource_policy.max_output_bytes
                                <= system_bundle.max_output_bytes
                    })
                    && record.compiled_bundle.is_none()
                    && record.compiled_summary.is_none()
                    && super::TaskRegistry::active_assignment_for_kind(
                        self.coordinator.durable_state(),
                        &AssignmentKind::WorkflowCompiler {
                            run_id: record.run.run_id.clone(),
                        },
                    )
                    .is_none_or(|active| {
                        active.node == *node
                            && active.state == AssignmentState::Offered
                            && active.lease_expires_at >= now
                    })
                    && record.assignment_retry.attempts < MAX_SYSTEM_ASSIGNMENT_ATTEMPTS
            })
            .min_by(|(_, left), (_, right)| {
                left.run
                    .created_at
                    .cmp(&right.run.created_at)
                    .then_with(|| left.run.run_id.cmp(&right.run.run_id))
            })
            .map(|(run_id, _)| run_id.clone());
        let Some(run_id) = selected else {
            return Ok(None);
        };
        let kind = AssignmentKind::WorkflowCompiler {
            run_id: run_id.clone(),
        };
        let existing = super::TaskRegistry::active_assignment_for_kind(
            self.coordinator.durable_state(),
            &kind,
        )
        .cloned();
        let authority = if let Some(existing) = existing {
            AssignmentAuthority {
                assignment_id: existing.assignment_id,
                attempt_id: existing.attempt_id,
                offer_epoch: existing.offer_epoch,
            }
        } else {
            let (attempts, offer_epoch) = {
                let record = self
                    .coordinator
                    .durable_state_mut()
                    .automated_runs
                    .get_mut(&run_id)
                    .expect("selected compiler run exists");
                record.assignment_retry.attempts =
                    record.assignment_retry.attempts.saturating_add(1);
                record.assignment_retry.next_offer_epoch = record
                    .assignment_retry
                    .next_offer_epoch
                    .saturating_add(1)
                    .max(1);
                (
                    record.assignment_retry.attempts,
                    record.assignment_retry.next_offer_epoch,
                )
            };
            let attempt_id = format!(
                "compile-attempt-{}",
                Digest::sha256(format!("{}\0{attempts}", run_id.as_str()))
                    .as_str()
                    .trim_start_matches("sha256:")
            );
            super::TaskRegistry::offer_active_assignment(
                self.coordinator.durable_state_mut(),
                kind,
                tenant.clone(),
                project.clone(),
                node.clone(),
                attempt_id,
                offer_epoch,
                now,
                SYSTEM_ASSIGNMENT_OFFER_SECONDS,
                run_id.as_str(),
            )
        };
        let expires_at_epoch_seconds = super::TaskRegistry::active_assignment(
            self.coordinator.durable_state(),
            &authority.assignment_id,
        )
        .expect("offered compiler assignment is active")
        .lease_expires_at;
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&run_id)
            .expect("selected compiler run exists");
        record.run.state = AutomatedRunState::CompilingWorkflow;
        record.run.waiting_reason = None;
        let request = record.compilation_request.clone();
        self.persist_durable_state()?;
        Ok(request.map(|request| NodeAssignmentOffer {
            assignment_id: authority.assignment_id,
            attempt_id: authority.attempt_id,
            tenant: tenant.clone(),
            project: project.clone(),
            node: node.clone(),
            lease_epoch: authority.offer_epoch,
            expires_at_epoch_seconds,
            work: NodeAssignmentWork::SystemTask {
                assignment: Box::new(SystemTaskAssignment {
                    owner: SystemTaskOwner::AutomatedRun {
                        run_id: request.run_id.clone(),
                    },
                    bundle_id: clusterflux_core::WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID.to_owned(),
                    bundle_digest: clusterflux_core::workflow_compiler_system_bundle_digest(),
                    environment_digest: request.compiler_image.clone(),
                    task: SystemTaskKind::CompileWorkflow {
                        request: Box::new(request),
                    },
                }),
            },
        }))
    }

    pub(super) fn acknowledge_system_task_offer(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
        assignment_id: &str,
        lease_epoch: u64,
        authority: &AssignmentAuthority,
    ) -> Result<bool, CoordinatorServiceError> {
        let now = self.current_epoch_seconds()?;
        let record =
            super::TaskRegistry::active_assignment(self.coordinator.durable_state(), assignment_id)
                .and_then(|active| match &active.kind {
                    AssignmentKind::WorkflowCompiler { run_id } => {
                        self.coordinator.durable_state().automated_runs.get(run_id)
                    }
                    AssignmentKind::ProcessTask { .. } => None,
                });
        let Some(record) = record else {
            return Ok(false);
        };
        if &record.run.tenant != tenant || &record.run.project != project {
            return Ok(false);
        }
        let assignment_seconds = record
            .compilation_request
            .as_ref()
            .map(|request| {
                request
                    .resource_policy
                    .wall_clock_seconds
                    .saturating_add(30)
            })
            .unwrap_or(SYSTEM_ASSIGNMENT_LEASE_SECONDS)
            .max(SYSTEM_ASSIGNMENT_LEASE_SECONDS);
        if authority.assignment_id != assignment_id || authority.offer_epoch != lease_epoch {
            return Ok(false);
        }
        if super::TaskRegistry::acknowledge_active_assignment(
            self.coordinator.durable_state_mut(),
            &NodeScopeKey::from_refs(tenant, project, node),
            authority,
            now,
            assignment_seconds,
        ) {
            self.persist_durable_state()?;
            return Ok(true);
        }
        Ok(false)
    }

    pub(super) fn active_node_assignment_is_authorized(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
        active: &ActiveNodeAssignment,
        now: u64,
    ) -> Result<bool, CoordinatorServiceError> {
        let authority = AssignmentAuthority {
            assignment_id: active.assignment_id.clone(),
            attempt_id: active.attempt_id.clone(),
            offer_epoch: active.lease_epoch,
        };
        let Some(assignment) = super::TaskRegistry::active_assignment(
            self.coordinator.durable_state(),
            &active.assignment_id,
        )
        .cloned() else {
            return Ok(false);
        };
        let assignment_seconds = match &assignment.kind {
            AssignmentKind::WorkflowCompiler { run_id } => {
                let Some(record) = self.coordinator.durable_state().automated_runs.get(run_id)
                else {
                    return Ok(false);
                };
                if record.run.tenant != *tenant
                    || record.run.project != *project
                    || !matches!(record.run.state, AutomatedRunState::CompilingWorkflow)
                    || record.compilation_request.is_none()
                    || record.compiled_bundle.is_some()
                {
                    return Ok(false);
                }
                record
                    .compilation_request
                    .as_ref()
                    .map(|request| {
                        request
                            .resource_policy
                            .wall_clock_seconds
                            .saturating_add(30)
                    })
                    .unwrap_or(SYSTEM_ASSIGNMENT_LEASE_SECONDS)
                    .max(SYSTEM_ASSIGNMENT_LEASE_SECONDS)
            }
            AssignmentKind::ProcessTask { process, task } => {
                if self
                    .coordinator
                    .active_process(tenant, project, process)
                    .is_none()
                    || self
                        .process_registry
                        .is_cancelled(&super::keys::process_control_key(tenant, project, process))
                    || self
                        .task_registry
                        .checkpoint(&super::keys::task_restart_key(
                            tenant, project, process, task,
                        ))
                        .is_none()
                {
                    return Ok(false);
                }
                180
            }
        };
        let authorized = super::TaskRegistry::authorize_active_assignment(
            self.coordinator.durable_state_mut(),
            &NodeScopeKey::from_refs(tenant, project, node),
            &authority,
            now,
            assignment_seconds,
        );
        if authorized {
            self.persist_durable_state()?;
        }
        Ok(authorized)
    }

    pub fn report_system_task(
        &mut self,
        result: SystemTaskResult,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        result
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        if result.bundle_id != clusterflux_core::WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID
            || result.bundle_digest != clusterflux_core::workflow_compiler_system_bundle_digest()
        {
            return Err(CoordinatorError::Unauthorized(
                "system task result does not match this release's pinned bundle".to_owned(),
            )
            .into());
        }
        match result.result {
            SystemTaskOutput::CompileWorkflow { result } => self.report_compile_workflow(*result),
        }
    }

    #[cfg(test)]
    pub fn report_system_compile_for_test(
        &mut self,
        result: WorkflowCompilationResult,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        self.report_system_task(SystemTaskResult {
            bundle_id: clusterflux_core::WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID.to_owned(),
            bundle_digest: clusterflux_core::workflow_compiler_system_bundle_digest(),
            result: SystemTaskOutput::CompileWorkflow {
                result: Box::new(result),
            },
        })
    }

    fn report_compile_workflow(
        &mut self,
        result: WorkflowCompilationResult,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        result
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        let existing_record = self
            .coordinator
            .durable_state()
            .automated_runs
            .get(&result.run_id)
            .cloned()
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        let authority = AssignmentAuthority {
            assignment_id: result.assignment_id.clone(),
            attempt_id: result.attempt_id.clone(),
            offer_epoch: result.lease_epoch,
        };
        let assignment_scope = NodeScopeKey::new(
            existing_record.run.tenant.clone(),
            existing_record.run.project.clone(),
            result.node.clone(),
        );
        if existing_record.run.state.is_terminal() {
            if super::TaskRegistry::terminal_assignment_matches(
                self.coordinator.durable_state(),
                &assignment_scope,
                &authority,
            ) {
                return Ok(existing_record);
            }
            return Err(CoordinatorError::Unauthorized(
                "terminal system task result does not match retained assignment history".to_owned(),
            )
            .into());
        }
        let now = self.current_epoch_seconds()?;
        let active_kind_matches = super::TaskRegistry::active_assignment(
            self.coordinator.durable_state(),
            &result.assignment_id,
        )
        .is_some_and(|active| {
            active.kind
                == (AssignmentKind::WorkflowCompiler {
                    run_id: result.run_id.clone(),
                })
        });
        let active_authorized = active_kind_matches
            && super::TaskRegistry::active_assignment_is_authorized(
                self.coordinator.durable_state(),
                &assignment_scope,
                &authority,
                now,
            );
        let terminal_authorized = super::TaskRegistry::terminal_assignment_matches(
            self.coordinator.durable_state(),
            &assignment_scope,
            &authority,
        );
        if !active_authorized && !terminal_authorized {
            return Err(CoordinatorError::Unauthorized(
                "system task result is stale, expired, or was not acknowledged".to_owned(),
            )
            .into());
        }
        if let Some(bundle) = &existing_record.compiled_bundle {
            if result
                .bundle
                .as_ref()
                .map(|candidate| &candidate.bundle_digest)
                != Some(&bundle.bundle_digest)
            {
                return Err(CoordinatorServiceError::Protocol(
                    "compiler result was retried with different content".to_owned(),
                ));
            }
            return Ok(existing_record);
        }
        if let Some(bundle) = &result.bundle {
            validate_compiled_module(
                bundle,
                existing_record.run.workflow_tree_digest.as_ref(),
                existing_record.compilation_request.as_ref(),
            )?;
            let source_environments = existing_record
                .compilation_request
                .as_ref()
                .map(|request| request.source.environments.clone())
                .unwrap_or_default();
            if bundle.environments != source_environments {
                return Err(CoordinatorServiceError::Protocol(
                    "compiled bundle environment identities do not match the exact triggered revision"
                        .to_owned(),
                ));
            }
        }
        let failure_ended_at = result
            .bundle
            .is_none()
            .then(|| self.current_epoch_seconds())
            .transpose()?;
        super::TaskRegistry::terminalize_active_assignment(
            self.coordinator.durable_state_mut(),
            &authority,
            now,
            true,
        );
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(&result.run_id)
            .expect("compiler result run existence was checked above");
        if let Some(bundle) = result.bundle {
            record.run.bundle_digest = Some(bundle.bundle_digest.clone());
            record.compiled_bundle = Some(bundle);
            record.run.state = AutomatedRunState::WaitingForProcessSlot;
        } else if result.retryable
            && record.assignment_retry.attempts < MAX_SYSTEM_ASSIGNMENT_ATTEMPTS
        {
            record.run.state = AutomatedRunState::WaitingForCompilerNode;
            record.run.waiting_reason = Some("eligible_node_retry_pending".to_owned());
        } else {
            record.run.state = AutomatedRunState::Failed;
            record.run.ended_at = failure_ended_at;
            record.run.failure_code = result.failure_code;
            record.run.failure_message = Some(result.compiler_transcript);
            record.compilation_request = None;
            record.source = None;
            record.compiled_bundle = None;
            if result.retryable {
                record.run.failure_message = Some(format!(
                    "workflow compilation exhausted {} bounded node attempts: {}",
                    MAX_SYSTEM_ASSIGNMENT_ATTEMPTS,
                    record.run.failure_message.as_deref().unwrap_or("")
                ));
            }
        }
        let response = record.clone();
        self.persist_durable_state()?;
        Ok(response)
    }

    pub fn launch_automated_run(
        &mut self,
        run_id: &RunId,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        let snapshot = self
            .coordinator
            .durable_state()
            .automated_runs
            .get(run_id)
            .cloned()
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        if snapshot.run.state == AutomatedRunState::Running || snapshot.run.state.is_terminal() {
            return Ok(snapshot);
        }
        let bundle = snapshot.compiled_bundle.clone().ok_or_else(|| {
            CoordinatorServiceError::Protocol("automated run is not compiled".to_owned())
        })?;
        let revision = snapshot.revision.clone().ok_or_else(|| {
            CoordinatorServiceError::Protocol("automated run has no repository revision".to_owned())
        })?;
        let entrypoint_export =
            compiled_entrypoint_export(&bundle.module_base64, bundle.default_entrypoint.as_str())?;
        if let Some(active) = self
            .coordinator
            .active_process_for_project(&snapshot.run.tenant, &snapshot.run.project)
        {
            if snapshot.run.process_id.as_ref() != Some(&active.id) {
                let record = self
                    .coordinator
                    .durable_state_mut()
                    .automated_runs
                    .get_mut(run_id)
                    .expect("run exists");
                record.run.state = AutomatedRunState::WaitingForProcessSlot;
                let response = record.clone();
                self.persist_durable_state()?;
                return Ok(response);
            }
        }

        let process = snapshot
            .run
            .process_id
            .clone()
            .unwrap_or_else(|| process_id_for_run(run_id));
        let launch_attempt = snapshot
            .launch_attempt
            .clone()
            .unwrap_or_else(|| format!("launch-{}", id_suffix(run_id.as_str())));
        {
            let record = self
                .coordinator
                .durable_state_mut()
                .automated_runs
                .get_mut(run_id)
                .expect("run exists");
            record.run.state = AutomatedRunState::Launching;
            record.run.process_id = Some(process.clone());
            record.launch_attempt = Some(launch_attempt.clone());
        }
        self.persist_durable_state()?;

        let process_epoch = match self.handle_start_process(
            snapshot.run.tenant.as_str().to_owned(),
            snapshot.run.project.as_str().to_owned(),
            Some("clusterflux-trigger".to_owned()),
            None,
            None,
            None,
            None,
            process.as_str().to_owned(),
            Some(launch_attempt.clone()),
            false,
        )? {
            CoordinatorResponse::ProcessStarted { epoch, .. } => epoch,
            _ => {
                return Err(CoordinatorServiceError::Protocol(
                    "automated process start returned an unexpected response".to_owned(),
                ))
            }
        };
        let context = TriggerContext {
            trigger_id: snapshot.run.primary_trigger_id.clone(),
            forge: self
                .coordinator
                .durable_state()
                .accepted_commit_triggers
                .get(&snapshot.run.primary_trigger_id)
                .map(|record| record.trigger.forge.clone())
                .ok_or_else(|| {
                    CoordinatorServiceError::Protocol("run trigger was removed".to_owned())
                })?,
            repository_id: snapshot.run.repository_id.clone(),
            commit_sha: snapshot.run.commit_sha.clone(),
            git_ref: snapshot.run.git_ref.clone(),
            event_kind: clusterflux_core::TriggerEventKind::Push,
            trusted: snapshot.run.trusted,
            source_snapshot: revision.source_snapshot.clone(),
        };
        context
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        {
            let record = self
                .coordinator
                .durable_state_mut()
                .automated_runs
                .get_mut(run_id)
                .expect("run exists");
            record.trigger_context = Some(context);
        }
        self.persist_durable_state()?;

        let task_spec = TaskSpec {
            tenant: snapshot.run.tenant.clone(),
            project: snapshot.run.project.clone(),
            process: process.clone(),
            task_definition: TaskDefinitionId::new(bundle.default_entrypoint.clone()),
            task_instance: TaskInstanceId::new(format!("main-{}", id_suffix(run_id.as_str()))),
            dispatch: TaskDispatch::CoordinatorNodeWasm {
                export: Some(entrypoint_export),
                abi: WasmExportAbi::EntrypointV1,
            },
            environment_id: None,
            environment: None,
            environment_digest: None,
            required_capabilities: BTreeSet::new(),
            dependency_cache: None,
            source_snapshot: Some(revision.source_snapshot.clone()),
            source_revision: Some(revision.clone()),
            required_artifacts: Vec::new(),
            args: Vec::new(),
            requested_secrets: Vec::new(),
            vfs_epoch: process_epoch,
            failure_policy: TaskFailurePolicy::FailFast,
            bundle_digest: Some(bundle.execution_module_digest.clone()),
        };
        let launch_result = self.handle_launch_task(
            snapshot.run.tenant.as_str().to_owned(),
            snapshot.run.project.as_str().to_owned(),
            Some("clusterflux-trigger".to_owned()),
            None,
            None,
            None,
            None,
            task_spec,
            false,
            String::new(),
            bundle.module_base64.clone(),
        );
        if let Err(error) = launch_result {
            let _ = self.handle_abort_process(
                snapshot.run.tenant.as_str().to_owned(),
                snapshot.run.project.as_str().to_owned(),
                "clusterflux-trigger".to_owned(),
                process.as_str().to_owned(),
                Some(launch_attempt),
            );
            self.fail_automated_run(run_id, "launch_failed", &error.to_string())?;
            return Err(error);
        }

        let now = self.current_epoch_seconds()?;
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(run_id)
            .expect("run exists");
        record.run.state = AutomatedRunState::Running;
        record.run.started_at.get_or_insert(now);
        record.compiled_summary = Some(clusterflux_core::CompiledWorkflowSummary::from(&bundle));
        record.compiled_bundle = None;
        record.compilation_request = None;
        record.source = None;
        let response = record.clone();
        self.persist_durable_state()?;
        Ok(response)
    }

    pub fn automated_run(&self, run_id: &RunId) -> Option<&AutomatedRunStageRecord> {
        self.coordinator.durable_state().automated_runs.get(run_id)
    }

    pub(super) fn automated_trigger_context(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Option<TriggerContext> {
        self.coordinator
            .durable_state()
            .automated_runs
            .values()
            .find(|record| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.process_id.as_ref() == Some(process)
            })
            .and_then(|record| record.trigger_context.clone())
    }

    pub(super) fn automated_source_revision(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Option<clusterflux_core::RepositoryRevision> {
        self.coordinator
            .durable_state()
            .automated_runs
            .values()
            .find(|record| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.process_id.as_ref() == Some(process)
            })
            .and_then(|record| record.revision.clone())
    }

    pub(super) fn record_automated_process_waiting_reason(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        reason: Option<&str>,
    ) {
        let reason = reason.map(super::processes::bounded_waiting_reason);
        let Some(record) = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .values_mut()
            .find(|record| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.process_id.as_ref() == Some(process)
                    && !record.run.state.is_terminal()
            })
        else {
            return;
        };
        if record.run.waiting_reason == reason {
            return;
        }
        record.run.waiting_reason = reason;
        let _ = self.persist_durable_state();
    }

    pub(super) fn automated_environment_definitions(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> std::collections::BTreeMap<String, clusterflux_core::EnvironmentResource> {
        let Some(run) = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .find(|record| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.process_id.as_ref() == Some(process)
            })
        else {
            return std::collections::BTreeMap::new();
        };
        run.revision_environments
            .iter()
            .map(|environment| (environment.name.clone(), environment.clone()))
            .collect()
    }

    pub(super) fn record_automated_publication_boundary(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        boundary: Option<&TaskBoundaryValue>,
    ) {
        let Some(boundary) = boundary else {
            return;
        };
        let Ok(value) = boundary.materialize() else {
            return;
        };
        let Ok(Some(publication)) = serde_json::from_value::<Option<PublicationResult>>(value)
        else {
            return;
        };
        if publication.validate().is_err() {
            return;
        }
        let Some(record) = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .values_mut()
            .find(|record| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.process_id.as_ref() == Some(process)
            })
        else {
            return;
        };
        record.run.publication_tag = Some(publication.tag);
        record.run.publication_url = Some(publication.release_url);
        let _ = self.persist_durable_state();
    }

    pub fn automated_runs(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> Vec<AutomatedRunRecord> {
        let mut runs = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| &record.run.tenant == tenant && &record.run.project == project)
            .map(|record| record.run.clone())
            .collect::<Vec<_>>();
        runs.sort_by(|left, right| {
            right
                .created_at
                .cmp(&left.created_at)
                .then_with(|| right.run_id.cmp(&left.run_id))
        });
        runs
    }

    pub fn automated_runs_page(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        cursor: Option<&str>,
        limit: usize,
    ) -> Result<(Vec<AutomatedRunRecord>, Option<String>), CoordinatorServiceError> {
        if limit == 0 || limit > MAX_RUNS_PER_PROJECT {
            return Err(CoordinatorServiceError::Protocol(format!(
                "automated run page limit must be between 1 and {MAX_RUNS_PER_PROJECT}"
            )));
        }
        let runs = self.automated_runs(tenant, project);
        let start = match cursor {
            None => 0,
            Some(cursor) => runs
                .iter()
                .position(|run| run.run_id.as_str() == cursor)
                .map(|index| index + 1)
                .ok_or_else(|| {
                    CoordinatorServiceError::Protocol(
                        "automated run cursor is unknown or expired".to_owned(),
                    )
                })?,
        };
        let end = start.saturating_add(limit).min(runs.len());
        let page = runs[start..end].to_vec();
        let next_cursor = (end < runs.len()).then(|| {
            page.last()
                .expect("non-empty page before more records")
                .run_id
                .to_string()
        });
        Ok((page, next_cursor))
    }

    pub fn cancel_automated_run(
        &mut self,
        run_id: &RunId,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        let snapshot = self
            .automated_run(run_id)
            .cloned()
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        if snapshot.run.state.is_terminal() {
            return Ok(snapshot);
        }
        if let Some(process) = &snapshot.run.process_id {
            if self
                .coordinator
                .active_process(&snapshot.run.tenant, &snapshot.run.project, process)
                .is_some()
            {
                self.handle_cancel_process(
                    snapshot.run.tenant.as_str().to_owned(),
                    snapshot.run.project.as_str().to_owned(),
                    "clusterflux-trigger".to_owned(),
                    process.as_str().to_owned(),
                )?;
            }
        }
        let now = self.current_epoch_seconds()?;
        self.terminalize_system_assignment_for_run(run_id, now);
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(run_id)
            .expect("run exists");
        record.run.state = AutomatedRunState::Cancelled;
        record.run.ended_at = Some(now);
        record.compilation_request = None;
        record.source = None;
        record.compiled_bundle = None;
        let response = record.clone();
        self.persist_durable_state()?;
        Ok(response)
    }

    pub fn retry_automated_run(
        &mut self,
        run_id: &RunId,
    ) -> Result<AutomatedRunStageRecord, CoordinatorServiceError> {
        let snapshot = self
            .automated_run(run_id)
            .cloned()
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        if !matches!(
            snapshot.run.state,
            AutomatedRunState::Failed | AutomatedRunState::Cancelled
        ) {
            return Err(CoordinatorServiceError::Protocol(
                "only failed or cancelled automated runs can be retried".to_owned(),
            ));
        }
        let accepted_trigger = self
            .coordinator
            .durable_state()
            .accepted_commit_triggers
            .get(&snapshot.run.primary_trigger_id)
            .cloned()
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    "automated run no longer has retained trigger source".to_owned(),
                )
            })?;
        let queued = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| {
                record.run.tenant == snapshot.run.tenant
                    && record.run.project == snapshot.run.project
                    && !record.run.state.is_terminal()
                    && record.run.state != AutomatedRunState::Running
            })
            .count();
        if queued >= MAX_QUEUED_RUNS_PER_PROJECT {
            return Err(CoordinatorServiceError::Protocol(format!(
                "project automated-run queue is full ({MAX_QUEUED_RUNS_PER_PROJECT})"
            )));
        }
        self.compact_automated_run_history(&snapshot.run.tenant, &snapshot.run.project)?;
        let retained = self
            .coordinator
            .durable_state()
            .automated_runs
            .values()
            .filter(|record| {
                record.run.tenant == snapshot.run.tenant
                    && record.run.project == snapshot.run.project
            })
            .count();
        if retained >= MAX_RUNS_PER_PROJECT {
            return Err(CoordinatorServiceError::Protocol(format!(
                "project automated-run retention is full ({MAX_RUNS_PER_PROJECT})"
            )));
        }

        let (run_key, retry_number) = (1_u32..=MAX_RUNS_PER_PROJECT as u32)
            .find_map(|retry_number| {
                let retry = retry_number.to_string();
                let key = Digest::from_parts([
                    b"clusterflux-automated-run-retry:v1".as_slice(),
                    run_id.as_str().as_bytes(),
                    retry.as_bytes(),
                ]);
                (!self
                    .coordinator
                    .durable_state()
                    .automated_run_keys
                    .contains_key(&key))
                .then_some((key, retry_number))
            })
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol("automated run retry history is full".to_owned())
            })?;
        let retry_run_id = run_id_from_key(&run_key);
        let retry_trigger_id = TriggerId::new(format!(
            "trigger-retry-{}",
            id_suffix(retry_run_id.as_str())
        ));
        let now = self.current_epoch_seconds()?;
        let mut trigger = accepted_trigger.trigger;
        trigger.trigger_id = retry_trigger_id.clone();
        trigger.delivery_id = format!("manual-retry-{}-{retry_number}", run_id.as_str());
        trigger.received_at = now;

        let mut run = snapshot.run;
        run.run_id = retry_run_id.clone();
        run.primary_trigger_id = retry_trigger_id.clone();
        run.workflow_tree_digest = None;
        run.bundle_digest = None;
        run.state = AutomatedRunState::Accepted;
        run.process_id = None;
        run.created_at = now;
        run.started_at = None;
        run.ended_at = None;
        run.failure_code = None;
        run.failure_message = None;
        run.waiting_reason = None;
        run.publication_tag = None;
        run.publication_url = None;
        let record = AutomatedRunStageRecord {
            run,
            run_key: run_key.clone(),
            source: None,
            revision_environments: Vec::new(),
            revision: None,
            compilation_request: None,
            assignment_retry: Default::default(),
            compiled_bundle: None,
            compiled_summary: None,
            trigger_context: None,
            launch_attempt: None,
        };
        let durable = self.coordinator.durable_state_mut();
        durable.accepted_commit_triggers.insert(
            retry_trigger_id,
            AcceptedCommitTriggerRecord {
                tenant: accepted_trigger.tenant,
                project: accepted_trigger.project,
                binding_id: accepted_trigger.binding_id,
                body_digest: Digest::sha256(format!(
                    "manual-retry\0{}\0{retry_number}",
                    run_id.as_str()
                )),
                trigger,
            },
        );
        durable
            .automated_run_keys
            .insert(run_key, retry_run_id.clone());
        durable.automated_runs.insert(retry_run_id, record.clone());
        self.persist_durable_state()?;
        Ok(record)
    }

    pub fn configure_project_environment(
        &mut self,
        record: ProjectEnvironmentRecord,
    ) -> Result<(), CoordinatorServiceError> {
        if record.name.is_empty() || record.name.len() > 128 {
            return Err(CoordinatorServiceError::Protocol(
                "environment name is empty or too long".to_owned(),
            ));
        }
        if record.definition.name != record.name {
            return Err(CoordinatorServiceError::Protocol(
                "environment record name does not match its definition".to_owned(),
            ));
        }
        if record
            .definition
            .requirements
            .arch
            .as_ref()
            .is_some_and(|arch| arch.trim().is_empty() || arch.len() > 128)
        {
            return Err(CoordinatorServiceError::Protocol(
                "environment architecture is empty or too long".to_owned(),
            ));
        }
        if record.immutable_digest != record.definition.digest {
            return Err(CoordinatorServiceError::Protocol(
                "environment immutable digest does not match its definition".to_owned(),
            ));
        }
        self.coordinator
            .durable_state_mut()
            .project_environments
            .insert(
                (
                    record.tenant.clone(),
                    record.project.clone(),
                    record.name.clone(),
                ),
                record,
            );
        self.persist_durable_state()
    }

    pub(super) fn record_automated_process_terminal(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        result: &ProcessFinalResult,
        now: u64,
    ) {
        let failure_message = matches!(result, ProcessFinalResult::Failed)
            .then(|| self.automated_process_failure_message(tenant, project, process));
        let Some(record) = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .values_mut()
            .find(|record| {
                &record.run.tenant == tenant
                    && &record.run.project == project
                    && record.run.process_id.as_ref() == Some(process)
            })
        else {
            return;
        };
        record.run.state = match result {
            ProcessFinalResult::Completed => AutomatedRunState::Completed,
            ProcessFinalResult::Failed => AutomatedRunState::Failed,
            ProcessFinalResult::Cancelled => AutomatedRunState::Cancelled,
        };
        record.run.waiting_reason = None;
        record.run.ended_at = Some(now);
        if let Some(message) = failure_message {
            record.run.failure_code = Some("process_failed".to_owned());
            record.run.failure_message = Some(message);
        }
        let _ = self.persist_durable_state();
    }

    fn automated_process_failure_message(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> String {
        let failed_events = || {
            self.task_registry.events().rev().filter(|event| {
                &event.tenant == tenant
                    && &event.project == project
                    && &event.process == process
                    && event.terminal_state == TaskTerminalState::Failed
            })
        };
        let event = failed_events()
            .find(|event| event.executor == TaskExecutor::Node)
            .or_else(|| failed_events().next());
        let Some(event) = event else {
            return "The automated process failed without a retained task diagnostic.".to_owned();
        };
        let detail = event.stderr_tail.trim();
        let detail = if detail.is_empty() {
            event.status_code.map_or_else(
                || "no error text was reported".to_owned(),
                |status| format!("command exited with status {status}"),
            )
        } else {
            detail.to_owned()
        };
        bounded_automated_failure_message(
            &format!("Task {} ({}) failed:", event.task, event.task_definition),
            &detail,
        )
    }

    fn fail_automated_run(
        &mut self,
        run_id: &RunId,
        code: &str,
        message: &str,
    ) -> Result<(), CoordinatorServiceError> {
        let now = self.current_epoch_seconds()?;
        self.terminalize_system_assignment_for_run(run_id, now);
        let record = self
            .coordinator
            .durable_state_mut()
            .automated_runs
            .get_mut(run_id)
            .ok_or_else(|| CoordinatorServiceError::Protocol("unknown automated run".to_owned()))?;
        if record.run.state.is_terminal() {
            return Ok(());
        }
        record.run.state = AutomatedRunState::Failed;
        record.run.ended_at = Some(now);
        record.run.failure_code = Some(code.to_owned());
        record.run.failure_message = Some(
            message
                .chars()
                .take(clusterflux_core::MAX_AUTOMATED_RUN_FAILURE_BYTES)
                .collect(),
        );
        record.compilation_request = None;
        record.source = None;
        record.compiled_bundle = None;
        self.persist_durable_state()
    }
}

fn bounded_automated_failure_message(prefix: &str, detail: &str) -> String {
    let maximum = clusterflux_core::MAX_AUTOMATED_RUN_FAILURE_BYTES;
    let separator = "\n…\n";
    if prefix.len() + 1 + detail.len() <= maximum {
        return format!("{prefix} {detail}");
    }
    let available = maximum.saturating_sub(prefix.len() + separator.len());
    let mut start = detail.len().saturating_sub(available);
    while start < detail.len() && !detail.is_char_boundary(start) {
        start += 1;
    }
    format!("{prefix}{separator}{}", &detail[start..])
}

fn compiled_entrypoint_export(
    module_base64: &str,
    default_entrypoint: &str,
) -> Result<String, CoordinatorServiceError> {
    let module = BASE64_STANDARD.decode(module_base64).map_err(|error| {
        CoordinatorServiceError::Protocol(format!(
            "compiled workflow module is not valid base64: {error}"
        ))
    })?;
    let descriptors = descriptor_records(&module, "clusterflux.entrypoints")
        .map_err(CoordinatorServiceError::Protocol)?;
    let descriptor = select_entrypoint(&descriptors, Some(default_entrypoint))
        .map_err(CoordinatorServiceError::Protocol)?;
    descriptor
        .get("export")
        .and_then(serde_json::Value::as_str)
        .filter(|export| !export.trim().is_empty())
        .map(str::to_owned)
        .ok_or_else(|| {
            CoordinatorServiceError::Protocol(format!(
                "entrypoint `{default_entrypoint}` descriptor omitted its Wasm export"
            ))
        })
}

fn validate_compiled_module(
    bundle: &CompiledWorkflowBundle,
    expected_source: Option<&Digest>,
    request: Option<&WorkflowCompilationRequest>,
) -> Result<(), CoordinatorServiceError> {
    bundle
        .validate_metadata()
        .map_err(CoordinatorServiceError::Protocol)?;
    if Some(&bundle.source_tree_digest) != expected_source {
        return Err(CoordinatorServiceError::Protocol(
            "compiled bundle source digest does not match its run".to_owned(),
        ));
    }
    if Some(&bundle.manifest_digest) != request.map(|request| &request.source.manifest.digest) {
        return Err(CoordinatorServiceError::Protocol(
            "compiled bundle manifest digest does not match its run".to_owned(),
        ));
    }
    let request = request.ok_or_else(|| {
        CoordinatorServiceError::Protocol(
            "compiled bundle has no authoritative compiler request".to_owned(),
        )
    })?;
    if bundle.compiler_identity.profile != clusterflux_core::CompilerProfile::HostedSandbox
        || bundle.compiler_identity.sdk_digest != request.compiler_sdk
        || bundle.compiler_identity.sandbox_image_digest.as_ref() != Some(&request.compiler_image)
        || bundle.compiler_identity.rustc_version != request.rust_toolchain
        || bundle.compiler_identity.target != "wasm32-unknown-unknown"
        || bundle.compiler_identity.sdk_version != clusterflux_core::SUPPORTED_WORKFLOW_SDK_VERSION
        || !bundle
            .compiler_identity
            .flags
            .iter()
            .map(String::as_str)
            .eq([
                "-Copt-level=1",
                "-Cdebuginfo=2",
                "-Cstrip=none",
                "-Cpanic=abort",
                "--remap-path-prefix=/workspace=.clusterflux",
            ])
    {
        return Err(CoordinatorServiceError::Protocol(
            "compiled bundle compiler, SDK, or sandbox identity does not match its assignment"
                .to_owned(),
        ));
    }
    if bundle.sdk_abi_version != clusterflux_core::WASM_TASK_ABI_VERSION {
        return Err(CoordinatorServiceError::Protocol(format!(
            "compiled bundle ABI {} is unsupported",
            bundle.sdk_abi_version
        )));
    }
    let bytes = BASE64_STANDARD
        .decode(&bundle.module_base64)
        .map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "compiled workflow module is not valid base64: {error}"
            ))
        })?;
    wasmparser::Validator::new()
        .validate_all(&bytes)
        .map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "compiled workflow module is invalid Wasm: {error}"
            ))
        })?;
    if bytes.len() > clusterflux_core::automation::MAX_COMPILED_WORKFLOW_MODULE_BYTES
        || Digest::sha256(&bytes) != bundle.execution_module_digest
    {
        return Err(CoordinatorServiceError::Protocol(
            "compiled workflow module is oversized or has the wrong digest".to_owned(),
        ));
    }
    let dependencies = &bundle.compiler_identity.trusted_dependencies;
    if dependencies.len() != 1
        || dependencies[0].package != "serde"
        || dependencies[0].version != clusterflux_core::SUPPORTED_WORKFLOW_SERDE_VERSION
        || dependencies[0].features.as_slice() != ["derive"]
        || !dependencies[0].digest.is_valid_sha256()
    {
        return Err(CoordinatorServiceError::Protocol(
            "compiled bundle trusted dependency identity does not match this release".to_owned(),
        ));
    }
    let descriptor_names = |section: &str| -> Result<Vec<String>, CoordinatorServiceError> {
        let mut names = descriptor_records(&bytes, section)
            .map_err(CoordinatorServiceError::Protocol)?
            .into_iter()
            .map(|descriptor| {
                descriptor
                    .get("name")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| {
                        CoordinatorServiceError::Protocol(format!(
                            "compiled workflow {section} descriptor omitted its name"
                        ))
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        names.sort();
        names.dedup();
        Ok(names)
    };
    if descriptor_names("clusterflux.entrypoints")? != bundle.entrypoints
        || descriptor_names("clusterflux.tasks")? != bundle.task_definitions
    {
        return Err(CoordinatorServiceError::Protocol(
            "compiled workflow descriptors do not match the returned bundle metadata".to_owned(),
        ));
    }
    let embedded_environments = super::main_runtime::bundle_environments(&bytes)?;
    let returned_environments = bundle
        .environments
        .iter()
        .cloned()
        .map(|environment| (environment.name.clone(), environment))
        .collect::<std::collections::BTreeMap<_, _>>();
    if embedded_environments != returned_environments {
        return Err(CoordinatorServiceError::Protocol(
            "compiled workflow embedded environments do not match the returned identities"
                .to_owned(),
        ));
    }
    Ok(())
}

fn run_id_from_key(key: &Digest) -> RunId {
    RunId::new(format!("run-{}", &key.as_str()["sha256:".len()..]))
}

fn process_id_for_run(run_id: &RunId) -> ProcessId {
    ProcessId::new(format!("process-{}", id_suffix(run_id.as_str())))
}

fn id_suffix(value: &str) -> &str {
    value.rsplit('-').next().unwrap_or(value)
}

#[cfg(test)]
mod compiled_entrypoint_export_tests {
    use super::*;

    fn leb_u32(mut value: u32) -> Vec<u8> {
        let mut encoded = Vec::new();
        loop {
            let mut byte = (value & 0x7f) as u8;
            value >>= 7;
            if value != 0 {
                byte |= 0x80;
            }
            encoded.push(byte);
            if value == 0 {
                return encoded;
            }
        }
    }

    fn descriptor_module(descriptor: &serde_json::Value) -> String {
        let section_name = b"clusterflux.entrypoints";
        let mut section = leb_u32(section_name.len() as u32);
        section.extend_from_slice(section_name);
        section.extend_from_slice(serde_json::to_string(descriptor).unwrap().as_bytes());
        section.push(b'\n');
        let mut module = b"\0asm\x01\0\0\0".to_vec();
        module.push(0);
        module.extend(leb_u32(section.len() as u32));
        module.extend(section);
        BASE64_STANDARD.encode(module)
    }

    #[test]
    fn automated_launch_uses_the_compiled_descriptor_export_not_its_public_name() {
        let module = descriptor_module(&serde_json::json!({
            "kind": "entrypoint",
            "name": "main",
            "export": "clusterflux_entry_v1_compiled_identity",
            "default": true,
        }));

        assert_eq!(
            compiled_entrypoint_export(&module, "main").unwrap(),
            "clusterflux_entry_v1_compiled_identity"
        );
    }
}
