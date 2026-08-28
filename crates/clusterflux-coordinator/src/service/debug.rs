use std::collections::{BTreeMap, BTreeSet};
use std::time::Instant;

use clusterflux_core::{
    Actor, NodeId, ProcessId, ProjectId, TaskInstanceId, TenantId, UserId,
    WasmHostDebugProbeResult, WASM_TASK_ABI_VERSION,
};

use crate::{CoordinatorError, CoordinatorServiceError};

use super::keys::{process_control_key, task_control_key, task_restart_key, TaskControlKey};
use super::{
    CoordinatorResponse, CoordinatorService, DebugAcknowledgementState, DebugAuditEvent,
    DebugParticipantAcknowledgement, TaskCancellationTarget, DEBUG_CONTROL_READ_BYTES,
};

mod validation;
use validation::{runtime_all_in_state, validate_debug_snapshot, validate_probe_symbols};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DebugPendingCommand {
    pub(super) epoch: u64,
    pub(super) command: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DebugEpochRuntime {
    pub(super) epoch: u64,
    pub(super) command: String,
    pub(super) expected: BTreeSet<TaskControlKey>,
    pub(super) acknowledgements: BTreeMap<TaskControlKey, DebugParticipantAcknowledgement>,
    pub(super) deadline: Instant,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct DebugBreakpointPlan {
    pub(super) actor: UserId,
    pub(super) revision: u64,
    pub(super) probe_symbols: BTreeSet<String>,
    pub(super) probe_locations: BTreeMap<String, clusterflux_core::SourceLocation>,
    pub(super) hit_epoch: Option<u64>,
    pub(super) hit_task: Option<TaskInstanceId>,
    pub(super) hit_probe_symbol: Option<String>,
}

impl CoordinatorService {
    pub(super) fn handle_debug_attach(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        let source_revision = self.automated_source_revision(&tenant, &project, &process);
        let audit_event = self.record_debug_audit_event(
            tenant,
            project,
            process.clone(),
            None,
            actor.clone(),
            "debug_attach",
            authorization.allowed,
            authorization.reason.clone(),
        )?;
        Ok(CoordinatorResponse::DebugAttach {
            process,
            actor,
            authorization,
            source_revision,
            charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
            used_debug_read_bytes: audit_event.used_debug_read_bytes,
            audit_event,
        })
    }

    pub(super) fn handle_set_debug_breakpoints(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        revision: u64,
        probe_symbols: Vec<String>,
        probe_locations: Vec<clusterflux_core::SourceLocation>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let probe_symbols = validate_probe_symbols(probe_symbols)?;
        if (!probe_locations.is_empty() && probe_locations.len() != probe_symbols.len())
            || probe_locations.iter().any(|location| {
                !probe_symbols.contains(&location.probe_id)
                    || location.source_path.is_empty()
                    || location.source_path.len() > 512
                    || location.source_path.starts_with('/')
                    || location.source_path.contains("..")
                    || location.line == 0
            })
        {
            return Err(CoordinatorServiceError::Protocol(
                "debug probe source locations do not match the requested symbols".to_owned(),
            ));
        }
        let probe_locations = probe_locations
            .into_iter()
            .map(|location| (location.probe_id.clone(), location))
            .collect::<BTreeMap<_, _>>();
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        let audit_event = self.record_debug_audit_event(
            tenant.clone(),
            project.clone(),
            process.clone(),
            None,
            actor.clone(),
            "set_debug_breakpoints",
            authorization.allowed,
            authorization.reason.clone(),
        )?;
        if !authorization.allowed {
            return Err(CoordinatorError::Unauthorized(format!(
                "set_debug_breakpoints denied: {}",
                authorization.reason
            ))
            .into());
        }
        let key = process_control_key(&tenant, &project, &process);
        if let Some(current) = self.debug_registry.breakpoint(&key) {
            if current.actor == actor && revision <= current.revision {
                return Ok(CoordinatorResponse::DebugBreakpoints {
                    process,
                    actor,
                    revision: current.revision,
                    probe_symbols: current.probe_symbols.iter().cloned().collect(),
                    hit_epoch: current.hit_epoch,
                    hit_task: current.hit_task.clone(),
                    hit_probe_symbol: current.hit_probe_symbol.clone(),
                    hit_source_location: current
                        .hit_probe_symbol
                        .as_ref()
                        .and_then(|symbol| current.probe_locations.get(symbol))
                        .cloned(),
                    charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
                    used_debug_read_bytes: audit_event.used_debug_read_bytes,
                    audit_event,
                });
            }
        }
        self.debug_registry.set_breakpoint(
            key,
            DebugBreakpointPlan {
                actor: actor.clone(),
                revision,
                probe_symbols: probe_symbols.iter().cloned().collect(),
                probe_locations,
                hit_epoch: None,
                hit_task: None,
                hit_probe_symbol: None,
            },
        );
        Ok(CoordinatorResponse::DebugBreakpoints {
            process,
            actor,
            revision,
            probe_symbols,
            hit_epoch: None,
            hit_task: None,
            hit_probe_symbol: None,
            hit_source_location: None,
            charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
            used_debug_read_bytes: audit_event.used_debug_read_bytes,
            audit_event,
        })
    }

    pub(super) fn handle_inspect_debug_breakpoints(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        let plan = self
            .debug_registry
            .breakpoint(&process_control_key(&tenant, &project, &process))
            .cloned()
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(format!(
                    "no debug breakpoints are configured for {process}"
                ))
            })?;
        if plan.actor != actor {
            return Err(CoordinatorError::Unauthorized(
                "debug breakpoint inspection belongs to another authenticated user".to_owned(),
            )
            .into());
        }
        let audit_event = self.record_debug_audit_event(
            tenant,
            project,
            process.clone(),
            plan.hit_task.clone(),
            actor.clone(),
            "inspect_debug_breakpoints",
            authorization.allowed,
            authorization.reason.clone(),
        )?;
        if !authorization.allowed {
            return Err(CoordinatorError::Unauthorized(format!(
                "inspect_debug_breakpoints denied: {}",
                authorization.reason
            ))
            .into());
        }
        let hit_source_location = plan
            .hit_probe_symbol
            .as_ref()
            .and_then(|symbol| plan.probe_locations.get(symbol))
            .cloned();
        Ok(CoordinatorResponse::DebugBreakpoints {
            process,
            actor,
            revision: plan.revision,
            probe_symbols: plan.probe_symbols.into_iter().collect(),
            hit_epoch: plan.hit_epoch,
            hit_task: plan.hit_task,
            hit_probe_symbol: plan.hit_probe_symbol,
            hit_source_location,
            charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
            used_debug_read_bytes: audit_event.used_debug_read_bytes,
            audit_event,
        })
    }

    pub(super) fn handle_create_debug_epoch(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        stopped_task: String,
        reason: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.handle_debug_epoch_control(
            tenant,
            project,
            actor_user,
            process,
            Some(stopped_task),
            None,
            "create_debug_epoch",
            "freeze",
            true,
            reason,
        )
    }

    pub(super) fn handle_resume_debug_epoch(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        epoch: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.handle_debug_epoch_control(
            tenant,
            project,
            actor_user,
            process,
            None,
            Some(epoch),
            "resume_debug_epoch",
            "resume",
            false,
            "continue requested by debugger",
        )
    }

    pub(super) fn handle_poll_debug_command(
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
        let pending = self
            .debug_registry
            .take_command(&task_control_key(&tenant, &project, &process, &node, &task));
        Ok(CoordinatorResponse::DebugCommand {
            process,
            task,
            epoch: pending.as_ref().map(|command| command.epoch),
            command: pending.map(|command| command.command),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_report_debug_state(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        epoch: u64,
        state: DebugAcknowledgementState,
        current_source_location: Option<clusterflux_core::SourceLocation>,
        stack_frames: Vec<String>,
        local_values: Vec<(String, String)>,
        task_args: Vec<(String, String)>,
        handles: Vec<(String, String)>,
        command_status: Option<String>,
        recent_output: Vec<String>,
        message: Option<String>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        validate_debug_snapshot(
            &stack_frames,
            &local_values,
            &task_args,
            &handles,
            command_status.as_deref(),
            &recent_output,
            message.as_deref(),
            current_source_location.as_ref(),
        )?;
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        self.coordinator
            .authorize_node_for_process(&node, &tenant, &project, &process)?;
        let participant_key = task_control_key(&tenant, &project, &process, &node, &task);
        let process_key = process_control_key(&tenant, &project, &process);
        self.debug_registry.validate_acknowledgement_source(
            &process_key,
            &participant_key,
            &process,
            epoch,
        )?;
        let task_definition = self
            .task_registry
            .checkpoint(&task_restart_key(&tenant, &project, &process, &task))
            .map(|checkpoint| checkpoint.assignment.task_spec.task_definition.clone())
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "debug acknowledgement does not name a coordinator-issued task instance"
                        .to_owned(),
                )
            })?;
        self.debug_registry.record_acknowledgement(
            &process_key,
            participant_key,
            &process,
            DebugParticipantAcknowledgement {
                node: node.clone(),
                task_definition,
                task: task.clone(),
                epoch,
                state: state.clone(),
                current_source_location,
                stack_frames,
                local_values,
                task_args,
                handles,
                command_status,
                recent_output,
                message,
            },
        )?;
        Ok(CoordinatorResponse::DebugStateRecorded {
            process,
            node,
            task,
            epoch,
            state,
        })
    }

    pub(super) fn handle_report_debug_probe_hit(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        probe_symbol: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let probe_symbol = validate_probe_symbols(vec![probe_symbol])?
            .into_iter()
            .next()
            .expect("one validated probe symbol remains one symbol");
        let tenant_id = TenantId::new(tenant.clone());
        let project_id = ProjectId::new(project.clone());
        let process_id = ProcessId::new(process.clone());
        let node_id = NodeId::new(node.clone());
        let task_id = TaskInstanceId::new(task.clone());
        self.coordinator.authorize_node_for_process(
            &node_id,
            &tenant_id,
            &project_id,
            &process_id,
        )?;
        let participant_key =
            task_control_key(&tenant_id, &project_id, &process_id, &node_id, &task_id);
        if !self.task_registry.is_active(&participant_key) {
            return Err(CoordinatorError::Unauthorized(
                "debug probe hit is not from an active task participant".to_owned(),
            )
            .into());
        }
        let attempt_key = task_restart_key(&tenant_id, &project_id, &process_id, &task_id);
        self.task_registry
            .update_current_attempt(&attempt_key, |attempt| {
                attempt.probe_symbol = Some(probe_symbol.clone());
            });
        let process_key = process_control_key(&tenant_id, &project_id, &process_id);
        let Some(plan) = self.debug_registry.breakpoint(&process_key).cloned() else {
            return Ok(CoordinatorResponse::DebugProbeHit {
                process: process_id,
                node: node_id,
                task: task_id,
                probe_symbol,
                breakpoint_matched: false,
                debug_epoch: None,
            });
        };
        if !plan.probe_symbols.contains(&probe_symbol) {
            return Ok(CoordinatorResponse::DebugProbeHit {
                process: process_id,
                node: node_id,
                task: task_id,
                probe_symbol,
                breakpoint_matched: false,
                debug_epoch: None,
            });
        }
        let response = self.handle_debug_epoch_control(
            tenant,
            project,
            plan.actor.as_str().to_owned(),
            process,
            Some(task.clone()),
            None,
            "wasm_debug_probe_hit",
            "freeze",
            true,
            format!("executing Wasm reached probe `{probe_symbol}`"),
        )?;
        let CoordinatorResponse::DebugEpoch { epoch, .. } = response else {
            unreachable!("debug epoch control always returns DebugEpoch")
        };
        self.debug_registry.record_breakpoint_hit(
            &process_key,
            epoch,
            task_id.clone(),
            probe_symbol.clone(),
        );
        Ok(CoordinatorResponse::DebugProbeHit {
            process: process_id,
            node: node_id,
            task: task_id,
            probe_symbol,
            breakpoint_matched: true,
            debug_epoch: Some(epoch),
        })
    }

    pub(super) fn handle_coordinator_main_debug_probe(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        task: TaskInstanceId,
        probe_symbol: String,
    ) -> Result<WasmHostDebugProbeResult, CoordinatorServiceError> {
        let probe_symbol = validate_probe_symbols(vec![probe_symbol])?
            .into_iter()
            .next()
            .expect("one validated probe symbol remains one symbol");
        let process_key = process_control_key(&tenant, &project, &process);
        let main_matches = self
            .main_runtime
            .controls
            .get(&process_key)
            .is_some_and(|control| control.task_instance == task);
        if !main_matches {
            return Err(CoordinatorError::Unauthorized(
                "debug probe does not belong to the active coordinator main participant".to_owned(),
            )
            .into());
        }
        let Some(plan) = self.debug_registry.breakpoint(&process_key).cloned() else {
            return Ok(WasmHostDebugProbeResult {
                abi_version: WASM_TASK_ABI_VERSION,
                breakpoint_matched: false,
                debug_epoch: None,
            });
        };
        if !plan.probe_symbols.contains(&probe_symbol) {
            return Ok(WasmHostDebugProbeResult {
                abi_version: WASM_TASK_ABI_VERSION,
                breakpoint_matched: false,
                debug_epoch: None,
            });
        }
        if let Some(control) = self.main_runtime.controls.get_mut(&process_key) {
            control.stopped_probe_symbol = Some(probe_symbol.clone());
        }
        let response = self.handle_debug_epoch_control(
            tenant.as_str().to_owned(),
            project.as_str().to_owned(),
            plan.actor.as_str().to_owned(),
            process.as_str().to_owned(),
            Some(task.as_str().to_owned()),
            None,
            "wasm_debug_probe_hit",
            "freeze",
            true,
            format!("coordinator main reached probe `{probe_symbol}`"),
        )?;
        let CoordinatorResponse::DebugEpoch { epoch, .. } = response else {
            unreachable!("debug epoch control always returns DebugEpoch")
        };
        self.debug_registry
            .record_breakpoint_hit(&process_key, epoch, task, probe_symbol);
        Ok(WasmHostDebugProbeResult {
            abi_version: WASM_TASK_ABI_VERSION,
            breakpoint_matched: true,
            debug_epoch: Some(epoch),
        })
    }

    pub(super) fn handle_inspect_debug_epoch(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        epoch: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        let process_key = process_control_key(&tenant, &project, &process);
        self.sync_coordinator_main_debug_acknowledgement(&process_key, epoch);
        let runtime = self
            .debug_registry
            .runtime(&process_key)
            .filter(|runtime| runtime.epoch == epoch)
            .cloned()
            .ok_or_else(|| {
                CoordinatorServiceError::Protocol(format!(
                    "debug epoch {epoch} is not active for {process}"
                ))
            })?;
        let audit_event = self.record_debug_audit_event(
            tenant,
            project,
            process.clone(),
            None,
            actor.clone(),
            "inspect_debug_epoch",
            authorization.allowed,
            authorization.reason.clone(),
        )?;
        if !authorization.allowed {
            return Err(CoordinatorError::Unauthorized(format!(
                "inspect_debug_epoch denied: {}",
                authorization.reason
            ))
            .into());
        }
        let acknowledgements = runtime
            .acknowledgements
            .values()
            .cloned()
            .collect::<Vec<_>>();
        let all_acknowledged = !runtime.expected.is_empty()
            && runtime
                .expected
                .iter()
                .all(|key| runtime.acknowledgements.contains_key(key));
        let fully_frozen = runtime.command == "freeze"
            && all_acknowledged
            && acknowledgements
                .iter()
                .all(|ack| ack.state == DebugAcknowledgementState::Frozen);
        let frozen_count = acknowledgements
            .iter()
            .filter(|ack| ack.state == DebugAcknowledgementState::Frozen)
            .count();
        let freeze_deadline_elapsed =
            runtime.command == "freeze" && Instant::now() >= runtime.deadline;
        let partially_frozen = runtime.command == "freeze"
            && freeze_deadline_elapsed
            && frozen_count > 0
            && !fully_frozen;
        let fully_resumed = runtime.command == "resume"
            && all_acknowledged
            && acknowledgements
                .iter()
                .all(|ack| ack.state == DebugAcknowledgementState::Running);
        let missing = runtime
            .expected
            .iter()
            .filter(|key| !runtime.acknowledgements.contains_key(*key))
            .cloned()
            .collect::<Vec<_>>();
        let failed = acknowledgements
            .iter()
            .any(|ack| ack.state == DebugAcknowledgementState::Failed)
            || (freeze_deadline_elapsed && !missing.is_empty());
        let mut failure_messages = acknowledgements
            .iter()
            .filter(|ack| ack.state == DebugAcknowledgementState::Failed)
            .map(|ack| {
                ack.message
                    .clone()
                    .unwrap_or_else(|| format!("task {} failed debug control", ack.task))
            })
            .collect::<Vec<_>>();
        if freeze_deadline_elapsed {
            failure_messages.extend(missing.iter().map(|(_, _, _, node, task)| {
                format!(
                    "task {task} on node {node} did not acknowledge frozen state within {} ms",
                    self.debug_freeze_timeout.as_millis()
                )
            }));
        }
        let expected_tasks = runtime
            .expected
            .into_iter()
            .map(|(_, _, process, node, task)| TaskCancellationTarget {
                process,
                node,
                task,
            })
            .collect();
        Ok(CoordinatorResponse::DebugEpochStatus {
            process,
            actor,
            epoch,
            command: runtime.command,
            expected_tasks,
            acknowledgements,
            fully_frozen,
            partially_frozen,
            fully_resumed,
            failed,
            failure_messages,
            charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
            used_debug_read_bytes: audit_event.used_debug_read_bytes,
            audit_event,
        })
    }

    pub(super) fn clear_debug_state_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.debug_registry.clear_process(tenant, project, process);
    }

    fn handle_debug_epoch_control(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        stopped_task: Option<String>,
        expected_epoch: Option<u64>,
        operation: &'static str,
        command: &'static str,
        all_stop_requested: bool,
        reason: impl Into<String>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        let authorization = self.coordinator.authorize_debug_attach(&context, &process);
        let reason = reason.into();
        let audit_event = self.record_debug_audit_event(
            tenant.clone(),
            project.clone(),
            process.clone(),
            stopped_task.as_ref().map(TaskInstanceId::new),
            actor.clone(),
            operation,
            authorization.allowed,
            if authorization.allowed {
                reason
            } else {
                authorization.reason.clone()
            },
        )?;
        if !authorization.allowed {
            return Err(CoordinatorError::Unauthorized(format!(
                "{operation} denied: {}",
                authorization.reason
            ))
            .into());
        }

        let process_key = process_control_key(&tenant, &project, &process);
        let epoch = match expected_epoch {
            Some(expected) => {
                let current = self.debug_registry.epoch(&process_key).ok_or_else(|| {
                    CoordinatorServiceError::Protocol(format!(
                        "cannot resume debug epoch {expected} for {process}: no active debug epoch"
                    ))
                })?;
                if current != expected {
                    return Err(CoordinatorServiceError::Protocol(format!(
                        "cannot resume debug epoch {expected} for {process}: current debug epoch is {current}"
                    )));
                }
                let runtime = self.debug_registry.runtime(&process_key).ok_or_else(|| {
                    CoordinatorServiceError::Protocol(format!(
                        "cannot resume debug epoch {expected} for {process}: participant state is unavailable"
                    ))
                })?;
                let has_frozen = runtime
                    .acknowledgements
                    .values()
                    .any(|ack| ack.state == DebugAcknowledgementState::Frozen);
                let settled = runtime
                    .expected
                    .iter()
                    .all(|key| runtime.acknowledgements.contains_key(key))
                    || Instant::now() >= runtime.deadline;
                if runtime.command != "freeze" || !has_frozen || !settled {
                    return Err(CoordinatorServiceError::Protocol(format!(
                        "cannot resume debug epoch {expected} for {process}: no settled frozen participant set is available"
                    )));
                }
                current
            }
            None => {
                if let Some(runtime) = self.debug_registry.runtime(&process_key) {
                    let previous_complete = runtime.command == "resume"
                        && runtime_all_in_state(runtime, DebugAcknowledgementState::Running);
                    if !previous_complete {
                        return Err(CoordinatorServiceError::Protocol(format!(
                            "cannot create a new debug epoch for {process}: epoch {} has not fully resumed",
                            runtime.epoch
                        )));
                    }
                }
                let next = self.debug_registry.epoch(&process_key).unwrap_or(0) + 1;
                self.debug_registry.set_epoch(process_key.clone(), next);
                next
            }
        };
        let resumable = if command == "resume" {
            self.debug_registry
                .runtime(&process_key)
                .map(|runtime| {
                    runtime
                        .acknowledgements
                        .iter()
                        .filter(|(_, ack)| ack.state == DebugAcknowledgementState::Frozen)
                        .map(|(key, _)| key.clone())
                        .collect::<BTreeSet<_>>()
                })
                .unwrap_or_default()
        } else {
            BTreeSet::new()
        };
        let mut affected_tasks = self
            .enqueue_debug_command_for_active_tasks(&tenant, &project, &process, epoch, command);
        let mut expected = self
            .task_registry
            .active_tasks()
            .filter(|(task_tenant, task_project, task_process, _, _)| {
                task_tenant == &tenant && task_project == &project && task_process == &process
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        if let Some(control) = self
            .main_runtime
            .controls
            .get(&process_key)
            .filter(|control| matches!(control.state.as_str(), "running" | "stopping"))
        {
            let key = task_control_key(
                &tenant,
                &project,
                &process,
                &NodeId::from("coordinator-main"),
                &control.task_instance,
            );
            expected.insert(key);
            affected_tasks.push(TaskCancellationTarget {
                process: process.clone(),
                node: NodeId::from("coordinator-main"),
                task: control.task_instance.clone(),
            });
        }
        if command == "resume" {
            expected.retain(|key| resumable.contains(key));
            affected_tasks.retain(|target| {
                resumable
                    .iter()
                    .any(|(_, _, _, node, task)| node == &target.node && task == &target.task)
            });
            self.debug_registry
                .retain_resumable_commands(epoch, &resumable);
        }
        self.debug_registry.set_runtime(
            process_key.clone(),
            DebugEpochRuntime {
                epoch,
                command: command.to_owned(),
                expected,
                acknowledgements: BTreeMap::new(),
                deadline: Instant::now() + self.debug_freeze_timeout,
            },
        );
        if let Some(control) = self
            .main_runtime
            .controls
            .get(&process_key)
            .filter(|control| matches!(control.state.as_str(), "running" | "stopping"))
        {
            if command == "freeze" {
                control.debug.request_freeze(epoch);
            } else if resumable.contains(&task_control_key(
                &tenant,
                &project,
                &process,
                &NodeId::from("coordinator-main"),
                &control.task_instance,
            )) {
                control.debug.request_resume(epoch);
            }
        }
        self.sync_coordinator_main_debug_acknowledgement(&process_key, epoch);
        Ok(CoordinatorResponse::DebugEpoch {
            process,
            actor,
            epoch,
            command: command.to_owned(),
            affected_tasks,
            all_stop_requested,
            charged_debug_read_bytes: audit_event.charged_debug_read_bytes,
            used_debug_read_bytes: audit_event.used_debug_read_bytes,
            audit_event,
        })
    }

    fn sync_coordinator_main_debug_acknowledgement(
        &mut self,
        process_key: &super::keys::ProcessControlKey,
        epoch: u64,
    ) {
        let Some(control) = self.main_runtime.controls.get(process_key) else {
            return;
        };
        let Some(runtime) = self.debug_registry.runtime(process_key) else {
            return;
        };
        if runtime.epoch != epoch {
            return;
        }
        let state = if runtime.command == "freeze" && control.debug.frozen_epoch() == Some(epoch) {
            Some(DebugAcknowledgementState::Frozen)
        } else if runtime.command == "resume"
            && control.debug.resume_requested(epoch)
            && control.debug.frozen_epoch() != Some(epoch)
        {
            Some(DebugAcknowledgementState::Running)
        } else {
            None
        };
        let Some(state) = state else {
            return;
        };
        let handles = control
            .handles
            .lock()
            .map(|handles| {
                let mut snapshot = handles
                    .iter()
                    .map(|(handle_id, spec)| {
                        (
                            format!("task_handle_{handle_id}"),
                            format!(
                                "definition={} instance={} state=active",
                                spec.task_definition, spec.task_instance
                            ),
                        )
                    })
                    .collect::<Vec<_>>();
                snapshot.sort_by(|left, right| left.0.cmp(&right.0));
                snapshot
            })
            .unwrap_or_else(|_| {
                vec![(
                    "handle-registry-diagnostic".to_owned(),
                    "coordinator main handle registry was unavailable".to_owned(),
                )]
            });
        let node = NodeId::from("coordinator-main");
        let key = task_control_key(
            &process_key.0,
            &process_key.1,
            &process_key.2,
            &node,
            &control.task_instance,
        );
        if !runtime.expected.contains(&key) {
            return;
        }
        self.debug_registry
            .record_acknowledgement(
                process_key,
                key,
                &process_key.2,
                DebugParticipantAcknowledgement {
                    node,
                    task_definition: control.task_definition.clone(),
                    task: control.task_instance.clone(),
                    epoch,
                    state,
                    current_source_location: control.debug.current_source_location(),
                    stack_frames: control
                        .stopped_probe_symbol
                        .as_deref()
                        .and_then(|symbol| symbol.strip_prefix("clusterflux.probe."))
                        .map(|function| format!("{function}::wasm"))
                        .into_iter()
                        .collect(),
                    local_values: Vec::new(),
                    task_args: Vec::new(),
                    handles,
                    command_status: None,
                    recent_output: vec![
                        "coordinator-hosted capless main acknowledged all-stop control".to_owned(),
                    ],
                    message: None,
                },
            )
            .expect("coordinator-main acknowledgement was validated before it was recorded");
    }

    fn enqueue_debug_command_for_active_tasks(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        epoch: u64,
        command: &str,
    ) -> Vec<TaskCancellationTarget> {
        let task_keys = self
            .task_registry
            .active_tasks()
            .filter(|(task_tenant, task_project, task_process, _, _)| {
                task_tenant == tenant && task_project == project && task_process == process
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in &task_keys {
            self.debug_registry.queue_command(
                key.clone(),
                DebugPendingCommand {
                    epoch,
                    command: command.to_owned(),
                },
            );
        }
        task_keys
            .into_iter()
            .map(|(_, _, process, node, task)| TaskCancellationTarget {
                process,
                task,
                node,
            })
            .collect()
    }

    pub(super) fn record_debug_audit_event(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        task: Option<TaskInstanceId>,
        actor: UserId,
        operation: &'static str,
        allowed: bool,
        reason: impl Into<String>,
    ) -> Result<DebugAuditEvent, CoordinatorServiceError> {
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let charged_debug_read_bytes = if allowed {
            self.quota.charge_debug_read(
                &tenant,
                &project,
                DEBUG_CONTROL_READ_BYTES,
                now_epoch_seconds,
            )?;
            DEBUG_CONTROL_READ_BYTES
        } else {
            0
        };
        let used_debug_read_bytes =
            self.quota
                .used_debug_read_bytes(&tenant, &project, now_epoch_seconds);
        let event = DebugAuditEvent {
            tenant,
            project,
            process,
            task,
            actor,
            operation: operation.to_owned(),
            allowed,
            reason: reason.into(),
            charged_debug_read_bytes,
            used_debug_read_bytes,
        };
        self.debug_registry.append_audit(
            event.clone(),
            super::MAX_DEBUG_AUDIT_EVENTS_PER_PROCESS,
            super::MAX_DEBUG_AUDIT_EVENTS_TOTAL,
        );
        Ok(event)
    }
}
