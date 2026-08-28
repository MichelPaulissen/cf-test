use std::collections::BTreeSet;
use std::collections::{BTreeMap, VecDeque};

use clusterflux_core::{ProcessId, ProjectId, TaskInstanceId, TenantId};

use crate::CoordinatorError;

use super::debug::{DebugBreakpointPlan, DebugEpochRuntime, DebugPendingCommand};
use super::keys::{ProcessControlKey, TaskControlKey};
use super::protocol::{
    DebugAcknowledgementState, DebugAuditEvent, DebugParticipantAcknowledgement,
};
use super::CoordinatorServiceError;

/// Owns debug epochs, participant state, breakpoint plans, pending commands,
/// and bounded audit history. Process cleanup is atomic across all five stores.
#[derive(Default)]
pub(super) struct DebugRegistry {
    audit_events: VecDeque<DebugAuditEvent>,
    epochs: BTreeMap<ProcessControlKey, u64>,
    epoch_runtime: BTreeMap<ProcessControlKey, DebugEpochRuntime>,
    breakpoints: BTreeMap<ProcessControlKey, DebugBreakpointPlan>,
    commands: BTreeMap<TaskControlKey, DebugPendingCommand>,
}

impl DebugRegistry {
    pub(super) fn breakpoint(&self, key: &ProcessControlKey) -> Option<&DebugBreakpointPlan> {
        self.breakpoints.get(key)
    }

    pub(super) fn set_breakpoint(&mut self, key: ProcessControlKey, plan: DebugBreakpointPlan) {
        self.breakpoints.insert(key, plan);
    }

    pub(super) fn record_breakpoint_hit(
        &mut self,
        key: &ProcessControlKey,
        epoch: u64,
        task: TaskInstanceId,
        probe_symbol: String,
    ) {
        if let Some(plan) = self.breakpoints.get_mut(key) {
            plan.hit_epoch = Some(epoch);
            plan.hit_task = Some(task);
            plan.hit_probe_symbol = Some(probe_symbol);
        }
    }

    pub(super) fn take_command(&mut self, key: &TaskControlKey) -> Option<DebugPendingCommand> {
        self.commands.remove(key)
    }

    pub(super) fn queue_command(&mut self, key: TaskControlKey, command: DebugPendingCommand) {
        self.commands.insert(key, command);
    }

    pub(super) fn clear_task_command(&mut self, key: &TaskControlKey) {
        self.commands.remove(key);
    }

    pub(super) fn retain_resumable_commands(
        &mut self,
        epoch: u64,
        resumable: &BTreeSet<TaskControlKey>,
    ) {
        self.commands.retain(|key, pending| {
            pending.epoch != epoch || pending.command != "resume" || resumable.contains(key)
        });
    }

    pub(super) fn epoch(&self, key: &ProcessControlKey) -> Option<u64> {
        self.epochs.get(key).copied()
    }

    pub(super) fn set_epoch(&mut self, key: ProcessControlKey, epoch: u64) {
        self.epochs.insert(key, epoch);
    }

    pub(super) fn epoch_keys(&self) -> impl Iterator<Item = &ProcessControlKey> {
        self.epochs.keys()
    }

    pub(super) fn runtime(&self, key: &ProcessControlKey) -> Option<&DebugEpochRuntime> {
        self.epoch_runtime.get(key)
    }

    pub(super) fn set_runtime(&mut self, key: ProcessControlKey, runtime: DebugEpochRuntime) {
        self.epoch_runtime.insert(key, runtime);
    }

    pub(super) fn validate_acknowledgement_source(
        &self,
        key: &ProcessControlKey,
        participant: &TaskControlKey,
        process: &ProcessId,
        epoch: u64,
    ) -> Result<(), CoordinatorServiceError> {
        let runtime = self.epoch_runtime.get(key).ok_or_else(|| {
            CoordinatorServiceError::Protocol(format!(
                "cannot acknowledge debug epoch {epoch} for {process}: no active debug epoch"
            ))
        })?;
        if runtime.epoch != epoch {
            return Err(CoordinatorServiceError::Protocol(format!(
                "cannot acknowledge debug epoch {epoch} for {process}: current debug epoch is {}",
                runtime.epoch
            )));
        }
        if !runtime.expected.contains(participant) {
            return Err(CoordinatorError::Unauthorized(
                "debug acknowledgement is not from an expected active task participant".to_owned(),
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn record_acknowledgement(
        &mut self,
        key: &ProcessControlKey,
        participant: TaskControlKey,
        process: &ProcessId,
        acknowledgement: DebugParticipantAcknowledgement,
    ) -> Result<(), CoordinatorServiceError> {
        self.validate_acknowledgement_source(key, &participant, process, acknowledgement.epoch)?;
        let runtime = self
            .epoch_runtime
            .get_mut(key)
            .expect("debug acknowledgement source was validated immediately before mutation");
        let valid_state = matches!(
            (runtime.command.as_str(), &acknowledgement.state),
            ("freeze", DebugAcknowledgementState::Frozen)
                | ("resume", DebugAcknowledgementState::Running)
                | (_, DebugAcknowledgementState::Failed)
        );
        if !valid_state {
            return Err(CoordinatorServiceError::Protocol(format!(
                "debug epoch {} command `{}` cannot be acknowledged as {:?}",
                acknowledgement.epoch, runtime.command, acknowledgement.state
            )));
        }
        runtime
            .acknowledgements
            .insert(participant, acknowledgement);
        Ok(())
    }

    pub(super) fn clear_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        let process_key = (tenant.clone(), project.clone(), process.clone());
        self.epochs.remove(&process_key);
        self.epoch_runtime.remove(&process_key);
        self.breakpoints.remove(&process_key);
        self.commands
            .retain(|(task_tenant, task_project, task_process, _, _), _| {
                task_tenant != tenant || task_project != project || task_process != process
            });
    }

    pub(super) fn remove_audit_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.audit_events.retain(|event| {
            &event.tenant != tenant || &event.project != project || &event.process != process
        });
    }

    pub(super) fn append_audit(
        &mut self,
        event: DebugAuditEvent,
        per_process_capacity: usize,
        total_capacity: usize,
    ) {
        let mut retained_for_process = self
            .audit_events
            .iter()
            .filter(|retained| {
                retained.tenant == event.tenant
                    && retained.project == event.project
                    && retained.process == event.process
            })
            .count();
        while retained_for_process >= per_process_capacity {
            let Some(index) = self.audit_events.iter().position(|retained| {
                retained.tenant == event.tenant
                    && retained.project == event.project
                    && retained.process == event.process
            }) else {
                break;
            };
            self.audit_events.remove(index);
            retained_for_process -= 1;
        }
        while self.audit_events.len() >= total_capacity {
            self.audit_events.pop_front();
        }
        self.audit_events.push_back(event);
    }

    #[cfg(test)]
    pub(super) fn audit_events(&self) -> impl Iterator<Item = &DebugAuditEvent> {
        self.audit_events.iter()
    }

    #[cfg(test)]
    pub(super) fn audit_len(&self) -> usize {
        self.audit_events.len()
    }

    #[cfg(test)]
    pub(super) fn contains_epoch(&self, key: &ProcessControlKey) -> bool {
        self.epochs.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn contains_breakpoint(&self, key: &ProcessControlKey) -> bool {
        self.breakpoints.contains_key(key)
    }

    #[cfg(test)]
    pub(super) fn commands_are_outside_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.commands
            .keys()
            .all(|(task_tenant, task_project, task_process, _, _)| {
                task_tenant != tenant || task_project != project || task_process != process
            })
    }
}
