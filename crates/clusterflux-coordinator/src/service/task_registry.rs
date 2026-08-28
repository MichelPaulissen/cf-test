use std::collections::{BTreeMap, BTreeSet, VecDeque};

use clusterflux_core::{
    AssignmentAuthority, Digest, NodeId, Placement, ProcessId, ProjectId, TaskInstanceId, TenantId,
};

use super::keys::{TaskAssignmentKey, TaskControlKey, TaskRestartKey};
use super::processes::{PendingTaskLaunch, TaskRestartCheckpoint};
use super::protocol::{
    TaskAssignment, TaskAttemptSnapshot, TaskAttemptState, TaskCompletionEvent,
    TaskFailureResolution, TaskTerminalState,
};
use crate::durable::{
    ActiveAssignmentRecord, AssignmentKind, AssignmentMutationRecord, AssignmentMutationResponse,
    AssignmentState, DurableState, NodeScopeKey, TerminalAssignmentRecord,
};

const MAX_TERMINAL_ASSIGNMENT_HISTORY: usize = 4_096;
const MAX_TERMINAL_MUTATIONS_PER_ASSIGNMENT: usize = 256;

pub(super) enum AssignmentMutationReplay {
    Missing,
    Exact(Box<clusterflux_protocol::CoordinatorResponse>),
    Conflict,
}

/// Owns every remote-task lifecycle collection. The façade may orchestrate
/// cross-domain work, but admission, indexing, transitions, and cleanup happen
/// through these methods so the collections cannot drift independently.
#[derive(Default)]
pub(super) struct TaskRegistry {
    task_events: VecDeque<TaskCompletionEvent>,
    task_terminal_states: BTreeMap<TaskRestartKey, TaskTerminalState>,
    task_assignments: BTreeMap<TaskAssignmentKey, VecDeque<TaskAssignment>>,
    task_restart_checkpoints: BTreeMap<TaskRestartKey, TaskRestartCheckpoint>,
    task_restart_checkpoint_order: VecDeque<TaskRestartKey>,
    task_attempts: BTreeMap<TaskRestartKey, Vec<TaskAttemptSnapshot>>,
    restart_launches: BTreeSet<TaskRestartKey>,
    pending_task_launches: VecDeque<PendingTaskLaunch>,
    task_placements: BTreeMap<TaskControlKey, Placement>,
    active_tasks: BTreeSet<TaskControlKey>,
    task_cancellations: BTreeSet<TaskControlKey>,
    task_aborts: BTreeSet<TaskControlKey>,
}

impl TaskRegistry {
    pub(super) fn offer_active_assignment(
        durable: &mut DurableState,
        kind: AssignmentKind,
        tenant: TenantId,
        project: ProjectId,
        node: NodeId,
        attempt_id: String,
        offer_epoch: u64,
        now: u64,
        offer_seconds: u64,
        owner_identity: &str,
    ) -> AssignmentAuthority {
        let identity = format!("{owner_identity}\0{attempt_id}\0{offer_epoch}");
        let assignment_id = format!(
            "assignment-{}",
            Digest::sha256(identity)
                .as_str()
                .trim_start_matches("sha256:")
        );
        let authority = AssignmentAuthority {
            assignment_id: assignment_id.clone(),
            attempt_id: attempt_id.clone(),
            offer_epoch,
        };
        durable.active_assignments.insert(
            assignment_id.clone(),
            ActiveAssignmentRecord {
                assignment_id,
                kind,
                tenant,
                project,
                node,
                attempt_id,
                offer_epoch,
                state: AssignmentState::Offered,
                offered_at: now,
                acknowledged_at: None,
                lease_expires_at: now.saturating_add(offer_seconds),
                terminal_mutations: VecDeque::new(),
            },
        );
        authority
    }

    pub(super) fn acknowledge_active_assignment(
        durable: &mut DurableState,
        scope: &NodeScopeKey,
        authority: &AssignmentAuthority,
        now: u64,
        assignment_seconds: u64,
    ) -> bool {
        let Some(active) = durable.active_assignments.get_mut(&authority.assignment_id) else {
            return Self::terminal_assignment_matches(durable, scope, authority);
        };
        if active.tenant != scope.tenant
            || active.project != scope.project
            || active.node != scope.node
            || active.attempt_id != authority.attempt_id
            || active.offer_epoch != authority.offer_epoch
            || active.lease_expires_at < now
            || !matches!(
                active.state,
                AssignmentState::Offered | AssignmentState::Acknowledged | AssignmentState::Running
            )
        {
            return false;
        }
        if active.acknowledged_at.is_none() {
            active.acknowledged_at = Some(now);
        }
        active.state = AssignmentState::Acknowledged;
        active.lease_expires_at = now.saturating_add(assignment_seconds);
        true
    }

    pub(super) fn authorize_active_assignment(
        durable: &mut DurableState,
        scope: &NodeScopeKey,
        authority: &AssignmentAuthority,
        now: u64,
        assignment_seconds: u64,
    ) -> bool {
        let Some(active) = durable.active_assignments.get_mut(&authority.assignment_id) else {
            return false;
        };
        if active.tenant != scope.tenant
            || active.project != scope.project
            || active.node != scope.node
            || active.attempt_id != authority.attempt_id
            || active.offer_epoch != authority.offer_epoch
            || active.acknowledged_at.is_none()
            || active.lease_expires_at < now
            || !matches!(
                active.state,
                AssignmentState::Acknowledged | AssignmentState::Running
            )
        {
            return false;
        }
        active.state = AssignmentState::Running;
        active.lease_expires_at = now.saturating_add(assignment_seconds);
        true
    }

    pub(super) fn active_assignment_is_authorized(
        durable: &DurableState,
        scope: &NodeScopeKey,
        authority: &AssignmentAuthority,
        now: u64,
    ) -> bool {
        durable
            .active_assignments
            .get(&authority.assignment_id)
            .is_some_and(|active| {
                active.tenant == scope.tenant
                    && active.project == scope.project
                    && active.node == scope.node
                    && active.attempt_id == authority.attempt_id
                    && active.offer_epoch == authority.offer_epoch
                    && active.acknowledged_at.is_some()
                    && active.lease_expires_at >= now
                    && matches!(
                        active.state,
                        AssignmentState::Acknowledged | AssignmentState::Running
                    )
            })
    }

    pub(super) fn terminalize_active_assignment(
        durable: &mut DurableState,
        authority: &AssignmentAuthority,
        now: u64,
        replay_allowed: bool,
    ) -> Option<ActiveAssignmentRecord> {
        let mut active = durable
            .active_assignments
            .remove(&authority.assignment_id)?;
        if active.attempt_id != authority.attempt_id || active.offer_epoch != authority.offer_epoch
        {
            durable
                .active_assignments
                .insert(active.assignment_id.clone(), active);
            return None;
        }
        active.state = AssignmentState::Terminal;
        while durable.terminal_assignment_history.len() >= MAX_TERMINAL_ASSIGNMENT_HISTORY {
            durable.terminal_assignment_history.pop_front();
        }
        durable
            .terminal_assignment_history
            .push_back(TerminalAssignmentRecord {
                assignment_id: active.assignment_id.clone(),
                tenant: active.tenant.clone(),
                project: active.project.clone(),
                node: active.node.clone(),
                attempt_id: active.attempt_id.clone(),
                offer_epoch: active.offer_epoch,
                terminal_at: now,
                replay_allowed,
                terminal_mutations: std::mem::take(&mut active.terminal_mutations),
            });
        Some(active)
    }

    pub(super) fn expired_active_assignments(
        durable: &DurableState,
        now: u64,
    ) -> Vec<ActiveAssignmentRecord> {
        durable
            .active_assignments
            .values()
            .filter(|active| active.lease_expires_at < now)
            .cloned()
            .collect()
    }

    pub(super) fn active_assignment<'a>(
        durable: &'a DurableState,
        assignment_id: &str,
    ) -> Option<&'a ActiveAssignmentRecord> {
        durable.active_assignments.get(assignment_id)
    }

    pub(super) fn active_assignment_for_kind<'a>(
        durable: &'a DurableState,
        kind: &AssignmentKind,
    ) -> Option<&'a ActiveAssignmentRecord> {
        durable
            .active_assignments
            .values()
            .find(|active| &active.kind == kind)
    }

    pub(super) fn terminal_assignment_matches(
        durable: &DurableState,
        scope: &NodeScopeKey,
        authority: &AssignmentAuthority,
    ) -> bool {
        durable
            .terminal_assignment_history
            .iter()
            .rev()
            .find(|terminal| terminal.assignment_id == authority.assignment_id)
            .is_some_and(|terminal| {
                terminal.replay_allowed
                    && terminal.tenant == scope.tenant
                    && terminal.project == scope.project
                    && terminal.node == scope.node
                    && terminal.attempt_id == authority.attempt_id
                    && terminal.offer_epoch == authority.offer_epoch
            })
    }

    pub(super) fn assignment_mutation_replay(
        durable: &DurableState,
        scope: &NodeScopeKey,
        authority: &AssignmentAuthority,
        process: &ProcessId,
        task: &TaskInstanceId,
        operation_id: &str,
        payload_digest: &Digest,
    ) -> AssignmentMutationReplay {
        let mutations = durable
            .active_assignments
            .get(&authority.assignment_id)
            .filter(|active| {
                active.tenant == scope.tenant
                    && active.project == scope.project
                    && active.node == scope.node
                    && active.attempt_id == authority.attempt_id
                    && active.offer_epoch == authority.offer_epoch
            })
            .map(|active| &active.terminal_mutations)
            .or_else(|| {
                durable
                    .terminal_assignment_history
                    .iter()
                    .rev()
                    .find(|terminal| {
                        terminal.replay_allowed
                            && terminal.assignment_id == authority.assignment_id
                            && terminal.tenant == scope.tenant
                            && terminal.project == scope.project
                            && terminal.node == scope.node
                            && terminal.attempt_id == authority.attempt_id
                            && terminal.offer_epoch == authority.offer_epoch
                    })
                    .map(|terminal| &terminal.terminal_mutations)
            });
        let Some(record) = mutations.and_then(|mutations| {
            mutations.iter().rev().find(|record| {
                record.process == *process
                    && record.task == *task
                    && record.operation_id == operation_id
            })
        }) else {
            return AssignmentMutationReplay::Missing;
        };
        if record.payload_digest == *payload_digest {
            AssignmentMutationReplay::Exact(Box::new(record.response.coordinator_response()))
        } else {
            AssignmentMutationReplay::Conflict
        }
    }

    pub(super) fn record_assignment_mutation(
        durable: &mut DurableState,
        authority: &AssignmentAuthority,
        process: ProcessId,
        task: TaskInstanceId,
        operation_id: String,
        payload_digest: Digest,
        response: &clusterflux_protocol::CoordinatorResponse,
    ) -> bool {
        let Some(response) = AssignmentMutationResponse::from_coordinator_response(response) else {
            return false;
        };
        let mutations = if let Some(active) = durable
            .active_assignments
            .get_mut(&authority.assignment_id)
            .filter(|active| {
                active.attempt_id == authority.attempt_id
                    && active.offer_epoch == authority.offer_epoch
            }) {
            &mut active.terminal_mutations
        } else if let Some(terminal) =
            durable
                .terminal_assignment_history
                .iter_mut()
                .rev()
                .find(|terminal| {
                    terminal.replay_allowed
                        && terminal.assignment_id == authority.assignment_id
                        && terminal.attempt_id == authority.attempt_id
                        && terminal.offer_epoch == authority.offer_epoch
                })
        {
            &mut terminal.terminal_mutations
        } else {
            return false;
        };
        while mutations.len() >= MAX_TERMINAL_MUTATIONS_PER_ASSIGNMENT {
            mutations.pop_front();
        }
        mutations.push_back(AssignmentMutationRecord {
            process,
            task,
            operation_id,
            payload_digest,
            response,
        });
        true
    }

    pub(super) fn active_task_spec(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        node: &NodeId,
        task: &TaskInstanceId,
    ) -> Option<&clusterflux_core::TaskSpec> {
        let control_key = (
            tenant.clone(),
            project.clone(),
            process.clone(),
            node.clone(),
            task.clone(),
        );
        if !self.active_tasks.contains(&control_key) {
            return None;
        }
        self.task_restart_checkpoints
            .get(&(
                tenant.clone(),
                project.clone(),
                process.clone(),
                task.clone(),
            ))
            .map(|checkpoint| &checkpoint.assignment.task_spec)
    }

    pub(super) fn events(
        &self,
    ) -> impl DoubleEndedIterator<Item = &TaskCompletionEvent> + ExactSizeIterator {
        self.task_events.iter()
    }

    pub(super) fn append_event(
        &mut self,
        event: TaskCompletionEvent,
        per_process_capacity: usize,
        total_capacity: usize,
    ) {
        let mut retained_for_process = self
            .task_events
            .iter()
            .filter(|retained| same_event_process(retained, &event))
            .count();
        while retained_for_process >= per_process_capacity {
            let Some(index) = self
                .task_events
                .iter()
                .position(|retained| same_event_process(retained, &event))
            else {
                break;
            };
            self.task_events.remove(index);
            retained_for_process -= 1;
        }
        while self.task_events.len() >= total_capacity {
            self.task_events.pop_front();
        }
        self.task_events.push_back(event);
    }

    pub(super) fn remove_events_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.task_events.retain(|event| {
            &event.tenant != tenant || &event.project != project || &event.process != process
        });
    }

    pub(super) fn has_event_in_scope(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.task_events.iter().any(|event| {
            &event.tenant == tenant && &event.project == project && &event.process == process
        })
    }

    pub(super) fn has_process_event_outside_scope(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.task_events.iter().any(|event| {
            &event.process == process && (&event.tenant != tenant || &event.project != project)
        })
    }

    pub(super) fn last_event_for_task(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> Option<&TaskCompletionEvent> {
        self.task_events.iter().rev().find(|event| {
            &event.tenant == tenant
                && &event.project == project
                && &event.process == process
                && &event.task == task
        })
    }

    pub(super) fn event_for_attempt(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
        attempt_id: &str,
    ) -> Option<&TaskCompletionEvent> {
        self.task_events.iter().rev().find(|event| {
            &event.tenant == tenant
                && &event.project == project
                && &event.process == process
                && &event.task == task
                && event.attempt_id.as_deref() == Some(attempt_id)
        })
    }

    pub(super) fn set_terminal_state(&mut self, key: TaskRestartKey, state: TaskTerminalState) {
        self.task_terminal_states.insert(key, state);
    }

    pub(super) fn has_terminal_state_for_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        state: TaskTerminalState,
    ) -> bool {
        self.task_terminal_states.iter().any(|(key, retained)| {
            &key.0 == tenant && &key.1 == project && &key.2 == process && retained == &state
        })
    }

    pub(super) fn poll_assignment(&self, key: &TaskAssignmentKey) -> Option<TaskAssignment> {
        self.task_assignments.get(key)?.front().cloned()
    }

    pub(super) fn acknowledge_process_assignment(
        &mut self,
        durable: &mut DurableState,
        key: &TaskAssignmentKey,
        authority: &AssignmentAuthority,
        now: u64,
        assignment_seconds: u64,
    ) -> bool {
        let queued_match = self
            .task_assignments
            .get(key)
            .and_then(|assignments| assignments.front())
            .is_some_and(|front| {
                front.assignment_id == authority.assignment_id
                    && front.attempt_id == authority.attempt_id
                    && front.offer_epoch == authority.offer_epoch
            });
        if !queued_match {
            return Self::acknowledge_active_assignment(
                durable,
                &NodeScopeKey::new(key.0.clone(), key.1.clone(), key.2.clone()),
                authority,
                now,
                assignment_seconds,
            );
        }
        if !Self::acknowledge_active_assignment(
            durable,
            &NodeScopeKey::new(key.0.clone(), key.1.clone(), key.2.clone()),
            authority,
            now,
            assignment_seconds,
        ) {
            return false;
        }
        let assignments_empty = {
            let assignments = self
                .task_assignments
                .get_mut(key)
                .expect("matching queued assignment remains present");
            assignments.pop_front();
            assignments.is_empty()
        };
        if assignments_empty {
            self.task_assignments.remove(key);
        }
        true
    }

    pub(super) fn enqueue_assignment(&mut self, assignment: TaskAssignment) {
        let key = (
            assignment.tenant.clone(),
            assignment.project.clone(),
            assignment.node.clone(),
        );
        self.task_assignments
            .entry(key)
            .or_default()
            .push_back(assignment);
    }

    pub(super) fn assignments_for_node(
        &self,
        key: &TaskAssignmentKey,
    ) -> impl Iterator<Item = &TaskAssignment> {
        self.task_assignments
            .get(key)
            .into_iter()
            .flat_map(|assignments| assignments.iter())
    }

    pub(super) fn remove_assignment_for_task(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        node: &NodeId,
        task: &TaskInstanceId,
    ) {
        self.task_assignments.retain(|_, assignments| {
            assignments.retain(|assignment| {
                &assignment.tenant != tenant
                    || &assignment.project != project
                    || &assignment.process != process
                    || &assignment.node != node
                    || &assignment.task != task
            });
            !assignments.is_empty()
        });
    }

    pub(super) fn remove_assignments_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.task_assignments.retain(|_, assignments| {
            assignments.retain(|assignment| {
                &assignment.tenant != tenant
                    || &assignment.project != project
                    || &assignment.process != process
            });
            !assignments.is_empty()
        });
    }

    pub(super) fn take_pending_launches(&mut self) -> VecDeque<PendingTaskLaunch> {
        std::mem::take(&mut self.pending_task_launches)
    }

    pub(super) fn restore_pending_launches(&mut self, launches: VecDeque<PendingTaskLaunch>) {
        self.pending_task_launches = launches;
    }

    pub(super) fn push_pending_launch(&mut self, launch: PendingTaskLaunch) {
        self.pending_task_launches.push_back(launch);
    }

    pub(super) fn pending_launches(&self) -> impl Iterator<Item = &PendingTaskLaunch> {
        self.pending_task_launches.iter()
    }

    pub(super) fn pending_count(&self) -> usize {
        self.pending_task_launches.len()
    }

    pub(super) fn queued_count_for_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> usize {
        self.pending_task_launches
            .iter()
            .filter(|pending| {
                &pending.tenant == tenant
                    && &pending.project == project
                    && &pending.process == process
            })
            .count()
    }

    pub(super) fn pending_waiting_reason_for_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Option<&str> {
        self.pending_task_launches
            .iter()
            .find(|pending| {
                &pending.tenant == tenant
                    && &pending.project == project
                    && &pending.process == process
            })
            .map(|pending| pending.waiting_reason.as_str())
    }

    pub(super) fn in_flight_count(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> usize {
        self.active_process_tasks(tenant, project, process).len()
            + self.queued_count_for_process(tenant, project, process)
    }

    pub(super) fn remove_pending_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.pending_task_launches.retain(|pending| {
            &pending.tenant != tenant || &pending.project != project || &pending.process != process
        });
    }

    pub(super) fn checkpoint(&self, key: &TaskRestartKey) -> Option<&TaskRestartCheckpoint> {
        self.task_restart_checkpoints.get(key)
    }

    pub(super) fn checkpoints(&self) -> impl Iterator<Item = &TaskRestartCheckpoint> {
        self.task_restart_checkpoints.values()
    }

    #[cfg(test)]
    pub(super) fn checkpoint_count_for_process(&self, process: &ProcessId) -> usize {
        self.task_restart_checkpoints
            .keys()
            .filter(|key| &key.2 == process)
            .count()
    }

    pub(super) fn store_checkpoint(
        &mut self,
        key: TaskRestartKey,
        checkpoint: TaskRestartCheckpoint,
        per_process_capacity: usize,
        total_capacity: usize,
    ) -> Vec<TaskRestartKey> {
        let mut removed = Vec::new();
        if self.remove_checkpoint(&key) {
            removed.push(key.clone());
        }
        self.task_restart_checkpoints
            .insert(key.clone(), checkpoint);
        self.task_restart_checkpoint_order.push_back(key.clone());
        while self
            .task_restart_checkpoint_order
            .iter()
            .filter(|candidate| same_restart_process(candidate, &key))
            .count()
            > per_process_capacity
        {
            let Some(index) = self
                .task_restart_checkpoint_order
                .iter()
                .position(|candidate| same_restart_process(candidate, &key))
            else {
                break;
            };
            if let Some(expired) = self.task_restart_checkpoint_order.remove(index) {
                self.task_restart_checkpoints.remove(&expired);
                removed.push(expired);
            }
        }
        while self.task_restart_checkpoint_order.len() > total_capacity {
            if let Some(expired) = self.task_restart_checkpoint_order.pop_front() {
                self.task_restart_checkpoints.remove(&expired);
                removed.push(expired);
            }
        }
        removed
    }

    pub(super) fn remove_checkpoint(&mut self, key: &TaskRestartKey) -> bool {
        let removed = self.task_restart_checkpoints.remove(key).is_some();
        self.task_restart_checkpoint_order
            .retain(|retained| retained != key);
        removed
    }

    pub(super) fn retain_process_checkpoints_for_tasks(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        retained_tasks: &BTreeSet<TaskInstanceId>,
    ) {
        self.task_restart_checkpoints.retain(|key, _| {
            &key.0 != tenant
                || &key.1 != project
                || &key.2 != process
                || retained_tasks.contains(&key.3)
        });
        self.task_restart_checkpoint_order.retain(|key| {
            &key.0 != tenant
                || &key.1 != project
                || &key.2 != process
                || retained_tasks.contains(&key.3)
        });
    }

    pub(super) fn begin_attempt(
        &mut self,
        key: TaskRestartKey,
        mut snapshot: TaskAttemptSnapshot,
        history_capacity: usize,
        per_task_capacity: usize,
    ) -> Result<(), ()> {
        while !self.task_attempts.contains_key(&key) && self.task_attempts.len() >= history_capacity
        {
            let removable = self.task_attempts.iter().find_map(|(candidate, attempts)| {
                attempts
                    .iter()
                    .all(|attempt| !attempt_state_is_runnable(&attempt.state))
                    .then(|| candidate.clone())
            });
            let Some(removable) = removable else {
                return Err(());
            };
            self.task_attempts.remove(&removable);
            self.task_terminal_states.remove(&removable);
        }
        self.task_terminal_states.remove(&key);
        let attempts = self.task_attempts.entry(key).or_default();
        for attempt in attempts.iter_mut() {
            attempt.current = false;
        }
        snapshot.attempt_number = u32::try_from(attempts.len() + 1).unwrap_or(u32::MAX);
        attempts.push(snapshot);
        if attempts.len() > per_task_capacity {
            attempts.remove(0);
        }
        Ok(())
    }

    pub(super) fn attempts(
        &self,
    ) -> impl Iterator<Item = (&TaskRestartKey, &Vec<TaskAttemptSnapshot>)> {
        self.task_attempts.iter()
    }

    pub(super) fn current_attempt(&self, key: &TaskRestartKey) -> Option<&TaskAttemptSnapshot> {
        self.task_attempts
            .get(key)?
            .iter()
            .rev()
            .find(|attempt| attempt.current)
    }

    #[cfg(test)]
    pub(super) fn attempt_history(&self, key: &TaskRestartKey) -> Option<&[TaskAttemptSnapshot]> {
        self.task_attempts.get(key).map(Vec::as_slice)
    }

    pub(super) fn attempt_count(&self, key: &TaskRestartKey) -> usize {
        self.task_attempts.get(key).map_or(0, Vec::len)
    }

    pub(super) fn last_attempt(&self, key: &TaskRestartKey) -> Option<&TaskAttemptSnapshot> {
        self.task_attempts.get(key)?.last()
    }

    pub(super) fn resolve_failed_attempt(
        &mut self,
        key: &TaskRestartKey,
        resolution: TaskFailureResolution,
    ) -> Option<String> {
        self.update_current_attempt(key, |attempt| {
            if attempt.state != TaskAttemptState::FailedAwaitingAction {
                return None;
            }
            attempt.state = match resolution {
                TaskFailureResolution::AcceptFailure => TaskAttemptState::Failed,
                TaskFailureResolution::Cancel => TaskAttemptState::Cancelled,
            };
            attempt.command_state = Some(
                match resolution {
                    TaskFailureResolution::AcceptFailure => "failure_accepted",
                    TaskFailureResolution::Cancel => "cancelled",
                }
                .to_owned(),
            );
            Some(attempt.attempt_id.clone())
        })
        .flatten()
    }

    pub(super) fn update_current_attempt<R>(
        &mut self,
        key: &TaskRestartKey,
        update: impl FnOnce(&mut TaskAttemptSnapshot) -> R,
    ) -> Option<R> {
        self.task_attempts
            .get_mut(key)?
            .iter_mut()
            .rev()
            .find(|attempt| attempt.current)
            .map(update)
    }

    pub(super) fn mark_restart_launch(&mut self, key: TaskRestartKey) {
        self.restart_launches.insert(key);
    }

    pub(super) fn clear_restart_launch(&mut self, key: &TaskRestartKey) {
        self.restart_launches.remove(key);
    }

    pub(super) fn is_restart_launch(&self, key: &TaskRestartKey) -> bool {
        self.restart_launches.contains(key)
    }

    pub(super) fn set_placement(&mut self, key: TaskControlKey, placement: Placement) {
        self.task_placements.insert(key, placement);
    }

    #[cfg(test)]
    pub(super) fn placement(&self, key: &TaskControlKey) -> Option<&Placement> {
        self.task_placements.get(key)
    }

    pub(super) fn activate(&mut self, key: TaskControlKey) {
        self.active_tasks.insert(key);
    }

    pub(super) fn is_active(&self, key: &TaskControlKey) -> bool {
        self.active_tasks.contains(key)
    }

    pub(super) fn active_tasks(&self) -> impl Iterator<Item = &TaskControlKey> {
        self.active_tasks.iter()
    }

    pub(super) fn active_count(&self) -> usize {
        self.active_tasks.len()
    }

    pub(super) fn request_cancel(&mut self, key: TaskControlKey) {
        self.task_cancellations.insert(key);
    }

    pub(super) fn is_cancelled(&self, key: &TaskControlKey) -> bool {
        self.task_cancellations.contains(key)
    }

    pub(super) fn is_aborted(&self, key: &TaskControlKey) -> bool {
        self.task_aborts.contains(key)
    }

    pub(super) fn finish_task(&mut self, key: &TaskControlKey) -> Option<Placement> {
        self.task_cancellations.remove(key);
        self.task_aborts.remove(key);
        self.active_tasks.remove(key);
        self.remove_assignment_for_task(&key.0, &key.1, &key.2, &key.3, &key.4);
        self.task_placements.remove(key)
    }

    pub(super) fn active_process_tasks(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Vec<TaskControlKey> {
        self.active_tasks
            .iter()
            .filter(|key| &key.0 == tenant && &key.1 == project && &key.2 == process)
            .cloned()
            .collect()
    }

    pub(super) fn active_task_for_logical_task(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> Option<TaskControlKey> {
        self.active_tasks
            .iter()
            .find(|key| {
                &key.0 == tenant && &key.1 == project && &key.2 == process && &key.4 == task
            })
            .cloned()
    }

    pub(super) fn request_cancel_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Vec<TaskControlKey> {
        let tasks = self.active_process_tasks(tenant, project, process);
        self.task_cancellations.extend(tasks.iter().cloned());
        tasks
    }

    pub(super) fn request_abort_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Vec<TaskControlKey> {
        let tasks = self.active_process_tasks(tenant, project, process);
        self.task_aborts.extend(tasks.iter().cloned());
        tasks
    }

    pub(super) fn clear_cancellations_for_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.task_cancellations
            .retain(|key| &key.0 != tenant || &key.1 != project || &key.2 != process);
    }

    pub(super) fn clear_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        self.task_cancellations
            .retain(|key| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.task_aborts
            .retain(|key| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.active_tasks
            .retain(|key| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.task_placements
            .retain(|key, _| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.remove_assignments_for_process(tenant, project, process);
        self.remove_pending_for_process(tenant, project, process);
        self.task_restart_checkpoints
            .retain(|key, _| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.task_restart_checkpoint_order
            .retain(|key| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.remove_events_for_process(tenant, project, process);
        self.task_attempts
            .retain(|key, _| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.task_terminal_states
            .retain(|key, _| &key.0 != tenant || &key.1 != project || &key.2 != process);
        self.restart_launches
            .retain(|key| &key.0 != tenant || &key.1 != project || &key.2 != process);
    }

    pub(super) fn revoke_node(&mut self, scope: &crate::NodeScopeKey) -> usize {
        let assignment_key = (
            scope.tenant.clone(),
            scope.project.clone(),
            scope.node.clone(),
        );
        let queued = self
            .task_assignments
            .remove(&assignment_key)
            .map_or(0, |assignments| assignments.len());
        self.active_tasks
            .retain(|key| key.0 != scope.tenant || key.1 != scope.project || key.3 != scope.node);
        self.task_cancellations
            .retain(|key| key.0 != scope.tenant || key.1 != scope.project || key.3 != scope.node);
        self.task_aborts
            .retain(|key| key.0 != scope.tenant || key.1 != scope.project || key.3 != scope.node);
        self.task_placements.retain(|key, _| {
            key.0 != scope.tenant || key.1 != scope.project || key.3 != scope.node
        });
        queued
    }

    pub(super) fn hard_drain_node(&mut self, scope: &crate::NodeScopeKey) {
        self.active_tasks
            .retain(|key| key.0 != scope.tenant || key.1 != scope.project || key.3 != scope.node);
        self.task_assignments.remove(&(
            scope.tenant.clone(),
            scope.project.clone(),
            scope.node.clone(),
        ));
        self.task_restart_checkpoints.retain(|_, checkpoint| {
            checkpoint.assignment.tenant != scope.tenant
                || checkpoint.assignment.project != scope.project
                || checkpoint.assignment.node != scope.node
        });
        self.task_restart_checkpoint_order
            .retain(|key| self.task_restart_checkpoints.contains_key(key));
    }

    pub(super) fn has_runnable_remote_work(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        !self
            .active_process_tasks(tenant, project, process)
            .is_empty()
            || self.pending_task_launches.iter().any(|pending| {
                &pending.tenant == tenant
                    && &pending.project == project
                    && &pending.process == process
            })
            || self.task_assignments.values().any(|assignments| {
                assignments.iter().any(|assignment| {
                    &assignment.tenant == tenant
                        && &assignment.project == project
                        && &assignment.process == process
                })
            })
            || self.task_attempts.iter().any(|(key, attempts)| {
                &key.0 == tenant
                    && &key.1 == project
                    && &key.2 == process
                    && attempts
                        .iter()
                        .rev()
                        .any(|attempt| attempt.current && attempt_state_is_runnable(&attempt.state))
            })
    }

    pub(super) fn task_is_known_or_active(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> bool {
        self.active_tasks
            .iter()
            .any(|key| &key.0 == tenant && &key.1 == project && &key.2 == process && &key.4 == task)
            || self.pending_task_launches.iter().any(|pending| {
                &pending.tenant == tenant
                    && &pending.project == project
                    && &pending.process == process
                    && &pending.task == task
            })
            || self.task_assignments.values().any(|assignments| {
                assignments.iter().any(|assignment| {
                    &assignment.tenant == tenant
                        && &assignment.project == project
                        && &assignment.process == process
                        && &assignment.task == task
                })
            })
    }

    pub(super) fn task_instance_exists(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> bool {
        self.task_is_known_or_active(tenant, project, process, task)
            || (!self.is_restart_launch(&(
                tenant.clone(),
                project.clone(),
                process.clone(),
                task.clone(),
            )) && self
                .last_event_for_task(tenant, project, process, task)
                .is_some())
    }

    #[cfg(test)]
    pub(super) fn clear_active(&mut self) {
        self.active_tasks.clear();
    }

    #[cfg(test)]
    pub(super) fn event_at(&self, index: usize) -> Option<&TaskCompletionEvent> {
        self.task_events.get(index)
    }

    #[cfg(test)]
    pub(super) fn checkpoints_are_empty(&self) -> bool {
        self.task_restart_checkpoints.is_empty()
    }
}

fn same_event_process(left: &TaskCompletionEvent, right: &TaskCompletionEvent) -> bool {
    left.tenant == right.tenant && left.project == right.project && left.process == right.process
}

fn same_restart_process(left: &TaskRestartKey, right: &TaskRestartKey) -> bool {
    left.0 == right.0 && left.1 == right.1 && left.2 == right.2
}

fn attempt_state_is_runnable(state: &TaskAttemptState) -> bool {
    matches!(
        state,
        TaskAttemptState::Queued
            | TaskAttemptState::Running
            | TaskAttemptState::FailedAwaitingAction
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use clusterflux_core::{
        Digest, TaskDefinitionId, TaskDispatch, TaskFailurePolicy, TaskSpec, WasmExportAbi,
    };

    fn assignment() -> TaskAssignment {
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("process");
        let task = TaskInstanceId::from("task");
        TaskAssignment {
            assignment_id: "assignment-placeholder".to_owned(),
            attempt_id: "attempt-placeholder".to_owned(),
            offer_epoch: 1,
            offer_expires_at_epoch_seconds: 30,
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task: task.clone(),
            node: NodeId::from("node"),
            epoch: 7,
            artifact_path: String::new(),
            task_spec: TaskSpec {
                tenant,
                project,
                process,
                task_definition: TaskDefinitionId::from("task"),
                task_instance: task,
                dispatch: TaskDispatch::CoordinatorNodeWasm {
                    export: Some("task".to_owned()),
                    abi: WasmExportAbi::TaskV1,
                },
                environment_id: None,
                environment: None,
                environment_digest: None,
                required_capabilities: BTreeSet::new(),
                dependency_cache: None,
                source_snapshot: None,
                source_revision: None,
                required_artifacts: Vec::new(),
                requested_secrets: Vec::new(),
                args: Vec::new(),
                vfs_epoch: 7,
                failure_policy: TaskFailurePolicy::FailFast,
                bundle_digest: Some(Digest::sha256("bundle")),
            },
            wasm_module_base64: String::new(),
        }
    }

    #[test]
    fn terminal_history_is_idempotent_without_becoming_live_authority() {
        let mut assignment = assignment();
        let key = (
            assignment.tenant.clone(),
            assignment.project.clone(),
            assignment.node.clone(),
        );
        let mut registry = TaskRegistry::default();
        let mut durable = DurableState::default();
        let authority = TaskRegistry::offer_active_assignment(
            &mut durable,
            AssignmentKind::ProcessTask {
                process: assignment.process.clone(),
                task: assignment.task.clone(),
            },
            assignment.tenant.clone(),
            assignment.project.clone(),
            assignment.node.clone(),
            "attempt-one".to_owned(),
            1,
            1,
            30,
            "owner",
        );
        assignment.assignment_id = authority.assignment_id.clone();
        assignment.attempt_id = authority.attempt_id.clone();
        assignment.offer_epoch = authority.offer_epoch;

        registry.enqueue_assignment(assignment.clone());
        assert!(registry.acknowledge_process_assignment(&mut durable, &key, &authority, 2, 30,));
        assert!(registry.poll_assignment(&key).is_none());
        assert!(TaskRegistry::active_assignment_is_authorized(
            &durable,
            &NodeScopeKey::new(key.0.clone(), key.1.clone(), key.2.clone()),
            &authority,
            2,
        ));
        TaskRegistry::terminalize_active_assignment(&mut durable, &authority, 3, true);
        assert!(!TaskRegistry::active_assignment_is_authorized(
            &durable,
            &NodeScopeKey::new(key.0.clone(), key.1.clone(), key.2.clone()),
            &authority,
            3,
        ));
        assert!(TaskRegistry::terminal_assignment_matches(
            &durable,
            &NodeScopeKey::new(key.0, key.1, key.2),
            &authority,
        ));
    }

    #[test]
    fn assignment_terminal_mutation_history_is_bounded_and_moves_to_terminal_history() {
        let mut durable = DurableState::default();
        let process = ProcessId::from("process");
        let task = TaskInstanceId::from("task");
        let authority = TaskRegistry::offer_active_assignment(
            &mut durable,
            AssignmentKind::ProcessTask {
                process: process.clone(),
                task: task.clone(),
            },
            TenantId::from("tenant"),
            ProjectId::from("project"),
            NodeId::from("node"),
            "attempt".to_owned(),
            1,
            1,
            30,
            "owner",
        );
        let response = clusterflux_protocol::CoordinatorResponse::TaskRecorded {
            process: process.clone(),
            task: task.clone(),
            events_recorded: 1,
        };
        for index in 0..=MAX_TERMINAL_MUTATIONS_PER_ASSIGNMENT {
            assert!(TaskRegistry::record_assignment_mutation(
                &mut durable,
                &authority,
                process.clone(),
                task.clone(),
                format!("operation-{index}"),
                Digest::sha256(index.to_string()),
                &response,
            ));
        }
        let active = durable
            .active_assignments
            .get(&authority.assignment_id)
            .unwrap();
        assert_eq!(
            active.terminal_mutations.len(),
            MAX_TERMINAL_MUTATIONS_PER_ASSIGNMENT
        );
        assert_eq!(
            active.terminal_mutations.front().unwrap().operation_id,
            "operation-1"
        );
        TaskRegistry::terminalize_active_assignment(&mut durable, &authority, 2, true);
        assert_eq!(
            durable
                .terminal_assignment_history
                .back()
                .unwrap()
                .terminal_mutations
                .len(),
            MAX_TERMINAL_MUTATIONS_PER_ASSIGNMENT
        );
    }

    #[test]
    fn terminal_history_churn_cannot_evict_cross_tenant_live_compiler_authority() {
        let mut durable = DurableState::default();
        let live_scope = NodeScopeKey::new(
            TenantId::from("compiler-tenant"),
            ProjectId::from("compiler-project"),
            NodeId::from("compiler-node"),
        );
        let live = TaskRegistry::offer_active_assignment(
            &mut durable,
            AssignmentKind::WorkflowCompiler {
                run_id: clusterflux_core::RunId::from("compiler-run"),
            },
            live_scope.tenant.clone(),
            live_scope.project.clone(),
            live_scope.node.clone(),
            "compiler-attempt".to_owned(),
            1,
            1,
            u64::MAX - 1,
            "compiler-owner",
        );
        assert!(TaskRegistry::acknowledge_active_assignment(
            &mut durable,
            &live_scope,
            &live,
            2,
            u64::MAX - 2,
        ));

        let noisy_scope = NodeScopeKey::new(
            TenantId::from("noisy-tenant"),
            ProjectId::from("noisy-project"),
            NodeId::from("noisy-node"),
        );
        for index in 0..(MAX_TERMINAL_ASSIGNMENT_HISTORY + 32) {
            let authority = TaskRegistry::offer_active_assignment(
                &mut durable,
                AssignmentKind::ProcessTask {
                    process: ProcessId::new(format!("process-{index}")),
                    task: TaskInstanceId::from("task"),
                },
                noisy_scope.tenant.clone(),
                noisy_scope.project.clone(),
                noisy_scope.node.clone(),
                format!("attempt-{index}"),
                1,
                2,
                30,
                &format!("noisy-owner-{index}"),
            );
            assert!(TaskRegistry::acknowledge_active_assignment(
                &mut durable,
                &noisy_scope,
                &authority,
                2,
                30,
            ));
            TaskRegistry::terminalize_active_assignment(&mut durable, &authority, 3, true);
        }

        assert_eq!(
            durable.terminal_assignment_history.len(),
            MAX_TERMINAL_ASSIGNMENT_HISTORY
        );
        assert!(TaskRegistry::active_assignment_is_authorized(
            &durable,
            &live_scope,
            &live,
            3,
        ));
        assert!(matches!(
            durable
                .active_assignments
                .get(&live.assignment_id)
                .map(|active| &active.kind),
            Some(AssignmentKind::WorkflowCompiler { .. })
        ));
    }
}
