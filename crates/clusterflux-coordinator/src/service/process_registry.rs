use std::collections::{BTreeMap, BTreeSet, VecDeque};

use clusterflux_core::{NodeId, ProcessId, ProjectId, TaskDefinitionId, TaskInstanceId, TenantId};

use super::keys::ProcessControlKey;
use super::summaries::StoredProcessSummary;
use super::{
    ProcessFinalResult, TaskTerminalState, MAX_RECENT_PROCESS_SUMMARIES_PER_PROJECT,
    MAX_RECENT_PROCESS_SUMMARIES_TOTAL,
};

/// Owns process cancellation/abort controls and bounded terminal summary history.
/// Every key includes tenant and project scope; terminal summary eviction enforces
/// both the per-project admission bound and the global safety ceiling.
pub(super) struct ProcessRegistry {
    scope_history: VecDeque<ProcessControlKey>,
    summaries: BTreeMap<ProcessControlKey, StoredProcessSummary>,
    summary_order: VecDeque<ProcessControlKey>,
    next_summary_order: u64,
    process_cancellations: BTreeSet<ProcessControlKey>,
    process_aborts: BTreeSet<ProcessControlKey>,
}

impl ProcessRegistry {
    pub(super) fn is_cancelled(&self, key: &ProcessControlKey) -> bool {
        self.process_cancellations.contains(key)
    }

    pub(super) fn is_aborted(&self, key: &ProcessControlKey) -> bool {
        self.process_aborts.contains(key)
    }

    pub(super) fn is_stopping(&self, key: &ProcessControlKey) -> bool {
        self.is_cancelled(key) || self.is_aborted(key)
    }

    pub(super) fn request_cancel(&mut self, key: ProcessControlKey) -> bool {
        self.process_cancellations.insert(key)
    }

    pub(super) fn request_abort(&mut self, key: ProcessControlKey) -> bool {
        self.process_aborts.insert(key)
    }

    pub(super) fn clear_cancel(&mut self, key: &ProcessControlKey) -> bool {
        self.process_cancellations.remove(key)
    }

    pub(super) fn clear_abort(&mut self, key: &ProcessControlKey) -> bool {
        self.process_aborts.remove(key)
    }

    pub(super) fn clear_control(&mut self, key: &ProcessControlKey) {
        self.clear_cancel(key);
        self.clear_abort(key);
    }

    pub(super) fn record_scope(&mut self, key: ProcessControlKey, limit: usize) {
        self.scope_history.retain(|retained| retained != &key);
        while self.scope_history.len() >= limit {
            self.scope_history.pop_front();
        }
        self.scope_history.push_back(key);
    }

    pub(super) fn scope_was_seen(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.scope_history.iter().any(
            |(historical_tenant, historical_project, historical_process)| {
                historical_tenant == tenant
                    && historical_project == project
                    && historical_process == process
            },
        )
    }

    pub(super) fn process_was_seen_outside_scope(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.scope_history.iter().any(
            |(historical_tenant, historical_project, historical_process)| {
                historical_process == process
                    && (historical_tenant != tenant || historical_project != project)
            },
        )
    }

    pub(super) fn start_summary(
        &mut self,
        key: ProcessControlKey,
        now_epoch_seconds: u64,
    ) -> Vec<ProcessControlKey> {
        self.summary_order.retain(|retained| retained != &key);
        let mut evicted = Vec::new();
        while self
            .summaries
            .keys()
            .filter(|(tenant, project, _)| tenant == &key.0 && project == &key.1)
            .count()
            >= MAX_RECENT_PROCESS_SUMMARIES_PER_PROJECT
        {
            let candidate = self.summary_order.iter().find(|candidate| {
                candidate.0 == key.0
                    && candidate.1 == key.1
                    && self
                        .summaries
                        .get(*candidate)
                        .is_some_and(|summary| summary.final_result.is_some())
            });
            let Some(candidate) = candidate.cloned() else {
                break;
            };
            self.remove_summary(&candidate);
            evicted.push(candidate);
        }
        while self.summaries.len() >= MAX_RECENT_PROCESS_SUMMARIES_TOTAL {
            let candidate = self.summary_order.iter().find(|candidate| {
                self.summaries
                    .get(*candidate)
                    .is_some_and(|summary| summary.final_result.is_some())
            });
            let Some(candidate) = candidate.cloned() else {
                break;
            };
            self.remove_summary(&candidate);
            evicted.push(candidate);
        }
        let order = self.allocate_summary_order();
        self.summaries.insert(
            key.clone(),
            StoredProcessSummary {
                started_at_epoch_seconds: now_epoch_seconds,
                ended_at_epoch_seconds: None,
                final_result: None,
                connected_nodes: Vec::new(),
                main_task_definition: None,
                main_task_instance: None,
                main_terminal_state: None,
                order,
            },
        );
        self.summary_order.push_back(key);
        evicted
    }

    pub(super) fn finish_summary(
        &mut self,
        key: ProcessControlKey,
        final_result: ProcessFinalResult,
        connected_nodes: Vec<NodeId>,
        now_epoch_seconds: u64,
    ) {
        if !self.summaries.contains_key(&key) {
            let order = self.allocate_summary_order();
            self.summary_order.push_back(key.clone());
            self.summaries.insert(
                key.clone(),
                StoredProcessSummary {
                    started_at_epoch_seconds: now_epoch_seconds,
                    ended_at_epoch_seconds: None,
                    final_result: None,
                    connected_nodes: Vec::new(),
                    main_task_definition: None,
                    main_task_instance: None,
                    main_terminal_state: None,
                    order,
                },
            );
        }
        let entry = self
            .summaries
            .get_mut(&key)
            .expect("process summary was inserted when absent");
        entry.ended_at_epoch_seconds = Some(now_epoch_seconds);
        entry.final_result = Some(final_result);
        entry.connected_nodes = connected_nodes;
    }

    pub(super) fn record_main_terminal(
        &mut self,
        key: &ProcessControlKey,
        task_definition: TaskDefinitionId,
        task_instance: TaskInstanceId,
        terminal_state: TaskTerminalState,
    ) -> bool {
        let Some(summary) = self.summaries.get_mut(key) else {
            return false;
        };
        summary.main_task_definition = Some(task_definition);
        summary.main_task_instance = Some(task_instance);
        summary.main_terminal_state = Some(terminal_state);
        true
    }

    pub(super) fn summaries_page(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        before_order: Option<u64>,
        limit: usize,
    ) -> (Vec<(ProcessControlKey, StoredProcessSummary)>, bool) {
        let mut stored = self
            .summaries
            .iter()
            .filter(|((entry_tenant, entry_project, _), summary)| {
                entry_tenant == tenant
                    && entry_project == project
                    && before_order.is_none_or(|order| summary.order < order)
            })
            .map(|(key, summary)| (key.clone(), summary.clone()))
            .collect::<Vec<_>>();
        stored.sort_by_key(|(_, item)| std::cmp::Reverse(item.order));
        let has_more = stored.len() > limit;
        stored.truncate(limit);
        (stored, has_more)
    }

    pub(super) fn summary(&self, key: &ProcessControlKey) -> Option<&StoredProcessSummary> {
        self.summaries.get(key)
    }

    pub(super) fn contains_summary(&self, key: &ProcessControlKey) -> bool {
        self.summaries.contains_key(key)
    }

    fn remove_summary(&mut self, key: &ProcessControlKey) {
        self.summaries.remove(key);
        self.summary_order.retain(|retained| retained != key);
    }

    fn allocate_summary_order(&mut self) -> u64 {
        let order = self.next_summary_order;
        self.next_summary_order = self.next_summary_order.saturating_add(1);
        order
    }
}

impl Default for ProcessRegistry {
    fn default() -> Self {
        Self {
            scope_history: VecDeque::new(),
            summaries: BTreeMap::new(),
            summary_order: VecDeque::new(),
            next_summary_order: 1,
            process_cancellations: BTreeSet::new(),
            process_aborts: BTreeSet::new(),
        }
    }
}
