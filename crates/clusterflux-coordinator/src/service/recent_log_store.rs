use std::collections::{BTreeMap, BTreeSet, VecDeque};

use clusterflux_core::{ProcessId, ProjectId, TaskInstanceId, TenantId};

use super::keys::{process_control_key, ProcessControlKey};
use super::protocol::{RecentLogEntry, TaskLogStream};
use super::{
    MAX_RECENT_LOG_BYTES_PER_PROJECT, MAX_RECENT_LOG_CHUNK_BYTES,
    MAX_RECENT_LOG_ENTRIES_PER_PROCESS, MAX_RECENT_LOG_ENTRIES_PER_PROJECT,
};

pub(super) type LogStreamKey = (TenantId, ProjectId, ProcessId, TaskInstanceId, String);

/// Owns restart-ephemeral recent logs and their accounting/truncation indexes.
/// Append enforces chunk, per-process, and per-project object/byte bounds; all
/// admission and cleanup keys include tenant and project scope.
pub(super) struct RecentLogStore {
    recent_logs: BTreeMap<(TenantId, ProjectId), VecDeque<RecentLogEntry>>,
    recent_log_dropped_through: BTreeMap<ProcessControlKey, u64>,
    recent_log_accounted_bytes: BTreeMap<LogStreamKey, u64>,
    recent_log_truncated_streams: BTreeSet<LogStreamKey>,
    recent_log_quota_truncated_streams: BTreeSet<LogStreamKey>,
    next_recent_log_sequence: u64,
}

impl RecentLogStore {
    pub(super) fn accounted_bytes(&self, key: &LogStreamKey) -> u64 {
        self.recent_log_accounted_bytes
            .get(key)
            .copied()
            .unwrap_or(0)
    }

    pub(super) fn set_accounted_bytes(&mut self, key: LogStreamKey, bytes: u64) {
        self.recent_log_accounted_bytes.insert(key, bytes);
    }

    pub(super) fn quota_truncated(&self, key: &LogStreamKey) -> bool {
        self.recent_log_quota_truncated_streams.contains(key)
    }

    pub(super) fn mark_source_truncated(&mut self, key: LogStreamKey) -> bool {
        self.recent_log_truncated_streams.insert(key)
    }

    pub(super) fn mark_quota_truncated(&mut self, key: LogStreamKey) -> bool {
        if !self.recent_log_quota_truncated_streams.insert(key.clone()) {
            return false;
        }
        self.recent_log_truncated_streams.insert(key);
        true
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn append(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        task: TaskInstanceId,
        stream: TaskLogStream,
        mut text: String,
        mut truncated: bool,
        server_timestamp_epoch_seconds: u64,
    ) -> u64 {
        if text.len() > MAX_RECENT_LOG_CHUNK_BYTES {
            let mut boundary = MAX_RECENT_LOG_CHUNK_BYTES;
            while !text.is_char_boundary(boundary) {
                boundary -= 1;
            }
            text.truncate(boundary);
            truncated = true;
        }
        let sequence = self.next_recent_log_sequence;
        self.next_recent_log_sequence = self.next_recent_log_sequence.saturating_add(1);
        let logs = self
            .recent_logs
            .entry((tenant.clone(), project.clone()))
            .or_default();
        let mut dropped = Vec::new();
        while logs.iter().filter(|entry| entry.process == process).count()
            >= MAX_RECENT_LOG_ENTRIES_PER_PROCESS
        {
            let Some(index) = logs.iter().position(|entry| entry.process == process) else {
                break;
            };
            if let Some(entry) = logs.remove(index) {
                dropped.push(entry);
            }
        }
        while logs.len() >= MAX_RECENT_LOG_ENTRIES_PER_PROJECT
            || logs
                .iter()
                .map(|entry| entry.text.len())
                .sum::<usize>()
                .saturating_add(text.len())
                > MAX_RECENT_LOG_BYTES_PER_PROJECT
        {
            match logs.pop_front() {
                Some(entry) => dropped.push(entry),
                None => break,
            }
        }
        logs.push_back(RecentLogEntry {
            sequence,
            process,
            task,
            stream,
            text,
            server_timestamp_epoch_seconds,
            truncated,
        });
        for entry in dropped {
            let key = process_control_key(&tenant, &project, &entry.process);
            self.recent_log_dropped_through
                .entry(key)
                .and_modify(|dropped_through| {
                    *dropped_through = (*dropped_through).max(entry.sequence);
                })
                .or_insert(entry.sequence);
        }
        sequence
    }

    pub(super) fn list(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: Option<&TaskInstanceId>,
        after_sequence: u64,
        limit: usize,
    ) -> (Vec<RecentLogEntry>, bool) {
        let history_truncated = self
            .recent_log_dropped_through
            .get(&process_control_key(tenant, project, process))
            .is_some_and(|dropped_through| *dropped_through > after_sequence);
        let entries = self
            .recent_logs
            .get(&(tenant.clone(), project.clone()))
            .into_iter()
            .flatten()
            .filter(|entry| {
                &entry.process == process
                    && entry.sequence > after_sequence
                    && task.is_none_or(|task| &entry.task == task)
            })
            .take(limit)
            .cloned()
            .collect();
        (entries, history_truncated)
    }

    pub(super) fn clear_task(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) {
        self.recent_log_accounted_bytes.retain(
            |(entry_tenant, entry_project, entry_process, entry_task, _), _| {
                entry_tenant != tenant
                    || entry_project != project
                    || entry_process != process
                    || entry_task != task
            },
        );
        self.recent_log_truncated_streams.retain(
            |(entry_tenant, entry_project, entry_process, entry_task, _)| {
                entry_tenant != tenant
                    || entry_project != project
                    || entry_process != process
                    || entry_task != task
            },
        );
        self.recent_log_quota_truncated_streams.retain(
            |(entry_tenant, entry_project, entry_process, entry_task, _)| {
                entry_tenant != tenant
                    || entry_project != project
                    || entry_process != process
                    || entry_task != task
            },
        );
    }

    pub(super) fn clear_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) {
        let key = process_control_key(tenant, project, process);
        self.recent_log_dropped_through.remove(&key);
        if let Some(logs) = self.recent_logs.get_mut(&(tenant.clone(), project.clone())) {
            logs.retain(|entry| &entry.process != process);
            if logs.is_empty() {
                self.recent_logs.remove(&(tenant.clone(), project.clone()));
            }
        }
        self.recent_log_accounted_bytes.retain(
            |(entry_tenant, entry_project, entry_process, _, _), _| {
                entry_tenant != tenant || entry_project != project || entry_process != process
            },
        );
        self.recent_log_truncated_streams.retain(
            |(entry_tenant, entry_project, entry_process, _, _)| {
                entry_tenant != tenant || entry_project != project || entry_process != process
            },
        );
        self.recent_log_quota_truncated_streams.retain(
            |(entry_tenant, entry_project, entry_process, _, _)| {
                entry_tenant != tenant || entry_project != project || entry_process != process
            },
        );
    }

    #[cfg(test)]
    pub(super) fn entries_for_project(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> Vec<RecentLogEntry> {
        self.recent_logs
            .get(&(tenant.clone(), project.clone()))
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    #[cfg(test)]
    pub(super) fn has_accounted_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.recent_log_accounted_bytes.keys().any(
            |(entry_tenant, entry_project, entry_process, _, _)| {
                entry_tenant == tenant && entry_project == project && entry_process == process
            },
        )
    }

    #[cfg(test)]
    pub(super) fn has_truncated_process(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.recent_log_truncated_streams.iter().any(
            |(entry_tenant, entry_project, entry_process, _, _)| {
                entry_tenant == tenant && entry_project == project && entry_process == process
            },
        )
    }
}

impl Default for RecentLogStore {
    fn default() -> Self {
        Self {
            recent_logs: BTreeMap::new(),
            recent_log_dropped_through: BTreeMap::new(),
            recent_log_accounted_bytes: BTreeMap::new(),
            recent_log_truncated_streams: BTreeSet::new(),
            recent_log_quota_truncated_streams: BTreeSet::new(),
            next_recent_log_sequence: 1,
        }
    }
}
