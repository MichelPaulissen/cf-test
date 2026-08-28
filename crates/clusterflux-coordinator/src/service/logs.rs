use clusterflux_core::{
    ArtifactFlush, ArtifactScopeKey, Digest, NodeId, ProcessId, ProjectId, TaskBoundaryValue,
    TaskInstanceId, TaskJoinResult, TaskJoinState, TenantId, UserId, VfsPath,
};

use crate::CoordinatorError;

use super::keys::{process_control_key, task_control_key, task_restart_key};
use super::protocol::TaskAttemptState;
use super::{
    artifact_id_from_path, CoordinatorResponse, CoordinatorService, CoordinatorServiceError,
    TaskCompletionEvent, TaskCompletionOrigin, TaskLogStream, TaskTerminalState,
    MAX_RECENT_LOG_CHUNK_BYTES, MAX_TASK_LOG_TAIL_BYTES,
};

#[derive(Debug, Clone, Copy)]
struct FinalLogStreamAcceptance {
    retained: bool,
    total_source_bytes: u64,
    source_truncated: bool,
}

impl CoordinatorService {
    pub(super) fn handle_report_task_log(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        stdout_bytes: u64,
        stderr_bytes: u64,
        stdout_tail: String,
        stderr_tail: String,
        stdout_truncated: bool,
        stderr_truncated: bool,
        backpressured: bool,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        validate_task_log_tail("stdout_tail", &stdout_tail)?;
        validate_task_log_tail("stderr_tail", &stderr_tail)?;
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let stdout = self.accept_final_log_stream(
            &tenant,
            &project,
            &process,
            &task,
            TaskLogStream::Stdout,
            stdout_bytes,
            &stdout_tail,
            stdout_truncated,
            now_epoch_seconds,
        )?;
        let stderr = self.accept_final_log_stream(
            &tenant,
            &project,
            &process,
            &task,
            TaskLogStream::Stderr,
            stderr_bytes,
            &stderr_tail,
            stderr_truncated,
            now_epoch_seconds,
        )?;
        Ok(CoordinatorResponse::TaskLogRecorded {
            process,
            task,
            stdout_bytes: stdout.total_source_bytes,
            stderr_bytes: stderr.total_source_bytes,
            stdout_tail: if !stdout.retained {
                "[log output truncated at project log quota]".to_owned()
            } else if stdout.source_truncated {
                format!("{stdout_tail}\n... truncated")
            } else {
                stdout_tail
            },
            stderr_tail: if !stderr.retained {
                "[log output truncated at project log quota]".to_owned()
            } else if stderr.source_truncated {
                format!("{stderr_tail}\n... truncated")
            } else {
                stderr_tail
            },
            backpressured,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_report_task_log_chunk(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        stream: TaskLogStream,
        offset: u64,
        source_bytes: u64,
        text: String,
        truncated: bool,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        if text.len() > MAX_RECENT_LOG_CHUNK_BYTES {
            return Err(CoordinatorServiceError::InvalidTaskLogTail(format!(
                "live log chunk is {} bytes; max is {MAX_RECENT_LOG_CHUNK_BYTES}",
                text.len()
            )));
        }
        if source_bytes == 0 && !text.is_empty() && !truncated {
            return Err(CoordinatorServiceError::Protocol(
                "live log chunk source_bytes must describe non-empty text".to_owned(),
            ));
        }
        if source_bytes > (MAX_RECENT_LOG_CHUNK_BYTES as u64).saturating_mul(4) {
            return Err(CoordinatorServiceError::Protocol(
                "live log chunk source_bytes exceeds the bounded chunk allowance".to_owned(),
            ));
        }
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        let key = recent_log_offset_key(&tenant, &project, &process, &task, &stream);
        let expected = self.recent_log_store.accounted_bytes(&key);
        let end = offset.checked_add(source_bytes).ok_or_else(|| {
            CoordinatorServiceError::Protocol(
                "live log chunk offset exceeds the supported range".to_owned(),
            )
        })?;
        let state_marker = source_bytes == 0 && truncated;
        if end < expected || (end == expected && !state_marker) {
            return Ok(CoordinatorResponse::TaskLogChunkRecorded {
                process,
                task,
                sequence: None,
                next_offset: expected,
            });
        }
        let now_epoch_seconds = self.current_epoch_seconds()?;
        if self.recent_log_store.quota_truncated(&key) {
            if end > expected {
                self.recent_log_store.set_accounted_bytes(key, end);
            }
            return Ok(CoordinatorResponse::TaskLogChunkRecorded {
                process,
                task,
                sequence: None,
                next_offset: end.max(expected),
            });
        }
        let newly_accounted = end.saturating_sub(expected);
        if self
            .quota
            .charge_log_bytes(&tenant, &project, newly_accounted, now_epoch_seconds)
            .is_err()
        {
            if end > expected {
                self.recent_log_store.set_accounted_bytes(key.clone(), end);
            }
            let sequence = self.mark_log_quota_truncated(
                &tenant,
                &project,
                &process,
                &task,
                &stream,
                now_epoch_seconds,
            );
            return Ok(CoordinatorResponse::TaskLogChunkRecorded {
                process,
                task,
                sequence,
                next_offset: end.max(expected),
            });
        }
        if offset > expected {
            self.record_recent_log(
                tenant.clone(),
                project.clone(),
                process.clone(),
                task.clone(),
                stream.clone(),
                format!("[log output lost: {} bytes]", offset - expected),
                true,
                now_epoch_seconds,
            );
        } else if offset < expected {
            self.record_recent_log(
                tenant.clone(),
                project.clone(),
                process.clone(),
                task.clone(),
                stream.clone(),
                format!(
                    "[log output overlap omitted: {} new source bytes]",
                    end - expected
                ),
                true,
                now_epoch_seconds,
            );
        }
        let marker_is_new = if truncated {
            self.recent_log_store.mark_source_truncated(key.clone())
        } else {
            false
        };
        let text = if state_marker && text.is_empty() {
            "[some output was unavailable or truncated at source]".to_owned()
        } else {
            text
        };
        let sequence = (!text.is_empty() && offset >= expected && (!state_marker || marker_is_new))
            .then(|| {
                self.record_recent_log(
                    tenant.clone(),
                    project.clone(),
                    process.clone(),
                    task.clone(),
                    stream,
                    text,
                    truncated,
                    now_epoch_seconds,
                )
            });
        if end > expected {
            self.recent_log_store.set_accounted_bytes(key, end);
        }
        Ok(CoordinatorResponse::TaskLogChunkRecorded {
            process,
            task,
            sequence,
            next_offset: end,
        })
    }

    pub(super) fn handle_report_vfs_metadata(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        artifact_path: Option<String>,
        artifact_digest: Option<Digest>,
        artifact_size_bytes: Option<u64>,
        large_bytes_uploaded: bool,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let artifact_path = artifact_path
            .map(VfsPath::new)
            .transpose()
            .map_err(|err| CoordinatorServiceError::InvalidArtifactPath(err.to_string()))?;
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        if let (Some(path), Some(digest)) = (&artifact_path, artifact_digest) {
            self.flush_artifact_metadata(ArtifactFlush {
                id: artifact_id_from_path(path).map_err(|error| {
                    CoordinatorServiceError::InvalidArtifactPath(error.to_string())
                })?,
                tenant,
                project,
                process: process.clone(),
                producer_task: task.clone(),
                retaining_node: node,
                digest,
                size: artifact_size_bytes.unwrap_or_default(),
            })?;
        }
        Ok(CoordinatorResponse::VfsMetadataRecorded {
            process,
            task,
            artifact_path,
            large_bytes_uploaded,
        })
    }

    pub(super) fn handle_task_completed(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        terminal_state: Option<TaskTerminalState>,
        status_code: Option<i32>,
        stdout_bytes: u64,
        stderr_bytes: u64,
        stdout_tail: String,
        stderr_tail: String,
        stdout_truncated: bool,
        stderr_truncated: bool,
        artifact_path: Option<String>,
        artifact_digest: Option<Digest>,
        artifact_size_bytes: Option<u64>,
        result: Option<TaskBoundaryValue>,
        origin: TaskCompletionOrigin,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        validate_task_log_tail("stdout_tail", &stdout_tail)?;
        validate_task_log_tail("stderr_tail", &stderr_tail)?;
        let artifact_path = artifact_path
            .map(VfsPath::new)
            .transpose()
            .map_err(|err| CoordinatorServiceError::InvalidArtifactPath(err.to_string()))?;
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let task = TaskInstanceId::new(task);
        if origin == TaskCompletionOrigin::SignedNode {
            self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        }
        let checkpoint = self
            .task_registry
            .checkpoint(&super::keys::task_restart_key(
                &tenant, &project, &process, &task,
            ))
            .ok_or_else(|| {
                CoordinatorError::Unauthorized(
                    "signed node task completion does not name a coordinator-issued task instance"
                        .to_owned(),
                )
            })?;
        if checkpoint.assignment.node != node {
            return Err(CoordinatorError::Unauthorized(
                "signed node task completion came from a node other than the assigned node"
                    .to_owned(),
            )
            .into());
        }
        let mut event = TaskCompletionEvent {
            tenant,
            project,
            process,
            node,
            executor: super::TaskExecutor::Node,
            task_definition: checkpoint.assignment.task_spec.task_definition.clone(),
            task,
            attempt_id: None,
            placement: None,
            terminal_state: terminal_state
                .unwrap_or_else(|| TaskTerminalState::from_status_code(status_code)),
            status_code,
            stdout_bytes,
            stderr_bytes,
            stdout_tail,
            stderr_tail,
            stdout_truncated,
            stderr_truncated,
            artifact_path,
            artifact_digest: artifact_digest.clone(),
            artifact_size_bytes,
            result,
        };
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let stdout = self.accept_final_log_stream(
            &event.tenant,
            &event.project,
            &event.process,
            &event.task,
            TaskLogStream::Stdout,
            event.stdout_bytes,
            &event.stdout_tail,
            event.stdout_truncated,
            now_epoch_seconds,
        )?;
        let stderr = self.accept_final_log_stream(
            &event.tenant,
            &event.project,
            &event.process,
            &event.task,
            TaskLogStream::Stderr,
            event.stderr_bytes,
            &event.stderr_tail,
            event.stderr_truncated,
            now_epoch_seconds,
        )?;
        event.stdout_bytes = stdout.total_source_bytes;
        event.stderr_bytes = stderr.total_source_bytes;
        event.stdout_truncated |= stdout.source_truncated;
        event.stderr_truncated |= stderr.source_truncated;
        if !stdout.retained {
            event.stdout_tail = "[log output truncated at project log quota]".to_owned();
            event.stdout_truncated = true;
        }
        if !stderr.retained {
            event.stderr_tail = "[log output truncated at project log quota]".to_owned();
            event.stderr_truncated = true;
        }
        let task_key = task_control_key(
            &event.tenant,
            &event.project,
            &event.process,
            &event.node,
            &event.task,
        );
        let process_key = process_control_key(&event.tenant, &event.project, &event.process);
        let process_was_aborted = self.process_registry.is_aborted(&process_key);
        event.placement = self.task_registry.finish_task(&task_key);
        if let (Some(path), Some(digest)) = (&event.artifact_path, artifact_digest) {
            self.flush_artifact_metadata(ArtifactFlush {
                id: artifact_id_from_path(path).map_err(|error| {
                    CoordinatorServiceError::InvalidArtifactPath(error.to_string())
                })?,
                tenant: event.tenant.clone(),
                project: event.project.clone(),
                process: event.process.clone(),
                producer_task: event.task.clone(),
                retaining_node: event.node.clone(),
                digest,
                size: artifact_size_bytes.unwrap_or(stdout_bytes),
            })?;
        }
        self.debug_registry.clear_task_command(&task_key);
        self.artifact_registry.release_task_holds(
            &event.tenant,
            &event.project,
            &event.process,
            &event.task,
        );
        self.clear_recent_log_offsets_for_task(
            &event.tenant,
            &event.project,
            &event.process,
            &event.task,
        );
        if process_was_aborted {
            let checkpoint_key = super::keys::task_restart_key(
                &event.tenant,
                &event.project,
                &event.process,
                &event.task,
            );
            self.remove_task_restart_checkpoint(&checkpoint_key);
        }
        let awaiting_operator = self.finish_task_attempt(&mut event);
        self.record_task_completion_event(event.clone());
        if !awaiting_operator {
            self.notify_coordinator_main_waiters(&event);
        }
        self.maybe_retire_terminal_process(&event.tenant, &event.project, &event.process)?;
        let events_recorded = self
            .task_registry
            .events()
            .filter(|recorded| {
                recorded.tenant == event.tenant
                    && recorded.project == event.project
                    && recorded.process == event.process
            })
            .count();
        Ok(CoordinatorResponse::TaskRecorded {
            process: event.process,
            task: event.task,
            events_recorded,
        })
    }

    pub(super) fn handle_list_task_events(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: Option<String>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let _actor = UserId::new(actor_user);
        let process = process.map(ProcessId::new);
        if let Some(process) = &process {
            self.authorize_task_event_process_scope(&tenant, &project, process)?;
        }
        let events = self
            .task_registry
            .events()
            .filter(|event| {
                event.tenant == tenant
                    && event.project == project
                    && process
                        .as_ref()
                        .is_none_or(|process| event.process == *process)
            })
            .cloned()
            .collect();
        Ok(CoordinatorResponse::TaskEvents { events })
    }

    pub(super) fn handle_list_task_snapshots(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let _actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        self.authorize_task_event_process_scope(&tenant, &project, &process)?;
        let snapshots = self
            .task_registry
            .attempts()
            .filter(
                |((attempt_tenant, attempt_project, attempt_process, _), _)| {
                    attempt_tenant == &tenant
                        && attempt_project == &project
                        && attempt_process == &process
                },
            )
            .flat_map(|(_, attempts)| attempts.iter().rev().cloned())
            .collect();
        Ok(CoordinatorResponse::TaskSnapshots { snapshots })
    }

    pub(super) fn authorize_task_event_process_scope(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Result<(), CoordinatorServiceError> {
        let active_in_scope = self
            .coordinator
            .active_process(tenant, project, process)
            .is_some();
        let historical_in_scope = self
            .task_registry
            .has_event_in_scope(tenant, project, process)
            || self
                .process_registry
                .scope_was_seen(tenant, project, process);
        let process_exists_outside_scope = self
            .coordinator
            .active_process_exists_outside_scope(tenant, project, process)
            || self
                .task_registry
                .has_process_event_outside_scope(tenant, project, process)
            || self
                .process_registry
                .process_was_seen_outside_scope(tenant, project, process);
        if !active_in_scope && !historical_in_scope && process_exists_outside_scope {
            return Err(CoordinatorError::Unauthorized(
                "task event access is outside the virtual process tenant/project scope".to_owned(),
            )
            .into());
        }
        Ok(())
    }

    pub(super) fn handle_list_recent_logs(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: Option<String>,
        after_sequence: Option<u64>,
        limit: u32,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let _actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let task = task.map(TaskInstanceId::new);
        self.authorize_task_event_process_scope(&tenant, &project, &process)?;
        let after_sequence = after_sequence.unwrap_or(0);
        let (entries, history_truncated) = self.recent_log_store.list(
            &tenant,
            &project,
            &process,
            task.as_ref(),
            after_sequence,
            limit as usize,
        );
        let next_sequence = entries.last().map(|entry| entry.sequence);
        Ok(CoordinatorResponse::RecentLogs {
            entries,
            next_sequence,
            history_truncated,
        })
    }

    pub(super) fn handle_join_task(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let _actor = UserId::new(actor_user);
        let process = ProcessId::new(process);
        let task = TaskInstanceId::new(task);
        Ok(CoordinatorResponse::TaskJoined {
            join: self.task_join_result(tenant, project, process, task),
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_join_child_task(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        parent_task: String,
        task: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = ProcessId::new(process);
        let node = NodeId::new(node);
        let parent_task = TaskInstanceId::new(parent_task);
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        if !self.task_registry.is_active(&super::keys::task_control_key(
            &tenant,
            &project,
            &process,
            &node,
            &parent_task,
        )) {
            return Err(CoordinatorError::Unauthorized(
                "child task join requires a currently active parent task on the signed node"
                    .to_owned(),
            )
            .into());
        }
        Ok(CoordinatorResponse::TaskJoined {
            join: self.task_join_result(tenant, project, process, TaskInstanceId::new(task)),
        })
    }

    pub(super) fn task_join_result(
        &self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        task: TaskInstanceId,
    ) -> TaskJoinResult {
        let attempt_key = task_restart_key(&tenant, &project, &process, &task);
        if self
            .task_registry
            .current_attempt(&attempt_key)
            .is_some_and(|attempt| {
                matches!(
                    attempt.state,
                    TaskAttemptState::Queued
                        | TaskAttemptState::Running
                        | TaskAttemptState::FailedAwaitingAction
                )
            })
        {
            return TaskJoinResult::pending(
                process,
                task,
                "logical task is still running or awaiting operator action",
            );
        }
        let event = self
            .task_registry
            .last_event_for_task(&tenant, &project, &process, &task);

        if let Some(event) = event {
            TaskJoinResult::from_remote_completion(
                event.process.clone(),
                event.task.clone(),
                event.node.clone(),
                join_state_for_terminal(&event.terminal_state),
                event.result.clone(),
                event.status_code,
                join_message_for_event(event),
            )
        } else {
            let known = self.task_is_known_or_active(&tenant, &project, &process, &task);
            TaskJoinResult::pending(
                process,
                task,
                if known {
                    "waiting for signed node task_completed event before join returns"
                } else {
                    "no signed node completion event has been observed for this task"
                },
            )
        }
    }

    pub(super) fn record_task_completion_event(&mut self, mut event: TaskCompletionEvent) {
        event.stdout_tail = bounded_log_tail(event.stdout_tail, &mut event.stdout_truncated);
        event.stderr_tail = bounded_log_tail(event.stderr_tail, &mut event.stderr_truncated);
        match event.executor {
            super::TaskExecutor::CoordinatorMain => self.record_main_terminal_state(
                &event.tenant,
                &event.project,
                &event.process,
                event.task_definition.clone(),
                event.task.clone(),
                event.terminal_state.clone(),
            ),
            super::TaskExecutor::Node => {
                self.task_registry.set_terminal_state(
                    task_restart_key(&event.tenant, &event.project, &event.process, &event.task),
                    event.terminal_state.clone(),
                );
            }
        }
        let process_scope = (
            event.tenant.clone(),
            event.project.clone(),
            event.process.clone(),
        );
        self.process_registry
            .record_scope(process_scope, super::MAX_TASK_EVENTS_TOTAL);
        self.task_registry.append_event(
            event,
            super::MAX_TASK_EVENTS_PER_PROCESS,
            super::MAX_TASK_EVENTS_TOTAL,
        );
    }

    #[allow(clippy::too_many_arguments)]
    fn record_recent_log(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        task: TaskInstanceId,
        stream: TaskLogStream,
        text: String,
        truncated: bool,
        server_timestamp_epoch_seconds: u64,
    ) -> u64 {
        self.recent_log_store.append(
            tenant,
            project,
            process,
            task,
            stream,
            text,
            truncated,
            server_timestamp_epoch_seconds,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn accept_final_log_stream(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
        stream: TaskLogStream,
        total_source_bytes: u64,
        final_tail: &str,
        source_truncated: bool,
        now_epoch_seconds: u64,
    ) -> Result<FinalLogStreamAcceptance, CoordinatorServiceError> {
        let key = recent_log_offset_key(tenant, project, process, task, &stream);
        let accounted = self.recent_log_store.accounted_bytes(&key);
        // A worker can restart after streaming logs but before recording completion. Its
        // replacement has no in-memory counters for the prior process. The authenticated live
        // byte count is already authoritative, so finalization must never move it backwards.
        let underreported = total_source_bytes < accounted;
        let total_source_bytes = total_source_bytes.max(accounted);
        let source_truncated = source_truncated || underreported;
        let remaining = total_source_bytes - accounted;
        if self.recent_log_store.quota_truncated(&key) {
            self.recent_log_store
                .set_accounted_bytes(key, total_source_bytes);
            return Ok(FinalLogStreamAcceptance {
                retained: false,
                total_source_bytes,
                source_truncated,
            });
        }
        if self
            .quota
            .charge_log_bytes(tenant, project, remaining, now_epoch_seconds)
            .is_err()
        {
            self.recent_log_store
                .set_accounted_bytes(key, total_source_bytes);
            self.mark_log_quota_truncated(
                tenant,
                project,
                process,
                task,
                &stream,
                now_epoch_seconds,
            );
            return Ok(FinalLogStreamAcceptance {
                retained: false,
                total_source_bytes,
                source_truncated,
            });
        }
        self.reconcile_final_log_stream(
            tenant,
            project,
            process,
            task,
            stream,
            total_source_bytes,
            final_tail,
            source_truncated,
            now_epoch_seconds,
        );
        Ok(FinalLogStreamAcceptance {
            retained: true,
            total_source_bytes,
            source_truncated,
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn mark_log_quota_truncated(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
        stream: &TaskLogStream,
        now_epoch_seconds: u64,
    ) -> Option<u64> {
        let key = recent_log_offset_key(tenant, project, process, task, stream);
        if !self.recent_log_store.mark_quota_truncated(key) {
            return None;
        }
        Some(self.record_recent_log(
            tenant.clone(),
            project.clone(),
            process.clone(),
            task.clone(),
            stream.clone(),
            "[log output truncated at project log quota]".to_owned(),
            true,
            now_epoch_seconds,
        ))
    }

    #[allow(clippy::too_many_arguments)]
    fn reconcile_final_log_stream(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
        stream: TaskLogStream,
        total_source_bytes: u64,
        final_tail: &str,
        source_truncated: bool,
        now_epoch_seconds: u64,
    ) {
        let key = recent_log_offset_key(tenant, project, process, task, &stream);
        let accounted = self.recent_log_store.accounted_bytes(&key);
        let mut visible_truncation = false;
        if total_source_bytes > accounted {
            let missing = total_source_bytes - accounted;
            if final_tail.is_empty() {
                self.record_recent_log(
                    tenant.clone(),
                    project.clone(),
                    process.clone(),
                    task.clone(),
                    stream.clone(),
                    format!("[log output unavailable: {missing} source bytes]"),
                    true,
                    now_epoch_seconds,
                );
                visible_truncation = true;
            } else if (final_tail.len() as u64) <= total_source_bytes {
                let tail_source_start = total_source_bytes - final_tail.len() as u64;
                if accounted < tail_source_start {
                    self.record_recent_log(
                        tenant.clone(),
                        project.clone(),
                        process.clone(),
                        task.clone(),
                        stream.clone(),
                        format!(
                            "[log output lost before final tail: {} source bytes]",
                            tail_source_start - accounted
                        ),
                        true,
                        now_epoch_seconds,
                    );
                    visible_truncation = true;
                }
                let source_start = accounted.max(tail_source_start) - tail_source_start;
                let mut byte_start = usize::try_from(source_start)
                    .unwrap_or(final_tail.len())
                    .min(final_tail.len());
                while byte_start < final_tail.len() && !final_tail.is_char_boundary(byte_start) {
                    byte_start += 1;
                }
                let suffix = &final_tail[byte_start..];
                if !suffix.is_empty() {
                    self.record_recent_log(
                        tenant.clone(),
                        project.clone(),
                        process.clone(),
                        task.clone(),
                        stream.clone(),
                        suffix.to_owned(),
                        source_truncated || visible_truncation,
                        now_epoch_seconds,
                    );
                    visible_truncation |= source_truncated;
                }
            } else if accounted == 0 {
                self.record_recent_log(
                    tenant.clone(),
                    project.clone(),
                    process.clone(),
                    task.clone(),
                    stream.clone(),
                    final_tail.to_owned(),
                    source_truncated,
                    now_epoch_seconds,
                );
                visible_truncation |= source_truncated;
            } else {
                self.record_recent_log(
                    tenant.clone(),
                    project.clone(),
                    process.clone(),
                    task.clone(),
                    stream.clone(),
                    format!(
                        "[{missing} additional source bytes could not be merged without duplicating redacted output]"
                    ),
                    true,
                    now_epoch_seconds,
                );
                visible_truncation = true;
            }
            self.recent_log_store
                .set_accounted_bytes(key.clone(), total_source_bytes);
        }

        let marker_is_new = (source_truncated || visible_truncation)
            && self.recent_log_store.mark_source_truncated(key);
        if marker_is_new && !visible_truncation {
            self.record_recent_log(
                tenant.clone(),
                project.clone(),
                process.clone(),
                task.clone(),
                stream,
                "[some output was unavailable or truncated at source]".to_owned(),
                true,
                now_epoch_seconds,
            );
        }
    }

    pub(super) fn clear_recent_log_offsets_for_task(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) {
        self.recent_log_store
            .clear_task(tenant, project, process, task);
    }

    fn finish_task_attempt(&mut self, event: &mut TaskCompletionEvent) -> bool {
        let key = task_restart_key(&event.tenant, &event.project, &event.process, &event.task);
        let Some(awaiting_operator) = self.task_registry.update_current_attempt(&key, |attempt| {
            event.attempt_id = Some(attempt.attempt_id.clone());
            attempt.status_code = event.status_code;
            attempt.artifact_path = event.artifact_path.clone();
            attempt.artifact_digest = event.artifact_digest.clone();
            attempt.artifact_size_bytes = event.artifact_size_bytes;
            attempt.error =
                (!event.stderr_tail.trim().is_empty()).then(|| event.stderr_tail.clone());
            let awaiting_operator = event.terminal_state == TaskTerminalState::Failed
                && attempt.failure_policy == clusterflux_core::TaskFailurePolicy::AwaitOperator;
            attempt.state = if awaiting_operator {
                TaskAttemptState::FailedAwaitingAction
            } else {
                match event.terminal_state {
                    TaskTerminalState::Completed => TaskAttemptState::Completed,
                    TaskTerminalState::Failed => TaskAttemptState::Failed,
                    TaskTerminalState::Cancelled => TaskAttemptState::Cancelled,
                }
            };
            attempt.command_state = Some(if awaiting_operator {
                "failed_awaiting_action".to_owned()
            } else {
                format!("{:?}", event.terminal_state).to_ascii_lowercase()
            });
            awaiting_operator
        }) else {
            return false;
        };
        awaiting_operator
    }

    pub(super) fn maybe_retire_terminal_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Result<bool, CoordinatorServiceError> {
        let process_key = process_control_key(tenant, project, process);
        if self.main_runtime.controls.contains_key(&process_key) {
            return Ok(false);
        }

        let has_runnable_remote_work = self
            .task_registry
            .has_runnable_remote_work(tenant, project, process);
        if has_runnable_remote_work {
            return Ok(false);
        }

        let main_completed = self
            .process_registry
            .summary(&process_key)
            .and_then(|summary| summary.main_terminal_state.as_ref())
            .is_some_and(|state| matches!(state, TaskTerminalState::Completed));
        let cancellation_completed = self.process_registry.is_cancelled(&process_key);
        if !main_completed && !cancellation_completed {
            return Ok(false);
        }

        self.process_registry.clear_control(&process_key);
        if self
            .coordinator
            .active_process(tenant, project, process)
            .is_none()
        {
            return Ok(false);
        }
        let final_result = if cancellation_completed {
            super::ProcessFinalResult::Cancelled
        } else if self.task_registry.has_terminal_state_for_process(
            tenant,
            project,
            process,
            TaskTerminalState::Failed,
        ) {
            super::ProcessFinalResult::Failed
        } else if self.task_registry.has_terminal_state_for_process(
            tenant,
            project,
            process,
            TaskTerminalState::Cancelled,
        ) {
            super::ProcessFinalResult::Cancelled
        } else {
            super::ProcessFinalResult::Completed
        };
        self.record_process_terminal(
            tenant,
            project,
            process,
            final_result,
            self.current_epoch_seconds()?,
        );
        self.coordinator.abort_process(tenant, project, process)?;
        self.clear_debug_state_for_process(tenant, project, process);
        self.clear_operator_panel_state(tenant, project, process);
        let (pinned, protected_processes) =
            self.artifact_retention_guards_for_project(tenant, project);
        self.artifact_registry.enforce_project_metadata_limit(
            tenant,
            project,
            &pinned,
            &protected_processes,
        );
        Ok(true)
    }

    fn flush_artifact_metadata(
        &mut self,
        flush: ArtifactFlush,
    ) -> Result<(), CoordinatorServiceError> {
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.artifact_registry
            .expire_download_links(now_epoch_seconds);
        let tenant = flush.tenant.clone();
        let project = flush.project.clone();
        let (pinned, protected_processes) =
            self.artifact_retention_guards_for_project(&tenant, &project);
        self.artifact_registry
            .flush_metadata_with_protected_processes(flush, &pinned, &protected_processes)
            .map(|_| ())
            .map_err(CoordinatorServiceError::Protocol)
    }

    fn artifact_retention_guards_for_project(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
    ) -> (
        std::collections::BTreeSet<ArtifactScopeKey>,
        std::collections::BTreeSet<ProcessId>,
    ) {
        let mut pinned = std::collections::BTreeSet::new();
        for checkpoint in self.task_registry.checkpoints() {
            if &checkpoint.assignment.tenant != tenant || &checkpoint.assignment.project != project
            {
                continue;
            }
            for artifact in &checkpoint.assignment.task_spec.required_artifacts {
                pinned.insert(ArtifactScopeKey::from_refs(
                    &checkpoint.assignment.tenant,
                    &checkpoint.assignment.project,
                    artifact,
                ));
            }
        }
        for pending in self.task_registry.pending_launches() {
            if &pending.tenant != tenant || &pending.project != project {
                continue;
            }
            for artifact in &pending.task_spec.required_artifacts {
                pinned.insert(ArtifactScopeKey::from_refs(
                    &pending.tenant,
                    &pending.project,
                    artifact,
                ));
            }
        }
        let protected_processes = self
            .coordinator
            .active_processes_for_project(tenant, project)
            .into_iter()
            .map(|process| process.id)
            .collect();
        (pinned, protected_processes)
    }

    fn task_is_known_or_active(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> bool {
        self.task_registry
            .task_is_known_or_active(tenant, project, process, task)
    }
}

fn recent_log_offset_key(
    tenant: &TenantId,
    project: &ProjectId,
    process: &ProcessId,
    task: &TaskInstanceId,
    stream: &TaskLogStream,
) -> (TenantId, ProjectId, ProcessId, TaskInstanceId, String) {
    (
        tenant.clone(),
        project.clone(),
        process.clone(),
        task.clone(),
        match stream {
            TaskLogStream::Stdout => "stdout",
            TaskLogStream::Stderr => "stderr",
        }
        .to_owned(),
    )
}

fn validate_task_log_tail(kind: &str, value: &str) -> Result<(), CoordinatorServiceError> {
    if value.len() > MAX_TASK_LOG_TAIL_BYTES {
        return Err(CoordinatorServiceError::InvalidTaskLogTail(format!(
            "{kind} is {} bytes; max is {MAX_TASK_LOG_TAIL_BYTES}",
            value.len()
        )));
    }
    Ok(())
}

fn bounded_log_tail(mut value: String, truncated: &mut bool) -> String {
    if value.len() <= MAX_TASK_LOG_TAIL_BYTES {
        return value;
    }
    let mut boundary = value.len() - MAX_TASK_LOG_TAIL_BYTES;
    while boundary < value.len() && !value.is_char_boundary(boundary) {
        boundary += 1;
    }
    value.drain(..boundary);
    *truncated = true;
    value
}

fn join_state_for_terminal(terminal: &TaskTerminalState) -> TaskJoinState {
    match terminal {
        TaskTerminalState::Completed => TaskJoinState::Completed,
        TaskTerminalState::Failed => TaskJoinState::Failed,
        TaskTerminalState::Cancelled => TaskJoinState::Cancelled,
    }
}

fn join_message_for_event(event: &TaskCompletionEvent) -> String {
    match event.terminal_state {
        TaskTerminalState::Completed => {
            "joined result from signed node task_completed event".to_owned()
        }
        TaskTerminalState::Failed => {
            let stderr = event.stderr_tail.trim();
            if stderr.is_empty() {
                "remote task failed".to_owned()
            } else {
                format!("remote task failed: {stderr}")
            }
        }
        TaskTerminalState::Cancelled => "remote task was cancelled".to_owned(),
    }
}
