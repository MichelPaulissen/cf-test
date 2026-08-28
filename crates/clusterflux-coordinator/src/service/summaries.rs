use std::collections::BTreeSet;
use std::time::Instant;

use clusterflux_core::{
    ArtifactId, ArtifactMetadata, NodeCapabilities, NodeId, NodeWorkPolicy, Os, ProcessId,
    ProjectId, TaskDefinitionId, TaskInstanceId, TenantId, UserId,
};

use super::keys::{process_control_key, ProcessControlKey};
use super::{
    ArtifactAvailability, ArtifactRetentionState, ArtifactSummary, CoordinatorResponse,
    CoordinatorService, CoordinatorServiceError, DebugAcknowledgementState, DebugEpochSummary,
    NodeSummary, ProcessActivityState, ProcessFinalResult, ProcessLifecycleState, ProcessSummary,
    TaskAttemptState,
};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct StoredProcessSummary {
    pub(super) started_at_epoch_seconds: u64,
    pub(super) ended_at_epoch_seconds: Option<u64>,
    pub(super) final_result: Option<ProcessFinalResult>,
    pub(super) connected_nodes: Vec<NodeId>,
    pub(super) main_task_definition: Option<TaskDefinitionId>,
    pub(super) main_task_instance: Option<TaskInstanceId>,
    pub(super) main_terminal_state: Option<super::TaskTerminalState>,
    pub(super) order: u64,
}

impl CoordinatorService {
    pub(super) fn handle_list_node_summaries(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let cursor = cursor.as_deref();
        self.refresh_all_node_drains();
        let mut nodes = self
            .coordinator
            .durable_state()
            .node_identities
            .iter()
            .filter(|(scope, identity)| {
                scope.tenant == tenant
                    && scope.project == project
                    && cursor.is_none_or(|cursor| identity.id.as_str() > cursor)
            })
            .map(|(scope, identity)| {
                let descriptor = self.node_registry.descriptor(scope);
                let online = descriptor.is_some()
                    && self.node_is_live(scope)
                    && self.node_registry.drain_status(scope).is_none_or(|status| {
                        status.state != clusterflux_core::NodeLifecycleState::Released
                    });
                let last_seen_epoch_seconds = self
                    .node_registry
                    .last_seen(scope)
                    .or(identity.last_seen_epoch_seconds);
                let runtime_state = if online {
                    "online"
                } else if last_seen_epoch_seconds.is_some() {
                    "offline"
                } else {
                    "never_connected"
                };
                let capabilities = descriptor
                    .map_or_else(unknown_node_capabilities, |descriptor| {
                        descriptor.capabilities.clone()
                    });
                NodeSummary {
                    id: identity.id.clone(),
                    display_name: identity.id.as_str().to_owned(),
                    credential_state: "active".to_owned(),
                    runtime_state: runtime_state.to_owned(),
                    online,
                    stale: !online && last_seen_epoch_seconds.is_some(),
                    last_seen_epoch_seconds,
                    capabilities_known: descriptor.is_some(),
                    automatic_workflow_compilation: descriptor.map_or_else(
                        || "unknown".to_owned(),
                        |descriptor| {
                            automatic_workflow_compilation_status(&descriptor.capabilities)
                        },
                    ),
                    capabilities,
                    artifact_connectivity: descriptor
                        .map(|descriptor| descriptor.artifact_connectivity.clone())
                        .unwrap_or_default(),
                    drain: self.node_registry.drain_status(scope).cloned(),
                }
            })
            .collect::<Vec<_>>();
        nodes.sort_by(|left, right| left.id.cmp(&right.id));
        let has_more = nodes.len() > limit as usize;
        nodes.truncate(limit as usize);
        let next_cursor = has_more
            .then(|| nodes.last().map(|node| node.id.as_str().to_owned()))
            .flatten();
        Ok(CoordinatorResponse::NodeSummaries {
            nodes,
            next_cursor,
            actor,
        })
    }

    pub(super) fn record_process_started(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        now_epoch_seconds: u64,
    ) {
        let key = process_control_key(tenant, project, process);
        self.recent_log_store
            .clear_process(tenant, project, process);
        for evicted in self.process_registry.start_summary(key, now_epoch_seconds) {
            self.recent_log_store
                .clear_process(&evicted.0, &evicted.1, &evicted.2);
        }
    }

    pub(super) fn record_process_terminal(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        final_result: ProcessFinalResult,
        now_epoch_seconds: u64,
    ) {
        let key = process_control_key(tenant, project, process);
        let connected_nodes = self
            .coordinator
            .active_process(tenant, project, process)
            .map(|active| active.connected_nodes.iter().cloned().collect())
            .unwrap_or_default();
        self.process_registry.finish_summary(
            key,
            final_result.clone(),
            connected_nodes,
            now_epoch_seconds,
        );
        self.artifact_registry
            .release_process_holds(tenant, project, process);
        self.record_automated_process_terminal(
            tenant,
            project,
            process,
            &final_result,
            now_epoch_seconds,
        );
    }

    pub(super) fn record_main_terminal_state(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task_definition: TaskDefinitionId,
        task_instance: TaskInstanceId,
        terminal_state: super::TaskTerminalState,
    ) {
        let key = process_control_key(tenant, project, process);
        if !self.process_registry.contains_summary(&key) {
            self.record_process_started(
                tenant,
                project,
                process,
                self.liveness_now_epoch_seconds(),
            );
        }
        let recorded = self.process_registry.record_main_terminal(
            &key,
            task_definition,
            task_instance,
            terminal_state,
        );
        debug_assert!(recorded, "process summary exists after start fallback");
    }

    pub(super) fn handle_list_process_summaries(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let cursor = parse_order_cursor(cursor.as_deref(), "process")?;
        let (stored, has_more) =
            self.process_registry
                .summaries_page(&tenant, &project, cursor, limit as usize);
        let processes = stored
            .into_iter()
            .map(|(key, stored)| self.process_summary_from_stored(&key, stored))
            .collect::<Vec<_>>();
        let next_cursor = has_more
            .then(|| processes.last().map(|process| process.order_cursor.clone()))
            .flatten();
        Ok(CoordinatorResponse::ProcessSummaries {
            processes,
            next_cursor,
            actor,
        })
    }

    fn process_summary_from_stored(
        &self,
        key: &ProcessControlKey,
        stored: StoredProcessSummary,
    ) -> ProcessSummary {
        let (tenant, project, process) = key;
        let active = self.coordinator.active_process(tenant, project, process);
        let process_key = process_control_key(tenant, project, process);
        let main_wait_state = active.and_then(|_| {
            if self
                .task_registry
                .queued_count_for_process(tenant, project, process)
                > 0
            {
                Some("waiting_for_node".to_owned())
            } else if self
                .main_runtime
                .is_waiting_for_task(tenant, project, process)
            {
                Some("waiting_for_task".to_owned())
            } else {
                None
            }
        });
        let main_wait_reason = active.and_then(|_| {
            self.task_registry
                .pending_waiting_reason_for_process(tenant, project, process)
                .map(str::to_owned)
        });
        let current_debug_epoch = self.debug_epoch_summary(&process_key);
        let awaiting_action = self.task_registry.attempts().any(
            |((attempt_tenant, attempt_project, attempt_process, _), attempts)| {
                attempt_tenant == tenant
                    && attempt_project == project
                    && attempt_process == process
                    && attempts.iter().any(|attempt| {
                        attempt.current && attempt.state == TaskAttemptState::FailedAwaitingAction
                    })
            },
        );
        let activity = if let Some(result) = &stored.final_result {
            match result {
                ProcessFinalResult::Completed => ProcessActivityState::Completed,
                ProcessFinalResult::Failed => ProcessActivityState::Failed,
                ProcessFinalResult::Cancelled => ProcessActivityState::Cancelled,
            }
        } else if self.process_registry.is_cancelled(&process_key) {
            ProcessActivityState::Cancelling
        } else if current_debug_epoch
            .as_ref()
            .is_some_and(|epoch| epoch.partially_frozen)
        {
            ProcessActivityState::DebugEpochPartial
        } else if awaiting_action {
            ProcessActivityState::AwaitingAction
        } else {
            match main_wait_state.as_deref() {
                Some("waiting_for_node") => ProcessActivityState::WaitingForNode,
                Some("waiting_for_task") => ProcessActivityState::WaitingForTask,
                _ => ProcessActivityState::Running,
            }
        };
        let connected_nodes = active
            .map(|active| active.connected_nodes.iter().cloned().collect())
            .unwrap_or(stored.connected_nodes);
        ProcessSummary {
            process: process.clone(),
            lifecycle: if active.is_some() {
                ProcessLifecycleState::Active
            } else {
                ProcessLifecycleState::RecentTerminal
            },
            activity,
            main_wait_state,
            main_wait_reason,
            started_at_epoch_seconds: stored.started_at_epoch_seconds,
            ended_at_epoch_seconds: stored.ended_at_epoch_seconds,
            final_result: stored.final_result,
            connected_nodes,
            current_debug_epoch,
            order_cursor: format!("process:{}", stored.order),
        }
    }

    fn debug_epoch_summary(&self, key: &ProcessControlKey) -> Option<DebugEpochSummary> {
        let runtime = self.debug_registry.runtime(key)?;
        let acknowledgements = runtime.acknowledgements.values().collect::<Vec<_>>();
        let all_acknowledged = !runtime.expected.is_empty()
            && runtime
                .expected
                .iter()
                .all(|participant| runtime.acknowledgements.contains_key(participant));
        let fully_frozen = runtime.command == "freeze"
            && all_acknowledged
            && acknowledgements
                .iter()
                .all(|ack| ack.state == DebugAcknowledgementState::Frozen);
        let freeze_deadline_elapsed =
            runtime.command == "freeze" && Instant::now() >= runtime.deadline;
        let frozen_count = acknowledgements
            .iter()
            .filter(|ack| ack.state == DebugAcknowledgementState::Frozen)
            .count();
        let partially_frozen = freeze_deadline_elapsed && frozen_count > 0 && !fully_frozen;
        let fully_resumed = runtime.command == "resume"
            && all_acknowledged
            && acknowledgements
                .iter()
                .all(|ack| ack.state == DebugAcknowledgementState::Running);
        let failed = acknowledgements
            .iter()
            .any(|ack| ack.state == DebugAcknowledgementState::Failed)
            || (freeze_deadline_elapsed
                && runtime
                    .expected
                    .iter()
                    .any(|participant| !runtime.acknowledgements.contains_key(participant)));
        Some(DebugEpochSummary {
            epoch: runtime.epoch,
            command: runtime.command.clone(),
            fully_frozen,
            partially_frozen,
            fully_resumed,
            failed,
        })
    }

    pub(super) fn handle_list_artifacts(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        process: Option<String>,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let _actor = UserId::new(actor_user);
        let process = process.map(ProcessId::new);
        if let Some(process) = &process {
            self.authorize_task_event_process_scope(&tenant, &project, process)?;
        }
        let cursor = parse_order_cursor(cursor.as_deref(), "artifact")?;
        let mut metadata = self
            .artifact_registry
            .metadata_for_project(&tenant, &project)
            .filter(|metadata| {
                process
                    .as_ref()
                    .is_none_or(|process| &metadata.process == process)
                    && cursor.is_none_or(|cursor| metadata.flushed_epoch < cursor)
            })
            .cloned()
            .collect::<Vec<_>>();
        metadata.sort_by_key(|item| std::cmp::Reverse(item.flushed_epoch));
        let has_more = metadata.len() > limit as usize;
        metadata.truncate(limit as usize);
        let artifacts = metadata
            .into_iter()
            .map(|metadata| self.artifact_summary(metadata))
            .collect::<Vec<_>>();
        let next_cursor = has_more
            .then(|| {
                artifacts
                    .last()
                    .map(|artifact| artifact.order_cursor.clone())
            })
            .flatten();
        Ok(CoordinatorResponse::Artifacts {
            artifacts,
            next_cursor,
        })
    }

    pub(super) fn handle_get_artifact(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let _actor = UserId::new(actor_user);
        let artifact = ArtifactId::new(artifact);
        let metadata = self
            .artifact_registry
            .metadata(&tenant, &project, &artifact)
            .cloned()
            .ok_or(clusterflux_core::DownloadError::NotFound)?;
        Ok(CoordinatorResponse::Artifact {
            artifact: self.artifact_summary(metadata),
        })
    }

    fn artifact_summary(&self, metadata: ArtifactMetadata) -> ArtifactSummary {
        let live_retaining_nodes = metadata
            .retaining_nodes
            .iter()
            .filter(|node| {
                self.node_is_live(&crate::NodeScopeKey::from_refs(
                    &metadata.tenant,
                    &metadata.project,
                    node,
                ))
            })
            .cloned()
            .collect::<BTreeSet<_>>();
        let safe_node = live_retaining_nodes
            .iter()
            .next()
            .cloned()
            .or_else(|| metadata.retaining_nodes.iter().next().cloned());
        let explicit_storage = !metadata.explicit_locations.is_empty();
        let downloadable_now = !live_retaining_nodes.is_empty() || explicit_storage;
        let availability = if downloadable_now {
            ArtifactAvailability::Available
        } else if !metadata.retaining_nodes.is_empty() {
            ArtifactAvailability::NodeOffline
        } else {
            ArtifactAvailability::Unavailable
        };
        let retention_state = if explicit_storage {
            ArtifactRetentionState::ExplicitStorage
        } else if !metadata.retaining_nodes.is_empty() {
            ArtifactRetentionState::NodeRetained
        } else {
            ArtifactRetentionState::Lost
        };
        let display_suffix = metadata.id.as_str().replace(':', "/");
        let display_path = format!("/vfs/artifacts/{display_suffix}");
        let display_name = display_suffix
            .rsplit('/')
            .next()
            .unwrap_or(metadata.id.as_str())
            .to_owned();
        ArtifactSummary {
            id: metadata.id,
            display_path,
            display_name,
            process: metadata.process,
            producer_task: metadata.producer_task,
            safe_node,
            digest: metadata.digest,
            size_bytes: metadata.size,
            availability,
            downloadable_now,
            retention_state,
            explicit_storage,
            order_cursor: format!("artifact:{}", metadata.flushed_epoch),
        }
    }
}

fn unknown_node_capabilities() -> NodeCapabilities {
    NodeCapabilities {
        os: Os::Other("unknown".to_owned()),
        arch: "unknown".to_owned(),
        capabilities: BTreeSet::new(),
        environment_backends: BTreeSet::new(),
        source_providers: BTreeSet::new(),
        work_policy: NodeWorkPolicy::default(),
        system_bundles: Vec::new(),
    }
}

fn automatic_workflow_compilation_status(
    capabilities: &clusterflux_core::NodeCapabilities,
) -> String {
    if capabilities.work_policy == clusterflux_core::NodeWorkPolicy::ExecutionOnly {
        return "disabled_by_node_policy".to_owned();
    }
    let manifest = clusterflux_core::workflow_compiler_system_manifest();
    if capabilities.system_bundles.iter().any(|bundle| {
        bundle.bundle_id == manifest.bundle_id
            && bundle.bundle_digest == manifest.bundle_digest
            && bundle.environment_digest == manifest.environment_digest
            && bundle.sdk_abi_version == manifest.sdk_abi_version
    }) {
        return "available".to_owned();
    }
    if capabilities.os != clusterflux_core::Os::Linux
        || !capabilities
            .environment_backends
            .contains(&clusterflux_core::EnvironmentBackend::Container)
    {
        return "unavailable_no_compatible_environment_backend".to_owned();
    }
    if capabilities.system_bundles.is_empty() {
        "unavailable_system_bundle_not_loaded".to_owned()
    } else {
        "unavailable_system_bundle_version_mismatch".to_owned()
    }
}

fn parse_order_cursor(
    cursor: Option<&str>,
    expected_kind: &str,
) -> Result<Option<u64>, CoordinatorServiceError> {
    cursor
        .map(|cursor| {
            let (kind, order) = cursor.split_once(':').ok_or_else(|| {
                CoordinatorServiceError::Protocol(format!(
                    "invalid {expected_kind} pagination cursor"
                ))
            })?;
            if kind != expected_kind {
                return Err(CoordinatorServiceError::Protocol(format!(
                    "invalid {expected_kind} pagination cursor"
                )));
            }
            order.parse::<u64>().map_err(|_| {
                CoordinatorServiceError::Protocol(format!(
                    "invalid {expected_kind} pagination cursor"
                ))
            })
        })
        .transpose()
}
