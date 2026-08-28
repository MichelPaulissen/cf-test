use std::collections::{BTreeMap, BTreeSet};
use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{
    generate_opaque_token, verify_node_request_signature, Actor, ArtifactHoldReason, ArtifactId,
    CredentialKind, Digest, NodeCapabilities, NodeDescriptor, NodeDrainBlocker,
    NodeDrainBlockerKind, NodeDrainStatus, NodeId, NodeLifecycleState, NodeSignedRequest,
    ProjectId, SourceProviderKind, TenantId, UserId,
};

use crate::{CoordinatorError, NodeScopeKey};

use super::{
    bounded_ttl, enrollment_grant_key, CoordinatorResponse, CoordinatorService,
    CoordinatorServiceError,
};

impl CoordinatorService {
    pub fn set_node_stale_after_seconds(&mut self, seconds: u64) {
        self.node_stale_after_seconds = seconds.max(1);
    }

    pub(super) fn liveness_now_epoch_seconds(&self) -> u64 {
        #[cfg(test)]
        if let Some(now) = self.server_time_override {
            return now;
        }
        unix_timestamp_seconds()
    }

    pub(super) fn node_is_live(&self, scope: &NodeScopeKey) -> bool {
        self.node_registry.is_live(
            scope,
            self.liveness_now_epoch_seconds(),
            self.node_stale_after_seconds,
        )
    }

    pub(super) fn live_node_descriptors(&self) -> Vec<NodeDescriptor> {
        self.node_registry.live_descriptors(
            self.liveness_now_epoch_seconds(),
            self.node_stale_after_seconds,
        )
    }

    pub(super) fn handle_begin_node_drain(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        ephemeral: bool,
        provider_deadline_epoch_seconds: Option<u64>,
        soft_drain_deadline_epoch_seconds: Option<u64>,
        hard_drain_deadline_epoch_seconds: Option<u64>,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = NodeScopeKey::new(
            TenantId::new(tenant),
            ProjectId::new(project),
            NodeId::new(node),
        );
        self.coordinator
            .node_identity(&scope.tenant, &scope.project, &scope.node)
            .ok_or(CoordinatorError::UnknownNode)?;
        self.node_registry.begin_drain(
            &scope,
            ephemeral,
            provider_deadline_epoch_seconds,
            soft_drain_deadline_epoch_seconds,
            hard_drain_deadline_epoch_seconds,
        );
        let status = self.refresh_node_drain_status(&scope);
        Ok(CoordinatorResponse::NodeDrainStatus { status })
    }

    /// Performs the release transition as a fenced coordinator operation. The
    /// blocker set is recomputed under the same exclusive service mutation that
    /// removes node locations, so a stale ReadyToRelease observation can never
    /// discard a newly-added hold or task.
    pub(super) fn handle_finalize_node_release(
        &mut self,
        tenant: String,
        project: String,
        node: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let scope = NodeScopeKey::new(
            TenantId::new(tenant),
            ProjectId::new(project),
            NodeId::new(node),
        );
        self.coordinator
            .node_identity(&scope.tenant, &scope.project, &scope.node)
            .ok_or(CoordinatorError::UnknownNode)?;
        let mut status = self.refresh_node_drain_status(&scope);
        if status.state == NodeLifecycleState::Released {
            return Ok(CoordinatorResponse::NodeDrainStatus { status });
        }
        let hard_reached = status
            .hard_drain_deadline_epoch_seconds
            .or(status.provider_deadline_epoch_seconds)
            .is_some_and(|deadline| deadline <= self.liveness_now_epoch_seconds());
        if hard_reached {
            self.apply_hard_drain_policy(&scope)?;
            status = self.refresh_node_drain_status(&scope);
            status.hard_deadline_reached = true;
            status.provider_deadline_reached = true;
            self.finalize_released_node(
                &scope,
                &mut status,
                "hard drain deadline reached; running work was aborted and remaining local retention was invalidated",
            );
        } else if status.ready_to_release() {
            self.finalize_released_node(&scope, &mut status, "all drain blockers cleared");
        }
        self.node_registry
            .record_drain_status(scope, status.clone());
        Ok(CoordinatorResponse::NodeDrainStatus { status })
    }

    pub(super) fn node_accepts_new_work(&self, scope: &NodeScopeKey) -> bool {
        self.node_registry.accepts_new_work(scope)
    }

    pub(super) fn refresh_all_node_drains(&mut self) {
        let scopes = self.node_registry.drain_scopes();
        for scope in scopes {
            self.refresh_node_drain_status(&scope);
        }
    }

    fn refresh_node_drain_status(&mut self, scope: &NodeScopeKey) -> NodeDrainStatus {
        let previous = self.node_registry.drain_status_or_active(scope);
        if matches!(
            previous.state,
            NodeLifecycleState::Active | NodeLifecycleState::Released
        ) {
            return previous;
        }
        let now = self.liveness_now_epoch_seconds();
        let soft_deadline_reached = previous
            .soft_drain_deadline_epoch_seconds
            .is_some_and(|deadline| deadline <= now);
        if soft_deadline_reached {
            self.apply_soft_drain_policy(scope);
        }
        let _ = self.expire_interchange_state();
        let relocation_waiting = self.ensure_drain_relocations(scope);
        let mut blockers = Vec::new();
        let running = self
            .task_registry
            .active_tasks()
            .filter(|(tenant, project, _, node, _)| {
                tenant == &scope.tenant && project == &scope.project && node == &scope.node
            })
            .map(|(_, _, process, _, task)| (process.clone(), task.clone()))
            .collect::<Vec<_>>();
        for (process, task) in &running {
            blockers.push(NodeDrainBlocker {
                kind: NodeDrainBlockerKind::RunningTask,
                summary: format!("Running task: {task}"),
                process: Some(process.clone()),
                task: Some(task.clone()),
                artifact: None,
                transfer_id: None,
                retained_bytes: 0,
            });
        }
        let queued = self
            .task_registry
            .assignments_for_node(&(
                scope.tenant.clone(),
                scope.project.clone(),
                scope.node.clone(),
            ))
            .collect::<Vec<_>>();
        for assignment in &queued {
            blockers.push(NodeDrainBlocker {
                kind: NodeDrainBlockerKind::QueuedTask,
                summary: format!("Queued task: {}", assignment.task),
                process: Some(assignment.process.clone()),
                task: Some(assignment.task.clone()),
                artifact: None,
                transfer_id: None,
                retained_bytes: 0,
            });
        }
        let transfers = self
            .interchange_registry
            .transfers()
            .filter(|transfer| {
                !transfer.record.state.terminal()
                    && transfer.record.tenant == scope.tenant
                    && transfer.record.project == scope.project
                    && (transfer.record.source_node == scope.node
                        || transfer.record.destination_node == scope.node)
            })
            .collect::<Vec<_>>();
        for transfer in &transfers {
            blockers.push(NodeDrainBlocker {
                kind: NodeDrainBlockerKind::ActiveTransfer,
                summary: format!(
                    "Moving artifact: {} to {} ({} of {} bytes verified)",
                    transfer.record.artifact,
                    transfer.record.destination_node,
                    transfer.record.bytes_completed,
                    transfer.record.total_bytes
                ),
                process: Some(transfer.record.process.clone()),
                task: None,
                artifact: Some(transfer.record.artifact.clone()),
                transfer_id: Some(transfer.record.transfer_id.clone()),
                retained_bytes: transfer
                    .record
                    .total_bytes
                    .saturating_sub(transfer.record.bytes_completed),
            });
        }
        let mut retained_bytes = 0_u64;
        for (metadata, holds) in self.artifact_registry.held_artifacts_on_node(
            &scope.tenant,
            &scope.project,
            &scope.node,
        ) {
            if metadata.retaining_nodes.len() != 1 {
                continue;
            }
            retained_bytes = retained_bytes.saturating_add(metadata.size);
            for hold in holds {
                let (kind, mut summary) = match hold.reason {
                    ArtifactHoldReason::ProcessRetention { process } => (
                        NodeDrainBlockerKind::SoleCopyArtifactHold,
                        format!("Artifact retained by active process {process}"),
                    ),
                    ArtifactHoldReason::ConsumerTask { task, .. } => (
                        NodeDrainBlockerKind::SoleCopyArtifactHold,
                        format!("Only copy retained for running task {task}"),
                    ),
                    ArtifactHoldReason::ActiveTransfer { transfer_id } => (
                        NodeDrainBlockerKind::ActiveTransfer,
                        format!("Artifact retained for transfer {transfer_id}"),
                    ),
                    ArtifactHoldReason::RestartCheckpoint { task, .. } => (
                        NodeDrainBlockerKind::RestartCheckpoint,
                        format!("Only copy retained for task restart {task}"),
                    ),
                    ArtifactHoldReason::DownloadExport { .. } => (
                        NodeDrainBlockerKind::DownloadExport,
                        "Artifact retained for download".to_owned(),
                    ),
                    ArtifactHoldReason::ExplicitRetention { label } => (
                        NodeDrainBlockerKind::SoleCopyArtifactHold,
                        format!("Artifact explicitly retained: {label}"),
                    ),
                };
                if let Some(waiting) = relocation_waiting.get(&metadata.id) {
                    summary.push_str(". ");
                    summary.push_str(waiting);
                }
                blockers.push(NodeDrainBlocker {
                    kind,
                    summary,
                    process: Some(metadata.process.clone()),
                    task: None,
                    artifact: Some(metadata.id.clone()),
                    transfer_id: None,
                    retained_bytes: metadata.size,
                });
            }
        }
        for checkpoint in self.task_registry.checkpoints().filter(|checkpoint| {
            checkpoint.assignment.tenant == scope.tenant
                && checkpoint.assignment.project == scope.project
                && checkpoint.assignment.node == scope.node
                && (checkpoint.checkpoint.depends_on_live_stack
                    || checkpoint.checkpoint.depends_on_live_socket)
        }) {
            blockers.push(NodeDrainBlocker {
                kind: NodeDrainBlockerKind::RestartCheckpoint,
                summary: format!("Task restart checkpoint: {}", checkpoint.assignment.task),
                process: Some(checkpoint.assignment.process.clone()),
                task: Some(checkpoint.assignment.task.clone()),
                artifact: None,
                transfer_id: None,
                retained_bytes: 0,
            });
        }
        for (tenant, project, process) in self.debug_registry.epoch_keys().filter(|key| {
            key.0 == scope.tenant
                && key.1 == scope.project
                && self
                    .coordinator
                    .active_process(&key.0, &key.1, &key.2)
                    .is_some_and(|active| active.connected_nodes.contains(&scope.node))
        }) {
            blockers.push(NodeDrainBlocker {
                kind: NodeDrainBlockerKind::DebugEpoch,
                summary: "Debug session is paused on this node".to_owned(),
                process: Some(process.clone()),
                task: None,
                artifact: None,
                transfer_id: None,
                retained_bytes: 0,
            });
            let _ = (tenant, project);
        }
        let state = if blockers.is_empty() {
            NodeLifecycleState::ReadyToRelease
        } else {
            NodeLifecycleState::Draining
        };
        let hard_deadline = previous
            .hard_drain_deadline_epoch_seconds
            .or(previous.provider_deadline_epoch_seconds);
        let hard_deadline_reached = hard_deadline.is_some_and(|deadline| deadline <= now);
        let status = NodeDrainStatus {
            node: scope.node.clone(),
            state,
            ephemeral: previous.ephemeral,
            provider_deadline_epoch_seconds: previous.provider_deadline_epoch_seconds,
            provider_deadline_reached: hard_deadline_reached,
            soft_drain_deadline_epoch_seconds: previous.soft_drain_deadline_epoch_seconds,
            hard_drain_deadline_epoch_seconds: hard_deadline,
            soft_deadline_reached,
            hard_deadline_reached,
            release_reason: previous.release_reason,
            running_task_count: running.len(),
            queued_task_count: queued.len(),
            active_transfer_count: transfers.len(),
            retained_bytes,
            blockers,
        };
        self.node_registry
            .record_drain_status(scope.clone(), status.clone());
        status
    }

    fn apply_soft_drain_policy(&mut self, scope: &NodeScopeKey) {
        let releases = self
            .artifact_registry
            .held_artifacts_on_node(&scope.tenant, &scope.project, &scope.node)
            .flat_map(|(metadata, holds)| {
                holds.into_iter().filter_map(|hold| {
                    matches!(hold.reason, ArtifactHoldReason::ExplicitRetention { .. })
                        .then_some((metadata.id.clone(), hold.reason))
                })
            })
            .collect::<Vec<_>>();
        for (artifact, reason) in releases {
            self.artifact_registry
                .remove_hold(&scope.tenant, &scope.project, &artifact, &reason);
        }
    }

    fn apply_hard_drain_policy(
        &mut self,
        scope: &NodeScopeKey,
    ) -> Result<(), CoordinatorServiceError> {
        let mut processes = self
            .task_registry
            .active_tasks()
            .filter(|(tenant, project, _, node, _)| {
                tenant == &scope.tenant && project == &scope.project && node == &scope.node
            })
            .map(|(_, _, process, _, _)| process.clone())
            .collect::<BTreeSet<_>>();
        let assignments = self.task_registry.assignments_for_node(&(
            scope.tenant.clone(),
            scope.project.clone(),
            scope.node.clone(),
        ));
        processes.extend(assignments.map(|assignment| assignment.process.clone()));
        processes.extend(
            self.interchange_registry
                .transfers()
                .filter(|transfer| {
                    !transfer.record.state.terminal()
                        && transfer.record.tenant == scope.tenant
                        && transfer.record.project == scope.project
                        && (transfer.record.source_node == scope.node
                            || transfer.record.destination_node == scope.node)
                })
                .map(|transfer| transfer.record.process.clone()),
        );
        for process in processes {
            if self
                .coordinator
                .active_process(&scope.tenant, &scope.project, &process)
                .is_some()
            {
                self.handle_abort_process(
                    scope.tenant.as_str().to_owned(),
                    scope.project.as_str().to_owned(),
                    "node-hard-drain-deadline".to_owned(),
                    process.as_str().to_owned(),
                    None,
                )?;
            }
        }

        let now = self.current_epoch_seconds()?;
        let released_transfer_holds = self
            .interchange_registry
            .cancel_node_for_hard_drain(scope, now);
        for (artifact, transfer_id) in released_transfer_holds {
            self.artifact_registry.remove_hold(
                &scope.tenant,
                &scope.project,
                &artifact,
                &ArtifactHoldReason::ActiveTransfer { transfer_id },
            );
        }
        self.task_registry.hard_drain_node(scope);
        Ok(())
    }

    fn finalize_released_node(
        &mut self,
        scope: &NodeScopeKey,
        status: &mut NodeDrainStatus,
        reason: &str,
    ) {
        self.artifact_registry
            .garbage_collect_node(&scope.tenant, &scope.project, &scope.node);
        self.node_registry.mark_released(scope);
        status.state = NodeLifecycleState::Released;
        status.running_task_count = 0;
        status.queued_task_count = 0;
        status.active_transfer_count = 0;
        status.retained_bytes = 0;
        status.blockers.clear();
        status.release_reason = Some(reason.to_owned());
    }

    /// Starts destination-initiated transfers for every held artifact whose only
    /// verified copy is on the draining node. Failures are deliberately reduced
    /// to user-facing availability/capacity wording for drain status output.
    fn ensure_drain_relocations(&mut self, scope: &NodeScopeKey) -> BTreeMap<ArtifactId, String> {
        let sole_copies = self
            .artifact_registry
            .held_artifacts_on_node(&scope.tenant, &scope.project, &scope.node)
            .filter(|(metadata, _)| metadata.retaining_nodes.len() == 1)
            .map(|(metadata, _)| metadata.clone())
            .collect::<Vec<_>>();
        let mut waiting = BTreeMap::new();
        for metadata in sole_copies {
            if self.interchange_registry.transfers().any(|transfer| {
                !transfer.record.state.terminal()
                    && transfer.record.tenant == scope.tenant
                    && transfer.record.project == scope.project
                    && transfer.record.artifact == metadata.id
                    && transfer.record.source_node == scope.node
            }) {
                continue;
            }
            let destination = self
                .node_registry
                .descriptors()
                .map(|(_, descriptor)| descriptor)
                .filter(|descriptor| {
                    descriptor.tenant == scope.tenant
                        && descriptor.project == scope.project
                        && descriptor.id != scope.node
                        && !metadata.retaining_nodes.contains(&descriptor.id)
                })
                .map(|descriptor| {
                    NodeScopeKey::from_refs(&descriptor.tenant, &descriptor.project, &descriptor.id)
                })
                .filter(|candidate| {
                    self.node_is_live(candidate)
                        && self.node_accepts_new_work(candidate)
                        && self
                            .node_registry
                            .has_active_advertisement(candidate, self.liveness_now_epoch_seconds())
                })
                .min_by_key(|candidate| {
                    let receiver_load = self
                        .interchange_registry
                        .transfers()
                        .filter(|transfer| {
                            !transfer.record.state.terminal()
                                && transfer.record.tenant == candidate.tenant
                                && transfer.record.project == candidate.project
                                && transfer.record.destination_node == candidate.node
                        })
                        .count();
                    (receiver_load, candidate.node.clone())
                });
            let Some(destination) = destination else {
                waiting.insert(
                    metadata.id,
                    "Movement is waiting for an eligible destination node".to_owned(),
                );
                continue;
            };
            if self
                .handle_request_artifact_interchange(
                    scope.tenant.to_string(),
                    scope.project.to_string(),
                    metadata.process.to_string(),
                    destination.node.to_string(),
                    metadata.id.to_string(),
                    0,
                )
                .is_err()
            {
                waiting.insert(
                    metadata.id,
                    "Movement is waiting for destination capacity or connectivity".to_owned(),
                );
            }
        }
        waiting
    }

    pub(super) fn handle_attach_node(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        public_key: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        self.coordinator.ensure_tenant_active(&tenant)?;
        self.coordinator.upsert_tenant(tenant.clone());
        self.coordinator.upsert_user(
            tenant.clone(),
            UserId::from("local-user"),
            CredentialKind::CliDeviceSession,
        );
        self.coordinator
            .upsert_project(tenant.clone(), project.clone(), "local");
        self.coordinator.upsert_source_provider_config(
            tenant.clone(),
            project.clone(),
            SourceProviderKind::Filesystem,
            Digest::sha256("local-filesystem"),
        );
        if self
            .coordinator
            .node_identity(&tenant, &project, &node)
            .is_none()
        {
            self.quota.ensure_node_admission(
                &tenant,
                self.coordinator.node_identity_count_for_tenant(&tenant),
                self.coordinator
                    .tenant_quota_override(&tenant)
                    .map(|record| &record.values),
            )?;
        }
        self.coordinator.enroll_node(
            tenant.clone(),
            project.clone(),
            node.clone(),
            public_key,
            "node:attach",
        );
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::NodeAttached {
            node,
            tenant,
            project,
        })
    }

    pub(super) fn handle_create_node_enrollment_grant(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        ttl_seconds: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        self.coordinator.ensure_tenant_active(&tenant)?;
        self.coordinator.upsert_tenant(tenant.clone());
        self.coordinator
            .upsert_user(tenant.clone(), actor, CredentialKind::CliDeviceSession);
        self.coordinator
            .upsert_project(tenant.clone(), project.clone(), "local");
        self.coordinator.upsert_source_provider_config(
            tenant.clone(),
            project.clone(),
            SourceProviderKind::Filesystem,
            Digest::sha256("local-filesystem"),
        );
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.node_registry
            .prune_enrollment_grants(now_epoch_seconds);
        if self.node_registry.enrollment_grant_count(&tenant, &project)
            >= super::MAX_ENROLLMENT_GRANTS_PER_PROJECT
        {
            return Err(CoordinatorServiceError::Protocol(
                "node enrollment grant limit reached for this project; consume a grant or wait for one to expire"
                    .to_owned(),
            ));
        }
        let grant =
            generate_opaque_token("node_grant").map_err(CoordinatorServiceError::Protocol)?;
        let ttl_seconds = bounded_ttl(ttl_seconds, self.admission.max_node_enrollment_ttl_seconds);
        let scope = "node:attach".to_owned();
        let expires_at_epoch_seconds = now_epoch_seconds.saturating_add(ttl_seconds);
        let enrollment = self.coordinator.create_node_enrollment_grant(
            tenant.clone(),
            project.clone(),
            grant.clone(),
            scope.clone(),
            expires_at_epoch_seconds,
        );
        self.node_registry
            .insert_enrollment_grant(enrollment_grant_key(&tenant, &project, &grant), enrollment);
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::NodeEnrollmentGrantCreated {
            tenant,
            project,
            grant,
            scope,
            expires_at_epoch_seconds,
        })
    }

    pub(super) fn handle_exchange_node_enrollment_grant(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        public_key: String,
        enrollment_grant: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.node_registry
            .prune_enrollment_grants(now_epoch_seconds);
        self.coordinator.ensure_tenant_active(&tenant)?;
        if self
            .coordinator
            .node_identity(&tenant, &project, &node)
            .is_none()
        {
            self.quota.ensure_node_admission(
                &tenant,
                self.coordinator.node_identity_count_for_tenant(&tenant),
                self.coordinator
                    .tenant_quota_override(&tenant)
                    .map(|record| &record.values),
            )?;
        }
        let grant_key = enrollment_grant_key(&tenant, &project, &enrollment_grant);
        let coordinator = &mut self.coordinator;
        let credential = self
            .node_registry
            .exchange_enrollment_grant(&grant_key, |grant| {
                coordinator.exchange_node_enrollment_grant(
                    grant,
                    node.clone(),
                    &public_key,
                    "node:attach",
                    now_epoch_seconds,
                )
            })?
            .ok_or(CoordinatorError::Enrollment(
                clusterflux_core::EnrollmentError::Expired,
            ))?;
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::NodeEnrollmentExchanged {
            node,
            tenant,
            project,
            credential,
        })
    }

    pub(super) fn handle_node_heartbeat(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        node_signature: Option<NodeSignedRequest>,
        payload_digest: &Digest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        self.authenticate_node_request(
            &NodeScopeKey::new(tenant, project, node.clone()),
            node_signature,
            "node_heartbeat",
            payload_digest,
        )?;
        Ok(CoordinatorResponse::NodeHeartbeat {
            node,
            epoch: self.coordinator.coordinator_epoch(),
        })
    }

    pub(super) fn handle_report_node_capabilities(
        &mut self,
        tenant: String,
        project: String,
        node: String,
        capabilities: NodeCapabilities,
        cached_environment_digests: Vec<Digest>,
        dependency_cache_digests: Vec<Digest>,
        source_snapshots: Vec<Digest>,
        artifact_locations: Vec<String>,
        online_reported: bool,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let node = NodeId::new(node);
        let node_scope = NodeScopeKey::from_refs(&tenant, &project, &node);
        let identity = self
            .coordinator
            .node_identity(&tenant, &project, &node)
            .ok_or(CoordinatorError::UnknownNode)?;
        debug_assert_eq!(identity.tenant, tenant);
        debug_assert_eq!(identity.project, project);
        capabilities.validate_public_report()?;
        for (kind, count) in [
            ("cached environments", cached_environment_digests.len()),
            ("dependency caches", dependency_cache_digests.len()),
            ("source snapshots", source_snapshots.len()),
            ("artifact locations", artifact_locations.len()),
        ] {
            if count > super::MAX_NODE_REPORTED_OBJECTS_PER_KIND {
                return Err(CoordinatorServiceError::Protocol(format!(
                    "node capability report contains {count} {kind}; limit is {}",
                    super::MAX_NODE_REPORTED_OBJECTS_PER_KIND
                )));
            }
        }
        if cached_environment_digests
            .iter()
            .chain(&dependency_cache_digests)
            .chain(&source_snapshots)
            .any(|digest| !digest.is_valid_sha256())
        {
            return Err(CoordinatorServiceError::Protocol(
                "node capability report contains an invalid digest".to_owned(),
            ));
        }
        if artifact_locations.iter().any(|artifact| {
            artifact.trim().is_empty()
                || artifact.len() > 256
                || artifact
                    .chars()
                    .any(|character| matches!(character, '/' | '\\' | '\0'))
        }) {
            return Err(CoordinatorServiceError::Protocol(
                "node capability report contains an invalid artifact id".to_owned(),
            ));
        }
        let mut artifact_locations = artifact_locations
            .into_iter()
            .map(ArtifactId::new)
            .collect::<BTreeSet<_>>();
        if !online_reported {
            artifact_locations.clear();
        }
        self.artifact_registry.reconcile_node_retention(
            &tenant,
            &project,
            &node,
            &artifact_locations,
        );

        let online = online_reported && self.node_is_live(&node_scope);
        let artifact_connectivity =
            self.artifact_connectivity_facts(&node_scope, self.current_epoch_seconds()?);
        self.node_registry.record_descriptor(
            node_scope,
            NodeDescriptor {
                id: node.clone(),
                tenant: tenant.clone(),
                project: project.clone(),
                capabilities,
                cached_environments: cached_environment_digests.into_iter().collect(),
                dependency_caches: dependency_cache_digests.into_iter().collect(),
                source_snapshots: source_snapshots.into_iter().collect(),
                artifact_locations,
                artifact_connectivity,
                online,
            },
        );
        let node_descriptors = self
            .node_registry
            .descriptor_count_for_project(&tenant, &project);
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::NodeCapabilitiesRecorded {
            node,
            node_descriptors,
        })
    }

    pub(super) fn handle_list_node_descriptors(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let descriptors = self
            .live_node_descriptors()
            .into_iter()
            .filter(|descriptor| descriptor.tenant == tenant && descriptor.project == project)
            .collect();
        Ok(CoordinatorResponse::NodeDescriptors { descriptors, actor })
    }

    pub(super) fn handle_revoke_node_credential(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        node: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let node = NodeId::new(node);
        let context = clusterflux_core::AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(actor.clone()),
        };
        self.coordinator.revoke_node_credential(&context, &node)?;
        let node_scope = NodeScopeKey::from_refs(&tenant, &project, &node);
        let descriptor_removed = self.node_registry.remove_node(&node_scope);
        let now = self.current_epoch_seconds()?;
        self.interchange_registry.fail_node(&node_scope, now);
        self.replay_registry.clear_node(&node_scope);
        self.artifact_registry
            .garbage_collect_node(&tenant, &project, &node);
        let queued_assignments_removed = self.task_registry.revoke_node(&node_scope);
        self.persist_durable_state()?;
        Ok(CoordinatorResponse::NodeCredentialRevoked {
            node,
            tenant,
            project,
            actor,
            descriptor_removed,
            queued_assignments_removed,
        })
    }

    pub(super) fn authenticate_node_request(
        &mut self,
        scope: &NodeScopeKey,
        node_signature: Option<NodeSignedRequest>,
        request_kind: &str,
        payload_digest: &Digest,
    ) -> Result<(), CoordinatorServiceError> {
        let identity = self
            .coordinator
            .node_identity(&scope.tenant, &scope.project, &scope.node)
            .ok_or(CoordinatorError::UnknownNode)?;
        let signature = node_signature.ok_or_else(|| {
            CoordinatorError::Unauthorized(
                "node request requires a signed proof of enrolled private-key possession"
                    .to_owned(),
            )
        })?;
        if signature.nonce.trim().is_empty() || signature.nonce.len() > 256 {
            return Err(CoordinatorError::Unauthorized(
                "node signed request nonce is missing or invalid".to_owned(),
            )
            .into());
        }
        let now_epoch_seconds = unix_timestamp_seconds();
        if signature
            .issued_at_epoch_seconds
            .abs_diff(now_epoch_seconds)
            > super::NODE_SIGNATURE_WINDOW_SECONDS
        {
            return Err(CoordinatorError::Unauthorized(
                "node signed request is expired or outside the allowed clock skew".to_owned(),
            )
            .into());
        }
        if let Err(super::ReplayAdmissionError::Duplicate) = self.replay_registry.prepare_node(
            scope,
            &signature.nonce,
            now_epoch_seconds,
            super::NODE_SIGNATURE_WINDOW_SECONDS,
        ) {
            return Err(CoordinatorError::Unauthorized(
                "node signed request nonce has already been used".to_owned(),
            )
            .into());
        }
        verify_node_request_signature(
            &identity.public_key,
            &scope.node,
            request_kind,
            payload_digest,
            &signature,
        )
        .map_err(CoordinatorError::Unauthorized)?;
        if let Err(super::ReplayAdmissionError::Capacity) = self.replay_registry.commit_node(
            scope.clone(),
            signature.nonce.clone(),
            now_epoch_seconds,
            super::MAX_NODE_REPLAY_NONCES_PER_AUTHORITY,
        ) {
            return Err(CoordinatorError::Unauthorized(
                "node signed request replay window is full; retry after the bounded signature window advances"
                    .to_owned(),
            )
            .into());
        }
        let seen_at = self.liveness_now_epoch_seconds();
        self.node_registry.mark_seen(scope, seen_at);
        self.coordinator.mark_node_identity_seen(
            &scope.tenant,
            &scope.project,
            &scope.node,
            seen_at,
        );
        Ok(())
    }
}

fn unix_timestamp_seconds() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or(0)
}
