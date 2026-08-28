use std::collections::{BTreeMap, BTreeSet};

use clusterflux_core::{
    artifact::IssuedDownloadLink, auth::same_tenant_project, Actor, ArtifactFlush, ArtifactHold,
    ArtifactHoldReason, ArtifactId, ArtifactMetadata, ArtifactScopeKey, ArtifactUnavailable,
    AuthContext, Digest, DownloadAction, DownloadError, DownloadLink, DownloadPolicy, NodeId,
    ProcessId, ProjectId, Scope, StorageLocation, TaskInstanceId, TenantId,
};

const MAX_ISSUED_DOWNLOAD_LINKS_PER_ARTIFACT: usize = 32;
const DOWNLOAD_LINK_TOMBSTONE_SECONDS: u64 = 15 * 60;
const MAX_ARTIFACT_METADATA_PER_PROJECT: usize = 1_024;

/// Owns tenant/project-scoped artifact metadata, retention holds, and expiring
/// download sessions. Admission has scoped metadata and per-artifact link limits,
/// and lifecycle methods keep protected live state from being evicted.
#[derive(Clone, Debug, Default)]
pub(super) struct ArtifactRegistry {
    artifacts: BTreeMap<ArtifactScopeKey, ArtifactMetadata>,
    holds: BTreeMap<ArtifactScopeKey, BTreeSet<ArtifactHold>>,
    issued_download_links: BTreeMap<Digest, IssuedDownloadLink>,
    next_epoch: u64,
}

impl ArtifactRegistry {
    #[cfg(test)]
    pub(super) fn flush_metadata(&mut self, flush: ArtifactFlush) -> ArtifactMetadata {
        self.flush_metadata_bounded(flush, &BTreeSet::new())
            .expect("an unpinned artifact scope always has an evictable metadata entry")
    }

    #[cfg(test)]
    pub(super) fn flush_metadata_bounded(
        &mut self,
        flush: ArtifactFlush,
        pinned: &BTreeSet<ArtifactScopeKey>,
    ) -> Result<ArtifactMetadata, String> {
        self.flush_metadata_with_protected_processes(flush, pinned, &BTreeSet::new())
    }

    pub(super) fn flush_metadata_with_protected_processes(
        &mut self,
        flush: ArtifactFlush,
        pinned: &BTreeSet<ArtifactScopeKey>,
        protected_processes: &BTreeSet<ProcessId>,
    ) -> Result<ArtifactMetadata, String> {
        let key = ArtifactScopeKey::from_refs(&flush.tenant, &flush.project, &flush.id);
        let replacing = self.artifacts.contains_key(&key);
        let retained_for_project = self
            .artifacts
            .values()
            .filter(|metadata| metadata.tenant == flush.tenant && metadata.project == flush.project)
            .count();
        let eviction = if replacing || retained_for_project < MAX_ARTIFACT_METADATA_PER_PROJECT {
            None
        } else {
            let mut protected_processes = protected_processes.clone();
            protected_processes.insert(flush.process.clone());
            Some(
                self.project_metadata_eviction_candidate(
                    &flush.tenant,
                    &flush.project,
                    pinned,
                    &protected_processes,
                )
                .ok_or_else(|| {
                    format!(
                        "artifact metadata capacity of {MAX_ARTIFACT_METADATA_PER_PROJECT} is \
                         exhausted by active or retained artifacts"
                    )
                })?,
            )
        };

        self.next_epoch = self.next_epoch.saturating_add(1);
        let metadata = ArtifactMetadata {
            id: flush.id.clone(),
            tenant: flush.tenant,
            project: flush.project,
            process: flush.process,
            producer_task: flush.producer_task,
            producer_node: flush.retaining_node.clone(),
            digest: flush.digest,
            size: flush.size,
            flushed_epoch: self.next_epoch,
            retaining_nodes: BTreeSet::from([flush.retaining_node]),
            explicit_locations: Vec::new(),
            coordinator_has_large_bytes: false,
        };
        if let Some(eviction) = eviction {
            self.artifacts.remove(&eviction);
            self.holds.remove(&eviction);
        }
        self.artifacts.insert(key, metadata.clone());
        self.add_hold(
            &metadata.tenant,
            &metadata.project,
            &metadata.id,
            ArtifactHoldReason::ProcessRetention {
                process: metadata.process.clone(),
            },
            self.next_epoch,
        )
        .expect("newly flushed artifact metadata exists");
        Ok(metadata)
    }

    pub(super) fn enforce_project_metadata_limit(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        pinned: &BTreeSet<ArtifactScopeKey>,
        protected_processes: &BTreeSet<ProcessId>,
    ) -> usize {
        let mut evicted = 0;
        while self
            .artifacts
            .values()
            .filter(|metadata| &metadata.tenant == tenant && &metadata.project == project)
            .count()
            > MAX_ARTIFACT_METADATA_PER_PROJECT
        {
            let candidate = self.project_metadata_eviction_candidate(
                tenant,
                project,
                pinned,
                protected_processes,
            );
            let Some(candidate) = candidate else {
                break;
            };
            self.artifacts.remove(&candidate);
            self.holds.remove(&candidate);
            evicted += 1;
        }
        evicted
    }

    fn project_metadata_eviction_candidate(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        pinned: &BTreeSet<ArtifactScopeKey>,
        protected_processes: &BTreeSet<ProcessId>,
    ) -> Option<ArtifactScopeKey> {
        self.artifacts
            .values()
            .filter(|metadata| {
                &metadata.tenant == tenant
                    && &metadata.project == project
                    && !pinned.contains(&ArtifactScopeKey::from_refs(
                        &metadata.tenant,
                        &metadata.project,
                        &metadata.id,
                    ))
                    && !protected_processes.contains(&metadata.process)
                    && self
                        .holds
                        .get(&ArtifactScopeKey::from_refs(
                            &metadata.tenant,
                            &metadata.project,
                            &metadata.id,
                        ))
                        .is_none_or(BTreeSet::is_empty)
                    && metadata.explicit_locations.is_empty()
                    && !self.issued_download_links.values().any(|issued| {
                        !issued.revoked
                            && issued.link.tenant == metadata.tenant
                            && issued.link.project == metadata.project
                            && issued.link.artifact == metadata.id
                    })
            })
            .min_by_key(|metadata| metadata.flushed_epoch)
            .map(|metadata| {
                ArtifactScopeKey::from_refs(&metadata.tenant, &metadata.project, &metadata.id)
            })
    }

    #[cfg(test)]
    pub(super) fn sync_to_explicit_store(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
        location: impl Into<String>,
    ) -> Result<(), ArtifactUnavailable> {
        let metadata = self
            .artifacts
            .get_mut(&ArtifactScopeKey::from_refs(tenant, project, artifact))
            .ok_or(ArtifactUnavailable)?;
        metadata.explicit_locations.push(location.into());
        Ok(())
    }

    pub(super) fn garbage_collect_node(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
    ) {
        for metadata in self
            .artifacts
            .values_mut()
            .filter(|metadata| &metadata.tenant == tenant && &metadata.project == project)
        {
            metadata.retaining_nodes.remove(node);
        }
    }

    /// Removes one node location after that node authoritatively reports that the
    /// retained bytes are gone. Other verified locations remain available.
    pub(super) fn remove_retaining_location(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
        node: &NodeId,
    ) -> bool {
        self.artifacts
            .get_mut(&ArtifactScopeKey::from_refs(tenant, project, artifact))
            .is_some_and(|metadata| metadata.retaining_nodes.remove(node))
    }

    pub(super) fn reconcile_node_retention(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        node: &NodeId,
        retained_artifacts: &BTreeSet<ArtifactId>,
    ) {
        for (key, metadata) in &mut self.artifacts {
            if &key.tenant != tenant || &key.project != project {
                continue;
            }
            if retained_artifacts.contains(&key.artifact) {
                metadata.retaining_nodes.insert(node.clone());
            } else {
                metadata.retaining_nodes.remove(node);
            }
        }
    }

    /// Records one node location after the node has verified and atomically installed the bytes.
    /// This deliberately does not reconcile unrelated objects retained by the same node.
    pub(super) fn record_verified_retaining_location(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
        node: &NodeId,
        digest: &Digest,
        size: u64,
    ) -> Result<(), ArtifactUnavailable> {
        let metadata = self
            .artifacts
            .get_mut(&ArtifactScopeKey::from_refs(tenant, project, artifact))
            .ok_or(ArtifactUnavailable)?;
        if &metadata.digest != digest || metadata.size != size {
            return Err(ArtifactUnavailable);
        }
        metadata.retaining_nodes.insert(node.clone());
        Ok(())
    }

    pub(super) fn metadata(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
    ) -> Option<&ArtifactMetadata> {
        self.artifacts
            .get(&ArtifactScopeKey::from_refs(tenant, project, artifact))
    }

    pub(super) fn metadata_for_project<'a>(
        &'a self,
        tenant: &'a TenantId,
        project: &'a ProjectId,
    ) -> impl Iterator<Item = &'a ArtifactMetadata> + 'a {
        self.artifacts
            .values()
            .filter(move |metadata| &metadata.tenant == tenant && &metadata.project == project)
    }

    pub(super) fn add_hold(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
        reason: ArtifactHoldReason,
        created_at_epoch_seconds: u64,
    ) -> Result<bool, ArtifactUnavailable> {
        let key = ArtifactScopeKey::from_refs(tenant, project, artifact);
        if !self.artifacts.contains_key(&key) {
            return Err(ArtifactUnavailable);
        }
        let holds = self.holds.entry(key).or_default();
        if holds.iter().any(|hold| hold.reason == reason) {
            return Ok(false);
        }
        Ok(holds.insert(ArtifactHold {
            reason,
            created_at_epoch_seconds,
        }))
    }

    pub(super) fn remove_hold(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
        reason: &ArtifactHoldReason,
    ) -> bool {
        let key = ArtifactScopeKey::from_refs(tenant, project, artifact);
        let Some(holds) = self.holds.get_mut(&key) else {
            return false;
        };
        let before = holds.len();
        holds.retain(|hold| &hold.reason != reason);
        let removed = before != holds.len();
        if holds.is_empty() {
            self.holds.remove(&key);
        }
        removed
    }

    pub(super) fn holds(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        artifact: &ArtifactId,
    ) -> Vec<ArtifactHold> {
        self.holds
            .get(&ArtifactScopeKey::from_refs(tenant, project, artifact))
            .into_iter()
            .flatten()
            .cloned()
            .collect()
    }

    pub(super) fn release_process_hold(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        artifact: &ArtifactId,
    ) -> bool {
        self.remove_hold(
            tenant,
            project,
            artifact,
            &ArtifactHoldReason::ProcessRetention {
                process: process.clone(),
            },
        )
    }

    pub(super) fn release_process_holds(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> usize {
        let mut removed = 0;
        self.holds.retain(|key, holds| {
            if &key.tenant == tenant && &key.project == project {
                let before = holds.len();
                holds.retain(|hold| match &hold.reason {
                    ArtifactHoldReason::ProcessRetention {
                        process: held_process,
                    }
                    | ArtifactHoldReason::ConsumerTask {
                        process: held_process,
                        ..
                    }
                    | ArtifactHoldReason::RestartCheckpoint {
                        process: held_process,
                        ..
                    } => held_process != process,
                    ArtifactHoldReason::ActiveTransfer { .. }
                    | ArtifactHoldReason::DownloadExport { .. }
                    | ArtifactHoldReason::ExplicitRetention { .. } => true,
                });
                removed += before.saturating_sub(holds.len());
            }
            !holds.is_empty()
        });
        removed
    }

    pub(super) fn release_task_holds(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> usize {
        let target = ArtifactHoldReason::ConsumerTask {
            process: process.clone(),
            task: task.clone(),
        };
        let mut removed = 0;
        self.holds.retain(|key, holds| {
            if &key.tenant == tenant && &key.project == project {
                let before = holds.len();
                holds.retain(|hold| hold.reason != target);
                removed += before.saturating_sub(holds.len());
            }
            !holds.is_empty()
        });
        removed
    }

    pub(super) fn release_restart_checkpoint_holds(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        task: &TaskInstanceId,
    ) -> usize {
        let target = ArtifactHoldReason::RestartCheckpoint {
            process: process.clone(),
            task: task.clone(),
        };
        let mut removed = 0;
        self.holds.retain(|key, holds| {
            if &key.tenant == tenant && &key.project == project {
                let before = holds.len();
                holds.retain(|hold| hold.reason != target);
                removed += before.saturating_sub(holds.len());
            }
            !holds.is_empty()
        });
        removed
    }

    pub(super) fn held_artifacts_on_node<'a>(
        &'a self,
        tenant: &'a TenantId,
        project: &'a ProjectId,
        node: &'a NodeId,
    ) -> impl Iterator<Item = (&'a ArtifactMetadata, Vec<ArtifactHold>)> + 'a {
        self.artifacts.values().filter_map(move |metadata| {
            if &metadata.tenant != tenant
                || &metadata.project != project
                || !metadata.retaining_nodes.contains(node)
            {
                return None;
            }
            let holds = self.holds(tenant, project, &metadata.id);
            (!holds.is_empty()).then_some((metadata, holds))
        })
    }

    pub(super) fn download_action(
        &self,
        context: &AuthContext,
        artifact: &ArtifactId,
        policy: &DownloadPolicy,
    ) -> Result<DownloadAction, DownloadError> {
        let metadata = self
            .artifacts
            .get(&ArtifactScopeKey::from_refs(
                &context.tenant,
                &context.project,
                artifact,
            ))
            .ok_or(DownloadError::NotFound)?;
        let scope = Scope {
            tenant: metadata.tenant.clone(),
            project: metadata.project.clone(),
            process: Some(metadata.process.clone()),
            task: Some(metadata.producer_task.clone()),
            node: None,
            artifact: Some(metadata.id.clone()),
        };
        let authz = same_tenant_project(context, &scope);
        if !authz.allowed {
            return Err(DownloadError::Unauthorized(authz.reason));
        }
        if metadata.size > policy.max_bytes {
            return Err(DownloadError::LimitExceeded {
                size: metadata.size,
                limit: policy.max_bytes,
            });
        }
        let source = metadata
            .retaining_nodes
            .iter()
            .next()
            .cloned()
            .map(StorageLocation::RetainedNode)
            .or_else(|| {
                metadata
                    .explicit_locations
                    .first()
                    .cloned()
                    .map(StorageLocation::ExplicitStore)
            })
            .ok_or(DownloadError::Unavailable)?;

        Ok(DownloadAction {
            artifact: artifact.clone(),
            source,
            scoped_token_subject: format!(
                "{}/{}/{}/{}",
                metadata.tenant, metadata.project, metadata.process, metadata.id
            ),
        })
    }

    pub(super) fn downloadable_size(
        &self,
        context: &AuthContext,
        artifact: &ArtifactId,
        policy: &DownloadPolicy,
    ) -> Result<u64, DownloadError> {
        self.download_action(context, artifact, policy)?;
        let metadata = self
            .artifacts
            .get(&ArtifactScopeKey::from_refs(
                &context.tenant,
                &context.project,
                artifact,
            ))
            .ok_or(DownloadError::NotFound)?;
        Ok(metadata.size)
    }

    pub(super) fn create_download_link(
        &mut self,
        context: &AuthContext,
        artifact: &ArtifactId,
        policy: &DownloadPolicy,
        token_nonce: &str,
        now_epoch_seconds: u64,
        ttl_seconds: u64,
    ) -> Result<DownloadLink, DownloadError> {
        self.expire_download_links(now_epoch_seconds);
        if self
            .issued_download_links
            .values()
            .filter(|issued| {
                issued.link.tenant == context.tenant
                    && issued.link.project == context.project
                    && issued.link.artifact == *artifact
            })
            .count()
            >= MAX_ISSUED_DOWNLOAD_LINKS_PER_ARTIFACT
        {
            return Err(DownloadError::Usage(
                "artifact download session limit reached; revoke a link or wait for expiry"
                    .to_owned(),
            ));
        }
        let action = self.download_action(context, artifact, policy)?;
        let metadata = self
            .artifacts
            .get(&ArtifactScopeKey::from_refs(
                &context.tenant,
                &context.project,
                artifact,
            ))
            .ok_or(DownloadError::NotFound)?;
        let expires_at_epoch_seconds = now_epoch_seconds.saturating_add(ttl_seconds);
        let policy_context_digest =
            download_policy_context_digest(metadata, &action.source, policy);
        let scoped_token_digest = Digest::from_parts([
            b"artifact-download-token:v2".as_slice(),
            action.scoped_token_subject.as_bytes(),
            actor_subject(&context.actor).as_bytes(),
            token_nonce.as_bytes(),
            metadata.digest.as_str().as_bytes(),
            metadata.size.to_string().as_bytes(),
            policy_context_digest.as_str().as_bytes(),
            expires_at_epoch_seconds.to_string().as_bytes(),
        ]);
        let link = DownloadLink {
            artifact: artifact.clone(),
            artifact_digest: metadata.digest.clone(),
            artifact_size_bytes: metadata.size,
            source: action.source,
            url_path: format!(
                "/artifacts/{}/{}/{}/{}",
                metadata.tenant, metadata.project, metadata.process, metadata.id
            ),
            scoped_token_digest,
            expires_at_epoch_seconds,
            tenant: metadata.tenant.clone(),
            project: metadata.project.clone(),
            process: metadata.process.clone(),
            actor: context.actor.clone(),
            max_bytes: policy.max_bytes,
            policy_context_digest,
        };
        self.issued_download_links.insert(
            link.scoped_token_digest.clone(),
            IssuedDownloadLink {
                link: link.clone(),
                revoked: false,
            },
        );
        let _ = self.add_hold(
            &link.tenant,
            &link.project,
            &link.artifact,
            ArtifactHoldReason::DownloadExport {
                token_digest: link.scoped_token_digest.clone(),
            },
            now_epoch_seconds,
        );
        Ok(link)
    }

    pub(super) fn revoke_download_link(
        &mut self,
        context: &AuthContext,
        artifact: &ArtifactId,
        presented_token_digest: &Digest,
    ) -> Result<DownloadLink, DownloadError> {
        let issued = self
            .issued_download_links
            .get(presented_token_digest)
            .ok_or(DownloadError::InvalidToken)?;
        if issued.link.tenant != context.tenant
            || issued.link.project != context.project
            || issued.link.artifact != *artifact
            || issued.link.actor != context.actor
        {
            return Err(DownloadError::InvalidToken);
        }
        self.download_action(
            context,
            artifact,
            &DownloadPolicy {
                max_bytes: issued.link.max_bytes,
            },
        )?;

        let issued = self
            .issued_download_links
            .get_mut(presented_token_digest)
            .ok_or(DownloadError::InvalidToken)?;
        issued.revoked = true;
        let link = issued.link.clone();
        self.remove_hold(
            &link.tenant,
            &link.project,
            &link.artifact,
            &ArtifactHoldReason::DownloadExport {
                token_digest: link.scoped_token_digest.clone(),
            },
        );
        Ok(link)
    }

    pub(super) fn expire_download_links(&mut self, now_epoch_seconds: u64) {
        let expired = self
            .issued_download_links
            .values()
            .filter(|issued| issued.link.expires_at_epoch_seconds < now_epoch_seconds)
            .map(|issued| issued.link.clone())
            .collect::<Vec<_>>();
        for link in expired {
            self.remove_hold(
                &link.tenant,
                &link.project,
                &link.artifact,
                &ArtifactHoldReason::DownloadExport {
                    token_digest: link.scoped_token_digest,
                },
            );
        }
        self.issued_download_links.retain(|_, issued| {
            issued
                .link
                .expires_at_epoch_seconds
                .saturating_add(DOWNLOAD_LINK_TOMBSTONE_SECONDS)
                >= now_epoch_seconds
        });
    }

    pub(super) fn retained_download_link_count(&self) -> usize {
        self.issued_download_links.len()
    }

    pub(super) fn artifact_count(&self) -> usize {
        self.artifacts.len()
    }
}

fn download_policy_context_digest(
    metadata: &ArtifactMetadata,
    source: &StorageLocation,
    policy: &DownloadPolicy,
) -> Digest {
    Digest::from_parts([
        b"artifact-download-policy-context:v1".as_slice(),
        metadata.tenant.as_str().as_bytes(),
        metadata.project.as_str().as_bytes(),
        metadata.process.as_str().as_bytes(),
        metadata.id.as_str().as_bytes(),
        metadata.digest.as_str().as_bytes(),
        metadata.size.to_string().as_bytes(),
        storage_location_key(source).as_bytes(),
        policy.max_bytes.to_string().as_bytes(),
    ])
}

fn actor_subject(actor: &Actor) -> String {
    match actor {
        Actor::User(id) => format!("user:{id}"),
        Actor::Agent(id) => format!("agent:{id}"),
        Actor::Node(id) => format!("node:{id}"),
        Actor::Task(id) => format!("task:{id}"),
    }
}

fn storage_location_key(source: &StorageLocation) -> String {
    match source {
        StorageLocation::RetainedNode(node) => format!("retained-node:{node}"),
        StorageLocation::ExplicitStore(location) => format!("explicit-store:{location}"),
    }
}

#[cfg(test)]
mod tests {
    use clusterflux_core::UserId;

    use super::*;

    fn registry_with_artifact() -> ArtifactRegistry {
        let mut registry = ArtifactRegistry::default();
        registry.flush_metadata(ArtifactFlush {
            id: ArtifactId::from("artifact"),
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            producer_task: TaskInstanceId::from("task"),
            retaining_node: NodeId::from("node"),
            digest: Digest::sha256("bytes"),
            size: 32,
        });
        registry
    }

    #[test]
    fn flush_publishes_metadata_without_coordinator_bytes() {
        let registry = registry_with_artifact();
        let metadata = registry
            .metadata(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &ArtifactId::from("artifact"),
            )
            .unwrap();

        assert!(!metadata.coordinator_has_large_bytes);
        assert_eq!(metadata.id, ArtifactId::from("artifact"));
        assert_eq!(metadata.tenant, TenantId::from("tenant"));
        assert_eq!(metadata.project, ProjectId::from("project"));
        assert_eq!(metadata.process, ProcessId::from("process"));
        assert_eq!(metadata.producer_task, TaskInstanceId::from("task"));
        assert_eq!(metadata.producer_node, NodeId::from("node"));
        assert_eq!(metadata.digest, Digest::sha256("bytes"));
        assert_eq!(metadata.size, 32);
        assert_eq!(metadata.flushed_epoch, 1);
        assert!(metadata.retaining_nodes.contains(&NodeId::from("node")));
        assert!(metadata.explicit_locations.is_empty());
    }

    #[test]
    fn unsynced_node_loss_surfaces_as_unavailable() {
        let mut registry = registry_with_artifact();
        registry.garbage_collect_node(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("node"),
        );
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };

        let error = registry
            .download_action(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 100 },
            )
            .unwrap_err();

        assert_eq!(error, DownloadError::Unavailable);
    }

    #[test]
    fn signed_node_retention_inventory_removes_garbage_collected_location() {
        let mut registry = registry_with_artifact();
        registry.reconcile_node_retention(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("node"),
            &BTreeSet::new(),
        );

        let metadata = registry
            .metadata(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &ArtifactId::from("artifact"),
            )
            .unwrap();

        assert!(metadata.retaining_nodes.is_empty());
    }

    #[test]
    fn signed_node_retention_inventory_restores_readvertised_location() {
        let mut registry = registry_with_artifact();
        let node = NodeId::from("node");
        let artifact = ArtifactId::from("artifact");
        registry.garbage_collect_node(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &node,
        );

        registry.reconcile_node_retention(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &node,
            &BTreeSet::from([artifact.clone()]),
        );

        let metadata = registry
            .metadata(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &artifact,
            )
            .unwrap();
        assert!(metadata.retaining_nodes.contains(&node));
    }

    #[test]
    fn explicit_user_storage_location_survives_node_retention_loss() {
        let mut registry = registry_with_artifact();
        registry
            .sync_to_explicit_store(
                &TenantId::from("tenant"),
                &ProjectId::from("project"),
                &ArtifactId::from("artifact"),
                "s3://bucket/app",
            )
            .unwrap();
        registry.garbage_collect_node(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("node"),
        );
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };

        let action = registry
            .download_action(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 100 },
            )
            .unwrap();

        assert_eq!(
            action.source,
            StorageLocation::ExplicitStore("s3://bucket/app".to_owned())
        );
        assert!(
            !registry
                .metadata(
                    &TenantId::from("tenant"),
                    &ProjectId::from("project"),
                    &ArtifactId::from("artifact"),
                )
                .unwrap()
                .coordinator_has_large_bytes
        );
    }

    #[test]
    fn cross_tenant_download_is_denied_even_with_known_artifact_id() {
        let registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("other"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };

        let error = registry
            .download_action(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 100 },
            )
            .unwrap_err();

        assert_eq!(error, DownloadError::NotFound);
    }

    #[test]
    fn cross_project_download_is_denied_even_with_known_artifact_id() {
        let registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("other-project"),
            actor: Actor::User(UserId::from("user")),
        };

        let error = registry
            .download_action(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 100 },
            )
            .unwrap_err();

        assert_eq!(error, DownloadError::NotFound);
    }

    #[test]
    fn duplicate_artifact_ids_are_isolated_across_metadata_links_retention_and_limits() {
        let artifact = ArtifactId::from("shared-artifact");
        let tenant_a = TenantId::from("tenant-a");
        let project_a = ProjectId::from("project-a");
        let tenant_b = TenantId::from("tenant-b");
        let project_b = ProjectId::from("project-b");
        let project_c = ProjectId::from("project-c");
        let node_a = NodeId::from("node-a");
        let node_b = NodeId::from("node-b");
        let node_c = NodeId::from("node-c");
        let mut registry = ArtifactRegistry::default();
        for (tenant, project, process, node, content, size) in [
            (&tenant_a, &project_a, "process-a", &node_a, "bytes-a", 17),
            (&tenant_b, &project_b, "process-b", &node_b, "bytes-b", 29),
            (&tenant_a, &project_c, "process-c", &node_c, "bytes-c", 31),
        ] {
            registry.flush_metadata(ArtifactFlush {
                id: artifact.clone(),
                tenant: tenant.clone(),
                project: project.clone(),
                process: ProcessId::from(process),
                producer_task: TaskInstanceId::from("producer"),
                retaining_node: node.clone(),
                digest: Digest::sha256(content),
                size,
            });
        }

        assert_eq!(registry.artifact_count(), 3);
        assert_eq!(
            registry
                .metadata(&tenant_a, &project_a, &artifact)
                .unwrap()
                .digest,
            Digest::sha256("bytes-a")
        );
        assert_eq!(
            registry
                .metadata(&tenant_b, &project_b, &artifact)
                .unwrap()
                .digest,
            Digest::sha256("bytes-b")
        );
        assert_eq!(
            registry
                .metadata(&tenant_a, &project_c, &artifact)
                .unwrap()
                .digest,
            Digest::sha256("bytes-c")
        );
        registry.flush_metadata(ArtifactFlush {
            id: artifact.clone(),
            tenant: tenant_a.clone(),
            project: project_a.clone(),
            process: ProcessId::from("process-a"),
            producer_task: TaskInstanceId::from("producer-repeat"),
            retaining_node: node_a.clone(),
            digest: Digest::sha256("bytes-a-repeat"),
            size: 18,
        });
        assert_eq!(registry.artifact_count(), 3);
        assert_eq!(
            registry
                .metadata(&tenant_a, &project_a, &artifact)
                .unwrap()
                .digest,
            Digest::sha256("bytes-a-repeat")
        );
        assert_eq!(
            registry
                .metadata(&tenant_b, &project_b, &artifact)
                .unwrap()
                .digest,
            Digest::sha256("bytes-b")
        );

        registry
            .sync_to_explicit_store(&tenant_a, &project_a, &artifact, "store://tenant-a")
            .unwrap();
        registry.garbage_collect_node(&tenant_a, &project_a, &node_a);
        let context_a = AuthContext {
            tenant: tenant_a.clone(),
            project: project_a.clone(),
            actor: Actor::User(UserId::from("user")),
        };
        let context_b = AuthContext {
            tenant: tenant_b.clone(),
            project: project_b.clone(),
            actor: Actor::User(UserId::from("user")),
        };
        let policy = DownloadPolicy { max_bytes: 100 };
        assert_eq!(
            registry
                .download_action(&context_a, &artifact, &policy)
                .unwrap()
                .source,
            StorageLocation::ExplicitStore("store://tenant-a".to_owned())
        );
        assert_eq!(
            registry
                .download_action(&context_b, &artifact, &policy)
                .unwrap()
                .source,
            StorageLocation::RetainedNode(node_b)
        );

        let first_a = registry
            .create_download_link(&context_a, &artifact, &policy, "same-nonce", 10, 60)
            .unwrap();
        let first_b = registry
            .create_download_link(&context_b, &artifact, &policy, "same-nonce", 10, 60)
            .unwrap();
        assert_ne!(
            first_a.scoped_token_digest, first_b.scoped_token_digest,
            "the full artifact scope must contribute to download tokens"
        );
        for index in 1..MAX_ISSUED_DOWNLOAD_LINKS_PER_ARTIFACT {
            registry
                .create_download_link(
                    &context_a,
                    &artifact,
                    &policy,
                    &format!("tenant-a-{index}"),
                    10,
                    60,
                )
                .unwrap();
        }
        assert!(matches!(
            registry.create_download_link(
                &context_a,
                &artifact,
                &policy,
                "tenant-a-over-limit",
                10,
                60,
            ),
            Err(DownloadError::Usage(_))
        ));
        registry
            .create_download_link(
                &context_b,
                &artifact,
                &policy,
                "tenant-b-still-independent",
                10,
                60,
            )
            .unwrap();
        registry
            .revoke_download_link(&context_a, &artifact, &first_a.scoped_token_digest)
            .unwrap();
        registry
            .revoke_download_link(&context_b, &artifact, &first_b.scoped_token_digest)
            .expect("revoking tenant A's link must not revoke tenant B's link");
        assert_eq!(
            registry
                .revoke_download_link(&context_b, &artifact, &first_a.scoped_token_digest)
                .unwrap_err(),
            DownloadError::InvalidToken
        );
    }

    #[test]
    fn download_link_is_not_created_when_artifact_is_unavailable_or_too_large() {
        let mut registry = registry_with_artifact();
        registry.garbage_collect_node(
            &TenantId::from("tenant"),
            &ProjectId::from("project"),
            &NodeId::from("node"),
        );
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };

        assert_eq!(
            registry
                .create_download_link(
                    &context,
                    &ArtifactId::from("artifact"),
                    &DownloadPolicy { max_bytes: 100 },
                    "nonce",
                    10,
                    60,
                )
                .unwrap_err(),
            DownloadError::Unavailable
        );

        let mut registry = registry_with_artifact();
        assert!(matches!(
            registry.create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 1 },
                "nonce",
                10,
                60,
            ),
            Err(DownloadError::LimitExceeded { .. })
        ));
    }

    #[test]
    fn download_link_is_authenticated_scoped_and_not_guessable() {
        let mut registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let link = registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 100 },
                "nonce-a",
                10,
                60,
            )
            .unwrap();
        let other = registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 100 },
                "nonce-b",
                10,
                60,
            )
            .unwrap();

        assert_eq!(link.tenant, TenantId::from("tenant"));
        assert_eq!(link.project, ProjectId::from("project"));
        assert_eq!(link.process, ProcessId::from("process"));
        assert_eq!(link.actor, Actor::User(UserId::from("user")));
        assert_eq!(link.max_bytes, 100);
        assert!(link.policy_context_digest.is_valid_sha256());
        assert_eq!(link.expires_at_epoch_seconds, 70);
        assert!(link
            .url_path
            .contains("/artifacts/tenant/project/process/artifact"));
        assert_ne!(link.scoped_token_digest, other.scoped_token_digest);
        assert!(matches!(link.source, StorageLocation::RetainedNode(_)));
    }

    #[test]
    fn download_link_is_bound_to_actor_and_policy_context_metadata() {
        let mut registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let other_actor = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("other-user")),
        };
        let policy = DownloadPolicy { max_bytes: 100 };
        let link = registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &policy,
                "nonce",
                10,
                60,
            )
            .unwrap();
        let other_policy_link = registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &DownloadPolicy { max_bytes: 99 },
                "other-policy",
                10,
                60,
            )
            .unwrap();
        assert_ne!(
            link.policy_context_digest,
            other_policy_link.policy_context_digest
        );
        assert_eq!(
            registry
                .revoke_download_link(
                    &other_actor,
                    &ArtifactId::from("artifact"),
                    &link.scoped_token_digest,
                )
                .unwrap_err(),
            DownloadError::InvalidToken
        );
    }

    #[test]
    fn download_link_history_expires_and_active_links_can_be_revoked() {
        let mut registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let policy = DownloadPolicy { max_bytes: 100 };
        registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &policy,
                "expired",
                10,
                5,
            )
            .unwrap();
        assert_eq!(registry.retained_download_link_count(), 1);
        registry.expire_download_links(10 + 5 + DOWNLOAD_LINK_TOMBSTONE_SECONDS + 1);
        assert_eq!(registry.retained_download_link_count(), 0);

        let active = registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &policy,
                "active",
                20,
                60,
            )
            .unwrap();
        let revoked = registry
            .revoke_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &active.scoped_token_digest,
            )
            .unwrap();
        assert_eq!(revoked.scoped_token_digest, active.scoped_token_digest);
        assert!(
            registry
                .issued_download_links
                .get(&active.scoped_token_digest)
                .unwrap()
                .revoked
        );
    }

    #[test]
    fn download_session_history_is_count_and_time_bounded() {
        let mut registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let policy = DownloadPolicy { max_bytes: 100 };
        for index in 0..MAX_ISSUED_DOWNLOAD_LINKS_PER_ARTIFACT {
            registry
                .create_download_link(
                    &context,
                    &ArtifactId::from("artifact"),
                    &policy,
                    &format!("bounded-{index}"),
                    10,
                    1,
                )
                .unwrap();
        }
        assert_eq!(
            registry.retained_download_link_count(),
            MAX_ISSUED_DOWNLOAD_LINKS_PER_ARTIFACT
        );
        assert!(matches!(
            registry.create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &policy,
                "over-limit",
                10,
                1,
            ),
            Err(DownloadError::Usage(_))
        ));

        registry.expire_download_links(12 + DOWNLOAD_LINK_TOMBSTONE_SECONDS);
        assert_eq!(registry.retained_download_link_count(), 0);
        registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &policy,
                "after-expiry",
                12 + DOWNLOAD_LINK_TOMBSTONE_SECONDS,
                1,
            )
            .unwrap();
    }

    #[test]
    fn artifact_metadata_is_bounded_per_project_without_evicting_live_or_retained_state() {
        let mut registry = ArtifactRegistry::default();
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        registry.flush_metadata(ArtifactFlush {
            id: ArtifactId::from("artifact-0"),
            tenant: TenantId::from("other-tenant"),
            project: ProjectId::from("other-project"),
            process: ProcessId::from("process"),
            producer_task: TaskInstanceId::from("other-task"),
            retaining_node: NodeId::from("other-node"),
            digest: Digest::sha256("other-content"),
            size: 1,
        });
        for index in 0..MAX_ARTIFACT_METADATA_PER_PROJECT {
            let id = ArtifactId::new(format!("artifact-{index}"));
            let process = ProcessId::new(if index == 3 {
                "active-process-3".to_owned()
            } else {
                format!("completed-process-{index}")
            });
            registry.flush_metadata(ArtifactFlush {
                id,
                tenant: tenant.clone(),
                project: project.clone(),
                process: process.clone(),
                producer_task: TaskInstanceId::new(format!("task-{index}")),
                retaining_node: NodeId::from("node"),
                digest: Digest::sha256(format!("content-{index}")),
                size: 1,
            });
            if index != 3 {
                registry.release_process_holds(&tenant, &project, &process);
            }
        }
        assert_eq!(
            registry.artifact_count(),
            MAX_ARTIFACT_METADATA_PER_PROJECT + 1
        );
        let pinned = BTreeSet::from([ArtifactScopeKey::new(
            tenant.clone(),
            project.clone(),
            ArtifactId::from("artifact-0"),
        )]);
        registry
            .sync_to_explicit_store(
                &tenant,
                &project,
                &ArtifactId::from("artifact-1"),
                "store://retained-export",
            )
            .unwrap();
        let context = AuthContext {
            tenant: tenant.clone(),
            project: project.clone(),
            actor: Actor::User(UserId::from("user")),
        };
        registry
            .create_download_link(
                &context,
                &ArtifactId::from("artifact-2"),
                &DownloadPolicy { max_bytes: 1 },
                "active-download",
                10,
                60,
            )
            .unwrap();
        let protected_processes = BTreeSet::from([
            ProcessId::from("active-process-3"),
            ProcessId::from("active-process"),
        ]);
        let next = ArtifactFlush {
            id: ArtifactId::from("artifact-next"),
            tenant: tenant.clone(),
            project: project.clone(),
            process: ProcessId::from("active-process"),
            producer_task: TaskInstanceId::from("task-next"),
            retaining_node: NodeId::from("node"),
            digest: Digest::sha256("next"),
            size: 1,
        };
        registry
            .flush_metadata_with_protected_processes(next, &pinned, &protected_processes)
            .unwrap();
        assert_eq!(
            registry.artifact_count(),
            MAX_ARTIFACT_METADATA_PER_PROJECT + 1
        );
        for id in ["artifact-0", "artifact-1", "artifact-2", "artifact-3"] {
            assert!(
                registry
                    .metadata(&tenant, &project, &ArtifactId::from(id))
                    .is_some(),
                "{id} was evicted despite being pinned, exported, downloaded, or live"
            );
        }
        assert!(
            registry
                .metadata(&tenant, &project, &ArtifactId::from("artifact-4"))
                .is_none(),
            "the oldest completed unprotected metadata should be evicted"
        );
        assert!(registry
            .metadata(&tenant, &project, &ArtifactId::from("artifact-next"))
            .is_some());
        assert_eq!(
            registry
                .metadata(
                    &TenantId::from("other-tenant"),
                    &ProjectId::from("other-project"),
                    &ArtifactId::from("artifact-0"),
                )
                .unwrap()
                .digest,
            Digest::sha256("other-content"),
            "eviction and pins in one scope must not affect an equal ID in another scope"
        );
    }

    #[test]
    fn artifact_metadata_capacity_rejects_atomically_when_every_entry_is_protected() {
        let mut registry = ArtifactRegistry::default();
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let active_process = ProcessId::from("active-process");
        for index in 0..MAX_ARTIFACT_METADATA_PER_PROJECT {
            registry.flush_metadata(ArtifactFlush {
                id: ArtifactId::new(format!("artifact-{index}")),
                tenant: tenant.clone(),
                project: project.clone(),
                process: active_process.clone(),
                producer_task: TaskInstanceId::new(format!("task-{index}")),
                retaining_node: NodeId::from("node"),
                digest: Digest::sha256(format!("content-{index}")),
                size: 1,
            });
        }

        let replacement = ArtifactFlush {
            id: ArtifactId::from("artifact-0"),
            tenant: tenant.clone(),
            project: project.clone(),
            process: active_process.clone(),
            producer_task: TaskInstanceId::from("replacement-task"),
            retaining_node: NodeId::from("node"),
            digest: Digest::sha256("replacement"),
            size: 2,
        };
        registry
            .flush_metadata_with_protected_processes(
                replacement,
                &BTreeSet::new(),
                &BTreeSet::from([active_process.clone()]),
            )
            .expect("replacement must remain possible at the metadata bound");
        assert_eq!(
            registry
                .metadata(&tenant, &project, &ArtifactId::from("artifact-0"))
                .unwrap()
                .digest,
            Digest::sha256("replacement")
        );

        let epoch_before_rejection = registry.next_epoch;
        let result = registry.flush_metadata_with_protected_processes(
            ArtifactFlush {
                id: ArtifactId::from("artifact-rejected"),
                tenant: tenant.clone(),
                project: project.clone(),
                process: active_process.clone(),
                producer_task: TaskInstanceId::from("rejected-task"),
                retaining_node: NodeId::from("node"),
                digest: Digest::sha256("rejected"),
                size: 3,
            },
            &BTreeSet::new(),
            &BTreeSet::from([active_process]),
        );

        assert!(result
            .unwrap_err()
            .contains("exhausted by active or retained artifacts"));
        assert_eq!(registry.next_epoch, epoch_before_rejection);
        assert_eq!(
            registry.metadata_for_project(&tenant, &project).count(),
            MAX_ARTIFACT_METADATA_PER_PROJECT
        );
        assert!(registry
            .metadata(&tenant, &project, &ArtifactId::from("artifact-rejected"))
            .is_none());
        assert_eq!(
            registry
                .metadata(&tenant, &project, &ArtifactId::from("artifact-0"))
                .unwrap()
                .digest,
            Digest::sha256("replacement"),
            "rejection must not modify existing metadata"
        );
    }

    #[test]
    fn guessed_download_token_is_rejected() {
        let mut registry = registry_with_artifact();
        let context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let error = registry
            .revoke_download_link(
                &context,
                &ArtifactId::from("artifact"),
                &Digest::sha256("guessed"),
            )
            .unwrap_err();

        assert_eq!(error, DownloadError::InvalidToken);
    }
}
