use clusterflux_core::{
    generate_opaque_token, Actor, ArtifactHandle, ArtifactHoldReason, ArtifactId, AuthContext,
    Digest, DownloadPolicy, NodeId, ProcessId, ProjectId, StorageLocation, TenantId, UserId,
};

use crate::NodeScopeKey;

use super::{bounded_ttl, CoordinatorResponse, CoordinatorService, CoordinatorServiceError};

impl CoordinatorService {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_release_artifact(
        &mut self,
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        artifact: String,
        digest: Digest,
        size_bytes: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = clusterflux_core::ProcessId::new(process);
        let node = NodeId::new(node);
        let task = clusterflux_core::TaskInstanceId::new(task);
        let artifact = ArtifactId::new(artifact);
        self.authorize_node_for_process_or_termination(&node, &tenant, &project, &process)?;
        let metadata = self
            .artifact_registry
            .metadata(&tenant, &project, &artifact)
            .ok_or(clusterflux_core::DownloadError::NotFound)?;
        if metadata.process != process || metadata.digest != digest || metadata.size != size_bytes {
            return Err(CoordinatorServiceError::Protocol(
                "artifact release handle does not match scoped coordinator metadata".to_owned(),
            ));
        }
        let task_active = self.task_registry.active_tasks().any(
            |(entry_tenant, entry_project, entry_process, entry_node, entry_task)| {
                entry_tenant == &tenant
                    && entry_project == &project
                    && entry_process == &process
                    && entry_node == &node
                    && entry_task == &task
            },
        );
        if !task_active
            && !self.process_registry.is_cancelled(&(
                tenant.clone(),
                project.clone(),
                process.clone(),
            ))
        {
            return Err(CoordinatorServiceError::Protocol(
                "artifact release must originate from an active task in the owning process"
                    .to_owned(),
            ));
        }
        self.release_process_artifact_hold(
            tenant,
            project,
            process,
            ArtifactHandle {
                id: artifact,
                digest,
                size_bytes,
            },
        )
    }

    pub(super) fn handle_coordinator_main_release_artifact(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        artifact: ArtifactHandle,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        self.release_process_artifact_hold(tenant, project, process, artifact)
    }

    fn release_process_artifact_hold(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        process: ProcessId,
        artifact: ArtifactHandle,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let metadata = self
            .artifact_registry
            .metadata(&tenant, &project, &artifact.id)
            .ok_or(clusterflux_core::DownloadError::NotFound)?;
        if metadata.process != process
            || metadata.digest != artifact.digest
            || metadata.size != artifact.size_bytes
        {
            return Err(CoordinatorServiceError::Protocol(
                "artifact release handle does not match scoped coordinator metadata".to_owned(),
            ));
        }
        let hold_removed =
            self.artifact_registry
                .release_process_hold(&tenant, &project, &process, &artifact.id);
        let remaining_holds = self
            .artifact_registry
            .holds(&tenant, &project, &artifact.id);
        Ok(CoordinatorResponse::ArtifactReleased {
            artifact: artifact.id,
            process,
            hold_removed,
            remaining_holds,
        })
    }

    pub(super) fn handle_create_artifact_download_link(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
        max_bytes: u64,
        ttl_seconds: u64,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let context = user_context(tenant, project, actor_user);
        let artifact = ArtifactId::new(artifact);
        let policy = DownloadPolicy { max_bytes };
        let action = self
            .artifact_registry
            .download_action(&context, &artifact, &policy)?;
        self.ensure_download_source_connectivity(
            &context.tenant,
            &context.project,
            &action.source,
        )?;
        // This is an authorization/metadata link only. Artifact bodies never reserve
        // coordinator relay or download-byte quota because node interchange moves them
        // directly over Iroh.
        self.artifact_registry
            .downloadable_size(&context, &artifact, &policy)?;
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let token_nonce = generate_opaque_token("artifact_download")
            .map_err(CoordinatorServiceError::Protocol)?;
        let ttl_seconds = bounded_ttl(
            ttl_seconds,
            self.admission.max_artifact_download_ttl_seconds,
        );
        let link = self.artifact_registry.create_download_link(
            &context,
            &artifact,
            &policy,
            &token_nonce,
            now_epoch_seconds,
            ttl_seconds,
        )?;
        Ok(CoordinatorResponse::ArtifactDownloadLink { link })
    }

    pub(super) fn handle_revoke_artifact_download_link(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
        token_digest: Digest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let context = user_context(tenant, project, actor_user);
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.artifact_registry
            .expire_download_links(now_epoch_seconds);
        let link = self.artifact_registry.revoke_download_link(
            &context,
            &ArtifactId::new(artifact),
            &token_digest,
        )?;
        Ok(CoordinatorResponse::ArtifactDownloadLinkRevoked { link })
    }

    pub(super) fn handle_export_artifact_to_node(
        &mut self,
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
        receiver_node: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let context = user_context(tenant, project, actor_user);
        let artifact = ArtifactId::new(artifact);
        let receiver_node = NodeId::new(receiver_node);
        let action = self.artifact_registry.download_action(
            &context,
            &artifact,
            &DownloadPolicy {
                max_bytes: u64::MAX,
            },
        )?;
        let StorageLocation::RetainedNode(_) = action.source else {
            return Err(clusterflux_core::DownloadError::Unavailable.into());
        };
        let metadata = self
            .artifact_registry
            .metadata(&context.tenant, &context.project, &artifact)
            .cloned()
            .ok_or(clusterflux_core::DownloadError::NotFound)?;
        if metadata.retaining_nodes.contains(&receiver_node) {
            return Ok(CoordinatorResponse::ArtifactExport {
                already_present: true,
                transfer: None,
                receiver_node,
                artifact_size_bytes: metadata.size,
            });
        }

        // An explicit export is a new, concrete retention need even after normal
        // process retirement released the producer's process hold. Bridge the
        // request into interchange creation with a short-lived hold; a successful
        // transfer replaces it with its own ActiveTransfer hold.
        let export_hold = ArtifactHoldReason::ExplicitRetention {
            label: generate_opaque_token("artifact_export_hold")
                .map_err(CoordinatorServiceError::Protocol)?,
        };
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.artifact_registry
            .add_hold(
                &context.tenant,
                &context.project,
                &artifact,
                export_hold.clone(),
                now_epoch_seconds,
            )
            .map_err(|_| clusterflux_core::DownloadError::Unavailable)?;
        let response = self.handle_request_artifact_interchange(
            context.tenant.as_str().to_owned(),
            context.project.as_str().to_owned(),
            metadata.process.as_str().to_owned(),
            receiver_node.as_str().to_owned(),
            artifact.as_str().to_owned(),
            0,
        );
        self.artifact_registry.remove_hold(
            &context.tenant,
            &context.project,
            &artifact,
            &export_hold,
        );
        let response = response?;
        let transfer = match response {
            CoordinatorResponse::ArtifactTransferAuthorization { transfer, .. } => transfer,
            _ => unreachable!("artifact interchange creation returns an authorization response"),
        };
        Ok(CoordinatorResponse::ArtifactExport {
            already_present: transfer.is_none(),
            transfer,
            receiver_node,
            artifact_size_bytes: metadata.size,
        })
    }

    fn ensure_download_source_connectivity(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        source: &StorageLocation,
    ) -> Result<(), clusterflux_core::DownloadError> {
        let StorageLocation::RetainedNode(node) = source else {
            return Ok(());
        };
        let node_scope = NodeScopeKey::from_refs(tenant, project, node);
        self.node_registry.descriptor(&node_scope).ok_or_else(|| {
            clusterflux_core::DownloadError::DirectConnectivityUnavailable(format!(
                "retaining node {node} has not reported online status for artifact download"
            ))
        })?;
        if !self.node_is_live(&node_scope) {
            return Err(
                clusterflux_core::DownloadError::DirectConnectivityUnavailable(format!(
                    "retaining node {node} is offline for artifact download"
                )),
            );
        }
        Ok(())
    }
}

fn user_context(tenant: String, project: String, actor_user: String) -> AuthContext {
    AuthContext {
        tenant: TenantId::new(tenant),
        project: ProjectId::new(project),
        actor: Actor::User(UserId::new(actor_user)),
    }
}
