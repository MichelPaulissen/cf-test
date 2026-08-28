use super::*;

impl CoordinatorService {
    pub fn handle_request(
        &mut self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        request
            .validate_external_identifiers()
            .map_err(CoordinatorServiceError::Protocol)?;
        self.reconcile_expired_process_assignments()?;
        self.pump_main_runtime_commands();
        let request_payload = serde_json::to_value(&request).map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "failed to canonicalize coordinator request for authentication: {error}"
            ))
        })?;
        let request_payload_digest =
            clusterflux_core::signed_request_payload_digest(&request_payload);
        match request {
            CoordinatorRequest::Ping => Ok(CoordinatorResponse::Pong {
                epoch: self.coordinator.coordinator_epoch(),
            }),
            CoordinatorRequest::Authenticated {
                session_secret,
                request,
            } => self.handle_authenticated_request(session_secret, request),
            CoordinatorRequest::AuthStatus {
                tenant,
                project,
                actor_user,
            } => {
                let tenant = TenantId::new(tenant);
                let project = ProjectId::new(project);
                let actor = UserId::new(actor_user);
                let account_state = self.coordinator.account_policy_state(&tenant);
                Ok(CoordinatorResponse::AuthStatus {
                    tenant,
                    project,
                    actor,
                    authenticated: true,
                    coordinator_version: env!("CARGO_PKG_VERSION").to_owned(),
                    workflow_sdk_version: clusterflux_core::SUPPORTED_WORKFLOW_SDK_VERSION
                        .to_owned(),
                    account_status: account_state.account_status,
                    suspended: account_state.suspended,
                    disabled: account_state.disabled,
                    deleted: account_state.deleted,
                    manual_review: account_state.manual_review,
                    sanitized_reason: account_state.sanitized_reason,
                    next_actions: account_state.next_actions,
                    sensitive_moderation_details_exposed: false,
                    signup_failure_details_exposed: false,
                })
            }
            CoordinatorRequest::AdminStatus {
                tenant,
                actor_user,
                admin_proof,
                admin_nonce,
                issued_at_epoch_seconds,
            } => self.handle_admin_status(
                tenant,
                actor_user,
                admin_proof,
                admin_nonce,
                issued_at_epoch_seconds,
            ),
            CoordinatorRequest::SuspendTenant {
                tenant,
                actor_user,
                target_tenant,
                admin_proof,
                admin_nonce,
                issued_at_epoch_seconds,
            } => self.handle_suspend_tenant(
                tenant,
                actor_user,
                target_tenant,
                admin_proof,
                admin_nonce,
                issued_at_epoch_seconds,
            ),
            CoordinatorRequest::CreateProject {
                tenant,
                actor_user,
                project,
                name,
            } => {
                let tenant = TenantId::new(tenant);
                let actor = UserId::new(actor_user);
                let project = ProjectId::new(project);
                self.coordinator.ensure_tenant_active(&tenant)?;
                if let Some(existing) = self.coordinator.project(&project) {
                    if existing.tenant != tenant {
                        return Err(CoordinatorError::Unauthorized(
                            "project id is outside the signed-in tenant scope".to_owned(),
                        )
                        .into());
                    }
                }
                if self.coordinator.project(&project).is_none() {
                    self.quota.ensure_project_admission(
                        &tenant,
                        self.coordinator.project_count_for_tenant(&tenant),
                        self.coordinator
                            .tenant_quota_override(&tenant)
                            .map(|record| &record.values),
                    )?;
                }
                self.coordinator.upsert_tenant(tenant.clone());
                self.coordinator.upsert_user(
                    tenant.clone(),
                    actor.clone(),
                    CredentialKind::BrowserSession,
                );
                self.coordinator
                    .upsert_project(tenant.clone(), project.clone(), name);
                self.coordinator.grant_project_debug(
                    tenant.clone(),
                    project.clone(),
                    actor.clone(),
                );
                self.persist_durable_state()?;
                let project = self
                    .coordinator
                    .project(&project)
                    .expect("project was just created")
                    .clone();
                Ok(CoordinatorResponse::ProjectCreated { project, actor })
            }
            CoordinatorRequest::SelectProject {
                tenant,
                actor_user,
                project,
            } => {
                let tenant = TenantId::new(tenant);
                let actor = UserId::new(actor_user);
                let project_id = ProjectId::new(project);
                let project = self
                    .coordinator
                    .project(&project_id)
                    .ok_or_else(|| {
                        CoordinatorError::Unauthorized(
                            "project is not visible to the signed-in user".to_owned(),
                        )
                    })?
                    .clone();
                if project.tenant != tenant {
                    return Err(CoordinatorError::Unauthorized(
                        "project is outside the signed-in tenant scope".to_owned(),
                    )
                    .into());
                }
                self.coordinator
                    .upsert_user(tenant, actor.clone(), CredentialKind::BrowserSession);
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::ProjectSelected { project, actor })
            }
            CoordinatorRequest::ListProjects { tenant, actor_user } => {
                let tenant = TenantId::new(tenant);
                let actor = UserId::new(actor_user);
                let context = clusterflux_core::AuthContext {
                    tenant: tenant.clone(),
                    project: ProjectId::from("__project_listing__"),
                    actor: Actor::User(actor.clone()),
                };
                self.coordinator
                    .upsert_user(tenant, actor.clone(), CredentialKind::BrowserSession);
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::Projects {
                    projects: self.coordinator.list_projects(&context),
                    actor,
                })
            }
            CoordinatorRequest::RegisterAgentPublicKey {
                tenant,
                project,
                user,
                agent,
                public_key,
            }
            | CoordinatorRequest::RotateAgentPublicKey {
                tenant,
                project,
                user,
                agent,
                public_key,
            } => {
                let tenant = TenantId::new(tenant);
                let project = ProjectId::new(project);
                let actor = UserId::new(user);
                let agent = AgentId::new(agent);
                self.coordinator.ensure_tenant_active(&tenant)?;
                if let Some(existing) = self.coordinator.project(&project) {
                    if existing.tenant != tenant {
                        return Err(CoordinatorError::Unauthorized(
                            "project id is outside the signed-in tenant scope".to_owned(),
                        )
                        .into());
                    }
                }
                self.coordinator.upsert_tenant(tenant.clone());
                self.coordinator.upsert_user(
                    tenant.clone(),
                    actor.clone(),
                    CredentialKind::CliDeviceSession,
                );
                self.coordinator
                    .upsert_project(tenant.clone(), project.clone(), "local");
                let record = self.coordinator.register_agent_public_key(
                    tenant,
                    project,
                    actor.clone(),
                    agent,
                    public_key,
                );
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::AgentPublicKey { record, actor })
            }
            CoordinatorRequest::ListAgentPublicKeys {
                tenant,
                project,
                user,
            } => {
                let tenant = TenantId::new(tenant);
                let project = ProjectId::new(project);
                let actor = UserId::new(user);
                let context = clusterflux_core::AuthContext {
                    tenant,
                    project,
                    actor: Actor::User(actor.clone()),
                };
                Ok(CoordinatorResponse::AgentPublicKeys {
                    records: self.coordinator.list_agent_public_keys(&context),
                    actor,
                })
            }
            CoordinatorRequest::RevokeAgentPublicKey {
                tenant,
                project,
                user,
                agent,
            } => {
                let tenant = TenantId::new(tenant);
                let project = ProjectId::new(project);
                let actor = UserId::new(user);
                let agent = AgentId::new(agent);
                let context = clusterflux_core::AuthContext {
                    tenant,
                    project,
                    actor: Actor::User(actor.clone()),
                };
                let record = self.coordinator.revoke_agent_public_key(&context, &agent)?;
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::AgentPublicKey { record, actor })
            }
            CoordinatorRequest::AttachNode {
                tenant,
                project,
                node,
                public_key,
            } => self.handle_attach_node(tenant, project, node, public_key),
            CoordinatorRequest::CreateNodeEnrollmentGrant {
                tenant,
                project,
                actor_user,
                ttl_seconds,
            } => self.handle_create_node_enrollment_grant(tenant, project, actor_user, ttl_seconds),
            CoordinatorRequest::ExchangeNodeEnrollmentGrant {
                tenant,
                project,
                node,
                public_key,
                enrollment_grant,
            } => self.handle_exchange_node_enrollment_grant(
                tenant,
                project,
                node,
                public_key,
                enrollment_grant,
            ),
            CoordinatorRequest::NodeHeartbeat {
                tenant,
                project,
                node,
                node_signature,
            } => self.handle_node_heartbeat(
                tenant,
                project,
                node,
                node_signature,
                &request_payload_digest,
            ),
            CoordinatorRequest::SignedNode {
                node,
                node_signature,
                request,
            } => self.handle_signed_node_request(node, node_signature, *request),
            CoordinatorRequest::ReportNodeCapabilities { .. }
            | CoordinatorRequest::ReportSystemTask { .. }
            | CoordinatorRequest::PollTaskSecretGrant { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::ListNodeDescriptors {
                tenant,
                project,
                actor_user,
            } => self.handle_list_node_descriptors(tenant, project, actor_user),
            CoordinatorRequest::ListNodeSummaries {
                tenant,
                project,
                actor_user,
                cursor,
                limit,
            } => self.handle_list_node_summaries(tenant, project, actor_user, cursor, limit),
            CoordinatorRequest::RevokeNodeCredential {
                tenant,
                project,
                actor_user,
                node,
            } => self.handle_revoke_node_credential(tenant, project, actor_user, node),
            CoordinatorRequest::ScheduleTask {
                tenant,
                project,
                environment,
                environment_digest,
                required_capabilities,
                dependency_cache,
                source_snapshot,
                required_artifacts,
                prefer_node,
            } => self.handle_schedule_task(
                tenant,
                project,
                environment,
                environment_digest,
                required_capabilities,
                dependency_cache,
                source_snapshot,
                required_artifacts,
                prefer_node,
            ),
            CoordinatorRequest::LaunchTask {
                tenant,
                project,
                actor_user,
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature,
                task_spec,
                wait_for_node,
                artifact_path,
                wasm_module_base64,
            } => self.handle_launch_task(
                tenant,
                project,
                actor_user,
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature,
                Some(&request_payload_digest),
                task_spec,
                wait_for_node,
                artifact_path,
                wasm_module_base64,
            ),
            CoordinatorRequest::LaunchChildTask { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::JoinChildTask { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::PollNodeAssignment { .. }
            | CoordinatorRequest::AcknowledgeNodeAssignment { .. } => {
                self.reject_unsigned_node_request()
            }
            CoordinatorRequest::RequestSourcePreparation {
                tenant,
                project,
                provider,
            } => self.handle_request_source_preparation(tenant, project, provider),
            CoordinatorRequest::CompleteSourcePreparation { .. } => {
                self.reject_unsigned_node_request()
            }
            CoordinatorRequest::StartProcess {
                tenant,
                project,
                actor_user,
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature,
                process,
                launch_attempt,
                restart,
            } => self.handle_start_process(
                tenant,
                project,
                actor_user,
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature,
                Some(&request_payload_digest),
                process,
                launch_attempt,
                restart,
            ),
            CoordinatorRequest::ReconnectNode { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::CancelTask {
                tenant,
                project,
                process,
                node,
                task,
            } => self.handle_cancel_task(tenant, project, process, node, task),
            CoordinatorRequest::CancelProcess {
                tenant,
                project,
                actor_user,
                process,
            } => self.handle_cancel_process(tenant, project, actor_user, process),
            CoordinatorRequest::AbortProcess {
                tenant,
                project,
                actor_user,
                process,
                launch_attempt,
            } => self.handle_abort_process(tenant, project, actor_user, process, launch_attempt),
            CoordinatorRequest::ListProcesses {
                tenant,
                project,
                actor_user,
            } => self.handle_list_processes(tenant, project, actor_user),
            CoordinatorRequest::ListProcessSummaries {
                tenant,
                project,
                actor_user,
                cursor,
                limit,
            } => self.handle_list_process_summaries(tenant, project, actor_user, cursor, limit),
            CoordinatorRequest::QuotaStatus {
                tenant,
                project,
                actor_user,
            } => self.handle_quota_status(tenant, project, actor_user),
            CoordinatorRequest::PollTaskControl { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::GetArtifactDataPlanePolicy { .. }
            | CoordinatorRequest::ReportIrohEndpointAdvertisement { .. }
            | CoordinatorRequest::RequestArtifactInterchange { .. }
            | CoordinatorRequest::PollArtifactProviderAssignment { .. }
            | CoordinatorRequest::PollArtifactReceiverAssignment { .. }
            | CoordinatorRequest::AcknowledgeArtifactAssignment { .. }
            | CoordinatorRequest::ReportArtifactInterchange { .. }
            | CoordinatorRequest::ReleaseArtifact { .. }
            | CoordinatorRequest::BeginNodeDrain { .. }
            | CoordinatorRequest::FinalizeNodeRelease { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::RestartTask {
                tenant,
                project,
                actor_user,
                process,
                task,
                replacement_bundle,
            } => self.handle_restart_task(
                tenant,
                project,
                actor_user,
                process,
                task,
                replacement_bundle,
            ),
            CoordinatorRequest::ResolveTaskFailure {
                tenant,
                project,
                actor_user,
                process,
                task,
                resolution,
            } => self.handle_resolve_task_failure(
                tenant, project, actor_user, process, task, resolution,
            ),
            request @ (CoordinatorRequest::DebugAttach { .. }
            | CoordinatorRequest::SetDebugBreakpoints { .. }
            | CoordinatorRequest::InspectDebugBreakpoints { .. }
            | CoordinatorRequest::CreateDebugEpoch { .. }
            | CoordinatorRequest::ResumeDebugEpoch { .. }
            | CoordinatorRequest::InspectDebugEpoch { .. }) => self.handle_debug_request(request),
            CoordinatorRequest::PollDebugCommand { .. }
            | CoordinatorRequest::ReportDebugState { .. }
            | CoordinatorRequest::ReportDebugProbeHit { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::ReportTaskLog { .. }
            | CoordinatorRequest::ReportTaskLogChunk { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::ReportVfsMetadata { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::TaskCompleted { .. } => self.reject_unsigned_node_request(),
            CoordinatorRequest::ListTaskEvents {
                tenant,
                project,
                actor_user,
                process,
            } => self.handle_list_task_events(tenant, project, actor_user, process),
            CoordinatorRequest::ListTaskSnapshots {
                tenant,
                project,
                actor_user,
                process,
            } => self.handle_list_task_snapshots(tenant, project, actor_user, process),
            CoordinatorRequest::ListRecentLogs {
                tenant,
                project,
                actor_user,
                process,
                task,
                after_sequence,
                limit,
            } => self.handle_list_recent_logs(
                tenant,
                project,
                actor_user,
                process,
                task,
                after_sequence,
                limit,
            ),
            CoordinatorRequest::JoinTask {
                tenant,
                project,
                actor_user,
                process,
                task,
            } => self.handle_join_task(tenant, project, actor_user, process, task),
            CoordinatorRequest::RenderOperatorPanel {
                tenant,
                project,
                process,
                actor_user,
                max_download_bytes,
                stopped,
            } => self.handle_render_operator_panel(
                tenant,
                project,
                actor_user,
                process,
                max_download_bytes,
                stopped,
            ),
            CoordinatorRequest::SubmitPanelEvent {
                tenant,
                project,
                process,
                actor_user,
                widget_id,
                kind,
                max_events,
            } => self.handle_submit_panel_event(
                tenant, project, process, actor_user, widget_id, kind, max_events,
            ),
            CoordinatorRequest::CreateArtifactDownloadLink {
                tenant,
                project,
                actor_user,
                artifact,
                max_bytes,
                ttl_seconds,
            } => self.handle_create_artifact_download_link(
                tenant,
                project,
                actor_user,
                artifact,
                max_bytes,
                ttl_seconds,
            ),
            CoordinatorRequest::ListArtifacts {
                tenant,
                project,
                actor_user,
                process,
                cursor,
                limit,
            } => self.handle_list_artifacts(tenant, project, actor_user, process, cursor, limit),
            CoordinatorRequest::GetArtifact {
                tenant,
                project,
                actor_user,
                artifact,
            } => self.handle_get_artifact(tenant, project, actor_user, artifact),
            CoordinatorRequest::RevokeArtifactDownloadLink {
                tenant,
                project,
                actor_user,
                artifact,
                token_digest,
            } => self.handle_revoke_artifact_download_link(
                tenant,
                project,
                actor_user,
                artifact,
                token_digest,
            ),
            CoordinatorRequest::ExportArtifactToNode {
                tenant,
                project,
                actor_user,
                artifact,
                receiver_node,
            } => self.handle_export_artifact_to_node(
                tenant,
                project,
                actor_user,
                artifact,
                receiver_node,
            ),
        }
    }

    fn handle_authenticated_request(
        &mut self,
        session_secret: String,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let context = if matches!(&request, AuthenticatedCoordinatorRequest::AuthStatus) {
            self.coordinator
                .authenticate_cli_session_for_status(&session_secret)?
        } else {
            self.coordinator.authenticate_cli_session(&session_secret)?
        };
        let authorized = authorize_authenticated_user_operation(&context, &request)?;
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.quota
            .charge_api_call(&context.tenant, &context.project, now_epoch_seconds)?;
        let _authorized_operation = authorized.operation;
        let actor = authorized.actor;
        match request {
            AuthenticatedCoordinatorRequest::AuthStatus => {
                let account_state = self.coordinator.account_policy_state(&context.tenant);
                Ok(CoordinatorResponse::AuthStatus {
                    tenant: context.tenant,
                    project: context.project,
                    actor,
                    authenticated: true,
                    coordinator_version: env!("CARGO_PKG_VERSION").to_owned(),
                    workflow_sdk_version: clusterflux_core::SUPPORTED_WORKFLOW_SDK_VERSION
                        .to_owned(),
                    account_status: account_state.account_status,
                    suspended: account_state.suspended,
                    disabled: account_state.disabled,
                    deleted: account_state.deleted,
                    manual_review: account_state.manual_review,
                    sanitized_reason: account_state.sanitized_reason,
                    next_actions: account_state.next_actions,
                    sensitive_moderation_details_exposed: false,
                    signup_failure_details_exposed: false,
                })
            }
            AuthenticatedCoordinatorRequest::RevokeCliSession => {
                self.coordinator.revoke_cli_session(&session_secret)?;
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::CliSessionRevoked {
                    tenant: context.tenant,
                    project: context.project,
                    actor,
                })
            }
            AuthenticatedCoordinatorRequest::CreateProject { project, name } => {
                let project = ProjectId::new(project);
                self.coordinator.ensure_tenant_active(&context.tenant)?;
                if let Some(existing) = self.coordinator.project(&project) {
                    if existing.tenant != context.tenant {
                        return Err(CoordinatorError::Unauthorized(
                            "project id is outside the authenticated tenant scope".to_owned(),
                        )
                        .into());
                    }
                }
                if self.coordinator.project(&project).is_none() {
                    self.quota.ensure_project_admission(
                        &context.tenant,
                        self.coordinator.project_count_for_tenant(&context.tenant),
                        self.coordinator
                            .tenant_quota_override(&context.tenant)
                            .map(|record| &record.values),
                    )?;
                }
                self.coordinator
                    .upsert_project(context.tenant.clone(), project.clone(), name);
                self.coordinator.grant_project_debug(
                    context.tenant.clone(),
                    project.clone(),
                    actor.clone(),
                );
                self.persist_durable_state()?;
                let project = self
                    .coordinator
                    .project(&project)
                    .expect("project was just created")
                    .clone();
                Ok(CoordinatorResponse::ProjectCreated { project, actor })
            }
            AuthenticatedCoordinatorRequest::SelectProject { project } => {
                let project_id = ProjectId::new(project);
                let project = self
                    .coordinator
                    .project(&project_id)
                    .ok_or_else(|| {
                        CoordinatorError::Unauthorized(
                            "project is not visible to the authenticated user".to_owned(),
                        )
                    })?
                    .clone();
                if project.tenant != context.tenant {
                    return Err(CoordinatorError::Unauthorized(
                        "project is outside the authenticated tenant scope".to_owned(),
                    )
                    .into());
                }
                self.coordinator
                    .select_cli_session_project(&session_secret, project_id)?;
                self.coordinator.grant_project_debug(
                    context.tenant,
                    project.id.clone(),
                    actor.clone(),
                );
                self.persist_durable_state()?;
                Ok(CoordinatorResponse::ProjectSelected { project, actor })
            }
            AuthenticatedCoordinatorRequest::ListProjects => Ok(CoordinatorResponse::Projects {
                projects: self.coordinator.list_projects(&context),
                actor,
            }),
            AuthenticatedCoordinatorRequest::ListAutomatedRuns { cursor, limit } => {
                let (runs, next_cursor) = self.automated_runs_page(
                    &context.tenant,
                    &context.project,
                    cursor.as_deref(),
                    limit as usize,
                )?;
                Ok(CoordinatorResponse::AutomatedRuns {
                    runs,
                    next_cursor,
                    actor,
                })
            }
            AuthenticatedCoordinatorRequest::GetAutomatedRun { run } => {
                let run = clusterflux_core::RunId::new(run);
                let record = self.automated_run(&run).ok_or_else(|| {
                    CoordinatorServiceError::Protocol("unknown automated run".to_owned())
                })?;
                if record.run.tenant != context.tenant || record.run.project != context.project {
                    return Err(CoordinatorError::Unauthorized(
                        "automated run is outside the authenticated project".to_owned(),
                    )
                    .into());
                }
                Ok(CoordinatorResponse::AutomatedRun {
                    run: record.run.clone(),
                    actor,
                })
            }
            AuthenticatedCoordinatorRequest::CancelAutomatedRun { run } => {
                let run = clusterflux_core::RunId::new(run);
                let existing = self.automated_run(&run).ok_or_else(|| {
                    CoordinatorServiceError::Protocol("unknown automated run".to_owned())
                })?;
                if existing.run.tenant != context.tenant || existing.run.project != context.project
                {
                    return Err(CoordinatorError::Unauthorized(
                        "automated run is outside the authenticated project".to_owned(),
                    )
                    .into());
                }
                let record = self.cancel_automated_run(&run)?;
                Ok(CoordinatorResponse::AutomatedRun {
                    run: record.run,
                    actor,
                })
            }
            AuthenticatedCoordinatorRequest::RetryAutomatedRun { run } => {
                let run = clusterflux_core::RunId::new(run);
                let existing = self.automated_run(&run).ok_or_else(|| {
                    CoordinatorServiceError::Protocol("unknown automated run".to_owned())
                })?;
                if existing.run.tenant != context.tenant || existing.run.project != context.project
                {
                    return Err(CoordinatorError::Unauthorized(
                        "automated run is outside the authenticated project".to_owned(),
                    )
                    .into());
                }
                let record = self.retry_automated_run(&run)?;
                Ok(CoordinatorResponse::AutomatedRun {
                    run: record.run,
                    actor,
                })
            }
            AuthenticatedCoordinatorRequest::TriggerAutomatedRun { .. }
            | AuthenticatedCoordinatorRequest::ListWebhookDeliveries { .. } => {
                Err(CoordinatorServiceError::Protocol(
                    "hosted repository automation is unavailable on this coordinator".to_owned(),
                ))
            }
            request @ (AuthenticatedCoordinatorRequest::SetProjectSecret { .. }
            | AuthenticatedCoordinatorRequest::ListProjectSecrets
            | AuthenticatedCoordinatorRequest::RevokeProjectSecret { .. }) => {
                self.handle_authenticated_project_secret(&context, actor, request)
            }
            request @ (AuthenticatedCoordinatorRequest::RegisterAgentPublicKey { .. }
            | AuthenticatedCoordinatorRequest::ListAgentPublicKeys
            | AuthenticatedCoordinatorRequest::RotateAgentPublicKey { .. }
            | AuthenticatedCoordinatorRequest::RevokeAgentPublicKey { .. }) => {
                self.handle_authenticated_agent_key_request(&context, &actor, request)
            }
            AuthenticatedCoordinatorRequest::CreateNodeEnrollmentGrant { ttl_seconds } => self
                .handle_create_node_enrollment_grant(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    ttl_seconds,
                ),
            AuthenticatedCoordinatorRequest::ListNodeDescriptors => self
                .handle_list_node_descriptors(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                ),
            AuthenticatedCoordinatorRequest::ListNodeSummaries { cursor, limit } => self
                .handle_list_node_summaries(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    cursor,
                    limit,
                ),
            AuthenticatedCoordinatorRequest::RevokeNodeCredential { node } => self
                .handle_revoke_node_credential(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    node,
                ),
            AuthenticatedCoordinatorRequest::StartProcess {
                process,
                launch_attempt,
                restart,
            } => self.handle_start_process(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                Some(actor.as_str().to_owned()),
                None,
                None,
                None,
                None,
                process,
                launch_attempt,
                restart,
            ),
            request @ AuthenticatedCoordinatorRequest::ScheduleTask { .. } => {
                self.handle_authenticated_schedule_task(&context, request)
            }
            request @ AuthenticatedCoordinatorRequest::LaunchTask { .. } => {
                self.handle_authenticated_launch_task(&context, &actor, request)
            }
            AuthenticatedCoordinatorRequest::CancelProcess { process } => self
                .handle_cancel_process(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    process,
                ),
            AuthenticatedCoordinatorRequest::AbortProcess {
                process,
                launch_attempt,
            } => self.handle_abort_process(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                launch_attempt,
            ),
            AuthenticatedCoordinatorRequest::ListProcesses => self.handle_list_processes(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
            ),
            AuthenticatedCoordinatorRequest::ListProcessSummaries { cursor, limit } => self
                .handle_list_process_summaries(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    cursor,
                    limit,
                ),
            AuthenticatedCoordinatorRequest::QuotaStatus => self.handle_quota_status(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
            ),
            AuthenticatedCoordinatorRequest::RestartTask {
                process,
                task,
                replacement_bundle,
            } => self.handle_restart_task(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                task,
                replacement_bundle,
            ),
            AuthenticatedCoordinatorRequest::ResolveTaskFailure {
                process,
                task,
                resolution,
            } => self.handle_resolve_task_failure(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                task,
                resolution,
            ),
            request @ (AuthenticatedCoordinatorRequest::DebugAttach { .. }
            | AuthenticatedCoordinatorRequest::SetDebugBreakpoints { .. }
            | AuthenticatedCoordinatorRequest::InspectDebugBreakpoints { .. }
            | AuthenticatedCoordinatorRequest::CreateDebugEpoch { .. }
            | AuthenticatedCoordinatorRequest::ResumeDebugEpoch { .. }
            | AuthenticatedCoordinatorRequest::InspectDebugEpoch { .. }) => self
                .handle_authenticated_debug_request(
                    &context.tenant,
                    &context.project,
                    &actor,
                    request,
                ),
            AuthenticatedCoordinatorRequest::ListTaskEvents { process } => self
                .handle_list_task_events(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    process,
                ),
            AuthenticatedCoordinatorRequest::ListTaskSnapshots { process } => self
                .handle_list_task_snapshots(
                    context.tenant.as_str().to_owned(),
                    context.project.as_str().to_owned(),
                    actor.as_str().to_owned(),
                    process,
                ),
            AuthenticatedCoordinatorRequest::ListRecentLogs {
                process,
                task,
                after_sequence,
                limit,
            } => self.handle_list_recent_logs(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                task,
                after_sequence,
                limit,
            ),
            AuthenticatedCoordinatorRequest::JoinTask { process, task } => self.handle_join_task(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                task,
            ),
            AuthenticatedCoordinatorRequest::CreateArtifactDownloadLink {
                artifact,
                max_bytes,
                ttl_seconds,
            } => self.handle_create_artifact_download_link(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                artifact,
                max_bytes,
                ttl_seconds,
            ),
            AuthenticatedCoordinatorRequest::ListArtifacts {
                process,
                cursor,
                limit,
            } => self.handle_list_artifacts(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                process,
                cursor,
                limit,
            ),
            AuthenticatedCoordinatorRequest::GetArtifact { artifact } => self.handle_get_artifact(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                artifact,
            ),
            AuthenticatedCoordinatorRequest::RevokeArtifactDownloadLink {
                artifact,
                token_digest,
            } => self.handle_revoke_artifact_download_link(
                context.tenant.as_str().to_owned(),
                context.project.as_str().to_owned(),
                actor.as_str().to_owned(),
                artifact,
                token_digest,
            ),
            request @ AuthenticatedCoordinatorRequest::ExportArtifactToNode { .. } => {
                self.handle_authenticated_artifact_export(&context, &actor, request)
            }
        }
    }
}
