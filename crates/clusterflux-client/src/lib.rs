mod session;
mod transport;
mod types;

use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};

use clusterflux_core::ApiError;
use clusterflux_protocol::{
    coordinator_wire_request, login_wire_request, AuthenticatedCoordinatorRequest,
    CoordinatorRequest, CoordinatorResponse, LoginRequest, LoginResponse,
    COORDINATOR_PROTOCOL_VERSION,
};
use thiserror::Error;
use transport::{ClientTransport, TransportRequest};

pub use clusterflux_core::{
    AgentId, ApiErrorCategory, ApiErrorCode, ArtifactId, Authorization, AutomatedRunRecord,
    AutomatedRunState, Capability, CredentialKind, Digest, DownloadLink, EnvironmentBackend,
    LimitKind, NodeCapabilities, NodeDrainBlocker, NodeDrainBlockerKind, NodeDrainStatus, NodeId,
    NodeLifecycleState, Os, ProcessId, ProjectId, RepositoryId, ResourceLimits, RunId,
    TaskDefinitionId, TaskFailurePolicy, TaskInstanceId, TenantId, UserId, VfsPath,
    WebhookDeliveryOutcome, WebhookDeliveryRecord,
};
pub use clusterflux_protocol::{CONTROL_API_PATH, LOGIN_API_PATH};
pub use session::{
    control_api_url, endpoint_api_url, endpoint_identity, endpoint_is_loopback, ControlSession,
    ControlTransportError, LoginSession, ProtocolSession, MAX_CONTROL_FRAME_BYTES,
};
pub use transport::{
    ClientTransportError, ControlTransport, MockTransport, TransportFuture, TransportResponse,
};
pub use types::*;

pub const CLIENT_API_VERSION: u64 = COORDINATOR_PROTOCOL_VERSION;

#[derive(Debug, Error)]
pub enum ClientError {
    #[error("Clusterflux API error: {0}")]
    Api(Box<ApiError>),
    #[error(transparent)]
    Transport(#[from] ClientTransportError),
    #[error("Clusterflux client protocol error: {0}")]
    Protocol(String),
    #[error(
        "Clusterflux client protocol error for request {request_id}: expected typed response {expected}, received {received}"
    )]
    UnexpectedResponse {
        request_id: String,
        expected: &'static str,
        received: &'static str,
    },
}

#[derive(Clone)]
pub struct ClusterfluxClient {
    transport: Arc<dyn ClientTransport>,
    session_secret: Arc<Mutex<Option<String>>>,
    next_request: Arc<AtomicU64>,
}

impl ClusterfluxClient {
    pub fn connect(endpoint: impl Into<String>) -> Result<Self, ClientError> {
        Ok(Self::with_transport(ControlTransport::new(endpoint)?))
    }

    pub fn with_transport(transport: impl ClientTransport) -> Self {
        Self {
            transport: Arc::new(transport),
            session_secret: Arc::new(Mutex::new(None)),
            next_request: Arc::new(AtomicU64::new(1)),
        }
    }

    pub fn with_session_credential(mut self, credential: &SessionCredential) -> Self {
        self.session_secret = Arc::new(Mutex::new(Some(credential.0.clone())));
        self
    }

    pub fn is_session_configured(&self) -> bool {
        self.session_secret
            .lock()
            .map(|secret| secret.is_some())
            .unwrap_or(false)
    }

    /// Sends a fully typed control-plane request without adding user-session
    /// authentication. Node and service clients use this for signed requests.
    pub async fn send_coordinator_request(
        &self,
        request: CoordinatorRequest,
    ) -> Result<CoordinatorResponse, ClientError> {
        self.send_control(request, None).await
    }

    pub async fn begin_browser_login(&self) -> Result<BrowserLoginStart, ClientError> {
        match self
            .send_login(
                LoginRequest::BeginWebBrowserLogin {},
                "web_browser_login_started",
            )
            .await?
        {
            LoginResponse::WebBrowserLoginStarted {
                transaction_id,
                authorization_url,
                expires_at_epoch_seconds,
            } => Ok(BrowserLoginStart {
                transaction_id,
                authorization_url,
                expires_at_epoch_seconds,
            }),
            _ => Err(unexpected_response("web_browser_login_started")),
        }
    }

    pub async fn exchange_browser_login_handoff(
        &self,
        transaction_id: impl Into<String>,
        handoff_code: impl Into<String>,
    ) -> Result<BrowserSession, ClientError> {
        match self
            .send_login(
                LoginRequest::ExchangeWebLoginHandoff {
                    transaction_id: transaction_id.into(),
                    handoff_code: handoff_code.into(),
                },
                "web_browser_session",
            )
            .await?
        {
            LoginResponse::WebBrowserSession { session } => Ok(BrowserSession {
                tenant: session.tenant,
                project: session.project,
                user: session.user,
                credential: SessionCredential(session.session_secret),
                expires_at_epoch_seconds: session.expires_at_epoch_seconds,
            }),
            _ => Err(unexpected_response("web_browser_session")),
        }
    }

    pub async fn cancel_browser_login(
        &self,
        transaction_id: impl Into<String>,
    ) -> Result<(), ClientError> {
        match self
            .send_login(
                LoginRequest::CancelWebBrowserLogin {
                    transaction_id: transaction_id.into(),
                },
                "web_browser_login_cancelled",
            )
            .await?
        {
            LoginResponse::WebBrowserLoginCancelled {} => Ok(()),
            _ => Err(unexpected_response("web_browser_login_cancelled")),
        }
    }

    pub async fn account_status(&self) -> Result<AccountStatus, ClientError> {
        match self
            .send_authenticated(AuthenticatedCoordinatorRequest::AuthStatus, "auth_status")
            .await?
        {
            CoordinatorResponse::AuthStatus {
                tenant,
                project,
                actor,
                authenticated,
                account_status,
                suspended,
                disabled,
                deleted,
                manual_review,
                sanitized_reason,
                next_actions,
                ..
            } => Ok(AccountStatus {
                tenant,
                project,
                actor,
                authenticated,
                account_status,
                suspended,
                disabled,
                deleted,
                manual_review,
                sanitized_reason,
                next_actions,
            }),
            _ => Err(unexpected_response("auth_status")),
        }
    }

    pub async fn logout(&self) -> Result<(), ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::RevokeCliSession,
                "cli_session_revoked",
            )
            .await?
        {
            CoordinatorResponse::CliSessionRevoked { .. } => {
                *self.session_secret.lock().map_err(|_| {
                    ClientError::Protocol("session credential lock was poisoned".to_owned())
                })? = None;
                Ok(())
            }
            _ => Err(unexpected_response("cli_session_revoked")),
        }
    }

    pub async fn list_projects(&self) -> Result<Vec<Project>, ClientError> {
        match self
            .send_authenticated(AuthenticatedCoordinatorRequest::ListProjects, "projects")
            .await?
        {
            CoordinatorResponse::Projects { projects, .. } => Ok(projects),
            _ => Err(unexpected_response("projects")),
        }
    }

    pub async fn create_project(
        &self,
        project: ProjectId,
        name: impl Into<String>,
    ) -> Result<Project, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::CreateProject {
                    project: project.to_string(),
                    name: name.into(),
                },
                "project_created",
            )
            .await?
        {
            CoordinatorResponse::ProjectCreated { project, .. } => Ok(project),
            _ => Err(unexpected_response("project_created")),
        }
    }

    pub async fn select_project(&self, project: ProjectId) -> Result<Project, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::SelectProject {
                    project: project.to_string(),
                },
                "project_selected",
            )
            .await?
        {
            CoordinatorResponse::ProjectSelected { project, .. } => Ok(project),
            _ => Err(unexpected_response("project_selected")),
        }
    }

    pub async fn register_agent_public_key(
        &self,
        agent: AgentId,
        public_key: impl Into<String>,
    ) -> Result<AgentPublicKey, ClientError> {
        self.agent_key_mutation(AuthenticatedCoordinatorRequest::RegisterAgentPublicKey {
            agent: agent.to_string(),
            public_key: public_key.into(),
        })
        .await
    }

    pub async fn list_agent_public_keys(&self) -> Result<Vec<AgentPublicKey>, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListAgentPublicKeys,
                "agent_public_keys",
            )
            .await?
        {
            CoordinatorResponse::AgentPublicKeys { records, .. } => Ok(records),
            _ => Err(unexpected_response("agent_public_keys")),
        }
    }

    pub async fn rotate_agent_public_key(
        &self,
        agent: AgentId,
        public_key: impl Into<String>,
    ) -> Result<AgentPublicKey, ClientError> {
        self.agent_key_mutation(AuthenticatedCoordinatorRequest::RotateAgentPublicKey {
            agent: agent.to_string(),
            public_key: public_key.into(),
        })
        .await
    }

    pub async fn revoke_agent_public_key(
        &self,
        agent: AgentId,
    ) -> Result<AgentPublicKey, ClientError> {
        self.agent_key_mutation(AuthenticatedCoordinatorRequest::RevokeAgentPublicKey {
            agent: agent.to_string(),
        })
        .await
    }

    async fn agent_key_mutation(
        &self,
        request: AuthenticatedCoordinatorRequest,
    ) -> Result<AgentPublicKey, ClientError> {
        match self.send_authenticated(request, "agent_public_key").await? {
            CoordinatorResponse::AgentPublicKey { record, .. } => Ok(record),
            _ => Err(unexpected_response("agent_public_key")),
        }
    }

    pub async fn create_node_enrollment_grant(
        &self,
        ttl_seconds: u64,
    ) -> Result<NodeEnrollmentGrant, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::CreateNodeEnrollmentGrant { ttl_seconds },
                "node_enrollment_grant_created",
            )
            .await?
        {
            CoordinatorResponse::NodeEnrollmentGrantCreated {
                tenant,
                project,
                grant,
                scope,
                expires_at_epoch_seconds,
            } => Ok(NodeEnrollmentGrant {
                tenant,
                project,
                grant,
                scope,
                expires_at_epoch_seconds,
            }),
            _ => Err(unexpected_response("node_enrollment_grant_created")),
        }
    }

    pub async fn list_nodes(&self) -> Result<Vec<NodeSummary>, ClientError> {
        Ok(self.list_nodes_page(None, 200).await?.nodes)
    }

    pub async fn list_nodes_page(
        &self,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<NodePage, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListNodeSummaries { cursor, limit },
                "node_summaries",
            )
            .await?
        {
            CoordinatorResponse::NodeSummaries {
                nodes, next_cursor, ..
            } => Ok(NodePage { nodes, next_cursor }),
            _ => Err(unexpected_response("node_summaries")),
        }
    }

    pub async fn revoke_node(&self, node: NodeId) -> Result<NodeRevocation, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::RevokeNodeCredential {
                    node: node.to_string(),
                },
                "node_credential_revoked",
            )
            .await?
        {
            CoordinatorResponse::NodeCredentialRevoked {
                node,
                tenant,
                project,
                actor,
                descriptor_removed,
                queued_assignments_removed,
            } => Ok(NodeRevocation {
                node,
                tenant,
                project,
                actor,
                descriptor_removed,
                queued_assignments_removed,
            }),
            _ => Err(unexpected_response("node_credential_revoked")),
        }
    }

    pub async fn list_processes(
        &self,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<ProcessPage, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListProcessSummaries { cursor, limit },
                "process_summaries",
            )
            .await?
        {
            CoordinatorResponse::ProcessSummaries {
                processes,
                next_cursor,
                ..
            } => Ok(ProcessPage {
                processes,
                next_cursor,
            }),
            _ => Err(unexpected_response("process_summaries")),
        }
    }

    pub async fn list_automated_runs(&self) -> Result<Vec<AutomatedRunRecord>, ClientError> {
        Ok(self.list_automated_runs_page(None, 64).await?.runs)
    }

    pub async fn list_automated_runs_page(
        &self,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<AutomatedRunPage, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListAutomatedRuns { cursor, limit },
                "automated_runs",
            )
            .await?
        {
            CoordinatorResponse::AutomatedRuns {
                runs, next_cursor, ..
            } => Ok(AutomatedRunPage { runs, next_cursor }),
            _ => Err(unexpected_response("automated_runs")),
        }
    }

    pub async fn retry_automated_run(&self, run: RunId) -> Result<AutomatedRunRecord, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::RetryAutomatedRun {
                    run: run.to_string(),
                },
                "automated_run",
            )
            .await?
        {
            CoordinatorResponse::AutomatedRun { run, .. } => Ok(run),
            _ => Err(unexpected_response("automated_run")),
        }
    }

    pub async fn get_automated_run(&self, run: RunId) -> Result<AutomatedRunRecord, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::GetAutomatedRun {
                    run: run.to_string(),
                },
                "automated_run",
            )
            .await?
        {
            CoordinatorResponse::AutomatedRun { run, .. } => Ok(run),
            _ => Err(unexpected_response("automated_run")),
        }
    }

    pub async fn trigger_automated_run(
        &self,
        repository: RepositoryId,
        git_ref: String,
        commit: Option<String>,
    ) -> Result<AutomatedRunRecord, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::TriggerAutomatedRun {
                    repository: repository.to_string(),
                    git_ref,
                    commit,
                },
                "automated_run",
            )
            .await?
        {
            CoordinatorResponse::AutomatedRun { run, .. } => Ok(run),
            _ => Err(unexpected_response("automated_run")),
        }
    }

    pub async fn list_webhook_deliveries_page(
        &self,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<WebhookDeliveryPage, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListWebhookDeliveries { cursor, limit },
                "webhook_deliveries",
            )
            .await?
        {
            CoordinatorResponse::WebhookDeliveries {
                deliveries,
                next_cursor,
                ..
            } => Ok(WebhookDeliveryPage {
                deliveries,
                next_cursor,
            }),
            _ => Err(unexpected_response("webhook_deliveries")),
        }
    }

    pub async fn cancel_process(
        &self,
        process: ProcessId,
    ) -> Result<ProcessCancellation, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::CancelProcess {
                    process: process.to_string(),
                },
                "process_cancellation_requested",
            )
            .await?
        {
            CoordinatorResponse::ProcessCancellationRequested {
                process,
                cancelled_tasks,
                affected_nodes,
            } => Ok(ProcessCancellation {
                process,
                affected_tasks: cancelled_tasks,
                affected_nodes,
                aborted: false,
            }),
            _ => Err(unexpected_response("process_cancellation_requested")),
        }
    }

    pub async fn abort_process(
        &self,
        process: ProcessId,
    ) -> Result<ProcessCancellation, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::AbortProcess {
                    process: process.to_string(),
                    launch_attempt: None,
                },
                "process_aborted",
            )
            .await?
        {
            CoordinatorResponse::ProcessAborted {
                process,
                aborted_tasks,
                affected_nodes,
            } => Ok(ProcessCancellation {
                process,
                affected_tasks: aborted_tasks,
                affected_nodes,
                aborted: true,
            }),
            _ => Err(unexpected_response("process_aborted")),
        }
    }

    pub async fn quota_status(&self) -> Result<QuotaStatus, ClientError> {
        match self
            .send_authenticated(AuthenticatedCoordinatorRequest::QuotaStatus, "quota_status")
            .await?
        {
            CoordinatorResponse::QuotaStatus {
                tenant,
                project,
                actor,
                policy_label,
                limits,
                window_seconds,
                usage,
                window_started_epoch_seconds,
                projects_current,
                projects_maximum,
                node_identities_current,
                node_identities_maximum,
                active_processes_current,
                active_processes_maximum,
            } => Ok(QuotaStatus {
                tenant,
                project,
                actor,
                policy_label,
                limits,
                window_seconds,
                usage,
                window_started_epoch_seconds,
                projects_current,
                projects_maximum,
                node_identities_current,
                node_identities_maximum,
                active_processes_current,
                active_processes_maximum,
            }),
            _ => Err(unexpected_response("quota_status")),
        }
    }

    pub async fn list_task_events(
        &self,
        process: Option<ProcessId>,
    ) -> Result<Vec<TaskCompletionEvent>, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListTaskEvents {
                    process: process.map(|process| process.to_string()),
                },
                "task_events",
            )
            .await?
        {
            CoordinatorResponse::TaskEvents { events } => Ok(events),
            _ => Err(unexpected_response("task_events")),
        }
    }

    pub async fn list_task_snapshots(
        &self,
        process: ProcessId,
    ) -> Result<Vec<TaskAttemptSnapshot>, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListTaskSnapshots {
                    process: process.to_string(),
                },
                "task_snapshots",
            )
            .await?
        {
            CoordinatorResponse::TaskSnapshots { snapshots } => Ok(snapshots),
            _ => Err(unexpected_response("task_snapshots")),
        }
    }

    pub async fn list_recent_logs(
        &self,
        process: ProcessId,
        task: Option<TaskInstanceId>,
        after_sequence: Option<u64>,
        limit: u32,
    ) -> Result<RecentLogPage, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListRecentLogs {
                    process: process.to_string(),
                    task: task.map(|task| task.to_string()),
                    after_sequence,
                    limit,
                },
                "recent_logs",
            )
            .await?
        {
            CoordinatorResponse::RecentLogs {
                entries,
                next_sequence,
                history_truncated,
            } => Ok(RecentLogPage {
                entries,
                next_sequence,
                history_truncated,
            }),
            _ => Err(unexpected_response("recent_logs")),
        }
    }

    pub async fn restart_task(
        &self,
        process: ProcessId,
        task: TaskInstanceId,
        replacement_bundle: Option<TaskReplacementBundle>,
    ) -> Result<TaskRestart, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::RestartTask {
                    process: process.to_string(),
                    task: task.to_string(),
                    replacement_bundle,
                },
                "task_restart",
            )
            .await?
        {
            CoordinatorResponse::TaskRestart {
                process,
                task,
                restarted_task_instance,
                restarted_attempt_id,
                actor,
                accepted,
                clean_boundary_available,
                active_task,
                completed_event_observed,
                requires_whole_process_restart,
                message,
                audit_event,
                ..
            } => Ok(TaskRestart {
                process,
                task,
                restarted_task_instance,
                restarted_attempt_id,
                actor,
                accepted,
                clean_boundary_available,
                active_task,
                completed_event_observed,
                requires_whole_process_restart,
                message,
                audit_event,
            }),
            _ => Err(unexpected_response("task_restart")),
        }
    }

    pub async fn resolve_task_failure(
        &self,
        process: ProcessId,
        task: TaskInstanceId,
        resolution: TaskFailureResolution,
    ) -> Result<TaskFailureResolutionResult, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ResolveTaskFailure {
                    process: process.to_string(),
                    task: task.to_string(),
                    resolution,
                },
                "task_failure_resolved",
            )
            .await?
        {
            CoordinatorResponse::TaskFailureResolved {
                process,
                task,
                attempt_id,
                resolution,
            } => Ok(TaskFailureResolutionResult {
                process,
                task,
                attempt_id,
                resolution,
            }),
            _ => Err(unexpected_response("task_failure_resolved")),
        }
    }

    pub async fn debug_attach(&self, process: ProcessId) -> Result<DebugAttach, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::DebugAttach {
                    process: process.to_string(),
                },
                "debug_attach",
            )
            .await?
        {
            CoordinatorResponse::DebugAttach {
                process,
                actor,
                authorization,
                audit_event,
                ..
            } => Ok(DebugAttach {
                process,
                actor,
                authorization,
                audit_event,
            }),
            _ => Err(unexpected_response("debug_attach")),
        }
    }

    pub async fn create_debug_epoch(
        &self,
        process: ProcessId,
        stopped_task: TaskInstanceId,
        reason: impl Into<String>,
    ) -> Result<DebugEpochControl, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::CreateDebugEpoch {
                    process: process.to_string(),
                    stopped_task: stopped_task.to_string(),
                    reason: reason.into(),
                },
                "debug_epoch",
            )
            .await?
        {
            CoordinatorResponse::DebugEpoch {
                process,
                actor,
                epoch,
                command,
                affected_tasks,
                all_stop_requested,
                audit_event,
                ..
            } => Ok(DebugEpochControl {
                process,
                actor,
                epoch,
                command,
                affected_tasks,
                all_stop_requested,
                audit_event,
            }),
            _ => Err(unexpected_response("debug_epoch")),
        }
    }

    pub async fn resume_debug_epoch(
        &self,
        process: ProcessId,
        epoch: u64,
    ) -> Result<DebugEpochControl, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ResumeDebugEpoch {
                    process: process.to_string(),
                    epoch,
                },
                "debug_epoch",
            )
            .await?
        {
            CoordinatorResponse::DebugEpoch {
                process,
                actor,
                epoch,
                command,
                affected_tasks,
                all_stop_requested,
                audit_event,
                ..
            } => Ok(DebugEpochControl {
                process,
                actor,
                epoch,
                command,
                affected_tasks,
                all_stop_requested,
                audit_event,
            }),
            _ => Err(unexpected_response("debug_epoch")),
        }
    }

    pub async fn inspect_debug_epoch(
        &self,
        process: ProcessId,
        epoch: u64,
    ) -> Result<DebugEpochStatus, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::InspectDebugEpoch {
                    process: process.to_string(),
                    epoch,
                },
                "debug_epoch_status",
            )
            .await?
        {
            CoordinatorResponse::DebugEpochStatus {
                process,
                actor,
                epoch,
                command,
                expected_tasks,
                acknowledgements,
                fully_frozen,
                partially_frozen,
                fully_resumed,
                failed,
                failure_messages,
                audit_event,
                ..
            } => Ok(DebugEpochStatus {
                process,
                actor,
                epoch,
                command,
                expected_tasks,
                acknowledgements,
                fully_frozen,
                partially_frozen,
                fully_resumed,
                failed,
                failure_messages,
                audit_event,
            }),
            _ => Err(unexpected_response("debug_epoch_status")),
        }
    }

    pub async fn list_artifacts(
        &self,
        process: Option<ProcessId>,
        cursor: Option<String>,
        limit: u32,
    ) -> Result<ArtifactPage, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::ListArtifacts {
                    process: process.map(|process| process.to_string()),
                    cursor,
                    limit,
                },
                "artifacts",
            )
            .await?
        {
            CoordinatorResponse::Artifacts {
                artifacts,
                next_cursor,
            } => Ok(ArtifactPage {
                artifacts,
                next_cursor,
            }),
            _ => Err(unexpected_response("artifacts")),
        }
    }

    pub async fn get_artifact(&self, artifact: ArtifactId) -> Result<ArtifactSummary, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::GetArtifact {
                    artifact: artifact.to_string(),
                },
                "artifact",
            )
            .await?
        {
            CoordinatorResponse::Artifact { artifact } => Ok(artifact),
            _ => Err(unexpected_response("artifact")),
        }
    }

    pub async fn create_artifact_download_link(
        &self,
        artifact: ArtifactId,
        max_bytes: u64,
        ttl_seconds: u64,
    ) -> Result<DownloadLink, ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::CreateArtifactDownloadLink {
                    artifact: artifact.to_string(),
                    max_bytes,
                    ttl_seconds,
                },
                "artifact_download_link",
            )
            .await?
        {
            CoordinatorResponse::ArtifactDownloadLink { link } => Ok(link),
            _ => Err(unexpected_response("artifact_download_link")),
        }
    }

    pub async fn revoke_artifact_download_link(
        &self,
        artifact: ArtifactId,
        token_digest: Digest,
    ) -> Result<(), ClientError> {
        match self
            .send_authenticated(
                AuthenticatedCoordinatorRequest::RevokeArtifactDownloadLink {
                    artifact: artifact.to_string(),
                    token_digest,
                },
                "artifact_download_link_revoked",
            )
            .await?
        {
            CoordinatorResponse::ArtifactDownloadLinkRevoked { .. } => Ok(()),
            _ => Err(unexpected_response("artifact_download_link_revoked")),
        }
    }

    async fn send_authenticated(
        &self,
        request: AuthenticatedCoordinatorRequest,
        expected_response: &'static str,
    ) -> Result<CoordinatorResponse, ClientError> {
        let session_secret = self
            .session_secret
            .lock()
            .map_err(|_| ClientError::Protocol("session credential lock was poisoned".to_owned()))?
            .clone()
            .ok_or_else(|| {
                ClientError::Api(Box::new(ApiError::from_message(
                    "client",
                    "no authenticated Clusterflux session is configured",
                )))
            })?;
        self.send_control(
            CoordinatorRequest::Authenticated {
                session_secret,
                request,
            },
            Some(expected_response),
        )
        .await
    }

    async fn send_control(
        &self,
        request: CoordinatorRequest,
        expected_response: Option<&'static str>,
    ) -> Result<CoordinatorResponse, ClientError> {
        let request_number = self.next_request.fetch_add(1, Ordering::Relaxed);
        let request_id = format!("client-{request_number}");
        request
            .validate_external_identifiers()
            .map_err(ClientError::Protocol)?;
        let envelope = coordinator_wire_request(&request_id, request);
        let body = serde_json::to_vec(&envelope)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let response = self
            .transport
            .send(TransportRequest {
                api_path: CONTROL_API_PATH.to_owned(),
                body,
            })
            .await?;
        let response: CoordinatorResponse =
            serde_json::from_slice(&response.body).map_err(|error| {
                ClientError::Protocol(format!("decode typed API response: {error}"))
            })?;
        match response {
            CoordinatorResponse::Error { error } => {
                if error.request_id != request_id {
                    return Err(ClientError::Protocol(format!(
                        "error response request_id {} does not match {request_id}",
                        error.request_id
                    )));
                }
                Err(ClientError::Api(Box::new(error)))
            }
            response => {
                if let Some(expected) = expected_response {
                    let received = response.kind();
                    if received != expected {
                        return Err(ClientError::UnexpectedResponse {
                            request_id,
                            expected,
                            received,
                        });
                    }
                }
                Ok(response)
            }
        }
    }

    async fn send_login(
        &self,
        request: LoginRequest,
        expected_response: &'static str,
    ) -> Result<LoginResponse, ClientError> {
        let request_number = self.next_request.fetch_add(1, Ordering::Relaxed);
        let request_id = format!("client-{request_number}");
        request
            .validate_external_inputs()
            .map_err(ClientError::Protocol)?;
        let envelope = login_wire_request(&request_id, request);
        let body = serde_json::to_vec(&envelope)
            .map_err(|error| ClientError::Protocol(error.to_string()))?;
        let response = self
            .transport
            .send(TransportRequest {
                api_path: LOGIN_API_PATH.to_owned(),
                body,
            })
            .await?;
        let response: LoginResponse = serde_json::from_slice(&response.body).map_err(|error| {
            ClientError::Protocol(format!("decode typed login response: {error}"))
        })?;
        match response {
            LoginResponse::Error { error } => {
                if error.request_id != request_id {
                    return Err(ClientError::Protocol(format!(
                        "error response request_id {} does not match {request_id}",
                        error.request_id
                    )));
                }
                Err(ClientError::Api(Box::new(error)))
            }
            response => {
                let received = response.kind();
                if received != expected_response {
                    return Err(ClientError::UnexpectedResponse {
                        request_id,
                        expected: expected_response,
                        received,
                    });
                }
                Ok(response)
            }
        }
    }
}

fn unexpected_response(expected: &str) -> ClientError {
    ClientError::Protocol(format!(
        "expected typed response {expected}, received another response variant"
    ))
}
