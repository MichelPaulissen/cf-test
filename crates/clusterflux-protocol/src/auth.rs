use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AgentPublicKeyRecord {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub user: UserId,
    pub agent: AgentId,
    pub public_key: String,
    pub public_key_fingerprint: Digest,
    pub version: u64,
    pub revoked: bool,
    pub scopes: Vec<String>,
    pub human_account_creation_privilege: bool,
    pub browser_interaction_required_each_run: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WorkflowActor {
    pub kind: String,
    pub user: Option<UserId>,
    pub agent: Option<AgentId>,
    pub credential_kind: CredentialKind,
    pub public_key_fingerprint: Option<Digest>,
    pub authenticated_without_browser: bool,
    pub scopes: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum AuthenticatedCoordinatorRequest {
    AuthStatus,
    RevokeCliSession,
    CreateProject {
        project: String,
        name: String,
    },
    SelectProject {
        project: String,
    },
    ListProjects,
    ListAutomatedRuns {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    GetAutomatedRun {
        run: String,
    },
    CancelAutomatedRun {
        run: String,
    },
    RetryAutomatedRun {
        run: String,
    },
    TriggerAutomatedRun {
        repository: String,
        git_ref: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        commit: Option<String>,
    },
    ListWebhookDeliveries {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    SetProjectSecret {
        name: String,
        value_base64: String,
    },
    ListProjectSecrets,
    RevokeProjectSecret {
        name: String,
    },
    RegisterAgentPublicKey {
        agent: String,
        public_key: String,
    },
    ListAgentPublicKeys,
    RotateAgentPublicKey {
        agent: String,
        public_key: String,
    },
    RevokeAgentPublicKey {
        agent: String,
    },
    CreateNodeEnrollmentGrant {
        #[serde(default = "default_node_enrollment_ttl_seconds")]
        ttl_seconds: u64,
    },
    ListNodeDescriptors,
    ListNodeSummaries {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    RevokeNodeCredential {
        node: String,
    },
    StartProcess {
        process: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        launch_attempt: Option<String>,
        #[serde(default)]
        restart: bool,
    },
    ScheduleTask {
        environment: Option<EnvironmentRequirements>,
        environment_digest: Option<Digest>,
        required_capabilities: Vec<Capability>,
        #[serde(default)]
        dependency_cache: Option<Digest>,
        source_snapshot: Option<Digest>,
        required_artifacts: Vec<String>,
        prefer_node: Option<String>,
    },
    LaunchTask {
        task_spec: Box<TaskSpec>,
        #[serde(default)]
        wait_for_node: bool,
        artifact_path: String,
        wasm_module_base64: String,
    },
    CancelProcess {
        process: String,
    },
    AbortProcess {
        process: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        launch_attempt: Option<String>,
    },
    ListProcesses,
    ListProcessSummaries {
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    QuotaStatus,
    RestartTask {
        process: String,
        task: String,
        #[serde(default)]
        replacement_bundle: Option<TaskReplacementBundle>,
    },
    ResolveTaskFailure {
        process: String,
        task: String,
        resolution: TaskFailureResolution,
    },
    DebugAttach {
        process: String,
    },
    SetDebugBreakpoints {
        process: String,
        #[serde(default)]
        revision: u64,
        probe_symbols: Vec<String>,
        #[serde(default)]
        probe_locations: Vec<SourceLocation>,
    },
    InspectDebugBreakpoints {
        process: String,
    },
    CreateDebugEpoch {
        process: String,
        stopped_task: String,
        reason: String,
    },
    ResumeDebugEpoch {
        process: String,
        epoch: u64,
    },
    InspectDebugEpoch {
        process: String,
        epoch: u64,
    },
    ListTaskEvents {
        #[serde(default)]
        process: Option<String>,
    },
    ListTaskSnapshots {
        process: String,
    },
    ListRecentLogs {
        process: String,
        #[serde(default)]
        task: Option<String>,
        #[serde(default)]
        after_sequence: Option<u64>,
        #[serde(default = "default_log_page_limit")]
        limit: u32,
    },
    JoinTask {
        process: String,
        task: String,
    },
    CreateArtifactDownloadLink {
        artifact: String,
        max_bytes: u64,
        #[serde(default = "default_download_ttl_seconds")]
        ttl_seconds: u64,
    },
    ListArtifacts {
        #[serde(default)]
        process: Option<String>,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    GetArtifact {
        artifact: String,
    },
    RevokeArtifactDownloadLink {
        artifact: String,
        token_digest: Digest,
    },
    ExportArtifactToNode {
        artifact: String,
        receiver_node: String,
    },
}

impl AuthenticatedCoordinatorRequest {
    pub const fn operation(&self) -> &'static str {
        match self {
            Self::AuthStatus => "auth_status",
            Self::RevokeCliSession => "revoke_cli_session",
            Self::CreateProject { .. } => "create_project",
            Self::SelectProject { .. } => "select_project",
            Self::ListProjects => "list_projects",
            Self::ListAutomatedRuns { .. } => "list_automated_runs",
            Self::GetAutomatedRun { .. } => "get_automated_run",
            Self::CancelAutomatedRun { .. } => "cancel_automated_run",
            Self::RetryAutomatedRun { .. } => "retry_automated_run",
            Self::TriggerAutomatedRun { .. } => "trigger_automated_run",
            Self::ListWebhookDeliveries { .. } => "list_webhook_deliveries",
            Self::SetProjectSecret { .. } => "set_project_secret",
            Self::ListProjectSecrets => "list_project_secrets",
            Self::RevokeProjectSecret { .. } => "revoke_project_secret",
            Self::RegisterAgentPublicKey { .. } => "register_agent_public_key",
            Self::ListAgentPublicKeys => "list_agent_public_keys",
            Self::RotateAgentPublicKey { .. } => "rotate_agent_public_key",
            Self::RevokeAgentPublicKey { .. } => "revoke_agent_public_key",
            Self::CreateNodeEnrollmentGrant { .. } => "create_node_enrollment_grant",
            Self::ListNodeDescriptors => "list_node_descriptors",
            Self::ListNodeSummaries { .. } => "list_node_summaries",
            Self::RevokeNodeCredential { .. } => "revoke_node_credential",
            Self::StartProcess { .. } => "start_process",
            Self::ScheduleTask { .. } => "schedule_task",
            Self::LaunchTask { .. } => "launch_task",
            Self::CancelProcess { .. } => "cancel_process",
            Self::AbortProcess { .. } => "abort_process",
            Self::ListProcesses => "list_processes",
            Self::ListProcessSummaries { .. } => "list_process_summaries",
            Self::QuotaStatus => "quota_status",
            Self::RestartTask { .. } => "restart_task",
            Self::ResolveTaskFailure { .. } => "resolve_task_failure",
            Self::DebugAttach { .. } => "debug_attach",
            Self::SetDebugBreakpoints { .. } => "set_debug_breakpoints",
            Self::InspectDebugBreakpoints { .. } => "inspect_debug_breakpoints",
            Self::CreateDebugEpoch { .. } => "create_debug_epoch",
            Self::ResumeDebugEpoch { .. } => "resume_debug_epoch",
            Self::InspectDebugEpoch { .. } => "inspect_debug_epoch",
            Self::ListTaskEvents { .. } => "list_task_events",
            Self::ListTaskSnapshots { .. } => "list_task_snapshots",
            Self::ListRecentLogs { .. } => "list_recent_logs",
            Self::JoinTask { .. } => "join_task",
            Self::CreateArtifactDownloadLink { .. } => "create_artifact_download_link",
            Self::ListArtifacts { .. } => "list_artifacts",
            Self::GetArtifact { .. } => "get_artifact",
            Self::RevokeArtifactDownloadLink { .. } => "revoke_artifact_download_link",
            Self::ExportArtifactToNode { .. } => "export_artifact_to_node",
        }
    }
}

impl TryFrom<CoordinatorRequest> for AuthenticatedCoordinatorRequest {
    type Error = String;

    fn try_from(request: CoordinatorRequest) -> Result<Self, Self::Error> {
        let operation = request.operation();
        let request = match request {
            CoordinatorRequest::AuthStatus { .. } => Self::AuthStatus,
            CoordinatorRequest::CreateProject { project, name, .. } => {
                Self::CreateProject { project, name }
            }
            CoordinatorRequest::SelectProject { project, .. } => Self::SelectProject { project },
            CoordinatorRequest::ListProjects { .. } => Self::ListProjects,
            CoordinatorRequest::RegisterAgentPublicKey {
                agent, public_key, ..
            } => Self::RegisterAgentPublicKey { agent, public_key },
            CoordinatorRequest::ListAgentPublicKeys { .. } => Self::ListAgentPublicKeys,
            CoordinatorRequest::RotateAgentPublicKey {
                agent, public_key, ..
            } => Self::RotateAgentPublicKey { agent, public_key },
            CoordinatorRequest::RevokeAgentPublicKey { agent, .. } => {
                Self::RevokeAgentPublicKey { agent }
            }
            CoordinatorRequest::CreateNodeEnrollmentGrant { ttl_seconds, .. } => {
                Self::CreateNodeEnrollmentGrant { ttl_seconds }
            }
            CoordinatorRequest::ListNodeDescriptors { .. } => Self::ListNodeDescriptors,
            CoordinatorRequest::ListNodeSummaries { cursor, limit, .. } => {
                Self::ListNodeSummaries { cursor, limit }
            }
            CoordinatorRequest::RevokeNodeCredential { node, .. } => {
                Self::RevokeNodeCredential { node }
            }
            CoordinatorRequest::StartProcess {
                process,
                launch_attempt,
                restart,
                ..
            } => Self::StartProcess {
                process,
                launch_attempt,
                restart,
            },
            CoordinatorRequest::ScheduleTask {
                environment,
                environment_digest,
                required_capabilities,
                dependency_cache,
                source_snapshot,
                required_artifacts,
                prefer_node,
                ..
            } => Self::ScheduleTask {
                environment,
                environment_digest,
                required_capabilities,
                dependency_cache,
                source_snapshot,
                required_artifacts,
                prefer_node,
            },
            CoordinatorRequest::LaunchTask {
                task_spec,
                wait_for_node,
                artifact_path,
                wasm_module_base64,
                ..
            } => Self::LaunchTask {
                task_spec: Box::new(task_spec),
                wait_for_node,
                artifact_path,
                wasm_module_base64,
            },
            CoordinatorRequest::CancelProcess { process, .. } => Self::CancelProcess { process },
            CoordinatorRequest::AbortProcess {
                process,
                launch_attempt,
                ..
            } => Self::AbortProcess {
                process,
                launch_attempt,
            },
            CoordinatorRequest::ListProcesses { .. } => Self::ListProcesses,
            CoordinatorRequest::ListProcessSummaries { cursor, limit, .. } => {
                Self::ListProcessSummaries { cursor, limit }
            }
            CoordinatorRequest::QuotaStatus { .. } => Self::QuotaStatus,
            CoordinatorRequest::RestartTask {
                process,
                task,
                replacement_bundle,
                ..
            } => Self::RestartTask {
                process,
                task,
                replacement_bundle,
            },
            CoordinatorRequest::ResolveTaskFailure {
                process,
                task,
                resolution,
                ..
            } => Self::ResolveTaskFailure {
                process,
                task,
                resolution,
            },
            CoordinatorRequest::DebugAttach { process, .. } => Self::DebugAttach { process },
            CoordinatorRequest::SetDebugBreakpoints {
                process,
                revision,
                probe_symbols,
                probe_locations,
                ..
            } => Self::SetDebugBreakpoints {
                process,
                revision,
                probe_symbols,
                probe_locations,
            },
            CoordinatorRequest::InspectDebugBreakpoints { process, .. } => {
                Self::InspectDebugBreakpoints { process }
            }
            CoordinatorRequest::CreateDebugEpoch {
                process,
                stopped_task,
                reason,
                ..
            } => Self::CreateDebugEpoch {
                process,
                stopped_task,
                reason,
            },
            CoordinatorRequest::ResumeDebugEpoch { process, epoch, .. } => {
                Self::ResumeDebugEpoch { process, epoch }
            }
            CoordinatorRequest::InspectDebugEpoch { process, epoch, .. } => {
                Self::InspectDebugEpoch { process, epoch }
            }
            CoordinatorRequest::ListTaskEvents { process, .. } => Self::ListTaskEvents { process },
            CoordinatorRequest::ListTaskSnapshots { process, .. } => {
                Self::ListTaskSnapshots { process }
            }
            CoordinatorRequest::ListRecentLogs {
                process,
                task,
                after_sequence,
                limit,
                ..
            } => Self::ListRecentLogs {
                process,
                task,
                after_sequence,
                limit,
            },
            CoordinatorRequest::JoinTask { process, task, .. } => Self::JoinTask { process, task },
            CoordinatorRequest::CreateArtifactDownloadLink {
                artifact,
                max_bytes,
                ttl_seconds,
                ..
            } => Self::CreateArtifactDownloadLink {
                artifact,
                max_bytes,
                ttl_seconds,
            },
            CoordinatorRequest::ListArtifacts {
                process,
                cursor,
                limit,
                ..
            } => Self::ListArtifacts {
                process,
                cursor,
                limit,
            },
            CoordinatorRequest::GetArtifact { artifact, .. } => Self::GetArtifact { artifact },
            CoordinatorRequest::RevokeArtifactDownloadLink {
                artifact,
                token_digest,
                ..
            } => Self::RevokeArtifactDownloadLink {
                artifact,
                token_digest,
            },
            CoordinatorRequest::ExportArtifactToNode {
                artifact,
                receiver_node,
                ..
            } => Self::ExportArtifactToNode {
                artifact,
                receiver_node,
            },
            _ => {
                return Err(format!(
                    "coordinator operation {operation} is not available through an authenticated session"
                ));
            }
        };
        Ok(request)
    }
}
