use clusterflux_core::{Actor, AuthContext, UserId};

use crate::CoordinatorError;

use super::{AuthenticatedCoordinatorRequest, CoordinatorServiceError};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum PublicUserOperation {
    AuthStatus,
    RevokeCliSession,
    CreateProject,
    SelectProject,
    ListProjects,
    ListAutomatedRuns,
    GetAutomatedRun,
    CancelAutomatedRun,
    RetryAutomatedRun,
    TriggerAutomatedRun,
    ListWebhookDeliveries,
    SetProjectSecret,
    ListProjectSecrets,
    RevokeProjectSecret,
    RegisterAgentPublicKey,
    ListAgentPublicKeys,
    RotateAgentPublicKey,
    RevokeAgentPublicKey,
    CreateNodeEnrollmentGrant,
    ListNodeDescriptors,
    ListNodeSummaries,
    RevokeNodeCredential,
    StartProcess,
    ScheduleTask,
    LaunchTask,
    CancelProcess,
    AbortProcess,
    ListProcesses,
    ListProcessSummaries,
    QuotaStatus,
    RestartTask,
    ResolveTaskFailure,
    DebugAttach,
    SetDebugBreakpoints,
    InspectDebugBreakpoints,
    CreateDebugEpoch,
    ResumeDebugEpoch,
    InspectDebugEpoch,
    ListTaskEvents,
    ListTaskSnapshots,
    ListRecentLogs,
    JoinTask,
    ListArtifacts,
    GetArtifact,
    CreateArtifactDownloadLink,
    RevokeArtifactDownloadLink,
    ExportArtifactToNode,
}

impl PublicUserOperation {
    pub(super) fn as_str(self) -> &'static str {
        match self {
            Self::AuthStatus => "auth_status",
            Self::RevokeCliSession => "revoke_cli_session",
            Self::CreateProject => "create_project",
            Self::SelectProject => "select_project",
            Self::ListProjects => "list_projects",
            Self::ListAutomatedRuns => "list_automated_runs",
            Self::GetAutomatedRun => "get_automated_run",
            Self::CancelAutomatedRun => "cancel_automated_run",
            Self::RetryAutomatedRun => "retry_automated_run",
            Self::TriggerAutomatedRun => "trigger_automated_run",
            Self::ListWebhookDeliveries => "list_webhook_deliveries",
            Self::SetProjectSecret => "set_project_secret",
            Self::ListProjectSecrets => "list_project_secrets",
            Self::RevokeProjectSecret => "revoke_project_secret",
            Self::RegisterAgentPublicKey => "register_agent_public_key",
            Self::ListAgentPublicKeys => "list_agent_public_keys",
            Self::RotateAgentPublicKey => "rotate_agent_public_key",
            Self::RevokeAgentPublicKey => "revoke_agent_public_key",
            Self::CreateNodeEnrollmentGrant => "create_node_enrollment_grant",
            Self::ListNodeDescriptors => "list_node_descriptors",
            Self::ListNodeSummaries => "list_node_summaries",
            Self::RevokeNodeCredential => "revoke_node_credential",
            Self::StartProcess => "start_process",
            Self::ScheduleTask => "schedule_task",
            Self::LaunchTask => "launch_task",
            Self::CancelProcess => "cancel_process",
            Self::AbortProcess => "abort_process",
            Self::ListProcesses => "list_processes",
            Self::ListProcessSummaries => "list_process_summaries",
            Self::QuotaStatus => "quota_status",
            Self::RestartTask => "restart_task",
            Self::ResolveTaskFailure => "resolve_task_failure",
            Self::DebugAttach => "debug_attach",
            Self::SetDebugBreakpoints => "set_debug_breakpoints",
            Self::InspectDebugBreakpoints => "inspect_debug_breakpoints",
            Self::CreateDebugEpoch => "create_debug_epoch",
            Self::ResumeDebugEpoch => "resume_debug_epoch",
            Self::InspectDebugEpoch => "inspect_debug_epoch",
            Self::ListTaskEvents => "list_task_events",
            Self::ListTaskSnapshots => "list_task_snapshots",
            Self::ListRecentLogs => "list_recent_logs",
            Self::JoinTask => "join_task",
            Self::ListArtifacts => "list_artifacts",
            Self::GetArtifact => "get_artifact",
            Self::CreateArtifactDownloadLink => "create_artifact_download_link",
            Self::RevokeArtifactDownloadLink => "revoke_artifact_download_link",
            Self::ExportArtifactToNode => "export_artifact_to_node",
        }
    }
}

impl From<&AuthenticatedCoordinatorRequest> for PublicUserOperation {
    fn from(request: &AuthenticatedCoordinatorRequest) -> Self {
        match request {
            AuthenticatedCoordinatorRequest::AuthStatus => Self::AuthStatus,
            AuthenticatedCoordinatorRequest::RevokeCliSession => Self::RevokeCliSession,
            AuthenticatedCoordinatorRequest::CreateProject { .. } => Self::CreateProject,
            AuthenticatedCoordinatorRequest::SelectProject { .. } => Self::SelectProject,
            AuthenticatedCoordinatorRequest::ListProjects => Self::ListProjects,
            AuthenticatedCoordinatorRequest::ListAutomatedRuns { .. } => Self::ListAutomatedRuns,
            AuthenticatedCoordinatorRequest::GetAutomatedRun { .. } => Self::GetAutomatedRun,
            AuthenticatedCoordinatorRequest::CancelAutomatedRun { .. } => Self::CancelAutomatedRun,
            AuthenticatedCoordinatorRequest::RetryAutomatedRun { .. } => Self::RetryAutomatedRun,
            AuthenticatedCoordinatorRequest::TriggerAutomatedRun { .. } => {
                Self::TriggerAutomatedRun
            }
            AuthenticatedCoordinatorRequest::ListWebhookDeliveries { .. } => {
                Self::ListWebhookDeliveries
            }
            AuthenticatedCoordinatorRequest::SetProjectSecret { .. } => Self::SetProjectSecret,
            AuthenticatedCoordinatorRequest::ListProjectSecrets => Self::ListProjectSecrets,
            AuthenticatedCoordinatorRequest::RevokeProjectSecret { .. } => {
                Self::RevokeProjectSecret
            }
            AuthenticatedCoordinatorRequest::RegisterAgentPublicKey { .. } => {
                Self::RegisterAgentPublicKey
            }
            AuthenticatedCoordinatorRequest::ListAgentPublicKeys => Self::ListAgentPublicKeys,
            AuthenticatedCoordinatorRequest::RotateAgentPublicKey { .. } => {
                Self::RotateAgentPublicKey
            }
            AuthenticatedCoordinatorRequest::RevokeAgentPublicKey { .. } => {
                Self::RevokeAgentPublicKey
            }
            AuthenticatedCoordinatorRequest::CreateNodeEnrollmentGrant { .. } => {
                Self::CreateNodeEnrollmentGrant
            }
            AuthenticatedCoordinatorRequest::ListNodeDescriptors => Self::ListNodeDescriptors,
            AuthenticatedCoordinatorRequest::ListNodeSummaries { .. } => Self::ListNodeSummaries,
            AuthenticatedCoordinatorRequest::RevokeNodeCredential { .. } => {
                Self::RevokeNodeCredential
            }
            AuthenticatedCoordinatorRequest::StartProcess { .. } => Self::StartProcess,
            AuthenticatedCoordinatorRequest::ScheduleTask { .. } => Self::ScheduleTask,
            AuthenticatedCoordinatorRequest::LaunchTask { .. } => Self::LaunchTask,
            AuthenticatedCoordinatorRequest::CancelProcess { .. } => Self::CancelProcess,
            AuthenticatedCoordinatorRequest::AbortProcess { .. } => Self::AbortProcess,
            AuthenticatedCoordinatorRequest::ListProcesses => Self::ListProcesses,
            AuthenticatedCoordinatorRequest::ListProcessSummaries { .. } => {
                Self::ListProcessSummaries
            }
            AuthenticatedCoordinatorRequest::QuotaStatus => Self::QuotaStatus,
            AuthenticatedCoordinatorRequest::RestartTask { .. } => Self::RestartTask,
            AuthenticatedCoordinatorRequest::ResolveTaskFailure { .. } => Self::ResolveTaskFailure,
            AuthenticatedCoordinatorRequest::DebugAttach { .. } => Self::DebugAttach,
            AuthenticatedCoordinatorRequest::SetDebugBreakpoints { .. } => {
                Self::SetDebugBreakpoints
            }
            AuthenticatedCoordinatorRequest::InspectDebugBreakpoints { .. } => {
                Self::InspectDebugBreakpoints
            }
            AuthenticatedCoordinatorRequest::CreateDebugEpoch { .. } => Self::CreateDebugEpoch,
            AuthenticatedCoordinatorRequest::ResumeDebugEpoch { .. } => Self::ResumeDebugEpoch,
            AuthenticatedCoordinatorRequest::InspectDebugEpoch { .. } => Self::InspectDebugEpoch,
            AuthenticatedCoordinatorRequest::ListTaskEvents { .. } => Self::ListTaskEvents,
            AuthenticatedCoordinatorRequest::ListTaskSnapshots { .. } => Self::ListTaskSnapshots,
            AuthenticatedCoordinatorRequest::ListRecentLogs { .. } => Self::ListRecentLogs,
            AuthenticatedCoordinatorRequest::JoinTask { .. } => Self::JoinTask,
            AuthenticatedCoordinatorRequest::ListArtifacts { .. } => Self::ListArtifacts,
            AuthenticatedCoordinatorRequest::GetArtifact { .. } => Self::GetArtifact,
            AuthenticatedCoordinatorRequest::CreateArtifactDownloadLink { .. } => {
                Self::CreateArtifactDownloadLink
            }
            AuthenticatedCoordinatorRequest::RevokeArtifactDownloadLink { .. } => {
                Self::RevokeArtifactDownloadLink
            }
            AuthenticatedCoordinatorRequest::ExportArtifactToNode { .. } => {
                Self::ExportArtifactToNode
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct AuthorizedPublicUser {
    pub(super) actor: UserId,
    pub(super) operation: PublicUserOperation,
}

pub(super) fn authorize_authenticated_user_operation(
    context: &AuthContext,
    request: &AuthenticatedCoordinatorRequest,
) -> Result<AuthorizedPublicUser, CoordinatorServiceError> {
    let operation = PublicUserOperation::from(request);
    let actor = match &context.actor {
        Actor::User(user) => user.clone(),
        _ => {
            return Err(CoordinatorError::Unauthorized(format!(
                "authenticated {} request requires a user CLI session",
                operation.as_str()
            ))
            .into());
        }
    };
    Ok(AuthorizedPublicUser { actor, operation })
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{AgentId, ProjectId, TenantId};

    use super::*;

    #[test]
    fn authenticated_public_authorization_requires_user_context_and_names_operation() {
        let request = AuthenticatedCoordinatorRequest::DebugAttach {
            process: "vp".to_owned(),
        };
        let agent_context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::Agent(AgentId::from("agent-ci")),
        };

        let denied = authorize_authenticated_user_operation(&agent_context, &request).unwrap_err();
        assert!(denied
            .to_string()
            .contains("authenticated debug_attach request requires a user CLI session"));

        let user_context = AuthContext {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            actor: Actor::User(UserId::from("user")),
        };
        let authorized = authorize_authenticated_user_operation(&user_context, &request).unwrap();
        assert_eq!(authorized.actor, UserId::from("user"));
        assert_eq!(authorized.operation, PublicUserOperation::DebugAttach);
    }
}
