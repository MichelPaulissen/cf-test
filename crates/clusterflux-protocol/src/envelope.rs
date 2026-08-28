use clusterflux_core::{Digest, RequestId};
use serde::{Deserialize, Serialize};

use crate::validation;
use crate::{
    CoordinatorRequest, LoginRequest, COORDINATOR_PROTOCOL_VERSION, COORDINATOR_WIRE_REQUEST_TYPE,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinatorAuthentication {
    None {},
    CliSession {
        session: bool,
        request_operation: String,
    },
    NodeSignature {
        node: String,
    },
    AgentSignature {
        agent: Option<String>,
        fingerprint: Option<Digest>,
    },
    AdminProof {
        actor: String,
        nonce: String,
        issued_at_epoch_seconds: u64,
    },
    NodeEnrollmentGrant {
        node: String,
    },
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum CoordinatorWireRequest {
    Envelope(CoordinatorRequestEnvelope),
}

impl CoordinatorWireRequest {
    pub fn into_request(self) -> Result<CoordinatorRequest, String> {
        self.into_parts().map(|(_, request)| request)
    }

    pub fn into_parts(self) -> Result<(String, CoordinatorRequest), String> {
        match self {
            Self::Envelope(envelope) => envelope.into_parts(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct CoordinatorRequestEnvelope {
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<CoordinatorAuthentication>,
    pub payload: CoordinatorRequest,
}

impl CoordinatorRequestEnvelope {
    pub fn new(request_id: impl Into<String>, payload: CoordinatorRequest) -> Self {
        Self {
            envelope_type: COORDINATOR_WIRE_REQUEST_TYPE.to_owned(),
            protocol_version: COORDINATOR_PROTOCOL_VERSION,
            request_id: request_id.into(),
            operation: payload.operation().to_owned(),
            authentication: Some(payload.authentication_metadata()),
            payload,
        }
    }

    pub fn into_request(self) -> Result<CoordinatorRequest, String> {
        self.into_parts().map(|(_, request)| request)
    }

    pub fn into_parts(self) -> Result<(String, CoordinatorRequest), String> {
        validate_envelope_header(&self.envelope_type, self.protocol_version, &self.request_id)?;
        self.payload.validate_external_identifiers()?;
        let payload_operation = self.payload.operation();
        if self.operation != payload_operation {
            return Err(format!(
                "coordinator wire operation {} does not match payload operation {}",
                self.operation, payload_operation
            ));
        }
        if let Some(authentication) = &self.authentication {
            let expected = self.payload.authentication_metadata();
            if authentication != &expected {
                return Err(format!(
                    "coordinator wire authentication metadata does not match payload operation {payload_operation}"
                ));
            }
        }
        Ok((self.request_id, self.payload))
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LoginRequestEnvelope {
    #[serde(rename = "type")]
    pub envelope_type: String,
    pub protocol_version: u64,
    pub request_id: String,
    pub operation: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub authentication: Option<CoordinatorAuthentication>,
    pub payload: LoginRequest,
}

impl LoginRequestEnvelope {
    pub fn new(request_id: impl Into<String>, payload: LoginRequest) -> Self {
        Self {
            envelope_type: COORDINATOR_WIRE_REQUEST_TYPE.to_owned(),
            protocol_version: COORDINATOR_PROTOCOL_VERSION,
            request_id: request_id.into(),
            operation: payload.operation().to_owned(),
            authentication: Some(CoordinatorAuthentication::None {}),
            payload,
        }
    }

    pub fn into_parts(self) -> Result<(String, LoginRequest), String> {
        validate_envelope_header(&self.envelope_type, self.protocol_version, &self.request_id)?;
        self.payload.validate_external_inputs()?;
        let payload_operation = self.payload.operation();
        if self.operation != payload_operation {
            return Err(format!(
                "coordinator wire operation {} does not match payload operation {}",
                self.operation, payload_operation
            ));
        }
        if let Some(authentication) = &self.authentication {
            let expected = CoordinatorAuthentication::None {};
            if authentication != &expected {
                return Err(format!(
                    "login wire authentication metadata does not match payload operation {payload_operation}"
                ));
            }
        }
        Ok((self.request_id, self.payload))
    }
}

fn validate_envelope_header(
    envelope_type: &str,
    protocol_version: u64,
    request_id: &str,
) -> Result<(), String> {
    if envelope_type != COORDINATOR_WIRE_REQUEST_TYPE {
        return Err(format!(
            "unsupported coordinator wire request type {envelope_type}; expected {COORDINATOR_WIRE_REQUEST_TYPE}"
        ));
    }
    if protocol_version != COORDINATOR_PROTOCOL_VERSION {
        return Err(format!(
            "unsupported coordinator protocol version {protocol_version}; expected {COORDINATOR_PROTOCOL_VERSION}"
        ));
    }
    RequestId::try_new(request_id.to_owned())
        .map_err(|error| format!("malformed coordinator wire request_id: {error}"))?;
    Ok(())
}

impl CoordinatorRequest {
    pub fn validate_external_identifiers(&self) -> Result<(), String> {
        validation::validate_coordinator_request(self, "request")
    }

    pub const fn operation(&self) -> &'static str {
        match self {
            Self::Ping => "ping",
            Self::Authenticated { .. } => "authenticated",
            Self::AuthStatus { .. } => "auth_status",
            Self::AdminStatus { .. } => "admin_status",
            Self::SuspendTenant { .. } => "suspend_tenant",
            Self::CreateProject { .. } => "create_project",
            Self::SelectProject { .. } => "select_project",
            Self::ListProjects { .. } => "list_projects",
            Self::RegisterAgentPublicKey { .. } => "register_agent_public_key",
            Self::ListAgentPublicKeys { .. } => "list_agent_public_keys",
            Self::RotateAgentPublicKey { .. } => "rotate_agent_public_key",
            Self::RevokeAgentPublicKey { .. } => "revoke_agent_public_key",
            Self::AttachNode { .. } => "attach_node",
            Self::CreateNodeEnrollmentGrant { .. } => "create_node_enrollment_grant",
            Self::ExchangeNodeEnrollmentGrant { .. } => "exchange_node_enrollment_grant",
            Self::NodeHeartbeat { .. } => "node_heartbeat",
            Self::SignedNode { .. } => "signed_node",
            Self::ReportNodeCapabilities { .. } => "report_node_capabilities",
            Self::PollNodeAssignment { .. } => "poll_node_assignment",
            Self::AcknowledgeNodeAssignment { .. } => "acknowledge_node_assignment",
            Self::ReportSystemTask { .. } => "report_system_task",
            Self::PollTaskSecretGrant { .. } => "poll_task_secret_grant",
            Self::GetArtifactDataPlanePolicy { .. } => "get_artifact_data_plane_policy",
            Self::ReportIrohEndpointAdvertisement { .. } => "report_iroh_endpoint_advertisement",
            Self::RequestArtifactInterchange { .. } => "request_artifact_interchange",
            Self::PollArtifactProviderAssignment { .. } => "poll_artifact_provider_assignment",
            Self::PollArtifactReceiverAssignment { .. } => "poll_artifact_receiver_assignment",
            Self::AcknowledgeArtifactAssignment { .. } => "acknowledge_artifact_assignment",
            Self::ReportArtifactInterchange { .. } => "report_artifact_interchange",
            Self::ReleaseArtifact { .. } => "release_artifact",
            Self::BeginNodeDrain { .. } => "begin_node_drain",
            Self::FinalizeNodeRelease { .. } => "finalize_node_release",
            Self::ListNodeDescriptors { .. } => "list_node_descriptors",
            Self::ListNodeSummaries { .. } => "list_node_summaries",
            Self::RevokeNodeCredential { .. } => "revoke_node_credential",
            Self::ScheduleTask { .. } => "schedule_task",
            Self::LaunchTask { .. } => "launch_task",
            Self::LaunchChildTask { .. } => "launch_child_task",
            Self::JoinChildTask { .. } => "join_child_task",
            Self::RequestSourcePreparation { .. } => "request_source_preparation",
            Self::CompleteSourcePreparation { .. } => "complete_source_preparation",
            Self::StartProcess { .. } => "start_process",
            Self::ReconnectNode { .. } => "reconnect_node",
            Self::CancelTask { .. } => "cancel_task",
            Self::CancelProcess { .. } => "cancel_process",
            Self::AbortProcess { .. } => "abort_process",
            Self::ListProcesses { .. } => "list_processes",
            Self::ListProcessSummaries { .. } => "list_process_summaries",
            Self::QuotaStatus { .. } => "quota_status",
            Self::PollTaskControl { .. } => "poll_task_control",
            Self::RestartTask { .. } => "restart_task",
            Self::ResolveTaskFailure { .. } => "resolve_task_failure",
            Self::DebugAttach { .. } => "debug_attach",
            Self::SetDebugBreakpoints { .. } => "set_debug_breakpoints",
            Self::InspectDebugBreakpoints { .. } => "inspect_debug_breakpoints",
            Self::CreateDebugEpoch { .. } => "create_debug_epoch",
            Self::ResumeDebugEpoch { .. } => "resume_debug_epoch",
            Self::InspectDebugEpoch { .. } => "inspect_debug_epoch",
            Self::PollDebugCommand { .. } => "poll_debug_command",
            Self::ReportDebugState { .. } => "report_debug_state",
            Self::ReportDebugProbeHit { .. } => "report_debug_probe_hit",
            Self::ReportTaskLog { .. } => "report_task_log",
            Self::ReportTaskLogChunk { .. } => "report_task_log_chunk",
            Self::ReportVfsMetadata { .. } => "report_vfs_metadata",
            Self::TaskCompleted { .. } => "task_completed",
            Self::ListTaskEvents { .. } => "list_task_events",
            Self::ListTaskSnapshots { .. } => "list_task_snapshots",
            Self::ListRecentLogs { .. } => "list_recent_logs",
            Self::JoinTask { .. } => "join_task",
            Self::RenderOperatorPanel { .. } => "render_operator_panel",
            Self::SubmitPanelEvent { .. } => "submit_panel_event",
            Self::CreateArtifactDownloadLink { .. } => "create_artifact_download_link",
            Self::ListArtifacts { .. } => "list_artifacts",
            Self::GetArtifact { .. } => "get_artifact",
            Self::RevokeArtifactDownloadLink { .. } => "revoke_artifact_download_link",
            Self::ExportArtifactToNode { .. } => "export_artifact_to_node",
        }
    }

    pub fn authentication_metadata(&self) -> CoordinatorAuthentication {
        match self {
            Self::Authenticated { request, .. } => CoordinatorAuthentication::CliSession {
                session: true,
                request_operation: request.operation().to_owned(),
            },
            Self::SignedNode { node, .. }
            | Self::NodeHeartbeat {
                node,
                node_signature: Some(_),
                ..
            } => CoordinatorAuthentication::NodeSignature { node: node.clone() },
            Self::LaunchTask {
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature: Some(_),
                ..
            }
            | Self::StartProcess {
                actor_agent,
                agent_public_key_fingerprint,
                agent_signature: Some(_),
                ..
            } => CoordinatorAuthentication::AgentSignature {
                agent: actor_agent.clone(),
                fingerprint: agent_public_key_fingerprint.clone(),
            },
            Self::AdminStatus {
                actor_user,
                admin_nonce,
                issued_at_epoch_seconds,
                ..
            }
            | Self::SuspendTenant {
                actor_user,
                admin_nonce,
                issued_at_epoch_seconds,
                ..
            } => CoordinatorAuthentication::AdminProof {
                actor: actor_user.clone(),
                nonce: admin_nonce.clone(),
                issued_at_epoch_seconds: *issued_at_epoch_seconds,
            },
            Self::ExchangeNodeEnrollmentGrant { node, .. } => {
                CoordinatorAuthentication::NodeEnrollmentGrant { node: node.clone() }
            }
            _ => CoordinatorAuthentication::None {},
        }
    }
}
