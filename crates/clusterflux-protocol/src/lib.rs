use std::collections::BTreeMap;

use clusterflux_core::{
    AgentId, AgentSignedRequest, ArtifactId, ArtifactTransferErrorCode, ArtifactTransferState,
    Authorization, AutomatedRunRecord, Capability, ClusterfluxPathKind, CredentialKind, Digest,
    DownloadLink, EnvironmentRequirements, IrohEndpointAdvertisement, LaunchAttemptId, LimitKind,
    NodeCapabilities, NodeDescriptor, NodeId, NodeSignedRequest, Placement, ProcessId, ProjectId,
    RepositoryId, RepositoryRevision, ResourceLimits, RunId, SourceLocation, SourcePreparation,
    SourceProviderKind, TaskBoundaryHandle, TaskBoundaryValue, TaskDefinitionId, TaskInstanceId,
    TaskJoinResult, TaskSpec, TenantId, UserId, VfsPath, WebhookDeliveryRecord,
    WorkflowCompilationRequest, WorkflowCompilationResult,
};
use serde::{Deserialize, Serialize};

mod artifacts;
mod auth;
mod automation;
mod debug;
mod envelope;
mod interchange;
mod login;
mod logs;
mod nodes;
mod panels;
mod processes;
mod projects;
mod responses;
mod tasks;
mod validation;
mod version;
mod wire;

#[cfg(test)]
mod validation_tests;

pub use artifacts::*;
pub use auth::*;
pub use automation::*;
pub use debug::*;
pub use envelope::{
    CoordinatorAuthentication, CoordinatorRequestEnvelope, CoordinatorWireRequest,
    LoginRequestEnvelope,
};
pub use interchange::*;
pub use login::*;
pub use logs::*;
pub use nodes::*;
pub use panels::*;
pub use processes::*;
pub use projects::*;
pub use responses::*;
pub use tasks::*;
pub use version::*;
pub use wire::{coordinator_wire_request, login_wire_request};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum CoordinatorRequest {
    Ping,
    Authenticated {
        session_secret: String,
        request: AuthenticatedCoordinatorRequest,
    },
    AuthStatus {
        tenant: String,
        project: String,
        actor_user: String,
    },
    AdminStatus {
        tenant: String,
        actor_user: String,
        admin_proof: Digest,
        admin_nonce: String,
        issued_at_epoch_seconds: u64,
    },
    SuspendTenant {
        tenant: String,
        actor_user: String,
        target_tenant: String,
        admin_proof: Digest,
        admin_nonce: String,
        issued_at_epoch_seconds: u64,
    },
    CreateProject {
        tenant: String,
        actor_user: String,
        project: String,
        name: String,
    },
    SelectProject {
        tenant: String,
        actor_user: String,
        project: String,
    },
    ListProjects {
        tenant: String,
        actor_user: String,
    },
    RegisterAgentPublicKey {
        tenant: String,
        project: String,
        user: String,
        agent: String,
        public_key: String,
    },
    ListAgentPublicKeys {
        tenant: String,
        project: String,
        user: String,
    },
    RotateAgentPublicKey {
        tenant: String,
        project: String,
        user: String,
        agent: String,
        public_key: String,
    },
    RevokeAgentPublicKey {
        tenant: String,
        project: String,
        user: String,
        agent: String,
    },
    AttachNode {
        tenant: String,
        project: String,
        node: String,
        public_key: String,
    },
    CreateNodeEnrollmentGrant {
        tenant: String,
        project: String,
        actor_user: String,
        #[serde(default = "default_node_enrollment_ttl_seconds")]
        ttl_seconds: u64,
    },
    ExchangeNodeEnrollmentGrant {
        tenant: String,
        project: String,
        node: String,
        public_key: String,
        enrollment_grant: String,
    },
    NodeHeartbeat {
        tenant: String,
        project: String,
        node: String,
        #[serde(default)]
        node_signature: Option<NodeSignedRequest>,
    },
    SignedNode {
        node: String,
        node_signature: NodeSignedRequest,
        request: Box<CoordinatorRequest>,
    },
    ReportNodeCapabilities {
        tenant: String,
        project: String,
        node: String,
        capabilities: NodeCapabilities,
        cached_environment_digests: Vec<Digest>,
        #[serde(default)]
        dependency_cache_digests: Vec<Digest>,
        source_snapshots: Vec<Digest>,
        artifact_locations: Vec<String>,
        online: bool,
    },
    PollNodeAssignment {
        tenant: String,
        project: String,
        node: String,
        accept_system_tasks: bool,
        accept_process_tasks: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        active_assignment: Option<ActiveNodeAssignment>,
    },
    AcknowledgeNodeAssignment {
        tenant: String,
        project: String,
        node: String,
        assignment_id: String,
        lease_epoch: u64,
    },
    ReportSystemTask {
        tenant: String,
        project: String,
        node: String,
        result: SystemTaskResult,
    },
    PollTaskSecretGrant {
        tenant: String,
        project: String,
        node: String,
        process: String,
        task: String,
        secret_name: String,
    },
    GetArtifactDataPlanePolicy {
        tenant: String,
        project: String,
        node: String,
    },
    ReportIrohEndpointAdvertisement {
        tenant: String,
        project: String,
        node: String,
        advertisement: IrohEndpointAdvertisement,
    },
    RequestArtifactInterchange {
        tenant: String,
        project: String,
        process: String,
        node: String,
        artifact: String,
        offset: u64,
    },
    PollArtifactProviderAssignment {
        tenant: String,
        project: String,
        node: String,
    },
    PollArtifactReceiverAssignment {
        tenant: String,
        project: String,
        node: String,
    },
    AcknowledgeArtifactAssignment {
        tenant: String,
        project: String,
        node: String,
        transfer_id: String,
        role: clusterflux_core::ArtifactAssignmentRole,
    },
    ReportArtifactInterchange {
        tenant: String,
        project: String,
        node: String,
        transfer_id: String,
        state: ArtifactTransferState,
        bytes_completed: u64,
        path_kind: ClusterfluxPathKind,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        failure_code: Option<ArtifactTransferErrorCode>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verified_digest: Option<Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        verified_size: Option<u64>,
    },
    ReleaseArtifact {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        artifact: String,
        digest: Digest,
        size_bytes: u64,
    },
    BeginNodeDrain {
        tenant: String,
        project: String,
        node: String,
        #[serde(default)]
        ephemeral: bool,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        provider_deadline_epoch_seconds: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        soft_drain_deadline_epoch_seconds: Option<u64>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        hard_drain_deadline_epoch_seconds: Option<u64>,
    },
    FinalizeNodeRelease {
        tenant: String,
        project: String,
        node: String,
    },
    ListNodeDescriptors {
        tenant: String,
        project: String,
        actor_user: String,
    },
    ListNodeSummaries {
        tenant: String,
        project: String,
        actor_user: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    RevokeNodeCredential {
        tenant: String,
        project: String,
        actor_user: String,
        node: String,
    },
    ScheduleTask {
        tenant: String,
        project: String,
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
        tenant: String,
        project: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_public_key_fingerprint: Option<Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_signature: Option<AgentSignedRequest>,
        task_spec: TaskSpec,
        #[serde(default)]
        wait_for_node: bool,
        artifact_path: String,
        wasm_module_base64: String,
    },
    LaunchChildTask {
        tenant: String,
        project: String,
        process: String,
        node: String,
        parent_task: String,
        task_spec: TaskSpec,
        #[serde(default)]
        wait_for_node: bool,
        artifact_path: String,
        wasm_module_base64: String,
    },
    JoinChildTask {
        tenant: String,
        project: String,
        process: String,
        node: String,
        parent_task: String,
        task: String,
    },
    RequestSourcePreparation {
        tenant: String,
        project: String,
        provider: SourceProviderKind,
    },
    CompleteSourcePreparation {
        tenant: String,
        project: String,
        node: String,
        provider: SourceProviderKind,
        source_snapshot: Digest,
    },
    StartProcess {
        tenant: String,
        project: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_user: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        actor_agent: Option<String>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_public_key_fingerprint: Option<Digest>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        agent_signature: Option<AgentSignedRequest>,
        process: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        launch_attempt: Option<String>,
        #[serde(default)]
        restart: bool,
    },
    ReconnectNode {
        tenant: String,
        project: String,
        node: String,
        process: String,
        epoch: u64,
    },
    CancelTask {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
    },
    CancelProcess {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    },
    AbortProcess {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        launch_attempt: Option<String>,
    },
    ListProcesses {
        tenant: String,
        project: String,
        actor_user: String,
    },
    ListProcessSummaries {
        tenant: String,
        project: String,
        actor_user: String,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    QuotaStatus {
        tenant: String,
        project: String,
        actor_user: String,
    },
    PollTaskControl {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        /// Logical children currently awaited by this task. The coordinator
        /// returns terminal join results on the task's existing control stream.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        child_tasks: Vec<String>,
    },
    RestartTask {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: String,
        #[serde(default)]
        replacement_bundle: Option<TaskReplacementBundle>,
    },
    ResolveTaskFailure {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: String,
        resolution: TaskFailureResolution,
    },
    DebugAttach {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    },
    SetDebugBreakpoints {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        #[serde(default)]
        revision: u64,
        probe_symbols: Vec<String>,
        #[serde(default)]
        probe_locations: Vec<SourceLocation>,
    },
    InspectDebugBreakpoints {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    },
    CreateDebugEpoch {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        stopped_task: String,
        reason: String,
    },
    ResumeDebugEpoch {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        epoch: u64,
    },
    InspectDebugEpoch {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        epoch: u64,
    },
    PollDebugCommand {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
    },
    ReportDebugState {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        epoch: u64,
        state: DebugAcknowledgementState,
        #[serde(default)]
        current_source_location: Option<SourceLocation>,
        #[serde(default)]
        stack_frames: Vec<String>,
        #[serde(default)]
        local_values: Vec<(String, String)>,
        #[serde(default)]
        task_args: Vec<(String, String)>,
        #[serde(default)]
        handles: Vec<(String, String)>,
        #[serde(default)]
        command_status: Option<String>,
        #[serde(default)]
        recent_output: Vec<String>,
        #[serde(default)]
        message: Option<String>,
    },
    ReportDebugProbeHit {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        probe_symbol: String,
    },
    ReportTaskLog {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        stdout_bytes: u64,
        stderr_bytes: u64,
        #[serde(default)]
        stdout_tail: String,
        #[serde(default)]
        stderr_tail: String,
        stdout_truncated: bool,
        stderr_truncated: bool,
        backpressured: bool,
    },
    ReportTaskLogChunk {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        stream: TaskLogStream,
        offset: u64,
        source_bytes: u64,
        text: String,
        #[serde(default)]
        truncated: bool,
    },
    ReportVfsMetadata {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        artifact_path: Option<String>,
        artifact_digest: Option<Digest>,
        artifact_size_bytes: Option<u64>,
        large_bytes_uploaded: bool,
    },
    TaskCompleted {
        tenant: String,
        project: String,
        process: String,
        node: String,
        task: String,
        #[serde(default)]
        terminal_state: Option<TaskTerminalState>,
        status_code: Option<i32>,
        stdout_bytes: u64,
        stderr_bytes: u64,
        #[serde(default)]
        stdout_tail: String,
        #[serde(default)]
        stderr_tail: String,
        #[serde(default)]
        stdout_truncated: bool,
        #[serde(default)]
        stderr_truncated: bool,
        artifact_path: Option<String>,
        artifact_digest: Option<Digest>,
        artifact_size_bytes: Option<u64>,
        #[serde(default)]
        result: Option<TaskBoundaryValue>,
    },
    ListTaskEvents {
        tenant: String,
        project: String,
        actor_user: String,
        #[serde(default)]
        process: Option<String>,
    },
    ListTaskSnapshots {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
    },
    ListRecentLogs {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        #[serde(default)]
        task: Option<String>,
        #[serde(default)]
        after_sequence: Option<u64>,
        #[serde(default = "default_log_page_limit")]
        limit: u32,
    },
    JoinTask {
        tenant: String,
        project: String,
        actor_user: String,
        process: String,
        task: String,
    },
    RenderOperatorPanel {
        tenant: String,
        project: String,
        process: String,
        actor_user: String,
        max_download_bytes: u64,
        stopped: bool,
    },
    SubmitPanelEvent {
        tenant: String,
        project: String,
        process: String,
        #[serde(default)]
        actor_user: Option<String>,
        widget_id: String,
        kind: PanelEventKind,
        max_events: u64,
    },
    CreateArtifactDownloadLink {
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
        max_bytes: u64,
        #[serde(default = "default_download_ttl_seconds")]
        ttl_seconds: u64,
    },
    ListArtifacts {
        tenant: String,
        project: String,
        actor_user: String,
        #[serde(default)]
        process: Option<String>,
        #[serde(default)]
        cursor: Option<String>,
        #[serde(default = "default_page_limit")]
        limit: u32,
    },
    GetArtifact {
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
    },
    RevokeArtifactDownloadLink {
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
        token_digest: Digest,
    },
    ExportArtifactToNode {
        tenant: String,
        project: String,
        actor_user: String,
        artifact: String,
        receiver_node: String,
    },
}

fn default_download_ttl_seconds() -> u64 {
    900
}

fn default_page_limit() -> u32 {
    50
}

fn default_log_page_limit() -> u32 {
    100
}

fn default_node_enrollment_ttl_seconds() -> u64 {
    900
}
