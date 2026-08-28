use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum CoordinatorResponse {
    Pong {
        epoch: u64,
    },
    AuthStatus {
        tenant: TenantId,
        project: ProjectId,
        actor: UserId,
        authenticated: bool,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        coordinator_version: String,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        workflow_sdk_version: String,
        account_status: String,
        suspended: bool,
        disabled: bool,
        deleted: bool,
        manual_review: bool,
        sanitized_reason: Option<String>,
        next_actions: Vec<String>,
        sensitive_moderation_details_exposed: bool,
        signup_failure_details_exposed: bool,
    },
    AdminStatus {
        tenant: TenantId,
        actor: UserId,
        suspended: bool,
        safe_default: String,
    },
    TenantSuspended {
        tenant: TenantId,
        actor: UserId,
        policy: ServicePolicyRecord,
    },
    ProjectCreated {
        project: ProjectRecord,
        actor: UserId,
    },
    ProjectSelected {
        project: ProjectRecord,
        actor: UserId,
    },
    Projects {
        projects: Vec<ProjectRecord>,
        actor: UserId,
    },
    AutomatedRuns {
        runs: Vec<AutomatedRunRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_cursor: Option<String>,
        actor: UserId,
    },
    AutomatedRun {
        run: AutomatedRunRecord,
        actor: UserId,
    },
    WebhookDeliveries {
        deliveries: Vec<WebhookDeliveryRecord>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        next_cursor: Option<String>,
        actor: UserId,
    },
    SystemTaskRecorded {
        run: AutomatedRunRecord,
    },
    ProjectSecretSet {
        secret: ProjectSecretMetadata,
        actor: UserId,
    },
    ProjectSecrets {
        secrets: Vec<ProjectSecretMetadata>,
        actor: UserId,
    },
    ProjectSecretRevoked {
        secret: ProjectSecretMetadata,
        actor: UserId,
    },
    TaskSecretGrant {
        grant: Option<super::TaskSecretGrant>,
    },
    CliSessionRevoked {
        tenant: TenantId,
        project: ProjectId,
        actor: UserId,
    },
    AgentPublicKey {
        record: AgentPublicKeyRecord,
        actor: UserId,
    },
    AgentPublicKeys {
        records: Vec<AgentPublicKeyRecord>,
        actor: UserId,
    },
    NodeAttached {
        node: NodeId,
        tenant: TenantId,
        project: ProjectId,
    },
    NodeEnrollmentGrantCreated {
        tenant: TenantId,
        project: ProjectId,
        grant: String,
        scope: String,
        expires_at_epoch_seconds: u64,
    },
    NodeEnrollmentExchanged {
        node: NodeId,
        tenant: TenantId,
        project: ProjectId,
        credential: clusterflux_core::NodeCredential,
    },
    NodeHeartbeat {
        node: NodeId,
        epoch: u64,
    },
    NodeCapabilitiesRecorded {
        node: NodeId,
        node_descriptors: usize,
    },
    NodeAssignment {
        assignment: Option<Box<NodeAssignmentOffer>>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        cancel_assignment: Option<ActiveNodeAssignment>,
    },
    NodeAssignmentAcknowledged {
        assignment_id: String,
        lease_epoch: u64,
    },
    NodeDrainStatus {
        status: clusterflux_core::NodeDrainStatus,
    },
    NodeDescriptors {
        descriptors: Vec<NodeDescriptor>,
        actor: UserId,
    },
    NodeSummaries {
        nodes: Vec<NodeSummary>,
        next_cursor: Option<String>,
        actor: UserId,
    },
    NodeCredentialRevoked {
        node: NodeId,
        tenant: TenantId,
        project: ProjectId,
        actor: UserId,
        descriptor_removed: bool,
        queued_assignments_removed: usize,
    },
    TaskPlacement {
        placement: Placement,
    },
    TaskLaunched {
        process: ProcessId,
        task: TaskInstanceId,
        actor: WorkflowActor,
        placement: Placement,
        assignment: Box<TaskAssignment>,
        charged_spawns: u64,
    },
    MainLaunched {
        process: ProcessId,
        task_definition: clusterflux_core::TaskDefinitionId,
        task_instance: TaskInstanceId,
        actor: WorkflowActor,
        state: String,
    },
    TaskQueued {
        process: ProcessId,
        task: TaskInstanceId,
        actor: WorkflowActor,
        reason: String,
        charged_spawns: u64,
        queued_tasks: usize,
    },
    ArtifactDataPlanePolicy {
        policy: clusterflux_core::ArtifactDataPlanePolicy,
    },
    IrohEndpointAdvertisementAccepted {
        endpoint_id: String,
        generation: u64,
        expires_at: u64,
    },
    ArtifactTransferAuthorization {
        authorization: Option<Box<clusterflux_core::ArtifactTransferAuthorization>>,
        transfer: Option<clusterflux_core::ArtifactTransferRecord>,
    },
    ArtifactProviderAssignment {
        authorization: Option<Box<clusterflux_core::ArtifactTransferAuthorization>>,
        /// Terminal transfer IDs are redelivered so provider pins are cancelled
        /// promptly even if an earlier control response was lost.
        retired_transfer_ids: Vec<String>,
    },
    ArtifactReceiverAssignment {
        authorization: Option<Box<clusterflux_core::ArtifactTransferAuthorization>>,
    },
    ArtifactAssignmentAcknowledged {
        transfer_id: String,
        role: clusterflux_core::ArtifactAssignmentRole,
        state: clusterflux_core::ArtifactAssignmentState,
    },
    ArtifactTransferProgressAccepted {
        transfer: clusterflux_core::ArtifactTransferRecord,
        /// The reporting node's renewed, role-scoped authorization. Nodes use
        /// this to refresh provider pins and receiver partial retention without
        /// sharing the opposite role's stream secret or endpoint authority.
        authorization: Option<Box<clusterflux_core::ArtifactTransferAuthorization>>,
    },
    ArtifactReleased {
        artifact: clusterflux_core::ArtifactId,
        process: ProcessId,
        hold_removed: bool,
        remaining_holds: Vec<clusterflux_core::ArtifactHold>,
    },
    SourcePreparation {
        status: SourcePreparationStatus,
    },
    SourcePreparationCompleted {
        node: NodeId,
        provider: SourceProviderKind,
        source_snapshot: Digest,
    },
    ProcessStarted {
        process: ProcessId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        launch_attempt: Option<String>,
        epoch: u64,
        actor: WorkflowActor,
        charged_spawns: u64,
    },
    NodeReconnected {
        node: NodeId,
        process: ProcessId,
    },
    TaskCancellationRequested {
        process: ProcessId,
        task: TaskInstanceId,
        node: NodeId,
    },
    ProcessCancellationRequested {
        process: ProcessId,
        cancelled_tasks: Vec<TaskCancellationTarget>,
        affected_nodes: Vec<NodeId>,
    },
    ProcessAborted {
        process: ProcessId,
        aborted_tasks: Vec<TaskCancellationTarget>,
        affected_nodes: Vec<NodeId>,
    },
    ProcessStatuses {
        processes: Vec<VirtualProcessStatus>,
        actor: UserId,
    },
    ProcessSummaries {
        processes: Vec<ProcessSummary>,
        next_cursor: Option<String>,
        actor: UserId,
    },
    QuotaStatus {
        tenant: TenantId,
        project: ProjectId,
        actor: UserId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        policy_label: Option<String>,
        limits: ResourceLimits,
        window_seconds: BTreeMap<LimitKind, u64>,
        usage: BTreeMap<LimitKind, u64>,
        window_started_epoch_seconds: BTreeMap<LimitKind, u64>,
        projects_current: u64,
        projects_maximum: u64,
        node_identities_current: u64,
        node_identities_maximum: u64,
        active_processes_current: u64,
        active_processes_maximum: u64,
    },
    TaskControl {
        process: ProcessId,
        task: TaskInstanceId,
        cancel_requested: bool,
        abort_requested: bool,
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        child_joins: Vec<clusterflux_core::TaskJoinResult>,
    },
    TaskRestart {
        process: ProcessId,
        task: TaskInstanceId,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restarted_task_instance: Option<clusterflux_core::TaskInstanceId>,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        restarted_attempt_id: Option<String>,
        actor: UserId,
        accepted: bool,
        clean_boundary_available: bool,
        active_task: bool,
        completed_event_observed: bool,
        requires_whole_process_restart: bool,
        message: String,
        audit_event: DebugAuditEvent,
        charged_debug_read_bytes: u64,
        used_debug_read_bytes: u64,
    },
    DebugCommand {
        process: ProcessId,
        task: TaskInstanceId,
        epoch: Option<u64>,
        command: Option<String>,
    },
    DebugStateRecorded {
        process: ProcessId,
        node: NodeId,
        task: TaskInstanceId,
        epoch: u64,
        state: DebugAcknowledgementState,
    },
    DebugAttach {
        process: ProcessId,
        actor: UserId,
        authorization: Authorization,
        source_revision: Option<RepositoryRevision>,
        audit_event: DebugAuditEvent,
        charged_debug_read_bytes: u64,
        used_debug_read_bytes: u64,
    },
    DebugBreakpoints {
        process: ProcessId,
        actor: UserId,
        revision: u64,
        probe_symbols: Vec<String>,
        hit_epoch: Option<u64>,
        hit_task: Option<TaskInstanceId>,
        hit_probe_symbol: Option<String>,
        hit_source_location: Option<SourceLocation>,
        audit_event: DebugAuditEvent,
        charged_debug_read_bytes: u64,
        used_debug_read_bytes: u64,
    },
    DebugProbeHit {
        process: ProcessId,
        node: NodeId,
        task: TaskInstanceId,
        probe_symbol: String,
        breakpoint_matched: bool,
        debug_epoch: Option<u64>,
    },
    DebugEpoch {
        process: ProcessId,
        actor: UserId,
        epoch: u64,
        command: String,
        affected_tasks: Vec<TaskCancellationTarget>,
        all_stop_requested: bool,
        audit_event: DebugAuditEvent,
        charged_debug_read_bytes: u64,
        used_debug_read_bytes: u64,
    },
    DebugEpochStatus {
        process: ProcessId,
        actor: UserId,
        epoch: u64,
        command: String,
        expected_tasks: Vec<TaskCancellationTarget>,
        acknowledgements: Vec<DebugParticipantAcknowledgement>,
        fully_frozen: bool,
        partially_frozen: bool,
        fully_resumed: bool,
        failed: bool,
        failure_messages: Vec<String>,
        audit_event: DebugAuditEvent,
        charged_debug_read_bytes: u64,
        used_debug_read_bytes: u64,
    },
    TaskLogRecorded {
        process: ProcessId,
        task: TaskInstanceId,
        stdout_bytes: u64,
        stderr_bytes: u64,
        stdout_tail: String,
        stderr_tail: String,
        backpressured: bool,
    },
    TaskLogChunkRecorded {
        process: ProcessId,
        task: TaskInstanceId,
        sequence: Option<u64>,
        next_offset: u64,
    },
    RecentLogs {
        entries: Vec<RecentLogEntry>,
        next_sequence: Option<u64>,
        history_truncated: bool,
    },
    VfsMetadataRecorded {
        process: ProcessId,
        task: TaskInstanceId,
        artifact_path: Option<VfsPath>,
        large_bytes_uploaded: bool,
    },
    TaskRecorded {
        process: ProcessId,
        task: TaskInstanceId,
        events_recorded: usize,
    },
    TaskEvents {
        events: Vec<TaskCompletionEvent>,
    },
    TaskSnapshots {
        snapshots: Vec<TaskAttemptSnapshot>,
    },
    TaskFailureResolved {
        process: ProcessId,
        task: TaskInstanceId,
        attempt_id: String,
        resolution: TaskFailureResolution,
    },
    TaskJoined {
        join: TaskJoinResult,
    },
    OperatorPanel {
        panel: PanelState,
    },
    PanelEventAccepted {
        used_events: u64,
        max_events: u64,
    },
    ArtifactDownloadLink {
        link: DownloadLink,
    },
    Artifacts {
        artifacts: Vec<ArtifactSummary>,
        next_cursor: Option<String>,
    },
    Artifact {
        artifact: ArtifactSummary,
    },
    ArtifactDownloadLinkRevoked {
        link: DownloadLink,
    },
    ArtifactExport {
        transfer: Option<clusterflux_core::ArtifactTransferRecord>,
        receiver_node: NodeId,
        artifact_size_bytes: u64,
        already_present: bool,
    },
    Error {
        #[serde(flatten)]
        error: clusterflux_core::ApiError,
    },
}

impl CoordinatorResponse {
    pub const fn kind(&self) -> &'static str {
        match self {
            Self::Pong { .. } => "pong",
            Self::AuthStatus { .. } => "auth_status",
            Self::AdminStatus { .. } => "admin_status",
            Self::TenantSuspended { .. } => "tenant_suspended",
            Self::ProjectCreated { .. } => "project_created",
            Self::ProjectSelected { .. } => "project_selected",
            Self::Projects { .. } => "projects",
            Self::AutomatedRuns { .. } => "automated_runs",
            Self::AutomatedRun { .. } => "automated_run",
            Self::WebhookDeliveries { .. } => "webhook_deliveries",
            Self::SystemTaskRecorded { .. } => "system_task_recorded",
            Self::ProjectSecretSet { .. } => "project_secret_set",
            Self::ProjectSecrets { .. } => "project_secrets",
            Self::ProjectSecretRevoked { .. } => "project_secret_revoked",
            Self::TaskSecretGrant { .. } => "task_secret_grant",
            Self::CliSessionRevoked { .. } => "cli_session_revoked",
            Self::AgentPublicKey { .. } => "agent_public_key",
            Self::AgentPublicKeys { .. } => "agent_public_keys",
            Self::NodeAttached { .. } => "node_attached",
            Self::NodeEnrollmentGrantCreated { .. } => "node_enrollment_grant_created",
            Self::NodeEnrollmentExchanged { .. } => "node_enrollment_exchanged",
            Self::NodeHeartbeat { .. } => "node_heartbeat",
            Self::NodeCapabilitiesRecorded { .. } => "node_capabilities_recorded",
            Self::NodeAssignment { .. } => "node_assignment",
            Self::NodeAssignmentAcknowledged { .. } => "node_assignment_acknowledged",
            Self::NodeDrainStatus { .. } => "node_drain_status",
            Self::NodeDescriptors { .. } => "node_descriptors",
            Self::NodeSummaries { .. } => "node_summaries",
            Self::NodeCredentialRevoked { .. } => "node_credential_revoked",
            Self::TaskPlacement { .. } => "task_placement",
            Self::TaskLaunched { .. } => "task_launched",
            Self::MainLaunched { .. } => "main_launched",
            Self::TaskQueued { .. } => "task_queued",
            Self::ArtifactDataPlanePolicy { .. } => "artifact_data_plane_policy",
            Self::IrohEndpointAdvertisementAccepted { .. } => {
                "iroh_endpoint_advertisement_accepted"
            }
            Self::ArtifactTransferAuthorization { .. } => "artifact_transfer_authorization",
            Self::ArtifactProviderAssignment { .. } => "artifact_provider_assignment",
            Self::ArtifactReceiverAssignment { .. } => "artifact_receiver_assignment",
            Self::ArtifactAssignmentAcknowledged { .. } => "artifact_assignment_acknowledged",
            Self::ArtifactTransferProgressAccepted { .. } => "artifact_transfer_progress_accepted",
            Self::ArtifactReleased { .. } => "artifact_released",
            Self::SourcePreparation { .. } => "source_preparation",
            Self::SourcePreparationCompleted { .. } => "source_preparation_completed",
            Self::ProcessStarted { .. } => "process_started",
            Self::NodeReconnected { .. } => "node_reconnected",
            Self::TaskCancellationRequested { .. } => "task_cancellation_requested",
            Self::ProcessCancellationRequested { .. } => "process_cancellation_requested",
            Self::ProcessAborted { .. } => "process_aborted",
            Self::ProcessStatuses { .. } => "process_statuses",
            Self::ProcessSummaries { .. } => "process_summaries",
            Self::QuotaStatus { .. } => "quota_status",
            Self::TaskControl { .. } => "task_control",
            Self::TaskRestart { .. } => "task_restart",
            Self::DebugCommand { .. } => "debug_command",
            Self::DebugStateRecorded { .. } => "debug_state_recorded",
            Self::DebugAttach { .. } => "debug_attach",
            Self::DebugBreakpoints { .. } => "debug_breakpoints",
            Self::DebugProbeHit { .. } => "debug_probe_hit",
            Self::DebugEpoch { .. } => "debug_epoch",
            Self::DebugEpochStatus { .. } => "debug_epoch_status",
            Self::TaskLogRecorded { .. } => "task_log_recorded",
            Self::TaskLogChunkRecorded { .. } => "task_log_chunk_recorded",
            Self::RecentLogs { .. } => "recent_logs",
            Self::VfsMetadataRecorded { .. } => "vfs_metadata_recorded",
            Self::TaskRecorded { .. } => "task_recorded",
            Self::TaskEvents { .. } => "task_events",
            Self::TaskSnapshots { .. } => "task_snapshots",
            Self::TaskFailureResolved { .. } => "task_failure_resolved",
            Self::TaskJoined { .. } => "task_joined",
            Self::OperatorPanel { .. } => "operator_panel",
            Self::PanelEventAccepted { .. } => "panel_event_accepted",
            Self::ArtifactDownloadLink { .. } => "artifact_download_link",
            Self::Artifacts { .. } => "artifacts",
            Self::Artifact { .. } => "artifact",
            Self::ArtifactDownloadLinkRevoked { .. } => "artifact_download_link_revoked",
            Self::ArtifactExport { .. } => "artifact_export",
            Self::Error { .. } => "error",
        }
    }

    pub fn error(request_id: impl Into<String>, message: impl Into<String>) -> Self {
        Self::Error {
            error: clusterflux_core::ApiError::from_message(request_id, message),
        }
    }
}
