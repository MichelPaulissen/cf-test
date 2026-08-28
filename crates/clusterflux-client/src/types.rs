use std::collections::BTreeMap;
use std::fmt;

use clusterflux_core::{
    Authorization, LimitKind, NodeId, ProcessId, ProjectId, ResourceLimits, TaskInstanceId,
    TenantId, UserId,
};
use serde::{Deserialize, Serialize};

pub use clusterflux_protocol::{
    AgentPublicKeyRecord as AgentPublicKey, ArtifactAvailability, ArtifactRetentionState,
    ArtifactSummary, DebugAcknowledgementState, DebugAuditEvent, DebugEpochSummary,
    DebugParticipantAcknowledgement, NodeSummary, ProcessActivityState, ProcessFinalResult,
    ProcessLifecycleState, ProcessSummary, ProjectRecord as Project, RecentLogEntry,
    TaskAttemptSnapshot, TaskAttemptState, TaskCancellationTarget, TaskCompletionEvent,
    TaskExecutor, TaskFailureResolution, TaskLogStream, TaskReplacementBundle, TaskTerminalState,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AccountStatus {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub actor: UserId,
    pub authenticated: bool,
    pub account_status: String,
    pub suspended: bool,
    pub disabled: bool,
    pub deleted: bool,
    pub manual_review: bool,
    pub sanitized_reason: Option<String>,
    pub next_actions: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeEnrollmentGrant {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub grant: String,
    pub scope: String,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodePage {
    pub nodes: Vec<NodeSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeRevocation {
    pub node: NodeId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub actor: UserId,
    pub descriptor_removed: bool,
    pub queued_assignments_removed: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessPage {
    pub processes: Vec<ProcessSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutomatedRunPage {
    pub runs: Vec<clusterflux_core::AutomatedRunRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct WebhookDeliveryPage {
    pub deliveries: Vec<clusterflux_core::WebhookDeliveryRecord>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RecentLogPage {
    pub entries: Vec<RecentLogEntry>,
    pub next_sequence: Option<u64>,
    pub history_truncated: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactPage {
    pub artifacts: Vec<ArtifactSummary>,
    pub next_cursor: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct QuotaStatus {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub actor: UserId,
    pub policy_label: Option<String>,
    pub limits: ResourceLimits,
    pub window_seconds: BTreeMap<LimitKind, u64>,
    pub usage: BTreeMap<LimitKind, u64>,
    pub window_started_epoch_seconds: BTreeMap<LimitKind, u64>,
    pub projects_current: u64,
    pub projects_maximum: u64,
    pub node_identities_current: u64,
    pub node_identities_maximum: u64,
    pub active_processes_current: u64,
    pub active_processes_maximum: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessCancellation {
    pub process: ProcessId,
    pub affected_tasks: Vec<TaskCancellationTarget>,
    pub affected_nodes: Vec<NodeId>,
    pub aborted: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugAttach {
    pub process: ProcessId,
    pub actor: UserId,
    pub authorization: Authorization,
    pub audit_event: DebugAuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugEpochControl {
    pub process: ProcessId,
    pub actor: UserId,
    pub epoch: u64,
    pub command: String,
    pub affected_tasks: Vec<TaskCancellationTarget>,
    pub all_stop_requested: bool,
    pub audit_event: DebugAuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugEpochStatus {
    pub process: ProcessId,
    pub actor: UserId,
    pub epoch: u64,
    pub command: String,
    pub expected_tasks: Vec<TaskCancellationTarget>,
    pub acknowledgements: Vec<DebugParticipantAcknowledgement>,
    pub fully_frozen: bool,
    pub partially_frozen: bool,
    pub fully_resumed: bool,
    pub failed: bool,
    pub failure_messages: Vec<String>,
    pub audit_event: DebugAuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskRestart {
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub restarted_task_instance: Option<TaskInstanceId>,
    pub restarted_attempt_id: Option<String>,
    pub actor: UserId,
    pub accepted: bool,
    pub clean_boundary_available: bool,
    pub active_task: bool,
    pub completed_event_observed: bool,
    pub requires_whole_process_restart: bool,
    pub message: String,
    pub audit_event: DebugAuditEvent,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskFailureResolutionResult {
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub attempt_id: String,
    pub resolution: TaskFailureResolution,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct BrowserLoginStart {
    pub transaction_id: String,
    pub authorization_url: String,
    pub expires_at_epoch_seconds: u64,
}

#[derive(Clone, PartialEq, Eq)]
pub struct SessionCredential(pub(crate) String);

impl SessionCredential {
    pub fn from_secret(secret: impl Into<String>) -> Self {
        Self(secret.into())
    }

    pub fn expose_secret(&self) -> &str {
        &self.0
    }
}

impl fmt::Debug for SessionCredential {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("SessionCredential([REDACTED])")
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct BrowserSession {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub user: UserId,
    pub credential: SessionCredential,
    pub expires_at_epoch_seconds: u64,
}
