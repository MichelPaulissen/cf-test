// Request handlers intentionally spell out their deserialized protocol fields.
// Keeping those authority and payload values explicit at this boundary is safer
// than passing an unvalidated wire request deeper into the service.
#![allow(clippy::too_many_arguments)]

use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{
    Actor, AgentId, ApiError, ApiErrorCategory, ApiErrorCode, AutomatedRunState,
    CapabilityReportError, CredentialKind, Digest, DownloadError, LimitError, NodeId, PanelError,
    ProcessId, ProjectId, TenantId, UserId,
};
use clusterflux_wasm_runtime::{WasmtimeRuntimeLimits, DEFAULT_MAX_RESIDENT_INVOCATIONS};
use thiserror::Error;

use crate::{Coordinator, CoordinatorError};

mod admin;
mod artifact_registry;
mod artifacts;
mod authenticated;
mod authorization;
mod automation;
mod debug;
mod debug_registry;
mod debug_requests;
mod durable_runtime;
mod interchange;
mod interchange_registry;
mod keys;
mod logs;
mod main_runtime;
mod node_registry;
mod nodes;
mod panels;
mod process_launch;
mod process_registry;
mod processes;
mod protocol;
mod quota;
mod recent_log_store;
mod replay_registry;
mod routing;
mod secrets;
mod signed_nodes;
mod summaries;
mod task_registry;
mod tcp;
pub use admin::{HostedAccountMutationResult, HostedTenantAdminStatus};
use artifact_registry::ArtifactRegistry;
use authorization::authorize_authenticated_user_operation;
use debug_registry::DebugRegistry;
use durable_runtime::RuntimeDurableStore;
pub use interchange::CoordinatorArtifactInterchangeConfiguration;
use interchange_registry::{AssignmentAcknowledgementError, InterchangeRegistry};
use keys::{artifact_id_from_path, enrollment_grant_key};
use node_registry::{EndpointAdvertisementError, NodeRegistry, SourceSnapshotAdmissionError};
use panels::PanelRegistry;
use process_registry::ProcessRegistry;
pub use protocol::{
    ArtifactAvailability, ArtifactRetentionState, ArtifactSummary, AuthenticatedCoordinatorRequest,
    CoordinatorRequest, CoordinatorResponse, CoordinatorWireRequest, DebugAcknowledgementState,
    DebugAuditEvent, DebugEpochSummary, DebugParticipantAcknowledgement, NodeSummary,
    ProcessActivityState, ProcessFinalResult, ProcessLifecycleState, ProcessSummary,
    RecentLogEntry, SourcePreparationDisposition, SourcePreparationStatus, TaskAssignment,
    TaskAttemptSnapshot, TaskAttemptState, TaskCancellationTarget, TaskCompletionEvent,
    TaskExecutor, TaskFailureResolution, TaskLogStream, TaskReplacementBundle, TaskTerminalState,
    VirtualProcessStatus, WorkflowActor,
};
pub use quota::{AdmissionQuotaLimits, CoordinatorQuotaConfiguration};
use recent_log_store::RecentLogStore;
use replay_registry::{ReplayAdmissionError, ReplayRegistry};
use secrets::SecretCipher;
use task_registry::TaskRegistry;
pub use tcp::{bind_listener, ClientAuthorityMode};

const MAX_TASK_LOG_TAIL_BYTES: usize = 256 * 1024;
const DEBUG_CONTROL_READ_BYTES: u64 = 1024;
const MAX_REPLAY_NONCES_PER_AUTHORITY: usize = 1_024;
const NODE_SIGNATURE_WINDOW_SECONDS: u64 = 30;
const MAX_NODE_REPLAY_NONCES_PER_AUTHORITY: usize = 4_096;
const MAX_ENROLLMENT_GRANTS_PER_PROJECT: usize = 64;
const MAX_TASK_EVENTS_PER_PROCESS: usize = 128;
const MAX_DEBUG_AUDIT_EVENTS_PER_PROCESS: usize = 256;
const MAX_RESTART_CHECKPOINTS_PER_PROCESS: usize = 128;
const MAX_TASK_EVENTS_TOTAL: usize = 8_192;
const MAX_DEBUG_AUDIT_EVENTS_TOTAL: usize = 8_192;
const MAX_RESTART_CHECKPOINTS_TOTAL: usize = 4_096;
const MAX_TASK_ATTEMPT_HISTORIES: usize = 1_000_000;
const MAX_IN_FLIGHT_TASKS_PER_PROCESS: usize = 256;
const MAX_NODE_REPORTED_OBJECTS_PER_KIND: usize = 1_024;
const MAX_RECENT_LOG_ENTRIES_PER_PROCESS: usize = 256;
const MAX_RECENT_LOG_ENTRIES_PER_PROJECT: usize = 1_024;
const MAX_RECENT_LOG_BYTES_PER_PROJECT: usize = 512 * 1024;
const MAX_RECENT_LOG_CHUNK_BYTES: usize = 16 * 1024;
const MAX_RECENT_PROCESS_SUMMARIES_PER_PROJECT: usize = 32;
const MAX_RECENT_PROCESS_SUMMARIES_TOTAL: usize = 8_192;
const DEFAULT_NODE_STALE_AFTER_SECONDS: u64 = 30;
const MAX_NODE_STALE_AFTER_SECONDS: u64 = 24 * 60 * 60;
const MAX_COORDINATOR_NESTED_JOIN_TIMEOUT_MS: u64 = 24 * 60 * 60 * 1_000;
const MAX_COORDINATOR_WAKEUPS_PER_MINUTE: u64 = 1_000_000;
pub const MAX_COORDINATOR_MAINS: usize = DEFAULT_MAX_RESIDENT_INVOCATIONS;
fn bounded_ttl(requested: u64, maximum: u64) -> u64 {
    requested.clamp(1, maximum)
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorMainRuntimeConfiguration {
    pub fuel_units_per_second: u64,
    pub fuel_burst_seconds: u64,
    pub memory_bytes: usize,
    pub nested_join_timeout_ms: u64,
    pub max_active_mains: usize,
    pub max_wakeups_per_minute: u64,
    pub max_output_bytes: usize,
    pub max_state_bytes: usize,
}

impl CoordinatorMainRuntimeConfiguration {
    pub fn validate(&self) -> Result<(), String> {
        if self.nested_join_timeout_ms == 0
            || self.nested_join_timeout_ms > MAX_COORDINATOR_NESTED_JOIN_TIMEOUT_MS
            || self.max_active_mains == 0
            || self.max_active_mains > MAX_COORDINATOR_MAINS
            || self.max_wakeups_per_minute == 0
            || self.max_wakeups_per_minute > MAX_COORDINATOR_WAKEUPS_PER_MINUTE
            || self.max_output_bytes == 0
            || self.max_output_bytes > MAX_TASK_LOG_TAIL_BYTES
            || self.max_state_bytes == 0
            || self.max_state_bytes > clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES
        {
            return Err(format!(
                "coordinator main limits are zero or exceed the bounded runtime ceilings (max_active_mains={MAX_COORDINATOR_MAINS})"
            ));
        }
        WasmtimeRuntimeLimits {
            fuel_units_per_second: self.fuel_units_per_second,
            fuel_burst_seconds: self.fuel_burst_seconds,
            memory_bytes: self.memory_bytes,
        }
        .validate()
        .map_err(|error| error.to_string())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CoordinatorServiceStartupConfiguration {
    pub node_stale_after_seconds: u64,
}

impl Default for CoordinatorServiceStartupConfiguration {
    fn default() -> Self {
        Self {
            node_stale_after_seconds: DEFAULT_NODE_STALE_AFTER_SECONDS,
        }
    }
}

impl CoordinatorServiceStartupConfiguration {
    pub fn validate(self) -> Result<Self, String> {
        if !(1..=MAX_NODE_STALE_AFTER_SECONDS).contains(&self.node_stale_after_seconds) {
            return Err(format!(
                "node stale interval must be between 1 and {MAX_NODE_STALE_AFTER_SECONDS} seconds"
            ));
        }
        Ok(self)
    }
}

impl Default for CoordinatorMainRuntimeConfiguration {
    fn default() -> Self {
        Self {
            fuel_units_per_second: 10_000_000,
            fuel_burst_seconds: 60,
            memory_bytes: 256 * 1024 * 1024,
            nested_join_timeout_ms: 24 * 60 * 60 * 1_000,
            max_active_mains: MAX_COORDINATOR_MAINS,
            max_wakeups_per_minute: 6_000,
            max_output_bytes: MAX_TASK_LOG_TAIL_BYTES,
            max_state_bytes: clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CoordinatorAdmission {
    pub workflow_placement_allowed: bool,
    pub max_node_enrollment_ttl_seconds: u64,
    pub max_artifact_download_ttl_seconds: u64,
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct CoordinatorOperationalMetrics {
    pub tenants: usize,
    pub users: usize,
    pub projects: usize,
    pub enrolled_nodes: usize,
    pub reported_nodes: usize,
    pub live_nodes: usize,
    pub active_processes: usize,
    pub active_coordinator_mains: usize,
    pub max_active_coordinator_mains: usize,
    pub active_tasks: usize,
    pub queued_tasks: usize,
    pub artifacts: usize,
    pub retained_download_links: usize,
    pub artifact_direct_body_bytes: u64,
    pub artifact_relayed_body_bytes: u64,
    pub artifact_unknown_path_body_bytes: u64,
    pub system_assignments_pending: usize,
    pub system_assignments_running: usize,
    pub system_assignments_failed: usize,
    pub compile_wait_seconds: u64,
    pub compile_duration_seconds: u64,
    pub compile_result_bytes: usize,
    pub system_bundle_mismatches: usize,
    pub node_policy_rejections: usize,
}

impl Default for CoordinatorAdmission {
    fn default() -> Self {
        Self {
            workflow_placement_allowed: true,
            max_node_enrollment_ttl_seconds: 15 * 60,
            max_artifact_download_ttl_seconds: 15 * 60,
        }
    }
}

#[derive(Debug, Error)]
pub enum CoordinatorServiceError {
    #[error("coordinator protocol I/O error: {0}")]
    Io(#[from] std::io::Error),
    #[error("coordinator protocol JSON error: {0}")]
    Json(#[from] serde_json::Error),
    #[error("coordinator protocol error: {0}")]
    Protocol(String),
    #[error("coordinator request failed: {0}")]
    Coordinator(#[from] CoordinatorError),
    #[error("artifact download request failed: {0}")]
    Download(#[from] clusterflux_core::DownloadError),
    #[error("scheduler placement failed: {0}")]
    Scheduler(#[from] clusterflux_core::PlacementError),
    #[error("resource limit failed: {0}")]
    Resource(#[from] LimitError),
    #[error("operator panel request failed: {0}")]
    Panel(#[from] clusterflux_core::PanelError),
    #[error("invalid node capability report: {0}")]
    CapabilityReport(#[from] CapabilityReportError),
    #[error("invalid VFS artifact path reported by node: {0}")]
    InvalidArtifactPath(String),
    #[error("invalid task log tail reported by node: {0}")]
    InvalidTaskLogTail(String),
    #[error("terminal node operation conflicts with its previously committed payload")]
    TerminalOperationConflict,
    #[error("node assignment acknowledgement is stale or outside node scope")]
    StaleNodeAssignmentAcknowledgement,
    #[error("node identity quota exceeded ({current} of {maximum})")]
    NodeIdentityQuota { current: u64, maximum: u64 },
    #[error("project quota exceeded ({current} of {maximum})")]
    ProjectQuota { current: u64, maximum: u64 },
    #[error("active process quota exceeded ({current} of {maximum})")]
    ActiveProcessQuota { current: u64, maximum: u64 },
    #[error("durable coordinator state failed: {0}")]
    Durable(String),
}

impl CoordinatorServiceError {
    pub fn api_error(&self, request_id: impl Into<String>) -> ApiError {
        let request_id = request_id.into();
        let message = self.to_string();
        let (code, category, retryable) = match self {
            Self::Io(_) => (
                ApiErrorCode::TemporaryCapacity,
                ApiErrorCategory::Availability,
                true,
            ),
            Self::Json(_)
            | Self::CapabilityReport(_)
            | Self::InvalidArtifactPath(_)
            | Self::InvalidTaskLogTail(_) => (
                ApiErrorCode::ValidationError,
                ApiErrorCategory::Validation,
                false,
            ),
            Self::Protocol(_) | Self::Coordinator(CoordinatorError::Unauthorized(_)) => {
                return ApiError::from_message(request_id, message);
            }
            Self::Coordinator(CoordinatorError::UnknownNode) => {
                (ApiErrorCode::NotFound, ApiErrorCategory::State, false)
            }
            Self::Coordinator(CoordinatorError::Enrollment(_)) => (
                ApiErrorCode::Unauthenticated,
                ApiErrorCategory::Authentication,
                false,
            ),
            Self::Coordinator(CoordinatorError::StaleProcessEpoch { .. }) => {
                (ApiErrorCode::Conflict, ApiErrorCategory::State, true)
            }
            Self::TerminalOperationConflict => {
                (ApiErrorCode::Conflict, ApiErrorCategory::State, false)
            }
            Self::StaleNodeAssignmentAcknowledgement => {
                (ApiErrorCode::Conflict, ApiErrorCategory::State, true)
            }
            Self::Download(DownloadError::NotFound) => {
                (ApiErrorCode::NotFound, ApiErrorCategory::State, false)
            }
            Self::Download(DownloadError::Unavailable)
            | Self::Download(DownloadError::DirectConnectivityUnavailable(_)) => (
                ApiErrorCode::ArtifactUnavailable,
                ApiErrorCategory::Availability,
                true,
            ),
            Self::Download(DownloadError::LimitExceeded { .. }) => (
                ApiErrorCode::ArtifactLimitExceeded,
                ApiErrorCategory::Resource,
                false,
            ),
            Self::Download(DownloadError::Unauthorized(_))
            | Self::Download(DownloadError::InvalidToken) => (
                ApiErrorCode::Forbidden,
                ApiErrorCategory::Authorization,
                false,
            ),
            Self::Download(DownloadError::Usage(_)) | Self::Resource(_) => (
                ApiErrorCode::QuotaExceeded,
                ApiErrorCategory::Resource,
                true,
            ),
            Self::Scheduler(_) => (
                ApiErrorCode::NoCapableNode,
                ApiErrorCategory::Availability,
                true,
            ),
            Self::Panel(PanelError::RateLimited | PanelError::LimitExceeded(_)) => (
                ApiErrorCode::QuotaExceeded,
                ApiErrorCategory::Resource,
                true,
            ),
            Self::Panel(PanelError::UnknownWidget(_)) => {
                (ApiErrorCode::NotFound, ApiErrorCategory::State, false)
            }
            Self::Panel(_) => (
                ApiErrorCode::Forbidden,
                ApiErrorCategory::Authorization,
                false,
            ),
            Self::NodeIdentityQuota { .. }
            | Self::ProjectQuota { .. }
            | Self::ActiveProcessQuota { .. } => (
                ApiErrorCode::QuotaExceeded,
                ApiErrorCategory::Resource,
                false,
            ),
            Self::Durable(_) => (
                ApiErrorCode::InternalError,
                ApiErrorCategory::Internal,
                true,
            ),
        };
        let error = ApiError::new(code, category, message, retryable, request_id);
        if let Self::NodeIdentityQuota { current, maximum } = self {
            return error.with_quota_details(
                "node_identity",
                *current,
                *maximum,
                [
                    "clusterflux node list".to_owned(),
                    "clusterflux node revoke <node-id> --yes".to_owned(),
                ],
            );
        }
        if let Self::ProjectQuota { current, maximum } = self {
            return error.with_quota_details(
                "project",
                *current,
                *maximum,
                ["clusterflux project list".to_owned()],
            );
        }
        if let Self::ActiveProcessQuota { current, maximum } = self {
            return error.with_quota_details(
                "active_process",
                *current,
                *maximum,
                ["clusterflux process list".to_owned()],
            );
        }
        error
    }
}

pub fn coordinator_service_error_response(
    request_id: impl Into<String>,
    error: &CoordinatorServiceError,
) -> CoordinatorResponse {
    CoordinatorResponse::Error {
        error: error.api_error(request_id),
    }
}

/// Runtime façade over one explicit durable owner (`Coordinator`) and bounded,
/// restart-ephemeral service registries. Registry implementation maps are never
/// serialized; restart-surviving state is converted only through `DurableState`.
pub struct CoordinatorService {
    coordinator: Coordinator,
    store: RuntimeDurableStore,
    node_registry: NodeRegistry,
    node_stale_after_seconds: u64,
    debug_freeze_timeout: std::time::Duration,
    process_registry: ProcessRegistry,
    task_registry: TaskRegistry,
    recent_log_store: RecentLogStore,
    debug_registry: DebugRegistry,
    main_runtime: main_runtime::CoordinatorMainRuntime,
    replay_registry: ReplayRegistry,
    panel_registry: PanelRegistry,
    artifact_registry: ArtifactRegistry,
    interchange_registry: InterchangeRegistry,
    artifact_interchange_configuration: CoordinatorArtifactInterchangeConfiguration,
    quota: quota::CoordinatorQuota,
    admission: CoordinatorAdmission,
    #[cfg(test)]
    server_time_override: Option<u64>,
    admin_token_digest: Option<Digest>,
    secret_cipher: Option<SecretCipher>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TaskCompletionOrigin {
    SignedNode,
    ExpiredAssignment,
}

impl CoordinatorService {
    pub fn project_record(&self, project: &ProjectId) -> Option<&crate::ProjectRecord> {
        self.coordinator.project(project)
    }

    pub fn operational_metrics(&self) -> CoordinatorOperationalMetrics {
        let (
            artifact_direct_body_bytes,
            artifact_relayed_body_bytes,
            artifact_unknown_path_body_bytes,
        ) = self.interchange_registry.metrics();
        let now = self.liveness_now_epoch_seconds();
        let automated_runs = self.coordinator.durable_state().automated_runs.values();
        let system_assignments_pending = automated_runs
            .clone()
            .filter(|record| record.run.state == AutomatedRunState::WaitingForCompilerNode)
            .count();
        let system_assignments_running = automated_runs
            .clone()
            .filter(|record| record.run.state == AutomatedRunState::CompilingWorkflow)
            .count();
        let system_assignments_failed = automated_runs
            .clone()
            .filter(|record| {
                record.run.state == AutomatedRunState::Failed
                    && record.run.failure_code.as_deref().is_some_and(|code| {
                        code.starts_with("compile") || code.starts_with("system_assignment")
                    })
            })
            .count();
        let compile_wait_seconds = automated_runs
            .clone()
            .filter(|record| record.run.state == AutomatedRunState::WaitingForCompilerNode)
            .map(|record| now.saturating_sub(record.run.created_at))
            .sum();
        let compile_duration_seconds = automated_runs
            .clone()
            .filter(|record| record.run.state == AutomatedRunState::CompilingWorkflow)
            .filter_map(|record| {
                TaskRegistry::active_assignment_for_kind(
                    self.coordinator.durable_state(),
                    &crate::AssignmentKind::WorkflowCompiler {
                        run_id: record.run.run_id.clone(),
                    },
                )
                .and_then(|active| active.acknowledged_at)
            })
            .map(|acknowledged_at| now.saturating_sub(acknowledged_at))
            .sum();
        let system_bundle_mismatches = automated_runs
            .clone()
            .filter(|record| {
                record.run.waiting_reason.as_deref()
                    == Some("system_bundle_version_mismatch_or_unavailable")
            })
            .count();
        let node_policy_rejections = automated_runs
            .clone()
            .filter(|record| {
                record.run.waiting_reason.as_deref()
                    == Some("node_policy_disables_workflow_compilation")
            })
            .count();
        let compile_result_bytes = automated_runs
            .filter_map(|record| record.compiled_bundle.as_ref())
            .map(|bundle| {
                bundle
                    .module_base64
                    .len()
                    .saturating_add(bundle.debug_metadata_base64.len())
            })
            .sum();
        CoordinatorOperationalMetrics {
            tenants: self.coordinator.tenant_count(),
            users: self.coordinator.user_count(),
            projects: self.coordinator.project_count(),
            enrolled_nodes: self.coordinator.node_identity_count(),
            reported_nodes: self.node_registry.reported_count(),
            live_nodes: self.node_registry.live_count(
                self.liveness_now_epoch_seconds(),
                self.node_stale_after_seconds,
            ),
            active_processes: self.coordinator.active_process_count(),
            active_coordinator_mains: self.main_runtime.active_main_count(),
            max_active_coordinator_mains: self.main_runtime.max_active_mains(),
            active_tasks: self.task_registry.active_count(),
            queued_tasks: self.task_registry.pending_count(),
            artifacts: self.artifact_registry.artifact_count(),
            retained_download_links: self.artifact_registry.retained_download_link_count(),
            artifact_direct_body_bytes,
            artifact_relayed_body_bytes,
            artifact_unknown_path_body_bytes,
            system_assignments_pending,
            system_assignments_running,
            system_assignments_failed,
            compile_wait_seconds,
            compile_duration_seconds,
            compile_result_bytes,
            system_bundle_mismatches,
            node_policy_rejections,
        }
    }

    pub fn set_debug_freeze_timeout(&mut self, timeout: std::time::Duration) {
        self.debug_freeze_timeout = timeout.max(std::time::Duration::from_millis(1));
    }

    pub fn configure_coordinator_main_runtime(
        &mut self,
        configuration: CoordinatorMainRuntimeConfiguration,
    ) -> Result<(), CoordinatorServiceError> {
        self.main_runtime.configure(configuration)
    }

    pub fn record_service_policy(
        &mut self,
        tenant: TenantId,
        name: impl Into<String>,
        digest: Digest,
    ) -> Result<crate::ServicePolicyRecord, CoordinatorServiceError> {
        let name = name.into();
        self.coordinator
            .upsert_service_policy_record(tenant.clone(), name.clone(), digest);
        self.persist_durable_state()?;
        Ok(self
            .coordinator
            .service_policy_record(&tenant, &name)
            .expect("service policy record was persisted immediately after insertion")
            .clone())
    }

    pub(super) fn authorize_node_for_process_or_termination(
        &self,
        node: &NodeId,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> Result<(), CoordinatorServiceError> {
        let process_key = keys::process_control_key(tenant, project, process);
        if self.process_registry.is_stopping(&process_key) {
            let identity = self
                .coordinator
                .node_identity(tenant, project, node)
                .ok_or(CoordinatorError::UnknownNode)?;
            debug_assert_eq!(&identity.tenant, tenant);
            debug_assert_eq!(&identity.project, project);
            return Ok(());
        }
        self.coordinator
            .authorize_node_for_process(node, tenant, project, process)?;
        Ok(())
    }

    pub fn new(coordinator_epoch: u64) -> Self {
        Self::new_with_optional_admin_token_and_admission(
            coordinator_epoch,
            std::env::var("CLUSTERFLUX_ADMIN_TOKEN").ok(),
            CoordinatorAdmission::default(),
        )
    }

    pub fn new_with_admin_token(coordinator_epoch: u64, admin_token: impl Into<String>) -> Self {
        Self::new_with_optional_admin_token_and_admission(
            coordinator_epoch,
            Some(admin_token.into()),
            CoordinatorAdmission::default(),
        )
    }

    pub fn new_with_admission(coordinator_epoch: u64, admission: CoordinatorAdmission) -> Self {
        Self::new_with_optional_admin_token_and_admission(
            coordinator_epoch,
            std::env::var("CLUSTERFLUX_ADMIN_TOKEN").ok(),
            admission,
        )
    }

    fn new_with_optional_admin_token_and_admission(
        coordinator_epoch: u64,
        admin_token: Option<String>,
        admission: CoordinatorAdmission,
    ) -> Self {
        Self::try_new_with_optional_admin_token_admission_and_database_url(
            coordinator_epoch,
            admin_token,
            admission,
            None,
            CoordinatorQuotaConfiguration::default(),
            CoordinatorServiceStartupConfiguration::default(),
        )
        .expect("in-memory durable coordinator store initialization cannot fail")
    }

    pub fn new_with_database_url(
        coordinator_epoch: u64,
        database_url: Option<&str>,
    ) -> Result<Self, CoordinatorServiceError> {
        Self::try_new_with_optional_admin_token_admission_and_database_url(
            coordinator_epoch,
            std::env::var("CLUSTERFLUX_ADMIN_TOKEN").ok(),
            CoordinatorAdmission::default(),
            database_url,
            CoordinatorQuotaConfiguration::default(),
            CoordinatorServiceStartupConfiguration::default(),
        )
    }

    pub fn new_with_admin_token_and_database_url(
        coordinator_epoch: u64,
        admin_token: impl Into<String>,
        database_url: Option<&str>,
    ) -> Result<Self, CoordinatorServiceError> {
        Self::new_with_admin_token_database_url_and_quota(
            coordinator_epoch,
            admin_token,
            database_url,
            CoordinatorQuotaConfiguration::default(),
        )
    }

    pub fn new_with_admin_token_database_url_and_quota(
        coordinator_epoch: u64,
        admin_token: impl Into<String>,
        database_url: Option<&str>,
        quota_configuration: CoordinatorQuotaConfiguration,
    ) -> Result<Self, CoordinatorServiceError> {
        Self::new_with_admin_token_database_url_quota_and_startup(
            coordinator_epoch,
            admin_token,
            database_url,
            quota_configuration,
            CoordinatorServiceStartupConfiguration::default(),
        )
    }

    pub fn new_with_admin_token_database_url_quota_and_startup(
        coordinator_epoch: u64,
        admin_token: impl Into<String>,
        database_url: Option<&str>,
        quota_configuration: CoordinatorQuotaConfiguration,
        startup: CoordinatorServiceStartupConfiguration,
    ) -> Result<Self, CoordinatorServiceError> {
        Self::try_new_with_optional_admin_token_admission_and_database_url(
            coordinator_epoch,
            Some(admin_token.into()),
            CoordinatorAdmission::default(),
            database_url,
            quota_configuration,
            startup,
        )
    }

    pub fn new_with_startup_configuration(
        coordinator_epoch: u64,
        admin_token: Option<String>,
        database_url: Option<&str>,
        startup: CoordinatorServiceStartupConfiguration,
    ) -> Result<Self, CoordinatorServiceError> {
        Self::try_new_with_optional_admin_token_admission_and_database_url(
            coordinator_epoch,
            admin_token,
            CoordinatorAdmission::default(),
            database_url,
            CoordinatorQuotaConfiguration::default(),
            startup,
        )
    }

    fn try_new_with_optional_admin_token_admission_and_database_url(
        coordinator_epoch: u64,
        admin_token: Option<String>,
        admission: CoordinatorAdmission,
        database_url: Option<&str>,
        quota_configuration: CoordinatorQuotaConfiguration,
        startup: CoordinatorServiceStartupConfiguration,
    ) -> Result<Self, CoordinatorServiceError> {
        let startup = startup
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        let mut store = RuntimeDurableStore::from_database_url(database_url)
            .map_err(CoordinatorServiceError::Durable)?;
        let coordinator = Coordinator::try_boot(&mut store, coordinator_epoch)
            .map_err(CoordinatorServiceError::Durable)?;
        let admin_token_digest = admin_token
            .filter(|token| !token.trim().is_empty())
            .map(Digest::sha256);
        let secret_cipher = SecretCipher::from_environment(
            std::env::var_os("CLUSTERFLUX_REQUIRE_SECRET_ENCRYPTION_KEY").is_some(),
        )?;
        let mut service = Self {
            coordinator,
            store,
            node_registry: NodeRegistry::default(),
            node_stale_after_seconds: startup.node_stale_after_seconds,
            debug_freeze_timeout: std::time::Duration::from_secs(5),
            process_registry: ProcessRegistry::default(),
            task_registry: TaskRegistry::default(),
            recent_log_store: RecentLogStore::default(),
            debug_registry: DebugRegistry::default(),
            main_runtime: main_runtime::CoordinatorMainRuntime::new()?,
            replay_registry: ReplayRegistry::default(),
            panel_registry: PanelRegistry::default(),
            artifact_registry: ArtifactRegistry::default(),
            interchange_registry: InterchangeRegistry::default(),
            artifact_interchange_configuration:
                CoordinatorArtifactInterchangeConfiguration::default(),
            quota: quota::CoordinatorQuota::new(quota_configuration),
            admission,
            #[cfg(test)]
            server_time_override: None,
            admin_token_digest,
            secret_cipher,
        };
        service.reconcile_active_assignments_after_coordinator_restart()?;
        service.reconcile_automated_runs_after_coordinator_restart()?;
        Ok(service)
    }

    pub fn durable_store_kind(&self) -> &'static str {
        self.store.kind()
    }

    fn persist_durable_state(&mut self) -> Result<(), CoordinatorServiceError> {
        self.coordinator
            .try_persist(&mut self.store)
            .map_err(CoordinatorServiceError::Durable)
    }

    fn current_epoch_seconds(&self) -> Result<u64, CoordinatorServiceError> {
        #[cfg(test)]
        if let Some(now) = self.server_time_override {
            return Ok(now);
        }
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|duration| duration.as_secs())
            .map_err(|err| CoordinatorServiceError::Protocol(format!("system clock error: {err}")))
    }

    fn handle_quota_status(
        &self,
        tenant: String,
        project: String,
        actor_user: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let actor = UserId::new(actor_user);
        let durable_project = self.coordinator.project(&project).ok_or_else(|| {
            CoordinatorError::Unauthorized("quota status requires an existing project".to_owned())
        })?;
        if durable_project.tenant != tenant {
            return Err(CoordinatorError::Unauthorized(
                "quota status project is outside the tenant scope".to_owned(),
            )
            .into());
        }
        let now_epoch_seconds = self.current_epoch_seconds()?;
        let status = self
            .quota
            .project_status(&tenant, &project, now_epoch_seconds);
        let admission_limits = self.quota.effective_admission_limits(
            self.coordinator
                .tenant_quota_override(&tenant)
                .map(|record| &record.values),
        );
        Ok(CoordinatorResponse::QuotaStatus {
            tenant: tenant.clone(),
            project,
            actor,
            policy_label: status.policy_label,
            limits: status.limits,
            window_seconds: status.window_seconds,
            usage: status.usage,
            window_started_epoch_seconds: status.window_started_epoch_seconds,
            projects_current: u64::try_from(self.coordinator.project_count_for_tenant(&tenant))
                .unwrap_or(u64::MAX),
            projects_maximum: admission_limits.max_projects,
            node_identities_current: u64::try_from(
                self.coordinator.node_identity_count_for_tenant(&tenant),
            )
            .unwrap_or(u64::MAX),
            node_identities_maximum: admission_limits.max_nodes,
            active_processes_current: u64::try_from(
                self.coordinator.active_process_count_for_tenant(&tenant),
            )
            .unwrap_or(u64::MAX),
            active_processes_maximum: admission_limits.max_active_processes,
        })
    }

    #[cfg(test)]
    fn set_server_time(&mut self, now_epoch_seconds: u64) {
        self.server_time_override = Some(now_epoch_seconds);
    }

    pub fn issue_cli_session(
        &mut self,
        tenant: TenantId,
        project: ProjectId,
        user: UserId,
        session_secret: &str,
        expires_at_epoch_seconds: Option<u64>,
    ) -> Result<crate::CliSessionRecord, CoordinatorServiceError> {
        self.coordinator.ensure_tenant_active(&tenant)?;
        if let Some(existing) = self.coordinator.project(&project) {
            if existing.tenant != tenant {
                return Err(CoordinatorError::Unauthorized(
                    "CLI session project belongs to a different tenant".to_owned(),
                )
                .into());
            }
        } else {
            self.coordinator
                .upsert_project(tenant.clone(), project.clone(), "Session project");
        }
        self.coordinator
            .grant_project_debug(tenant.clone(), project.clone(), user.clone());
        let record = self.coordinator.issue_cli_session(
            tenant,
            project,
            user,
            session_secret,
            expires_at_epoch_seconds,
        );
        self.persist_durable_state()?;
        Ok(record)
    }

    pub fn authenticate_cli_session_context(
        &self,
        session_secret: &str,
    ) -> Result<clusterflux_core::AuthContext, CoordinatorServiceError> {
        Ok(self.coordinator.authenticate_cli_session(session_secret)?)
    }

    pub fn authenticate_cli_session_status_context(
        &self,
        session_secret: &str,
    ) -> Result<clusterflux_core::AuthContext, CoordinatorServiceError> {
        Ok(self
            .coordinator
            .authenticate_cli_session_for_status(session_secret)?)
    }

    pub fn charge_authenticated_api_call(
        &mut self,
        context: &clusterflux_core::AuthContext,
    ) -> Result<(), CoordinatorServiceError> {
        let now_epoch_seconds = self.current_epoch_seconds()?;
        self.quota
            .charge_api_call(&context.tenant, &context.project, now_epoch_seconds)?;
        Ok(())
    }

    pub fn revoke_cli_session(
        &mut self,
        session_secret: &str,
    ) -> Result<crate::CliSessionRecord, CoordinatorServiceError> {
        let record = self.coordinator.revoke_cli_session(session_secret)?;
        self.persist_durable_state()?;
        Ok(record)
    }
}

#[cfg(test)]
mod tests;
