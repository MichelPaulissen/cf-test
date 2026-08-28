use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TaskReplacementBundle {
    pub bundle_digest: Digest,
    pub wasm_module_base64: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub source_snapshot: Option<Digest>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskFailureResolution {
    AcceptFailure,
    Cancel,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskTerminalState {
    Completed,
    Failed,
    Cancelled,
}

impl TaskTerminalState {
    pub fn from_status_code(status_code: Option<i32>) -> Self {
        match status_code {
            Some(0) => Self::Completed,
            _ => Self::Failed,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskExecutor {
    CoordinatorMain,
    Node,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCompletionEvent {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub node: NodeId,
    pub executor: TaskExecutor,
    pub task_definition: clusterflux_core::TaskDefinitionId,
    pub task: TaskInstanceId,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub attempt_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub placement: Option<Placement>,
    pub terminal_state: TaskTerminalState,
    pub status_code: Option<i32>,
    pub stdout_bytes: u64,
    pub stderr_bytes: u64,
    pub stdout_tail: String,
    pub stderr_tail: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub artifact_path: Option<VfsPath>,
    pub artifact_digest: Option<Digest>,
    pub artifact_size_bytes: Option<u64>,
    pub result: Option<TaskBoundaryValue>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TaskAttemptState {
    Queued,
    Running,
    FailedAwaitingAction,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAttemptSnapshot {
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub attempt_id: String,
    pub attempt_number: u32,
    pub task_definition: clusterflux_core::TaskDefinitionId,
    pub display_name: String,
    pub state: TaskAttemptState,
    pub current: bool,
    pub node: Option<NodeId>,
    pub environment_id: Option<String>,
    pub environment_digest: Option<Digest>,
    pub argument_summary: Vec<String>,
    pub handle_summary: Vec<String>,
    pub command_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub waiting_reason: Option<String>,
    pub vfs_checkpoint: String,
    pub probe_symbol: Option<String>,
    pub source_path: Option<String>,
    pub source_line: Option<u32>,
    pub restart_compatible: bool,
    pub failure_policy: clusterflux_core::TaskFailurePolicy,
    pub artifact_path: Option<VfsPath>,
    pub artifact_digest: Option<Digest>,
    pub artifact_size_bytes: Option<u64>,
    pub status_code: Option<i32>,
    pub error: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskAssignment {
    pub assignment_id: String,
    pub attempt_id: String,
    pub offer_epoch: u64,
    pub offer_expires_at_epoch_seconds: u64,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub node: NodeId,
    pub epoch: u64,
    pub artifact_path: String,
    pub task_spec: TaskSpec,
    pub wasm_module_base64: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemTaskOwner {
    AutomatedRun { run_id: RunId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemTaskKind {
    CompileWorkflow {
        request: Box<WorkflowCompilationRequest>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemTaskAssignment {
    pub owner: SystemTaskOwner,
    pub bundle_id: String,
    pub bundle_digest: Digest,
    pub environment_digest: Digest,
    pub task: SystemTaskKind,
}

/// Result envelope shared by all release-owned system tasks. The inner
/// domain result is deliberately typed: nodes cannot ask the coordinator to
/// execute an arbitrary command or interpret an untrusted task name.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemTaskResult {
    pub bundle_id: String,
    pub bundle_digest: Digest,
    pub result: SystemTaskOutput,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum SystemTaskOutput {
    CompileWorkflow {
        result: Box<WorkflowCompilationResult>,
    },
}

impl SystemTaskResult {
    pub fn validate(&self) -> Result<(), String> {
        if self.bundle_id.is_empty() || self.bundle_id.len() > 128 {
            return Err("system task result has an invalid bundle id".to_owned());
        }
        match &self.result {
            SystemTaskOutput::CompileWorkflow { result } => result.validate(),
        }
    }
}

/// One bounded piece of node-owned work. Process and release-owned system
/// tasks share this envelope and therefore share redelivery,
/// acknowledgement, scope, and fencing semantics.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum NodeAssignmentWork {
    Task {
        assignment: Box<TaskAssignment>,
    },
    SystemTask {
        assignment: Box<SystemTaskAssignment>,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeAssignmentOffer {
    pub assignment_id: String,
    pub attempt_id: String,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub node: NodeId,
    pub lease_epoch: u64,
    pub expires_at_epoch_seconds: u64,
    pub work: NodeAssignmentWork,
}

/// Fence for work already acknowledged by this node. Nodes include the fence
/// in their normal assignment poll so revocation and cancellation use the
/// same control-plane path as delivery.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ActiveNodeAssignment {
    pub assignment_id: String,
    pub attempt_id: String,
    pub lease_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCancellationTarget {
    pub process: ProcessId,
    pub task: TaskInstanceId,
    pub node: NodeId,
}
