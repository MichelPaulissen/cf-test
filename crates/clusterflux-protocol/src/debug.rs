use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugAuditEvent {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub task: Option<TaskInstanceId>,
    pub actor: UserId,
    pub operation: String,
    pub allowed: bool,
    pub reason: String,
    pub charged_debug_read_bytes: u64,
    pub used_debug_read_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DebugAcknowledgementState {
    Frozen,
    Running,
    Failed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugParticipantAcknowledgement {
    pub node: NodeId,
    pub task_definition: clusterflux_core::TaskDefinitionId,
    pub task: TaskInstanceId,
    pub epoch: u64,
    pub state: DebugAcknowledgementState,
    #[serde(default)]
    pub current_source_location: Option<clusterflux_core::SourceLocation>,
    pub stack_frames: Vec<String>,
    pub local_values: Vec<(String, String)>,
    pub task_args: Vec<(String, String)>,
    pub handles: Vec<(String, String)>,
    pub command_status: Option<String>,
    pub recent_output: Vec<String>,
    pub message: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DebugEpochSummary {
    pub epoch: u64,
    pub command: String,
    pub fully_frozen: bool,
    pub partially_frozen: bool,
    pub fully_resumed: bool,
    pub failed: bool,
}
