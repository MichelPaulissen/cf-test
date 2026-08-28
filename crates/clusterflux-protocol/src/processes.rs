use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualProcessStatus {
    pub process: ProcessId,
    pub state: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_task_definition: Option<clusterflux_core::TaskDefinitionId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_task_instance: Option<TaskInstanceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_wait_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_wait_reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_debug_epoch: Option<u64>,
    pub connected_nodes: Vec<NodeId>,
    pub coordinator_epoch: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessLifecycleState {
    Active,
    RecentTerminal,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessActivityState {
    Running,
    WaitingForNode,
    WaitingForTask,
    AwaitingAction,
    DebugEpochPartial,
    Cancelling,
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProcessFinalResult {
    Completed,
    Failed,
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessSummary {
    pub process: ProcessId,
    pub lifecycle: ProcessLifecycleState,
    pub activity: ProcessActivityState,
    pub main_wait_state: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub main_wait_reason: Option<String>,
    pub started_at_epoch_seconds: u64,
    pub ended_at_epoch_seconds: Option<u64>,
    pub final_result: Option<ProcessFinalResult>,
    pub connected_nodes: Vec<NodeId>,
    pub current_debug_epoch: Option<DebugEpochSummary>,
    pub order_cursor: String,
}
