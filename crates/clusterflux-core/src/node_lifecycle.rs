use serde::{Deserialize, Serialize};

use crate::{ArtifactId, NodeId, ProcessId, TaskInstanceId};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycleState {
    #[default]
    Active,
    Draining,
    ReadyToRelease,
    Released,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeDrainBlockerKind {
    RunningTask,
    QueuedTask,
    ActiveTransfer,
    SoleCopyArtifactHold,
    RestartCheckpoint,
    DebugEpoch,
    DownloadExport,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDrainBlocker {
    pub kind: NodeDrainBlockerKind,
    pub summary: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub process: Option<ProcessId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub task: Option<TaskInstanceId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub artifact: Option<ArtifactId>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub transfer_id: Option<String>,
    #[serde(default)]
    pub retained_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeDrainStatus {
    pub node: NodeId,
    pub state: NodeLifecycleState,
    pub ephemeral: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_deadline_epoch_seconds: Option<u64>,
    /// Legacy alias for `hard_drain_deadline_epoch_seconds` retained for wire
    /// compatibility with older nodes.
    #[serde(default)]
    pub provider_deadline_reached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub soft_drain_deadline_epoch_seconds: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hard_drain_deadline_epoch_seconds: Option<u64>,
    #[serde(default)]
    pub soft_deadline_reached: bool,
    #[serde(default)]
    pub hard_deadline_reached: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub release_reason: Option<String>,
    pub running_task_count: usize,
    pub queued_task_count: usize,
    pub active_transfer_count: usize,
    pub retained_bytes: u64,
    pub blockers: Vec<NodeDrainBlocker>,
}

impl NodeDrainStatus {
    pub fn active(node: NodeId) -> Self {
        Self {
            node,
            state: NodeLifecycleState::Active,
            ephemeral: false,
            provider_deadline_epoch_seconds: None,
            provider_deadline_reached: false,
            soft_drain_deadline_epoch_seconds: None,
            hard_drain_deadline_epoch_seconds: None,
            soft_deadline_reached: false,
            hard_deadline_reached: false,
            release_reason: None,
            running_task_count: 0,
            queued_task_count: 0,
            active_transfer_count: 0,
            retained_bytes: 0,
            blockers: Vec::new(),
        }
    }

    pub fn ready_to_release(&self) -> bool {
        self.state == NodeLifecycleState::ReadyToRelease && self.blockers.is_empty()
    }
}
