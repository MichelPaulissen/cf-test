use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAvailability {
    Available,
    NodeOffline,
    Unavailable,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRetentionState {
    NodeRetained,
    ExplicitStorage,
    Lost,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactSummary {
    pub id: ArtifactId,
    pub display_path: String,
    pub display_name: String,
    pub process: ProcessId,
    pub producer_task: TaskInstanceId,
    pub safe_node: Option<NodeId>,
    pub digest: Digest,
    pub size_bytes: u64,
    pub availability: ArtifactAvailability,
    pub downloadable_now: bool,
    pub retention_state: ArtifactRetentionState,
    pub explicit_storage: bool,
    pub order_cursor: String,
}
