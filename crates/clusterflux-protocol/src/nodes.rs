use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeSummary {
    pub id: NodeId,
    pub display_name: String,
    #[serde(default)]
    pub credential_state: String,
    #[serde(default)]
    pub runtime_state: String,
    pub online: bool,
    pub stale: bool,
    pub last_seen_epoch_seconds: Option<u64>,
    pub capabilities: NodeCapabilities,
    #[serde(default)]
    pub capabilities_known: bool,
    #[serde(default)]
    pub automatic_workflow_compilation: String,
    pub artifact_connectivity: clusterflux_core::ArtifactConnectivityFacts,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub drain: Option<clusterflux_core::NodeDrainStatus>,
}
