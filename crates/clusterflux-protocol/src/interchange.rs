use super::*;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourcePreparationDisposition {
    Pending { reason: String },
    Assigned { node: NodeId },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePreparationStatus {
    pub preparation: SourcePreparation,
    pub disposition: SourcePreparationDisposition,
}
