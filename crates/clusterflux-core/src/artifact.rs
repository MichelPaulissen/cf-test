use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Actor, ArtifactId, Digest, NodeId, ProcessId, ProjectId, TaskInstanceId, TenantId};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ArtifactHandle {
    pub id: ArtifactId,
    pub digest: Digest,
    pub size_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum StorageLocation {
    RetainedNode(NodeId),
    ExplicitStore(String),
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RetentionPolicy {
    pub best_effort_node_retention: bool,
    pub max_download_bytes: u64,
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        Self {
            best_effort_node_retention: true,
            max_download_bytes: 256 * 1024 * 1024,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadPolicy {
    pub max_bytes: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadAction {
    pub artifact: ArtifactId,
    pub source: StorageLocation,
    pub scoped_token_subject: String,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct DownloadLink {
    pub artifact: ArtifactId,
    pub artifact_digest: Digest,
    pub artifact_size_bytes: u64,
    pub source: StorageLocation,
    pub url_path: String,
    pub scoped_token_digest: Digest,
    pub expires_at_epoch_seconds: u64,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub actor: Actor,
    pub max_bytes: u64,
    pub policy_context_digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IssuedDownloadLink {
    pub link: DownloadLink,
    pub revoked: bool,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum DownloadError {
    #[error("artifact does not exist")]
    NotFound,
    #[error("artifact is unavailable from current retention or explicit storage")]
    Unavailable,
    #[error("artifact download direct connectivity unavailable: {0}")]
    DirectConnectivityUnavailable(String),
    #[error("artifact download denied: {0}")]
    Unauthorized(String),
    #[error("artifact size {size} exceeds download limit {limit}")]
    LimitExceeded { size: u64, limit: u64 },
    #[error("download link token is invalid for this scoped artifact link")]
    InvalidToken,
    #[error("download usage limit failed: {0}")]
    Usage(String),
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
#[error("artifact is unavailable because node-local unsynced bytes were lost")]
pub struct ArtifactUnavailable;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactMetadata {
    pub id: ArtifactId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub producer_task: TaskInstanceId,
    pub producer_node: NodeId,
    pub digest: Digest,
    pub size: u64,
    pub flushed_epoch: u64,
    pub retaining_nodes: BTreeSet<NodeId>,
    pub explicit_locations: Vec<String>,
    pub coordinator_has_large_bytes: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct ArtifactScopeKey {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub artifact: ArtifactId,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum ArtifactHoldReason {
    ProcessRetention {
        process: ProcessId,
    },
    ConsumerTask {
        process: ProcessId,
        task: TaskInstanceId,
    },
    ActiveTransfer {
        transfer_id: String,
    },
    RestartCheckpoint {
        process: ProcessId,
        task: TaskInstanceId,
    },
    DownloadExport {
        token_digest: Digest,
    },
    ExplicitRetention {
        label: String,
    },
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
pub struct ArtifactHold {
    pub reason: ArtifactHoldReason,
    pub created_at_epoch_seconds: u64,
}

impl ArtifactScopeKey {
    pub fn new(tenant: TenantId, project: ProjectId, artifact: ArtifactId) -> Self {
        Self {
            tenant,
            project,
            artifact,
        }
    }

    pub fn from_refs(tenant: &TenantId, project: &ProjectId, artifact: &ArtifactId) -> Self {
        Self::new(tenant.clone(), project.clone(), artifact.clone())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ArtifactFlush {
    pub id: ArtifactId,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub producer_task: TaskInstanceId,
    pub retaining_node: NodeId,
    pub digest: Digest,
    pub size: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_retention_policy_is_best_effort_node_retention() {
        let policy = RetentionPolicy::default();

        assert!(policy.best_effort_node_retention);
        assert_eq!(policy.max_download_bytes, 256 * 1024 * 1024);
    }
}
