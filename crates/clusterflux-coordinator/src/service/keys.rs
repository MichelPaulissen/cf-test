use clusterflux_core::{
    ArtifactId, NodeId, ProcessId, ProjectId, TaskInstanceId, TenantId, VfsPath,
};
use thiserror::Error;

pub(super) type TaskControlKey = (TenantId, ProjectId, ProcessId, NodeId, TaskInstanceId);
pub(super) type TaskRestartKey = (TenantId, ProjectId, ProcessId, TaskInstanceId);
pub(super) type TaskAssignmentKey = (TenantId, ProjectId, NodeId);
pub(super) type PanelStopKey = (TenantId, ProjectId, ProcessId);
pub(super) type EnrollmentGrantKey = (TenantId, ProjectId, String);
pub(super) type ProcessControlKey = (TenantId, ProjectId, ProcessId);

pub(super) fn task_control_key(
    tenant: &TenantId,
    project: &ProjectId,
    process: &ProcessId,
    node: &NodeId,
    task: &TaskInstanceId,
) -> TaskControlKey {
    (
        tenant.clone(),
        project.clone(),
        process.clone(),
        node.clone(),
        task.clone(),
    )
}

pub(super) fn task_restart_key(
    tenant: &TenantId,
    project: &ProjectId,
    process: &ProcessId,
    task: &TaskInstanceId,
) -> TaskRestartKey {
    (
        tenant.clone(),
        project.clone(),
        process.clone(),
        task.clone(),
    )
}

pub(super) fn process_control_key(
    tenant: &TenantId,
    project: &ProjectId,
    process: &ProcessId,
) -> ProcessControlKey {
    (tenant.clone(), project.clone(), process.clone())
}

pub(super) fn panel_stop_key(
    tenant: &TenantId,
    project: &ProjectId,
    process: &ProcessId,
) -> PanelStopKey {
    (tenant.clone(), project.clone(), process.clone())
}

pub(super) fn enrollment_grant_key(
    tenant: &TenantId,
    project: &ProjectId,
    grant: &str,
) -> EnrollmentGrantKey {
    (tenant.clone(), project.clone(), grant.to_owned())
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub(super) enum ArtifactPathError {
    #[error("path must start with the exact /vfs/artifacts/ prefix")]
    WrongPrefix,
    #[error("path must name an artifact after /vfs/artifacts/")]
    EmptyArtifact,
    #[error("mapped artifact identifier is invalid: {0}")]
    InvalidArtifactId(#[from] clusterflux_core::IdParseError),
}

pub(super) fn artifact_id_from_path(path: &VfsPath) -> Result<ArtifactId, ArtifactPathError> {
    let value = path
        .as_str()
        .strip_prefix("/vfs/artifacts/")
        .ok_or(ArtifactPathError::WrongPrefix)?;
    if value.is_empty() {
        return Err(ArtifactPathError::EmptyArtifact);
    }
    ArtifactId::try_new(value.replace('/', ":")).map_err(ArtifactPathError::from)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_id_conversion_is_fallible_and_structural() {
        assert_eq!(
            artifact_id_from_path(&VfsPath::new("/vfs/artifacts/build/output").unwrap()).unwrap(),
            ArtifactId::from("build:output")
        );
        for path in [
            "/vfs/other/output",
            "/vfs/artifacts",
            "/vfs/artifacts/bad artifact!",
        ] {
            let path = VfsPath::new(path).unwrap();
            assert!(artifact_id_from_path(&path).is_err(), "{path:?}");
        }

        let mapped = format!("/vfs/artifacts/{}", "x".repeat(256));
        assert!(artifact_id_from_path(&VfsPath::new(mapped).unwrap()).is_err());
    }
}
