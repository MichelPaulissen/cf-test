use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Digest, TaskInstanceId, VfsManifest};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CheckpointBoundary {
    pub task_entrypoint: String,
    pub serialized_args: Digest,
    pub environment_digest: Digest,
    pub vfs_epoch: u64,
    pub task_abi: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TaskCheckpoint {
    pub task: TaskInstanceId,
    pub boundary: CheckpointBoundary,
    pub vfs_manifest: VfsManifest,
    pub depends_on_live_stack: bool,
    pub depends_on_live_socket: bool,
    pub depends_on_ephemeral_artifact_durability: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RestartRequest {
    pub task: TaskInstanceId,
    pub entrypoint: String,
    pub serialized_args: Digest,
    pub environment_digest: Digest,
    pub task_abi: Digest,
    pub source_edited: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum RestartDecision {
    RestartTask {
        task: TaskInstanceId,
        from_vfs_epoch: u64,
        discard_unflushed_changes: bool,
    },
    RestartWholeVirtualProcess {
        message: String,
    },
}

#[derive(Clone, Debug, Default)]
pub struct RestartPolicy;

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CompatibilityFailure {
    #[error("task entrypoint changed")]
    Entrypoint,
    #[error("serialized task arguments changed")]
    Args,
    #[error("environment digest changed")]
    Environment,
    #[error("task ABI changed")]
    TaskAbi,
    #[error("checkpoint depends on unsupported live stack migration")]
    LiveStack,
    #[error("checkpoint depends on unsupported live socket checkpointing")]
    LiveSocket,
    #[error("checkpoint incorrectly treats ephemeral artifacts as durable")]
    EphemeralArtifactDurability,
}

impl RestartPolicy {
    pub fn decide(&self, checkpoint: &TaskCheckpoint, request: &RestartRequest) -> RestartDecision {
        match compatibility_failure(checkpoint, request) {
            None => RestartDecision::RestartTask {
                task: checkpoint.task.clone(),
                from_vfs_epoch: checkpoint.boundary.vfs_epoch,
                discard_unflushed_changes: true,
            },
            Some(failure) => RestartDecision::RestartWholeVirtualProcess {
                message: format!(
                    "cannot restart selected task `{}` from checkpoint: {failure}; restart the whole virtual process",
                    checkpoint.task
                ),
            },
        }
    }
}

fn compatibility_failure(
    checkpoint: &TaskCheckpoint,
    request: &RestartRequest,
) -> Option<CompatibilityFailure> {
    if checkpoint.depends_on_live_stack {
        return Some(CompatibilityFailure::LiveStack);
    }
    if checkpoint.depends_on_live_socket {
        return Some(CompatibilityFailure::LiveSocket);
    }
    if checkpoint.depends_on_ephemeral_artifact_durability {
        return Some(CompatibilityFailure::EphemeralArtifactDurability);
    }
    if checkpoint.boundary.task_entrypoint != request.entrypoint {
        return Some(CompatibilityFailure::Entrypoint);
    }
    if checkpoint.boundary.serialized_args != request.serialized_args {
        return Some(CompatibilityFailure::Args);
    }
    if checkpoint.boundary.environment_digest != request.environment_digest {
        return Some(CompatibilityFailure::Environment);
    }
    if checkpoint.boundary.task_abi != request.task_abi {
        return Some(CompatibilityFailure::TaskAbi);
    }
    None
}

#[cfg(test)]
mod tests {
    use std::path::PathBuf;

    use crate::{
        EnvironmentKind, EnvironmentRequirements, EnvironmentResource, NodeId, VfsOverlay, VfsPath,
    };

    use super::*;

    fn env(digest_input: &str) -> EnvironmentResource {
        EnvironmentResource {
            name: "linux".to_owned(),
            kind: EnvironmentKind::Containerfile,
            recipe_path: PathBuf::from("envs/linux/Containerfile"),
            context_path: PathBuf::from("envs/linux"),
            context_manifest: Vec::new(),
            context_manifest_digest: Digest::from_parts([b"environment-context:v1"]),
            digest: Digest::sha256(digest_input),
            requirements: EnvironmentRequirements::linux_container(),
        }
    }

    fn checkpoint() -> (TaskCheckpoint, EnvironmentResource) {
        let environment = env("env");
        let mut overlay = VfsOverlay::new(TaskInstanceId::from("task"), NodeId::from("node"));
        overlay.write(
            VfsPath::new("/vfs/artifacts/app").unwrap(),
            Digest::sha256("app"),
            3,
        );
        let manifest = overlay.flush();
        (
            TaskCheckpoint {
                task: TaskInstanceId::from("task"),
                boundary: CheckpointBoundary {
                    task_entrypoint: "compile_linux".to_owned(),
                    serialized_args: Digest::sha256("args"),
                    environment_digest: environment.digest.clone(),
                    vfs_epoch: manifest.epoch,
                    task_abi: Digest::sha256("abi"),
                },
                vfs_manifest: manifest,
                depends_on_live_stack: false,
                depends_on_live_socket: false,
                depends_on_ephemeral_artifact_durability: false,
            },
            environment,
        )
    }

    fn restart_request(environment: EnvironmentResource) -> RestartRequest {
        RestartRequest {
            task: TaskInstanceId::from("task"),
            entrypoint: "compile_linux".to_owned(),
            serialized_args: Digest::sha256("args"),
            environment_digest: environment.digest,
            task_abi: Digest::sha256("abi"),
            source_edited: true,
        }
    }

    fn assert_whole_process_restart(decision: RestartDecision, expected_reason: &str) {
        match decision {
            RestartDecision::RestartWholeVirtualProcess { message } => {
                assert!(
                    message.contains(expected_reason),
                    "restart message `{message}` did not include `{expected_reason}`"
                );
                assert!(
                    message.contains("restart the whole virtual process"),
                    "restart message `{message}` did not direct a whole-process restart"
                );
            }
            RestartDecision::RestartTask { .. } => {
                panic!("incompatible checkpoint unexpectedly restarted selected task")
            }
        }
    }

    #[test]
    fn compatible_restart_uses_task_boundary_and_discards_unflushed_changes() {
        let (checkpoint, environment) = checkpoint();
        let request = restart_request(environment);

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_eq!(
            decision,
            RestartDecision::RestartTask {
                task: TaskInstanceId::from("task"),
                from_vfs_epoch: 1,
                discard_unflushed_changes: true
            }
        );
    }

    #[test]
    fn incompatible_environment_requires_whole_process_restart() {
        let (checkpoint, _) = checkpoint();
        let request = restart_request(env("changed-env"));

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "environment digest changed");
    }

    #[test]
    fn incompatible_entrypoint_requires_whole_process_restart() {
        let (checkpoint, environment) = checkpoint();
        let mut request = restart_request(environment);
        request.entrypoint = "package_linux".to_owned();

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "task entrypoint changed");
    }

    #[test]
    fn incompatible_serialized_args_require_whole_process_restart() {
        let (checkpoint, environment) = checkpoint();
        let mut request = restart_request(environment);
        request.serialized_args = Digest::sha256("changed-args");

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "serialized task arguments changed");
    }

    #[test]
    fn incompatible_task_abi_requires_whole_process_restart() {
        let (checkpoint, environment) = checkpoint();
        let mut request = restart_request(environment);
        request.task_abi = Digest::sha256("changed-abi");

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "task ABI changed");
    }

    #[test]
    fn restart_never_claims_live_stack_migration() {
        let (mut checkpoint, environment) = checkpoint();
        checkpoint.depends_on_live_stack = true;
        let request = restart_request(environment);

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "live stack");
    }

    #[test]
    fn restart_never_claims_live_socket_checkpointing() {
        let (mut checkpoint, environment) = checkpoint();
        checkpoint.depends_on_live_socket = true;
        let request = restart_request(environment);

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "live socket");
    }

    #[test]
    fn restart_never_depends_on_ephemeral_artifact_durability() {
        let (mut checkpoint, environment) = checkpoint();
        checkpoint.depends_on_ephemeral_artifact_durability = true;
        let request = restart_request(environment);

        let decision = RestartPolicy.decide(&checkpoint, &request);

        assert_whole_process_restart(decision, "ephemeral artifacts");
    }
}
