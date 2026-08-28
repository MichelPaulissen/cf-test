use clusterflux_core::{
    CommandInvocation, Digest, NativeCommandPolicy, NodeId, TaskInstanceId, VfsObject, VfsOverlay,
    VfsPath,
};
use serde::{Deserialize, Serialize};

use super::BackendError;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CapturedCommandLogs {
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub backpressured: bool,
}

pub const DEFAULT_COMMAND_LOG_LIMIT_BYTES: usize = 256 * 1024;

pub fn authorize_node_command(
    hosted_control_plane: bool,
    node_has_command_capability: bool,
) -> Result<(), BackendError> {
    NativeCommandPolicy {
        hosted_control_plane,
        node_has_command_capability,
    }
    .authorize()
    .map_err(BackendError::Denied)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct VirtualThreadCommand {
    pub virtual_thread: TaskInstanceId,
    pub invocation: CommandInvocation,
    pub stage_stdout_as: Option<VfsPath>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct CommandOutput {
    pub virtual_thread: TaskInstanceId,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_source_bytes: u64,
    pub stderr_source_bytes: u64,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub log_backpressured: bool,
    pub staged_artifact: Option<VfsObject>,
}

#[derive(Clone, Debug)]
pub struct LocalCommandExecutor {
    pub node: NodeId,
    pub hosted_control_plane: bool,
    pub has_command_capability: bool,
}

impl LocalCommandExecutor {
    pub fn run(
        &self,
        command: VirtualThreadCommand,
        overlay: &mut VfsOverlay,
    ) -> Result<CommandOutput, BackendError> {
        self.run_with_log_limit(command, overlay, DEFAULT_COMMAND_LOG_LIMIT_BYTES)
    }

    pub fn run_with_log_limit(
        &self,
        command: VirtualThreadCommand,
        overlay: &mut VfsOverlay,
        max_log_bytes: usize,
    ) -> Result<CommandOutput, BackendError> {
        authorize_node_command(self.hosted_control_plane, self.has_command_capability)?;

        let output = std::process::Command::new(&command.invocation.program)
            .args(&command.invocation.args)
            .output()
            .map_err(|err| BackendError::Command(format!("{err:#}")))?;

        let logs = capture_command_logs(
            &command.virtual_thread,
            &output.stdout,
            &output.stderr,
            max_log_bytes,
        );
        let stdout_source_bytes = output.stdout.len() as u64;
        let stderr_source_bytes = output.stderr.len() as u64;
        let staged_artifact = if let Some(path) = command.stage_stdout_as {
            Some(overlay.write(
                path,
                Digest::sha256(&output.stdout),
                output.stdout.len() as u64,
            ))
        } else {
            None
        };

        Ok(CommandOutput {
            virtual_thread: command.virtual_thread,
            status_code: output.status.code(),
            stdout: logs.stdout,
            stderr: logs.stderr,
            stdout_source_bytes,
            stderr_source_bytes,
            stdout_truncated: logs.stdout_truncated,
            stderr_truncated: logs.stderr_truncated,
            log_backpressured: logs.backpressured,
            staged_artifact,
        })
    }
}

pub(super) fn capture_command_logs(
    _task: &TaskInstanceId,
    stdout: &[u8],
    stderr: &[u8],
    max_log_bytes: usize,
) -> CapturedCommandLogs {
    let stdout_truncated = stdout.len() > max_log_bytes;
    let stderr_truncated = stderr.len() > max_log_bytes;
    let stdout_start = stdout.len().saturating_sub(max_log_bytes);
    let stderr_start = stderr.len().saturating_sub(max_log_bytes);
    CapturedCommandLogs {
        stdout: String::from_utf8_lossy(&stdout[stdout_start..]).into_owned(),
        stderr: String::from_utf8_lossy(&stderr[stderr_start..]).into_owned(),
        stdout_truncated,
        stderr_truncated,
        backpressured: stdout_truncated || stderr_truncated,
    }
}
