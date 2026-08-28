use clusterflux_core::TaskSpec;
#[cfg(target_arch = "wasm32")]
use clusterflux_core::{TaskBoundaryValue, TaskDefinitionId, TaskFailurePolicy};
use serde::de::DeserializeOwned;

#[cfg(target_arch = "wasm32")]
use crate::EnvRef;

#[derive(Clone, Debug)]
pub(crate) struct RemoteTaskHandle {
    pub spec: TaskSpec,
    #[cfg_attr(not(target_arch = "wasm32"), allow(dead_code))]
    pub host_handle_id: u64,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum TaskRuntimeError {
    NotRunningInsideClusterflux,
    Argument(String),
    Configuration(String),
    Protocol(String),
    RemoteTask(String),
    ArtifactUnavailable(String),
    ArtifactReleased(String),
    Cancelled(String),
    ResultDecode(String),
    CommandFailed {
        program: String,
        status_code: Option<i32>,
        stdout: String,
        stderr: String,
        stdout_truncated: bool,
        stderr_truncated: bool,
    },
}

impl std::fmt::Display for TaskRuntimeError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let (kind, message) = match self {
            Self::NotRunningInsideClusterflux => {
                return formatter.write_str(
                    "distributed SDK operations require a running Clusterflux Wasm task",
                );
            }
            Self::Argument(message) => ("task argument", message),
            Self::Configuration(message) => ("product runtime configuration", message),
            Self::Protocol(message) => ("coordinator protocol", message),
            Self::RemoteTask(message) => ("remote task", message),
            Self::ArtifactUnavailable(message) => ("artifact unavailable", message),
            Self::ArtifactReleased(message) => ("artifact released", message),
            Self::Cancelled(message) => ("task cancelled", message),
            Self::ResultDecode(message) => ("remote result", message),
            Self::CommandFailed {
                program,
                status_code,
                stdout,
                stderr,
                stdout_truncated,
                stderr_truncated,
            } => {
                return write!(
                    formatter,
                    "command `{program}` failed with status {status_code:?}; stdout{}: {stdout:?}; stderr{}: {stderr:?}",
                    if *stdout_truncated { " (truncated)" } else { "" },
                    if *stderr_truncated { " (truncated)" } else { "" },
                );
            }
        };
        write!(formatter, "{kind} error: {message}")
    }
}

impl std::error::Error for TaskRuntimeError {}

pub(crate) fn join_remote_task<R>(handle: RemoteTaskHandle) -> Result<R, TaskRuntimeError>
where
    R: DeserializeOwned,
{
    #[cfg(target_arch = "wasm32")]
    {
        let response: Result<clusterflux_core::WasmHostTaskJoinResult, String> = guest_host_call(
            &clusterflux_core::WasmHostTaskJoinRequest {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                handle_id: handle.host_handle_id,
            },
            GuestHostCall::Join,
        )?;
        let response = response.map_err(TaskRuntimeError::RemoteTask)?;
        decode_boundary_value(response.result)
    }
    #[cfg(not(target_arch = "wasm32"))]
    {
        let _ = handle;
        Err(TaskRuntimeError::NotRunningInsideClusterflux)
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn start_guest_host_task(
    task_definition: TaskDefinitionId,
    environment: Option<EnvRef>,
    args: Vec<TaskBoundaryValue>,
    requested_secrets: Vec<String>,
    failure_policy: TaskFailurePolicy,
) -> Result<RemoteTaskHandle, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostTaskStartRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
        task_definition,
        environment_id: environment.map(|environment| environment.name.to_owned()),
        args,
        requested_secrets,
        failure_policy,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostTaskHandle, String> =
        guest_host_call(&request, GuestHostCall::Start)?;
    let response = response.map_err(TaskRuntimeError::RemoteTask)?;
    Ok(RemoteTaskHandle {
        spec: response.task_spec,
        host_handle_id: response.handle_id,
    })
}

#[cfg(target_arch = "wasm32")]
enum GuestHostCall {
    Start,
    Join,
    Command,
    TaskControl,
    DebugProbe,
    SourceSnapshot,
    TriggerContext,
    Vfs,
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn run_guest_host_command(
    program: String,
    args: Vec<String>,
    working_directory: String,
    environment_variables: std::collections::BTreeMap<String, String>,
    secret_environment_variables: std::collections::BTreeMap<String, String>,
    timeout_ms: u64,
    network: clusterflux_core::CommandNetworkPolicy,
) -> Result<clusterflux_core::WasmHostCommandResult, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostCommandRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
        program,
        args,
        working_directory,
        environment_variables,
        secret_environment_variables,
        timeout_ms,
        network,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostCommandResult, String> =
        guest_host_call(&request, GuestHostCall::Command)?;
    response.map_err(TaskRuntimeError::RemoteTask)
}

#[cfg(target_arch = "wasm32")]
fn classify_vfs_host_error(error: String) -> TaskRuntimeError {
    if let Some(message) = error.strip_prefix("artifact_unavailable:") {
        TaskRuntimeError::ArtifactUnavailable(message.trim().to_owned())
    } else if let Some(message) = error.strip_prefix("artifact_released:") {
        TaskRuntimeError::ArtifactReleased(message.trim().to_owned())
    } else if let Some(message) = error.strip_prefix("artifact_cancelled:") {
        TaskRuntimeError::Cancelled(message.trim().to_owned())
    } else {
        TaskRuntimeError::RemoteTask(error)
    }
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn guest_cancellation_requested() -> Result<bool, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostTaskControlRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostTaskControlResult, String> =
        guest_host_call(&request, GuestHostCall::TaskControl)?;
    response
        .map(|result| result.cancellation_requested)
        .map_err(TaskRuntimeError::RemoteTask)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn guest_debug_probe(
    symbol: String,
    source_location: Option<clusterflux_core::SourceLocation>,
) -> Result<clusterflux_core::WasmHostDebugProbeResult, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostDebugProbeRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
        symbol,
        source_location,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostDebugProbeResult, String> =
        guest_host_call(&request, GuestHostCall::DebugProbe)?;
    response.map_err(TaskRuntimeError::RemoteTask)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn guest_vfs_operation(
    operation: clusterflux_core::WasmHostVfsOperation,
) -> Result<clusterflux_core::WasmHostVfsResult, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostVfsRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
        operation,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostVfsResult, String> =
        guest_host_call(&request, GuestHostCall::Vfs)?;
    response.map_err(classify_vfs_host_error)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn guest_source_snapshot(
) -> Result<clusterflux_core::WasmHostSourceSnapshotResult, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostSourceSnapshotRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostSourceSnapshotResult, String> =
        guest_host_call(&request, GuestHostCall::SourceSnapshot)?;
    response.map_err(TaskRuntimeError::RemoteTask)
}

#[cfg(target_arch = "wasm32")]
pub(crate) fn guest_trigger_context(
) -> Result<clusterflux_core::WasmHostTriggerContextResult, TaskRuntimeError> {
    let request = clusterflux_core::WasmHostTriggerContextRequest {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
    };
    request.validate().map_err(TaskRuntimeError::Argument)?;
    let response: Result<clusterflux_core::WasmHostTriggerContextResult, String> =
        guest_host_call(&request, GuestHostCall::TriggerContext)?;
    response.map_err(TaskRuntimeError::RemoteTask)
}

#[cfg(target_arch = "wasm32")]
fn guest_host_call<I, O>(input: &I, call: GuestHostCall) -> Result<O, TaskRuntimeError>
where
    I: serde::Serialize,
    O: DeserializeOwned,
{
    #[link(wasm_import_module = "clusterflux")]
    unsafe extern "C" {
        #[link_name = "task_start_v1"]
        fn task_start_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "task_join_v1"]
        fn task_join_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "command_run_v1"]
        fn command_run_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "vfs_operation_v1"]
        fn vfs_operation_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "source_snapshot_v1"]
        fn source_snapshot_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "trigger_context_v1"]
        fn trigger_context_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "task_control_v1"]
        fn task_control_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
        #[link_name = "debug_probe_v1"]
        fn debug_probe_v1(
            input_pointer: u32,
            input_length: u32,
            output_pointer: u32,
            output_capacity: u32,
        ) -> i32;
    }

    let input =
        serde_json::to_vec(input).map_err(|error| TaskRuntimeError::Protocol(error.to_string()))?;
    if input.len() > clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES {
        return Err(TaskRuntimeError::Argument(
            "Wasm host-call request exceeds the task ABI limit".to_owned(),
        ));
    }
    let mut output = vec![0_u8; clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES];
    let written = unsafe {
        match call {
            GuestHostCall::Start => task_start_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::Join => task_join_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::Command => command_run_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::TaskControl => task_control_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::DebugProbe => debug_probe_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::Vfs => vfs_operation_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::SourceSnapshot => source_snapshot_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
            GuestHostCall::TriggerContext => trigger_context_v1(
                input.as_ptr() as u32,
                input.len() as u32,
                output.as_mut_ptr() as u32,
                output.len() as u32,
            ),
        }
    };
    if written <= 0 || written as usize > output.len() {
        return Err(TaskRuntimeError::Protocol(format!(
            "Wasm host-call returned invalid response length {written}"
        )));
    }
    serde_json::from_slice(&output[..written as usize])
        .map_err(|error| TaskRuntimeError::Protocol(error.to_string()))
}

#[cfg(target_arch = "wasm32")]
fn decode_boundary_value<R>(value: TaskBoundaryValue) -> Result<R, TaskRuntimeError>
where
    R: DeserializeOwned,
{
    let value = value
        .materialize()
        .map_err(TaskRuntimeError::ResultDecode)?;
    serde_json::from_value(value).map_err(|error| TaskRuntimeError::ResultDecode(error.to_string()))
}
