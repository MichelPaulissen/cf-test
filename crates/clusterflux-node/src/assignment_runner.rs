use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

#[cfg(unix)]
use std::os::unix::process::CommandExt;

use crate::artifact_interchange::ArtifactWarmupManager;
use crate::coordinator_session::CoordinatorSession;
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{
    Capability, CommandInvocation, Digest, NodeId, Os, ProcessId, ProjectId, TaskBoundaryValue,
    TaskDispatch, TaskInstanceId, TaskJoinResult, TaskJoinState, TaskSpec, TenantId, VfsManifest,
    WasmExportAbi, WasmHostDebugProbeRequest, WasmHostDebugProbeResult,
    WasmHostSourceSnapshotRequest, WasmHostSourceSnapshotResult, WasmHostTaskHandle,
    WasmHostTaskJoinRequest, WasmHostTaskJoinResult, WasmHostTaskStartRequest,
    WasmHostVfsOperation, WasmHostVfsRequest, WasmHostVfsResult, WasmTaskInvocation,
    WasmTaskOutcome, WasmTaskResult,
};
use clusterflux_node::{
    execute_dangerous_native_checkout_task, BackendError, CommandOutput,
    LinuxRootlessPodmanBackend, LocalCheckoutTaskRequest, LocalSourceCheckout,
    LocalTaskCancellation, PodmanCommand, ProcessOutput, ProcessRunner, WasmDebugControl,
    WindowsContainerdNerdctlBackend, DEFAULT_COMMAND_LOG_LIMIT_BYTES,
};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use clusterflux_source::{
    materialize_exact_repository_revision_cancellable, snapshot_project_cancellable,
    MaterializedRepositoryRevision,
};
use clusterflux_wasm_runtime::{
    AsyncWasmTaskHost, WasmExecution, WasmExecutionService, WasmExecutionServiceConfiguration,
    WasmHostFuture, WasmTaskError, WasmtimeRuntimeLimits,
};
use tokio_util::sync::CancellationToken;
use zeroize::{Zeroize, Zeroizing};

const MAX_CHILD_TASK_HANDLES: usize = 256;
pub(crate) const MAX_RESIDENT_WASM_TASKS: usize = 256;
const WASM_COMMAND_RESULT_HEADROOM_BYTES: usize = 1024;
const WASM_HOST_CONTROL_CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const WASM_HOST_CONTROL_IO_TIMEOUT: Duration = Duration::from_secs(30);
use crate::daemon::{Args, RuntimeTask};
use crate::task_artifacts::{task_output_root, NodeArtifactStore, TaskArtifactStore};

mod process_runner;
use process_runner::CoordinatorControlledProcessRunner;
mod control_watcher;
use control_watcher::TaskControlWatchers;
pub(crate) mod validation;
use validation::{
    authorize_command_network, bundle_environments, capability_from_descriptor,
    is_secret_environment_name, redact_configured_values, require_command_environment,
    resolve_task_export, task_descriptors, verify_environment_digest, verify_source_snapshot,
};

#[derive(Debug)]
struct AssignmentExecutionError {
    message: String,
    logs: NativeCommandLogSnapshot,
}

impl std::fmt::Display for AssignmentExecutionError {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(&self.message)
    }
}

impl std::error::Error for AssignmentExecutionError {}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NativeCommandLogSnapshot {
    pub(crate) stdout: String,
    pub(crate) stderr: String,
    pub(crate) stdout_source_bytes: u64,
    pub(crate) stderr_source_bytes: u64,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) log_backpressured: bool,
}

#[derive(Debug, Default)]
struct NativeCommandLogState {
    stdout: String,
    stderr: String,
    stdout_truncated: bool,
    stderr_truncated: bool,
    log_backpressured: bool,
}

impl NativeCommandLogState {
    fn record(&mut self, output: &CommandOutput) {
        self.stdout_truncated |= output.stdout_truncated
            || append_bounded_log_tail(
                &mut self.stdout,
                &output.stdout,
                DEFAULT_COMMAND_LOG_LIMIT_BYTES,
            );
        self.stderr_truncated |= output.stderr_truncated
            || append_bounded_log_tail(
                &mut self.stderr,
                &output.stderr,
                DEFAULT_COMMAND_LOG_LIMIT_BYTES,
            );
        self.log_backpressured |= output.log_backpressured;
    }

    fn snapshot(
        &self,
        stdout_source_bytes: &AtomicU64,
        stderr_source_bytes: &AtomicU64,
    ) -> NativeCommandLogSnapshot {
        NativeCommandLogSnapshot {
            stdout: self.stdout.clone(),
            stderr: self.stderr.clone(),
            stdout_source_bytes: stdout_source_bytes.load(Ordering::Relaxed),
            stderr_source_bytes: stderr_source_bytes.load(Ordering::Relaxed),
            stdout_truncated: self.stdout_truncated,
            stderr_truncated: self.stderr_truncated,
            log_backpressured: self.log_backpressured,
        }
    }
}

fn native_log_snapshot(
    state: &Mutex<NativeCommandLogState>,
    stdout_source_bytes: &AtomicU64,
    stderr_source_bytes: &AtomicU64,
) -> NativeCommandLogSnapshot {
    state
        .lock()
        .map(|state| state.snapshot(stdout_source_bytes, stderr_source_bytes))
        .unwrap_or_else(|_| NativeCommandLogSnapshot {
            stdout_source_bytes: stdout_source_bytes.load(Ordering::Relaxed),
            stderr_source_bytes: stderr_source_bytes.load(Ordering::Relaxed),
            stdout_truncated: true,
            stderr_truncated: true,
            log_backpressured: true,
            ..NativeCommandLogSnapshot::default()
        })
}

fn execution_error_with_logs(
    message: impl Into<String>,
    stdout_source_bytes: &AtomicU64,
    stderr_source_bytes: &AtomicU64,
    state: &Mutex<NativeCommandLogState>,
) -> Box<dyn std::error::Error> {
    Box::new(AssignmentExecutionError {
        message: message.into(),
        logs: native_log_snapshot(state, stdout_source_bytes, stderr_source_bytes),
    })
}

fn remove_task_output_root(output_root: &std::path::Path) {
    if std::fs::symlink_metadata(output_root)
        .map(|metadata| metadata.is_dir() && !metadata.file_type().is_symlink())
        .unwrap_or(false)
    {
        let _ = std::fs::remove_dir_all(output_root);
    }
}

pub(crate) fn assignment_error_logs(
    error: &(dyn std::error::Error + 'static),
) -> NativeCommandLogSnapshot {
    error
        .downcast_ref::<AssignmentExecutionError>()
        .map(|error| error.logs.clone())
        .unwrap_or_default()
}

fn append_bounded_log_tail(current: &mut String, addition: &str, maximum: usize) -> bool {
    let combined_len = current.len().saturating_add(addition.len());
    current.push_str(addition);
    if current.len() <= maximum {
        return false;
    }
    let mut start = current.len().saturating_sub(maximum);
    while start < current.len() && !current.is_char_boundary(start) {
        start += 1;
    }
    *current = current[start..].to_owned();
    combined_len > current.len()
}

fn retain_utf8_tail(value: &str, maximum: usize) -> String {
    if value.len() <= maximum {
        return value.to_owned();
    }
    let mut start = value.len().saturating_sub(maximum);
    while start < value.len() && !value.is_char_boundary(start) {
        start += 1;
    }
    value[start..].to_owned()
}

fn bounded_wasm_command_result(
    output: &CommandOutput,
) -> Result<clusterflux_core::WasmHostCommandResult, String> {
    let initial_per_stream =
        (clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES - WASM_COMMAND_RESULT_HEADROOM_BYTES) / 2;
    let mut result = clusterflux_core::WasmHostCommandResult {
        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
        status_code: output.status_code,
        stdout: retain_utf8_tail(&output.stdout, initial_per_stream),
        stderr: retain_utf8_tail(&output.stderr, initial_per_stream),
        stdout_truncated: output.stdout_truncated || output.stdout.len() > initial_per_stream,
        stderr_truncated: output.stderr_truncated || output.stderr.len() > initial_per_stream,
    };
    loop {
        let encoded = serde_json::to_vec(&Ok::<_, String>(&result)).map_err(|error| {
            format!("Wasm command result serialization invariant could not be checked: {error}")
        })?;
        if encoded.len() <= clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES {
            return Ok(result);
        }
        if result.stdout.is_empty() && result.stderr.is_empty() {
            return Err(format!(
                "Wasm command result serialization invariant failed: metadata exceeds {} bytes",
                clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES
            ));
        }
        if result.stdout.len() >= result.stderr.len() && !result.stdout.is_empty() {
            let next = result.stdout.len() / 2;
            result.stdout = retain_utf8_tail(&result.stdout, next);
            result.stdout_truncated = true;
        } else {
            let next = result.stderr.len() / 2;
            result.stderr = retain_utf8_tail(&result.stderr, next);
            result.stderr_truncated = true;
        }
    }
}

pub(crate) fn node_wasm_execution_service() -> Result<WasmExecutionService, WasmTaskError> {
    WasmExecutionService::new(WasmExecutionServiceConfiguration {
        thread_name: "clusterflux-node-wasm".to_owned(),
        max_resident_invocations: MAX_RESIDENT_WASM_TASKS,
        ..WasmExecutionServiceConfiguration::default()
    })
}

pub(crate) struct NodeWasmAssignment {
    execution: Option<WasmExecution>,
    task_id: TaskInstanceId,
    node_id: NodeId,
    command_stdout_source_bytes: Arc<AtomicU64>,
    command_stderr_source_bytes: Arc<AtomicU64>,
    command_logs: Arc<Mutex<NativeCommandLogState>>,
    abort_requested: Arc<AtomicBool>,
    control_watchers: Option<TaskControlWatchers>,
    output_root: Option<PathBuf>,
}

pub(crate) type WasmAssignmentResult =
    Result<(CommandOutput, VfsManifest, Option<TaskBoundaryValue>), Box<dyn std::error::Error>>;

impl NodeWasmAssignment {
    pub(crate) fn abort(&self) {
        self.abort_requested.store(true, Ordering::Release);
    }

    pub(crate) fn try_result(&mut self) -> Option<WasmAssignmentResult> {
        let result = self.execution.as_mut()?.try_result()?;
        self.execution.take();
        let completed = self.finish(result);
        self.cleanup();
        Some(completed)
    }

    #[cfg(test)]
    pub(crate) fn blocking_wait(mut self) -> WasmAssignmentResult {
        let result = self
            .execution
            .take()
            .expect("Wasm assignment execution is present")
            .blocking_wait();
        let completed = self.finish(result);
        self.cleanup();
        completed
    }

    fn finish(&self, result: Result<WasmTaskResult, WasmTaskError>) -> WasmAssignmentResult {
        let result = result.map_err(|error| {
            execution_error_with_logs(
                error.to_string(),
                &self.command_stdout_source_bytes,
                &self.command_stderr_source_bytes,
                &self.command_logs,
            )
        })?;
        if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
            eprintln!(
                "clusterflux debug control: Wasm assignment returned for task {}",
                self.task_id
            );
        }
        let boundary_result = match result.outcome {
            WasmTaskOutcome::Completed => Some(result.result.ok_or_else(|| {
                execution_error_with_logs(
                    "completed Wasm task omitted result",
                    &self.command_stdout_source_bytes,
                    &self.command_stderr_source_bytes,
                    &self.command_logs,
                )
            })?),
            WasmTaskOutcome::Failed => {
                return Err(execution_error_with_logs(
                    result
                        .error
                        .unwrap_or_else(|| "Wasm task failed without an error".to_owned()),
                    &self.command_stdout_source_bytes,
                    &self.command_stderr_source_bytes,
                    &self.command_logs,
                ));
            }
        };
        let artifacts = TaskArtifactStore::new(self.task_id.clone(), self.node_id.clone());
        let manifest = artifacts.flush();
        let logs = native_log_snapshot(
            &self.command_logs,
            &self.command_stdout_source_bytes,
            &self.command_stderr_source_bytes,
        );
        Ok((
            CommandOutput {
                virtual_thread: self.task_id.clone(),
                status_code: Some(0),
                stdout: logs.stdout,
                stderr: logs.stderr,
                stdout_source_bytes: logs.stdout_source_bytes,
                stderr_source_bytes: logs.stderr_source_bytes,
                stdout_truncated: logs.stdout_truncated,
                stderr_truncated: logs.stderr_truncated,
                log_backpressured: logs.log_backpressured,
                staged_artifact: None,
            },
            manifest,
            boundary_result,
        ))
    }

    fn cleanup(&mut self) {
        if let Some(mut watchers) = self.control_watchers.take() {
            watchers.shutdown();
        }
        if let Some(output_root) = self.output_root.take() {
            remove_task_output_root(&output_root);
        }
    }
}

impl Drop for NodeWasmAssignment {
    fn drop(&mut self) {
        self.abort();
        self.cleanup();
    }
}

pub(crate) fn submit_verified_wasmtime_assignment(
    execution_service: &WasmExecutionService,
    args: &Args,
    task: &RuntimeTask,
    node_private_key: &str,
    artifact_warmups: Option<ArtifactWarmupManager>,
) -> Result<NodeWasmAssignment, Box<dyn std::error::Error>> {
    if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
        eprintln!(
            "clusterflux debug control: starting Wasm assignment for task {}",
            task.task
        );
    }
    let expected_bundle_digest = task.bundle_digest.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "wasmtime task assignment includes module bytes but is missing bundle_digest",
        )
    })?;
    let module_base64 = task
        .wasm_module_base64
        .as_ref()
        .expect("caller checked wasm_module_base64");
    let module = BASE64_STANDARD.decode(module_base64)?;
    let actual_bundle_digest = Digest::sha256(&module);
    if &actual_bundle_digest != expected_bundle_digest {
        return Err(format!(
            "bundle digest mismatch: expected {expected_bundle_digest}, received {actual_bundle_digest}"
        )
        .into());
    }
    let task_spec = task.task_spec.as_ref().ok_or_else(|| {
        std::io::Error::new(
            std::io::ErrorKind::InvalidInput,
            "Wasm task assignment is missing its versioned TaskSpec",
        )
    })?;
    let (declared_export, abi) = match &task_spec.dispatch {
        TaskDispatch::CoordinatorNodeWasm { export, abi } => (export.as_deref(), abi),
    };
    let resolved_export;
    let export = match declared_export {
        Some(export) => export,
        None if abi == &WasmExportAbi::TaskV1 => {
            resolved_export = resolve_task_export(&module, task_spec.task_definition.as_str())?;
            &resolved_export
        }
        None => {
            return Err("Wasm entrypoint assignment omitted its descriptor export".into());
        }
    };
    let command_stdout_source_bytes = Arc::new(AtomicU64::new(0));
    let command_stderr_source_bytes = Arc::new(AtomicU64::new(0));
    let command_logs = Arc::new(Mutex::new(NativeCommandLogState::default()));
    match abi {
        WasmExportAbi::EntrypointV1 | WasmExportAbi::TaskV1 => {
            let invocation = WasmTaskInvocation::new(
                task_spec.task_definition.clone(),
                task_spec.task_instance.clone(),
                task_spec.args.clone(),
            );
            let PreparedCoordinatorWasmTaskHost {
                host,
                mut control_watchers,
            } = CoordinatorWasmTaskHost::prepare(
                args,
                task,
                node_private_key,
                &module,
                Arc::clone(&command_stdout_source_bytes),
                Arc::clone(&command_stderr_source_bytes),
                Arc::clone(&command_logs),
                artifact_warmups.clone(),
            )?;
            let abort_requested = Arc::clone(&host.abort_requested);
            let output_root = host.output_root.clone();
            let host = AsyncCoordinatorWasmTaskHost::new(host);
            let execution = match execution_service.submit_task_export_verified(
                module,
                expected_bundle_digest.clone(),
                export.to_owned(),
                invocation,
                WasmtimeRuntimeLimits::default(),
                Box::new(host),
            ) {
                Ok(execution) => execution,
                Err(error) => {
                    if let Some(mut watchers) = control_watchers.take() {
                        watchers.shutdown();
                    }
                    remove_task_output_root(&output_root);
                    return Err(error.into());
                }
            };
            Ok(NodeWasmAssignment {
                execution: Some(execution),
                task_id: TaskInstanceId::new(task.task.clone()),
                node_id: NodeId::new(args.node.clone()),
                command_stdout_source_bytes,
                command_stderr_source_bytes,
                command_logs,
                abort_requested,
                control_watchers,
                output_root: Some(output_root),
            })
        }
    }
}

struct PreparedCoordinatorWasmTaskHost {
    host: CoordinatorWasmTaskHost,
    control_watchers: Option<TaskControlWatchers>,
}

#[derive(Default)]
struct ChildJoinNotifications {
    terminal: Mutex<HashMap<TaskInstanceId, TaskJoinResult>>,
    changed: tokio::sync::Notify,
}

impl ChildJoinNotifications {
    fn record(&self, joins: Vec<TaskJoinResult>) {
        let Ok(mut terminal) = self.terminal.lock() else {
            return;
        };
        let mut recorded = false;
        for join in joins {
            if join.state != TaskJoinState::Pending {
                terminal.insert(join.task_instance.clone(), join);
                recorded = true;
            }
        }
        drop(terminal);
        if recorded {
            self.changed.notify_waiters();
        }
    }

    fn take(&self, task: &TaskInstanceId) -> Result<Option<TaskJoinResult>, String> {
        self.terminal
            .lock()
            .map_err(|_| "child-join notification registry was unavailable".to_owned())
            .map(|mut terminal| terminal.remove(task))
    }
}

struct CoordinatorWasmTaskHost {
    args: Args,
    process: String,
    parent_task: String,
    epoch: u64,
    bundle_digest: clusterflux_core::Digest,
    wasm_module_base64: String,
    node_private_key: String,
    assignment_authority: clusterflux_core::AssignmentAuthority,
    allow_command: bool,
    allow_network: bool,
    allow_source_snapshot: bool,
    environment_id: Option<String>,
    environment_digest: Option<Digest>,
    source_snapshot: Option<Digest>,
    source_revision: Option<clusterflux_core::RepositoryRevision>,
    source_root: PathBuf,
    _materialized_source: Option<MaterializedRepositoryRevision>,
    _empty_source: Option<tempfile::TempDir>,
    requested_secrets: Vec<String>,
    output_root: PathBuf,
    task_descriptors: HashMap<String, serde_json::Value>,
    environments: BTreeMap<String, clusterflux_core::EnvironmentResource>,
    next_handle_id: u64,
    handles: Arc<Mutex<HashMap<u64, TaskSpec>>>,
    child_joins: Arc<ChildJoinNotifications>,
    command_status: Arc<Mutex<Option<String>>>,
    command_stdout_source_bytes: Arc<AtomicU64>,
    command_stderr_source_bytes: Arc<AtomicU64>,
    command_logs: Arc<Mutex<NativeCommandLogState>>,
    cancellation_requested: CancellationToken,
    abort_requested: Arc<AtomicBool>,
    debug_control: Arc<WasmDebugControl>,
    artifact_warmups: Option<ArtifactWarmupManager>,
}

impl CoordinatorWasmTaskHost {
    #[allow(
        clippy::too_many_arguments,
        reason = "the task host receives distinct signed authority and bounded log-accounting channels"
    )]
    fn prepare(
        args: &Args,
        parent: &RuntimeTask,
        node_private_key: &str,
        module: &[u8],
        command_stdout_source_bytes: Arc<AtomicU64>,
        command_stderr_source_bytes: Arc<AtomicU64>,
        command_logs: Arc<Mutex<NativeCommandLogState>>,
        artifact_warmups: Option<ArtifactWarmupManager>,
    ) -> Result<PreparedCoordinatorWasmTaskHost, Box<dyn std::error::Error>> {
        let task_spec = parent
            .task_spec
            .as_ref()
            .ok_or("Wasm task host requires a parent TaskSpec")?;
        let cancellation_requested = CancellationToken::new();
        let abort_requested = Arc::new(AtomicBool::new(false));
        let debug_control = Arc::new(WasmDebugControl::default());
        let handles = Arc::new(Mutex::new(HashMap::new()));
        let child_joins = Arc::new(ChildJoinNotifications::default());
        let command_status = Arc::new(Mutex::new(None));
        let task_instance = TaskInstanceId::from(parent.task.as_str());
        let bundle_digest = parent
            .bundle_digest
            .clone()
            .ok_or("Wasm task host requires a bundle digest")?;
        // Wasmtime accepts both binary Wasm and WAT in development tests. Descriptor
        // discovery is required only if the guest actually invokes task_start_v1; module
        // compilation/digest verification remains authoritative for malformed input.
        let task_descriptors = task_descriptors(module).unwrap_or_default();
        let environments = bundle_environments(module)?;
        let output_root =
            task_output_root(args.project_root.as_deref(), &args.node, &task_instance)?;
        let task_args = task_spec
            .args
            .iter()
            .enumerate()
            .map(|(index, value)| (format!("arg_{index}"), format!("{value:?}")))
            .collect();
        let control_watchers = artifact_warmups.as_ref().map(|warmups| {
            TaskControlWatchers::start(
                warmups.runtime_handle(),
                warmups.task_tracker(),
                args.clone(),
                parent.process.clone(),
                parent.task.clone(),
                task_spec.task_definition.as_str().to_owned(),
                parent.assignment_authority.clone(),
                node_private_key.to_owned(),
                cancellation_requested.clone(),
                Arc::clone(&abort_requested),
                Arc::clone(&debug_control),
                task_args,
                Arc::clone(&handles),
                Arc::clone(&child_joins),
                Arc::clone(&command_status),
                warmups.shutdown_token(),
            )
        });
        let node_capabilities = args.node_capabilities();
        let allow_source_snapshot = task_spec
            .required_capabilities
            .contains(&Capability::SourceFilesystem)
            && node_capabilities
                .capabilities
                .contains(&Capability::SourceFilesystem);
        let materialized_source = task_spec
            .source_revision
            .as_ref()
            .map(|revision| {
                materialize_exact_repository_revision_cancellable(revision, || {
                    cancellation_requested.is_cancelled() || abort_requested.load(Ordering::Acquire)
                })
            })
            .transpose()?;
        let mut empty_source = None;
        let source_root = if let Some(source) = &materialized_source {
            source.root().to_path_buf()
        } else if task_spec.source_snapshot.is_some() {
            args.project_root.clone().ok_or(
                "source-backed task requires either an immutable Git revision or a node checkout",
            )?
        } else if allow_source_snapshot {
            return Err(
                "source-backed task is missing its process-authoritative source identity".into(),
            );
        } else {
            let directory = tempfile::Builder::new()
                .prefix("clusterflux-empty-source-")
                .tempdir()?;
            let path = directory.path().to_path_buf();
            empty_source = Some(directory);
            path
        };
        let host = Self {
            args: args.clone(),
            process: parent.process.clone(),
            parent_task: parent.task.clone(),
            epoch: parent.epoch.unwrap_or(task_spec.vfs_epoch),
            bundle_digest,
            wasm_module_base64: BASE64_STANDARD.encode(module),
            node_private_key: node_private_key.to_owned(),
            assignment_authority: parent.assignment_authority.clone(),
            allow_command: task_spec
                .required_capabilities
                .contains(&Capability::Command)
                && node_capabilities
                    .capabilities
                    .contains(&Capability::Command),
            allow_network: task_spec
                .required_capabilities
                .contains(&Capability::Network)
                && node_capabilities
                    .capabilities
                    .contains(&Capability::Network),
            allow_source_snapshot,
            environment_id: task_spec.environment_id.clone(),
            environment_digest: task_spec.environment_digest.clone(),
            source_snapshot: task_spec.source_snapshot.clone(),
            source_revision: task_spec.source_revision.clone(),
            source_root,
            _materialized_source: materialized_source,
            _empty_source: empty_source,
            requested_secrets: task_spec.requested_secrets.clone(),
            output_root,
            task_descriptors,
            environments,
            next_handle_id: 1,
            handles,
            child_joins,
            command_status,
            command_stdout_source_bytes,
            command_stderr_source_bytes,
            command_logs,
            cancellation_requested,
            abort_requested,
            debug_control,
            artifact_warmups,
        };
        Ok(PreparedCoordinatorWasmTaskHost {
            host,
            control_watchers,
        })
    }

    fn session(&self) -> Result<CoordinatorSession, String> {
        CoordinatorSession::connect_with_timeouts(
            &self.args.coordinator,
            WASM_HOST_CONTROL_CONNECT_TIMEOUT,
            WASM_HOST_CONTROL_IO_TIMEOUT,
        )
        .map_err(|error| error.to_string())
    }

    fn signed_request(
        &self,
        request_kind: &str,
        payload: CoordinatorRequest,
    ) -> Result<CoordinatorRequest, String> {
        crate::node_identity::signed_node_assignment_request(
            &self.args,
            &self.node_private_key,
            &self.assignment_authority,
            request_kind,
            payload,
        )
        .map_err(|error| error.to_string())
    }
}
impl CoordinatorWasmTaskHost {
    fn start_task(
        &mut self,
        request: WasmHostTaskStartRequest,
    ) -> Result<WasmHostTaskHandle, String> {
        request.validate()?;
        let descriptor = self
            .task_descriptors
            .get(request.task_definition.as_str())
            .ok_or_else(|| {
                format!(
                    "bundle has no task descriptor named `{}`",
                    request.task_definition
                )
            })?;
        let export = descriptor
            .get("export")
            .and_then(serde_json::Value::as_str)
            .filter(|export| !export.trim().is_empty())
            .ok_or_else(|| {
                format!(
                    "task `{}` descriptor omitted its Wasm export",
                    request.task_definition
                )
            })?;
        let mut required_capabilities = descriptor
            .get("required_capabilities")
            .and_then(serde_json::Value::as_array)
            .into_iter()
            .flatten()
            .map(|value| {
                capability_from_descriptor(
                    value
                        .as_str()
                        .ok_or("task capability descriptor is not a string")?,
                )
            })
            .collect::<Result<BTreeSet<_>, _>>()?;
        let resolved_environment = request
            .environment_id
            .as_deref()
            .map(|name| {
                self.environments.get(name).cloned().ok_or_else(|| {
                    format!("bundle environment manifest has no environment `{name}`")
                })
            })
            .transpose()?;
        let environment = resolved_environment
            .as_ref()
            .map(|environment| environment.requirements.clone());
        let environment_digest = resolved_environment
            .as_ref()
            .map(|environment| environment.digest.clone());
        if let Some(environment) = &environment {
            required_capabilities.extend(environment.capabilities.iter().cloned());
        }
        let handle_id = self.next_handle_id;
        let task_instance = clusterflux_core::TaskInstanceId::new(format!(
            "{}:child:{}",
            self.parent_task, handle_id
        ));
        let required_artifacts = request
            .args
            .iter()
            .flat_map(TaskBoundaryValue::required_artifacts)
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect::<Vec<_>>();
        let source_snapshots = request
            .args
            .iter()
            .flat_map(TaskBoundaryValue::source_snapshots)
            .collect::<BTreeSet<_>>();
        if source_snapshots.len() > 1 {
            return Err(
                "one child task invocation cannot require multiple distinct source snapshots"
                    .to_owned(),
            );
        }
        if self
            .handles
            .lock()
            .map_err(|_| "Wasm task handle registry lock was poisoned".to_owned())?
            .len()
            >= MAX_CHILD_TASK_HANDLES
        {
            return Err(format!(
                "Wasm child task-handle limit of {MAX_CHILD_TASK_HANDLES} reached"
            ));
        }
        let source_snapshot = source_snapshots.into_iter().next();
        let source_revision = self
            .source_revision
            .clone()
            .filter(|revision| source_snapshot.as_ref() == Some(&revision.source_snapshot));
        let spec = TaskSpec {
            tenant: TenantId::from(self.args.tenant.as_str()),
            project: ProjectId::from(self.args.project.as_str()),
            process: ProcessId::from(self.process.as_str()),
            task_definition: request.task_definition.clone(),
            task_instance: task_instance.clone(),
            dispatch: TaskDispatch::CoordinatorNodeWasm {
                export: Some(export.to_owned()),
                abi: WasmExportAbi::TaskV1,
            },
            environment_id: request.environment_id,
            environment,
            environment_digest,
            required_capabilities,
            dependency_cache: None,
            source_snapshot,
            source_revision,
            required_artifacts,
            args: request.args,
            requested_secrets: request.requested_secrets,
            vfs_epoch: self.epoch,
            failure_policy: request.failure_policy,
            bundle_digest: Some(self.bundle_digest.clone()),
        };
        let mut session = self.session()?;
        let artifact_path = format!("/vfs/artifacts/{}-result.json", spec.task_instance);
        let response = session
            .request(self.signed_request(
                "launch_child_task",
                CoordinatorRequest::LaunchChildTask {
                    tenant: self.args.tenant.clone(),
                    project: self.args.project.clone(),
                    process: self.process.clone(),
                    node: self.args.node.clone(),
                    parent_task: self.parent_task.clone(),
                    task_spec: spec.clone(),
                    wait_for_node: true,
                    artifact_path,
                    wasm_module_base64: self.wasm_module_base64.clone(),
                },
            )?)
            .map_err(|error| error.to_string())?;
        match response {
            CoordinatorResponse::TaskLaunched { .. } | CoordinatorResponse::TaskQueued { .. } => {}
            other => return Err(format!("unexpected child launch response {other:?}")),
        }
        self.next_handle_id = self.next_handle_id.saturating_add(1);
        self.handles
            .lock()
            .map_err(|_| "Wasm task handle registry lock was poisoned".to_owned())?
            .insert(handle_id, spec.clone());
        Ok(WasmHostTaskHandle {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            handle_id,
            task_spec: spec,
        })
    }

    fn join_task_spec(&mut self, request: &WasmHostTaskJoinRequest) -> Result<TaskSpec, String> {
        if request.abi_version != clusterflux_core::WASM_TASK_ABI_VERSION {
            return Err(format!(
                "unsupported Wasm task ABI version {}",
                request.abi_version
            ));
        }
        self.handles
            .lock()
            .map_err(|_| "Wasm task handle registry lock was poisoned".to_owned())?
            .get(&request.handle_id)
            .cloned()
            .ok_or_else(|| format!("unknown Wasm task handle {}", request.handle_id))
    }

    fn complete_join_task(
        &mut self,
        handle_id: u64,
        spec: TaskSpec,
        join: TaskJoinResult,
    ) -> Result<WasmHostTaskJoinResult, String> {
        match join.state {
            TaskJoinState::Completed => {
                let result = join
                    .result
                    .ok_or("completed child task omitted its boundary result")?;
                self.handles
                    .lock()
                    .map_err(|_| "Wasm task handle registry lock was poisoned".to_owned())?
                    .remove(&handle_id);
                Ok(WasmHostTaskJoinResult {
                    abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                    task_instance: spec.task_instance,
                    result,
                })
            }
            TaskJoinState::Failed | TaskJoinState::Cancelled => {
                self.handles
                    .lock()
                    .map_err(|_| "Wasm task handle registry lock was poisoned".to_owned())?
                    .remove(&handle_id);
                Err(join.message)
            }
            TaskJoinState::Pending => {
                Err("task-control stream reported a non-terminal child join".to_owned())
            }
        }
    }

    fn abandon_join_task(&mut self, handle_id: u64) -> Result<(), String> {
        self.handles
            .lock()
            .map_err(|_| "Wasm task handle registry lock was poisoned".to_owned())?
            .remove(&handle_id);
        Ok(())
    }

    fn run_command(
        &mut self,
        mut request: clusterflux_core::WasmHostCommandRequest,
    ) -> Result<clusterflux_core::WasmHostCommandResult, String> {
        request.validate()?;
        if !self.allow_command {
            return Err(
                "Wasm task did not declare Command capability or the selected node did not grant it"
                    .to_owned(),
            );
        }
        authorize_command_network(&request.network, self.allow_network)?;
        let environment_id = require_command_environment(self.environment_id.as_deref())?;
        let project_root = &self.source_root;
        let source_inventory = snapshot_project_cancellable(project_root, || {
            self.cancellation_requested.is_cancelled()
                || self.abort_requested.load(Ordering::Acquire)
        })?;
        let source_digest = match (&self.source_snapshot, &self.source_revision) {
            (Some(expected), Some(revision)) => {
                if expected != &revision.source_snapshot {
                    return Err(
                        "materialized Git revision does not match task source handle".to_owned(),
                    );
                }
                expected.clone()
            }
            (Some(expected), None) => {
                if &source_inventory.digest != expected {
                    return Err(format!(
                        "node checkout source snapshot mismatch: task requires {expected}, but the current checkout is {}",
                        source_inventory.digest
                    ));
                }
                expected.clone()
            }
            (None, None) => Digest::from_parts([
                b"clusterflux-empty-task-source:v1".as_slice(),
                self.parent_task.as_bytes(),
            ]),
            (None, Some(_)) => {
                return Err("task carries Git revision metadata without a source handle".to_owned())
            }
        };
        let expected_environment_digest = self.environment_digest.as_ref().ok_or_else(|| {
                format!(
                    "task selected environment `{environment_id}` without a bundle-authoritative environment digest"
                )
            })?;
        let environment_root = if project_root.join("envs").exists() {
            project_root.as_path()
        } else {
            self.args.project_root.as_deref().ok_or_else(|| {
                format!("task selected environment `{environment_id}`, but the node has no environment definitions")
            })?
        };
        let environment = verify_environment_digest(
            environment_root,
            environment_id,
            expected_environment_digest,
        )?;
        let checkout = project_root
            .canonicalize()
            .map_err(|error| format!("resolve node project checkout: {error}"))?;
        let task_id = TaskInstanceId::from(self.parent_task.as_str());
        let mut artifacts =
            TaskArtifactStore::new(task_id.clone(), NodeId::from(self.args.node.as_str()));
        let mut configured_secrets = Zeroizing::new(Vec::new());
        for (environment_name, secret_name) in &request.secret_environment_variables {
            if !self
                .requested_secrets
                .iter()
                .any(|name| name == secret_name)
            {
                return Err(format!(
                    "command requested undeclared task secret `{secret_name}`"
                ));
            }
            let mut session = self.session()?;
            let response = session
                .request(self.signed_request(
                    "poll_task_secret_grant",
                    CoordinatorRequest::PollTaskSecretGrant {
                        tenant: self.args.tenant.clone(),
                        project: self.args.project.clone(),
                        node: self.args.node.clone(),
                        process: self.process.clone(),
                        task: self.parent_task.clone(),
                        secret_name: secret_name.clone(),
                    },
                )?)
                .map_err(|error| error.to_string())?;
            let CoordinatorResponse::TaskSecretGrant { grant: Some(grant) } = response else {
                return Err("task secret grant is unavailable".to_owned());
            };
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map_err(|_| "system clock is before the Unix epoch".to_owned())?
                .as_secs();
            validate_task_secret_grant(&grant, secret_name, &self.process, &self.parent_task, now)?;
            let value = BASE64_STANDARD
                .decode(grant.value_base64.expose_base64())
                .map_err(|_| "task secret grant value is malformed".to_owned())?;
            let value = String::from_utf8(value).map_err(|_| {
                "task secret is not valid UTF-8 for environment injection".to_owned()
            })?;
            configured_secrets.push(value.clone());
            request
                .environment_variables
                .insert(environment_name.clone(), value);
        }
        configured_secrets.extend(
            request
                .environment_variables
                .iter()
                .filter(|(name, value)| is_secret_environment_name(name) && !value.is_empty())
                .map(|(_, value)| value.clone()),
        );
        let secret_environment_names = request
            .secret_environment_variables
            .keys()
            .cloned()
            .collect::<BTreeSet<_>>();
        let mut runner = CoordinatorControlledProcessRunner::new(
            self,
            Duration::from_millis(request.timeout_ms),
            configured_secrets.to_vec(),
        );
        let mut invocation = CommandInvocation {
            program: request.program,
            args: request.args,
            working_directory: request.working_directory,
            environment_variables: request.environment_variables,
            timeout_ms: request.timeout_ms,
            network: request.network,
            env: Some(environment),
        };
        let task_request = LocalCheckoutTaskRequest {
            process: ProcessId::from(self.process.as_str()),
            virtual_thread: task_id,
            execution_attempt: format!(
                "{}:{}",
                self.assignment_authority.assignment_id, self.assignment_authority.attempt_id
            ),
            invocation: &invocation,
            checkout: LocalSourceCheckout {
                snapshot: source_digest,
                host_path: checkout,
                inventory: Some(source_inventory),
            },
            output_root: self.output_root.clone(),
            stage_stdout_as: None,
            system_package_dir: self.args.system_compiler_package_dir.clone(),
            run_policy: self.args.task_container_policy(),
            cancellation: LocalTaskCancellation::new(
                self.cancellation_requested.clone(),
                Arc::clone(&self.abort_requested),
            ),
        };
        let execution = if self.args.dangerous_allow_native_commands {
            execute_dangerous_native_checkout_task(
                task_request,
                &mut runner,
                artifacts.overlay_mut(),
            )
        } else {
            match Os::current() {
                Os::Linux => LinuxRootlessPodmanBackend.execute_local_checkout_task(
                    task_request,
                    &mut runner,
                    artifacts.overlay_mut(),
                ),
                Os::Windows => WindowsContainerdNerdctlBackend.execute_local_checkout_task(
                    task_request,
                    &mut runner,
                    artifacts.overlay_mut(),
                ),
                Os::Macos | Os::Other(_) => Err(BackendError::Denied(
                    "this platform has no configured container command backend; native execution requires --dangerous-allow-native-commands"
                        .to_owned(),
                )),
            }
        };
        for (name, value) in &mut invocation.environment_variables {
            if secret_environment_names.contains(name) || is_secret_environment_name(name) {
                value.zeroize();
            }
        }
        let output = execution.map_err(|error| {
            if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
                eprintln!("clusterflux command host failed: {error}");
            }
            error.to_string()
        })?;
        let stdout = redact_configured_values(output.stdout.clone(), &configured_secrets);
        let stderr = redact_configured_values(output.stderr.clone(), &configured_secrets);
        if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
            eprintln!(
                "clusterflux command host completed: status={:?} stdout={:?} stderr={:?}",
                output.status_code, stdout, stderr
            );
        }
        let output = CommandOutput {
            virtual_thread: output.virtual_thread,
            status_code: output.status_code,
            stdout,
            stderr,
            stdout_source_bytes: self.command_stdout_source_bytes.load(Ordering::Relaxed),
            stderr_source_bytes: self.command_stderr_source_bytes.load(Ordering::Relaxed),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
            log_backpressured: output.log_backpressured,
            staged_artifact: output.staged_artifact,
        };
        self.command_logs
            .lock()
            .map_err(|_| "native command log state lock was poisoned".to_owned())?
            .record(&output);
        bounded_wasm_command_result(&output)
    }

    fn debug_probe(
        &mut self,
        request: WasmHostDebugProbeRequest,
    ) -> Result<WasmHostDebugProbeResult, String> {
        request.validate()?;
        let source_location = request.source_location.clone();
        let mut session = self.session()?;
        let response = session
            .request(self.signed_request(
                "report_debug_probe_hit",
                CoordinatorRequest::ReportDebugProbeHit {
                    tenant: self.args.tenant.clone(),
                    project: self.args.project.clone(),
                    process: self.process.clone(),
                    node: self.args.node.clone(),
                    task: self.parent_task.clone(),
                    probe_symbol: request.symbol,
                },
            )?)
            .map_err(|error| error.to_string())?;
        let CoordinatorResponse::DebugProbeHit {
            breakpoint_matched,
            debug_epoch,
            ..
        } = response
        else {
            return Err("coordinator returned an unexpected debug-probe response".to_owned());
        };
        self.debug_control.record_source_location(source_location);
        let result = WasmHostDebugProbeResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            breakpoint_matched,
            debug_epoch,
        };
        if result.breakpoint_matched {
            if let Some(epoch) = result.debug_epoch {
                self.debug_control.request_freeze(epoch);
            }
        }
        Ok(result)
    }

    fn vfs_operation(&mut self, request: WasmHostVfsRequest) -> Result<WasmHostVfsResult, String> {
        request.validate()?;
        let store =
            NodeArtifactStore::for_runtime(self.args.project_root.as_deref(), &self.args.node)?;
        let (retained, relative_path) = match request.operation {
            WasmHostVfsOperation::FlushOutput { relative_path } => {
                let retained = store.retain_output_file(&self.output_root, &relative_path)?;
                (retained, relative_path)
            }
            WasmHostVfsOperation::MaterializeArtifact {
                artifact,
                relative_path,
            } => {
                if let Some(warmups) = &self.artifact_warmups {
                    warmups.materialize(
                        &ProcessId::from(self.process.as_str()),
                        &TaskInstanceId::from(self.parent_task.as_str()),
                        &artifact,
                        &self.output_root,
                        &relative_path,
                        &self.cancellation_requested,
                        &self.abort_requested,
                    )?;
                } else {
                    store.materialize_into_output(&artifact, &self.output_root, &relative_path)?;
                }
                let retained = store
                    .metadata(&artifact.id)?
                    .ok_or_else(|| format!("artifact `{}` became unavailable", artifact.id))?;
                (retained, relative_path)
            }
            WasmHostVfsOperation::ReleaseArtifact { artifact } => {
                let process = ProcessId::from(self.process.as_str());
                let task = TaskInstanceId::from(self.parent_task.as_str());
                let mut session = self.session()?;
                let response = session
                    .request(self.signed_request(
                        "release_artifact",
                        CoordinatorRequest::ReleaseArtifact {
                            tenant: self.args.tenant.clone(),
                            project: self.args.project.clone(),
                            process: self.process.clone(),
                            node: self.args.node.clone(),
                            task: self.parent_task.clone(),
                            artifact: artifact.id.to_string(),
                            digest: artifact.digest.clone(),
                            size_bytes: artifact.size_bytes,
                        },
                    )?)
                    .map_err(|error| error.to_string())?;
                if !matches!(response, CoordinatorResponse::ArtifactReleased { .. }) {
                    return Err(
                        "coordinator returned an unexpected artifact-release response".to_owned(),
                    );
                }
                if let Some(warmups) = &self.artifact_warmups {
                    warmups.release(&process, &task, &artifact);
                }
                let retained = store.metadata(&artifact.id)?.unwrap_or(
                    crate::task_artifacts::RetainedArtifact {
                        id: artifact.id,
                        digest: artifact.digest,
                        size_bytes: artifact.size_bytes,
                        path: PathBuf::new(),
                    },
                );
                (retained, String::new())
            }
        };
        Ok(WasmHostVfsResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            artifact: clusterflux_core::ArtifactHandle {
                id: retained.id,
                digest: retained.digest,
                size_bytes: retained.size_bytes,
            },
            relative_path,
        })
    }

    fn snapshot_source(
        &mut self,
        request: WasmHostSourceSnapshotRequest,
    ) -> Result<WasmHostSourceSnapshotResult, String> {
        request.validate()?;
        if !self.allow_source_snapshot {
            return Err(
                "Wasm task did not declare SourceFilesystem capability or the selected node did not grant it"
                    .to_owned(),
            );
        }
        let snapshot = authoritative_source_snapshot(
            &self.source_root,
            self.source_snapshot.as_ref(),
            self.source_revision.as_ref(),
            || {
                self.cancellation_requested.is_cancelled()
                    || self.abort_requested.load(Ordering::Acquire)
            },
        )?;
        Ok(WasmHostSourceSnapshotResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            snapshot,
        })
    }
}

fn authoritative_source_snapshot(
    source_root: &Path,
    source_snapshot: Option<&Digest>,
    source_revision: Option<&clusterflux_core::RepositoryRevision>,
    cancelled: impl Fn() -> bool,
) -> Result<Digest, String> {
    match (source_snapshot, source_revision) {
        // The revision handle is an authority over repository identity, clone URL, and
        // commit, not the digest produced by snapshotting a checkout. `prepare` has
        // already validated this metadata and materialized that exact commit.
        (Some(expected), Some(revision)) => {
            if expected != &revision.source_snapshot {
                return Err(
                    "materialized Git revision does not match task source handle".to_owned(),
                );
            }
            Ok(expected.clone())
        }
        (Some(expected), None) => Ok(verify_source_snapshot(source_root, expected)?.digest),
        (None, None) => Ok(snapshot_project_cancellable(source_root, cancelled)?.digest),
        (None, Some(_)) => {
            Err("task carries Git revision metadata without a source handle".to_owned())
        }
    }
}

fn validate_task_secret_grant(
    grant: &clusterflux_protocol::TaskSecretGrant,
    secret_name: &str,
    process: &str,
    task: &str,
    now: u64,
) -> Result<(), String> {
    if grant.secret_name != secret_name
        || grant.process.as_str() != process
        || grant.task.as_str() != task
    {
        return Err("task secret grant scope does not match its command".to_owned());
    }
    if now >= grant.expires_at_epoch_seconds {
        return Err("task secret grant expired before command injection".to_owned());
    }
    Ok(())
}

struct AsyncCoordinatorWasmTaskHost {
    inner: Arc<Mutex<CoordinatorWasmTaskHost>>,
    cancellation_requested: CancellationToken,
    abort_requested: Arc<AtomicBool>,
    debug_control: Arc<WasmDebugControl>,
    child_joins: Arc<ChildJoinNotifications>,
}

impl AsyncCoordinatorWasmTaskHost {
    fn new(host: CoordinatorWasmTaskHost) -> Self {
        let cancellation_requested = host.cancellation_requested.clone();
        let abort_requested = Arc::clone(&host.abort_requested);
        let debug_control = Arc::clone(&host.debug_control);
        let child_joins = Arc::clone(&host.child_joins);
        Self {
            inner: Arc::new(Mutex::new(host)),
            cancellation_requested,
            abort_requested,
            debug_control,
            child_joins,
        }
    }
}

async fn blocking_host_call<T, F>(
    host: Arc<Mutex<CoordinatorWasmTaskHost>>,
    call: F,
) -> Result<T, String>
where
    T: Send + 'static,
    F: FnOnce(&mut CoordinatorWasmTaskHost) -> Result<T, String> + Send + 'static,
{
    tokio::task::spawn_blocking(move || {
        let mut host = host
            .lock()
            .map_err(|_| "Wasm task host lock was poisoned".to_owned())?;
        call(&mut host)
    })
    .await
    .map_err(|error| format!("Wasm task host blocking operation failed: {error}"))?
}

async fn abandon_child_join(
    host: Arc<Mutex<CoordinatorWasmTaskHost>>,
    handle_id: u64,
    error: String,
) -> Result<WasmHostTaskJoinResult, String> {
    blocking_host_call(host, move |host| host.abandon_join_task(handle_id)).await?;
    Err(error)
}

impl AsyncWasmTaskHost for AsyncCoordinatorWasmTaskHost {
    fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
        Some(Arc::clone(&self.abort_requested))
    }

    fn debug_control(&self) -> Option<Arc<WasmDebugControl>> {
        Some(Arc::clone(&self.debug_control))
    }

    fn start_task(
        &mut self,
        request: WasmHostTaskStartRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskHandle> {
        let host = Arc::clone(&self.inner);
        Box::pin(
            async move { blocking_host_call(host, move |host| host.start_task(request)).await },
        )
    }

    fn join_task(
        &mut self,
        request: WasmHostTaskJoinRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskJoinResult> {
        let host = Arc::clone(&self.inner);
        let cancellation_requested = self.cancellation_requested.clone();
        let abort_requested = Arc::clone(&self.abort_requested);
        let child_joins = Arc::clone(&self.child_joins);
        Box::pin(async move {
            let started = Instant::now();
            let task_spec = blocking_host_call(Arc::clone(&host), {
                let request = request.clone();
                move |host| host.join_task_spec(&request)
            })
            .await?;
            let task = task_spec.task_instance.clone();
            loop {
                // Register for notification before inspecting terminal state so a
                // completion racing this check cannot be missed.
                let notified = child_joins.changed.notified();
                tokio::pin!(notified);
                notified.as_mut().enable();
                if let Some(join) = child_joins.take(&task)? {
                    return blocking_host_call(Arc::clone(&host), move |host| {
                        host.complete_join_task(request.handle_id, task_spec, join)
                    })
                    .await;
                }
                if cancellation_requested.is_cancelled() || abort_requested.load(Ordering::Acquire)
                {
                    let error =
                        clusterflux_core::limits::TaskJoinError::Cancelled { task: task.clone() }
                            .to_string();
                    return abandon_child_join(Arc::clone(&host), request.handle_id, error).await;
                }
                let join_timeout = clusterflux_core::limits::task_join_timeout();
                let remaining = join_timeout.saturating_sub(started.elapsed());
                if remaining.is_zero() {
                    let error = clusterflux_core::limits::TaskJoinError::timeout(
                        task.clone(),
                        join_timeout,
                    )
                    .to_string();
                    return abandon_child_join(Arc::clone(&host), request.handle_id, error).await;
                }
                tokio::select! {
                    () = &mut notified => {}
                    () = cancellation_requested.cancelled() => {
                        let error = clusterflux_core::limits::TaskJoinError::Cancelled {
                            task: task.clone(),
                        }.to_string();
                        return abandon_child_join(
                            Arc::clone(&host),
                            request.handle_id,
                            error,
                        ).await;
                    }
                    () = tokio::time::sleep(remaining) => {
                        let error = clusterflux_core::limits::TaskJoinError::timeout(
                            task.clone(),
                            join_timeout,
                        ).to_string();
                        return abandon_child_join(
                            Arc::clone(&host),
                            request.handle_id,
                            error,
                        ).await;
                    }
                }
            }
        })
    }

    fn run_command(
        &mut self,
        request: clusterflux_core::WasmHostCommandRequest,
    ) -> WasmHostFuture<'_, clusterflux_core::WasmHostCommandResult> {
        let host = Arc::clone(&self.inner);
        Box::pin(async move {
            let result = blocking_host_call(host, move |host| host.run_command(request)).await;
            if std::env::var_os("CLUSTERFLUX_DEBUG_CONTROL_TRACE").is_some() {
                if let Err(error) = &result {
                    eprintln!("clusterflux command host rejected request: {error}");
                }
            }
            result
        })
    }

    fn poll_task_control(
        &mut self,
        request: clusterflux_core::WasmHostTaskControlRequest,
    ) -> WasmHostFuture<'_, clusterflux_core::WasmHostTaskControlResult> {
        let cancellation_requested = self.cancellation_requested.clone();
        Box::pin(async move {
            request.validate()?;
            Ok(clusterflux_core::WasmHostTaskControlResult {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                cancellation_requested: cancellation_requested.is_cancelled(),
            })
        })
    }

    fn debug_probe(
        &mut self,
        request: WasmHostDebugProbeRequest,
    ) -> WasmHostFuture<'_, WasmHostDebugProbeResult> {
        let host = Arc::clone(&self.inner);
        Box::pin(
            async move { blocking_host_call(host, move |host| host.debug_probe(request)).await },
        )
    }

    fn vfs_operation(
        &mut self,
        request: WasmHostVfsRequest,
    ) -> WasmHostFuture<'_, WasmHostVfsResult> {
        let host = Arc::clone(&self.inner);
        Box::pin(
            async move { blocking_host_call(host, move |host| host.vfs_operation(request)).await },
        )
    }

    fn snapshot_source(
        &mut self,
        request: WasmHostSourceSnapshotRequest,
    ) -> WasmHostFuture<'_, WasmHostSourceSnapshotResult> {
        let host = Arc::clone(&self.inner);
        Box::pin(async move {
            blocking_host_call(host, move |host| host.snapshot_source(request)).await
        })
    }
}

#[cfg(test)]
mod tests;
