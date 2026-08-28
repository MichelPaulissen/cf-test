use std::io::{BufRead, BufReader};
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::{Duration, Instant};

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_client::MAX_CONTROL_FRAME_BYTES;
use clusterflux_core::{
    Digest, ProcessId, ProjectId, TaskDefinitionId, TaskDispatch, TaskInstanceId, TaskSpec,
    TenantId, WasmExportAbi,
};
use clusterflux_protocol::{
    CoordinatorRequest, CoordinatorResponse, DebugParticipantAcknowledgement, TaskReplacementBundle,
};
use serde_json::{json, Value};

use crate::virtual_model::{AdapterState, RuntimeLaunchRecord};

mod debug_protocol;
mod local_tools;
mod transport;
pub(crate) use debug_protocol::parse_task_restart_response;
use debug_protocol::{
    coordinator_debug_epoch_request, parse_debug_epoch_response, wait_for_debug_epoch_state,
};
use local_tools::{child_stderr_suffix, local_tool_command};
pub(crate) use transport::client_user_request;
use transport::{coordinator_request, coordinator_request_allow_error, CoordinatorSession};

pub(crate) struct LocalRuntimeSession {
    coordinator: Option<Child>,
    worker: Option<Child>,
}

impl Drop for LocalRuntimeSession {
    fn drop(&mut self) {
        for child in [&mut self.worker, &mut self.coordinator] {
            if let Some(mut child) = child.take() {
                let _ = child.kill();
                let _ = child.wait();
            }
        }
    }
}

#[derive(Debug)]
struct DebugBundle {
    module_base64: String,
    module_size_bytes: usize,
    digest: Digest,
    source_snapshot: Digest,
    entry_export: String,
    entry_name: String,
}

const INLINE_BUNDLE_REQUEST_OVERHEAD_BYTES: usize = 96 * 1024;
const MAX_INLINE_WASM_MODULE_BYTES: usize =
    ((MAX_CONTROL_FRAME_BYTES - INLINE_BUNDLE_REQUEST_OVERHEAD_BYTES) / 4) * 3;
const LOCAL_NODE_ATTACH_TIMEOUT: Duration = Duration::from_secs(5 * 60);
const LOCAL_NODE_ENROLLMENT_TTL_SECONDS: u64 = 10 * 60;

struct ChildGuard(Option<Child>);

impl ChildGuard {
    fn new(child: Child) -> Self {
        Self(Some(child))
    }

    fn child_mut(&mut self) -> &mut Child {
        self.0.as_mut().expect("guarded child is present")
    }

    fn take(&mut self) -> Child {
        self.0.take().expect("guarded child is present")
    }
}

impl Drop for ChildGuard {
    fn drop(&mut self) {
        if let Some(mut child) = self.0.take() {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct DebugEpochRecord {
    pub(crate) epoch: u64,
    pub(crate) command: String,
    pub(crate) affected_tasks: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, serde::Serialize)]
pub(crate) struct DebugEpochStatusRecord {
    pub(crate) epoch: u64,
    pub(crate) command: String,
    pub(crate) expected_tasks: usize,
    pub(crate) acknowledgements: Vec<DebugParticipantAcknowledgement>,
    pub(crate) fully_frozen: bool,
    pub(crate) partially_frozen: bool,
    pub(crate) fully_resumed: bool,
    pub(crate) failed: bool,
    pub(crate) failure_messages: Vec<String>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct TaskRestartRecord {
    pub(crate) accepted: bool,
    pub(crate) restarted_task_instance: Option<TaskInstanceId>,
    pub(crate) restarted_attempt_id: Option<String>,
    pub(crate) clean_boundary_available: bool,
    pub(crate) requires_whole_process_restart: bool,
    pub(crate) active_task: bool,
    pub(crate) completed_event_observed: bool,
    pub(crate) message: String,
}

pub(crate) enum RuntimeContinuationOutcome {
    Snapshot(RuntimeLaunchRecord),
    Diagnostic(String),
    Breakpoint(RuntimeLaunchRecord),
    Exception(RuntimeLaunchRecord),
    Terminal(RuntimeLaunchRecord),
}

pub(crate) fn run_local_services_runtime(
    state: &mut AdapterState,
) -> Result<(RuntimeLaunchRecord, LocalRuntimeSession)> {
    let repo = std::env::current_dir()?;
    let mut coordinator_command = local_tool_command(
        "CLUSTERFLUX_COORDINATOR_BIN",
        "clusterflux-coordinator",
        "clusterflux-coordinator",
        &repo,
    );
    let mut coordinator = coordinator_command
        .args(["--listen", "127.0.0.1:0", "--allow-local-trusted-loopback"])
        .current_dir(&repo)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let result = (|| {
        let stdout = coordinator
            .stdout
            .take()
            .ok_or_else(|| anyhow!("coordinator stdout was not captured"))?;
        let mut ready_line = String::new();
        BufReader::new(stdout).read_line(&mut ready_line)?;
        let ready: Value = serde_json::from_str(&ready_line)?;
        let listen = ready
            .get("listen")
            .and_then(Value::as_str)
            .ok_or_else(|| anyhow!("coordinator did not report a listen address"))?
            .to_owned();
        let project_response = coordinator_request(
            &listen,
            CoordinatorRequest::CreateProject {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                name: "DAP local services project".to_owned(),
            },
        )?;
        if !matches!(project_response, CoordinatorResponse::ProjectCreated { .. }) {
            return Err(anyhow!(
                "local coordinator returned an unexpected project-create response"
            ));
        }
        let enrollment = coordinator_request(
            &listen,
            CoordinatorRequest::CreateNodeEnrollmentGrant {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                ttl_seconds: LOCAL_NODE_ENROLLMENT_TTL_SECONDS,
            },
        )?;
        let enrollment_grant = match enrollment {
            CoordinatorResponse::NodeEnrollmentGrantCreated { grant, .. } => grant,
            _ => {
                return Err(anyhow!(
                    "local coordinator returned an unexpected enrollment response"
                ))
            }
        };

        let mut worker_command = local_tool_command(
            "CLUSTERFLUX_NODE_BIN",
            "clusterflux-node",
            "clusterflux-node",
            &repo,
        );
        let mut worker = ChildGuard::new(
            worker_command
                .args([
                    "--coordinator",
                    &listen,
                    "--tenant",
                    state.tenant.as_str(),
                    "--project-id",
                    state.project_id.as_str(),
                    "--node",
                    "dap-node",
                    "--enrollment-grant",
                    &enrollment_grant,
                    "--worker",
                    "--project-root",
                    &state.project,
                    "--assignment-poll-ms",
                    "100",
                    "--no-workflow-compilation",
                ])
                .current_dir(&repo)
                .stdout(Stdio::null())
                .stderr(Stdio::piped())
                .spawn()?,
        );
        wait_for_local_node(&listen, state, "dap-node", worker.child_mut())?;

        let record = launch_services_debug_entrypoint(&listen, state, &repo)?;
        Ok((record, worker.take()))
    })();
    match result {
        Ok((record, worker)) => Ok((
            record,
            LocalRuntimeSession {
                coordinator: Some(coordinator),
                worker: Some(worker),
            },
        )),
        Err(error) => {
            let _ = coordinator.kill();
            let _ = coordinator.wait();
            Err(error)
        }
    }
}

fn build_debug_bundle(state: &AdapterState, repo: &Path) -> Result<DebugBundle> {
    let mut command = local_tool_command(
        "CLUSTERFLUX_CLI_BIN",
        "clusterflux",
        "clusterflux-cli",
        repo,
    );
    command.args(["build", "--project", &state.project]);
    if let Some(entry) = state.requested_entrypoint.as_deref() {
        command.args(["--entry", entry]);
    }
    let output = command.arg("--json").current_dir(repo).output()?;
    if !output.status.success() {
        return Err(anyhow!(
            "Clusterflux bundle build failed before debug launch: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let report: Value = serde_json::from_slice(&output.stdout)?;
    debug_bundle_from_build_report(&report, repo, state.requested_entrypoint.as_deref())
}

fn debug_bundle_from_build_report(
    report: &Value,
    repo: &Path,
    requested_entrypoint: Option<&str>,
) -> Result<DebugBundle> {
    let module_path = report
        .pointer("/bundle_artifact/module")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("bundle build omitted module path"))?;
    let module_path = if Path::new(module_path).is_absolute() {
        Path::new(module_path).to_path_buf()
    } else {
        repo.join(module_path)
    };
    let module = std::fs::read(&module_path)?;
    let descriptor = report
        .get("selected_entrypoint")
        .ok_or_else(|| anyhow!("bundle build report omitted selected entrypoint"))?;
    let selected_name = descriptor.get("name").and_then(Value::as_str);
    if requested_entrypoint.is_some() && requested_entrypoint != selected_name {
        return Err(anyhow!("bundle build selected an unexpected entrypoint"));
    }
    let entry = selected_name.ok_or_else(|| anyhow!("selected entrypoint omitted its name"))?;
    let entry_export = descriptor
        .get("export")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("entrypoint `{entry}` omitted its Wasm export"))?
        .to_owned();
    let entry_name = descriptor
        .get("name")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("entrypoint `{entry}` omitted its registered name"))?
        .to_owned();
    let digest = report
        .pointer("/bundle_artifact/execution_module_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("bundle build omitted execution module digest"))?;
    let digest = Digest::from_sha256_hex(
        digest
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("bundle build returned a malformed SHA-256 digest"))?,
    )
    .map_err(|error| anyhow!("bundle build returned a malformed SHA-256 digest: {error}"))?;
    let actual_digest = Digest::sha256(&module);
    if actual_digest != digest {
        return Err(anyhow!(
            "built Wasm module digest changed before debug launch: expected {digest}, actual {actual_digest}"
        ));
    }
    let debug_sidecar_path = report
        .pointer("/bundle_artifact/debug_sidecar")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("bundle build omitted debug sidecar path"))?;
    let debug_sidecar_path = if Path::new(debug_sidecar_path).is_absolute() {
        Path::new(debug_sidecar_path).to_path_buf()
    } else {
        repo.join(debug_sidecar_path)
    };
    let debug_sidecar = std::fs::read(&debug_sidecar_path)?;
    let debug_digest = report
        .pointer("/bundle_artifact/debug_sidecar_digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("bundle build omitted debug sidecar digest"))?;
    if Digest::sha256(&debug_sidecar).as_str() != debug_digest {
        return Err(anyhow!("debug sidecar digest changed before debug launch"));
    }
    let debug: Value = serde_json::from_slice(&debug_sidecar)
        .map_err(|error| anyhow!("parse workflow debug sidecar: {error}"))?;
    if debug.get("format").and_then(Value::as_str) != Some("clusterflux-wasm-debug-v2")
        || debug
            .pointer("/path_remapping/0/from")
            .and_then(Value::as_str)
            != Some("/workflow")
        || debug
            .pointer("/path_remapping/0/to")
            .and_then(Value::as_str)
            != Some(".clusterflux")
    {
        return Err(anyhow!(
            "workflow debug sidecar has invalid source remapping"
        ));
    }
    let source_inventory = debug
        .get("source_inventory")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("workflow debug sidecar omitted compiled source inventory"))?;
    if source_inventory.is_empty()
        || source_inventory.iter().any(|path| {
            path.as_str().is_none_or(|path| {
                !path.starts_with(".clusterflux/") || path.contains("..") || path.contains('\\')
            })
        })
    {
        return Err(anyhow!(
            "workflow debug sidecar source inventory is invalid"
        ));
    }
    let section_names = debug
        .get("sections")
        .and_then(Value::as_array)
        .ok_or_else(|| anyhow!("workflow debug sidecar omitted raw sections"))?
        .iter()
        .filter_map(|section| section.get("name").and_then(Value::as_str))
        .collect::<std::collections::BTreeSet<_>>();
    if !section_names.contains(".debug_info") || !section_names.contains(".debug_line") {
        return Err(anyhow!(
            "workflow debug sidecar omitted DWARF info or line tables"
        ));
    }
    let source_snapshot = report
        .pointer("/source_snapshot/digest")
        .and_then(Value::as_str)
        .ok_or_else(|| anyhow!("bundle build omitted source snapshot digest"))?;
    let source_snapshot = Digest::from_sha256_hex(
        source_snapshot
            .strip_prefix("sha256:")
            .ok_or_else(|| anyhow!("bundle build returned a malformed source snapshot digest"))?,
    )
    .map_err(|error| {
        anyhow!("bundle build returned a malformed source snapshot digest: {error}")
    })?;
    Ok(DebugBundle {
        module_size_bytes: module.len(),
        module_base64: BASE64_STANDARD.encode(module),
        digest,
        source_snapshot,
        entry_export,
        entry_name,
    })
}

fn launch_services_debug_entrypoint(
    coordinator: &str,
    state: &mut AdapterState,
    repo: &Path,
) -> Result<RuntimeLaunchRecord> {
    let bundle = build_debug_bundle(state, repo)?;
    state.entry = bundle.entry_name.clone();
    state.process = crate::virtual_model::process_id(&state.project, &state.entry);
    validate_inline_bundle_size(bundle.module_size_bytes)?;
    let launch_attempt = new_launch_attempt_id();
    let started = match coordinator_request_allow_error(
        coordinator,
        client_user_request(
            state,
            CoordinatorRequest::StartProcess {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: Some(state.actor_user.to_string()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: state.process.to_string(),
                launch_attempt: Some(launch_attempt.clone()),
                restart: state.restart_existing,
            },
        ),
    ) {
        Ok(started) => started,
        Err(error) => {
            return Err(debug_launch_error_with_rollback(
                coordinator,
                state,
                &launch_attempt,
                error,
            ));
        }
    };
    if let CoordinatorResponse::Error { error } = &started {
        return Err(anyhow!("{}", error.message));
    }
    let (started_launch_attempt, epoch) = match &started {
        CoordinatorResponse::ProcessStarted {
            launch_attempt,
            epoch,
            ..
        } => (launch_attempt.as_deref(), *epoch),
        _ => {
            return Err(debug_launch_error_with_rollback(
                coordinator,
                state,
                &launch_attempt,
                anyhow!("coordinator returned an unexpected process-start response"),
            ))
        }
    };
    if started_launch_attempt != Some(launch_attempt.as_str()) {
        return Err(debug_launch_error_with_rollback(
            coordinator,
            state,
            &launch_attempt,
            anyhow!("coordinator returned a debug launch owned by a different attempt"),
        ));
    }
    if let Err(error) = set_services_debug_breakpoints_at(coordinator, state) {
        return Err(debug_launch_error_with_rollback(
            coordinator,
            state,
            &launch_attempt,
            error,
        ));
    }
    let launch = match coordinator_request(
        coordinator,
        client_user_request(
            state,
            CoordinatorRequest::LaunchTask {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: Some(state.actor_user.to_string()),
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                task_spec: TaskSpec {
                    tenant: TenantId::new(state.tenant.to_string()),
                    project: ProjectId::new(state.project_id.to_string()),
                    process: ProcessId::new(state.process.to_string()),
                    task_definition: TaskDefinitionId::new(bundle.entry_name),
                    task_instance: TaskInstanceId::new(format!("ti:{}:main", state.process)),
                    dispatch: TaskDispatch::CoordinatorNodeWasm {
                        export: Some(bundle.entry_export),
                        abi: WasmExportAbi::EntrypointV1,
                    },
                    environment_id: None,
                    environment: None,
                    environment_digest: None,
                    required_capabilities: Default::default(),
                    dependency_cache: None,
                    source_snapshot: Some(bundle.source_snapshot),
                    source_revision: None,
                    required_artifacts: Vec::new(),
                    args: Vec::new(),
                    requested_secrets: Vec::new(),
                    vfs_epoch: epoch,
                    failure_policy: Default::default(),
                    bundle_digest: Some(bundle.digest),
                },
                wait_for_node: true,
                artifact_path: "/vfs/artifacts/dap-output.txt".to_owned(),
                wasm_module_base64: bundle.module_base64,
            },
        ),
    ) {
        Ok(launch) => launch,
        Err(error) => {
            return Err(debug_launch_error_with_rollback(
                coordinator,
                state,
                &launch_attempt,
                error,
            ));
        }
    };
    if !matches!(&launch, CoordinatorResponse::MainLaunched { .. }) {
        return Err(debug_launch_error_with_rollback(
            coordinator,
            state,
            &launch_attempt,
            anyhow!(
                "coordinator did not start the capless main runtime: {}",
                serde_json::to_string(&launch)?
            ),
        ));
    }
    // The launch acknowledgement is the commit point. Failures while fetching
    // observation state after this line must not abort a process that is running.
    let mut observation_diagnostics = Vec::new();
    let inject_post_commit_observation_failure =
        std::env::var_os("CLUSTERFLUX_TEST_DAP_POST_COMMIT_OBSERVATION_FAILURE").is_some();
    let task_snapshots = (if inject_post_commit_observation_failure {
        Err(anyhow!("injected post-commit task observation failure"))
    } else {
        fetch_task_snapshots(coordinator, state)
    })
    .unwrap_or_else(|error| {
        observation_diagnostics.push(format!(
            "initial task observation failed after main_launched: {error:#}"
        ));
        json!({ "snapshots": [] })
    });
    let (process_statuses, process_status) = (if inject_post_commit_observation_failure {
        Err(anyhow!("injected post-commit process observation failure"))
    } else {
        fetch_current_process_status(coordinator, state)
    })
    .unwrap_or_else(|error| {
        observation_diagnostics.push(format!(
            "initial process observation failed after main_launched: {error:#}"
        ));
        (json!({ "processes": [] }), None)
    });
    let node = process_status
        .as_ref()
        .and_then(|status| status.get("connected_nodes"))
        .and_then(Value::as_array)
        .and_then(|nodes| nodes.first())
        .and_then(Value::as_str)
        .unwrap_or("coordinator-main")
        .to_owned();
    Ok(RuntimeLaunchRecord {
        coordinator: coordinator.to_owned(),
        node,
        node_report: json!({
            "process": started,
            "task_launch": launch,
            "process_status": process_status,
            "process_statuses": process_statuses,
            "task_snapshots": task_snapshots,
            "observation_diagnostics": observation_diagnostics,
        }),
        task_events: json!({ "events": [] }),
        placed_task_launched: true,
        status_code: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        event_count: 0,
        debug_epoch: None,
        stopped_task: None,
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch: state.source_mismatch.clone(),
        all_participants_frozen: false,
    })
}

fn validate_inline_bundle_size(module_size_bytes: usize) -> Result<()> {
    if module_size_bytes <= MAX_INLINE_WASM_MODULE_BYTES {
        return Ok(());
    }
    Err(anyhow!(
        "built Wasm module is {module_size_bytes} bytes, but the current {MAX_CONTROL_FRAME_BYTES}-byte inline control frame supports at most {MAX_INLINE_WASM_MODULE_BYTES} raw bytes; no virtual process was created"
    ))
}

fn debug_launch_error_with_rollback(
    coordinator: &str,
    state: &AdapterState,
    launch_attempt: &str,
    launch_error: anyhow::Error,
) -> anyhow::Error {
    let rollback = coordinator_request(
        coordinator,
        client_user_request(
            state,
            CoordinatorRequest::AbortProcess {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
                launch_attempt: Some(launch_attempt.to_owned()),
            },
        ),
    );
    match rollback {
        Ok(CoordinatorResponse::ProcessAborted { .. }) => launch_error,
        Ok(response) => {
            anyhow!("{launch_error}; debug launch rollback was not acknowledged: {response:?}")
        }
        Err(rollback_error) => {
            anyhow!("{launch_error}; debug launch rollback also failed: {rollback_error}")
        }
    }
}

static NEXT_LAUNCH_ATTEMPT: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(1);

fn new_launch_attempt_id() -> String {
    let sequence = NEXT_LAUNCH_ATTEMPT.fetch_add(1, Ordering::Relaxed);
    let nanos = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_nanos();
    format!("dap-launch-{}-{nanos}-{sequence}", std::process::id())
}

fn set_services_debug_breakpoints_at(coordinator: &str, state: &AdapterState) -> Result<()> {
    static INJECTED_INSTALL_FAILURE: AtomicBool = AtomicBool::new(false);
    if std::env::var("CLUSTERFLUX_TEST_DAP_BREAKPOINT_DELAY_REVISION")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        == Some(state.breakpoint_revision)
    {
        let delay_ms = std::env::var("CLUSTERFLUX_TEST_DAP_BREAKPOINT_DELAY_MS")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(750);
        std::thread::sleep(Duration::from_millis(delay_ms));
    }
    let revision_failure =
        std::env::var("CLUSTERFLUX_TEST_DAP_BREAKPOINT_INSTALLATION_FAILURE_REVISION")
            .ok()
            .and_then(|value| value.parse::<u64>().ok())
            == Some(state.breakpoint_revision);
    if (revision_failure
        || std::env::var_os("CLUSTERFLUX_TEST_DAP_BREAKPOINT_INSTALLATION_FAILURE").is_some())
        && state.has_breakpoints()
        && !INJECTED_INSTALL_FAILURE.swap(true, Ordering::SeqCst)
    {
        return Err(anyhow!(
            "coordinator breakpoint installation failed: injected live-install failure"
        ));
    }
    let response = coordinator_request(
        coordinator,
        client_user_request(
            state,
            CoordinatorRequest::SetDebugBreakpoints {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
                revision: state.breakpoint_revision,
                probe_symbols: state.requested_probe_symbols(),
                probe_locations: state.breakpoint_locations().cloned().collect(),
            },
        ),
    )?;
    if !matches!(response, CoordinatorResponse::DebugBreakpoints { .. }) {
        return Err(anyhow!(
            "coordinator returned an unexpected breakpoint response"
        ));
    }
    Ok(())
}

fn wait_for_local_node(
    coordinator: &str,
    state: &AdapterState,
    node: &str,
    worker: &mut Child,
) -> Result<()> {
    let deadline = Instant::now() + LOCAL_NODE_ATTACH_TIMEOUT;
    loop {
        if let Some(status) = worker.try_wait()? {
            return Err(anyhow!(
                "local Clusterflux worker `{node}` exited before attaching ({status}){}",
                child_stderr_suffix(worker)
            ));
        }
        let response = coordinator_request(
            coordinator,
            CoordinatorRequest::ListNodeDescriptors {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
            },
        )?;
        match response {
            CoordinatorResponse::NodeDescriptors { descriptors, .. }
                if descriptors
                    .iter()
                    .any(|descriptor| descriptor.id.as_str() == node) =>
            {
                return Ok(())
            }
            CoordinatorResponse::NodeDescriptors { .. } => {}
            _ => {
                return Err(anyhow!(
                    "coordinator returned an unexpected node-list response"
                ))
            }
        }
        if Instant::now() >= deadline {
            let _ = worker.kill();
            let _ = worker.wait();
            return Err(anyhow!(
                "local Clusterflux worker `{node}` did not attach within {} seconds{}",
                LOCAL_NODE_ATTACH_TIMEOUT.as_secs(),
                child_stderr_suffix(worker)
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

fn wait_for_debug_epoch_state_at(
    coordinator: &str,
    state: &AdapterState,
    epoch: u64,
    frozen: bool,
) -> Result<DebugEpochStatusRecord> {
    let deadline = Instant::now() + Duration::from_secs(60);
    loop {
        let response = coordinator_request(
            coordinator,
            client_user_request(
                state,
                CoordinatorRequest::InspectDebugEpoch {
                    tenant: state.tenant.to_string(),
                    project: state.project_id.to_string(),
                    actor_user: state.actor_user.to_string(),
                    process: state.process.to_string(),
                    epoch,
                },
            ),
        )?;
        let status = match response {
            CoordinatorResponse::DebugEpochStatus {
                epoch,
                command,
                expected_tasks,
                acknowledgements,
                fully_frozen,
                partially_frozen,
                fully_resumed,
                failed,
                failure_messages,
                ..
            } => DebugEpochStatusRecord {
                epoch,
                command,
                expected_tasks: expected_tasks.len(),
                acknowledgements,
                fully_frozen,
                partially_frozen,
                fully_resumed,
                failed,
                failure_messages,
            },
            _ => {
                return Err(anyhow!(
                    "coordinator returned an unexpected debug epoch status response"
                ))
            }
        };
        let partially_frozen = frozen && status.partially_frozen;
        if status.fully_frozen || partially_frozen || (!frozen && status.fully_resumed) {
            return Ok(status);
        }
        if status.failed {
            return Err(anyhow!(
                "debug epoch {epoch} participant failed: {}",
                status.failure_messages.join("; ")
            ));
        }
        let ready_field = if frozen {
            "fully_frozen"
        } else {
            "fully_resumed"
        };
        if Instant::now() >= deadline {
            return Err(anyhow!(
                "debug epoch {epoch} did not reach {ready_field} within 60 seconds"
            ));
        }
        std::thread::sleep(Duration::from_millis(50));
    }
}

pub(crate) fn run_live_services_runtime(state: &mut AdapterState) -> Result<RuntimeLaunchRecord> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    let repo = std::env::current_dir()?;
    launch_services_debug_entrypoint(&coordinator, state, &repo)
}

pub(crate) fn set_services_debug_breakpoints(state: &AdapterState) -> Result<()> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    set_services_debug_breakpoints_at(&coordinator, state)
}

fn fetch_task_snapshots(coordinator: &str, state: &AdapterState) -> Result<Value> {
    let response = coordinator_request(
        coordinator,
        client_user_request(
            state,
            CoordinatorRequest::ListTaskSnapshots {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
            },
        ),
    )?;
    match response {
        response @ CoordinatorResponse::TaskSnapshots { .. } => Ok(serde_json::to_value(response)?),
        _ => Err(anyhow!(
            "coordinator returned an unexpected task-snapshot response"
        )),
    }
}

fn fetch_task_snapshots_in(
    session: &mut CoordinatorSession,
    state: &AdapterState,
) -> Result<Value> {
    let response = session.request(client_user_request(
        state,
        CoordinatorRequest::ListTaskSnapshots {
            tenant: state.tenant.to_string(),
            project: state.project_id.to_string(),
            actor_user: state.actor_user.to_string(),
            process: state.process.to_string(),
        },
    ))?;
    match response {
        response @ CoordinatorResponse::TaskSnapshots { .. } => Ok(serde_json::to_value(response)?),
        _ => Err(anyhow!(
            "coordinator returned an unexpected task-snapshot response"
        )),
    }
}

fn fetch_current_process_status(
    coordinator: &str,
    state: &AdapterState,
) -> Result<(Value, Option<Value>)> {
    let response = coordinator_request(
        coordinator,
        client_user_request(
            state,
            CoordinatorRequest::ListProcessSummaries {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                cursor: None,
                limit: 100,
            },
        ),
    )?;
    let statuses = match response {
        response @ CoordinatorResponse::ProcessSummaries { .. } => serde_json::to_value(response)?,
        _ => {
            return Err(anyhow!(
                "coordinator returned an unexpected process-summary response"
            ))
        }
    };
    let summary = statuses
        .get("processes")
        .and_then(Value::as_array)
        .and_then(|processes| {
            processes.iter().find(|process| {
                process.get("process").and_then(Value::as_str) == Some(state.process.as_str())
            })
        })
        .cloned();
    let current = merge_active_process_status(state, summary, |request| {
        coordinator_request(coordinator, request)
    })?;
    Ok((statuses, current))
}

fn fetch_current_process_status_in(
    session: &mut CoordinatorSession,
    state: &AdapterState,
) -> Result<(Value, Option<Value>)> {
    let response = session.request(client_user_request(
        state,
        CoordinatorRequest::ListProcessSummaries {
            tenant: state.tenant.to_string(),
            project: state.project_id.to_string(),
            actor_user: state.actor_user.to_string(),
            cursor: None,
            limit: 100,
        },
    ))?;
    let statuses = match response {
        response @ CoordinatorResponse::ProcessSummaries { .. } => serde_json::to_value(response)?,
        _ => {
            return Err(anyhow!(
                "coordinator returned an unexpected process-summary response"
            ))
        }
    };
    let summary = statuses
        .get("processes")
        .and_then(Value::as_array)
        .and_then(|processes| {
            processes.iter().find(|process| {
                process.get("process").and_then(Value::as_str) == Some(state.process.as_str())
            })
        })
        .cloned();
    let current = merge_active_process_status(state, summary, |request| session.request(request))?;
    Ok((statuses, current))
}

fn merge_active_process_status<F>(
    state: &AdapterState,
    summary: Option<Value>,
    mut request: F,
) -> Result<Option<Value>>
where
    F: FnMut(CoordinatorRequest) -> Result<CoordinatorResponse>,
{
    let Some(mut summary) = summary else {
        return Ok(None);
    };
    if summary.get("lifecycle").and_then(Value::as_str) != Some("active") {
        return Ok(Some(summary));
    }
    let active_statuses = request(client_user_request(
        state,
        CoordinatorRequest::ListProcesses {
            tenant: state.tenant.to_string(),
            project: state.project_id.to_string(),
            actor_user: state.actor_user.to_string(),
        },
    ))?;
    let active_statuses = match active_statuses {
        response @ CoordinatorResponse::ProcessStatuses { .. } => serde_json::to_value(response)?,
        _ => {
            return Err(anyhow!(
                "coordinator returned an unexpected process-status response"
            ))
        }
    };
    let active = active_statuses
        .get("processes")
        .and_then(Value::as_array)
        .and_then(|processes| {
            processes.iter().find(|process| {
                process.get("process").and_then(Value::as_str) == Some(state.process.as_str())
            })
        });
    if let (Some(summary), Some(active)) =
        (summary.as_object_mut(), active.and_then(Value::as_object))
    {
        for (key, value) in active {
            summary.entry(key.clone()).or_insert_with(|| value.clone());
        }
    }
    Ok(Some(summary))
}

pub(crate) fn relaunch_services_main_runtime(state: &AdapterState) -> Result<RuntimeLaunchRecord> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    let repo = std::env::current_dir()?;
    let mut restart_state = state.clone();
    restart_state.restart_existing = true;
    launch_services_debug_entrypoint(&coordinator, &mut restart_state, &repo)
}

pub(crate) fn attach_services_runtime(state: &AdapterState) -> Result<RuntimeLaunchRecord> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    let debug_attach = coordinator_request(
        &coordinator,
        client_user_request(
            state,
            CoordinatorRequest::DebugAttach {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
            },
        ),
    )?;
    let (authorization, source_revision) = match &debug_attach {
        CoordinatorResponse::DebugAttach {
            authorization,
            source_revision,
            ..
        } => (authorization, source_revision.as_ref()),
        _ => {
            return Err(anyhow!(
                "coordinator returned an unexpected debug-attach response"
            ))
        }
    };
    if !authorization.allowed {
        return Err(anyhow!("debug attach denied: {}", authorization.reason));
    }
    let source_mismatch = source_revision.and_then(|revision| {
        let local = Command::new("git")
            .args(["rev-parse", "HEAD"])
            .current_dir(&state.project)
            .output()
            .ok()
            .filter(|output| output.status.success())?;
        let local = String::from_utf8(local.stdout).ok()?;
        let local = local.trim();
        (local != revision.commit_sha).then(|| {
            format!(
                "debug source mismatch: process uses commit {}, local checkout uses {local}",
                revision.commit_sha
            )
        })
    });
    let events = coordinator_request(
        &coordinator,
        client_user_request(
            state,
            CoordinatorRequest::ListTaskEvents {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: Some(state.process.to_string()),
            },
        ),
    )?;
    let event_count = match &events {
        CoordinatorResponse::TaskEvents { events } => events.len(),
        _ => {
            return Err(anyhow!(
                "coordinator returned an unexpected task-events response"
            ))
        }
    };
    let events = serde_json::to_value(events)?;
    let task_snapshots = fetch_task_snapshots(&coordinator, state)?;
    let active_snapshot_count = task_snapshots
        .get("snapshots")
        .and_then(Value::as_array)
        .map(|snapshots| {
            snapshots
                .iter()
                .filter(|snapshot| {
                    snapshot.get("current").and_then(Value::as_bool) == Some(true)
                        && matches!(
                            snapshot.get("state").and_then(Value::as_str),
                            Some("queued" | "running" | "failed_awaiting_action")
                        )
                })
                .count()
        })
        .unwrap_or(0);
    let (process_statuses, process_status) = fetch_current_process_status(&coordinator, state)?;
    let node = process_status
        .as_ref()
        .and_then(|status| status.get("connected_nodes"))
        .and_then(Value::as_array)
        .and_then(|nodes| nodes.first())
        .and_then(Value::as_str)
        .unwrap_or("coordinator-main")
        .to_owned();
    let active_main = process_status
        .as_ref()
        .and_then(|status| status.get("main_task_instance"))
        .and_then(Value::as_str)
        .is_some();

    Ok(RuntimeLaunchRecord {
        coordinator,
        node,
        node_report: json!({
            "debug_attach": debug_attach,
            "process_status": process_status,
            "process_statuses": process_statuses,
            "task_snapshots": task_snapshots,
        }),
        task_events: events,
        placed_task_launched: active_main || active_snapshot_count > 0,
        status_code: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        event_count,
        debug_epoch: None,
        stopped_task: None,
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch,
        all_participants_frozen: false,
    })
}

pub(crate) fn create_debug_epoch(
    state: &AdapterState,
    stopped_task: &TaskInstanceId,
    reason: &str,
) -> Result<DebugEpochRecord> {
    let response = coordinator_debug_epoch_request(
        state,
        client_user_request(
            state,
            CoordinatorRequest::CreateDebugEpoch {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
                stopped_task: stopped_task.as_str().to_owned(),
                reason: reason.to_owned(),
            },
        ),
    )?;
    parse_debug_epoch_response(response)
}

pub(crate) fn resume_debug_epoch(state: &AdapterState, epoch: u64) -> Result<DebugEpochRecord> {
    let response = coordinator_debug_epoch_request(
        state,
        client_user_request(
            state,
            CoordinatorRequest::ResumeDebugEpoch {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
                epoch,
            },
        ),
    )?;
    parse_debug_epoch_response(response)
}

pub(crate) fn wait_for_debug_epoch_frozen(
    state: &AdapterState,
    epoch: u64,
) -> Result<DebugEpochStatusRecord> {
    wait_for_debug_epoch_state(state, epoch, true)
}

pub(crate) fn wait_for_debug_epoch_resumed(
    state: &AdapterState,
    epoch: u64,
) -> Result<DebugEpochStatusRecord> {
    wait_for_debug_epoch_state(state, epoch, false)
}

pub(crate) fn debug_epoch_runtime_record(
    state: &AdapterState,
    status: &DebugEpochStatusRecord,
    stopped_task: &TaskInstanceId,
) -> Result<RuntimeLaunchRecord> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    let task_snapshots = fetch_task_snapshots(&coordinator, state)?;
    let (process_statuses, process_status) = fetch_current_process_status(&coordinator, state)?;
    let node = status
        .acknowledgements
        .first()
        .map(|acknowledgement| acknowledgement.node.as_str())
        .unwrap_or("coordinator-main")
        .to_owned();
    Ok(RuntimeLaunchRecord {
        coordinator,
        node,
        node_report: json!({
            "debug_epoch": {
                "epoch": status.epoch,
                "command": status.command,
                "expected_tasks": status.expected_tasks,
                "acknowledgements": status.acknowledgements,
                "fully_frozen": status.fully_frozen,
                "partially_frozen": status.partially_frozen,
                "fully_resumed": status.fully_resumed,
                "failed": status.failed,
                "failure_messages": status.failure_messages,
            },
            "task_snapshots": task_snapshots,
            "process_status": process_status,
            "process_statuses": process_statuses,
        }),
        task_events: json!({ "events": [] }),
        placed_task_launched: true,
        status_code: None,
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        event_count: state.runtime_event_count,
        debug_epoch: Some(status.epoch),
        stopped_task: Some(stopped_task.to_string()),
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch: state.source_mismatch.clone(),
        all_participants_frozen: status.fully_frozen,
    })
}

pub(crate) fn observe_services_runtime(
    state: &AdapterState,
    previous_debug_epoch: u64,
    cancelled: &AtomicBool,
    mut emit: impl FnMut(RuntimeContinuationOutcome) -> bool,
) -> Result<()> {
    let coordinator =
        crate::view_state::normalize_coordinator_endpoint(&state.coordinator_endpoint);
    let mut session = None;
    let mut reconnect_delay = Duration::from_millis(100);
    let mut poll_delay = Duration::from_millis(100);
    let mut last_snapshot_fingerprint = state.runtime_snapshot_fingerprint.clone();
    let inject_connection_loss =
        std::env::var("CLUSTERFLUX_TEST_DAP_OBSERVER_CONNECTION_LOSS").as_deref() == Ok("1");
    let mut connection_loss_injected = false;
    let inject_snapshot_failure =
        std::env::var_os("CLUSTERFLUX_TEST_DAP_OBSERVER_SNAPSHOT_FAILURE").is_some();
    let mut snapshot_failure_injected = false;
    let inject_process_status_failure =
        std::env::var_os("CLUSTERFLUX_TEST_DAP_OBSERVER_PROCESS_STATUS_FAILURE").is_some();
    let mut process_status_failure_injected = false;
    let inject_fallback_failure =
        std::env::var_os("CLUSTERFLUX_TEST_DAP_OBSERVER_FALLBACK_FAILURE").is_some();
    let mut fallback_failure_stage = 0_u8;
    let inject_debug_epoch_wait_failure =
        std::env::var_os("CLUSTERFLUX_TEST_DAP_OBSERVER_DEBUG_EPOCH_WAIT_FAILURE").is_some();
    let mut debug_epoch_wait_failure_injected = false;
    let mut reported_awaiting_action = None;
    loop {
        if cancelled.load(Ordering::Acquire) {
            return Ok(());
        }
        if session.is_none() {
            match CoordinatorSession::connect(&coordinator) {
                Ok(connected) => {
                    session = Some(connected);
                    reconnect_delay = Duration::from_millis(100);
                }
                Err(error) => {
                    if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                        "runtime observer reconnect failed: {error:#}; retrying in {} ms",
                        reconnect_delay.as_millis()
                    ))) {
                        return Ok(());
                    }
                    std::thread::sleep(reconnect_delay);
                    reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                    continue;
                }
            }
        }
        // Events remain useful for output and attempt details, but terminal
        // authority comes from the durable process summary read below.
        let current_session = session.as_mut().expect("observer session connected");
        let events = match current_session.request(client_user_request(
            state,
            CoordinatorRequest::ListTaskEvents {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: Some(state.process.to_string()),
            },
        )) {
            Ok(response @ CoordinatorResponse::TaskEvents { .. }) => {
                serde_json::to_value(response)?
            }
            Ok(_) => {
                return Err(anyhow!(
                    "coordinator returned an unexpected task-events response"
                ))
            }
            Err(error) => {
                if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                    "runtime observer connection lost: {error:#}; reconnecting in {} ms",
                    reconnect_delay.as_millis()
                ))) {
                    return Ok(());
                }
                session = None;
                std::thread::sleep(reconnect_delay);
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        if inject_connection_loss && !connection_loss_injected {
            connection_loss_injected = true;
            session = None;
            if !emit(RuntimeContinuationOutcome::Diagnostic(
                "runtime observer injected one transient connection loss; reconnecting".to_owned(),
            )) {
                return Ok(());
            }
            std::thread::sleep(reconnect_delay);
            continue;
        }
        let snapshot_request = if inject_snapshot_failure && !snapshot_failure_injected {
            snapshot_failure_injected = true;
            Err(anyhow!("injected task snapshot transport failure"))
        } else {
            fetch_task_snapshots_in(current_session, state)
        };
        let task_snapshots = match snapshot_request {
            Ok(snapshots) => snapshots,
            Err(error) => {
                if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                    "runtime snapshot observation failed: {error:#}; reconnecting in {} ms",
                    reconnect_delay.as_millis()
                ))) {
                    return Ok(());
                }
                session = None;
                std::thread::sleep(reconnect_delay);
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        let process_status_request =
            if inject_process_status_failure && !process_status_failure_injected {
                process_status_failure_injected = true;
                Err(anyhow!("injected process-status transport failure"))
            } else {
                fetch_current_process_status_in(current_session, state)
            };
        let (process_statuses, process_status) = match process_status_request {
            Ok(status) => status,
            Err(error) => {
                if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                    "runtime process observation failed: {error:#}; reconnecting in {} ms",
                    reconnect_delay.as_millis()
                ))) {
                    return Ok(());
                }
                session = None;
                std::thread::sleep(reconnect_delay);
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        reconnect_delay = Duration::from_millis(100);
        if !has_current_runtime_task(&task_snapshots) {
            if let Some(mut outcome) =
                terminal_runtime_outcome(&coordinator, state, &events, process_status.as_ref())
            {
                if let RuntimeContinuationOutcome::Terminal(record) = &mut outcome {
                    record.node_report = json!({
                        "terminal_event": record.node_report.get("terminal_event"),
                        "task_snapshots": task_snapshots,
                        "process_status": process_status,
                        "process_statuses": process_statuses,
                    });
                }
                emit(outcome);
                return Ok(());
            }
        }
        let awaiting_action = failed_awaiting_action_snapshot(&task_snapshots)
            .map(|(task, attempt)| (task.to_owned(), attempt.to_owned()));
        let stop_after_snapshot = awaiting_action.as_ref().is_some_and(|(failed_task, _)| {
            !has_other_runnable_current_task(&task_snapshots, failed_task)
        });
        if let Some((failed_task, failed_attempt)) = awaiting_action.as_ref() {
            let newly_reported = reported_awaiting_action
                .as_ref()
                .is_none_or(|(task, attempt)| task != failed_task || attempt != failed_attempt);
            if newly_reported {
                let failed_event = events
                    .get("events")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                    .rev()
                    .find(|event| {
                        event.get("task").and_then(Value::as_str) == Some(failed_task.as_str())
                            && event.get("terminal_state").and_then(Value::as_str) == Some("failed")
                    })
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let event_count = events
                    .get("events")
                    .and_then(Value::as_array)
                    .map(Vec::len)
                    .unwrap_or(state.runtime_event_count);
                let snapshot_fingerprint = serde_json::to_string(&json!({
                    "task_snapshots": task_snapshots,
                    "process_status": process_status,
                }))?;
                if !emit(RuntimeContinuationOutcome::Exception(RuntimeLaunchRecord {
                    coordinator: coordinator.clone(),
                    node: failed_event
                        .get("node")
                        .and_then(Value::as_str)
                        .unwrap_or("unknown")
                        .to_owned(),
                    node_report: json!({
                        "task_snapshots": task_snapshots,
                        "process_status": process_status,
                        "process_statuses": process_statuses,
                        "failed_awaiting_action": failed_task,
                        "snapshot_fingerprint": snapshot_fingerprint,
                    }),
                    task_events: events,
                    placed_task_launched: true,
                    status_code: failed_event
                        .get("status_code")
                        .and_then(Value::as_i64)
                        .map(|status| status as i32)
                        .or(Some(1)),
                    stdout_bytes: failed_event
                        .get("stdout_bytes")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    stderr_bytes: failed_event
                        .get("stderr_bytes")
                        .and_then(Value::as_u64)
                        .unwrap_or(0),
                    stdout_tail: failed_event
                        .get("stdout_tail")
                        .and_then(Value::as_str)
                        .unwrap_or_default()
                        .to_owned(),
                    stderr_tail: failed_event
                        .get("stderr_tail")
                        .and_then(Value::as_str)
                        .unwrap_or("task failed awaiting operator action")
                        .to_owned(),
                    stdout_truncated: failed_event
                        .get("stdout_truncated")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    stderr_truncated: failed_event
                        .get("stderr_truncated")
                        .and_then(Value::as_bool)
                        .unwrap_or(false),
                    artifact_path: failed_event
                        .get("artifact_path")
                        .and_then(Value::as_str)
                        .map(str::to_owned),
                    event_count,
                    debug_epoch: None,
                    stopped_task: Some(failed_task.clone()),
                    stopped_probe_symbol: None,
                    stopped_location: None,
                    source_mismatch: state.source_mismatch.clone(),
                    all_participants_frozen: false,
                })) {
                    return Ok(());
                }
                reported_awaiting_action = Some((failed_task.clone(), failed_attempt.clone()));
                last_snapshot_fingerprint = snapshot_fingerprint;
                if stop_after_snapshot {
                    return Ok(());
                }
                std::thread::sleep(poll_delay);
                continue;
            }
        }

        let breakpoint_request = if inject_fallback_failure && fallback_failure_stage == 0 {
            fallback_failure_stage = 1;
            Err(anyhow!("injected breakpoint inspection transport failure"))
        } else {
            current_session.request(client_user_request(
                state,
                CoordinatorRequest::InspectDebugBreakpoints {
                    tenant: state.tenant.to_string(),
                    project: state.project_id.to_string(),
                    actor_user: state.actor_user.to_string(),
                    process: state.process.to_string(),
                },
            ))
        }
        .and_then(|response| match response {
            response @ CoordinatorResponse::DebugBreakpoints { .. } => {
                serde_json::to_value(response).map_err(anyhow::Error::from)
            }
            _ => Err(anyhow!(
                "coordinator returned an unexpected breakpoint response"
            )),
        });
        let breakpoint = match breakpoint_request {
            Ok(breakpoint) => breakpoint,
            Err(inspect_error) => {
                // Main completion records its terminal event and clears ephemeral
                // debug state in one coordinator pump. That pump can occur between
                // the event read above and this inspection request. Re-read the
                // durable event stream before treating the missing debug state as
                // an adapter failure.
                let fallback_request = if inject_fallback_failure && fallback_failure_stage == 1 {
                    fallback_failure_stage = 2;
                    Err(anyhow!("injected fallback event transport failure"))
                } else {
                    current_session.request(client_user_request(
                        state,
                        CoordinatorRequest::ListTaskEvents {
                            tenant: state.tenant.to_string(),
                            project: state.project_id.to_string(),
                            actor_user: state.actor_user.to_string(),
                            process: Some(state.process.to_string()),
                        },
                    ))
                }
                .and_then(|response| match response {
                    response @ CoordinatorResponse::TaskEvents { .. } => {
                        serde_json::to_value(response).map_err(anyhow::Error::from)
                    }
                    _ => Err(anyhow!(
                        "coordinator returned an unexpected task-events response"
                    )),
                });
                let events = match fallback_request {
                    Ok(events) => events,
                    Err(fallback_error) => {
                        if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                            "runtime breakpoint and fallback event observation failed: {inspect_error:#}; {fallback_error:#}; reconnecting in {} ms",
                            reconnect_delay.as_millis()
                        ))) {
                            return Ok(());
                        }
                        session = None;
                        std::thread::sleep(reconnect_delay);
                        reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                        continue;
                    }
                };
                if let Some(mut outcome) =
                    terminal_runtime_outcome(&coordinator, state, &events, process_status.as_ref())
                {
                    let task_snapshots = match fetch_task_snapshots_in(current_session, state) {
                        Ok(snapshots) => snapshots,
                        Err(snapshot_error) => {
                            if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                                "runtime fallback terminal snapshot observation failed: {snapshot_error:#}; reconnecting in {} ms",
                                reconnect_delay.as_millis()
                            ))) {
                                return Ok(());
                            }
                            session = None;
                            std::thread::sleep(reconnect_delay);
                            reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                            continue;
                        }
                    };
                    if !has_current_runtime_task(&task_snapshots) {
                        if let RuntimeContinuationOutcome::Terminal(record) = &mut outcome {
                            record.node_report = json!({
                                "terminal_event": record.node_report.get("terminal_event"),
                                "task_snapshots": task_snapshots,
                            });
                        }
                        emit(outcome);
                        return Ok(());
                    }
                }
                if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                    "runtime breakpoint observation failed: {inspect_error:#}; reconnecting in {} ms",
                    reconnect_delay.as_millis()
                ))) {
                    return Ok(());
                }
                session = None;
                std::thread::sleep(reconnect_delay);
                reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                continue;
            }
        };
        if let Some(epoch) = breakpoint.get("hit_epoch").and_then(Value::as_u64) {
            if epoch > previous_debug_epoch {
                let frozen_request =
                    if inject_debug_epoch_wait_failure && !debug_epoch_wait_failure_injected {
                        debug_epoch_wait_failure_injected = true;
                        Err(anyhow!("injected Debug Epoch wait transport failure"))
                    } else {
                        wait_for_debug_epoch_state_at(&coordinator, state, epoch, true)
                    };
                let frozen = match frozen_request {
                    Ok(frozen) => frozen,
                    Err(error) => {
                        if !emit(RuntimeContinuationOutcome::Diagnostic(format!(
                            "runtime Debug Epoch observation failed: {error:#}; reconnecting in {} ms",
                            reconnect_delay.as_millis()
                        ))) {
                            return Ok(());
                        }
                        session = None;
                        std::thread::sleep(reconnect_delay);
                        reconnect_delay = (reconnect_delay * 2).min(Duration::from_secs(5));
                        continue;
                    }
                };
                let node = frozen
                    .acknowledgements
                    .first()
                    .map(|acknowledgement| acknowledgement.node.as_str())
                    .unwrap_or("unknown")
                    .to_owned();
                let fully_frozen = frozen.fully_frozen;
                emit(RuntimeContinuationOutcome::Breakpoint(
                    RuntimeLaunchRecord {
                        coordinator,
                        node,
                        node_report: json!({
                            "breakpoint": breakpoint,
                            "debug_epoch": frozen,
                            "task_snapshots": task_snapshots,
                            "process_status": process_status,
                            "process_statuses": process_statuses,
                        }),
                        task_events: json!({ "events": [] }),
                        placed_task_launched: true,
                        status_code: None,
                        stdout_bytes: 0,
                        stderr_bytes: 0,
                        stdout_tail: String::new(),
                        stderr_tail: String::new(),
                        stdout_truncated: false,
                        stderr_truncated: false,
                        artifact_path: None,
                        event_count: state.runtime_event_count,
                        debug_epoch: Some(epoch),
                        stopped_task: breakpoint
                            .get("hit_task")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        stopped_probe_symbol: breakpoint
                            .get("hit_probe_symbol")
                            .and_then(Value::as_str)
                            .map(str::to_owned),
                        stopped_location: breakpoint
                            .get("hit_source_location")
                            .cloned()
                            .and_then(|location| serde_json::from_value(location).ok()),
                        source_mismatch: state.source_mismatch.clone(),
                        all_participants_frozen: fully_frozen,
                    },
                ));
                return Ok(());
            }
        }

        let snapshot_fingerprint = serde_json::to_string(&json!({
            "task_snapshots": task_snapshots,
            "process_status": process_status,
        }))?;
        if snapshot_fingerprint != last_snapshot_fingerprint {
            last_snapshot_fingerprint = snapshot_fingerprint.clone();
            poll_delay = Duration::from_millis(100);
            if !emit(RuntimeContinuationOutcome::Snapshot(RuntimeLaunchRecord {
                coordinator: coordinator.clone(),
                node: process_status
                    .as_ref()
                    .and_then(|status| status.get("connected_nodes"))
                    .and_then(Value::as_array)
                    .and_then(|nodes| nodes.first())
                    .and_then(Value::as_str)
                    .unwrap_or("coordinator-main")
                    .to_owned(),
                node_report: json!({
                    "task_snapshots": task_snapshots,
                    "process_status": process_status,
                    "process_statuses": process_statuses,
                    "snapshot_fingerprint": snapshot_fingerprint,
                }),
                task_events: events,
                placed_task_launched: true,
                status_code: awaiting_action.as_ref().map(|_| 1),
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                artifact_path: None,
                event_count: state.runtime_event_count,
                debug_epoch: None,
                stopped_task: awaiting_action
                    .as_ref()
                    .map(|(failed_task, _)| failed_task.clone()),
                stopped_probe_symbol: None,
                stopped_location: None,
                source_mismatch: state.source_mismatch.clone(),
                all_participants_frozen: false,
            })) {
                return Ok(());
            }
        } else {
            poll_delay = (poll_delay * 2).min(Duration::from_secs(5));
        }
        if stop_after_snapshot {
            return Ok(());
        }
        std::thread::sleep(poll_delay);
    }
}

pub(crate) fn failed_awaiting_action_snapshot(task_snapshots: &Value) -> Option<(&str, &str)> {
    task_snapshots
        .get("snapshots")?
        .as_array()?
        .iter()
        .find(|snapshot| {
            snapshot.get("current").and_then(Value::as_bool) == Some(true)
                && snapshot.get("state").and_then(Value::as_str) == Some("failed_awaiting_action")
        })
        .and_then(|snapshot| {
            Some((
                snapshot.get("task")?.as_str()?,
                snapshot.get("attempt_id")?.as_str()?,
            ))
        })
}

fn has_other_runnable_current_task(task_snapshots: &Value, failed_task: &str) -> bool {
    task_snapshots
        .get("snapshots")
        .and_then(Value::as_array)
        .is_some_and(|snapshots| {
            snapshots.iter().any(|snapshot| {
                snapshot.get("current").and_then(Value::as_bool) == Some(true)
                    && snapshot.get("task").and_then(Value::as_str) != Some(failed_task)
                    && matches!(
                        snapshot.get("state").and_then(Value::as_str),
                        Some("queued" | "running")
                    )
            })
        })
}

fn has_current_runtime_task(task_snapshots: &Value) -> bool {
    task_snapshots
        .get("snapshots")
        .and_then(Value::as_array)
        .is_some_and(|snapshots| {
            snapshots.iter().any(|snapshot| {
                snapshot.get("current").and_then(Value::as_bool) == Some(true)
                    && matches!(
                        snapshot.get("state").and_then(Value::as_str),
                        Some("queued" | "running" | "failed_awaiting_action")
                    )
            })
        })
}

#[cfg(test)]
pub(crate) fn whole_process_status_code(
    main_status_code: Option<i32>,
    task_snapshots: &Value,
) -> Option<i32> {
    let main_status_code = main_status_code?;
    if main_status_code != 0 {
        return Some(main_status_code);
    }

    let snapshots = task_snapshots.get("snapshots").and_then(Value::as_array)?;
    for snapshot in snapshots
        .iter()
        .filter(|snapshot| snapshot.get("current").and_then(Value::as_bool) == Some(true))
    {
        match snapshot.get("state").and_then(Value::as_str) {
            Some("completed") => {}
            Some("failed" | "cancelled" | "failed_awaiting_action") => {
                return Some(
                    snapshot
                        .get("status_code")
                        .and_then(Value::as_i64)
                        .and_then(|status| i32::try_from(status).ok())
                        .filter(|status| *status != 0)
                        .unwrap_or(1),
                );
            }
            Some("queued" | "running") => return None,
            _ => return Some(1),
        }
    }
    Some(0)
}

fn terminal_runtime_outcome(
    coordinator: &str,
    state: &AdapterState,
    events: &Value,
    process_status: Option<&Value>,
) -> Option<RuntimeContinuationOutcome> {
    let final_result = process_status?
        .get("final_result")
        .and_then(Value::as_str)?;
    let status_code = match final_result {
        "completed" => 0,
        "failed" | "cancelled" => 1,
        _ => return None,
    };
    let event = events
        .get("events")
        .and_then(Value::as_array)
        .and_then(|events| {
            events.iter().rev().find(|event| {
                event.get("executor").and_then(Value::as_str) == Some("coordinator_main")
            })
        });
    Some(RuntimeContinuationOutcome::Terminal(RuntimeLaunchRecord {
        coordinator: coordinator.to_owned(),
        node: event
            .and_then(|event| event.get("node"))
            .and_then(Value::as_str)
            .or_else(|| {
                process_status
                    .and_then(|status| status.get("connected_nodes"))
                    .and_then(Value::as_array)
                    .and_then(|nodes| nodes.first())
                    .and_then(Value::as_str)
            })
            .unwrap_or("coordinator-main")
            .to_owned(),
        node_report: json!({
            "terminal_event": event,
            "process_status": process_status,
        }),
        task_events: events.clone(),
        placed_task_launched: true,
        status_code: Some(status_code),
        stdout_bytes: event
            .and_then(|event| event.get("stdout_bytes"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        stderr_bytes: event
            .and_then(|event| event.get("stderr_bytes"))
            .and_then(Value::as_u64)
            .unwrap_or(0),
        stdout_tail: event
            .and_then(|event| event.get("stdout_tail"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stderr_tail: event
            .and_then(|event| event.get("stderr_tail"))
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_owned(),
        stdout_truncated: event
            .and_then(|event| event.get("stdout_truncated"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stderr_truncated: event
            .and_then(|event| event.get("stderr_truncated"))
            .and_then(Value::as_bool)
            .unwrap_or(false),
        artifact_path: event
            .and_then(|event| event.get("artifact_path"))
            .and_then(Value::as_str)
            .map(str::to_owned),
        event_count: events
            .get("events")
            .and_then(Value::as_array)
            .map(Vec::len)
            .unwrap_or(0),
        debug_epoch: None,
        stopped_task: None,
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch: state.source_mismatch.clone(),
        all_participants_frozen: false,
    }))
}

pub(crate) fn restart_task(
    state: &AdapterState,
    task: &TaskInstanceId,
) -> Result<TaskRestartRecord> {
    let repo = std::env::current_dir()?;
    let replacement = build_debug_bundle(state, &repo)?;
    let response = coordinator_debug_epoch_request(
        state,
        client_user_request(
            state,
            CoordinatorRequest::RestartTask {
                tenant: state.tenant.to_string(),
                project: state.project_id.to_string(),
                actor_user: state.actor_user.to_string(),
                process: state.process.to_string(),
                task: task.as_str().to_owned(),
                replacement_bundle: Some(TaskReplacementBundle {
                    bundle_digest: replacement.digest,
                    wasm_module_base64: replacement.module_base64,
                    source_snapshot: Some(replacement.source_snapshot),
                }),
            },
        ),
    )?;
    parse_task_restart_response(response)
}

#[cfg(test)]
mod transactional_launch_tests {
    use std::io::{BufRead as _, Write as _};
    use std::net::TcpListener;

    use super::*;

    fn test_debug_sidecar(root: &Path) -> (std::path::PathBuf, Digest) {
        let path = root.join("debug-sidecar.json");
        let bytes = serde_json::to_vec(&json!({
            "format": "clusterflux-wasm-debug-v2",
            "path_remapping": [{"from": "/workflow", "to": ".clusterflux"}],
            "source_inventory": [".clusterflux/main.rs"],
            "sections": [
                {"name": ".debug_info", "data_base64": "AA=="},
                {"name": ".debug_line", "data_base64": "AA=="}
            ]
        }))
        .unwrap();
        std::fs::write(&path, &bytes).unwrap();
        (path, Digest::sha256(bytes))
    }

    #[test]
    fn dap_bundle_uses_the_cli_report_source_and_entrypoint_authority() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.wasm");
        let module = b"report-authoritative-module";
        std::fs::write(&module_path, module).unwrap();
        let bundle_digest = Digest::sha256(module);
        let (debug_sidecar, debug_sidecar_digest) = test_debug_sidecar(temp.path());
        let source_snapshot = Digest::sha256("report-authoritative-source");
        let report = json!({
            "bundle_artifact": {
                "module": module_path,
                "execution_module_digest": bundle_digest,
                "debug_sidecar": debug_sidecar,
                "debug_sidecar_digest": debug_sidecar_digest,
            },
            "source_snapshot": {
                "digest": source_snapshot,
                "provider": "git",
                "file_count": 1,
                "total_bytes": 27,
                "source_mode": "working_tree",
            },
            "selected_entrypoint": {
                "name": "build",
                "export": "clusterflux_main_build",
                "stable_id": "main:build",
            },
        });

        let bundle = debug_bundle_from_build_report(&report, temp.path(), Some("build")).unwrap();

        assert_eq!(bundle.digest, bundle_digest);
        assert_eq!(bundle.source_snapshot, source_snapshot);
        assert_eq!(bundle.entry_export, "clusterflux_main_build");
        assert_eq!(bundle.entry_name, "build");
        assert!(!temp.path().join("entrypoints.json").exists());
    }

    #[test]
    fn dap_bundle_rejects_a_module_changed_after_the_build_report() {
        let temp = tempfile::tempdir().unwrap();
        let module_path = temp.path().join("module.wasm");
        std::fs::write(&module_path, b"changed module").unwrap();
        let (debug_sidecar, debug_sidecar_digest) = test_debug_sidecar(temp.path());
        let report = json!({
            "bundle_artifact": {
                "module": module_path,
                "execution_module_digest": Digest::sha256("original module"),
                "debug_sidecar": debug_sidecar,
                "debug_sidecar_digest": debug_sidecar_digest,
            },
            "source_snapshot": {
                "digest": Digest::sha256("source"),
            },
            "selected_entrypoint": {
                "name": "build",
                "export": "clusterflux_main_build",
                "stable_id": "main:build",
            },
        });

        let error = debug_bundle_from_build_report(&report, temp.path(), Some("build"))
            .unwrap_err()
            .to_string();
        assert!(error.contains("module digest changed"));
    }

    #[test]
    fn current_child_task_keeps_runtime_observation_alive_after_main_completion() {
        assert!(has_current_runtime_task(&json!({
            "snapshots": [{
                "current": true,
                "state": "running",
                "task": "child"
            }]
        })));
        assert!(!has_current_runtime_task(&json!({
            "snapshots": [{
                "current": false,
                "state": "completed",
                "task": "main"
            }]
        })));
    }

    #[test]
    fn failed_task_observation_stays_live_until_unaffected_tasks_settle() {
        let with_running_sibling = json!({
            "snapshots": [
                {
                    "current": true,
                    "state": "failed_awaiting_action",
                    "task": "failed"
                },
                {
                    "current": true,
                    "state": "running",
                    "task": "unaffected"
                }
            ]
        });
        assert!(has_other_runnable_current_task(
            &with_running_sibling,
            "failed"
        ));

        let after_sibling_completion = json!({
            "snapshots": [
                {
                    "current": true,
                    "state": "failed_awaiting_action",
                    "task": "failed"
                },
                {
                    "current": true,
                    "state": "completed",
                    "task": "unaffected"
                }
            ]
        });
        assert!(!has_other_runnable_current_task(
            &after_sibling_completion,
            "failed"
        ));
    }

    #[test]
    fn inline_bundle_limit_is_checked_before_process_creation() {
        assert_eq!(MAX_CONTROL_FRAME_BYTES, 16 * 1024 * 1024);
        validate_inline_bundle_size(MAX_INLINE_WASM_MODULE_BYTES).unwrap();
        let error = validate_inline_bundle_size(MAX_INLINE_WASM_MODULE_BYTES + 1)
            .unwrap_err()
            .to_string();
        assert!(error.contains("no virtual process was created"));
    }

    #[test]
    fn durable_process_summary_is_terminal_authority_after_event_rotation() {
        let state = AdapterState {
            runtime_event_count: 10_000,
            ..AdapterState::default()
        };
        let completed = terminal_runtime_outcome(
            "127.0.0.1:1",
            &state,
            &json!({ "events": [] }),
            Some(&json!({
                "process": state.process.as_str(),
                "lifecycle": "recent_terminal",
                "final_result": "completed",
                "connected_nodes": []
            })),
        )
        .expect("the durable summary should terminate observation");
        let RuntimeContinuationOutcome::Terminal(completed) = completed else {
            panic!("expected terminal outcome");
        };
        assert_eq!(completed.status_code, Some(0));

        let failed = terminal_runtime_outcome(
            "127.0.0.1:1",
            &state,
            &json!({
                "events": [{
                    "executor": "coordinator_main",
                    "terminal_state": "completed",
                    "status_code": 0
                }]
            }),
            Some(&json!({
                "process": state.process.as_str(),
                "lifecycle": "recent_terminal",
                "final_result": "failed",
                "connected_nodes": []
            })),
        )
        .expect("the aggregate summary should override a successful main event");
        let RuntimeContinuationOutcome::Terminal(failed) = failed else {
            panic!("expected terminal outcome");
        };
        assert_eq!(failed.status_code, Some(1));
    }

    #[test]
    fn failed_debug_launch_reconnects_and_aborts_the_process() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let address = listener.local_addr().unwrap().to_string();
        let server = std::thread::spawn(move || {
            let (mut stream, _) = listener.accept().unwrap();
            let mut line = String::new();
            std::io::BufReader::new(stream.try_clone().unwrap())
                .read_line(&mut line)
                .unwrap();
            assert!(line.contains("\"type\":\"abort_process\""));
            writeln!(
                stream,
                "{}",
                json!({
                    "type": "process_aborted",
                    "process": "vp-test",
                    "aborted_tasks": [],
                    "affected_nodes": []
                })
            )
            .unwrap();
        });
        let state = AdapterState {
            process: clusterflux_core::ProcessId::from("vp-test"),
            ..AdapterState::default()
        };
        let error = debug_launch_error_with_rollback(
            &address,
            &state,
            "launch-test",
            anyhow!("launch acknowledgement was lost"),
        );
        assert!(error
            .to_string()
            .contains("launch acknowledgement was lost"));
        server.join().unwrap();
    }
}
