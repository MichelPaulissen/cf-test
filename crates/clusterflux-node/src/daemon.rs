use std::collections::{BTreeMap, BTreeSet};
use std::io::Write;
use std::path::PathBuf;
use std::time::{Duration, Instant};

use clap::Parser;
use clusterflux_core::{
    sign_node_request, signed_request_payload_digest, ApiError, ApiErrorCode, ArtifactId,
    AssignmentAuthority, Capability, Digest, EnvironmentBackend, NodeCapabilities, NodeDrainStatus,
    NodeId, NodeLifecycleState, NodeWorkPolicy, Os, ProcessId, ProjectId, SystemBundleCapability,
    TaskInstanceId, TaskSpec, TenantId,
};
use clusterflux_protocol::{
    ActiveNodeAssignment, CoordinatorRequest, CoordinatorResponse, NodeAssignmentWork,
    SystemTaskKind, TaskAssignment,
};
use clusterflux_source::snapshot_project;
use serde_json::{json, Value};
use tokio_util::sync::CancellationToken;

use crate::artifact_interchange::NodeArtifactDataPlane;
use crate::assignment_runner::{
    assignment_error_logs, node_wasm_execution_service, submit_verified_wasmtime_assignment,
    NativeCommandLogSnapshot, NodeWasmAssignment, WasmAssignmentResult, MAX_RESIDENT_WASM_TASKS,
};
#[cfg(test)]
use crate::coordinator_session::control_endpoint_identity;
use crate::coordinator_session::CoordinatorSession;
use crate::debug_agent::poll_task_cancellation;
use crate::node_identity::{
    establish_node_identity, node_nonce, node_private_key_for_runtime,
    signed_node_assignment_operation_request, signed_node_assignment_request, signed_node_request,
    unix_timestamp_seconds, validate_node_identity_configuration,
};
#[cfg(test)]
use crate::node_identity::{load_or_create_local_node_credential, unix_timestamp_nanos};
use crate::task_artifacts::{
    clean_stale_task_output_roots, current_epoch_seconds, NodeArtifactRetentionLimits,
    NodeArtifactStore,
};
use crate::task_reports::{record_cancelled_task, record_completed_task, record_failed_task};
use clusterflux_node::{
    ContainerRunPolicy, LinuxRootlessPodmanBackend, ProcessRunner, StdProcessRunner,
    WindowsContainerdNerdctlBackend,
};
use clusterflux_wasm_runtime::WasmExecutionService;

const DEFAULT_DEBUG_FREEZE_TIMEOUT_MILLIS: u64 = 5_000;
const MAX_DEBUG_FREEZE_TIMEOUT_MILLIS: u64 = 5 * 60 * 1_000;
const MAX_CONTROL_POLL_MILLIS: u64 = 60_000;
const MAX_EPHEMERAL_TIMEOUT_SECONDS: u64 = 24 * 60 * 60;
const MAX_PROVIDER_DEADLINE_HORIZON_SECONDS: u64 = 30 * 24 * 60 * 60;
const MAX_COORDINATOR_RECONNECT_SECONDS: u64 = 24 * 60 * 60;
pub(crate) const DEFAULT_HOSTED_COORDINATOR_ENDPOINT: &str = "https://clusterflux.lesstuff.com";

#[derive(Clone, Parser)]
#[command(name = "clusterflux-node", version, about = "Clusterflux node worker")]
pub(crate) struct Args {
    #[arg(
        long,
        value_name = "URL",
        default_value = DEFAULT_HOSTED_COORDINATOR_ENDPOINT,
        value_parser = parse_coordinator_endpoint
    )]
    pub(crate) coordinator: String,
    #[arg(long, default_value = "tenant", value_parser = parse_tenant_id)]
    pub(crate) tenant: String,
    #[arg(long = "project-id", default_value = "project", value_parser = parse_project_id)]
    pub(crate) project: String,
    #[arg(long, value_name = "PATH")]
    pub(crate) project_root: Option<PathBuf>,
    #[arg(long, default_value = "node", value_parser = parse_node_id)]
    pub(crate) node: String,
    #[arg(long, value_name = "GRANT", value_parser = parse_enrollment_grant)]
    pub(crate) enrollment_grant: Option<String>,
    #[arg(long, value_name = "KEY", value_parser = parse_node_public_key)]
    pub(crate) public_key: Option<String>,
    #[arg(long, default_value_t = 0, value_parser = parse_control_poll_ms)]
    pub(crate) control_poll_ms: u64,
    #[arg(long, default_value_t = 100, value_parser = parse_assignment_poll_ms)]
    pub(crate) assignment_poll_ms: u64,
    /// Maximum jittered reconnect delay after a transient coordinator failure; zero disables retries.
    #[arg(
        long,
        default_value_t = 60 * 60,
        value_parser = parse_coordinator_reconnect_max_seconds
    )]
    pub(crate) coordinator_reconnect_max_seconds: u64,
    /// Maximum CPUs available to each project task container on this node.
    #[arg(long, default_value_t = 2, value_parser = parse_task_cpu_count)]
    pub(crate) task_cpus: u16,
    /// Maximum GiB of memory available to each project task container on this node.
    #[arg(long, default_value_t = 2, value_parser = parse_task_memory_gib)]
    pub(crate) task_memory_gib: u16,
    /// Maximum processes and threads available to each project task container.
    #[arg(long, default_value_t = 256, value_parser = parse_task_pids_limit)]
    pub(crate) task_pids_limit: u32,
    #[arg(long)]
    pub(crate) emit_ready: bool,
    #[arg(long)]
    pub(crate) worker: bool,
    /// Operator-approved capabilities that cannot be inferred from the host.
    #[arg(long = "cap", value_parser = parse_capability)]
    pub(crate) capabilities: Vec<Capability>,
    /// DANGEROUS: run workflow commands directly on the host instead of in containers.
    #[arg(long)]
    pub(crate) dangerous_allow_native_commands: bool,
    /// Keep this node execution-only even when a compiler backend is configured.
    #[arg(long, conflicts_with = "system_tasks_only")]
    pub(crate) no_workflow_compilation: bool,
    /// Accept release-owned pre-process work but reject project process tasks.
    #[arg(long, conflicts_with = "no_workflow_compilation")]
    pub(crate) system_tasks_only: bool,
    #[arg(long)]
    pub(crate) system_compiler_image: Option<String>,
    #[arg(long)]
    pub(crate) system_compiler_runsc_version: Option<String>,
    #[arg(long, default_value = "podman", value_parser = ["podman", "gvisor"])]
    pub(crate) system_compiler_sandbox: String,
    #[arg(long, default_value = "podman")]
    pub(crate) system_compiler_podman: String,
    #[arg(long, default_value = "runsc")]
    pub(crate) system_compiler_runsc: String,
    #[arg(skip)]
    pub(crate) system_compiler_package_verified: bool,
    /// Startup-verified, release-owned compiler package available to task containers.
    #[arg(skip)]
    pub(crate) system_compiler_package_dir: Option<PathBuf>,
    #[arg(long)]
    pub(crate) ephemeral: bool,
    #[arg(long, value_name = "SECONDS")]
    pub(crate) provider_deadline_epoch_seconds: Option<u64>,
    #[arg(long, value_name = "SECONDS")]
    pub(crate) soft_drain_deadline_epoch_seconds: Option<u64>,
    #[arg(long, value_name = "SECONDS")]
    pub(crate) hard_drain_deadline_epoch_seconds: Option<u64>,
    #[arg(long, default_value_t = 60, value_parser = parse_positive_u64)]
    pub(crate) ephemeral_startup_deadline_seconds: u64,
    #[arg(long, default_value_t = 30, value_parser = parse_positive_u64)]
    pub(crate) ephemeral_idle_after_work_seconds: u64,
    #[arg(skip = DEFAULT_DEBUG_FREEZE_TIMEOUT_MILLIS)]
    pub(crate) debug_freeze_timeout_ms: u64,
    #[arg(skip = NodeArtifactRetentionLimits::default())]
    pub(crate) artifact_retention: NodeArtifactRetentionLimits,
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeTask {
    pub(crate) process: String,
    pub(crate) task: String,
    pub(crate) epoch: Option<u64>,
    pub(crate) task_spec: Option<TaskSpec>,
    pub(crate) bundle_digest: Option<Digest>,
    pub(crate) wasm_module_base64: Option<String>,
    pub(crate) assignment_authority: AssignmentAuthority,
}

impl Args {
    pub(crate) fn node_capabilities(&self) -> NodeCapabilities {
        let mut capabilities = NodeCapabilities::detect_current();
        capabilities
            .capabilities
            .extend(self.capabilities.iter().cloned());
        if self.dangerous_allow_native_commands {
            capabilities.capabilities.insert(Capability::Command);
            if capabilities.os == Os::Windows {
                capabilities
                    .capabilities
                    .insert(Capability::WindowsCommandDev);
                capabilities
                    .environment_backends
                    .insert(EnvironmentBackend::WindowsCommandDev);
            }
        }
        capabilities
    }

    pub(crate) fn task_container_policy(&self) -> ContainerRunPolicy {
        ContainerRunPolicy {
            cpu_count: self.task_cpus,
            memory_bytes: u64::from(self.task_memory_gib) * 1024 * 1024 * 1024,
            pids_limit: self.task_pids_limit,
            ..ContainerRunPolicy::default()
        }
    }
}

struct ActiveRuntimeTask {
    task: RuntimeTask,
    debug_command: Value,
    execution: NodeWasmAssignment,
    artifact_warmups: crate::artifact_interchange::ArtifactWarmupManager,
    warmup_process: ProcessId,
    warmup_task: TaskInstanceId,
}

struct ActiveWorkflowCompilation {
    assignment_id: String,
    attempt_id: String,
    lease_epoch: u64,
    execution: crate::system_compiler::SystemCompilationExecution,
}

enum RuntimeTaskLaunch {
    Active(Box<ActiveRuntimeTask>),
    Finished(Value),
}

pub(crate) fn run() -> Result<(), Box<dyn std::error::Error>> {
    let mut args = parse_args()?;
    if !args.worker {
        return Err(
            "one-shot native command mode was removed; run `clusterflux-node --worker` and launch a bundled Wasm task through the coordinator"
                .into(),
        );
    }
    let worker_shutdown = CancellationToken::new();

    if args.dangerous_allow_native_commands {
        eprintln!(
            "WARNING: --dangerous-allow-native-commands bypasses container isolation for workflow commands on this node."
        );
    }
    if Os::current() == Os::Windows {
        eprintln!(
            "Windows process-isolated tasks enforce CPU and memory limits and a read-only source mount. runhcs does not support a read-only container root or expose the per-task PID limit; the writable container layer remains ephemeral."
        );
    }
    let compiler_profile = if args.no_workflow_compilation || Os::current() != Os::Linux {
        eprintln!(
            "Automatic workflow compilation disabled on this node; compiler image inspection and import were skipped. A compiler-capable Linux node must remain online."
        );
        None
    } else {
        match crate::system_compiler::self_check(&mut args) {
            Ok(profile) => Some(profile),
            Err(error) => {
                eprintln!(
                    "Automatic workflow compilation unavailable: {error}. Node remains usable for ordinary process tasks."
                );
                None
            }
        }
    };

    let node_private_key = node_private_key_for_runtime(args.project_root.as_deref(), &args.node)?;
    validate_node_identity_configuration(&args, &node_private_key)?;
    let reconnect_max_delay = (args.coordinator_reconnect_max_seconds > 0)
        .then(|| Duration::from_secs(args.coordinator_reconnect_max_seconds));
    let mut session =
        CoordinatorSession::connect_with_retries(&args.coordinator, reconnect_max_delay)?;
    let registration = establish_node_identity(&mut session, &args, &node_private_key)?;
    let heartbeat = match session.request_signed_heartbeat(|| {
        let heartbeat_request = CoordinatorRequest::NodeHeartbeat {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            node: args.node.clone(),
            node_signature: None,
        };
        let heartbeat_signature = sign_node_request(
            &node_private_key,
            &NodeId::from(args.node.as_str()),
            "node_heartbeat",
            &signed_request_payload_digest(&serde_json::to_value(&heartbeat_request)?),
            node_nonce("node-heartbeat"),
            unix_timestamp_seconds(),
        )
        .map_err(|err| std::io::Error::new(std::io::ErrorKind::InvalidInput, err))?;
        Ok(CoordinatorRequest::NodeHeartbeat {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            node: args.node.clone(),
            node_signature: Some(heartbeat_signature),
        })
    })? {
        response @ CoordinatorResponse::NodeHeartbeat { .. } => serde_json::to_value(response)?,
        _ => return Err("coordinator returned an unexpected node-heartbeat response".into()),
    };
    clean_stale_task_output_roots(args.project_root.as_deref(), &args.node)?;
    let artifact_store = NodeArtifactStore::for_runtime(args.project_root.as_deref(), &args.node)?;
    let retention_limits = args.artifact_retention;
    artifact_store.garbage_collect(retention_limits, &BTreeSet::new(), current_epoch_seconds())?;
    let capability_report = report_node_capabilities(
        &args,
        &mut session,
        &node_private_key,
        &artifact_store,
        compiler_profile.as_ref(),
        true,
    )?;

    if args.system_tasks_only {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()?;
        runtime.block_on(worker_loop(
            &args,
            &mut session,
            registration,
            heartbeat,
            capability_report,
            &node_private_key,
            None,
            compiler_profile,
            worker_shutdown,
        ))
    } else {
        let artifact_data_plane = NodeArtifactDataPlane::start(
            &args,
            &mut session,
            &node_private_key,
            &artifact_store,
            worker_shutdown.clone(),
        )?;
        let runtime = artifact_data_plane.runtime_handle();
        let worker_result = runtime.block_on(worker_loop(
            &args,
            &mut session,
            registration,
            heartbeat,
            capability_report,
            &node_private_key,
            Some(&artifact_data_plane),
            compiler_profile,
            worker_shutdown,
        ));
        artifact_data_plane.shutdown();
        worker_result
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the lifecycle root keeps runtime, signed session, report, and cancellation authorities explicit"
)]
async fn worker_loop(
    args: &Args,
    session: &mut CoordinatorSession,
    registration: Value,
    heartbeat: Value,
    mut capability_report: Value,
    node_private_key: &str,
    artifact_data_plane: Option<&NodeArtifactDataPlane>,
    compiler_profile: Option<SystemBundleCapability>,
    shutdown: CancellationToken,
) -> Result<(), Box<dyn std::error::Error>> {
    const ARTIFACT_GC_INTERVAL: Duration = Duration::from_secs(30);
    let initial_idle_poll_backoff = Duration::from_millis(args.assignment_poll_ms);
    let artifact_store = NodeArtifactStore::for_runtime(args.project_root.as_deref(), &args.node)?;
    let retention_limits = args.artifact_retention;
    let mut last_artifact_gc = Instant::now();
    let mut restart_pins = BTreeMap::<ArtifactId, Instant>::new();
    let mut drain_requested = false;
    let mut idle_poll_backoff = initial_idle_poll_backoff;
    let worker_started = Instant::now();
    let mut last_activity = worker_started;
    let mut completed_work = false;
    let mut wasm_execution_service = node_wasm_execution_service()?;
    let mut active_tasks = BTreeMap::<String, ActiveRuntimeTask>::new();
    let mut active_compilation: Option<ActiveWorkflowCompilation> = None;
    let mut capability_connection_generation = session.connection_generation();
    if args.emit_ready {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "node_status": "ready",
                "mode": "worker",
                "node": &args.node,
            }))?
        );
        std::io::stdout().flush()?;
    }

    loop {
        let completed_compilation = active_compilation
            .as_mut()
            .and_then(|compilation| compilation.execution.try_result());
        if let Some(result) = completed_compilation {
            let compilation = active_compilation
                .take()
                .expect("finished compiler assignment remains active");
            drop(compilation);
            report_system_task_result(args, session, node_private_key, result)?;
            completed_work = true;
            last_activity = Instant::now();
        }
        let completed = active_tasks
            .iter_mut()
            .filter_map(|(task, active)| {
                active
                    .execution
                    .try_result()
                    .map(|result| (task.clone(), result))
            })
            .collect::<Vec<_>>();
        for (task_key, result) in completed {
            let active = active_tasks
                .remove(&task_key)
                .expect("completed active task is still registered");
            active
                .artifact_warmups
                .finish_task(&active.warmup_process, &active.warmup_task);
            let report = finish_runtime_task(
                args,
                session,
                active.task,
                registration.clone(),
                heartbeat.clone(),
                capability_report.clone(),
                active.debug_command,
                node_private_key,
                result,
            )?;
            pin_report_artifacts(&report, retention_limits, &mut restart_pins)?;
            println!("{}", serde_json::to_string(&report)?);
            std::io::stdout().flush()?;
            completed_work = true;
            last_activity = Instant::now();
        }
        if shutdown.is_cancelled() {
            if let Some(compilation) = &active_compilation {
                compilation.execution.abort();
            }
            for active in active_tasks.values() {
                active.execution.abort();
            }
            if !active_tasks.is_empty() || active_compilation.is_some() {
                tokio::time::sleep(Duration::from_millis(10)).await;
                continue;
            }
            if let Err(error) = report_node_capabilities(
                args,
                session,
                node_private_key,
                &artifact_store,
                compiler_profile.as_ref(),
                false,
            ) {
                if !is_account_suspended_error(error.as_ref()) {
                    return Err(error);
                }
            }
            wasm_execution_service.shutdown()?;
            return Ok(());
        }
        if session.connection_generation() != capability_connection_generation {
            match report_node_capabilities(
                args,
                session,
                node_private_key,
                &artifact_store,
                compiler_profile.as_ref(),
                true,
            ) {
                Ok(report) => capability_report = report,
                Err(error) if is_account_suspended_error(error.as_ref()) => {}
                Err(error) => return Err(error),
            }
            capability_connection_generation = session.connection_generation();
        }
        let now_epoch_seconds = unix_timestamp_seconds();
        drain_requested |= args
            .soft_drain_deadline_epoch_seconds
            .is_some_and(|deadline| deadline <= now_epoch_seconds)
            || args
                .hard_drain_deadline_epoch_seconds
                .or(args.provider_deadline_epoch_seconds)
                .is_some_and(|deadline| deadline <= now_epoch_seconds);
        if args.ephemeral && !drain_requested {
            drain_requested = ephemeral_drain_due(
                args.ephemeral,
                completed_work,
                worker_started.elapsed(),
                last_activity.elapsed(),
                Duration::from_secs(args.ephemeral_startup_deadline_seconds),
                Duration::from_secs(args.ephemeral_idle_after_work_seconds),
            );
        }
        if let Some(artifact_data_plane) = artifact_data_plane {
            match artifact_data_plane.service_receiver_assignment(
                args,
                session,
                node_private_key,
                &artifact_store,
            ) {
                Ok(true) => {
                    last_activity = Instant::now();
                    idle_poll_backoff = initial_idle_poll_backoff;
                    continue;
                }
                Ok(false) => {}
                // Artifact-transfer admission is deliberately closed while an
                // account is suspended. Keep the worker alive so its separate
                // assignment/control polls can observe cancellation and report
                // terminal task state through the cleanup lane.
                Err(error) if is_account_suspended_error(error.as_ref()) => {}
                Err(error) => return Err(error),
            }
        }
        if last_artifact_gc.elapsed() >= ARTIFACT_GC_INTERVAL {
            let now = Instant::now();
            restart_pins.retain(|_, expiry| *expiry > now);
            let mut pinned = restart_pins.keys().cloned().collect::<BTreeSet<_>>();
            if let Some(artifact_data_plane) = artifact_data_plane {
                pinned.extend(
                    artifact_data_plane
                        .provider_pins(current_epoch_seconds())
                        .await,
                );
                artifact_data_plane.garbage_collect_partials(current_epoch_seconds())?;
            }
            artifact_store.garbage_collect(retention_limits, &pinned, current_epoch_seconds())?;
            match report_node_capabilities(
                args,
                session,
                node_private_key,
                &artifact_store,
                compiler_profile.as_ref(),
                true,
            ) {
                Ok(report) => capability_report = report,
                Err(error) if is_account_suspended_error(error.as_ref()) => {}
                Err(error) => return Err(error),
            }
            capability_connection_generation = session.connection_generation();
            last_artifact_gc = Instant::now();
        }
        if drain_requested {
            let status = begin_node_drain(args, session, node_private_key)?;
            if args.emit_ready {
                println!(
                    "{}",
                    serde_json::to_string(&json!({
                        "node_status": "draining",
                        "node": &args.node,
                        "drain": &status,
                    }))?
                );
                std::io::stdout().flush()?;
            }
            if status.hard_deadline_reached || status.provider_deadline_reached {
                for active in active_tasks.values() {
                    active.execution.abort();
                }
                if let Some(compilation) = &active_compilation {
                    compilation.execution.abort();
                }
            }
            if active_tasks.is_empty()
                && active_compilation.is_none()
                && (status.state == NodeLifecycleState::ReadyToRelease
                    || status.hard_deadline_reached
                    || status.provider_deadline_reached)
            {
                let released = finalize_node_release(args, session, node_private_key)?;
                if released.state == NodeLifecycleState::Released {
                    if let Err(error) = report_node_capabilities(
                        args,
                        session,
                        node_private_key,
                        &artifact_store,
                        compiler_profile.as_ref(),
                        false,
                    ) {
                        if !is_account_suspended_error(error.as_ref()) {
                            return Err(error);
                        }
                    }
                    wasm_execution_service.shutdown()?;
                    return Ok(());
                }
            }
            if status.queued_task_count == 0 {
                let sleep_for = if active_tasks.is_empty() {
                    idle_poll_backoff
                } else {
                    initial_idle_poll_backoff
                };
                wait_for_worker_poll(
                    sleep_for,
                    args,
                    drain_requested,
                    completed_work,
                    worker_started,
                    last_activity,
                    &shutdown,
                )
                .await;
                if active_tasks.is_empty() {
                    idle_poll_backoff = next_assignment_poll_backoff(idle_poll_backoff);
                } else {
                    idle_poll_backoff = initial_idle_poll_backoff;
                }
                continue;
            }
        }
        let accept_system_tasks = compiler_profile.is_some() && active_compilation.is_none();
        let accept_process_tasks =
            !args.system_tasks_only && active_tasks.len() < MAX_RESIDENT_WASM_TASKS;
        if !accept_system_tasks && !accept_process_tasks && active_compilation.is_none() {
            wait_for_worker_poll(
                initial_idle_poll_backoff,
                args,
                drain_requested,
                completed_work,
                worker_started,
                last_activity,
                &shutdown,
            )
            .await;
            idle_poll_backoff = initial_idle_poll_backoff;
            continue;
        }
        let active_assignment = active_compilation
            .as_ref()
            .map(|active| ActiveNodeAssignment {
                assignment_id: active.assignment_id.clone(),
                attempt_id: active.attempt_id.clone(),
                lease_epoch: active.lease_epoch,
            });
        let poll_assignment = |session: &mut CoordinatorSession| {
            session.request_signed(|| {
                signed_node_request(
                    args,
                    node_private_key,
                    "poll_node_assignment",
                    CoordinatorRequest::PollNodeAssignment {
                        tenant: args.tenant.clone(),
                        project: args.project.clone(),
                        node: args.node.clone(),
                        accept_system_tasks,
                        accept_process_tasks,
                        active_assignment: active_assignment.clone(),
                    },
                )
            })
        };
        let response = match poll_assignment(session) {
            Ok(response) => response,
            Err(error)
                if session.connection_generation() != capability_connection_generation
                    || error
                        .downcast_ref::<ApiError>()
                        .is_some_and(|error| error.code == ApiErrorCode::NoCapableNode) =>
            {
                capability_report = report_node_capabilities(
                    args,
                    session,
                    node_private_key,
                    &artifact_store,
                    compiler_profile.as_ref(),
                    true,
                )?;
                capability_connection_generation = session.connection_generation();
                poll_assignment(session)?
            }
            Err(error) => return Err(error),
        };
        let CoordinatorResponse::NodeAssignment {
            assignment,
            cancel_assignment,
        } = response
        else {
            return Err("coordinator returned an unexpected node-assignment response".into());
        };
        if cancel_assignment.is_some() {
            if let Some(active) = &active_compilation {
                active.execution.abort();
            }
        }
        let Some(offer) = assignment else {
            let sleep_for = if active_tasks.is_empty() {
                idle_poll_backoff
            } else {
                initial_idle_poll_backoff
            };
            wait_for_worker_poll(
                sleep_for,
                args,
                drain_requested,
                completed_work,
                worker_started,
                last_activity,
                &shutdown,
            )
            .await;
            if active_tasks.is_empty() {
                idle_poll_backoff = next_assignment_poll_backoff(idle_poll_backoff);
            } else {
                idle_poll_backoff = initial_idle_poll_backoff;
            }
            continue;
        };
        idle_poll_backoff = initial_idle_poll_backoff;
        let assignment_authority = AssignmentAuthority {
            assignment_id: offer.assignment_id.clone(),
            attempt_id: offer.attempt_id.clone(),
            offer_epoch: offer.lease_epoch,
        };
        let acknowledgement = match session.request_signed(|| {
            signed_node_assignment_request(
                args,
                node_private_key,
                &assignment_authority,
                "acknowledge_node_assignment",
                CoordinatorRequest::AcknowledgeNodeAssignment {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    node: args.node.clone(),
                    assignment_id: offer.assignment_id.clone(),
                    lease_epoch: offer.lease_epoch,
                },
            )
        }) {
            Ok(acknowledgement) => acknowledgement,
            Err(error) if is_stale_assignment_acknowledgement(error.as_ref()) => {
                eprintln!(
                    "Coordinator retired a node assignment before it was acknowledged; polling for current work."
                );
                wait_for_worker_poll(
                    initial_idle_poll_backoff,
                    args,
                    drain_requested,
                    completed_work,
                    worker_started,
                    last_activity,
                    &shutdown,
                )
                .await;
                continue;
            }
            Err(error) => return Err(error),
        };
        if !matches!(
            acknowledgement,
            CoordinatorResponse::NodeAssignmentAcknowledged { .. }
        ) {
            return Err("coordinator rejected the node-assignment acknowledgement".into());
        }
        let assignment_id = offer.assignment_id;
        let attempt_id = offer.attempt_id;
        let lease_epoch = offer.lease_epoch;
        let assignment = match offer.work {
            NodeAssignmentWork::SystemTask { assignment } => {
                if assignment.bundle_id != clusterflux_core::WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID
                    || assignment.bundle_digest
                        != clusterflux_core::workflow_compiler_system_bundle_digest()
                {
                    return Err("workflow compiler system assignment identity mismatch".into());
                }
                let SystemTaskKind::CompileWorkflow { request } = assignment.task;
                if assignment.environment_digest != request.compiler_image {
                    return Err("workflow compiler system environment identity mismatch".into());
                }
                let cancellation = shutdown.child_token();
                active_compilation = Some(ActiveWorkflowCompilation {
                    assignment_id: assignment_id.clone(),
                    attempt_id: attempt_id.clone(),
                    lease_epoch,
                    execution: crate::system_compiler::start_system_compilation(
                        &wasm_execution_service,
                        args,
                        *request,
                        assignment_id,
                        attempt_id,
                        lease_epoch,
                        cancellation,
                    )?,
                });
                continue;
            }
            NodeAssignmentWork::Task { assignment } => assignment,
        };
        let runtime_task = runtime_task_from_assignment(*assignment)?;
        if args.emit_ready {
            let locally_ready_artifacts = artifact_store
                .artifact_ids()?
                .into_iter()
                .collect::<BTreeSet<_>>();
            let (required_artifact_count, locally_ready_artifact_count) = runtime_task
                .task_spec
                .as_ref()
                .map(|task_spec| {
                    (
                        task_spec.required_artifacts.len(),
                        task_spec
                            .required_artifacts
                            .iter()
                            .filter(|artifact| locally_ready_artifacts.contains(*artifact))
                            .count(),
                    )
                })
                .unwrap_or_default();
            println!(
                "{}",
                serde_json::to_string(&json!({
                    "node_status": "assignment_started",
                    "node": &args.node,
                    "process": &runtime_task.process,
                    "virtual_thread": &runtime_task.task,
                    "task_spec": &runtime_task.task_spec,
                    "assignment_authority": {
                        "assignment_id": &assignment_id,
                        "attempt_id": &attempt_id,
                        "offer_epoch": lease_epoch,
                    },
                    "required_artifact_count": required_artifact_count,
                    "locally_ready_artifact_count": locally_ready_artifact_count,
                }))?
            );
            std::io::stdout().flush()?;
        }
        let warmups = artifact_data_plane
            .ok_or("process task reached a system-tasks-only node")?
            .warmups();
        let warmup_task = TaskInstanceId::try_new(runtime_task.task.clone())?;
        if let Some(task_spec) = &runtime_task.task_spec {
            // This only schedules low-priority background work. It never waits for
            // connection establishment or artifact body bytes before Wasm starts.
            warmups.start_task(
                &ProcessId::try_new(runtime_task.process.clone())?,
                &warmup_task,
                &task_spec.artifact_handles(),
            )?;
        }
        if let Some(task_spec) = &runtime_task.task_spec {
            let expiry = Instant::now()
                .checked_add(Duration::from_secs(retention_limits.restart_pin_seconds))
                .unwrap_or_else(Instant::now);
            for artifact in &task_spec.required_artifacts {
                restart_pins.insert(artifact.clone(), expiry);
            }
        }
        let warmup_process = ProcessId::try_new(runtime_task.process.clone())?;
        let launch = launch_runtime_task(
            args,
            session,
            runtime_task,
            registration.clone(),
            heartbeat.clone(),
            capability_report.clone(),
            node_private_key,
            &wasm_execution_service,
            warmups.clone(),
            warmup_process.clone(),
            warmup_task.clone(),
        )
        .await;
        let launch = match launch {
            Ok(launch) => launch,
            Err(error) => {
                warmups.finish_task(&warmup_process, &warmup_task);
                return Err(error);
            }
        };
        match launch {
            RuntimeTaskLaunch::Active(active) => {
                let active = *active;
                let task_key = active.task.task.clone();
                if active_tasks.contains_key(&task_key) {
                    active.execution.abort();
                    active
                        .artifact_warmups
                        .finish_task(&active.warmup_process, &active.warmup_task);
                    return Err(format!(
                        "node received duplicate active assignment for task `{task_key}`"
                    )
                    .into());
                }
                active_tasks.insert(task_key, active);
            }
            RuntimeTaskLaunch::Finished(report) => {
                warmups.finish_task(&warmup_process, &warmup_task);
                pin_report_artifacts(&report, retention_limits, &mut restart_pins)?;
                println!("{}", serde_json::to_string(&report)?);
                std::io::stdout().flush()?;
                completed_work = true;
                last_activity = Instant::now();
            }
        }
    }
}

fn is_account_suspended_error(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|error| error.code == ApiErrorCode::AccountSuspended)
}

fn is_stale_assignment_acknowledgement(error: &(dyn std::error::Error + 'static)) -> bool {
    error
        .downcast_ref::<ApiError>()
        .is_some_and(|error| error.code == ApiErrorCode::Conflict && error.retryable)
}

fn pin_report_artifacts(
    report: &Value,
    retention_limits: NodeArtifactRetentionLimits,
    restart_pins: &mut BTreeMap<ArtifactId, Instant>,
) -> Result<(), Box<dyn std::error::Error>> {
    let Some(metadata) = report.get("vfs_metadata_response") else {
        return Ok(());
    };
    let responses = metadata
        .as_array()
        .map(|responses| responses.iter().collect::<Vec<_>>())
        .unwrap_or_else(|| vec![metadata]);
    let expiry = Instant::now()
        .checked_add(Duration::from_secs(retention_limits.restart_pin_seconds))
        .unwrap_or_else(Instant::now);
    for artifact in responses.into_iter().filter_map(|response| {
        response
            .get("artifact_path")
            .and_then(Value::as_str)
            .and_then(|path| path.strip_prefix("/vfs/artifacts/"))
    }) {
        restart_pins.insert(ArtifactId::try_new(artifact.to_owned())?, expiry);
    }
    Ok(())
}

fn begin_node_drain(
    args: &Args,
    session: &mut CoordinatorSession,
    node_private_key: &str,
) -> Result<NodeDrainStatus, Box<dyn std::error::Error>> {
    let response = session.request_signed(|| {
        signed_node_request(
            args,
            node_private_key,
            "begin_node_drain",
            CoordinatorRequest::BeginNodeDrain {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
                ephemeral: args.ephemeral,
                provider_deadline_epoch_seconds: args.provider_deadline_epoch_seconds,
                soft_drain_deadline_epoch_seconds: args.soft_drain_deadline_epoch_seconds,
                hard_drain_deadline_epoch_seconds: args
                    .hard_drain_deadline_epoch_seconds
                    .or(args.provider_deadline_epoch_seconds),
            },
        )
    })?;
    match response {
        CoordinatorResponse::NodeDrainStatus { status } => Ok(status),
        _ => Err("coordinator returned an unexpected node-drain response".into()),
    }
}

fn finalize_node_release(
    args: &Args,
    session: &mut CoordinatorSession,
    node_private_key: &str,
) -> Result<NodeDrainStatus, Box<dyn std::error::Error>> {
    let response = session.request_signed(|| {
        signed_node_request(
            args,
            node_private_key,
            "finalize_node_release",
            CoordinatorRequest::FinalizeNodeRelease {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
            },
        )
    })?;
    match response {
        CoordinatorResponse::NodeDrainStatus { status } => Ok(status),
        _ => Err("coordinator returned an unexpected node-release response".into()),
    }
}

fn report_system_task_result(
    args: &Args,
    session: &mut CoordinatorSession,
    node_private_key: &str,
    result: clusterflux_core::WorkflowCompilationResult,
) -> Result<(), Box<dyn std::error::Error>> {
    let authority = AssignmentAuthority {
        assignment_id: result.assignment_id.clone(),
        attempt_id: result.attempt_id.clone(),
        offer_epoch: result.lease_epoch,
    };
    let operation_id = format!("system-result-{}", authority.assignment_id);
    let response = session.request_signed(|| {
        signed_node_assignment_operation_request(
            args,
            node_private_key,
            &authority,
            "report_system_task",
            &operation_id,
            CoordinatorRequest::ReportSystemTask {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
                result: clusterflux_protocol::SystemTaskResult {
                    bundle_id: clusterflux_core::WORKFLOW_COMPILER_SYSTEM_BUNDLE_ID.to_owned(),
                    bundle_digest: clusterflux_core::workflow_compiler_system_bundle_digest(),
                    result: clusterflux_protocol::SystemTaskOutput::CompileWorkflow {
                        result: Box::new(result.clone()),
                    },
                },
            },
        )
    })?;
    if matches!(response, CoordinatorResponse::SystemTaskRecorded { .. }) {
        Ok(())
    } else {
        Err("coordinator rejected the workflow compilation result".into())
    }
}

fn report_node_capabilities(
    args: &Args,
    session: &mut CoordinatorSession,
    node_private_key: &str,
    artifact_store: &NodeArtifactStore,
    compiler_profile: Option<&SystemBundleCapability>,
    online: bool,
) -> Result<Value, Box<dyn std::error::Error>> {
    let (artifact_locations, source_snapshots, mut capabilities) = if args.system_tasks_only {
        (
            Vec::new(),
            Vec::new(),
            NodeCapabilities {
                os: clusterflux_core::Os::current(),
                arch: std::env::consts::ARCH.to_owned(),
                capabilities: BTreeSet::from([
                    Capability::Command,
                    Capability::Containers,
                    Capability::RootlessPodman,
                ]),
                environment_backends: BTreeSet::from([EnvironmentBackend::Container]),
                source_providers: BTreeSet::new(),
                work_policy: NodeWorkPolicy::SystemTasksOnly,
                system_bundles: Vec::new(),
            },
        )
    } else {
        (
            artifact_store
                .artifact_ids()?
                .into_iter()
                .map(|artifact| artifact.as_str().to_owned())
                .collect::<Vec<_>>(),
            args.project_root
                .as_deref()
                .map(snapshot_project)
                .transpose()?
                .into_iter()
                .map(|snapshot| snapshot.digest)
                .collect::<Vec<_>>(),
            args.node_capabilities(),
        )
    };
    if args.no_workflow_compilation {
        capabilities.work_policy = NodeWorkPolicy::ExecutionOnly;
    }
    if let Some(profile) = compiler_profile {
        capabilities.system_bundles.push(profile.clone());
    }
    let cached_environment_digests = if args.system_tasks_only {
        Vec::new()
    } else {
        cached_environment_digests(args.project_root.as_deref())?
    };
    let response = session.request_signed(|| {
        signed_node_request(
            args,
            node_private_key,
            "report_node_capabilities",
            CoordinatorRequest::ReportNodeCapabilities {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
                capabilities: capabilities.clone(),
                cached_environment_digests: cached_environment_digests.clone(),
                dependency_cache_digests: Vec::new(),
                source_snapshots: source_snapshots.clone(),
                artifact_locations: artifact_locations.clone(),
                online,
            },
        )
    })?;
    match response {
        response @ CoordinatorResponse::NodeCapabilitiesRecorded { .. } => {
            serde_json::to_value(response).map_err(Into::into)
        }
        _ => Err("coordinator returned an unexpected capability-report response".into()),
    }
}

fn cached_environment_digests(
    project_root: Option<&std::path::Path>,
) -> Result<Vec<Digest>, Box<dyn std::error::Error>> {
    let Some(project_root) = project_root else {
        return Ok(Vec::new());
    };
    let materialized_source =
        clusterflux_source::materialize_clean_local_git_revision(project_root)?;
    let discovery_root = materialized_source
        .as_ref()
        .map_or(project_root, |source| source.root());
    let environments = clusterflux_core::discover_environments(discovery_root)?;
    let mut runner = StdProcessRunner;
    let mut cached = Vec::new();
    for environment in environments {
        if environment.requirements.os.as_ref() != Some(&Os::current()) {
            continue;
        }
        let materialization = match Os::current() {
            Os::Linux => LinuxRootlessPodmanBackend.materialize_environment(&environment)?,
            Os::Windows => WindowsContainerdNerdctlBackend.materialize_environment(&environment)?,
            Os::Macos | Os::Other(_) => continue,
        };
        let inspection = runner.run(&materialization.inspect)?;
        match inspection.status_code {
            Some(0) => cached.push(environment.digest),
            Some(1) => {}
            status => {
                return Err(format!(
                    "inspect immutable environment `{}` failed with status {status:?}: {}",
                    environment.name,
                    String::from_utf8_lossy(&inspection.stderr)
                )
                .into())
            }
        }
    }
    Ok(cached)
}

pub(crate) fn runtime_task_from_assignment(
    assignment: TaskAssignment,
) -> Result<RuntimeTask, Box<dyn std::error::Error>> {
    let assignment_authority = AssignmentAuthority {
        assignment_id: assignment.assignment_id.clone(),
        attempt_id: assignment.attempt_id.clone(),
        offer_epoch: assignment.offer_epoch,
    };
    let task_spec = assignment.task_spec;
    Ok(RuntimeTask {
        process: assignment.process.to_string(),
        task: assignment.task.to_string(),
        epoch: Some(assignment.epoch),
        bundle_digest: task_spec.bundle_digest.clone(),
        task_spec: Some(task_spec),
        wasm_module_base64: Some(assignment.wasm_module_base64),
        assignment_authority,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "runtime execution keeps registration, heartbeat, capability, signing, and artifact authorities explicit"
)]
async fn launch_runtime_task(
    args: &Args,
    session: &mut CoordinatorSession,
    mut task: RuntimeTask,
    registration: Value,
    heartbeat: Value,
    capability_report: Value,
    node_private_key: &str,
    execution_service: &WasmExecutionService,
    artifact_warmups: crate::artifact_interchange::ArtifactWarmupManager,
    warmup_process: ProcessId,
    warmup_task: TaskInstanceId,
) -> Result<RuntimeTaskLaunch, Box<dyn std::error::Error>> {
    let epoch = match task.epoch {
        Some(epoch) => epoch,
        None => {
            let started = session.request(CoordinatorRequest::StartProcess {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                actor_user: None,
                actor_agent: None,
                agent_public_key_fingerprint: None,
                agent_signature: None,
                process: task.process.clone(),
                launch_attempt: None,
                restart: false,
            })?;
            match started {
                CoordinatorResponse::ProcessStarted { epoch, .. } => epoch,
                _ => return Err("coordinator returned an unexpected process-start response".into()),
            }
        }
    };
    task.epoch = Some(epoch);
    session.request_signed(|| {
        signed_node_assignment_request(
            args,
            node_private_key,
            &task.assignment_authority,
            "reconnect_node",
            CoordinatorRequest::ReconnectNode {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
                process: task.process.clone(),
                epoch,
            },
        )
    })?;
    let debug_command = session.request_signed(|| {
        signed_node_assignment_request(
            args,
            node_private_key,
            &task.assignment_authority,
            "poll_debug_command",
            CoordinatorRequest::PollDebugCommand {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                process: task.process.clone(),
                node: args.node.clone(),
                task: task.task.clone(),
            },
        )
    })?;
    let debug_command = match debug_command {
        response @ CoordinatorResponse::DebugCommand { .. } => serde_json::to_value(response)?,
        _ => return Err("coordinator returned an unexpected debug-command response".into()),
    };
    if args.emit_ready && !args.worker {
        println!(
            "{}",
            serde_json::to_string(&json!({
                "node_status": "ready",
                "node": &args.node,
                "process": &task.process,
                "task": &task.task,
            }))?
        );
        std::io::stdout().flush()?;
    }
    if args.control_poll_ms > 0
        && poll_task_cancellation(session, args, &task, node_private_key).await?
    {
        return Ok(RuntimeTaskLaunch::Finished(record_cancelled_task(
            args,
            session,
            &task,
            registration,
            heartbeat,
            capability_report,
            debug_command,
            node_private_key,
            NativeCommandLogSnapshot::default(),
        )?));
    }

    let execution = submit_verified_wasmtime_assignment(
        execution_service,
        args,
        &task,
        node_private_key,
        Some(artifact_warmups.clone()),
    );
    match execution {
        Ok(execution) => Ok(RuntimeTaskLaunch::Active(Box::new(ActiveRuntimeTask {
            task,
            debug_command,
            execution,
            artifact_warmups,
            warmup_process,
            warmup_task,
        }))),
        Err(error) => Ok(RuntimeTaskLaunch::Finished(finish_runtime_task(
            args,
            session,
            task,
            registration,
            heartbeat,
            capability_report,
            debug_command,
            node_private_key,
            Err(error),
        )?)),
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "completion keeps reporting context explicit after the resident Wasm execution yields"
)]
fn finish_runtime_task(
    args: &Args,
    session: &mut CoordinatorSession,
    task: RuntimeTask,
    registration: Value,
    heartbeat: Value,
    capability_report: Value,
    debug_command: Value,
    node_private_key: &str,
    execution: WasmAssignmentResult,
) -> Result<Value, Box<dyn std::error::Error>> {
    match execution {
        Ok((output, manifest, result)) => match crate::task_artifacts::retained_result_artifacts(
            args.project_root.as_deref(),
            &args.node,
            result.as_ref(),
        ) {
            Ok(retained) => record_completed_task(
                args,
                session,
                task,
                output,
                manifest,
                result,
                retained,
                registration,
                heartbeat,
                capability_report,
                debug_command,
                node_private_key,
            ),
            Err(error) => record_failed_task(
                args,
                session,
                &task,
                registration,
                heartbeat,
                capability_report,
                debug_command,
                node_private_key,
                &error,
                NativeCommandLogSnapshot {
                    stdout: output.stdout,
                    stderr: output.stderr,
                    stdout_source_bytes: output.stdout_source_bytes,
                    stderr_source_bytes: output.stderr_source_bytes,
                    stdout_truncated: output.stdout_truncated,
                    stderr_truncated: output.stderr_truncated,
                    log_backpressured: output.log_backpressured,
                },
            ),
        },
        Err(error) => {
            let logs = assignment_error_logs(error.as_ref());
            let error = error.to_string();
            if error.contains("task execution cancelled:") {
                record_cancelled_task(
                    args,
                    session,
                    &task,
                    registration,
                    heartbeat,
                    capability_report,
                    debug_command,
                    node_private_key,
                    logs,
                )
            } else {
                record_failed_task(
                    args,
                    session,
                    &task,
                    registration,
                    heartbeat,
                    capability_report,
                    debug_command,
                    node_private_key,
                    &error,
                    logs,
                )
            }
        }
    }
}

fn parse_args() -> Result<Args, Box<dyn std::error::Error>> {
    let mut args = Args::parse();
    crate::node_identity::apply_stored_node_scope(&mut args)?;
    args.debug_freeze_timeout_ms = environment_bounded_u64(
        "CLUSTERFLUX_DEBUG_FREEZE_TIMEOUT_MS",
        DEFAULT_DEBUG_FREEZE_TIMEOUT_MILLIS,
        1,
        MAX_DEBUG_FREEZE_TIMEOUT_MILLIS,
    )?;
    args.artifact_retention = NodeArtifactRetentionLimits::from_environment()?;
    if args.system_tasks_only && Os::current() != Os::Linux {
        return Err("--system-tasks-only requires a compiler-capable Linux node".into());
    }
    validate_provider_deadlines(&args, unix_timestamp_seconds())?;
    Ok(args)
}

fn parse_positive_u64(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid positive integer: {error}"))?;
    if !(1..=MAX_EPHEMERAL_TIMEOUT_SECONDS).contains(&parsed) {
        return Err(format!(
            "value must be between 1 and {MAX_EPHEMERAL_TIMEOUT_SECONDS} seconds"
        ));
    }
    Ok(parsed)
}

fn parse_task_cpu_count(value: &str) -> Result<u16, String> {
    parse_bounded_u16(value, 1, 256, "task CPU count")
}

fn parse_task_memory_gib(value: &str) -> Result<u16, String> {
    parse_bounded_u16(value, 1, 1024, "task memory")
}

fn parse_task_pids_limit(value: &str) -> Result<u32, String> {
    let parsed = value
        .parse::<u32>()
        .map_err(|error| format!("invalid task PID limit: {error}"))?;
    if !(64..=65_536).contains(&parsed) {
        return Err("task PID limit must be between 64 and 65536".to_owned());
    }
    Ok(parsed)
}

fn parse_bounded_u16(value: &str, minimum: u16, maximum: u16, name: &str) -> Result<u16, String> {
    let parsed = value
        .parse::<u16>()
        .map_err(|error| format!("invalid {name}: {error}"))?;
    if !(minimum..=maximum).contains(&parsed) {
        return Err(format!("{name} must be between {minimum} and {maximum}"));
    }
    Ok(parsed)
}

fn parse_capability(value: &str) -> Result<Capability, String> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "command" => Ok(Capability::Command),
        "containers" => Ok(Capability::Containers),
        "rootless_podman" => Ok(Capability::RootlessPodman),
        "containerd_nerdctl" => Ok(Capability::ContainerdNerdctl),
        "source_filesystem" => Ok(Capability::SourceFilesystem),
        "source_git" => Ok(Capability::SourceGit),
        "host_filesystem" => Ok(Capability::HostFilesystem),
        "network" => Ok(Capability::Network),
        "secrets" => Ok(Capability::Secrets),
        "inbound_ports" => Ok(Capability::InboundPorts),
        "arbitrary_syscalls" => Ok(Capability::ArbitrarySyscalls),
        "vfs_artifacts" => Ok(Capability::VfsArtifacts),
        "windows_command_dev" => Err(
            "windows_command_dev cannot be granted with --cap; start the node with --dangerous-allow-native-commands"
                .to_owned(),
        ),
        "artifact_transfer" => Ok(Capability::ArtifactTransfer),
        "workflow_compiler" | "workflow.compile" => Err(
            "workflow.compile is advertised only after the node compiler self-check passes"
                .to_owned(),
        ),
        _ => Err(format!("unsupported node capability `{value}`")),
    }
}

fn parse_coordinator_endpoint(value: &str) -> Result<String, String> {
    clusterflux_client::endpoint_identity(value)
        .map(|_| value.to_owned())
        .map_err(|error| error.to_string())
}

fn parse_tenant_id(value: &str) -> Result<String, String> {
    TenantId::try_new(value)
        .map(|tenant| tenant.to_string())
        .map_err(|error| error.to_string())
}

fn parse_project_id(value: &str) -> Result<String, String> {
    ProjectId::try_new(value)
        .map(|project| project.to_string())
        .map_err(|error| error.to_string())
}

fn parse_node_id(value: &str) -> Result<String, String> {
    NodeId::try_new(value)
        .map(|node| node.to_string())
        .map_err(|error| error.to_string())
}

fn parse_enrollment_grant(value: &str) -> Result<String, String> {
    clusterflux_core::validate_opaque_token(value, 512)
        .map(|()| value.to_owned())
        .map_err(|error| error.to_string())
}

fn parse_node_public_key(value: &str) -> Result<String, String> {
    clusterflux_core::validate_opaque_token(value, 512)
        .map(|()| value.to_owned())
        .map_err(|error| error.to_string())
}

fn parse_control_poll_ms(value: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|error| format!("invalid control poll interval: {error}"))?;
    if value > MAX_CONTROL_POLL_MILLIS {
        return Err(format!(
            "control poll duration must not exceed {MAX_CONTROL_POLL_MILLIS} milliseconds"
        ));
    }
    Ok(value)
}

fn parse_coordinator_reconnect_max_seconds(value: &str) -> Result<u64, String> {
    let value = value
        .parse::<u64>()
        .map_err(|error| format!("invalid coordinator reconnect delay: {error}"))?;
    if value > MAX_COORDINATOR_RECONNECT_SECONDS {
        return Err(format!(
            "--coordinator-reconnect-max-seconds must be between 0 and {MAX_COORDINATOR_RECONNECT_SECONDS}"
        ));
    }
    Ok(value)
}

fn environment_bounded_u64(
    name: &str,
    default: u64,
    minimum: u64,
    maximum: u64,
) -> Result<u64, String> {
    let configured = match std::env::var(name) {
        Ok(value) => value,
        Err(std::env::VarError::NotPresent) => default.to_string(),
        Err(std::env::VarError::NotUnicode(_)) => {
            return Err(format!("{name} must contain valid Unicode"));
        }
    };
    let value = configured
        .parse::<u64>()
        .map_err(|error| format!("{name} is invalid: {error}"))?;
    if !(minimum..=maximum).contains(&value) {
        return Err(format!("{name} must be between {minimum} and {maximum}"));
    }
    Ok(value)
}

fn validate_provider_deadlines(args: &Args, now: u64) -> Result<(), String> {
    let maximum = now.saturating_add(MAX_PROVIDER_DEADLINE_HORIZON_SECONDS);
    for (name, deadline) in [
        (
            "--provider-deadline-epoch-seconds",
            args.provider_deadline_epoch_seconds,
        ),
        (
            "--soft-drain-deadline-epoch-seconds",
            args.soft_drain_deadline_epoch_seconds,
        ),
        (
            "--hard-drain-deadline-epoch-seconds",
            args.hard_drain_deadline_epoch_seconds,
        ),
    ] {
        if deadline.is_some_and(|deadline| deadline > maximum) {
            return Err(format!(
                "{name} must not be more than {MAX_PROVIDER_DEADLINE_HORIZON_SECONDS} seconds in the future"
            ));
        }
    }
    let hard = args
        .hard_drain_deadline_epoch_seconds
        .or(args.provider_deadline_epoch_seconds);
    if matches!(
        (args.soft_drain_deadline_epoch_seconds, hard),
        (Some(soft), Some(hard)) if soft > hard
    ) {
        return Err("soft drain deadline must not follow the hard provider deadline".to_owned());
    }
    Ok(())
}

fn parse_assignment_poll_ms(value: &str) -> Result<u64, String> {
    let parsed = value
        .parse::<u64>()
        .map_err(|error| format!("invalid assignment poll interval: {error}"))?;
    validate_assignment_poll_ms(parsed)
}

fn validate_assignment_poll_ms(value: u64) -> Result<u64, String> {
    const MINIMUM_MS: u64 = 100;
    const MAXIMUM_MS: u64 = 2_000;
    if !(MINIMUM_MS..=MAXIMUM_MS).contains(&value) {
        return Err(format!(
            "--assignment-poll-ms must be between {MINIMUM_MS} and {MAXIMUM_MS} ms; idle polling backs off to the {MAXIMUM_MS} ms ceiling"
        ));
    }
    Ok(value)
}

fn next_assignment_poll_backoff(current: Duration) -> Duration {
    match current.as_millis() {
        0..=100 => Duration::from_millis(250),
        101..=250 => Duration::from_millis(500),
        251..=500 => Duration::from_secs(1),
        _ => Duration::from_secs(2),
    }
}

fn next_worker_drain_wait(
    args: &Args,
    completed_work: bool,
    worker_started: Instant,
    last_activity: Instant,
) -> Option<Duration> {
    let now_epoch_seconds = unix_timestamp_seconds();
    let mut waits = [
        args.soft_drain_deadline_epoch_seconds
            .map(|deadline| Duration::from_secs(deadline.saturating_sub(now_epoch_seconds))),
        args.hard_drain_deadline_epoch_seconds
            .or(args.provider_deadline_epoch_seconds)
            .map(|deadline| Duration::from_secs(deadline.saturating_sub(now_epoch_seconds))),
        args.ephemeral.then(|| {
            if completed_work {
                Duration::from_secs(args.ephemeral_idle_after_work_seconds)
                    .saturating_sub(last_activity.elapsed())
            } else {
                Duration::from_secs(args.ephemeral_startup_deadline_seconds)
                    .saturating_sub(worker_started.elapsed())
            }
        }),
    ]
    .into_iter()
    .flatten();
    waits.next().map(|first| waits.fold(first, Duration::min))
}

#[allow(clippy::too_many_arguments)]
async fn wait_for_worker_poll(
    requested: Duration,
    args: &Args,
    drain_requested: bool,
    completed_work: bool,
    worker_started: Instant,
    last_activity: Instant,
    shutdown: &CancellationToken,
) {
    let delay = if drain_requested {
        requested
    } else {
        next_worker_drain_wait(args, completed_work, worker_started, last_activity)
            .map_or(requested, |deadline| requested.min(deadline))
    };
    tokio::select! {
        () = tokio::time::sleep(delay) => {}
        () = shutdown.cancelled() => {}
    }
}

fn ephemeral_drain_due(
    ephemeral: bool,
    completed_work: bool,
    worker_elapsed: Duration,
    idle_elapsed: Duration,
    startup_deadline: Duration,
    idle_deadline: Duration,
) -> bool {
    ephemeral
        && if completed_work {
            idle_elapsed >= idle_deadline
        } else {
            worker_elapsed >= startup_deadline
        }
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeSet;
    use std::time::{Duration, Instant};

    use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
    use clap::Parser;
    use clusterflux_core::{
        ApiError, ApiErrorCategory, ApiErrorCode, Capability, Digest, ProcessId, ProjectId,
        TaskBoundaryValue, TaskDispatch, TaskInstanceId, TaskSpec, TenantId, WasmExportAbi,
        WasmTaskResult,
    };
    use tokio_util::sync::CancellationToken;

    use super::{
        control_endpoint_identity, ephemeral_drain_due, is_account_suspended_error,
        is_stale_assignment_acknowledgement, load_or_create_local_node_credential,
        next_worker_drain_wait, parse_control_poll_ms, parse_positive_u64,
        validate_assignment_poll_ms, validate_provider_deadlines, wait_for_worker_poll, Args,
        ContainerRunPolicy, RuntimeTask, DEFAULT_HOSTED_COORDINATOR_ENDPOINT,
        MAX_PROVIDER_DEADLINE_HORIZON_SECONDS,
    };
    use crate::assignment_runner::{
        node_wasm_execution_service, submit_verified_wasmtime_assignment,
    };

    #[test]
    fn suspended_account_capability_publication_is_skippable_but_other_errors_are_not() {
        let suspended = ApiError::new(
            ApiErrorCode::AccountSuspended,
            ApiErrorCategory::Authorization,
            "tenant is suspended",
            false,
            "node-1",
        );
        let forbidden = ApiError::new(
            ApiErrorCode::Forbidden,
            ApiErrorCategory::Authorization,
            "forbidden",
            false,
            "node-2",
        );
        assert!(is_account_suspended_error(&suspended));
        assert!(!is_account_suspended_error(&forbidden));
    }

    #[test]
    fn only_retryable_assignment_conflicts_are_discarded_as_stale_offers() {
        let stale = ApiError::new(
            ApiErrorCode::Conflict,
            ApiErrorCategory::State,
            "node assignment acknowledgement is stale",
            true,
            "node-1",
        );
        let terminal_conflict = ApiError::new(
            ApiErrorCode::Conflict,
            ApiErrorCategory::State,
            "terminal operation conflict",
            false,
            "node-2",
        );
        let forbidden = ApiError::new(
            ApiErrorCode::Forbidden,
            ApiErrorCategory::Authorization,
            "outside node scope",
            false,
            "node-3",
        );

        assert!(is_stale_assignment_acknowledgement(&stale));
        assert!(!is_stale_assignment_acknowledgement(&terminal_conflict));
        assert!(!is_stale_assignment_acknowledgement(&forbidden));
    }

    #[test]
    fn node_poll_interval_cannot_exhaust_the_bounded_replay_window() {
        assert!(validate_assignment_poll_ms(100).is_ok());
        assert!(validate_assignment_poll_ms(2_000).is_ok());
        assert!(validate_assignment_poll_ms(99).is_err());
        assert!(validate_assignment_poll_ms(2_001).is_err());
    }

    #[test]
    fn clap_configuration_rejects_unsafe_or_unknown_values() {
        let hosted = Args::try_parse_from(["clusterflux-node", "--worker"]).unwrap();
        assert_eq!(hosted.coordinator, DEFAULT_HOSTED_COORDINATOR_ENDPOINT);
        assert_eq!(hosted.coordinator_reconnect_max_seconds, 60 * 60);
        let reconnect_disabled = Args::try_parse_from([
            "clusterflux-node",
            "--coordinator-reconnect-max-seconds",
            "0",
        ])
        .unwrap();
        assert_eq!(reconnect_disabled.coordinator_reconnect_max_seconds, 0);
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator-reconnect-max-seconds",
            "86401",
        ])
        .is_err());

        let args = Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--worker",
        ])
        .unwrap();
        assert_eq!(args.assignment_poll_ms, 100);
        assert_eq!(args.task_container_policy(), ContainerRunPolicy::default());
        assert!(!args.no_workflow_compilation);
        assert!(!args.system_tasks_only);
        assert!(!args.dangerous_allow_native_commands);
        let dangerous = Args::try_parse_from([
            "clusterflux-node",
            "--worker",
            "--dangerous-allow-native-commands",
        ])
        .unwrap();
        assert!(dangerous.dangerous_allow_native_commands);
        assert!(dangerous
            .node_capabilities()
            .capabilities
            .contains(&Capability::Command));
        assert!(
            Args::try_parse_from(["clusterflux-node", "--worker", "--allow-native-commands",])
                .is_err()
        );
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--worker",
            "--cap",
            "windows-command-dev",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--system-tasks-only",
            "--no-workflow-compilation",
        ])
        .is_err());
        let args = Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--worker",
            "--cap",
            "network",
            "--cap",
            "source-git",
            "--cap",
            "secrets",
            "--task-cpus",
            "8",
            "--task-memory-gib",
            "16",
            "--task-pids-limit",
            "1024",
        ])
        .unwrap();
        assert!(args.capabilities.contains(&Capability::Network));
        assert!(args.capabilities.contains(&Capability::SourceGit));
        assert!(args.capabilities.contains(&Capability::Secrets));
        assert_eq!(args.task_container_policy().cpu_count, 8);
        assert_eq!(
            args.task_container_policy().memory_bytes,
            16 * 1024 * 1024 * 1024
        );
        assert_eq!(args.task_container_policy().pids_limit, 1_024);
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--cap",
            "workflow-compiler",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--task-cpus",
            "0",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--task-memory-gib",
            "0",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--task-pids-limit",
            "63",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--assignment-poll-ms",
            "99",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "http://clusterflux.example",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--ephemeral-startup-deadline-seconds",
            "0",
        ])
        .is_err());
        assert!(Args::try_parse_from([
            "clusterflux-node",
            "--coordinator",
            "127.0.0.1:7999",
            "--unknown",
        ])
        .is_err());
        assert!(parse_positive_u64(&u64::MAX.to_string()).is_err());
        assert!(parse_control_poll_ms(&u64::MAX.to_string()).is_err());

        let mut deadlines = test_args();
        deadlines.provider_deadline_epoch_seconds =
            Some(10 + MAX_PROVIDER_DEADLINE_HORIZON_SECONDS + 1);
        assert!(validate_provider_deadlines(&deadlines, 10).is_err());
        deadlines.provider_deadline_epoch_seconds = Some(20);
        deadlines.soft_drain_deadline_epoch_seconds = Some(21);
        assert!(validate_provider_deadlines(&deadlines, 10).is_err());
    }

    #[test]
    fn ephemeral_nodes_drain_when_unused_or_idle_but_persistent_nodes_do_not() {
        let startup = Duration::from_secs(60);
        let idle = Duration::from_secs(30);
        assert!(!ephemeral_drain_due(
            true,
            false,
            Duration::from_secs(59),
            Duration::ZERO,
            startup,
            idle,
        ));
        assert!(ephemeral_drain_due(
            true,
            false,
            startup,
            Duration::ZERO,
            startup,
            idle,
        ));
        assert!(!ephemeral_drain_due(
            true,
            true,
            Duration::from_secs(600),
            Duration::from_secs(29),
            startup,
            idle,
        ));
        assert!(ephemeral_drain_due(
            true,
            true,
            Duration::from_secs(600),
            idle,
            startup,
            idle,
        ));
        assert!(!ephemeral_drain_due(
            false,
            true,
            Duration::from_secs(600),
            Duration::from_secs(600),
            startup,
            idle,
        ));
    }

    #[test]
    fn worker_poll_uses_ephemeral_deadline_and_shutdown_token() {
        let mut args = test_args();
        args.ephemeral = true;
        args.ephemeral_startup_deadline_seconds = 1;
        let worker_started = Instant::now()
            .checked_sub(Duration::from_millis(950))
            .unwrap();
        let remaining = next_worker_drain_wait(&args, false, worker_started, worker_started)
            .expect("ephemeral workers have a drain deadline");
        assert!(remaining <= Duration::from_millis(50));

        let shutdown = CancellationToken::new();
        shutdown.cancel();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .unwrap();
        let started = Instant::now();
        runtime.block_on(wait_for_worker_poll(
            Duration::from_secs(60),
            &args,
            false,
            false,
            worker_started,
            worker_started,
            &shutdown,
        ));
        assert!(started.elapsed() < Duration::from_millis(100));
    }

    #[test]
    fn hosted_url_remains_an_https_control_endpoint() {
        assert_eq!(
            control_endpoint_identity("https://clusterflux.lesstuff.com").unwrap(),
            "https://clusterflux.lesstuff.com/api/v1/control"
        );
        assert_eq!(
            control_endpoint_identity("https://clusterflux.lesstuff.com/api/v1/control").unwrap(),
            "https://clusterflux.lesstuff.com/api/v1/control"
        );
        assert_eq!(
            control_endpoint_identity("127.0.0.1:7999").unwrap(),
            "clusterflux+tcp://127.0.0.1:7999"
        );
    }

    #[test]
    fn daemon_local_node_credential_is_durable_between_runs() {
        let temp = std::env::temp_dir().join(format!(
            "clusterflux-node-credential-test-{}-{}",
            std::process::id(),
            super::unix_timestamp_nanos()
        ));
        std::fs::create_dir_all(&temp).unwrap();
        let first = load_or_create_local_node_credential(&temp, "daemon-node").unwrap();
        let second = load_or_create_local_node_credential(&temp, "daemon-node").unwrap();

        assert_eq!(first, second);
        assert!(temp.join(".clusterflux-state").join("nodes").exists());

        std::fs::remove_dir_all(&temp).unwrap();
    }

    #[test]
    fn daemon_wasm_task_assignment_uses_abi_version_and_verifies_bundle_digest() {
        let project_root = tempfile::tempdir().unwrap();
        let mut args = test_args();
        args.project_root = Some(project_root.path().to_path_buf());
        let task_instance = TaskInstanceId::from("task_add_one-1");
        let boundary = TaskBoundaryValue::SmallJson(serde_json::json!(2));
        let result = serde_json::to_string(&WasmTaskResult::completed(
            task_instance.clone(),
            boundary.clone(),
        ))
        .unwrap();
        let wat_result = result.replace('\\', "\\\\").replace('"', "\\\"");
        let result_length = result.len();
        let packed = ((result_length as u64) << 32) | 2048;
        let wasm = wat::parse_str(format!(
            r#"(module
                  (memory (export "memory") 1)
                  (data (i32.const 2048) "{wat_result}")
                  (func (export "clusterflux_alloc_v1") (param i32) (result i32)
                    i32.const 1024)
                  (func (export "task_add_one") (param i32 i32) (result i64)
                    i64.const {packed}))"#
        ))
        .unwrap();
        let task = RuntimeTask {
            process: "vp".to_owned(),
            task: task_instance.as_str().to_owned(),
            epoch: Some(7),
            task_spec: Some(TaskSpec {
                tenant: TenantId::from("tenant"),
                project: ProjectId::from("project"),
                process: ProcessId::from("vp"),
                task_definition: clusterflux_core::TaskDefinitionId::from("task_add_one"),
                task_instance,
                dispatch: TaskDispatch::CoordinatorNodeWasm {
                    export: Some("task_add_one".to_owned()),
                    abi: WasmExportAbi::TaskV1,
                },
                environment_id: None,
                environment: None,
                environment_digest: None,
                required_capabilities: BTreeSet::new(),
                dependency_cache: None,
                source_snapshot: None,
                source_revision: None,
                required_artifacts: Vec::new(),
                args: Vec::new(),
                requested_secrets: Vec::new(),
                vfs_epoch: 7,
                failure_policy: Default::default(),
                bundle_digest: Some(Digest::sha256(&wasm)),
            }),
            bundle_digest: Some(Digest::sha256(&wasm)),
            wasm_module_base64: Some(BASE64_STANDARD.encode(&wasm)),
            assignment_authority: clusterflux_core::AssignmentAuthority {
                assignment_id: "test-assignment".to_owned(),
                attempt_id: "test-attempt".to_owned(),
                offer_epoch: 1,
            },
        };

        let mut service = node_wasm_execution_service().unwrap();
        let (output, manifest, result) = submit_verified_wasmtime_assignment(
            &service,
            &args,
            &task,
            "test-node-private-key",
            None,
        )
        .unwrap()
        .blocking_wait()
        .unwrap();

        assert_eq!(output.status_code, Some(0));
        assert_eq!(output.stdout, "");
        assert_eq!(output.stdout_source_bytes, 0);
        assert!(output.staged_artifact.is_none());
        assert!(manifest.objects.is_empty());
        assert!(!manifest.large_bytes_uploaded);
        assert_eq!(result, Some(boundary.clone()));

        let mismatch = RuntimeTask {
            bundle_digest: Some(Digest::sha256("different bundle bytes")),
            wasm_module_base64: Some(BASE64_STANDARD.encode("not valid wasm")),
            ..task.clone()
        };
        let (second_output, _, second_result) = submit_verified_wasmtime_assignment(
            &service,
            &args,
            &task,
            "test-node-private-key",
            None,
        )
        .unwrap()
        .blocking_wait()
        .unwrap();
        assert_eq!(second_output.status_code, Some(0));
        assert_eq!(second_result, Some(boundary));
        let metrics = service.metrics();
        assert_eq!(metrics.module_compilations, 1);
        assert_eq!(metrics.module_cache_hits, 1);

        let error = match submit_verified_wasmtime_assignment(
            &service,
            &args,
            &mismatch,
            "test-node-private-key",
            None,
        ) {
            Ok(_) => panic!("bundle digest mismatch should be rejected before submission"),
            Err(error) => error,
        };
        assert!(error.to_string().contains("bundle digest mismatch"));
        assert!(!error.to_string().contains("failed to parse"));
        service.shutdown().unwrap();
    }

    fn test_args() -> Args {
        Args {
            coordinator: "127.0.0.1:1".to_owned(),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            project_root: None,
            node: "node".to_owned(),
            enrollment_grant: None,
            public_key: None,
            control_poll_ms: 0,
            assignment_poll_ms: 1,
            coordinator_reconnect_max_seconds: 0,
            task_cpus: 2,
            task_memory_gib: 2,
            task_pids_limit: 256,
            emit_ready: false,
            worker: false,
            capabilities: Vec::new(),
            dangerous_allow_native_commands: false,
            no_workflow_compilation: true,
            system_tasks_only: false,
            system_compiler_image: None,
            system_compiler_runsc_version: None,
            system_compiler_sandbox: "podman".to_owned(),
            system_compiler_podman: "podman".to_owned(),
            system_compiler_runsc: "runsc".to_owned(),
            system_compiler_package_verified: false,
            system_compiler_package_dir: None,
            ephemeral: false,
            provider_deadline_epoch_seconds: None,
            soft_drain_deadline_epoch_seconds: None,
            hard_drain_deadline_epoch_seconds: None,
            ephemeral_startup_deadline_seconds: 60,
            ephemeral_idle_after_work_seconds: 30,
            debug_freeze_timeout_ms: 5_000,
            artifact_retention: crate::task_artifacts::NodeArtifactRetentionLimits::default(),
        }
    }
}
