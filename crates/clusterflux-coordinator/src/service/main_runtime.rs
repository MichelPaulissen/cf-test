use std::collections::{BTreeMap, BTreeSet, HashMap};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64_STANDARD, Engine as _};
use clusterflux_core::{
    ArtifactHandle, Capability, CredentialKind, Digest, EnvironmentResource, NodeId, ProcessId,
    ProjectId, TaskBoundaryValue, TaskDefinitionId, TaskDispatch, TaskInstanceId, TaskJoinState,
    TaskSpec, TenantId, TriggerContext, WasmExportAbi, WasmHostCommandRequest,
    WasmHostCommandResult, WasmHostDebugProbeRequest, WasmHostDebugProbeResult,
    WasmHostSourceSnapshotRequest, WasmHostSourceSnapshotResult, WasmHostTaskControlRequest,
    WasmHostTaskControlResult, WasmHostTaskHandle, WasmHostTaskJoinRequest, WasmHostTaskJoinResult,
    WasmHostTaskStartRequest, WasmHostTriggerContextRequest, WasmHostTriggerContextResult,
    WasmHostVfsOperation, WasmHostVfsRequest, WasmHostVfsResult, WasmTaskInvocation,
    WasmTaskOutcome, WasmTaskResult,
};
use clusterflux_wasm_runtime::{
    AsyncWasmTaskHost, WasmDebugControl, WasmExecution, WasmExecutionService,
    WasmExecutionServiceConfiguration, WasmHostFuture, WasmtimeRuntimeLimits,
};
use tokio::sync::{mpsc, oneshot};
use wasmparser::{Parser, Payload};

use crate::{CoordinatorError, CoordinatorServiceError};

use super::keys::{process_control_key, task_restart_key, ProcessControlKey, TaskRestartKey};
use super::{
    CoordinatorResponse, CoordinatorService, TaskCompletionEvent, TaskExecutor, TaskTerminalState,
    WorkflowActor,
};

#[derive(Clone)]
pub(super) struct MainScope {
    pub(super) tenant: TenantId,
    pub(super) project: ProjectId,
    pub(super) process: ProcessId,
    pub(super) task_definition: TaskDefinitionId,
    pub(super) task_instance: TaskInstanceId,
    pub(super) epoch: u64,
    pub(super) launch_id: u64,
}

enum MainCommand {
    StartTask {
        scope: MainScope,
        handle_id: u64,
        task_spec: Box<TaskSpec>,
        wasm_module_base64: String,
        response: oneshot::Sender<Result<WasmHostTaskHandle, String>>,
    },
    JoinTask {
        scope: MainScope,
        task_instance: TaskInstanceId,
        response: oneshot::Sender<Result<WasmHostTaskJoinResult, String>>,
    },
    DebugProbe {
        scope: MainScope,
        request: WasmHostDebugProbeRequest,
        response: oneshot::Sender<Result<WasmHostDebugProbeResult, String>>,
    },
    ReleaseArtifact {
        scope: MainScope,
        artifact: ArtifactHandle,
        response: oneshot::Sender<Result<(), String>>,
    },
    Finished {
        scope: MainScope,
        result: Result<WasmTaskResult, String>,
    },
}

pub(super) struct CoordinatorMainControl {
    pub(super) task_definition: TaskDefinitionId,
    pub(super) task_instance: TaskInstanceId,
    pub(super) abort: Arc<AtomicBool>,
    pub(super) debug: Arc<WasmDebugControl>,
    pub(super) state: String,
    pub(super) stopped_probe_symbol: Option<String>,
    pub(super) handles: Arc<Mutex<HashMap<u64, TaskSpec>>>,
    pub(super) launch_id: u64,
}

pub(super) struct CoordinatorMainRuntime {
    sender: mpsc::Sender<MainCommand>,
    receiver: mpsc::Receiver<MainCommand>,
    pub(super) controls: BTreeMap<ProcessControlKey, CoordinatorMainControl>,
    executions: BTreeMap<ProcessControlKey, MainExecution>,
    join_waiters:
        BTreeMap<TaskRestartKey, Vec<oneshot::Sender<Result<WasmHostTaskJoinResult, String>>>>,
    next_launch_id: u64,
    runtime_limits: WasmtimeRuntimeLimits,
    nested_join_timeout: Duration,
    max_active_mains: usize,
    max_wakeups_per_minute: u64,
    max_output_bytes: usize,
    max_state_bytes: usize,
    execution_service: WasmExecutionService,
}

struct MainExecution {
    scope: MainScope,
    execution: WasmExecution,
}

impl CoordinatorMainRuntime {
    pub(super) fn new() -> Result<Self, CoordinatorServiceError> {
        let (sender, receiver) = mpsc::channel(1_024);
        let execution_service = WasmExecutionService::new(WasmExecutionServiceConfiguration {
            thread_name: "clusterflux-coordinator-wasm".to_owned(),
            ..WasmExecutionServiceConfiguration::default()
        })
        .map_err(|error| CoordinatorServiceError::Protocol(error.to_string()))?;
        Ok(Self {
            sender,
            receiver,
            controls: BTreeMap::new(),
            executions: BTreeMap::new(),
            join_waiters: BTreeMap::new(),
            next_launch_id: 1,
            runtime_limits: WasmtimeRuntimeLimits::default(),
            nested_join_timeout: clusterflux_core::limits::task_join_timeout(),
            max_active_mains: super::MAX_COORDINATOR_MAINS,
            max_wakeups_per_minute: 6_000,
            max_output_bytes: super::MAX_TASK_LOG_TAIL_BYTES,
            max_state_bytes: clusterflux_core::MAX_WASM_TASK_ENVELOPE_BYTES,
            execution_service,
        })
    }
    pub(super) fn active_main_count(&self) -> usize {
        self.controls.len()
    }

    pub(super) fn max_active_mains(&self) -> usize {
        self.max_active_mains
    }

    pub(super) fn configure(
        &mut self,
        configuration: super::CoordinatorMainRuntimeConfiguration,
    ) -> Result<(), CoordinatorServiceError> {
        configuration
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
        let limits = WasmtimeRuntimeLimits {
            fuel_units_per_second: configuration.fuel_units_per_second,
            fuel_burst_seconds: configuration.fuel_burst_seconds,
            memory_bytes: configuration.memory_bytes,
        };
        self.runtime_limits = limits;
        self.nested_join_timeout = Duration::from_millis(configuration.nested_join_timeout_ms);
        self.max_active_mains = configuration.max_active_mains;
        self.max_wakeups_per_minute = configuration.max_wakeups_per_minute;
        self.max_output_bytes = configuration.max_output_bytes;
        self.max_state_bytes = configuration.max_state_bytes;
        Ok(())
    }

    fn ensure_launch_capacity(
        &self,
        process_key: &ProcessControlKey,
        process: &ProcessId,
    ) -> Result<(), CoordinatorServiceError> {
        if self.controls.contains_key(process_key) {
            return Err(CoordinatorServiceError::Protocol(format!(
                "virtual process {process} already has a coordinator main instance"
            )));
        }
        if self.controls.len() >= self.max_active_mains {
            return Err(CoordinatorServiceError::Protocol(format!(
                "admission.coordinator_main_limit: global coordinator-main limit of {} reached",
                self.max_active_mains
            )));
        }
        Ok(())
    }

    pub(super) fn is_waiting_for_task(
        &self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
    ) -> bool {
        self.join_waiters
            .keys()
            .any(|(waiter_tenant, waiter_project, waiter_process, _)| {
                waiter_tenant == tenant && waiter_project == project && waiter_process == process
            })
    }

    fn drain_commands(&mut self) -> Vec<MainCommand> {
        let mut commands = Vec::new();
        while let Ok(command) = self.receiver.try_recv() {
            commands.push(command);
        }
        let completed = self
            .executions
            .iter_mut()
            .filter_map(|(key, execution)| {
                execution
                    .execution
                    .try_result()
                    .map(|result| (key.clone(), execution.scope.clone(), result))
            })
            .collect::<Vec<_>>();
        for (key, scope, result) in completed {
            self.executions.remove(&key);
            commands.push(MainCommand::Finished {
                scope,
                result: result.map_err(|error| error.to_string()),
            });
        }
        commands
    }

    fn launch(
        &mut self,
        mut scope: MainScope,
        export: String,
        module: Vec<u8>,
        wasm_module_base64: String,
        bundle_digest: Digest,
        task_descriptors: HashMap<String, serde_json::Value>,
        environments: BTreeMap<String, EnvironmentResource>,
        trigger_context: Option<TriggerContext>,
        source_snapshot: Option<Digest>,
        source_revision: Option<clusterflux_core::RepositoryRevision>,
    ) -> Result<(), CoordinatorServiceError> {
        let process_key = process_control_key(&scope.tenant, &scope.project, &scope.process);
        self.ensure_launch_capacity(&process_key, &scope.process)?;
        scope.launch_id = self.next_launch_id;
        self.next_launch_id = self.next_launch_id.saturating_add(1);
        let abort = Arc::new(AtomicBool::new(false));
        let debug = Arc::new(WasmDebugControl::default());
        let handles = Arc::new(Mutex::new(HashMap::new()));
        self.controls.insert(
            process_key.clone(),
            CoordinatorMainControl {
                task_definition: scope.task_definition.clone(),
                task_instance: scope.task_instance.clone(),
                abort: Arc::clone(&abort),
                debug: Arc::clone(&debug),
                state: "running".to_owned(),
                stopped_probe_symbol: None,
                handles: Arc::clone(&handles),
                launch_id: scope.launch_id,
            },
        );
        let sender = self.sender.clone();
        let invocation = WasmTaskInvocation::new(
            scope.task_definition.clone(),
            scope.task_instance.clone(),
            Vec::new(),
        );
        let host = CoordinatorMainHost {
            scope: scope.clone(),
            sender,
            abort,
            debug,
            task_descriptors,
            environments,
            trigger_context,
            source_snapshot,
            source_revision,
            bundle_digest: bundle_digest.clone(),
            wasm_module_base64,
            next_handle_id: 1,
            handles,
            nested_join_timeout: self.nested_join_timeout,
            wake_rate: GuestWakeRate::new(self.max_wakeups_per_minute),
        };
        let execution = match self.execution_service.submit_task_export_verified(
            module,
            bundle_digest,
            export,
            invocation,
            self.runtime_limits.clone(),
            Box::new(host),
        ) {
            Ok(execution) => execution,
            Err(error) => {
                self.controls.remove(&process_key);
                return Err(CoordinatorServiceError::Protocol(error.to_string()));
            }
        };
        self.executions
            .insert(process_key, MainExecution { scope, execution });
        Ok(())
    }

    pub(super) fn interrupt_process(
        &mut self,
        tenant: &TenantId,
        project: &ProjectId,
        process: &ProcessId,
        reason: &str,
    ) {
        let process_key = process_control_key(tenant, project, process);
        if let Some(control) = self.controls.get_mut(&process_key) {
            control.abort.store(true, Ordering::Release);
            control.state = "stopping".to_owned();
        }
        let waiter_keys = self
            .join_waiters
            .keys()
            .filter(|(waiter_tenant, waiter_project, waiter_process, _)| {
                waiter_tenant == tenant && waiter_project == project && waiter_process == process
            })
            .cloned()
            .collect::<Vec<_>>();
        for key in waiter_keys {
            if let Some(waiters) = self.join_waiters.remove(&key) {
                for waiter in waiters {
                    let _ = waiter.send(Err(reason.to_owned()));
                }
            }
        }
    }

    fn is_current_scope(&self, scope: &MainScope) -> bool {
        self.controls
            .get(&process_control_key(
                &scope.tenant,
                &scope.project,
                &scope.process,
            ))
            .is_some_and(|control| control.launch_id == scope.launch_id)
    }
}

struct CoordinatorMainHost {
    scope: MainScope,
    sender: mpsc::Sender<MainCommand>,
    abort: Arc<AtomicBool>,
    debug: Arc<WasmDebugControl>,
    task_descriptors: HashMap<String, serde_json::Value>,
    environments: BTreeMap<String, EnvironmentResource>,
    trigger_context: Option<TriggerContext>,
    source_snapshot: Option<Digest>,
    source_revision: Option<clusterflux_core::RepositoryRevision>,
    bundle_digest: Digest,
    wasm_module_base64: String,
    next_handle_id: u64,
    handles: Arc<Mutex<HashMap<u64, TaskSpec>>>,
    nested_join_timeout: Duration,
    wake_rate: GuestWakeRate,
}

struct GuestWakeRate {
    maximum_per_minute: u64,
    window_started: Instant,
    used: u64,
}

impl GuestWakeRate {
    fn new(maximum_per_minute: u64) -> Self {
        Self {
            maximum_per_minute,
            window_started: Instant::now(),
            used: 0,
        }
    }

    fn charge(&mut self) -> Result<(), String> {
        if self.window_started.elapsed() >= Duration::from_secs(60) {
            self.window_started = Instant::now();
            self.used = 0;
        }
        if self.used >= self.maximum_per_minute {
            return Err(format!(
                "coordinator main wake-rate limit of {} per minute reached",
                self.maximum_per_minute
            ));
        }
        self.used = self.used.saturating_add(1);
        Ok(())
    }
}

async fn wait_for_abort_signal(abort: Arc<AtomicBool>) {
    while !abort.load(Ordering::Acquire) {
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
}

impl AsyncWasmTaskHost for CoordinatorMainHost {
    fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
        Some(Arc::clone(&self.abort))
    }

    fn debug_control(&self) -> Option<Arc<WasmDebugControl>> {
        Some(Arc::clone(&self.debug))
    }

    fn start_task(
        &mut self,
        request: WasmHostTaskStartRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskHandle> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            request.validate()?;
            if self.abort.load(Ordering::Acquire) {
                return Err("coordinator main is stopping".to_owned());
            }
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
            let selected_environment = request
                .environment_id
                .as_deref()
                .map(|environment| {
                    self.environments.get(environment).cloned().ok_or_else(|| {
                        format!("bundle environment manifest has no environment `{environment}`")
                    })
                })
                .transpose()?;
            let environment = selected_environment
                .as_ref()
                .map(|environment| environment.requirements.clone());
            let environment_digest = selected_environment
                .as_ref()
                .map(|environment| environment.digest.clone());
            if let Some(environment) = &environment {
                required_capabilities.extend(environment.capabilities.iter().cloned());
            }
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
                    "one task invocation cannot require multiple distinct source snapshots"
                        .to_owned(),
                );
            }
            if self
                .handles
                .lock()
                .map_err(|_| "coordinator main handle registry is unavailable".to_owned())?
                .len()
                >= super::MAX_IN_FLIGHT_TASKS_PER_PROCESS
            {
                return Err(format!(
                    "coordinator main task-handle limit of {} reached",
                    super::MAX_IN_FLIGHT_TASKS_PER_PROCESS
                ));
            }
            let handle_id = self.next_handle_id;
            let task_instance =
                TaskInstanceId::new(format!("{}:child:{handle_id}", self.scope.task_instance));
            let mut source_snapshot = source_snapshots.into_iter().next();
            let source_revision = if let Some(snapshot) = &source_snapshot {
                self.source_revision
                    .clone()
                    .filter(|revision| &revision.source_snapshot == snapshot)
            } else if required_capabilities.contains(&Capability::SourceFilesystem) {
                self.source_revision.clone()
            } else {
                None
            };
            if source_snapshot.is_none() {
                source_snapshot = source_revision
                    .as_ref()
                    .map(|revision| revision.source_snapshot.clone());
            }
            if source_snapshot.is_none()
                && required_capabilities.contains(&Capability::SourceFilesystem)
            {
                source_snapshot = self.source_snapshot.clone();
            }
            let task_spec = TaskSpec {
                tenant: self.scope.tenant.clone(),
                project: self.scope.project.clone(),
                process: self.scope.process.clone(),
                task_definition: request.task_definition,
                task_instance,
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
                vfs_epoch: self.scope.epoch,
                failure_policy: request.failure_policy,
                bundle_digest: Some(self.bundle_digest.clone()),
            };
            let (response, receiver) = oneshot::channel();
            self.sender
                .send(MainCommand::StartTask {
                    scope: self.scope.clone(),
                    handle_id,
                    task_spec: Box::new(task_spec.clone()),
                    wasm_module_base64: self.wasm_module_base64.clone(),
                    response,
                })
                .await
                .map_err(|_| "coordinator main command channel closed".to_owned())?;
            let handle = receiver
                .await
                .map_err(|_| "coordinator main task-start response channel closed".to_owned())??;
            self.handles
                .lock()
                .map_err(|_| "coordinator main handle registry is unavailable".to_owned())?
                .insert(handle_id, task_spec);
            self.next_handle_id = self.next_handle_id.saturating_add(1);
            Ok(handle)
        })
    }

    fn join_task(
        &mut self,
        request: WasmHostTaskJoinRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskJoinResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            let task_spec = self
                .handles
                .lock()
                .map_err(|_| "coordinator main handle registry is unavailable".to_owned())?
                .get(&request.handle_id)
                .cloned()
                .ok_or_else(|| format!("unknown Wasm task handle {}", request.handle_id))?;
            let (response, receiver) = oneshot::channel();
            let task_instance = task_spec.task_instance.clone();
            self.sender
                .send(MainCommand::JoinTask {
                    scope: self.scope.clone(),
                    task_instance: task_instance.clone(),
                    response,
                })
                .await
                .map_err(|_| "coordinator main command channel closed".to_owned())?;
            let joined = tokio::select! {
                joined = receiver => joined.map_err(|_| {
                    "coordinator main task-join response channel closed".to_owned()
                })?,
                () = tokio::time::sleep(self.nested_join_timeout) => {
                    return Err(clusterflux_core::limits::TaskJoinError::timeout(
                        task_instance.clone(),
                        self.nested_join_timeout,
                    )
                    .to_string());
                }
                () = wait_for_abort_signal(Arc::clone(&self.abort)) => {
                    return Err(clusterflux_core::limits::TaskJoinError::Cancelled {
                        task: task_instance.clone(),
                    }
                    .to_string());
                }
            };
            self.handles
                .lock()
                .map_err(|_| "coordinator main handle registry is unavailable".to_owned())?
                .remove(&request.handle_id);
            joined
        })
    }

    fn run_command(
        &mut self,
        _request: WasmHostCommandRequest,
    ) -> WasmHostFuture<'_, WasmHostCommandResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            Err("coordinator main is capless and cannot run native commands".to_owned())
        })
    }

    fn poll_task_control(
        &mut self,
        request: WasmHostTaskControlRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskControlResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            request.validate()?;
            Ok(WasmHostTaskControlResult {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                cancellation_requested: self.abort.load(Ordering::Acquire),
            })
        })
    }

    fn debug_probe(
        &mut self,
        request: WasmHostDebugProbeRequest,
    ) -> WasmHostFuture<'_, WasmHostDebugProbeResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            request.validate()?;
            self.debug
                .record_source_location(request.source_location.clone());
            let (response, receiver) = oneshot::channel();
            self.sender
                .send(MainCommand::DebugProbe {
                    scope: self.scope.clone(),
                    request,
                    response,
                })
                .await
                .map_err(|_| "coordinator main command channel closed".to_owned())?;
            receiver
                .await
                .map_err(|_| "coordinator main debug-probe response channel closed".to_owned())?
        })
    }

    fn vfs_operation(
        &mut self,
        request: WasmHostVfsRequest,
    ) -> WasmHostFuture<'_, WasmHostVfsResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            request.validate()?;
            let WasmHostVfsOperation::ReleaseArtifact { artifact } = request.operation else {
                return Err(
                    "coordinator main is capless and cannot access task VFS files".to_owned(),
                );
            };
            let (response, receiver) = oneshot::channel();
            self.sender
                .send(MainCommand::ReleaseArtifact {
                    scope: self.scope.clone(),
                    artifact: artifact.clone(),
                    response,
                })
                .await
                .map_err(|_| "coordinator main artifact-release channel closed".to_owned())?;
            receiver.await.map_err(|_| {
                "coordinator main artifact-release response channel closed".to_owned()
            })??;
            Ok(WasmHostVfsResult {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                artifact,
                relative_path: String::new(),
            })
        })
    }

    fn snapshot_source(
        &mut self,
        _request: WasmHostSourceSnapshotRequest,
    ) -> WasmHostFuture<'_, WasmHostSourceSnapshotResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            Err("coordinator main is capless and cannot access source checkouts".to_owned())
        })
    }

    fn trigger_context(
        &mut self,
        request: WasmHostTriggerContextRequest,
    ) -> WasmHostFuture<'_, WasmHostTriggerContextResult> {
        Box::pin(async move {
            self.wake_rate.charge()?;
            request.validate()?;
            let context = self
                .trigger_context
                .clone()
                .ok_or_else(|| "this Wasm invocation has no forge trigger context".to_owned())?;
            Ok(WasmHostTriggerContextResult {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                context,
            })
        })
    }
}

impl CoordinatorService {
    #[allow(clippy::too_many_arguments)]
    pub(super) fn handle_launch_coordinator_main(
        &mut self,
        tenant: String,
        project: String,
        actor_user: Option<String>,
        actor_agent: Option<String>,
        agent_public_key_fingerprint: Option<Digest>,
        agent_signature: Option<clusterflux_core::AgentSignedRequest>,
        request_payload_digest: Option<&Digest>,
        task_spec: TaskSpec,
        wasm_module_base64: String,
    ) -> Result<CoordinatorResponse, CoordinatorServiceError> {
        let tenant = TenantId::new(tenant);
        let project = ProjectId::new(project);
        let process = task_spec.process.clone();
        let task_instance = task_spec.task_instance.clone();
        let actor = self.workflow_actor(
            &tenant,
            &project,
            actor_user,
            actor_agent,
            agent_public_key_fingerprint,
            agent_signature,
            request_payload_digest,
            "launch_task",
            &process,
            Some(&task_instance),
        )?;
        let process_key = process_control_key(&tenant, &project, &process);
        let had_main = self.main_runtime.controls.contains_key(&process_key);
        let result = (|| {
            let active = self
                .coordinator
                .active_process(&tenant, &project, &process)
                .ok_or_else(|| {
                    CoordinatorError::Unauthorized(
                        "coordinator main launch requires an active virtual process".to_owned(),
                    )
                })?;
            debug_assert_eq!(active.tenant, tenant);
            debug_assert_eq!(active.project, project);
            self.main_runtime
                .ensure_launch_capacity(&process_key, &process)?;
            if task_spec.tenant != tenant || task_spec.project != project {
                return Err(CoordinatorError::Unauthorized(
                    "coordinator main TaskSpec is outside the authenticated scope".to_owned(),
                )
                .into());
            }
            if task_spec.vfs_epoch != active.coordinator_epoch {
                return Err(CoordinatorError::Unauthorized(format!(
                    "coordinator main TaskSpec VFS epoch {} does not match active process epoch {}",
                    task_spec.vfs_epoch, active.coordinator_epoch
                ))
                .into());
            }
            let export = match &task_spec.dispatch {
                TaskDispatch::CoordinatorNodeWasm {
                    export: Some(export),
                    abi: WasmExportAbi::EntrypointV1,
                } => export.clone(),
                _ => {
                    return Err(CoordinatorServiceError::Protocol(
                        "coordinator main requires an explicit EntrypointV1 Wasm export".to_owned(),
                    ))
                }
            };
            if task_spec.environment_id.is_some()
                || task_spec.environment.is_some()
                || task_spec.environment_digest.is_some()
                || !task_spec.required_capabilities.is_empty()
                || task_spec.dependency_cache.is_some()
                || !task_spec.required_artifacts.is_empty()
                || !task_spec.args.is_empty()
            {
                return Err(CoordinatorError::Unauthorized(
                "coordinator main must be capless and may not receive environment, artifact, cache, or argument authority"
                    .to_owned(),
            )
            .into());
            }
            let bundle_digest = task_spec.bundle_digest.clone().ok_or_else(|| {
                CoordinatorServiceError::Protocol(
                    "coordinator main TaskSpec omitted bundle digest".to_owned(),
                )
            })?;
            let module = BASE64_STANDARD
                .decode(&wasm_module_base64)
                .map_err(|error| {
                    CoordinatorServiceError::Protocol(format!(
                        "coordinator main module is not valid base64: {error}"
                    ))
                })?;
            let actual_digest = Digest::sha256(&module);
            if actual_digest != bundle_digest {
                return Err(CoordinatorError::Unauthorized(format!(
                "coordinator main module digest mismatch: expected {bundle_digest}, actual {actual_digest}"
            ))
            .into());
            }
            WasmTaskInvocation::new(
                task_spec.task_definition.clone(),
                task_instance.clone(),
                Vec::new(),
            )
            .validate()
            .map_err(CoordinatorServiceError::Protocol)?;
            let descriptors = task_descriptors(&module)?;
            let mut environments = bundle_environments(&module)?;
            environments
                .extend(self.automated_environment_definitions(&tenant, &project, &process));
            let trigger_context = self.automated_trigger_context(&tenant, &project, &process);
            let automated_source_revision =
                self.automated_source_revision(&tenant, &project, &process);
            if task_spec.source_revision.is_some()
                && automated_source_revision.is_some()
                && task_spec.source_revision != automated_source_revision
            {
                return Err(CoordinatorError::Unauthorized(
                    "coordinator main source revision does not match the automated run".to_owned(),
                )
                .into());
            }
            let source_revision = task_spec
                .source_revision
                .clone()
                .or(automated_source_revision);
            let source_snapshot = task_spec.source_snapshot.clone().or_else(|| {
                source_revision
                    .as_ref()
                    .map(|revision| revision.source_snapshot.clone())
            });
            let scope = MainScope {
                tenant: tenant.clone(),
                project: project.clone(),
                process: process.clone(),
                task_definition: task_spec.task_definition.clone(),
                task_instance: task_instance.clone(),
                epoch: task_spec.vfs_epoch,
                launch_id: 0,
            };
            self.main_runtime.launch(
                scope,
                export,
                module,
                wasm_module_base64,
                bundle_digest,
                descriptors,
                environments,
                trigger_context,
                source_snapshot,
                source_revision,
            )?;
            Ok(CoordinatorResponse::MainLaunched {
                process: process.clone(),
                task_definition: task_spec.task_definition,
                task_instance,
                actor,
                state: "running".to_owned(),
            })
        })();
        if result.is_err() && !had_main {
            self.main_runtime.interrupt_process(
                &tenant,
                &project,
                &process,
                "coordinator main launch failed admission or validation",
            );
            self.record_process_terminal(
                &tenant,
                &project,
                &process,
                super::ProcessFinalResult::Failed,
                self.liveness_now_epoch_seconds(),
            );
            let _ = self.coordinator.abort_process(&tenant, &project, &process);
        }
        result
    }

    pub(super) fn pump_main_runtime_commands(&mut self) {
        let commands = self.main_runtime.drain_commands();
        for command in commands {
            match command {
                MainCommand::StartTask {
                    scope,
                    handle_id,
                    task_spec,
                    wasm_module_base64,
                    response,
                } => {
                    let task_spec = *task_spec;
                    if !self.main_runtime.is_current_scope(&scope) {
                        let _ = response.send(Err(
                            "coordinator main process incarnation was replaced".to_owned(),
                        ));
                        continue;
                    }
                    let actor = WorkflowActor {
                        kind: "task".to_owned(),
                        user: None,
                        agent: None,
                        credential_kind: CredentialKind::TaskCredential,
                        public_key_fingerprint: None,
                        authenticated_without_browser: true,
                        scopes: vec!["process:spawn-child".to_owned()],
                    };
                    let result = self
                        .handle_launch_task_with_actor(
                            scope.tenant,
                            scope.project,
                            actor,
                            task_spec.clone(),
                            true,
                            format!("/vfs/artifacts/{}-result.json", task_spec.task_instance),
                            wasm_module_base64,
                        )
                        .and_then(|launch| match launch {
                            CoordinatorResponse::TaskLaunched { .. }
                            | CoordinatorResponse::TaskQueued { .. } => Ok(WasmHostTaskHandle {
                                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                                handle_id,
                                task_spec,
                            }),
                            other => Err(CoordinatorServiceError::Protocol(format!(
                                "unexpected coordinator-main child launch response: {other:?}"
                            ))),
                        })
                        .map_err(|error| error.to_string());
                    let _ = response.send(result);
                }
                MainCommand::JoinTask {
                    scope,
                    task_instance,
                    response,
                } => {
                    if !self.main_runtime.is_current_scope(&scope) {
                        let _ = response.send(Err(
                            "coordinator main process incarnation was replaced".to_owned(),
                        ));
                        continue;
                    }
                    let join = self.task_join_result(
                        scope.tenant.clone(),
                        scope.project.clone(),
                        scope.process.clone(),
                        task_instance.clone(),
                    );
                    match join.state {
                        TaskJoinState::Completed => {
                            let result = join
                                .result
                                .ok_or_else(|| {
                                    "completed child task omitted its boundary result".to_owned()
                                })
                                .map(|result| WasmHostTaskJoinResult {
                                    abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                                    task_instance,
                                    result,
                                });
                            let _ = response.send(result);
                        }
                        TaskJoinState::Failed | TaskJoinState::Cancelled => {
                            let _ = response.send(Err(join.message));
                        }
                        TaskJoinState::Pending => {
                            self.main_runtime
                                .join_waiters
                                .entry(task_restart_key(
                                    &scope.tenant,
                                    &scope.project,
                                    &scope.process,
                                    &task_instance,
                                ))
                                .or_default()
                                .push(response);
                        }
                    }
                }
                MainCommand::DebugProbe {
                    scope,
                    request,
                    response,
                } => {
                    if !self.main_runtime.is_current_scope(&scope) {
                        let _ = response.send(Err(
                            "coordinator main process incarnation was replaced".to_owned(),
                        ));
                        continue;
                    }
                    let result = self
                        .handle_coordinator_main_debug_probe(
                            scope.tenant,
                            scope.project,
                            scope.process,
                            scope.task_instance,
                            request.symbol,
                        )
                        .map_err(|error| error.to_string());
                    let _ = response.send(result);
                }
                MainCommand::ReleaseArtifact {
                    scope,
                    artifact,
                    response,
                } => {
                    if !self.main_runtime.is_current_scope(&scope) {
                        let _ = response.send(Err(
                            "coordinator main process incarnation was replaced".to_owned(),
                        ));
                        continue;
                    }
                    let result = self
                        .handle_coordinator_main_release_artifact(
                            scope.tenant,
                            scope.project,
                            scope.process,
                            artifact,
                        )
                        .map(|_| ())
                        .map_err(|error| error.to_string());
                    let _ = response.send(result);
                }
                MainCommand::Finished { scope, result } => {
                    if !self.main_runtime.is_current_scope(&scope) {
                        continue;
                    }
                    self.record_coordinator_main_completion(scope, result);
                }
            }
        }
    }

    pub(super) fn notify_coordinator_main_waiters(&mut self, event: &TaskCompletionEvent) {
        let key = task_restart_key(&event.tenant, &event.project, &event.process, &event.task);
        let Some(waiters) = self.main_runtime.join_waiters.remove(&key) else {
            return;
        };
        let result = match event.terminal_state {
            TaskTerminalState::Completed => event
                .result
                .clone()
                .ok_or_else(|| "completed child task omitted its boundary result".to_owned())
                .map(|result| WasmHostTaskJoinResult {
                    abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                    task_instance: event.task.clone(),
                    result,
                }),
            TaskTerminalState::Failed | TaskTerminalState::Cancelled => {
                Err(event.stderr_tail.clone())
            }
        };
        for waiter in waiters {
            let _ = waiter.send(result.clone());
        }
    }

    pub(super) fn record_coordinator_main_completion(
        &mut self,
        scope: MainScope,
        result: Result<WasmTaskResult, String>,
    ) {
        let max_state_bytes = self.main_runtime.max_state_bytes;
        let max_output_bytes = self.main_runtime.max_output_bytes;
        let result = result.and_then(|result| {
            result
                .validate_for(&scope.task_instance)
                .map_err(|error| error.to_string())?;
            if result.error.as_ref().is_some_and(|error| error.len() > max_output_bytes) {
                return Err(format!(
                    "coordinator main error output exceeds the configured {max_output_bytes}-byte limit"
                ));
            }
            if result.result.as_ref().is_some_and(|value| {
                serde_json::to_vec(value)
                    .map(|encoded| encoded.len() > max_state_bytes)
                    .unwrap_or(true)
            }) {
                return Err(format!(
                    "coordinator main result state exceeds the configured {max_state_bytes}-byte limit"
                ));
            }
            Ok(result)
        });
        let (terminal_state, boundary, error) = match result {
            Ok(result) if result.outcome == WasmTaskOutcome::Completed => {
                (TaskTerminalState::Completed, result.result, String::new())
            }
            Ok(result) => (
                TaskTerminalState::Failed,
                None,
                result
                    .error
                    .unwrap_or_else(|| "coordinator main failed without an error".to_owned()),
            ),
            Err(error) => (TaskTerminalState::Failed, None, error),
        };
        if matches!(terminal_state, TaskTerminalState::Completed) {
            self.record_automated_publication_boundary(
                &scope.tenant,
                &scope.project,
                &scope.process,
                boundary.as_ref(),
            );
        }
        let main_completed = matches!(terminal_state, TaskTerminalState::Completed);
        let main_state = match terminal_state {
            TaskTerminalState::Completed => "completed",
            TaskTerminalState::Failed => "failed",
            TaskTerminalState::Cancelled => "cancelled",
        };
        let event = TaskCompletionEvent {
            tenant: scope.tenant.clone(),
            project: scope.project.clone(),
            process: scope.process.clone(),
            node: NodeId::from("coordinator-main"),
            executor: TaskExecutor::CoordinatorMain,
            task_definition: scope.task_definition,
            task: scope.task_instance,
            attempt_id: None,
            placement: None,
            terminal_state,
            status_code: if error.is_empty() { Some(0) } else { None },
            stdout_bytes: 0,
            stderr_bytes: error.len() as u64,
            stdout_tail: String::new(),
            stderr_tail: error,
            stdout_truncated: false,
            stderr_truncated: false,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: boundary,
        };
        self.record_task_completion_event(event);
        if let Some(control) = self.main_runtime.controls.get_mut(&process_control_key(
            &scope.tenant,
            &scope.project,
            &scope.process,
        )) {
            control.state = main_state.to_owned();
            control.stopped_probe_symbol = None;
            if let Ok(mut handles) = control.handles.lock() {
                handles.clear();
            }
        }
        let process_key = process_control_key(&scope.tenant, &scope.project, &scope.process);
        self.main_runtime.controls.remove(&process_key);
        if main_completed {
            let _ =
                self.maybe_retire_terminal_process(&scope.tenant, &scope.project, &scope.process);
            return;
        }
        self.task_registry
            .request_abort_for_process(&scope.tenant, &scope.project, &scope.process);
        self.process_registry.request_abort(process_key.clone());
        self.record_process_terminal(
            &scope.tenant,
            &scope.project,
            &scope.process,
            super::ProcessFinalResult::Failed,
            self.liveness_now_epoch_seconds(),
        );
        let _ = self
            .coordinator
            .abort_process(&scope.tenant, &scope.project, &scope.process);
        self.clear_debug_state_for_process(&scope.tenant, &scope.project, &scope.process);
        self.clear_operator_panel_state(&scope.tenant, &scope.project, &scope.process);
    }
}

pub(super) fn task_descriptors(
    module: &[u8],
) -> Result<HashMap<String, serde_json::Value>, CoordinatorServiceError> {
    let mut descriptors = HashMap::new();
    for payload in Parser::new(0).parse_all(module) {
        let Payload::CustomSection(section) = payload.map_err(|error| {
            CoordinatorServiceError::Protocol(format!("parse coordinator main bundle: {error}"))
        })?
        else {
            continue;
        };
        if section.name() != "clusterflux.tasks" {
            continue;
        }
        for record in section
            .data()
            .split(|byte| *byte == b'\n' || *byte == 0)
            .filter(|record| !record.is_empty())
        {
            let descriptor: serde_json::Value = serde_json::from_slice(record)?;
            let name = descriptor
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or_else(|| {
                    CoordinatorServiceError::Protocol("task descriptor omitted its name".to_owned())
                })?
                .to_owned();
            descriptors.insert(name, descriptor);
        }
    }
    Ok(descriptors)
}

pub(super) fn bundle_environments(
    module: &[u8],
) -> Result<BTreeMap<String, EnvironmentResource>, CoordinatorServiceError> {
    for payload in Parser::new(0).parse_all(module) {
        let Payload::CustomSection(section) = payload.map_err(|error| {
            CoordinatorServiceError::Protocol(format!(
                "parse coordinator main environment manifest: {error}"
            ))
        })?
        else {
            continue;
        };
        if section.name() != "clusterflux.environments" {
            continue;
        }
        let environments: Vec<EnvironmentResource> = serde_json::from_slice(section.data())
            .map_err(|error| {
                CoordinatorServiceError::Protocol(format!(
                    "bundle environment manifest is invalid: {error}"
                ))
            })?;
        let mut by_name = BTreeMap::new();
        for environment in environments {
            if by_name
                .insert(environment.name.clone(), environment)
                .is_some()
            {
                return Err(CoordinatorServiceError::Protocol(
                    "bundle environment manifest contains duplicate names".to_owned(),
                ));
            }
        }
        return Ok(by_name);
    }
    Ok(BTreeMap::new())
}

pub(super) fn capability_from_descriptor(capability: &str) -> Result<Capability, String> {
    match capability.to_ascii_lowercase().as_str() {
        "command" => Ok(Capability::Command),
        "rootless_podman" => Ok(Capability::RootlessPodman),
        "containerd_nerdctl" => Ok(Capability::ContainerdNerdctl),
        "source_git" => Ok(Capability::SourceGit),
        "source_filesystem" => Ok(Capability::SourceFilesystem),
        "network" => Ok(Capability::Network),
        "host_filesystem" => Ok(Capability::HostFilesystem),
        "secrets" => Ok(Capability::Secrets),
        "inbound_ports" => Ok(Capability::InboundPorts),
        "arbitrary_syscalls" => Ok(Capability::ArbitrarySyscalls),
        "vfs_artifacts" => Ok(Capability::VfsArtifacts),
        "windows_command_dev" => Ok(Capability::WindowsCommandDev),
        "artifact_transfer" => Ok(Capability::ArtifactTransfer),
        "workflow_compiler" | "workflow.compile" => Err(
            "workflow compilation is a release-owned system task, not a user capability".to_owned(),
        ),
        other => Err(format!("unknown task capability `{other}`")),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::keys::task_control_key;

    fn test_main_host(scope: MainScope, sender: mpsc::Sender<MainCommand>) -> CoordinatorMainHost {
        CoordinatorMainHost {
            scope,
            sender,
            abort: Arc::new(AtomicBool::new(false)),
            debug: Arc::new(WasmDebugControl::default()),
            task_descriptors: HashMap::new(),
            environments: BTreeMap::new(),
            trigger_context: None,
            source_snapshot: None,
            source_revision: None,
            bundle_digest: Digest::sha256("coordinator-main-test-bundle"),
            wasm_module_base64: String::new(),
            next_handle_id: 1,
            handles: Arc::new(Mutex::new(HashMap::new())),
            nested_join_timeout: Duration::from_secs(1),
            wake_rate: GuestWakeRate::new(100),
        }
    }

    #[test]
    fn source_less_child_has_no_source_authority_or_placement_constraint() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (sender, mut receiver) = mpsc::channel(1);
            let scope = MainScope {
                tenant: TenantId::from("tenant"),
                project: ProjectId::from("project"),
                process: ProcessId::from("vp-source-bound"),
                task_definition: TaskDefinitionId::from("main"),
                task_instance: TaskInstanceId::from("ti:vp-source-bound:main"),
                epoch: 7,
                launch_id: 1,
            };
            let process_source = Digest::sha256("process working tree");
            let mut host = test_main_host(scope, sender);
            host.source_snapshot = Some(process_source.clone());
            host.task_descriptors.insert(
                "source-less".to_owned(),
                serde_json::json!({
                    "export": "clusterflux_task_v1_source_less",
                    "required_capabilities": []
                }),
            );
            let request = WasmHostTaskStartRequest {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                task_definition: TaskDefinitionId::from("source-less"),
                environment_id: None,
                args: Vec::new(),
                requested_secrets: Vec::new(),
                failure_policy: clusterflux_core::TaskFailurePolicy::default(),
            };

            let (started, captured) = tokio::join!(host.start_task(request), async {
                let MainCommand::StartTask {
                    handle_id,
                    task_spec,
                    response,
                    ..
                } = receiver.recv().await.expect("task-start command")
                else {
                    panic!("expected task-start command");
                };
                let task_spec = *task_spec;
                response
                    .send(Ok(WasmHostTaskHandle {
                        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                        handle_id,
                        task_spec: task_spec.clone(),
                    }))
                    .expect("task-start response accepted");
                task_spec
            });

            let started = started.expect("source-less child should start");
            assert_eq!(captured.source_snapshot, None);
            assert_eq!(started.task_spec.source_snapshot, None);
            assert!(captured.source_revision.is_none());
            assert!(!captured
                .required_capabilities
                .contains(&Capability::SourceFilesystem));
            captured
                .validate_boundary_authority()
                .expect("placement identity must not become source authority");

            assert_eq!(
                CoordinatorService::task_placement_source_snapshot(&captured),
                None
            );
        });
    }

    #[test]
    fn source_backed_child_inherits_process_source_authority() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (sender, mut receiver) = mpsc::channel(1);
            let scope = MainScope {
                tenant: TenantId::from("tenant"),
                project: ProjectId::from("project"),
                process: ProcessId::from("vp-source-backed"),
                task_definition: TaskDefinitionId::from("main"),
                task_instance: TaskInstanceId::from("ti:vp-source-backed:main"),
                epoch: 7,
                launch_id: 1,
            };
            let process_source = Digest::sha256("process working tree");
            let mut host = test_main_host(scope, sender);
            host.source_snapshot = Some(process_source.clone());
            host.task_descriptors.insert(
                "source-backed".to_owned(),
                serde_json::json!({
                    "export": "clusterflux_task_v1_source_backed",
                    "required_capabilities": ["source_filesystem"]
                }),
            );
            let request = WasmHostTaskStartRequest {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                task_definition: TaskDefinitionId::from("source-backed"),
                environment_id: None,
                args: Vec::new(),
                requested_secrets: Vec::new(),
                failure_policy: clusterflux_core::TaskFailurePolicy::default(),
            };

            let (started, captured) = tokio::join!(host.start_task(request), async {
                let MainCommand::StartTask {
                    handle_id,
                    task_spec,
                    response,
                    ..
                } = receiver.recv().await.expect("task-start command")
                else {
                    panic!("expected task-start command");
                };
                let task_spec = *task_spec;
                response
                    .send(Ok(WasmHostTaskHandle {
                        abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                        handle_id,
                        task_spec: task_spec.clone(),
                    }))
                    .expect("task-start response accepted");
                task_spec
            });

            let started = started.expect("source-backed child should start");
            assert_eq!(captured.source_snapshot, Some(process_source.clone()));
            assert_eq!(
                started.task_spec.source_snapshot,
                Some(process_source.clone())
            );
            assert!(captured.source_revision.is_none());
            assert!(captured
                .required_capabilities
                .contains(&Capability::SourceFilesystem));
            assert_eq!(
                CoordinatorService::task_placement_source_snapshot(&captured),
                Some(process_source.clone())
            );
            captured
                .validate_boundary_authority()
                .expect("source-backed task should carry process source authority");
        });
    }

    #[test]
    fn coordinator_main_artifact_release_is_capless_metadata_control() {
        let mut service = CoordinatorService::new(6);
        service.set_server_time(100);
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("vp-release");
        let main_task = TaskInstanceId::from("ti:vp-release:main");
        let scope = MainScope {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task_definition: TaskDefinitionId::from("main"),
            task_instance: main_task.clone(),
            epoch: 6,
            launch_id: 1,
        };
        service
            .coordinator
            .start_process(tenant.clone(), project.clone(), process.clone());
        service.main_runtime.controls.insert(
            process_control_key(&tenant, &project, &process),
            CoordinatorMainControl {
                task_definition: scope.task_definition.clone(),
                task_instance: main_task,
                abort: Arc::new(AtomicBool::new(false)),
                debug: Arc::new(WasmDebugControl::default()),
                state: "running".to_owned(),
                stopped_probe_symbol: None,
                handles: Arc::new(Mutex::new(HashMap::new())),
                launch_id: 1,
            },
        );
        let artifact = ArtifactHandle {
            id: clusterflux_core::ArtifactId::from("main-release-artifact"),
            digest: Digest::sha256("main release bytes"),
            size_bytes: 18,
        };
        service
            .artifact_registry
            .flush_metadata(clusterflux_core::ArtifactFlush {
                id: artifact.id.clone(),
                tenant: tenant.clone(),
                project: project.clone(),
                process: process.clone(),
                producer_task: TaskInstanceId::from("producer"),
                retaining_node: NodeId::from("worker"),
                digest: artifact.digest.clone(),
                size: artifact.size_bytes,
            });

        let mut host = test_main_host(scope.clone(), service.main_runtime.sender.clone());
        let release = artifact.clone();
        let worker = std::thread::spawn(move || {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
                .block_on(host.vfs_operation(WasmHostVfsRequest {
                    abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                    operation: WasmHostVfsOperation::ReleaseArtifact { artifact: release },
                }))
        });
        let deadline = Instant::now() + Duration::from_secs(2);
        while !worker.is_finished() && Instant::now() < deadline {
            service.pump_main_runtime_commands();
            std::thread::yield_now();
        }
        let released = worker
            .join()
            .expect("coordinator main release thread should finish")
            .expect("capless coordinator main release should succeed");
        assert_eq!(released.artifact, artifact);
        assert!(service
            .artifact_registry
            .holds(&tenant, &project, &artifact.id)
            .is_empty());

        let mut capless_host = test_main_host(scope, service.main_runtime.sender.clone());
        let materialize = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(capless_host.vfs_operation(WasmHostVfsRequest {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                operation: WasmHostVfsOperation::MaterializeArtifact {
                    artifact,
                    relative_path: "not-allowed".to_owned(),
                },
            }));
        assert!(materialize
            .unwrap_err()
            .contains("cannot access task VFS files"));
    }

    #[test]
    fn completed_main_releases_process_slot_and_debug_state() {
        let mut service = CoordinatorService::new(7);
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("vp-current");
        let main_task = TaskInstanceId::from("ti:vp-current:main");
        let scope = MainScope {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task_definition: TaskDefinitionId::from("build"),
            task_instance: main_task.clone(),
            epoch: 7,
            launch_id: 1,
        };
        service
            .coordinator
            .start_process(tenant.clone(), project.clone(), process.clone());
        let process_key = process_control_key(&tenant, &project, &process);
        service.main_runtime.controls.insert(
            process_key.clone(),
            CoordinatorMainControl {
                task_definition: scope.task_definition.clone(),
                task_instance: main_task.clone(),
                abort: Arc::new(AtomicBool::new(false)),
                debug: Arc::new(WasmDebugControl::default()),
                state: "running".to_owned(),
                stopped_probe_symbol: None,
                handles: Arc::new(Mutex::new(HashMap::new())),
                launch_id: 1,
            },
        );
        service.debug_registry.set_epoch(process_key.clone(), 2);
        service.debug_registry.set_runtime(
            process_key.clone(),
            super::super::debug::DebugEpochRuntime {
                epoch: 2,
                command: "resume".to_owned(),
                expected: BTreeSet::new(),
                acknowledgements: BTreeMap::new(),
                deadline: std::time::Instant::now(),
            },
        );

        service.record_coordinator_main_completion(
            scope,
            Ok(WasmTaskResult::completed(
                main_task,
                TaskBoundaryValue::SmallJson(serde_json::Value::Null),
            )),
        );

        assert!(service
            .coordinator
            .active_process(&tenant, &project, &process)
            .is_none());
        let CoordinatorResponse::ProcessStatuses { processes, .. } = service
            .handle_list_processes(
                tenant.as_str().to_owned(),
                project.as_str().to_owned(),
                "user".to_owned(),
            )
            .unwrap()
        else {
            panic!("expected process statuses");
        };
        assert!(processes.is_empty());
        assert!(!service.main_runtime.controls.contains_key(&process_key));
        assert!(!service.debug_registry.contains_epoch(&process_key));
        assert!(service.debug_registry.runtime(&process_key).is_none());
        assert!(!service.process_registry.is_aborted(&process_key));
    }

    #[test]
    fn completed_main_keeps_process_and_debug_state_for_active_children() {
        let mut service = CoordinatorService::new(7);
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("vp-current");
        let main_task = TaskInstanceId::from("ti:vp-current:main");
        let child_task = TaskInstanceId::from("ti:vp-current:child:1");
        let child_node = NodeId::from("worker");
        let scope = MainScope {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task_definition: TaskDefinitionId::from("build"),
            task_instance: main_task.clone(),
            epoch: 7,
            launch_id: 1,
        };
        service
            .coordinator
            .start_process(tenant.clone(), project.clone(), process.clone());
        let process_key = process_control_key(&tenant, &project, &process);
        service.main_runtime.controls.insert(
            process_key.clone(),
            CoordinatorMainControl {
                task_definition: scope.task_definition.clone(),
                task_instance: main_task.clone(),
                abort: Arc::new(AtomicBool::new(false)),
                debug: Arc::new(WasmDebugControl::default()),
                state: "running".to_owned(),
                stopped_probe_symbol: None,
                handles: Arc::new(Mutex::new(HashMap::new())),
                launch_id: 1,
            },
        );
        let child_key = task_control_key(&tenant, &project, &process, &child_node, &child_task);
        service.task_registry.activate(child_key.clone());
        service.debug_registry.set_epoch(process_key.clone(), 2);

        service.record_coordinator_main_completion(
            scope,
            Ok(WasmTaskResult::completed(
                main_task,
                TaskBoundaryValue::SmallJson(serde_json::Value::Null),
            )),
        );

        assert!(service
            .coordinator
            .active_process(&tenant, &project, &process)
            .is_some());
        assert!(!service.main_runtime.controls.contains_key(&process_key));
        assert!(service.debug_registry.contains_epoch(&process_key));
        assert!(!service.process_registry.is_aborted(&process_key));
        assert!(service.task_registry.is_active(&child_key));
        assert!(!service.task_registry.is_aborted(&child_key));
    }

    #[test]
    fn failed_main_aborts_unfinished_children_and_clears_process_debug_state() {
        let mut service = CoordinatorService::new(7);
        let tenant = TenantId::from("tenant");
        let project = ProjectId::from("project");
        let process = ProcessId::from("vp-failed-main");
        let main_task = TaskInstanceId::from("ti:vp-failed-main:main");
        let child_task = TaskInstanceId::from("ti:vp-failed-main:child:1");
        let child_node = NodeId::from("worker");
        let scope = MainScope {
            tenant: tenant.clone(),
            project: project.clone(),
            process: process.clone(),
            task_definition: TaskDefinitionId::from("build"),
            task_instance: main_task.clone(),
            epoch: 7,
            launch_id: 1,
        };
        service
            .coordinator
            .start_process(tenant.clone(), project.clone(), process.clone());
        let process_key = process_control_key(&tenant, &project, &process);
        service.main_runtime.controls.insert(
            process_key.clone(),
            CoordinatorMainControl {
                task_definition: scope.task_definition.clone(),
                task_instance: main_task,
                abort: Arc::new(AtomicBool::new(false)),
                debug: Arc::new(WasmDebugControl::default()),
                state: "running".to_owned(),
                stopped_probe_symbol: None,
                handles: Arc::new(Mutex::new(HashMap::new())),
                launch_id: 1,
            },
        );
        let child_key = task_control_key(&tenant, &project, &process, &child_node, &child_task);
        service.task_registry.activate(child_key.clone());
        service.debug_registry.set_epoch(process_key.clone(), 2);

        service.record_coordinator_main_completion(scope, Err("main crashed".to_owned()));

        assert!(service
            .coordinator
            .active_process(&tenant, &project, &process)
            .is_none());
        assert!(service.task_registry.is_active(&child_key));
        assert!(service.task_registry.is_aborted(&child_key));
        assert!(service.process_registry.is_aborted(&process_key));
        assert!(!service.debug_registry.contains_epoch(&process_key));
        assert!(service.task_registry.events().any(|event| {
            event.process == process
                && event.executor == TaskExecutor::CoordinatorMain
                && event.terminal_state == TaskTerminalState::Failed
        }));
    }
}
