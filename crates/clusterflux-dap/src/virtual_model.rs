use std::collections::{BTreeMap, BTreeSet};
use std::path::Path;

use anyhow::{anyhow, Result};
use clusterflux_core::{
    BundleDebugProbe, DebugRuntimeState, Digest, ProcessId, ProjectId, SourceLocation,
    TaskDefinitionId, TaskInstanceId, TenantId, UserId,
};
use serde_json::Value;

use crate::demo_backend::{launch_threads, LINUX_THREAD, MAIN_THREAD};

#[derive(Clone)]
pub(crate) struct VirtualThread {
    pub(crate) id: i64,
    pub(crate) frame_id: i64,
    pub(crate) locals_ref: i64,
    pub(crate) wasm_locals_ref: i64,
    pub(crate) args_ref: i64,
    pub(crate) runtime_ref: i64,
    pub(crate) output_ref: i64,
    pub(crate) target_ref: i64,
    pub(crate) vfs_ref: i64,
    pub(crate) command_ref: i64,
    pub(crate) task: TaskInstanceId,
    pub(crate) attempt_id: String,
    pub(crate) task_definition: TaskDefinitionId,
    pub(crate) name: String,
    pub(crate) line: i64,
    pub(crate) state: DebugRuntimeState,
    pub(crate) freeze_supported: bool,
    pub(crate) recent_output: Vec<String>,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
    pub(crate) stdout_tail: String,
    pub(crate) stderr_tail: String,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) runtime_stack_frames: Vec<String>,
    pub(crate) current_source_location: Option<SourceLocation>,
    pub(crate) wasm_local_values: Vec<(String, String)>,
    pub(crate) runtime_task_args: Vec<(String, String)>,
    pub(crate) runtime_handles: Vec<(String, String)>,
    pub(crate) runtime_command_status: Option<String>,
    pub(crate) runtime_node: Option<String>,
    pub(crate) runtime_environment: Option<String>,
    pub(crate) runtime_vfs_checkpoint: Option<String>,
    pub(crate) restart_compatible: Option<bool>,
}

#[derive(Clone)]
pub(crate) struct AdapterState {
    pub(crate) process: ProcessId,
    pub(crate) epoch: u64,
    pub(crate) entry: String,
    pub(crate) requested_entrypoint: Option<String>,
    pub(crate) project: String,
    pub(crate) source_path: String,
    pub(crate) runtime_backend: RuntimeBackend,
    pub(crate) coordinator_endpoint: String,
    pub(crate) tenant: TenantId,
    pub(crate) project_id: ProjectId,
    pub(crate) actor_user: UserId,
    pub(crate) client_session_secret: Option<String>,
    pub(crate) session_mode: DapSessionMode,
    pub(crate) restart_existing: bool,
    pub(crate) command_status: String,
    pub(crate) last_task_failed: bool,
    pub(crate) runtime_artifact_path: Option<String>,
    pub(crate) runtime_event_count: usize,
    pub(crate) runtime_snapshot_fingerprint: String,
    pub(crate) next_thread_id: i64,
    pub(crate) coordinator_debug_epoch: Option<u64>,
    pub(crate) debug_all_threads_stopped: bool,
    pub(crate) stopped_task: Option<TaskInstanceId>,
    pub(crate) stopped_probe_symbol: Option<String>,
    pub(crate) debug_probes: Vec<BundleDebugProbe>,
    pub(crate) breakpoints_by_source: BTreeMap<String, Vec<SourceLocation>>,
    pub(crate) stopped_location: Option<SourceLocation>,
    pub(crate) source_mismatch: Option<String>,
    pub(crate) source_inventory: BTreeSet<String>,
    pub(crate) breakpoints_installed: bool,
    pub(crate) breakpoint_revision: u64,
    pub(crate) threads: BTreeMap<i64, VirtualThread>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum RuntimeBackend {
    Simulated,
    LocalServices,
    LiveServices,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) enum DapSessionMode {
    Launch,
    Attach,
}

impl RuntimeBackend {
    pub(crate) fn description(&self) -> &'static str {
        match self {
            RuntimeBackend::Simulated => "simulated debug adapter state",
            RuntimeBackend::LocalServices => "local services",
            RuntimeBackend::LiveServices => "live services",
        }
    }
}

impl Default for AdapterState {
    fn default() -> Self {
        let entry = String::new();
        let project = ".".to_owned();
        Self {
            process: process_id(&project, &entry),
            epoch: 0,
            threads: launch_threads(&entry),
            entry,
            requested_entrypoint: None,
            project,
            source_path: "src/lib.rs".to_owned(),
            runtime_backend: RuntimeBackend::Simulated,
            coordinator_endpoint: "https://clusterflux.lesstuff.com".to_owned(),
            tenant: TenantId::from("tenant"),
            project_id: ProjectId::from("project"),
            actor_user: UserId::from("dap"),
            client_session_secret: None,
            session_mode: DapSessionMode::Launch,
            restart_existing: false,
            command_status: "waiting for launch".to_owned(),
            last_task_failed: false,
            runtime_artifact_path: None,
            runtime_event_count: 0,
            runtime_snapshot_fingerprint: String::new(),
            next_thread_id: LINUX_THREAD,
            coordinator_debug_epoch: None,
            debug_all_threads_stopped: true,
            stopped_task: None,
            stopped_probe_symbol: None,
            debug_probes: Vec::new(),
            breakpoints_by_source: BTreeMap::new(),
            stopped_location: None,
            source_mismatch: None,
            source_inventory: BTreeSet::from(["src/lib.rs".to_owned()]),
            breakpoints_installed: false,
            breakpoint_revision: 0,
        }
    }
}

impl AdapterState {
    pub(crate) fn requested_probe_symbols(&self) -> Vec<String> {
        let mut symbols = self
            .breakpoints_by_source
            .values()
            .flatten()
            .map(|location| location.probe_id.clone())
            .collect::<Vec<_>>();
        symbols.sort();
        symbols.dedup();
        symbols
    }

    pub(crate) fn breakpoint_locations(&self) -> impl Iterator<Item = &SourceLocation> {
        self.breakpoints_by_source.values().flatten()
    }

    pub(crate) fn has_breakpoints(&self) -> bool {
        self.breakpoints_by_source
            .values()
            .any(|locations| !locations.is_empty())
    }

    pub(crate) fn configure_launch(
        &mut self,
        project: String,
        requested_entrypoint: Option<String>,
        runtime_backend: RuntimeBackend,
        coordinator_endpoint: Option<String>,
        source_path: Option<String>,
    ) -> Result<()> {
        self.entry = requested_entrypoint.clone().unwrap_or_default();
        self.requested_entrypoint = requested_entrypoint;
        self.process = process_id(&project, &self.entry);
        self.source_path =
            source_path.unwrap_or_else(|| crate::source::infer_source_path(&project));
        self.project = project;
        self.runtime_backend = runtime_backend;
        if self.runtime_backend == RuntimeBackend::LiveServices {
            let project_scope = load_project_scope(&self.project);
            let session = load_client_session(&self.project).ok_or_else(|| {
                anyhow!(
                    "no authenticated CLI session was found for this workspace; run `clusterflux login --browser` from {}",
                    self.project
                )
            })?;
            if let Some(configured) = project_scope.as_ref() {
                let mismatches = scope_mismatches(configured, &session);
                if !mismatches.is_empty() {
                    return Err(anyhow!(
                        "the stored CLI session does not match this workspace ({mismatches}); run `clusterflux login --browser` from {}",
                        self.project
                    ));
                }
            }
            if let Some(requested) = coordinator_endpoint.as_deref() {
                if crate::view_state::normalize_coordinator_endpoint(requested)
                    != crate::view_state::normalize_coordinator_endpoint(&session.coordinator)
                {
                    return Err(anyhow!(
                        "the debug coordinator does not match the authenticated CLI session coordinator"
                    ));
                }
            }
            self.coordinator_endpoint =
                crate::view_state::normalize_coordinator_endpoint(&session.coordinator);
            self.tenant = TenantId::try_new(session.tenant)
                .map_err(|error| anyhow!("invalid tenant in CLI session: {error}"))?;
            self.project_id = ProjectId::try_new(session.project)
                .map_err(|error| anyhow!("invalid project in CLI session: {error}"))?;
            self.actor_user = UserId::try_new(session.user)
                .map_err(|error| anyhow!("invalid user in CLI session: {error}"))?;
            self.client_session_secret = Some(session.session_secret);
        } else {
            self.coordinator_endpoint = crate::view_state::normalize_coordinator_endpoint(
                coordinator_endpoint.as_deref().unwrap_or("127.0.0.1:0"),
            );
            self.client_session_secret = None;
        }
        self.session_mode = DapSessionMode::Launch;
        self.restart_existing = false;
        self.command_status = "waiting for configurationDone".to_owned();
        self.last_task_failed = false;
        self.runtime_artifact_path = None;
        self.runtime_event_count = 0;
        self.runtime_snapshot_fingerprint.clear();
        self.next_thread_id = LINUX_THREAD;
        self.coordinator_debug_epoch = None;
        self.debug_all_threads_stopped = true;
        self.stopped_task = None;
        self.stopped_probe_symbol = None;
        self.stopped_location = None;
        self.source_mismatch = None;
        let (source_inventory, debug_probes) =
            crate::breakpoints::load_bundle_debug_model(&self.project, &self.source_path);
        self.source_inventory = source_inventory;
        self.debug_probes = debug_probes;
        self.epoch = 0;
        self.breakpoints_by_source.clear();
        self.breakpoints_installed = self.runtime_backend == RuntimeBackend::Simulated;
        self.breakpoint_revision = 0;
        self.threads = if self.runtime_backend == RuntimeBackend::Simulated {
            launch_threads(&self.entry)
        } else {
            BTreeMap::new()
        };
        Ok(())
    }

    pub(crate) fn apply_runtime_record(&mut self, record: RuntimeLaunchRecord) {
        self.coordinator_endpoint = record.coordinator.clone();
        if self.runtime_backend != RuntimeBackend::Simulated {
            if let Some(snapshots) = record.node_report.get("task_snapshots") {
                self.reconcile_runtime_threads(snapshots, record.node_report.get("process_status"));
            } else if record.node_report.get("terminal_event").is_some() {
                self.threads.clear();
            }
        }
        if let Some(fingerprint) = record
            .node_report
            .get("snapshot_fingerprint")
            .and_then(Value::as_str)
        {
            self.runtime_snapshot_fingerprint = fingerprint.to_owned();
        }
        if !record.placed_task_launched {
            self.command_status = format!(
                "virtual process started through {}; no runtime task event observed yet",
                self.runtime_backend.description()
            );
            self.last_task_failed = false;
            self.runtime_artifact_path = None;
            self.runtime_event_count = record.event_count;
            if let Some(thread) = self.threads.get_mut(&MAIN_THREAD) {
                thread.recent_output.push(format!(
                    "coordinator-side process started through {}",
                    self.runtime_backend.description()
                ));
                thread
                    .recent_output
                    .push("an attached worker will be required when the process reaches work that must be placed on a node".to_owned());
            }
            let _ = crate::view_state::write_view_state(self, &record);
            return;
        }

        let task_failed = record.status_code.is_some_and(|status| status != 0);
        let debug_details = record
            .node_report
            .get("debug_epoch")
            .and_then(|status| {
                let count = |field: &str| {
                    status.get(field).and_then(|value| {
                        value.as_array().map(Vec::len).or_else(|| {
                            value.as_u64().and_then(|value| usize::try_from(value).ok())
                        })
                    })
                };
                let expected = count("expected_tasks")?;
                let acknowledged = count("acknowledgements")?;
                let failures = status
                    .get("failure_messages")
                    .and_then(Value::as_array)
                    .map(|messages| {
                        messages
                            .iter()
                            .filter_map(Value::as_str)
                            .collect::<Vec<_>>()
                            .join("; ")
                    })
                    .unwrap_or_default();
                Some(if failures.is_empty() {
                    format!(" after {acknowledged}/{expected} participant acknowledgements")
                } else {
                    format!(
                        " after {acknowledged}/{expected} participant acknowledgements ({failures})"
                    )
                })
            })
            .unwrap_or_default();
        self.command_status = if record.debug_epoch.is_some() {
            format!(
                "{} through {} at executing Wasm probe {} with debug epoch {}{}",
                if record.all_participants_frozen {
                    "fully frozen"
                } else {
                    "partially frozen"
                },
                self.runtime_backend.description(),
                record.stopped_probe_symbol.as_deref().unwrap_or("unknown"),
                record.debug_epoch.unwrap_or_default(),
                debug_details
            )
        } else if let Some(status) = record.status_code {
            format!(
                "{} through {} with status {status}",
                if task_failed { "failed" } else { "completed" },
                self.runtime_backend.description()
            )
        } else {
            format!("running through {}", self.runtime_backend.description())
        };
        self.last_task_failed = task_failed;
        self.runtime_artifact_path = record.artifact_path.clone();
        self.runtime_event_count = record.event_count;
        self.stopped_task = record
            .stopped_task
            .as_deref()
            .and_then(|task| TaskInstanceId::try_new(task).ok());
        self.stopped_probe_symbol = record.stopped_probe_symbol.clone();
        self.stopped_location = record.stopped_location.clone();
        self.source_mismatch = record.source_mismatch.clone();
        if record.debug_epoch.is_some() {
            self.debug_all_threads_stopped = record.all_participants_frozen;
            self.epoch = record.debug_epoch.unwrap_or(self.epoch);
            self.coordinator_debug_epoch = record.debug_epoch;
            if let Some(acknowledgements) = record
                .node_report
                .pointer("/debug_epoch/acknowledgements")
                .and_then(Value::as_array)
            {
                for acknowledgement in acknowledgements {
                    let Some(task) = acknowledgement.get("task").and_then(Value::as_str) else {
                        continue;
                    };
                    let Some(task_definition) = acknowledgement
                        .get("task_definition")
                        .and_then(Value::as_str)
                    else {
                        continue;
                    };
                    let Ok(task_id) = TaskInstanceId::try_new(task) else {
                        continue;
                    };
                    let Ok(task_definition_id) = TaskDefinitionId::try_new(task_definition) else {
                        continue;
                    };
                    let coordinator_main = acknowledgement.get("node").and_then(Value::as_str)
                        == Some("coordinator-main");
                    let thread_id = if coordinator_main {
                        MAIN_THREAD
                    } else {
                        self.threads
                            .values()
                            .find(|thread| thread.task.as_str() == task)
                            .map(|thread| thread.id)
                            .unwrap_or_else(|| {
                                self.insert_runtime_thread(
                                    task_id.clone(),
                                    task_definition_id.clone(),
                                )
                            })
                    };
                    let thread = self
                        .threads
                        .get_mut(&thread_id)
                        .expect("runtime thread was found or inserted");
                    thread.task = task_id;
                    thread.task_definition = task_definition_id;
                    thread.runtime_stack_frames = acknowledgement
                        .get("stack_frames")
                        .and_then(Value::as_array)
                        .into_iter()
                        .flatten()
                        .filter_map(Value::as_str)
                        .map(str::to_owned)
                        .collect();
                    thread.current_source_location = acknowledgement
                        .get("current_source_location")
                        .cloned()
                        .and_then(|location| serde_json::from_value(location).ok());
                    if let Some(location) = &thread.current_source_location {
                        thread.line = i64::from(location.line);
                    }
                    thread.wasm_local_values =
                        value_string_pairs(acknowledgement.get("local_values"));
                    thread.runtime_task_args = value_string_pairs(acknowledgement.get("task_args"));
                    thread.runtime_handles = value_string_pairs(acknowledgement.get("handles"));
                    thread.runtime_command_status = acknowledgement
                        .get("command_status")
                        .and_then(Value::as_str)
                        .map(str::to_owned);
                    thread.state = match acknowledgement.get("state").and_then(Value::as_str) {
                        Some("frozen") => DebugRuntimeState::Frozen,
                        Some("failed") => DebugRuntimeState::Failed(
                            acknowledgement
                                .get("message")
                                .and_then(Value::as_str)
                                .unwrap_or("participant failed to freeze")
                                .to_owned(),
                        ),
                        _ => thread.state.clone(),
                    };
                }
            }
            if let Some(thread) = self.threads.get_mut(&MAIN_THREAD) {
                thread.recent_output.push(format!(
                    "executing task {} reported the breakpoint hit",
                    record.stopped_task.as_deref().unwrap_or("unknown")
                ));
            }
        }
        if let Some(terminal_event) = record.node_report.get("terminal_event") {
            let terminal_task = terminal_event
                .get("task")
                .and_then(Value::as_str)
                .unwrap_or(self.entry.as_str())
                .to_owned();
            let terminal_thread_id = self
                .threads
                .values()
                .find(|thread| thread.task.as_str() == terminal_task.as_str())
                .map(|thread| thread.id);
            if let Some(thread) = terminal_thread_id.and_then(|id| self.threads.get_mut(&id)) {
                thread.stdout_bytes = record.stdout_bytes;
                thread.stderr_bytes = record.stderr_bytes;
                thread.stdout_tail = record.stdout_tail.clone();
                thread.stderr_tail = record.stderr_tail.clone();
                thread.stdout_truncated = record.stdout_truncated;
                thread.stderr_truncated = record.stderr_truncated;
                thread.recent_output.push(format!(
                    "{} task {} with {} stdout bytes and {} stderr bytes",
                    terminal_event
                        .get("executor")
                        .and_then(Value::as_str)
                        .unwrap_or("runtime"),
                    if task_failed { "failed" } else { "completed" },
                    record.stdout_bytes,
                    record.stderr_bytes
                ));
                thread.recent_output.push(format!(
                    "coordinator recorded {} task event(s)",
                    record.event_count
                ));
                thread.state = if task_failed {
                    DebugRuntimeState::Failed(format!(
                        "local services task exited with status {:?}",
                        record.status_code
                    ))
                } else {
                    DebugRuntimeState::Completed
                };
            }
        }
        let _ = crate::view_state::write_view_state(self, &record);
    }

    fn insert_runtime_thread(
        &mut self,
        task: TaskInstanceId,
        task_definition: TaskDefinitionId,
    ) -> i64 {
        let id = self.allocate_runtime_thread_id();
        let line = self
            .debug_probes
            .iter()
            .find(|probe| {
                probe.task == task_definition || probe.function == task_definition.as_str()
            })
            .map(|probe| i64::from(probe.line_start))
            .unwrap_or(1);
        let definition_name = task_definition.as_str().replace(['_', '-'], " ");
        let name = if task.as_str() == task_definition.as_str() {
            definition_name
        } else {
            format!("{definition_name} ({task})")
        };
        self.threads.insert(
            id,
            VirtualThread {
                id,
                frame_id: 1000 + id,
                locals_ref: 5000 + id,
                wasm_locals_ref: 9000 + id,
                args_ref: 2000 + id,
                runtime_ref: 3000 + id,
                output_ref: 4000 + id,
                target_ref: 6000 + id,
                vfs_ref: 7000 + id,
                command_ref: 8000 + id,
                task,
                attempt_id: "unknown-attempt".to_owned(),
                task_definition,
                name,
                line,
                state: DebugRuntimeState::Running,
                freeze_supported: true,
                recent_output: vec!["runtime participant reported by the node".to_owned()],
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                runtime_stack_frames: Vec::new(),
                current_source_location: None,
                wasm_local_values: Vec::new(),
                runtime_task_args: Vec::new(),
                runtime_handles: Vec::new(),
                runtime_command_status: None,
                runtime_node: None,
                runtime_environment: None,
                runtime_vfs_checkpoint: None,
                restart_compatible: None,
            },
        );
        id
    }

    fn allocate_runtime_thread_id(&mut self) -> i64 {
        while self.threads.contains_key(&self.next_thread_id) || self.next_thread_id == MAIN_THREAD
        {
            self.next_thread_id += 1;
        }
        let id = self.next_thread_id;
        self.next_thread_id += 1;
        id
    }

    fn reconcile_runtime_threads(
        &mut self,
        task_snapshots: &Value,
        process_status: Option<&Value>,
    ) {
        let desired =
            coordinator_threads_from_snapshots(&self.entry, task_snapshots, process_status);
        let previous = std::mem::take(&mut self.threads);
        let mut reconciled = BTreeMap::new();
        for (_, mut thread) in desired {
            let coordinator_main = process_status
                .and_then(|status| status.get("main_task_instance"))
                .and_then(Value::as_str)
                .is_some_and(|task| task == thread.task.as_str());
            let existing = if coordinator_main {
                previous.get(&MAIN_THREAD)
            } else {
                previous
                    .values()
                    .find(|current| current.task == thread.task)
            };
            if let Some(existing) = existing {
                preserve_thread_identity(&mut thread, existing);
            } else if !coordinator_main {
                thread.id = self.allocate_runtime_thread_id();
                assign_thread_references(&mut thread);
            } else {
                thread.id = MAIN_THREAD;
                assign_thread_references(&mut thread);
            }
            reconciled.insert(thread.id, thread);
        }
        self.threads = reconciled;
    }

    pub(crate) fn apply_attach_record(&mut self, record: RuntimeLaunchRecord) {
        self.coordinator_endpoint = record.coordinator.clone();
        self.command_status = format!(
            "attached to existing virtual process through {}; coordinator task event(s): {}",
            self.runtime_backend.description(),
            record.event_count
        );
        self.last_task_failed = false;
        self.runtime_artifact_path = None;
        self.runtime_event_count = record.event_count;
        self.reconcile_runtime_threads(
            record
                .node_report
                .get("task_snapshots")
                .unwrap_or(&Value::Null),
            record.node_report.get("process_status"),
        );
        if let Some(thread) = self.threads.get_mut(&MAIN_THREAD) {
            thread.recent_output.push(format!(
                "attached to existing virtual process through {}",
                self.runtime_backend.description()
            ));
            thread.recent_output.push(format!(
                "coordinator returned {} task event(s) for this process",
                record.event_count
            ));
        }
        let _ = crate::view_state::write_view_state(self, &record);
    }
}

fn preserve_thread_identity(thread: &mut VirtualThread, existing: &VirtualThread) {
    thread.id = existing.id;
    thread.frame_id = existing.frame_id;
    thread.locals_ref = existing.locals_ref;
    thread.wasm_locals_ref = existing.wasm_locals_ref;
    thread.args_ref = existing.args_ref;
    thread.runtime_ref = existing.runtime_ref;
    thread.output_ref = existing.output_ref;
    thread.target_ref = existing.target_ref;
    thread.vfs_ref = existing.vfs_ref;
    thread.command_ref = existing.command_ref;
    if thread.recent_output.is_empty() {
        thread.recent_output = existing.recent_output.clone();
    }
}

fn assign_thread_references(thread: &mut VirtualThread) {
    let id = thread.id;
    thread.frame_id = 1000 + id;
    thread.locals_ref = 5000 + id;
    thread.wasm_locals_ref = 9000 + id;
    thread.args_ref = 2000 + id;
    thread.runtime_ref = 3000 + id;
    thread.output_ref = 4000 + id;
    thread.target_ref = 6000 + id;
    thread.vfs_ref = 7000 + id;
    thread.command_ref = 8000 + id;
}

fn value_string_pairs(value: Option<&Value>) -> Vec<(String, String)> {
    value
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(|pair| {
            let pair = pair.as_array()?;
            Some((
                pair.first()?.as_str()?.to_owned(),
                pair.get(1)?.as_str()?.to_owned(),
            ))
        })
        .collect()
}

#[derive(Clone, Debug)]
struct ProjectScope {
    coordinator: Option<String>,
    tenant: String,
    project: String,
    user: String,
}

#[derive(Clone, Debug)]
struct ClientSession {
    coordinator: String,
    tenant: String,
    project: String,
    user: String,
    session_secret: String,
}

fn load_project_scope(project: &str) -> Option<ProjectScope> {
    for ancestor in Path::new(project).ancestors() {
        let file = ancestor.join(".clusterflux-state/project.json");
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let Ok(config) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        return Some(ProjectScope {
            coordinator: config
                .get("coordinator")
                .and_then(Value::as_str)
                .map(str::to_owned),
            tenant: config.get("tenant")?.as_str()?.to_owned(),
            project: config.get("project")?.as_str()?.to_owned(),
            user: config.get("user")?.as_str()?.to_owned(),
        });
    }
    None
}

fn load_client_session(project: &str) -> Option<ClientSession> {
    for ancestor in Path::new(project).ancestors() {
        let file = ancestor.join(".clusterflux-state/session.json");
        let Ok(bytes) = std::fs::read(file) else {
            continue;
        };
        let Ok(session) = serde_json::from_slice::<Value>(&bytes) else {
            continue;
        };
        let secret = session
            .get("session_secret")
            .and_then(Value::as_str)
            .filter(|secret| !secret.trim().is_empty())?;
        return Some(ClientSession {
            coordinator: session.get("coordinator")?.as_str()?.to_owned(),
            tenant: session.get("tenant")?.as_str()?.to_owned(),
            project: session.get("project")?.as_str()?.to_owned(),
            user: session.get("user")?.as_str()?.to_owned(),
            session_secret: secret.to_owned(),
        });
    }
    None
}

fn scope_mismatches(project: &ProjectScope, session: &ClientSession) -> String {
    let mut fields = Vec::new();
    if project.coordinator.as_deref().is_some_and(|coordinator| {
        crate::view_state::normalize_coordinator_endpoint(coordinator)
            != crate::view_state::normalize_coordinator_endpoint(&session.coordinator)
    }) {
        fields.push("coordinator");
    }
    if project.tenant != session.tenant {
        fields.push("tenant");
    }
    if project.project != session.project {
        fields.push("project");
    }
    if project.user != session.user {
        fields.push("user");
    }
    fields.join(", ")
}

#[derive(Clone, Debug)]
pub(crate) struct RuntimeLaunchRecord {
    pub(crate) coordinator: String,
    pub(crate) node: String,
    pub(crate) node_report: Value,
    pub(crate) task_events: Value,
    pub(crate) placed_task_launched: bool,
    pub(crate) status_code: Option<i32>,
    pub(crate) stdout_bytes: u64,
    pub(crate) stderr_bytes: u64,
    pub(crate) stdout_tail: String,
    pub(crate) stderr_tail: String,
    pub(crate) stdout_truncated: bool,
    pub(crate) stderr_truncated: bool,
    pub(crate) artifact_path: Option<String>,
    pub(crate) event_count: usize,
    pub(crate) debug_epoch: Option<u64>,
    pub(crate) stopped_task: Option<String>,
    pub(crate) stopped_probe_symbol: Option<String>,
    pub(crate) stopped_location: Option<SourceLocation>,
    pub(crate) source_mismatch: Option<String>,
    pub(crate) all_participants_frozen: bool,
}

pub(crate) fn process_id(project: &str, entry: &str) -> ProcessId {
    let digest = Digest::from_parts([
        b"dap-process:v1".as_slice(),
        project.as_bytes(),
        entry.as_bytes(),
    ]);
    let suffix = digest
        .as_str()
        .trim_start_matches("sha256:")
        .chars()
        .take(12)
        .collect::<String>();
    ProcessId::new(format!("vp-{suffix}"))
}

fn coordinator_main_thread(
    entry: &str,
    task: TaskInstanceId,
    task_definition: TaskDefinitionId,
) -> VirtualThread {
    let name = format!("{entry} coordinator main ({task})");
    VirtualThread {
        id: MAIN_THREAD,
        frame_id: 1_001,
        locals_ref: 2_001,
        wasm_locals_ref: 2_501,
        args_ref: 3_001,
        runtime_ref: 3_501,
        output_ref: 4_001,
        target_ref: 4_501,
        vfs_ref: 5_001,
        command_ref: 5_501,
        task,
        attempt_id: "main:unknown".to_owned(),
        task_definition,
        name,
        line: 0,
        state: DebugRuntimeState::Running,
        freeze_supported: true,
        recent_output: Vec::new(),
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        runtime_stack_frames: Vec::new(),
        current_source_location: None,
        wasm_local_values: Vec::new(),
        runtime_task_args: Vec::new(),
        runtime_handles: Vec::new(),
        runtime_command_status: None,
        runtime_node: Some("coordinator-main".to_owned()),
        runtime_environment: None,
        runtime_vfs_checkpoint: None,
        restart_compatible: None,
    }
}

#[cfg(test)]
#[allow(dead_code)]
fn coordinator_threads_from_events(
    entry: &str,
    task_events: &Value,
    process_status: Option<&Value>,
) -> BTreeMap<i64, VirtualThread> {
    let mut threads = BTreeMap::new();
    let mut main = launch_threads(entry)
        .remove(&MAIN_THREAD)
        .expect("launch thread model should include main");
    if let Some(status) = process_status {
        if let Some(task) = status.get("main_task_instance").and_then(Value::as_str) {
            if let Ok(task) = TaskInstanceId::try_new(task) {
                main.task = task;
            }
        }
        if let Some(definition) = status.get("main_task_definition").and_then(Value::as_str) {
            if let Ok(definition) = TaskDefinitionId::try_new(definition) {
                main.task_definition = definition;
            }
        }
        main.name = format!("{entry} coordinator main ({})", main.task);
        main.state = if status
            .get("main_debug_epoch")
            .and_then(Value::as_u64)
            .is_some()
        {
            DebugRuntimeState::Frozen
        } else {
            DebugRuntimeState::Running
        };
        main.recent_output = vec![format!(
            "coordinator reports main state {}",
            status
                .get("main_state")
                .and_then(Value::as_str)
                .unwrap_or("running")
        )];
    }
    threads.insert(MAIN_THREAD, main);

    let Some(events) = task_events.get("events").and_then(Value::as_array) else {
        return threads;
    };
    let mut next_worker_thread = LINUX_THREAD;
    for (index, event) in events.iter().enumerate() {
        let coordinator_main =
            event.get("executor").and_then(Value::as_str) == Some("coordinator_main");
        let id = if coordinator_main {
            MAIN_THREAD
        } else {
            let id = next_worker_thread;
            next_worker_thread += 1;
            id
        };
        let Some(mut thread) = coordinator_event_thread(id, index, event) else {
            continue;
        };
        if coordinator_main {
            thread.name = format!("{entry} coordinator main ({})", thread.task);
            thread.recent_output.push(
                "terminal state was recorded by the coordinator-hosted main runtime".to_owned(),
            );
        }
        threads.insert(id, thread);
    }
    threads
}

fn coordinator_threads_from_snapshots(
    entry: &str,
    task_snapshots: &Value,
    process_status: Option<&Value>,
) -> BTreeMap<i64, VirtualThread> {
    let mut threads = BTreeMap::new();
    if let Some(status) = process_status {
        if let Some(task) = status.get("main_task_instance").and_then(Value::as_str) {
            let task_definition = status
                .get("main_task_definition")
                .and_then(Value::as_str)
                .unwrap_or(entry);
            let (Ok(task), Ok(task_definition)) = (
                TaskInstanceId::try_new(task),
                TaskDefinitionId::try_new(task_definition),
            ) else {
                return threads;
            };
            let mut main = coordinator_main_thread(entry, task, task_definition);
            main.attempt_id = format!(
                "main:{}",
                status
                    .get("coordinator_epoch")
                    .and_then(Value::as_u64)
                    .unwrap_or_default()
            );
            main.line = 0;
            main.runtime_stack_frames.clear();
            main.state = if status
                .get("main_debug_epoch")
                .and_then(Value::as_u64)
                .is_some()
            {
                DebugRuntimeState::Frozen
            } else {
                DebugRuntimeState::Running
            };
            main.runtime_node = Some("coordinator-main".to_owned());
            main.runtime_environment = Some("coordinator-capless".to_owned());
            main.runtime_vfs_checkpoint = status
                .get("coordinator_epoch")
                .and_then(Value::as_u64)
                .map(|epoch| format!("vfs-epoch:{epoch}"));
            main.restart_compatible = Some(false);
            main.recent_output.clear();
            threads.insert(MAIN_THREAD, main);
        }
    }

    let Some(snapshots) = task_snapshots.get("snapshots").and_then(Value::as_array) else {
        return threads;
    };
    let mut next_id = if threads.contains_key(&MAIN_THREAD) {
        LINUX_THREAD
    } else {
        MAIN_THREAD
    };
    for snapshot in snapshots {
        if snapshot.get("current").and_then(Value::as_bool) != Some(true)
            || !matches!(
                snapshot.get("state").and_then(Value::as_str),
                Some("queued" | "running" | "failed_awaiting_action")
            )
        {
            continue;
        }
        let Some(task) = snapshot.get("task").and_then(Value::as_str) else {
            continue;
        };
        let Some(task_definition) = snapshot.get("task_definition").and_then(Value::as_str) else {
            continue;
        };
        let Ok(task_id) = TaskInstanceId::try_new(task) else {
            continue;
        };
        let Ok(task_definition_id) = TaskDefinitionId::try_new(task_definition) else {
            continue;
        };
        let attempt_id = snapshot
            .get("attempt_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-attempt")
            .to_owned();
        let state = match snapshot.get("state").and_then(Value::as_str) {
            Some("queued" | "running") => DebugRuntimeState::Running,
            Some("failed_awaiting_action") => {
                DebugRuntimeState::Failed("failed awaiting operator action".to_owned())
            }
            _ => continue,
        };
        let argument_summary = snapshot
            .get("argument_summary")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(index, value)| Some((format!("arg_{index}"), value.as_str()?.to_owned())))
            .collect();
        let handle_summary = snapshot
            .get("handle_summary")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
            .enumerate()
            .filter_map(|(index, value)| {
                Some((format!("handle_{index}"), value.as_str()?.to_owned()))
            })
            .collect();
        let display_name = snapshot
            .get("display_name")
            .and_then(Value::as_str)
            .unwrap_or(task_definition);
        let short_attempt = attempt_id.chars().take(16).collect::<String>();
        let id = next_id;
        next_id += 1;
        threads.insert(
            id,
            VirtualThread {
                id,
                frame_id: 1000 + id,
                locals_ref: 5000 + id,
                wasm_locals_ref: 9000 + id,
                args_ref: 2000 + id,
                runtime_ref: 3000 + id,
                output_ref: 4000 + id,
                target_ref: 6000 + id,
                vfs_ref: 7000 + id,
                command_ref: 8000 + id,
                task: task_id,
                attempt_id,
                task_definition: task_definition_id,
                name: format!("{display_name} ({task}, attempt {short_attempt})"),
                line: snapshot
                    .get("source_line")
                    .and_then(Value::as_i64)
                    .unwrap_or(0),
                state,
                freeze_supported: true,
                recent_output: Vec::new(),
                stdout_bytes: 0,
                stderr_bytes: 0,
                stdout_tail: String::new(),
                stderr_tail: String::new(),
                stdout_truncated: false,
                stderr_truncated: false,
                runtime_stack_frames: Vec::new(),
                current_source_location: None,
                wasm_local_values: Vec::new(),
                runtime_task_args: argument_summary,
                runtime_handles: handle_summary,
                runtime_command_status: snapshot
                    .get("command_state")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                runtime_node: snapshot
                    .get("node")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                runtime_environment: snapshot
                    .get("environment_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                runtime_vfs_checkpoint: snapshot
                    .get("vfs_checkpoint")
                    .and_then(Value::as_str)
                    .map(str::to_owned),
                restart_compatible: snapshot.get("restart_compatible").and_then(Value::as_bool),
            },
        );
    }
    threads
}

#[cfg(test)]
#[allow(dead_code)]
fn coordinator_event_thread(id: i64, _event_index: usize, event: &Value) -> Option<VirtualThread> {
    let task = event.get("task").and_then(Value::as_str)?;
    let task_definition = event.get("task_definition").and_then(Value::as_str)?;
    let task_id = TaskInstanceId::try_new(task).ok()?;
    let task_definition_id = TaskDefinitionId::try_new(task_definition).ok()?;
    let definition_name = task_definition.replace(['_', '-'], " ");
    let name = if task == task_definition {
        definition_name
    } else {
        format!("{definition_name} ({task})")
    };
    let stdout_tail = event
        .get("stdout_tail")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let stderr_tail = event
        .get("stderr_tail")
        .and_then(Value::as_str)
        .unwrap_or_default()
        .to_owned();
    let stdout_bytes = event
        .get("stdout_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let stderr_bytes = event
        .get("stderr_bytes")
        .and_then(Value::as_u64)
        .unwrap_or(0);
    let status_code = event.get("status_code").and_then(Value::as_i64);
    let state = match event.get("terminal_state").and_then(Value::as_str) {
        Some("completed") => DebugRuntimeState::Completed,
        Some("cancelled") => DebugRuntimeState::Failed(format!("task {task} was cancelled")),
        Some("failed") => DebugRuntimeState::Failed(format!("task {task} failed")),
        _ if status_code == Some(0) => DebugRuntimeState::Completed,
        _ => {
            DebugRuntimeState::Failed(format!("task {task} completed with status {status_code:?}"))
        }
    };
    Some(VirtualThread {
        id,
        frame_id: 1000 + id,
        locals_ref: 5000 + id,
        wasm_locals_ref: 9000 + id,
        args_ref: 2000 + id,
        runtime_ref: 3000 + id,
        output_ref: 4000 + id,
        target_ref: 6000 + id,
        vfs_ref: 7000 + id,
        command_ref: 8000 + id,
        task: task_id,
        attempt_id: event
            .get("attempt_id")
            .and_then(Value::as_str)
            .unwrap_or("unknown-attempt")
            .to_owned(),
        task_definition: task_definition_id,
        name,
        line: 0,
        state,
        freeze_supported: true,
        recent_output: vec![format!(
            "coordinator task event from {} {}",
            event
                .get("executor")
                .and_then(Value::as_str)
                .unwrap_or("node"),
            event
                .get("node")
                .and_then(Value::as_str)
                .unwrap_or("unknown")
        )],
        stdout_bytes,
        stderr_bytes,
        stdout_tail,
        stderr_tail,
        stdout_truncated: event
            .get("stdout_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        stderr_truncated: event
            .get("stderr_truncated")
            .and_then(Value::as_bool)
            .unwrap_or(false),
        runtime_stack_frames: Vec::new(),
        current_source_location: None,
        wasm_local_values: Vec::new(),
        runtime_task_args: Vec::new(),
        runtime_handles: Vec::new(),
        runtime_command_status: None,
        runtime_node: event.get("node").and_then(Value::as_str).map(str::to_owned),
        runtime_environment: None,
        runtime_vfs_checkpoint: None,
        restart_compatible: None,
    })
}
