use std::collections::BTreeMap;
use std::io::{self, BufReader};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{mpsc, Arc};
use std::thread;

use anyhow::Result;
use clusterflux_core::DebugRuntimeState;
use serde_json::{json, Value};

use crate::breakpoints::{
    freeze_all, freeze_all_at_location, next_breakpoint_after, position_confirmed_breakpoint_stop,
    request_thread, request_thread_id, resolve_breakpoints_for_source_locations,
    restart_requires_whole_process, simulated_freeze_failure_thread, step_thread,
    stopped_thread_for_breakpoint,
};
use crate::dap_protocol::{initialize_capabilities, read_message, DapWriter};
use crate::demo_backend::{
    is_explicit_demo_backend, start_simulated_backend, LINUX_THREAD, MAIN_THREAD,
};
use crate::runtime_client::{
    attach_services_runtime, create_debug_epoch, debug_epoch_runtime_record,
    observe_services_runtime, relaunch_services_main_runtime, restart_task, resume_debug_epoch,
    run_live_services_runtime, run_local_services_runtime, set_services_debug_breakpoints,
    wait_for_debug_epoch_frozen, wait_for_debug_epoch_resumed, LocalRuntimeSession,
    RuntimeContinuationOutcome,
};
use crate::variables::variables_response;
use crate::virtual_model::{AdapterState, DapSessionMode, RuntimeBackend, VirtualThread};

enum AdapterEvent {
    Request(Value),
    InputClosed,
    InputFailed(String),
    LaunchFinished {
        generation: u64,
        result: std::result::Result<LaunchCompletion, String>,
    },
    ObservationUpdate {
        generation: u64,
        outcome: RuntimeContinuationOutcome,
    },
    ObservationFinished {
        generation: u64,
    },
    PauseFinished {
        generation: u64,
        result: std::result::Result<AdapterState, String>,
    },
    ResumeFinished {
        generation: u64,
        request: Value,
        thread_id: i64,
        result: std::result::Result<AdapterState, String>,
    },
    BreakpointsUpdated {
        generation: u64,
        revision: u64,
        result: std::result::Result<(), String>,
    },
}

struct LaunchCompletion {
    state: AdapterState,
    local_runtime_session: Option<LocalRuntimeSession>,
    breakpoint_revision: u64,
    observation_diagnostics: Vec<String>,
}

pub(crate) fn run_adapter() -> Result<()> {
    let mut writer = DapWriter::new();
    let mut state = AdapterState::default();
    let mut _local_runtime_session = None;
    let mut runtime_started = false;
    let mut runtime_starting = false;
    let mut runtime_generation = 0_u64;
    let mut observation_cancel = None;
    let (event_tx, event_rx) = mpsc::channel();
    spawn_input_reader(event_tx.clone());

    while let Ok(event) = event_rx.recv() {
        let request = match event {
            AdapterEvent::Request(request) => request,
            AdapterEvent::InputClosed => {
                cancel_observation(&mut observation_cancel);
                break;
            }
            AdapterEvent::InputFailed(message) => {
                cancel_observation(&mut observation_cancel);
                return Err(anyhow::anyhow!(message));
            }
            AdapterEvent::LaunchFinished { generation, result } => {
                if generation != runtime_generation {
                    continue;
                }
                runtime_starting = false;
                match result {
                    Ok(mut completion) => {
                        let requested_breakpoints = state.breakpoints_by_source.clone();
                        let requested_revision = state.breakpoint_revision;
                        let installed_revision = completion.breakpoint_revision;
                        completion.state.breakpoints_by_source = requested_breakpoints;
                        completion.state.breakpoint_revision = requested_revision;
                        completion.state.breakpoints_installed =
                            completion.state.source_mismatch.is_none()
                                && installed_revision == requested_revision;
                        let previous_threads = state.threads.clone();
                        state = completion.state;
                        emit_thread_lifecycle(&mut writer, &previous_threads, &state.threads)?;
                        if let Some(session) = completion.local_runtime_session {
                            _local_runtime_session = Some(session);
                        }
                        for diagnostic in completion.observation_diagnostics {
                            writer.output("stderr", format!("{diagnostic}\n"))?;
                        }
                        runtime_started = true;
                        if let Some(mismatch) = state.source_mismatch.as_deref() {
                            emit_unverified_breakpoints(&mut writer, &state, mismatch)?;
                        } else if state.breakpoints_installed {
                            emit_verified_breakpoints(&mut writer, &state)?;
                        } else {
                            let breakpoint_state = state.clone();
                            let breakpoint_tx = event_tx.clone();
                            let revision = state.breakpoint_revision;
                            thread::spawn(move || {
                                let result = set_services_debug_breakpoints(&breakpoint_state)
                                    .map_err(|error| {
                                        format!("coordinator breakpoint update failed: {error:#}")
                                    });
                                let _ = breakpoint_tx.send(AdapterEvent::BreakpointsUpdated {
                                    generation,
                                    revision,
                                    result,
                                });
                            });
                        }
                        writer.output(
                            "console",
                            if state.session_mode == DapSessionMode::Attach {
                                format!(
                                    "Attached to Clusterflux virtual process {} with {:?} runtime\n",
                                    state.process, state.runtime_backend
                                )
                            } else {
                                format!(
                                    "Clusterflux bundle refreshed for entry `{}`; virtual process {} is running with {:?} runtime\n",
                                    state.entry, state.process, state.runtime_backend
                                )
                            },
                        )?;
                        spawn_runtime_observer(
                            &event_tx,
                            &state,
                            runtime_generation,
                            &mut observation_cancel,
                        );
                    }
                    Err(message) => {
                        runtime_started = false;
                        writer.output("stderr", format!("{message}\n"))?;
                        writer.event("terminated", json!({ "restart": false }))?;
                    }
                }
                continue;
            }
            AdapterEvent::ObservationUpdate {
                generation,
                outcome,
            } => {
                if generation != runtime_generation {
                    continue;
                }
                emit_runtime_outcome(&mut writer, &mut state, outcome)?;
                continue;
            }
            AdapterEvent::ObservationFinished { generation } => {
                if generation == runtime_generation {
                    observation_cancel = None;
                }
                continue;
            }
            AdapterEvent::PauseFinished { generation, result } => {
                if generation != runtime_generation {
                    continue;
                }
                match result {
                    Ok(paused_state) => {
                        state = paused_state;
                        let stopped_thread = default_thread_id(&state);
                        writer.event(
                            "stopped",
                            json!({
                                "reason": "pause",
                                "description": debug_epoch_stop_description(&state, "Clusterflux Debug Epoch pause"),
                                "threadId": stopped_thread,
                                "allThreadsStopped": state.debug_all_threads_stopped,
                            }),
                        )?;
                    }
                    Err(message) => {
                        writer.output("stderr", format!("{message}\n"))?;
                        spawn_runtime_observer(
                            &event_tx,
                            &state,
                            runtime_generation,
                            &mut observation_cancel,
                        );
                    }
                }
                continue;
            }
            AdapterEvent::ResumeFinished {
                generation,
                request,
                thread_id,
                result,
            } => {
                if generation != runtime_generation {
                    continue;
                }
                match result {
                    Ok(resumed_state) => {
                        state = resumed_state;
                        for thread in state.threads.values_mut() {
                            if thread.state == DebugRuntimeState::Frozen {
                                thread.state = DebugRuntimeState::Running;
                            }
                        }
                        writer.response(&request, true, json!({ "allThreadsContinued": true }))?;
                        writer.event(
                            "continued",
                            json!({
                                "threadId": thread_id,
                                "allThreadsContinued": true,
                            }),
                        )?;
                        spawn_runtime_observer(
                            &event_tx,
                            &state,
                            runtime_generation,
                            &mut observation_cancel,
                        );
                    }
                    Err(message) => {
                        writer.output("stderr", format!("{message}\n"))?;
                        writer.error_response(&request, message)?;
                        spawn_runtime_observer(
                            &event_tx,
                            &state,
                            runtime_generation,
                            &mut observation_cancel,
                        );
                    }
                }
                continue;
            }
            AdapterEvent::BreakpointsUpdated {
                generation,
                revision,
                result,
            } => {
                if breakpoint_update_is_current(
                    generation,
                    runtime_generation,
                    revision,
                    state.breakpoint_revision,
                ) {
                    match result {
                        Ok(()) => {
                            state.breakpoints_installed = true;
                            emit_verified_breakpoints(&mut writer, &state)?;
                        }
                        Err(message) => {
                            state.breakpoints_installed = false;
                            emit_unverified_breakpoints(&mut writer, &state, &message)?;
                            writer.output("stderr", format!("{message}\n"))?;
                        }
                    }
                }
                continue;
            }
        };
        let command = request
            .get("command")
            .and_then(Value::as_str)
            .unwrap_or_default();
        match command {
            "initialize" => writer.response(&request, true, initialize_capabilities())?,
            "launch" | "attach" => {
                let args = request
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                let requested_entrypoint =
                    args.get("entry").and_then(Value::as_str).map(str::to_owned);
                let project = args
                    .get("project")
                    .and_then(Value::as_str)
                    .unwrap_or(".")
                    .to_owned();
                let runtime_backend = match runtime_backend_from_launch_arg(
                    args.get("runtimeBackend").and_then(Value::as_str),
                ) {
                    Ok(runtime_backend) => runtime_backend,
                    Err(message) => {
                        writer.error_response(&request, message)?;
                        continue;
                    }
                };
                let coordinator_endpoint = args
                    .get("coordinatorEndpoint")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                let source_path = args
                    .get("sourcePath")
                    .and_then(Value::as_str)
                    .map(str::to_owned);
                if let Err(err) = state.configure_launch(
                    project,
                    requested_entrypoint,
                    runtime_backend,
                    coordinator_endpoint,
                    source_path,
                ) {
                    writer.error_response(&request, err.to_string())?;
                    continue;
                }
                cancel_observation(&mut observation_cancel);
                runtime_generation = runtime_generation.saturating_add(1);
                runtime_started = false;
                runtime_starting = false;
                _local_runtime_session = None;
                state.restart_existing = args
                    .get("restartExisting")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
                if let Some(process_id) = args.get("processId").and_then(Value::as_str) {
                    match clusterflux_core::ProcessId::try_new(process_id.to_owned()) {
                        Ok(process) => state.process = process,
                        Err(error) => {
                            writer.error_response(
                                &request,
                                format!("invalid DAP processId: {error}"),
                            )?;
                            continue;
                        }
                    }
                }
                if command == "attach" {
                    state.session_mode = DapSessionMode::Attach;
                    state.command_status =
                        format!("attached to existing virtual process {}", state.process);
                }
                writer.response(&request, true, json!({}))?;
                writer.event("initialized", json!({}))?;
            }
            "setBreakpoints" => {
                let requested_source_path = request
                    .get("arguments")
                    .and_then(|value| value.get("source"))
                    .and_then(|value| value.get("path"))
                    .and_then(Value::as_str);
                let requested_locations = request
                    .get("arguments")
                    .and_then(|value| value.get("breakpoints"))
                    .and_then(Value::as_array)
                    .map(|items| {
                        items
                            .iter()
                            .filter_map(|item| {
                                Some((
                                    item.get("line")?.as_i64()?,
                                    item.get("column").and_then(Value::as_i64),
                                ))
                            })
                            .collect::<Vec<_>>()
                    })
                    .unwrap_or_default();
                let resolved = resolve_breakpoints_for_source_locations(
                    &mut state,
                    requested_source_path,
                    requested_locations,
                );
                state.breakpoint_revision = state.breakpoint_revision.saturating_add(1);
                let breakpoint_revision = state.breakpoint_revision;
                let coordinator_backed = matches!(
                    state.runtime_backend,
                    RuntimeBackend::LocalServices | RuntimeBackend::LiveServices
                );
                state.breakpoints_installed = !coordinator_backed;
                let response = resolved
                    .iter()
                    .map(|breakpoint| {
                        let mut dap = breakpoint.to_dap();
                        if coordinator_backed && breakpoint.verified {
                            dap["verified"] = Value::Bool(false);
                            dap["message"] = Value::String(
                                "Pending coordinator breakpoint installation".to_owned(),
                            );
                        }
                        dap
                    })
                    .collect::<Vec<_>>();
                writer.response(&request, true, json!({ "breakpoints": response }))?;
                if runtime_started
                    && matches!(
                        state.runtime_backend,
                        RuntimeBackend::LocalServices | RuntimeBackend::LiveServices
                    )
                {
                    let breakpoint_state = state.clone();
                    let breakpoint_tx = event_tx.clone();
                    let generation = runtime_generation;
                    thread::spawn(move || {
                        let result =
                            set_services_debug_breakpoints(&breakpoint_state).map_err(|error| {
                                format!("coordinator breakpoint update failed: {error:#}")
                            });
                        let _ = breakpoint_tx.send(AdapterEvent::BreakpointsUpdated {
                            generation,
                            revision: breakpoint_revision,
                            result,
                        });
                    });
                }
            }
            "setExceptionBreakpoints" => {
                writer.response(&request, true, json!({ "breakpoints": [] }))?;
            }
            "configurationDone" => {
                if runtime_starting || runtime_started {
                    writer.error_response(
                        &request,
                        "the Clusterflux runtime has already been started for this DAP session",
                    )?;
                    continue;
                }
                writer.response(&request, true, json!({}))?;
                if state.runtime_backend == RuntimeBackend::Simulated {
                    if state.session_mode == DapSessionMode::Attach {
                        state.command_status =
                            format!("attached to existing virtual process {}", state.process);
                    } else {
                        start_simulated_backend(&mut state);
                    }
                    writer.output(
                        "console",
                        format!(
                            "Clusterflux explicit demo backend started virtual process {}\n",
                            state.process
                        ),
                    )?;
                    if state.has_breakpoints() {
                        let stopped_thread = stopped_thread_for_breakpoint(&state);
                        match freeze_all(&mut state, stopped_thread, None) {
                            Ok(()) => writer.event(
                                "stopped",
                                json!({
                                    "reason": "breakpoint",
                                    "description": "Clusterflux explicit demo all-stop",
                                    "threadId": stopped_thread,
                                    "allThreadsStopped": true,
                                }),
                            )?,
                            Err(failure) => {
                                writer.output("stderr", format!("{}\n", failure.message()))?
                            }
                        }
                    }
                    runtime_started = true;
                    continue;
                }

                runtime_starting = true;
                cancel_observation(&mut observation_cancel);
                runtime_generation = runtime_generation.saturating_add(1);
                let generation = runtime_generation;
                let launch_state = state.clone();
                let launch_tx = event_tx.clone();
                thread::spawn(move || {
                    let mut completed_state = launch_state;
                    let result = if completed_state.session_mode == DapSessionMode::Attach {
                        attach_services_runtime(&completed_state)
                            .and_then(|record| {
                                completed_state.apply_attach_record(record);
                                if completed_state.source_mismatch.is_none() {
                                    set_services_debug_breakpoints(&completed_state)?;
                                } else {
                                    completed_state.breakpoints_installed = false;
                                }
                                Ok(())
                            })
                            .map(|()| {
                                let breakpoint_revision = completed_state.breakpoint_revision;
                                let observation_diagnostics =
                                    completed_state.source_mismatch.iter().cloned().collect();
                                LaunchCompletion {
                                    state: completed_state,
                                    local_runtime_session: None,
                                    breakpoint_revision,
                                    observation_diagnostics,
                                }
                            })
                            .map_err(|error| format!("services runtime attach failed: {error:#}"))
                    } else {
                        match completed_state.runtime_backend.clone() {
                            RuntimeBackend::LocalServices => {
                                run_local_services_runtime(&mut completed_state)
                                    .map(|(record, session)| {
                                        let observation_diagnostics =
                                            runtime_observation_diagnostics(&record);
                                        completed_state.apply_runtime_record(record);
                                        let breakpoint_revision =
                                            completed_state.breakpoint_revision;
                                        LaunchCompletion {
                                            state: completed_state,
                                            local_runtime_session: Some(session),
                                            breakpoint_revision,
                                            observation_diagnostics,
                                        }
                                    })
                                    .map_err(|error| {
                                        format!("local services runtime launch failed: {error:#}")
                                    })
                            }
                            RuntimeBackend::LiveServices => {
                                run_live_services_runtime(&mut completed_state)
                                    .map(|record| {
                                        let observation_diagnostics =
                                            runtime_observation_diagnostics(&record);
                                        completed_state.apply_runtime_record(record);
                                        let breakpoint_revision =
                                            completed_state.breakpoint_revision;
                                        LaunchCompletion {
                                            state: completed_state,
                                            local_runtime_session: None,
                                            breakpoint_revision,
                                            observation_diagnostics,
                                        }
                                    })
                                    .map_err(|error| {
                                        format!("live services runtime launch failed: {error:#}")
                                    })
                            }
                            RuntimeBackend::Simulated => {
                                unreachable!("the explicit demo backend is handled synchronously")
                            }
                        }
                    };
                    let _ = launch_tx.send(AdapterEvent::LaunchFinished { generation, result });
                });
            }
            "threads" => {
                let threads = state
                    .threads
                    .values()
                    .map(|thread| {
                        json!({
                            "id": thread.id,
                            "name": format!("{}/{}", state.process, thread.name),
                        })
                    })
                    .collect::<Vec<_>>();
                writer.response(&request, true, json!({ "threads": threads }))?;
            }
            "stackTrace" => {
                if state.threads.is_empty() {
                    writer.error_response(
                        &request,
                        "runtime threads are not available yet; the asynchronous launch is still starting",
                    )?;
                    continue;
                }
                let thread = request_thread(&request, &state);
                let source_path = crate::source::stack_source_path(&state, thread);
                let frame_location = state
                    .stopped_location
                    .as_ref()
                    .filter(|_| state.stopped_task.as_ref() == Some(&thread.task))
                    .or(thread.current_source_location.as_ref());
                let stack_frames = if state.runtime_backend != RuntimeBackend::Simulated
                    && thread.runtime_stack_frames.is_empty()
                    && frame_location.is_none()
                {
                    Vec::new()
                } else {
                    let runtime_frame_name = thread
                        .runtime_stack_frames
                        .first()
                        .cloned()
                        .unwrap_or_else(|| format!("{}::run", thread.name));
                    let frame_name = runtime_frame_name
                        .strip_suffix("::wasm")
                        .and_then(|probe_id| {
                            state.debug_probes.iter().find(|probe| {
                                probe.probe_symbol == format!("clusterflux.probe.{probe_id}")
                            })
                        })
                        .map(|probe| format!("{}::wasm", probe.function))
                        .unwrap_or(runtime_frame_name);
                    let mut frame = json!({
                        "id": thread.frame_id,
                        "name": frame_name,
                        "line": frame_location.map(|location| location.line).unwrap_or_else(|| u32::try_from(thread.line).unwrap_or(0)),
                        "column": frame_location.and_then(|location| location.column).unwrap_or(1),
                    });
                    if let Some(source_path) = source_path {
                        frame["source"] = json!({
                            "name": crate::source::source_name(&source_path),
                            "path": source_path,
                            "presentationHint": "normal"
                        });
                    }
                    vec![frame]
                };
                let total_frames = stack_frames.len();
                writer.response(
                    &request,
                    true,
                    json!({
                        "stackFrames": stack_frames,
                        "totalFrames": total_frames
                    }),
                )?;
            }
            "source" => match crate::source::source_response(&state, &request) {
                Ok(body) => writer.response(&request, true, body)?,
                Err(err) => writer.error_response(&request, err.to_string())?,
            },
            "scopes" => {
                if state.threads.is_empty() {
                    writer.error_response(
                        &request,
                        "runtime scopes are not available yet; the asynchronous launch is still starting",
                    )?;
                    continue;
                }
                let frame_id = request
                    .get("arguments")
                    .and_then(|value| value.get("frameId"))
                    .and_then(Value::as_i64)
                    .unwrap_or(1000 + crate::demo_backend::MAIN_THREAD);
                let thread = state
                    .threads
                    .values()
                    .find(|thread| thread.frame_id == frame_id)
                    .cloned()
                    .unwrap_or_else(|| state.threads[&crate::demo_backend::MAIN_THREAD].clone());
                writer.response(
                    &request,
                    true,
                    json!({
                        "scopes": [
                            {
                                "name": "Source Locals",
                                "variablesReference": thread.locals_ref,
                                "expensive": false,
                                "presentationHint": "locals"
                            },
                            {
                                "name": "Wasm Frame Locals",
                                "variablesReference": thread.wasm_locals_ref,
                                "expensive": false,
                                "presentationHint": "locals"
                            },
                            {
                                "name": "Task Args and Handles",
                                "variablesReference": thread.args_ref,
                                "expensive": false,
                                "presentationHint": "arguments"
                            },
                            {
                                "name": "Clusterflux Runtime",
                                "variablesReference": thread.runtime_ref,
                                "expensive": false
                            },
                            {
                                "name": "Recent Output",
                                "variablesReference": thread.output_ref,
                                "expensive": false
                            }
                        ]
                    }),
                )?;
            }
            "variables" => {
                let reference = request
                    .get("arguments")
                    .and_then(|value| value.get("variablesReference"))
                    .and_then(Value::as_i64)
                    .unwrap_or(0);
                writer.response(&request, true, variables_response(&state, reference))?;
            }
            "evaluate" => {
                let expression = request
                    .get("arguments")
                    .and_then(|value| value.get("expression"))
                    .and_then(Value::as_str)
                    .unwrap_or_default();
                let result = match expression {
                    "virtual_process_id" => state.process.to_string(),
                    "debug_epoch" => state.epoch.to_string(),
                    "command_status" => state.command_status.clone(),
                    _ => "not available".to_owned(),
                };
                writer.response(
                    &request,
                    true,
                    json!({ "result": result, "variablesReference": 0 }),
                )?;
            }
            "pause" => {
                if matches!(
                    state.runtime_backend,
                    RuntimeBackend::LocalServices | RuntimeBackend::LiveServices
                ) {
                    if !runtime_started || state.threads.is_empty() {
                        writer.error_response(
                            &request,
                            "the Clusterflux runtime has not reported an active task to pause yet",
                        )?;
                        continue;
                    }
                    cancel_observation(&mut observation_cancel);
                    runtime_generation = runtime_generation.saturating_add(1);
                    let generation = runtime_generation;
                    let mut pause_state = state.clone();
                    let pause_tx = event_tx.clone();
                    let stopped_thread = default_thread_id(&pause_state);
                    writer.response(&request, true, json!({}))?;
                    thread::spawn(move || {
                        let result = freeze_all(&mut pause_state, stopped_thread, None)
                            .map_err(|failure| failure.message())
                            .and_then(|()| {
                                record_coordinator_debug_epoch(
                                    &mut pause_state,
                                    stopped_thread,
                                    "pause",
                                )
                                .map_err(|error| {
                                    format!("coordinator debug epoch failed: {error:#}")
                                })
                            })
                            .map(|()| pause_state);
                        let _ = pause_tx.send(AdapterEvent::PauseFinished { generation, result });
                    });
                    continue;
                }
                let stopped_thread = default_thread_id(&state);
                match freeze_all(
                    &mut state,
                    stopped_thread,
                    simulated_freeze_failure_thread(&request),
                ) {
                    Ok(()) => {
                        if let Err(err) =
                            record_coordinator_debug_epoch(&mut state, stopped_thread, "pause")
                        {
                            let message = format!("coordinator debug epoch failed: {err:#}");
                            writer.output("stderr", format!("{message}\n"))?;
                            writer.error_response(&request, message)?;
                            continue;
                        }
                        writer.response(&request, true, json!({}))?;
                        writer.event(
                            "stopped",
                            json!({
                                "reason": "pause",
                                    "description": debug_epoch_stop_description(&state, "Clusterflux Debug Epoch pause"),
                                "threadId": stopped_thread,
                                "allThreadsStopped": state.debug_all_threads_stopped,
                            }),
                        )?;
                    }
                    Err(failure) => {
                        let message = failure.message();
                        writer.output("stderr", format!("{message}\n"))?;
                        writer.error_response(&request, message)?;
                    }
                }
            }
            "continue" => {
                let thread_id =
                    request_thread_id(&request).unwrap_or_else(|| default_thread_id(&state));
                if matches!(
                    state.runtime_backend,
                    RuntimeBackend::LocalServices | RuntimeBackend::LiveServices
                ) {
                    if !runtime_started {
                        writer.error_response(
                            &request,
                            "the Clusterflux runtime is still starting",
                        )?;
                        continue;
                    }
                    cancel_observation(&mut observation_cancel);
                    runtime_generation = runtime_generation.saturating_add(1);
                    let generation = runtime_generation;
                    let mut resume_state = state.clone();
                    let resume_tx = event_tx.clone();
                    let resume_request = request.clone();
                    thread::spawn(move || {
                        let result = resume_coordinator_epoch(&mut resume_state)
                            .map(|()| resume_state)
                            .map_err(|error| {
                                format!("coordinator debug epoch resume failed: {error:#}")
                            });
                        let _ = resume_tx.send(AdapterEvent::ResumeFinished {
                            generation,
                            request: resume_request,
                            thread_id,
                            result,
                        });
                    });
                    continue;
                }
                let next_breakpoint = next_breakpoint_after(&state, thread_id);
                if let Err(err) = resume_coordinator_epoch(&mut state) {
                    let message = format!("coordinator debug epoch resume failed: {err:#}");
                    writer.output("stderr", format!("{message}\n"))?;
                    writer.error_response(&request, message)?;
                    continue;
                }
                for thread in state.threads.values_mut() {
                    if thread.state == DebugRuntimeState::Frozen {
                        thread.state = DebugRuntimeState::Running;
                    }
                }
                writer.response(&request, true, json!({ "allThreadsContinued": true }))?;
                writer.event(
                    "continued",
                    json!({
                        "threadId": thread_id,
                        "allThreadsContinued": true,
                    }),
                )?;
                if let Some((stopped_thread, location)) = next_breakpoint {
                    match freeze_all_at_location(&mut state, stopped_thread, location, None) {
                        Ok(()) => {
                            if let Err(err) = record_coordinator_debug_epoch(
                                &mut state,
                                stopped_thread,
                                "breakpoint",
                            ) {
                                let message = format!("coordinator debug epoch failed: {err:#}");
                                writer.output("stderr", format!("{message}\n"))?;
                                writer.error_response(&request, message)?;
                                continue;
                            }
                            writer.event(
                                "stopped",
                                json!({
                                    "reason": "breakpoint",
                                    "description": debug_epoch_stop_description(&state, "Clusterflux Debug Epoch all-stop"),
                                    "threadId": stopped_thread,
                                    "allThreadsStopped": state.debug_all_threads_stopped,
                                }),
                            )?;
                        }
                        Err(failure) => {
                            let message = failure.message();
                            writer.output("stderr", format!("{message}\n"))?;
                            writer.error_response(&request, message)?;
                        }
                    }
                } else {
                    writer.event("terminated", json!({}))?;
                }
            }
            "next" | "stepIn" | "stepOut" => {
                if state.runtime_backend != RuntimeBackend::Simulated {
                    writer.error_response(
                        &request,
                        "source stepping is not yet available from the executing node; use continue or pause instead of a synthetic step",
                    )?;
                    continue;
                }
                let thread_id = request_thread_id(&request).unwrap_or(LINUX_THREAD);
                let description = match command {
                    "next" => "step over",
                    "stepIn" => "step in",
                    "stepOut" => "step out",
                    _ => "step",
                };
                step_thread(&mut state, thread_id, description);
                writer.response(&request, true, json!({}))?;
                writer.event(
                    "stopped",
                    json!({
                        "reason": "step",
                        "description": format!("Clusterflux Debug Epoch {description}"),
                        "threadId": thread_id,
                        "allThreadsStopped": state.debug_all_threads_stopped,
                    }),
                )?;
            }
            "restart" | "restartFrame" => {
                let thread_id = request_thread_id(&request)
                    .or_else(|| {
                        request
                            .get("arguments")
                            .and_then(|arguments| arguments.get("frameId"))
                            .and_then(Value::as_i64)
                            .and_then(|frame_id| {
                                state
                                    .threads
                                    .values()
                                    .find(|thread| thread.frame_id == frame_id)
                                    .map(|thread| thread.id)
                            })
                    })
                    .unwrap_or_else(|| default_thread_id(&state));
                if restart_requires_whole_process(&request) {
                    let message = format!(
                        "Incompatible source edit requires whole virtual-process restart for {}",
                        state.process
                    );
                    writer.output("stderr", format!("{message}\n"))?;
                    writer.error_response(&request, message)?;
                    continue;
                }
                let restarting_failed_task = state
                    .threads
                    .get(&thread_id)
                    .is_some_and(|thread| matches!(thread.state, DebugRuntimeState::Failed(_)));
                if state.runtime_backend != RuntimeBackend::Simulated {
                    if thread_id == MAIN_THREAD && restarting_failed_task {
                        match relaunch_services_main_runtime(&state) {
                            Ok(record) => {
                                state.apply_runtime_record(record);
                                state.epoch = 0;
                                state.coordinator_debug_epoch = None;
                                state.stopped_task = None;
                                state.stopped_probe_symbol = None;
                                writer.response(&request, true, json!({}))?;
                                writer.output(
                                    "console",
                                    "Rebuilt the current bundle and restarted the failed coordinator main from its entry boundary\n",
                                )?;
                                cancel_observation(&mut observation_cancel);
                                runtime_generation = runtime_generation.saturating_add(1);
                                spawn_runtime_observer(
                                    &event_tx,
                                    &state,
                                    runtime_generation,
                                    &mut observation_cancel,
                                );
                            }
                            Err(err) => {
                                let message = format!("coordinator main restart failed: {err:#}");
                                writer.output("stderr", format!("{message}\n"))?;
                                writer.error_response(&request, message)?;
                            }
                        }
                        continue;
                    }
                    match restart_task_through_coordinator(&mut state, thread_id) {
                        Ok(message) => {
                            if let Some(thread) = state.threads.get_mut(&thread_id) {
                                thread.state = DebugRuntimeState::Running;
                                thread.recent_output.push(message.clone());
                            }
                            state.last_task_failed = false;
                            state.command_status = message.clone();
                            writer.response(&request, true, json!({}))?;
                            writer.output("console", format!("{message}\n"))?;
                            cancel_observation(&mut observation_cancel);
                            runtime_generation = runtime_generation.saturating_add(1);
                            spawn_runtime_observer(
                                &event_tx,
                                &state,
                                runtime_generation,
                                &mut observation_cancel,
                            );
                        }
                        Err(err) => {
                            let message = format!("coordinator task restart failed: {err:#}");
                            writer.output("stderr", format!("{message}\n"))?;
                            writer.error_response(&request, message)?;
                        }
                    }
                    continue;
                }
                if let Some(thread) = state.threads.get_mut(&thread_id) {
                    thread.state = DebugRuntimeState::Running;
                    thread
                        .recent_output
                        .push("task restarted from VFS checkpoint".to_owned());
                }
                if restarting_failed_task {
                    state.last_task_failed = false;
                }
                state.command_status = format!(
                    "{} task restarted from compatible VFS checkpoint",
                    if restarting_failed_task {
                        "failed"
                    } else {
                        "selected"
                    }
                );
                writer.response(&request, true, json!({}))?;
                writer.output(
                    "console",
                    format!(
                        "Restarted {} task from compatible VFS checkpoint on thread {thread_id}\n",
                        if restarting_failed_task {
                            "failed"
                        } else {
                            "selected"
                        }
                    ),
                )?;
            }
            "disconnect" | "terminate" => {
                cancel_observation(&mut observation_cancel);
                writer.response(&request, true, json!({}))?;
                writer.event("terminated", json!({}))?;
                break;
            }
            _ => writer.error_response(&request, format!("unsupported DAP command: {command}"))?,
        }
    }

    Ok(())
}

fn spawn_input_reader(event_tx: mpsc::Sender<AdapterEvent>) {
    thread::spawn(move || {
        let mut reader = BufReader::new(io::stdin());
        loop {
            match read_message(&mut reader) {
                Ok(Some(request)) => {
                    if event_tx.send(AdapterEvent::Request(request)).is_err() {
                        return;
                    }
                }
                Ok(None) => {
                    let _ = event_tx.send(AdapterEvent::InputClosed);
                    return;
                }
                Err(error) => {
                    let _ = event_tx.send(AdapterEvent::InputFailed(format!(
                        "DAP input failed: {error:#}"
                    )));
                    return;
                }
            }
        }
    });
}

fn cancel_observation(observation_cancel: &mut Option<Arc<AtomicBool>>) {
    if let Some(cancelled) = observation_cancel.take() {
        cancelled.store(true, Ordering::Release);
    }
}

fn spawn_runtime_observer(
    event_tx: &mpsc::Sender<AdapterEvent>,
    state: &AdapterState,
    generation: u64,
    observation_cancel: &mut Option<Arc<AtomicBool>>,
) {
    cancel_observation(observation_cancel);
    if state.runtime_backend == RuntimeBackend::Simulated {
        return;
    }
    let cancelled = Arc::new(AtomicBool::new(false));
    *observation_cancel = Some(cancelled.clone());
    let observer_state = state.clone();
    let observer_tx = event_tx.clone();
    let previous_debug_epoch = state.coordinator_debug_epoch.unwrap_or(state.epoch);
    thread::spawn(move || {
        let result = observe_services_runtime(
            &observer_state,
            previous_debug_epoch,
            cancelled.as_ref(),
            |outcome| {
                observer_tx
                    .send(AdapterEvent::ObservationUpdate {
                        generation,
                        outcome,
                    })
                    .is_ok()
            },
        );
        if let Err(error) = result {
            let _ = observer_tx.send(AdapterEvent::ObservationUpdate {
                generation,
                outcome: RuntimeContinuationOutcome::Diagnostic(format!(
                    "runtime observer stopped unexpectedly: {error:#}"
                )),
            });
        }
        let _ = observer_tx.send(AdapterEvent::ObservationFinished { generation });
    });
}

pub(crate) fn breakpoint_update_is_current(
    update_generation: u64,
    runtime_generation: u64,
    update_revision: u64,
    current_revision: u64,
) -> bool {
    update_generation == runtime_generation && update_revision == current_revision
}

fn runtime_observation_diagnostics(
    record: &crate::virtual_model::RuntimeLaunchRecord,
) -> Vec<String> {
    record
        .node_report
        .get("observation_diagnostics")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
        .filter_map(Value::as_str)
        .map(str::to_owned)
        .collect()
}

fn emit_verified_breakpoints(writer: &mut DapWriter, state: &AdapterState) -> Result<()> {
    if !state.breakpoints_installed {
        return Ok(());
    }
    for (index, location) in state.breakpoint_locations().enumerate() {
        writer.event(
            "breakpoint",
            json!({
                "reason": "changed",
                "breakpoint": {
                    "id": index + 1,
                    "verified": true,
                    "line": location.line,
                    "source": { "path": location.source_path },
                    "message": "Installed by the Clusterflux coordinator",
                }
            }),
        )?;
    }
    Ok(())
}

fn emit_unverified_breakpoints(
    writer: &mut DapWriter,
    state: &AdapterState,
    coordinator_error: &str,
) -> Result<()> {
    for (index, location) in state.breakpoint_locations().enumerate() {
        writer.event(
            "breakpoint",
            json!({
                "reason": "changed",
                "breakpoint": {
                    "id": index + 1,
                    "verified": false,
                    "line": location.line,
                    "source": { "path": location.source_path },
                    "message": format!("Coordinator breakpoint installation failed: {coordinator_error}"),
                }
            }),
        )?;
    }
    Ok(())
}

fn emit_thread_lifecycle(
    writer: &mut DapWriter,
    previous: &BTreeMap<i64, VirtualThread>,
    current: &BTreeMap<i64, VirtualThread>,
) -> Result<()> {
    for (id, thread) in previous {
        if current
            .get(id)
            .is_none_or(|current| current.task != thread.task)
        {
            writer.event("thread", json!({ "reason": "exited", "threadId": id }))?;
        }
    }
    for (id, thread) in current {
        if previous
            .get(id)
            .is_none_or(|previous| previous.task != thread.task)
        {
            writer.event("thread", json!({ "reason": "started", "threadId": id }))?;
        }
    }
    Ok(())
}

fn apply_runtime_record_with_thread_events(
    writer: &mut DapWriter,
    state: &mut AdapterState,
    record: crate::virtual_model::RuntimeLaunchRecord,
) -> Result<()> {
    let previous = state.threads.clone();
    state.apply_runtime_record(record);
    emit_thread_lifecycle(writer, &previous, &state.threads)
}

fn emit_runtime_outcome(
    writer: &mut DapWriter,
    state: &mut AdapterState,
    outcome: RuntimeContinuationOutcome,
) -> Result<()> {
    match outcome {
        RuntimeContinuationOutcome::Snapshot(record) => {
            apply_runtime_record_with_thread_events(writer, state, record)?;
        }
        RuntimeContinuationOutcome::Diagnostic(message) => {
            writer.output("stderr", format!("{message}\n"))?;
        }
        RuntimeContinuationOutcome::Breakpoint(record) => {
            apply_runtime_record_with_thread_events(writer, state, record)?;
            let stopped_thread = stopped_thread_for_breakpoint(state);
            position_confirmed_breakpoint_stop(state, stopped_thread);
            writer.event(
                "stopped",
                json!({
                    "reason": "breakpoint",
                    "description": debug_epoch_stop_description(state, "Clusterflux Debug Epoch all-stop confirmed by every active participant"),
                    "threadId": stopped_thread,
                    "allThreadsStopped": state.debug_all_threads_stopped,
                }),
            )?;
        }
        RuntimeContinuationOutcome::Exception(record) => {
            apply_runtime_record_with_thread_events(writer, state, record)?;
            let stopped_thread = stopped_thread_for_breakpoint(state);
            writer.output("stderr", format!("{}\n", state.command_status))?;
            writer.event(
                "stopped",
                json!({
                    "reason": "exception",
                    "description": "Task failed and is awaiting operator action",
                    "threadId": stopped_thread,
                    "allThreadsStopped": false,
                }),
            )?;
        }
        RuntimeContinuationOutcome::Terminal(record) => {
            let exit_code = record.status_code.unwrap_or(1);
            apply_runtime_record_with_thread_events(writer, state, record)?;
            if state.last_task_failed {
                writer.output("stderr", format!("{}\n", state.command_status))?;
            }
            writer.event("exited", json!({ "exitCode": exit_code }))?;
            writer.event("terminated", json!({}))?;
        }
    }
    Ok(())
}

fn restart_task_through_coordinator(state: &mut AdapterState, thread_id: i64) -> Result<String> {
    let task = state
        .threads
        .get(&thread_id)
        .map(|thread| thread.task.clone())
        .ok_or_else(|| anyhow::anyhow!("selected debug thread does not map to a virtual task"))?;
    let record = restart_task(state, &task)?;
    if !record.accepted {
        let mut message = format!(
            "coordinator refused task restart for `{task}`: {}",
            record.message
        );
        if record.requires_whole_process_restart {
            message.push_str("; whole virtual-process restart required");
        }
        if record.active_task {
            message.push_str("; selected task is still active");
        }
        if record.completed_event_observed {
            message.push_str("; only terminal task-event metadata is available");
        }
        return Err(anyhow::anyhow!(message));
    }
    if !record.clean_boundary_available {
        return Err(anyhow::anyhow!(
            "coordinator accepted task restart for `{task}` without a clean checkpoint boundary"
        ));
    }
    let restarted_task = record.restarted_task_instance.ok_or_else(|| {
        anyhow::anyhow!("coordinator accepted task restart without its stable task-instance ID")
    })?;
    if let Some(thread) = state.threads.get_mut(&thread_id) {
        thread.task = restarted_task.clone();
        thread.attempt_id = record.restarted_attempt_id.clone().ok_or_else(|| {
            anyhow::anyhow!("coordinator accepted task restart without a new attempt ID")
        })?;
    }
    let (inventory, probes) =
        crate::breakpoints::load_bundle_debug_model(&state.project, &state.source_path);
    state.source_inventory = inventory;
    state.debug_probes = probes;
    Ok(format!(
        "Coordinator restarted logical task `{restarted_task}` as attempt `{}` from the rebuilt bundle and a clean runtime checkpoint boundary",
        record.restarted_attempt_id.as_deref().unwrap_or("unknown")
    ))
}

fn record_coordinator_debug_epoch(
    state: &mut AdapterState,
    stopped_thread: i64,
    reason: &str,
) -> Result<()> {
    if state.runtime_backend == RuntimeBackend::Simulated {
        return Ok(());
    }
    let stopped_task = state
        .threads
        .get(&stopped_thread)
        .map(|thread| thread.task.clone())
        .unwrap_or_else(|| state.threads[&default_thread_id(state)].task.clone());
    let record = create_debug_epoch(state, &stopped_task, reason)?;
    let status = wait_for_debug_epoch_frozen(state, record.epoch)?;
    let runtime_record = debug_epoch_runtime_record(state, &status, &stopped_task)?;
    state.apply_runtime_record(runtime_record);
    state.debug_all_threads_stopped = status.fully_frozen;
    state.epoch = record.epoch;
    state.coordinator_debug_epoch = Some(record.epoch);
    let previous_status = state.command_status.clone();
    let freeze_state = if status.fully_frozen {
        "fully frozen"
    } else if status.partially_frozen {
        "partially frozen; missing or failed participants remain explicitly unavailable"
    } else {
        "not frozen"
    };
    state.command_status = format!(
        "{previous_status}; debug epoch {} is {freeze_state} for command {} after {}/{} signed participant freeze acknowledgements",
        status.epoch,
        status.command,
        status.acknowledgements.len(),
        status.expected_tasks
    );
    if let Some(thread) = state.threads.get_mut(&stopped_thread) {
        thread.recent_output.push(format!(
            "coordinator debug epoch {} is {freeze_state} after {}/{} signed participant acknowledgements",
            status.epoch,
            status.acknowledgements.len(),
            status.expected_tasks
        ));
    }
    Ok(())
}

fn debug_epoch_stop_description(state: &AdapterState, fully_frozen: &str) -> String {
    if state.debug_all_threads_stopped {
        fully_frozen.to_owned()
    } else {
        "Clusterflux Debug Epoch is partially frozen; missing or failed participants remain running or unavailable, so inspected state may be inconsistent".to_owned()
    }
}

fn default_thread_id(state: &AdapterState) -> i64 {
    if state.runtime_backend == RuntimeBackend::Simulated
        && state.threads.contains_key(&LINUX_THREAD)
    {
        LINUX_THREAD
    } else {
        MAIN_THREAD
    }
}

fn resume_coordinator_epoch(state: &mut AdapterState) -> Result<()> {
    let Some(epoch) = state.coordinator_debug_epoch else {
        return Ok(());
    };
    if state.runtime_backend == RuntimeBackend::Simulated {
        return Ok(());
    }
    let record = resume_debug_epoch(state, epoch)?;
    let status = wait_for_debug_epoch_resumed(state, epoch)?;
    state.coordinator_debug_epoch = None;
    state.command_status = format!(
        "debug epoch {} resumed after {}/{} signed participant acknowledgements",
        status.epoch,
        status.acknowledgements.len(),
        status.expected_tasks
    );
    let status_thread = default_thread_id(state);
    if let Some(thread) = state.threads.get_mut(&status_thread) {
        thread.recent_output.push(format!(
            "coordinator debug epoch {} resumed with {} after {}/{} acknowledgements ({} affected task(s))",
            status.epoch,
            status.command,
            status.acknowledgements.len(),
            status.expected_tasks,
            record.affected_tasks
        ));
    }
    Ok(())
}

pub(crate) fn runtime_backend_from_launch_arg(
    value: Option<&str>,
) -> Result<RuntimeBackend, String> {
    match value {
        None | Some("local-services") => Ok(RuntimeBackend::LocalServices),
        Some("live-services") => Ok(RuntimeBackend::LiveServices),
        Some(value) if is_explicit_demo_backend(value) => Ok(RuntimeBackend::Simulated),
        Some(value) => Err(format!(
            "unsupported Clusterflux runtimeBackend `{value}`; use local-services, live-services, or explicit demo"
        )),
    }
}
