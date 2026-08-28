use super::*;

pub(super) fn task_host_linker(
    engine: &Engine,
) -> Result<Linker<WasmtimeTaskHostState>, WasmTaskError> {
    let mut linker = Linker::new(engine);
    linker
        .func_wrap(
            "clusterflux",
            "task_start_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::Start,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "trigger_context_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::TriggerContext,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "source_snapshot_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::SourceSnapshot,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "vfs_operation_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::Vfs,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "command_run_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::Command,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "task_control_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::TaskControl,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "debug_probe_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::DebugProbe,
                )
            },
        )
        .map_err(wasmtime_error)?;
    linker
        .func_wrap(
            "clusterflux",
            "task_join_v1",
            |mut caller: Caller<'_, WasmtimeTaskHostState>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                task_host_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                    TaskHostOperation::Join,
                )
            },
        )
        .map_err(wasmtime_error)?;
    Ok(linker)
}

pub(super) fn task_host_stub_linker<T: 'static>(
    engine: &Engine,
) -> Result<Linker<T>, WasmTaskError> {
    let mut linker = Linker::new(engine);
    for import in [
        "task_start_v1",
        "task_join_v1",
        "command_run_v1",
        "task_control_v1",
        "source_snapshot_v1",
        "trigger_context_v1",
        "vfs_operation_v1",
    ] {
        linker
            .func_wrap(
                "clusterflux",
                import,
                |_input_pointer: u32,
                 _input_length: u32,
                 _output_pointer: u32,
                 _output_capacity: u32|
                 -> i32 { -1 },
            )
            .map_err(wasmtime_error)?;
    }
    linker
        .func_wrap(
            "clusterflux",
            "debug_probe_v1",
            |mut caller: Caller<'_, T>,
             input_pointer: u32,
             input_length: u32,
             output_pointer: u32,
             output_capacity: u32|
             -> i32 {
                debug_probe_stub_call(
                    &mut caller,
                    input_pointer,
                    input_length,
                    output_pointer,
                    output_capacity,
                )
            },
        )
        .map_err(wasmtime_error)?;
    Ok(linker)
}

fn debug_probe_stub_call<T>(
    caller: &mut Caller<'_, T>,
    input_pointer: u32,
    input_length: u32,
    output_pointer: u32,
    output_capacity: u32,
) -> i32 {
    let Some(memory) = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    else {
        return -2;
    };
    let mut input = vec![0_u8; input_length as usize];
    if memory
        .read(&*caller, input_pointer as usize, &mut input)
        .is_err()
    {
        return -3;
    }
    let response: Result<WasmHostDebugProbeResult, String> =
        match serde_json::from_slice::<WasmHostDebugProbeRequest>(&input) {
            Ok(request) => request.validate().map(|()| WasmHostDebugProbeResult {
                abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
                breakpoint_matched: false,
                debug_epoch: None,
            }),
            Err(error) => Err(error.to_string()),
        };
    let Ok(encoded) = serde_json::to_vec(&response) else {
        return -4;
    };
    if encoded.len() > output_capacity as usize {
        return -(encoded.len() as i32);
    }
    if memory
        .write(caller, output_pointer as usize, &encoded)
        .is_err()
    {
        return -5;
    }
    encoded.len() as i32
}

enum TaskHostOperation {
    Start,
    Join,
    Command,
    TaskControl,
    DebugProbe,
    SourceSnapshot,
    TriggerContext,
    Vfs,
}

fn task_host_call(
    caller: &mut Caller<'_, WasmtimeTaskHostState>,
    input_pointer: u32,
    input_length: u32,
    output_pointer: u32,
    output_capacity: u32,
    operation: TaskHostOperation,
) -> i32 {
    if input_length as usize > MAX_WASM_TASK_ENVELOPE_BYTES
        || output_capacity as usize > MAX_WASM_TASK_ENVELOPE_BYTES
    {
        return -1;
    }
    let Some(memory) = caller
        .get_export("memory")
        .and_then(|export| export.into_memory())
    else {
        return -2;
    };
    let mut input = vec![0_u8; input_length as usize];
    if memory
        .read(&*caller, input_pointer as usize, &mut input)
        .is_err()
    {
        return -3;
    }
    if let Some(debug) = caller.data().host.debug_control() {
        let stack_frames = WasmBacktrace::force_capture(&*caller)
            .frames()
            .iter()
            .take(16)
            .map(|frame| {
                frame
                    .func_name()
                    .map(str::to_owned)
                    .unwrap_or_else(|| format!("wasm_function_{}", frame.func_index()))
            })
            .collect();
        debug.record_stack_frames(stack_frames);
    }
    let encoded = match operation {
        TaskHostOperation::Start => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug.enter_quiescent_host_boundary(abort.as_deref());
            }
            let response: Result<WasmHostTaskHandle, String> =
                match serde_json::from_slice::<WasmHostTaskStartRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.start_task(request)),
                    Err(error) => Err(error.to_string()),
                };
            if let Some(debug) = &debug {
                debug.leave_quiescent_host_boundary(abort.as_deref());
            }
            serde_json::to_vec(&response)
        }
        TaskHostOperation::Join => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug.enter_quiescent_host_boundary(abort.as_deref());
            }
            let response: Result<WasmHostTaskJoinResult, String> = match serde_json::from_slice::<
                WasmHostTaskJoinRequest,
            >(&input)
            {
                Ok(request) if request.abi_version == clusterflux_core::WASM_TASK_ABI_VERSION => {
                    caller.data_mut().host.join_task(request)
                }
                Ok(request) => Err(format!(
                    "unsupported Wasm task ABI version {}",
                    request.abi_version
                )),
                Err(error) => Err(error.to_string()),
            };
            if let Some(debug) = &debug {
                debug.leave_quiescent_host_boundary(abort.as_deref());
            }
            serde_json::to_vec(&response)
        }
        TaskHostOperation::Command => {
            let response: Result<WasmHostCommandResult, String> =
                match serde_json::from_slice::<WasmHostCommandRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.run_command(request)),
                    Err(error) => Err(error.to_string()),
                };
            if let Err(error) = &response {
                if error.contains("task execution cancelled:") {
                    caller.data_mut().fatal_host_error = Some(error.clone());
                }
            }
            serde_json::to_vec(&response)
        }
        TaskHostOperation::TaskControl => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug.enter_quiescent_host_boundary(abort.as_deref());
            }
            let response: Result<WasmHostTaskControlResult, String> =
                match serde_json::from_slice::<WasmHostTaskControlRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.poll_task_control(request)),
                    Err(error) => Err(error.to_string()),
                };
            if let Some(debug) = &debug {
                debug.leave_quiescent_host_boundary(abort.as_deref());
            }
            serde_json::to_vec(&response)
        }
        TaskHostOperation::DebugProbe => {
            // A matched probe requests a Debug Epoch from inside this host call. Keep
            // the guest at this quiescent boundary until every participant has frozen
            // and the debugger resumes the epoch; otherwise a short-lived task can run
            // past the probe (or trap) before its control watcher acknowledges all-stop.
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug.enter_quiescent_host_boundary(abort.as_deref());
            }
            let response: Result<WasmHostDebugProbeResult, String> =
                match serde_json::from_slice::<WasmHostDebugProbeRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.debug_probe(request)),
                    Err(error) => Err(error.to_string()),
                };
            if let Some(debug) = &debug {
                debug.leave_quiescent_host_boundary(abort.as_deref());
            }
            serde_json::to_vec(&response)
        }
        TaskHostOperation::Vfs => {
            let response: Result<WasmHostVfsResult, String> =
                match serde_json::from_slice::<WasmHostVfsRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.vfs_operation(request)),
                    Err(error) => Err(error.to_string()),
                };
            serde_json::to_vec(&response)
        }
        TaskHostOperation::SourceSnapshot => {
            let response: Result<WasmHostSourceSnapshotResult, String> =
                match serde_json::from_slice::<WasmHostSourceSnapshotRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.snapshot_source(request)),
                    Err(error) => Err(error.to_string()),
                };
            serde_json::to_vec(&response)
        }
        TaskHostOperation::TriggerContext => {
            let response: Result<WasmHostTriggerContextResult, String> =
                match serde_json::from_slice::<WasmHostTriggerContextRequest>(&input) {
                    Ok(request) => request
                        .validate()
                        .and_then(|()| caller.data_mut().host.trigger_context(request)),
                    Err(error) => Err(error.to_string()),
                };
            serde_json::to_vec(&response)
        }
    };
    let Ok(encoded) = encoded else {
        return -4;
    };
    let current_fuel = caller.get_fuel().unwrap_or(0);
    let refilled_fuel = caller.data_mut().refill_fuel_after_host_call(current_fuel);
    if caller.set_fuel(refilled_fuel).is_err() {
        return -8;
    }
    if encoded.is_empty() || encoded.len() > output_capacity as usize {
        return -5;
    }
    if memory
        .write(&mut *caller, output_pointer as usize, &encoded)
        .is_err()
    {
        return -6;
    }
    i32::try_from(encoded.len()).unwrap_or(-7)
}
