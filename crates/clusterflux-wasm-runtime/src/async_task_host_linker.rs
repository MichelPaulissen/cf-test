use super::*;

#[derive(Clone, Copy)]
enum AsyncTaskHostOperation {
    Start,
    Join,
    Command,
    TaskControl,
    DebugProbe,
    SourceSnapshot,
    TriggerContext,
    Vfs,
}

pub(super) fn async_task_host_linker(
    engine: &Engine,
) -> Result<Linker<AsyncWasmtimeTaskHostState>, WasmTaskError> {
    let mut linker = Linker::new(engine);
    for (name, operation) in [
        ("task_start_v1", AsyncTaskHostOperation::Start),
        ("task_join_v1", AsyncTaskHostOperation::Join),
        ("command_run_v1", AsyncTaskHostOperation::Command),
        ("task_control_v1", AsyncTaskHostOperation::TaskControl),
        ("debug_probe_v1", AsyncTaskHostOperation::DebugProbe),
        ("source_snapshot_v1", AsyncTaskHostOperation::SourceSnapshot),
        ("trigger_context_v1", AsyncTaskHostOperation::TriggerContext),
        ("vfs_operation_v1", AsyncTaskHostOperation::Vfs),
    ] {
        linker
            .func_wrap_async(
                "clusterflux",
                name,
                move |caller: Caller<'_, AsyncWasmtimeTaskHostState>,
                      (input_pointer, input_length, output_pointer, output_capacity): (
                    u32,
                    u32,
                    u32,
                    u32,
                )| {
                    Box::new(async move {
                        async_task_host_call(
                            caller,
                            input_pointer,
                            input_length,
                            output_pointer,
                            output_capacity,
                            operation,
                        )
                        .await
                    })
                },
            )
            .map_err(wasmtime_error)?;
    }
    Ok(linker)
}

async fn async_task_host_call(
    mut caller: Caller<'_, AsyncWasmtimeTaskHostState>,
    input_pointer: u32,
    input_length: u32,
    output_pointer: u32,
    output_capacity: u32,
    operation: AsyncTaskHostOperation,
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
        .read(&caller, input_pointer as usize, &mut input)
        .is_err()
    {
        return -3;
    }
    if let Some(debug) = caller.data().host.debug_control() {
        let stack_frames = WasmBacktrace::force_capture(&caller)
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
        AsyncTaskHostOperation::Start => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug
                    .enter_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            let response: Result<WasmHostTaskHandle, String> =
                match serde_json::from_slice::<WasmHostTaskStartRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.start_task(request).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error.to_string()),
                };
            if let Some(debug) = &debug {
                debug
                    .leave_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::Join => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug
                    .enter_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            let response: Result<WasmHostTaskJoinResult, String> = match serde_json::from_slice::<
                WasmHostTaskJoinRequest,
            >(&input)
            {
                Ok(request) if request.abi_version == clusterflux_core::WASM_TASK_ABI_VERSION => {
                    caller.data_mut().host.join_task(request).await
                }
                Ok(request) => Err(format!(
                    "unsupported Wasm task ABI version {}",
                    request.abi_version
                )),
                Err(error) => Err(error.to_string()),
            };
            if let Some(debug) = &debug {
                debug
                    .leave_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::Command => {
            let response: Result<WasmHostCommandResult, String> =
                match serde_json::from_slice::<WasmHostCommandRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.run_command(request).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error.to_string()),
                };
            if let Err(error) = &response {
                if error.contains("task execution cancelled:") {
                    caller.data_mut().fatal_host_error = Some(error.clone());
                }
            }
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::TaskControl => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug
                    .enter_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            let response: Result<WasmHostTaskControlResult, String> =
                match serde_json::from_slice::<WasmHostTaskControlRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.poll_task_control(request).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error.to_string()),
                };
            if let Some(debug) = &debug {
                debug
                    .leave_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::DebugProbe => {
            let debug = caller.data().host.debug_control();
            let abort = caller.data().host.abort_signal();
            if let Some(debug) = &debug {
                debug
                    .enter_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            let response: Result<WasmHostDebugProbeResult, String> =
                match serde_json::from_slice::<WasmHostDebugProbeRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.debug_probe(request).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error.to_string()),
                };
            if let Some(debug) = &debug {
                debug
                    .leave_quiescent_host_boundary_async(abort.as_deref())
                    .await;
            }
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::Vfs => {
            let response: Result<WasmHostVfsResult, String> =
                match serde_json::from_slice::<WasmHostVfsRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.vfs_operation(request).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error.to_string()),
                };
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::SourceSnapshot => {
            let response: Result<WasmHostSourceSnapshotResult, String> =
                match serde_json::from_slice::<WasmHostSourceSnapshotRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.snapshot_source(request).await,
                        Err(error) => Err(error),
                    },
                    Err(error) => Err(error.to_string()),
                };
            serde_json::to_vec(&response)
        }
        AsyncTaskHostOperation::TriggerContext => {
            let response: Result<WasmHostTriggerContextResult, String> =
                match serde_json::from_slice::<WasmHostTriggerContextRequest>(&input) {
                    Ok(request) => match request.validate() {
                        Ok(()) => caller.data_mut().host.trigger_context(request).await,
                        Err(error) => Err(error),
                    },
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
        .write(&mut caller, output_pointer as usize, &encoded)
        .is_err()
    {
        return -6;
    }
    i32::try_from(encoded.len()).unwrap_or(-7)
}
