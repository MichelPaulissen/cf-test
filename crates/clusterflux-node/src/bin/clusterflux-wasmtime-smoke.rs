use std::fs;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};

use clusterflux_core::{
    ArtifactHandle, ArtifactId, Digest, StructuredTaskBoundary, TaskBoundaryHandle,
    TaskBoundaryValue, WasmHostCommandRequest, WasmHostCommandResult,
    WasmHostSourceSnapshotRequest, WasmHostSourceSnapshotResult, WasmHostTaskControlRequest,
    WasmHostTaskControlResult, WasmHostTaskHandle, WasmHostTaskJoinRequest, WasmHostTaskJoinResult,
    WasmHostTaskStartRequest, WasmHostVfsOperation, WasmHostVfsRequest, WasmHostVfsResult,
    WasmTaskInvocation, WasmTaskOutcome,
};
use clusterflux_node::{WasmTaskHost, WasmtimeTaskRuntime};
use serde_json::json;
use wasmparser::{Parser, Payload};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<String> = std::env::args().collect();
    if args.len() == 4 && args[1] == "--host-command" {
        return run_host_command_smoke(&args[2], &args[3]);
    }
    if args.len() == 6 && args[1] == "--debug-freeze-resume" {
        return run_debug_freeze_resume_smoke(&args[2], &args[3], &args[4], &args[5]);
    }
    if args.len() == 6 && args[1] == "--task-abi" {
        return run_task_abi_smoke(&args[2], &args[3], &args[4], &args[5]);
    }
    if args.len() == 4 && args[1] == "--task-artifact" {
        return run_task_artifact_smoke(&args[2], &args[3]);
    }
    if args.len() != 5 {
        return Err(
            "usage: clusterflux-wasmtime-smoke <module.wasm> <export> <i32-arg> <expected-i32> | --host-command <module.wasm> <task> | --debug-freeze-resume <module.wasm> <export> <i32-arg> <expected-i32> | --task-abi <module.wasm> <export> <task> <args-json> | --task-artifact <module.wasm> <task>".into(),
        );
    }

    let module = PathBuf::from(&args[1]);
    let export = &args[2];
    let arg: i32 = args[3].parse()?;
    let expected: i32 = args[4].parse()?;

    let wasm = fs::read(&module)?;
    let runtime = WasmtimeTaskRuntime::new()?;
    let result = runtime.run_i32_export(&wasm, export, arg)?;
    if result != expected {
        return Err(format!("expected {expected}, got {result} from export `{export}`").into());
    }

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "wasmtime_task_smoke",
            "module": module,
            "export": export,
            "arg": arg,
            "result": result,
        }))?
    );
    Ok(())
}

fn run_task_artifact_smoke(module: &str, task: &str) -> Result<(), Box<dyn std::error::Error>> {
    let module = PathBuf::from(module);
    let wasm = fs::read(&module)?;
    let export = task_export(&wasm, task)?;
    let published = Arc::new(Mutex::new(None));
    let input_artifact = ArtifactHandle {
        id: ArtifactId::from("compiler-output"),
        digest: Digest::sha256("compiler-output"),
        size_bytes: 15,
    };
    let source_snapshot = Digest::sha256("standalone-source-snapshot");
    let package_input = TaskBoundaryValue::Structured(StructuredTaskBoundary {
        value: serde_json::json!({
            "release_name": "release.tar",
            "source": {
                "$task_handle": { "index": 0, "kind": "source_snapshot" }
            },
            "executable": {
                "$task_handle": { "index": 1, "kind": "artifact" }
            },
            "inputs": [{
                "$task_handle": { "index": 2, "kind": "artifact" }
            }],
        }),
        handles: vec![
            TaskBoundaryHandle::SourceSnapshot(source_snapshot),
            TaskBoundaryHandle::Artifact(input_artifact.clone()),
            TaskBoundaryHandle::Artifact(input_artifact.clone()),
        ],
    });
    let result = WasmtimeTaskRuntime::new()?.run_task_export_verified_with_task_host(
        &wasm,
        &Digest::sha256(&wasm),
        &export,
        &WasmTaskInvocation::new(
            clusterflux_core::TaskDefinitionId::from(task),
            clusterflux_core::TaskInstanceId::new(format!("{task}-1")),
            vec![package_input],
        ),
        Box::new(ArtifactRecordingHost {
            published: Arc::clone(&published),
            executed_command: Arc::new(Mutex::new(None)),
            allow_command: true,
        }),
    )?;
    if result.outcome != WasmTaskOutcome::Completed {
        return Err(format!("artifact task failed: {:?}", result.error).into());
    }
    let Some(TaskBoundaryValue::Artifact(result_artifact)) = result.result else {
        return Err("artifact task did not return an Artifact handle".into());
    };
    let (name, host_artifact) = published
        .lock()
        .map_err(|_| "artifact recording host lock was poisoned")?
        .clone()
        .ok_or("Wasm task did not invoke clusterflux.vfs_operation_v1 flush_output")?;
    if result_artifact != host_artifact {
        return Err("Wasm task returned a handle other than the host-issued artifact ID".into());
    }
    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "wasmtime_task_artifact_smoke",
            "module": module,
            "task": task,
            "export": export,
            "artifact": result_artifact,
            "artifact_name": name,
            "artifact_digest": host_artifact.digest,
            "artifact_size_bytes": host_artifact.size_bytes,
            "host_import": "clusterflux.vfs_operation_v1",
            "host_issued_handle_returned": true,
        }))?
    );
    Ok(())
}

type PublishedArtifact = (String, ArtifactHandle);
type ExecutedCommand = (WasmHostCommandRequest, WasmHostCommandResult);

struct ArtifactRecordingHost {
    published: Arc<Mutex<Option<PublishedArtifact>>>,
    executed_command: Arc<Mutex<Option<ExecutedCommand>>>,
    allow_command: bool,
}

impl WasmTaskHost for ArtifactRecordingHost {
    fn start_task(
        &mut self,
        _request: WasmHostTaskStartRequest,
    ) -> Result<WasmHostTaskHandle, String> {
        Err("artifact smoke task must not spawn".to_owned())
    }

    fn join_task(
        &mut self,
        _request: WasmHostTaskJoinRequest,
    ) -> Result<WasmHostTaskJoinResult, String> {
        Err("artifact smoke task must not join".to_owned())
    }

    fn run_command(
        &mut self,
        request: WasmHostCommandRequest,
    ) -> Result<WasmHostCommandResult, String> {
        request.validate()?;
        if !self.allow_command {
            return Err("this smoke task was not granted Command capability".to_owned());
        }
        let result = WasmHostCommandResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            status_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            stdout_truncated: false,
            stderr_truncated: false,
        };
        *self
            .executed_command
            .lock()
            .map_err(|_| "command recording host lock was poisoned".to_owned())? =
            Some((request, result.clone()));
        Ok(result)
    }

    fn poll_task_control(
        &mut self,
        request: WasmHostTaskControlRequest,
    ) -> Result<WasmHostTaskControlResult, String> {
        request.validate()?;
        Ok(WasmHostTaskControlResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            cancellation_requested: false,
        })
    }

    fn vfs_operation(&mut self, request: WasmHostVfsRequest) -> Result<WasmHostVfsResult, String> {
        request.validate()?;
        let (artifact, relative_path) = match request.operation {
            WasmHostVfsOperation::FlushOutput { relative_path } => {
                let digest = Digest::sha256(format!("standalone-vfs-smoke:{relative_path}"));
                let artifact = ArtifactHandle {
                    id: ArtifactId::new(format!(
                        "{}-{}",
                        relative_path.replace('/', "_"),
                        digest.as_str().trim_start_matches("sha256:")
                    )),
                    digest,
                    size_bytes: relative_path.len() as u64,
                };
                *self
                    .published
                    .lock()
                    .map_err(|_| "artifact recording host lock was poisoned".to_owned())? =
                    Some((relative_path.clone(), artifact.clone()));
                (artifact, relative_path)
            }
            WasmHostVfsOperation::MaterializeArtifact {
                artifact,
                relative_path,
            } => (artifact, relative_path),
            WasmHostVfsOperation::ReleaseArtifact { artifact } => (artifact, String::new()),
        };
        Ok(WasmHostVfsResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            artifact,
            relative_path,
        })
    }

    fn snapshot_source(
        &mut self,
        request: WasmHostSourceSnapshotRequest,
    ) -> Result<WasmHostSourceSnapshotResult, String> {
        request.validate()?;
        Ok(WasmHostSourceSnapshotResult {
            abi_version: clusterflux_core::WASM_TASK_ABI_VERSION,
            snapshot: Digest::sha256("standalone-source-snapshot"),
        })
    }
}

fn task_export(wasm: &[u8], task: &str) -> Result<String, Box<dyn std::error::Error>> {
    for payload in Parser::new(0).parse_all(wasm) {
        let Payload::CustomSection(section) = payload? else {
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
            if descriptor.get("name").and_then(serde_json::Value::as_str) == Some(task) {
                return descriptor
                    .get("export")
                    .and_then(serde_json::Value::as_str)
                    .map(str::to_owned)
                    .ok_or_else(|| format!("task `{task}` descriptor omitted export").into());
            }
        }
    }
    Err(format!("module has no task descriptor `{task}`").into())
}

fn run_task_abi_smoke(
    module: &str,
    export: &str,
    task: &str,
    args: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let module = PathBuf::from(module);
    let wasm = fs::read(&module)?;
    let args: Vec<TaskBoundaryValue> = serde_json::from_str(args)?;
    let invocation = WasmTaskInvocation::new(
        clusterflux_core::TaskDefinitionId::from(task),
        clusterflux_core::TaskInstanceId::new(format!("{task}-1")),
        args,
    );
    let result = WasmtimeTaskRuntime::new()?.run_task_export_verified(
        &wasm,
        &Digest::sha256(&wasm),
        export,
        &invocation,
    )?;
    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "wasm_task_abi_smoke",
            "module": module,
            "export": export,
            "invocation": invocation,
            "result": result,
        }))?
    );
    Ok(())
}

fn run_debug_freeze_resume_smoke(
    module: &str,
    export: &str,
    arg: &str,
    expected: &str,
) -> Result<(), Box<dyn std::error::Error>> {
    let module = PathBuf::from(module);
    let arg: i32 = arg.parse()?;
    let expected: i32 = expected.parse()?;
    let wasm = fs::read(&module)?;
    let runtime = WasmtimeTaskRuntime::new()?;
    let probe = runtime.freeze_resume_i32_export_probe(&wasm, export, arg)?;
    if probe.result != expected {
        return Err(format!(
            "expected {expected}, got {} from export `{export}`",
            probe.result
        )
        .into());
    }

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "wasmtime_debug_freeze_resume_smoke",
            "module": module,
            "export": export,
            "task": probe.task,
            "frozen_state": probe.frozen_state,
            "resumed_state": probe.resumed_state,
            "stack_frames": probe.stack_frames,
            "local_values": probe.local_values,
            "wasm_function": probe.wasm_function,
            "wasm_pc": probe.wasm_pc,
            "arg": arg,
            "result": probe.result,
            "node_runtime_reached_wasm_task": true,
            "node_runtime_captured_wasm_locals": true,
        }))?
    );
    Ok(())
}

fn run_host_command_smoke(module: &str, task: &str) -> Result<(), Box<dyn std::error::Error>> {
    let module = PathBuf::from(module);
    let wasm = fs::read(&module)?;
    let export = task_export(&wasm, task)?;
    let published = Arc::new(Mutex::new(None));
    let executed_command = Arc::new(Mutex::new(None));
    let result = WasmtimeTaskRuntime::new()?.run_task_export_verified_with_task_host(
        &wasm,
        &Digest::sha256(&wasm),
        &export,
        &WasmTaskInvocation::new(
            clusterflux_core::TaskDefinitionId::from(task),
            clusterflux_core::TaskInstanceId::new(format!("{task}-1")),
            vec![TaskBoundaryValue::SourceSnapshot(Digest::sha256(
                "standalone-source-snapshot",
            ))],
        ),
        Box::new(ArtifactRecordingHost {
            published: Arc::clone(&published),
            executed_command: Arc::clone(&executed_command),
            allow_command: true,
        }),
    )?;
    if result.outcome != WasmTaskOutcome::Completed {
        return Err(format!("command task failed: {:?}", result.error).into());
    }
    let Some(TaskBoundaryValue::Artifact(result_artifact)) = result.result else {
        return Err("command task did not return its published Artifact handle".into());
    };
    let (request, command_result) = executed_command
        .lock()
        .map_err(|_| "command recording host lock was poisoned")?
        .clone()
        .ok_or("Wasm task did not invoke clusterflux.command_run_v1")?;
    let (artifact_name, host_artifact) = published
        .lock()
        .map_err(|_| "artifact recording host lock was poisoned")?
        .clone()
        .ok_or("command task did not publish its command output")?;
    if result_artifact != host_artifact {
        return Err("command task returned a handle other than the published artifact".into());
    }

    println!(
        "{}",
        serde_json::to_string(&json!({
            "type": "wasmtime_host_command_smoke",
            "module": module,
            "task": task,
            "export": export,
            "program": request.program,
            "args": request.args,
            "working_directory": request.working_directory,
            "environment_variables": request.environment_variables,
            "timeout_ms": request.timeout_ms,
            "network": request.network,
            "status_code": command_result.status_code,
            "stdout": command_result.stdout,
            "artifact": result_artifact,
            "artifact_name": artifact_name,
            "artifact_digest": host_artifact.digest,
            "artifact_size_bytes": host_artifact.size_bytes,
            "node_host_import": "clusterflux.command_run_v1",
            "artifact_host_import": "clusterflux.vfs_operation_v1",
            "flagship_linux_build_task": true,
            "node_executed_host_command": true,
            "hosted_control_plane_ran_command": false,
        }))?
    );
    Ok(())
}
