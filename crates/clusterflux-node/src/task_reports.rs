use clusterflux_core::{AssignmentAuthority, TaskBoundaryValue, TaskInstanceId, VfsManifest};
use clusterflux_node::CommandOutput;
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse, TaskTerminalState};
use serde_json::{json, Value};
use std::time::Duration;

use crate::assignment_runner::NativeCommandLogSnapshot;
use crate::daemon::RuntimeTask;
use crate::{
    coordinator_session::CoordinatorSession,
    daemon::Args,
    node_identity::{signed_node_assignment_operation_request, signed_node_assignment_request},
    task_artifacts::RetainedArtifact,
};

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_completed_task(
    args: &Args,
    session: &mut CoordinatorSession,
    task: RuntimeTask,
    mut output: CommandOutput,
    manifest: VfsManifest,
    result: Option<TaskBoundaryValue>,
    retained: Vec<RetainedArtifact>,
    registration: Value,
    heartbeat: Value,
    capability_report: Value,
    debug_command: Value,
    node_private_key: &str,
) -> Result<Value, Box<dyn std::error::Error>> {
    let staged = output.staged_artifact.as_ref();
    let direct_result_artifact = match &result {
        Some(TaskBoundaryValue::Artifact(artifact)) => Some(&artifact.id),
        _ => None,
    };
    let primary_retained =
        direct_result_artifact.and_then(|id| retained.iter().find(|artifact| &artifact.id == id));
    let artifact_digest = primary_retained
        .map(|artifact| artifact.digest.clone())
        .or_else(|| staged.map(|artifact| artifact.digest.clone()));
    let artifact_path = primary_retained
        .map(|artifact| format!("/vfs/artifacts/{}", artifact.id))
        .or_else(|| staged.map(|artifact| artifact.path.as_str().to_owned()));
    let artifact_size_bytes = primary_retained
        .map(|artifact| artifact.size_bytes)
        .or_else(|| staged.map(|artifact| artifact.size));
    let (log_event, final_log_failed) =
        report_final_log_best_effort(args, &task, node_private_key, &output);
    output.stdout_truncated |= final_log_failed;
    output.stderr_truncated |= final_log_failed;
    let mut metadata = retained
        .iter()
        .map(|artifact| {
            (
                Some(format!("/vfs/artifacts/{}", artifact.id)),
                Some(artifact.digest.clone()),
                Some(artifact.size_bytes),
            )
        })
        .collect::<Vec<_>>();
    if let Some(staged) = staged {
        let path = staged.path.as_str().to_owned();
        if !metadata
            .iter()
            .any(|(artifact_path, _, _)| artifact_path.as_deref() == Some(path.as_str()))
        {
            metadata.push((Some(path), Some(staged.digest.clone()), Some(staged.size)));
        }
    }
    if metadata.is_empty() {
        metadata.push((None, None, None));
    }
    let mut vfs_metadata = Vec::with_capacity(metadata.len());
    for (path, digest, size_bytes) in metadata {
        let response = request_terminal_mutation(
            session,
            args,
            node_private_key,
            &task.assignment_authority,
            "report_vfs_metadata",
            CoordinatorRequest::ReportVfsMetadata {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                process: task.process.clone(),
                node: args.node.clone(),
                task: task.task.clone(),
                artifact_path: path,
                artifact_digest: digest,
                artifact_size_bytes: size_bytes,
                large_bytes_uploaded: manifest.large_bytes_uploaded,
            },
        )?;
        match response {
            response @ CoordinatorResponse::VfsMetadataRecorded { .. } => {
                vfs_metadata.push(serde_json::to_value(response)?);
            }
            _ => return Err("coordinator returned an unexpected VFS metadata response".into()),
        }
    }
    let vfs_metadata = if vfs_metadata.len() == 1 {
        vfs_metadata
            .pop()
            .expect("one VFS metadata response exists")
    } else {
        Value::Array(vfs_metadata)
    };
    let recorded = request_terminal_mutation(
        session,
        args,
        node_private_key,
        &task.assignment_authority,
        "task_completed",
        CoordinatorRequest::TaskCompleted {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            process: task.process.clone(),
            node: args.node.clone(),
            task: task.task.clone(),
            terminal_state: None,
            status_code: output.status_code,
            stdout_bytes: output.stdout_source_bytes,
            stderr_bytes: output.stderr_source_bytes,
            stdout_tail: output.stdout.clone(),
            stderr_tail: output.stderr.clone(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
            artifact_path,
            artifact_digest,
            artifact_size_bytes,
            result,
        },
    )?;
    let recorded = match recorded {
        response @ CoordinatorResponse::TaskRecorded { .. } => serde_json::to_value(response)?,
        _ => return Err("coordinator returned an unexpected task-completion response".into()),
    };
    Ok(completed_node_report(
        output,
        manifest.large_bytes_uploaded,
        registration,
        heartbeat,
        capability_report,
        debug_command,
        log_event,
        vfs_metadata,
        recorded,
        session.requests(),
    ))
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_failed_task(
    args: &Args,
    session: &mut CoordinatorSession,
    task: &RuntimeTask,
    registration: Value,
    heartbeat: Value,
    capability_report: Value,
    debug_command: Value,
    node_private_key: &str,
    error: &str,
    mut logs: NativeCommandLogSnapshot,
) -> Result<Value, Box<dyn std::error::Error>> {
    let error = bounded_runtime_error(error);
    logs.stderr_source_bytes = logs.stderr_source_bytes.saturating_add(error.len() as u64);
    logs.stderr_truncated |= append_bounded_runtime_error(&mut logs.stderr, &error);
    let mut output = CommandOutput {
        virtual_thread: clusterflux_core::TaskInstanceId::from(task.task.as_str()),
        status_code: Some(-1),
        stdout: logs.stdout,
        stderr: logs.stderr,
        stdout_source_bytes: logs.stdout_source_bytes,
        stderr_source_bytes: logs.stderr_source_bytes,
        stdout_truncated: logs.stdout_truncated,
        stderr_truncated: logs.stderr_truncated,
        log_backpressured: logs.log_backpressured,
        staged_artifact: None,
    };
    let (log_event, final_log_failed) =
        report_final_log_best_effort(args, task, node_private_key, &output);
    output.stdout_truncated |= final_log_failed;
    output.stderr_truncated |= final_log_failed;
    let vfs_metadata = request_terminal_mutation(
        session,
        args,
        node_private_key,
        &task.assignment_authority,
        "report_vfs_metadata",
        CoordinatorRequest::ReportVfsMetadata {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            process: task.process.clone(),
            node: args.node.clone(),
            task: task.task.clone(),
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            large_bytes_uploaded: false,
        },
    )?;
    let vfs_metadata = match vfs_metadata {
        response @ CoordinatorResponse::VfsMetadataRecorded { .. } => {
            serde_json::to_value(response)?
        }
        _ => return Err("coordinator returned an unexpected VFS metadata response".into()),
    };
    let recorded = request_terminal_mutation(
        session,
        args,
        node_private_key,
        &task.assignment_authority,
        "task_completed",
        CoordinatorRequest::TaskCompleted {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            process: task.process.clone(),
            node: args.node.clone(),
            task: task.task.clone(),
            terminal_state: Some(TaskTerminalState::Failed),
            status_code: Some(-1),
            stdout_bytes: output.stdout_source_bytes,
            stderr_bytes: output.stderr_source_bytes,
            stdout_tail: output.stdout.clone(),
            stderr_tail: output.stderr.clone(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: None,
        },
    )?;
    let recorded = match recorded {
        response @ CoordinatorResponse::TaskRecorded { .. } => serde_json::to_value(response)?,
        _ => return Err("coordinator returned an unexpected task-completion response".into()),
    };
    Ok(failed_node_report(
        task,
        &output,
        registration,
        heartbeat,
        capability_report,
        debug_command,
        log_event,
        vfs_metadata,
        recorded,
        session.requests(),
    ))
}

fn report_final_log_best_effort(
    args: &Args,
    task: &RuntimeTask,
    node_private_key: &str,
    output: &CommandOutput,
) -> (Value, bool) {
    let result = (|| -> Result<Value, Box<dyn std::error::Error>> {
        let mut log_session = CoordinatorSession::connect_with_timeouts(
            &args.coordinator,
            Duration::from_secs(1),
            Duration::from_secs(3),
        )?;
        let response = log_session.request(signed_node_assignment_request(
            args,
            node_private_key,
            &task.assignment_authority,
            "report_task_log",
            CoordinatorRequest::ReportTaskLog {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                process: task.process.clone(),
                node: args.node.clone(),
                task: task.task.clone(),
                stdout_bytes: output.stdout_source_bytes,
                stderr_bytes: output.stderr_source_bytes,
                stdout_tail: output.stdout.clone(),
                stderr_tail: output.stderr.clone(),
                stdout_truncated: output.stdout_truncated,
                stderr_truncated: output.stderr_truncated,
                backpressured: output.log_backpressured,
            },
        )?)?;
        match response {
            response @ CoordinatorResponse::TaskLogRecorded { .. } => {
                Ok(serde_json::to_value(response)?)
            }
            _ => Err("coordinator returned an unexpected task-log response".into()),
        }
    })();
    match result {
        Ok(response) => (response, false),
        Err(error) => (
            json!({
                "type": "task_log_report_unavailable",
                "retryable": true,
                "message": format!(
                    "final log submission failed; task completion continued and some output may be unavailable: {error}"
                ),
            }),
            true,
        ),
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn record_cancelled_task(
    args: &Args,
    session: &mut CoordinatorSession,
    task: &RuntimeTask,
    registration: Value,
    heartbeat: Value,
    capability_report: Value,
    debug_command: Value,
    node_private_key: &str,
    mut output: NativeCommandLogSnapshot,
) -> Result<Value, Box<dyn std::error::Error>> {
    let command_output = CommandOutput {
        virtual_thread: TaskInstanceId::from(task.task.as_str()),
        status_code: None,
        stdout: output.stdout.clone(),
        stderr: output.stderr.clone(),
        stdout_source_bytes: output.stdout_source_bytes,
        stderr_source_bytes: output.stderr_source_bytes,
        stdout_truncated: output.stdout_truncated,
        stderr_truncated: output.stderr_truncated,
        log_backpressured: output.log_backpressured,
        staged_artifact: None,
    };
    let (log_event, final_log_failed) =
        report_final_log_best_effort(args, task, node_private_key, &command_output);
    output.stdout_truncated |= final_log_failed;
    output.stderr_truncated |= final_log_failed;
    let recorded = request_terminal_mutation(
        session,
        args,
        node_private_key,
        &task.assignment_authority,
        "task_completed",
        CoordinatorRequest::TaskCompleted {
            tenant: args.tenant.clone(),
            project: args.project.clone(),
            process: task.process.clone(),
            node: args.node.clone(),
            task: task.task.clone(),
            terminal_state: Some(TaskTerminalState::Cancelled),
            status_code: None,
            stdout_bytes: output.stdout_source_bytes,
            stderr_bytes: output.stderr_source_bytes,
            stdout_tail: output.stdout.clone(),
            stderr_tail: output.stderr.clone(),
            stdout_truncated: output.stdout_truncated,
            stderr_truncated: output.stderr_truncated,
            artifact_path: None,
            artifact_digest: None,
            artifact_size_bytes: None,
            result: None,
        },
    )?;
    let recorded = match recorded {
        response @ CoordinatorResponse::TaskRecorded { .. } => serde_json::to_value(response)?,
        _ => return Err("coordinator returned an unexpected task-completion response".into()),
    };
    Ok(cancelled_node_report(
        task,
        &output,
        registration,
        heartbeat,
        capability_report,
        debug_command,
        log_event,
        recorded,
        session.requests(),
    ))
}

fn request_terminal_mutation(
    session: &mut CoordinatorSession,
    args: &Args,
    node_private_key: &str,
    authority: &AssignmentAuthority,
    request_kind: &str,
    request: CoordinatorRequest,
) -> Result<CoordinatorResponse, Box<dyn std::error::Error>> {
    let operation_id = clusterflux_core::generate_opaque_token("node_operation")?;
    session.request_signed(|| {
        signed_node_assignment_operation_request(
            args,
            node_private_key,
            authority,
            request_kind,
            &operation_id,
            request.clone(),
        )
    })
}

fn bounded_runtime_error(error: &str) -> String {
    const MAX_BYTES: usize = 16 * 1024;
    if error.len() <= MAX_BYTES {
        return error.to_owned();
    }
    let boundary = error
        .char_indices()
        .take_while(|(index, _)| *index <= MAX_BYTES)
        .map(|(index, _)| index)
        .last()
        .unwrap_or(0);
    format!("{}\n<truncated>", &error[..boundary])
}

fn append_bounded_runtime_error(stderr: &mut String, error: &str) -> bool {
    const MAX_BYTES: usize = clusterflux_node::DEFAULT_COMMAND_LOG_LIMIT_BYTES;
    if !stderr.is_empty() && !stderr.ends_with('\n') {
        stderr.push('\n');
    }
    stderr.push_str(error);
    if stderr.len() <= MAX_BYTES {
        return false;
    }
    let mut start = stderr.len().saturating_sub(MAX_BYTES);
    while start < stderr.len() && !stderr.is_char_boundary(start) {
        start += 1;
    }
    *stderr = stderr[start..].to_owned();
    true
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn completed_node_report(
    output: CommandOutput,
    large_bytes_uploaded: bool,
    registration_response: Value,
    heartbeat_response: Value,
    capability_response: Value,
    debug_command_response: Value,
    log_event_response: Value,
    vfs_metadata_response: Value,
    coordinator_response: Value,
    session_requests: usize,
) -> Value {
    json!({
        "node_status": "completed",
        "virtual_thread": output.virtual_thread,
        "terminal_state": if output.status_code == Some(0) { "completed" } else { "failed" },
        "status_code": output.status_code,
        "stdout_bytes": output.stdout_source_bytes,
        "stderr_bytes": output.stderr_source_bytes,
        "stdout_tail": &output.stdout,
        "stderr_tail": &output.stderr,
        "stdout_truncated": output.stdout_truncated,
        "stderr_truncated": output.stderr_truncated,
        "log_backpressured": output.log_backpressured,
        "staged_artifact": output.staged_artifact,
        "large_bytes_uploaded": large_bytes_uploaded,
        "registration_response": registration_response,
        "heartbeat_response": heartbeat_response,
        "capability_response": capability_response,
        "debug_command_response": debug_command_response,
        "log_event_response": log_event_response,
        "vfs_metadata_response": vfs_metadata_response,
        "session_requests": session_requests,
        "coordinator_response": coordinator_response,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn cancelled_node_report(
    task: &RuntimeTask,
    output: &NativeCommandLogSnapshot,
    registration_response: Value,
    heartbeat_response: Value,
    capability_response: Value,
    debug_command_response: Value,
    log_event_response: Value,
    coordinator_response: Value,
    session_requests: usize,
) -> Value {
    json!({
        "node_status": "cancelled",
        "virtual_thread": &task.task,
        "terminal_state": "cancelled",
        "status_code": null,
        "stdout_bytes": output.stdout_source_bytes,
        "stderr_bytes": output.stderr_source_bytes,
        "stdout_tail": &output.stdout,
        "stderr_tail": &output.stderr,
        "stdout_truncated": output.stdout_truncated,
        "stderr_truncated": output.stderr_truncated,
        "log_backpressured": output.log_backpressured,
        "staged_artifact": null,
        "large_bytes_uploaded": false,
        "registration_response": registration_response,
        "heartbeat_response": heartbeat_response,
        "capability_response": capability_response,
        "debug_command_response": debug_command_response,
        "log_event_response": log_event_response,
        "vfs_metadata_response": null,
        "session_requests": session_requests,
        "coordinator_response": coordinator_response,
    })
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn failed_node_report(
    task: &RuntimeTask,
    output: &CommandOutput,
    registration_response: Value,
    heartbeat_response: Value,
    capability_response: Value,
    debug_command_response: Value,
    log_event_response: Value,
    vfs_metadata_response: Value,
    coordinator_response: Value,
    session_requests: usize,
) -> Value {
    json!({
        "node_status": "failed",
        "virtual_thread": &task.task,
        "terminal_state": "failed",
        "status_code": -1,
        "stdout_bytes": output.stdout_source_bytes,
        "stderr_bytes": output.stderr_source_bytes,
        "stdout_tail": &output.stdout,
        "stderr_tail": &output.stderr,
        "stdout_truncated": output.stdout_truncated,
        "stderr_truncated": output.stderr_truncated,
        "log_backpressured": output.log_backpressured,
        "staged_artifact": null,
        "large_bytes_uploaded": false,
        "registration_response": registration_response,
        "heartbeat_response": heartbeat_response,
        "capability_response": capability_response,
        "debug_command_response": debug_command_response,
        "log_event_response": log_event_response,
        "vfs_metadata_response": vfs_metadata_response,
        "session_requests": session_requests,
        "coordinator_response": coordinator_response,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use clusterflux_core::{
        ArtifactHandle, ArtifactId, Digest, NodeId, ProcessId, StructuredTaskBoundary,
        TaskBoundaryHandle, TaskInstanceId, VfsPath,
    };
    use clusterflux_protocol::CoordinatorResponse;
    use std::collections::BTreeMap;
    use std::io::{BufRead, BufReader, Write};
    use std::net::TcpListener;
    use std::sync::mpsc;
    use std::thread;

    #[test]
    fn completed_report_uses_source_counts_instead_of_bounded_tail_lengths() {
        let report = completed_node_report(
            CommandOutput {
                virtual_thread: TaskInstanceId::from("task"),
                status_code: Some(0),
                stdout: "bounded tail".to_owned(),
                stderr: String::new(),
                stdout_source_bytes: 519,
                stderr_source_bytes: 0,
                stdout_truncated: true,
                stderr_truncated: false,
                log_backpressured: false,
                staged_artifact: None,
            },
            false,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            1,
        );

        assert_eq!(report["stdout_bytes"], 519);
        assert_eq!(report["stdout_tail"], "bounded tail");
        assert!(report.get("task_assignment_response").is_none());
    }

    #[test]
    fn failed_final_log_submission_does_not_block_vfs_or_task_completion() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let coordinator = listener.local_addr().unwrap().to_string();
        let (requests_sender, requests_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (main_stream, _) = listener.accept().unwrap();
            let main_handler = thread::spawn(move || {
                let mut writer = main_stream.try_clone().unwrap();
                let mut reader = BufReader::new(main_stream);
                let responses = [
                    CoordinatorResponse::VfsMetadataRecorded {
                        process: ProcessId::from("process"),
                        task: TaskInstanceId::from("task"),
                        artifact_path: None,
                        large_bytes_uploaded: false,
                    },
                    CoordinatorResponse::TaskRecorded {
                        process: ProcessId::from("process"),
                        task: TaskInstanceId::from("task"),
                        events_recorded: 1,
                    },
                ];
                for response in responses {
                    let mut request = String::new();
                    reader.read_line(&mut request).unwrap();
                    requests_sender.send(request).unwrap();
                    serde_json::to_writer(&mut writer, &response).unwrap();
                    writer.write_all(b"\n").unwrap();
                }
            });
            let (log_stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(log_stream).read_line(&mut request).unwrap();
            // Drop the dedicated final-log connection without a response.
            main_handler.join().unwrap();
        });
        let args = Args {
            coordinator: coordinator.clone(),
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
            worker: true,
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
        };
        let task = RuntimeTask {
            process: "process".to_owned(),
            task: "task".to_owned(),
            epoch: None,
            task_spec: None,
            bundle_digest: None,
            wasm_module_base64: None,
            assignment_authority: clusterflux_core::AssignmentAuthority {
                assignment_id: "report-test-assignment".to_owned(),
                attempt_id: "report-test-attempt".to_owned(),
                offer_epoch: 1,
            },
        };
        let output = CommandOutput {
            virtual_thread: TaskInstanceId::from("task"),
            status_code: Some(0),
            stdout: "compiler output".to_owned(),
            stderr: String::new(),
            stdout_source_bytes: 15,
            stderr_source_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            log_backpressured: false,
            staged_artifact: None,
        };
        let manifest = VfsManifest {
            epoch: 1,
            producer: TaskInstanceId::from("task"),
            node: NodeId::from("node"),
            objects: BTreeMap::new(),
            large_bytes_uploaded: false,
        };
        let mut session = CoordinatorSession::connect(&coordinator).unwrap();
        let report = record_completed_task(
            &args,
            &mut session,
            task,
            output,
            manifest,
            Some(TaskBoundaryValue::SmallJson(json!(42))),
            Vec::new(),
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            &clusterflux_core::derive_ed25519_private_key_from_seed("final-log-test"),
        )
        .unwrap();
        server.join().unwrap();
        let requests = requests_receiver.into_iter().collect::<Vec<_>>();

        assert_eq!(report["node_status"], "completed");
        assert_eq!(
            report["log_event_response"]["type"],
            "task_log_report_unavailable"
        );
        assert_eq!(report["stdout_truncated"], true);
        assert_eq!(requests.len(), 2);
        assert!(requests[0].contains("report_vfs_metadata"));
        assert!(requests[1].contains("task_completed"));
        assert!(requests[1].contains("\"stdout_truncated\":true"));
    }

    #[test]
    fn completed_structured_result_reports_every_artifact_before_completion() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let coordinator = listener.local_addr().unwrap().to_string();
        let (requests_sender, requests_receiver) = mpsc::channel();
        let server = thread::spawn(move || {
            let (main_stream, _) = listener.accept().unwrap();
            let main_handler = thread::spawn(move || {
                let mut writer = main_stream.try_clone().unwrap();
                let mut reader = BufReader::new(main_stream);
                let responses = [
                    CoordinatorResponse::VfsMetadataRecorded {
                        process: ProcessId::from("process"),
                        task: TaskInstanceId::from("task"),
                        artifact_path: Some(VfsPath::new("/vfs/artifacts/archive-digest").unwrap()),
                        large_bytes_uploaded: false,
                    },
                    CoordinatorResponse::VfsMetadataRecorded {
                        process: ProcessId::from("process"),
                        task: TaskInstanceId::from("task"),
                        artifact_path: Some(
                            VfsPath::new("/vfs/artifacts/checksums-digest").unwrap(),
                        ),
                        large_bytes_uploaded: false,
                    },
                    CoordinatorResponse::TaskRecorded {
                        process: ProcessId::from("process"),
                        task: TaskInstanceId::from("task"),
                        events_recorded: 1,
                    },
                ];
                for response in responses {
                    let mut request = String::new();
                    reader.read_line(&mut request).unwrap();
                    requests_sender.send(request).unwrap();
                    serde_json::to_writer(&mut writer, &response).unwrap();
                    writer.write_all(b"\n").unwrap();
                }
            });
            let (log_stream, _) = listener.accept().unwrap();
            let mut request = String::new();
            BufReader::new(log_stream).read_line(&mut request).unwrap();
            main_handler.join().unwrap();
        });
        let args = Args {
            coordinator: coordinator.clone(),
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
            worker: true,
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
        };
        let task = RuntimeTask {
            process: "process".to_owned(),
            task: "task".to_owned(),
            epoch: None,
            task_spec: None,
            bundle_digest: None,
            wasm_module_base64: None,
            assignment_authority: clusterflux_core::AssignmentAuthority {
                assignment_id: "multi-report-assignment".to_owned(),
                attempt_id: "multi-report-attempt".to_owned(),
                offer_epoch: 1,
            },
        };
        let archive = RetainedArtifact {
            id: ArtifactId::from("archive-digest"),
            digest: Digest::sha256("archive"),
            size_bytes: 7,
            path: std::path::PathBuf::new(),
        };
        let checksums = RetainedArtifact {
            id: ArtifactId::from("checksums-digest"),
            digest: Digest::sha256("checksums"),
            size_bytes: 9,
            path: std::path::PathBuf::new(),
        };
        let handles = [&archive, &checksums]
            .into_iter()
            .map(|artifact| {
                TaskBoundaryHandle::Artifact(ArtifactHandle {
                    id: artifact.id.clone(),
                    digest: artifact.digest.clone(),
                    size_bytes: artifact.size_bytes,
                })
            })
            .collect();
        let result = TaskBoundaryValue::Structured(StructuredTaskBoundary {
            value: json!({
                "archive": {"$task_handle": {"index": 0, "kind": "artifact"}},
                "checksums": {"$task_handle": {"index": 1, "kind": "artifact"}},
            }),
            handles,
        });
        let output = CommandOutput {
            virtual_thread: TaskInstanceId::from("task"),
            status_code: Some(0),
            stdout: String::new(),
            stderr: String::new(),
            stdout_source_bytes: 0,
            stderr_source_bytes: 0,
            stdout_truncated: false,
            stderr_truncated: false,
            log_backpressured: false,
            staged_artifact: None,
        };
        let manifest = VfsManifest {
            epoch: 1,
            producer: TaskInstanceId::from("task"),
            node: NodeId::from("node"),
            objects: BTreeMap::new(),
            large_bytes_uploaded: false,
        };
        let mut session = CoordinatorSession::connect(&coordinator).unwrap();
        let report = record_completed_task(
            &args,
            &mut session,
            task,
            output,
            manifest,
            Some(result),
            vec![archive, checksums],
            Value::Null,
            Value::Null,
            Value::Null,
            Value::Null,
            &clusterflux_core::derive_ed25519_private_key_from_seed("multi-report-test"),
        )
        .unwrap();
        server.join().unwrap();
        let requests = requests_receiver.into_iter().collect::<Vec<_>>();

        assert_eq!(report["vfs_metadata_response"].as_array().unwrap().len(), 2);
        assert_eq!(requests.len(), 3);
        assert!(requests[0].contains("/vfs/artifacts/archive-digest"));
        assert!(requests[1].contains("/vfs/artifacts/checksums-digest"));
        assert!(requests[2].contains("task_completed"));
        assert!(requests[2].contains("\"artifact_path\":null"));
    }
}
