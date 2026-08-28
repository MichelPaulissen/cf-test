#![allow(clippy::field_reassign_with_default)]

use std::fs;
use std::io::Cursor;

use clusterflux_core::{
    ProcessId, ProjectId, SourceLocation, TaskDefinitionId, TaskInstanceId, TenantId, UserId,
};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse, DebugAuditEvent};
use serde_json::json;

use super::*;

#[test]
fn reads_standard_dap_content_length_frame_from_generic_client() {
    let payload = json!({
        "seq": 7,
        "type": "request",
        "command": "threads"
    })
    .to_string();
    let frame = format!("Content-Length: {}\r\n\r\n{payload}", payload.len());
    let mut reader = Cursor::new(frame.into_bytes());

    let message = read_message(&mut reader)
        .unwrap()
        .expect("DAP frame should contain a request");

    assert_eq!(message["seq"], 7);
    assert_eq!(message["type"], "request");
    assert_eq!(message["command"], "threads");
}

#[test]
fn initialize_capabilities_use_standard_dap_flags() {
    let capabilities = initialize_capabilities();
    let capabilities = capabilities
        .as_object()
        .expect("initialize capabilities should be an object");

    assert_eq!(
        capabilities.get("supportsConfigurationDoneRequest"),
        Some(&json!(true))
    );
    assert_eq!(capabilities.get("supportsRestartFrame"), Some(&json!(true)));
    assert_eq!(capabilities.get("supportsStepBack"), Some(&json!(false)));
    assert!(capabilities
        .keys()
        .all(|key| key.starts_with("supports") && !key.contains("clusterflux")));
}

#[test]
fn stale_breakpoint_success_and_failure_completions_are_not_current() {
    assert!(crate::adapter::breakpoint_update_is_current(4, 4, 9, 9));
    assert!(!crate::adapter::breakpoint_update_is_current(4, 4, 8, 9));
    assert!(!crate::adapter::breakpoint_update_is_current(3, 4, 9, 9));
}

#[test]
fn runtime_backend_defaults_to_local_services_and_requires_explicit_demo() {
    assert_eq!(
        runtime_backend_from_launch_arg(None).unwrap(),
        RuntimeBackend::LocalServices
    );
    assert_eq!(
        runtime_backend_from_launch_arg(Some("simulated")).unwrap(),
        RuntimeBackend::Simulated
    );
    assert_eq!(
        runtime_backend_from_launch_arg(Some("demo")).unwrap(),
        RuntimeBackend::Simulated
    );
    assert!(runtime_backend_from_launch_arg(Some("unknown")).is_err());
}

#[test]
fn live_dap_uses_matching_stored_cli_session_and_omits_claimed_scope() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("examples/demo");
    fs::create_dir_all(temp.path().join(".clusterflux-state")).unwrap();
    fs::create_dir_all(&project).unwrap();
    fs::write(
        temp.path().join(".clusterflux-state/session.json"),
        serde_json::to_vec(&json!({
            "coordinator": "https://hosted.example.test",
            "tenant": "tenant-session",
            "project": "project-session",
            "user": "user-session",
            "session_secret": "dap-session-secret"
        }))
        .unwrap(),
    )
    .unwrap();

    let mut state = AdapterState::default();
    state
        .configure_launch(
            project.to_string_lossy().into_owned(),
            Some("build".to_owned()),
            RuntimeBackend::LiveServices,
            Some("https://hosted.example.test/".to_owned()),
            None,
        )
        .unwrap();
    assert_eq!(state.tenant.as_str(), "tenant-session");
    assert_eq!(state.project_id.as_str(), "project-session");
    assert_eq!(state.actor_user.as_str(), "user-session");
    assert_eq!(
        state.client_session_secret.as_deref(),
        Some("dap-session-secret")
    );

    let request = client_user_request(
        &state,
        CoordinatorRequest::DebugAttach {
            tenant: "forged-tenant".to_owned(),
            project: "forged-project".to_owned(),
            actor_user: "forged-user".to_owned(),
            process: "vp".to_owned(),
        },
    );
    let request = serde_json::to_value(request).unwrap();
    assert_eq!(request["type"], "authenticated");
    assert_eq!(request["session_secret"], "dap-session-secret");
    assert_eq!(request["request"]["type"], "debug_attach");
    assert!(request["request"].get("tenant").is_none());
    assert!(request["request"].get("project").is_none());
    assert!(request["request"].get("actor_user").is_none());

    let mismatch = state.configure_launch(
        project.to_string_lossy().into_owned(),
        Some("build".to_owned()),
        RuntimeBackend::LiveServices,
        Some("https://different.example.test".to_owned()),
        None,
    );
    assert!(mismatch
        .unwrap_err()
        .to_string()
        .contains("does not match the authenticated CLI session"));
}

#[test]
fn local_dap_does_not_inherit_hosted_project_scope() {
    let temp = tempfile::tempdir().unwrap();
    let project = temp.path().join("examples/demo");
    fs::create_dir_all(temp.path().join(".clusterflux-state")).unwrap();
    fs::create_dir_all(&project).unwrap();
    fs::write(
        temp.path().join(".clusterflux-state/project.json"),
        serde_json::to_vec(&json!({
            "coordinator": "https://hosted.example.test",
            "tenant": "tenant-hosted",
            "project": "project-hosted",
            "user": "user-hosted"
        }))
        .unwrap(),
    )
    .unwrap();

    let mut state = AdapterState::default();
    state
        .configure_launch(
            project.to_string_lossy().into_owned(),
            Some("build".to_owned()),
            RuntimeBackend::LocalServices,
            None,
            None,
        )
        .unwrap();

    assert_eq!(state.tenant.as_str(), "tenant");
    assert_eq!(state.project_id.as_str(), "project");
    assert_eq!(state.actor_user.as_str(), "dap");
}

#[test]
fn compatible_restart_frame_does_not_require_whole_process_restart() {
    let request = json!({
        "command": "restartFrame",
        "arguments": {
            "frameId": 1,
            "sourceEdit": {
                "compatibility": "compatible"
            }
        }
    });

    assert!(!restart_requires_whole_process(&request));
}

#[test]
fn incompatible_source_edit_requires_whole_process_restart() {
    for arguments in [
        json!({ "sourceCompatibility": "incompatible" }),
        json!({ "sourceEdit": { "compatibility": "whole-process" } }),
        json!({ "requiresWholeProcessRestart": true }),
    ] {
        let request = json!({
            "command": "restartFrame",
            "arguments": arguments,
        });

        assert!(restart_requires_whole_process(&request));
    }
}

#[test]
fn task_restart_response_preserves_coordinator_boundary_decision() {
    let process = ProcessId::from("process");
    let task = TaskInstanceId::from("task");
    let actor = UserId::from("user");
    let record = parse_task_restart_response(CoordinatorResponse::TaskRestart {
        process: process.clone(),
        task: task.clone(),
        restarted_task_instance: None,
        restarted_attempt_id: None,
        actor: actor.clone(),
        accepted: false,
        clean_boundary_available: false,
        requires_whole_process_restart: true,
        active_task: false,
        completed_event_observed: true,
        message: "selected task has only terminal event metadata; restart requires a captured checkpoint boundary".to_owned(),
        audit_event: DebugAuditEvent {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process,
            task: Some(task),
            actor,
            operation: "task_restart".to_owned(),
            allowed: false,
            reason: "no checkpoint".to_owned(),
            charged_debug_read_bytes: 0,
            used_debug_read_bytes: 0,
        },
        charged_debug_read_bytes: 0,
        used_debug_read_bytes: 0,
    })
    .unwrap();

    assert!(!record.accepted);
    assert!(!record.clean_boundary_available);
    assert!(record.requires_whole_process_restart);
    assert!(!record.active_task);
    assert!(record.completed_event_observed);
    assert!(record.message.contains("checkpoint boundary"));
}

#[test]
fn nonzero_local_runtime_record_marks_linux_task_failed() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LocalServices;

    state.apply_runtime_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:7999".to_owned(),
        node: "node".to_owned(),
        node_report: json!({
            "task_snapshots": { "snapshots": [{
                "task": "compile-linux-1",
                "task_definition": "compile-linux",
                "attempt_id": "attempt-1",
                "current": true,
                "state": "failed_awaiting_action"
            }] },
            "terminal_event": {
                "task": "compile-linux-1",
                "task_definition": "compile-linux"
            }
        }),
        task_events: json!({ "events": [] }),
        placed_task_launched: true,
        status_code: Some(1),
        stdout_bytes: 0,
        stderr_bytes: 12,
        stdout_tail: String::new(),
        stderr_tail: "failed".to_owned(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        event_count: 1,
        debug_epoch: None,
        stopped_task: Some("compile-linux-1".to_owned()),
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch: None,
        all_participants_frozen: false,
    });
    let exact_runtime_thread = state
        .threads
        .values()
        .find(|thread| thread.task == TaskInstanceId::from("compile-linux-1"))
        .expect("the exact terminal task instance should have its own thread");

    assert!(state.last_task_failed);
    assert!(state
        .command_status
        .contains("failed through local services"));
    assert!(matches!(
        exact_runtime_thread.state,
        DebugRuntimeState::Failed(_)
    ));
    assert!(exact_runtime_thread
        .recent_output
        .iter()
        .any(|line| line.contains("task failed")));
    assert_eq!(
        stopped_thread_for_breakpoint(&state),
        exact_runtime_thread.id,
        "a non-debug exception stop must identify the exact failed task"
    );
    assert_eq!(state.threads.len(), 1);
}

#[test]
fn freeze_all_reports_failure_without_claiming_all_stop() {
    let mut state = AdapterState::default();
    state
        .threads
        .get_mut(&PACKAGE_THREAD)
        .expect("package thread should exist")
        .freeze_supported = false;

    let error = freeze_all(&mut state, LINUX_THREAD, None).unwrap_err();

    assert_eq!(error.thread_id, PACKAGE_THREAD);
    assert_eq!(error.task, TaskInstanceId::from("package-release"));
    assert!(error.message().contains("could not freeze"));
    assert_eq!(state.epoch, 0);
    assert!(state
        .threads
        .values()
        .all(|thread| thread.state == DebugRuntimeState::Running));
}

#[test]
fn freeze_all_success_freezes_every_running_participant() {
    let mut state = AdapterState::default();

    freeze_all(&mut state, LINUX_THREAD, None).unwrap();

    assert_eq!(state.epoch, 1);
    assert!(state
        .threads
        .values()
        .all(|thread| thread.state == DebugRuntimeState::Frozen));
}

#[test]
fn breakpoint_line_selects_main_or_spawned_virtual_thread() {
    let mut state = AdapterState::default();
    let location = |line| SourceLocation {
        source_path: "src/lib.rs".to_owned(),
        line,
        column: None,
        probe_id: String::new(),
    };

    state
        .breakpoints_by_source
        .insert("src/lib.rs".to_owned(), vec![location(12)]);
    assert_eq!(stopped_thread_for_breakpoint(&state), MAIN_THREAD);

    state
        .breakpoints_by_source
        .insert("src/lib.rs".to_owned(), vec![location(42)]);
    assert_eq!(stopped_thread_for_breakpoint(&state), LINUX_THREAD);
}

#[test]
fn breakpoint_resolution_uses_bundle_debug_probe_metadata() {
    let mut state = AdapterState::default();
    state.debug_probes = vec![BundleDebugProbe {
        id: "probe-linux".to_owned(),
        probe_symbol: "clusterflux.probe.linux".to_owned(),
        source_path: "src/lib.rs".to_owned(),
        line_start: 20,
        line_end: 30,
        function: "compile_linux".to_owned(),
        task: clusterflux_core::TaskDefinitionId::from("compile-linux"),
    }];

    let resolved = resolve_breakpoints(&mut state, vec![22, 80]);

    assert_eq!(resolved.len(), 2);
    assert!(resolved[0].verified);
    assert!(resolved[0].message.contains("probe-linux"));
    assert!(!resolved[1].verified);
    assert!(resolved[1].message.contains("No Clusterflux debug probe"));
    assert_eq!(state.breakpoints_by_source["src/lib.rs"][0].line, 22);
    assert_eq!(stopped_thread_for_breakpoint(&state), LINUX_THREAD);
}

#[test]
fn breakpoint_updates_in_compiled_sources_are_independent() {
    let project = tempfile::tempdir().unwrap();
    let source_dir = project.path().join("src");
    fs::create_dir_all(&source_dir).unwrap();
    fs::write(source_dir.join("build.rs"), "pub fn build() {}\n").unwrap();
    fs::write(source_dir.join("main.rs"), "fn main() {}\n").unwrap();

    let mut state = AdapterState::default();
    state.project = project.path().to_string_lossy().into_owned();
    state.source_path = "src/lib.rs".to_owned();
    state.breakpoints_by_source.insert(
        "src/lib.rs".to_owned(),
        vec![SourceLocation {
            source_path: "src/lib.rs".to_owned(),
            line: 1,
            column: None,
            probe_id: "lib-probe".to_owned(),
        }],
    );
    state.source_inventory.insert("src/main.rs".to_owned());
    state.debug_probes.push(BundleDebugProbe {
        id: "main-probe".to_owned(),
        probe_symbol: "clusterflux.probe.main".to_owned(),
        source_path: "src/main.rs".to_owned(),
        line_start: 1,
        line_end: 1,
        function: "main".to_owned(),
        task: TaskDefinitionId::new("main"),
    });

    let requested_source = source_dir.join("main.rs");
    let resolved = resolve_breakpoints_for_source(&mut state, requested_source.to_str(), vec![1]);

    assert_eq!(resolved.len(), 1);
    assert!(resolved[0].verified);
    assert_eq!(state.breakpoints_by_source["src/lib.rs"][0].line, 1);
    assert_eq!(state.breakpoints_by_source["src/main.rs"][0].line, 1);

    let resolved = crate::breakpoints::resolve_breakpoints_for_source_locations(
        &mut state,
        requested_source.to_str(),
        vec![(1, Some(7))],
    );
    assert_eq!(resolved[0].column, Some(7));
    assert_eq!(
        state.breakpoints_by_source["src/main.rs"][0].column,
        Some(7)
    );
}

#[test]
fn source_qualified_breakpoints_and_stack_frames_keep_module_identity() {
    let project = tempfile::tempdir().unwrap();
    let workflow = project.path().join(".clusterflux");
    fs::create_dir_all(&workflow).unwrap();
    for file in ["main.rs", "tasks.rs", "release.rs"] {
        fs::write(workflow.join(file), "fn duplicate() {}\n").unwrap();
    }
    let mut state = AdapterState::default();
    state.project = project.path().to_string_lossy().into_owned();
    state.source_inventory = [
        ".clusterflux/main.rs".to_owned(),
        ".clusterflux/tasks.rs".to_owned(),
        ".clusterflux/release.rs".to_owned(),
    ]
    .into_iter()
    .collect();
    for (index, file) in ["main.rs", "tasks.rs", "release.rs"]
        .into_iter()
        .enumerate()
    {
        state.debug_probes.push(BundleDebugProbe {
            id: format!("probe-{index}"),
            probe_symbol: format!("clusterflux.probe.{index}"),
            source_path: format!(".clusterflux/{file}"),
            line_start: 1,
            line_end: 1,
            function: "duplicate".to_owned(),
            task: TaskDefinitionId::new(format!("task-{index}")),
        });
        let source = workflow.join(file);
        let resolved = resolve_breakpoints_for_source(&mut state, source.to_str(), vec![1]);
        assert!(resolved[0].verified);
    }
    assert_eq!(state.breakpoints_by_source.len(), 3);
    assert_eq!(
        state
            .breakpoint_locations()
            .map(|location| location.probe_id.clone())
            .collect::<std::collections::BTreeSet<_>>()
            .len(),
        3
    );

    let main = state.threads.get(&MAIN_THREAD).unwrap().clone();
    state.stopped_task = Some(main.task.clone());
    state.stopped_location = Some(SourceLocation {
        source_path: ".clusterflux/tasks.rs".to_owned(),
        line: 1,
        column: Some(1),
        probe_id: "clusterflux.probe.1".to_owned(),
    });
    assert!(crate::source::stack_source_path(&state, &main)
        .unwrap()
        .ends_with(".clusterflux/tasks.rs"));

    state.source_mismatch = Some("exact trigger commit differs from checkout".to_owned());
    let rejected =
        resolve_breakpoints_for_source(&mut state, workflow.join("main.rs").to_str(), vec![1]);
    assert!(!rejected[0].verified);
    assert!(rejected[0].message.contains("differs"));
}

#[test]
fn frozen_participants_keep_their_own_source_locations() {
    let project = tempfile::tempdir().unwrap();
    let workflow = project.path().join(".clusterflux");
    fs::create_dir_all(&workflow).unwrap();
    for file in ["main.rs", "tasks.rs", "release.rs"] {
        fs::write(workflow.join(file), "fn probe() {}\n").unwrap();
    }
    let locations = [
        ("main-task", "main", ".clusterflux/main.rs", 11),
        ("worker-task", "worker", ".clusterflux/tasks.rs", 22),
        ("publish-task", "publish", ".clusterflux/release.rs", 33),
    ];
    let acknowledgements = locations
        .iter()
        .enumerate()
        .map(|(index, (task, definition, source_path, line))| {
            json!({
                "node": if index == 0 { "coordinator-main" } else { "worker" },
                "task": task,
                "task_definition": definition,
                "state": "frozen",
                "stack_frames": [format!("{definition}::wasm")],
                "current_source_location": {
                    "source_path": source_path,
                    "line": line,
                    "column": 1,
                    "probe_id": format!("clusterflux.probe.{definition}")
                }
            })
        })
        .collect::<Vec<_>>();
    let mut state = AdapterState::default();
    state.project = project.path().to_string_lossy().into_owned();
    state.runtime_backend = RuntimeBackend::LiveServices;
    state.apply_runtime_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:7999".to_owned(),
        node: "worker".to_owned(),
        node_report: json!({"debug_epoch": {"acknowledgements": acknowledgements}}),
        task_events: json!({"events": []}),
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
        debug_epoch: Some(7),
        stopped_task: Some("worker-task".to_owned()),
        stopped_probe_symbol: Some("clusterflux.probe.worker".to_owned()),
        stopped_location: Some(SourceLocation {
            source_path: ".clusterflux/tasks.rs".to_owned(),
            line: 22,
            column: Some(1),
            probe_id: "clusterflux.probe.worker".to_owned(),
        }),
        source_mismatch: None,
        all_participants_frozen: true,
    });

    for (task, _, source_path, line) in locations {
        let thread = state
            .threads
            .values()
            .find(|thread| thread.task.as_str() == task)
            .unwrap();
        assert_eq!(thread.current_source_location.as_ref().unwrap().line, line);
        assert!(crate::source::stack_source_path(&state, thread)
            .unwrap()
            .ends_with(source_path));
    }
}

#[test]
fn launch_threads_include_windows_task_in_same_virtual_process() {
    let state = AdapterState::default();
    let windows = state
        .threads
        .get(&WINDOWS_THREAD)
        .expect("windows task should be debugger-visible");

    assert_eq!(state.threads.len(), 4);
    assert_eq!(windows.id, WINDOWS_THREAD);
    assert_eq!(windows.task, TaskInstanceId::from("compile-windows"));
    assert_eq!(windows.name, "compile windows");
    assert_eq!(windows.line, 52);
    assert_eq!(process_id(&state.project, &state.entry), state.process);
}

#[test]
fn vscode_and_dap_share_stable_workspace_process_identity() {
    assert_eq!(
        process_id("/workspace/app", "build"),
        clusterflux_core::ProcessId::from("vp-e4bd6ef50539")
    );
}

#[test]
fn windows_thread_runtime_variables_share_virtual_process() {
    let state = AdapterState::default();
    let windows = state
        .threads
        .get(&WINDOWS_THREAD)
        .expect("windows task should be debugger-visible");

    let variables = variables_response(&state, windows.runtime_ref);
    let variables = variables["variables"]
        .as_array()
        .expect("variables response should be an array");

    assert!(variables.iter().any(|variable| {
        variable["name"] == "virtual_process_id" && variable["value"] == state.process.to_string()
    }));
    assert!(variables.iter().any(|variable| {
        variable["name"] == "virtual_thread" && variable["value"] == "compile-windows"
    }));
    assert!(variables.iter().any(|variable| {
        variable["name"] == "task_attempt_id"
            && variable["value"] == format!("demo-attempt-{WINDOWS_THREAD}")
    }));
}

#[test]
fn variables_expose_mvp_runtime_handles_and_output_tails() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LocalServices;
    state.apply_runtime_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:7999".to_owned(),
        node: "node".to_owned(),
        node_report: json!({
            "task_snapshots": { "snapshots": [{
                "task": "compile-linux-1",
                "task_definition": "compile-linux",
                "attempt_id": "attempt-1",
                "current": true,
                "state": "running"
            }] },
            "terminal_event": {
                "task": "compile-linux-1",
                "task_definition": "compile-linux"
            }
        }),
        task_events: json!({ "events": [] }),
        placed_task_launched: true,
        status_code: Some(0),
        stdout_bytes: 11,
        stderr_bytes: 7,
        stdout_tail: "hello tail\n".to_owned(),
        stderr_tail: "warn\n".to_owned(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: Some("/vfs/artifacts/dap-output.txt".to_owned()),
        event_count: 1,
        debug_epoch: None,
        stopped_task: None,
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch: None,
        all_participants_frozen: false,
    });
    let exact_thread_id = state
        .threads
        .values()
        .find(|thread| thread.task == TaskInstanceId::from("compile-linux-1"))
        .map(|thread| thread.id)
        .expect("the exact terminal task instance should have its own thread");
    {
        let runtime_thread = state.threads.get_mut(&exact_thread_id).unwrap();
        runtime_thread.runtime_task_args =
            vec![("source".to_owned(), "source://checkout".to_owned())];
        runtime_thread.runtime_handles = vec![(
            "artifact".to_owned(),
            "artifact://runtime/output".to_owned(),
        )];
        runtime_thread.runtime_command_status = Some("frozen native command pid 42".to_owned());
    }
    let runtime_thread = state
        .threads
        .get(&exact_thread_id)
        .expect("exact runtime thread should exist");

    let args = variables_response(&state, runtime_thread.args_ref);
    let args = args["variables"]
        .as_array()
        .expect("variables response should be an array");
    assert!(args.iter().any(|variable| {
        variable["name"] == "source"
            && variable["value"] == "source://checkout"
            && variable["type"] == "task-argument"
    }));
    assert!(args.iter().any(|variable| {
        variable["name"] == "artifact"
            && variable["value"] == "artifact://runtime/output"
            && variable["type"] == "runtime-handle"
    }));

    let runtime = variables_response(&state, runtime_thread.runtime_ref);
    let runtime = runtime["variables"].as_array().unwrap();
    let command_ref = runtime
        .iter()
        .find(|variable| variable["name"] == "command_spec")
        .and_then(|variable| variable["variablesReference"].as_i64())
        .expect("command spec should have child variables");
    assert!(runtime
        .iter()
        .any(|variable| variable["name"] == "stdout_tail" && variable["value"] == "hello tail\n"));
    assert!(runtime
        .iter()
        .any(|variable| variable["name"] == "stderr_tail" && variable["value"] == "warn\n"));

    let command = variables_response(&state, command_ref);
    let command = command["variables"].as_array().unwrap();
    assert!(command.iter().any(|variable| {
        variable["name"] == "status" && variable["value"] == "frozen native command pid 42"
    }));
    assert!(!command.iter().any(|variable| {
        variable["name"] == "program" || variable["name"] == "required_capability"
    }));
}

#[test]
fn attach_record_replaces_demo_threads_with_authoritative_task_snapshots() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LiveServices;
    state.apply_attach_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:9443".to_owned(),
        node: "coordinator-debug-attach".to_owned(),
        node_report: json!({
            "debug_attach": {
                "authorization": {
                    "allowed": true,
                    "reason": "debug attach allowed"
                }
            },
            "process_status": {
                "main_task_definition": "sha256:main-definition",
                "main_task_instance": format!("ti:{}:main", state.process),
                "main_debug_epoch": null,
                "coordinator_epoch": 1
            },
            "task_snapshots": {
                "snapshots": [{
                    "task": "compile-linux-1",
                    "task_definition": "compile-linux",
                    "attempt_id": "attempt-compile-linux-1",
                    "display_name": "compile linux",
                    "current": true,
                    "state": "running",
                    "node": "worker-linux"
                }]
            }
        }),
        task_events: json!({
            "events": [{
                "tenant": "tenant",
                "project": "project",
                "process": state.process.to_string(),
                "node": "worker-linux",
                "executor": "node",
                "task_definition": "compile-linux",
                "task": "compile-linux-1",
                "terminal_state": "completed",
                "status_code": 0,
                "stdout_bytes": 4,
                "stderr_bytes": 0,
                "stdout_tail": "done",
                "stderr_tail": "",
                "stdout_truncated": false,
                "stderr_truncated": false,
                "artifact_path": "/vfs/artifacts/from-attach.txt",
                "artifact_digest": "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "artifact_size_bytes": 4
            }]
        }),
        placed_task_launched: true,
        status_code: Some(0),
        stdout_bytes: 4,
        stderr_bytes: 0,
        stdout_tail: "done".to_owned(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: Some("/vfs/artifacts/from-attach.txt".to_owned()),
        event_count: 1,
        debug_epoch: None,
        stopped_task: None,
        stopped_probe_symbol: None,
            stopped_location: None,
            source_mismatch: None,
        all_participants_frozen: false,
    });

    assert_eq!(state.threads.len(), 2);
    assert!(state.threads.contains_key(&MAIN_THREAD));
    assert!(!state.threads.contains_key(&WINDOWS_THREAD));
    let linux = state
        .threads
        .get(&LINUX_THREAD)
        .expect("current coordinator task snapshot should become debugger thread");
    assert_eq!(linux.task, TaskInstanceId::from("compile-linux-1"));
    assert_eq!(
        linux.task_definition,
        clusterflux_core::TaskDefinitionId::from("compile-linux")
    );
    assert!(linux.stdout_tail.is_empty());
    assert_eq!(linux.state, DebugRuntimeState::Running);
    assert_eq!(state.runtime_artifact_path, None);
    assert!(state
        .command_status
        .contains("attached to existing virtual process"));
    assert!(state.command_status.contains("coordinator task event"));
}

#[test]
fn attach_projects_active_coordinator_main_without_inventing_a_worker_task() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LiveServices;
    let main_instance = format!("ti:{}:main", state.process);
    state.apply_attach_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:9443".to_owned(),
        node: "coordinator-main".to_owned(),
        node_report: json!({
            "debug_attach": { "authorization": { "allowed": true } },
            "process_status": {
                "process": state.process.to_string(),
                "state": "running",
                "main_task_definition": "sha256:main-definition",
                "main_task_instance": main_instance,
                "main_state": "running",
                "main_debug_epoch": null,
                "connected_nodes": [],
                "coordinator_epoch": 1
            }
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
        source_mismatch: None,
        all_participants_frozen: false,
    });

    assert_eq!(state.threads.len(), 1);
    let main = state.threads.get(&MAIN_THREAD).unwrap();
    assert_eq!(main.task, TaskInstanceId::from(main_instance.as_str()));
    assert_eq!(
        main.task_definition,
        clusterflux_core::TaskDefinitionId::from("sha256:main-definition")
    );
    assert_eq!(main.state, DebugRuntimeState::Running);
    assert!(main.name.contains("coordinator main"));
}

#[test]
fn terminal_events_do_not_resurrect_threads_absent_from_current_snapshots() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LiveServices;
    let main_instance = format!("ti:{}:main", state.process);
    state.apply_attach_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:9443".to_owned(),
        node: "coordinator-main".to_owned(),
        node_report: json!({
            "debug_attach": { "authorization": { "allowed": true } },
            "task_snapshots": { "snapshots": [] }
        }),
        task_events: json!({
            "events": [
                {
                    "node": "worker-linux",
                    "executor": "node",
                    "task_definition": "compile_linux",
                    "task": "ti:child:1",
                    "terminal_state": "completed",
                    "status_code": 0
                },
                {
                    "node": "coordinator-main",
                    "executor": "coordinator_main",
                    "task_definition": "sha256:main-definition",
                    "task": main_instance,
                    "terminal_state": "completed",
                    "status_code": 0
                }
            ]
        }),
        placed_task_launched: true,
        status_code: Some(0),
        stdout_bytes: 0,
        stderr_bytes: 0,
        stdout_tail: String::new(),
        stderr_tail: String::new(),
        stdout_truncated: false,
        stderr_truncated: false,
        artifact_path: None,
        event_count: 2,
        debug_epoch: None,
        stopped_task: None,
        stopped_probe_symbol: None,
        stopped_location: None,
        source_mismatch: None,
        all_participants_frozen: false,
    });

    assert!(state.threads.is_empty());
}

#[test]
fn terminal_record_without_snapshots_clears_active_threads() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LiveServices;
    assert!(!state.threads.is_empty());

    state.apply_runtime_record(RuntimeLaunchRecord {
        coordinator: "127.0.0.1:9443".to_owned(),
        node: "coordinator-main".to_owned(),
        node_report: json!({ "terminal_event": { "terminal_state": "completed" } }),
        task_events: json!({ "events": [] }),
        placed_task_launched: true,
        status_code: Some(0),
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
        source_mismatch: None,
        all_participants_frozen: false,
    });

    assert!(state.threads.is_empty());
}

#[test]
fn source_locals_infer_clusterflux_api_values_from_runtime_state() {
    let project = std::env::temp_dir().join(format!(
        "clusterflux-dap-source-locals-{}",
        std::process::id()
    ));
    let src = project.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.rs"),
        r#"async fn run_build_workflow() {
    let source = prepare_source_snapshot();
    let linux = clusterflux::spawn::async_task_with_arg(source.clone(), compile_linux)
        .name("compile linux")
        .env(linux_env())
        .start()
        .await
        .unwrap();
    let linux_thread = linux.virtual_thread_id();
    let linux_artifact = linux.join().await.unwrap();
    let package = clusterflux::spawn::async_task_with_arg(
        vec![linux_artifact.clone()],
        package_release,
    )
    .name("package artifacts")
    .env(linux_env())
    .start()
    .await
    .unwrap();
    let package_artifact = package.join().await.unwrap();
}
"#,
    )
    .unwrap();

    let mut state = AdapterState::default();
    state.project = project.to_string_lossy().into_owned();
    state.source_path = "src/lib.rs".to_owned();
    let source = fs::read_to_string(project.join(&state.source_path)).unwrap();
    let inspection_line = source
        .lines()
        .position(|line| line.contains("let package_artifact = package.join()"))
        .map(|index| index as i64 + 1)
        .expect("flagship source must expose the post-join locals inspection point");
    state.threads.get_mut(&MAIN_THREAD).unwrap().line = inspection_line;
    let thread = state.threads[&MAIN_THREAD].clone();

    let locals = variables_response(&state, thread.locals_ref);
    let locals = locals["variables"].as_array().unwrap();

    assert!(locals.iter().any(|variable| {
        variable["name"] == "linux"
            && variable["value"].as_str().is_some_and(|value| {
                value.contains("TaskHandle")
                    && value.contains("compile-linux")
                    && value.contains("virtual_thread_id = 2")
            })
    }));
    assert!(locals
        .iter()
        .any(|variable| { variable["name"] == "linux_thread" && variable["value"] == "2" }));
    assert!(locals.iter().any(|variable| {
        variable["name"] == "linux_artifact"
            && variable["value"]
                .as_str()
                .is_some_and(|value| value.contains("Artifact"))
    }));
    assert!(locals.iter().any(|variable| {
        variable["name"] == "unavailable-local-diagnostic"
            && variable["type"] == "unavailable-local"
    }));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn source_locals_infer_task_with_arg_values_from_runtime_state() {
    let project = std::env::temp_dir().join(format!(
        "clusterflux-dap-task-with-arg-{}",
        std::process::id()
    ));
    let src = project.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("main.rs"),
        r#"use clusterflux::{Artifact, EnvRef, SourceSnapshot};

async fn build_release() -> Result<(), clusterflux::TaskArgError> {
    let source = prepare_source_snapshot();

    let compile = clusterflux::spawn::task_with_arg(source.clone(), compile_linux)
        .name("compile linux")
        .env(linux_command_env())
        .start()
        .await?;

    let compile_thread = compile.virtual_thread_id();
    let linux_artifact = compile.join().await;

    let package = clusterflux::spawn::task_with_arg(vec![linux_artifact.clone()], package_release)
        .name("package release")
        .env(coordinator_env())
        .start()
        .await?;

    let package_thread = package.virtual_thread_id();
    let release_artifact = package.join().await;
    Ok(())
}

fn prepare_source_snapshot() -> SourceSnapshot {
    SourceSnapshot {
        digest: "source://coordinator/quick-test-checkout".to_owned(),
    }
}

fn linux_command_env() -> EnvRef {
    clusterflux::env!("linux-command")
}

fn coordinator_env() -> EnvRef {
    clusterflux::env!("coordinator")
}

fn compile_linux(source: SourceSnapshot) -> Artifact {
    Artifact { id: source.digest }
}

fn package_release(inputs: Vec<Artifact>) -> Artifact {
    inputs.into_iter().next().unwrap()
}
"#,
    )
    .unwrap();

    let mut state = AdapterState::default();
    state.project = project.to_string_lossy().into_owned();
    state.source_path = "src/main.rs".to_owned();
    state.threads.get_mut(&MAIN_THREAD).unwrap().line = 23;
    let thread = state.threads[&MAIN_THREAD].clone();

    let locals = variables_response(&state, thread.locals_ref);
    let locals = locals["variables"].as_array().unwrap();

    assert!(locals.iter().any(|variable| {
        variable["name"] == "source"
            && variable["value"]
                .as_str()
                .is_some_and(|value| value.contains("source://coordinator/quick-test-checkout"))
    }));
    assert!(locals.iter().any(|variable| {
        variable["name"] == "compile"
            && variable["value"].as_str().is_some_and(|value| {
                value.contains("TaskHandle")
                    && value.contains("compile-linux")
                    && value.contains("virtual_thread_id = 2")
                    && value.contains("linux-command")
            })
    }));
    assert!(locals
        .iter()
        .any(|variable| variable["name"] == "compile_thread" && variable["value"] == "2"));
    assert!(locals.iter().any(|variable| {
        variable["name"] == "linux_artifact"
            && variable["value"]
                .as_str()
                .is_some_and(|value| value.contains("Artifact"))
    }));
    assert!(locals.iter().any(|variable| {
        variable["name"] == "package"
            && variable["value"].as_str().is_some_and(|value| {
                value.contains("TaskHandle")
                    && value.contains("package-release")
                    && value.contains("virtual_thread_id = 4")
                    && value.contains("coordinator")
            })
    }));
    assert!(locals
        .iter()
        .any(|variable| variable["name"] == "package_thread" && variable["value"] == "4"));
    assert!(locals.iter().any(|variable| {
        variable["name"] == "release_artifact"
            && variable["value"]
                .as_str()
                .is_some_and(|value| value.contains("Artifact"))
    }));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn wasm_frame_locals_expose_only_values_from_the_node_snapshot() {
    let project = std::env::temp_dir().join(format!(
        "clusterflux-dap-wasm-locals-{}",
        std::process::id()
    ));
    let src = project.join("src");
    fs::create_dir_all(&src).unwrap();
    fs::write(
        src.join("lib.rs"),
        "pub extern \"C\" fn task_add_one(input: i32) -> i32 {\n    input + 1\n}\n",
    )
    .unwrap();

    let mut state = AdapterState::default();
    state.project = project.to_string_lossy().into_owned();
    state.source_path = "src/lib.rs".to_owned();
    let source = fs::read_to_string(Path::new(&state.project).join(&state.source_path)).unwrap();
    state.threads.get_mut(&MAIN_THREAD).unwrap().line = source
        .lines()
        .position(|line| line.contains("input + 1"))
        .map(|line| line as i64 + 1)
        .expect("task_add_one source line");
    state
        .threads
        .get_mut(&MAIN_THREAD)
        .unwrap()
        .wasm_local_values = vec![("wasm_local_0".to_owned(), "I32(41)".to_owned())];
    let thread = state.threads[&MAIN_THREAD].clone();

    let locals = variables_response(&state, thread.wasm_locals_ref);
    let locals = locals["variables"].as_array().unwrap();

    assert!(locals.iter().any(|variable| {
        variable["name"] == "wasm_local_0"
            && variable["type"] == "wasm-frame-local"
            && variable["value"]
                .as_str()
                .is_some_and(|value| value.contains("41"))
    }));
    assert!(!locals
        .iter()
        .any(|variable| variable["name"] == "wasm-local-diagnostic"));

    let _ = fs::remove_dir_all(project);
}

#[test]
fn detects_current_failed_attempt_awaiting_operator_action() {
    let snapshots = json!({
        "snapshots": [
            {
                "task": "task-stale",
                "attempt_id": "attempt-stale",
                "state": "failed_awaiting_action",
                "current": false
            },
            {
                "task": "task-current",
                "attempt_id": "attempt-current",
                "state": "failed_awaiting_action",
                "current": true
            }
        ]
    });

    assert_eq!(
        runtime_client::failed_awaiting_action_snapshot(&snapshots),
        Some(("task-current", "attempt-current"))
    );
}

#[test]
fn whole_process_terminal_status_covers_every_current_logical_task_attempt() {
    let snapshots = |items: serde_json::Value| json!({ "snapshots": items });

    assert_eq!(
        whole_process_status_code(
            Some(0),
            &snapshots(json!([
                {
                    "task": "child",
                    "current": true,
                    "state": "completed",
                    "status_code": 0
                }
            ]))
        ),
        Some(0),
        "a successful main and final child must succeed"
    );
    for (state, status_code) in [("failed", 23), ("cancelled", 1)] {
        assert_eq!(
            whole_process_status_code(
                Some(0),
                &snapshots(json!([
                    {
                        "task": "child",
                        "current": true,
                        "state": state,
                        "status_code": status_code
                    }
                ]))
            ),
            Some(status_code),
            "a terminal child must determine the whole-process result"
        );
    }
    assert_eq!(
        whole_process_status_code(
            Some(0),
            &snapshots(json!([
                {
                    "task": "accepted-failure",
                    "current": true,
                    "state": "failed",
                    "command_state": "failure_accepted",
                    "status_code": 17
                }
            ]))
        ),
        Some(17),
        "accepting an AwaitOperator failure releases the process but does not turn failure into success"
    );
    assert_eq!(
        whole_process_status_code(
            Some(0),
            &snapshots(json!([
                {
                    "task": "restarted",
                    "attempt_id": "attempt-1",
                    "current": false,
                    "state": "failed",
                    "status_code": 7
                },
                {
                    "task": "restarted",
                    "attempt_id": "attempt-2",
                    "current": true,
                    "state": "completed",
                    "status_code": 0
                }
            ]))
        ),
        Some(0),
        "a successful replacement attempt is authoritative over stale failed attempts"
    );
    assert_eq!(
        whole_process_status_code(
            Some(9),
            &snapshots(json!([
                {
                    "task": "child",
                    "current": true,
                    "state": "completed",
                    "status_code": 0
                }
            ]))
        ),
        Some(9),
        "a failed coordinator main cannot be masked by successful children"
    );
}

#[test]
fn exact_task_instance_ids_keep_stable_dap_threads_across_snapshot_reordering_and_retry() {
    let mut state = AdapterState::default();
    state.runtime_backend = RuntimeBackend::LiveServices;
    let record = |snapshots: serde_json::Value| RuntimeLaunchRecord {
        coordinator: "127.0.0.1:9443".to_owned(),
        node: "node-a".to_owned(),
        node_report: json!({
            "task_snapshots": { "snapshots": snapshots },
            "process_status": null
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
        source_mismatch: None,
        all_participants_frozen: false,
    };
    state.apply_attach_record(record(json!([
        {
            "task": "lane-stable",
            "task_definition": "build_lane",
            "attempt_id": "stable-1",
            "current": true,
            "state": "running"
        },
        {
            "task": "lane-recovering",
            "task_definition": "build_lane",
            "attempt_id": "recovering-1",
            "current": true,
            "state": "failed_awaiting_action"
        }
    ])));
    let stable_id = state
        .threads
        .values()
        .find(|thread| thread.task == TaskInstanceId::from("lane-stable"))
        .unwrap()
        .id;
    let recovering_id = state
        .threads
        .values()
        .find(|thread| thread.task == TaskInstanceId::from("lane-recovering"))
        .unwrap()
        .id;
    assert_ne!(stable_id, recovering_id);

    state.apply_runtime_record(record(json!([
        {
            "task": "lane-new",
            "task_definition": "build_lane",
            "attempt_id": "new-1",
            "current": true,
            "state": "running"
        },
        {
            "task": "lane-stable",
            "task_definition": "build_lane",
            "attempt_id": "stable-2",
            "current": true,
            "state": "running"
        }
    ])));

    let stable = state
        .threads
        .values()
        .find(|thread| thread.task == TaskInstanceId::from("lane-stable"))
        .unwrap();
    let new_lane = state
        .threads
        .values()
        .find(|thread| thread.task == TaskInstanceId::from("lane-new"))
        .unwrap();
    assert_eq!(stable.id, stable_id);
    assert_eq!(stable.attempt_id, "stable-2");
    assert!(state
        .threads
        .values()
        .all(|thread| thread.task != TaskInstanceId::from("lane-recovering")));
    assert!(new_lane.id > recovering_id);
}
