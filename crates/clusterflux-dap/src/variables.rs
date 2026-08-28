use std::collections::BTreeMap;
use std::fs;

use clusterflux_core::{Digest, TaskInstanceId};
use serde_json::{json, Value};

use crate::breakpoints::parse_rust_function_name;
use crate::demo_backend::{LINUX_THREAD, MAIN_THREAD, PACKAGE_THREAD, WINDOWS_THREAD};
use crate::virtual_model::{AdapterState, VirtualThread};

pub(crate) fn variables_response(state: &AdapterState, reference: i64) -> Value {
    let Some(thread) = state.threads.values().find(|thread| {
        thread.locals_ref == reference
            || thread.wasm_locals_ref == reference
            || thread.args_ref == reference
            || thread.runtime_ref == reference
            || thread.output_ref == reference
            || thread.target_ref == reference
            || thread.vfs_ref == reference
            || thread.command_ref == reference
    }) else {
        return json!({ "variables": [] });
    };

    if thread.locals_ref == reference {
        return json!({ "variables": source_locals_variables(state, thread) });
    }

    if thread.wasm_locals_ref == reference {
        return json!({ "variables": wasm_frame_local_variables(state, thread) });
    }

    if thread.args_ref == reference {
        let mut variables = thread
            .runtime_task_args
            .iter()
            .map(|(name, value)| {
                json!({
                    "name": name,
                    "value": value,
                    "type": "task-argument",
                    "variablesReference": 0,
                })
            })
            .chain(thread.runtime_handles.iter().map(|(name, value)| {
                json!({
                    "name": name,
                    "value": value,
                    "type": "runtime-handle",
                    "variablesReference": 0,
                })
            }))
            .collect::<Vec<_>>();
        if variables.is_empty() {
            variables.push(json!({
                "name": "runtime-boundary-diagnostic",
                "value": "the frozen runtime participant reported no task arguments or handles at this probe",
                "type": "diagnostic",
                "variablesReference": 0,
            }));
        }
        return json!({ "variables": variables });
    }

    if thread.target_ref == reference {
        let runtime_backed =
            state.runtime_backend != crate::virtual_model::RuntimeBackend::Simulated;
        return json!({
            "variables": [
                {
                    "name": "task",
                    "value": thread.task.to_string(),
                    "variablesReference": 0
                },
                {
                    "name": "attempt",
                    "value": thread.attempt_id,
                    "variablesReference": 0
                },
                {
                    "name": "environment",
                    "value": if runtime_backed { thread.runtime_environment.as_deref().unwrap_or("unknown") } else { task_environment(thread) },
                    "variablesReference": 0
                },
                {
                    "name": "kind",
                    "value": if thread.id == MAIN_THREAD { "wasm entrypoint" } else { "wasm task" },
                    "variablesReference": 0
                },
                {
                    "name": "required_capability",
                    "value": if runtime_backed { "not reported by the frozen node participant" } else if thread.id == MAIN_THREAD { "none" } else { "Command" },
                    "variablesReference": 0
                }
            ]
        });
    }

    if thread.vfs_ref == reference {
        if state.runtime_backend != crate::virtual_model::RuntimeBackend::Simulated {
            return json!({
                "variables": [
                {
                    "name": "runtime-vfs-diagnostic",
                    "value": thread.runtime_vfs_checkpoint.as_deref().unwrap_or("the coordinator has no current VFS checkpoint identity"),
                        "variablesReference": 0
                    },
                    {
                        "name": "reported_artifact_path",
                        "value": state.runtime_artifact_path.as_deref().unwrap_or("unavailable"),
                        "variablesReference": 0
                    }
                ]
            });
        }
        return json!({
            "variables": [
                {
                    "name": "/vfs/artifacts",
                    "value": artifact_handle_value(state, thread),
                    "variablesReference": 0
                },
                {
                    "name": "/vfs/sources",
                    "value": format!("source://local-checkout/{}", project_snapshot_suffix(&state.project)),
                    "variablesReference": 0
                },
                {
                    "name": "/vfs/blobs",
                    "value": blob_digest(state, thread),
                    "variablesReference": 0
                },
                {
                    "name": "durability",
                    "value": "best-effort until explicitly exported or stored",
                    "variablesReference": 0
                }
            ]
        });
    }

    if thread.runtime_ref == reference {
        return json!({
            "variables": [
                {
                    "name": "virtual_process_id",
                    "value": state.process.to_string(),
                    "variablesReference": 0
                },
                {
                    "name": "virtual_thread",
                    "value": thread.task.to_string(),
                    "variablesReference": 0
                },
                {
                    "name": "task_attempt_id",
                    "value": thread.attempt_id,
                    "variablesReference": 0
                },
                {
                    "name": "node",
                    "value": thread.runtime_node.as_deref().unwrap_or("unknown"),
                    "variablesReference": 0
                },
                {
                    "name": "restart_compatible",
                    "value": thread.restart_compatible.map_or("unknown".to_owned(), |value| value.to_string()),
                    "variablesReference": 0
                },
                {
                    "name": "debug_epoch",
                    "value": state.epoch,
                    "variablesReference": 0
                },
                {
                    "name": "state",
                    "value": format!("{:?}", thread.state),
                    "variablesReference": 0
                },
                {
                    "name": "runtime_backend",
                    "value": format!("{:?}", state.runtime_backend),
                    "variablesReference": 0
                },
                {
                    "name": "coordinator_task_events",
                    "value": state.runtime_event_count,
                    "variablesReference": 0
                },
                {
                    "name": "command_status",
                    "value": thread.runtime_command_status.as_deref().unwrap_or(&state.command_status),
                    "variablesReference": 0
                },
                {
                    "name": "command_spec",
                    "value": command_spec_summary(state, thread),
                    "variablesReference": if thread.runtime_command_status.is_some() { thread.command_ref } else { 0 }
                },
                {
                    "name": "stdout_tail",
                    "value": output_tail_display(&thread.stdout_tail, thread.stdout_bytes, thread.stdout_truncated, "stdout"),
                    "variablesReference": 0
                },
                {
                    "name": "stderr_tail",
                    "value": output_tail_display(&thread.stderr_tail, thread.stderr_bytes, thread.stderr_truncated, "stderr"),
                    "variablesReference": 0
                }
            ]
        });
    }

    if thread.command_ref == reference {
        if state.runtime_backend != crate::virtual_model::RuntimeBackend::Simulated {
            return json!({
                "variables": [
                    {
                        "name": "status",
                        "value": thread.runtime_command_status.as_deref().unwrap_or("no native command state was reported by this participant"),
                        "variablesReference": 0
                    },
                    {
                        "name": "command-spec-diagnostic",
                        "value": "the node debug snapshot does not yet report native command program, arguments, or capability requirements",
                        "variablesReference": 0
                    }
                ]
            });
        }
        return json!({
            "variables": [
                {
                    "name": "program",
                    "value": command_program(thread),
                    "variablesReference": 0
                },
                {
                    "name": "args",
                    "value": command_args_summary(state, thread),
                    "variablesReference": 0
                },
                {
                    "name": "required_capability",
                    "value": if thread.id == MAIN_THREAD { "none" } else { "Command" },
                    "variablesReference": 0
                },
                {
                    "name": "status",
                    "value": state.command_status,
                    "variablesReference": 0
                }
            ]
        });
    }

    let mut variables = vec![
        json!({
            "name": "stdout_tail",
            "value": output_tail_display(&thread.stdout_tail, thread.stdout_bytes, thread.stdout_truncated, "stdout"),
            "variablesReference": 0
        }),
        json!({
            "name": "stderr_tail",
            "value": output_tail_display(&thread.stderr_tail, thread.stderr_bytes, thread.stderr_truncated, "stderr"),
            "variablesReference": 0
        }),
    ];
    variables.extend(
        thread
            .recent_output
            .iter()
            .enumerate()
            .map(|(index, output)| {
                json!({
                    "name": format!("line_{index}"),
                    "value": output,
                    "variablesReference": 0
                })
            }),
    );

    json!({ "variables": variables })
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SourceLocal {
    name: String,
    line: i64,
    value: Option<String>,
}

fn source_locals_variables(state: &AdapterState, thread: &VirtualThread) -> Vec<Value> {
    let (locals, diagnostic) = source_locals_for_thread(state, thread);
    let mut variables = locals
        .into_iter()
        .map(|local| {
            let has_value = local.value.is_some();
            let value = local.value.unwrap_or_else(|| {
                format!(
                    "cannot be inspected: source-level local from line {} is known, but DWARF/runtime value snapshot is unavailable",
                    local.line
                )
            });
            json!({
                "name": local.name,
                "value": value,
                "type": if has_value { "clusterflux-source-local" } else { "unavailable-local" },
                "variablesReference": 0
            })
        })
        .collect::<Vec<_>>();
    variables.push(json!({
        "name": "unavailable-local-diagnostic",
        "value": diagnostic,
        "type": "unavailable-local",
        "variablesReference": 0
    }));
    variables
}

fn wasm_frame_local_variables(_state: &AdapterState, thread: &VirtualThread) -> Vec<Value> {
    if thread.wasm_local_values.is_empty() {
        return vec![json!({
            "name": "wasm-local-diagnostic",
            "value": "the frozen node participant did not report inspectable Wasm frame locals at this safepoint",
            "type": "unavailable-local",
            "variablesReference": 0
        })];
    }
    thread
        .wasm_local_values
        .iter()
        .map(|(name, value)| {
            json!({
                "name": name,
                "value": value,
                "type": "wasm-frame-local",
                "variablesReference": 0
            })
        })
        .collect()
}

fn source_locals_for_thread(
    state: &AdapterState,
    thread: &VirtualThread,
) -> (Vec<SourceLocal>, String) {
    if state.runtime_backend != crate::virtual_model::RuntimeBackend::Simulated && thread.line <= 0
    {
        return (
            Vec::new(),
            "cannot be inspected: the coordinator has no current source location for this attempt"
                .to_owned(),
        );
    }
    let source_path = crate::source::resolve_source_path(&state.project, &state.source_path);
    let Ok(source) = fs::read_to_string(&source_path) else {
        return (
            Vec::new(),
            format!(
                "cannot be inspected: source file `{}` is unavailable; task args and handles remain visible",
                source_path.display()
            ),
        );
    };
    let lines = source.lines().collect::<Vec<_>>();
    if lines.is_empty() {
        return (
            Vec::new(),
            "cannot be inspected: source file is empty; task args and handles remain visible"
                .to_owned(),
        );
    }
    let current = usize::try_from(thread.line)
        .ok()
        .and_then(|line| line.checked_sub(1))
        .unwrap_or(0)
        .min(lines.len() - 1);
    let function_start = lines[..=current]
        .iter()
        .rposition(|line| parse_rust_function_name(line).is_some())
        .unwrap_or(0);
    let mut locals = Vec::new();
    let mut runtime_values = BTreeMap::new();
    let mut index = function_start;
    while index <= current {
        let Some(name) = parse_let_binding_name(lines[index]) else {
            index += 1;
            continue;
        };

        let line = (index + 1) as i64;
        let mut statement = lines[index].to_owned();
        while !statement.contains(';') && index < current {
            index += 1;
            statement.push('\n');
            statement.push_str(lines[index]);
        }

        let runtime_value =
            infer_clusterflux_source_local_value(state, &statement, &runtime_values);
        if let Some(value) = runtime_value.clone() {
            runtime_values.insert(name.clone(), value);
        }
        locals.push(SourceLocal {
            name,
            line,
            value: runtime_value.map(|value| value.display(state)),
        });
        index += 1;
    }
    let diagnostic = if locals.is_empty() {
        "cannot be inspected: no source-level `let` locals are in scope for this frame; task args and handles remain visible"
            .to_owned()
    } else if locals.iter().any(|local| local.value.is_some()) {
        "selected source-level Clusterflux API locals are populated from virtual-thread runtime state; non-Clusterflux locals remain best-effort until DWARF value snapshots are available"
            .to_owned()
    } else {
        "cannot be inspected: selected source-level local names are best-effort until DWARF/runtime value snapshots are available"
            .to_owned()
    };
    (locals, diagnostic)
}

fn parse_let_binding_name(line: &str) -> Option<String> {
    let rest = line.trim_start().strip_prefix("let ")?;
    let rest = rest
        .trim_start()
        .strip_prefix("mut ")
        .unwrap_or(rest)
        .trim_start();
    let name = rest
        .chars()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>();
    (!name.is_empty()).then_some(name)
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum SourceLocalRuntimeValue {
    SourceSnapshot(String),
    TaskHandle {
        task: TaskInstanceId,
        thread_id: i64,
        env: String,
        state: String,
    },
    ThreadId(i64),
    Artifact(String),
}

impl SourceLocalRuntimeValue {
    fn display(&self, _state: &AdapterState) -> String {
        match self {
            SourceLocalRuntimeValue::SourceSnapshot(digest) => {
                format!("SourceSnapshot {{ digest = \"{digest}\" }}")
            }
            SourceLocalRuntimeValue::TaskHandle {
                task,
                thread_id,
                env,
                state,
            } => format!(
                "TaskHandle {{ task = \"{task}\", virtual_thread_id = {thread_id}, env = \"{env}\", state = {state} }}"
            ),
            SourceLocalRuntimeValue::ThreadId(thread_id) => thread_id.to_string(),
            SourceLocalRuntimeValue::Artifact(artifact) => {
                format!("Artifact {{ id = \"{artifact}\" }}")
            }
        }
    }
}

fn infer_clusterflux_source_local_value(
    state: &AdapterState,
    statement: &str,
    runtime_values: &BTreeMap<String, SourceLocalRuntimeValue>,
) -> Option<SourceLocalRuntimeValue> {
    if statement.contains("prepare_source_snapshot()") {
        return Some(SourceLocalRuntimeValue::SourceSnapshot(
            source_snapshot_digest_from_project(state).unwrap_or_else(|| {
                format!(
                    "source://local-checkout/{}",
                    project_snapshot_suffix(&state.project)
                )
            }),
        ));
    }

    if let Some(task_function) = extract_spawn_task_function(statement) {
        let task_name = extract_string_argument(statement, ".name(");
        let spawned_thread =
            thread_for_spawn_statement(state, &task_function, task_name.as_deref())?;
        return Some(SourceLocalRuntimeValue::TaskHandle {
            task: spawned_thread.task.clone(),
            thread_id: spawned_thread.id,
            env: extract_env_name(statement)
                .unwrap_or_else(|| task_environment(spawned_thread).to_owned()),
            state: format!("{:?}", spawned_thread.state),
        });
    }

    if let Some(receiver) = receiver_before_method(statement, ".virtual_thread_id()") {
        if let Some(SourceLocalRuntimeValue::TaskHandle { thread_id, .. }) =
            runtime_values.get(&receiver)
        {
            return Some(SourceLocalRuntimeValue::ThreadId(*thread_id));
        }
    }

    if let Some(receiver) = receiver_before_method(statement, ".join()") {
        if let Some(SourceLocalRuntimeValue::TaskHandle { thread_id, .. }) =
            runtime_values.get(&receiver)
        {
            if let Some(thread) = state.threads.get(thread_id) {
                return Some(SourceLocalRuntimeValue::Artifact(artifact_handle_value(
                    state, thread,
                )));
            }
        }
    }

    None
}

fn extract_spawn_task_function(statement: &str) -> Option<String> {
    for marker in [
        "clusterflux::spawn::async_task(",
        "clusterflux::spawn::task(",
    ] {
        if let Some(args) = extract_call_arguments(statement, marker) {
            return args.first().cloned();
        }
    }
    for marker in [
        "clusterflux::spawn::async_task_with_arg(",
        "clusterflux::spawn::task_with_arg(",
    ] {
        if let Some(args) = extract_call_arguments(statement, marker) {
            return args.get(1).cloned();
        }
    }
    None
}

fn source_snapshot_digest_from_project(state: &AdapterState) -> Option<String> {
    let source = fs::read_to_string(crate::source::resolve_source_path(
        &state.project,
        &state.source_path,
    ))
    .ok()?;
    let digest_marker = source.find("digest:")?;
    let after_digest = &source[digest_marker..];
    let first_quote = after_digest.find('"')? + 1;
    let rest = &after_digest[first_quote..];
    let end_quote = rest.find('"')?;
    Some(rest[..end_quote].to_owned())
}

fn extract_call_arguments(statement: &str, marker: &str) -> Option<Vec<String>> {
    let start = statement.find(marker)? + marker.len();
    let rest = &statement[start..];
    let mut args = Vec::new();
    let mut current = String::new();
    let mut depth = 0_i32;
    let mut in_string = false;
    let mut escaped = false;

    for ch in rest.chars() {
        if in_string {
            current.push(ch);
            if escaped {
                escaped = false;
            } else if ch == '\\' {
                escaped = true;
            } else if ch == '"' {
                in_string = false;
            }
            continue;
        }

        match ch {
            '"' => {
                in_string = true;
                current.push(ch);
            }
            '(' | '[' | '{' => {
                depth += 1;
                current.push(ch);
            }
            ')' => {
                if depth == 0 {
                    let value = current.trim();
                    if !value.is_empty() {
                        args.push(value.to_owned());
                    }
                    return (!args.is_empty()).then_some(args);
                }
                depth -= 1;
                current.push(ch);
            }
            ']' | '}' => {
                depth -= 1;
                current.push(ch);
            }
            ',' if depth == 0 => {
                let value = current.trim();
                if !value.is_empty() {
                    args.push(value.to_owned());
                }
                current.clear();
            }
            _ => current.push(ch),
        }
    }

    None
}

fn extract_string_argument(statement: &str, marker: &str) -> Option<String> {
    let start = statement.find(marker)? + marker.len();
    let rest = &statement[start..];
    let quoted = rest.strip_prefix('"')?;
    let end = quoted.find('"')?;
    Some(quoted[..end].to_owned())
}

fn extract_env_name(statement: &str) -> Option<String> {
    if statement.contains("windows_env") || statement.contains("env!(\"windows\")") {
        return Some("windows".to_owned());
    }
    if statement.contains("linux_command_env") || statement.contains("env!(\"linux-command\")") {
        return Some("linux-command".to_owned());
    }
    if statement.contains("linux_env") || statement.contains("env!(\"linux\")") {
        return Some("linux".to_owned());
    }
    if statement.contains("coordinator_env") || statement.contains("env!(\"coordinator\")") {
        return Some("coordinator".to_owned());
    }
    None
}

fn receiver_before_method(statement: &str, method: &str) -> Option<String> {
    let before = statement.split(method).next()?.trim_end();
    let receiver = before
        .chars()
        .rev()
        .take_while(|ch| ch.is_ascii_alphanumeric() || *ch == '_')
        .collect::<String>()
        .chars()
        .rev()
        .collect::<String>();
    (!receiver.is_empty()).then_some(receiver)
}

fn thread_for_spawn_statement<'a>(
    state: &'a AdapterState,
    task_function: &str,
    task_name: Option<&str>,
) -> Option<&'a VirtualThread> {
    if let Some(task_name) = task_name {
        if let Some(thread) = state
            .threads
            .values()
            .find(|thread| thread.name == task_name)
        {
            return Some(thread);
        }
    }
    let normalized = task_function.replace('_', "-");
    state.threads.values().find(|thread| {
        thread.task.as_str() == normalized
            || (thread.id == PACKAGE_THREAD && normalized == "package-release")
    })
}

fn task_environment(thread: &VirtualThread) -> &'static str {
    match thread.id {
        WINDOWS_THREAD => "windows",
        MAIN_THREAD => "coordinator",
        PACKAGE_THREAD => "coordinator",
        LINUX_THREAD => "linux",
        _ => "unconstrained",
    }
}

fn artifact_handle_value(state: &AdapterState, thread: &VirtualThread) -> String {
    if state.runtime_backend != crate::virtual_model::RuntimeBackend::Simulated {
        return state.runtime_artifact_path.clone().unwrap_or_else(|| {
            "unavailable: runtime participant did not report an artifact handle".to_owned()
        });
    }
    if thread.id == LINUX_THREAD {
        return state.runtime_artifact_path.clone().unwrap_or_else(|| {
            format!("artifact://{}/{}/app.tar.zst", state.process, thread.task)
        });
    }
    if thread.id == PACKAGE_THREAD {
        return "artifact://package/release.tar.zst".to_owned();
    }
    format!("artifact://{}/{}/app.tar.zst", state.process, thread.task)
}

fn blob_digest(state: &AdapterState, thread: &VirtualThread) -> String {
    Digest::from_parts([
        b"blob:v1".as_slice(),
        state.project.as_bytes(),
        thread.task.as_str().as_bytes(),
    ])
    .as_str()
    .to_owned()
}

fn command_spec_summary(state: &AdapterState, thread: &VirtualThread) -> String {
    if state.runtime_backend != crate::virtual_model::RuntimeBackend::Simulated {
        return thread
            .runtime_command_status
            .clone()
            .unwrap_or_else(|| "no native command state reported".to_owned());
    }
    format!(
        "{} {} ({})",
        command_program(thread),
        command_args_summary(state, thread),
        state.command_status
    )
}

fn command_program(thread: &VirtualThread) -> &'static str {
    if thread.id == MAIN_THREAD {
        "coordinator-side wasm"
    } else {
        "cargo"
    }
}

fn command_args_summary(state: &AdapterState, thread: &VirtualThread) -> String {
    if thread.id == MAIN_THREAD {
        return format!("entry={}", state.entry);
    }
    format!("test --quiet --manifest-path {}/Cargo.toml", state.project)
}

fn output_tail_display(tail: &str, bytes: u64, truncated: bool, stream: &str) -> String {
    if tail.is_empty() {
        return format!("no {stream} captured ({bytes} bytes)");
    }
    if truncated {
        format!("{tail}\n... truncated")
    } else {
        tail.to_owned()
    }
}

fn project_snapshot_suffix(project: &str) -> String {
    Digest::from_parts([b"source-snapshot:v1".as_slice(), project.as_bytes()])
        .as_str()
        .trim_start_matches("sha256:")
        .chars()
        .take(12)
        .collect()
}
