use std::collections::BTreeMap;

use clusterflux_core::{DebugRuntimeState, TaskInstanceId};

use crate::virtual_model::{AdapterState, VirtualThread};

pub(crate) const MAIN_THREAD: i64 = 1;
pub(crate) const LINUX_THREAD: i64 = 2;
pub(crate) const WINDOWS_THREAD: i64 = 3;
pub(crate) const PACKAGE_THREAD: i64 = 4;

pub(crate) fn is_explicit_demo_backend(value: &str) -> bool {
    value == "simulated" || value == "demo"
}

pub(crate) fn launch_threads(entry: &str) -> BTreeMap<i64, VirtualThread> {
    [
        thread(MAIN_THREAD, "main", &format!("{entry} virtual process"), 12),
        thread(LINUX_THREAD, "compile-linux", "compile linux", 42),
        thread(WINDOWS_THREAD, "compile-windows", "compile windows", 52),
        thread(PACKAGE_THREAD, "package-release", "package artifacts", 64),
    ]
    .into_iter()
    .map(|thread| (thread.id, thread))
    .collect()
}

pub(crate) fn start_simulated_backend(state: &mut AdapterState) {
    state.command_status = "running under simulated debug adapter state".to_owned();
}

fn thread(id: i64, task: &str, name: &str, line: i64) -> VirtualThread {
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
        task: TaskInstanceId::from(task),
        attempt_id: format!("demo-attempt-{id}"),
        task_definition: clusterflux_core::TaskDefinitionId::from(task),
        name: name.to_owned(),
        line,
        state: DebugRuntimeState::Running,
        freeze_supported: true,
        recent_output: vec![format!("{name}: waiting")],
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
        runtime_node: Some("demo-node".to_owned()),
        runtime_environment: Some("demo".to_owned()),
        runtime_vfs_checkpoint: Some("demo-vfs".to_owned()),
        restart_compatible: Some(true),
    }
}
