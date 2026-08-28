use std::fs;
use std::path::Path;

use anyhow::Result;
use serde_json::json;

use crate::virtual_model::{AdapterState, RuntimeLaunchRecord};

pub(crate) fn normalize_coordinator_endpoint(endpoint: &str) -> String {
    endpoint.trim().trim_end_matches('/').to_owned()
}

pub(crate) fn write_view_state(state: &AdapterState, record: &RuntimeLaunchRecord) -> Result<()> {
    let dir = Path::new(&state.project).join(".clusterflux-state");
    fs::create_dir_all(&dir)?;
    let node_status = if record.placed_task_launched {
        if record.status_code == Some(0) {
            "completed"
        } else {
            "failed"
        }
    } else {
        "not-required-yet"
    };
    let process_status = if record.placed_task_launched {
        if record.status_code == Some(0) {
            "completed"
        } else {
            "failed"
        }
    } else {
        "running"
    };
    let log_message = if record.placed_task_launched {
        "node task output was staged as a VFS artifact"
    } else {
        "coordinator-side virtual process started; capability task not launched"
    };
    let artifact_status = if record.placed_task_launched {
        "best-effort retained on the attached node"
    } else {
        "not produced until a capability task is placed"
    };
    let view_state = json!({
        "nodes": [{
            "id": record.node,
            "status": node_status,
            "capabilities": format!("connected to {}", record.coordinator),
        }],
        "processes": [{
            "id": state.process.as_str(),
            "status": process_status,
            "entry": state.entry,
        }],
        "logs": [{
            "task": "compile-linux",
            "message": log_message,
            "bytes": format!("stdout={} stderr={}", record.stdout_bytes, record.stderr_bytes),
        }],
        "artifacts": [{
            "path": record.artifact_path.clone().unwrap_or_else(|| "/vfs/artifacts/dap-output.txt".to_owned()),
            "status": artifact_status,
            "size": "reported by node",
        }],
        "inspector": [
            {
                "label": "Runtime backend",
                "value": state.runtime_backend.description(),
            },
            {
                "label": "Coordinator",
                "value": record.coordinator,
            },
            {
                "label": "Node report",
                "value": record.node_report.to_string(),
            },
            {
                "label": "Task events",
                "value": record.task_events.to_string(),
            }
        ]
    });
    fs::write(
        dir.join("views.json"),
        serde_json::to_string_pretty(&view_state)?,
    )?;
    Ok(())
}
