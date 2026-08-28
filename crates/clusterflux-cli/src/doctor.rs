use std::path::PathBuf;
use std::time::Duration;

use anyhow::{Context, Result};
use clusterflux_client::ProtocolSession;
use clusterflux_core::{Capability, NodeCapabilities};
use clusterflux_protocol::CoordinatorRequest;
use serde_json::{json, Value};

use crate::auth::auth_state_value;
use crate::config::read_project_config;
use crate::tools::{command_available, sibling_binary};
use crate::DoctorArgs;

const DOCTOR_COORDINATOR_TIMEOUT: Duration = Duration::from_millis(500);

pub(crate) fn doctor_report(args: DoctorArgs, cwd: PathBuf) -> Result<Value> {
    let config = read_project_config(&cwd)?;
    let coordinator = args.scope.coordinator.or_else(|| {
        config
            .as_ref()
            .and_then(|config| config.coordinator.clone())
    });
    let coordinator_reachability = coordinator_reachability(coordinator.as_deref());
    let dependencies = json!({
        "cargo": command_available("cargo"),
        "git": command_available("git"),
        "podman": command_available("podman"),
        "clusterflux-node": command_available("clusterflux-node") || sibling_binary("clusterflux-node").is_some(),
        "clusterflux-coordinator": command_available("clusterflux-coordinator") || sibling_binary("clusterflux-coordinator").is_some(),
        "clusterflux-debug-dap": command_available("clusterflux-debug-dap") || sibling_binary("clusterflux-debug-dap").is_some(),
    });
    let node_readiness = NodeCapabilities::detect_current();
    let node_readiness_summary = node_readiness_summary(&node_readiness, &dependencies);
    Ok(json!({
        "command": "doctor",
        "cwd": cwd,
        "coordinator": coordinator,
        "coordinator_reachability": coordinator_reachability,
        "auth": auth_state_value(&cwd)?,
        "project": config,
        "dependencies": dependencies,
        "node_readiness": node_readiness,
        "node_readiness_summary": node_readiness_summary,
        "next_actions": [
            "clusterflux login --browser",
            "clusterflux project init",
            "clusterflux node attach",
            "clusterflux run"
        ]
    }))
}

fn node_readiness_summary(capabilities: &NodeCapabilities, dependencies: &Value) -> Value {
    let has_command = capabilities.capabilities.contains(&Capability::Command);
    let has_vfs_artifacts = capabilities
        .capabilities
        .contains(&Capability::VfsArtifacts);
    let has_source_filesystem = capabilities
        .capabilities
        .contains(&Capability::SourceFilesystem);
    let has_container_backend = capabilities
        .environment_backends
        .contains(&clusterflux_core::EnvironmentBackend::Container);
    let podman_available = dependencies
        .get("podman")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let git_available = dependencies
        .get("git")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let clusterflux_node_available = dependencies
        .get("clusterflux-node")
        .and_then(Value::as_bool)
        .unwrap_or(false);

    let mut missing = Vec::new();
    if has_container_backend && !podman_available {
        missing.push("podman");
    }
    if capabilities.source_providers.contains("git") && !git_available {
        missing.push("git");
    }
    if !clusterflux_node_available {
        missing.push("clusterflux-node");
    }

    let basic_runtime_ready = true;
    let local_dependencies_ready = missing.is_empty();
    let status = if basic_runtime_ready && local_dependencies_ready {
        "ready_to_attach"
    } else if basic_runtime_ready {
        "local_dependencies_missing"
    } else {
        "limited_capabilities"
    };
    let next_actions = if status == "ready_to_attach" {
        vec![
            "clusterflux node enroll",
            "clusterflux node attach",
            "clusterflux-node --worker",
        ]
    } else {
        vec![
            "install missing local dependencies",
            "rerun clusterflux doctor",
        ]
    };

    json!({
        "status": status,
        "explicit_attach_required": true,
        "command_execution_capability": has_command,
        "wasm_runtime": "wasmtime",
        "wasm_runtime_is_baseline": true,
        "artifact_capability": has_vfs_artifacts,
        "source_filesystem_capability": has_source_filesystem,
        "container_backend_reported": has_container_backend,
        "podman_binary_available": podman_available,
        "git_binary_available": git_available,
        "node_binary_available": clusterflux_node_available,
        "missing_local_dependencies": missing,
        "source_providers": capabilities.source_providers.iter().collect::<Vec<_>>(),
        "next_actions": next_actions,
    })
}

fn coordinator_reachability(coordinator: Option<&str>) -> Value {
    let Some(coordinator) = coordinator else {
        return json!({
            "checked": false,
            "status": "not_configured",
            "next_action": "run clusterflux login --browser or pass --coordinator"
        });
    };

    match ping_coordinator(coordinator, DOCTOR_COORDINATOR_TIMEOUT) {
        Ok(response) => json!({
            "checked": true,
            "status": "reachable",
            "coordinator": coordinator,
            "response": response
        }),
        Err(err) => json!({
            "checked": true,
            "status": "unreachable",
            "coordinator": coordinator,
            "error": err.to_string(),
            "next_action": "check the coordinator URL, network, and service status"
        }),
    }
}

fn ping_coordinator(coordinator: &str, timeout: Duration) -> Result<Value> {
    let mut session =
        ProtocolSession::connect_with_timeouts(coordinator, "doctor", timeout, timeout)
            .with_context(|| format!("failed to connect to coordinator {coordinator}"))?;
    let response = session
        .request(&CoordinatorRequest::Ping)
        .with_context(|| format!("coordinator ping failed for {coordinator}"))?;
    Ok(serde_json::to_value(response)?)
}
