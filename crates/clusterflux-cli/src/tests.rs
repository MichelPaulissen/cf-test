#![allow(clippy::useless_concat)]

use std::fs;

use clap::CommandFactory;

use super::*;

fn parse(args: &[&str]) -> Cli {
    Cli::parse_from(args)
}

fn launch_attempt_from_wire(line: &str) -> String {
    let wire: Value = serde_json::from_str(line).unwrap();
    wire.pointer("/payload/request/launch_attempt")
        .or_else(|| wire.pointer("/payload/launch_attempt"))
        .and_then(Value::as_str)
        .expect("start request must carry a launch attempt")
        .to_owned()
}

fn canonical_error_response(line: &str, message: &str) -> Value {
    let wire: Value = serde_json::from_str(line).unwrap();
    let request_id = wire["request_id"]
        .as_str()
        .expect("coordinator request envelope must carry a request id");
    serde_json::to_value(clusterflux_protocol::CoordinatorResponse::error(
        request_id, message,
    ))
    .unwrap()
}

fn test_workflow_actor(
    kind: &str,
    user: Option<&str>,
    agent: Option<&str>,
    credential_kind: &str,
    authenticated_without_browser: bool,
) -> Value {
    json!({
        "kind": kind,
        "user": user,
        "agent": agent,
        "credential_kind": credential_kind,
        "public_key_fingerprint": null,
        "authenticated_without_browser": authenticated_without_browser,
        "scopes": ["project:read", "project:run"],
    })
}

fn test_node_capabilities() -> Value {
    json!({
        "os": "Linux",
        "arch": "x86_64",
        "capabilities": [],
        "environment_backends": [],
        "source_providers": [],
    })
}

fn test_artifact_connectivity() -> Value {
    json!({
        "endpoint_advertised": false,
        "recent_path": "unknown",
        "recent_direct_failure": false,
        "relay_policy": "direct_required",
    })
}

fn test_node_descriptor(id: &str, tenant: &str, project: &str, online: bool) -> Value {
    json!({
        "id": id,
        "tenant": tenant,
        "project": project,
        "capabilities": test_node_capabilities(),
        "cached_environments": [],
        "dependency_caches": [],
        "source_snapshots": [],
        "artifact_locations": [],
        "artifact_connectivity": test_artifact_connectivity(),
        "online": online,
    })
}

fn test_task_completion_event(
    tenant: &str,
    project: &str,
    process: &str,
    node: &str,
    task: &str,
) -> Value {
    json!({
        "tenant": tenant,
        "project": project,
        "process": process,
        "node": node,
        "executor": "node",
        "task_definition": format!("definition-{task}"),
        "task": task,
        "terminal_state": "completed",
        "status_code": 0,
        "stdout_bytes": 0,
        "stderr_bytes": 0,
        "stdout_tail": "",
        "stderr_tail": "",
        "stdout_truncated": false,
        "stderr_truncated": false,
        "artifact_path": null,
        "artifact_digest": null,
        "artifact_size_bytes": null,
        "result": null,
    })
}

fn write_runnable_wasm_project(project: &Path) {
    write_constrained_workflow(
        project,
        "cli-run-fixture",
        r#"
#[clusterflux::task]
#[unsafe(no_mangle)]
pub extern "C" fn task_add_one(value: i32) -> i32 { value + 1 }

#[clusterflux::main]
pub fn build_main() -> i32 { 7 }

#[clusterflux::main(name = "test")]
pub fn test_main() -> i32 { 8 }
"#,
    );
}

fn write_constrained_workflow(project: &Path, name: &str, source: &str) {
    fs::create_dir_all(project.join(".clusterflux")).unwrap();
    let sdk = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../clusterflux-sdk")
        .canonicalize()
        .unwrap();
    let sdk_hint = sdk.to_string_lossy();
    fs::write(
        project.join(".clusterflux/Cargo.toml"),
        format!(
            "[package]\nname = {name:?}\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\npath = \"main.rs\"\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nclusterflux = {{ package = \"clusterflux-sdk\", version = \"=0.2.0\", path = {sdk_hint:?} }}\n\n[workspace]\nresolver = \"3\"\n"
        ),
    )
    .unwrap();
    fs::write(project.join(".clusterflux/main.rs"), source).unwrap();
}

mod auth_and_doctor;
mod automation_ops;
mod bundle_and_node;
mod command_controls;
mod projects_and_reports;
mod run_and_login;
