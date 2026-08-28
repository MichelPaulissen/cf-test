use std::collections::{BTreeMap, HashMap};
use std::path::Path;

use clusterflux_core::{Capability, Digest};
use clusterflux_source::{snapshot_project, SourceSnapshotInventory};
use wasmparser::{Parser, Payload};

pub(super) fn verify_source_snapshot(
    project_root: &Path,
    expected: &Digest,
) -> Result<SourceSnapshotInventory, String> {
    let actual = snapshot_project(project_root)?;
    if &actual.digest != expected {
        return Err(format!(
            "node checkout source snapshot mismatch: task requires {expected}, but the current checkout is {}",
            actual.digest
        ));
    }
    Ok(actual)
}

pub(super) fn authorize_command_network(
    policy: &clusterflux_core::CommandNetworkPolicy,
    allow_network: bool,
) -> Result<(), String> {
    if policy == &clusterflux_core::CommandNetworkPolicy::Enabled && !allow_network {
        return Err(
            "Wasm task requested network access without an explicit granted Network capability"
                .to_owned(),
        );
    }
    Ok(())
}

pub(super) fn require_command_environment(environment_id: Option<&str>) -> Result<&str, String> {
    environment_id.ok_or_else(|| {
        "native commands require an explicit command-capable environment; attach one with .env(clusterflux::env!(\"name\"))"
            .to_owned()
    })
}

pub(super) fn verify_environment_digest(
    project_root: &Path,
    environment_id: &str,
    expected: &Digest,
) -> Result<clusterflux_core::EnvironmentResource, String> {
    let environment = clusterflux_core::discover_environments(project_root)
        .map_err(|error| error.to_string())?
        .into_iter()
        .find(|environment| environment.name == environment_id)
        .ok_or_else(|| {
            format!(
                "node checkout has no environment `{environment_id}` under {}/envs",
                project_root.display()
            )
        })?;
    if &environment.digest != expected {
        return Err(format!(
            "node environment `{environment_id}` does not match the bundle: task requires {expected}, but the current recipe is {}",
            environment.digest
        ));
    }
    Ok(environment)
}

pub(super) fn is_secret_environment_name(name: &str) -> bool {
    let name = name.to_ascii_uppercase();
    ["SECRET", "TOKEN", "PASSWORD", "CREDENTIAL", "PRIVATE_KEY"]
        .iter()
        .any(|marker| name.contains(marker))
}

pub(super) fn redact_configured_values(mut text: String, values: &[String]) -> String {
    for value in values.iter().filter(|value| value.len() >= 4) {
        text = text.replace(value, "[REDACTED]");
    }
    text
}

pub(super) fn capability_from_descriptor(value: &str) -> Result<Capability, String> {
    match value.trim().to_ascii_lowercase().replace('-', "_").as_str() {
        "command" => Ok(Capability::Command),
        "containers" => Ok(Capability::Containers),
        "rootless_podman" => Ok(Capability::RootlessPodman),
        "containerd_nerdctl" => Ok(Capability::ContainerdNerdctl),
        "source_filesystem" => Ok(Capability::SourceFilesystem),
        "source_git" => Ok(Capability::SourceGit),
        "host_filesystem" => Ok(Capability::HostFilesystem),
        "network" => Ok(Capability::Network),
        "secrets" => Ok(Capability::Secrets),
        "inbound_ports" => Ok(Capability::InboundPorts),
        "arbitrary_syscalls" => Ok(Capability::ArbitrarySyscalls),
        "vfs_artifacts" => Ok(Capability::VfsArtifacts),
        "windows_command_dev" => Ok(Capability::WindowsCommandDev),
        "artifact_transfer" => Ok(Capability::ArtifactTransfer),
        "workflow_compiler" | "workflow.compile" => Err(
            "workflow compilation is a release-owned system task, not a user capability".to_owned(),
        ),
        other => Err(format!("unknown task capability `{other}`")),
    }
}

pub(super) fn task_descriptors(
    module: &[u8],
) -> Result<HashMap<String, serde_json::Value>, Box<dyn std::error::Error>> {
    let mut descriptors = HashMap::new();
    for payload in Parser::new(0).parse_all(module) {
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
            let name = descriptor
                .get("name")
                .and_then(serde_json::Value::as_str)
                .ok_or("task descriptor omitted name")?
                .to_owned();
            descriptors.insert(name, descriptor);
        }
    }
    Ok(descriptors)
}

pub(super) fn bundle_environments(
    module: &[u8],
) -> Result<BTreeMap<String, clusterflux_core::EnvironmentResource>, Box<dyn std::error::Error>> {
    for payload in Parser::new(0).parse_all(module) {
        let Payload::CustomSection(section) = payload? else {
            continue;
        };
        if section.name() != "clusterflux.environments" {
            continue;
        }
        let environments: Vec<clusterflux_core::EnvironmentResource> =
            serde_json::from_slice(section.data())?;
        let mut by_name = BTreeMap::new();
        for environment in environments {
            if by_name
                .insert(environment.name.clone(), environment)
                .is_some()
            {
                return Err("bundle environment manifest contains duplicate names".into());
            }
        }
        return Ok(by_name);
    }
    Ok(BTreeMap::new())
}

pub(crate) fn resolve_task_export(
    module: &[u8],
    task: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    for payload in Parser::new(0).parse_all(module) {
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
            if descriptor.get("name").and_then(serde_json::Value::as_str) != Some(task) {
                continue;
            }
            if descriptor
                .get("abi_version")
                .and_then(serde_json::Value::as_u64)
                != Some(clusterflux_core::WASM_TASK_ABI_VERSION as u64)
            {
                return Err(format!("task `{task}` uses an unsupported Wasm ABI version").into());
            }
            return descriptor
                .get("export")
                .and_then(serde_json::Value::as_str)
                .filter(|export| !export.trim().is_empty())
                .map(str::to_owned)
                .ok_or_else(|| format!("task `{task}` descriptor omitted its Wasm export").into());
        }
    }
    Err(format!("bundle has no task descriptor named `{task}`").into())
}
