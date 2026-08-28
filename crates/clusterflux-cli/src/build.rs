use std::path::{Path, PathBuf};
use std::process::Command;

use anyhow::{bail, Context, Result};
use clusterflux_core::{
    discover_environments, finalize_compiled_workflow, CompiledWorkflowBundle,
    CompiledWorkflowInput, CompilerDependencyIdentity, CompilerIdentity, CompilerProfile, Digest,
};
use clusterflux_source::snapshot_project_with_provider;
use serde_json::{json, Value};

use crate::errors::cli_error_summary_for_category;
use crate::CheckArgs;
use crate::{bundle_inspection, BuildArgs, BundleInspectArgs};

pub(crate) fn build_report(args: BuildArgs, cwd: PathBuf) -> Result<Value> {
    let mut inspection = bundle_inspection(
        BundleInspectArgs {
            project: args.project.clone(),
            source_provider: args.source_provider.clone(),
            disabled_source_providers: args.disabled_source_providers.clone(),
            json: true,
        },
        cwd,
    )?;
    let diagnostics = inspection.pre_schedule_diagnostics.clone();
    let blocking_diagnostic = diagnostics
        .iter()
        .find(|diagnostic| diagnostic.severity == "error")
        .cloned();
    if let Some(diagnostic) = blocking_diagnostic {
        let machine_category = match diagnostic.category.as_str() {
            "environment" => "environment",
            "source_provider" | "capability" => "capability",
            _ => "unknown",
        };
        return Ok(json!({
            "command": "build",
            "status": "blocked_before_schedule",
            "bundle": inspection,
            "diagnostics": diagnostics,
            "contains_full_repository_upload": false,
            "content_addressed": false,
            "debug_metadata_available": false,
            "scheduled_work": false,
            "machine_error": cli_error_summary_for_category(machine_category, &diagnostic.message),
        }));
    }

    let wasm = compile_project_wasm(&inspection.project, args.entry.as_deref(), false)?;
    let compiled_task_abi = compiled_task_abi_digest(&wasm.task_descriptors);
    inspection.metadata.task_metadata.task_abi = compiled_task_abi.clone();
    inspection.metadata.task_metadata.entrypoints = wasm.bundle.entrypoints.clone();
    inspection.metadata.task_metadata.default_entrypoint = wasm.bundle.default_entrypoint.clone();
    inspection.metadata.task_metadata.authority = "compiled_wasm_descriptors".to_owned();
    inspection.metadata.task_metadata.boundary = "shared_bundle_finalizer".to_owned();
    inspection.metadata.restart_compatibility.compares_task_abi = compiled_task_abi;
    inspection.metadata.debug_metadata.probes = compiled_debug_probes(
        &inspection.metadata.debug_metadata.probes,
        &wasm.bundle.source_paths,
        &wasm.entrypoint_descriptors,
        &wasm.task_descriptors,
    );
    let bundle_digest = wasm.bundle.bundle_digest.clone();
    let source_snapshot = snapshot_project_with_provider(
        &inspection.project,
        &inspection.source_provider_manifest.kind,
    )
    .map_err(anyhow::Error::msg)
    .context("snapshot the source checkout used by this build")?;
    let task_compatibility_metadata = json!({
        "task_abi": inspection.metadata.task_metadata.task_abi,
        "restart": inspection.metadata.restart_compatibility,
        "descriptors": wasm.task_descriptors,
    });
    let environment_digests = inspection
        .metadata
        .environments
        .iter()
        .map(|environment| {
            json!({
                "name": environment.name,
                "digest": environment.digest,
            })
        })
        .collect::<Vec<_>>();
    let output = args.output.unwrap_or_else(|| {
        inspection.project.join("target/clusterflux/build").join(
            bundle_digest
                .as_str()
                .trim_start_matches("sha256:")
                .get(..16)
                .unwrap_or("bundle"),
        )
    });
    let bundle_artifact = write_bundle(
        &output,
        &wasm,
        &BundleWriteInputs {
            bundle_digest: &bundle_digest,
            inspection: &inspection,
            tasks: &wasm.task_descriptors,
            entrypoints: &wasm.entrypoint_descriptors,
            source_snapshot: &source_snapshot,
            selected_entrypoint: &wasm.selected_entrypoint,
            task_compatibility_metadata: &task_compatibility_metadata,
            environment_digests: &environment_digests,
        },
    )?;

    Ok(json!({
        "command": "build",
        "status": "built",
        "source_snapshot": source_snapshot,
        "bundle_digest": bundle_digest,
        "execution_module_digest": wasm.bundle.execution_module_digest,
        "selected_entrypoint": wasm.selected_entrypoint,
        "task_compatibility_metadata": task_compatibility_metadata,
        "environment_digests": environment_digests,
        "bundle": inspection,
        "bundle_artifact": bundle_artifact,
        "diagnostics": diagnostics,
        "contains_full_repository_upload": false,
        "content_addressed": true,
        "debug_metadata_available": true,
        "scheduled_work": false,
    }))
}

pub(crate) fn check_report(args: CheckArgs, cwd: PathBuf) -> Result<Value> {
    let project = args.project.unwrap_or(cwd);
    let compiled = compile_project_wasm(&project, None, args.message_format == "rustc-json")?;
    Ok(json!({
        "command": "check",
        "status": "checked",
        "project": project,
        "manifest_digest": compiled.bundle.manifest_digest,
        "workflow_tree_digest": compiled.bundle.source_tree_digest,
        "compiler": "cargo",
        "compiler_identity": compiled.bundle.compiler_identity,
        "message_format": args.message_format,
        "cargo_invoked": true,
        "descriptor_validation": true,
    }))
}

struct CompiledWasm {
    bytes: Vec<u8>,
    package: String,
    target: String,
    bundle: CompiledWorkflowBundle,
    debug_sidecar: Vec<u8>,
    task_descriptors: Vec<Value>,
    entrypoint_descriptors: Vec<Value>,
    selected_entrypoint: Value,
}

fn compile_project_wasm(
    project: &Path,
    requested_entrypoint: Option<&str>,
    rustc_json_errors: bool,
) -> Result<CompiledWasm> {
    let project_root = project
        .canonicalize()
        .context("resolve local Clusterflux project root")?;
    let workflow_root = project_root.join(".clusterflux");
    let manifest_path = workflow_root.join("Cargo.toml");
    let manifest_digest = Digest::sha256(
        std::fs::read(&manifest_path)
            .with_context(|| format!("read Cargo manifest {}", manifest_path.display()))?,
    );
    let metadata_output = Command::new("cargo")
        .args(["metadata", "--format-version", "1"])
        .arg("--manifest-path")
        .arg(&manifest_path)
        .output()
        .context("start cargo metadata for .clusterflux project")?;
    if !metadata_output.status.success() {
        bail!(
            "cargo metadata failed for {}: {}",
            manifest_path.display(),
            String::from_utf8_lossy(&metadata_output.stderr).trim()
        );
    }
    let metadata: Value = serde_json::from_slice(&metadata_output.stdout)
        .context("decode cargo metadata for .clusterflux project")?;
    let package = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages.iter().find(|package| {
                package["manifest_path"].as_str().is_some_and(|path| {
                    std::fs::canonicalize(path).ok() == std::fs::canonicalize(&manifest_path).ok()
                })
            })
        })
        .context("cargo metadata omitted the .clusterflux package")?;
    let package_name = package["name"]
        .as_str()
        .context("Cargo package omitted its name")?
        .to_owned();
    let target = package["targets"]
        .as_array()
        .and_then(|targets| {
            targets.iter().find(|target| {
                target["crate_types"]
                    .as_array()
                    .is_some_and(|types| types.iter().any(|kind| kind == "cdylib"))
            })
        })
        .context(".clusterflux Cargo package has no cdylib target")?;
    let target_name = target["name"]
        .as_str()
        .context("Cargo cdylib target omitted its name")?
        .to_owned();
    let target_dir = project_root.join("target/clusterflux/cargo");
    let remap = format!(
        "--remap-path-prefix={}=.clusterflux",
        workflow_root.display()
    );
    let flags = vec![
        "-Copt-level=1".to_owned(),
        "-Cdebuginfo=2".to_owned(),
        "-Cstrip=none".to_owned(),
        "-Cpanic=abort".to_owned(),
        remap,
    ];
    let compile = Command::new("cargo")
        .arg("rustc")
        .arg("--manifest-path")
        .arg(&manifest_path)
        .args([
            "--lib",
            "--release",
            "--target",
            "wasm32-unknown-unknown",
            "--target-dir",
        ])
        .arg(&target_dir)
        .arg("--message-format=json-render-diagnostics")
        .arg("--")
        .args(&flags)
        .output()
        .context("start Cargo workflow compilation")?;
    if !compile.status.success() {
        if rustc_json_errors {
            for diagnostic in canonical_rustc_diagnostics(&compile.stdout) {
                println!("{diagnostic}");
            }
            bail!("Clusterflux Cargo build failed; canonical rustc diagnostics were emitted");
        }
        bail!(
            "Clusterflux Cargo build failed:\n{}",
            cargo_diagnostics(&compile).trim()
        );
    }
    let module_path = cargo_wasm_artifact(&compile.stdout, &target_name).unwrap_or_else(|| {
        target_dir
            .join("wasm32-unknown-unknown/release")
            .join(format!("{}.wasm", target_name.replace('-', "_")))
    });
    let module = std::fs::read(&module_path)
        .with_context(|| format!("read Cargo Wasm artifact {}", module_path.display()))?;
    let (rustc_version, rustc_commit) = rustc_identity()?;
    let (sdk_version, sdk_digest) = cargo_sdk_identity(&metadata)?;
    let serde_identity = cargo_dependency_identity(&metadata, "serde", &["derive"])?;
    let compiler_identity = CompilerIdentity {
        profile: CompilerProfile::LocalCargo,
        rustc_version,
        rustc_commit,
        target: "wasm32-unknown-unknown".to_owned(),
        flags,
        sdk_version,
        sdk_digest,
        trusted_dependencies: vec![serde_identity],
        sandbox_image_digest: None,
    };
    let environments = discover_environments(&project_root)
        .map_err(|error| anyhow::Error::msg(error.to_string()))?
        .into_iter()
        .map(|mut environment| {
            if let Ok(relative) = environment.recipe_path.strip_prefix(&project_root) {
                environment.recipe_path = relative.to_path_buf();
            }
            if let Ok(relative) = environment.context_path.strip_prefix(&project_root) {
                environment.context_path = relative.to_path_buf();
            }
            environment
        })
        .collect::<Vec<_>>();
    let (source_paths, source_tree_digest) =
        cargo_compiled_source_identity(&target_dir, &target_name, &workflow_root)?;
    let finalized = finalize_compiled_workflow(CompiledWorkflowInput {
        wasm_bytes: module,
        compiler_identity,
        manifest_digest,
        source_identity: source_tree_digest,
        normalized_source_paths: source_paths,
        environments,
        requested_entrypoint: requested_entrypoint.map(str::to_owned),
    })
    .map_err(anyhow::Error::msg)
    .context("finalize Cargo workflow artifact")?;
    Ok(CompiledWasm {
        bytes: finalized.execution_module,
        package: package_name,
        target: target_name,
        bundle: finalized.bundle,
        debug_sidecar: finalized.debug_sidecar,
        task_descriptors: finalized.task_descriptors,
        entrypoint_descriptors: finalized.entrypoint_descriptors,
        selected_entrypoint: finalized.selected_entrypoint,
    })
}

fn cargo_wasm_artifact(stdout: &[u8], target_name: &str) -> Option<PathBuf> {
    String::from_utf8_lossy(stdout).lines().find_map(|line| {
        let message: Value = serde_json::from_str(line).ok()?;
        if message["reason"] != "compiler-artifact" || message["target"]["name"] != target_name {
            return None;
        }
        message["filenames"]
            .as_array()?
            .iter()
            .filter_map(Value::as_str)
            .find(|path| path.ends_with(".wasm"))
            .map(PathBuf::from)
    })
}

fn cargo_diagnostics(output: &std::process::Output) -> String {
    let rendered = String::from_utf8_lossy(&output.stdout)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|message| message["message"]["rendered"].as_str().map(str::to_owned))
        .collect::<String>();
    if rendered.trim().is_empty() {
        String::from_utf8_lossy(&output.stderr).trim().to_owned()
    } else {
        rendered.trim().to_owned()
    }
}

fn canonical_rustc_diagnostics(output: &[u8]) -> Vec<String> {
    String::from_utf8_lossy(output)
        .lines()
        .filter_map(|line| serde_json::from_str::<Value>(line).ok())
        .filter_map(|value| {
            if value.get("reason").and_then(Value::as_str) == Some("compiler-message") {
                value.get("message").cloned()
            } else if value.get("spans").and_then(Value::as_array).is_some() {
                Some(value)
            } else {
                None
            }
        })
        .filter_map(|diagnostic| serde_json::to_string(&diagnostic).ok())
        .collect()
}

fn compiled_task_abi_digest(descriptors: &[Value]) -> Digest {
    let mut descriptors = descriptors.to_vec();
    descriptors.sort_by(|left, right| {
        left.get("name")
            .and_then(Value::as_str)
            .cmp(&right.get("name").and_then(Value::as_str))
    });
    let mut parts = vec![b"compiled-task-abi:v1".to_vec()];
    for descriptor in descriptors {
        parts.push(serde_json::to_vec(&descriptor).expect("descriptor JSON is serializable"));
    }
    Digest::from_parts(parts)
}

fn compiled_debug_probes(
    candidates: &[clusterflux_core::BundleDebugProbe],
    compiled_source_paths: &[String],
    entrypoints: &[Value],
    tasks: &[Value],
) -> Vec<clusterflux_core::BundleDebugProbe> {
    let descriptors = entrypoints
        .iter()
        .chain(tasks)
        .filter_map(|descriptor| {
            Some((
                descriptor.get("name")?.as_str()?.to_owned(),
                descriptor.get("probe_symbol")?.as_str()?.to_owned(),
            ))
        })
        .collect::<std::collections::BTreeMap<_, _>>();
    let compiled_source_paths = compiled_source_paths
        .iter()
        .map(|path| path.trim_start_matches("./").replace('\\', "/"))
        .collect::<std::collections::BTreeSet<_>>();
    candidates
        .iter()
        .filter_map(|candidate| {
            let source_path = candidate.source_path.trim_start_matches("./");
            if !compiled_source_paths.contains(source_path) {
                return None;
            }
            let probe_symbol = descriptors.get(candidate.task.as_str())?.clone();
            let mut probe = candidate.clone();
            probe.id = Digest::from_parts([
                b"compiled-debug-probe:v1".as_slice(),
                source_path.as_bytes(),
                probe_symbol.as_bytes(),
            ])
            .as_str()
            .to_owned();
            probe.probe_symbol = probe_symbol;
            Some(probe)
        })
        .collect()
}

fn rustc_identity() -> Result<(String, Option<String>)> {
    let output = Command::new("rustc").arg("-vV").output()?;
    if !output.status.success() {
        bail!(
            "rustc -vV failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let text = String::from_utf8(output.stdout)?;
    let version = text
        .lines()
        .find_map(|line| line.strip_prefix("release: "))
        .unwrap_or(text.lines().next().unwrap_or("unknown"))
        .to_owned();
    let commit = text
        .lines()
        .find_map(|line| line.strip_prefix("commit-hash: "))
        .map(str::to_owned);
    Ok((version, commit))
}

fn cargo_sdk_identity(metadata: &Value) -> Result<(String, Digest)> {
    let package = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package["name"] == "clusterflux-sdk")
        })
        .context("Cargo dependency graph omitted clusterflux-sdk")?;
    let version = package["version"]
        .as_str()
        .context("clusterflux-sdk metadata omitted its version")?
        .to_owned();
    let manifest = package["manifest_path"]
        .as_str()
        .context("clusterflux-sdk metadata omitted its manifest path")?;
    let manifest_digest = Digest::sha256(
        std::fs::read(manifest).with_context(|| format!("read SDK manifest {manifest}"))?,
    );
    let digest = Digest::from_parts([
        b"clusterflux-sdk-package:v1".as_slice(),
        version.as_bytes(),
        manifest_digest.as_str().as_bytes(),
    ]);
    Ok((version, digest))
}

fn cargo_dependency_identity(
    metadata: &Value,
    package_name: &str,
    features: &[&str],
) -> Result<CompilerDependencyIdentity> {
    let package = metadata["packages"]
        .as_array()
        .and_then(|packages| {
            packages
                .iter()
                .find(|package| package["name"] == package_name)
        })
        .with_context(|| format!("Cargo dependency graph omitted {package_name}"))?;
    let version = package["version"]
        .as_str()
        .with_context(|| format!("{package_name} metadata omitted its version"))?
        .to_owned();
    let manifest = package["manifest_path"]
        .as_str()
        .with_context(|| format!("{package_name} metadata omitted its manifest path"))?;
    Ok(CompilerDependencyIdentity {
        package: package_name.to_owned(),
        version,
        features: features
            .iter()
            .map(|feature| (*feature).to_owned())
            .collect(),
        digest: Digest::sha256(
            std::fs::read(manifest)
                .with_context(|| format!("read trusted dependency manifest {manifest}"))?,
        ),
    })
}

fn cargo_compiled_source_identity(
    target_dir: &Path,
    target_name: &str,
    workflow_root: &Path,
) -> Result<(Vec<String>, Digest)> {
    let dependency_file = target_dir
        .join("wasm32-unknown-unknown/release")
        .join(format!("{}.d", target_name.replace('-', "_")));
    let dependency_info = std::fs::read_to_string(&dependency_file).with_context(|| {
        format!(
            "read Cargo dependency inventory {}",
            dependency_file.display()
        )
    })?;
    let mut paths = clusterflux_core::parse_makefile_dep_info(&dependency_info)
        .map_err(anyhow::Error::msg)?
        .into_iter()
        .filter_map(|candidate| {
            let path = Path::new(&candidate);
            let relative = path.strip_prefix(workflow_root).ok()?;
            (relative.extension().and_then(|value| value.to_str()) == Some("rs")).then(|| {
                format!(
                    ".clusterflux/{}",
                    relative.to_string_lossy().replace('\\', "/")
                )
            })
        })
        .collect::<Vec<_>>();
    paths.sort();
    paths.dedup();
    if paths.is_empty() {
        bail!("Cargo dependency inventory contains no compiled .clusterflux Rust sources");
    }
    let mut identity = vec![b"clusterflux-local-cargo-source:v2".to_vec()];
    for path in &paths {
        let relative = path.trim_start_matches(".clusterflux/");
        let bytes = std::fs::read(workflow_root.join(relative))
            .with_context(|| format!("read compiled workflow source inventory path `{path}`"))?;
        identity.push(path.as_bytes().to_vec());
        identity.push((bytes.len() as u64).to_be_bytes().to_vec());
        identity.push(Digest::sha256(bytes).as_str().as_bytes().to_vec());
    }
    Ok((paths, Digest::from_parts(identity)))
}

struct BundleWriteInputs<'a> {
    bundle_digest: &'a Digest,
    inspection: &'a crate::bundle::BundleInspection,
    tasks: &'a [Value],
    entrypoints: &'a [Value],
    source_snapshot: &'a clusterflux_source::SourceSnapshotInventory,
    selected_entrypoint: &'a Value,
    task_compatibility_metadata: &'a Value,
    environment_digests: &'a [Value],
}

fn write_bundle(
    output: &Path,
    wasm: &CompiledWasm,
    inputs: &BundleWriteInputs<'_>,
) -> Result<Value> {
    let BundleWriteInputs {
        bundle_digest,
        inspection,
        tasks,
        entrypoints,
        source_snapshot,
        selected_entrypoint,
        task_compatibility_metadata,
        environment_digests,
    } = inputs;
    std::fs::create_dir_all(output)?;
    let module_path = output.join("module.wasm");
    let task_path = output.join("task-descriptors.json");
    let entrypoint_path = output.join("entrypoints.json");
    let environment_path = output.join("environments.json");
    let source_path = output.join("source-provider.json");
    let source_snapshot_path = output.join("source-snapshot.json");
    let vfs_path = output.join("vfs-seed.json");
    let debug_path = output.join("debug-metadata.json");
    let debug_sidecar_path = output.join("debug-sidecar.json");
    let manifest_path = output.join("manifest.json");
    std::fs::write(&module_path, &wasm.bytes)?;
    write_json(&task_path, &json!(tasks))?;
    write_json(&entrypoint_path, &json!(entrypoints))?;
    write_json(&environment_path, &json!(inspection.metadata.environments))?;
    write_json(&source_path, &json!(inspection.source_provider_manifest))?;
    write_json(&source_snapshot_path, &json!(source_snapshot))?;
    write_json(
        &vfs_path,
        &json!({
            "epoch": 0,
            "mounts": ["/vfs/artifacts", "/vfs/sources", "/vfs/blobs"],
            "large_bytes_embedded": false,
        }),
    )?;
    write_json(&debug_path, &json!(inspection.metadata.debug_metadata))?;
    std::fs::write(&debug_sidecar_path, &wasm.debug_sidecar)?;
    let manifest = json!({
        "kind": "clusterflux-bundle",
        "format_version": 1,
        "package": wasm.package,
        "target": wasm.target,
        "bundle_digest": bundle_digest,
        "execution_module_digest": wasm.bundle.execution_module_digest,
        "manifest_digest": wasm.bundle.manifest_digest,
        "workflow_tree_digest": wasm.bundle.source_tree_digest,
        "debug_sidecar_digest": wasm.bundle.debug_sidecar_digest,
        "module": "module.wasm",
        "module_size_bytes": wasm.bytes.len(),
        "task_descriptors": "task-descriptors.json",
        "entrypoints": "entrypoints.json",
        "environments": "environments.json",
        "source_provider": "source-provider.json",
        "source_snapshot": source_snapshot,
        "selected_entrypoint": selected_entrypoint,
        "task_compatibility_metadata": task_compatibility_metadata,
        "environment_digests": environment_digests,
        "vfs_seed": "vfs-seed.json",
        "debug_metadata": "debug-metadata.json",
        "debug_sidecar": "debug-sidecar.json",
        "path_remapping": wasm.bundle.path_remapping,
        "required_capabilities": tasks.iter().flat_map(|task| {
            task["required_capabilities"].as_array().into_iter().flatten().cloned()
        }).collect::<Vec<_>>(),
        "metadata_identity": inspection.metadata.identity,
        "coordinator_receives_source_bytes_by_default": false,
        "embeds_full_repository": false,
    });
    write_json(&manifest_path, &manifest)?;
    Ok(json!({
        "directory": output,
        "manifest": manifest_path,
        "module": module_path,
        "debug_sidecar": debug_sidecar_path,
        "compiler": "cargo",
        "compiler_identity": wasm.bundle.compiler_identity,
        "source_paths": wasm.bundle.source_paths,
        "bundle_digest": bundle_digest,
        "execution_module_digest": wasm.bundle.execution_module_digest,
        "manifest_digest": wasm.bundle.manifest_digest,
        "debug_sidecar_digest": wasm.bundle.debug_sidecar_digest,
        "source_snapshot": source_snapshot,
        "selected_entrypoint": selected_entrypoint,
        "module_size_bytes": wasm.bytes.len(),
        "task_descriptor_count": tasks.len(),
        "entrypoint_count": entrypoints.len(),
        "files": [
            "manifest.json",
            "module.wasm",
            "task-descriptors.json",
            "entrypoints.json",
            "environments.json",
            "source-provider.json",
            "source-snapshot.json",
            "vfs-seed.json",
            "debug-metadata.json",
            "debug-sidecar.json",
        ],
    }))
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let mut bytes = serde_json::to_vec_pretty(value)?;
    bytes.push(b'\n');
    std::fs::write(path, bytes).with_context(|| format!("failed to write {}", path.display()))
}

#[cfg(test)]
mod diagnostic_tests {
    use super::*;

    #[test]
    fn canonicalizes_cargo_envelopes_and_accepts_raw_rustc_messages() {
        let diagnostic = json!({
            "message": "broken",
            "level": "error",
            "spans": [{"file_name": ".clusterflux/main.rs", "is_primary": true}]
        });
        let input = format!(
            "{}\n{}\n",
            json!({"reason": "compiler-message", "message": diagnostic}),
            diagnostic
        );
        let parsed = canonical_rustc_diagnostics(input.as_bytes());
        assert_eq!(parsed.len(), 2);
        assert_eq!(
            serde_json::from_str::<Value>(&parsed[0]).unwrap(),
            diagnostic
        );
        assert_eq!(
            serde_json::from_str::<Value>(&parsed[1]).unwrap(),
            diagnostic
        );
    }
}
