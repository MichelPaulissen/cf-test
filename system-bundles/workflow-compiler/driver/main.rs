use std::path::{Path, PathBuf};
use std::process::Command;

use clusterflux_core::{
    CompiledWorkflowInput, CompilerDependencyIdentity, CompilerIdentity, CompilerProfile, Digest,
    EnvironmentResource, NormalizedWorkflowManifest, finalize_compiled_workflow,
};

fn main() {
    if let Err(error) = run() {
        eprintln!("Clusterflux system compiler driver: {error}");
        std::process::exit(1);
    }
}

fn run() -> Result<(), String> {
    let mut arguments = std::env::args_os().skip(1);
    let source = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("expected source path")?;
    let output = arguments
        .next()
        .map(PathBuf::from)
        .ok_or("expected bundle output path")?;
    if arguments.next().is_some() {
        return Err("unexpected compiler argument".to_owned());
    }
    let appliance_mode = std::env::var_os("CLUSTERFLUX_COMPILER_APPLIANCE").is_some();
    if appliance_mode
        && (source != Path::new("/workspace/main.rs")
            || output != Path::new("/clusterflux/output/bundle.json"))
    {
        return Err("compiler input/output paths must use the fixed appliance mounts".to_owned());
    }
    let workflow_root = source
        .parent()
        .ok_or("workflow crate root has no parent directory")?;
    let output_root = output
        .parent()
        .ok_or("compiler bundle output has no parent directory")?;
    let manifest_bytes = std::fs::read(workflow_root.join("Cargo.toml"))
        .map_err(|error| format!("read constrained workflow manifest: {error}"))?;
    let manifest = NormalizedWorkflowManifest::parse(&manifest_bytes)
        .map_err(|error| format!("validate constrained workflow manifest: {error}"))?;
    let module_path = output_root.join("workflow.wasm");
    let dependency_path = output_root.join("workflow.d");
    let rustc_path = std::env::var("CLUSTERFLUX_WORKFLOW_RUSTC").unwrap_or_else(|_| {
        if appliance_mode {
            "/opt/rust/bin/rustc".to_owned()
        } else {
            executable_on_path("rustc")
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "rustc".to_owned())
        }
    });
    let linker_path = std::env::var("CLUSTERFLUX_WORKFLOW_LINKER").unwrap_or_else(|_| {
        if appliance_mode {
            "/opt/rust/bin/rust-lld".to_owned()
        } else {
            executable_on_path("wasm-ld")
                .map(|path| path.display().to_string())
                .unwrap_or_else(|| "rust-lld".to_owned())
        }
    });
    let sdk_rlib = std::env::var("CLUSTERFLUX_WORKFLOW_SDK_RLIB")
        .unwrap_or_else(|_| "/opt/clusterflux/sdk/libclusterflux.rlib".to_owned());
    let sdk_dependencies = std::env::var("CLUSTERFLUX_WORKFLOW_SDK_DEPS")
        .unwrap_or_else(|_| "/opt/clusterflux/sdk/deps".to_owned());
    let serde_rlib = match std::env::var("CLUSTERFLUX_WORKFLOW_SERDE_RLIB") {
        Ok(path) => PathBuf::from(path),
        Err(_) => trusted_rlib(Path::new(&sdk_dependencies), "serde")?,
    };
    let crate_name = manifest.crate_name();
    let remap = format!(
        "--remap-path-prefix={}=.clusterflux",
        workflow_root.display()
    );
    let sdk_extern = format!("clusterflux={sdk_rlib}");
    let serde_extern = format!("serde={}", serde_rlib.display());
    let sdk_search = format!("-Ldependency={sdk_dependencies}");
    let linker = format!("-Clinker={linker_path}");
    let emit = format!("--emit=link,dep-info={}", dependency_path.display());
    let mut rustc_command = Command::new(&rustc_path);
    rustc_command.args([
        "--edition=2024",
        "--crate-name",
        crate_name.as_str(),
        "--crate-type=cdylib",
        "--target=wasm32-unknown-unknown",
        "-Copt-level=1",
        "-Cdebuginfo=2",
        "-Cstrip=none",
        "-Cpanic=abort",
        linker.as_str(),
        emit.as_str(),
        remap.as_str(),
        "--extern",
        sdk_extern.as_str(),
        // SDK derives expand to `serde` trait paths. This is a compiler-owned,
        // prebuilt dependency of the trusted SDK, not a user manifest dependency.
        "--extern",
        serde_extern.as_str(),
        sdk_search.as_str(),
    ]);
    if let Ok(host_dependencies) = std::env::var("CLUSTERFLUX_WORKFLOW_HOST_DEPS") {
        rustc_command.arg(format!("-Ldependency={host_dependencies}"));
    }
    if std::env::var("CLUSTERFLUX_RUSTC_ERROR_FORMAT").as_deref() == Ok("json") {
        rustc_command.arg("--error-format=json");
    }
    let rustc = rustc_command
        .arg(&source)
        .arg("-o")
        .arg(&module_path)
        .env_clear()
        .env(
            "PATH",
            Path::new(&rustc_path)
                .parent()
                .and_then(Path::to_str)
                .unwrap_or("/opt/rust/bin"),
        )
        .env("RUST_BACKTRACE", "0")
        .output()
        .map_err(|error| format!("start rustc: {error}"))?;
    if !rustc.status.success() {
        return Err(format!(
            "rustc failed: {}",
            bounded_text(
                &rustc.stderr,
                clusterflux_core::MAX_COMPILER_DIAGNOSTIC_BYTES
            )
        ));
    }
    let module = std::fs::read(module_path)
        .map_err(|error| format!("read compiled Wasm module: {error}"))?;
    let source_tree_digest = std::env::var("CLUSTERFLUX_SOURCE_TREE")
        .map_err(|_| "compiler source-tree digest is missing")?
        .strip_prefix("sha256:")
        .ok_or("compiler source-tree digest is malformed")
        .and_then(|value| {
            Digest::from_sha256_hex(value.to_owned())
                .map_err(|_| "compiler source-tree digest is malformed")
        })?;
    let (rustc_version, rustc_commit) = rustc_identity(&rustc_path)?;
    let sdk_digest = digest_from_environment("CLUSTERFLUX_COMPILER_SDK_DIGEST")?;
    let sandbox_image_digest = digest_from_environment("CLUSTERFLUX_COMPILER_IMAGE_DIGEST")?;
    let compiler_identity = CompilerIdentity {
        profile: CompilerProfile::HostedSandbox,
        rustc_version,
        rustc_commit,
        target: "wasm32-unknown-unknown".to_owned(),
        flags: vec![
            "-Copt-level=1".to_owned(),
            "-Cdebuginfo=2".to_owned(),
            "-Cstrip=none".to_owned(),
            "-Cpanic=abort".to_owned(),
            "--remap-path-prefix=/workspace=.clusterflux".to_owned(),
        ],
        sdk_version: clusterflux_core::SUPPORTED_WORKFLOW_SDK_VERSION.to_owned(),
        sdk_digest,
        trusted_dependencies: vec![CompilerDependencyIdentity {
            package: "serde".to_owned(),
            version: clusterflux_core::SUPPORTED_WORKFLOW_SERDE_VERSION.to_owned(),
            features: vec!["derive".to_owned()],
            digest: Digest::sha256(
                std::fs::read(&serde_rlib)
                    .map_err(|error| format!("read trusted Serde artifact: {error}"))?,
            ),
        }],
        sandbox_image_digest: Some(sandbox_image_digest),
    };
    let environments = read_environment_manifest(workflow_root)?;
    let finalized = finalize_compiled_workflow(CompiledWorkflowInput {
        wasm_bytes: module,
        compiler_identity,
        manifest_digest: manifest.digest,
        source_identity: source_tree_digest,
        normalized_source_paths: hosted_source_paths(workflow_root, &dependency_path)?,
        environments,
        requested_entrypoint: None,
    })?;
    let bytes = serde_json::to_vec(&finalized.bundle).map_err(|error| error.to_string())?;
    std::fs::write(output, bytes).map_err(|error| format!("write bundle: {error}"))
}

fn rustc_identity(rustc_path: &str) -> Result<(String, Option<String>), String> {
    let output = Command::new(rustc_path)
        .arg("-vV")
        .output()
        .map_err(|error| format!("inspect rustc identity: {error}"))?;
    if !output.status.success() {
        return Err("rustc -vV failed".to_owned());
    }
    let text = String::from_utf8(output.stdout).map_err(|error| error.to_string())?;
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

fn digest_from_environment(name: &str) -> Result<Digest, String> {
    let value = std::env::var(name).map_err(|_| format!("{name} is missing"))?;
    Digest::from_sha256_hex(
        value
            .strip_prefix("sha256:")
            .ok_or_else(|| format!("{name} is malformed"))?
            .to_owned(),
    )
    .map_err(|_| format!("{name} is malformed"))
}

fn read_environment_manifest(workflow_root: &Path) -> Result<Vec<EnvironmentResource>, String> {
    let path = workflow_root.join(".clusterflux-environments.json");
    if !path.exists() {
        return Ok(Vec::new());
    }
    let bytes = std::fs::read(&path)
        .map_err(|error| format!("read exact-revision environment manifest: {error}"))?;
    serde_json::from_slice(&bytes)
        .map_err(|error| format!("decode exact-revision environment manifest: {error}"))
}

fn hosted_source_paths(
    workflow_root: &Path,
    dependency_path: &Path,
) -> Result<Vec<String>, String> {
    let dependency_info = std::fs::read_to_string(dependency_path)
        .map_err(|error| format!("read rustc dependency inventory: {error}"))?;
    let mut paths = clusterflux_core::parse_makefile_dep_info(&dependency_info)?
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
    Ok(paths)
}

fn trusted_rlib(directory: &Path, crate_name: &str) -> Result<PathBuf, String> {
    let prefix = format!("lib{crate_name}-");
    let mut candidates = std::fs::read_dir(directory)
        .map_err(|error| format!("inspect trusted SDK dependency directory: {error}"))?
        .filter_map(Result::ok)
        .map(|entry| entry.path())
        .filter(|path| {
            path.file_name()
                .and_then(|name| name.to_str())
                .is_some_and(|name| name.starts_with(&prefix) && name.ends_with(".rlib"))
        })
        .collect::<Vec<_>>();
    candidates.sort();
    if candidates.len() != 1 {
        return Err(format!(
            "trusted SDK dependency `{crate_name}` must resolve to exactly one rlib"
        ));
    }
    Ok(candidates.pop().expect("one candidate was checked"))
}

fn executable_on_path(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|path| {
        std::env::split_paths(&path)
            .map(|directory| directory.join(name))
            .find(|candidate| candidate.is_file())
    })
}

fn bounded_text(bytes: &[u8], limit: usize) -> String {
    let bytes = &bytes[..bytes.len().min(limit)];
    String::from_utf8_lossy(bytes).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bounded_text_never_exceeds_the_diagnostic_budget() {
        assert_eq!(bounded_text(b"abcdef", 3), "abc");
        let limit = clusterflux_core::MAX_COMPILER_DIAGNOSTIC_BYTES;
        assert!(bounded_text(&vec![b'x'; limit + 1], limit).len() <= limit);
    }
}
