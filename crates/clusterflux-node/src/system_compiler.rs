//! Release-owned workflow compilation as an ordinary node system task.

use std::fs::{self, OpenOptions};
use std::io::{Read, Seek};
#[cfg(unix)]
use std::os::fd::AsRawFd;
#[cfg(unix)]
use std::os::unix::process::CommandExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use crate::daemon::Args;
use clusterflux_core::{
    workflow_compiler_system_bundle_digest, CommandBackendKind, CommandInvocation,
    CommandNetworkPolicy, Digest, NodeId, ProcessId, SystemBundleCapability, SystemTaskSandbox,
    TaskDefinitionId, TaskInstanceId, VfsOverlay, WasmHostCommandRequest, WasmHostCommandResult,
    WasmHostSourceSnapshotRequest, WasmHostSourceSnapshotResult, WasmHostTaskControlRequest,
    WasmHostTaskControlResult, WasmHostTaskHandle, WasmHostTaskJoinRequest, WasmHostTaskJoinResult,
    WasmHostVfsRequest, WasmHostVfsResult, WasmTaskInvocation, WorkflowCompilationRequest,
    WorkflowCompilationResult, MAX_COMPILER_DIAGNOSTIC_BYTES, WASM_TASK_ABI_VERSION,
    WORKFLOW_COMPILER_SYSTEM_BUNDLE_BYTES, WORKFLOW_COMPILER_SYSTEM_TASK_NAME,
};
use clusterflux_node::{
    BackendError, ContainerRunPolicy, LinuxRootlessPodmanBackend, LocalSourceCheckout,
    MaterializedEnvironment, PodmanCommand, ProcessOutput, ProcessRunner,
};
use clusterflux_wasm_runtime::{
    AsyncWasmTaskHost, WasmExecution, WasmExecutionService, WasmHostFuture, WasmTaskError,
    WasmtimeRuntimeLimits,
};
use tokio_util::sync::CancellationToken;

const MAX_COMPILER_OUTPUT_FILES: usize = 8;
pub(crate) struct SystemCompilationExecution {
    execution: WasmExecution,
    result: Arc<Mutex<Option<WorkflowCompilationResult>>>,
    cancellation: CancellationToken,
    abort: Arc<AtomicBool>,
    fallback: WorkflowCompilationResult,
}

impl SystemCompilationExecution {
    pub(crate) fn abort(&self) {
        self.abort.store(true, Ordering::Release);
        self.cancellation.cancel();
    }

    pub(crate) fn try_result(&mut self) -> Option<WorkflowCompilationResult> {
        let wasm_result = self.execution.try_result()?;
        Some(finish_system_compilation(
            &self.result,
            &self.fallback,
            wasm_result,
        ))
    }
}

fn finish_system_compilation(
    result: &Mutex<Option<WorkflowCompilationResult>>,
    fallback: &WorkflowCompilationResult,
    wasm_result: Result<clusterflux_core::WasmTaskResult, WasmTaskError>,
) -> WorkflowCompilationResult {
    if let Ok(mut result) = result.lock() {
        if let Some(result) = result.take() {
            return result;
        }
    }
    let mut fallback = fallback.clone();
    fallback.compiler_transcript = truncate(
        match wasm_result {
            Ok(result) => format!(
                "compiler system bundle returned no compiler result: {:?}",
                result.outcome
            ),
            Err(error) => format!("compiler system bundle execution failed: {error}"),
        },
        MAX_COMPILER_DIAGNOSTIC_BYTES,
    );
    fallback
}

struct SystemCompilerHost {
    args: Args,
    request: WorkflowCompilationRequest,
    assignment_id: String,
    attempt_id: String,
    lease_epoch: u64,
    result: Arc<Mutex<Option<WorkflowCompilationResult>>>,
    cancellation: CancellationToken,
    abort: Arc<AtomicBool>,
}

impl AsyncWasmTaskHost for SystemCompilerHost {
    fn abort_signal(&self) -> Option<Arc<AtomicBool>> {
        Some(Arc::clone(&self.abort))
    }

    fn start_task(
        &mut self,
        _request: clusterflux_core::WasmHostTaskStartRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskHandle> {
        Box::pin(async { Err("system compiler bundle cannot start child tasks".to_owned()) })
    }

    fn join_task(
        &mut self,
        _request: WasmHostTaskJoinRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskJoinResult> {
        Box::pin(async { Err("system compiler bundle has no child tasks".to_owned()) })
    }

    fn run_command(
        &mut self,
        command: WasmHostCommandRequest,
    ) -> WasmHostFuture<'_, WasmHostCommandResult> {
        let args = self.args.clone();
        let request = self.request.clone();
        let assignment_id = self.assignment_id.clone();
        let attempt_id = self.attempt_id.clone();
        let lease_epoch = self.lease_epoch;
        let result_slot = Arc::clone(&self.result);
        let cancellation = self.cancellation.clone();
        Box::pin(async move {
            command.validate()?;
            if command.program != "/opt/clusterflux/bin/compile-workflow"
                || command.args != ["/workspace/main.rs", "/clusterflux/output/bundle.json"]
                || command.working_directory != "/workspace"
                || command.network != clusterflux_core::CommandNetworkPolicy::Disabled
                || !command.environment_variables.is_empty()
                || !command.secret_environment_variables.is_empty()
            {
                return Err(
                    "system compiler bundle requested command authority outside its fixed policy"
                        .to_owned(),
                );
            }
            let compiled = tokio::task::spawn_blocking(move || {
                compile_assignment(
                    &args,
                    request,
                    assignment_id,
                    attempt_id,
                    lease_epoch,
                    cancellation,
                )
            })
            .await
            .map_err(|error| format!("system compiler command worker failed: {error}"))?;
            let succeeded = compiled.bundle.is_some();
            let transcript = compiled.compiler_transcript.clone();
            result_slot
                .lock()
                .map_err(|_| "system compiler result lock was poisoned".to_owned())?
                .replace(compiled);
            Ok(WasmHostCommandResult {
                abi_version: WASM_TASK_ABI_VERSION,
                status_code: Some(if succeeded { 0 } else { 1 }),
                stdout: String::new(),
                stderr: transcript,
                stdout_truncated: false,
                stderr_truncated: false,
            })
        })
    }

    fn poll_task_control(
        &mut self,
        request: WasmHostTaskControlRequest,
    ) -> WasmHostFuture<'_, WasmHostTaskControlResult> {
        let cancelled = self.cancellation.is_cancelled() || self.abort.load(Ordering::Acquire);
        Box::pin(async move {
            request.validate()?;
            Ok(WasmHostTaskControlResult {
                abi_version: WASM_TASK_ABI_VERSION,
                cancellation_requested: cancelled,
            })
        })
    }

    fn vfs_operation(
        &mut self,
        _request: WasmHostVfsRequest,
    ) -> WasmHostFuture<'_, WasmHostVfsResult> {
        Box::pin(async { Err("system compiler bundle has no VFS authority".to_owned()) })
    }

    fn snapshot_source(
        &mut self,
        _request: WasmHostSourceSnapshotRequest,
    ) -> WasmHostFuture<'_, WasmHostSourceSnapshotResult> {
        Box::pin(async {
            Err("system compiler bundle receives only bounded assigned source".to_owned())
        })
    }
}

pub(crate) fn start_system_compilation(
    service: &WasmExecutionService,
    args: &Args,
    request: WorkflowCompilationRequest,
    assignment_id: String,
    attempt_id: String,
    lease_epoch: u64,
    cancellation: CancellationToken,
) -> Result<SystemCompilationExecution, Box<dyn std::error::Error>> {
    let module = WORKFLOW_COMPILER_SYSTEM_BUNDLE_BYTES.to_vec();
    let export = crate::assignment_runner::validation::resolve_task_export(
        &module,
        WORKFLOW_COMPILER_SYSTEM_TASK_NAME,
    )?;
    let result = Arc::new(Mutex::new(None));
    let abort = Arc::new(AtomicBool::new(false));
    let fallback = WorkflowCompilationResult {
        assignment_id: assignment_id.clone(),
        attempt_id: attempt_id.clone(),
        lease_epoch,
        run_id: request.run_id.clone(),
        node: NodeId::new(args.node.clone()),
        bundle: None,
        compiler_transcript: "compiler system bundle did not complete".to_owned(),
        failure_code: Some("system_bundle_failed".to_owned()),
        retryable: true,
    };
    let host = SystemCompilerHost {
        args: args.clone(),
        request,
        assignment_id,
        attempt_id,
        lease_epoch,
        result: Arc::clone(&result),
        cancellation: cancellation.clone(),
        abort: Arc::clone(&abort),
    };
    let invocation = WasmTaskInvocation::new(
        TaskDefinitionId::from(WORKFLOW_COMPILER_SYSTEM_TASK_NAME),
        TaskInstanceId::from(WORKFLOW_COMPILER_SYSTEM_TASK_NAME),
        Vec::new(),
    );
    let execution = service.submit_task_export_verified(
        module,
        workflow_compiler_system_bundle_digest(),
        export,
        invocation,
        WasmtimeRuntimeLimits::default(),
        Box::new(host),
    )?;
    Ok(SystemCompilationExecution {
        execution,
        result,
        cancellation,
        abort,
        fallback,
    })
}

pub(crate) fn self_check(args: &mut Args) -> Result<SystemBundleCapability, String> {
    let manifest = clusterflux_core::workflow_compiler_system_manifest();
    materialize_packaged_compiler_image(args)?;
    let image = required_setting(
        args.system_compiler_image.as_deref(),
        "--system-compiler-image",
    )?;
    if image.contains(char::is_whitespace) || image.contains("latest") {
        return Err(
            "workflow compiler image must be an immutable, non-latest OCI reference".into(),
        );
    }
    let digest = image.rsplit_once('@').map_or(image, |(_, digest)| digest);
    Digest::from_sha256_hex(
        digest
            .strip_prefix("sha256:")
            .ok_or("workflow compiler image digest must begin with sha256:")?,
    )?;
    if image != digest && !image.ends_with(&format!("@{digest}")) {
        return Err("system compiler image reference must end in its immutable digest".into());
    }
    let sandbox = if args.system_compiler_sandbox == "gvisor" {
        let expected_version = required_setting(
            args.system_compiler_runsc_version.as_deref(),
            "--system-compiler-runsc-version",
        )?;
        let output = Command::new(&args.system_compiler_runsc)
            .arg("--version")
            .output()
            .map_err(|error| format!("execute pinned gVisor runtime: {error}"))?;
        if !output.status.success() {
            return Err("pinned gVisor runsc runtime is unavailable".into());
        }
        let version = String::from_utf8_lossy(&output.stdout);
        let resolved_runsc = fs::canonicalize(&args.system_compiler_runsc)
            .map_err(|error| format!("resolve pinned gVisor runtime: {error}"))?;
        if !runsc_version_matches(expected_version, &version, &resolved_runsc) {
            return Err(format!(
                "runsc version does not match configured pin `{expected_version}`: {} ({})",
                version.trim(),
                resolved_runsc.display()
            ));
        }
        SystemTaskSandbox::Gvisor
    } else {
        SystemTaskSandbox::RootlessPodman
    };
    let podman_info = Command::new(&args.system_compiler_podman)
        .args(["info", "--format", "{{.Host.Security.Rootless}}"])
        .output()
        .map_err(|error| format!("execute rootless Podman self-check: {error}"))?;
    if !podman_info.status.success()
        || String::from_utf8_lossy(&podman_info.stdout).trim() != "true"
    {
        return Err("workflow compiler requires rootless Podman".into());
    }
    let image_status = Command::new(&args.system_compiler_podman)
        .args(["image", "exists", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("inspect pinned compiler environment: {error}"))?;
    if !image_status.success() {
        return Err("pinned workflow compiler environment is not present locally".into());
    }
    let image_environment = Command::new(&args.system_compiler_podman)
        .args([
            "image",
            "inspect",
            "--format",
            "{{ index .Config.Labels \"org.clusterflux.environment-digest\" }}",
            image,
        ])
        .output()
        .map_err(|error| format!("inspect compiler environment identity: {error}"))?;
    let image_environment_matches = image_environment.status.success()
        && String::from_utf8_lossy(&image_environment.stdout).trim()
            == manifest.environment_digest.as_str();
    if !image_environment_matches && !args.system_compiler_package_verified {
        return Err(format!(
            "pinned workflow compiler environment does not match this Clusterflux release (expected {})",
            manifest.environment_digest
        ));
    }
    tempfile::Builder::new()
        .prefix("clusterflux-compiler-self-check-")
        .tempdir()
        .map_err(|error| format!("create bounded compiler output directory: {error}"))?;
    Ok(SystemBundleCapability {
        bundle_id: manifest.bundle_id,
        bundle_digest: manifest.bundle_digest,
        sdk_abi_version: manifest.sdk_abi_version,
        wasm_target: manifest.wasm_target,
        rust_toolchain: manifest.rust_toolchain,
        environment_digest: manifest.environment_digest,
        sandbox,
        max_source_bytes: manifest.max_source_bytes,
        max_output_bytes: manifest.max_output_bytes,
        max_concurrent_assignments: 1,
    })
}

fn materialize_packaged_compiler_image(args: &mut Args) -> Result<(), String> {
    let package = match installed_system_compiler_package(false) {
        Ok(package) => package,
        Err(_) if args.system_compiler_image.is_some() => return Ok(()),
        Err(error) => return Err(error),
    };
    if args
        .system_compiler_image
        .as_deref()
        .is_some_and(|configured| configured != package.image_reference)
    {
        return Ok(());
    }
    let _import_lock = CompilerImageImportLock::acquire(&package.image_digest)?;
    if packaged_compiler_image_matches(
        compiler_image_identity(args, &package.image_reference)?.as_ref(),
        &package,
    ) {
        eprintln!(
            "Automatic workflow compiler image already present: {} ({})",
            package.image_reference, package.environment_digest
        );
        args.system_compiler_image = Some(package.image_reference);
        args.system_compiler_package_verified = true;
        args.system_compiler_package_dir = Some(package.share_dir);
        return Ok(());
    }
    let package = installed_system_compiler_package(true)?;
    let loaded = Command::new(&args.system_compiler_podman)
        .args(["load", "--input"])
        .arg(&package.archive)
        .output()
        .map_err(|error| format!("load packaged compiler environment: {error}"))?;
    if !loaded.status.success() {
        return Err(format!(
            "load packaged compiler environment: {}",
            String::from_utf8_lossy(&loaded.stderr).trim()
        ));
    }
    let Some(identity) = compiler_image_identity(args, &package.image_reference)? else {
        return Err("packaged compiler environment did not load its release identity".to_owned());
    };
    if identity.image_digest != package.image_digest
        || identity
            .environment_digest
            .as_ref()
            .is_some_and(|digest| digest != &package.environment_digest)
    {
        return Err(format!(
            "imported compiler image identity mismatch: expected {} / {}, got {} / {}",
            package.image_digest,
            package.environment_digest,
            identity.image_digest,
            identity
                .environment_digest
                .as_ref()
                .map_or("unlabeled", Digest::as_str),
        ));
    }
    eprintln!(
        "Automatic workflow compiler image imported: {} ({})",
        package.image_reference, package.environment_digest
    );
    args.system_compiler_image = Some(package.image_reference);
    args.system_compiler_package_verified = true;
    args.system_compiler_package_dir = Some(package.share_dir);
    Ok(())
}

fn installed_system_compiler_package(
    verify_archive: bool,
) -> Result<clusterflux_node::system_package::VerifiedSystemCompilerPackage, String> {
    let executable = std::env::current_exe()
        .map_err(|error| format!("locate clusterflux-node executable: {error}"))?;
    let install_root = executable
        .parent()
        .and_then(Path::parent)
        .ok_or("clusterflux-node executable has no install root")?;
    let share_dir = install_root.join("share").join("clusterflux");
    let package = if verify_archive {
        clusterflux_node::system_package::verify_system_compiler_package(&share_dir)
    } else {
        clusterflux_node::system_package::inspect_system_compiler_package(&share_dir)
    };
    package
        .map_err(|error| {
            format!(
                "installed compiler package at {} is unavailable: {error}; reinstall clusterflux-node or provide --system-compiler-image",
                share_dir.display()
            )
        })
}

struct CompilerImageIdentity {
    image_digest: Digest,
    environment_digest: Option<Digest>,
}

fn packaged_compiler_image_matches(
    identity: Option<&CompilerImageIdentity>,
    package: &clusterflux_node::system_package::VerifiedSystemCompilerPackage,
) -> bool {
    identity.is_some_and(|identity| {
        identity.image_digest == package.image_digest
            && identity
                .environment_digest
                .as_ref()
                .is_none_or(|digest| digest == &package.environment_digest)
    })
}

fn compiler_image_identity(
    args: &Args,
    image: &str,
) -> Result<Option<CompilerImageIdentity>, String> {
    let exists = Command::new(&args.system_compiler_podman)
        .args(["image", "exists", image])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()
        .map_err(|error| format!("inspect packaged compiler image presence: {error}"))?;
    if !exists.success() {
        if exists.code() == Some(1) {
            return Ok(None);
        }
        return Err(format!(
            "inspect packaged compiler image presence failed with status {:?}",
            exists.code()
        ));
    }
    let inspected = Command::new(&args.system_compiler_podman)
        .args([
            "image",
            "inspect",
            "--format",
            "{{.Id}}\n{{ index .Config.Labels \"org.clusterflux.environment-digest\" }}",
            image,
        ])
        .output()
        .map_err(|error| format!("inspect packaged compiler image identity: {error}"))?;
    if !inspected.status.success() {
        return Err(format!(
            "inspect packaged compiler image identity failed: {}",
            String::from_utf8_lossy(&inspected.stderr).trim()
        ));
    }
    let output = String::from_utf8_lossy(&inspected.stdout);
    let mut lines = output.lines();
    let image_id = lines.next().unwrap_or_default().trim();
    let image_id = image_id.strip_prefix("sha256:").unwrap_or(image_id);
    let image_digest = Digest::from_sha256_hex(image_id)
        .map_err(|error| format!("inspect packaged compiler image digest: {error}"))?;
    let environment = lines.next().unwrap_or_default().trim();
    let environment_digest = if environment.is_empty() {
        None
    } else {
        Some(
            Digest::from_sha256_hex(
                environment
                    .strip_prefix("sha256:")
                    .ok_or("inspect packaged compiler environment digest omitted sha256 prefix")?,
            )
            .map_err(|error| format!("inspect packaged compiler environment digest: {error}"))?,
        )
    };
    Ok(Some(CompilerImageIdentity {
        image_digest,
        environment_digest,
    }))
}

struct CompilerImageImportLock {
    _file: fs::File,
}

impl CompilerImageImportLock {
    fn acquire(image_digest: &Digest) -> Result<Self, String> {
        let directory = std::env::var_os("XDG_RUNTIME_DIR")
            .map(PathBuf::from)
            .unwrap_or_else(std::env::temp_dir)
            .join("clusterflux");
        Self::acquire_in(&directory, image_digest)
    }

    fn acquire_in(directory: &Path, image_digest: &Digest) -> Result<Self, String> {
        fs::create_dir_all(directory)
            .map_err(|error| format!("create compiler image import lock directory: {error}"))?;
        let lock_name = format!(
            "compiler-image-{}.lock",
            image_digest.as_str().trim_start_matches("sha256:")
        );
        let file = OpenOptions::new()
            .read(true)
            .write(true)
            .create(true)
            .truncate(false)
            .open(directory.join(lock_name))
            .map_err(|error| format!("open compiler image import lock: {error}"))?;
        #[cfg(unix)]
        {
            let status = unsafe { libc::flock(file.as_raw_fd(), libc::LOCK_EX) };
            if status != 0 {
                return Err(format!(
                    "acquire compiler image import lock: {}",
                    std::io::Error::last_os_error()
                ));
            }
        }
        Ok(Self { _file: file })
    }
}

impl Drop for CompilerImageImportLock {
    fn drop(&mut self) {
        #[cfg(unix)]
        unsafe {
            libc::flock(self._file.as_raw_fd(), libc::LOCK_UN);
        }
    }
}

fn runsc_version_matches(expected: &str, version: &str, resolved_path: &Path) -> bool {
    version.contains(expected) || resolved_path.to_string_lossy().contains(expected)
}

pub(crate) fn compile_assignment(
    args: &Args,
    request: WorkflowCompilationRequest,
    assignment_id: String,
    attempt_id: String,
    lease_epoch: u64,
    cancellation: CancellationToken,
) -> WorkflowCompilationResult {
    let manifest = clusterflux_core::workflow_compiler_system_manifest();
    let node = NodeId::new(args.node.clone());
    let failure = |code: &str, message: String, retryable: bool| WorkflowCompilationResult {
        assignment_id: assignment_id.clone(),
        attempt_id: attempt_id.clone(),
        lease_epoch,
        run_id: request.run_id.clone(),
        node: node.clone(),
        bundle: None,
        compiler_transcript: truncate(message, MAX_COMPILER_DIAGNOSTIC_BYTES),
        failure_code: Some(code.to_owned()),
        retryable,
    };
    if let Err(error) = request.validate() {
        return failure("invalid_request", error, false);
    }
    if request.compiler_image != manifest.environment_digest {
        return failure(
            "compiler_identity_mismatch",
            "compiler assignment does not match this node's pinned image".to_owned(),
            false,
        );
    }
    if request.compiler_profile
        != clusterflux_core::workflow_compiler_profile_id(&request.compiler_image)
    {
        return failure(
            "compiler_identity_mismatch",
            "compiler assignment does not match this node's compiler profile".to_owned(),
            false,
        );
    }
    if request.compiler_sdk != manifest.sdk_digest {
        return failure(
            "compiler_identity_mismatch",
            "compiler assignment does not match this node's pinned SDK".to_owned(),
            false,
        );
    }
    if request.rust_toolchain != manifest.rust_toolchain {
        return failure(
            "compiler_identity_mismatch",
            "compiler assignment does not match this node's pinned Rust toolchain".to_owned(),
            false,
        );
    }

    let temp = match tempfile::Builder::new()
        .prefix("clusterflux-gvisor-compile-")
        .tempdir()
    {
        Ok(temp) => temp,
        Err(error) => return failure("temporary_storage", error.to_string(), true),
    };
    let source_dir = temp.path().join("source");
    let output_dir = temp.path().join("output");
    if let Err(error) = fs::create_dir_all(&source_dir).and_then(|_| fs::create_dir(&output_dir)) {
        return failure("temporary_storage", error.to_string(), true);
    }
    for file in &request.source.files {
        let relative = match file.path.strip_prefix(".clusterflux/") {
            Some(relative) => relative,
            None => {
                return failure(
                    "invalid_source_path",
                    format!("compiler source path escaped .clusterflux: {}", file.path),
                    false,
                )
            }
        };
        let destination = source_dir.join(relative);
        if let Some(parent) = destination.parent() {
            if let Err(error) = fs::create_dir_all(parent) {
                return failure("temporary_storage", error.to_string(), true);
            }
        }
        if let Err(error) = fs::write(&destination, &file.bytes) {
            return failure("temporary_storage", error.to_string(), true);
        }
    }
    let environment_manifest = match serde_json::to_vec(&request.source.environments) {
        Ok(bytes) => bytes,
        Err(error) => return failure("invalid_environment_manifest", error.to_string(), false),
    };
    if let Err(error) = fs::write(
        source_dir.join(".clusterflux-environments.json"),
        environment_manifest,
    ) {
        return failure("temporary_storage", error.to_string(), true);
    }
    if let Err(error) = make_source_read_only(&source_dir) {
        return failure("temporary_storage", error.to_string(), true);
    }

    let image = match args.system_compiler_image.as_deref() {
        Some(image) => image,
        None => {
            return failure(
                "configuration",
                "compiler image is missing".to_owned(),
                false,
            )
        }
    };
    let invocation = CommandInvocation {
        program: "/opt/clusterflux/bin/compile-workflow".to_owned(),
        args: vec![
            "/workspace/main.rs".to_owned(),
            "/clusterflux/output/bundle.json".to_owned(),
        ],
        working_directory: "/workspace".to_owned(),
        environment_variables: [
            (
                "CLUSTERFLUX_SOURCE_TREE".to_owned(),
                request.source.tree_digest.to_string(),
            ),
            (
                "CLUSTERFLUX_COMPILER_SDK_DIGEST".to_owned(),
                request.compiler_sdk.to_string(),
            ),
            (
                "CLUSTERFLUX_COMPILER_IMAGE_DIGEST".to_owned(),
                request.compiler_image.to_string(),
            ),
            ("CLUSTERFLUX_COMPILER_APPLIANCE".to_owned(), "1".to_owned()),
        ]
        .into_iter()
        .collect(),
        timeout_ms: request
            .resource_policy
            .wall_clock_seconds
            .saturating_mul(1000),
        network: CommandNetworkPolicy::Disabled,
        env: None,
    };
    let policy = ContainerRunPolicy {
        cpu_count: request.resource_policy.cpu_count,
        memory_bytes: request.resource_policy.memory_bytes,
        pids_limit: 256,
        immutable_root: true,
        pull_never: true,
        keep_id: Some((65532, 65532)),
        tmpfs: Some("/tmp:rw,noexec,nosuid,nodev,size=64m".to_owned()),
        file_size_bytes: Some(request.resource_policy.max_output_bytes as u64),
    };
    let plan = match LinuxRootlessPodmanBackend.plan_materialized_local_checkout_run(
        ProcessId::from(request.run_id.as_str()),
        TaskInstanceId::from(WORKFLOW_COMPILER_SYSTEM_TASK_NAME),
        &invocation,
        LocalSourceCheckout {
            host_path: source_dir.clone(),
            snapshot: request.source.tree_digest.clone(),
            inventory: None,
        },
        output_dir.clone(),
        None,
        MaterializedEnvironment {
            name: "clusterflux-system-compiler".to_owned(),
            backend: CommandBackendKind::LinuxRootlessPodman,
            local_reference: image.to_owned(),
        },
        &policy,
    ) {
        Ok(plan) => plan,
        Err(error) => return failure("sandbox_plan", error.to_string(), false),
    };
    let mut runner = BoundedSystemProcessRunner {
        podman: args.system_compiler_podman.clone(),
        runsc: args.system_compiler_runsc.clone(),
        sandbox: args.system_compiler_sandbox.clone(),
        cancellation,
        timeout: Duration::from_secs(request.resource_policy.wall_clock_seconds),
        output_dir: output_dir.clone(),
        output_budget: request.resource_policy.max_output_bytes.saturating_mul(3),
        transcript_budget: MAX_COMPILER_DIAGNOSTIC_BYTES,
    };
    let mut overlay = VfsOverlay::new(
        TaskInstanceId::from(WORKFLOW_COMPILER_SYSTEM_TASK_NAME),
        node.clone(),
    );
    let command_output = match LinuxRootlessPodmanBackend.execute_run_plan_with_log_limit(
        plan,
        &mut runner,
        &mut overlay,
        MAX_COMPILER_DIAGNOSTIC_BYTES,
    ) {
        Ok(output) => output,
        Err(error) => {
            let retryable = matches!(error, BackendError::Cancelled(_) | BackendError::Command(_));
            return failure("compiler_execution", error.to_string(), retryable);
        }
    };
    let transcript = truncate(
        format!("{}{}", command_output.stdout, command_output.stderr),
        MAX_COMPILER_DIAGNOSTIC_BYTES,
    );
    if command_output.status_code != Some(0) {
        return failure(
            "compiler_failed",
            format!(
                "workflow compiler exited with status {:?}: {transcript}",
                command_output.status_code
            ),
            false,
        );
    }
    if let Err(error) = validate_output_directory(&output_dir) {
        return failure("invalid_output", error, false);
    }
    let bundle_bytes = match fs::read(output_dir.join("bundle.json")) {
        Ok(bytes) if bytes.len() <= request.resource_policy.max_output_bytes => bytes,
        Ok(_) => {
            return failure(
                "oversized_output",
                "compiler bundle exceeds the configured output limit".to_owned(),
                false,
            )
        }
        Err(error) => return failure("missing_output", error.to_string(), false),
    };
    let bundle = match serde_json::from_slice(&bundle_bytes) {
        Ok(bundle) => bundle,
        Err(error) => return failure("invalid_bundle", error.to_string(), false),
    };
    WorkflowCompilationResult {
        assignment_id,
        attempt_id,
        lease_epoch,
        run_id: request.run_id,
        node,
        bundle: Some(bundle),
        compiler_transcript: truncate(transcript, request.resource_policy.max_diagnostic_bytes),
        failure_code: None,
        retryable: false,
    }
}

struct BoundedSystemProcessRunner {
    podman: String,
    runsc: String,
    sandbox: String,
    cancellation: CancellationToken,
    timeout: Duration,
    output_dir: PathBuf,
    output_budget: usize,
    transcript_budget: usize,
}

impl ProcessRunner for BoundedSystemProcessRunner {
    fn run(&mut self, podman: &PodmanCommand) -> Result<ProcessOutput, BackendError> {
        let mut arguments = podman.args.clone();
        apply_system_sandbox(&mut arguments, &self.sandbox, &self.runsc)?;
        let stdout =
            tempfile::tempfile().map_err(|error| BackendError::Command(error.to_string()))?;
        let stderr =
            tempfile::tempfile().map_err(|error| BackendError::Command(error.to_string()))?;
        let stdout_reader = stdout
            .try_clone()
            .map_err(|error| BackendError::Command(error.to_string()))?;
        let stderr_reader = stderr
            .try_clone()
            .map_err(|error| BackendError::Command(error.to_string()))?;
        let mut command = Command::new(&self.podman);
        command
            .args(arguments)
            .envs(&podman.environment)
            .stdin(Stdio::null())
            .stdout(Stdio::from(stdout))
            .stderr(Stdio::from(stderr));
        // The command owns a process group so cancellation also terminates the
        // container monitor and rustc rather than leaving detached work.
        #[cfg(unix)]
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) != 0 {
                    return Err(std::io::Error::last_os_error());
                }
                Ok(())
            });
        }
        let mut child = command
            .spawn()
            .map_err(|error| BackendError::Command(error.to_string()))?;
        let started = Instant::now();
        let status = loop {
            match child.try_wait() {
                Ok(Some(status)) => break status,
                Ok(None) => {}
                Err(error) => {
                    terminate_compiler_group(&mut child);
                    return Err(BackendError::Command(error.to_string()));
                }
            }
            if self.cancellation.is_cancelled() {
                terminate_compiler_group(&mut child);
                return Err(BackendError::Cancelled(
                    "system assignment cancellation requested".to_owned(),
                ));
            }
            if started.elapsed() >= self.timeout {
                terminate_compiler_group(&mut child);
                return Err(BackendError::Cancelled(format!(
                    "system command exceeded {} seconds",
                    self.timeout.as_secs()
                )));
            }
            let output_bytes = directory_bytes(&self.output_dir, self.output_budget)
                .map_err(BackendError::Command)?;
            if output_bytes > self.output_budget {
                terminate_compiler_group(&mut child);
                return Err(BackendError::Denied(
                    "system command output exceeded its bounded byte limit".to_owned(),
                ));
            }
            let transcript_bytes = stdout_reader
                .metadata()
                .map(|metadata| metadata.len())
                .unwrap_or(u64::MAX)
                .saturating_add(
                    stderr_reader
                        .metadata()
                        .map(|metadata| metadata.len())
                        .unwrap_or(u64::MAX),
                );
            if transcript_bytes > self.transcript_budget as u64 {
                terminate_compiler_group(&mut child);
                return Err(BackendError::Denied(
                    "system command logs exceeded their bounded byte limit".to_owned(),
                ));
            }
            std::thread::sleep(Duration::from_millis(50));
        };
        let stdout = read_bounded_bytes(stdout_reader, self.transcript_budget)
            .map_err(|error| BackendError::Command(error.to_string()))?;
        let remaining = self.transcript_budget.saturating_sub(stdout.len());
        let stderr = read_bounded_bytes(stderr_reader, remaining)
            .map_err(|error| BackendError::Command(error.to_string()))?;
        Ok(ProcessOutput {
            status_code: status.code(),
            stdout,
            stderr,
        })
    }
}

fn apply_system_sandbox(
    arguments: &mut Vec<String>,
    sandbox: &str,
    runsc: &str,
) -> Result<(), BackendError> {
    if sandbox != "gvisor" {
        return Ok(());
    }
    if arguments.first().map(String::as_str) != Some("run") {
        return Err(BackendError::Denied(
            "gVisor system-task policy only accepts Podman run plans".to_owned(),
        ));
    }
    arguments.splice(
        1..1,
        [
            "--runtime".to_owned(),
            runsc.to_owned(),
            "--runtime-flag=platform=systrap".to_owned(),
            "--runtime-flag=ignore-cgroups".to_owned(),
        ],
    );
    Ok(())
}

fn required_setting<'a>(value: Option<&'a str>, name: &str) -> Result<&'a str, String> {
    value
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(|| format!("{name} is required for automatic workflow compilation"))
}

fn make_source_read_only(root: &Path) -> Result<(), std::io::Error> {
    for entry in walk(root)? {
        let metadata = fs::metadata(&entry)?;
        let mut permissions = metadata.permissions();
        permissions.set_readonly(true);
        fs::set_permissions(entry, permissions)?;
    }
    let mut permissions = fs::metadata(root)?.permissions();
    permissions.set_readonly(true);
    fs::set_permissions(root, permissions)
}

fn walk(root: &Path) -> Result<Vec<PathBuf>, std::io::Error> {
    let mut pending = vec![root.to_owned()];
    let mut entries = Vec::new();
    while let Some(directory) = pending.pop() {
        for entry in fs::read_dir(directory)? {
            let path = entry?.path();
            if path.is_dir() {
                pending.push(path.clone());
            }
            entries.push(path);
        }
    }
    entries.sort_by_key(|path| std::cmp::Reverse(path.components().count()));
    Ok(entries)
}

fn validate_output_directory(output: &Path) -> Result<(), String> {
    let entries = walk(output).map_err(|error| error.to_string())?;
    if entries.len() > MAX_COMPILER_OUTPUT_FILES {
        return Err("compiler created too many output files".to_owned());
    }
    for path in entries {
        let metadata = fs::symlink_metadata(&path).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err("compiler output contains a symlink or special file".to_owned());
        }
    }
    Ok(())
}

fn directory_bytes(root: &Path, stop_after: usize) -> Result<usize, String> {
    let mut total = 0_usize;
    for path in walk(root).map_err(|error| error.to_string())? {
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
            Err(error) => return Err(error.to_string()),
        };
        if metadata.file_type().is_symlink() || (!metadata.is_file() && !metadata.is_dir()) {
            return Err("compiler output contains a symlink or special file".to_owned());
        }
        if metadata.is_file() {
            total = total.saturating_add(metadata.len() as usize);
            if total > stop_after {
                break;
            }
        }
    }
    Ok(total)
}

fn terminate_compiler_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        libc::killpg(child.id() as libc::pid_t, libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn read_bounded_bytes(mut file: fs::File, limit: usize) -> Result<Vec<u8>, std::io::Error> {
    file.seek(std::io::SeekFrom::Start(0))?;
    let mut bytes = Vec::new();
    file.take(limit.saturating_add(1) as u64)
        .read_to_end(&mut bytes)?;
    if bytes.len() > limit {
        bytes.truncate(limit);
    }
    Ok(bytes)
}

fn truncate(value: String, limit: usize) -> String {
    if value.len() <= limit {
        return value;
    }
    let mut end = limit;
    while !value.is_char_boundary(end) {
        end -= 1;
    }
    value[..end].to_owned()
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{
        RepositoryId, RunId, TriggerId, WorkflowCompilerResourcePolicy, WorkflowSource,
        WorkflowSourceFile,
    };

    use super::*;

    fn request() -> WorkflowCompilationRequest {
        let source = WorkflowSource::new(
            TriggerId::from("trigger"),
            RepositoryId::from("repository"),
            "1111111111111111111111111111111111111111",
            vec![
                WorkflowSourceFile::new(
                    ".clusterflux/Cargo.toml",
                    0o100644,
                    b"[package]\nname='compiler-test'\nversion='0.0.0'\nedition='2024'\npublish=false\n[lib]\npath='main.rs'\ncrate-type=['cdylib']\n[dependencies]\nclusterflux={package='clusterflux-sdk',version='=0.2.0'}\n[workspace]\nresolver='3'\n"
                        .to_vec(),
                )
                .unwrap(),
                WorkflowSourceFile::new(
                    ".clusterflux/main.rs",
                    0o100644,
                    b"use clusterflux::prelude::*;\n#[clusterflux::main]\npub async fn main() -> Result<()> { Ok(()) }\n".to_vec(),
                )
                .unwrap(),
            ],
        )
        .unwrap();
        let manifest = clusterflux_core::workflow_compiler_system_manifest();
        WorkflowCompilationRequest {
            run_id: RunId::from("run"),
            source,
            compiler_profile: clusterflux_core::workflow_compiler_profile_id(
                &manifest.environment_digest,
            ),
            compiler_image: manifest.environment_digest,
            compiler_sdk: manifest.sdk_digest,
            rust_toolchain: manifest.rust_toolchain,
            resource_policy: WorkflowCompilerResourcePolicy::default(),
        }
    }

    fn planned_arguments(sandbox: &str) -> Vec<String> {
        let request = request();
        let invocation = CommandInvocation {
            program: "/opt/clusterflux/bin/compile-workflow".to_owned(),
            args: vec![
                "/workspace/main.rs".to_owned(),
                "/clusterflux/output/bundle.json".to_owned(),
            ],
            working_directory: "/workspace".to_owned(),
            environment_variables: Default::default(),
            timeout_ms: 1_000,
            network: CommandNetworkPolicy::Disabled,
            env: None,
        };
        let policy = ContainerRunPolicy {
            cpu_count: request.resource_policy.cpu_count,
            memory_bytes: request.resource_policy.memory_bytes,
            pids_limit: 256,
            immutable_root: true,
            pull_never: true,
            keep_id: Some((65532, 65532)),
            tmpfs: Some("/tmp:rw,noexec,nosuid,nodev,size=64m".to_owned()),
            file_size_bytes: Some(request.resource_policy.max_output_bytes as u64),
        };
        let mut arguments = LinuxRootlessPodmanBackend
            .plan_materialized_local_checkout_run(
                ProcessId::from("run"),
                TaskInstanceId::from(WORKFLOW_COMPILER_SYSTEM_TASK_NAME),
                &invocation,
                LocalSourceCheckout {
                    host_path: PathBuf::from("/tmp/source"),
                    snapshot: request.source.tree_digest,
                    inventory: None,
                },
                PathBuf::from("/tmp/output"),
                None,
                MaterializedEnvironment {
                    name: "compiler".to_owned(),
                    backend: CommandBackendKind::LinuxRootlessPodman,
                    local_reference:
                        "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
                            .to_owned(),
                },
                &policy,
            )
            .unwrap()
            .run
            .args;
        apply_system_sandbox(&mut arguments, sandbox, "/usr/local/bin/runsc-pinned").unwrap();
        arguments
    }

    #[test]
    fn compiler_command_has_one_fail_closed_gvisor_sandbox_path() {
        let arguments = planned_arguments("gvisor");
        let rendered = arguments.join(" ");
        assert!(rendered.contains("--runtime /usr/local/bin/runsc-pinned"));
        assert!(rendered.contains("--runtime-flag=platform=systrap"));
        assert!(rendered.contains("--runtime-flag=ignore-cgroups"));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--network", "none"]));
        assert!(rendered.contains("--read-only"));
        assert!(rendered.contains("--cap-drop all"));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--security-opt", "no-new-privileges"]));
        assert!(rendered.contains("--userns=keep-id:uid=65532,gid=65532"));
        assert!(rendered.contains("--ulimit fsize="));
        assert!(rendered.contains("/tmp/source:/workspace:ro,Z"));
        assert!(rendered.contains("/tmp/output:/clusterflux/output:rw,Z"));
        assert!(!rendered.contains("runc"));
        assert!(!rendered.contains("crun"));
        assert_eq!(
            &arguments[arguments.len() - 4..],
            &[
                "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "/opt/clusterflux/bin/compile-workflow",
                "/workspace/main.rs",
                "/clusterflux/output/bundle.json",
            ]
        );
    }

    #[test]
    fn default_compiler_command_uses_rootless_podman_without_runsc() {
        let arguments = planned_arguments("podman");
        let rendered = arguments.join(" ");
        assert!(!rendered.contains("--runtime"));
        assert!(arguments
            .windows(2)
            .any(|pair| pair == ["--network", "none"]));
        assert!(rendered.contains("--read-only"));
    }

    #[test]
    fn compiler_image_decision_imports_absent_or_mismatched_and_skips_exact_identity() {
        let image_digest = Digest::sha256("image");
        let environment_digest = Digest::sha256("environment");
        let package = clusterflux_node::system_package::VerifiedSystemCompilerPackage {
            share_dir: PathBuf::from("/package"),
            archive: PathBuf::from("/package/image.oci.tar"),
            image_reference: image_digest.to_string(),
            image_digest: image_digest.clone(),
            environment_digest: environment_digest.clone(),
            archive_digest: Digest::sha256("archive"),
        };
        assert!(!packaged_compiler_image_matches(None, &package));
        assert!(!packaged_compiler_image_matches(
            Some(&CompilerImageIdentity {
                image_digest: Digest::sha256("wrong"),
                environment_digest: Some(environment_digest.clone()),
            }),
            &package,
        ));
        assert!(!packaged_compiler_image_matches(
            Some(&CompilerImageIdentity {
                image_digest: image_digest.clone(),
                environment_digest: Some(Digest::sha256("wrong-environment")),
            }),
            &package,
        ));
        assert!(packaged_compiler_image_matches(
            Some(&CompilerImageIdentity {
                image_digest: image_digest.clone(),
                environment_digest: None,
            }),
            &package,
        ));
        assert!(packaged_compiler_image_matches(
            Some(&CompilerImageIdentity {
                image_digest,
                environment_digest: Some(environment_digest),
            }),
            &package,
        ));
    }

    #[cfg(unix)]
    #[test]
    fn compiler_image_import_lock_serializes_concurrent_startup() {
        let directory = tempfile::tempdir().unwrap();
        let digest = Digest::sha256("image");
        let first = CompilerImageImportLock::acquire_in(directory.path(), &digest).unwrap();
        let path = directory.path().to_owned();
        let (sender, receiver) = std::sync::mpsc::channel();
        let thread = std::thread::spawn(move || {
            sender.send("waiting").unwrap();
            let _second = CompilerImageImportLock::acquire_in(&path, &digest).unwrap();
            sender.send("acquired").unwrap();
        });
        assert_eq!(receiver.recv().unwrap(), "waiting");
        assert!(receiver.recv_timeout(Duration::from_millis(50)).is_err());
        drop(first);
        assert_eq!(
            receiver.recv_timeout(Duration::from_secs(1)).unwrap(),
            "acquired"
        );
        thread.join().unwrap();
    }

    #[test]
    fn runsc_pin_accepts_the_reported_version_or_immutable_package_path() {
        assert!(runsc_version_matches(
            "20250512.0",
            "runsc version VERSION_MISSING",
            Path::new("/nix/store/abc-gvisor-20250512.0/bin/runsc"),
        ));
        assert!(runsc_version_matches(
            "release-20250512.0",
            "runsc version release-20250512.0",
            Path::new("/usr/local/bin/runsc"),
        ));
        assert!(!runsc_version_matches(
            "20250512.0",
            "runsc version VERSION_MISSING",
            Path::new("/usr/local/bin/runsc"),
        ));
    }

    #[test]
    fn output_validator_rejects_symlinks_and_excess_files() {
        #[cfg(unix)]
        {
            let temp = tempfile::tempdir().unwrap();
            std::os::unix::fs::symlink("missing", temp.path().join("link")).unwrap();
            assert!(validate_output_directory(temp.path())
                .unwrap_err()
                .contains("symlink"));
        }

        let temp = tempfile::tempdir().unwrap();
        for index in 0..=MAX_COMPILER_OUTPUT_FILES {
            fs::write(temp.path().join(format!("output-{index}")), b"x").unwrap();
        }
        assert!(validate_output_directory(temp.path())
            .unwrap_err()
            .contains("too many"));
    }

    #[test]
    #[ignore = "requires the release compiler OCI image and rootless Podman"]
    fn release_system_bundle_compiles_through_wasm_and_normal_command_lane() {
        let image = std::env::var("CLUSTERFLUX_TEST_SYSTEM_COMPILER_IMAGE")
            .expect("set CLUSTERFLUX_TEST_SYSTEM_COMPILER_IMAGE to an immutable local image id");
        let mut args = Args {
            coordinator: "127.0.0.1:1".to_owned(),
            tenant: "tenant".to_owned(),
            project: "project".to_owned(),
            project_root: None,
            node: "ordinary-node".to_owned(),
            enrollment_grant: None,
            public_key: None,
            control_poll_ms: 0,
            assignment_poll_ms: 100,
            coordinator_reconnect_max_seconds: 0,
            task_cpus: 2,
            task_memory_gib: 2,
            task_pids_limit: 256,
            emit_ready: false,
            worker: true,
            capabilities: Vec::new(),
            dangerous_allow_native_commands: false,
            no_workflow_compilation: false,
            system_tasks_only: false,
            system_compiler_image: Some(image),
            system_compiler_runsc_version: std::env::var(
                "CLUSTERFLUX_TEST_SYSTEM_COMPILER_RUNSC_VERSION",
            )
            .ok(),
            system_compiler_sandbox: std::env::var("CLUSTERFLUX_TEST_SYSTEM_COMPILER_SANDBOX")
                .unwrap_or_else(|_| "podman".to_owned()),
            system_compiler_podman: std::env::var("CLUSTERFLUX_TEST_PODMAN")
                .unwrap_or_else(|_| "podman".to_owned()),
            system_compiler_runsc: std::env::var("CLUSTERFLUX_TEST_RUNSC")
                .unwrap_or_else(|_| "runsc".to_owned()),
            system_compiler_package_verified: std::env::var_os(
                "CLUSTERFLUX_TEST_SYSTEM_COMPILER_PACKAGE_VERIFIED",
            )
            .is_some(),
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
        self_check(&mut args).expect("release compiler image should pass node self-check");
        let mut service = crate::assignment_runner::node_wasm_execution_service().unwrap();
        let mut execution = start_system_compilation(
            &service,
            &args,
            request(),
            "system-smoke-assignment".to_owned(),
            "system-smoke-attempt".to_owned(),
            1,
            CancellationToken::new(),
        )
        .unwrap();
        let deadline = Instant::now() + Duration::from_secs(180);
        let result = loop {
            if let Some(result) = execution.try_result() {
                break result;
            }
            assert!(Instant::now() < deadline, "system compilation timed out");
            std::thread::sleep(Duration::from_millis(100));
        };
        service.shutdown().unwrap();
        assert!(
            result.bundle.is_some(),
            "system compilation failed: {}",
            result.compiler_transcript
        );
        assert_eq!(result.node, NodeId::from("ordinary-node"));
    }
}
