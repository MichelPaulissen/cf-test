use std::collections::BTreeMap;
use std::path::PathBuf;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;

use clusterflux_core::{
    Capability, CommandBackendKind, CommandInvocation, CommandPlan, Digest, EnvironmentKind,
    GuestRuntimeKind, ProcessId, TaskInstanceId, VfsObject, VfsOverlay, VfsPath,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as ShaDigest, Sha256};
use thiserror::Error;
use tokio_util::sync::CancellationToken;

mod command_runner;
mod windows_dev;
pub use clusterflux_wasm_runtime::{
    WasmDebugControl, WasmTaskError, WasmTaskHost, WasmtimeDebugProbe, WasmtimeTaskRuntime,
};
use command_runner::capture_command_logs;
pub mod system_package;
pub use command_runner::{
    authorize_node_command, CapturedCommandLogs, CommandOutput, LocalCommandExecutor,
    VirtualThreadCommand, DEFAULT_COMMAND_LOG_LIMIT_BYTES,
};
pub use windows_dev::{
    WindowsCommandDevBackend, WindowsContainerdNerdctlBackend, WindowsSandboxStubBackend,
};

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct MaterializedEnvironment {
    pub name: String,
    pub backend: CommandBackendKind,
    pub local_reference: String,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum BackendError {
    #[error("native command denied: {0}")]
    Denied(String),
    #[error("environment is required for this backend")]
    MissingEnvironment,
    #[error("command failed to execute: {0}")]
    Command(String),
    #[error("task execution cancelled: {0}")]
    Cancelled(String),
    #[error("artifact staging failed: {0}")]
    Artifact(String),
    #[error("unsupported environment kind for backend")]
    UnsupportedEnvironment,
    #[error("node cannot freeze task `{task}` for the current debug epoch")]
    DebugFreezeUnsupported { task: TaskInstanceId },
}

pub trait CommandBackend {
    fn kind(&self) -> CommandBackendKind;
    fn plan(&self, invocation: &CommandInvocation) -> Result<CommandPlan, BackendError>;
}

#[derive(Clone, Debug, Default)]
pub struct LinuxRootlessPodmanBackend;

fn container_identity(process: &ProcessId, task: &TaskInstanceId) -> String {
    let mut digest = Sha256::new();
    digest.update(process.to_string().as_bytes());
    digest.update([0]);
    digest.update(task.to_string().as_bytes());
    let suffix = digest
        .finalize()
        .iter()
        .take(12)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("clusterflux-{suffix}")
}

fn container_attempt_identity(
    process: &ProcessId,
    task: &TaskInstanceId,
    execution_attempt: &str,
) -> String {
    let logical_identity = container_identity(process, task);
    let mut digest = Sha256::new();
    digest.update(execution_attempt.as_bytes());
    let suffix = digest
        .finalize()
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    format!("{logical_identity}-{suffix}")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodmanCommand {
    pub program: String,
    pub args: Vec<String>,
    /// Optional host-side working directory. Container runtime invocations do
    /// not set this; the dangerous native-command override does.
    #[serde(skip, default)]
    pub working_directory: Option<PathBuf>,
    /// Environment inherited by the host-side process. Container variables are
    /// named on the Podman command line without placing their values there.
    #[serde(skip, default)]
    pub environment: BTreeMap<String, String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ProcessOutput {
    pub status_code: Option<i32>,
    pub stdout: Vec<u8>,
    pub stderr: Vec<u8>,
}

pub trait ProcessRunner {
    fn run(&mut self, command: &PodmanCommand) -> Result<ProcessOutput, BackendError>;
}

#[derive(Clone, Debug, Default)]
pub struct StdProcessRunner;

impl ProcessRunner for StdProcessRunner {
    fn run(&mut self, command: &PodmanCommand) -> Result<ProcessOutput, BackendError> {
        let output = std::process::Command::new(&command.program)
            .args(&command.args)
            .envs(&command.environment)
            .current_dir(
                command
                    .working_directory
                    .as_deref()
                    .unwrap_or_else(|| std::path::Path::new(".")),
            )
            .output()
            .map_err(|err| BackendError::Command(format!("{err:#}")))?;

        Ok(ProcessOutput {
            status_code: output.status.code(),
            stdout: output.stdout,
            stderr: output.stderr,
        })
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PodmanEnvironmentMaterialization {
    pub environment: String,
    pub image_tag: String,
    pub inspect: PodmanCommand,
    pub build: PodmanCommand,
    pub rootless_user_podman: bool,
    pub embeds_full_image_in_bundle: bool,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LocalSourceCheckout {
    pub host_path: PathBuf,
    pub snapshot: Digest,
    /// Validated immutable file plan required by backends that must stage a
    /// checkout instead of mounting it directly (currently Windows runhcs).
    pub inventory: Option<clusterflux_source::SourceSnapshotInventory>,
}

#[derive(Clone, Debug)]
pub struct LocalTaskCancellation {
    requested: CancellationToken,
    aborted: Arc<AtomicBool>,
}

impl LocalTaskCancellation {
    pub fn new(requested: CancellationToken, aborted: Arc<AtomicBool>) -> Self {
        Self { requested, aborted }
    }

    pub fn is_cancelled(&self) -> bool {
        self.requested.is_cancelled() || self.aborted.load(Ordering::Acquire)
    }
}

impl Default for LocalTaskCancellation {
    fn default() -> Self {
        Self {
            requested: CancellationToken::new(),
            aborted: Arc::new(AtomicBool::new(false)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct LocalCheckoutTaskRequest<'a> {
    pub process: ProcessId,
    pub virtual_thread: TaskInstanceId,
    /// Coordinator-issued assignment/attempt identity. Windows uses this to
    /// keep a retry from colliding with an orphaned nerdctl name record.
    pub execution_attempt: String,
    pub invocation: &'a CommandInvocation,
    pub checkout: LocalSourceCheckout,
    pub output_root: PathBuf,
    pub stage_stdout_as: Option<VfsPath>,
    /// A release-owned compiler package verified by the node before startup.
    pub system_package_dir: Option<PathBuf>,
    /// Operator-selected ceiling for this node's project task containers.
    pub run_policy: ContainerRunPolicy,
    pub cancellation: LocalTaskCancellation,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum SourceAccessMode {
    LocalCheckoutBindMount {
        host_path: PathBuf,
        container_path: String,
        read_only: bool,
        snapshot: Digest,
    },
    NodePreparedSnapshot {
        node_path: PathBuf,
        container_path: String,
        snapshot: Digest,
    },
    HostNativeCheckout {
        host_path: PathBuf,
        snapshot: Digest,
    },
}

pub fn execute_dangerous_native_checkout_task(
    request: LocalCheckoutTaskRequest<'_>,
    runner: &mut impl ProcessRunner,
    overlay: &mut VfsOverlay,
) -> Result<LinuxCommandTaskOutput, BackendError> {
    let working_directory = native_checkout_working_directory(
        &request.checkout.host_path,
        &request.invocation.working_directory,
    )?;
    let lifecycle =
        LinuxTaskLifecycle::new(request.process.clone(), request.virtual_thread.clone());
    let plan = LinuxCommandRunPlan {
        process: request.process,
        virtual_thread: request.virtual_thread,
        image_tag: "dangerous-host-native".to_owned(),
        run: PodmanCommand {
            program: request.invocation.program.clone(),
            args: request.invocation.args.clone(),
            working_directory: Some(working_directory),
            environment: request.invocation.environment_variables.clone(),
        },
        source_access: SourceAccessMode::HostNativeCheckout {
            host_path: request.checkout.host_path,
            snapshot: request.checkout.snapshot,
        },
        output_root: request.output_root,
        stage_stdout_as: request.stage_stdout_as,
        uses_full_repo_tarball: false,
        coordinator_routed_file_reads: false,
        lifecycle,
    };
    LinuxRootlessPodmanBackend.execute_run_plan(plan, runner, overlay)
}

fn native_checkout_working_directory(
    checkout: &std::path::Path,
    requested: &str,
) -> Result<PathBuf, BackendError> {
    let checkout = checkout.canonicalize().map_err(|error| {
        BackendError::Command(format!("resolve native command checkout: {error}"))
    })?;
    let normalized = requested.replace('\\', "/");
    let suffix = if normalized == "/workspace" || normalized.eq_ignore_ascii_case("c:/workspace") {
        ""
    } else {
        normalized
            .strip_prefix("/workspace/")
            .or_else(|| normalized.strip_prefix("C:/workspace/"))
            .ok_or_else(|| {
                BackendError::Command(
                    "native command working directory must be under /workspace".to_owned(),
                )
            })?
    };
    let mut target = checkout.clone();
    for component in suffix.split('/').filter(|component| !component.is_empty()) {
        if matches!(component, "." | "..") {
            return Err(BackendError::Command(
                "native command working directory cannot traverse outside /workspace".to_owned(),
            ));
        }
        target.push(component);
    }
    let target = target.canonicalize().map_err(|error| {
        BackendError::Command(format!("resolve native command working directory: {error}"))
    })?;
    if !target.starts_with(&checkout) {
        return Err(BackendError::Command(
            "native command working directory escapes the checkout".to_owned(),
        ));
    }
    Ok(target)
}

impl SourceAccessMode {
    pub fn uses_full_repo_tarball(&self) -> bool {
        false
    }

    pub fn coordinator_routed_file_reads(&self) -> bool {
        false
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum LinuxTaskState {
    Running,
    Frozen,
    Cancelled,
    Completed,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxTaskLifecycle {
    pub process: ProcessId,
    pub virtual_thread: TaskInstanceId,
    pub log_stream: String,
    pub cancellation_token: String,
    pub debug_participant: String,
    pub freeze_supported: bool,
    pub state: LinuxTaskState,
}

impl LinuxTaskLifecycle {
    pub fn new(process: ProcessId, virtual_thread: TaskInstanceId) -> Self {
        Self {
            log_stream: format!("process/{process}/task/{virtual_thread}/logs"),
            cancellation_token: format!("cancel:{process}:{virtual_thread}"),
            debug_participant: format!("debug:{process}:{virtual_thread}"),
            process,
            virtual_thread,
            freeze_supported: true,
            state: LinuxTaskState::Running,
        }
    }

    pub fn freeze_for_debug_epoch(&mut self) -> Result<(), BackendError> {
        if !self.freeze_supported {
            return Err(BackendError::DebugFreezeUnsupported {
                task: self.virtual_thread.clone(),
            });
        }
        self.state = LinuxTaskState::Frozen;
        Ok(())
    }

    pub fn resume_after_debug_epoch(&mut self) {
        if self.state == LinuxTaskState::Frozen {
            self.state = LinuxTaskState::Running;
        }
    }

    pub fn cancel(&mut self) {
        self.state = LinuxTaskState::Cancelled;
    }

    pub fn complete(&mut self) {
        self.state = LinuxTaskState::Completed;
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxCommandRunPlan {
    pub process: ProcessId,
    pub virtual_thread: TaskInstanceId,
    pub image_tag: String,
    pub run: PodmanCommand,
    pub source_access: SourceAccessMode,
    pub output_root: PathBuf,
    pub stage_stdout_as: Option<VfsPath>,
    pub uses_full_repo_tarball: bool,
    pub coordinator_routed_file_reads: bool,
    pub lifecycle: LinuxTaskLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct LinuxCommandTaskOutput {
    pub virtual_thread: TaskInstanceId,
    pub status_code: Option<i32>,
    pub stdout: String,
    pub stderr: String,
    pub stdout_truncated: bool,
    pub stderr_truncated: bool,
    pub log_backpressured: bool,
    pub staged_artifact: Option<VfsObject>,
    pub lifecycle: LinuxTaskLifecycle,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ContainerRunPolicy {
    pub cpu_count: u16,
    pub memory_bytes: u64,
    pub pids_limit: u32,
    pub immutable_root: bool,
    pub pull_never: bool,
    pub keep_id: Option<(u32, u32)>,
    pub tmpfs: Option<String>,
    pub file_size_bytes: Option<u64>,
}

impl Default for ContainerRunPolicy {
    fn default() -> Self {
        Self {
            cpu_count: 2,
            memory_bytes: 2 * 1024 * 1024 * 1024,
            pids_limit: 256,
            immutable_root: false,
            pull_never: false,
            keep_id: None,
            tmpfs: None,
            file_size_bytes: None,
        }
    }
}

impl LinuxRootlessPodmanBackend {
    pub fn materialize_environment(
        &self,
        env: &clusterflux_core::EnvironmentResource,
    ) -> Result<PodmanEnvironmentMaterialization, BackendError> {
        match env.kind {
            EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile => {}
            EnvironmentKind::NixFlake => return Err(BackendError::UnsupportedEnvironment),
        }

        let image_tag = self.image_tag(env);
        Ok(PodmanEnvironmentMaterialization {
            environment: env.name.clone(),
            image_tag: image_tag.clone(),
            inspect: PodmanCommand {
                program: "podman".to_owned(),
                args: vec!["image".to_owned(), "exists".to_owned(), image_tag.clone()],
                working_directory: None,
                environment: BTreeMap::new(),
            },
            build: PodmanCommand {
                program: "podman".to_owned(),
                args: vec![
                    "build".to_owned(),
                    "--pull=missing".to_owned(),
                    "--tag".to_owned(),
                    image_tag,
                    "--file".to_owned(),
                    env.recipe_path.to_string_lossy().into_owned(),
                    env.context_path.to_string_lossy().into_owned(),
                ],
                working_directory: None,
                environment: BTreeMap::new(),
            },
            rootless_user_podman: true,
            embeds_full_image_in_bundle: false,
        })
    }

    pub fn plan_local_checkout_run(
        &self,
        process: ProcessId,
        virtual_thread: TaskInstanceId,
        invocation: &CommandInvocation,
        checkout: LocalSourceCheckout,
        output_root: PathBuf,
        stage_stdout_as: Option<VfsPath>,
    ) -> Result<LinuxCommandRunPlan, BackendError> {
        self.plan_local_checkout_run_with_policy(
            process,
            virtual_thread,
            invocation,
            checkout,
            output_root,
            stage_stdout_as,
            &ContainerRunPolicy::default(),
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_local_checkout_run_with_policy(
        &self,
        process: ProcessId,
        virtual_thread: TaskInstanceId,
        invocation: &CommandInvocation,
        checkout: LocalSourceCheckout,
        output_root: PathBuf,
        stage_stdout_as: Option<VfsPath>,
        policy: &ContainerRunPolicy,
    ) -> Result<LinuxCommandRunPlan, BackendError> {
        let env = invocation
            .env
            .as_ref()
            .ok_or(BackendError::MissingEnvironment)?;
        let materialization = self.materialize_environment(env)?;
        self.plan_materialized_local_checkout_run(
            process,
            virtual_thread,
            invocation,
            checkout,
            output_root,
            stage_stdout_as,
            MaterializedEnvironment {
                name: materialization.environment,
                backend: CommandBackendKind::LinuxRootlessPodman,
                local_reference: materialization.image_tag,
            },
            policy,
        )
    }

    /// Plan a command in a release-pinned environment that has already been
    /// materialized and verified by the node. This is the same execution lane
    /// used by project commands; it only avoids rebuilding a trusted system
    /// image from repository-controlled files.
    #[allow(clippy::too_many_arguments)]
    pub fn plan_materialized_local_checkout_run(
        &self,
        process: ProcessId,
        virtual_thread: TaskInstanceId,
        invocation: &CommandInvocation,
        checkout: LocalSourceCheckout,
        output_root: PathBuf,
        stage_stdout_as: Option<VfsPath>,
        environment: MaterializedEnvironment,
        policy: &ContainerRunPolicy,
    ) -> Result<LinuxCommandRunPlan, BackendError> {
        if environment.backend != CommandBackendKind::LinuxRootlessPodman
            || environment.local_reference.trim().is_empty()
        {
            return Err(BackendError::UnsupportedEnvironment);
        }
        let source_access = SourceAccessMode::LocalCheckoutBindMount {
            host_path: checkout.host_path.clone(),
            container_path: "/workspace".to_owned(),
            read_only: true,
            snapshot: checkout.snapshot,
        };
        let lifecycle = LinuxTaskLifecycle::new(process.clone(), virtual_thread.clone());
        let container_identity = container_identity(&process, &virtual_thread);
        let network = podman_network(&invocation.network);
        let mut args = vec![
            "run".to_owned(),
            "--rm".to_owned(),
            // Names are derived from the exact process/task identity. Replacing
            // that name recovers only this task's container after a node crash;
            // it cannot match an unrelated workload.
            "--replace".to_owned(),
            "--name".to_owned(),
            container_identity,
            "--network".to_owned(),
            network.to_owned(),
            "--cpus".to_owned(),
            policy.cpu_count.to_string(),
            "--memory".to_owned(),
            policy.memory_bytes.to_string(),
            "--pids-limit".to_owned(),
            policy.pids_limit.to_string(),
            "--security-opt".to_owned(),
            "no-new-privileges".to_owned(),
            "--cap-drop".to_owned(),
            "all".to_owned(),
            "--volume".to_owned(),
            format!("{}:/workspace:ro,Z", checkout.host_path.to_string_lossy()),
            "--volume".to_owned(),
            format!("{}:/clusterflux/output:rw,Z", output_root.to_string_lossy()),
            "--env".to_owned(),
            "CARGO_TARGET_DIR=/clusterflux/output/target".to_owned(),
            "--workdir".to_owned(),
            invocation.working_directory.clone(),
        ];
        if policy.pull_never {
            args.splice(2..2, ["--pull=never".to_owned()]);
        }
        if policy.immutable_root {
            args.splice(2..2, ["--read-only".to_owned()]);
        }
        if let Some((uid, gid)) = policy.keep_id {
            args.splice(2..2, [format!("--userns=keep-id:uid={uid},gid={gid}")]);
        }
        if let Some(tmpfs) = &policy.tmpfs {
            args.splice(2..2, ["--tmpfs".to_owned(), tmpfs.clone()]);
        }
        if let Some(file_size_bytes) = policy.file_size_bytes {
            args.splice(
                2..2,
                [
                    "--ulimit".to_owned(),
                    format!("fsize={file_size_bytes}:{file_size_bytes}"),
                ],
            );
        }
        let mut process_environment = BTreeMap::new();
        for (name, value) in &invocation.environment_variables {
            args.push("--env".to_owned());
            args.push(name.clone());
            process_environment.insert(name.clone(), value.clone());
        }
        args.push(environment.local_reference.clone());
        args.push(invocation.program.clone());
        args.extend(invocation.args.iter().cloned());

        Ok(LinuxCommandRunPlan {
            process,
            virtual_thread,
            image_tag: environment.local_reference,
            run: PodmanCommand {
                program: "podman".to_owned(),
                args,
                working_directory: None,
                environment: process_environment,
            },
            source_access,
            output_root,
            stage_stdout_as,
            uses_full_repo_tarball: false,
            coordinator_routed_file_reads: false,
            lifecycle,
        })
    }

    pub fn execute_environment_materialization(
        &self,
        env: &clusterflux_core::EnvironmentResource,
        runner: &mut impl ProcessRunner,
    ) -> Result<MaterializedEnvironment, BackendError> {
        let materialization = self.materialize_environment(env)?;
        let inspection = runner.run(&materialization.inspect)?;
        match inspection.status_code {
            Some(0) => {}
            Some(1) => {
                let output = runner.run(&materialization.build)?;
                if output.status_code != Some(0) {
                    return Err(BackendError::Command(format!(
                        "podman build for environment `{}` failed with status {:?}: {}",
                        materialization.environment,
                        output.status_code,
                        String::from_utf8_lossy(&output.stderr)
                    )));
                }
            }
            status => {
                return Err(BackendError::Command(format!(
                    "podman image lookup for environment `{}` failed with status {status:?}: {}",
                    materialization.environment,
                    String::from_utf8_lossy(&inspection.stderr)
                )));
            }
        }

        Ok(MaterializedEnvironment {
            name: materialization.environment,
            backend: CommandBackendKind::LinuxRootlessPodman,
            local_reference: materialization.image_tag,
        })
    }

    /// Normal task execution consumes only deployment-prebuilt immutable
    /// environments. Building recipes is an explicit setup operation.
    pub fn require_materialized_environment(
        &self,
        env: &clusterflux_core::EnvironmentResource,
        runner: &mut impl ProcessRunner,
    ) -> Result<MaterializedEnvironment, BackendError> {
        let materialization = self.materialize_environment(env)?;
        let inspection = runner.run(&materialization.inspect)?;
        if inspection.status_code != Some(0) {
            return Err(BackendError::Command(format!(
                "prebuilt immutable environment `{}` ({}) is unavailable; run clusterflux-environment-setup during deployment",
                materialization.environment, materialization.image_tag
            )));
        }
        Ok(MaterializedEnvironment {
            name: materialization.environment,
            backend: CommandBackendKind::LinuxRootlessPodman,
            local_reference: materialization.image_tag,
        })
    }

    pub fn execute_run_plan(
        &self,
        plan: LinuxCommandRunPlan,
        runner: &mut impl ProcessRunner,
        overlay: &mut VfsOverlay,
    ) -> Result<LinuxCommandTaskOutput, BackendError> {
        self.execute_run_plan_with_log_limit(plan, runner, overlay, DEFAULT_COMMAND_LOG_LIMIT_BYTES)
    }

    pub fn execute_run_plan_with_log_limit(
        &self,
        mut plan: LinuxCommandRunPlan,
        runner: &mut impl ProcessRunner,
        overlay: &mut VfsOverlay,
        max_log_bytes: usize,
    ) -> Result<LinuxCommandTaskOutput, BackendError> {
        let output = runner.run(&plan.run)?;
        let logs = capture_command_logs(
            &plan.virtual_thread,
            &output.stdout,
            &output.stderr,
            max_log_bytes,
        );
        let staged_artifact = if output.status_code == Some(0) {
            if let Some(path) = plan.stage_stdout_as.take() {
                Some(overlay.write(
                    path,
                    Digest::sha256(&output.stdout),
                    output.stdout.len() as u64,
                ))
            } else {
                None
            }
        } else {
            None
        };

        if output.status_code == Some(0) {
            plan.lifecycle.complete();
        }

        Ok(LinuxCommandTaskOutput {
            virtual_thread: plan.virtual_thread,
            status_code: output.status_code,
            stdout: logs.stdout,
            stderr: logs.stderr,
            stdout_truncated: logs.stdout_truncated,
            stderr_truncated: logs.stderr_truncated,
            log_backpressured: logs.backpressured,
            staged_artifact,
            lifecycle: plan.lifecycle,
        })
    }

    pub fn execute_local_checkout_task(
        &self,
        request: LocalCheckoutTaskRequest<'_>,
        runner: &mut impl ProcessRunner,
        overlay: &mut VfsOverlay,
    ) -> Result<LinuxCommandTaskOutput, BackendError> {
        let env = request
            .invocation
            .env
            .as_ref()
            .ok_or(BackendError::MissingEnvironment)?;
        self.require_materialized_environment(env, runner)?;
        let plan = self.plan_local_checkout_run_with_policy(
            request.process,
            request.virtual_thread,
            request.invocation,
            request.checkout,
            request.output_root,
            request.stage_stdout_as,
            &request.run_policy,
        )?;
        let plan = mount_system_package(plan, request.system_package_dir.as_deref())?;
        self.execute_run_plan(plan, runner, overlay)
    }

    fn image_tag(&self, env: &clusterflux_core::EnvironmentResource) -> String {
        environment_image_tag(env)
    }
}

fn environment_image_tag(env: &clusterflux_core::EnvironmentResource) -> String {
    clusterflux_core::environment_image_tag(env)
}

fn mount_system_package(
    mut plan: LinuxCommandRunPlan,
    system_package_dir: Option<&std::path::Path>,
) -> Result<LinuxCommandRunPlan, BackendError> {
    let Some(system_package_dir) = system_package_dir else {
        return Ok(plan);
    };
    if !system_package_dir.is_absolute() {
        return Err(BackendError::Command(
            "verified system package path must be absolute".to_owned(),
        ));
    }
    let image_index = plan
        .run
        .args
        .iter()
        .position(|argument| argument == &plan.image_tag)
        .ok_or_else(|| BackendError::Command("Podman run plan omitted its image".to_owned()))?;
    plan.run.args.splice(
        image_index..image_index,
        [
            "--volume".to_owned(),
            format!(
                "{}:/clusterflux/system:ro",
                system_package_dir.to_string_lossy()
            ),
            "--env".to_owned(),
            "CLUSTERFLUX_SYSTEM_PACKAGE_DIR=/clusterflux/system".to_owned(),
            "--env".to_owned(),
            "CLUSTERFLUX_SYSTEM_COMPILER_IMAGE_ARCHIVE=/clusterflux/system/system-compiler-image.oci.tar"
                .to_owned(),
        ],
    );
    Ok(plan)
}

fn podman_network(policy: &clusterflux_core::CommandNetworkPolicy) -> &'static str {
    match policy {
        clusterflux_core::CommandNetworkPolicy::Disabled => "none",
        clusterflux_core::CommandNetworkPolicy::Enabled => "pasta",
    }
}

impl CommandBackend for LinuxRootlessPodmanBackend {
    fn kind(&self) -> CommandBackendKind {
        CommandBackendKind::LinuxRootlessPodman
    }

    fn plan(&self, invocation: &CommandInvocation) -> Result<CommandPlan, BackendError> {
        let env = invocation
            .env
            .as_ref()
            .ok_or(BackendError::MissingEnvironment)?;
        match env.kind {
            EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile => Ok(CommandPlan {
                guest_runtime: GuestRuntimeKind::Wasmtime,
                backend: CommandBackendKind::LinuxRootlessPodman,
                required_capability: Capability::RootlessPodman,
                user_attached_development_execution: false,
            }),
            EnvironmentKind::NixFlake => Err(BackendError::UnsupportedEnvironment),
        }
    }
}

#[cfg(test)]
mod tests {
    use std::collections::VecDeque;
    use std::path::PathBuf;

    use clusterflux_core::{
        DebugRuntimeState, Digest, EnvironmentRequirements, EnvironmentResource, NodeId, ProjectId,
        TenantId,
    };

    use super::*;

    #[derive(Default)]
    struct RecordingRunner {
        commands: Vec<PodmanCommand>,
        outputs: VecDeque<ProcessOutput>,
    }

    impl RecordingRunner {
        fn with_outputs(outputs: impl IntoIterator<Item = ProcessOutput>) -> Self {
            Self {
                commands: Vec::new(),
                outputs: outputs.into_iter().collect(),
            }
        }
    }

    impl ProcessRunner for RecordingRunner {
        fn run(&mut self, command: &PodmanCommand) -> Result<ProcessOutput, BackendError> {
            self.commands.push(command.clone());
            self.outputs.pop_front().ok_or_else(|| {
                BackendError::Command("recording runner has no output queued".to_owned())
            })
        }
    }

    fn success_output(stdout: impl Into<Vec<u8>>) -> ProcessOutput {
        ProcessOutput {
            status_code: Some(0),
            stdout: stdout.into(),
            stderr: Vec::new(),
        }
    }

    fn container_env() -> EnvironmentResource {
        EnvironmentResource {
            name: "linux".to_owned(),
            kind: EnvironmentKind::Containerfile,
            recipe_path: PathBuf::from("envs/linux/Containerfile"),
            context_path: PathBuf::from("envs/linux"),
            context_manifest: Vec::new(),
            context_manifest_digest: Digest::from_parts([b"environment-context:v1"]),
            digest: Digest::sha256("recipe"),
            requirements: EnvironmentRequirements::linux_container(),
        }
    }

    fn windows_container_env() -> EnvironmentResource {
        EnvironmentResource {
            name: "windows".to_owned(),
            kind: EnvironmentKind::Dockerfile,
            recipe_path: PathBuf::from(r"C:\checkout\envs\windows\Dockerfile"),
            context_path: PathBuf::from(r"C:\checkout\envs\windows"),
            context_manifest: Vec::new(),
            context_manifest_digest: Digest::from_parts([b"environment-context:v1"]),
            digest: Digest::sha256("windows-recipe"),
            requirements: EnvironmentRequirements::windows_container(),
        }
    }

    #[test]
    fn rootless_network_policy_uses_podmans_pasta_helper() {
        assert_eq!(
            podman_network(&clusterflux_core::CommandNetworkPolicy::Enabled),
            "pasta"
        );
        assert_eq!(
            podman_network(&clusterflux_core::CommandNetworkPolicy::Disabled),
            "none"
        );
    }

    #[test]
    fn linux_backend_plans_rootless_podman_under_wasmtime_virtual_task() {
        let invocation = CommandInvocation {
            program: "cargo".to_owned(),
            args: vec!["build".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment_variables: Default::default(),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(container_env()),
        };
        let plan = LinuxRootlessPodmanBackend.plan(&invocation).unwrap();

        assert_eq!(plan.guest_runtime, GuestRuntimeKind::Wasmtime);
        assert_eq!(plan.backend, CommandBackendKind::LinuxRootlessPodman);
        assert_eq!(plan.required_capability, Capability::RootlessPodman);
    }

    #[test]
    fn linux_backend_materializes_containerfile_with_rootless_podman_without_vendored_image() {
        let env = container_env();
        let materialization = LinuxRootlessPodmanBackend
            .materialize_environment(&env)
            .unwrap();

        assert_eq!(materialization.environment, "linux");
        assert!(materialization
            .image_tag
            .starts_with("clusterflux-env/linux:"));
        assert_eq!(materialization.image_tag.matches(':').count(), 1);
        assert_eq!(materialization.inspect.program, "podman");
        assert_eq!(
            materialization.inspect.args,
            ["image", "exists", materialization.image_tag.as_str()]
        );
        assert_eq!(materialization.build.program, "podman");
        assert!(materialization.rootless_user_podman);
        assert!(!materialization.embeds_full_image_in_bundle);
        assert!(materialization.build.args.contains(&"build".to_owned()));
        assert!(materialization
            .build
            .args
            .contains(&"--pull=missing".to_owned()));
        assert!(materialization
            .build
            .args
            .contains(&"envs/linux/Containerfile".to_owned()));
        assert!(materialization
            .build
            .args
            .contains(&"envs/linux".to_owned()));
    }

    #[test]
    fn linux_run_plan_keeps_local_checkout_local_and_avoids_coordinator_file_reads() {
        let invocation = CommandInvocation {
            program: "cargo".to_owned(),
            args: vec!["build".to_owned(), "--release".to_owned()],
            working_directory: "/workspace/crate".to_owned(),
            environment_variables: std::collections::BTreeMap::from([(
                "BUILD_MODE".to_owned(),
                "release".to_owned(),
            )]),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(container_env()),
        };
        let plan = LinuxRootlessPodmanBackend
            .plan_local_checkout_run(
                ProcessId::from("vp"),
                TaskInstanceId::from("compile-linux"),
                &invocation,
                LocalSourceCheckout {
                    host_path: PathBuf::from("/work/example"),
                    snapshot: Digest::sha256("checkout"),
                    inventory: None,
                },
                PathBuf::from("/work/output"),
                Some(VfsPath::new("/vfs/artifacts/app").unwrap()),
            )
            .unwrap();

        assert_eq!(plan.run.program, "podman");
        assert!(plan.run.args.contains(&"run".to_owned()));
        assert!(plan.run.args.contains(&"--replace".to_owned()));
        let name_index = plan
            .run
            .args
            .iter()
            .position(|argument| argument == "--name")
            .expect("Podman task has a stable container identity");
        assert!(plan.run.args[name_index + 1].starts_with("clusterflux-"));
        assert!(plan.run.args.contains(&"--network".to_owned()));
        assert!(plan.run.args.contains(&"none".to_owned()));
        assert!(plan.run.args.contains(&"--cpus".to_owned()));
        assert!(plan.run.args.contains(&"--memory".to_owned()));
        assert!(plan.run.args.contains(&"--pids-limit".to_owned()));
        assert!(plan.run.args.contains(&"no-new-privileges".to_owned()));
        assert!(plan.run.args.contains(&"all".to_owned()));
        assert!(plan.run.args.contains(&"/workspace/crate".to_owned()));
        assert!(plan.run.args.contains(&"BUILD_MODE".to_owned()));
        assert!(!plan
            .run
            .args
            .iter()
            .any(|argument| argument.contains("release") && argument.starts_with("BUILD_MODE=")));
        assert_eq!(
            plan.run.environment.get("BUILD_MODE").map(String::as_str),
            Some("release")
        );
        assert!(plan
            .run
            .args
            .contains(&"/work/example:/workspace:ro,Z".to_owned()));
        assert!(plan.run.args.contains(&"cargo".to_owned()));
        assert!(plan.run.args.contains(&"--release".to_owned()));
        assert!(!plan.uses_full_repo_tarball);
        assert!(!plan.coordinator_routed_file_reads);
        assert!(!plan.source_access.uses_full_repo_tarball());
        assert!(!plan.source_access.coordinator_routed_file_reads());
        assert_eq!(
            plan.stage_stdout_as,
            Some(VfsPath::new("/vfs/artifacts/app").unwrap())
        );
        assert_eq!(plan.lifecycle.process, ProcessId::from("vp"));
        assert_eq!(
            plan.lifecycle.virtual_thread,
            TaskInstanceId::from("compile-linux")
        );
        assert_eq!(plan.lifecycle.state, LinuxTaskState::Running);

        match &plan.source_access {
            SourceAccessMode::LocalCheckoutBindMount {
                host_path,
                container_path,
                read_only,
                ..
            } => {
                assert_eq!(host_path, &PathBuf::from("/work/example"));
                assert_eq!(container_path, "/workspace");
                assert!(*read_only);
            }
            SourceAccessMode::NodePreparedSnapshot { .. } => {
                panic!("local Linux build should use the node-local checkout")
            }
            SourceAccessMode::HostNativeCheckout { .. } => {
                panic!("local Linux container build should not use host-native execution")
            }
        }
    }

    #[test]
    fn linux_backend_consumes_prebuilt_environment_then_runs_and_stages_artifact() {
        let invocation = CommandInvocation {
            program: "cargo".to_owned(),
            args: vec!["build".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment_variables: Default::default(),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(container_env()),
        };
        let mut runner =
            RecordingRunner::with_outputs([success_output([]), success_output(b"artifact-bytes")]);
        let mut overlay =
            VfsOverlay::new(TaskInstanceId::from("compile-linux"), NodeId::from("node"));

        let output = LinuxRootlessPodmanBackend
            .execute_local_checkout_task(
                LocalCheckoutTaskRequest {
                    process: ProcessId::from("vp"),
                    virtual_thread: TaskInstanceId::from("compile-linux"),
                    execution_attempt: "linux-test-attempt".to_owned(),
                    invocation: &invocation,
                    checkout: LocalSourceCheckout {
                        host_path: PathBuf::from("/work/demo"),
                        snapshot: Digest::sha256("checkout"),
                        inventory: None,
                    },
                    output_root: PathBuf::from("/work/output"),
                    stage_stdout_as: Some(VfsPath::new("/vfs/artifacts/app.tar.zst").unwrap()),
                    system_package_dir: Some(PathBuf::from(
                        "/nix/store/verified-clusterflux/share/clusterflux",
                    )),
                    run_policy: ContainerRunPolicy {
                        cpu_count: 8,
                        memory_bytes: 16 * 1024 * 1024 * 1024,
                        pids_limit: 1_024,
                        ..ContainerRunPolicy::default()
                    },
                    cancellation: LocalTaskCancellation::default(),
                },
                &mut runner,
                &mut overlay,
            )
            .unwrap();
        let manifest = overlay.flush();

        assert_eq!(runner.commands.len(), 2);
        assert_eq!(runner.commands[0].program, "podman");
        assert_eq!(&runner.commands[0].args[..2], ["image", "exists"]);
        assert_eq!(runner.commands[1].program, "podman");
        assert!(runner.commands[1].args.contains(&"run".to_owned()));
        assert!(runner.commands[1]
            .args
            .windows(2)
            .any(|pair| pair == ["--cpus", "8"]));
        assert!(runner.commands[1]
            .args
            .windows(2)
            .any(|pair| pair == ["--memory", "17179869184"]));
        assert!(runner.commands[1]
            .args
            .windows(2)
            .any(|pair| pair == ["--pids-limit", "1024"]));
        assert!(runner.commands[1]
            .args
            .contains(&"/work/demo:/workspace:ro,Z".to_owned()));
        assert!(runner.commands[1].args.contains(
            &"/nix/store/verified-clusterflux/share/clusterflux:/clusterflux/system:ro".to_owned()
        ));
        assert!(runner.commands[1]
            .args
            .contains(&"CLUSTERFLUX_SYSTEM_PACKAGE_DIR=/clusterflux/system".to_owned()));
        assert!(runner.commands[1].args.contains(
            &"CLUSTERFLUX_SYSTEM_COMPILER_IMAGE_ARCHIVE=/clusterflux/system/system-compiler-image.oci.tar"
                .to_owned()
        ));
        assert!(!runner.commands[1]
            .args
            .iter()
            .any(|argument| argument.contains("podman.sock")));
        assert_eq!(output.status_code, Some(0));
        assert_eq!(output.stdout, "artifact-bytes");
        assert_eq!(output.lifecycle.state, LinuxTaskState::Completed);
        assert!(output.staged_artifact.is_some());
        assert!(manifest
            .objects
            .contains_key(&VfsPath::new("/vfs/artifacts/app.tar.zst").unwrap()));
        assert!(!manifest.large_bytes_uploaded);
    }

    #[test]
    fn normal_task_run_refuses_to_build_a_missing_environment() {
        let env = container_env();
        let mut runner = RecordingRunner::with_outputs([ProcessOutput {
            status_code: Some(1),
            stdout: Vec::new(),
            stderr: Vec::new(),
        }]);

        let error = LinuxRootlessPodmanBackend
            .require_materialized_environment(&env, &mut runner)
            .unwrap_err();

        assert!(error.to_string().contains("clusterflux-environment-setup"));
        assert_eq!(runner.commands.len(), 1);
        assert_eq!(&runner.commands[0].args[..2], ["image", "exists"]);
    }

    #[test]
    fn linux_backend_reuses_digest_tagged_environment_without_rebuilding() {
        let env = container_env();
        let mut runner = RecordingRunner::with_outputs([success_output([])]);

        let materialized = LinuxRootlessPodmanBackend
            .execute_environment_materialization(&env, &mut runner)
            .unwrap();

        assert_eq!(materialized.name, env.name);
        assert_eq!(runner.commands.len(), 1);
        assert_eq!(&runner.commands[0].args[..2], ["image", "exists"]);
        assert_eq!(runner.commands[0].args[2], materialized.local_reference);
    }

    #[test]
    fn linux_backend_does_not_treat_podman_lookup_errors_as_cache_misses() {
        let env = container_env();
        let mut runner = RecordingRunner::with_outputs([ProcessOutput {
            status_code: Some(125),
            stdout: Vec::new(),
            stderr: b"storage unavailable".to_vec(),
        }]);

        let error = LinuxRootlessPodmanBackend
            .execute_environment_materialization(&env, &mut runner)
            .unwrap_err();

        assert!(error.to_string().contains("podman image lookup"));
        assert!(error.to_string().contains("storage unavailable"));
        assert_eq!(runner.commands.len(), 1);
    }

    #[test]
    fn linux_backend_retains_final_log_tail_without_truncating_staged_artifact_bytes() {
        let invocation = CommandInvocation {
            program: "cargo".to_owned(),
            args: vec!["build".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment_variables: Default::default(),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(container_env()),
        };
        let mut runner =
            RecordingRunner::with_outputs([success_output(b"abcdef"), success_output(b"unused")]);
        let mut overlay =
            VfsOverlay::new(TaskInstanceId::from("compile-linux"), NodeId::from("node"));
        let plan = LinuxRootlessPodmanBackend
            .plan_local_checkout_run(
                ProcessId::from("vp"),
                TaskInstanceId::from("compile-linux"),
                &invocation,
                LocalSourceCheckout {
                    host_path: PathBuf::from("/work/demo"),
                    snapshot: Digest::sha256("checkout"),
                    inventory: None,
                },
                PathBuf::from("/work/output"),
                Some(VfsPath::new("/vfs/artifacts/app.txt").unwrap()),
            )
            .unwrap();

        let output = LinuxRootlessPodmanBackend
            .execute_run_plan_with_log_limit(plan, &mut runner, &mut overlay, 4)
            .unwrap();

        assert_eq!(output.virtual_thread, TaskInstanceId::from("compile-linux"));
        assert_eq!(output.stdout, "cdef");
        assert!(output.stdout_truncated);
        assert!(output.log_backpressured);
        assert_eq!(output.staged_artifact.as_ref().unwrap().size, 6);
    }

    #[test]
    fn explicit_environment_setup_reports_a_failed_podman_build() {
        let invocation = CommandInvocation {
            program: "cargo".to_owned(),
            args: vec!["build".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment_variables: Default::default(),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(container_env()),
        };
        let mut runner = RecordingRunner::with_outputs([
            ProcessOutput {
                status_code: Some(1),
                stdout: Vec::new(),
                stderr: Vec::new(),
            },
            ProcessOutput {
                status_code: Some(125),
                stdout: Vec::new(),
                stderr: b"image build failed".to_vec(),
            },
        ]);
        let error = LinuxRootlessPodmanBackend
            .execute_environment_materialization(invocation.env.as_ref().unwrap(), &mut runner)
            .unwrap_err();

        assert!(error.to_string().contains("podman build"));
        assert!(error.to_string().contains("image build failed"));
        assert_eq!(runner.commands.len(), 2);
    }

    #[test]
    fn linux_task_lifecycle_supports_cancel_and_all_stop_freeze_resume() {
        let mut lifecycle =
            LinuxTaskLifecycle::new(ProcessId::from("vp"), TaskInstanceId::from("compile-linux"));

        lifecycle.freeze_for_debug_epoch().unwrap();
        assert_eq!(lifecycle.state, LinuxTaskState::Frozen);

        lifecycle.resume_after_debug_epoch();
        assert_eq!(lifecycle.state, LinuxTaskState::Running);

        lifecycle.cancel();
        assert_eq!(lifecycle.state, LinuxTaskState::Cancelled);

        let mut unsupported = LinuxTaskLifecycle::new(
            ProcessId::from("vp"),
            TaskInstanceId::from("native-command"),
        );
        unsupported.freeze_supported = false;
        let error = unsupported.freeze_for_debug_epoch().unwrap_err();
        assert!(matches!(error, BackendError::DebugFreezeUnsupported { .. }));
    }

    #[test]
    fn windows_backend_is_labeled_user_attached_dev_execution() {
        let invocation = CommandInvocation {
            program: "cmd".to_owned(),
            args: vec!["/C".to_owned(), "build.bat".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment_variables: Default::default(),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: None,
        };
        let plan = WindowsCommandDevBackend.plan(&invocation).unwrap();

        assert!(plan.user_attached_development_execution);
        assert_eq!(plan.required_capability, Capability::WindowsCommandDev);
    }

    #[test]
    fn windows_backend_uses_nerdctl_without_native_execution() {
        let invocation = CommandInvocation {
            program: "cmd.exe".to_owned(),
            args: vec!["/C".to_owned(), "build.cmd".to_owned()],
            working_directory: "/workspace/crates/node".to_owned(),
            environment_variables: BTreeMap::from([(
                "BUILD_CHANNEL".to_owned(),
                "test-value-not-in-argv".to_owned(),
            )]),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(windows_container_env()),
        };
        let backend = WindowsContainerdNerdctlBackend;
        let command_plan = backend.plan(&invocation).unwrap();
        assert_eq!(
            command_plan.backend,
            CommandBackendKind::WindowsContainerdNerdctl
        );
        assert_eq!(
            command_plan.required_capability,
            Capability::ContainerdNerdctl
        );
        assert!(!command_plan.user_attached_development_execution);

        let materialization = backend
            .materialize_environment(invocation.env.as_ref().unwrap())
            .unwrap();
        assert_eq!(materialization.inspect.program, "nerdctl");
        assert_eq!(materialization.build.program, "nerdctl");
        assert!(!materialization.rootless_user_podman);

        let run = backend
            .plan_local_checkout_run_with_policy(
                ProcessId::from("windows-process"),
                TaskInstanceId::from("windows-task"),
                "windows-attempt-one",
                &invocation,
                LocalSourceCheckout {
                    host_path: PathBuf::from(r"C:\checkout"),
                    snapshot: Digest::sha256("source"),
                    inventory: None,
                },
                PathBuf::from(r"C:\node-output"),
                None,
                &ContainerRunPolicy {
                    cpu_count: 4,
                    memory_bytes: 8 * 1024 * 1024 * 1024,
                    pids_limit: 512,
                    ..ContainerRunPolicy::default()
                },
            )
            .unwrap();
        assert_eq!(run.run.program, "nerdctl");
        assert!(run
            .run
            .args
            .windows(2)
            .any(|args| args == ["--isolation", "process"]));
        assert!(run.run.args.windows(2).any(|args| args == ["--cpus", "4"]));
        assert!(run
            .run
            .args
            .windows(2)
            .any(|args| args == ["--memory", "8589934592"]));
        assert!(!run.run.args.contains(&"--pids-limit".to_owned()));
        assert!(!run.run.args.contains(&"--mount".to_owned()));
        assert!(!run.run.args.contains(&"--read-only".to_owned()));
        assert_eq!(
            run.run
                .args
                .windows(2)
                .find(|args| args[0] == "--volume")
                .map(|args| args[1].as_str()),
            Some(r"C:\checkout:C:\workspace:ro")
        );
        assert!(run
            .run
            .args
            .windows(2)
            .any(|args| args == ["--network", "none"]));
        let container_name = run
            .run
            .args
            .windows(2)
            .find(|args| args[0] == "--name")
            .map(|args| args[1].clone())
            .unwrap();
        assert!(container_name.starts_with("clusterflux-"));
        assert!(run.run.args.windows(2).any(|args| {
            args[0] == "--label" && args[1].starts_with("clusterflux.task-identity=clusterflux-")
        }));
        let retry = backend
            .plan_local_checkout_run_with_policy(
                ProcessId::from("windows-process"),
                TaskInstanceId::from("windows-task"),
                "windows-attempt-two",
                &invocation,
                LocalSourceCheckout {
                    host_path: PathBuf::from(r"C:\checkout"),
                    snapshot: Digest::sha256("source"),
                    inventory: None,
                },
                PathBuf::from(r"C:\node-output"),
                None,
                &ContainerRunPolicy::default(),
            )
            .unwrap();
        let retry_name = retry
            .run
            .args
            .windows(2)
            .find(|args| args[0] == "--name")
            .map(|args| args[1].clone())
            .unwrap();
        assert_ne!(container_name, retry_name);
        assert!(run
            .run
            .args
            .contains(&r"C:\workspace\crates\node".to_owned()));
        assert!(run.run.args.contains(&"BUILD_CHANNEL".to_owned()));
        assert!(!run.run.args.contains(&"test-value-not-in-argv".to_owned()));
        assert_eq!(
            run.run.environment.get("BUILD_CHANNEL").map(String::as_str),
            Some("test-value-not-in-argv")
        );
    }

    #[test]
    fn windows_backend_removes_labeled_previous_attempt_before_running() {
        let invocation = CommandInvocation {
            program: "cmd.exe".to_owned(),
            args: vec!["/C".to_owned(), "build.cmd".to_owned()],
            working_directory: "/workspace".to_owned(),
            environment_variables: BTreeMap::new(),
            timeout_ms: 60_000,
            network: clusterflux_core::CommandNetworkPolicy::Disabled,
            env: Some(windows_container_env()),
        };
        let previous = "0123456789abcdef0123456789abcdef";
        let mut runner = RecordingRunner::with_outputs([
            success_output([]),
            success_output(format!("{previous}\r\n")),
            success_output([]),
            success_output([]),
        ]);
        let task = TaskInstanceId::from("windows-task");
        let mut overlay = VfsOverlay::new(task.clone(), NodeId::from("windows-node"));

        let output = WindowsContainerdNerdctlBackend
            .execute_local_checkout_task(
                LocalCheckoutTaskRequest {
                    process: ProcessId::from("windows-process"),
                    virtual_thread: task,
                    execution_attempt: "windows-attempt".to_owned(),
                    invocation: &invocation,
                    checkout: LocalSourceCheckout {
                        host_path: PathBuf::from(r"C:\checkout"),
                        snapshot: Digest::sha256("source"),
                        inventory: None,
                    },
                    output_root: PathBuf::from(r"C:\node-output"),
                    stage_stdout_as: None,
                    system_package_dir: None,
                    run_policy: ContainerRunPolicy::default(),
                    cancellation: LocalTaskCancellation::default(),
                },
                &mut runner,
                &mut overlay,
            )
            .unwrap();

        assert_eq!(output.status_code, Some(0));
        assert_eq!(runner.commands[1].args[0], "ps");
        assert!(runner.commands[1]
            .args
            .iter()
            .any(|arg| arg.starts_with("label=clusterflux.task-identity=clusterflux-")));
        assert_eq!(
            runner.commands[2].args,
            ["rm", "--force", previous].map(str::to_owned)
        );
        assert_eq!(runner.commands[3].args[0], "run");
    }

    #[test]
    fn hosted_control_plane_native_command_is_denied() {
        let error = authorize_node_command(true, true).unwrap_err();

        assert!(matches!(error, BackendError::Denied(_)));
    }

    #[test]
    fn native_command_is_denied_without_command_capability() {
        let error = authorize_node_command(false, false).unwrap_err();

        assert!(matches!(error, BackendError::Denied(_)));
        assert!(error
            .to_string()
            .contains("lacks native command capability"));
    }

    #[test]
    fn wasmtime_runtime_runs_named_task_export() {
        let runtime = WasmtimeTaskRuntime::new().unwrap();
        let wasm = r#"
                (module
                  (func (export "task_add_one") (param i32) (result i32)
                    local.get 0
                    i32.const 1
                    i32.add))
                "#;
        let result = runtime.run_i32_export(wasm, "task_add_one", 41).unwrap();

        assert_eq!(result, 42);

        let verified = runtime
            .run_i32_export_verified(wasm, &Digest::sha256(wasm), "task_add_one", 41)
            .unwrap();
        assert_eq!(verified, 42);
    }

    #[test]
    fn wasmtime_runtime_rejects_bundle_digest_mismatch_before_compilation() {
        let runtime = WasmtimeTaskRuntime::new().unwrap();
        let error = runtime
            .run_i32_export_verified(
                "not a valid wasm module",
                &Digest::sha256("different task bundle bytes"),
                "task_add_one",
                41,
            )
            .unwrap_err();

        assert!(matches!(error, WasmTaskError::BundleDigestMismatch { .. }));
        assert!(!error.to_string().contains("failed to parse"));
    }

    #[test]
    fn wasmtime_runtime_freezes_and_resumes_wasm_debug_participant() {
        let runtime = WasmtimeTaskRuntime::new().unwrap();
        let probe = runtime
            .freeze_resume_i32_export_probe(
                r#"
                (module
                  (func (export "task_add_one") (param i32) (result i32)
                    local.get 0
                    i32.const 1
                    i32.add))
                "#,
                "task_add_one",
                41,
            )
            .unwrap();

        assert_eq!(probe.task, TaskInstanceId::from("task_add_one"));
        assert_eq!(probe.frozen_state, DebugRuntimeState::Frozen);
        assert_eq!(probe.resumed_state, DebugRuntimeState::Running);
        assert_eq!(probe.result, 42);
        assert!(probe
            .stack_frames
            .iter()
            .any(|frame| frame.contains("task_add_one")));
        assert!(probe
            .local_values
            .iter()
            .any(|(name, value)| { name == "wasm_local_0" && value.contains("41") }));
        assert!(probe.wasm_pc.is_some());
    }

    #[cfg(unix)]
    #[test]
    fn native_command_output_is_associated_with_virtual_thread_and_staged_to_vfs() {
        let executor = LocalCommandExecutor {
            node: clusterflux_core::NodeId::from("node"),
            hosted_control_plane: false,
            has_command_capability: true,
        };
        let mut overlay =
            VfsOverlay::new(TaskInstanceId::from("compile-linux"), NodeId::from("node"));
        let output = executor
            .run(
                VirtualThreadCommand {
                    virtual_thread: TaskInstanceId::from("compile-linux"),
                    invocation: CommandInvocation {
                        program: "sh".to_owned(),
                        args: vec![
                            "-c".to_owned(),
                            "printf artifact; printf log >&2".to_owned(),
                        ],
                        working_directory: "/workspace".to_owned(),
                        environment_variables: Default::default(),
                        timeout_ms: 60_000,
                        network: clusterflux_core::CommandNetworkPolicy::Disabled,
                        env: None,
                    },
                    stage_stdout_as: Some(VfsPath::new("/vfs/artifacts/app.txt").unwrap()),
                },
                &mut overlay,
            )
            .unwrap();
        let manifest = overlay.flush();

        assert_eq!(output.virtual_thread, TaskInstanceId::from("compile-linux"));
        assert_eq!(output.stdout, "artifact");
        assert_eq!(output.stderr, "log");
        assert!(output.staged_artifact.is_some());
        assert!(!manifest.large_bytes_uploaded);
        assert!(manifest
            .objects
            .contains_key(&VfsPath::new("/vfs/artifacts/app.txt").unwrap()));
    }

    #[cfg(unix)]
    #[test]
    fn local_command_executor_retains_each_stream_tail_and_reports_backpressure() {
        let executor = LocalCommandExecutor {
            node: clusterflux_core::NodeId::from("node"),
            hosted_control_plane: false,
            has_command_capability: true,
        };
        let mut overlay =
            VfsOverlay::new(TaskInstanceId::from("compile-linux"), NodeId::from("node"));
        let output = executor
            .run_with_log_limit(
                VirtualThreadCommand {
                    virtual_thread: TaskInstanceId::from("compile-linux"),
                    invocation: CommandInvocation {
                        program: "sh".to_owned(),
                        args: vec!["-c".to_owned(), "printf abcdef; printf err >&2".to_owned()],
                        working_directory: "/workspace".to_owned(),
                        environment_variables: Default::default(),
                        timeout_ms: 60_000,
                        network: clusterflux_core::CommandNetworkPolicy::Disabled,
                        env: None,
                    },
                    stage_stdout_as: None,
                },
                &mut overlay,
                4,
            )
            .unwrap();

        assert_eq!(output.virtual_thread, TaskInstanceId::from("compile-linux"));
        assert_eq!(output.stdout, "cdef");
        assert_eq!(output.stderr, "err");
        assert!(output.stdout_truncated);
        assert!(!output.stderr_truncated);
        assert!(output.log_backpressured);
    }

    #[test]
    fn public_node_crate_does_not_require_hosted_service_types() {
        let _tenant = TenantId::from("tenant");
        let _project = ProjectId::from("project");
        let _backend = LinuxRootlessPodmanBackend;
    }
}
