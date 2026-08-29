use std::collections::BTreeMap;
#[cfg(windows)]
use std::path::Path;

#[cfg(windows)]
use clusterflux_source::{SourceSnapshotEntry, SourceSnapshotEntryKind, SourceSnapshotInventory};

use clusterflux_core::{
    Capability, CommandBackendKind, CommandInvocation, CommandPlan, EnvironmentKind,
    GuestRuntimeKind, ProcessId, TaskInstanceId, VfsOverlay, VfsPath,
};

use crate::{
    container_attempt_identity, container_identity, environment_image_tag, BackendError,
    CommandBackend, ContainerRunPolicy, LinuxCommandRunPlan, LinuxCommandTaskOutput,
    LinuxRootlessPodmanBackend, LocalCheckoutTaskRequest, MaterializedEnvironment, PodmanCommand,
    PodmanEnvironmentMaterialization, ProcessRunner, SourceAccessMode,
};

const TASK_IDENTITY_LABEL: &str = "clusterflux.task-identity";

#[derive(Clone, Debug, Default)]
pub struct WindowsContainerdNerdctlBackend;

impl WindowsContainerdNerdctlBackend {
    pub fn materialize_environment(
        &self,
        env: &clusterflux_core::EnvironmentResource,
    ) -> Result<PodmanEnvironmentMaterialization, BackendError> {
        match env.kind {
            EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile => {}
            EnvironmentKind::NixFlake => return Err(BackendError::UnsupportedEnvironment),
        }
        if env.requirements.os != Some(clusterflux_core::Os::Windows) {
            return Err(BackendError::UnsupportedEnvironment);
        }

        let image_tag = environment_image_tag(env);
        Ok(PodmanEnvironmentMaterialization {
            environment: env.name.clone(),
            image_tag: image_tag.clone(),
            inspect: PodmanCommand {
                program: "nerdctl".to_owned(),
                args: vec!["image".to_owned(), "inspect".to_owned(), image_tag.clone()],
                working_directory: None,
                environment: BTreeMap::new(),
            },
            build: PodmanCommand {
                program: "nerdctl".to_owned(),
                args: vec![
                    "build".to_owned(),
                    "--tag".to_owned(),
                    image_tag,
                    "--file".to_owned(),
                    env.recipe_path.to_string_lossy().into_owned(),
                    env.context_path.to_string_lossy().into_owned(),
                ],
                working_directory: None,
                environment: BTreeMap::new(),
            },
            rootless_user_podman: false,
            embeds_full_image_in_bundle: false,
        })
    }

    pub fn execute_environment_materialization(
        &self,
        env: &clusterflux_core::EnvironmentResource,
        runner: &mut impl ProcessRunner,
    ) -> Result<MaterializedEnvironment, BackendError> {
        let materialization = self.materialize_environment(env)?;
        let inspection = runner.run(&materialization.inspect)?;
        if inspection.status_code != Some(0) {
            let output = runner.run(&materialization.build)?;
            if output.status_code != Some(0) {
                return Err(BackendError::Command(format!(
                    "nerdctl build for environment `{}` failed with status {:?}: {}",
                    materialization.environment,
                    output.status_code,
                    String::from_utf8_lossy(&output.stderr)
                )));
            }
        }
        Ok(MaterializedEnvironment {
            name: materialization.environment,
            backend: CommandBackendKind::WindowsContainerdNerdctl,
            local_reference: materialization.image_tag,
        })
    }

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
            backend: CommandBackendKind::WindowsContainerdNerdctl,
            local_reference: materialization.image_tag,
        })
    }

    #[allow(clippy::too_many_arguments)]
    pub fn plan_local_checkout_run_with_policy(
        &self,
        process: ProcessId,
        virtual_thread: TaskInstanceId,
        execution_attempt: &str,
        invocation: &CommandInvocation,
        checkout: crate::LocalSourceCheckout,
        output_root: std::path::PathBuf,
        stage_stdout_as: Option<VfsPath>,
        policy: &ContainerRunPolicy,
    ) -> Result<LinuxCommandRunPlan, BackendError> {
        let env = invocation
            .env
            .as_ref()
            .ok_or(BackendError::MissingEnvironment)?;
        let materialization = self.materialize_environment(env)?;
        let source_access = SourceAccessMode::LocalCheckoutBindMount {
            host_path: checkout.host_path.clone(),
            container_path: r"C:\workspace".to_owned(),
            read_only: true,
            snapshot: checkout.snapshot,
        };
        let lifecycle = crate::LinuxTaskLifecycle::new(process.clone(), virtual_thread.clone());
        let logical_identity = container_identity(&process, &virtual_thread);
        let physical_identity =
            container_attempt_identity(&process, &virtual_thread, execution_attempt);
        let mut args = vec![
            "run".to_owned(),
            "--rm".to_owned(),
            "--name".to_owned(),
            physical_identity,
            "--label".to_owned(),
            format!("{TASK_IDENTITY_LABEL}={logical_identity}"),
            "--isolation".to_owned(),
            "process".to_owned(),
            "--cpus".to_owned(),
            policy.cpu_count.to_string(),
            "--memory".to_owned(),
            policy.memory_bytes.to_string(),
            // nerdctl's Windows backend maps CPU and memory to HCS resource
            // controls. Its PID-limit option is Linux-only, so the node must
            // not claim to enforce the policy by passing an ignored flag.
            "--volume".to_owned(),
            windows_volume_mount(&checkout.host_path, r"C:\workspace", true)?,
            "--volume".to_owned(),
            windows_volume_mount(&output_root, r"C:\clusterflux\output", false)?,
            "--workdir".to_owned(),
            windows_container_working_directory(&invocation.working_directory)?,
        ];
        if invocation.network == clusterflux_core::CommandNetworkPolicy::Disabled {
            args.splice(2..2, ["--network".to_owned(), "none".to_owned()]);
        }
        if policy.pull_never {
            args.splice(2..2, ["--pull=never".to_owned()]);
        }
        // runhcs rejects an OCI read-only root filesystem for Windows
        // containers. Its writable layer remains ephemeral and isolated; only
        // the declared output volume can write back to the host.
        let mut process_environment = BTreeMap::new();
        for (name, value) in &invocation.environment_variables {
            args.push("--env".to_owned());
            args.push(name.clone());
            process_environment.insert(name.clone(), value.clone());
        }
        args.push(materialization.image_tag.clone());
        args.push(invocation.program.clone());
        args.extend(invocation.args.iter().cloned());

        Ok(LinuxCommandRunPlan {
            process,
            virtual_thread,
            image_tag: materialization.image_tag,
            run: PodmanCommand {
                program: "nerdctl".to_owned(),
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
        self.remove_previous_task_attempts(&request.process, &request.virtual_thread, runner)?;

        #[cfg(windows)]
        let (checkout, _container_mounts) = {
            let mut checkout = request.checkout;
            let inventory = checkout.inventory.take().ok_or_else(|| {
                BackendError::Command(
                    "Windows task source omitted its validated snapshot inventory".to_owned(),
                )
            })?;
            let mounts = PreparedWindowsContainerMounts::new(
                &checkout.host_path,
                &request.output_root,
                &inventory,
                &request.cancellation,
            )?;
            checkout.host_path = mounts.source_root().to_path_buf();
            (checkout, mounts)
        };
        #[cfg(not(windows))]
        let checkout = request.checkout;
        let plan = self.plan_local_checkout_run_with_policy(
            request.process,
            request.virtual_thread,
            &request.execution_attempt,
            request.invocation,
            checkout,
            request.output_root,
            request.stage_stdout_as,
            &request.run_policy,
        )?;
        LinuxRootlessPodmanBackend.execute_run_plan(plan, runner, overlay)
    }

    fn remove_previous_task_attempts(
        &self,
        process: &ProcessId,
        task: &TaskInstanceId,
        runner: &mut impl ProcessRunner,
    ) -> Result<(), BackendError> {
        let logical_identity = container_identity(process, task);
        let listed = runner.run(&PodmanCommand {
            program: "nerdctl".to_owned(),
            args: vec![
                "ps".to_owned(),
                "--all".to_owned(),
                "--quiet".to_owned(),
                "--filter".to_owned(),
                format!("label={TASK_IDENTITY_LABEL}={logical_identity}"),
            ],
            working_directory: None,
            environment: BTreeMap::new(),
        })?;
        if listed.status_code != Some(0) {
            return Err(BackendError::Command(format!(
                "list previous Windows container attempts for `{logical_identity}` failed with status {:?}: {}",
                listed.status_code,
                String::from_utf8_lossy(&listed.stderr)
            )));
        }
        for container in String::from_utf8_lossy(&listed.stdout)
            .lines()
            .map(str::trim)
            .filter(|container| !container.is_empty())
        {
            if container.len() < 12
                || container.len() > 128
                || !container.bytes().all(|byte| byte.is_ascii_hexdigit())
            {
                return Err(BackendError::Command(
                    "nerdctl returned an invalid container identity during retry cleanup"
                        .to_owned(),
                ));
            }
            let removed = runner.run(&PodmanCommand {
                program: "nerdctl".to_owned(),
                args: vec!["rm".to_owned(), "--force".to_owned(), container.to_owned()],
                working_directory: None,
                environment: BTreeMap::new(),
            })?;
            if removed.status_code != Some(0) {
                return Err(BackendError::Command(format!(
                    "remove previous Windows container attempt `{container}` failed with status {:?}: {}",
                    removed.status_code,
                    String::from_utf8_lossy(&removed.stderr)
                )));
            }
        }
        Ok(())
    }
}

impl CommandBackend for WindowsContainerdNerdctlBackend {
    fn kind(&self) -> CommandBackendKind {
        CommandBackendKind::WindowsContainerdNerdctl
    }

    fn plan(&self, invocation: &CommandInvocation) -> Result<CommandPlan, BackendError> {
        let env = invocation
            .env
            .as_ref()
            .ok_or(BackendError::MissingEnvironment)?;
        match env.kind {
            EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile => Ok(CommandPlan {
                guest_runtime: GuestRuntimeKind::Wasmtime,
                backend: CommandBackendKind::WindowsContainerdNerdctl,
                required_capability: Capability::ContainerdNerdctl,
                user_attached_development_execution: false,
            }),
            EnvironmentKind::NixFlake => Err(BackendError::UnsupportedEnvironment),
        }
    }
}

fn windows_volume_mount(
    host: &std::path::Path,
    container: &str,
    read_only: bool,
) -> Result<String, BackendError> {
    let host = host.to_string_lossy();
    if host.contains(',') || host.contains('\n') || host.contains('\r') {
        return Err(BackendError::Command(
            "Windows container bind-mount path contains an unsupported character".to_owned(),
        ));
    }
    Ok(format!(
        "{host}:{container}{}",
        if read_only { ":ro" } else { "" }
    ))
}

fn windows_container_working_directory(value: &str) -> Result<String, BackendError> {
    let normalized = value.replace('\\', "/");
    if normalized == "/workspace" || normalized.eq_ignore_ascii_case("c:/workspace") {
        return Ok(r"C:\workspace".to_owned());
    }
    let suffix = normalized
        .strip_prefix("/workspace/")
        .or_else(|| normalized.strip_prefix("C:/workspace/"))
        .ok_or_else(|| {
            BackendError::Command(
                "Windows container working directory must be under /workspace".to_owned(),
            )
        })?;
    if suffix.split('/').any(|component| component == "..") {
        return Err(BackendError::Command(
            "Windows container working directory cannot traverse outside /workspace".to_owned(),
        ));
    }
    Ok(format!(r"C:\workspace\{}", suffix.replace('/', r"\")))
}

#[cfg(windows)]
struct PreparedWindowsContainerMounts {
    source: tempfile::TempDir,
}

#[cfg(windows)]
impl PreparedWindowsContainerMounts {
    fn new(
        source_root: &Path,
        output_root: &Path,
        inventory: &SourceSnapshotInventory,
        cancellation: &crate::LocalTaskCancellation,
    ) -> Result<Self, BackendError> {
        inventory.validate_materialization_plan().map_err(|error| {
            BackendError::Command(format!("validate Windows task source inventory: {error}"))
        })?;
        let source = tempfile::Builder::new()
            .prefix("container-source-")
            .tempdir()
            .map_err(|error| {
                BackendError::Command(format!(
                    "create isolated Windows container source staging directory: {error}"
                ))
            })?;
        verify_windows_staging_capacity(source.path(), inventory.total_bytes)?;
        copy_windows_source_inventory(source_root, source.path(), inventory, cancellation)?;
        // Cargo cannot reliably create its first directory directly beneath a
        // process-isolated Windows bind mount. Materialize the fixed target
        // directory before handing the mount to runhcs.
        std::fs::create_dir_all(output_root.join("target")).map_err(|error| {
            BackendError::Command(format!(
                "prepare Windows container output directory `{}`: {error}",
                output_root.join("target").display()
            ))
        })?;
        grant_windows_container_access(source.path(), "RX")?;
        grant_windows_container_access(output_root, "M")?;
        Ok(Self { source })
    }

    fn source_root(&self) -> &Path {
        self.source.path()
    }
}

#[cfg(windows)]
fn copy_windows_source_inventory(
    source: &Path,
    target: &Path,
    inventory: &SourceSnapshotInventory,
    cancellation: &crate::LocalTaskCancellation,
) -> Result<(), BackendError> {
    use std::io::{Read, Write};
    use std::os::windows::fs::{MetadataExt, OpenOptionsExt};

    use sha2::{Digest as _, Sha256};
    use windows_sys::Win32::Storage::FileSystem::{
        FILE_ATTRIBUTE_REPARSE_POINT, FILE_FLAG_OPEN_REPARSE_POINT, FILE_FLAG_SEQUENTIAL_SCAN,
    };

    let metadata = std::fs::symlink_metadata(source).map_err(|error| {
        BackendError::Command(format!(
            "inspect Windows task source `{}`: {error}",
            source.display()
        ))
    })?;
    if metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
        return Err(BackendError::Command(format!(
            "Windows task source contains unsupported symbolic link or reparse point `{}`",
            source.display()
        )));
    }
    if !metadata.is_dir() {
        return Err(BackendError::Command(format!(
            "Windows task source root is not a directory: `{}`",
            source.display()
        )));
    }

    eprintln!(
        "staging {} validated Windows source files ({} bytes)",
        inventory.file_count, inventory.total_bytes
    );
    let mut copied_files = 0_usize;
    let mut copied_bytes = 0_u64;
    for entry in &inventory.entries {
        if cancellation.is_cancelled() {
            return Err(BackendError::Cancelled(
                "Windows source staging was cancelled".to_owned(),
            ));
        }
        match entry.kind {
            SourceSnapshotEntryKind::Deleted => continue,
            SourceSnapshotEntryKind::Symlink => {
                return Err(BackendError::Command(format!(
                    "Windows task source inventory contains unsupported symbolic link `{}`",
                    entry.path
                )))
            }
            SourceSnapshotEntryKind::File => {}
        }
        validate_windows_source_ancestors(source, entry)?;
        let entry_source = inventory_path(source, &entry.path);
        let entry_target = inventory_path(target, &entry.path);
        if let Some(parent) = entry_target.parent() {
            std::fs::create_dir_all(parent).map_err(|error| {
                BackendError::Command(format!(
                    "create Windows staged source directory `{}`: {error}",
                    parent.display()
                ))
            })?;
        }
        let mut input = std::fs::OpenOptions::new()
            .read(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT | FILE_FLAG_SEQUENTIAL_SCAN)
            .open(&entry_source)
            .map_err(|error| {
                BackendError::Command(format!(
                    "open Windows task source file `{}`: {error}",
                    entry_source.display()
                ))
            })?;
        let input_metadata = input.metadata().map_err(|error| {
            BackendError::Command(format!(
                "inspect opened Windows task source file `{}`: {error}",
                entry_source.display()
            ))
        })?;
        if input_metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
            || !input_metadata.is_file()
        {
            return Err(BackendError::Command(format!(
                "Windows task source contains unsupported filesystem entry `{}`",
                entry_source.display()
            )));
        }
        if input_metadata.len() != entry.size_bytes {
            return Err(BackendError::Command(format!(
                "Windows task source file `{}` changed size after snapshot (expected {}, found {})",
                entry.path,
                entry.size_bytes,
                input_metadata.len()
            )));
        }
        let mut output = std::fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&entry_target)
            .map_err(|error| {
                BackendError::Command(format!(
                    "create Windows staged source file `{}`: {error}",
                    entry_target.display()
                ))
            })?;
        let mut hasher = Sha256::new();
        let mut file_bytes = 0_u64;
        let mut buffer = [0_u8; 64 * 1024];
        loop {
            if cancellation.is_cancelled() {
                return Err(BackendError::Cancelled(
                    "Windows source staging was cancelled".to_owned(),
                ));
            }
            let read = input.read(&mut buffer).map_err(|error| {
                BackendError::Command(format!(
                    "read Windows task source file `{}`: {error}",
                    entry.path
                ))
            })?;
            if read == 0 {
                break;
            }
            file_bytes = file_bytes.checked_add(read as u64).ok_or_else(|| {
                BackendError::Command("Windows source byte accounting overflowed".to_owned())
            })?;
            if file_bytes > entry.size_bytes {
                return Err(BackendError::Command(format!(
                    "Windows task source file `{}` grew while being staged",
                    entry.path
                )));
            }
            hasher.update(&buffer[..read]);
            output.write_all(&buffer[..read]).map_err(|error| {
                BackendError::Command(format!(
                    "write Windows staged source file `{}`: {error}",
                    entry.path
                ))
            })?;
        }
        if file_bytes != entry.size_bytes {
            return Err(BackendError::Command(format!(
                "Windows task source file `{}` changed while being staged",
                entry.path
            )));
        }
        let actual_digest =
            clusterflux_core::Digest::from_sha256_hex(format!("{:x}", hasher.finalize()))
                .map_err(BackendError::Command)?;
        if actual_digest != entry.digest {
            return Err(BackendError::Command(format!(
                "Windows task source file `{}` digest changed after snapshot",
                entry.path
            )));
        }
        copied_files += 1;
        copied_bytes = copied_bytes.checked_add(file_bytes).ok_or_else(|| {
            BackendError::Command("Windows source byte accounting overflowed".to_owned())
        })?;
        if copied_files % 1_000 == 0 {
            eprintln!(
                "staged {copied_files}/{} Windows source files ({copied_bytes} bytes)",
                inventory.file_count
            );
        }
    }
    eprintln!("Windows source staging complete: {copied_files} files, {copied_bytes} bytes");
    Ok(())
}

#[cfg(windows)]
fn inventory_path(root: &Path, relative: &str) -> std::path::PathBuf {
    relative
        .split('/')
        .fold(root.to_path_buf(), |path, part| path.join(part))
}

#[cfg(windows)]
fn validate_windows_source_ancestors(
    root: &Path,
    entry: &SourceSnapshotEntry,
) -> Result<(), BackendError> {
    use std::os::windows::fs::MetadataExt;
    use windows_sys::Win32::Storage::FileSystem::FILE_ATTRIBUTE_REPARSE_POINT;

    let mut current = root.to_path_buf();
    let component_count = entry.path.split('/').count();
    for component in entry
        .path
        .split('/')
        .take(component_count.saturating_sub(1))
    {
        current.push(component);
        let metadata = std::fs::symlink_metadata(&current).map_err(|error| {
            BackendError::Command(format!(
                "inspect Windows task source directory `{}`: {error}",
                current.display()
            ))
        })?;
        if !metadata.is_dir() || metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0 {
            return Err(BackendError::Command(format!(
                "Windows task source contains unsupported directory or reparse point `{}`",
                current.display()
            )));
        }
    }
    Ok(())
}

#[cfg(windows)]
fn verify_windows_staging_capacity(path: &Path, snapshot_bytes: u64) -> Result<(), BackendError> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::GetDiskFreeSpaceExW;

    let mut wide = path.as_os_str().encode_wide().collect::<Vec<_>>();
    wide.push(0);
    let mut available = 0_u64;
    // SAFETY: `wide` is a live NUL-terminated UTF-16 path and the remaining
    // output pointers are either valid or explicitly null.
    let succeeded = unsafe {
        GetDiskFreeSpaceExW(
            wide.as_ptr(),
            &mut available,
            std::ptr::null_mut(),
            std::ptr::null_mut(),
        )
    };
    if succeeded == 0 {
        return Err(BackendError::Command(format!(
            "inspect free space for Windows task staging `{}`: {}",
            path.display(),
            std::io::Error::last_os_error()
        )));
    }
    let required = snapshot_bytes.saturating_add(64 * 1024 * 1024);
    if available < required {
        return Err(BackendError::Command(format!(
            "Windows task source staging requires {required} free bytes including headroom, but only {available} are available"
        )));
    }
    Ok(())
}

#[cfg(windows)]
fn grant_windows_container_access(path: &Path, rights: &str) -> Result<(), BackendError> {
    let grant = format!("*S-1-5-11:(OI)(CI){rights}");
    let output = std::process::Command::new("icacls.exe")
        .arg(path)
        .args(["/grant", &grant, "/T", "/C", "/Q"])
        .output()
        .map_err(|error| {
            BackendError::Command(format!(
                "start Windows container mount ACL preparation for `{}`: {error}",
                path.display()
            ))
        })?;
    if output.status.success() {
        return Ok(());
    }
    Err(BackendError::Command(format!(
        "prepare Windows container mount ACL for `{}` failed with status {:?}: {}",
        path.display(),
        output.status.code(),
        String::from_utf8_lossy(&output.stderr).trim()
    )))
}

#[derive(Clone, Debug, Default)]
pub struct WindowsCommandDevBackend;

impl CommandBackend for WindowsCommandDevBackend {
    fn kind(&self) -> CommandBackendKind {
        CommandBackendKind::WindowsCommandDev
    }

    fn plan(&self, _invocation: &CommandInvocation) -> Result<CommandPlan, BackendError> {
        Ok(CommandPlan {
            guest_runtime: GuestRuntimeKind::Wasmtime,
            backend: CommandBackendKind::WindowsCommandDev,
            required_capability: Capability::WindowsCommandDev,
            user_attached_development_execution: true,
        })
    }
}

#[derive(Clone, Debug, Default)]
pub struct WindowsSandboxStubBackend;

impl CommandBackend for WindowsSandboxStubBackend {
    fn kind(&self) -> CommandBackendKind {
        CommandBackendKind::StubbedWindowsSandbox
    }

    fn plan(&self, _invocation: &CommandInvocation) -> Result<CommandPlan, BackendError> {
        Err(BackendError::Denied(
            "Windows sandbox backend is an explicit stub for MVP; use windows-command-dev only for user-attached development execution"
                .to_owned(),
        ))
    }
}
