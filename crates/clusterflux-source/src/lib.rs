use std::collections::BTreeMap;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitStatus, Stdio};
use std::time::{Duration, Instant};

#[cfg(test)]
use clusterflux_core::discover_environments;
use clusterflux_core::{
    environment_resource_from_revision_bytes, validate_commit_sha, validate_public_clone_url,
    validate_workflow_source_path, CommitTrigger, Digest, EnvironmentContextFile, EnvironmentKind,
    EnvironmentResource, ProjectModel, RepositoryRevision, SourceProviderKind, WorkflowSource,
    WorkflowSourceFile, MAX_ENVIRONMENT_CONTEXT_BYTES, MAX_ENVIRONMENT_CONTEXT_DEPTH,
    MAX_ENVIRONMENT_CONTEXT_FILES, MAX_ENVIRONMENT_CONTEXT_FILE_BYTES,
    MAX_ENVIRONMENT_CONTEXT_PATH_BYTES, MAX_WORKFLOW_SOURCE_BYTES, MAX_WORKFLOW_SOURCE_FILES,
};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};

const MAX_SNAPSHOT_FILES: usize = 20_000;
const MAX_SNAPSHOT_FILE_BYTES: u64 = 256 * 1024 * 1024;
const MAX_SNAPSHOT_TOTAL_BYTES: u64 = 1024 * 1024 * 1024;
const DEFAULT_GIT_TIMEOUT: Duration = Duration::from_secs(90);
const MAX_GIT_DIAGNOSTIC_BYTES: usize = 64 * 1024;
const MAX_WORKFLOW_FETCH_DISK_BYTES: u64 = 64 * 1024 * 1024;
const MAX_REVISION_CHECKOUT_DISK_BYTES: u64 = 2 * 1024 * 1024 * 1024;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProjectSourceOrigin {
    LocalCheckout,
    ExactForgeRevision { commit_sha: String },
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshotIdentity {
    pub digest: Digest,
    pub provider: String,
    pub mode: String,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ResolvedClusterfluxProject {
    pub project_root: PathBuf,
    pub workflow_root: PathBuf,
    pub manifest_digest: Digest,
    pub crate_root: PathBuf,
    pub workflow_files: Vec<WorkflowSourceFile>,
    pub environments: Vec<EnvironmentResource>,
    pub source_snapshot: SourceSnapshotIdentity,
    pub source_origin: ProjectSourceOrigin,
    pub model: ProjectModel,
}

pub fn resolve_local_clusterflux_project(
    project_root: &Path,
    provider: &SourceProviderKind,
) -> Result<ResolvedClusterfluxProject, String> {
    let project_root = project_root
        .canonicalize()
        .map_err(|error| format!("resolve Clusterflux project root: {error}"))?;
    let model =
        ProjectModel::discover_without_config(&project_root).map_err(|error| error.to_string())?;
    let workflow_root = project_root.join(".clusterflux");
    let crate_root = workflow_root.join("main.rs");
    let mut workflow_files = Vec::new();
    collect_local_workflow_files(&workflow_root, &workflow_root, &mut workflow_files)?;
    workflow_files.sort_by(|left, right| left.path.cmp(&right.path));
    let manifest_count = workflow_files
        .iter()
        .filter(|file| file.path == ".clusterflux/Cargo.toml")
        .count();
    if manifest_count != 1
        || !workflow_files
            .iter()
            .any(|file| file.path == ".clusterflux/main.rs")
    {
        return Err(
            "Clusterflux project requires .clusterflux/Cargo.toml and .clusterflux/main.rs"
                .to_owned(),
        );
    }
    let snapshot = snapshot_project_with_provider(&project_root, provider)?;
    Ok(ResolvedClusterfluxProject {
        project_root,
        workflow_root,
        manifest_digest: model.manifest_digest.clone(),
        crate_root,
        workflow_files,
        environments: model.environments.clone(),
        source_snapshot: SourceSnapshotIdentity {
            digest: snapshot.digest,
            provider: snapshot.provider,
            mode: snapshot.source_mode,
        },
        source_origin: ProjectSourceOrigin::LocalCheckout,
        model,
    })
}

fn collect_local_workflow_files(
    workflow_root: &Path,
    directory: &Path,
    files: &mut Vec<WorkflowSourceFile>,
) -> Result<(), String> {
    for entry in fs::read_dir(directory).map_err(|error| {
        format!(
            "read workflow source directory {}: {error}",
            directory.display()
        )
    })? {
        let entry = entry.map_err(|error| format!("inspect workflow source entry: {error}"))?;
        let path = entry.path();
        let metadata = fs::symlink_metadata(&path)
            .map_err(|error| format!("inspect workflow source {}: {error}", path.display()))?;
        if metadata.file_type().is_symlink() {
            return Err(format!(
                "workflow source `{}` must not be a symlink",
                path.display()
            ));
        }
        if metadata.is_dir() {
            collect_local_workflow_files(workflow_root, &path, files)?;
            continue;
        }
        if !metadata.is_file() {
            return Err(format!(
                "workflow source `{}` must be a regular file",
                path.display()
            ));
        }
        let relative = path
            .strip_prefix(workflow_root)
            .map_err(|_| "workflow source escaped .clusterflux".to_owned())?;
        let relative = slash_path(relative)?;
        if relative == "Cargo.lock" {
            continue;
        }
        if relative != "Cargo.toml" && !relative.ends_with(".rs") {
            return Err(format!(
                "workflow directory contains unsupported source file `.clusterflux/{relative}`"
            ));
        }
        if files.len() >= MAX_WORKFLOW_SOURCE_FILES {
            return Err(format!(
                "workflow source exceeds the {MAX_WORKFLOW_SOURCE_FILES} file limit"
            ));
        }
        let source_path = format!(".clusterflux/{relative}");
        validate_workflow_source_path(&source_path)?;
        let bytes = fs::read(&path)
            .map_err(|error| format!("read workflow source {}: {error}", path.display()))?;
        let mode = if is_executable(&metadata) {
            0o100755
        } else {
            0o100644
        };
        files.push(WorkflowSourceFile::new(source_path, mode, bytes)?);
    }
    let total = files.iter().map(|file| file.bytes.len()).sum::<usize>();
    if total > MAX_WORKFLOW_SOURCE_BYTES {
        return Err(format!(
            "workflow source exceeds {MAX_WORKFLOW_SOURCE_BYTES} total bytes"
        ));
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(metadata: &fs::Metadata) -> bool {
    use std::os::unix::fs::PermissionsExt;
    metadata.permissions().mode() & 0o111 != 0
}

#[cfg(not(unix))]
fn is_executable(_metadata: &fs::Metadata) -> bool {
    false
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ExactRevisionSourceLimits {
    pub max_files: usize,
    pub max_file_bytes: usize,
    pub max_total_bytes: usize,
    pub git_timeout: Duration,
}

impl Default for ExactRevisionSourceLimits {
    fn default() -> Self {
        Self {
            max_files: MAX_WORKFLOW_SOURCE_FILES,
            max_file_bytes: clusterflux_core::automation::MAX_WORKFLOW_SOURCE_FILE_BYTES,
            max_total_bytes: MAX_WORKFLOW_SOURCE_BYTES,
            git_timeout: DEFAULT_GIT_TIMEOUT,
        }
    }
}

impl ExactRevisionSourceLimits {
    pub fn validate(&self) -> Result<(), String> {
        if self.max_files == 0
            || self.max_files > MAX_WORKFLOW_SOURCE_FILES
            || self.max_file_bytes == 0
            || self.max_file_bytes > clusterflux_core::automation::MAX_WORKFLOW_SOURCE_FILE_BYTES
            || self.max_total_bytes == 0
            || self.max_total_bytes > MAX_WORKFLOW_SOURCE_BYTES
            || self.git_timeout.is_zero()
            || self.git_timeout > Duration::from_secs(10 * 60)
        {
            return Err("exact-revision source limits exceed public compiler bounds".to_owned());
        }
        Ok(())
    }
}

/// Temporary, exact public Git checkout held for the lifetime of one task.
pub struct MaterializedRepositoryRevision {
    directory: tempfile::TempDir,
}

impl MaterializedRepositoryRevision {
    pub fn root(&self) -> &Path {
        self.directory.path()
    }
}

/// Canonical checkout of the current local Git revision for deployment-time
/// environment materialization. The selected project's environment definitions
/// must be clean so the image identity cannot silently diverge from `HEAD`.
#[derive(Debug)]
pub struct MaterializedLocalGitRevision {
    _directory: tempfile::TempDir,
    project_root: PathBuf,
}

impl MaterializedLocalGitRevision {
    pub fn root(&self) -> &Path {
        &self.project_root
    }
}

pub fn materialize_clean_local_git_revision(
    project_root: &Path,
) -> Result<Option<MaterializedLocalGitRevision>, String> {
    let project_root = resolve_project_root(project_root)?;
    let Some(repository_root) = git_repository_root(&project_root)? else {
        return Ok(None);
    };
    let project_prefix = project_root
        .strip_prefix(&repository_root)
        .map_err(|_| "project root is outside its discovered Git repository".to_owned())?;
    let environment_path = if project_prefix.as_os_str().is_empty() {
        "envs".to_owned()
    } else {
        format!("{}/envs", slash_path(project_prefix)?)
    };
    let status = run_git(
        &repository_root,
        [
            "status",
            "--porcelain=v1",
            "-z",
            "--untracked-files=all",
            "--",
            environment_path.as_str(),
        ],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
    )?;
    if !status.is_empty() {
        let changed = status
            .split(|byte| *byte == 0)
            .filter(|entry| !entry.is_empty())
            .take(8)
            .map(|entry| String::from_utf8_lossy(entry).into_owned())
            .collect::<Vec<_>>()
            .join(", ");
        return Err(format!(
            "environment definitions must be committed before immutable image setup: {changed}"
        ));
    }
    let commit = run_git(
        &repository_root,
        ["rev-parse", "--verify", "HEAD"],
        DEFAULT_GIT_TIMEOUT,
        128,
    )?;
    let commit = std::str::from_utf8(&commit)
        .map_err(|_| "Git returned a non-UTF-8 commit identity".to_owned())?
        .trim()
        .to_owned();
    validate_commit_sha(&commit)?;
    let repository_text = repository_root
        .to_str()
        .ok_or_else(|| "Git repository path is not UTF-8".to_owned())?;
    #[cfg(windows)]
    let repository_text = {
        let slash_path = repository_text.replace('\\', "/");
        if let Some(unc) = slash_path.strip_prefix("//?/UNC/") {
            format!("//{unc}")
        } else {
            slash_path
                .strip_prefix("//?/")
                .unwrap_or(&slash_path)
                .to_owned()
        }
    };
    #[cfg(not(windows))]
    let repository_text = repository_text.to_owned();
    let directory = tempfile::Builder::new()
        .prefix("clusterflux-local-revision-")
        .tempdir()
        .map_err(|error| format!("create local revision checkout: {error}"))?;
    run_git_cancellable_bounded(
        directory.path(),
        [
            "clone",
            "--quiet",
            "--no-checkout",
            "--no-hardlinks",
            repository_text.as_str(),
            "checkout",
        ],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &|| false,
    )?;
    let checkout = directory.path().join("checkout");
    run_git(
        &checkout,
        ["config", "core.autocrlf", "false"],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
    )?;
    run_git(
        &checkout,
        ["checkout", "--quiet", "--detach", commit.as_str()],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
    )?;
    let materialized_project_root = checkout.join(project_prefix);
    if !materialized_project_root.is_dir() {
        return Err("materialized local Git revision omits the selected project".to_owned());
    }
    Ok(Some(MaterializedLocalGitRevision {
        _directory: directory,
        project_root: materialized_project_root,
    }))
}

pub fn materialize_exact_repository_revision(
    revision: &RepositoryRevision,
) -> Result<MaterializedRepositoryRevision, String> {
    materialize_exact_repository_revision_cancellable(revision, || false)
}

pub fn materialize_exact_repository_revision_cancellable(
    revision: &RepositoryRevision,
    cancelled: impl Fn() -> bool,
) -> Result<MaterializedRepositoryRevision, String> {
    revision.validate()?;
    let expected_snapshot = Digest::from_parts([
        b"clusterflux-git-revision:v1".as_slice(),
        revision.repository_id.as_str().as_bytes(),
        revision.clone_url.as_bytes(),
        revision.commit_sha.as_bytes(),
    ]);
    if expected_snapshot != revision.source_snapshot {
        return Err("repository revision source handle does not match its metadata".to_owned());
    }
    let directory = tempfile::Builder::new()
        .prefix("clusterflux-exact-checkout-")
        .tempdir()
        .map_err(|error| format!("create exact checkout: {error}"))?;
    run_git_cancellable_bounded(
        directory.path(),
        ["init", "--quiet"],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &cancelled,
    )?;
    run_git_cancellable_bounded(
        directory.path(),
        ["config", "core.autocrlf", "false"],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &cancelled,
    )?;
    run_git_cancellable_bounded(
        directory.path(),
        ["remote", "add", "origin", revision.clone_url.as_str()],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &cancelled,
    )?;
    run_git_cancellable_bounded(
        directory.path(),
        [
            "fetch",
            "--quiet",
            "--depth=1",
            "--no-tags",
            "origin",
            revision.commit_sha.as_str(),
        ],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &cancelled,
    )?;
    run_git_cancellable_bounded(
        directory.path(),
        ["checkout", "--quiet", "--detach", "FETCH_HEAD"],
        DEFAULT_GIT_TIMEOUT,
        MAX_GIT_DIAGNOSTIC_BYTES,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &cancelled,
    )?;
    let actual = run_git_cancellable_bounded(
        directory.path(),
        ["rev-parse", "--verify", "HEAD^{commit}"],
        DEFAULT_GIT_TIMEOUT,
        256,
        MAX_REVISION_CHECKOUT_DISK_BYTES,
        &cancelled,
    )?;
    if String::from_utf8(actual)
        .map_err(|_| "Git returned a non-UTF-8 checkout identity".to_owned())?
        .trim()
        != revision.commit_sha
    {
        return Err("materialized checkout does not match the required commit".to_owned());
    }
    Ok(MaterializedRepositoryRevision { directory })
}

pub fn load_exact_workflow_source(
    trigger: &CommitTrigger,
    configured_clone_url: &str,
    limits: &ExactRevisionSourceLimits,
) -> Result<(WorkflowSource, RepositoryRevision), String> {
    trigger.validate()?;
    validate_public_clone_url(configured_clone_url)?;
    validate_commit_sha(&trigger.commit_sha)?;
    limits.validate()?;
    if trigger.repository_url != configured_clone_url {
        return Err("trigger repository URL does not match the configured binding".to_owned());
    }

    let loaded =
        load_exact_workflow_source_from_validated_binding(trigger, configured_clone_url, limits)?;
    loaded.1.validate()?;
    Ok(loaded)
}

/// Resolve one branch or tag from a public binding without cloning its worktree.
/// The Git command is non-interactive, time bounded, and output bounded. Annotated
/// tags resolve to their peeled commit rather than the tag object.
pub fn resolve_public_git_ref(repository_url: &str, git_ref: &str) -> Result<String, String> {
    validate_public_clone_url(repository_url)?;
    if git_ref.len() > 512
        || !(git_ref.starts_with("refs/heads/") || git_ref.starts_with("refs/tags/"))
        || git_ref.ends_with('/')
    {
        return Err("Git ref must identify a branch or tag".to_owned());
    }
    let peeled = format!("{git_ref}^{{}}");
    let workspace = isolated_git_metadata_workspace()?;
    let output = run_git(
        workspace.path(),
        ["ls-remote", repository_url, git_ref, peeled.as_str()],
        DEFAULT_GIT_TIMEOUT,
        4 * 1024,
    )?;
    parse_resolved_git_ref(&output, git_ref)
}

fn isolated_git_metadata_workspace() -> Result<tempfile::TempDir, String> {
    tempfile::Builder::new()
        .prefix("clusterflux-git-metadata-")
        .tempdir()
        .map_err(|error| format!("create Git metadata temporary directory: {error}"))
}

fn parse_resolved_git_ref(output: &[u8], git_ref: &str) -> Result<String, String> {
    let output = std::str::from_utf8(output)
        .map_err(|_| "Git returned non-UTF-8 ref metadata".to_owned())?;
    let peeled_ref = format!("{git_ref}^{{}}");
    let mut exact = None;
    let mut peeled = None;
    for line in output.lines().filter(|line| !line.trim().is_empty()) {
        let (commit, reference) = line
            .split_once('\t')
            .ok_or_else(|| "Git returned malformed ref metadata".to_owned())?;
        validate_commit_sha(commit)?;
        if reference == peeled_ref {
            peeled = Some(commit.to_owned());
        } else if reference == git_ref {
            exact = Some(commit.to_owned());
        } else {
            return Err("Git returned an unexpected ref while resolving the binding".to_owned());
        }
    }
    peeled
        .or(exact)
        .ok_or_else(|| format!("Git ref `{git_ref}` was not found"))
}

fn load_exact_workflow_source_from_validated_binding(
    trigger: &CommitTrigger,
    configured_clone_url: &str,
    limits: &ExactRevisionSourceLimits,
) -> Result<(WorkflowSource, RepositoryRevision), String> {
    let checkout = tempfile::Builder::new()
        .prefix("clusterflux-exact-source-")
        .tempdir()
        .map_err(|error| format!("create exact-source temporary directory: {error}"))?;
    run_git(
        checkout.path(),
        ["init", "--quiet"],
        limits.git_timeout,
        MAX_GIT_DIAGNOSTIC_BYTES,
    )?;
    run_git(
        checkout.path(),
        ["remote", "add", "origin", configured_clone_url],
        limits.git_timeout,
        MAX_GIT_DIAGNOSTIC_BYTES,
    )?;

    let filtered = run_git(
        checkout.path(),
        [
            "fetch",
            "--quiet",
            "--filter=blob:none",
            "--depth=1",
            "origin",
            trigger.commit_sha.as_str(),
        ],
        limits.git_timeout,
        MAX_GIT_DIAGNOSTIC_BYTES,
    );
    if filtered.is_err() {
        run_git(
            checkout.path(),
            [
                "fetch",
                "--quiet",
                "--depth=1",
                "origin",
                trigger.commit_sha.as_str(),
            ],
            limits.git_timeout,
            MAX_GIT_DIAGNOSTIC_BYTES,
        )?;
    }

    let fetched = run_git(
        checkout.path(),
        ["rev-parse", "--verify", "FETCH_HEAD^{commit}"],
        limits.git_timeout,
        256,
    )?;
    let fetched = String::from_utf8(fetched)
        .map_err(|_| "Git returned a non-UTF-8 commit identity".to_owned())?;
    if fetched.trim() != trigger.commit_sha {
        return Err(format!(
            "fetched commit {} does not match trigger commit {}",
            fetched.trim(),
            trigger.commit_sha
        ));
    }

    let tree = run_git(
        checkout.path(),
        [
            "ls-tree",
            "-rz",
            "-l",
            "--full-tree",
            "FETCH_HEAD",
            "--",
            ".clusterflux",
            "envs",
        ],
        limits.git_timeout,
        limits
            .max_files
            .saturating_mul(clusterflux_core::automation::MAX_WORKFLOW_SOURCE_PATH_BYTES + 128),
    )?;
    let all_entries = parse_revision_tree(&tree, limits)?;
    let entries = all_entries
        .iter()
        .filter(|entry| entry.3.starts_with(".clusterflux/"))
        .cloned()
        .collect::<Vec<_>>();
    let mut files = Vec::with_capacity(entries.len());
    let total_bytes = entries
        .iter()
        .try_fold(0_usize, |total, (_, _, size, path)| {
            let maximum = if path == ".clusterflux/Cargo.toml" {
                clusterflux_core::MAX_WORKFLOW_MANIFEST_BYTES
            } else {
                limits.max_file_bytes
            };
            if *size > maximum {
                return Err(format!(
                    "workflow source file `{path}` is {size} bytes; limit is {maximum} bytes"
                ));
            }
            let next = total.saturating_add(*size);
            if next > limits.max_total_bytes {
                return Err(format!(
                    "workflow source exceeds {} total bytes",
                    limits.max_total_bytes
                ));
            }
            Ok(next)
        })?;
    let _ = total_bytes;
    for (mode, object_id, expected_size, path) in entries {
        let bytes = run_git(
            checkout.path(),
            ["cat-file", "blob", object_id.as_str()],
            limits.git_timeout,
            expected_size,
        )?;
        if bytes.len() != expected_size {
            return Err(format!(
                "workflow blob `{path}` size changed during exact-commit loading"
            ));
        }
        files.push(WorkflowSourceFile::new(path, mode, bytes)?);
    }

    let environments = load_revision_environments(checkout.path(), &all_entries, limits)?;

    let source = WorkflowSource::new_with_environments(
        trigger.trigger_id.clone(),
        trigger.repository_id.clone(),
        trigger.commit_sha.clone(),
        files,
        environments,
    )?;
    let source_snapshot = Digest::from_parts([
        b"clusterflux-git-revision:v1".as_slice(),
        trigger.repository_id.as_str().as_bytes(),
        configured_clone_url.as_bytes(),
        trigger.commit_sha.as_bytes(),
    ]);
    let revision = RepositoryRevision {
        repository_id: trigger.repository_id.clone(),
        clone_url: configured_clone_url.to_owned(),
        commit_sha: trigger.commit_sha.clone(),
        source_snapshot,
    };
    Ok((source, revision))
}

fn parse_revision_tree(
    bytes: &[u8],
    limits: &ExactRevisionSourceLimits,
) -> Result<Vec<(u32, String, usize, String)>, String> {
    let mut entries = Vec::new();
    for record in bytes
        .split(|byte| *byte == 0)
        .filter(|record| !record.is_empty())
    {
        if entries.len() >= limits.max_files {
            return Err(format!(
                "workflow source exceeds the {} file limit",
                limits.max_files
            ));
        }
        let record = std::str::from_utf8(record)
            .map_err(|_| "Git workflow tree contains a non-UTF-8 path".to_owned())?;
        let (metadata, path) = record
            .split_once('\t')
            .ok_or_else(|| "Git workflow tree record is malformed".to_owned())?;
        let mut metadata = metadata.split_ascii_whitespace();
        let mode = metadata
            .next()
            .ok_or_else(|| "Git workflow tree record omits mode".to_owned())?;
        let kind = metadata
            .next()
            .ok_or_else(|| "Git workflow tree record omits object kind".to_owned())?;
        let object_id = metadata
            .next()
            .ok_or_else(|| "Git workflow tree record omits object ID".to_owned())?;
        let size = metadata
            .next()
            .ok_or_else(|| "Git workflow tree record omits blob size".to_owned())?
            .parse::<usize>()
            .map_err(|_| "Git workflow tree blob size is malformed".to_owned())?;
        if kind != "blob" || !matches!(mode, "100644" | "100755") {
            return Err(format!(
                "workflow source `{path}` must be a regular non-symlink file"
            ));
        }
        if path.starts_with(".clusterflux/") {
            if path != ".clusterflux/Cargo.toml" && !path.ends_with(".rs") {
                return Err(format!(
                    "workflow directory contains unsupported non-Rust file `{path}`"
                ));
            }
            validate_workflow_source_path(path)?;
        } else {
            validate_environment_revision_path(path)?;
        }
        let mode = u32::from_str_radix(mode, 8)
            .map_err(|_| "Git workflow tree mode is malformed".to_owned())?;
        entries.push((mode, object_id.to_owned(), size, path.to_owned()));
    }
    entries.sort_by(|left, right| left.3.cmp(&right.3));
    Ok(entries)
}

fn validate_environment_revision_path(path: &str) -> Result<(), String> {
    let Some((name, relative)) = path
        .strip_prefix("envs/")
        .and_then(|rest| rest.split_once('/'))
    else {
        return Err(format!(
            "unsupported or invalid environment revision path `{path}`"
        ));
    };
    let first = relative.split('/').next().unwrap_or_default();
    let valid = !name.is_empty()
        && name.len() <= 128
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        && !matches!(first, ".git" | "target" | ".clusterflux")
        && !relative.is_empty()
        && relative.len() <= MAX_ENVIRONMENT_CONTEXT_PATH_BYTES
        && relative.split('/').count() <= MAX_ENVIRONMENT_CONTEXT_DEPTH
        && !relative.contains('\\')
        && relative
            .split('/')
            .all(|component| !component.is_empty() && !matches!(component, "." | ".."));
    if !valid || path.len() > clusterflux_core::automation::MAX_WORKFLOW_SOURCE_PATH_BYTES {
        return Err(format!(
            "unsupported or invalid environment revision path `{path}`"
        ));
    }
    Ok(())
}

fn load_revision_environments(
    checkout: &Path,
    entries: &[(u32, String, usize, String)],
    limits: &ExactRevisionSourceLimits,
) -> Result<Vec<EnvironmentResource>, String> {
    let mut by_name: BTreeMap<String, Vec<(u32, String, String, usize)>> = BTreeMap::new();
    for (mode, object, size, path) in entries.iter().filter(|entry| entry.3.starts_with("envs/")) {
        let name = path
            .strip_prefix("envs/")
            .and_then(|rest| rest.split_once('/'))
            .map(|(name, _)| name.to_owned())
            .ok_or_else(|| format!("invalid environment revision path `{path}`"))?;
        by_name
            .entry(name)
            .or_default()
            .push((*mode, path.clone(), object.clone(), *size));
    }
    if by_name.len() > 64 {
        return Err("exact revision contains too many environments".to_owned());
    }
    let mut resources = Vec::new();
    for (name, files) in by_name {
        let recipe = files.iter().find(|(_, path, _, _)| {
            matches!(
                path.rsplit('/').next(),
                Some("Containerfile" | "Dockerfile" | "flake.nix")
            )
        });
        let Some((_, recipe_path, recipe_object, recipe_size)) = recipe else {
            continue;
        };
        if *recipe_size > limits.max_file_bytes {
            return Err(format!(
                "environment recipe `{recipe_path}` exceeds its byte limit"
            ));
        }
        let recipe_bytes = run_git(
            checkout,
            ["cat-file", "blob", recipe_object.as_str()],
            limits.git_timeout,
            *recipe_size,
        )?;
        let metadata_bytes = if let Some((_, path, object, size)) = files
            .iter()
            .find(|(_, path, _, _)| path.ends_with("/environment.toml"))
        {
            if *size > limits.max_file_bytes {
                return Err(format!(
                    "environment metadata `{path}` exceeds its byte limit"
                ));
            }
            run_git(
                checkout,
                ["cat-file", "blob", object.as_str()],
                limits.git_timeout,
                *size,
            )?
        } else {
            Vec::new()
        };
        if files.len() > MAX_ENVIRONMENT_CONTEXT_FILES {
            return Err(format!(
                "environment `{name}` exceeds its context file limit"
            ));
        }
        let context_total = files
            .iter()
            .try_fold(0_usize, |total, (_, path, _, size)| {
                if *size > MAX_ENVIRONMENT_CONTEXT_FILE_BYTES {
                    return Err(format!(
                        "environment context file `{path}` exceeds its byte limit"
                    ));
                }
                let total = total.saturating_add(*size);
                if total > MAX_ENVIRONMENT_CONTEXT_BYTES {
                    return Err(format!(
                        "environment `{name}` exceeds its total context byte limit"
                    ));
                }
                Ok(total)
            })?;
        let mut context_manifest = Vec::with_capacity(files.len());
        for (mode, path, object, size) in &files {
            let bytes = run_git(
                checkout,
                ["cat-file", "blob", object.as_str()],
                limits.git_timeout,
                *size,
            )?;
            if bytes.len() != *size {
                return Err(format!(
                    "environment blob `{path}` size changed while loading"
                ));
            }
            let relative = path
                .strip_prefix(&format!("envs/{name}/"))
                .ok_or_else(|| format!("environment context path `{path}` escaped its root"))?;
            context_manifest.push(EnvironmentContextFile {
                path: relative.to_owned(),
                mode: *mode,
                size: *size as u64,
                digest: Digest::sha256(&bytes),
            });
        }
        let _ = context_total;
        let kind = match recipe_path.rsplit('/').next() {
            Some("Containerfile") => EnvironmentKind::Containerfile,
            Some("Dockerfile") => EnvironmentKind::Dockerfile,
            Some("flake.nix") => EnvironmentKind::NixFlake,
            _ => unreachable!("recipe selection was bounded"),
        };
        resources.push(environment_resource_from_revision_bytes(
            &name,
            kind,
            PathBuf::from(recipe_path),
            PathBuf::from(format!("envs/{name}")),
            &recipe_bytes,
            &metadata_bytes,
            context_manifest,
        )?);
    }
    Ok(resources)
}

fn run_git<const N: usize>(
    directory: &Path,
    arguments: [&str; N],
    timeout: Duration,
    max_stdout_bytes: usize,
) -> Result<Vec<u8>, String> {
    run_git_cancellable(directory, arguments, timeout, max_stdout_bytes, &|| false)
}

fn run_git_cancellable<const N: usize>(
    directory: &Path,
    arguments: [&str; N],
    timeout: Duration,
    max_stdout_bytes: usize,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, String> {
    run_git_cancellable_bounded(
        directory,
        arguments,
        timeout,
        max_stdout_bytes,
        MAX_WORKFLOW_FETCH_DISK_BYTES,
        cancelled,
    )
}

fn run_git_cancellable_bounded<const N: usize>(
    directory: &Path,
    arguments: [&str; N],
    timeout: Duration,
    max_stdout_bytes: usize,
    max_workspace_bytes: u64,
    cancelled: &dyn Fn() -> bool,
) -> Result<Vec<u8>, String> {
    let stdout =
        tempfile::tempfile().map_err(|error| format!("create Git stdout file: {error}"))?;
    let stderr =
        tempfile::tempfile().map_err(|error| format!("create Git stderr file: {error}"))?;
    let mut command = Command::new("git");
    command
        .current_dir(directory)
        .env("GIT_TERMINAL_PROMPT", "0")
        .env("GIT_CONFIG_NOSYSTEM", "1")
        .args(arguments)
        .stdout(Stdio::from(
            stdout
                .try_clone()
                .map_err(|error| format!("clone Git stdout file: {error}"))?,
        ))
        .stderr(Stdio::from(
            stderr
                .try_clone()
                .map_err(|error| format!("clone Git stderr file: {error}"))?,
        ));
    #[cfg(unix)]
    {
        use std::os::unix::process::CommandExt;
        // SAFETY: setpgid is async-signal-safe and does not access Rust-owned memory.
        unsafe {
            command.pre_exec(|| {
                if libc::setpgid(0, 0) == 0 {
                    Ok(())
                } else {
                    Err(std::io::Error::last_os_error())
                }
            });
        }
    }
    let mut child = command
        .spawn()
        .map_err(|error| format!("start Git: {error}"))?;
    let started = Instant::now();
    let mut last_disk_check = Instant::now();
    let status = loop {
        if cancelled() {
            terminate_process_group(&mut child);
            return Err("Git operation was cancelled".to_owned());
        }
        if last_disk_check.elapsed() >= Duration::from_millis(100) {
            last_disk_check = Instant::now();
            if workspace_size(directory, max_workspace_bytes)? > max_workspace_bytes {
                terminate_process_group(&mut child);
                return Err(format!(
                    "Git workspace exceeds the {max_workspace_bytes}-byte disk limit"
                ));
            }
        }
        match child.try_wait() {
            Ok(Some(status)) => break status,
            Ok(None) if started.elapsed() >= timeout => {
                terminate_process_group(&mut child);
                return Err(format!(
                    "Git operation exceeded {} seconds",
                    timeout.as_secs()
                ));
            }
            Ok(None) => std::thread::sleep(Duration::from_millis(25)),
            Err(error) => {
                terminate_process_group(&mut child);
                return Err(format!("wait for Git: {error}"));
            }
        }
    };
    finish_git_output(status, stdout, stderr, max_stdout_bytes)
}

fn terminate_process_group(child: &mut std::process::Child) {
    #[cfg(unix)]
    unsafe {
        libc::kill(-(child.id() as i32), libc::SIGKILL);
    }
    let _ = child.kill();
    let _ = child.wait();
}

fn workspace_size(root: &Path, limit: u64) -> Result<u64, String> {
    let mut total = 0_u64;
    let mut pending = vec![root.to_path_buf()];
    while let Some(directory) = pending.pop() {
        let entries = match fs::read_dir(&directory) {
            Ok(entries) => entries,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound && directory != root => {
                continue;
            }
            Err(error) => return Err(format!("inspect Git workspace disk use: {error}")),
        };
        for entry in entries {
            let entry = match entry {
                Ok(entry) => entry,
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => continue,
                Err(error) => return Err(format!("inspect Git workspace entry: {error}")),
            };
            let Some(metadata) = workspace_entry_metadata(&entry.path())? else {
                continue;
            };
            if metadata.is_dir() {
                pending.push(entry.path());
            } else if metadata.is_file() {
                total = total.saturating_add(metadata.len());
                if total > limit {
                    return Ok(total);
                }
            }
        }
    }
    Ok(total)
}

fn workspace_entry_metadata(path: &Path) -> Result<Option<fs::Metadata>, String> {
    match fs::symlink_metadata(path) {
        Ok(metadata) => Ok(Some(metadata)),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(format!("inspect Git workspace metadata: {error}")),
    }
}

fn finish_git_output(
    status: ExitStatus,
    mut stdout: fs::File,
    mut stderr: fs::File,
    max_stdout_bytes: usize,
) -> Result<Vec<u8>, String> {
    use std::io::{Seek, SeekFrom};
    stdout
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek Git stdout: {error}"))?;
    stderr
        .seek(SeekFrom::Start(0))
        .map_err(|error| format!("seek Git stderr: {error}"))?;
    let mut output = Vec::new();
    stdout
        .by_ref()
        .take(max_stdout_bytes.saturating_add(1) as u64)
        .read_to_end(&mut output)
        .map_err(|error| format!("read Git stdout: {error}"))?;
    if output.len() > max_stdout_bytes {
        return Err(format!(
            "Git output exceeds the {max_stdout_bytes}-byte limit"
        ));
    }
    let mut diagnostic = Vec::new();
    stderr
        .take(MAX_GIT_DIAGNOSTIC_BYTES as u64)
        .read_to_end(&mut diagnostic)
        .map_err(|error| format!("read Git stderr: {error}"))?;
    if !status.success() {
        return Err(format!(
            "Git exited with status {:?}: {}",
            status.code(),
            String::from_utf8_lossy(&diagnostic).trim()
        ));
    }
    Ok(output)
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshotInventory {
    pub digest: Digest,
    pub provider: String,
    pub file_count: usize,
    pub total_bytes: u64,
    pub source_mode: String,
    pub entries: Vec<SourceSnapshotEntry>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SourceSnapshotEntryKind {
    File,
    Symlink,
    Deleted,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceSnapshotEntry {
    pub path: String,
    pub kind: SourceSnapshotEntryKind,
    pub executable: bool,
    pub digest: Digest,
    pub size_bytes: u64,
}

impl SourceSnapshotInventory {
    /// Revalidates the immutable materialization plan before a backend uses it.
    /// Snapshot creation already applies these checks; this second boundary keeps
    /// filesystem backends from trusting a malformed or stale in-memory plan.
    pub fn validate_materialization_plan(&self) -> Result<(), String> {
        if self.file_count != self.entries.len() {
            return Err("source snapshot file count does not match its entries".to_owned());
        }
        if self.file_count > MAX_SNAPSHOT_FILES {
            return Err(format!(
                "source snapshot has {} files; limit is {MAX_SNAPSHOT_FILES}",
                self.file_count
            ));
        }
        let mut previous = None;
        let mut total_bytes = 0_u64;
        for entry in &self.entries {
            validate_relative_source_path(&entry.path)?;
            if previous.is_some_and(|previous: &str| previous >= entry.path.as_str()) {
                return Err("source snapshot entries are not sorted and unique".to_owned());
            }
            previous = Some(entry.path.as_str());
            if entry.size_bytes > MAX_SNAPSHOT_FILE_BYTES {
                return Err(format!(
                    "source file `{}` is {} bytes; per-file limit is {MAX_SNAPSHOT_FILE_BYTES}",
                    entry.path, entry.size_bytes
                ));
            }
            total_bytes = total_bytes
                .checked_add(entry.size_bytes)
                .ok_or_else(|| "source snapshot byte accounting overflowed".to_owned())?;
        }
        if total_bytes != self.total_bytes {
            return Err("source snapshot total bytes do not match its entries".to_owned());
        }
        if total_bytes > MAX_SNAPSHOT_TOTAL_BYTES {
            return Err(format!(
                "source snapshot is {total_bytes} bytes; limit is {MAX_SNAPSHOT_TOTAL_BYTES}"
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct SnapshotFile {
    path: String,
    kind: &'static str,
    executable: bool,
    digest: Digest,
    size_bytes: u64,
}

pub fn snapshot_project(project_root: &Path) -> Result<SourceSnapshotInventory, String> {
    snapshot_project_cancellable(project_root, || false)
}

pub fn snapshot_project_cancellable(
    project_root: &Path,
    cancelled: impl Fn() -> bool,
) -> Result<SourceSnapshotInventory, String> {
    let project_root = resolve_project_root(project_root)?;
    check_snapshot_cancelled(&cancelled)?;
    if let Some(repository_root) = git_repository_root(&project_root)? {
        snapshot_git_project(&repository_root, &project_root, &cancelled)
    } else {
        snapshot_filesystem_project(&project_root, &cancelled)
    }
}

pub fn snapshot_project_with_provider(
    project_root: &Path,
    provider: &SourceProviderKind,
) -> Result<SourceSnapshotInventory, String> {
    let project_root = resolve_project_root(project_root)?;
    match provider {
        SourceProviderKind::Filesystem => snapshot_filesystem_project(&project_root, &|| false),
        SourceProviderKind::Git => {
            let repository_root = git_repository_root(&project_root)?.ok_or_else(|| {
                "Git source provider requires the project to be inside a Git checkout".to_owned()
            })?;
            snapshot_git_project(&repository_root, &project_root, &|| false)
        }
        SourceProviderKind::Custom(provider) => Err(format!(
            "custom source provider `{provider}` has no built-in snapshot implementation"
        )),
    }
}

pub fn detect_source_provider(project_root: &Path) -> Result<SourceProviderKind, String> {
    let project_root = resolve_project_root(project_root)?;
    Ok(if git_repository_root(&project_root)?.is_some() {
        SourceProviderKind::Git
    } else {
        SourceProviderKind::Filesystem
    })
}

fn resolve_project_root(project_root: &Path) -> Result<PathBuf, String> {
    let project_root = project_root
        .canonicalize()
        .map_err(|error| format!("resolve source checkout: {error}"))?;
    if !project_root.is_dir() {
        return Err("source checkout root is not a directory".to_owned());
    }
    Ok(project_root)
}

fn snapshot_git_project(
    repository_root: &Path,
    project_root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<SourceSnapshotInventory, String> {
    check_snapshot_cancelled(cancelled)?;
    let project_prefix = project_root
        .strip_prefix(repository_root)
        .map_err(|_| "source checkout is outside its discovered Git repository".to_owned())?;
    let project_prefix = if project_prefix.as_os_str().is_empty() {
        ".".to_owned()
    } else {
        slash_path(project_prefix)?
    };
    let index_executable = git_index_executable_modes(repository_root, &project_prefix)?;
    let mut command = git_command(repository_root);
    command
        .args([
            "ls-files",
            "-z",
            "--cached",
            "--others",
            "--exclude-standard",
            "--",
        ])
        .arg(&project_prefix);
    let output = command
        .output()
        .map_err(|error| format!("enumerate Git source snapshot: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "enumerate Git source snapshot failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut files = Vec::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        check_snapshot_cancelled(cancelled)?;
        let repository_relative =
            std::str::from_utf8(raw).map_err(|_| "Git source path is not UTF-8".to_owned())?;
        let absolute = repository_root.join(repository_relative);
        let relative = absolute
            .strip_prefix(project_root)
            .map_err(|_| "Git enumerated source outside the selected project".to_owned())?;
        files.push(snapshot_file(
            &absolute,
            &slash_path(relative)?,
            Some(
                index_executable
                    .get(repository_relative)
                    .copied()
                    .unwrap_or(false),
            ),
            cancelled,
        )?);
    }
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);
    validate_snapshot_bounds(&files)?;

    let head =
        git_text(repository_root, &["rev-parse", "HEAD"]).unwrap_or_else(|| "unborn".to_owned());
    let roots = git_text(repository_root, &["rev-list", "--max-parents=0", "HEAD"])
        .unwrap_or_else(|| "unborn".to_owned());
    let remote = git_text(repository_root, &["config", "--get", "remote.origin.url"])
        .unwrap_or_else(|| "no-origin".to_owned());
    let submodules = git_text(
        repository_root,
        &["submodule", "status", "--recursive", "--", &project_prefix],
    )
    .unwrap_or_else(|| "no-submodules".to_owned());
    finish_snapshot(
        "git",
        "working_tree",
        [
            b"node-source-snapshot:git:v1".to_vec(),
            head.into_bytes(),
            roots.into_bytes(),
            remote.into_bytes(),
            submodules.into_bytes(),
            project_prefix.into_bytes(),
        ],
        files,
    )
}

fn git_index_executable_modes(
    repository_root: &Path,
    project_prefix: &str,
) -> Result<BTreeMap<String, bool>, String> {
    let output = git_command(repository_root)
        .args(["ls-files", "-z", "--stage", "--"])
        .arg(project_prefix)
        .output()
        .map_err(|error| format!("enumerate Git index modes: {error}"))?;
    if !output.status.success() {
        return Err(format!(
            "enumerate Git index modes failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        ));
    }
    let mut modes = BTreeMap::new();
    for raw in output
        .stdout
        .split(|byte| *byte == 0)
        .filter(|raw| !raw.is_empty())
    {
        let record =
            std::str::from_utf8(raw).map_err(|_| "Git index path is not UTF-8".to_owned())?;
        let (metadata, path) = record
            .split_once('\t')
            .ok_or_else(|| "Git returned an invalid index-mode record".to_owned())?;
        let mut metadata = metadata.split_ascii_whitespace();
        let mode = metadata
            .next()
            .ok_or_else(|| "Git index-mode record omitted its mode".to_owned())?;
        let _object = metadata
            .next()
            .ok_or_else(|| "Git index-mode record omitted its object".to_owned())?;
        let stage = metadata
            .next()
            .ok_or_else(|| "Git index-mode record omitted its stage".to_owned())?;
        if stage != "0" {
            return Err(format!(
                "source snapshot cannot identify unmerged Git index path `{path}`"
            ));
        }
        modes.insert(path.to_owned(), mode == "100755");
    }
    Ok(modes)
}

fn snapshot_filesystem_project(
    project_root: &Path,
    cancelled: &dyn Fn() -> bool,
) -> Result<SourceSnapshotInventory, String> {
    let mut paths = Vec::new();
    collect_filesystem_paths(project_root, project_root, &mut paths, cancelled)?;
    paths.sort();
    if paths.len() > MAX_SNAPSHOT_FILES {
        return Err(format!(
            "source snapshot has {} files; limit is {MAX_SNAPSHOT_FILES}",
            paths.len()
        ));
    }
    let mut files = Vec::with_capacity(paths.len());
    for absolute in paths {
        check_snapshot_cancelled(cancelled)?;
        let relative = absolute
            .strip_prefix(project_root)
            .map_err(|_| "filesystem source escaped its project root".to_owned())?;
        files.push(snapshot_file(
            &absolute,
            &slash_path(relative)?,
            None,
            cancelled,
        )?);
    }
    // `PathBuf` ordering is component-based, while the materialization plan
    // is ordered by its portable slash-separated path. Those orders differ
    // for pairs such as `src/run.rs` and `src/run/local.rs`. Sort only after
    // normalization so a non-Git checkout produces the same valid inventory
    // on Linux, Windows, and macOS.
    files.sort_by(|left, right| left.path.cmp(&right.path));
    files.dedup_by(|left, right| left.path == right.path);
    validate_snapshot_bounds(&files)?;
    finish_snapshot(
        "filesystem",
        "filesystem_tree",
        [b"node-source-snapshot:filesystem:v1".to_vec()],
        files,
    )
}

fn finish_snapshot<const N: usize>(
    provider: &'static str,
    source_mode: &'static str,
    identity_parts: [Vec<u8>; N],
    files: Vec<SnapshotFile>,
) -> Result<SourceSnapshotInventory, String> {
    let mut parts = identity_parts.into_iter().collect::<Vec<_>>();
    let mut total_bytes = 0_u64;
    for file in &files {
        total_bytes = total_bytes
            .checked_add(file.size_bytes)
            .ok_or_else(|| "source snapshot byte accounting overflowed".to_owned())?;
        parts.push(file.path.as_bytes().to_vec());
        parts.push(file.kind.as_bytes().to_vec());
        parts.push(if file.executable { b"x" } else { b"-" }.to_vec());
        parts.push(file.digest.as_str().as_bytes().to_vec());
        parts.push(file.size_bytes.to_string().into_bytes());
    }
    let entries = files
        .into_iter()
        .map(|file| SourceSnapshotEntry {
            path: file.path,
            kind: match file.kind {
                "file" => SourceSnapshotEntryKind::File,
                "symlink" => SourceSnapshotEntryKind::Symlink,
                "deleted" => SourceSnapshotEntryKind::Deleted,
                _ => unreachable!("snapshot_file constructs only known entry kinds"),
            },
            executable: file.executable,
            digest: file.digest,
            size_bytes: file.size_bytes,
        })
        .collect::<Vec<_>>();
    let inventory = SourceSnapshotInventory {
        digest: Digest::from_parts(parts),
        provider: provider.to_owned(),
        file_count: entries.len(),
        total_bytes,
        source_mode: source_mode.to_owned(),
        entries,
    };
    inventory.validate_materialization_plan()?;
    Ok(inventory)
}

fn snapshot_file(
    absolute: &Path,
    relative: &str,
    executable_override: Option<bool>,
    cancelled: &dyn Fn() -> bool,
) -> Result<SnapshotFile, String> {
    check_snapshot_cancelled(cancelled)?;
    validate_relative_source_path(relative)?;
    let metadata = match fs::symlink_metadata(absolute) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(SnapshotFile {
                path: relative.to_owned(),
                kind: "deleted",
                executable: false,
                digest: Digest::sha256("deleted"),
                size_bytes: 0,
            })
        }
        Err(error) => return Err(error.to_string()),
    };
    if metadata.file_type().is_symlink() {
        let target = fs::read_link(absolute).map_err(|error| error.to_string())?;
        let target = target
            .to_str()
            .ok_or_else(|| "source symlink target is not UTF-8".to_owned())?;
        return Ok(SnapshotFile {
            path: relative.to_owned(),
            kind: "symlink",
            executable: false,
            digest: Digest::from_parts([b"source-symlink:v1".as_slice(), target.as_bytes()]),
            size_bytes: target.len() as u64,
        });
    }
    if !metadata.is_file() {
        return Err(format!("source snapshot entry `{relative}` is not a file"));
    }
    if metadata.len() > MAX_SNAPSHOT_FILE_BYTES {
        return Err(format!(
            "source file `{relative}` is {} bytes; per-file limit is {MAX_SNAPSHOT_FILE_BYTES}",
            metadata.len()
        ));
    }
    let mut file = fs::File::open(absolute).map_err(|error| error.to_string())?;
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        check_snapshot_cancelled(cancelled)?;
        let read = file.read(&mut buffer).map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| "source file size overflowed".to_owned())?;
        if size_bytes > MAX_SNAPSHOT_FILE_BYTES {
            return Err(format!(
                "source file `{relative}` grew beyond {MAX_SNAPSHOT_FILE_BYTES} bytes while hashing"
            ));
        }
        hasher.update(&buffer[..read]);
    }
    let digest = Digest::from_sha256_hex(format!("{:x}", hasher.finalize()))?;
    #[cfg(unix)]
    let executable = {
        use std::os::unix::fs::PermissionsExt;
        metadata.permissions().mode() & 0o111 != 0
    };
    #[cfg(not(unix))]
    let executable = false;
    let executable = executable_override.unwrap_or(executable);
    Ok(SnapshotFile {
        path: relative.to_owned(),
        kind: "file",
        executable,
        digest,
        size_bytes,
    })
}

fn validate_snapshot_bounds(files: &[SnapshotFile]) -> Result<(), String> {
    if files.len() > MAX_SNAPSHOT_FILES {
        return Err(format!(
            "source snapshot has {} files; limit is {MAX_SNAPSHOT_FILES}",
            files.len()
        ));
    }
    let total = files
        .iter()
        .try_fold(0_u64, |total, file| total.checked_add(file.size_bytes))
        .ok_or_else(|| "source snapshot byte accounting overflowed".to_owned())?;
    if total > MAX_SNAPSHOT_TOTAL_BYTES {
        return Err(format!(
            "source snapshot is {total} bytes; limit is {MAX_SNAPSHOT_TOTAL_BYTES}"
        ));
    }
    Ok(())
}

fn collect_filesystem_paths(
    root: &Path,
    directory: &Path,
    paths: &mut Vec<PathBuf>,
    cancelled: &dyn Fn() -> bool,
) -> Result<(), String> {
    check_snapshot_cancelled(cancelled)?;
    for entry in fs::read_dir(directory).map_err(|error| error.to_string())? {
        check_snapshot_cancelled(cancelled)?;
        let entry = entry.map_err(|error| error.to_string())?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| "source path is not UTF-8".to_owned())?;
        if directory == root && matches!(name.as_str(), ".git" | ".clusterflux-state" | "target") {
            continue;
        }
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            collect_filesystem_paths(root, &entry.path(), paths, cancelled)?;
        } else if file_type.is_file() || file_type.is_symlink() {
            paths.push(entry.path());
            if paths.len() > MAX_SNAPSHOT_FILES {
                return Err(format!(
                    "source snapshot exceeds file-count limit of {MAX_SNAPSHOT_FILES}"
                ));
            }
        }
    }
    Ok(())
}

fn check_snapshot_cancelled(cancelled: &dyn Fn() -> bool) -> Result<(), String> {
    if cancelled() {
        Err("source snapshot cancelled".to_owned())
    } else {
        Ok(())
    }
}

fn git_repository_root(project_root: &Path) -> Result<Option<PathBuf>, String> {
    let output = git_command(project_root)
        .args(["rev-parse", "--show-toplevel"])
        .output();
    let Ok(output) = output else {
        return Ok(None);
    };
    if !output.status.success() {
        return Ok(None);
    }
    let root = String::from_utf8(output.stdout)
        .map_err(|_| "Git repository root is not UTF-8".to_owned())?;
    let root = PathBuf::from(root.trim())
        .canonicalize()
        .map_err(|error| error.to_string())?;
    Ok(Some(root))
}

fn git_text(repository_root: &Path, args: &[&str]) -> Option<String> {
    let output = git_command(repository_root).args(args).output().ok()?;
    if !output.status.success() {
        return None;
    }
    String::from_utf8(output.stdout)
        .ok()
        .map(|value| value.trim().to_owned())
}

fn git_command(repository_root: &Path) -> Command {
    let mut command = Command::new("git");
    command
        .arg("-C")
        .arg(repository_root)
        .env("GIT_OPTIONAL_LOCKS", "0")
        .env("GIT_TERMINAL_PROMPT", "0");
    command
}

fn slash_path(path: &Path) -> Result<String, String> {
    let mut result = String::new();
    for component in path.components() {
        let component = component
            .as_os_str()
            .to_str()
            .ok_or_else(|| "source path is not UTF-8".to_owned())?;
        if !result.is_empty() {
            result.push('/');
        }
        result.push_str(component);
    }
    Ok(result)
}

fn validate_relative_source_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.starts_with('/')
        || path.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || component.contains('\0')
        })
    {
        return Err("source snapshot path must be a safe relative path".to_owned());
    }
    if path.len() > MAX_ENVIRONMENT_CONTEXT_PATH_BYTES {
        return Err(format!(
            "source snapshot path exceeds {MAX_ENVIRONMENT_CONTEXT_PATH_BYTES} bytes"
        ));
    }
    if path.split('/').count() > MAX_ENVIRONMENT_CONTEXT_DEPTH {
        return Err(format!(
            "source snapshot path exceeds depth limit of {MAX_ENVIRONMENT_CONTEXT_DEPTH}"
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn git(root: &Path, args: &[&str]) {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .env("GIT_AUTHOR_NAME", "Clusterflux Test")
            .env("GIT_AUTHOR_EMAIL", "test@clusterflux.invalid")
            .env("GIT_COMMITTER_NAME", "Clusterflux Test")
            .env("GIT_COMMITTER_EMAIL", "test@clusterflux.invalid")
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn initialize_repository(root: &Path, message: &str) {
        git(root, &["init", "--quiet"]);
        git(root, &["add", "."]);
        git(root, &["commit", "--quiet", "-m", message]);
    }

    fn git_text_output(root: &Path, args: &[&str]) -> String {
        let output = Command::new("git")
            .arg("-C")
            .arg(root)
            .args(args)
            .output()
            .unwrap();
        assert!(output.status.success());
        String::from_utf8(output.stdout).unwrap().trim().to_owned()
    }

    fn exact_trigger(repository_url: String, sha: String) -> CommitTrigger {
        CommitTrigger {
            trigger_id: clusterflux_core::TriggerId::from("trigger-source-test"),
            forge: clusterflux_core::ForgeKind::GitHub,
            repository_id: clusterflux_core::RepositoryId::from("github:example/source"),
            repository_url,
            commit_sha: sha,
            git_ref: "refs/heads/main".to_owned(),
            delivery_id: "delivery-source-test".to_owned(),
            event_kind: clusterflux_core::TriggerEventKind::Push,
            actor: Some("developer".to_owned()),
            trusted: true,
            received_at: 1,
        }
    }

    fn local_repository_url(path: &Path) -> String {
        format!("{}{}", concat!("file:", "//"), path.display())
    }

    #[test]
    fn workspace_disk_scan_ignores_entries_removed_by_git() {
        let temp = tempfile::tempdir().unwrap();
        let vanished = temp.path().join("vanished.lock");
        fs::write(&vanished, "temporary Git state").unwrap();
        fs::remove_file(&vanished).unwrap();

        assert!(workspace_entry_metadata(&vanished).unwrap().is_none());
        assert_eq!(workspace_size(temp.path(), 1024).unwrap(), 0);
    }

    #[test]
    fn dirty_and_untracked_content_changes_snapshot_identity() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn value() -> u8 { 1 }").unwrap();
        initialize_repository(temp.path(), "initial source");
        let first = snapshot_project(temp.path()).unwrap();

        fs::write(temp.path().join("src/lib.rs"), "pub fn value() -> u8 { 2 }").unwrap();
        let dirty = snapshot_project(temp.path()).unwrap();
        fs::write(
            temp.path().join("fixture.c"),
            "int main(void) { return 0; }",
        )
        .unwrap();
        let untracked = snapshot_project(temp.path()).unwrap();

        assert_ne!(first.digest, dirty.digest);
        assert_ne!(dirty.digest, untracked.digest);
        assert_eq!(untracked.provider, "git");
        assert_eq!(untracked.file_count, 2);
    }

    #[cfg(unix)]
    #[test]
    fn git_snapshot_executable_identity_comes_from_the_portable_index_mode() {
        use std::os::unix::fs::PermissionsExt;

        let temp = tempfile::tempdir().unwrap();
        let script = temp.path().join("script.sh");
        fs::write(&script, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&script, fs::Permissions::from_mode(0o755)).unwrap();
        initialize_repository(temp.path(), "executable source");
        let executable = snapshot_project(temp.path()).unwrap();

        fs::set_permissions(&script, fs::Permissions::from_mode(0o644)).unwrap();
        let windows_like_worktree = snapshot_project(temp.path()).unwrap();
        assert_eq!(executable.digest, windows_like_worktree.digest);

        git(temp.path(), &["update-index", "--chmod=-x", "script.sh"]);
        let non_executable_index = snapshot_project(temp.path()).unwrap();
        assert_ne!(windows_like_worktree.digest, non_executable_index.digest);

        let untracked = temp.path().join("untracked.sh");
        fs::write(&untracked, "#!/bin/sh\nexit 0\n").unwrap();
        fs::set_permissions(&untracked, fs::Permissions::from_mode(0o755)).unwrap();
        let untracked_executable = snapshot_project(temp.path()).unwrap();
        fs::set_permissions(&untracked, fs::Permissions::from_mode(0o644)).unwrap();
        let untracked_non_executable = snapshot_project(temp.path()).unwrap();
        assert_eq!(untracked_executable.digest, untracked_non_executable.digest);
    }

    #[test]
    fn deployment_checkout_uses_canonical_git_bytes_and_rejects_dirty_environments() {
        let repository = tempfile::tempdir().unwrap();
        let environment = repository.path().join("envs/windows");
        fs::create_dir_all(&environment).unwrap();
        fs::write(
            environment.join("Containerfile"),
            "FROM mcr.microsoft.com/windows/nanoserver:ltsc2025\nRUN echo ready\n",
        )
        .unwrap();
        fs::write(
            environment.join("environment.toml"),
            "version = 1\nname = \"windows\"\nos = \"windows\"\n",
        )
        .unwrap();
        initialize_repository(repository.path(), "canonical environment");
        let canonical = discover_environments(repository.path()).unwrap()[0]
            .digest
            .clone();

        git(repository.path(), &["config", "core.autocrlf", "true"]);
        fs::remove_file(environment.join("Containerfile")).unwrap();
        fs::remove_file(environment.join("environment.toml")).unwrap();
        git(repository.path(), &["checkout", "--", "envs/windows"]);
        assert!(fs::read(environment.join("Containerfile"))
            .unwrap()
            .windows(2)
            .any(|bytes| bytes == b"\r\n"));

        let materialized = materialize_clean_local_git_revision(repository.path())
            .unwrap()
            .unwrap();
        assert_eq!(
            discover_environments(materialized.root()).unwrap()[0].digest,
            canonical
        );
        assert!(
            !fs::read(materialized.root().join("envs/windows/Containerfile"))
                .unwrap()
                .windows(2)
                .any(|bytes| bytes == b"\r\n")
        );

        fs::write(environment.join("Containerfile"), "FROM scratch\n").unwrap();
        assert!(materialize_clean_local_git_revision(repository.path())
            .unwrap_err()
            .contains("must be committed"));
    }

    #[test]
    fn different_repositories_at_the_same_path_are_not_identified_by_path() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("source.txt"), "identical source content").unwrap();
        initialize_repository(temp.path(), "first repository identity");
        let first = snapshot_project(temp.path()).unwrap();

        fs::remove_dir_all(temp.path().join(".git")).unwrap();
        initialize_repository(temp.path(), "second repository identity");
        let second = snapshot_project(temp.path()).unwrap();

        assert_ne!(first.digest, second.digest);
        assert_eq!(first.provider, "git");
        assert_eq!(second.provider, "git");
    }

    #[test]
    fn nested_projects_detect_and_use_the_repository_source_provider() {
        let temp = tempfile::tempdir().unwrap();
        let project = temp.path().join("workspace/member");
        fs::create_dir_all(&project).unwrap();
        fs::write(project.join("source.txt"), "member source").unwrap();
        initialize_repository(temp.path(), "workspace source");

        assert_eq!(
            detect_source_provider(&project).unwrap(),
            SourceProviderKind::Git
        );
        let snapshot = snapshot_project_with_provider(&project, &SourceProviderKind::Git).unwrap();
        assert_eq!(snapshot.provider, "git");
        assert_eq!(snapshot.source_mode, "working_tree");
        assert_eq!(snapshot.file_count, 1);
    }

    #[test]
    fn explicit_filesystem_mode_is_stable_even_inside_a_git_checkout() {
        let temp = tempfile::tempdir().unwrap();
        fs::write(temp.path().join("source.txt"), "source").unwrap();
        initialize_repository(temp.path(), "source");

        let git_snapshot = snapshot_project(temp.path()).unwrap();
        let filesystem_snapshot =
            snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem).unwrap();

        assert_eq!(filesystem_snapshot.provider, "filesystem");
        assert_eq!(filesystem_snapshot.source_mode, "filesystem_tree");
        assert_ne!(git_snapshot.digest, filesystem_snapshot.digest);
        let encoded = serde_json::to_value(&filesystem_snapshot).unwrap();
        assert_eq!(encoded["digest"], filesystem_snapshot.digest.as_str());
    }

    #[test]
    fn filesystem_snapshot_includes_workflow_source_but_excludes_generated_state() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join(".clusterflux")).unwrap();
        fs::create_dir_all(temp.path().join(".clusterflux-state")).unwrap();
        fs::write(temp.path().join(".clusterflux/main.rs"), "fn main() {}\n").unwrap();
        fs::write(temp.path().join(".clusterflux-state/views.json"), "first\n").unwrap();
        let first =
            snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem).unwrap();

        fs::write(
            temp.path().join(".clusterflux-state/views.json"),
            "second\n",
        )
        .unwrap();
        let state_changed =
            snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem).unwrap();
        fs::write(temp.path().join(".clusterflux/main.rs"), "fn main() { }\n").unwrap();
        let source_changed =
            snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem).unwrap();

        assert_eq!(first.digest, state_changed.digest);
        assert_ne!(state_changed.digest, source_changed.digest);
        assert_eq!(first.file_count, 1);
    }

    #[test]
    fn hostile_relative_paths_and_oversized_files_are_rejected() {
        for path in ["", "/absolute", "../escape", "a/../escape", "a//b"] {
            assert!(
                validate_relative_source_path(path).is_err(),
                "accepted {path}"
            );
        }

        let temp = tempfile::tempdir().unwrap();
        let oversized = fs::File::create(temp.path().join("oversized.bin")).unwrap();
        oversized.set_len(MAX_SNAPSHOT_FILE_BYTES + 1).unwrap();
        let error = snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem)
            .unwrap_err();
        assert!(error.contains("per-file limit"));
    }

    #[test]
    fn materialization_plan_revalidates_shape_order_paths_and_bytes() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src")).unwrap();
        fs::write(temp.path().join("Cargo.toml"), "[workspace]\n").unwrap();
        fs::write(temp.path().join("src/lib.rs"), "pub fn ready() {}\n").unwrap();
        let inventory =
            snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem).unwrap();
        inventory.validate_materialization_plan().unwrap();

        let mut wrong_count = inventory.clone();
        wrong_count.file_count += 1;
        assert!(wrong_count
            .validate_materialization_plan()
            .unwrap_err()
            .contains("file count"));

        let mut unsorted = inventory.clone();
        unsorted.entries.reverse();
        assert!(unsorted
            .validate_materialization_plan()
            .unwrap_err()
            .contains("sorted and unique"));

        let mut escaping = inventory.clone();
        escaping.entries[0].path = "../escape".to_owned();
        assert!(escaping.validate_materialization_plan().is_err());

        let mut wrong_bytes = inventory;
        wrong_bytes.total_bytes += 1;
        assert!(wrong_bytes
            .validate_materialization_plan()
            .unwrap_err()
            .contains("total bytes"));
    }

    #[test]
    fn filesystem_snapshot_sorts_portable_paths_after_normalization() {
        let temp = tempfile::tempdir().unwrap();
        fs::create_dir_all(temp.path().join("src/run")).unwrap();
        fs::write(temp.path().join("src/run.rs"), "pub mod local_services;\n").unwrap();
        fs::write(
            temp.path().join("src/run/local_services.rs"),
            "pub fn ready() {}\n",
        )
        .unwrap();

        let inventory =
            snapshot_project_with_provider(temp.path(), &SourceProviderKind::Filesystem).unwrap();
        let paths = inventory
            .entries
            .iter()
            .map(|entry| entry.path.as_str())
            .collect::<Vec<_>>();
        assert_eq!(paths, ["src/run.rs", "src/run/local_services.rs"]);
        inventory.validate_materialization_plan().unwrap();
    }

    fn write_workflow_manifest(root: &Path) -> usize {
        let manifest = b"[package]\nname='source-test'\nversion='0.0.0'\nedition='2024'\npublish=false\n[lib]\npath='main.rs'\ncrate-type=['cdylib']\n[dependencies]\nclusterflux={package='clusterflux-sdk',version='=0.2.0'}\n[workspace]\nresolver='3'\n";
        fs::write(root.join(".clusterflux/Cargo.toml"), manifest).unwrap();
        manifest.len()
    }

    #[test]
    fn exact_workflow_loader_keeps_the_triggered_old_commit_after_branch_advances() {
        let repository = tempfile::tempdir().unwrap();
        fs::create_dir_all(repository.path().join(".clusterflux/nested")).unwrap();
        write_workflow_manifest(repository.path());
        fs::write(
            repository.path().join(".clusterflux/main.rs"),
            "mod nested; const REVISION: &str = \"old\";",
        )
        .unwrap();
        fs::write(
            repository.path().join(".clusterflux/nested.rs"),
            "pub fn workflow() {}",
        )
        .unwrap();
        fs::write(repository.path().join("outside.txt"), "not compiler input").unwrap();
        fs::create_dir_all(repository.path().join("envs/linux")).unwrap();
        fs::write(
            repository.path().join("envs/linux/Containerfile"),
            "FROM alpine:3.21\n",
        )
        .unwrap();
        fs::write(
            repository.path().join("envs/linux/environment.toml"),
            "version = 1\nname = 'linux'\n",
        )
        .unwrap();
        fs::write(
            repository.path().join("envs/linux/install-tool.sh"),
            "echo old tool\n",
        )
        .unwrap();
        initialize_repository(repository.path(), "old workflow");
        let old_sha = git_text_output(repository.path(), &["rev-parse", "HEAD"]);
        let old_environment_digest = discover_environments(repository.path()).unwrap()[0]
            .digest
            .clone();

        fs::write(
            repository.path().join(".clusterflux/main.rs"),
            "mod nested; const REVISION: &str = \"new\";",
        )
        .unwrap();
        fs::write(
            repository.path().join("envs/linux/Containerfile"),
            "FROM alpine:3.22\n",
        )
        .unwrap();
        fs::write(
            repository.path().join("envs/linux/install-tool.sh"),
            "echo new tool\n",
        )
        .unwrap();
        git(repository.path(), &["add", "."]);
        git(
            repository.path(),
            &["commit", "--quiet", "-m", "new workflow"],
        );

        let url = local_repository_url(repository.path());
        let trigger = exact_trigger(url.clone(), old_sha.clone());
        let (source, revision) = load_exact_workflow_source_from_validated_binding(
            &trigger,
            &url,
            &ExactRevisionSourceLimits::default(),
        )
        .unwrap();

        assert_eq!(source.commit_sha, old_sha);
        assert_eq!(source.files.len(), 3);
        assert_eq!(source.environments.len(), 1);
        assert_eq!(source.environments[0].name, "linux");
        assert_eq!(source.environments[0].digest, old_environment_digest);
        assert!(source.environments[0]
            .context_manifest
            .iter()
            .any(|file| file.path == "install-tool.sh"));
        assert_ne!(
            source.environments[0].digest,
            discover_environments(repository.path()).unwrap()[0].digest
        );
        assert!(String::from_utf8(
            source
                .files
                .iter()
                .find(|file| file.path == ".clusterflux/main.rs")
                .unwrap()
                .bytes
                .clone()
        )
        .unwrap()
        .contains("old"));
        assert_eq!(revision.commit_sha, source.commit_sha);
        assert_eq!(
            revision.source_snapshot,
            Digest::from_parts([
                b"clusterflux-git-revision:v1".as_slice(),
                trigger.repository_id.as_str().as_bytes(),
                url.as_bytes(),
                old_sha.as_bytes(),
            ])
        );
    }

    #[test]
    fn exact_workflow_loader_rejects_missing_main_non_rust_and_oversized_source() {
        for (name, path, contents, expected) in [
            (
                "missing-main",
                ".clusterflux/tasks.rs",
                "pub fn task() {}",
                "main.rs",
            ),
            (
                "non-rust",
                ".clusterflux/config.toml",
                "forbidden = true",
                "non-Rust",
            ),
        ] {
            let repository = tempfile::tempdir().unwrap();
            fs::create_dir_all(repository.path().join(".clusterflux")).unwrap();
            write_workflow_manifest(repository.path());
            if name == "non-rust" {
                fs::write(
                    repository.path().join(".clusterflux/main.rs"),
                    "fn main() {}",
                )
                .unwrap();
            }
            fs::write(repository.path().join(path), contents).unwrap();
            initialize_repository(repository.path(), name);
            let sha = git_text_output(repository.path(), &["rev-parse", "HEAD"]);
            let url = local_repository_url(repository.path());
            let trigger = exact_trigger(url.clone(), sha);
            let error = load_exact_workflow_source_from_validated_binding(
                &trigger,
                &url,
                &ExactRevisionSourceLimits::default(),
            )
            .unwrap_err();
            assert!(error.contains(expected), "{error}");
        }

        let repository = tempfile::tempdir().unwrap();
        fs::create_dir_all(repository.path().join(".clusterflux")).unwrap();
        let manifest_bytes = write_workflow_manifest(repository.path());
        fs::write(repository.path().join(".clusterflux/main.rs"), "12345").unwrap();
        initialize_repository(repository.path(), "oversized");
        let sha = git_text_output(repository.path(), &["rev-parse", "HEAD"]);
        let url = local_repository_url(repository.path());
        let trigger = exact_trigger(url.clone(), sha);
        let error = load_exact_workflow_source_from_validated_binding(
            &trigger,
            &url,
            &ExactRevisionSourceLimits {
                max_file_bytes: 4,
                max_total_bytes: manifest_bytes + 4,
                ..ExactRevisionSourceLimits::default()
            },
        )
        .unwrap_err();
        assert!(error.contains("limit"), "{error}");
    }

    #[cfg(unix)]
    #[test]
    fn exact_workflow_tree_rejects_symlinks_and_path_traversal() {
        use std::os::unix::fs::symlink;

        let repository = tempfile::tempdir().unwrap();
        fs::create_dir_all(repository.path().join(".clusterflux")).unwrap();
        write_workflow_manifest(repository.path());
        fs::write(repository.path().join("real.rs"), "pub fn real() {}").unwrap();
        fs::write(
            repository.path().join(".clusterflux/main.rs"),
            "fn main() {}",
        )
        .unwrap();
        symlink("../real.rs", repository.path().join(".clusterflux/link.rs")).unwrap();
        initialize_repository(repository.path(), "symlink");
        let sha = git_text_output(repository.path(), &["rev-parse", "HEAD"]);
        let url = local_repository_url(repository.path());
        let trigger = exact_trigger(url.clone(), sha);
        assert!(load_exact_workflow_source_from_validated_binding(
            &trigger,
            &url,
            &ExactRevisionSourceLimits::default(),
        )
        .unwrap_err()
        .contains("regular non-symlink"));

        let limits = ExactRevisionSourceLimits::default();
        assert!(parse_revision_tree(
            b"100644 blob 0123456789abcdef 12\t.clusterflux/../escape.rs\0",
            &limits,
        )
        .is_err());
        assert!(parse_revision_tree(
            b"100644 blob 0123456789abcdef 12\t.clusterflux/main.rs\0\
              100644 blob 1123456789abcdef 12\t.clusterflux/tasks.rs\0",
            &ExactRevisionSourceLimits {
                max_files: 1,
                ..limits
            },
        )
        .unwrap_err()
        .contains("file limit"));
    }

    #[test]
    fn ref_resolution_prefers_peeled_tag_and_requires_an_exact_ref() {
        let tag_object = "1111111111111111111111111111111111111111";
        let commit = "2222222222222222222222222222222222222222";
        let output = format!("{tag_object}\trefs/tags/v1.0.0\n{commit}\trefs/tags/v1.0.0^{{}}\n");
        assert_eq!(
            parse_resolved_git_ref(output.as_bytes(), "refs/tags/v1.0.0").unwrap(),
            commit
        );
        assert!(parse_resolved_git_ref(
            format!("{commit}\trefs/heads/other\n").as_bytes(),
            "refs/heads/main"
        )
        .is_err());
        assert!(parse_resolved_git_ref(b"", "refs/heads/main")
            .unwrap_err()
            .contains("not found"));
    }

    #[test]
    fn public_ref_resolution_uses_an_empty_isolated_workspace() {
        let workspace = isolated_git_metadata_workspace().unwrap();
        assert_ne!(
            workspace.path().canonicalize().unwrap(),
            Path::new(".").canonicalize().unwrap()
        );
        assert_eq!(workspace_size(workspace.path(), 1).unwrap(), 0);
    }
}
