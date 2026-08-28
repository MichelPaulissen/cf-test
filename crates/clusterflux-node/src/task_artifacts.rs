use std::collections::BTreeSet;
use std::fs::{self, OpenOptions};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

use clusterflux_core::{ArtifactId, Digest, NodeId, TaskInstanceId, VfsManifest, VfsOverlay};
use sha2::{Digest as _, Sha256};

const MAX_NODE_ARTIFACT_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_NODE_ARTIFACT_STORE_BYTES: u64 = 64 * 1024 * 1024 * 1024;
const DEFAULT_MAX_NODE_ARTIFACT_COUNT: usize = 1_024;
const DEFAULT_MAX_NODE_ARTIFACT_AGE_SECONDS: u64 = 7 * 24 * 60 * 60;
const DEFAULT_NODE_ARTIFACT_RESTART_PIN_SECONDS: u64 = 60 * 60;
const MAX_NODE_ARTIFACT_STORE_BYTES: u64 = 64 * 1024 * 1024 * 1024 * 1024;
const MAX_NODE_ARTIFACT_COUNT: usize = 1_000_000;
const MAX_NODE_ARTIFACT_AGE_SECONDS: u64 = 365 * 24 * 60 * 60;
const MAX_NODE_ARTIFACT_RESTART_PIN_SECONDS: u64 = 30 * 24 * 60 * 60;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NodeArtifactRetentionLimits {
    pub(crate) max_bytes: u64,
    pub(crate) max_count: usize,
    pub(crate) max_age_seconds: u64,
    pub(crate) restart_pin_seconds: u64,
}

impl Default for NodeArtifactRetentionLimits {
    fn default() -> Self {
        Self {
            max_bytes: DEFAULT_MAX_NODE_ARTIFACT_STORE_BYTES,
            max_count: DEFAULT_MAX_NODE_ARTIFACT_COUNT,
            max_age_seconds: DEFAULT_MAX_NODE_ARTIFACT_AGE_SECONDS,
            restart_pin_seconds: DEFAULT_NODE_ARTIFACT_RESTART_PIN_SECONDS,
        }
    }
}

impl NodeArtifactRetentionLimits {
    pub(crate) fn from_environment() -> Result<Self, String> {
        Self {
            max_bytes: environment_u64(
                "CLUSTERFLUX_NODE_ARTIFACT_MAX_BYTES",
                DEFAULT_MAX_NODE_ARTIFACT_STORE_BYTES,
            )?,
            max_count: usize::try_from(environment_u64(
                "CLUSTERFLUX_NODE_ARTIFACT_MAX_COUNT",
                DEFAULT_MAX_NODE_ARTIFACT_COUNT as u64,
            )?)
            .map_err(|_| "CLUSTERFLUX_NODE_ARTIFACT_MAX_COUNT does not fit usize".to_owned())?,
            max_age_seconds: environment_u64(
                "CLUSTERFLUX_NODE_ARTIFACT_MAX_AGE_SECONDS",
                DEFAULT_MAX_NODE_ARTIFACT_AGE_SECONDS,
            )?,
            restart_pin_seconds: environment_u64(
                "CLUSTERFLUX_NODE_ARTIFACT_RESTART_PIN_SECONDS",
                DEFAULT_NODE_ARTIFACT_RESTART_PIN_SECONDS,
            )?,
        }
        .validate()
    }

    pub(crate) fn validate(self) -> Result<Self, String> {
        if !(1..=MAX_NODE_ARTIFACT_STORE_BYTES).contains(&self.max_bytes)
            || !(1..=MAX_NODE_ARTIFACT_COUNT).contains(&self.max_count)
            || !(1..=MAX_NODE_ARTIFACT_AGE_SECONDS).contains(&self.max_age_seconds)
            || !(1..=MAX_NODE_ARTIFACT_RESTART_PIN_SECONDS).contains(&self.restart_pin_seconds)
            || self.restart_pin_seconds > self.max_age_seconds
        {
            return Err(
                "node artifact retention limits are zero or exceed their safety ceilings"
                    .to_owned(),
            );
        }
        Ok(self)
    }
}

#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub(crate) struct NodeArtifactGcReport {
    pub(crate) retained_count: usize,
    pub(crate) retained_bytes: u64,
    pub(crate) evicted: Vec<ArtifactId>,
    pub(crate) limits_satisfied: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct RetainedArtifact {
    pub(crate) id: ArtifactId,
    pub(crate) digest: Digest,
    pub(crate) size_bytes: u64,
    pub(crate) path: PathBuf,
}

#[derive(Clone, Debug)]
pub(crate) struct NodeArtifactStore {
    root: PathBuf,
}

impl NodeArtifactStore {
    pub(crate) fn for_runtime(project_root: Option<&Path>, node: &str) -> Result<Self, String> {
        let base = project_root
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."));
        let node = node
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || "._-".contains(character) {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>();
        let root = base
            .join("target/clusterflux")
            .join("node-artifacts")
            .join(node);
        if fs::symlink_metadata(&root)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err("node artifact store root must not be a symbolic link".to_owned());
        }
        fs::create_dir_all(&root).map_err(|error| error.to_string())?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&root, fs::Permissions::from_mode(0o700))
                .map_err(|error| error.to_string())?;
        }
        let root = root.canonicalize().map_err(|error| error.to_string())?;
        Ok(Self { root })
    }

    pub(crate) fn retain_output_file(
        &self,
        output_root: &Path,
        relative_path: &str,
    ) -> Result<RetainedArtifact, String> {
        let source = confined_output_file(output_root, relative_path)?;
        let name = relative_path.replace('/', "_");
        validate_artifact_component(&name, "artifact name", 240)?;
        let temporary = self.root.join(format!(
            ".flush.{}.{}.tmp",
            std::process::id(),
            NEXT_FILE_ID.fetch_add(1, Ordering::Relaxed)
        ));
        let retained = (|| {
            let mut input = open_regular_readonly(&source, "task output")?;
            let metadata = input.metadata().map_err(|error| error.to_string())?;
            if metadata.len() > MAX_NODE_ARTIFACT_BYTES {
                return Err(format!(
                    "task output is {} bytes; node artifact limit is {MAX_NODE_ARTIFACT_BYTES} bytes",
                    metadata.len()
                ));
            }
            let mut output = create_new_private_file(&temporary)?;
            let (digest, size) = copy_and_hash(&mut input, &mut output, MAX_NODE_ARTIFACT_BYTES)?;
            output.sync_all().map_err(|error| error.to_string())?;
            let digest_hex = digest
                .as_str()
                .strip_prefix("sha256:")
                .ok_or_else(|| "task output digest is not SHA-256".to_owned())?;
            let id = ArtifactId::new(format!("{name}-{digest_hex}"));
            let path = self.root.join(id.as_str());
            match fs::hard_link(&temporary, &path) {
                Ok(()) => {
                    fs::remove_file(&temporary).map_err(|error| error.to_string())?;
                    Ok(RetainedArtifact {
                        id,
                        digest,
                        size_bytes: size,
                        path,
                    })
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                    let existing = self
                        .metadata(&id)?
                        .ok_or_else(|| "retained artifact disappeared during flush".to_owned())?;
                    if existing.digest != digest || existing.size_bytes != size {
                        return Err("retained artifact path has conflicting bytes".to_owned());
                    }
                    Ok(existing)
                }
                Err(error) => Err(error.to_string()),
            }
        })();
        let _ = fs::remove_file(&temporary);
        retained
    }

    pub(crate) fn materialize_into_output(
        &self,
        artifact: &clusterflux_core::ArtifactHandle,
        output_root: &Path,
        relative_path: &str,
    ) -> Result<PathBuf, String> {
        let retained = self
            .metadata(&artifact.id)?
            .ok_or_else(|| format!("retained artifact `{}` is unavailable", artifact.id))?;
        if retained.digest != artifact.digest || retained.size_bytes != artifact.size_bytes {
            return Err(
                "artifact handle digest/size does not match retained node metadata".to_owned(),
            );
        }
        let target = confined_output_target(output_root, relative_path)?;
        let copied = (|| {
            let mut output = create_new_private_file(&target)?;
            let mut input = open_regular_readonly(&retained.path, "retained artifact")?;
            let (digest, size_bytes) =
                copy_and_hash(&mut input, &mut output, MAX_NODE_ARTIFACT_BYTES)?;
            output.sync_all().map_err(|error| error.to_string())?;
            Ok::<_, String>((digest, size_bytes))
        })();
        let (digest, size_bytes) = match copied {
            Ok(copied) => copied,
            Err(error) => {
                let _ = fs::remove_file(&target);
                return Err(error);
            }
        };
        if size_bytes != artifact.size_bytes || digest != artifact.digest {
            let _ = fs::remove_file(&target);
            return Err("materialized artifact digest/size changed during local copy".to_owned());
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&target, fs::Permissions::from_mode(0o444))
                .map_err(|error| error.to_string())?;
        }
        Ok(target)
    }

    pub(crate) fn interchange_destination(&self, id: &ArtifactId) -> Result<PathBuf, String> {
        validate_artifact_component(id.as_str(), "artifact id", 256)?;
        Ok(self.root.join(id.as_str()))
    }

    pub(crate) fn interchange_source(&self, id: &ArtifactId) -> Result<Option<PathBuf>, String> {
        let path = self.interchange_destination(id)?;
        match fs::symlink_metadata(&path) {
            Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
                Err("retained artifact path is not a regular non-symlink file".to_owned())
            }
            Ok(_) => Ok(Some(path)),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error.to_string()),
        }
    }

    pub(crate) fn interchange_partial_root(&self) -> PathBuf {
        self.root.join(".interchange-partials")
    }

    pub(crate) fn metadata(&self, id: &ArtifactId) -> Result<Option<RetainedArtifact>, String> {
        validate_artifact_component(id.as_str(), "artifact id", 256)?;
        let path = self.root.join(id.as_str());
        let metadata = match fs::symlink_metadata(&path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error.to_string()),
        };
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err("retained artifact path is not a regular non-symlink file".to_owned());
        }
        if metadata.len() > MAX_NODE_ARTIFACT_BYTES {
            return Err(format!(
                "retained artifact exceeds node artifact limit of {MAX_NODE_ARTIFACT_BYTES} bytes"
            ));
        }
        let mut file = open_regular_readonly(&path, "retained artifact")?;
        let (digest, size_bytes) = hash_reader(&mut file, MAX_NODE_ARTIFACT_BYTES)?;
        Ok(Some(RetainedArtifact {
            id: id.clone(),
            digest,
            size_bytes,
            path,
        }))
    }

    #[cfg(test)]
    pub(crate) fn read_verified(
        &self,
        id: &ArtifactId,
        expected_digest: &Digest,
        expected_size_bytes: u64,
    ) -> Result<Vec<u8>, String> {
        let retained = self
            .metadata(id)?
            .ok_or_else(|| format!("retained artifact `{id}` no longer exists on this node"))?;
        if &retained.digest != expected_digest || retained.size_bytes != expected_size_bytes {
            return Err(format!(
                "retained artifact `{id}` does not match coordinator digest/size metadata"
            ));
        }
        fs::read(retained.path).map_err(|error| error.to_string())
    }

    pub(crate) fn garbage_collect(
        &self,
        limits: NodeArtifactRetentionLimits,
        pinned: &BTreeSet<ArtifactId>,
        now_epoch_seconds: u64,
    ) -> Result<NodeArtifactGcReport, String> {
        let mut entries = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "retained artifact filename is not UTF-8".to_owned())?;
            if name.starts_with('.') {
                continue;
            }
            validate_artifact_component(&name, "artifact id", 256)?;
            let metadata = entry.metadata().map_err(|error| error.to_string())?;
            if !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_file()
                || !metadata.is_file()
            {
                continue;
            }
            entries.push(StoredArtifactEntry {
                id: ArtifactId::new(name),
                path: entry.path(),
                size_bytes: metadata.len(),
                modified_epoch_seconds: metadata
                    .modified()
                    .ok()
                    .and_then(system_time_epoch_seconds)
                    .unwrap_or_default(),
            });
        }
        entries.sort_by(|left, right| {
            left.modified_epoch_seconds
                .cmp(&right.modified_epoch_seconds)
                .then_with(|| left.id.cmp(&right.id))
        });

        let age_cutoff = now_epoch_seconds.saturating_sub(limits.max_age_seconds);
        let mut retained_count = entries.len();
        let mut retained_bytes = entries
            .iter()
            .try_fold(0_u64, |total, entry| total.checked_add(entry.size_bytes))
            .ok_or_else(|| "node artifact byte accounting overflowed".to_owned())?;
        let mut evicted = Vec::new();
        for entry in &entries {
            let expired = entry.modified_epoch_seconds <= age_cutoff;
            let over_count = retained_count > limits.max_count;
            let over_bytes = retained_bytes > limits.max_bytes;
            if !(expired || over_count || over_bytes) || pinned.contains(&entry.id) {
                continue;
            }
            match fs::remove_file(&entry.path) {
                Ok(()) => {
                    retained_count = retained_count.saturating_sub(1);
                    retained_bytes = retained_bytes.saturating_sub(entry.size_bytes);
                    evicted.push(entry.id.clone());
                }
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                    retained_count = retained_count.saturating_sub(1);
                    retained_bytes = retained_bytes.saturating_sub(entry.size_bytes);
                    evicted.push(entry.id.clone());
                }
                Err(error) => return Err(error.to_string()),
            }
        }
        let retained_ids = self.artifact_ids()?.into_iter().collect::<BTreeSet<_>>();
        let retained_has_expired = entries.iter().any(|entry| {
            retained_ids.contains(&entry.id) && entry.modified_epoch_seconds <= age_cutoff
        });
        Ok(NodeArtifactGcReport {
            retained_count,
            retained_bytes,
            evicted,
            limits_satisfied: retained_count <= limits.max_count
                && retained_bytes <= limits.max_bytes
                && !retained_has_expired,
        })
    }

    pub(crate) fn artifact_ids(&self) -> Result<Vec<ArtifactId>, String> {
        let mut ids = Vec::new();
        for entry in fs::read_dir(&self.root).map_err(|error| error.to_string())? {
            let entry = entry.map_err(|error| error.to_string())?;
            if !entry
                .file_type()
                .map_err(|error| error.to_string())?
                .is_file()
            {
                continue;
            }
            let name = entry
                .file_name()
                .into_string()
                .map_err(|_| "retained artifact filename is not UTF-8".to_owned())?;
            if name.starts_with('.') {
                continue;
            }
            validate_artifact_component(&name, "artifact id", 256)?;
            ids.push(ArtifactId::new(name));
        }
        ids.sort();
        Ok(ids)
    }
}

#[derive(Clone, Debug)]
struct StoredArtifactEntry {
    id: ArtifactId,
    path: PathBuf,
    size_bytes: u64,
    modified_epoch_seconds: u64,
}

pub(crate) fn retained_result_artifacts(
    project_root: Option<&Path>,
    node: &str,
    result: Option<&clusterflux_core::TaskBoundaryValue>,
) -> Result<Vec<RetainedArtifact>, String> {
    let handles = result
        .into_iter()
        .flat_map(clusterflux_core::TaskBoundaryValue::artifact_handles)
        .collect::<BTreeSet<_>>();
    if handles.is_empty() {
        return Ok(Vec::new());
    }
    let store = NodeArtifactStore::for_runtime(project_root, node)?;
    handles
        .into_iter()
        .map(|handle| {
            let retained = store.metadata(&handle.id)?.ok_or_else(|| {
                format!(
                    "task returned artifact `{}` without flushing a file on this node",
                    handle.id
                )
            })?;
            if retained.digest != handle.digest || retained.size_bytes != handle.size_bytes {
                return Err("task artifact handle does not match retained file metadata".to_owned());
            }
            Ok(retained)
        })
        .collect()
}

static NEXT_FILE_ID: AtomicU64 = AtomicU64::new(1);
static NEXT_OUTPUT_ROOT_ID: AtomicU64 = AtomicU64::new(1);

pub(crate) fn task_output_root(
    project_root: Option<&Path>,
    node: &str,
    task: &TaskInstanceId,
) -> Result<PathBuf, String> {
    let safe = |value: &str| {
        value
            .chars()
            .map(|character| {
                if character.is_ascii_alphanumeric() || "._-".contains(character) {
                    character
                } else {
                    '_'
                }
            })
            .collect::<String>()
    };
    let parent = task_output_parent(project_root).join(safe(node));
    fs::create_dir_all(&parent).map_err(|error| error.to_string())?;
    let now_nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_nanos())
        .unwrap_or_default();
    let root = parent.join(format!(
        "{}.{}.{}.{}",
        safe(task.as_str()),
        std::process::id(),
        now_nanos,
        NEXT_OUTPUT_ROOT_ID.fetch_add(1, Ordering::Relaxed)
    ));
    fs::create_dir(&root).map_err(|error| error.to_string())?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755))
            .map_err(|error| error.to_string())?;
    }
    root.canonicalize().map_err(|error| error.to_string())
}

pub(crate) fn clean_stale_task_output_roots(
    project_root: Option<&Path>,
    node: &str,
) -> Result<usize, String> {
    let node = node
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || "._-".contains(character) {
                character
            } else {
                '_'
            }
        })
        .collect::<String>();
    let parent = task_output_parent(project_root).join(node);
    let parent_metadata = match fs::symlink_metadata(&parent) {
        Ok(metadata) => metadata,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(0),
        Err(error) => return Err(error.to_string()),
    };
    if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
        return Err("task-output store root must be a non-symlink directory".to_owned());
    }
    let mut removed = 0;
    for entry in fs::read_dir(&parent).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        let file_type = entry.file_type().map_err(|error| error.to_string())?;
        if file_type.is_dir() {
            fs::remove_dir_all(entry.path()).map_err(|error| error.to_string())?;
        } else {
            fs::remove_file(entry.path()).map_err(|error| error.to_string())?;
        }
        removed += 1;
    }
    Ok(removed)
}

fn task_output_parent(project_root: Option<&Path>) -> PathBuf {
    #[cfg(windows)]
    {
        let _ = project_root;
        std::env::temp_dir()
            .join("clusterflux")
            .join("task-outputs")
    }
    #[cfg(not(windows))]
    {
        project_root
            .map(Path::to_path_buf)
            .unwrap_or_else(|| PathBuf::from("."))
            .join("target/clusterflux")
            .join("task-outputs")
    }
}

fn confined_output_file(output_root: &Path, relative_path: &str) -> Result<PathBuf, String> {
    validate_relative_path(relative_path)?;
    let root = output_root.canonicalize().map_err(|error| {
        format!(
            "resolve task output root `{}` before publishing `{relative_path}`: {error}",
            output_root.display()
        )
    })?;
    reject_symlink_components(&root, relative_path, true)?;
    let path = root.join(relative_path);
    let metadata = fs::symlink_metadata(&path).map_err(|error| {
        format!(
            "inspect task output `{}` before publication: {error}",
            path.display()
        )
    })?;
    if metadata.file_type().is_symlink() {
        return Err("task output publication rejects symbolic links".to_owned());
    }
    let canonical = path.canonicalize().map_err(|error| {
        format!(
            "resolve task output `{}` before publication: {error}",
            path.display()
        )
    })?;
    if !canonical.starts_with(&root) {
        return Err("task output path escapes its bounded output root".to_owned());
    }
    Ok(canonical)
}

fn confined_output_target(output_root: &Path, relative_path: &str) -> Result<PathBuf, String> {
    validate_relative_path(relative_path)?;
    let root = output_root
        .canonicalize()
        .map_err(|error| error.to_string())?;
    let path = root.join(relative_path);
    let parent = path
        .parent()
        .ok_or_else(|| "task output target has no parent".to_owned())?;
    create_confined_directories(&root, relative_path)?;
    reject_symlink_components(&root, relative_path, false)?;
    let parent = parent.canonicalize().map_err(|error| error.to_string())?;
    if !parent.starts_with(&root) {
        return Err("task output target escapes its bounded output root".to_owned());
    }
    Ok(path)
}

fn create_confined_directories(root: &Path, relative_path: &str) -> Result<(), String> {
    let components = relative_path.split('/').collect::<Vec<_>>();
    let mut current = root.to_path_buf();
    for component in components.iter().take(components.len().saturating_sub(1)) {
        current.push(component);
        match fs::symlink_metadata(&current) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err("task output target rejects symbolic-link directories".to_owned())
            }
            Ok(metadata) if !metadata.is_dir() => {
                return Err("task output target parent is not a directory".to_owned())
            }
            Ok(_) => {}
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                fs::create_dir(&current).map_err(|error| error.to_string())?;
                #[cfg(unix)]
                {
                    use std::os::unix::fs::PermissionsExt;
                    fs::set_permissions(&current, fs::Permissions::from_mode(0o755))
                        .map_err(|error| error.to_string())?;
                }
            }
            Err(error) => return Err(error.to_string()),
        }
    }
    Ok(())
}

fn reject_symlink_components(
    root: &Path,
    relative_path: &str,
    include_leaf: bool,
) -> Result<(), String> {
    let components = relative_path.split('/').collect::<Vec<_>>();
    let count = if include_leaf {
        components.len()
    } else {
        components.len().saturating_sub(1)
    };
    let mut current = root.to_path_buf();
    for component in components.iter().take(count) {
        current.push(component);
        let metadata = fs::symlink_metadata(&current).map_err(|error| error.to_string())?;
        if metadata.file_type().is_symlink() {
            return Err("task output path rejects symbolic-link components".to_owned());
        }
    }
    Ok(())
}

fn open_regular_readonly(path: &Path, label: &str) -> Result<fs::File, String> {
    let metadata = fs::symlink_metadata(path).map_err(|error| error.to_string())?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(format!("{label} must be a regular non-symlink file"));
    }
    let mut options = OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    let file = options.open(path).map_err(|error| error.to_string())?;
    if !file
        .metadata()
        .map_err(|error| error.to_string())?
        .is_file()
    {
        return Err(format!("{label} must remain a regular file while open"));
    }
    Ok(file)
}

fn create_new_private_file(path: &Path) -> Result<fs::File, String> {
    let mut options = OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options
            .mode(0o600)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC);
    }
    options.open(path).map_err(|error| error.to_string())
}

fn hash_reader(reader: &mut impl Read, limit: u64) -> Result<(Digest, u64), String> {
    let mut sink = std::io::sink();
    copy_and_hash(reader, &mut sink, limit)
}

fn copy_and_hash(
    reader: &mut impl Read,
    writer: &mut impl Write,
    limit: u64,
) -> Result<(Digest, u64), String> {
    let mut hasher = Sha256::new();
    let mut size_bytes = 0_u64;
    let mut buffer = [0_u8; 64 * 1024];
    loop {
        let read = reader
            .read(&mut buffer)
            .map_err(|error| error.to_string())?;
        if read == 0 {
            break;
        }
        size_bytes = size_bytes
            .checked_add(read as u64)
            .ok_or_else(|| "artifact size accounting overflowed".to_owned())?;
        if size_bytes > limit {
            return Err(format!(
                "artifact exceeds bounded size limit of {limit} bytes"
            ));
        }
        hasher.update(&buffer[..read]);
        writer
            .write_all(&buffer[..read])
            .map_err(|error| error.to_string())?;
    }
    let digest_hex = format!("{:x}", hasher.finalize());
    Ok((Digest::from_sha256_hex(&digest_hex)?, size_bytes))
}

fn environment_u64(name: &str, default: u64) -> Result<u64, String> {
    match std::env::var(name) {
        Ok(value) => value
            .parse::<u64>()
            .map_err(|_| format!("{name} must be an unsigned integer")),
        Err(std::env::VarError::NotPresent) => Ok(default),
        Err(error) => Err(format!("read {name}: {error}")),
    }
}

fn system_time_epoch_seconds(time: SystemTime) -> Option<u64> {
    time.duration_since(UNIX_EPOCH)
        .ok()
        .map(|duration| duration.as_secs())
}

pub(crate) fn current_epoch_seconds() -> u64 {
    system_time_epoch_seconds(SystemTime::now()).unwrap_or_default()
}

fn validate_relative_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > 240
        || path.starts_with('/')
        || path.starts_with('\\')
        || path.split('/').any(|component| {
            component.is_empty()
                || component == "."
                || component == ".."
                || !component
                    .chars()
                    .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
        })
    {
        return Err("task output path must be a safe relative path".to_owned());
    }
    Ok(())
}

fn validate_artifact_component(value: &str, label: &str, max_len: usize) -> Result<(), String> {
    if value.trim().is_empty()
        || value.len() > max_len
        || !value
            .chars()
            .all(|character| character.is_ascii_alphanumeric() || "._-".contains(character))
    {
        return Err(format!("{label} is invalid"));
    }
    Ok(())
}

pub(crate) struct TaskArtifactStore {
    overlay: VfsOverlay,
}

impl TaskArtifactStore {
    pub(crate) fn new(task: TaskInstanceId, node: NodeId) -> Self {
        Self {
            overlay: VfsOverlay::new(task, node),
        }
    }

    pub(crate) fn overlay_mut(&mut self) -> &mut VfsOverlay {
        &mut self.overlay
    }

    pub(crate) fn flush(mut self) -> VfsManifest {
        self.overlay.flush()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn artifact_retention_rejects_zero_and_effectively_unbounded_limits() {
        assert!(NodeArtifactRetentionLimits::default().validate().is_ok());
        for limits in [
            NodeArtifactRetentionLimits {
                max_bytes: 0,
                ..NodeArtifactRetentionLimits::default()
            },
            NodeArtifactRetentionLimits {
                max_bytes: u64::MAX,
                ..NodeArtifactRetentionLimits::default()
            },
            NodeArtifactRetentionLimits {
                max_count: usize::MAX,
                ..NodeArtifactRetentionLimits::default()
            },
            NodeArtifactRetentionLimits {
                max_age_seconds: u64::MAX,
                ..NodeArtifactRetentionLimits::default()
            },
            NodeArtifactRetentionLimits {
                restart_pin_seconds: u64::MAX,
                ..NodeArtifactRetentionLimits::default()
            },
        ] {
            assert!(limits.validate().is_err());
        }
    }

    fn retain_fixture(
        store: &NodeArtifactStore,
        workspace: &Path,
        name: &str,
        bytes: &[u8],
    ) -> RetainedArtifact {
        let output = workspace.join("output");
        fs::create_dir_all(&output).unwrap();
        let path = output.join(name);
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent).unwrap();
        }
        fs::write(path, bytes).unwrap();
        store.retain_output_file(&output, name).unwrap()
    }

    #[test]
    fn node_artifact_store_retains_real_content_addressed_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node/a").unwrap();
        let retained = retain_fixture(&store, temp.path(), "app.tar.zst", b"real artifact bytes");

        assert_eq!(retained.digest, Digest::sha256(b"real artifact bytes"));
        assert_eq!(retained.size_bytes, 19);
        assert_eq!(fs::read(&retained.path).unwrap(), b"real artifact bytes");
        assert_eq!(store.metadata(&retained.id).unwrap().unwrap(), retained);
    }

    #[test]
    fn nested_task_result_registers_every_retained_artifact() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let archive = retain_fixture(&store, temp.path(), "archive.tar.gz", b"archive");
        let checksums = retain_fixture(&store, temp.path(), "SHA256SUMS", b"checksums");
        let handles = [&archive, &checksums]
            .into_iter()
            .map(|artifact| {
                clusterflux_core::TaskBoundaryHandle::Artifact(clusterflux_core::ArtifactHandle {
                    id: artifact.id.clone(),
                    digest: artifact.digest.clone(),
                    size_bytes: artifact.size_bytes,
                })
            })
            .collect();
        let result = clusterflux_core::TaskBoundaryValue::Structured(
            clusterflux_core::StructuredTaskBoundary {
                value: serde_json::json!({
                    "archive": {"$task_handle": {"index": 0, "kind": "artifact"}},
                    "checksums": {"$task_handle": {"index": 1, "kind": "artifact"}},
                }),
                handles,
            },
        );

        let retained = retained_result_artifacts(Some(temp.path()), "node-a", Some(&result))
            .expect("every nested artifact is retained");

        assert_eq!(retained.len(), 2);
        assert!(retained.iter().any(|artifact| artifact.id == archive.id));
        assert!(retained.iter().any(|artifact| artifact.id == checksums.id));
    }

    #[test]
    fn node_artifact_store_rejects_path_traversal() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let output = temp.path().join("output");
        fs::create_dir_all(&output).unwrap();

        assert!(store.retain_output_file(&output, "../escape").is_err());
        assert!(store.metadata(&ArtifactId::from("../escape")).is_err());
    }

    #[test]
    fn node_artifact_store_reads_only_digest_verified_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let retained = retain_fixture(&store, temp.path(), "result.bin", b"verified bytes");

        assert_eq!(
            store
                .read_verified(&retained.id, &retained.digest, retained.size_bytes)
                .unwrap(),
            b"verified bytes"
        );
        assert!(store
            .read_verified(&retained.id, &Digest::sha256("wrong"), retained.size_bytes)
            .is_err());
        assert_eq!(store.artifact_ids().unwrap(), vec![retained.id]);
    }

    #[test]
    fn downstream_materialization_copies_exact_digest_verified_bytes() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let retained = retain_fixture(&store, temp.path(), "build/app", b"real compiler output");
        let consumer = temp.path().join("consumer");
        fs::create_dir_all(&consumer).unwrap();
        let handle = clusterflux_core::ArtifactHandle {
            id: retained.id,
            digest: retained.digest,
            size_bytes: retained.size_bytes,
        };

        let path = store
            .materialize_into_output(&handle, &consumer, "package/app")
            .unwrap();

        assert_eq!(path, consumer.join("package/app"));
        assert_eq!(fs::read(&path).unwrap(), b"real compiler output");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&path).unwrap().permissions().mode() & 0o777,
                0o444
            );
        }
    }

    #[test]
    fn materialization_rejects_a_corrupt_handle_and_removes_partial_output() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let retained = retain_fixture(&store, temp.path(), "app", b"artifact");
        let consumer = temp.path().join("consumer");
        fs::create_dir_all(&consumer).unwrap();
        let handle = clusterflux_core::ArtifactHandle {
            id: retained.id,
            digest: Digest::sha256("forged"),
            size_bytes: retained.size_bytes,
        };

        assert!(store
            .materialize_into_output(&handle, &consumer, "app")
            .is_err());
        assert!(!consumer.join("app").exists());
    }

    #[cfg(unix)]
    #[test]
    fn publication_and_materialization_reject_symlink_components() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let output = temp.path().join("output");
        let outside = temp.path().join("outside");
        fs::create_dir_all(&output).unwrap();
        fs::create_dir_all(&outside).unwrap();
        fs::write(outside.join("secret"), b"outside").unwrap();
        symlink(outside.join("secret"), output.join("linked-file")).unwrap();
        symlink(&outside, output.join("linked-dir")).unwrap();

        assert!(store.retain_output_file(&output, "linked-file").is_err());
        assert!(store
            .retain_output_file(&output, "linked-dir/secret")
            .is_err());

        let retained = retain_fixture(&store, temp.path(), "safe", b"safe");
        let handle = clusterflux_core::ArtifactHandle {
            id: retained.id,
            digest: retained.digest,
            size_bytes: retained.size_bytes,
        };
        assert!(store
            .materialize_into_output(&handle, &output, "linked-dir/copied")
            .is_err());
        assert!(!outside.join("copied").exists());
    }

    #[test]
    fn garbage_collection_obeys_count_bytes_age_and_pins() {
        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "node-a").unwrap();
        let pinned = retain_fixture(&store, temp.path(), "pinned", b"12345");
        let disposable = retain_fixture(&store, temp.path(), "disposable", b"67890");
        let pins = BTreeSet::from([pinned.id.clone()]);

        let report = store
            .garbage_collect(
                NodeArtifactRetentionLimits {
                    max_bytes: 5,
                    max_count: 1,
                    max_age_seconds: u64::MAX,
                    restart_pin_seconds: 60,
                },
                &pins,
                current_epoch_seconds(),
            )
            .unwrap();

        assert_eq!(report.evicted, vec![disposable.id]);
        assert!(report.limits_satisfied);
        assert_eq!(store.artifact_ids().unwrap(), vec![pinned.id.clone()]);

        let pinned_over_limit = store
            .garbage_collect(
                NodeArtifactRetentionLimits {
                    max_bytes: 0,
                    max_count: 0,
                    max_age_seconds: 0,
                    restart_pin_seconds: 60,
                },
                &pins,
                current_epoch_seconds().saturating_add(1),
            )
            .unwrap();
        assert!(pinned_over_limit.evicted.is_empty());
        assert!(!pinned_over_limit.limits_satisfied);
        assert!(pinned.path.exists());
    }

    #[test]
    fn active_provider_lease_pins_source_across_node_garbage_collection() {
        use clusterflux_artifact_transfer::ArtifactProviderRegistry;
        use clusterflux_core::{
            ArtifactRelayPolicy, ArtifactTransferLease, ProcessId, ProjectId, TenantId,
        };

        let temp = tempfile::tempdir().unwrap();
        let store = NodeArtifactStore::for_runtime(Some(temp.path()), "source-node").unwrap();
        let retained = retain_fixture(&store, temp.path(), "source.bin", b"leased source bytes");
        let now = current_epoch_seconds();
        let lease = ArtifactTransferLease {
            transfer_id: "gc-overlap-transfer".to_owned(),
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            artifact: retained.id.clone(),
            digest: retained.digest.clone(),
            size_bytes: retained.size_bytes,
            source_node: NodeId::from("source-node"),
            source_endpoint_id: "source-endpoint".to_owned(),
            destination_node: NodeId::from("destination-node"),
            destination_endpoint_id: "destination-endpoint".to_owned(),
            allowed_offset: 0,
            maximum_bytes: retained.size_bytes,
            relay_policy: ArtifactRelayPolicy::DirectRequired,
            direct_path_deadline_ms: 5_000,
            expires_at: now + 60,
            active_lease_expires_at: now + 60,
            nonce: "gc-overlap-nonce".to_owned(),
        };
        let provider = ArtifactProviderRegistry::new("source-endpoint".to_owned(), 8);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime
            .block_on(provider.register_verified_source(lease, [73_u8; 32], &retained.path, now))
            .unwrap();

        let pins = runtime.block_on(provider.pinned_artifacts(now));
        assert_eq!(pins, BTreeSet::from([retained.id.clone()]));
        let limits = NodeArtifactRetentionLimits {
            max_bytes: 0,
            max_count: 0,
            max_age_seconds: 0,
            restart_pin_seconds: 0,
        };
        let overlapped = store.garbage_collect(limits, &pins, now + 1).unwrap();
        assert!(overlapped.evicted.is_empty());
        assert!(retained.path.exists());

        runtime.block_on(provider.cancel("gc-overlap-transfer"));
        let pins = runtime.block_on(provider.pinned_artifacts(now + 1));
        assert!(pins.is_empty());
        let released = store.garbage_collect(limits, &pins, now + 1).unwrap();
        assert_eq!(released.evicted, vec![retained.id]);
        assert!(!retained.path.exists());
    }

    #[test]
    fn task_output_roots_are_unique_and_stale_roots_are_cleaned_on_node_start() {
        let temp = tempfile::tempdir().unwrap();
        let task = TaskInstanceId::from("task:1");
        let first = task_output_root(Some(temp.path()), "node-a", &task).unwrap();
        let second = task_output_root(Some(temp.path()), "node-a", &task).unwrap();
        fs::write(first.join("stale"), b"one").unwrap();
        fs::write(second.join("stale"), b"two").unwrap();

        assert_ne!(first, second);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            assert_eq!(
                fs::metadata(&first).unwrap().permissions().mode() & 0o777,
                0o755
            );
        }
        assert_eq!(
            clean_stale_task_output_roots(Some(temp.path()), "node-a").unwrap(),
            2
        );
        assert!(!first.exists());
        assert!(!second.exists());
    }
}
