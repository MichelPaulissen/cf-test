use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Capability, Digest, Os};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnvironmentKind {
    Containerfile,
    Dockerfile,
    NixFlake,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentRequirements {
    pub os: Option<Os>,
    pub arch: Option<String>,
    pub capabilities: BTreeSet<Capability>,
    #[serde(default)]
    pub secret_declarations: BTreeSet<String>,
}

impl EnvironmentRequirements {
    pub fn linux_container() -> Self {
        Self {
            os: Some(Os::Linux),
            arch: None,
            capabilities: BTreeSet::from([Capability::Containers, Capability::RootlessPodman]),
            secret_declarations: BTreeSet::new(),
        }
    }

    pub fn windows_command_dev() -> Self {
        Self {
            os: Some(Os::Windows),
            arch: None,
            capabilities: BTreeSet::from([Capability::WindowsCommandDev]),
            secret_declarations: BTreeSet::new(),
        }
    }

    pub fn windows_container() -> Self {
        Self {
            os: Some(Os::Windows),
            arch: None,
            capabilities: BTreeSet::from([Capability::Containers, Capability::ContainerdNerdctl]),
            secret_declarations: BTreeSet::new(),
        }
    }

    pub fn unconstrained() -> Self {
        Self {
            os: None,
            arch: None,
            capabilities: BTreeSet::new(),
            secret_declarations: BTreeSet::new(),
        }
    }
}

pub const MAX_ENVIRONMENT_CONTEXT_FILES: usize = 128;
pub const MAX_ENVIRONMENT_CONTEXT_FILE_BYTES: usize = 1024 * 1024;
pub const MAX_ENVIRONMENT_CONTEXT_BYTES: usize = 8 * 1024 * 1024;
pub const MAX_ENVIRONMENT_CONTEXT_PATH_BYTES: usize = 512;
pub const MAX_ENVIRONMENT_CONTEXT_DEPTH: usize = 16;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EnvironmentContextFile {
    pub path: String,
    pub mode: u32,
    pub size: u64,
    pub digest: Digest,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentResource {
    pub name: String,
    pub kind: EnvironmentKind,
    pub recipe_path: PathBuf,
    pub context_path: PathBuf,
    #[serde(default)]
    pub context_manifest: Vec<EnvironmentContextFile>,
    #[serde(default = "empty_context_manifest_identity")]
    pub context_manifest_digest: Digest,
    pub digest: Digest,
    pub requirements: EnvironmentRequirements,
}

fn empty_context_manifest_identity() -> Digest {
    context_manifest_identity(&[])
}

impl EnvironmentResource {
    pub fn validate_context_identity(&self) -> Result<(), String> {
        let mut manifest = self.context_manifest.clone();
        validate_context_manifest(&mut manifest)?;
        if manifest != self.context_manifest
            || context_manifest_identity(&manifest) != self.context_manifest_digest
        {
            return Err("environment context manifest identity is invalid".to_owned());
        }
        Ok(())
    }
}

pub fn environment_image_tag(environment: &EnvironmentResource) -> String {
    let name = environment
        .name
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_') {
                character
            } else {
                '-'
            }
        })
        .collect::<String>();
    let digest = environment
        .digest
        .as_str()
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || matches!(character, '-' | '_' | '.') {
                character
            } else {
                '-'
            }
        })
        .take(24)
        .collect::<String>();
    format!("clusterflux-env/{name}:{digest}")
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentReference {
    pub name: String,
    pub byte_offset: usize,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct EnvironmentDiagnostic {
    pub reference: EnvironmentReference,
    pub message: String,
}

#[derive(Debug, Error)]
pub enum EnvironmentError {
    #[error("failed to read environment resources under {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
    #[error("invalid environment `{name}`: {message}")]
    Invalid { name: String, message: String },
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct EnvironmentManifest {
    version: u32,
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    os: Option<String>,
    #[serde(default)]
    arch: Option<String>,
    #[serde(default)]
    capabilities: Vec<String>,
    #[serde(default)]
    secrets: Vec<String>,
}

pub fn discover_environments(
    project_root: &Path,
) -> Result<Vec<EnvironmentResource>, EnvironmentError> {
    let envs_dir = project_root.join("envs");
    if !envs_dir.exists() {
        return Ok(Vec::new());
    }

    let mut resources = Vec::new();
    let entries = fs::read_dir(&envs_dir).map_err(|source| EnvironmentError::Read {
        path: envs_dir.clone(),
        source,
    })?;

    for entry in entries {
        let entry = entry.map_err(|source| EnvironmentError::Read {
            path: envs_dir.clone(),
            source,
        })?;
        let path = entry.path();
        if !path.is_dir() {
            continue;
        }
        let Some(name) = path.file_name().and_then(|name| name.to_str()) else {
            continue;
        };

        if let Some(resource) = discover_one(project_root, name, &path)? {
            resources.push(resource);
        }
    }

    resources.sort_by(|left, right| left.name.cmp(&right.name));
    Ok(resources)
}

pub fn diagnose_environment_references(
    source: &str,
    environments: &[EnvironmentResource],
) -> Vec<EnvironmentDiagnostic> {
    let known = environments
        .iter()
        .map(|environment| environment.name.as_str())
        .collect::<BTreeSet<_>>();

    find_env_macro_references(source)
        .into_iter()
        .filter(|reference| !known.contains(reference.name.as_str()))
        .map(|reference| EnvironmentDiagnostic {
            message: format!(
                "missing Clusterflux environment `{}`; expected envs/{}/Containerfile or envs/{}/Dockerfile",
                reference.name, reference.name, reference.name
            ),
            reference,
        })
        .collect()
}

fn discover_one(
    project_root: &Path,
    name: &str,
    env_dir: &Path,
) -> Result<Option<EnvironmentResource>, EnvironmentError> {
    let candidates = [
        ("Containerfile", EnvironmentKind::Containerfile),
        ("Dockerfile", EnvironmentKind::Dockerfile),
        ("flake.nix", EnvironmentKind::NixFlake),
    ];

    for (file_name, kind) in candidates {
        let recipe_path = env_dir.join(file_name);
        if !recipe_path.exists() {
            continue;
        }

        let recipe_bytes = fs::read(&recipe_path).map_err(|source| EnvironmentError::Read {
            path: recipe_path.clone(),
            source,
        })?;
        let metadata_path = env_dir.join("environment.toml");
        let metadata_bytes = if metadata_path.is_file() {
            fs::read(&metadata_path).map_err(|source| EnvironmentError::Read {
                path: metadata_path,
                source,
            })?
        } else {
            Vec::new()
        };
        let relative_recipe = recipe_path
            .strip_prefix(project_root)
            .unwrap_or(&recipe_path)
            .to_path_buf();
        let relative_context = env_dir.strip_prefix(project_root).unwrap_or(env_dir);
        let context_manifest = collect_environment_context(env_dir)?;
        return environment_resource_from_revision_bytes(
            name,
            kind,
            relative_recipe,
            relative_context.to_path_buf(),
            &recipe_bytes,
            &metadata_bytes,
            context_manifest,
        )
        .map(Some)
        .map_err(|message| EnvironmentError::Invalid {
            name: name.to_owned(),
            message,
        });
    }

    Ok(None)
}

/// Builds the normalized environment identity shared by local discovery and
/// exact-revision hosted loading. Only the recipe and bounded policy metadata
/// are eager; context bytes remain in the repository until a node materializes
/// the pinned revision.
pub fn environment_resource_from_revision_bytes(
    name: &str,
    kind: EnvironmentKind,
    recipe_path: PathBuf,
    context_path: PathBuf,
    recipe_bytes: &[u8],
    metadata_bytes: &[u8],
    mut context_manifest: Vec<EnvironmentContextFile>,
) -> Result<EnvironmentResource, String> {
    validate_context_manifest(&mut context_manifest)?;
    let context_manifest_digest = context_manifest_identity(&context_manifest);
    let requirements = parse_environment_manifest(name, &kind, metadata_bytes)?;
    let portable_recipe_path = recipe_path.to_string_lossy().replace('\\', "/");
    let digest = Digest::from_parts([
        b"environment:v3".as_slice(),
        name.as_bytes(),
        format!("{kind:?}").as_bytes(),
        portable_recipe_path.as_bytes(),
        Digest::sha256(recipe_bytes).as_str().as_bytes(),
        Digest::sha256(metadata_bytes).as_str().as_bytes(),
        context_manifest_digest.as_str().as_bytes(),
        serde_json::to_vec(&requirements)
            .map_err(|error| format!("encode normalized environment requirements: {error}"))?
            .as_slice(),
    ]);
    Ok(EnvironmentResource {
        name: name.to_owned(),
        kind,
        recipe_path,
        context_path,
        context_manifest,
        context_manifest_digest,
        digest,
        requirements,
    })
}

fn parse_environment_manifest(
    directory_name: &str,
    kind: &EnvironmentKind,
    bytes: &[u8],
) -> Result<EnvironmentRequirements, String> {
    let mut requirements = match kind {
        EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile
            if directory_name.eq_ignore_ascii_case("windows") =>
        {
            EnvironmentRequirements::windows_container()
        }
        EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile => {
            EnvironmentRequirements::linux_container()
        }
        EnvironmentKind::NixFlake => EnvironmentRequirements::unconstrained(),
    };
    if bytes.is_empty() {
        return Ok(requirements);
    }
    let manifest: EnvironmentManifest =
        toml::from_str(std::str::from_utf8(bytes).map_err(|_| "environment.toml is not UTF-8")?)
            .map_err(|error| format!("parse environment.toml: {error}"))?;
    if manifest.version != 1 {
        return Err(format!(
            "unsupported environment.toml version {}; expected 1",
            manifest.version
        ));
    }
    if manifest
        .name
        .as_deref()
        .is_some_and(|name| name != directory_name)
    {
        return Err(format!(
            "environment.toml name must match directory `{directory_name}`"
        ));
    }
    if !manifest.secrets.is_empty() {
        return Err(
            "environment secrets are unsupported; keep secrets out of materialized VMs".to_owned(),
        );
    }
    if let Some(os) = manifest.os.as_deref() {
        requirements.os = Some(match os {
            "linux" => Os::Linux,
            "windows" => Os::Windows,
            "macos" => Os::Macos,
            _ => return Err(format!("unsupported environment OS `{os}`")),
        });
        if matches!(
            kind,
            EnvironmentKind::Containerfile | EnvironmentKind::Dockerfile
        ) {
            requirements
                .capabilities
                .remove(&Capability::RootlessPodman);
            requirements
                .capabilities
                .remove(&Capability::ContainerdNerdctl);
            match requirements.os {
                Some(Os::Linux) => {
                    requirements.capabilities.insert(Capability::RootlessPodman);
                }
                Some(Os::Windows) => {
                    requirements
                        .capabilities
                        .insert(Capability::ContainerdNerdctl);
                }
                Some(Os::Macos) | Some(Os::Other(_)) | None => {}
            }
        }
    }
    if let Some(arch) = manifest.arch {
        if arch.is_empty()
            || arch.len() > 64
            || !arch
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'-'))
        {
            return Err(format!("invalid environment architecture `{arch}`"));
        }
        requirements.arch = Some(arch);
    }
    if !manifest.capabilities.is_empty() {
        for capability in manifest.capabilities {
            match capability.as_str() {
                "command" => {
                    requirements.capabilities.insert(Capability::Command);
                }
                "container" => {
                    requirements.capabilities.insert(Capability::Containers);
                    match requirements.os {
                        Some(Os::Linux) => {
                            requirements.capabilities.insert(Capability::RootlessPodman);
                        }
                        Some(Os::Windows) => {
                            requirements
                                .capabilities
                                .insert(Capability::ContainerdNerdctl);
                        }
                        Some(Os::Macos) | Some(Os::Other(_)) | None => {}
                    }
                }
                "network" => {
                    requirements.capabilities.insert(Capability::Network);
                }
                "source_filesystem" => {
                    requirements
                        .capabilities
                        .insert(Capability::SourceFilesystem);
                }
                "source_git" => {
                    requirements.capabilities.insert(Capability::SourceGit);
                }
                "vfs_artifacts" => {
                    requirements.capabilities.insert(Capability::VfsArtifacts);
                }
                other => return Err(format!("unsupported environment capability `{other}`")),
            }
        }
    }
    Ok(requirements)
}

fn collect_environment_context(
    root: &Path,
) -> Result<Vec<EnvironmentContextFile>, EnvironmentError> {
    fn visit(
        root: &Path,
        directory: &Path,
        files: &mut Vec<EnvironmentContextFile>,
        total: &mut usize,
    ) -> Result<(), EnvironmentError> {
        let entries = fs::read_dir(directory).map_err(|source| EnvironmentError::Read {
            path: directory.to_path_buf(),
            source,
        })?;
        let mut paths = entries
            .map(|entry| {
                entry
                    .map(|entry| entry.path())
                    .map_err(|source| EnvironmentError::Read {
                        path: directory.to_path_buf(),
                        source,
                    })
            })
            .collect::<Result<Vec<_>, _>>()?;
        paths.sort();
        for path in paths {
            let relative = path
                .strip_prefix(root)
                .expect("context path is beneath root");
            let relative_text = relative
                .to_str()
                .ok_or_else(|| EnvironmentError::Invalid {
                    name: root.display().to_string(),
                    message: "context path is not UTF-8".to_owned(),
                })?
                .replace('\\', "/");
            let first = relative_text.split('/').next().unwrap_or_default();
            if matches!(first, ".git" | "target" | ".clusterflux") {
                continue;
            }
            validate_context_path(&relative_text).map_err(|message| EnvironmentError::Invalid {
                name: root.display().to_string(),
                message,
            })?;
            let metadata =
                fs::symlink_metadata(&path).map_err(|source| EnvironmentError::Read {
                    path: path.clone(),
                    source,
                })?;
            if metadata.file_type().is_symlink() {
                return Err(EnvironmentError::Invalid {
                    name: root.display().to_string(),
                    message: format!("context path `{relative_text}` is a symlink"),
                });
            }
            if metadata.is_dir() {
                visit(root, &path, files, total)?;
                continue;
            }
            if !metadata.is_file() {
                return Err(EnvironmentError::Invalid {
                    name: root.display().to_string(),
                    message: format!("context path `{relative_text}` is not a regular file"),
                });
            }
            let size = usize::try_from(metadata.len()).unwrap_or(usize::MAX);
            if files.len() >= MAX_ENVIRONMENT_CONTEXT_FILES
                || size > MAX_ENVIRONMENT_CONTEXT_FILE_BYTES
                || total.saturating_add(size) > MAX_ENVIRONMENT_CONTEXT_BYTES
            {
                return Err(EnvironmentError::Invalid {
                    name: root.display().to_string(),
                    message: format!(
                        "context file `{relative_text}` exceeds bounded context limits"
                    ),
                });
            }
            let bytes = fs::read(&path).map_err(|source| EnvironmentError::Read {
                path: path.clone(),
                source,
            })?;
            *total += bytes.len();
            files.push(EnvironmentContextFile {
                path: relative_text,
                mode: normalized_mode(&metadata),
                size: metadata.len(),
                digest: Digest::sha256(&bytes),
            });
        }
        Ok(())
    }

    let mut files = Vec::new();
    let mut total = 0;
    visit(root, root, &mut files, &mut total)?;
    Ok(files)
}

#[cfg(unix)]
fn normalized_mode(metadata: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    if metadata.permissions().mode() & 0o111 == 0 {
        0o100644
    } else {
        0o100755
    }
}

#[cfg(not(unix))]
fn normalized_mode(_metadata: &fs::Metadata) -> u32 {
    0o100644
}

fn validate_context_manifest(files: &mut [EnvironmentContextFile]) -> Result<(), String> {
    files.sort();
    if files.len() > MAX_ENVIRONMENT_CONTEXT_FILES {
        return Err("environment context contains too many files".to_owned());
    }
    let mut total = 0_u64;
    for file in files.iter() {
        validate_context_path(&file.path)?;
        if !matches!(file.mode, 0o100644 | 0o100755)
            || file.size > MAX_ENVIRONMENT_CONTEXT_FILE_BYTES as u64
            || !file.digest.is_valid_sha256()
        {
            return Err(format!(
                "environment context file `{}` is invalid",
                file.path
            ));
        }
        total = total.saturating_add(file.size);
    }
    if total > MAX_ENVIRONMENT_CONTEXT_BYTES as u64
        || files.windows(2).any(|pair| pair[0].path == pair[1].path)
    {
        return Err(
            "environment context manifest exceeds limits or has duplicate paths".to_owned(),
        );
    }
    Ok(())
}

fn validate_context_path(path: &str) -> Result<(), String> {
    if path.is_empty()
        || path.len() > MAX_ENVIRONMENT_CONTEXT_PATH_BYTES
        || path.starts_with('/')
        || path.contains('\\')
        || path.split('/').count() > MAX_ENVIRONMENT_CONTEXT_DEPTH
        || path
            .split('/')
            .any(|component| component.is_empty() || matches!(component, "." | ".."))
    {
        return Err(format!("invalid environment context path `{path}`"));
    }
    Ok(())
}

fn context_manifest_identity(files: &[EnvironmentContextFile]) -> Digest {
    let mut parts = vec![b"environment-context:v1".to_vec()];
    for file in files {
        parts.push(file.path.as_bytes().to_vec());
        parts.push(file.mode.to_string().into_bytes());
        parts.push(file.size.to_string().into_bytes());
        parts.push(file.digest.as_str().as_bytes().to_vec());
    }
    Digest::from_parts(parts)
}

fn find_env_macro_references(source: &str) -> Vec<EnvironmentReference> {
    let mut references = Vec::new();
    let mut cursor = 0;

    while let Some(index) = source[cursor..].find("env!(") {
        let start = cursor + index;
        let mut pos = start + "env!(".len();
        while source[pos..].starts_with(char::is_whitespace) {
            pos += source[pos..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
        }
        if !source[pos..].starts_with('"') {
            cursor = pos;
            continue;
        }
        pos += 1;
        let name_start = pos;
        while pos < source.len() && !source[pos..].starts_with('"') {
            pos += source[pos..]
                .chars()
                .next()
                .map(char::len_utf8)
                .unwrap_or(1);
        }
        if pos < source.len() {
            references.push(EnvironmentReference {
                name: source[name_start..pos].to_owned(),
                byte_offset: start,
            });
        }
        cursor = pos.saturating_add(1);
    }

    references
}

#[cfg(test)]
mod tests {
    use std::fs;

    use super::*;

    #[test]
    fn discovers_containerfile_environments_by_logical_name() {
        let temp = tempfile::tempdir().unwrap();
        let linux = temp.path().join("envs/linux");
        fs::create_dir_all(&linux).unwrap();
        fs::write(linux.join("Containerfile"), "FROM alpine\n").unwrap();

        let envs = discover_environments(temp.path()).unwrap();

        assert_eq!(envs.len(), 1);
        assert_eq!(envs[0].name, "linux");
        assert_eq!(envs[0].kind, EnvironmentKind::Containerfile);
        assert!(!envs[0].digest.as_str().is_empty());
    }

    #[test]
    fn legacy_environment_without_context_identity_loads_as_empty_context() {
        let temp = tempfile::tempdir().unwrap();
        let linux = temp.path().join("envs/linux");
        fs::create_dir_all(&linux).unwrap();
        fs::write(linux.join("Containerfile"), "FROM alpine\n").unwrap();
        let environment = discover_environments(temp.path()).unwrap().remove(0);
        let mut encoded = serde_json::to_value(environment).unwrap();
        let object = encoded.as_object_mut().unwrap();
        object.remove("context_manifest");
        object.remove("context_manifest_digest");

        let restored: EnvironmentResource = serde_json::from_value(encoded).unwrap();

        assert!(restored.context_manifest.is_empty());
        assert_eq!(
            restored.context_manifest_digest,
            context_manifest_identity(&[])
        );
        restored.validate_context_identity().unwrap();
    }

    #[test]
    fn missing_env_macro_reference_reports_clear_diagnostic() {
        let source = r#"fn main() { let _ = env!("windows"); }"#;
        let diagnostics = diagnose_environment_references(source, &[]);

        assert_eq!(diagnostics.len(), 1);
        assert!(diagnostics[0]
            .message
            .contains("envs/windows/Containerfile"));
    }

    #[test]
    fn windows_environment_name_uses_containerd_nerdctl_requirements() {
        let temp = tempfile::tempdir().unwrap();
        let windows = temp.path().join("envs/windows");
        fs::create_dir_all(&windows).unwrap();
        fs::write(
            windows.join("Dockerfile"),
            "# Windows container environment\n",
        )
        .unwrap();

        let envs = discover_environments(temp.path()).unwrap();

        assert_eq!(envs[0].name, "windows");
        assert_eq!(envs[0].requirements.os, Some(Os::Windows));
        assert!(envs[0]
            .requirements
            .capabilities
            .contains(&Capability::ContainerdNerdctl));
        assert!(!envs[0]
            .requirements
            .capabilities
            .contains(&Capability::WindowsCommandDev));
    }

    #[test]
    fn context_file_changes_environment_identity() {
        let temp = tempfile::tempdir().unwrap();
        let linux = temp.path().join("envs/linux");
        fs::create_dir_all(&linux).unwrap();
        fs::write(
            linux.join("Containerfile"),
            "FROM alpine\nCOPY install-tool.sh /\n",
        )
        .unwrap();
        fs::write(linux.join("install-tool.sh"), "echo one\n").unwrap();
        let first = discover_environments(temp.path()).unwrap().remove(0);

        fs::write(linux.join("install-tool.sh"), "echo two\n").unwrap();
        let second = discover_environments(temp.path()).unwrap().remove(0);

        assert_ne!(
            first.context_manifest_digest,
            second.context_manifest_digest
        );
        assert_ne!(first.digest, second.digest);
        assert_eq!(second.context_manifest[1].path, "install-tool.sh");
    }

    #[test]
    fn environment_identity_normalizes_windows_path_separators() {
        let metadata = b"version = 1\nname = \"windows-node-build\"\nos = \"windows\"\narch = \"x86_64\"\ncapabilities = [\"command\"]\nsecrets = []\n";
        let manifest = vec![EnvironmentContextFile {
            path: "Containerfile".to_owned(),
            mode: 0o100644,
            size: 12,
            digest: Digest::sha256("FROM scratch"),
        }];
        let slash = environment_resource_from_revision_bytes(
            "windows-node-build",
            EnvironmentKind::Containerfile,
            PathBuf::from("envs/windows-node-build/Containerfile"),
            PathBuf::from("envs/windows-node-build"),
            b"FROM scratch",
            metadata,
            manifest.clone(),
        )
        .unwrap();
        let backslash = environment_resource_from_revision_bytes(
            "windows-node-build",
            EnvironmentKind::Containerfile,
            PathBuf::from(r"envs\windows-node-build\Containerfile"),
            PathBuf::from(r"envs\windows-node-build"),
            b"FROM scratch",
            metadata,
            manifest,
        )
        .unwrap();

        assert_eq!(slash.digest, backslash.digest);
    }

    #[test]
    fn environment_manifest_is_strict_and_controls_placement_requirements() {
        let temp = tempfile::tempdir().unwrap();
        let linux = temp.path().join("envs/release-build");
        fs::create_dir_all(&linux).unwrap();
        fs::write(linux.join("Containerfile"), "FROM alpine\n").unwrap();
        fs::write(
            linux.join("environment.toml"),
            "version = 1\nname = \"release-build\"\nos = \"linux\"\narch = \"x86_64\"\ncapabilities = [\"command\", \"container\"]\nsecrets = []\n",
        )
        .unwrap();

        let environment = discover_environments(temp.path()).unwrap().remove(0);
        assert_eq!(environment.requirements.os, Some(Os::Linux));
        assert_eq!(environment.requirements.arch.as_deref(), Some("x86_64"));
        assert!(environment
            .requirements
            .capabilities
            .contains(&Capability::Command));
        assert!(environment
            .requirements
            .capabilities
            .contains(&Capability::Containers));

        fs::write(
            linux.join("environment.toml"),
            "version = 1\nunsupported = true\n",
        )
        .unwrap();
        assert!(discover_environments(temp.path())
            .unwrap_err()
            .to_string()
            .contains("unknown field"));
    }

    #[test]
    fn environment_manifest_refuses_secret_materialization() {
        let temp = tempfile::tempdir().unwrap();
        let linux = temp.path().join("envs/linux");
        fs::create_dir_all(&linux).unwrap();
        fs::write(linux.join("Containerfile"), "FROM alpine\n").unwrap();
        fs::write(
            linux.join("environment.toml"),
            "version = 1\nsecrets = [\"TOKEN\"]\n",
        )
        .unwrap();

        assert!(discover_environments(temp.path())
            .unwrap_err()
            .to_string()
            .contains("keep secrets out"));
    }
}
