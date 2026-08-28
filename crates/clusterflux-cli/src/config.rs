use std::path::{Path, PathBuf};

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::CliScopeArgs;

pub(crate) const DEFAULT_HOSTED_COORDINATOR_ENDPOINT: &str = "https://clusterflux.lesstuff.com";

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct ProjectConfig {
    pub(crate) tenant: String,
    pub(crate) project: String,
    pub(crate) user: String,
    pub(crate) coordinator: Option<String>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub(crate) struct StoredCliSession {
    pub(crate) kind: String,
    pub(crate) coordinator: String,
    pub(crate) tenant: String,
    pub(crate) project: String,
    pub(crate) user: String,
    pub(crate) cli_session_credential_kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(crate) session_secret: Option<String>,
    pub(crate) token_expiry_posture: String,
    pub(crate) expires_at: Option<String>,
    pub(crate) provider_tokens_exposed_to_cli: bool,
    pub(crate) provider_tokens_sent_to_nodes: bool,
    pub(crate) created_at_unix_seconds: u64,
}

pub(crate) fn default_hosted_coordinator_endpoint() -> String {
    DEFAULT_HOSTED_COORDINATOR_ENDPOINT.to_owned()
}

pub(crate) fn project_config_file(project: &Path) -> PathBuf {
    project.join(".clusterflux-state").join("project.json")
}

pub(crate) fn session_config_file(project: &Path) -> PathBuf {
    project.join(".clusterflux-state").join("session.json")
}

pub(crate) fn read_project_config(project: &Path) -> Result<Option<ProjectConfig>> {
    let file = project_config_file(project);
    if !file.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
    let config = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    Ok(Some(config))
}

pub(crate) fn write_project_config(project: &Path, config: &ProjectConfig) -> Result<()> {
    let file = project_config_file(project);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    std::fs::write(&file, serde_json::to_vec_pretty(config)?)
        .with_context(|| format!("failed to write {}", file.display()))
}

pub(crate) fn read_cli_session(project: &Path) -> Result<Option<StoredCliSession>> {
    let file = session_config_file(project);
    if !file.exists() {
        return Ok(None);
    }
    let bytes =
        std::fs::read(&file).with_context(|| format!("failed to read {}", file.display()))?;
    let session = serde_json::from_slice(&bytes)
        .with_context(|| format!("failed to parse {}", file.display()))?;
    Ok(Some(session))
}

pub(crate) fn write_cli_session(project: &Path, session: &StoredCliSession) -> Result<PathBuf> {
    let file = session_config_file(project);
    if let Some(parent) = file.parent() {
        std::fs::create_dir_all(parent)
            .with_context(|| format!("failed to create {}", parent.display()))?;
    }
    let bytes = serde_json::to_vec_pretty(session)?;
    let mut options = std::fs::OpenOptions::new();
    options.create(true).truncate(true).write(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    use std::io::Write;
    let mut output = options
        .open(&file)
        .with_context(|| format!("failed to open {}", file.display()))?;
    output
        .write_all(&bytes)
        .with_context(|| format!("failed to write {}", file.display()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&file, std::fs::Permissions::from_mode(0o600))
            .with_context(|| format!("failed to secure {}", file.display()))?;
    }
    Ok(file)
}

pub(crate) fn effective_project_scope(
    scope: &CliScopeArgs,
    config: Option<&ProjectConfig>,
) -> CliScopeArgs {
    CliScopeArgs {
        coordinator: scope
            .coordinator
            .clone()
            .or_else(|| config.and_then(|config| config.coordinator.clone())),
        tenant: effective_scope_value(
            &scope.tenant,
            config.map(|config| config.tenant.as_str()),
            "tenant",
        ),
        project: effective_scope_value(
            &scope.project,
            config.map(|config| config.project.as_str()),
            "project",
        ),
        user: effective_scope_value(
            &scope.user,
            config.map(|config| config.user.as_str()),
            "user",
        ),
        json: scope.json,
    }
}

pub(crate) fn effective_scope_value(
    cli_value: &str,
    config_value: Option<&str>,
    default_value: &str,
) -> String {
    if cli_value == default_value {
        config_value.unwrap_or(cli_value).to_owned()
    } else {
        cli_value.to_owned()
    }
}
