use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};

use clusterflux_core::{NodeId, ProjectId, TenantId};
use iroh::SecretKey;
use serde::{Deserialize, Serialize};
use thiserror::Error;

const IDENTITY_KIND: &str = "clusterflux_iroh_endpoint_identity";
const IDENTITY_SCHEMA_VERSION: u16 = 1;

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrohIdentityScope {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub node: NodeId,
}

#[derive(Clone, Debug)]
pub struct PersistentIrohIdentity {
    scope: IrohIdentityScope,
    secret_key: SecretKey,
    generation: u64,
    path: PathBuf,
}

impl PersistentIrohIdentity {
    pub fn load_or_create(
        path: impl AsRef<Path>,
        scope: IrohIdentityScope,
    ) -> Result<Self, IdentityError> {
        let path = path.as_ref();
        let parent = path.parent().ok_or(IdentityError::MissingParent)?;
        ensure_private_directory(parent)?;

        match fs::symlink_metadata(path) {
            Ok(metadata) => {
                if metadata.file_type().is_symlink() || !metadata.is_file() {
                    return Err(IdentityError::UnsafeIdentityPath(path.to_path_buf()));
                }
                ensure_private_file_permissions(path, &metadata)?;
                Self::load_existing(path, scope)
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Self::create(path, scope),
            Err(error) => Err(error.into()),
        }
    }

    fn load_existing(path: &Path, scope: IrohIdentityScope) -> Result<Self, IdentityError> {
        let stored: StoredIrohIdentity = serde_json::from_slice(&fs::read(path)?)?;
        if stored.kind != IDENTITY_KIND || stored.schema_version != IDENTITY_SCHEMA_VERSION {
            return Err(IdentityError::UnsupportedIdentityFormat);
        }
        if stored.tenant != scope.tenant
            || stored.project != scope.project
            || stored.node != scope.node
        {
            return Err(IdentityError::ScopeMismatch);
        }
        if stored.generation == 0 {
            return Err(IdentityError::InvalidGeneration);
        }
        let secret_bytes =
            hex::decode(&stored.secret_key_hex).map_err(|_| IdentityError::InvalidSecretKey)?;
        let secret_bytes: [u8; 32] = secret_bytes
            .try_into()
            .map_err(|_| IdentityError::InvalidSecretKey)?;
        let secret_key = SecretKey::from_bytes(&secret_bytes);
        if secret_key.public().to_string() != stored.endpoint_id {
            return Err(IdentityError::EndpointIdMismatch);
        }
        Ok(Self {
            scope,
            secret_key,
            generation: stored.generation,
            path: path.to_path_buf(),
        })
    }

    fn create(path: &Path, scope: IrohIdentityScope) -> Result<Self, IdentityError> {
        let secret_key = SecretKey::generate();
        let generation = 1;
        let stored = StoredIrohIdentity {
            kind: IDENTITY_KIND.to_owned(),
            schema_version: IDENTITY_SCHEMA_VERSION,
            tenant: scope.tenant.clone(),
            project: scope.project.clone(),
            node: scope.node.clone(),
            endpoint_id: secret_key.public().to_string(),
            secret_key_hex: hex::encode(secret_key.to_bytes()),
            generation,
        };
        let parent = path.parent().ok_or(IdentityError::MissingParent)?;
        let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
        set_private_file_permissions(temporary.as_file())?;
        clusterflux_core::secure_private_path(temporary.path(), false)?;
        temporary.write_all(&serde_json::to_vec_pretty(&stored)?)?;
        temporary.as_file().sync_all()?;
        match temporary.persist_noclobber(path) {
            Ok(_) => sync_directory(parent)?,
            Err(error) if error.error.kind() == std::io::ErrorKind::AlreadyExists => {
                return Self::load_existing(path, scope);
            }
            Err(error) => return Err(error.error.into()),
        }
        Ok(Self {
            scope,
            secret_key,
            generation,
            path: path.to_path_buf(),
        })
    }

    pub fn endpoint_id(&self) -> String {
        self.secret_key.public().to_string()
    }

    pub fn generation(&self) -> u64 {
        self.generation
    }

    pub fn scope(&self) -> &IrohIdentityScope {
        &self.scope
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub(crate) fn secret_key(&self) -> SecretKey {
        self.secret_key.clone()
    }
}

#[derive(Debug, Serialize, Deserialize)]
struct StoredIrohIdentity {
    kind: String,
    schema_version: u16,
    tenant: TenantId,
    project: ProjectId,
    node: NodeId,
    endpoint_id: String,
    secret_key_hex: String,
    generation: u64,
}

fn ensure_private_directory(path: &Path) -> Result<(), IdentityError> {
    fs::create_dir_all(path)?;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() {
        return Err(IdentityError::UnsafeIdentityDirectory(path.to_path_buf()));
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    }
    clusterflux_core::secure_private_path(path, true)?;
    Ok(())
}

fn set_private_file_permissions(file: &fs::File) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}

fn ensure_private_file_permissions(
    path: &Path,
    metadata: &fs::Metadata,
) -> Result<(), IdentityError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if metadata.permissions().mode() & 0o077 != 0 {
            return Err(IdentityError::InsecurePermissions(path.to_path_buf()));
        }
    }
    clusterflux_core::secure_private_path(path, false)?;
    let _ = metadata;
    Ok(())
}

fn sync_directory(path: &Path) -> Result<(), IdentityError> {
    fs::File::open(path)?.sync_all()?;
    Ok(())
}

#[derive(Debug, Error)]
pub enum IdentityError {
    #[error("Iroh identity path has no parent directory")]
    MissingParent,
    #[error("Iroh identity directory is not a safe private directory: {0}")]
    UnsafeIdentityDirectory(PathBuf),
    #[error("Iroh identity path is not a regular non-symlink file: {0}")]
    UnsafeIdentityPath(PathBuf),
    #[error("Iroh identity file permissions are not private: {0}")]
    InsecurePermissions(PathBuf),
    #[error("stored Iroh identity uses an unsupported format")]
    UnsupportedIdentityFormat,
    #[error("stored Iroh identity belongs to another tenant, project, or node")]
    ScopeMismatch,
    #[error("stored Iroh identity generation must be non-zero")]
    InvalidGeneration,
    #[error("stored Iroh secret key is invalid")]
    InvalidSecretKey,
    #[error("stored Iroh endpoint ID does not match its secret key")]
    EndpointIdMismatch,
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope(node: &str) -> IrohIdentityScope {
        IrohIdentityScope {
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            node: NodeId::from(node),
        }
    }

    #[test]
    fn identity_is_persistent_and_separate_per_node_scope() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("identity/iroh.json");
        let first = PersistentIrohIdentity::load_or_create(&path, scope("node-a")).unwrap();
        let second = PersistentIrohIdentity::load_or_create(&path, scope("node-a")).unwrap();
        assert_eq!(first.endpoint_id(), second.endpoint_id());
        assert_eq!(first.generation(), 1);
        assert!(matches!(
            PersistentIrohIdentity::load_or_create(&path, scope("node-b")),
            Err(IdentityError::ScopeMismatch)
        ));
    }

    #[cfg(unix)]
    #[test]
    fn identity_refuses_symlink_files() {
        use std::os::unix::fs::symlink;

        let temp = tempfile::tempdir().unwrap();
        let target = temp.path().join("target");
        fs::write(&target, b"not an identity").unwrap();
        let directory = temp.path().join("identity");
        fs::create_dir(&directory).unwrap();
        let path = directory.join("iroh.json");
        symlink(&target, &path).unwrap();
        assert!(matches!(
            PersistentIrohIdentity::load_or_create(path, scope("node-a")),
            Err(IdentityError::UnsafeIdentityPath(_))
        ));
    }
}
