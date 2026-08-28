use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::{Capability, Digest, ProjectId, TenantId};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceProviderKind {
    Filesystem,
    Git,
    Custom(String),
}

impl SourceProviderKind {
    pub fn provider_id(&self) -> &str {
        match self {
            SourceProviderKind::Filesystem => "filesystem",
            SourceProviderKind::Git => "git",
            SourceProviderKind::Custom(provider) => provider,
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SourceTransferMode {
    RequiredContent,
    ExplicitSnapshotChunks,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceTransferPolicy {
    pub local_source_bytes_remain_node_local: bool,
    pub coordinator_receives_source_bytes_by_default: bool,
    pub default_full_repo_tarball: bool,
    pub allowed_remote_transfer: BTreeSet<SourceTransferMode>,
}

impl SourceTransferPolicy {
    pub fn local_first_snapshot_chunks() -> Self {
        Self {
            local_source_bytes_remain_node_local: true,
            coordinator_receives_source_bytes_by_default: false,
            default_full_repo_tarball: false,
            allowed_remote_transfer: BTreeSet::from([
                SourceTransferMode::RequiredContent,
                SourceTransferMode::ExplicitSnapshotChunks,
            ]),
        }
    }
}

impl Default for SourceTransferPolicy {
    fn default() -> Self {
        Self::local_first_snapshot_chunks()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourceProviderManifest {
    pub kind: SourceProviderKind,
    pub digest: Digest,
    pub description: String,
    #[serde(default)]
    pub coordinator_requires_checkout_access: bool,
    #[serde(default)]
    pub transfer_policy: SourceTransferPolicy,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum SourceManifestError {
    #[error("source provider manifest digest is not a valid sha256 digest: {0}")]
    InvalidDigest(String),
    #[error("custom source provider id `{0}` is invalid")]
    InvalidProviderId(String),
    #[error("source provider manifest description must be non-empty")]
    EmptyDescription,
    #[error("source provider manifest description is too long")]
    DescriptionTooLong,
    #[error("source provider manifest description contains control characters")]
    DescriptionControlCharacter,
    #[error("source provider manifest would require coordinator checkout access")]
    CoordinatorCheckoutAccess,
    #[error("source provider manifest would send source bytes to the coordinator by default")]
    CoordinatorReceivesSourceBytes,
    #[error("source provider manifest would default to a full-repo tarball")]
    DefaultFullRepoTarball,
    #[error("source provider manifest has no allowed remote transfer mode")]
    MissingRemoteTransferMode,
}

pub trait SourceProviderModule {
    fn kind(&self) -> SourceProviderKind;
    fn manifest(&self) -> SourceProviderManifest;
}

impl SourceProviderManifest {
    pub fn local_first(kind: SourceProviderKind, description: impl Into<String>) -> Self {
        let transfer_policy = SourceTransferPolicy::local_first_snapshot_chunks();
        let digest = Self::digest_for(&kind, false, &transfer_policy);
        Self {
            kind,
            digest,
            description: description.into(),
            coordinator_requires_checkout_access: false,
            transfer_policy,
        }
    }

    pub fn validate_public_mvp(&self) -> Result<(), SourceManifestError> {
        self.validate_shape()?;
        if self.coordinator_requires_checkout_access {
            return Err(SourceManifestError::CoordinatorCheckoutAccess);
        }
        if self
            .transfer_policy
            .coordinator_receives_source_bytes_by_default
        {
            return Err(SourceManifestError::CoordinatorReceivesSourceBytes);
        }
        if self.transfer_policy.default_full_repo_tarball {
            return Err(SourceManifestError::DefaultFullRepoTarball);
        }
        if self.transfer_policy.allowed_remote_transfer.is_empty() {
            return Err(SourceManifestError::MissingRemoteTransferMode);
        }
        Ok(())
    }

    fn validate_shape(&self) -> Result<(), SourceManifestError> {
        if !self.digest.is_valid_sha256() {
            return Err(SourceManifestError::InvalidDigest(
                self.digest.as_str().to_owned(),
            ));
        }
        if let SourceProviderKind::Custom(provider) = &self.kind {
            if !valid_provider_id(provider) {
                return Err(SourceManifestError::InvalidProviderId(provider.clone()));
            }
        }
        if self.description.trim().is_empty() {
            return Err(SourceManifestError::EmptyDescription);
        }
        if self.description.len() > 256 {
            return Err(SourceManifestError::DescriptionTooLong);
        }
        if self.description.chars().any(char::is_control) {
            return Err(SourceManifestError::DescriptionControlCharacter);
        }
        Ok(())
    }

    fn digest_for(
        kind: &SourceProviderKind,
        coordinator_requires_checkout_access: bool,
        transfer_policy: &SourceTransferPolicy,
    ) -> Digest {
        let mut modes = transfer_policy
            .allowed_remote_transfer
            .iter()
            .map(|mode| format!("{mode:?}"))
            .collect::<Vec<_>>();
        modes.sort();
        let mut parts = vec![
            b"source-provider-manifest:v2".to_vec(),
            kind.provider_id().as_bytes().to_vec(),
            coordinator_requires_checkout_access
                .to_string()
                .into_bytes(),
            transfer_policy
                .local_source_bytes_remain_node_local
                .to_string()
                .into_bytes(),
            transfer_policy
                .coordinator_receives_source_bytes_by_default
                .to_string()
                .into_bytes(),
            transfer_policy
                .default_full_repo_tarball
                .to_string()
                .into_bytes(),
        ];
        parts.extend(modes.into_iter().map(String::into_bytes));
        Digest::from_parts(parts)
    }
}

fn valid_provider_id(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 64
        && provider
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SourcePreparation {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub provider: SourceProviderKind,
    pub required_capabilities: BTreeSet<Capability>,
    pub coordinator_requires_checkout_access: bool,
}

impl SourcePreparation {
    pub fn node_task(tenant: TenantId, project: ProjectId, provider: SourceProviderKind) -> Self {
        let capability = match provider {
            SourceProviderKind::Filesystem => Capability::SourceFilesystem,
            SourceProviderKind::Git => Capability::SourceGit,
            SourceProviderKind::Custom(_) => Capability::SourceFilesystem,
        };

        Self {
            tenant,
            project,
            provider,
            required_capabilities: BTreeSet::from([capability]),
            coordinator_requires_checkout_access: false,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn source_preparation_can_be_scheduled_as_node_task() {
        let prep = SourcePreparation::node_task(
            TenantId::from("tenant"),
            ProjectId::from("project"),
            SourceProviderKind::Git,
        );

        assert!(!prep.coordinator_requires_checkout_access);
        assert!(prep.required_capabilities.contains(&Capability::SourceGit));
    }

    #[test]
    fn local_first_source_manifest_rejects_bulk_coordinator_paths() {
        let manifest = SourceProviderManifest::local_first(
            SourceProviderKind::Git,
            "node-side Git snapshot provider",
        );

        assert!(manifest.validate_public_mvp().is_ok());
        assert!(!manifest.coordinator_requires_checkout_access);
        assert!(
            !manifest
                .transfer_policy
                .coordinator_receives_source_bytes_by_default
        );
        assert!(!manifest.transfer_policy.default_full_repo_tarball);
        assert!(manifest
            .transfer_policy
            .allowed_remote_transfer
            .contains(&SourceTransferMode::ExplicitSnapshotChunks));
    }

    #[test]
    fn source_manifest_validation_treats_manifest_as_hostile_input() {
        let mut manifest = SourceProviderManifest::local_first(
            SourceProviderKind::Custom("gitlab-lfs".to_owned()),
            "custom provider",
        );
        assert!(manifest.validate_public_mvp().is_ok());

        manifest.kind = SourceProviderKind::Custom("../checkout".to_owned());
        assert_eq!(
            manifest.validate_public_mvp(),
            Err(SourceManifestError::InvalidProviderId(
                "../checkout".to_owned()
            ))
        );

        manifest.kind = SourceProviderKind::Git;
        manifest.digest = Digest::sha256("valid");
        manifest.coordinator_requires_checkout_access = true;
        assert_eq!(
            manifest.validate_public_mvp(),
            Err(SourceManifestError::CoordinatorCheckoutAccess)
        );

        manifest.coordinator_requires_checkout_access = false;
        manifest
            .transfer_policy
            .coordinator_receives_source_bytes_by_default = true;
        assert_eq!(
            manifest.validate_public_mvp(),
            Err(SourceManifestError::CoordinatorReceivesSourceBytes)
        );

        manifest
            .transfer_policy
            .coordinator_receives_source_bytes_by_default = false;
        manifest.transfer_policy.default_full_repo_tarball = true;
        assert_eq!(
            manifest.validate_public_mvp(),
            Err(SourceManifestError::DefaultFullRepoTarball)
        );
    }

    #[test]
    fn source_manifest_rejects_malformed_digest_from_json() {
        let mut manifest = SourceProviderManifest::local_first(
            SourceProviderKind::Filesystem,
            "filesystem provider",
        );
        let value = serde_json::to_value(&manifest).unwrap();
        let mut object = value.as_object().unwrap().clone();
        object.insert(
            "digest".to_owned(),
            serde_json::Value::String("sha256:not-a-real-digest".to_owned()),
        );
        manifest = serde_json::from_value(serde_json::Value::Object(object)).unwrap();

        assert_eq!(
            manifest.validate_public_mvp(),
            Err(SourceManifestError::InvalidDigest(
                "sha256:not-a-real-digest".to_owned()
            ))
        );
    }
}
