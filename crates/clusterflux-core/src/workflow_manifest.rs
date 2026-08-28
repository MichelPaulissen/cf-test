use serde::{Deserialize, Serialize};
use thiserror::Error;

use crate::Digest;

pub const SUPPORTED_WORKFLOW_SDK_VERSION: &str = "0.2.0";
pub const SUPPORTED_WORKFLOW_SERDE_VERSION: &str = "1.0.228";
pub const SUPPORTED_WORKFLOW_EDITION: &str = "2024";
pub const MAX_WORKFLOW_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_PACKAGE_NAME_BYTES: usize = 64;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NormalizedWorkflowManifest {
    pub package_name: String,
    pub package_version: String,
    pub edition: String,
    pub publish: bool,
    pub crate_root: String,
    pub crate_type: String,
    pub sdk_version: String,
    pub serde_version: Option<String>,
    pub serde_features: Vec<String>,
    pub workspace_resolver: String,
    pub digest: Digest,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum WorkflowManifestError {
    #[error("workflow manifest exceeds the {MAX_WORKFLOW_MANIFEST_BYTES}-byte limit")]
    Oversized,
    #[error("workflow manifest is not UTF-8")]
    NotUtf8,
    #[error("hosted automatic compilation rejected this Cargo manifest: {0}")]
    InvalidToml(String),
    #[error("invalid Cargo package name `{0}`")]
    InvalidPackageName(String),
    #[error("workflow package version must be exactly `0.0.0`")]
    InvalidVersion,
    #[error("workflow edition must be exactly `{SUPPORTED_WORKFLOW_EDITION}`")]
    InvalidEdition,
    #[error("workflow package must set `publish = false`")]
    PublishMustBeFalse,
    #[error("the workflow crate root must be `.clusterflux/main.rs`")]
    InvalidCrateRoot,
    #[error("workflow crate-type must be exactly `[\"cdylib\"]`")]
    InvalidCrateType,
    #[error("this workflow may build locally, but hosted automatic compilation supports only the built-in Clusterflux SDK version {supported}; the manifest declared {declared}")]
    UnsupportedSdk { declared: String, supported: String },
    #[error("workflow workspace resolver must be exactly `3`")]
    InvalidWorkspaceResolver,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictManifest {
    package: StrictPackage,
    lib: StrictLib,
    dependencies: StrictDependencies,
    workspace: StrictWorkspace,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictPackage {
    name: String,
    version: String,
    edition: String,
    publish: bool,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct StrictLib {
    path: String,
    crate_type: Vec<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictDependencies {
    clusterflux: HostedSdkDependency,
    #[serde(default)]
    serde: Option<HostedSerdeDependency>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields, rename_all = "kebab-case")]
struct HostedSerdeDependency {
    version: String,
    features: Vec<String>,
    #[serde(default = "default_true")]
    default_features: bool,
}

fn default_true() -> bool {
    true
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct HostedSdkDependency {
    package: String,
    version: String,
    // A local Cargo hint only. Hosted compilation validates its shape but
    // never resolves, reads, or sends this path to a compiler assignment.
    path: Option<String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct StrictWorkspace {
    resolver: String,
}

impl NormalizedWorkflowManifest {
    pub fn parse(bytes: &[u8]) -> Result<Self, WorkflowManifestError> {
        if bytes.len() > MAX_WORKFLOW_MANIFEST_BYTES {
            return Err(WorkflowManifestError::Oversized);
        }
        let text = std::str::from_utf8(bytes).map_err(|_| WorkflowManifestError::NotUtf8)?;
        let parsed: StrictManifest = toml::from_str(text)
            .map_err(|error| WorkflowManifestError::InvalidToml(targeted_toml_error(&error)))?;
        validate_package_name(&parsed.package.name)?;
        if parsed.package.version != "0.0.0" {
            return Err(WorkflowManifestError::InvalidVersion);
        }
        if parsed.package.edition != SUPPORTED_WORKFLOW_EDITION {
            return Err(WorkflowManifestError::InvalidEdition);
        }
        if parsed.package.publish {
            return Err(WorkflowManifestError::PublishMustBeFalse);
        }
        if parsed.lib.path != "main.rs" {
            return Err(WorkflowManifestError::InvalidCrateRoot);
        }
        if parsed.lib.crate_type.as_slice() != ["cdylib"] {
            return Err(WorkflowManifestError::InvalidCrateType);
        }
        let expected_sdk = format!("={SUPPORTED_WORKFLOW_SDK_VERSION}");
        if parsed.dependencies.clusterflux.package != "clusterflux-sdk"
            || parsed.dependencies.clusterflux.version != expected_sdk
        {
            return Err(WorkflowManifestError::UnsupportedSdk {
                declared: parsed
                    .dependencies
                    .clusterflux
                    .version
                    .trim_start_matches('=')
                    .to_owned(),
                supported: SUPPORTED_WORKFLOW_SDK_VERSION.to_owned(),
            });
        }
        if let Some(path) = &parsed.dependencies.clusterflux.path {
            validate_local_sdk_hint(path)?;
        }
        let serde_identity = parsed
            .dependencies
            .serde
            .map(|serde| {
                let expected = format!("={SUPPORTED_WORKFLOW_SERDE_VERSION}");
                if serde.version != expected
                    || serde.features.as_slice() != ["derive"]
                    || !serde.default_features
                {
                    return Err(WorkflowManifestError::InvalidToml(format!(
                    "hosted Serde must be exactly version {expected} with features = [\"derive\"]"
                )));
                }
                Ok((SUPPORTED_WORKFLOW_SERDE_VERSION.to_owned(), serde.features))
            })
            .transpose()?;
        if parsed.workspace.resolver != "3" {
            return Err(WorkflowManifestError::InvalidWorkspaceResolver);
        }
        let digest = Digest::from_parts([
            b"clusterflux-workflow-manifest:v1".as_slice(),
            parsed.package.name.as_bytes(),
            b"0.0.0".as_slice(),
            SUPPORTED_WORKFLOW_EDITION.as_bytes(),
            b"false".as_slice(),
            b"main.rs".as_slice(),
            b"cdylib".as_slice(),
            SUPPORTED_WORKFLOW_SDK_VERSION.as_bytes(),
            serde_identity
                .as_ref()
                .map(|(version, _)| version.as_bytes())
                .unwrap_or(b"none"),
            b"3".as_slice(),
        ]);
        Ok(Self {
            package_name: parsed.package.name,
            package_version: "0.0.0".to_owned(),
            edition: SUPPORTED_WORKFLOW_EDITION.to_owned(),
            publish: false,
            crate_root: "main.rs".to_owned(),
            crate_type: "cdylib".to_owned(),
            sdk_version: SUPPORTED_WORKFLOW_SDK_VERSION.to_owned(),
            serde_version: serde_identity.as_ref().map(|(version, _)| version.clone()),
            serde_features: serde_identity
                .map(|(_, features)| features)
                .unwrap_or_default(),
            workspace_resolver: "3".to_owned(),
            digest,
        })
    }

    pub fn crate_name(&self) -> String {
        self.package_name.replace('-', "_")
    }
}

fn validate_local_sdk_hint(path: &str) -> Result<(), WorkflowManifestError> {
    let bounded = !path.is_empty()
        && path.len() <= 512
        && !path.contains('\0')
        && !std::path::Path::new(path).is_absolute();
    if !bounded {
        return Err(WorkflowManifestError::InvalidToml(
            "the Clusterflux SDK path hint must be a bounded relative Cargo path; hosted compilation never reads it"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_package_name(name: &str) -> Result<(), WorkflowManifestError> {
    let valid = !name.is_empty()
        && name.len() <= MAX_PACKAGE_NAME_BYTES
        && name
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_'))
        && name
            .bytes()
            .next()
            .is_some_and(|byte| byte.is_ascii_alphanumeric())
        && name
            .bytes()
            .last()
            .is_some_and(|byte| byte.is_ascii_alphanumeric());
    if !valid {
        return Err(WorkflowManifestError::InvalidPackageName(name.to_owned()));
    }
    Ok(())
}

fn targeted_toml_error(error: &toml::de::Error) -> String {
    let message = error.to_string();
    if message.contains("unknown field") {
        if message.contains("features") {
            return "hosted workflows do not support features or target-specific dependencies"
                .to_owned();
        }
        if message.contains("dependencies") {
            return "this workflow may build locally, but hosted automatic compilation supports only the built-in Clusterflux SDK and exact supported Serde derive dependency".to_owned();
        }
        if message.contains("build") {
            return "hosted workflows do not support build scripts".to_owned();
        }
    }
    message
}

#[cfg(test)]
mod tests {
    use super::*;

    fn valid_manifest(name: &str) -> String {
        format!(
            "[package]\nname = \"{name}\"\nversion = \"0.0.0\"\nedition = \"2024\"\npublish = false\n\n[lib]\npath = \"main.rs\"\ncrate-type = [\"cdylib\"]\n\n[dependencies]\nclusterflux = {{ package = \"clusterflux-sdk\", version = \"=0.2.0\", path = \"../crates/clusterflux-sdk\" }}\n\n[workspace]\nresolver = \"3\"\n"
        )
    }

    #[test]
    fn valid_manifest_normalizes_independent_of_order_and_comments() {
        let first =
            NormalizedWorkflowManifest::parse(valid_manifest("demo-workflow").as_bytes()).unwrap();
        let reordered = b"# editor-compatible, hosted-safe\n[workspace]\nresolver='3'\n[dependencies]\nclusterflux={package='clusterflux-sdk',version='=0.2.0',path='../crates/clusterflux-sdk'}\n[lib]\ncrate-type=['cdylib']\npath='main.rs'\n[package]\npublish=false\nedition='2024'\nversion='0.0.0'\nname='demo-workflow'\n";
        let second = NormalizedWorkflowManifest::parse(reordered).unwrap();
        assert_eq!(first, second);
        assert_eq!(first.crate_name(), "demo_workflow");
    }

    #[test]
    fn accepts_only_the_exact_trusted_serde_derive_profile() {
        let manifest = valid_manifest("serde-workflow").replace(
            "[workspace]",
            "serde = { version = '=1.0.228', features = ['derive'] }\n\n[workspace]",
        );
        let parsed = NormalizedWorkflowManifest::parse(manifest.as_bytes()).unwrap();
        assert_eq!(parsed.serde_version.as_deref(), Some("1.0.228"));
        assert_eq!(parsed.serde_features, ["derive"]);

        let unsupported = manifest.replace("1.0.228", "1.0.227");
        assert!(NormalizedWorkflowManifest::parse(unsupported.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("exactly version"));
    }

    #[test]
    fn rejects_every_dependency_form_and_unsupported_table() {
        let path_dependency = valid_manifest("demo").replace(
            "clusterflux = { package = \"clusterflux-sdk\", version = \"=0.2.0\", path = \"../crates/clusterflux-sdk\" }",
            "clusterflux = { path = \"../sdk\" }",
        );
        assert!(
            NormalizedWorkflowManifest::parse(path_dependency.as_bytes())
                .unwrap_err()
                .to_string()
                .contains("hosted automatic compilation")
        );
        let features = format!("{}\n[features]\ndefault=[]\n", valid_manifest("demo"));
        assert!(NormalizedWorkflowManifest::parse(features.as_bytes())
            .unwrap_err()
            .to_string()
            .contains("features"));
    }

    #[test]
    fn rejects_wrong_exact_values_and_resource_excess() {
        let wrong_sdk =
            valid_manifest("demo").replace(&format!("={SUPPORTED_WORKFLOW_SDK_VERSION}"), "=9.9.9");
        assert!(matches!(
            NormalizedWorkflowManifest::parse(wrong_sdk.as_bytes()),
            Err(WorkflowManifestError::UnsupportedSdk { .. })
        ));
        assert_eq!(
            NormalizedWorkflowManifest::parse(&vec![b'x'; MAX_WORKFLOW_MANIFEST_BYTES + 1]),
            Err(WorkflowManifestError::Oversized)
        );
    }
}
