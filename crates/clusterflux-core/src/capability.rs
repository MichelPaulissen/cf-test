use std::collections::BTreeSet;

use serde::{Deserialize, Serialize};
use thiserror::Error;

#[cfg(not(target_arch = "wasm32"))]
use wait_timeout::ChildExt;

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Capability {
    Command,
    Containers,
    RootlessPodman,
    ContainerdNerdctl,
    SourceFilesystem,
    SourceGit,
    HostFilesystem,
    Network,
    Secrets,
    InboundPorts,
    ArbitrarySyscalls,
    VfsArtifacts,
    ArtifactTransfer,
    WindowsCommandDev,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NodeWorkPolicy {
    #[default]
    Normal,
    ExecutionOnly,
    SystemTasksOnly,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum SystemTaskSandbox {
    RootlessPodman,
    Gvisor,
    DedicatedVm,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SystemBundleCapability {
    pub bundle_id: String,
    pub bundle_digest: crate::Digest,
    pub sdk_abi_version: u32,
    pub wasm_target: String,
    pub rust_toolchain: String,
    pub environment_digest: crate::Digest,
    pub sandbox: SystemTaskSandbox,
    pub max_source_bytes: usize,
    pub max_output_bytes: usize,
    pub max_concurrent_assignments: u16,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum EnvironmentBackend {
    Container,
    NixFlake,
    WindowsCommandDev,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Os {
    Linux,
    Windows,
    Macos,
    Other(String),
}

impl Os {
    pub fn current() -> Self {
        match std::env::consts::OS {
            "linux" => Self::Linux,
            "windows" => Self::Windows,
            "macos" => Self::Macos,
            other => Self::Other(other.to_owned()),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeCapabilities {
    pub os: Os,
    pub arch: String,
    pub capabilities: BTreeSet<Capability>,
    pub environment_backends: BTreeSet<EnvironmentBackend>,
    pub source_providers: BTreeSet<String>,
    #[serde(default)]
    pub work_policy: NodeWorkPolicy,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub system_bundles: Vec<SystemBundleCapability>,
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum CapabilityReportError {
    #[error("node architecture `{0}` is invalid")]
    InvalidArchitecture(String),
    #[error("node OS label `{0}` is invalid")]
    InvalidOsLabel(String),
    #[error("source provider id `{0}` is invalid")]
    InvalidSourceProvider(String),
    #[error("system bundle capability is invalid: {0}")]
    InvalidSystemBundle(String),
}

impl NodeCapabilities {
    pub fn detect_current() -> Self {
        let os = Os::current();
        let mut capabilities = BTreeSet::from([
            Capability::SourceFilesystem,
            Capability::SourceGit,
            Capability::VfsArtifacts,
            Capability::ArtifactTransfer,
        ]);
        let mut environment_backends = BTreeSet::new();

        match os {
            Os::Linux => {
                if rootless_podman_available() {
                    capabilities.insert(Capability::Command);
                    capabilities.insert(Capability::Containers);
                    capabilities.insert(Capability::RootlessPodman);
                    environment_backends.insert(EnvironmentBackend::Container);
                }
            }
            Os::Windows => {
                if containerd_nerdctl_available() {
                    capabilities.insert(Capability::Command);
                    capabilities.insert(Capability::Containers);
                    capabilities.insert(Capability::ContainerdNerdctl);
                    environment_backends.insert(EnvironmentBackend::Container);
                }
            }
            Os::Macos | Os::Other(_) => {}
        }

        let work_policy = if matches!(os, Os::Windows | Os::Macos) {
            NodeWorkPolicy::ExecutionOnly
        } else {
            NodeWorkPolicy::Normal
        };
        Self {
            os,
            arch: std::env::consts::ARCH.to_owned(),
            capabilities,
            environment_backends,
            source_providers: BTreeSet::from(["filesystem".to_owned(), "git".to_owned()]),
            work_policy,
            system_bundles: Vec::new(),
        }
    }

    pub fn with_capability(mut self, capability: Capability) -> Self {
        self.capabilities.insert(capability);
        self
    }

    pub fn has_all(&self, required: &BTreeSet<Capability>) -> bool {
        required
            .iter()
            .all(|capability| self.capabilities.contains(capability))
    }

    pub fn validate_public_report(&self) -> Result<(), CapabilityReportError> {
        if !valid_capability_label(&self.arch) {
            return Err(CapabilityReportError::InvalidArchitecture(
                self.arch.clone(),
            ));
        }
        if let Os::Other(label) = &self.os {
            if !valid_capability_label(label) {
                return Err(CapabilityReportError::InvalidOsLabel(label.clone()));
            }
        }
        for provider in &self.source_providers {
            if !valid_source_provider_id(provider) {
                return Err(CapabilityReportError::InvalidSourceProvider(
                    provider.clone(),
                ));
            }
        }
        for profile in &self.system_bundles {
            if !valid_capability_label(&profile.bundle_id)
                || !profile.bundle_digest.is_valid_sha256()
                || profile.sdk_abi_version == 0
                || profile.wasm_target != "wasm32-unknown-unknown"
                || profile.rust_toolchain.trim().is_empty()
                || !profile.environment_digest.is_valid_sha256()
                || profile.max_source_bytes == 0
                || profile.max_output_bytes == 0
                || profile.max_concurrent_assignments == 0
            {
                return Err(CapabilityReportError::InvalidSystemBundle(
                    "metadata or limits are invalid".to_owned(),
                ));
            }
        }
        let identities = self
            .system_bundles
            .iter()
            .map(|profile| (&profile.bundle_id, &profile.bundle_digest))
            .collect::<BTreeSet<_>>();
        if identities.len() != self.system_bundles.len() {
            return Err(CapabilityReportError::InvalidSystemBundle(
                "duplicate system bundle identity".to_owned(),
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ContainerdNerdctlReadiness {
    pub ready: bool,
    pub failure_layer: Option<String>,
    pub message: String,
    pub namespace: String,
    pub server_version: Option<String>,
    pub os_type: Option<String>,
    pub storage_driver: Option<String>,
    pub storage_plugins: Vec<String>,
}

#[cfg(not(target_arch = "wasm32"))]
pub fn probe_containerd_nerdctl_readiness() -> ContainerdNerdctlReadiness {
    use std::process::{Command, Stdio};
    use std::time::Duration;

    const PROBE_TIMEOUT: Duration = Duration::from_secs(5);
    const MAX_OUTPUT_BYTES: usize = 64 * 1024;

    let mut child = match Command::new("nerdctl")
        .args(["info", "--format", "{{json .}}"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
    {
        Ok(child) => child,
        Err(error) => {
            return failed_nerdctl_readiness(
                "nerdctl_client",
                format!("start bounded nerdctl server probe: {error}"),
            )
        }
    };
    match child.wait_timeout(PROBE_TIMEOUT) {
        Ok(Some(_)) => {}
        Ok(None) => {
            let _ = child.kill();
            let _ = child.wait();
            return failed_nerdctl_readiness(
                "containerd_connectivity",
                "nerdctl info did not complete within 5 seconds".to_owned(),
            );
        }
        Err(error) => {
            let _ = child.kill();
            let _ = child.wait();
            return failed_nerdctl_readiness(
                "containerd_connectivity",
                format!("wait for nerdctl info: {error}"),
            );
        }
    }
    let output = match child.wait_with_output() {
        Ok(output) => output,
        Err(error) => {
            return failed_nerdctl_readiness(
                "containerd_connectivity",
                format!("collect nerdctl info output: {error}"),
            )
        }
    };
    if output.stdout.len() > MAX_OUTPUT_BYTES || output.stderr.len() > MAX_OUTPUT_BYTES {
        return failed_nerdctl_readiness(
            "nerdctl_protocol",
            "nerdctl info output exceeded the 64 KiB bound".to_owned(),
        );
    }
    if !output.status.success() {
        return failed_nerdctl_readiness(
            "containerd_connectivity",
            format!(
                "nerdctl info failed with status {:?}: {}",
                output.status.code(),
                String::from_utf8_lossy(&output.stderr).trim()
            ),
        );
    }
    parse_containerd_nerdctl_info(&output.stdout)
}

#[cfg(target_arch = "wasm32")]
pub fn probe_containerd_nerdctl_readiness() -> ContainerdNerdctlReadiness {
    failed_nerdctl_readiness(
        "platform",
        "containerd readiness cannot be probed from wasm".to_owned(),
    )
}

#[cfg(not(target_arch = "wasm32"))]
fn parse_containerd_nerdctl_info(stdout: &[u8]) -> ContainerdNerdctlReadiness {
    let value: serde_json::Value = match serde_json::from_slice(stdout) {
        Ok(value) => value,
        Err(error) => {
            return failed_nerdctl_readiness(
                "nerdctl_protocol",
                format!("parse nerdctl info JSON: {error}"),
            )
        }
    };
    let object = match value.as_object() {
        Some(object) => object,
        None => {
            return failed_nerdctl_readiness(
                "nerdctl_protocol",
                "nerdctl info did not return a JSON object".to_owned(),
            )
        }
    };
    let server_version = object
        .get("ServerVersion")
        .and_then(serde_json::Value::as_str)
        .filter(|value| !value.trim().is_empty())
        .map(str::to_owned);
    let os_type = object
        .get("OSType")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let storage_driver = object
        .get("Driver")
        .and_then(serde_json::Value::as_str)
        .map(str::to_owned);
    let storage_plugins = value
        .pointer("/Plugins/Storage")
        .and_then(serde_json::Value::as_array)
        .map(|plugins| {
            plugins
                .iter()
                .filter_map(serde_json::Value::as_str)
                .map(str::to_owned)
                .collect::<Vec<_>>()
        })
        .unwrap_or_default();
    if server_version.is_none() {
        return failed_nerdctl_readiness(
            "containerd_connectivity",
            "nerdctl info omitted the containerd server version".to_owned(),
        );
    }
    if os_type.as_deref() != Some("windows") || storage_driver.as_deref() != Some("windows") {
        return ContainerdNerdctlReadiness {
            ready: false,
            failure_layer: Some("windows_runtime".to_owned()),
            message: "containerd did not report the Windows runtime and storage driver".to_owned(),
            namespace: "default".to_owned(),
            server_version,
            os_type,
            storage_driver,
            storage_plugins,
        };
    }
    if !storage_plugins
        .iter()
        .any(|plugin| matches!(plugin.as_str(), "windows" | "cimfs" | "windows-lcow"))
    {
        return ContainerdNerdctlReadiness {
            ready: false,
            failure_layer: Some("windows_snapshotter".to_owned()),
            message: "containerd reported no usable Windows storage plugin".to_owned(),
            namespace: "default".to_owned(),
            server_version,
            os_type,
            storage_driver,
            storage_plugins,
        };
    }
    ContainerdNerdctlReadiness {
        ready: true,
        failure_layer: None,
        message: "containerd default namespace and Windows runtime are reachable".to_owned(),
        namespace: "default".to_owned(),
        server_version,
        os_type,
        storage_driver,
        storage_plugins,
    }
}

fn failed_nerdctl_readiness(layer: &str, message: String) -> ContainerdNerdctlReadiness {
    ContainerdNerdctlReadiness {
        ready: false,
        failure_layer: Some(layer.to_owned()),
        message,
        namespace: "default".to_owned(),
        server_version: None,
        os_type: None,
        storage_driver: None,
        storage_plugins: Vec::new(),
    }
}

#[cfg(not(target_arch = "wasm32"))]
fn containerd_nerdctl_available() -> bool {
    probe_containerd_nerdctl_readiness().ready
}

#[cfg(target_arch = "wasm32")]
fn containerd_nerdctl_available() -> bool {
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn rootless_podman_available() -> bool {
    const ATTEMPTS: usize = 3;
    for attempt in 0..ATTEMPTS {
        match std::process::Command::new("podman")
            .args(["info", "--format", "{{.Host.Security.Rootless}}"])
            .output()
        {
            Ok(output) if rootless_podman_probe_succeeded(&output) => return true,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return false,
            Ok(_) | Err(_) if attempt + 1 < ATTEMPTS => {
                std::thread::sleep(std::time::Duration::from_millis(250));
            }
            Ok(_) | Err(_) => {}
        }
    }
    false
}

#[cfg(not(target_arch = "wasm32"))]
fn rootless_podman_probe_succeeded(output: &std::process::Output) -> bool {
    output.status.success() && String::from_utf8_lossy(&output.stdout).trim() == "true"
}

#[cfg(target_arch = "wasm32")]
fn rootless_podman_available() -> bool {
    false
}

fn valid_capability_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 64
        && label.bytes().all(
            |byte| matches!(byte, b'a'..=b'z' | b'A'..=b'Z' | b'0'..=b'9' | b'-' | b'_' | b'.'),
        )
}

fn valid_source_provider_id(provider: &str) -> bool {
    !provider.is_empty()
        && provider.len() <= 64
        && provider
            .bytes()
            .all(|byte| matches!(byte, b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capabilities() -> NodeCapabilities {
        NodeCapabilities {
            os: Os::Linux,
            arch: "x86_64".to_owned(),
            capabilities: BTreeSet::from([Capability::Command]),
            environment_backends: BTreeSet::new(),
            source_providers: BTreeSet::from(["filesystem".to_owned(), "git".to_owned()]),
            work_policy: NodeWorkPolicy::Normal,
            system_bundles: Vec::new(),
        }
    }

    #[test]
    fn capability_reports_validate_hostile_strings() {
        assert!(capabilities().validate_public_report().is_ok());

        let mut invalid_arch = capabilities();
        invalid_arch.arch = "x86_64\nmalicious".to_owned();
        assert_eq!(
            invalid_arch.validate_public_report(),
            Err(CapabilityReportError::InvalidArchitecture(
                "x86_64\nmalicious".to_owned()
            ))
        );

        let mut invalid_provider = capabilities();
        invalid_provider
            .source_providers
            .insert("../checkout".to_owned());
        assert_eq!(
            invalid_provider.validate_public_report(),
            Err(CapabilityReportError::InvalidSourceProvider(
                "../checkout".to_owned()
            ))
        );
    }

    #[test]
    fn nerdctl_readiness_requires_a_windows_server_and_storage_plugin() {
        let ready = parse_containerd_nerdctl_info(
            br#"{"Driver":"windows","Plugins":{"Storage":["cimfs","windows"]},"OSType":"windows","ServerVersion":"v2.3.4"}"#,
        );
        assert!(ready.ready);
        assert_eq!(ready.failure_layer, None);

        let client_only = parse_containerd_nerdctl_info(br#"{"OSType":"windows"}"#);
        assert!(!client_only.ready);
        assert_eq!(
            client_only.failure_layer.as_deref(),
            Some("containerd_connectivity")
        );

        let linux = parse_containerd_nerdctl_info(
            br#"{"Driver":"overlayfs","Plugins":{"Storage":["overlayfs"]},"OSType":"linux","ServerVersion":"v2"}"#,
        );
        assert!(!linux.ready);
        assert_eq!(linux.failure_layer.as_deref(), Some("windows_runtime"));
    }
}
