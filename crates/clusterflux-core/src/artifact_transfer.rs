use std::fmt;
use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use crate::{ArtifactId, Digest, NodeId, ProcessId, ProjectId, TenantId};

pub const CLUSTERFLUX_ARTIFACT_ALPN: &[u8] = b"clusterflux/artifact/1";
pub const ARTIFACT_TRANSFER_PROTOCOL_VERSION: u16 = 1;
pub const MAX_ENDPOINT_DIRECT_ADDRESSES: usize = 32;
pub const MAX_ENDPOINT_RELAY_URLS: usize = 8;
pub const MAX_ENDPOINT_ID_BYTES: usize = 128;
pub const MAX_RELAY_URL_BYTES: usize = 2_048;
pub const MAX_TRANSFER_ID_BYTES: usize = 128;
pub const MAX_TRANSFER_ERROR_MESSAGE_BYTES: usize = 1_024;

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IrohRelayConfiguration {
    #[default]
    Disabled,
    Custom(Vec<ClusterfluxRelayConfig>),
}

#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ClusterfluxRelayConfig {
    pub url: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub access_token: Option<String>,
}

impl fmt::Debug for ClusterfluxRelayConfig {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        let url = if self.url.contains('@') || self.url.contains('?') || self.url.contains('#') {
            "[REDACTED URL]".to_owned()
        } else if let Some((scheme, remainder)) = self.url.split_once("://") {
            format!(
                "{scheme}://{}",
                remainder.split('/').next().unwrap_or_default()
            )
        } else {
            "[INVALID URL]".to_owned()
        };
        formatter
            .debug_struct("ClusterfluxRelayConfig")
            .field("url", &url)
            .field(
                "access_token",
                &self.access_token.as_ref().map(|_| "[REDACTED]"),
            )
            .finish()
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactDataPlanePolicy {
    pub relay: IrohRelayConfiguration,
    pub artifact_relay_policy: ArtifactRelayPolicy,
    pub generation: u64,
    pub endpoint_advertisement_ttl_seconds: u64,
    pub direct_path_deadline_ms: u64,
    pub direct_path_grace_period_ms: u64,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactConnectivityFacts {
    pub endpoint_advertised: bool,
    pub recent_path: ClusterfluxPathKind,
    pub recent_direct_failure: bool,
    pub relay_policy: ArtifactRelayPolicy,
}

impl Default for ArtifactConnectivityFacts {
    fn default() -> Self {
        Self {
            endpoint_advertised: false,
            recent_path: ClusterfluxPathKind::Unknown,
            recent_direct_failure: false,
            relay_policy: ArtifactRelayPolicy::DirectRequired,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactRelayPolicy {
    #[default]
    DirectRequired,
    RelayFallbackAllowed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterfluxDeploymentMode {
    HostedPublic,
    SelfHosted,
    LocalOffline,
}

impl ClusterfluxDeploymentMode {
    pub fn default_artifact_relay_policy(self) -> ArtifactRelayPolicy {
        match self {
            Self::HostedPublic | Self::LocalOffline => ArtifactRelayPolicy::DirectRequired,
            Self::SelfHosted => ArtifactRelayPolicy::RelayFallbackAllowed,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ClusterfluxPathKind {
    Local,
    Direct,
    Relayed,
    #[default]
    Unknown,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTransferPhase {
    #[default]
    Queued,
    Connecting,
    WaitingForDirect,
    Transferring,
    Verifying,
    Complete,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAssignmentState {
    #[default]
    Offered,
    Acknowledged,
    Ready,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactAssignmentRole {
    Provider,
    Receiver,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTransferRetryClass {
    RetrySameSource,
    TryAnotherSource,
    WaitAndRetryPath,
    PermanentSourceInvalidation,
    DoNotRetry,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct IrohEndpointAdvertisement {
    pub tenant: TenantId,
    pub project: ProjectId,
    pub node: NodeId,
    pub endpoint_id: String,
    pub generation: u64,
    pub relay_configuration_generation: u64,
    pub direct_addresses: Vec<SocketAddr>,
    pub relay_urls: Vec<String>,
    pub expires_at: u64,
}

impl IrohEndpointAdvertisement {
    pub fn validate_bounds(&self) -> Result<(), String> {
        validate_endpoint_id(&self.endpoint_id)?;
        if self.direct_addresses.len() > MAX_ENDPOINT_DIRECT_ADDRESSES {
            return Err("Iroh endpoint advertisement has too many direct addresses".to_owned());
        }
        validate_relay_urls(&self.relay_urls)?;
        if self.generation == 0 || self.relay_configuration_generation == 0 {
            return Err("Iroh endpoint advertisement generations must be non-zero".to_owned());
        }
        Ok(())
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactTransferLease {
    pub transfer_id: String,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub artifact: ArtifactId,
    pub digest: Digest,
    pub size_bytes: u64,
    pub source_node: NodeId,
    pub source_endpoint_id: String,
    pub destination_node: NodeId,
    pub destination_endpoint_id: String,
    pub allowed_offset: u64,
    pub maximum_bytes: u64,
    pub relay_policy: ArtifactRelayPolicy,
    #[serde(default)]
    pub direct_path_deadline_ms: u64,
    /// Short-lived authorization for opening or resuming the body stream.
    pub expires_at: u64,
    /// Renewable lifetime for coordinator need, provider pins, and receiver partials.
    #[serde(default)]
    pub active_lease_expires_at: u64,
    pub nonce: String,
}

impl ArtifactTransferLease {
    pub fn validate_bounds(&self) -> Result<(), String> {
        if self.transfer_id.is_empty() || self.transfer_id.len() > MAX_TRANSFER_ID_BYTES {
            return Err("artifact transfer ID is empty or exceeds its size limit".to_owned());
        }
        validate_endpoint_id(&self.source_endpoint_id)?;
        validate_endpoint_id(&self.destination_endpoint_id)?;
        if self.nonce.is_empty() || self.nonce.len() > MAX_TRANSFER_ID_BYTES {
            return Err("artifact transfer lease has an invalid nonce".to_owned());
        }
        if self.allowed_offset > self.size_bytes {
            return Err("artifact transfer lease offset exceeds artifact size".to_owned());
        }
        let remaining = self.size_bytes.saturating_sub(self.allowed_offset);
        if self.maximum_bytes < remaining {
            return Err(
                "artifact transfer lease byte limit is smaller than the permitted range".to_owned(),
            );
        }
        if self.active_lease_expires_at != 0 && self.active_lease_expires_at < self.expires_at {
            return Err(
                "artifact active-transfer lease expires before its stream ticket".to_owned(),
            );
        }
        Ok(())
    }

    pub fn retention_expires_at(&self) -> u64 {
        self.active_lease_expires_at.max(self.expires_at)
    }

    pub fn permits_offset(&self, offset: u64) -> bool {
        offset >= self.allowed_offset
            && offset <= self.size_bytes
            && self.size_bytes.saturating_sub(offset) <= self.maximum_bytes
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AuthorizedPeerEndpoint {
    pub node: NodeId,
    pub endpoint_id: String,
    pub generation: u64,
    pub direct_addresses: Vec<SocketAddr>,
    pub relay_urls: Vec<String>,
}

impl AuthorizedPeerEndpoint {
    pub fn validate_bounds(&self) -> Result<(), String> {
        validate_endpoint_id(&self.endpoint_id)?;
        if self.generation == 0 {
            return Err("authorized peer endpoint generation must be non-zero".to_owned());
        }
        if self.direct_addresses.len() > MAX_ENDPOINT_DIRECT_ADDRESSES {
            return Err("authorized peer endpoint contains too many direct addresses".to_owned());
        }
        validate_relay_urls(&self.relay_urls)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactTransferAuthorization {
    pub lease: ArtifactTransferLease,
    pub transfer_secret: [u8; 32],
    pub peer: AuthorizedPeerEndpoint,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTransferState {
    Requested,
    SourceSelected,
    Connecting,
    WaitingForDirect,
    Transferring,
    Verifying,
    Completed,
    Retrying,
    Failed,
    Cancelled,
    Expired,
}

impl ArtifactTransferState {
    pub fn terminal(self) -> bool {
        matches!(
            self,
            Self::Completed | Self::Failed | Self::Cancelled | Self::Expired
        )
    }

    pub fn permits_transition_to(self, next: Self) -> bool {
        if self == next {
            return true;
        }
        match self {
            Self::Requested => matches!(
                next,
                Self::SourceSelected | Self::Failed | Self::Cancelled | Self::Expired
            ),
            Self::SourceSelected => matches!(
                next,
                Self::Connecting | Self::Retrying | Self::Failed | Self::Cancelled | Self::Expired
            ),
            Self::Connecting => matches!(
                next,
                Self::WaitingForDirect
                    | Self::Transferring
                    | Self::Retrying
                    | Self::Failed
                    | Self::Cancelled
                    | Self::Expired
            ),
            Self::WaitingForDirect => matches!(
                next,
                Self::Transferring
                    | Self::Retrying
                    | Self::Failed
                    | Self::Cancelled
                    | Self::Expired
            ),
            Self::Transferring => matches!(
                next,
                Self::Verifying | Self::Retrying | Self::Failed | Self::Cancelled | Self::Expired
            ),
            Self::Verifying => matches!(
                next,
                Self::Completed | Self::Retrying | Self::Failed | Self::Cancelled | Self::Expired
            ),
            Self::Retrying => matches!(
                next,
                Self::SourceSelected
                    | Self::Connecting
                    | Self::Failed
                    | Self::Cancelled
                    | Self::Expired
            ),
            Self::Completed | Self::Failed | Self::Cancelled | Self::Expired => false,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ArtifactTransferErrorCode {
    NoArtifactLocation,
    SourceNodeOffline,
    DestinationNodeOffline,
    EndpointAdvertisementMissing,
    RelayAssistUnavailable,
    DirectPathTimeout,
    RelayPathForbidden,
    ConnectionFailed,
    PeerIdentityMismatch,
    TransferLeaseRejected,
    TransferLeaseExpired,
    ArtifactMissingAtSource,
    RangeInvalid,
    DestinationDiskFull,
    SizeMismatch,
    DigestMismatch,
    TransferCancelled,
    CapacityUnavailable,
}

impl ArtifactTransferErrorCode {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::NoArtifactLocation => "no_artifact_location",
            Self::SourceNodeOffline => "source_node_offline",
            Self::DestinationNodeOffline => "destination_node_offline",
            Self::EndpointAdvertisementMissing => "endpoint_advertisement_missing",
            Self::RelayAssistUnavailable => "relay_assist_unavailable",
            Self::DirectPathTimeout => "direct_path_timeout",
            Self::RelayPathForbidden => "relay_path_forbidden",
            Self::ConnectionFailed => "connection_failed",
            Self::PeerIdentityMismatch => "peer_identity_mismatch",
            Self::TransferLeaseRejected => "transfer_lease_rejected",
            Self::TransferLeaseExpired => "transfer_lease_expired",
            Self::ArtifactMissingAtSource => "artifact_missing_at_source",
            Self::RangeInvalid => "range_invalid",
            Self::DestinationDiskFull => "destination_disk_full",
            Self::SizeMismatch => "size_mismatch",
            Self::DigestMismatch => "digest_mismatch",
            Self::TransferCancelled => "transfer_cancelled",
            Self::CapacityUnavailable => "capacity_unavailable",
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ArtifactTransferRecord {
    pub transfer_id: String,
    pub tenant: TenantId,
    pub project: ProjectId,
    pub process: ProcessId,
    pub artifact: ArtifactId,
    pub source_node: NodeId,
    pub destination_node: NodeId,
    pub bytes_completed: u64,
    pub path_kind: ClusterfluxPathKind,
    pub state: ArtifactTransferState,
    pub created_at: u64,
    pub updated_at: u64,
    /// Renewable active-transfer lease deadline.
    pub expires_at: u64,
    #[serde(default)]
    pub stream_ticket_expires_at: u64,
    #[serde(default)]
    pub last_progress_at: u64,
    #[serde(default)]
    pub total_bytes: u64,
    #[serde(default)]
    pub phase: ArtifactTransferPhase,
    pub failure_code: Option<ArtifactTransferErrorCode>,
    pub attempt_count: u32,
}

impl ArtifactTransferErrorCode {
    pub fn retry_class(self) -> ArtifactTransferRetryClass {
        match self {
            Self::DirectPathTimeout | Self::RelayPathForbidden => {
                ArtifactTransferRetryClass::WaitAndRetryPath
            }
            Self::RelayAssistUnavailable
            | Self::ConnectionFailed
            | Self::TransferLeaseExpired
            | Self::CapacityUnavailable
            | Self::SourceNodeOffline
            | Self::DestinationNodeOffline
            | Self::EndpointAdvertisementMissing => ArtifactTransferRetryClass::RetrySameSource,
            Self::ArtifactMissingAtSource | Self::SizeMismatch | Self::DigestMismatch => {
                ArtifactTransferRetryClass::PermanentSourceInvalidation
            }
            Self::PeerIdentityMismatch | Self::TransferLeaseRejected | Self::RangeInvalid => {
                ArtifactTransferRetryClass::TryAnotherSource
            }
            Self::NoArtifactLocation | Self::DestinationDiskFull | Self::TransferCancelled => {
                ArtifactTransferRetryClass::DoNotRetry
            }
        }
    }
}

fn validate_endpoint_id(endpoint_id: &str) -> Result<(), String> {
    if endpoint_id.is_empty() || endpoint_id.len() > MAX_ENDPOINT_ID_BYTES {
        return Err("Iroh endpoint ID is empty or exceeds its size limit".to_owned());
    }
    Ok(())
}

fn validate_relay_urls(relay_urls: &[String]) -> Result<(), String> {
    if relay_urls.len() > MAX_ENDPOINT_RELAY_URLS {
        return Err("Iroh endpoint contains too many relay URLs".to_owned());
    }
    if relay_urls
        .iter()
        .any(|url| url.is_empty() || url.len() > MAX_RELAY_URL_BYTES)
    {
        return Err("Iroh endpoint contains an invalid relay URL".to_owned());
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn deployment_defaults_keep_hosted_artifact_bytes_off_relays() {
        assert_eq!(
            ClusterfluxDeploymentMode::HostedPublic.default_artifact_relay_policy(),
            ArtifactRelayPolicy::DirectRequired
        );
        assert_eq!(
            ClusterfluxDeploymentMode::SelfHosted.default_artifact_relay_policy(),
            ArtifactRelayPolicy::RelayFallbackAllowed
        );
    }

    #[test]
    fn all_failure_codes_have_stable_snake_case_values() {
        assert_eq!(
            ArtifactTransferErrorCode::PeerIdentityMismatch.as_str(),
            "peer_identity_mismatch"
        );
        assert_eq!(
            ArtifactTransferErrorCode::DestinationDiskFull.as_str(),
            "destination_disk_full"
        );
    }

    #[test]
    fn relay_configuration_debug_redacts_access_tokens() {
        let configuration = ClusterfluxRelayConfig {
            url: "https://relay.example".to_owned(),
            access_token: Some("relay-secret-value".to_owned()),
        };
        let rendered = format!("{configuration:?}");
        assert!(rendered.contains("https://relay.example"));
        assert!(rendered.contains("[REDACTED]"));
        assert!(!rendered.contains("relay-secret-value"));

        let configuration = ClusterfluxRelayConfig {
            url: "https://relay.example?access_token=url-secret".to_owned(),
            access_token: None,
        };
        let rendered = format!("{configuration:?}");
        assert!(rendered.contains("[REDACTED URL]"));
        assert!(!rendered.contains("url-secret"));
    }
}
