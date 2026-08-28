use std::collections::BTreeSet;
use std::str::FromStr;

use clusterflux_core::{
    AuthorizedPeerEndpoint, IrohEndpointAdvertisement, IrohRelayConfiguration,
    CLUSTERFLUX_ARTIFACT_ALPN, MAX_ENDPOINT_DIRECT_ADDRESSES, MAX_ENDPOINT_RELAY_URLS,
};
use iroh::{
    endpoint::presets, Endpoint, EndpointAddr, EndpointId, RelayConfig, RelayMap, RelayMode,
    RelayUrl, TransportAddr,
};
use thiserror::Error;

use crate::{
    IrohIdentityScope, PathPolicy, PathPolicyError, PathPolicyMetrics, PersistentIrohIdentity,
};

#[derive(Clone, Debug)]
pub struct EndpointBindConfig {
    pub relay: IrohRelayConfiguration,
}

impl Default for EndpointBindConfig {
    fn default() -> Self {
        Self {
            relay: IrohRelayConfiguration::Disabled,
        }
    }
}

#[derive(Clone, Debug)]
pub struct ClusterfluxEndpoint {
    endpoint: Endpoint,
    identity_scope: IrohIdentityScope,
    identity_generation: u64,
    configured_relays: BTreeSet<String>,
}

impl ClusterfluxEndpoint {
    pub async fn bind(
        identity: &PersistentIrohIdentity,
        config: EndpointBindConfig,
    ) -> Result<Self, EndpointError> {
        Self::bind_with_ip_transports(identity, config, true, false).await
    }

    /// Construct a relay-only endpoint for controlled topology diagnostics.
    /// Production nodes must use [`Self::bind`] so direct paths remain available.
    #[doc(hidden)]
    pub async fn bind_relay_only_for_diagnostics(
        identity: &PersistentIrohIdentity,
        config: EndpointBindConfig,
    ) -> Result<Self, EndpointError> {
        Self::bind_with_ip_transports(identity, config, false, false).await
    }

    /// Construct an IPv6-only endpoint for controlled topology diagnostics.
    /// Production nodes must use [`Self::bind`] so all host IP transports remain available.
    #[doc(hidden)]
    pub async fn bind_ipv6_only_for_diagnostics(
        identity: &PersistentIrohIdentity,
        config: EndpointBindConfig,
    ) -> Result<Self, EndpointError> {
        Self::bind_with_ip_transports(identity, config, true, true).await
    }

    async fn bind_with_ip_transports(
        identity: &PersistentIrohIdentity,
        config: EndpointBindConfig,
        enable_ip_transports: bool,
        ipv6_only: bool,
    ) -> Result<Self, EndpointError> {
        let (relay_mode, configured_relays) = relay_mode(&config.relay)?;
        // Minimal supplies only the mandatory crypto provider. Address lookup remains empty,
        // and only the explicitly supplied Clusterflux relay map can be installed.
        let mut builder = Endpoint::builder(presets::Minimal)
            .secret_key(identity.secret_key())
            .alpns(vec![CLUSTERFLUX_ARTIFACT_ALPN.to_vec()])
            .clear_address_lookup()
            .relay_mode(relay_mode);
        if !enable_ip_transports {
            builder = builder.clear_ip_transports();
        } else if ipv6_only {
            builder = builder
                .clear_ip_transports()
                .bind_addr("[::]:0")
                .map_err(|error| EndpointError::Bind(error.to_string()))?;
        }
        let endpoint = builder
            .bind()
            .await
            .map_err(|error| EndpointError::Bind(error.to_string()))?;
        if endpoint.id().to_string() != identity.endpoint_id() {
            endpoint.close().await;
            return Err(EndpointError::LocalIdentityMismatch);
        }
        Ok(Self {
            endpoint,
            identity_scope: identity.scope().clone(),
            identity_generation: identity.generation(),
            configured_relays,
        })
    }

    pub fn endpoint_id(&self) -> String {
        self.endpoint.id().to_string()
    }

    pub fn identity_scope(&self) -> &IrohIdentityScope {
        &self.identity_scope
    }

    pub fn advertisement(
        &self,
        relay_configuration_generation: u64,
        expires_at: u64,
    ) -> Result<IrohEndpointAdvertisement, EndpointError> {
        let address = self.endpoint.addr();
        let direct_addresses = address
            .addrs
            .iter()
            .filter_map(|address| match address {
                TransportAddr::Ip(address) => Some(*address),
                _ => None,
            })
            .take(MAX_ENDPOINT_DIRECT_ADDRESSES)
            .collect::<Vec<_>>();
        let relay_urls = address
            .addrs
            .iter()
            .filter_map(|address| match address {
                TransportAddr::Relay(url) => Some(url.to_string()),
                _ => None,
            })
            .take(MAX_ENDPOINT_RELAY_URLS)
            .collect::<Vec<_>>();
        let advertisement = IrohEndpointAdvertisement {
            tenant: self.identity_scope.tenant.clone(),
            project: self.identity_scope.project.clone(),
            node: self.identity_scope.node.clone(),
            endpoint_id: self.endpoint_id(),
            generation: self.identity_generation,
            relay_configuration_generation,
            direct_addresses,
            relay_urls,
            expires_at,
        };
        advertisement
            .validate_bounds()
            .map_err(EndpointError::InvalidAdvertisement)?;
        Ok(advertisement)
    }

    pub async fn probe_authorized_peer(
        &self,
        peer: &AuthorizedPeerEndpoint,
        policy: &PathPolicy,
        metrics: &PathPolicyMetrics,
    ) -> Result<clusterflux_core::ClusterfluxPathKind, EndpointError> {
        let address = self.authorized_endpoint_addr(peer)?;
        let connection = self
            .endpoint
            .connect(address, CLUSTERFLUX_ARTIFACT_ALPN)
            .await
            .map_err(|error| EndpointError::Connect(error.to_string()))?;
        let expected = EndpointId::from_str(&peer.endpoint_id)
            .map_err(|error| EndpointError::InvalidEndpointId(error.to_string()))?;
        if connection.remote_id() != expected {
            connection.close(1_u32.into(), b"peer identity mismatch");
            return Err(EndpointError::PeerIdentityMismatch);
        }
        let result = policy
            .wait_for_permitted_path(&connection, metrics)
            .await
            .map_err(EndpointError::PathPolicy);
        connection.close(0_u32.into(), b"path probe complete");
        result
    }

    pub async fn close(self) {
        self.endpoint.close().await;
    }

    pub(crate) fn endpoint(&self) -> &Endpoint {
        &self.endpoint
    }

    pub(crate) fn authorized_endpoint_addr(
        &self,
        peer: &AuthorizedPeerEndpoint,
    ) -> Result<EndpointAddr, EndpointError> {
        peer.validate_bounds()
            .map_err(EndpointError::InvalidPeerAddress)?;
        let endpoint_id = EndpointId::from_str(&peer.endpoint_id)
            .map_err(|error| EndpointError::InvalidEndpointId(error.to_string()))?;
        let mut addresses = peer
            .direct_addresses
            .iter()
            .copied()
            .map(TransportAddr::Ip)
            .collect::<Vec<_>>();
        for relay in &peer.relay_urls {
            let parsed = parse_clusterflux_relay_url(relay)?;
            if !self.configured_relays.contains(&parsed.to_string()) {
                return Err(EndpointError::UnconfiguredPeerRelay);
            }
            addresses.push(TransportAddr::Relay(parsed));
        }
        if addresses.is_empty() {
            return Err(EndpointError::PeerHasNoAuthorizedAddress);
        }
        Ok(EndpointAddr::from_parts(endpoint_id, addresses))
    }
}

fn relay_mode(
    configuration: &IrohRelayConfiguration,
) -> Result<(RelayMode, BTreeSet<String>), EndpointError> {
    match configuration {
        IrohRelayConfiguration::Disabled => Ok((RelayMode::Disabled, BTreeSet::new())),
        IrohRelayConfiguration::Custom(relays) => {
            if relays.is_empty() || relays.len() > MAX_ENDPOINT_RELAY_URLS {
                return Err(EndpointError::InvalidRelayConfiguration);
            }
            let mut urls = BTreeSet::new();
            let configs = relays
                .iter()
                .map(|relay| {
                    let url = parse_clusterflux_relay_url(&relay.url)?;
                    if !urls.insert(url.to_string()) {
                        return Err(EndpointError::DuplicateRelayUrl);
                    }
                    let config = RelayConfig::from(url);
                    Ok(match &relay.access_token {
                        Some(token) if !token.is_empty() && token.len() <= 4_096 => {
                            config.with_auth_token(token.clone())
                        }
                        Some(_) => return Err(EndpointError::InvalidRelayAccessToken),
                        None => config,
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            Ok((RelayMode::Custom(RelayMap::from_iter(configs)), urls))
        }
    }
}

fn parse_clusterflux_relay_url(value: &str) -> Result<RelayUrl, EndpointError> {
    let url = RelayUrl::from_str(value)
        .map_err(|error| EndpointError::InvalidRelayUrl(error.to_string()))?;
    if !matches!(url.scheme(), "https" | "http") {
        return Err(EndpointError::InvalidRelayUrl(
            "relay URL must use HTTP or HTTPS".to_owned(),
        ));
    }
    let host = url.host_str().unwrap_or_default().trim_end_matches('.');
    if host.is_empty() || is_public_iroh_domain(host) {
        return Err(EndpointError::PublicIrohServiceForbidden);
    }
    Ok(url)
}

fn is_public_iroh_domain(host: &str) -> bool {
    let host = host.to_ascii_lowercase();
    ["iroh.link", "iroh.computer", "n0.computer"]
        .iter()
        .any(|domain| host == *domain || host.ends_with(&format!(".{domain}")))
}

#[derive(Debug, Error)]
pub enum EndpointError {
    #[error("Iroh endpoint bind failed: {0}")]
    Bind(String),
    #[error("Iroh connection failed: {0}")]
    Connect(String),
    #[error("Iroh endpoint does not match the persistent node identity")]
    LocalIdentityMismatch,
    #[error("authorized Iroh endpoint ID is invalid: {0}")]
    InvalidEndpointId(String),
    #[error("Iroh authenticated peer identity differs from the authorized endpoint")]
    PeerIdentityMismatch,
    #[error("Iroh relay configuration is empty or exceeds its bound")]
    InvalidRelayConfiguration,
    #[error("Iroh relay URL is duplicated")]
    DuplicateRelayUrl,
    #[error("Iroh relay access token is empty or exceeds its bound")]
    InvalidRelayAccessToken,
    #[error("Iroh relay URL is invalid: {0}")]
    InvalidRelayUrl(String),
    #[error("Iroh public relay and discovery services are forbidden")]
    PublicIrohServiceForbidden,
    #[error("peer advertised a relay that is not in the coordinator-delivered relay policy")]
    UnconfiguredPeerRelay,
    #[error("authorized Iroh peer has no direct address or configured relay")]
    PeerHasNoAuthorizedAddress,
    #[error("authorized Iroh peer address is invalid: {0}")]
    InvalidPeerAddress(String),
    #[error("local Iroh endpoint advertisement is invalid: {0}")]
    InvalidAdvertisement(String),
    #[error(transparent)]
    PathPolicy(#[from] PathPolicyError),
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{ClusterfluxRelayConfig, NodeId, ProjectId, TenantId};

    use super::*;

    #[test]
    fn public_iroh_relays_are_rejected_from_production_configuration() {
        let configuration = IrohRelayConfiguration::Custom(vec![ClusterfluxRelayConfig {
            url: "https://use1-1.relay.n0.iroh.link".to_owned(),
            access_token: None,
        }]);
        assert!(matches!(
            relay_mode(&configuration),
            Err(EndpointError::PublicIrohServiceForbidden)
        ));
    }

    #[tokio::test]
    async fn minimal_endpoint_starts_without_public_services() {
        let temp = tempfile::tempdir().unwrap();
        let identity = PersistentIrohIdentity::load_or_create(
            temp.path().join("node/iroh.json"),
            IrohIdentityScope {
                tenant: TenantId::from("tenant"),
                project: ProjectId::from("project"),
                node: NodeId::from("node"),
            },
        )
        .unwrap();
        let endpoint = ClusterfluxEndpoint::bind(&identity, EndpointBindConfig::default())
            .await
            .unwrap();
        assert_eq!(endpoint.endpoint_id(), identity.endpoint_id());
        let advertisement = endpoint.advertisement(1, u64::MAX).unwrap();
        assert!(advertisement.relay_urls.is_empty());
        endpoint.close().await;
    }
}
