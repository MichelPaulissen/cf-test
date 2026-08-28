use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clusterflux_artifact_transfer::{
    ArtifactDataPlaneMetrics, ArtifactProviderRegistry, ArtifactProviderServer, ArtifactReceiver,
    EndpointBindConfig, IrohIdentityScope, PartialStoreConfig, PathPolicyMetrics,
    PersistentIrohIdentity,
};
use clusterflux_core::{
    ArtifactId, ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferLease,
    AuthorizedPeerEndpoint, ClusterfluxPathKind, ClusterfluxRelayConfig, Digest,
    IrohRelayConfiguration, NodeId, ProcessId, ProjectId, TenantId,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CLUSTERFLUX_TEST_RELAY_URL and CLUSTERFLUX_TEST_RELAY_TOKEN"]
async fn self_hosted_relay_only_transfer_is_verified_and_metered() {
    run_live_relay_transfer(LiveRelayTopology::RelayOnlyFallback).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires CLUSTERFLUX_TEST_RELAY_URL and CLUSTERFLUX_TEST_RELAY_TOKEN"]
async fn custom_relay_assists_direct_path_before_body_stream() {
    run_live_relay_transfer(LiveRelayTopology::RelayAssistedDirect).await;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LiveRelayTopology {
    RelayOnlyFallback,
    RelayAssistedDirect,
}

async fn run_live_relay_transfer(topology: LiveRelayTopology) {
    let relay_url = std::env::var("CLUSTERFLUX_TEST_RELAY_URL")
        .expect("CLUSTERFLUX_TEST_RELAY_URL is required");
    let relay_token = std::env::var("CLUSTERFLUX_TEST_RELAY_TOKEN")
        .expect("CLUSTERFLUX_TEST_RELAY_TOKEN is required");
    let relay = IrohRelayConfiguration::Custom(vec![ClusterfluxRelayConfig {
        url: relay_url.clone(),
        access_token: Some(relay_token),
    }]);
    let relay_config = EndpointBindConfig { relay };

    let temp = tempfile::tempdir().unwrap();
    let tenant = TenantId::from("relay-test-tenant");
    let project = ProjectId::from("relay-test-project");
    let source_node = NodeId::from("relay-source");
    let destination_node = NodeId::from("relay-destination");
    let source_identity = PersistentIrohIdentity::load_or_create(
        temp.path().join("source-identity/iroh.json"),
        IrohIdentityScope {
            tenant: tenant.clone(),
            project: project.clone(),
            node: source_node.clone(),
        },
    )
    .unwrap();
    let destination_identity = PersistentIrohIdentity::load_or_create(
        temp.path().join("destination-identity/iroh.json"),
        IrohIdentityScope {
            tenant: tenant.clone(),
            project: project.clone(),
            node: destination_node.clone(),
        },
    )
    .unwrap();
    let (source_endpoint, destination_endpoint) = match topology {
        LiveRelayTopology::RelayOnlyFallback => (
            clusterflux_artifact_transfer::ClusterfluxEndpoint::bind_relay_only_for_diagnostics(
                &source_identity,
                relay_config.clone(),
            )
            .await
            .unwrap(),
            clusterflux_artifact_transfer::ClusterfluxEndpoint::bind_relay_only_for_diagnostics(
                &destination_identity,
                relay_config,
            )
            .await
            .unwrap(),
        ),
        LiveRelayTopology::RelayAssistedDirect => (
            clusterflux_artifact_transfer::ClusterfluxEndpoint::bind(
                &source_identity,
                relay_config.clone(),
            )
            .await
            .unwrap(),
            clusterflux_artifact_transfer::ClusterfluxEndpoint::bind(
                &destination_identity,
                relay_config,
            )
            .await
            .unwrap(),
        ),
    };

    let bytes = (0..1_500_000_u32)
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>();
    let digest = Digest::sha256(&bytes);
    let artifact = ArtifactId::from("relay-only-release-asset");
    let source_path = temp.path().join("source-artifact");
    std::fs::write(&source_path, &bytes).unwrap();
    let now = now();
    let lease = ArtifactTransferLease {
        transfer_id: "transfer-relay-only".to_owned(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: ProcessId::from("relay-only-process"),
        artifact: artifact.clone(),
        digest: digest.clone(),
        size_bytes: bytes.len() as u64,
        source_node: source_node.clone(),
        source_endpoint_id: source_endpoint.endpoint_id(),
        destination_node: destination_node.clone(),
        destination_endpoint_id: destination_endpoint.endpoint_id(),
        allowed_offset: 0,
        maximum_bytes: bytes.len() as u64,
        relay_policy: match topology {
            LiveRelayTopology::RelayOnlyFallback => ArtifactRelayPolicy::RelayFallbackAllowed,
            LiveRelayTopology::RelayAssistedDirect => ArtifactRelayPolicy::DirectRequired,
        },
        direct_path_deadline_ms: 20_000,
        expires_at: now + 120,
        active_lease_expires_at: now + 120,
        nonce: "relay-only-single-use-nonce".to_owned(),
    };
    let transfer_secret = [47_u8; 32];
    let provider = ArtifactProviderRegistry::new(source_endpoint.endpoint_id(), 8);
    provider
        .register_verified_source(lease.clone(), transfer_secret, &source_path, now)
        .await
        .unwrap();
    let source_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let source_path_metrics = Arc::new(PathPolicyMetrics::default());
    let server = ArtifactProviderServer::start(
        &source_endpoint,
        provider,
        source_metrics.clone(),
        source_path_metrics.clone(),
    );

    let advertised = source_endpoint.advertisement(1, now + 120).unwrap();
    match topology {
        LiveRelayTopology::RelayOnlyFallback => assert!(advertised.direct_addresses.is_empty()),
        LiveRelayTopology::RelayAssistedDirect => {
            assert!(!advertised.direct_addresses.is_empty())
        }
    }
    assert_eq!(advertised.relay_urls.len(), 1);
    assert_eq!(
        advertised.relay_urls[0].trim_end_matches('/'),
        relay_url.trim_end_matches('/')
    );
    let authorization = ArtifactTransferAuthorization {
        lease,
        transfer_secret,
        peer: AuthorizedPeerEndpoint {
            node: source_node,
            endpoint_id: advertised.endpoint_id,
            generation: advertised.generation,
            // Dial through the configured relay first. With IP transports enabled,
            // Iroh exchanges candidates over that path and must migrate to direct
            // before a DirectRequired artifact stream can open.
            direct_addresses: Vec::new(),
            relay_urls: advertised.relay_urls,
        },
    };
    let destination_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let destination_path_metrics = Arc::new(PathPolicyMetrics::default());
    let receiver = ArtifactReceiver::new(
        destination_endpoint.clone(),
        PartialStoreConfig::new(temp.path().join("destination-store/.partials")),
        destination_metrics.clone(),
        destination_path_metrics.clone(),
    )
    .unwrap()
    .with_path_deadlines(Duration::from_secs(10), Duration::ZERO);
    let destination_path = temp.path().join("destination-store/artifact");
    let completed = receiver
        .download(&authorization, &destination_path, now)
        .await
        .unwrap();

    assert_eq!(completed.digest, digest);
    assert_eq!(completed.bytes_transferred, bytes.len() as u64);
    assert_eq!(std::fs::read(&destination_path).unwrap(), bytes);
    let source_snapshot = source_metrics.snapshot();
    let destination_snapshot = destination_metrics.snapshot();
    match topology {
        LiveRelayTopology::RelayOnlyFallback => {
            assert_eq!(completed.path_kind, ClusterfluxPathKind::Relayed);
            assert_eq!(source_snapshot.direct_body_bytes, 0);
            assert_eq!(destination_snapshot.direct_body_bytes, 0);
            assert_eq!(source_snapshot.relayed_body_bytes, bytes.len() as u64);
            assert_eq!(destination_snapshot.relayed_body_bytes, bytes.len() as u64);
            assert!(source_path_metrics.selected_relay() > 0);
            assert!(destination_path_metrics.selected_relay() > 0);
        }
        LiveRelayTopology::RelayAssistedDirect => {
            assert_eq!(completed.path_kind, ClusterfluxPathKind::Direct);
            assert_eq!(source_snapshot.direct_body_bytes, bytes.len() as u64);
            assert_eq!(destination_snapshot.direct_body_bytes, bytes.len() as u64);
            assert_eq!(source_snapshot.relayed_body_bytes, 0);
            assert_eq!(destination_snapshot.relayed_body_bytes, 0);
            assert!(source_path_metrics.selected_direct() > 0);
            assert!(destination_path_metrics.selected_direct() > 0);
        }
    }

    receiver.close_connections().await;
    server.shutdown().await.unwrap();
    destination_endpoint.close().await;
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
