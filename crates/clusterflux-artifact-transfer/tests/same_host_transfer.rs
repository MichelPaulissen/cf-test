use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clusterflux_artifact_transfer::{
    ArtifactDataPlaneMetrics, ArtifactProviderRegistry, ArtifactProviderServer, ArtifactReceiver,
    EndpointBindConfig, IrohIdentityScope, PartialStoreConfig, PathPolicyMetrics,
    PersistentIrohIdentity,
};
use clusterflux_core::{
    ArtifactId, ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferLease,
    AuthorizedPeerEndpoint, Digest, NodeId, ProcessId, ProjectId, TenantId,
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn same_host_transfer_is_authenticated_direct_raw_and_verified() {
    let temp = tempfile::tempdir().unwrap();
    let tenant = TenantId::from("tenant");
    let project = ProjectId::from("project");
    let source_node = NodeId::from("source");
    let destination_node = NodeId::from("destination");
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
    let source_endpoint = clusterflux_artifact_transfer::ClusterfluxEndpoint::bind(
        &source_identity,
        EndpointBindConfig::default(),
    )
    .await
    .unwrap();
    let destination_endpoint = clusterflux_artifact_transfer::ClusterfluxEndpoint::bind(
        &destination_identity,
        EndpointBindConfig::default(),
    )
    .await
    .unwrap();

    let bytes = (0..2_500_000_u32)
        .flat_map(u32::to_be_bytes)
        .collect::<Vec<_>>();
    let digest = Digest::sha256(&bytes);
    let artifact = ArtifactId::from("cross-node-release-asset");
    let source_path = temp.path().join("source-artifact");
    std::fs::write(&source_path, &bytes).unwrap();
    let now = now();
    let lease = ArtifactTransferLease {
        transfer_id: "transfer-same-host".to_owned(),
        tenant: tenant.clone(),
        project: project.clone(),
        process: ProcessId::from("process"),
        artifact: artifact.clone(),
        digest: digest.clone(),
        size_bytes: bytes.len() as u64,
        source_node: source_node.clone(),
        source_endpoint_id: source_endpoint.endpoint_id(),
        destination_node: destination_node.clone(),
        destination_endpoint_id: destination_endpoint.endpoint_id(),
        allowed_offset: 0,
        maximum_bytes: bytes.len() as u64,
        relay_policy: ArtifactRelayPolicy::DirectRequired,
        direct_path_deadline_ms: 5_000,
        expires_at: now + 60,
        active_lease_expires_at: now + 60,
        nonce: "single-use-nonce".to_owned(),
    };
    let transfer_secret = [29_u8; 32];
    let provider = ArtifactProviderRegistry::new(source_endpoint.endpoint_id(), 8);
    provider
        .register_verified_source(lease.clone(), transfer_secret, &source_path, now)
        .await
        .unwrap();
    let source_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let source_path_metrics = Arc::new(PathPolicyMetrics::default());
    let server = ArtifactProviderServer::start(
        &source_endpoint,
        provider.clone(),
        source_metrics.clone(),
        source_path_metrics,
    );

    let advertised = source_endpoint.advertisement(1, now + 60).unwrap();
    assert!(advertised.relay_urls.is_empty());
    assert!(!advertised.direct_addresses.is_empty());
    let authorization = ArtifactTransferAuthorization {
        lease,
        transfer_secret,
        peer: AuthorizedPeerEndpoint {
            node: source_node,
            endpoint_id: advertised.endpoint_id,
            generation: advertised.generation,
            direct_addresses: advertised.direct_addresses,
            relay_urls: advertised.relay_urls,
        },
    };
    let destination_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let partial_root = temp.path().join("destination-store/.partials");
    std::fs::create_dir_all(&partial_root).unwrap();
    let partial_stem = Digest::from_parts([
        tenant.as_str().as_bytes(),
        project.as_str().as_bytes(),
        destination_node.as_str().as_bytes(),
        artifact.as_str().as_bytes(),
        digest.as_str().as_bytes(),
    ])
    .as_str()
    .trim_start_matches("sha256:")
    .to_owned();
    let resume_offset = 1_337_777_usize;
    std::fs::write(
        partial_root.join(format!("{partial_stem}.partial")),
        &bytes[..resume_offset],
    )
    .unwrap();
    let receiver = ArtifactReceiver::new(
        destination_endpoint.clone(),
        PartialStoreConfig::new(partial_root),
        destination_metrics.clone(),
        Arc::new(PathPolicyMetrics::default()),
    )
    .unwrap()
    .with_path_deadlines(Duration::from_secs(10), Duration::from_millis(100));
    let destination_path = temp
        .path()
        .join("destination-store")
        .join(artifact.as_str());
    let completed = receiver
        .download(&authorization, &destination_path, now)
        .await
        .unwrap();

    assert_eq!(completed.resumed_from, resume_offset as u64);
    assert_eq!(
        completed.bytes_transferred,
        (bytes.len() - resume_offset) as u64
    );
    assert_eq!(completed.digest, digest);
    assert_eq!(
        completed.path_kind,
        clusterflux_core::ClusterfluxPathKind::Direct
    );
    assert_eq!(std::fs::read(&destination_path).unwrap(), bytes);
    let already_present = receiver
        .download(&authorization, &destination_path, now)
        .await
        .unwrap();
    assert!(already_present.already_present);
    assert_eq!(already_present.resumed_from, bytes.len() as u64);
    assert_eq!(already_present.bytes_transferred, 0);
    assert_eq!(
        provider.pinned_artifacts(now).await,
        std::iter::once(artifact.clone()).collect()
    );
    assert!(provider.pinned_artifacts(now + 61).await.is_empty());
    let destination_snapshot = destination_metrics.snapshot();
    assert_eq!(
        destination_snapshot.direct_body_bytes,
        (bytes.len() - resume_offset) as u64
    );
    assert_eq!(destination_snapshot.relayed_body_bytes, 0);
    assert_eq!(destination_snapshot.completed_transfers, 1);
    let expected_source_bytes = (bytes.len() - resume_offset) as u64;
    let source_snapshot = tokio::time::timeout(Duration::from_secs(2), async {
        loop {
            let snapshot = source_metrics.snapshot();
            if snapshot.direct_body_bytes + snapshot.relayed_body_bytes >= expected_source_bytes {
                break snapshot;
            }
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("provider metrics must settle after the receiver verifies the stream");
    assert_eq!(source_snapshot.direct_body_bytes, expected_source_bytes);
    assert_eq!(source_snapshot.relayed_body_bytes, 0);

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
