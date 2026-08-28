use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use clusterflux_artifact_transfer::{
    ArtifactDataPlaneMetrics, ArtifactProviderRegistry, ArtifactProviderServer, ArtifactReceiver,
    ClusterfluxEndpoint, EndpointBindConfig, IrohIdentityScope, PartialStoreConfig,
    PathPolicyMetrics, PersistentIrohIdentity,
};
use clusterflux_core::{
    ArtifactId, ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferErrorCode,
    ArtifactTransferLease, AuthorizedPeerEndpoint, ClusterfluxPathKind, ClusterfluxRelayConfig,
    Digest, IrohEndpointAdvertisement, IrohRelayConfiguration, NodeId, ProcessId, ProjectId,
    TenantId,
};
use serde_json::json;

const QUALIFYING_DURATION_SECONDS: u64 = 2 * 60 * 60;
const DEFAULT_PHASE_SECONDS: u64 = 5 * 60;
const DEFAULT_INTERVAL_MILLISECONDS: u64 = 500;
const ARTIFACT_BYTES: usize = 64 * 1024;
const RELAY_TRANSFER_INTERVAL: u64 = 10;
const PARTIAL_GC_INTERVAL: u64 = 10;
const MAXIMUM_TRANSFER_ATTEMPTS: u64 = 4;
const MAXIMUM_RSS_BYTES: u64 = 512 * 1024 * 1024;
const MAXIMUM_RSS_GROWTH_BYTES: u64 = 192 * 1024 * 1024;

#[derive(Debug, Default)]
struct SoakTotals {
    phases: u64,
    direct_transfers: u64,
    relayed_transfers: u64,
    transient_retries: u64,
    resumed_transfers: u64,
    partials_collected: u64,
    direct_source_body_bytes: u64,
    direct_destination_body_bytes: u64,
    relay_source_body_bytes: u64,
    relay_destination_body_bytes: u64,
    unknown_path_body_bytes: u64,
    direct_selected: u64,
    relay_selected: u64,
    minimum_rss_bytes: u64,
    maximum_rss_bytes: u64,
    maximum_partial_entries: usize,
}

#[derive(Debug)]
struct PhaseEvidence {
    direct_transfers: u64,
    relayed_transfers: u64,
    transient_retries: u64,
    resumed_transfers: u64,
    partials_collected: u64,
    direct_source_body_bytes: u64,
    direct_destination_body_bytes: u64,
    relay_source_body_bytes: u64,
    relay_destination_body_bytes: u64,
    unknown_path_body_bytes: u64,
    direct_selected: u64,
    relay_selected: u64,
    minimum_rss_bytes: u64,
    maximum_rss_bytes: u64,
    maximum_partial_entries: usize,
    endpoint_ids: [String; 4],
}

#[derive(Clone, Copy, Debug)]
struct TransferOutcome {
    retries: u64,
    resumed: bool,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "qualifying run lasts at least two hours and requires an isolated Clusterflux relay"]
async fn connection_partial_gc_soak_is_bounded() {
    let duration_seconds = environment_u64(
        "CLUSTERFLUX_ARTIFACT_SOAK_SECONDS",
        QUALIFYING_DURATION_SECONDS,
    );
    let allow_short = std::env::var("CLUSTERFLUX_ARTIFACT_SOAK_ALLOW_SHORT")
        .ok()
        .as_deref()
        == Some("1");
    assert!(
        duration_seconds >= QUALIFYING_DURATION_SECONDS || allow_short,
        "a qualifying soak must run for at least {QUALIFYING_DURATION_SECONDS} seconds"
    );
    let phase_seconds = environment_u64(
        "CLUSTERFLUX_ARTIFACT_SOAK_PHASE_SECONDS",
        DEFAULT_PHASE_SECONDS,
    )
    .clamp(10, duration_seconds.max(10));
    let interval = Duration::from_millis(
        environment_u64(
            "CLUSTERFLUX_ARTIFACT_SOAK_INTERVAL_MS",
            DEFAULT_INTERVAL_MILLISECONDS,
        )
        .clamp(25, 10_000),
    );
    let relay = relay_configuration();
    let temp = tempfile::tempdir().unwrap();
    let bytes = (0..ARTIFACT_BYTES)
        .map(|offset| ((offset * 31 + 17) % 251) as u8)
        .collect::<Vec<_>>();
    let digest = Digest::sha256(&bytes);
    let direct_source_path = temp.path().join("direct-source-artifact");
    let relay_source_path = temp.path().join("relay-source-artifact");
    std::fs::write(&direct_source_path, &bytes).unwrap();
    std::fs::write(&relay_source_path, &bytes).unwrap();

    let started = Instant::now();
    let deadline = started + Duration::from_secs(duration_seconds);
    let mut totals = SoakTotals {
        minimum_rss_bytes: u64::MAX,
        ..SoakTotals::default()
    };
    let mut persistent_endpoint_ids: Option<[String; 4]> = None;
    while Instant::now() < deadline {
        let remaining = deadline.saturating_duration_since(Instant::now());
        if remaining < Duration::from_secs(10) {
            tokio::time::sleep(remaining).await;
            break;
        }
        let phase_deadline = deadline.min(Instant::now() + Duration::from_secs(phase_seconds));
        let evidence = run_phase(
            temp.path(),
            relay.clone(),
            totals.phases.saturating_add(1),
            phase_deadline,
            interval,
            &direct_source_path,
            &relay_source_path,
            &digest,
            bytes.len() as u64,
        )
        .await;
        if let Some(expected) = &persistent_endpoint_ids {
            assert_eq!(
                &evidence.endpoint_ids, expected,
                "node reconnect changed a persistent endpoint identity"
            );
        } else {
            persistent_endpoint_ids = Some(evidence.endpoint_ids.clone());
        }
        totals.phases = totals.phases.saturating_add(1);
        totals.direct_transfers = totals
            .direct_transfers
            .saturating_add(evidence.direct_transfers);
        totals.relayed_transfers = totals
            .relayed_transfers
            .saturating_add(evidence.relayed_transfers);
        totals.transient_retries = totals
            .transient_retries
            .saturating_add(evidence.transient_retries);
        totals.resumed_transfers = totals
            .resumed_transfers
            .saturating_add(evidence.resumed_transfers);
        totals.partials_collected = totals
            .partials_collected
            .saturating_add(evidence.partials_collected);
        totals.direct_source_body_bytes = totals
            .direct_source_body_bytes
            .saturating_add(evidence.direct_source_body_bytes);
        totals.direct_destination_body_bytes = totals
            .direct_destination_body_bytes
            .saturating_add(evidence.direct_destination_body_bytes);
        totals.relay_source_body_bytes = totals
            .relay_source_body_bytes
            .saturating_add(evidence.relay_source_body_bytes);
        totals.relay_destination_body_bytes = totals
            .relay_destination_body_bytes
            .saturating_add(evidence.relay_destination_body_bytes);
        totals.unknown_path_body_bytes = totals
            .unknown_path_body_bytes
            .saturating_add(evidence.unknown_path_body_bytes);
        totals.direct_selected = totals
            .direct_selected
            .saturating_add(evidence.direct_selected);
        totals.relay_selected = totals
            .relay_selected
            .saturating_add(evidence.relay_selected);
        totals.minimum_rss_bytes = totals.minimum_rss_bytes.min(evidence.minimum_rss_bytes);
        totals.maximum_rss_bytes = totals.maximum_rss_bytes.max(evidence.maximum_rss_bytes);
        totals.maximum_partial_entries = totals
            .maximum_partial_entries
            .max(evidence.maximum_partial_entries);
        println!(
            "soak_progress={}",
            json!({
                "elapsed_seconds": started.elapsed().as_secs(),
                "phases": totals.phases,
                "direct_transfers": totals.direct_transfers,
                "relayed_transfers": totals.relayed_transfers,
                "transient_retries": totals.transient_retries,
                "resumed_transfers": totals.resumed_transfers,
                "partials_collected": totals.partials_collected,
                "maximum_rss_bytes": totals.maximum_rss_bytes,
            })
        );
    }

    assert!(totals.phases >= 1);
    assert!(totals.direct_transfers >= totals.phases.saturating_mul(2));
    assert!(totals.relayed_transfers >= totals.phases);
    assert!(totals.partials_collected >= totals.phases);
    let completed_transfers = totals
        .direct_transfers
        .saturating_add(totals.relayed_transfers);
    let maximum_transient_retries = completed_transfers
        .saturating_div(50)
        .saturating_add(totals.phases.saturating_mul(2));
    assert!(totals.transient_retries <= maximum_transient_retries);
    assert!(totals.resumed_transfers <= totals.transient_retries);
    assert_eq!(
        totals.direct_destination_body_bytes,
        totals
            .direct_transfers
            .saturating_mul(ARTIFACT_BYTES as u64),
        "receiver must account every completed direct body byte exactly once"
    );
    assert_eq!(
        totals.relay_destination_body_bytes,
        totals
            .relayed_transfers
            .saturating_mul(ARTIFACT_BYTES as u64),
        "receiver must account every completed relayed body byte exactly once"
    );
    assert!(
        totals.direct_source_body_bytes
            >= totals
                .direct_transfers
                .saturating_sub(totals.transient_retries)
                .saturating_mul(ARTIFACT_BYTES as u64)
    );
    assert!(
        totals.direct_source_body_bytes
            <= totals
                .direct_transfers
                .saturating_add(totals.transient_retries)
                .saturating_mul(ARTIFACT_BYTES as u64)
    );
    assert!(
        totals.relay_source_body_bytes
            >= totals
                .relayed_transfers
                .saturating_sub(totals.transient_retries)
                .saturating_mul(ARTIFACT_BYTES as u64)
    );
    assert!(
        totals.relay_source_body_bytes
            <= totals
                .relayed_transfers
                .saturating_add(totals.transient_retries)
                .saturating_mul(ARTIFACT_BYTES as u64)
    );
    assert_eq!(totals.unknown_path_body_bytes, 0);
    assert!(totals.direct_selected >= totals.direct_transfers.saturating_mul(2));
    assert!(totals.relay_selected >= totals.relayed_transfers.saturating_mul(2));
    assert!(totals.maximum_partial_entries <= 2);
    if totals.minimum_rss_bytes != u64::MAX {
        assert!(totals.maximum_rss_bytes <= MAXIMUM_RSS_BYTES);
        assert!(
            totals
                .maximum_rss_bytes
                .saturating_sub(totals.minimum_rss_bytes)
                <= MAXIMUM_RSS_GROWTH_BYTES,
            "resident memory grew beyond the soak bound"
        );
    }
    assert!(
        allow_short || started.elapsed() >= Duration::from_secs(QUALIFYING_DURATION_SECONDS),
        "qualifying soak ended before two elapsed hours"
    );

    println!("soak_elapsed_seconds={}", started.elapsed().as_secs());
    println!("soak_phases={}", totals.phases);
    println!("soak_direct_transfers={}", totals.direct_transfers);
    println!("soak_relayed_transfers={}", totals.relayed_transfers);
    println!("soak_transient_retries={}", totals.transient_retries);
    println!("soak_resumed_transfers={}", totals.resumed_transfers);
    println!("soak_partials_collected={}", totals.partials_collected);
    println!(
        "soak_direct_source_body_bytes={}",
        totals.direct_source_body_bytes
    );
    println!(
        "soak_direct_body_bytes={}",
        totals.direct_destination_body_bytes
    );
    println!(
        "soak_relay_source_body_bytes={}",
        totals.relay_source_body_bytes
    );
    println!(
        "soak_relayed_body_bytes={}",
        totals.relay_destination_body_bytes
    );
    println!(
        "soak_unknown_path_body_bytes={}",
        totals.unknown_path_body_bytes
    );
    println!("soak_direct_selected={}", totals.direct_selected);
    println!("soak_relay_selected={}", totals.relay_selected);
    println!("soak_minimum_rss_bytes={}", totals.minimum_rss_bytes);
    println!("soak_maximum_rss_bytes={}", totals.maximum_rss_bytes);
    println!(
        "soak_maximum_partial_entries={}",
        totals.maximum_partial_entries
    );
}

#[allow(clippy::too_many_arguments)]
async fn run_phase(
    root: &Path,
    relay: IrohRelayConfiguration,
    phase: u64,
    deadline: Instant,
    interval: Duration,
    direct_source_path: &Path,
    relay_source_path: &Path,
    digest: &Digest,
    size_bytes: u64,
) -> PhaseEvidence {
    let tenant = TenantId::from("artifact-soak-tenant");
    let project = ProjectId::from("artifact-soak-project");
    let direct_source_node = NodeId::from("artifact-soak-direct-source");
    let direct_destination_node = NodeId::from("artifact-soak-direct-destination");
    let relay_source_node = NodeId::from("artifact-soak-relay-source");
    let relay_destination_node = NodeId::from("artifact-soak-relay-destination");
    let direct_source_identity = identity(
        root.join("direct-source-identity/iroh.json"),
        &tenant,
        &project,
        &direct_source_node,
    );
    let direct_destination_identity = identity(
        root.join("direct-destination-identity/iroh.json"),
        &tenant,
        &project,
        &direct_destination_node,
    );
    let relay_source_identity = identity(
        root.join("relay-source-identity/iroh.json"),
        &tenant,
        &project,
        &relay_source_node,
    );
    let relay_destination_identity = identity(
        root.join("relay-destination-identity/iroh.json"),
        &tenant,
        &project,
        &relay_destination_node,
    );
    let relay_config = EndpointBindConfig { relay };
    let direct_source_endpoint =
        ClusterfluxEndpoint::bind(&direct_source_identity, relay_config.clone())
            .await
            .unwrap();
    let direct_destination_endpoint =
        ClusterfluxEndpoint::bind(&direct_destination_identity, relay_config.clone())
            .await
            .unwrap();
    let relay_source_endpoint = ClusterfluxEndpoint::bind_relay_only_for_diagnostics(
        &relay_source_identity,
        relay_config.clone(),
    )
    .await
    .unwrap();
    let relay_destination_endpoint = ClusterfluxEndpoint::bind_relay_only_for_diagnostics(
        &relay_destination_identity,
        relay_config,
    )
    .await
    .unwrap();

    let direct_advertisement =
        wait_for_relay_advertisement(&direct_source_endpoint, phase, true).await;
    let relay_advertisement =
        wait_for_relay_advertisement(&relay_source_endpoint, phase, false).await;
    let endpoint_ids = [
        direct_source_endpoint.endpoint_id(),
        direct_destination_endpoint.endpoint_id(),
        relay_source_endpoint.endpoint_id(),
        relay_destination_endpoint.endpoint_id(),
    ];

    let direct_registry = ArtifactProviderRegistry::new(direct_source_endpoint.endpoint_id(), 4);
    let relay_registry = ArtifactProviderRegistry::new(relay_source_endpoint.endpoint_id(), 4);
    let direct_source_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let direct_destination_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let relay_source_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let relay_destination_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let direct_source_paths = Arc::new(PathPolicyMetrics::default());
    let direct_destination_paths = Arc::new(PathPolicyMetrics::default());
    let relay_source_paths = Arc::new(PathPolicyMetrics::default());
    let relay_destination_paths = Arc::new(PathPolicyMetrics::default());
    let direct_server = ArtifactProviderServer::start(
        &direct_source_endpoint,
        direct_registry.clone(),
        Arc::clone(&direct_source_metrics),
        Arc::clone(&direct_source_paths),
    );
    let relay_server = ArtifactProviderServer::start(
        &relay_source_endpoint,
        relay_registry.clone(),
        Arc::clone(&relay_source_metrics),
        Arc::clone(&relay_source_paths),
    );
    let direct_partial_root = root.join("direct-partials");
    let relay_partial_root = root.join("relay-partials");
    let direct_receiver = ArtifactReceiver::new(
        direct_destination_endpoint.clone(),
        PartialStoreConfig::new(direct_partial_root.clone()),
        Arc::clone(&direct_destination_metrics),
        Arc::clone(&direct_destination_paths),
    )
    .unwrap()
    .with_path_deadlines(Duration::from_secs(20), Duration::ZERO);
    let relay_receiver = ArtifactReceiver::new(
        relay_destination_endpoint.clone(),
        PartialStoreConfig::new(relay_partial_root),
        Arc::clone(&relay_destination_metrics),
        Arc::clone(&relay_destination_paths),
    )
    .unwrap()
    .with_path_deadlines(Duration::from_secs(20), Duration::ZERO);

    let mut direct_transfers = 0_u64;
    let mut relayed_transfers = 0_u64;
    let mut transient_retries = 0_u64;
    let mut resumed_transfers = 0_u64;
    let mut partials_collected = 0_u64;
    let mut maximum_partial_entries = 0_usize;
    let mut minimum_rss_bytes = u64::MAX;
    let mut maximum_rss_bytes = 0_u64;
    while Instant::now() < deadline {
        let cycle = direct_transfers.saturating_add(1);
        let direct_outcome = transfer_one(
            phase,
            cycle,
            "direct",
            ArtifactRelayPolicy::DirectRequired,
            &tenant,
            &project,
            &direct_source_node,
            &direct_destination_node,
            &direct_source_endpoint,
            &direct_destination_endpoint,
            &direct_advertisement,
            &direct_registry,
            &direct_receiver,
            direct_source_path,
            digest,
            size_bytes,
            &root.join("direct-installed"),
            0x51,
        )
        .await;
        direct_transfers = direct_transfers.saturating_add(1);
        transient_retries = transient_retries.saturating_add(direct_outcome.retries);
        resumed_transfers = resumed_transfers.saturating_add(u64::from(direct_outcome.resumed));

        if cycle == 1 || cycle.is_multiple_of(RELAY_TRANSFER_INTERVAL) {
            let relay_outcome = transfer_one(
                phase,
                cycle,
                "relay",
                ArtifactRelayPolicy::RelayFallbackAllowed,
                &tenant,
                &project,
                &relay_source_node,
                &relay_destination_node,
                &relay_source_endpoint,
                &relay_destination_endpoint,
                &relay_advertisement,
                &relay_registry,
                &relay_receiver,
                relay_source_path,
                digest,
                size_bytes,
                &root.join("relay-installed"),
                0x73,
            )
            .await;
            relayed_transfers = relayed_transfers.saturating_add(1);
            transient_retries = transient_retries.saturating_add(relay_outcome.retries);
            resumed_transfers = resumed_transfers.saturating_add(u64::from(relay_outcome.resumed));
        }

        if cycle == 1 || cycle.is_multiple_of(PARTIAL_GC_INTERVAL) {
            seed_expired_partial(&direct_partial_root, phase, cycle, digest, size_bytes);
            maximum_partial_entries =
                maximum_partial_entries.max(entry_count(&direct_partial_root));
            let removed = direct_receiver.garbage_collect_partials(now()).unwrap();
            assert_eq!(removed, 1, "expired soak partial was not collected");
            partials_collected = partials_collected.saturating_add(removed as u64);
            assert_eq!(entry_count(&direct_partial_root), 0);
        }

        let rss = resident_set_bytes();
        if rss > 0 {
            minimum_rss_bytes = minimum_rss_bytes.min(rss);
            maximum_rss_bytes = maximum_rss_bytes.max(rss);
            assert!(rss <= MAXIMUM_RSS_BYTES, "soak RSS exceeded its hard bound");
        }
        tokio::time::sleep(interval).await;
    }

    assert!(direct_transfers >= 1);
    assert!(relayed_transfers >= 1);
    assert!(direct_registry.pinned_artifacts(now()).await.is_empty());
    assert!(relay_registry.pinned_artifacts(now()).await.is_empty());
    assert_eq!(entry_count(&direct_partial_root), 0);
    let direct_source_snapshot = direct_source_metrics.snapshot();
    let direct_destination_snapshot = direct_destination_metrics.snapshot();
    let relay_source_snapshot = relay_source_metrics.snapshot();
    let relay_destination_snapshot = relay_destination_metrics.snapshot();
    assert_eq!(direct_source_snapshot.relayed_body_bytes, 0);
    assert_eq!(direct_destination_snapshot.relayed_body_bytes, 0);
    assert_eq!(relay_source_snapshot.direct_body_bytes, 0);
    assert_eq!(relay_destination_snapshot.direct_body_bytes, 0);
    assert_eq!(direct_source_snapshot.unknown_path_body_bytes, 0);
    assert_eq!(direct_destination_snapshot.unknown_path_body_bytes, 0);
    assert_eq!(relay_source_snapshot.unknown_path_body_bytes, 0);
    assert_eq!(relay_destination_snapshot.unknown_path_body_bytes, 0);
    assert_eq!(
        direct_destination_snapshot.completed_transfers,
        direct_transfers
    );
    assert_eq!(
        relay_destination_snapshot.completed_transfers,
        relayed_transfers
    );

    direct_receiver.close_connections().await;
    relay_receiver.close_connections().await;
    direct_server.shutdown().await.unwrap();
    relay_server.shutdown().await.unwrap();
    direct_destination_endpoint.close().await;
    relay_destination_endpoint.close().await;
    direct_source_endpoint.close().await;
    relay_source_endpoint.close().await;

    PhaseEvidence {
        direct_transfers,
        relayed_transfers,
        transient_retries,
        resumed_transfers,
        partials_collected,
        direct_source_body_bytes: direct_source_snapshot.direct_body_bytes,
        direct_destination_body_bytes: direct_destination_snapshot.direct_body_bytes,
        relay_source_body_bytes: relay_source_snapshot.relayed_body_bytes,
        relay_destination_body_bytes: relay_destination_snapshot.relayed_body_bytes,
        unknown_path_body_bytes: direct_source_snapshot
            .unknown_path_body_bytes
            .saturating_add(direct_destination_snapshot.unknown_path_body_bytes)
            .saturating_add(relay_source_snapshot.unknown_path_body_bytes)
            .saturating_add(relay_destination_snapshot.unknown_path_body_bytes),
        direct_selected: direct_source_paths
            .selected_direct()
            .saturating_add(direct_destination_paths.selected_direct()),
        relay_selected: relay_source_paths
            .selected_relay()
            .saturating_add(relay_destination_paths.selected_relay()),
        minimum_rss_bytes,
        maximum_rss_bytes,
        maximum_partial_entries,
        endpoint_ids,
    }
}

#[allow(clippy::too_many_arguments)]
async fn transfer_one(
    phase: u64,
    cycle: u64,
    label: &str,
    relay_policy: ArtifactRelayPolicy,
    tenant: &TenantId,
    project: &ProjectId,
    source_node: &NodeId,
    destination_node: &NodeId,
    source_endpoint: &ClusterfluxEndpoint,
    destination_endpoint: &ClusterfluxEndpoint,
    advertisement: &IrohEndpointAdvertisement,
    registry: &ArtifactProviderRegistry,
    receiver: &ArtifactReceiver,
    source_path: &Path,
    digest: &Digest,
    size_bytes: u64,
    destination_root: &Path,
    secret_byte: u8,
) -> TransferOutcome {
    let artifact_name = format!("soak-{label}-{phase}-{cycle}");
    let artifact = ArtifactId::from(artifact_name.as_str());
    let destination_path = destination_root.join(artifact.as_str());
    let expected_path = match relay_policy {
        ArtifactRelayPolicy::DirectRequired => ClusterfluxPathKind::Direct,
        ArtifactRelayPolicy::RelayFallbackAllowed => ClusterfluxPathKind::Relayed,
    };
    let mut retries = 0_u64;
    for attempt in 1..=MAXIMUM_TRANSFER_ATTEMPTS {
        let timestamp = now();
        let transfer_id = format!("soak-{label}-{phase}-{cycle}-{attempt}");
        let transfer_secret = [secret_byte; 32];
        let lease = ArtifactTransferLease {
            transfer_id: transfer_id.clone(),
            tenant: tenant.clone(),
            project: project.clone(),
            process: ProcessId::from("artifact-soak-process"),
            artifact: artifact.clone(),
            digest: digest.clone(),
            size_bytes,
            source_node: source_node.clone(),
            source_endpoint_id: source_endpoint.endpoint_id(),
            destination_node: destination_node.clone(),
            destination_endpoint_id: destination_endpoint.endpoint_id(),
            allowed_offset: 0,
            maximum_bytes: size_bytes,
            relay_policy,
            direct_path_deadline_ms: 20_000,
            expires_at: timestamp.saturating_add(120),
            active_lease_expires_at: timestamp.saturating_add(120),
            nonce: format!("soak-nonce-{label}-{phase}-{cycle}-{attempt}"),
        };
        registry
            .register_verified_source(lease.clone(), transfer_secret, source_path, timestamp)
            .await
            .unwrap();
        assert_eq!(
            registry.pinned_artifacts(timestamp).await,
            BTreeSet::from([artifact.clone()])
        );
        if attempt == 1
            && phase == 1
            && cycle == 1
            && label == "direct"
            && std::env::var("CLUSTERFLUX_ARTIFACT_SOAK_FORCE_RETRY_ONCE")
                .ok()
                .as_deref()
                == Some("1")
        {
            registry.cancel(&transfer_id).await;
            assert!(registry.pinned_artifacts(timestamp).await.is_empty());
            retries = retries.saturating_add(1);
            println!(
                "soak_transient_retry={}",
                json!({
                    "phase": phase,
                    "cycle": cycle,
                    "path": label,
                    "attempt": attempt,
                    "code": ArtifactTransferErrorCode::ConnectionFailed.as_str(),
                    "diagnostic_injection": true,
                })
            );
            continue;
        }
        let authorization = ArtifactTransferAuthorization {
            lease,
            transfer_secret,
            peer: AuthorizedPeerEndpoint {
                node: source_node.clone(),
                endpoint_id: advertisement.endpoint_id.clone(),
                generation: advertisement.generation,
                // Every phase starts through the isolated relay. Direct endpoints exchange
                // candidates over that connection and must migrate before opening the body.
                direct_addresses: Vec::new(),
                relay_urls: advertisement.relay_urls.clone(),
            },
        };
        let result = receiver
            .download(&authorization, &destination_path, timestamp)
            .await;
        registry.cancel(&transfer_id).await;
        assert!(registry.pinned_artifacts(timestamp).await.is_empty());
        match result {
            Ok(completed) => {
                assert_eq!(completed.path_kind, expected_path);
                assert_eq!(completed.digest, *digest);
                assert_eq!(completed.size_bytes, size_bytes);
                assert_eq!(
                    completed
                        .resumed_from
                        .saturating_add(completed.bytes_transferred),
                    size_bytes
                );
                assert_eq!(
                    tokio::fs::read(&destination_path).await.unwrap().len() as u64,
                    size_bytes
                );
                tokio::fs::remove_file(&destination_path).await.unwrap();
                return TransferOutcome {
                    retries,
                    resumed: completed.resumed_from > 0,
                };
            }
            Err(error) => {
                let code = error.stable_code();
                assert!(
                    matches!(
                        code,
                        ArtifactTransferErrorCode::ConnectionFailed
                            | ArtifactTransferErrorCode::RelayPathForbidden
                            | ArtifactTransferErrorCode::DirectPathTimeout
                    ),
                    "soak transfer returned a non-retryable error: {error:?}: {error}"
                );
                assert!(
                    attempt < MAXIMUM_TRANSFER_ATTEMPTS,
                    "soak transfer exhausted {MAXIMUM_TRANSFER_ATTEMPTS} attempts: {error:?}: {error}"
                );
                retries = retries.saturating_add(1);
                println!(
                    "soak_transient_retry={}",
                    json!({
                        "phase": phase,
                        "cycle": cycle,
                        "path": label,
                        "attempt": attempt,
                        "code": code.as_str(),
                    })
                );
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
        }
    }
    unreachable!("bounded transfer-attempt loop always returns or panics")
}

fn identity(
    path: PathBuf,
    tenant: &TenantId,
    project: &ProjectId,
    node: &NodeId,
) -> PersistentIrohIdentity {
    PersistentIrohIdentity::load_or_create(
        path,
        IrohIdentityScope {
            tenant: tenant.clone(),
            project: project.clone(),
            node: node.clone(),
        },
    )
    .unwrap()
}

async fn wait_for_relay_advertisement(
    endpoint: &ClusterfluxEndpoint,
    relay_configuration_generation: u64,
    require_direct: bool,
) -> IrohEndpointAdvertisement {
    for _ in 0..100 {
        let advertisement = endpoint
            .advertisement(relay_configuration_generation, now().saturating_add(120))
            .unwrap();
        if !advertisement.relay_urls.is_empty()
            && (!require_direct || !advertisement.direct_addresses.is_empty())
            && (require_direct || advertisement.direct_addresses.is_empty())
        {
            return advertisement;
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
    panic!("endpoint did not publish the required isolated-relay advertisement");
}

fn seed_expired_partial(root: &Path, phase: u64, cycle: u64, digest: &Digest, size_bytes: u64) {
    let stem = format!("expired-{phase}-{cycle}");
    std::fs::write(root.join(format!("{stem}.partial")), b"expired").unwrap();
    let timestamp = now();
    std::fs::write(
        root.join(format!("{stem}.json")),
        serde_json::to_vec_pretty(&json!({
            "transfer_id": format!("expired-{phase}-{cycle}"),
            "artifact": format!("expired-{phase}-{cycle}"),
            "digest": digest,
            "expected_size": size_bytes,
            "received_contiguous_bytes": 7,
            "last_update": timestamp.saturating_sub(1),
            "expiry": timestamp.saturating_sub(1),
        }))
        .unwrap(),
    )
    .unwrap();
}

fn entry_count(root: &Path) -> usize {
    std::fs::read_dir(root).unwrap().count()
}

fn relay_configuration() -> IrohRelayConfiguration {
    let relay_url = std::env::var("CLUSTERFLUX_TEST_RELAY_URL")
        .expect("CLUSTERFLUX_TEST_RELAY_URL is required");
    let relay_token = std::env::var("CLUSTERFLUX_TEST_RELAY_TOKEN")
        .expect("CLUSTERFLUX_TEST_RELAY_TOKEN is required");
    IrohRelayConfiguration::Custom(vec![ClusterfluxRelayConfig {
        url: relay_url,
        access_token: Some(relay_token),
    }])
}

fn environment_u64(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .map(|value| {
            value
                .parse::<u64>()
                .unwrap_or_else(|_| panic!("{name} is invalid"))
        })
        .unwrap_or(default)
}

fn resident_set_bytes() -> u64 {
    let Ok(status) = std::fs::read_to_string("/proc/self/status") else {
        return 0;
    };
    status
        .lines()
        .find_map(|line| {
            let kibibytes = line.strip_prefix("VmRSS:")?.split_whitespace().next()?;
            kibibytes.parse::<u64>().ok()
        })
        .unwrap_or(0)
        .saturating_mul(1024)
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
