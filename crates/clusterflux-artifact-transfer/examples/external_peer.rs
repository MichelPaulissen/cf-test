use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

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
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

const TENANT: &str = "external-topology-tenant";
const PROJECT: &str = "external-topology-project";
const SOURCE_NODE: &str = "external-topology-source";
const DESTINATION_NODE: &str = "external-topology-destination";
const ARTIFACT: &str = "external-topology-artifact";
const PROCESS: &str = "external-topology-process";
const TRANSFER_SECRET: [u8; 32] = [0x6d; 32];

#[derive(Debug, Serialize, Deserialize)]
struct DestinationReady {
    event: String,
    advertisement: IrohEndpointAdvertisement,
}

#[derive(Debug, Serialize, Deserialize)]
struct SourceReady {
    event: String,
    advertisement: IrohEndpointAdvertisement,
    authorization: ArtifactTransferAuthorization,
}

#[derive(Debug, Serialize)]
struct TransferEvidence {
    event: &'static str,
    endpoint_id: String,
    digest: Digest,
    size_bytes: u64,
    bytes_transferred: u64,
    resumed_from: u64,
    path_kind: ClusterfluxPathKind,
    direct_body_bytes: u64,
    relayed_body_bytes: u64,
    unknown_path_body_bytes: u64,
    selected_direct: u64,
    selected_relay: u64,
}

#[derive(Debug, Serialize)]
struct DirectReadyEvidence {
    event: &'static str,
    path_kind: ClusterfluxPathKind,
    selected_direct: u64,
    selected_relay: u64,
}

#[derive(Debug, Serialize)]
struct DirectUnavailableEvidence {
    event: &'static str,
    error_code: ArtifactTransferErrorCode,
    partial_entries: usize,
    installed: bool,
    direct_body_bytes: u64,
    relayed_body_bytes: u64,
    unknown_path_body_bytes: u64,
    selected_direct: u64,
    selected_relay: u64,
}

#[derive(Debug, Serialize)]
struct InterruptedEvidence {
    event: &'static str,
    error_code: ArtifactTransferErrorCode,
    partial_bytes: u64,
    selected_direct: u64,
    selected_relay: u64,
}

#[derive(Debug, Serialize)]
struct DiskFullEvidence {
    event: &'static str,
    error_code: ArtifactTransferErrorCode,
    partial_bytes: u64,
    direct_body_bytes: u64,
    relayed_body_bytes: u64,
    unknown_path_body_bytes: u64,
}

#[derive(Debug, Serialize)]
struct CorruptionEvidence {
    event: &'static str,
    error_code: ArtifactTransferErrorCode,
    partial_bytes: u64,
    partial_entries: usize,
    installed: bool,
    direct_body_bytes: u64,
    relayed_body_bytes: u64,
    unknown_path_body_bytes: u64,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 2)]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("external Iroh peer smoke failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let mut arguments = std::env::args().skip(1);
    let role = arguments.next().ok_or_else(|| usage("role is required"))?;
    let state_dir = PathBuf::from(
        arguments
            .next()
            .ok_or_else(|| usage("state directory is required"))?,
    );
    if arguments.next().is_some() {
        return Err(usage("unexpected extra argument"));
    }
    std::fs::create_dir_all(&state_dir).map_err(|error| error.to_string())?;
    match role.as_str() {
        "source" => run_source(&state_dir).await,
        "destination" => run_destination(&state_dir).await,
        _ => Err(usage("role must be source or destination")),
    }
}

async fn run_destination(state_dir: &Path) -> Result<(), String> {
    let now = now()?;
    let relay_only = relay_only_mode();
    let ipv6_only = ipv6_only_mode();
    let identity = PersistentIrohIdentity::load_or_create(
        state_dir.join("iroh-identity.json"),
        IrohIdentityScope {
            tenant: TenantId::from(TENANT),
            project: ProjectId::from(PROJECT),
            node: NodeId::from(DESTINATION_NODE),
        },
    )
    .map_err(|error| error.to_string())?;
    let mut endpoint = if relay_only {
        ClusterfluxEndpoint::bind_relay_only_for_diagnostics(&identity, relay_config()?).await
    } else if ipv6_only {
        ClusterfluxEndpoint::bind_ipv6_only_for_diagnostics(&identity, relay_config()?).await
    } else {
        ClusterfluxEndpoint::bind(&identity, relay_config()?).await
    }
    .map_err(|error| error.to_string())?;
    write_event(&DestinationReady {
        event: "destination_ready".to_owned(),
        advertisement: endpoint
            .advertisement(1, now + 300)
            .map_err(|error| error.to_string())?,
    })?;

    let source: SourceReady = read_event().await?;
    if source.event != "source_ready" {
        return Err("destination expected a source_ready event".to_owned());
    }
    let data_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let path_metrics = Arc::new(PathPolicyMetrics::default());
    let mut receiver = ArtifactReceiver::new(
        endpoint.clone(),
        PartialStoreConfig::new(state_dir.join("partials")),
        Arc::clone(&data_metrics),
        Arc::clone(&path_metrics),
    )
    .map_err(|error| error.to_string())?
    .with_path_deadlines(Duration::from_secs(30), Duration::ZERO);
    let expect_direct_unavailable = std::env::var("CLUSTERFLUX_EXTERNAL_EXPECT_DIRECT_UNAVAILABLE")
        .ok()
        .as_deref()
        == Some("1");
    let selected = match receiver
        .warm_authorized_peer(&source.authorization, now)
        .await
    {
        Ok(selected) if expect_direct_unavailable => {
            return Err(format!(
                "UDP-blocked mode unexpectedly selected a {selected:?} path"
            ));
        }
        Ok(selected) => selected,
        Err(error) if expect_direct_unavailable => {
            if error.stable_code() != ArtifactTransferErrorCode::DirectPathTimeout {
                return Err(format!(
                    "UDP-blocked connection returned {}, not DirectPathTimeout",
                    error.stable_code().as_str()
                ));
            }
            let snapshot = data_metrics.snapshot();
            let partial_root = state_dir.join("partials");
            write_event(&DirectUnavailableEvidence {
                event: "destination_direct_unavailable",
                error_code: error.stable_code(),
                partial_entries: std::fs::read_dir(&partial_root)
                    .map_err(|error| error.to_string())?
                    .count(),
                installed: state_dir.join("installed-artifact").exists(),
                direct_body_bytes: snapshot.direct_body_bytes,
                relayed_body_bytes: snapshot.relayed_body_bytes,
                unknown_path_body_bytes: snapshot.unknown_path_body_bytes,
                selected_direct: path_metrics.selected_direct(),
                selected_relay: path_metrics.selected_relay(),
            })?;
            receiver.close_connections().await;
            endpoint.close().await;
            return Ok(());
        }
        Err(error) => return Err(error.to_string()),
    };
    write_event(&DirectReadyEvidence {
        event: if relay_only {
            "destination_relay_ready"
        } else {
            "destination_direct_ready"
        },
        path_kind: selected,
        selected_direct: path_metrics.selected_direct(),
        selected_relay: path_metrics.selected_relay(),
    })?;
    if read_line().await?.trim() != "start" {
        return Err("destination expected the start command".to_owned());
    }
    let expect_path_loss = std::env::var("CLUSTERFLUX_EXTERNAL_EXPECT_PATH_LOSS")
        .ok()
        .as_deref()
        == Some("1");
    let expect_network_change = std::env::var("CLUSTERFLUX_EXTERNAL_EXPECT_NETWORK_CHANGE")
        .ok()
        .as_deref()
        == Some("1");
    let expect_disk_full = std::env::var("CLUSTERFLUX_EXTERNAL_EXPECT_DISK_FULL")
        .ok()
        .as_deref()
        == Some("1");
    let expect_corruption = std::env::var("CLUSTERFLUX_EXTERNAL_EXPECT_CORRUPTION")
        .ok()
        .as_deref()
        == Some("1");
    let destination_path = state_dir.join("installed-artifact");
    let completed = if expect_corruption {
        let error = match receiver
            .download(&source.authorization, &destination_path, now)
            .await
        {
            Ok(_) => return Err("corruption mode unexpectedly installed the artifact".to_owned()),
            Err(error) => error,
        };
        if error.stable_code() != ArtifactTransferErrorCode::DigestMismatch {
            return Err(format!(
                "corrupt transfer returned {} ({error:?}: {error}), not DigestMismatch",
                error.stable_code().as_str(),
            ));
        }
        let partial_root = state_dir.join("partials");
        let snapshot = data_metrics.snapshot();
        write_event(&CorruptionEvidence {
            event: "destination_corruption_rejected",
            error_code: error.stable_code(),
            partial_bytes: retained_partial_bytes(&partial_root)?,
            partial_entries: std::fs::read_dir(&partial_root)
                .map_err(|error| error.to_string())?
                .count(),
            installed: destination_path.exists(),
            direct_body_bytes: snapshot.direct_body_bytes,
            relayed_body_bytes: snapshot.relayed_body_bytes,
            unknown_path_body_bytes: snapshot.unknown_path_body_bytes,
        })?;
        receiver.close_connections().await;
        endpoint.close().await;
        return Ok(());
    } else if expect_disk_full {
        let error = match receiver
            .download(&source.authorization, &destination_path, now)
            .await
        {
            Ok(_) => {
                return Err("disk-full mode unexpectedly completed the transfer attempt".to_owned())
            }
            Err(error) => error,
        };
        if error.stable_code() != ArtifactTransferErrorCode::DestinationDiskFull {
            return Err(format!(
                "disk-full attempt returned {} ({error:?}: {error}), not DestinationDiskFull",
                error.stable_code().as_str(),
            ));
        }
        let snapshot = data_metrics.snapshot();
        write_event(&DiskFullEvidence {
            event: "destination_disk_full",
            error_code: error.stable_code(),
            partial_bytes: retained_partial_bytes(&state_dir.join("partials"))?,
            direct_body_bytes: snapshot.direct_body_bytes,
            relayed_body_bytes: snapshot.relayed_body_bytes,
            unknown_path_body_bytes: snapshot.unknown_path_body_bytes,
        })?;
        receiver.close_connections().await;
        endpoint.close().await;
        return Ok(());
    } else if expect_path_loss || expect_network_change {
        let error = match receiver
            .download(&source.authorization, &destination_path, now)
            .await
        {
            Ok(_) => {
                return Err(
                    "path-loss mode unexpectedly completed the first transfer attempt".to_owned(),
                )
            }
            Err(error) => error,
        };
        if !matches!(
            error.stable_code(),
            ArtifactTransferErrorCode::RelayPathForbidden
                | ArtifactTransferErrorCode::ConnectionFailed
        ) {
            return Err(format!(
                "path-loss attempt returned {}, not a path-loss cancellation",
                error.stable_code().as_str()
            ));
        }
        let partial_bytes = retained_partial_bytes(&state_dir.join("partials"))?;
        if partial_bytes == 0 || partial_bytes >= source.authorization.lease.size_bytes {
            return Err(format!(
                "path-loss attempt retained an invalid partial size of {partial_bytes} bytes"
            ));
        }
        write_event(&InterruptedEvidence {
            event: "destination_interrupted",
            error_code: error.stable_code(),
            partial_bytes,
            selected_direct: path_metrics.selected_direct(),
            selected_relay: path_metrics.selected_relay(),
        })?;
        if expect_network_change {
            if read_line().await?.trim() != "rebind" {
                return Err("destination expected the rebind command".to_owned());
            }
            receiver.close_connections().await;
            endpoint.close().await;
            endpoint = ClusterfluxEndpoint::bind(&identity, relay_config()?)
                .await
                .map_err(|error| error.to_string())?;
            write_event(&DestinationReady {
                event: "destination_rebound".to_owned(),
                advertisement: endpoint
                    .advertisement(2, crate::now()? + 300)
                    .map_err(|error| error.to_string())?,
            })?;
            receiver = ArtifactReceiver::new(
                endpoint.clone(),
                PartialStoreConfig::new(state_dir.join("partials")),
                Arc::clone(&data_metrics),
                Arc::clone(&path_metrics),
            )
            .map_err(|error| error.to_string())?
            .with_path_deadlines(Duration::from_secs(30), Duration::ZERO);
        }
        if read_line().await?.trim() != "resume" {
            return Err("destination expected the resume command".to_owned());
        }
        receiver
            .download(&source.authorization, &destination_path, crate::now()?)
            .await
            .map_err(|error| error.to_string())?
    } else {
        receiver
            .download(&source.authorization, &destination_path, now)
            .await
            .map_err(|error| error.to_string())?
    };
    let snapshot = data_metrics.snapshot();
    write_event(&TransferEvidence {
        event: "destination_completed",
        endpoint_id: endpoint.endpoint_id(),
        digest: completed.digest,
        size_bytes: completed.size_bytes,
        bytes_transferred: completed.bytes_transferred,
        resumed_from: completed.resumed_from,
        path_kind: completed.path_kind,
        direct_body_bytes: snapshot.direct_body_bytes,
        relayed_body_bytes: snapshot.relayed_body_bytes,
        unknown_path_body_bytes: snapshot.unknown_path_body_bytes,
        selected_direct: path_metrics.selected_direct(),
        selected_relay: path_metrics.selected_relay(),
    })?;
    receiver.close_connections().await;
    endpoint.close().await;
    Ok(())
}

async fn run_source(state_dir: &Path) -> Result<(), String> {
    let relay_only = relay_only_mode();
    let ipv6_only = ipv6_only_mode();
    let destination: DestinationReady = read_event().await?;
    if destination.event != "destination_ready" {
        return Err("source expected a destination_ready event".to_owned());
    }
    destination
        .advertisement
        .validate_bounds()
        .map_err(|error| format!("destination advertisement is invalid: {error}"))?;
    if destination.advertisement.tenant != TenantId::from(TENANT)
        || destination.advertisement.project != ProjectId::from(PROJECT)
        || destination.advertisement.node != NodeId::from(DESTINATION_NODE)
    {
        return Err("destination advertisement has the wrong scope".to_owned());
    }

    let now = now()?;
    let identity = PersistentIrohIdentity::load_or_create(
        state_dir.join("iroh-identity.json"),
        IrohIdentityScope {
            tenant: TenantId::from(TENANT),
            project: ProjectId::from(PROJECT),
            node: NodeId::from(SOURCE_NODE),
        },
    )
    .map_err(|error| error.to_string())?;
    let endpoint = if relay_only {
        ClusterfluxEndpoint::bind_relay_only_for_diagnostics(&identity, relay_config()?).await
    } else if ipv6_only {
        ClusterfluxEndpoint::bind_ipv6_only_for_diagnostics(&identity, relay_config()?).await
    } else {
        ClusterfluxEndpoint::bind(&identity, relay_config()?).await
    }
    .map_err(|error| error.to_string())?;
    let source_path = state_dir.join("source-artifact");
    let (digest, size_bytes) = write_source_artifact(&source_path).await?;
    let source_advertisement = endpoint
        .advertisement(1, now + 300)
        .map_err(|error| error.to_string())?;
    let lease = ArtifactTransferLease {
        transfer_id: format!("external-topology-{now}"),
        tenant: TenantId::from(TENANT),
        project: ProjectId::from(PROJECT),
        process: ProcessId::from(PROCESS),
        artifact: ArtifactId::from(ARTIFACT),
        digest: digest.clone(),
        size_bytes,
        source_node: NodeId::from(SOURCE_NODE),
        source_endpoint_id: endpoint.endpoint_id(),
        destination_node: NodeId::from(DESTINATION_NODE),
        destination_endpoint_id: destination.advertisement.endpoint_id,
        allowed_offset: 0,
        maximum_bytes: size_bytes,
        relay_policy: if relay_only {
            ArtifactRelayPolicy::RelayFallbackAllowed
        } else {
            ArtifactRelayPolicy::DirectRequired
        },
        direct_path_deadline_ms: 20_000,
        expires_at: now + 300,
        active_lease_expires_at: now + 300,
        nonce: format!("external-topology-nonce-{now}"),
    };
    let registry = ArtifactProviderRegistry::new(endpoint.endpoint_id(), 4);
    registry
        .register_verified_source(lease.clone(), TRANSFER_SECRET, &source_path, now)
        .await
        .map_err(|error| error.to_string())?;
    if std::env::var("CLUSTERFLUX_EXTERNAL_EXPECT_CORRUPTION")
        .ok()
        .as_deref()
        == Some("1")
    {
        let mut source = tokio::fs::OpenOptions::new()
            .write(true)
            .open(&source_path)
            .await
            .map_err(|error| error.to_string())?;
        source
            .write_all(&[0xff])
            .await
            .map_err(|error| error.to_string())?;
        source.sync_all().await.map_err(|error| error.to_string())?;
    }
    let data_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let path_metrics = Arc::new(PathPolicyMetrics::default());
    let server = ArtifactProviderServer::start(
        &endpoint,
        registry,
        Arc::clone(&data_metrics),
        Arc::clone(&path_metrics),
    );
    write_event(&SourceReady {
        event: "source_ready".to_owned(),
        advertisement: source_advertisement.clone(),
        authorization: ArtifactTransferAuthorization {
            lease,
            transfer_secret: TRANSFER_SECRET,
            peer: AuthorizedPeerEndpoint {
                node: NodeId::from(SOURCE_NODE),
                endpoint_id: source_advertisement.endpoint_id,
                generation: source_advertisement.generation,
                // Force the connection to begin through the explicit relay. In the normal
                // modes Iroh exchanges candidates there and migrates before DirectRequired
                // accepts. Relay-only diagnostics deliberately have no IP candidates.
                direct_addresses: Vec::new(),
                relay_urls: source_advertisement.relay_urls,
            },
        },
    })?;

    let shutdown = read_line().await?;
    if shutdown.trim() != "shutdown" {
        return Err("source expected the shutdown command".to_owned());
    }
    let snapshot = data_metrics.snapshot();
    write_event(&TransferEvidence {
        event: "source_completed",
        endpoint_id: endpoint.endpoint_id(),
        digest,
        size_bytes,
        bytes_transferred: snapshot
            .direct_body_bytes
            .saturating_add(snapshot.relayed_body_bytes)
            .saturating_add(snapshot.unknown_path_body_bytes),
        resumed_from: 0,
        path_kind: if snapshot.direct_body_bytes > 0
            && snapshot.relayed_body_bytes == 0
            && snapshot.unknown_path_body_bytes == 0
        {
            ClusterfluxPathKind::Direct
        } else if snapshot.relayed_body_bytes == size_bytes {
            ClusterfluxPathKind::Relayed
        } else {
            ClusterfluxPathKind::Unknown
        },
        direct_body_bytes: snapshot.direct_body_bytes,
        relayed_body_bytes: snapshot.relayed_body_bytes,
        unknown_path_body_bytes: snapshot.unknown_path_body_bytes,
        selected_direct: path_metrics.selected_direct(),
        selected_relay: path_metrics.selected_relay(),
    })?;
    server.shutdown().await.map_err(|error| error.to_string())?;
    Ok(())
}

async fn write_source_artifact(path: &Path) -> Result<(Digest, u64), String> {
    let artifact_bytes = std::env::var("CLUSTERFLUX_EXTERNAL_ARTIFACT_BYTES")
        .ok()
        .map(|value| value.parse::<u64>())
        .transpose()
        .map_err(|error| format!("CLUSTERFLUX_EXTERNAL_ARTIFACT_BYTES is invalid: {error}"))?
        .unwrap_or(6_000_000);
    if artifact_bytes == 0 || artifact_bytes > 512 * 1024 * 1024 {
        return Err(
            "CLUSTERFLUX_EXTERNAL_ARTIFACT_BYTES must be between 1 and 536870912".to_owned(),
        );
    }
    let mut file = tokio::fs::File::create(path)
        .await
        .map_err(|error| error.to_string())?;
    let chunk = (0..1024 * 1024)
        .map(|offset| ((offset * 31 + 17) % 251) as u8)
        .collect::<Vec<_>>();
    let mut remaining = artifact_bytes;
    let mut hasher = Sha256::new();
    while remaining > 0 {
        let count = chunk.len().min(remaining as usize);
        file.write_all(&chunk[..count])
            .await
            .map_err(|error| error.to_string())?;
        hasher.update(&chunk[..count]);
        remaining -= count as u64;
    }
    file.sync_all().await.map_err(|error| error.to_string())?;
    let digest = Digest::from_sha256_hex(hex::encode(hasher.finalize()))?;
    Ok((digest, artifact_bytes))
}

fn retained_partial_bytes(root: &Path) -> Result<u64, String> {
    let mut bytes = 0;
    for entry in std::fs::read_dir(root).map_err(|error| error.to_string())? {
        let entry = entry.map_err(|error| error.to_string())?;
        if entry.path().extension().and_then(|value| value.to_str()) == Some("partial") {
            bytes = bytes.max(entry.metadata().map_err(|error| error.to_string())?.len());
        }
    }
    Ok(bytes)
}

fn relay_config() -> Result<EndpointBindConfig, String> {
    let url = std::env::var("CLUSTERFLUX_TEST_RELAY_URL")
        .map_err(|_| "CLUSTERFLUX_TEST_RELAY_URL is required".to_owned())?;
    let access_token = std::env::var("CLUSTERFLUX_TEST_RELAY_TOKEN")
        .map_err(|_| "CLUSTERFLUX_TEST_RELAY_TOKEN is required".to_owned())?;
    Ok(EndpointBindConfig {
        relay: IrohRelayConfiguration::Custom(vec![ClusterfluxRelayConfig {
            url,
            access_token: Some(access_token),
        }]),
    })
}

fn relay_only_mode() -> bool {
    std::env::var("CLUSTERFLUX_EXTERNAL_RELAY_ONLY")
        .ok()
        .as_deref()
        == Some("1")
}

fn ipv6_only_mode() -> bool {
    std::env::var("CLUSTERFLUX_EXTERNAL_IPV6_ONLY")
        .ok()
        .as_deref()
        == Some("1")
}

async fn read_event<T: for<'de> Deserialize<'de>>() -> Result<T, String> {
    let line = read_line().await?;
    serde_json::from_str(line.trim()).map_err(|error| error.to_string())
}

async fn read_line() -> Result<String, String> {
    let mut line = String::new();
    let read = BufReader::new(tokio::io::stdin())
        .read_line(&mut line)
        .await
        .map_err(|error| error.to_string())?;
    if read == 0 {
        return Err("peer control input closed unexpectedly".to_owned());
    }
    Ok(line)
}

fn write_event(event: &impl Serialize) -> Result<(), String> {
    let encoded = serde_json::to_string(event).map_err(|error| error.to_string())?;
    println!("{encoded}");
    std::io::stdout().flush().map_err(|error| error.to_string())
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}

fn usage(message: &str) -> String {
    format!("{message}; usage: external_peer source|destination STATE_DIRECTORY")
}
