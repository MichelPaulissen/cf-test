use std::path::PathBuf;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use clusterflux_artifact_transfer::{
    ArtifactDataPlaneMetrics, ArtifactProviderRegistry, ArtifactProviderServer, ArtifactReceiver,
    ClusterfluxEndpoint, EndpointBindConfig, IrohIdentityScope, PartialStoreConfig,
    PathPolicyMetrics, PersistentIrohIdentity,
};
use clusterflux_core::{
    ArtifactId, ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferErrorCode,
    ArtifactTransferLease, AuthorizedPeerEndpoint, ClusterfluxRelayConfig, Digest,
    IrohRelayConfiguration, NodeId, ProcessId, ProjectId, TenantId,
};
use serde::Serialize;

const ARTIFACT_BYTES: usize = 1_000_000;

#[derive(Debug)]
struct Arguments {
    mode: String,
    state_dir: PathBuf,
    tenant: TenantId,
    project: ProjectId,
    source_node: NodeId,
    destination_node: NodeId,
    relay_url: String,
}

#[derive(Debug, Serialize)]
struct IdentityEvidence {
    event: &'static str,
    source_endpoint_id: String,
    destination_endpoint_id: String,
}

#[derive(Debug, Serialize)]
struct BodyNegativeEvidence {
    event: &'static str,
    error_code: ArtifactTransferErrorCode,
    final_artifact_installed: bool,
    source_direct_body_bytes: u64,
    source_relayed_body_bytes: u64,
    source_unknown_path_body_bytes: u64,
    destination_direct_body_bytes: u64,
    destination_relayed_body_bytes: u64,
    destination_unknown_path_body_bytes: u64,
    source_selected_relay: u64,
    destination_selected_relay: u64,
}

#[derive(Debug, Serialize)]
struct ConnectionLimitEvidence {
    event: &'static str,
    attempted_connections: usize,
    local_relay_addresses: usize,
}

#[derive(Debug, Serialize)]
struct RevocationEvidence {
    event: &'static str,
    local_relay_address_present: bool,
}

#[tokio::main(flavor = "multi_thread", worker_threads = 4)]
async fn main() {
    if let Err(error) = run().await {
        eprintln!("public hosted relay proof failed: {error}");
        std::process::exit(1);
    }
}

async fn run() -> Result<(), String> {
    let arguments = arguments()?;
    std::fs::create_dir_all(&arguments.state_dir).map_err(|error| error.to_string())?;
    let source_identity = identity(&arguments, true)?;
    let destination_identity = identity(&arguments, false)?;
    match arguments.mode.as_str() {
        "identity" => write_evidence(&IdentityEvidence {
            event: "public_hosted_identities",
            source_endpoint_id: source_identity.endpoint_id(),
            destination_endpoint_id: destination_identity.endpoint_id(),
        }),
        "body-negative" => {
            run_body_negative(&arguments, &source_identity, &destination_identity).await
        }
        "connection-limit" => run_connection_limit(&arguments, &source_identity).await,
        "revoked" => run_revoked(&arguments, &source_identity).await,
        _ => Err(usage()),
    }
}

fn arguments() -> Result<Arguments, String> {
    let mut arguments = std::env::args().skip(1);
    let parsed = Arguments {
        mode: arguments.next().ok_or_else(usage)?,
        state_dir: PathBuf::from(arguments.next().ok_or_else(usage)?),
        tenant: TenantId::new(arguments.next().ok_or_else(usage)?),
        project: ProjectId::new(arguments.next().ok_or_else(usage)?),
        source_node: NodeId::new(arguments.next().ok_or_else(usage)?),
        destination_node: NodeId::new(arguments.next().ok_or_else(usage)?),
        relay_url: arguments.next().ok_or_else(usage)?,
    };
    if arguments.next().is_some() {
        return Err(usage());
    }
    Ok(parsed)
}

fn usage() -> String {
    "usage: public_hosted_relay <identity|body-negative|connection-limit|revoked> STATE_DIR TENANT PROJECT SOURCE_NODE DESTINATION_NODE RELAY_URL".to_owned()
}

fn identity(arguments: &Arguments, source: bool) -> Result<PersistentIrohIdentity, String> {
    let (directory, node) = if source {
        ("source", arguments.source_node.clone())
    } else {
        ("destination", arguments.destination_node.clone())
    };
    PersistentIrohIdentity::load_or_create(
        arguments
            .state_dir
            .join(directory)
            .join("iroh-identity.json"),
        IrohIdentityScope {
            tenant: arguments.tenant.clone(),
            project: arguments.project.clone(),
            node,
        },
    )
    .map_err(|error| error.to_string())
}

fn relay_config(arguments: &Arguments) -> EndpointBindConfig {
    EndpointBindConfig {
        relay: IrohRelayConfiguration::Custom(vec![ClusterfluxRelayConfig {
            url: arguments.relay_url.clone(),
            access_token: None,
        }]),
    }
}

async fn bind_relay_only(
    arguments: &Arguments,
    identity: &PersistentIrohIdentity,
) -> Result<ClusterfluxEndpoint, String> {
    ClusterfluxEndpoint::bind_relay_only_for_diagnostics(identity, relay_config(arguments))
        .await
        .map_err(|error| error.to_string())
}

async fn wait_for_relay(
    endpoint: &ClusterfluxEndpoint,
    relay_url: &str,
    timeout: Duration,
) -> Result<bool, String> {
    let deadline = tokio::time::Instant::now() + timeout;
    let expected = relay_url.trim_end_matches('/');
    loop {
        let advertisement = endpoint
            .advertisement(1, now()?.saturating_add(120))
            .map_err(|error| error.to_string())?;
        if advertisement
            .relay_urls
            .iter()
            .any(|url| url.trim_end_matches('/') == expected)
        {
            return Ok(true);
        }
        if tokio::time::Instant::now() >= deadline {
            return Ok(false);
        }
        tokio::time::sleep(Duration::from_millis(100)).await;
    }
}

async fn run_connection_limit(
    arguments: &Arguments,
    identity: &PersistentIrohIdentity,
) -> Result<(), String> {
    let mut endpoints = Vec::new();
    let mut relay_addresses = 0_usize;
    for index in 0..3 {
        let endpoint = bind_relay_only(arguments, identity).await?;
        let connected = wait_for_relay(
            &endpoint,
            &arguments.relay_url,
            if index < 2 {
                Duration::from_secs(10)
            } else {
                Duration::from_secs(4)
            },
        )
        .await?;
        relay_addresses += usize::from(connected);
        endpoints.push(endpoint);
    }
    let evidence = ConnectionLimitEvidence {
        event: "public_hosted_connection_limit",
        attempted_connections: endpoints.len(),
        local_relay_addresses: relay_addresses,
    };
    for endpoint in endpoints {
        endpoint.close().await;
    }
    write_evidence(&evidence)
}

async fn run_body_negative(
    arguments: &Arguments,
    source_identity: &PersistentIrohIdentity,
    destination_identity: &PersistentIrohIdentity,
) -> Result<(), String> {
    let source_endpoint = bind_relay_only(arguments, source_identity).await?;
    let destination_endpoint = bind_relay_only(arguments, destination_identity).await?;
    if !wait_for_relay(
        &source_endpoint,
        &arguments.relay_url,
        Duration::from_secs(10),
    )
    .await?
        || !wait_for_relay(
            &destination_endpoint,
            &arguments.relay_url,
            Duration::from_secs(10),
        )
        .await?
    {
        return Err("authorized public relay did not admit both active EndpointIds".to_owned());
    }

    let artifact_bytes = (0..ARTIFACT_BYTES)
        .map(|index| (index % 251) as u8)
        .collect::<Vec<_>>();
    let artifact = ArtifactId::from("public-hosted-body-negative");
    let digest = Digest::sha256(&artifact_bytes);
    let source_path = arguments.state_dir.join("source-artifact");
    std::fs::write(&source_path, &artifact_bytes).map_err(|error| error.to_string())?;
    let now = now()?;
    let lease = ArtifactTransferLease {
        transfer_id: "public-hosted-body-negative".to_owned(),
        tenant: arguments.tenant.clone(),
        project: arguments.project.clone(),
        process: ProcessId::from("public-hosted-relay-proof"),
        artifact: artifact.clone(),
        digest,
        size_bytes: artifact_bytes.len() as u64,
        source_node: arguments.source_node.clone(),
        source_endpoint_id: source_endpoint.endpoint_id(),
        destination_node: arguments.destination_node.clone(),
        destination_endpoint_id: destination_endpoint.endpoint_id(),
        allowed_offset: 0,
        maximum_bytes: artifact_bytes.len() as u64,
        relay_policy: ArtifactRelayPolicy::DirectRequired,
        direct_path_deadline_ms: 5_000,
        expires_at: now.saturating_add(60),
        active_lease_expires_at: now.saturating_add(60),
        nonce: "public-hosted-body-negative".to_owned(),
    };
    let transfer_secret = [0x5a; 32];
    let registry = ArtifactProviderRegistry::new(source_endpoint.endpoint_id(), 4);
    registry
        .register_verified_source(lease.clone(), transfer_secret, &source_path, now)
        .await
        .map_err(|error| error.to_string())?;
    let source_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let source_paths = Arc::new(PathPolicyMetrics::default());
    let provider = ArtifactProviderServer::start(
        &source_endpoint,
        registry,
        Arc::clone(&source_metrics),
        Arc::clone(&source_paths),
    );
    let authorization = ArtifactTransferAuthorization {
        lease,
        transfer_secret,
        peer: AuthorizedPeerEndpoint {
            node: arguments.source_node.clone(),
            endpoint_id: source_endpoint.endpoint_id(),
            generation: source_identity.generation(),
            direct_addresses: Vec::new(),
            relay_urls: vec![arguments.relay_url.clone()],
        },
    };
    let destination_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
    let destination_paths = Arc::new(PathPolicyMetrics::default());
    let receiver = ArtifactReceiver::new(
        destination_endpoint.clone(),
        PartialStoreConfig::new(arguments.state_dir.join("destination-partials")),
        Arc::clone(&destination_metrics),
        Arc::clone(&destination_paths),
    )
    .map_err(|error| error.to_string())?
    .with_path_deadlines(Duration::from_secs(3), Duration::ZERO);
    let destination_path = arguments.state_dir.join("installed-artifact");
    let error = receiver
        .download(&authorization, &destination_path, now)
        .await
        .expect_err("relay-only public path must not open a DirectRequired artifact stream");
    if error.stable_code() != ArtifactTransferErrorCode::DirectPathTimeout {
        return Err(format!(
            "public body-negative attempt returned {}, not direct_path_timeout: {error}",
            error.stable_code().as_str()
        ));
    }
    let source = source_metrics.snapshot();
    let destination = destination_metrics.snapshot();
    let evidence = BodyNegativeEvidence {
        event: "public_hosted_body_negative",
        error_code: error.stable_code(),
        final_artifact_installed: destination_path.exists(),
        source_direct_body_bytes: source.direct_body_bytes,
        source_relayed_body_bytes: source.relayed_body_bytes,
        source_unknown_path_body_bytes: source.unknown_path_body_bytes,
        destination_direct_body_bytes: destination.direct_body_bytes,
        destination_relayed_body_bytes: destination.relayed_body_bytes,
        destination_unknown_path_body_bytes: destination.unknown_path_body_bytes,
        source_selected_relay: source_paths.selected_relay(),
        destination_selected_relay: destination_paths.selected_relay(),
    };
    receiver.close_connections().await;
    provider
        .shutdown()
        .await
        .map_err(|error| error.to_string())?;
    destination_endpoint.close().await;
    source_endpoint.close().await;
    if evidence.final_artifact_installed
        || evidence.source_direct_body_bytes != 0
        || evidence.source_relayed_body_bytes != 0
        || evidence.source_unknown_path_body_bytes != 0
        || evidence.destination_direct_body_bytes != 0
        || evidence.destination_relayed_body_bytes != 0
        || evidence.destination_unknown_path_body_bytes != 0
        || evidence.destination_selected_relay == 0
    {
        return Err(format!(
            "public relay body-negative invariants failed: {evidence:?}"
        ));
    }
    write_evidence(&evidence)
}

async fn run_revoked(
    arguments: &Arguments,
    identity: &PersistentIrohIdentity,
) -> Result<(), String> {
    let endpoint = bind_relay_only(arguments, identity).await?;
    let relay_advertised =
        wait_for_relay(&endpoint, &arguments.relay_url, Duration::from_secs(5)).await?;
    endpoint.close().await;
    write_evidence(&RevocationEvidence {
        event: "public_hosted_revocation_denied",
        local_relay_address_present: relay_advertised,
    })
}

fn write_evidence(value: &impl Serialize) -> Result<(), String> {
    println!(
        "{}",
        serde_json::to_string(value).map_err(|error| error.to_string())?
    );
    Ok(())
}

fn now() -> Result<u64, String> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .map_err(|error| error.to_string())
}
