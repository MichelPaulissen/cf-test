use std::collections::{BTreeMap, BTreeSet};
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use clusterflux_core::{
    ArtifactId, ArtifactRelayPolicy, ArtifactTransferErrorCode, ArtifactTransferLease, Digest,
    CLUSTERFLUX_ARTIFACT_ALPN,
};
use iroh::endpoint::{Connection, RecvStream, SendStream, VarInt};
use iroh::protocol::{AcceptError, ProtocolHandler, Router};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt};
use tokio::sync::{watch, Mutex, Semaphore};

use crate::metrics::ArtifactDataPlaneMetrics;
use crate::path_policy::{
    selected_connection_path_kind, PathPolicy, PathPolicyError, PathPolicyMetrics,
};
use crate::protocol::{read_request, write_response, GetArtifactRequest, GetArtifactResponse};
use crate::ClusterfluxEndpoint;

const PROVIDER_BUFFER_BYTES: usize = 1024 * 1024;
const MAX_CONCURRENT_PROVIDER_STREAMS: usize = 32;
const STREAM_CANCEL_CODE: VarInt = VarInt::from_u32(0xCF01);

#[derive(Clone, Debug)]
pub struct ArtifactProviderRegistry {
    local_endpoint_id: String,
    leases: Arc<Mutex<BTreeMap<String, ProviderLease>>>,
    maximum_active_leases: usize,
}

#[derive(Debug)]
struct ProviderLease {
    lease: ArtifactTransferLease,
    transfer_secret: [u8; 32],
    source_path: PathBuf,
    active: bool,
    completed: bool,
    cancellation: watch::Sender<bool>,
}

impl ProviderLease {
    fn payload_matches(
        &self,
        lease: &ArtifactTransferLease,
        transfer_secret: &[u8; 32],
        source_path: &Path,
    ) -> bool {
        self.lease.tenant == lease.tenant
            && self.lease.project == lease.project
            && self.lease.process == lease.process
            && self.lease.artifact == lease.artifact
            && self.lease.digest == lease.digest
            && self.lease.size_bytes == lease.size_bytes
            && self.lease.source_node == lease.source_node
            && self.lease.destination_node == lease.destination_node
            && self.lease.source_endpoint_id == lease.source_endpoint_id
            && self.lease.destination_endpoint_id == lease.destination_endpoint_id
            && self.transfer_secret == *transfer_secret
            && self.source_path == source_path
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProviderSourceRegistration {
    Registered,
    Refreshed,
}

#[derive(Debug)]
struct AuthorizedSource {
    lease: ArtifactTransferLease,
    source_path: PathBuf,
    cancellation: watch::Receiver<bool>,
}

fn expire_leases(leases: &mut BTreeMap<String, ProviderLease>, now_epoch_seconds: u64) {
    leases.retain(|_, registered| {
        let active = registered.lease.retention_expires_at() >= now_epoch_seconds;
        if !active {
            let _ = registered.cancellation.send(true);
        }
        active
    });
}

impl ArtifactProviderRegistry {
    pub fn new(local_endpoint_id: String, maximum_active_leases: usize) -> Self {
        Self {
            local_endpoint_id,
            leases: Arc::new(Mutex::new(BTreeMap::new())),
            maximum_active_leases: maximum_active_leases.max(1),
        }
    }

    pub async fn register_verified_source(
        &self,
        lease: ArtifactTransferLease,
        transfer_secret: [u8; 32],
        source_path: impl AsRef<Path>,
        now_epoch_seconds: u64,
    ) -> Result<ProviderSourceRegistration, ProviderError> {
        lease
            .validate_bounds()
            .map_err(ProviderError::InvalidLease)?;
        if lease.source_endpoint_id != self.local_endpoint_id {
            return Err(ProviderError::WrongSourceEndpoint);
        }
        if lease.expires_at < now_epoch_seconds {
            return Err(ProviderError::LeaseExpired);
        }
        if transfer_secret.iter().all(|byte| *byte == 0) {
            return Err(ProviderError::InvalidTransferSecret);
        }
        let source_path = source_path.as_ref().to_path_buf();
        {
            let mut leases = self.leases.lock().await;
            expire_leases(&mut leases, now_epoch_seconds);
            if let Some(registered) = leases.get_mut(&lease.transfer_id) {
                if !registered.payload_matches(&lease, &transfer_secret, &source_path) {
                    return Err(ProviderError::DuplicateTransferId);
                }
                // The source was verified when this exact immutable assignment was
                // first registered. Refresh tickets and active retention without
                // re-reading the entire file on every idempotent redelivery.
                registered.lease = lease;
                registered.completed = false;
                return Ok(ProviderSourceRegistration::Refreshed);
            }
            if leases.len() >= self.maximum_active_leases {
                return Err(ProviderError::CapacityUnavailable);
            }
        }
        let (digest, size) = hash_regular_file(&source_path).await?;
        if digest != lease.digest || size != lease.size_bytes {
            return Err(ProviderError::SourceIntegrityMismatch);
        }

        let mut leases = self.leases.lock().await;
        expire_leases(&mut leases, now_epoch_seconds);
        if let Some(registered) = leases.get_mut(&lease.transfer_id) {
            if !registered.payload_matches(&lease, &transfer_secret, &source_path) {
                return Err(ProviderError::DuplicateTransferId);
            }
            registered.lease = lease;
            registered.completed = false;
            return Ok(ProviderSourceRegistration::Refreshed);
        }
        if leases.len() >= self.maximum_active_leases {
            return Err(ProviderError::CapacityUnavailable);
        }
        let (cancellation, _) = watch::channel(false);
        leases.insert(
            lease.transfer_id.clone(),
            ProviderLease {
                lease,
                transfer_secret,
                source_path,
                active: false,
                completed: false,
                cancellation,
            },
        );
        Ok(ProviderSourceRegistration::Registered)
    }

    pub async fn cancel(&self, transfer_id: &str) {
        if let Some(registered) = self.leases.lock().await.remove(transfer_id) {
            let _ = registered.cancellation.send(true);
        }
    }

    pub async fn expire(&self, now_epoch_seconds: u64) {
        let mut leases = self.leases.lock().await;
        expire_leases(&mut leases, now_epoch_seconds);
    }

    pub async fn pinned_artifacts(&self, now_epoch_seconds: u64) -> BTreeSet<ArtifactId> {
        self.leases
            .lock()
            .await
            .values()
            // A successful send is not the same as a verified receiver install. Keep the
            // source pinned for the full bounded lease lifetime so receiver verification or
            // an alternate-source retry cannot race source garbage collection.
            .filter(|registered| registered.lease.retention_expires_at() >= now_epoch_seconds)
            .map(|registered| registered.lease.artifact.clone())
            .collect()
    }

    async fn authorize(
        &self,
        remote_endpoint_id: &str,
        request: &GetArtifactRequest,
        now_epoch_seconds: u64,
    ) -> Result<AuthorizedSource, ProviderError> {
        let mut leases = self.leases.lock().await;
        let registered = leases
            .get_mut(&request.transfer_id)
            .ok_or(ProviderError::LeaseRejected)?;
        if registered.lease.expires_at < now_epoch_seconds {
            return Err(ProviderError::LeaseExpired);
        }
        if registered.completed || registered.active {
            return Err(ProviderError::LeaseReplay);
        }
        if registered.lease.destination_endpoint_id != remote_endpoint_id {
            return Err(ProviderError::PeerIdentityMismatch);
        }
        if !constant_time_eq(&registered.transfer_secret, &request.transfer_secret) {
            return Err(ProviderError::LeaseRejected);
        }
        if registered.lease.artifact != request.artifact
            || registered.lease.digest != request.expected_digest
            || registered.lease.size_bytes != request.expected_size
        {
            return Err(ProviderError::LeaseRejected);
        }
        if !registered.lease.permits_offset(request.offset) {
            return Err(ProviderError::RangeInvalid);
        }
        registered.active = true;
        Ok(AuthorizedSource {
            lease: registered.lease.clone(),
            source_path: registered.source_path.clone(),
            cancellation: registered.cancellation.subscribe(),
        })
    }

    async fn finish_attempt(&self, transfer_id: &str, completed: bool) {
        if let Some(registered) = self.leases.lock().await.get_mut(transfer_id) {
            registered.active = false;
            registered.completed |= completed;
        }
    }
}

#[derive(Clone, Debug)]
struct ArtifactProtocolHandler {
    registry: ArtifactProviderRegistry,
    data_metrics: Arc<ArtifactDataPlaneMetrics>,
    path_metrics: Arc<PathPolicyMetrics>,
    stream_slots: Arc<Semaphore>,
}

impl ArtifactProtocolHandler {
    async fn handle_stream(
        &self,
        connection: Connection,
        mut send: SendStream,
        mut receive: RecvStream,
    ) {
        let request = match read_request(&mut receive).await {
            Ok(request) => request,
            Err(_) => {
                let _ = send.reset(STREAM_CANCEL_CODE);
                return;
            }
        };
        let now = current_epoch_seconds();
        let authorized = self
            .registry
            .authorize(&connection.remote_id().to_string(), &request, now)
            .await;
        let authorized = match authorized {
            Ok(authorized) => authorized,
            Err(error) => {
                let response = GetArtifactResponse::Rejected {
                    code: error.stable_code(),
                    message: error.public_message(),
                };
                let _ = write_response(&mut send, &response).await;
                let _ = send.finish();
                return;
            }
        };
        let transfer_id = authorized.lease.transfer_id.clone();
        let path_policy = match authorized.lease.relay_policy {
            ArtifactRelayPolicy::DirectRequired => PathPolicy::direct_required(
                Duration::from_millis(authorized.lease.direct_path_deadline_ms.max(1)),
            ),
            ArtifactRelayPolicy::RelayFallbackAllowed => {
                PathPolicy::relay_fallback_allowed(Duration::ZERO)
            }
        };
        if authorized.lease.relay_policy == ArtifactRelayPolicy::DirectRequired
            && path_policy
                .wait_for_permitted_path(&connection, &self.path_metrics)
                .await
                .is_err()
        {
            // The receiver may observe the migrated direct path slightly before the
            // provider does. Let Iroh's path state converge, while still opening no
            // response body stream until the provider independently sees direct.
            let _ = write_response(
                &mut send,
                &GetArtifactResponse::Rejected {
                    code: ArtifactTransferErrorCode::RelayPathForbidden,
                    message: "deployment policy requires a direct artifact path".to_owned(),
                },
            )
            .await;
            let _ = send.finish();
            self.registry.finish_attempt(&transfer_id, false).await;
            return;
        }
        let response = GetArtifactResponse::Accepted {
            artifact: authorized.lease.artifact.clone(),
            digest: authorized.lease.digest.clone(),
            total_size: authorized.lease.size_bytes,
            offset: request.offset,
            remaining_size: authorized.lease.size_bytes.saturating_sub(request.offset),
        };
        if write_response(&mut send, &response).await.is_err() {
            self.registry.finish_attempt(&transfer_id, false).await;
            return;
        }

        let body = send_source_body(
            &connection,
            &mut send,
            &authorized.source_path,
            request.offset,
            authorized.lease.size_bytes.saturating_sub(request.offset),
            &path_policy,
            &self.path_metrics,
            &self.data_metrics,
            authorized.cancellation,
        );
        let transferred = path_policy
            .run_while_permitted(&connection, &self.path_metrics, body)
            .await;
        match transferred {
            Ok(bytes) if bytes == authorized.lease.size_bytes.saturating_sub(request.offset) => {
                let finished = send.finish().is_ok();
                self.registry.finish_attempt(&transfer_id, finished).await;
            }
            _ => {
                let _ = send.reset(STREAM_CANCEL_CODE);
                self.registry.finish_attempt(&transfer_id, false).await;
            }
        }
    }
}

impl ProtocolHandler for ArtifactProtocolHandler {
    async fn accept(&self, connection: Connection) -> Result<(), AcceptError> {
        loop {
            let (mut send, mut receive) = match connection.accept_bi().await {
                Ok(streams) => streams,
                Err(_) => return Ok(()),
            };
            let permit = match self.stream_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    let _ = receive.stop(STREAM_CANCEL_CODE);
                    let _ = write_response(
                        &mut send,
                        &GetArtifactResponse::Rejected {
                            code: ArtifactTransferErrorCode::CapacityUnavailable,
                            message: "artifact provider stream capacity is temporarily unavailable"
                                .to_owned(),
                        },
                    )
                    .await;
                    let _ = send.finish();
                    continue;
                }
            };
            let handler = self.clone();
            let stream_connection = connection.clone();
            tokio::spawn(async move {
                let _permit = permit;
                handler
                    .handle_stream(stream_connection, send, receive)
                    .await;
            });
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactProviderServer {
    router: Router,
}

impl ArtifactProviderServer {
    pub fn start(
        endpoint: &ClusterfluxEndpoint,
        registry: ArtifactProviderRegistry,
        data_metrics: Arc<ArtifactDataPlaneMetrics>,
        path_metrics: Arc<PathPolicyMetrics>,
    ) -> Self {
        let handler = ArtifactProtocolHandler {
            registry,
            data_metrics,
            path_metrics,
            stream_slots: Arc::new(Semaphore::new(MAX_CONCURRENT_PROVIDER_STREAMS)),
        };
        let router = Router::builder(endpoint.endpoint().clone())
            .accept(CLUSTERFLUX_ARTIFACT_ALPN, handler)
            .spawn();
        Self { router }
    }

    pub async fn shutdown(&self) -> Result<(), ProviderError> {
        self.router
            .shutdown()
            .await
            .map_err(|error| ProviderError::Server(error.to_string()))
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "the provider stream keeps connection policy, byte bounds, metrics, and cancellation explicit"
)]
async fn send_source_body(
    connection: &Connection,
    send: &mut iroh::endpoint::SendStream,
    source_path: &Path,
    offset: u64,
    maximum: u64,
    path_policy: &PathPolicy,
    path_metrics: &PathPolicyMetrics,
    metrics: &ArtifactDataPlaneMetrics,
    mut cancellation: watch::Receiver<bool>,
) -> Result<u64, PathPolicyError> {
    let mut file = open_regular_file(source_path)
        .map(tokio::fs::File::from_std)
        .map_err(|error| PathPolicyError::Transfer(error.to_string()))?;
    file.seek(SeekFrom::Start(offset))
        .await
        .map_err(|error| PathPolicyError::Transfer(error.to_string()))?;
    let mut remaining = maximum;
    let mut transferred = 0_u64;
    let mut buffer = vec![0; PROVIDER_BUFFER_BYTES];
    while remaining > 0 {
        if *cancellation.borrow() {
            return Err(PathPolicyError::Transfer(
                "artifact transfer cancelled".to_owned(),
            ));
        }
        let read_bound = buffer.len().min(remaining as usize);
        let read = tokio::select! {
            biased;
            changed = cancellation.changed() => {
                let _ = changed;
                return Err(PathPolicyError::Transfer("artifact transfer cancelled".to_owned()));
            }
            read = file.read(&mut buffer[..read_bound]) => {
                read.map_err(|error| PathPolicyError::Transfer(error.to_string()))?
            }
        };
        if read == 0 {
            return Err(PathPolicyError::Transfer(
                "source artifact ended before its verified size".to_owned(),
            ));
        }
        let mut written_from_buffer = 0;
        while written_from_buffer < read {
            let permitted_path = if path_policy.relay_policy == ArtifactRelayPolicy::DirectRequired
            {
                path_policy
                    .wait_for_direct_recovery(connection, path_metrics)
                    .await?
            } else {
                selected_connection_path_kind(connection)
            };
            let written = tokio::select! {
                biased;
                changed = cancellation.changed() => {
                    let _ = changed;
                    return Err(PathPolicyError::Transfer("artifact transfer cancelled".to_owned()));
                }
                written = send.write(&buffer[written_from_buffer..read]) => {
                    written.map_err(|error| PathPolicyError::Transfer(error.to_string()))?
                }
            };
            if written == 0 {
                return Err(PathPolicyError::Transfer(
                    "artifact stream accepted zero body bytes".to_owned(),
                ));
            }
            let observed_path = selected_connection_path_kind(connection);
            let accounted_path = if observed_path == clusterflux_core::ClusterfluxPathKind::Unknown
            {
                permitted_path
            } else {
                observed_path
            };
            metrics.record_body_bytes(accounted_path, written as u64);
            written_from_buffer += written;
            transferred = transferred.saturating_add(written as u64);
            remaining = remaining.saturating_sub(written as u64);
        }
    }
    Ok(transferred)
}

async fn hash_regular_file(path: &Path) -> Result<(Digest, u64), ProviderError> {
    let mut file = tokio::fs::File::from_std(open_regular_file(path)?);
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0; PROVIDER_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(ProviderError::SourceTooLarge)?;
        hasher.update(&buffer[..read]);
    }
    let digest = Digest::from_sha256_hex(hex::encode(hasher.finalize()))
        .map_err(ProviderError::InvalidDigest)?;
    Ok((digest, size))
}

fn open_regular_file(path: &Path) -> Result<std::fs::File, ProviderError> {
    let metadata = std::fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ProviderError::UnsafeSourcePath);
    }
    let mut options = std::fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

fn constant_time_eq(left: &[u8; 32], right: &[u8; 32]) -> bool {
    left.iter()
        .zip(right)
        .fold(0_u8, |difference, (left, right)| {
            difference | (left ^ right)
        })
        == 0
}

fn current_epoch_seconds() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|duration| duration.as_secs())
        .unwrap_or_default()
}

#[derive(Debug, Error)]
pub enum ProviderError {
    #[error("artifact transfer lease is invalid: {0}")]
    InvalidLease(String),
    #[error("artifact transfer lease is not registered on its source endpoint")]
    WrongSourceEndpoint,
    #[error("artifact transfer lease has expired")]
    LeaseExpired,
    #[error("artifact transfer secret must be random and non-zero")]
    InvalidTransferSecret,
    #[error("artifact source path is not a regular non-symlink file")]
    UnsafeSourcePath,
    #[error("artifact source does not match coordinator size/digest metadata")]
    SourceIntegrityMismatch,
    #[error("artifact source size overflowed")]
    SourceTooLarge,
    #[error("artifact provider has no capacity for another lease")]
    CapacityUnavailable,
    #[error("artifact transfer ID is already registered")]
    DuplicateTransferId,
    #[error("artifact transfer lease was rejected")]
    LeaseRejected,
    #[error("artifact transfer lease is already active or completed")]
    LeaseReplay,
    #[error("authenticated peer does not match the transfer destination")]
    PeerIdentityMismatch,
    #[error("artifact transfer range is outside the lease")]
    RangeInvalid,
    #[error("artifact digest is invalid: {0}")]
    InvalidDigest(String),
    #[error("artifact provider server failed: {0}")]
    Server(String),
    #[error(transparent)]
    Io(#[from] std::io::Error),
}

impl ProviderError {
    pub fn stable_code(&self) -> ArtifactTransferErrorCode {
        match self {
            Self::LeaseExpired => ArtifactTransferErrorCode::TransferLeaseExpired,
            Self::PeerIdentityMismatch => ArtifactTransferErrorCode::PeerIdentityMismatch,
            Self::RangeInvalid => ArtifactTransferErrorCode::RangeInvalid,
            Self::CapacityUnavailable => ArtifactTransferErrorCode::CapacityUnavailable,
            Self::UnsafeSourcePath | Self::SourceIntegrityMismatch | Self::Io(_) => {
                ArtifactTransferErrorCode::ArtifactMissingAtSource
            }
            _ => ArtifactTransferErrorCode::TransferLeaseRejected,
        }
    }

    fn public_message(&self) -> String {
        match self.stable_code() {
            ArtifactTransferErrorCode::TransferLeaseExpired => {
                "artifact transfer authorization expired".to_owned()
            }
            ArtifactTransferErrorCode::PeerIdentityMismatch => {
                "authenticated peer is not the authorized receiver".to_owned()
            }
            ArtifactTransferErrorCode::RangeInvalid => {
                "artifact resume offset is not authorized".to_owned()
            }
            ArtifactTransferErrorCode::CapacityUnavailable => {
                "artifact provider capacity is unavailable".to_owned()
            }
            ArtifactTransferErrorCode::ArtifactMissingAtSource => {
                "authorized artifact is unavailable at the source".to_owned()
            }
            _ => "artifact transfer authorization was rejected".to_owned(),
        }
    }
}

#[cfg(test)]
mod tests {
    use clusterflux_core::{NodeId, ProcessId, ProjectId, TenantId};

    use super::*;

    fn lease(bytes: &[u8]) -> ArtifactTransferLease {
        ArtifactTransferLease {
            transfer_id: "provider-redelivery".to_owned(),
            tenant: TenantId::from("tenant"),
            project: ProjectId::from("project"),
            process: ProcessId::from("process"),
            artifact: ArtifactId::from("artifact"),
            digest: Digest::sha256(bytes),
            size_bytes: bytes.len() as u64,
            source_node: NodeId::from("source"),
            source_endpoint_id: "source-endpoint".to_owned(),
            destination_node: NodeId::from("destination"),
            destination_endpoint_id: "destination-endpoint".to_owned(),
            allowed_offset: 0,
            maximum_bytes: bytes.len() as u64,
            relay_policy: ArtifactRelayPolicy::DirectRequired,
            direct_path_deadline_ms: 5_000,
            expires_at: 120,
            active_lease_expires_at: 180,
            nonce: "provider-redelivery-nonce".to_owned(),
        }
    }

    #[test]
    fn identical_assignment_redelivery_refreshes_without_rehashing_source() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let original = b"verified-source";
        std::fs::write(&source, original).unwrap();
        let registry = ArtifactProviderRegistry::new("source-endpoint".to_owned(), 2);
        let secret = [7_u8; 32];
        let mut authorization = lease(original);

        assert_eq!(
            runtime
                .block_on(registry.register_verified_source(
                    authorization.clone(),
                    secret,
                    &source,
                    100,
                ))
                .unwrap(),
            ProviderSourceRegistration::Registered
        );

        // If the idempotent path re-opened or re-hashed the file, this mutation
        // would make the refresh fail. The original immutable assignment remains
        // the authority and only its bounded lifetimes may change.
        std::fs::write(&source, b"tampered-source").unwrap();
        authorization.expires_at = 150;
        authorization.active_lease_expires_at = 210;
        assert_eq!(
            runtime
                .block_on(registry.register_verified_source(
                    authorization.clone(),
                    secret,
                    &source,
                    110,
                ))
                .unwrap(),
            ProviderSourceRegistration::Refreshed
        );

        let error = runtime
            .block_on(registry.register_verified_source(authorization, [8_u8; 32], &source, 110))
            .unwrap_err();
        assert!(matches!(error, ProviderError::DuplicateTransferId));
    }

    #[test]
    fn retired_provider_lease_signals_active_stream_cancellation() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("source");
        let bytes = b"cancellable-source";
        std::fs::write(&source, bytes).unwrap();
        let registry = ArtifactProviderRegistry::new("source-endpoint".to_owned(), 2);
        let lease = lease(bytes);
        let secret = [9_u8; 32];
        runtime
            .block_on(registry.register_verified_source(lease.clone(), secret, &source, 100))
            .unwrap();
        let request = GetArtifactRequest::new(
            lease.transfer_id.clone(),
            secret,
            lease.artifact.clone(),
            lease.digest.clone(),
            lease.size_bytes,
            0,
        );
        let authorized = runtime
            .block_on(registry.authorize("destination-endpoint", &request, 100))
            .unwrap();
        assert!(!*authorized.cancellation.borrow());

        runtime.block_on(registry.cancel(&lease.transfer_id));

        assert!(*authorized.cancellation.borrow());
        assert!(runtime.block_on(registry.pinned_artifacts(100)).is_empty());
    }
}
