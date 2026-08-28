use std::fs;
use std::io::SeekFrom;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, AtomicU8, Ordering};
use std::sync::Arc;
use std::time::Duration;

use clusterflux_core::{
    ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferErrorCode, Digest,
};
use iroh::endpoint::VarInt;
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncSeekExt, AsyncWriteExt};

use crate::metrics::ArtifactDataPlaneMetrics;
use crate::path_policy::{
    selected_connection_path_kind, PathPolicy, PathPolicyError, PathPolicyMetrics,
};
use crate::pool::{ConnectionPool, ConnectionPoolKey};
use crate::protocol::{read_response, write_request, GetArtifactRequest, GetArtifactResponse};
use crate::ClusterfluxEndpoint;

const RECEIVER_BUFFER_BYTES: usize = 1024 * 1024;
const STREAM_CANCEL_CODE: VarInt = VarInt::from_u32(0xCF02);

#[derive(Debug, Default)]
pub struct TransferProgress {
    bytes_verified: AtomicU64,
    path_kind: AtomicU8,
}

impl TransferProgress {
    pub fn snapshot(&self) -> (u64, clusterflux_core::ClusterfluxPathKind) {
        let path = match self.path_kind.load(Ordering::Acquire) {
            1 => clusterflux_core::ClusterfluxPathKind::Local,
            2 => clusterflux_core::ClusterfluxPathKind::Direct,
            3 => clusterflux_core::ClusterfluxPathKind::Relayed,
            _ => clusterflux_core::ClusterfluxPathKind::Unknown,
        };
        (self.bytes_verified.load(Ordering::Acquire), path)
    }

    fn record(&self, bytes_verified: u64, path: clusterflux_core::ClusterfluxPathKind) {
        self.bytes_verified.store(bytes_verified, Ordering::Release);
        self.path_kind.store(
            match path {
                clusterflux_core::ClusterfluxPathKind::Local => 1,
                clusterflux_core::ClusterfluxPathKind::Direct => 2,
                clusterflux_core::ClusterfluxPathKind::Relayed => 3,
                clusterflux_core::ClusterfluxPathKind::Unknown => 0,
            },
            Ordering::Release,
        );
    }
}

#[derive(Clone, Debug)]
pub struct PartialStoreConfig {
    pub root: PathBuf,
    pub maximum_total_bytes: u64,
    pub maximum_partial_count: usize,
    pub maximum_age: Duration,
}

impl PartialStoreConfig {
    pub fn new(root: PathBuf) -> Self {
        Self {
            root,
            maximum_total_bytes: 64 * 1024 * 1024 * 1024,
            maximum_partial_count: 128,
            maximum_age: Duration::from_secs(24 * 60 * 60),
        }
    }
}

#[derive(Clone, Debug)]
pub struct ArtifactReceiver {
    endpoint: ClusterfluxEndpoint,
    partials: PartialStore,
    pool: Arc<ConnectionPool>,
    data_metrics: Arc<ArtifactDataPlaneMetrics>,
    path_metrics: Arc<PathPolicyMetrics>,
    direct_path_deadline: Duration,
    direct_path_grace_period: Duration,
}

impl ArtifactReceiver {
    pub fn new(
        endpoint: ClusterfluxEndpoint,
        partial_config: PartialStoreConfig,
        data_metrics: Arc<ArtifactDataPlaneMetrics>,
        path_metrics: Arc<PathPolicyMetrics>,
    ) -> Result<Self, ReceiveError> {
        Ok(Self {
            endpoint,
            partials: PartialStore::open(partial_config)?,
            pool: Arc::new(ConnectionPool::new(64, Duration::from_secs(5 * 60))),
            data_metrics,
            path_metrics,
            direct_path_deadline: Duration::from_secs(20),
            direct_path_grace_period: Duration::from_secs(2),
        })
    }

    pub fn with_path_deadlines(
        mut self,
        direct_path_deadline: Duration,
        direct_path_grace_period: Duration,
    ) -> Self {
        self.direct_path_deadline = direct_path_deadline;
        self.direct_path_grace_period = direct_path_grace_period;
        self
    }

    pub async fn download(
        &self,
        authorization: &ArtifactTransferAuthorization,
        destination_path: impl AsRef<Path>,
        now_epoch_seconds: u64,
    ) -> Result<CompletedTransfer, ReceiveError> {
        self.download_with_progress(authorization, destination_path, now_epoch_seconds, None)
            .await
    }

    pub async fn download_with_progress(
        &self,
        authorization: &ArtifactTransferAuthorization,
        destination_path: impl AsRef<Path>,
        now_epoch_seconds: u64,
        progress: Option<&TransferProgress>,
    ) -> Result<CompletedTransfer, ReceiveError> {
        self.validate_authorization(authorization, now_epoch_seconds)?;
        let lease = &authorization.lease;
        let destination_path = destination_path.as_ref();
        if let Some(existing) =
            verify_existing_destination(destination_path, &lease.digest, lease.size_bytes).await?
        {
            if let Some(progress) = progress {
                progress.record(
                    lease.size_bytes,
                    clusterflux_core::ClusterfluxPathKind::Local,
                );
            }
            return Ok(CompletedTransfer {
                artifact: lease.artifact.clone(),
                digest: lease.digest.clone(),
                size_bytes: lease.size_bytes,
                installed_path: existing,
                resumed_from: lease.size_bytes,
                bytes_transferred: 0,
                path_kind: clusterflux_core::ClusterfluxPathKind::Local,
                already_present: true,
            });
        }

        let mut partial = self
            .partials
            .prepare(authorization, now_epoch_seconds)
            .await?;
        let resumed_from = partial.received_bytes;
        let key = ConnectionPoolKey::new(
            lease.tenant.clone(),
            lease.project.clone(),
            &authorization.peer,
            lease.relay_policy,
        );
        let connection = self
            .pool
            .get_or_connect(&self.endpoint, key.clone(), &authorization.peer)
            .await
            .map_err(|error| ReceiveError::Connection(error.to_string()))?;
        let policy = match lease.relay_policy {
            ArtifactRelayPolicy::DirectRequired => {
                PathPolicy::direct_required(self.direct_path_deadline)
            }
            ArtifactRelayPolicy::RelayFallbackAllowed => {
                PathPolicy::relay_fallback_allowed(self.direct_path_grace_period)
            }
        };
        let initial_path = match policy
            .wait_for_permitted_path(&connection, &self.path_metrics)
            .await
        {
            Ok(path) => path,
            Err(error) => {
                self.pool.invalidate(&key).await;
                return Err(error.into());
            }
        };
        if let Some(progress) = progress {
            progress.record(resumed_from, initial_path);
        }

        // The artifact stream is deliberately not opened until the selected path satisfies
        // the lease policy. This keeps hosted assist relays free of normal body bytes.
        let (mut send, mut receive) = connection
            .open_bi()
            .await
            .map_err(|error| ReceiveError::Connection(error.to_string()))?;
        let request = GetArtifactRequest::new(
            lease.transfer_id.clone(),
            authorization.transfer_secret,
            lease.artifact.clone(),
            lease.digest.clone(),
            lease.size_bytes,
            resumed_from,
        );
        write_request(&mut send, &request).await?;
        send.finish()
            .map_err(|error| ReceiveError::Connection(error.to_string()))?;
        match read_response(&mut receive).await? {
            GetArtifactResponse::Accepted {
                artifact,
                digest,
                total_size,
                offset,
                remaining_size,
            } if artifact == lease.artifact
                && digest == lease.digest
                && total_size == lease.size_bytes
                && offset == resumed_from
                && remaining_size == lease.size_bytes.saturating_sub(resumed_from) => {}
            GetArtifactResponse::Accepted { .. } => {
                let _ = receive.stop(STREAM_CANCEL_CODE);
                return Err(ReceiveError::ResponseMismatch);
            }
            GetArtifactResponse::Rejected { code, message } => {
                return Err(ReceiveError::Rejected { code, message });
            }
        }

        let body = receive_body(
            &connection,
            &mut receive,
            &mut partial,
            lease.size_bytes,
            &self.data_metrics,
            progress,
        );
        let received = policy
            .run_while_permitted(&connection, &self.path_metrics, body)
            .await;
        let received = match received {
            Ok(received) => received,
            Err(error) => {
                let _ = receive.stop(STREAM_CANCEL_CODE);
                partial.persist_metadata(now_epoch_seconds)?;
                if matches!(error, PathPolicyError::RelayPathForbidden) {
                    self.pool.invalidate(&key).await;
                }
                return Err(error.into());
            }
        };
        if partial.received_bytes != lease.size_bytes {
            partial.persist_metadata(now_epoch_seconds)?;
            return Err(ReceiveError::SizeMismatch {
                expected: lease.size_bytes,
                actual: partial.received_bytes,
            });
        }
        partial.file.sync_all().await?;
        let actual_digest = Digest::from_sha256_hex(hex::encode(partial.hasher.clone().finalize()))
            .map_err(ReceiveError::InvalidDigest)?;
        if actual_digest != lease.digest {
            self.data_metrics.record_integrity_failure();
            partial.remove()?;
            return Err(ReceiveError::DigestMismatch);
        }
        let installed_path = partial.install(destination_path, &lease.digest, lease.size_bytes)?;
        self.data_metrics.record_completed(resumed_from > 0);
        Ok(CompletedTransfer {
            artifact: lease.artifact.clone(),
            digest: lease.digest.clone(),
            size_bytes: lease.size_bytes,
            installed_path,
            resumed_from,
            bytes_transferred: received,
            path_kind: selected_connection_path_kind(&connection).max_by_fallback(initial_path),
            already_present: false,
        })
    }

    pub async fn warm_authorized_peer(
        &self,
        authorization: &ArtifactTransferAuthorization,
        now_epoch_seconds: u64,
    ) -> Result<clusterflux_core::ClusterfluxPathKind, ReceiveError> {
        self.validate_authorization(authorization, now_epoch_seconds)?;
        let lease = &authorization.lease;
        let key = ConnectionPoolKey::new(
            lease.tenant.clone(),
            lease.project.clone(),
            &authorization.peer,
            lease.relay_policy,
        );
        let connection = self
            .pool
            .get_or_connect(&self.endpoint, key.clone(), &authorization.peer)
            .await
            .map_err(|error| ReceiveError::Connection(error.to_string()))?;
        let policy = match lease.relay_policy {
            ArtifactRelayPolicy::DirectRequired => {
                PathPolicy::direct_required(self.direct_path_deadline)
            }
            ArtifactRelayPolicy::RelayFallbackAllowed => {
                PathPolicy::relay_fallback_allowed(self.direct_path_grace_period)
            }
        };
        match policy
            .wait_for_permitted_path(&connection, &self.path_metrics)
            .await
        {
            Ok(path) => Ok(path),
            Err(error) => {
                self.pool.invalidate(&key).await;
                Err(error.into())
            }
        }
    }

    pub fn garbage_collect_partials(&self, now_epoch_seconds: u64) -> Result<usize, ReceiveError> {
        self.partials.garbage_collect(now_epoch_seconds)
    }

    /// Extends the retention lifetime of an existing verified partial after the
    /// coordinator renews the active transfer lease. The exact transfer,
    /// artifact, digest, and size must still match, so renewal cannot adopt an
    /// unrelated partial or weaken its integrity binding.
    pub fn renew_partial(
        &self,
        authorization: &ArtifactTransferAuthorization,
        now_epoch_seconds: u64,
    ) -> Result<bool, ReceiveError> {
        self.validate_authorization_identity(authorization)?;
        if authorization.lease.retention_expires_at() < now_epoch_seconds {
            return Err(ReceiveError::LeaseExpired);
        }
        self.partials.renew(authorization, now_epoch_seconds)
    }

    pub async fn close_connections(&self) {
        self.pool.close_all().await;
    }

    fn validate_authorization(
        &self,
        authorization: &ArtifactTransferAuthorization,
        now_epoch_seconds: u64,
    ) -> Result<(), ReceiveError> {
        self.validate_authorization_identity(authorization)?;
        if authorization.lease.expires_at < now_epoch_seconds {
            return Err(ReceiveError::LeaseExpired);
        }
        Ok(())
    }

    fn validate_authorization_identity(
        &self,
        authorization: &ArtifactTransferAuthorization,
    ) -> Result<(), ReceiveError> {
        authorization
            .lease
            .validate_bounds()
            .map_err(ReceiveError::InvalidLease)?;
        authorization
            .peer
            .validate_bounds()
            .map_err(ReceiveError::InvalidPeer)?;
        let scope = self.endpoint.identity_scope();
        let lease = &authorization.lease;
        if lease.tenant != scope.tenant
            || lease.project != scope.project
            || lease.destination_node != scope.node
            || lease.destination_endpoint_id != self.endpoint.endpoint_id()
        {
            return Err(ReceiveError::WrongDestination);
        }
        if authorization.peer.node != lease.source_node
            || authorization.peer.endpoint_id != lease.source_endpoint_id
        {
            return Err(ReceiveError::PeerIdentityMismatch);
        }
        if authorization.transfer_secret.iter().all(|byte| *byte == 0) {
            return Err(ReceiveError::InvalidTransferSecret);
        }
        Ok(())
    }
}

trait PathKindFallback {
    fn max_by_fallback(self, fallback: Self) -> Self;
}

impl PathKindFallback for clusterflux_core::ClusterfluxPathKind {
    fn max_by_fallback(self, fallback: Self) -> Self {
        if self == Self::Unknown {
            fallback
        } else {
            self
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CompletedTransfer {
    pub artifact: clusterflux_core::ArtifactId,
    pub digest: Digest,
    pub size_bytes: u64,
    pub installed_path: PathBuf,
    pub resumed_from: u64,
    pub bytes_transferred: u64,
    pub path_kind: clusterflux_core::ClusterfluxPathKind,
    pub already_present: bool,
}

#[derive(Clone, Debug)]
struct PartialStore {
    config: PartialStoreConfig,
}

impl PartialStore {
    fn open(config: PartialStoreConfig) -> Result<Self, ReceiveError> {
        fs::create_dir_all(&config.root)?;
        let metadata = fs::symlink_metadata(&config.root)?;
        if metadata.file_type().is_symlink() || !metadata.is_dir() {
            return Err(ReceiveError::UnsafePartialRoot);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&config.root, fs::Permissions::from_mode(0o700))?;
        }
        if config.maximum_total_bytes == 0 || config.maximum_partial_count == 0 {
            return Err(ReceiveError::InvalidPartialLimits);
        }
        Ok(Self { config })
    }

    async fn prepare(
        &self,
        authorization: &ArtifactTransferAuthorization,
        now_epoch_seconds: u64,
    ) -> Result<PartialSession, ReceiveError> {
        let stem = partial_stem(authorization);
        let partial_path = self.config.root.join(format!("{stem}.partial"));
        let metadata_path = self.config.root.join(format!("{stem}.json"));
        self.ensure_capacity(&partial_path, authorization.lease.size_bytes)?;
        let expected = PartialMetadata {
            transfer_id: authorization.lease.transfer_id.clone(),
            artifact: authorization.lease.artifact.clone(),
            digest: authorization.lease.digest.clone(),
            expected_size: authorization.lease.size_bytes,
            received_contiguous_bytes: 0,
            last_update: now_epoch_seconds,
            expiry: authorization.lease.retention_expires_at(),
        };

        let mut metadata = match fs::symlink_metadata(&metadata_path) {
            Ok(file_metadata) => {
                if file_metadata.file_type().is_symlink() || !file_metadata.is_file() {
                    return Err(ReceiveError::UnsafePartialMetadata);
                }
                let mut stored: PartialMetadata =
                    serde_json::from_slice(&fs::read(&metadata_path)?)?;
                if stored.artifact != expected.artifact
                    || stored.digest != expected.digest
                    || stored.expected_size != expected.expected_size
                {
                    return Err(ReceiveError::PartialMetadataMismatch);
                }
                // A failed source may be replaced by a new short-lived lease. The verified
                // contiguous prefix remains valid because the stable key and these checks bind
                // it to the same destination-scoped artifact digest and exact size.
                stored.transfer_id = expected.transfer_id;
                stored.expiry = expected.expiry;
                stored
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => expected,
            Err(error) => return Err(error.into()),
        };

        let standard_file = match fs::symlink_metadata(&partial_path) {
            Ok(file_metadata) => {
                if file_metadata.file_type().is_symlink() || !file_metadata.is_file() {
                    return Err(ReceiveError::UnsafePartialPath);
                }
                open_partial_file(&partial_path, false)?
            }
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
                open_partial_file(&partial_path, true)?
            }
            Err(error) => return Err(error.into()),
        };
        let mut file = tokio::fs::File::from_std(standard_file);
        let actual_length = file.metadata().await?.len();
        if actual_length > authorization.lease.size_bytes {
            return Err(ReceiveError::PartialExceedsExpectedSize);
        }
        let mut hasher = Sha256::new();
        file.seek(SeekFrom::Start(0)).await?;
        let mut verified = 0_u64;
        let mut buffer = vec![0; RECEIVER_BUFFER_BYTES];
        loop {
            let read = file.read(&mut buffer).await?;
            if read == 0 {
                break;
            }
            verified = verified.saturating_add(read as u64);
            hasher.update(&buffer[..read]);
        }
        if verified != actual_length {
            return Err(ReceiveError::PartialReadChanged);
        }
        metadata.received_contiguous_bytes = verified;
        metadata.last_update = now_epoch_seconds;
        file.seek(SeekFrom::Start(verified)).await?;
        let mut session = PartialSession {
            partial_path,
            metadata_path,
            metadata,
            file,
            hasher,
            received_bytes: verified,
        };
        session.persist_metadata(now_epoch_seconds)?;
        Ok(session)
    }

    fn ensure_capacity(
        &self,
        requested_partial: &Path,
        expected_size: u64,
    ) -> Result<(), ReceiveError> {
        if expected_size > self.config.maximum_total_bytes {
            return Err(ReceiveError::PartialCapacityUnavailable);
        }
        let mut count = 0_usize;
        let mut bytes = 0_u64;
        let mut requested_existing_bytes = None;
        for entry in fs::read_dir(&self.config.root)? {
            let entry = entry?;
            if entry
                .path()
                .extension()
                .is_some_and(|extension| extension == "partial")
            {
                let metadata = entry.metadata()?;
                if metadata.is_file() {
                    count = count.saturating_add(1);
                    bytes = bytes.saturating_add(metadata.len());
                    if entry.path() == requested_partial {
                        requested_existing_bytes = Some(metadata.len());
                    }
                }
            }
        }
        let count_after_prepare =
            count.saturating_add(usize::from(requested_existing_bytes.is_none()));
        let bytes_after_completion = bytes
            .saturating_sub(requested_existing_bytes.unwrap_or_default())
            .saturating_add(expected_size);
        if count_after_prepare > self.config.maximum_partial_count
            || bytes_after_completion > self.config.maximum_total_bytes
        {
            return Err(ReceiveError::PartialCapacityUnavailable);
        }
        Ok(())
    }

    fn garbage_collect(&self, now_epoch_seconds: u64) -> Result<usize, ReceiveError> {
        let age_cutoff = now_epoch_seconds.saturating_sub(self.config.maximum_age.as_secs());
        let mut removed = 0;
        for entry in fs::read_dir(&self.config.root)? {
            let entry = entry?;
            let path = entry.path();
            if path.extension().is_none_or(|extension| extension != "json") {
                continue;
            }
            let metadata: PartialMetadata = match serde_json::from_slice(&fs::read(&path)?) {
                Ok(metadata) => metadata,
                Err(_) => continue,
            };
            if metadata.expiry >= now_epoch_seconds && metadata.last_update > age_cutoff {
                continue;
            }
            let partial = path.with_extension("partial");
            remove_if_regular(&partial)?;
            remove_if_regular(&path)?;
            removed += 1;
        }
        Ok(removed)
    }

    fn renew(
        &self,
        authorization: &ArtifactTransferAuthorization,
        now_epoch_seconds: u64,
    ) -> Result<bool, ReceiveError> {
        let metadata_path = self
            .config
            .root
            .join(format!("{}.json", partial_stem(authorization)));
        let file_metadata = match fs::symlink_metadata(&metadata_path) {
            Ok(metadata) => metadata,
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(false),
            Err(error) => return Err(error.into()),
        };
        if file_metadata.file_type().is_symlink() || !file_metadata.is_file() {
            return Err(ReceiveError::UnsafePartialMetadata);
        }
        let mut stored: PartialMetadata = serde_json::from_slice(&fs::read(&metadata_path)?)?;
        if stored.transfer_id != authorization.lease.transfer_id
            || stored.artifact != authorization.lease.artifact
            || stored.digest != authorization.lease.digest
            || stored.expected_size != authorization.lease.size_bytes
        {
            return Err(ReceiveError::PartialMetadataMismatch);
        }
        stored.expiry = stored
            .expiry
            .max(authorization.lease.retention_expires_at());
        stored.last_update = stored.last_update.max(now_epoch_seconds);
        persist_partial_metadata(&metadata_path, &stored)?;
        Ok(true)
    }
}

#[derive(Debug)]
struct PartialSession {
    partial_path: PathBuf,
    metadata_path: PathBuf,
    metadata: PartialMetadata,
    file: tokio::fs::File,
    hasher: Sha256,
    received_bytes: u64,
}

impl PartialSession {
    fn persist_metadata(&mut self, now_epoch_seconds: u64) -> Result<(), ReceiveError> {
        self.metadata.received_contiguous_bytes = self.received_bytes;
        self.metadata.last_update = now_epoch_seconds;
        persist_partial_metadata(&self.metadata_path, &self.metadata)
    }

    fn install(
        self,
        destination_path: &Path,
        expected_digest: &Digest,
        expected_size: u64,
    ) -> Result<PathBuf, ReceiveError> {
        let parent = destination_path
            .parent()
            .ok_or(ReceiveError::UnsafeDestination)?;
        fs::create_dir_all(parent)?;
        let parent_metadata = fs::symlink_metadata(parent)?;
        if parent_metadata.file_type().is_symlink() || !parent_metadata.is_dir() {
            return Err(ReceiveError::UnsafeDestination);
        }
        match fs::hard_link(&self.partial_path, destination_path) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                let (digest, size) = hash_regular_file_sync(destination_path)?;
                if &digest != expected_digest || size != expected_size {
                    return Err(ReceiveError::DestinationConflict);
                }
            }
            Err(error) => return Err(classify_install_error(error)),
        }
        fs::File::open(parent)?.sync_all()?;
        remove_if_regular(&self.partial_path)?;
        remove_if_regular(&self.metadata_path)?;
        Ok(destination_path.to_path_buf())
    }

    fn remove(self) -> Result<(), ReceiveError> {
        remove_if_regular(&self.partial_path)?;
        remove_if_regular(&self.metadata_path)?;
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
struct PartialMetadata {
    transfer_id: String,
    artifact: clusterflux_core::ArtifactId,
    digest: Digest,
    expected_size: u64,
    received_contiguous_bytes: u64,
    last_update: u64,
    expiry: u64,
}

fn persist_partial_metadata(
    metadata_path: &Path,
    metadata: &PartialMetadata,
) -> Result<(), ReceiveError> {
    let parent = metadata_path
        .parent()
        .ok_or(ReceiveError::UnsafePartialMetadata)?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    set_private_file(temporary.as_file())?;
    use std::io::Write;
    temporary.write_all(&serde_json::to_vec_pretty(metadata)?)?;
    temporary.as_file().sync_all()?;
    fs::rename(temporary.path(), metadata_path)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

async fn receive_body(
    connection: &iroh::endpoint::Connection,
    receive: &mut iroh::endpoint::RecvStream,
    partial: &mut PartialSession,
    expected_size: u64,
    metrics: &ArtifactDataPlaneMetrics,
    progress: Option<&TransferProgress>,
) -> Result<u64, PathPolicyError> {
    let initial = partial.received_bytes;
    let mut buffer = vec![0; RECEIVER_BUFFER_BYTES];
    loop {
        let read = receive
            .read(&mut buffer)
            .await
            .map_err(|error| PathPolicyError::Transfer(error.to_string()))?;
        let Some(read) = read else {
            break;
        };
        if read == 0 {
            continue;
        }
        let next = partial
            .received_bytes
            .checked_add(read as u64)
            .ok_or_else(|| PathPolicyError::Transfer("artifact size overflow".to_owned()))?;
        if next > expected_size {
            return Err(PathPolicyError::Transfer(
                "provider sent more bytes than the authorized artifact size".to_owned(),
            ));
        }
        partial
            .file
            .write_all(&buffer[..read])
            .await
            .map_err(|error| {
                if is_storage_full(&error) {
                    PathPolicyError::DestinationDiskFull
                } else {
                    PathPolicyError::Transfer(error.to_string())
                }
            })?;
        partial.hasher.update(&buffer[..read]);
        partial.received_bytes = next;
        let path = selected_connection_path_kind(connection);
        metrics.record_body_bytes(path, read as u64);
        if let Some(progress) = progress {
            progress.record(next, path);
        }
    }
    Ok(partial.received_bytes.saturating_sub(initial))
}

async fn verify_existing_destination(
    destination: &Path,
    expected_digest: &Digest,
    expected_size: u64,
) -> Result<Option<PathBuf>, ReceiveError> {
    match fs::symlink_metadata(destination) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() || !metadata.is_file() {
                return Err(ReceiveError::UnsafeDestination);
            }
            let (digest, size) = hash_regular_file_async(destination).await?;
            if &digest == expected_digest && size == expected_size {
                Ok(Some(destination.to_path_buf()))
            } else {
                Err(ReceiveError::DestinationConflict)
            }
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(error) => Err(error.into()),
    }
}

async fn hash_regular_file_async(path: &Path) -> Result<(Digest, u64), ReceiveError> {
    let file = open_readonly_regular(path)?;
    let mut file = tokio::fs::File::from_std(file);
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0; RECEIVER_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer).await?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(ReceiveError::SizeOverflow)?;
        hasher.update(&buffer[..read]);
    }
    let digest = Digest::from_sha256_hex(hex::encode(hasher.finalize()))
        .map_err(ReceiveError::InvalidDigest)?;
    Ok((digest, size))
}

fn hash_regular_file_sync(path: &Path) -> Result<(Digest, u64), ReceiveError> {
    use std::io::Read;

    let mut file = open_readonly_regular(path)?;
    let mut hasher = Sha256::new();
    let mut size = 0_u64;
    let mut buffer = vec![0; RECEIVER_BUFFER_BYTES];
    loop {
        let read = file.read(&mut buffer)?;
        if read == 0 {
            break;
        }
        size = size
            .checked_add(read as u64)
            .ok_or(ReceiveError::SizeOverflow)?;
        hasher.update(&buffer[..read]);
    }
    let digest = Digest::from_sha256_hex(hex::encode(hasher.finalize()))
        .map_err(ReceiveError::InvalidDigest)?;
    Ok((digest, size))
}

fn open_readonly_regular(path: &Path) -> Result<fs::File, ReceiveError> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() {
        return Err(ReceiveError::UnsafeDestination);
    }
    let mut options = fs::OpenOptions::new();
    options.read(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

fn open_partial_file(path: &Path, create: bool) -> Result<fs::File, ReceiveError> {
    let mut options = fs::OpenOptions::new();
    options.read(true).write(true).create_new(create);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    Ok(options.open(path)?)
}

fn partial_stem(authorization: &ArtifactTransferAuthorization) -> String {
    Digest::from_parts([
        authorization.lease.tenant.as_str().as_bytes(),
        authorization.lease.project.as_str().as_bytes(),
        authorization.lease.destination_node.as_str().as_bytes(),
        authorization.lease.artifact.as_str().as_bytes(),
        authorization.lease.digest.as_str().as_bytes(),
    ])
    .as_str()
    .trim_start_matches("sha256:")
    .to_owned()
}

fn set_private_file(file: &fs::File) -> Result<(), ReceiveError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        file.set_permissions(fs::Permissions::from_mode(0o600))?;
    }
    let _ = file;
    Ok(())
}

fn remove_if_regular(path: &Path) -> Result<(), ReceiveError> {
    match fs::symlink_metadata(path) {
        Ok(metadata) if metadata.file_type().is_symlink() || !metadata.is_file() => {
            Err(ReceiveError::UnsafePartialPath)
        }
        Ok(_) => {
            fs::remove_file(path)?;
            Ok(())
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
    }
}

fn classify_install_error(error: std::io::Error) -> ReceiveError {
    if is_storage_full(&error) {
        ReceiveError::DestinationDiskFull
    } else {
        ReceiveError::Io(error)
    }
}

fn is_storage_full(error: &std::io::Error) -> bool {
    error.kind() == std::io::ErrorKind::StorageFull || error.raw_os_error() == Some(libc::ENOSPC)
}

#[derive(Debug, Error)]
pub enum ReceiveError {
    #[error("artifact transfer lease is invalid: {0}")]
    InvalidLease(String),
    #[error("authorized source endpoint is invalid: {0}")]
    InvalidPeer(String),
    #[error("artifact transfer lease is for another destination")]
    WrongDestination,
    #[error("authorized peer does not match the transfer source")]
    PeerIdentityMismatch,
    #[error("artifact transfer lease has expired")]
    LeaseExpired,
    #[error("artifact transfer secret must be random and non-zero")]
    InvalidTransferSecret,
    #[error("Iroh artifact connection failed: {0}")]
    Connection(String),
    #[error("artifact provider response does not match the authorized object or range")]
    ResponseMismatch,
    #[error("artifact provider rejected the transfer ({code:?}): {message}")]
    Rejected {
        code: ArtifactTransferErrorCode,
        message: String,
    },
    #[error("artifact size mismatch: expected {expected} bytes, received {actual}")]
    SizeMismatch { expected: u64, actual: u64 },
    #[error("artifact SHA-256 digest mismatch")]
    DigestMismatch,
    #[error("destination already contains conflicting artifact bytes")]
    DestinationConflict,
    #[error("destination disk is full")]
    DestinationDiskFull,
    #[error("artifact partial root is not a private non-symlink directory")]
    UnsafePartialRoot,
    #[error("artifact partial path is unsafe")]
    UnsafePartialPath,
    #[error("artifact partial metadata path is unsafe")]
    UnsafePartialMetadata,
    #[error("artifact destination path is unsafe")]
    UnsafeDestination,
    #[error("artifact partial store limits must be non-zero")]
    InvalidPartialLimits,
    #[error("artifact partial store capacity is unavailable")]
    PartialCapacityUnavailable,
    #[error("artifact partial metadata does not match the transfer lease")]
    PartialMetadataMismatch,
    #[error("artifact partial exceeds the authorized expected size")]
    PartialExceedsExpectedSize,
    #[error("artifact partial changed while it was being verified")]
    PartialReadChanged,
    #[error("artifact byte count overflowed")]
    SizeOverflow,
    #[error("artifact digest is invalid: {0}")]
    InvalidDigest(String),
    #[error(transparent)]
    PathPolicy(#[from] PathPolicyError),
    #[error(transparent)]
    Protocol(#[from] crate::ProtocolError),
    #[error(transparent)]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Json(#[from] serde_json::Error),
}

impl ReceiveError {
    pub fn stable_code(&self) -> ArtifactTransferErrorCode {
        if matches!(self, Self::Io(error) if is_storage_full(error)) {
            return ArtifactTransferErrorCode::DestinationDiskFull;
        }
        match self {
            Self::LeaseExpired => ArtifactTransferErrorCode::TransferLeaseExpired,
            Self::PeerIdentityMismatch | Self::WrongDestination => {
                ArtifactTransferErrorCode::PeerIdentityMismatch
            }
            Self::InvalidLease(_)
            | Self::InvalidPeer(_)
            | Self::InvalidTransferSecret
            | Self::ResponseMismatch
            | Self::PartialMetadataMismatch => ArtifactTransferErrorCode::TransferLeaseRejected,
            Self::Rejected { code, .. } => *code,
            Self::SizeMismatch { .. } | Self::PartialExceedsExpectedSize => {
                ArtifactTransferErrorCode::SizeMismatch
            }
            Self::DigestMismatch | Self::DestinationConflict => {
                ArtifactTransferErrorCode::DigestMismatch
            }
            Self::DestinationDiskFull | Self::PartialCapacityUnavailable => {
                ArtifactTransferErrorCode::DestinationDiskFull
            }
            Self::PathPolicy(PathPolicyError::DirectPathTimeout) => {
                ArtifactTransferErrorCode::DirectPathTimeout
            }
            Self::PathPolicy(PathPolicyError::RelayPathForbidden) => {
                ArtifactTransferErrorCode::RelayPathForbidden
            }
            Self::PathPolicy(PathPolicyError::DestinationDiskFull) => {
                ArtifactTransferErrorCode::DestinationDiskFull
            }
            Self::PathPolicy(PathPolicyError::ConnectionClosed)
            | Self::PathPolicy(PathPolicyError::NoSelectedPath)
            | Self::PathPolicy(PathPolicyError::Transfer(_))
            | Self::Connection(_)
            | Self::Protocol(_)
            | Self::Io(_)
            | Self::Json(_)
            | Self::UnsafePartialRoot
            | Self::UnsafePartialPath
            | Self::UnsafePartialMetadata
            | Self::UnsafeDestination
            | Self::InvalidPartialLimits
            | Self::PartialReadChanged
            | Self::SizeOverflow
            | Self::InvalidDigest(_) => ArtifactTransferErrorCode::ConnectionFailed,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr, SocketAddr};

    use clusterflux_core::{
        ArtifactId, ArtifactRelayPolicy, ArtifactTransferAuthorization, ArtifactTransferLease,
        AuthorizedPeerEndpoint, Digest, NodeId, ProcessId, ProjectId, TenantId,
    };

    use super::*;

    fn authorization(size_bytes: u64, expires_at: u64) -> ArtifactTransferAuthorization {
        ArtifactTransferAuthorization {
            lease: ArtifactTransferLease {
                transfer_id: "partial-test-transfer".to_owned(),
                tenant: TenantId::from("tenant"),
                project: ProjectId::from("project"),
                process: ProcessId::from("process"),
                artifact: ArtifactId::from("artifact"),
                digest: Digest::sha256("expected artifact"),
                size_bytes,
                source_node: NodeId::from("source"),
                source_endpoint_id: "source-endpoint".to_owned(),
                destination_node: NodeId::from("destination"),
                destination_endpoint_id: "destination-endpoint".to_owned(),
                allowed_offset: 0,
                maximum_bytes: size_bytes,
                relay_policy: ArtifactRelayPolicy::DirectRequired,
                direct_path_deadline_ms: 5_000,
                expires_at,
                active_lease_expires_at: expires_at,
                nonce: "partial-test-nonce".to_owned(),
            },
            transfer_secret: [31_u8; 32],
            peer: AuthorizedPeerEndpoint {
                node: NodeId::from("source"),
                endpoint_id: "source-endpoint".to_owned(),
                generation: 1,
                direct_addresses: vec![SocketAddr::new(IpAddr::V4(Ipv4Addr::LOCALHOST), 4000)],
                relay_urls: Vec::new(),
            },
        }
    }

    #[test]
    fn partial_capacity_is_bounded_and_reports_disk_full() {
        let temp = tempfile::tempdir().unwrap();
        let store = PartialStore::open(PartialStoreConfig {
            root: temp.path().join("partials"),
            maximum_total_bytes: 4,
            maximum_partial_count: 1,
            maximum_age: Duration::from_secs(60),
        })
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let error = match runtime.block_on(store.prepare(&authorization(5, 120), 100)) {
            Ok(_) => panic!("oversized partial should be rejected"),
            Err(error) => error,
        };
        assert!(matches!(error, ReceiveError::PartialCapacityUnavailable));
        assert_eq!(
            error.stable_code(),
            ArtifactTransferErrorCode::DestinationDiskFull
        );
    }

    #[test]
    fn wrapped_storage_full_error_reports_disk_full() {
        let error = ReceiveError::Io(std::io::Error::new(
            std::io::ErrorKind::StorageFull,
            "wrapped ENOSPC",
        ));
        assert_eq!(
            error.stable_code(),
            ArtifactTransferErrorCode::DestinationDiskFull
        );
    }

    #[test]
    fn renewed_active_lease_extends_matching_partial_retention_atomically() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("partials");
        let store = PartialStore::open(PartialStoreConfig {
            root: root.clone(),
            maximum_total_bytes: 1024,
            maximum_partial_count: 4,
            maximum_age: Duration::from_secs(60),
        })
        .unwrap();
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        let mut authorization = authorization(4, 120);
        drop(
            runtime
                .block_on(store.prepare(&authorization, 100))
                .unwrap(),
        );
        authorization.lease.expires_at = 150;
        authorization.lease.active_lease_expires_at = 240;

        assert!(store.renew(&authorization, 110).unwrap());
        let metadata_path = root.join(format!("{}.json", partial_stem(&authorization)));
        let metadata: PartialMetadata =
            serde_json::from_slice(&fs::read(metadata_path).unwrap()).unwrap();
        assert_eq!(metadata.expiry, 240);
        assert_eq!(metadata.last_update, 110);

        let mut conflicting = authorization;
        conflicting.lease.transfer_id = "different-transfer".to_owned();
        assert!(matches!(
            store.renew(&conflicting, 111),
            Err(ReceiveError::PartialMetadataMismatch)
        ));
    }

    #[test]
    fn partial_gc_removes_expired_records_and_keeps_active_records() {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("partials");
        let store = PartialStore::open(PartialStoreConfig {
            root: root.clone(),
            maximum_total_bytes: 1024,
            maximum_partial_count: 4,
            maximum_age: Duration::from_secs(10),
        })
        .unwrap();
        let metadata = |transfer_id: &str, last_update: u64, expiry: u64| PartialMetadata {
            transfer_id: transfer_id.to_owned(),
            artifact: ArtifactId::from("artifact"),
            digest: Digest::sha256("expected artifact"),
            expected_size: 4,
            received_contiguous_bytes: 4,
            last_update,
            expiry,
        };
        for (stem, record) in [
            ("expired", metadata("expired", 80, 90)),
            ("active", metadata("active", 95, 110)),
        ] {
            fs::write(root.join(format!("{stem}.partial")), b"data").unwrap();
            fs::write(
                root.join(format!("{stem}.json")),
                serde_json::to_vec(&record).unwrap(),
            )
            .unwrap();
        }

        assert_eq!(store.garbage_collect(100).unwrap(), 1);
        assert!(!root.join("expired.partial").exists());
        assert!(!root.join("expired.json").exists());
        assert!(root.join("active.partial").exists());
        assert!(root.join("active.json").exists());
    }
}
