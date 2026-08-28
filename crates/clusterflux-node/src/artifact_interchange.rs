use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

use clusterflux_artifact_transfer::{
    ArtifactDataPlaneMetrics, ArtifactProviderRegistry, ArtifactProviderServer, ArtifactReceiver,
    ClusterfluxEndpoint, EndpointBindConfig, IrohIdentityScope, PartialStoreConfig,
    PathPolicyMetrics, PersistentIrohIdentity, TransferProgress,
};
use clusterflux_core::{
    sign_node_request, signed_request_payload_digest, ArtifactAssignmentRole,
    ArtifactDataPlanePolicy, ArtifactHandle, ArtifactId, ArtifactTransferAuthorization,
    ArtifactTransferErrorCode, ArtifactTransferRecord, ArtifactTransferState, ClusterfluxPathKind,
    Digest, NodeId, ProcessId, ProjectId, TaskInstanceId, TenantId,
};
use clusterflux_protocol::{CoordinatorRequest, CoordinatorResponse};
use serde_json::Value;
use tokio_util::sync::CancellationToken;
use tokio_util::task::TaskTracker;

use crate::coordinator_session::{AsyncCoordinatorSession, CoordinatorSession};
use crate::daemon::Args;
use crate::node_identity::{node_nonce, signed_node_request, unix_timestamp_seconds};
use crate::task_artifacts::NodeArtifactStore;

const MAX_ARTIFACT_SOURCE_ATTEMPTS: usize = 16;

#[derive(Clone, Default)]
struct ActiveReceiverTransfers {
    ids: Arc<Mutex<BTreeSet<String>>>,
}

impl ActiveReceiverTransfers {
    fn try_acquire(&self, transfer_id: &str) -> Option<ActiveReceiverGuard> {
        let mut ids = self.ids.lock().ok()?;
        if !ids.insert(transfer_id.to_owned()) {
            return None;
        }
        Some(ActiveReceiverGuard {
            transfer_id: transfer_id.to_owned(),
            active: self.clone(),
        })
    }
}

struct ActiveReceiverGuard {
    transfer_id: String,
    active: ActiveReceiverTransfers,
}

impl Drop for ActiveReceiverGuard {
    fn drop(&mut self) {
        if let Ok(mut ids) = self.active.ids.lock() {
            ids.remove(&self.transfer_id);
        }
    }
}

#[derive(Clone)]
pub(crate) struct ArtifactWarmupManager {
    inner: Arc<ArtifactWarmupInner>,
}

struct ArtifactWarmupInner {
    args: Args,
    node_private_key: String,
    artifact_store: NodeArtifactStore,
    receiver: ArtifactReceiver,
    runtime: tokio::runtime::Handle,
    tasks: TaskTracker,
    entries: Mutex<BTreeMap<Digest, Arc<ArtifactWarmupEntry>>>,
    active_receivers: ActiveReceiverTransfers,
    shutdown: CancellationToken,
}

type ArtifactWarmupConsumer = (ProcessId, TaskInstanceId, ArtifactId);

struct ArtifactWarmupEntry {
    digest: Digest,
    size_bytes: u64,
    state: Mutex<ArtifactWarmupState>,
    changed: tokio::sync::Notify,
    consumers: Mutex<BTreeMap<ArtifactWarmupConsumer, ArtifactHandle>>,
    demanded: Mutex<BTreeSet<ArtifactWarmupConsumer>>,
    ready_handle: Mutex<Option<ArtifactHandle>>,
    cancel: Mutex<CancellationToken>,
}

impl ArtifactWarmupEntry {
    fn cancellation(&self) -> CancellationToken {
        self.cancel
            .lock()
            .map(|cancel| cancel.clone())
            .unwrap_or_else(|poisoned| poisoned.into_inner().clone())
    }

    fn cancel(&self) {
        self.cancellation().cancel();
        self.changed.notify_waiters();
    }

    fn reset_cancellation(&self) {
        let mut cancel = self
            .cancel
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        *cancel = CancellationToken::new();
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ArtifactWarmupState {
    Queued,
    Transferring,
    Ready,
    Failed(ArtifactWarmupFailure),
    Cancelled,
}

#[derive(Clone, Debug, PartialEq, Eq)]
struct ArtifactWarmupFailure {
    message: String,
    retry_class: clusterflux_core::ArtifactTransferRetryClass,
}

impl ArtifactWarmupFailure {
    fn from_message(message: String) -> Self {
        Self {
            retry_class: retry_class_from_message(&message),
            message,
        }
    }

    fn retryable_on_demand(&self) -> bool {
        matches!(
            self.retry_class,
            clusterflux_core::ArtifactTransferRetryClass::RetrySameSource
                | clusterflux_core::ArtifactTransferRetryClass::WaitAndRetryPath
        )
    }
}

impl ArtifactWarmupState {
    fn terminal(&self) -> bool {
        matches!(self, Self::Ready | Self::Failed(_) | Self::Cancelled)
    }
}

fn retry_class_from_message(message: &str) -> clusterflux_core::ArtifactTransferRetryClass {
    for code in [
        ArtifactTransferErrorCode::NoArtifactLocation,
        ArtifactTransferErrorCode::SourceNodeOffline,
        ArtifactTransferErrorCode::DestinationNodeOffline,
        ArtifactTransferErrorCode::EndpointAdvertisementMissing,
        ArtifactTransferErrorCode::RelayAssistUnavailable,
        ArtifactTransferErrorCode::DirectPathTimeout,
        ArtifactTransferErrorCode::RelayPathForbidden,
        ArtifactTransferErrorCode::ConnectionFailed,
        ArtifactTransferErrorCode::PeerIdentityMismatch,
        ArtifactTransferErrorCode::TransferLeaseRejected,
        ArtifactTransferErrorCode::TransferLeaseExpired,
        ArtifactTransferErrorCode::ArtifactMissingAtSource,
        ArtifactTransferErrorCode::RangeInvalid,
        ArtifactTransferErrorCode::DestinationDiskFull,
        ArtifactTransferErrorCode::SizeMismatch,
        ArtifactTransferErrorCode::DigestMismatch,
        ArtifactTransferErrorCode::TransferCancelled,
        ArtifactTransferErrorCode::CapacityUnavailable,
    ] {
        if message.contains(code.as_str()) {
            return code.retry_class();
        }
    }
    if message.contains("connect")
        || message.contains("connection")
        || message.contains("temporar")
        || message.contains("lease ended")
        || message.contains("ticket expired")
        || message.contains("source did not become ready")
    {
        clusterflux_core::ArtifactTransferRetryClass::RetrySameSource
    } else {
        clusterflux_core::ArtifactTransferRetryClass::DoNotRetry
    }
}

impl ArtifactWarmupManager {
    #[allow(
        clippy::too_many_arguments,
        reason = "warm-up ownership keeps transfer, store, runtime, cancellation, and task-set authorities explicit"
    )]
    fn new(
        args: Args,
        node_private_key: String,
        artifact_store: NodeArtifactStore,
        receiver: ArtifactReceiver,
        runtime: tokio::runtime::Handle,
        active_receivers: ActiveReceiverTransfers,
        shutdown: CancellationToken,
        tasks: TaskTracker,
    ) -> Self {
        Self {
            inner: Arc::new(ArtifactWarmupInner {
                args,
                node_private_key,
                artifact_store,
                receiver,
                runtime,
                tasks,
                entries: Mutex::new(BTreeMap::new()),
                active_receivers,
                shutdown,
            }),
        }
    }

    pub(crate) fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.inner.runtime.clone()
    }

    pub(crate) fn task_tracker(&self) -> TaskTracker {
        self.inner.tasks.clone()
    }

    pub(crate) fn shutdown_token(&self) -> CancellationToken {
        self.inner.shutdown.clone()
    }

    pub(crate) fn start_task(
        &self,
        process: &ProcessId,
        task: &TaskInstanceId,
        handles: &[ArtifactHandle],
    ) -> Result<(), String> {
        for handle in handles {
            self.ensure_entry(process, task, handle, false)?;
        }
        Ok(())
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "materialization keeps the exact consumer, artifact, path, demand, and cancellation authorities explicit"
    )]
    pub(crate) fn materialize(
        &self,
        process: &ProcessId,
        task: &TaskInstanceId,
        handle: &ArtifactHandle,
        output_root: &Path,
        relative_path: &str,
        cancellation_requested: &CancellationToken,
        abort_requested: &AtomicBool,
    ) -> Result<(), String> {
        if self.local_handle_matches(handle)? {
            return self
                .inner
                .artifact_store
                .materialize_into_output(handle, output_root, relative_path)
                .map(|_| ());
        }
        let entry = self.ensure_entry(process, task, handle, true)?;
        let consumer = (process.clone(), task.clone(), handle.id.clone());
        let mut retried_on_demand = false;
        loop {
            if cancellation_requested.is_cancelled()
                || abort_requested.load(Ordering::Acquire)
                || self.inner.shutdown.is_cancelled()
            {
                self.remove_consumer_interest(&entry, &consumer);
                return Err(format!(
                    "artifact_cancelled: materialization of `{}` was cancelled",
                    handle.id
                ));
            }
            let changed = entry.changed.notified();
            let state = entry
                .state
                .lock()
                .map_err(|_| "artifact warm-up state lock poisoned")?;
            match &*state {
                ArtifactWarmupState::Ready => {
                    drop(state);
                    let ready_handle = entry
                        .ready_handle
                        .lock()
                        .map_err(|_| "artifact warm-up ready-handle lock poisoned")?
                        .clone()
                        .ok_or("artifact warm-up completed without a verified local handle")?;
                    self.ensure_local_alias(&ready_handle, handle)?;
                    return self
                        .inner
                        .artifact_store
                        .materialize_into_output(handle, output_root, relative_path)
                        .map(|_| ());
                }
                ArtifactWarmupState::Failed(failure)
                    if failure.retryable_on_demand() && !retried_on_demand =>
                {
                    drop(state);
                    if self.restart_failed_entry(&entry)? {
                        retried_on_demand = true;
                    }
                }
                ArtifactWarmupState::Failed(failure) => {
                    return Err(format!(
                        "artifact_unavailable: artifact `{}` could not be obtained: {}",
                        handle.id, failure.message
                    ));
                }
                ArtifactWarmupState::Cancelled => {
                    return Err(format!(
                        "artifact_cancelled: materialization of `{}` was cancelled",
                        handle.id
                    ));
                }
                ArtifactWarmupState::Queued | ArtifactWarmupState::Transferring => {
                    drop(state);
                    let entry_cancel = entry.cancellation();
                    let shutdown = self.inner.shutdown.clone();
                    self.inner.runtime.block_on(async {
                        tokio::select! {
                            () = changed => {}
                            () = entry_cancel.cancelled() => {}
                            () = shutdown.cancelled() => {}
                            () = tokio::time::sleep(Duration::from_millis(100)) => {}
                        }
                    });
                }
            }
        }
    }

    pub(crate) fn release(
        &self,
        process: &ProcessId,
        task: &TaskInstanceId,
        handle: &ArtifactHandle,
    ) {
        let entry = self
            .inner
            .entries
            .lock()
            .ok()
            .and_then(|entries| entries.get(&handle.digest).cloned());
        if let Some(entry) = entry {
            self.remove_consumer_interest(
                &entry,
                &(process.clone(), task.clone(), handle.id.clone()),
            );
        }
    }

    pub(crate) fn finish_task(&self, process: &ProcessId, task: &TaskInstanceId) {
        let entries = self
            .inner
            .entries
            .lock()
            .map(|entries| entries.values().cloned().collect::<Vec<_>>())
            .unwrap_or_default();
        for entry in entries {
            let consumers = entry
                .consumers
                .lock()
                .map(|consumers| {
                    consumers
                        .keys()
                        .filter(|(candidate_process, candidate_task, _)| {
                            candidate_process == process && candidate_task == task
                        })
                        .cloned()
                        .collect::<Vec<_>>()
                })
                .unwrap_or_default();
            for consumer in consumers {
                self.remove_consumer_interest(&entry, &consumer);
            }
        }
    }

    fn shutdown(&self) {
        self.inner.shutdown.cancel();
        if let Ok(entries) = self.inner.entries.lock() {
            for entry in entries.values() {
                entry.cancel();
            }
        }
    }

    fn ensure_entry(
        &self,
        process: &ProcessId,
        task: &TaskInstanceId,
        handle: &ArtifactHandle,
        demanded: bool,
    ) -> Result<Arc<ArtifactWarmupEntry>, String> {
        if !handle.digest.is_valid_sha256() {
            return Err("artifact warm-up handle has an invalid digest".to_owned());
        }
        let (entry, start) = {
            let mut entries = self
                .inner
                .entries
                .lock()
                .map_err(|_| "artifact warm-up registry lock poisoned")?;
            if let Some(entry) = entries.get(&handle.digest) {
                if entry.size_bytes != handle.size_bytes {
                    return Err("artifact handles with the same digest disagree on size".to_owned());
                }
                (Arc::clone(entry), false)
            } else {
                let entry = Arc::new(ArtifactWarmupEntry {
                    digest: handle.digest.clone(),
                    size_bytes: handle.size_bytes,
                    state: Mutex::new(ArtifactWarmupState::Queued),
                    changed: tokio::sync::Notify::new(),
                    consumers: Mutex::new(BTreeMap::new()),
                    demanded: Mutex::new(BTreeSet::new()),
                    ready_handle: Mutex::new(None),
                    cancel: Mutex::new(CancellationToken::new()),
                });
                entries.insert(handle.digest.clone(), Arc::clone(&entry));
                (entry, true)
            }
        };
        let consumer = (process.clone(), task.clone(), handle.id.clone());
        entry
            .consumers
            .lock()
            .map_err(|_| "artifact warm-up consumer lock poisoned")?
            .insert(consumer.clone(), handle.clone());
        if demanded {
            entry
                .demanded
                .lock()
                .map_err(|_| "artifact warm-up consumer lock poisoned")?
                .insert(consumer);
        }
        if start {
            self.spawn_warmup_entry(Arc::clone(&entry));
        }
        Ok(entry)
    }

    async fn run_entry(&self, entry: Arc<ArtifactWarmupEntry>, cancel: CancellationToken) {
        let result = self.transfer_entry(&entry, &cancel).await;
        let next = match result {
            Ok(()) => ArtifactWarmupState::Ready,
            Err(_error) if cancel.is_cancelled() => ArtifactWarmupState::Cancelled,
            Err(error) => ArtifactWarmupState::Failed(ArtifactWarmupFailure::from_message(error)),
        };
        if let Ok(mut state) = entry.state.lock() {
            *state = next;
            entry.changed.notify_waiters();
        }
        let has_consumers = entry
            .consumers
            .lock()
            .map(|consumers| !consumers.is_empty())
            .unwrap_or(false);
        if !has_consumers {
            if let Ok(mut entries) = self.inner.entries.lock() {
                entries.retain(|_, candidate| !Arc::ptr_eq(candidate, &entry));
            }
        }
    }

    fn spawn_warmup_entry(&self, entry: Arc<ArtifactWarmupEntry>) {
        if self.inner.shutdown.is_cancelled() {
            entry.cancel();
            return;
        }
        let cancel = entry.cancellation();
        let manager = self.clone();
        self.inner.tasks.spawn_on(
            async move {
                manager.run_entry(entry, cancel).await;
            },
            &self.inner.runtime,
        );
    }

    async fn transfer_entry(
        &self,
        entry: &ArtifactWarmupEntry,
        cancel: &CancellationToken,
    ) -> Result<(), String> {
        let mut last_error = "artifact warm-up did not start".to_owned();
        let mut invalid_consumers = BTreeSet::<(ProcessId, ArtifactId)>::new();
        for attempt in 0..MAX_ARTIFACT_SOURCE_ATTEMPTS {
            if cancel.is_cancelled() || self.inner.shutdown.is_cancelled() {
                return Err("artifact warm-up cancelled".to_owned());
            }
            let Some((process, handle)) = self.select_warmup_consumer(entry, &invalid_consumers)?
            else {
                return Err("artifact warm-up has no live consumer scope".to_owned());
            };
            if self.local_handle_matches(&handle)? {
                self.set_ready_handle(entry, handle)?;
                return Ok(());
            }
            match self
                .transfer_consumer(entry, &process, &handle, cancel)
                .await
            {
                Ok(()) => {
                    self.set_ready_handle(entry, handle)?;
                    return Ok(());
                }
                Err(error) => {
                    if error.contains(ArtifactTransferErrorCode::TransferCancelled.as_str())
                        || error.contains("artifact_released")
                    {
                        invalid_consumers.insert((process, handle.id));
                    }
                    last_error = error;
                    let delay = match attempt {
                        0 => 100,
                        1 => 250,
                        2 => 500,
                        3 => 1_000,
                        _ => 2_000,
                    };
                    tokio::select! {
                        () = tokio::time::sleep(Duration::from_millis(delay)) => {}
                        () = cancel.cancelled() => {
                            return Err("artifact warm-up cancelled".to_owned());
                        }
                        () = self.inner.shutdown.cancelled() => {
                            return Err("artifact warm-up cancelled".to_owned());
                        }
                    }
                }
            }
        }
        Err(format!(
            "bounded source attempts were exhausted: {last_error}"
        ))
    }

    async fn transfer_consumer(
        &self,
        entry: &ArtifactWarmupEntry,
        process: &ProcessId,
        handle: &ArtifactHandle,
        cancel: &CancellationToken,
    ) -> Result<(), String> {
        let session = AsyncCoordinatorSession::connect_with_timeouts(
            &self.inner.args.coordinator,
            Duration::from_secs(3),
            Duration::from_secs(30),
        )
        .map_err(|error| format!("connect artifact warm-up control session: {error}"))?;
        let response = session
            .request(
                signed_node_request(
                    &self.inner.args,
                    &self.inner.node_private_key,
                    "request_artifact_interchange",
                    CoordinatorRequest::RequestArtifactInterchange {
                        tenant: self.inner.args.tenant.clone(),
                        project: self.inner.args.project.clone(),
                        process: process.to_string(),
                        node: self.inner.args.node.clone(),
                        artifact: handle.id.to_string(),
                        offset: 0,
                    },
                )
                .map_err(|error| error.to_string())?,
            )
            .await?;
        let CoordinatorResponse::ArtifactTransferAuthorization { authorization, .. } = response
        else {
            return Err(
                "coordinator returned an unexpected artifact-authorization response".to_owned(),
            );
        };
        let Some(authorization) = authorization.map(|value| *value) else {
            if self.local_handle_matches(handle)? {
                return Ok(());
            }
            return Err(
                "coordinator reported a local cache hit but verified bytes are absent".to_owned(),
            );
        };
        if authorization.lease.digest != entry.digest
            || authorization.lease.size_bytes != entry.size_bytes
        {
            return Err("coordinator artifact authorization conflicts with task handle".to_owned());
        }
        let _active_receiver = loop {
            if let Some(guard) = self
                .inner
                .active_receivers
                .try_acquire(&authorization.lease.transfer_id)
            {
                break guard;
            }
            if cancel.is_cancelled() || self.inner.shutdown.is_cancelled() {
                return Err("artifact warm-up cancelled".to_owned());
            }
            if self.local_handle_matches(handle)? {
                return Ok(());
            }
            tokio::select! {
                () = tokio::time::sleep(Duration::from_millis(100)) => {}
                () = cancel.cancelled() => {
                    return Err("artifact warm-up cancelled".to_owned());
                }
                () = self.inner.shutdown.cancelled() => {
                    return Err("artifact warm-up cancelled".to_owned());
                }
            }
        };
        acknowledge_assignment_async(
            &self.inner.args,
            &session,
            &self.inner.node_private_key,
            &authorization,
            ArtifactAssignmentRole::Receiver,
        )
        .await?;
        if let Ok(mut state) = entry.state.lock() {
            *state = ArtifactWarmupState::Transferring;
            entry.changed.notify_waiters();
        }
        self.receive_authorization(&session, &authorization, cancel)
            .await
    }

    fn select_warmup_consumer(
        &self,
        entry: &ArtifactWarmupEntry,
        invalid: &BTreeSet<(ProcessId, ArtifactId)>,
    ) -> Result<Option<(ProcessId, ArtifactHandle)>, String> {
        let consumers = entry
            .consumers
            .lock()
            .map_err(|_| "artifact warm-up consumer lock poisoned")?;
        let demanded = entry
            .demanded
            .lock()
            .map_err(|_| "artifact warm-up consumer lock poisoned")?;
        let eligible =
            |key: &ArtifactWarmupConsumer| !invalid.contains(&(key.0.clone(), key.2.clone()));
        let selected = demanded
            .iter()
            .find(|key| eligible(key))
            .and_then(|key| {
                consumers
                    .get(key)
                    .map(|handle| (key.0.clone(), handle.clone()))
            })
            .or_else(|| {
                consumers.iter().find_map(|(key, handle)| {
                    eligible(key).then(|| (key.0.clone(), handle.clone()))
                })
            });
        Ok(selected)
    }

    fn set_ready_handle(
        &self,
        entry: &ArtifactWarmupEntry,
        handle: ArtifactHandle,
    ) -> Result<(), String> {
        *entry
            .ready_handle
            .lock()
            .map_err(|_| "artifact warm-up ready-handle lock poisoned")? = Some(handle);
        Ok(())
    }

    async fn receive_authorization(
        &self,
        session: &AsyncCoordinatorSession,
        authorization: &ArtifactTransferAuthorization,
        cancel: &CancellationToken,
    ) -> Result<(), String> {
        let mut authorization = authorization.clone();
        let allowed_offset = authorization.lease.allowed_offset;
        let receiver = self.inner.receiver.clone();
        let warm_authorization = authorization.clone();
        let warm_connection =
            receiver.warm_authorized_peer(&warm_authorization, unix_timestamp_seconds());
        let provider_ready = self.wait_for_provider_ready(session, &mut authorization, cancel);
        let (warmed, ready) = tokio::join!(warm_connection, provider_ready);
        ready?;
        if let Err(error) = warmed {
            let _ = self
                .report_transfer(
                    session,
                    &mut authorization,
                    ArtifactTransferState::Failed,
                    allowed_offset,
                    ClusterfluxPathKind::Unknown,
                    Some(error.stable_code()),
                    None,
                    None,
                )
                .await;
            return Err(error.to_string());
        }
        self.report_transfer(
            session,
            &mut authorization,
            ArtifactTransferState::Transferring,
            allowed_offset,
            ClusterfluxPathKind::Unknown,
            None,
            None,
            None,
        )
        .await?;
        let destination = self
            .inner
            .artifact_store
            .interchange_destination(&authorization.lease.artifact)?;
        let receiver = self.inner.receiver.clone();
        let download_authorization = authorization.clone();
        let progress = Arc::new(TransferProgress::default());
        let download_progress = Arc::clone(&progress);
        let download = receiver.download_with_progress(
            &download_authorization,
            destination,
            unix_timestamp_seconds(),
            Some(&download_progress),
        );
        tokio::pin!(download);
        let mut progress_tick = tokio::time::interval(Duration::from_millis(100));
        progress_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_reported = allowed_offset;
        let mut last_progress_report = Instant::now();
        let completed = loop {
            tokio::select! {
                completed = &mut download => break completed,
                () = cancel.cancelled() => {
                    let _ = self
                        .report_transfer(
                            session,
                            &mut authorization,
                            ArtifactTransferState::Cancelled,
                            last_reported,
                            progress.snapshot().1,
                            Some(ArtifactTransferErrorCode::TransferCancelled),
                            None,
                            None,
                        )
                        .await;
                    return Err("artifact warm-up cancelled".to_owned());
                }
                () = self.inner.shutdown.cancelled() => {
                    let _ = self
                        .report_transfer(
                            session,
                            &mut authorization,
                            ArtifactTransferState::Cancelled,
                            last_reported,
                            progress.snapshot().1,
                            Some(ArtifactTransferErrorCode::TransferCancelled),
                            None,
                            None,
                        )
                        .await;
                    return Err("artifact warm-up cancelled".to_owned());
                }
                _ = progress_tick.tick() => {
                    if last_progress_report.elapsed() < Duration::from_secs(1) {
                        continue;
                    }
                    let (bytes_verified, path_kind) = progress.snapshot();
                    self
                        .report_transfer(
                            session,
                            &mut authorization,
                            ArtifactTransferState::Transferring,
                            bytes_verified,
                            path_kind,
                            None,
                            None,
                            None,
                        )
                        .await
                        .map_err(|error| format!("artifact transfer lease ended: {error}"))?;
                    last_reported = last_reported.max(bytes_verified);
                    last_progress_report = Instant::now();
                }
            }
        };
        match completed {
            Ok(completed) => {
                self.report_transfer(
                    session,
                    &mut authorization,
                    ArtifactTransferState::Verifying,
                    completed.size_bytes,
                    completed.path_kind,
                    None,
                    None,
                    None,
                )
                .await?;
                self.report_transfer(
                    session,
                    &mut authorization,
                    ArtifactTransferState::Completed,
                    completed.size_bytes,
                    completed.path_kind,
                    None,
                    Some(completed.digest),
                    Some(completed.size_bytes),
                )
                .await?;
                Ok(())
            }
            Err(error) => {
                let _ = self
                    .report_transfer(
                        session,
                        &mut authorization,
                        ArtifactTransferState::Failed,
                        last_reported,
                        progress.snapshot().1,
                        Some(error.stable_code()),
                        None,
                        None,
                    )
                    .await;
                Err(error.to_string())
            }
        }
    }

    async fn wait_for_provider_ready(
        &self,
        session: &AsyncCoordinatorSession,
        authorization: &mut ArtifactTransferAuthorization,
        cancel: &CancellationToken,
    ) -> Result<(), String> {
        let mut delay = Duration::from_millis(100);
        loop {
            tokio::select! {
                () = tokio::time::sleep(delay) => {}
                () = cancel.cancelled() => {
                    return Err("artifact warm-up cancelled".to_owned());
                }
                () = self.inner.shutdown.cancelled() => {
                    return Err("artifact warm-up cancelled".to_owned());
                }
            }
            delay = (delay * 2).min(Duration::from_secs(2));
            let response = session
                .request(
                    signed_node_request(
                        &self.inner.args,
                        &self.inner.node_private_key,
                        "request_artifact_interchange",
                        CoordinatorRequest::RequestArtifactInterchange {
                            tenant: self.inner.args.tenant.clone(),
                            project: self.inner.args.project.clone(),
                            process: authorization.lease.process.to_string(),
                            node: self.inner.args.node.clone(),
                            artifact: authorization.lease.artifact.to_string(),
                            offset: authorization.lease.allowed_offset,
                        },
                    )
                    .map_err(|error| error.to_string())?,
                )
                .await?;
            refresh_authorization_from_response(authorization, &response)
                .map_err(|error| error.to_string())?;
            let transfer = transfer_from_response(&response)
                .ok_or("coordinator omitted artifact transfer state")?;
            match transfer.state {
                ArtifactTransferState::Connecting
                | ArtifactTransferState::WaitingForDirect
                | ArtifactTransferState::Transferring
                | ArtifactTransferState::Verifying
                | ArtifactTransferState::Completed => return Ok(()),
                ArtifactTransferState::Failed
                | ArtifactTransferState::Cancelled
                | ArtifactTransferState::Expired => {
                    return Err(format!(
                        "artifact source preparation ended in {:?}: {:?}",
                        transfer.state, transfer.failure_code
                    ));
                }
                ArtifactTransferState::Requested
                | ArtifactTransferState::SourceSelected
                | ArtifactTransferState::Retrying => {}
            }
        }
    }

    #[allow(
        clippy::too_many_arguments,
        reason = "the signed transfer report mirrors the bounded coordinator protocol fields"
    )]
    async fn report_transfer(
        &self,
        session: &AsyncCoordinatorSession,
        authorization: &mut ArtifactTransferAuthorization,
        state: ArtifactTransferState,
        bytes_completed: u64,
        path_kind: ClusterfluxPathKind,
        failure_code: Option<ArtifactTransferErrorCode>,
        verified_digest: Option<Digest>,
        verified_size: Option<u64>,
    ) -> Result<CoordinatorResponse, String> {
        let terminal = state.terminal();
        let response = report_transfer_request_async(
            &self.inner.args,
            session,
            &self.inner.node_private_key,
            authorization,
            state,
            bytes_completed,
            path_kind,
            failure_code,
            verified_digest,
            verified_size,
        )
        .await?;
        refresh_authorization_from_response(authorization, &response)
            .map_err(|error| error.to_string())?;
        if !terminal {
            self.inner
                .receiver
                .renew_partial(authorization, unix_timestamp_seconds())
                .map_err(|error| error.to_string())?;
        }
        Ok(response)
    }

    fn remove_consumer_interest(
        &self,
        entry: &Arc<ArtifactWarmupEntry>,
        consumer: &ArtifactWarmupConsumer,
    ) {
        let empty = remove_consumer_from_entry(entry, consumer);
        if empty {
            let terminal = entry
                .state
                .lock()
                .map(|state| state.terminal())
                .unwrap_or(true);
            if terminal {
                if let Ok(mut entries) = self.inner.entries.lock() {
                    entries.retain(|_, candidate| !Arc::ptr_eq(candidate, entry));
                }
            }
        }
    }

    fn restart_failed_entry(&self, entry: &Arc<ArtifactWarmupEntry>) -> Result<bool, String> {
        if !reset_retryable_failed_entry(entry)? {
            return Ok(false);
        }
        self.spawn_warmup_entry(Arc::clone(entry));
        Ok(true)
    }

    fn local_handle_matches(&self, handle: &ArtifactHandle) -> Result<bool, String> {
        Ok(self
            .inner
            .artifact_store
            .metadata(&handle.id)?
            .is_some_and(|local| {
                local.digest == handle.digest && local.size_bytes == handle.size_bytes
            }))
    }

    fn ensure_local_alias(
        &self,
        canonical: &ArtifactHandle,
        requested: &ArtifactHandle,
    ) -> Result<(), String> {
        if canonical.id == requested.id || self.local_handle_matches(requested)? {
            return Ok(());
        }
        let source = self
            .inner
            .artifact_store
            .interchange_source(&canonical.id)?
            .ok_or_else(|| format!("warmed artifact `{}` disappeared", canonical.id))?;
        let destination = self
            .inner
            .artifact_store
            .interchange_destination(&requested.id)?;
        match std::fs::hard_link(source, &destination) {
            Ok(()) => {}
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {}
            Err(error) => return Err(format!("create artifact digest alias: {error}")),
        }
        if !self.local_handle_matches(requested)? {
            let _ = std::fs::remove_file(destination);
            return Err("artifact digest alias did not verify".to_owned());
        }
        Ok(())
    }
}

fn remove_consumer_from_entry(
    entry: &ArtifactWarmupEntry,
    consumer: &ArtifactWarmupConsumer,
) -> bool {
    let empty = entry
        .consumers
        .lock()
        .map(|mut consumers| {
            consumers.remove(consumer);
            consumers.is_empty()
        })
        .unwrap_or(false);
    if let Ok(mut demanded) = entry.demanded.lock() {
        demanded.remove(consumer);
    }
    if empty {
        entry.cancel();
    }
    empty
}

fn reset_retryable_failed_entry(entry: &ArtifactWarmupEntry) -> Result<bool, String> {
    let mut state = entry
        .state
        .lock()
        .map_err(|_| "artifact warm-up state lock poisoned")?;
    let ArtifactWarmupState::Failed(failure) = &*state else {
        return Ok(false);
    };
    if !failure.retryable_on_demand() {
        return Ok(false);
    }
    entry.reset_cancellation();
    *state = ArtifactWarmupState::Queued;
    Ok(true)
}

pub(crate) struct NodeArtifactDataPlane {
    runtime: tokio::runtime::Runtime,
    endpoint: ClusterfluxEndpoint,
    provider_registry: ArtifactProviderRegistry,
    provider_server: ArtifactProviderServer,
    receiver: ArtifactReceiver,
    warmups: ArtifactWarmupManager,
    policy: ArtifactDataPlanePolicy,
    shutdown: CancellationToken,
    tasks: TaskTracker,
    active_receivers: ActiveReceiverTransfers,
    shutdown_complete: bool,
}

impl NodeArtifactDataPlane {
    pub(crate) fn start(
        args: &Args,
        session: &mut CoordinatorSession,
        node_private_key: &str,
        artifact_store: &NodeArtifactStore,
        shutdown: CancellationToken,
    ) -> Result<Self, Box<dyn std::error::Error>> {
        let response = session.request_signed(|| {
            signed_node_request(
                args,
                node_private_key,
                "get_artifact_data_plane_policy",
                CoordinatorRequest::GetArtifactDataPlanePolicy {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    node: args.node.clone(),
                },
            )
        })?;
        let CoordinatorResponse::ArtifactDataPlanePolicy { policy } = response else {
            return Err("coordinator returned an unexpected artifact-policy response".into());
        };
        let project_root = args
            .project_root
            .clone()
            .unwrap_or(std::env::current_dir()?);
        let identity = PersistentIrohIdentity::load_or_create(
            iroh_identity_path(&project_root, &args.node),
            IrohIdentityScope {
                tenant: TenantId::try_new(args.tenant.clone())?,
                project: ProjectId::try_new(args.project.clone())?,
                node: NodeId::try_new(args.node.clone())?,
            },
        )?;
        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .max_blocking_threads(16)
            .enable_all()
            .thread_name("clusterflux-iroh")
            .build()?;
        let (endpoint, provider_registry, provider_server, receiver) = runtime.block_on(async {
            let endpoint = ClusterfluxEndpoint::bind(
                &identity,
                EndpointBindConfig {
                    relay: policy.relay.clone(),
                },
            )
            .await?;
            let data_metrics = Arc::new(ArtifactDataPlaneMetrics::default());
            let path_metrics = Arc::new(PathPolicyMetrics::default());
            let provider_registry = ArtifactProviderRegistry::new(endpoint.endpoint_id(), 128);
            let provider_server = ArtifactProviderServer::start(
                &endpoint,
                provider_registry.clone(),
                Arc::clone(&data_metrics),
                Arc::clone(&path_metrics),
            );
            let receiver = ArtifactReceiver::new(
                endpoint.clone(),
                PartialStoreConfig::new(artifact_store.interchange_partial_root()),
                data_metrics,
                path_metrics,
            )?
            .with_path_deadlines(
                Duration::from_millis(policy.direct_path_deadline_ms),
                Duration::from_millis(policy.direct_path_grace_period_ms),
            );
            Ok::<_, Box<dyn std::error::Error>>((
                endpoint,
                provider_registry,
                provider_server,
                receiver,
            ))
        })?;
        let active_receivers = ActiveReceiverTransfers::default();
        let tasks = TaskTracker::new();
        let warmups = ArtifactWarmupManager::new(
            args.clone(),
            node_private_key.to_owned(),
            artifact_store.clone(),
            receiver.clone(),
            runtime.handle().clone(),
            active_receivers.clone(),
            shutdown.child_token(),
            tasks.clone(),
        );
        let mut data_plane = Self {
            runtime,
            endpoint,
            provider_registry,
            provider_server,
            receiver,
            warmups,
            policy,
            shutdown,
            tasks,
            active_receivers,
            shutdown_complete: false,
        };
        data_plane.start_shutdown_signal_task()?;
        data_plane.report_advertisement(args, session, node_private_key)?;
        data_plane.start_provider_control(args, node_private_key, artifact_store);
        Ok(data_plane)
    }

    pub(crate) fn warmups(&self) -> ArtifactWarmupManager {
        self.warmups.clone()
    }

    pub(crate) fn runtime_handle(&self) -> tokio::runtime::Handle {
        self.runtime.handle().clone()
    }

    fn start_provider_control(
        &mut self,
        args: &Args,
        node_private_key: &str,
        artifact_store: &NodeArtifactStore,
    ) {
        let context = ProviderControlContext {
            args: args.clone(),
            node_private_key: node_private_key.to_owned(),
            artifact_store: artifact_store.clone(),
            endpoint: self.endpoint.clone(),
            provider_registry: self.provider_registry.clone(),
            policy: self.policy.clone(),
            shutdown: self.shutdown.child_token(),
        };
        self.tasks.spawn_on(context.run(), self.runtime.handle());
    }

    #[cfg(unix)]
    fn start_shutdown_signal_task(&self) -> Result<(), Box<dyn std::error::Error>> {
        let (mut interrupt, mut terminate) = self.runtime.block_on(async {
            let interrupt =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
            let terminate =
                tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
            Ok::<_, std::io::Error>((interrupt, terminate))
        })?;
        let task_shutdown = self.shutdown.clone();
        self.tasks.spawn_on(
            async move {
                tokio::select! {
                    _ = interrupt.recv() => task_shutdown.cancel(),
                    _ = terminate.recv() => task_shutdown.cancel(),
                    () = task_shutdown.cancelled() => {}
                }
            },
            self.runtime.handle(),
        );
        Ok(())
    }

    #[cfg(not(unix))]
    fn start_shutdown_signal_task(&self) -> Result<(), Box<dyn std::error::Error>> {
        let task_shutdown = self.shutdown.clone();
        self.tasks.spawn_on(
            async move {
                tokio::select! {
                    result = tokio::signal::ctrl_c() => {
                        if let Err(error) = result {
                            eprintln!("Clusterflux node shutdown signal listener failed: {error}");
                        }
                        task_shutdown.cancel();
                    }
                    () = task_shutdown.cancelled() => {}
                }
            },
            self.runtime.handle(),
        );
        Ok(())
    }

    pub(crate) fn service_receiver_assignment(
        &self,
        args: &Args,
        session: &mut CoordinatorSession,
        node_private_key: &str,
        artifact_store: &NodeArtifactStore,
    ) -> Result<bool, Box<dyn std::error::Error>> {
        let response = session.request_signed(|| {
            signed_node_request(
                args,
                node_private_key,
                "poll_artifact_receiver_assignment",
                CoordinatorRequest::PollArtifactReceiverAssignment {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    node: args.node.clone(),
                },
            )
        })?;
        let CoordinatorResponse::ArtifactReceiverAssignment { authorization } = response else {
            return Err("coordinator returned an unexpected receiver-assignment response".into());
        };
        let Some(authorization) = authorization.map(|value| *value) else {
            return Ok(false);
        };
        acknowledge_assignment(
            args,
            session,
            node_private_key,
            &authorization,
            ArtifactAssignmentRole::Receiver,
        )?;
        let Some(active_guard) = self
            .active_receivers
            .try_acquire(&authorization.lease.transfer_id)
        else {
            // A task warm-up or an earlier redelivery already owns this exact
            // transfer. Refresh its partial lease, but never start a duplicate
            // body stream.
            let _ = self
                .receiver
                .renew_partial(&authorization, unix_timestamp_seconds());
            return Ok(true);
        };
        let context = ReceiverAssignmentContext {
            args: args.clone(),
            node_private_key: node_private_key.to_owned(),
            artifact_store: artifact_store.clone(),
            receiver: self.receiver.clone(),
            shutdown: self.shutdown.child_token(),
        };
        let transfer_id = authorization.lease.transfer_id.clone();
        self.tasks.spawn_on(async move {
            let _active_guard = active_guard;
            let result = AsyncCoordinatorSession::connect_with_timeouts(
                &context.args.coordinator,
                Duration::from_secs(3),
                Duration::from_secs(30),
            )
            .map_err(|error| error.to_string());
            let result = match result {
                Ok(receiver_session) => match context
                    .receive_authorization(&receiver_session, authorization.clone())
                    .await
                {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        eprintln!(
                            "Clusterflux artifact receiver assignment failed for transfer {transfer_id}: {error}"
                        );
                        let retry_request = signed_node_request(
                            &context.args,
                            &context.node_private_key,
                            "request_artifact_interchange",
                            CoordinatorRequest::RequestArtifactInterchange {
                                tenant: context.args.tenant.clone(),
                                project: context.args.project.clone(),
                                process: authorization.lease.process.to_string(),
                                node: context.args.node.clone(),
                                artifact: authorization.lease.artifact.to_string(),
                                offset: 0,
                            },
                        )
                        .map_err(|error| error.to_string());
                        match retry_request {
                            Ok(request) => receiver_session.request(request).await.map(|_| ()),
                            Err(error) => Err(error.to_string()),
                        }
                    }
                },
                Err(error) => Err(error),
            };
            if let Err(error) = result {
                eprintln!(
                    "Clusterflux artifact receiver exhausted alternate sources for {transfer_id}: {error}"
                );
            }
        }, self.runtime.handle());
        Ok(true)
    }

    pub(crate) async fn provider_pins(&self, now_epoch_seconds: u64) -> BTreeSet<ArtifactId> {
        self.provider_registry
            .pinned_artifacts(now_epoch_seconds)
            .await
    }

    pub(crate) fn garbage_collect_partials(
        &self,
        now_epoch_seconds: u64,
    ) -> Result<usize, Box<dyn std::error::Error>> {
        Ok(self.receiver.garbage_collect_partials(now_epoch_seconds)?)
    }

    pub(crate) fn shutdown(mut self) {
        self.shutdown_inner();
    }

    fn shutdown_inner(&mut self) {
        if self.shutdown_complete {
            return;
        }
        self.warmups.shutdown();
        self.shutdown.cancel();
        self.tasks.close();
        self.runtime.block_on(self.tasks.wait());
        let _ = self.runtime.block_on(self.provider_server.shutdown());
        self.runtime.block_on(self.receiver.close_connections());
        self.runtime.block_on(self.endpoint.clone().close());
        self.shutdown_complete = true;
    }

    fn report_advertisement(
        &self,
        args: &Args,
        session: &mut CoordinatorSession,
        node_private_key: &str,
    ) -> Result<(), Box<dyn std::error::Error>> {
        report_endpoint_advertisement(
            args,
            session,
            node_private_key,
            &self.endpoint,
            &self.policy,
        )
    }
}

impl Drop for NodeArtifactDataPlane {
    fn drop(&mut self) {
        self.shutdown_inner();
    }
}

#[derive(Clone)]
struct ReceiverAssignmentContext {
    args: Args,
    node_private_key: String,
    artifact_store: NodeArtifactStore,
    receiver: ArtifactReceiver,
    shutdown: CancellationToken,
}

impl ReceiverAssignmentContext {
    async fn receive_authorization(
        &self,
        session: &AsyncCoordinatorSession,
        mut authorization: ArtifactTransferAuthorization,
    ) -> Result<(), String> {
        let allowed_offset = authorization.lease.allowed_offset;
        let receiver = self.receiver.clone();
        let warm_authorization = authorization.clone();
        let warm_connection =
            receiver.warm_authorized_peer(&warm_authorization, unix_timestamp_seconds());
        let provider_ready = self.wait_for_provider_ready(session, &mut authorization);
        let (warmed, ready) = tokio::join!(warm_connection, provider_ready);
        ready?;
        if let Err(error) = warmed {
            self.report_and_refresh(
                session,
                &mut authorization,
                ArtifactTransferState::Failed,
                allowed_offset,
                ClusterfluxPathKind::Unknown,
                Some(error.stable_code()),
                None,
                None,
            )
            .await?;
            return Err(error.to_string());
        }
        self.report_and_refresh(
            session,
            &mut authorization,
            ArtifactTransferState::Transferring,
            allowed_offset,
            ClusterfluxPathKind::Unknown,
            None,
            None,
            None,
        )
        .await?;
        let destination = self
            .artifact_store
            .interchange_destination(&authorization.lease.artifact)
            .map_err(|error| error.to_string())?;
        let receiver = self.receiver.clone();
        let download_authorization = authorization.clone();
        let progress = Arc::new(TransferProgress::default());
        let download_progress = Arc::clone(&progress);
        let download = receiver.download_with_progress(
            &download_authorization,
            destination,
            unix_timestamp_seconds(),
            Some(&download_progress),
        );
        tokio::pin!(download);
        let mut progress_tick = tokio::time::interval(Duration::from_millis(100));
        progress_tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut last_reported = allowed_offset;
        let mut last_progress_report = Instant::now();
        let completed = loop {
            tokio::select! {
                completed = &mut download => break completed,
                () = self.shutdown.cancelled() => {
                    let _ = self
                        .report_and_refresh(
                            session,
                            &mut authorization,
                            ArtifactTransferState::Cancelled,
                            last_reported,
                            progress.snapshot().1,
                            Some(ArtifactTransferErrorCode::TransferCancelled),
                            None,
                            None,
                        )
                        .await;
                    return Err("artifact receiver cancelled during node shutdown".to_owned());
                }
                _ = progress_tick.tick() => {
                    if last_progress_report.elapsed() < Duration::from_secs(1) {
                        continue;
                    }
                    let (bytes_verified, path_kind) = progress.snapshot();
                    self.report_and_refresh(
                        session,
                        &mut authorization,
                        ArtifactTransferState::Transferring,
                        bytes_verified,
                        path_kind,
                        None,
                        None,
                        None,
                    )
                    .await
                    .map_err(|error| format!("artifact transfer lease ended: {error}"))?;
                    last_reported = last_reported.max(bytes_verified);
                    last_progress_report = Instant::now();
                }
            }
        };
        match completed {
            Ok(completed) => {
                self.report_and_refresh(
                    session,
                    &mut authorization,
                    ArtifactTransferState::Verifying,
                    completed.size_bytes,
                    completed.path_kind,
                    None,
                    None,
                    None,
                )
                .await?;
                self.report_and_refresh(
                    session,
                    &mut authorization,
                    ArtifactTransferState::Completed,
                    completed.size_bytes,
                    completed.path_kind,
                    None,
                    Some(completed.digest),
                    Some(completed.size_bytes),
                )
                .await?;
                Ok(())
            }
            Err(error) => {
                self.report_and_refresh(
                    session,
                    &mut authorization,
                    ArtifactTransferState::Failed,
                    last_reported,
                    progress.snapshot().1,
                    Some(error.stable_code()),
                    None,
                    None,
                )
                .await?;
                Err(error.to_string())
            }
        }
    }

    async fn wait_for_provider_ready(
        &self,
        session: &AsyncCoordinatorSession,
        authorization: &mut ArtifactTransferAuthorization,
    ) -> Result<(), String> {
        let mut idle_poll_backoff = Duration::from_millis(100);
        loop {
            tokio::select! {
                () = tokio::time::sleep(idle_poll_backoff) => {}
                () = self.shutdown.cancelled() => {
                    return Err("artifact receiver cancelled during node shutdown".to_owned());
                }
            }
            let response = session
                .request(
                    signed_node_request(
                        &self.args,
                        &self.node_private_key,
                        "request_artifact_interchange",
                        CoordinatorRequest::RequestArtifactInterchange {
                            tenant: self.args.tenant.clone(),
                            project: self.args.project.clone(),
                            process: authorization.lease.process.to_string(),
                            node: self.args.node.clone(),
                            artifact: authorization.lease.artifact.to_string(),
                            offset: authorization.lease.allowed_offset,
                        },
                    )
                    .map_err(|error| error.to_string())?,
                )
                .await?;
            refresh_authorization_from_response(authorization, &response)
                .map_err(|error| error.to_string())?;
            let transfer = transfer_from_response(&response)
                .ok_or("coordinator omitted artifact transfer state")?;
            match transfer.state {
                ArtifactTransferState::Connecting
                | ArtifactTransferState::WaitingForDirect
                | ArtifactTransferState::Transferring
                | ArtifactTransferState::Verifying
                | ArtifactTransferState::Completed => return Ok(()),
                ArtifactTransferState::Failed
                | ArtifactTransferState::Cancelled
                | ArtifactTransferState::Expired => {
                    return Err(format!(
                        "artifact source preparation ended in {:?}: {:?}",
                        transfer.state, transfer.failure_code
                    ));
                }
                ArtifactTransferState::Requested
                | ArtifactTransferState::SourceSelected
                | ArtifactTransferState::Retrying => {
                    idle_poll_backoff = next_idle_poll_backoff(idle_poll_backoff);
                }
            }
        }
    }

    #[allow(clippy::too_many_arguments)]
    async fn report_and_refresh(
        &self,
        session: &AsyncCoordinatorSession,
        authorization: &mut ArtifactTransferAuthorization,
        state: ArtifactTransferState,
        bytes_completed: u64,
        path_kind: ClusterfluxPathKind,
        failure_code: Option<ArtifactTransferErrorCode>,
        verified_digest: Option<Digest>,
        verified_size: Option<u64>,
    ) -> Result<(), String> {
        let terminal = state.terminal();
        let response = report_transfer_request_async(
            &self.args,
            session,
            &self.node_private_key,
            authorization,
            state,
            bytes_completed,
            path_kind,
            failure_code,
            verified_digest,
            verified_size,
        )
        .await?;
        refresh_authorization_from_response(authorization, &response)
            .map_err(|error| error.to_string())?;
        if !terminal {
            self.receiver
                .renew_partial(authorization, unix_timestamp_seconds())
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
struct ProviderControlContext {
    args: Args,
    node_private_key: String,
    artifact_store: NodeArtifactStore,
    endpoint: ClusterfluxEndpoint,
    provider_registry: ArtifactProviderRegistry,
    policy: ArtifactDataPlanePolicy,
    shutdown: CancellationToken,
}

impl ProviderControlContext {
    async fn run(self) {
        const RECONNECT_BACKOFF: Duration = Duration::from_millis(250);
        loop {
            if self.shutdown.is_cancelled() {
                return;
            }
            let session = match AsyncCoordinatorSession::connect_with_timeouts(
                &self.args.coordinator,
                Duration::from_secs(3),
                Duration::from_secs(5),
            ) {
                Ok(session) => session,
                Err(error) => {
                    eprintln!("Clusterflux artifact provider control connection failed: {error}");
                    tokio::select! {
                        () = tokio::time::sleep(RECONNECT_BACKOFF) => {}
                        () = self.shutdown.cancelled() => return,
                    }
                    continue;
                }
            };
            if let Err(error) = self.run_session(&session).await {
                eprintln!("Clusterflux artifact provider control session failed: {error}");
            }
            tokio::select! {
                () = tokio::time::sleep(RECONNECT_BACKOFF) => {}
                () = self.shutdown.cancelled() => return,
            }
        }
    }

    async fn run_session(&self, session: &AsyncCoordinatorSession) -> Result<(), String> {
        let refresh_after = Duration::from_secs(
            self.policy
                .endpoint_advertisement_ttl_seconds
                .saturating_div(2)
                .max(1),
        );
        let mut last_advertisement = Instant::now();
        let mut last_heartbeat = Instant::now();
        let mut idle_poll_backoff = Duration::from_millis(100);
        loop {
            if self.shutdown.is_cancelled() {
                return Ok(());
            }
            if last_heartbeat.elapsed() >= Duration::from_secs(10) {
                report_node_heartbeat_async(&self.args, session, &self.node_private_key).await?;
                last_heartbeat = Instant::now();
            }
            if last_advertisement.elapsed() >= refresh_after {
                report_endpoint_advertisement_async(
                    &self.args,
                    session,
                    &self.node_private_key,
                    &self.endpoint,
                    &self.policy,
                )
                .await?;
                last_advertisement = Instant::now();
            }
            let response = session
                .request(
                    signed_node_request(
                        &self.args,
                        &self.node_private_key,
                        "poll_artifact_provider_assignment",
                        CoordinatorRequest::PollArtifactProviderAssignment {
                            tenant: self.args.tenant.clone(),
                            project: self.args.project.clone(),
                            node: self.args.node.clone(),
                        },
                    )
                    .map_err(|error| error.to_string())?,
                )
                .await?;
            let CoordinatorResponse::ArtifactProviderAssignment {
                authorization,
                retired_transfer_ids,
            } = response
            else {
                return Err(
                    "coordinator returned an unexpected provider-assignment response".to_owned(),
                );
            };
            for transfer_id in retired_transfer_ids {
                self.provider_registry.cancel(&transfer_id).await;
            }
            if let Some(authorization) = authorization.map(|value| *value) {
                self.prepare_provider_assignment(session, authorization)
                    .await?;
                idle_poll_backoff = Duration::from_millis(100);
                continue;
            }
            tokio::select! {
                () = tokio::time::sleep(idle_poll_backoff) => {}
                () = self.shutdown.cancelled() => return Ok(()),
            }
            idle_poll_backoff = next_idle_poll_backoff(idle_poll_backoff);
        }
    }

    async fn provider_source(&self, artifact: ArtifactId) -> Result<Option<PathBuf>, String> {
        let artifact_store = self.artifact_store.clone();
        tokio::task::spawn_blocking(move || artifact_store.interchange_source(&artifact))
            .await
            .map_err(|error| format!("artifact provider source task failed: {error}"))?
    }

    async fn prepare_provider_assignment(
        &self,
        session: &AsyncCoordinatorSession,
        mut authorization: ArtifactTransferAuthorization,
    ) -> Result<(), String> {
        let source = self
            .provider_source(authorization.lease.artifact.clone())
            .await?
            .ok_or(ArtifactTransferErrorCode::ArtifactMissingAtSource);
        let result = match source {
            Ok(source) => {
                self.provider_registry
                    .register_verified_source(
                        authorization.lease.clone(),
                        authorization.transfer_secret,
                        source,
                        unix_timestamp_seconds(),
                    )
                    .await
            }
            Err(code) => {
                report_transfer_request_async(
                    &self.args,
                    session,
                    &self.node_private_key,
                    &authorization,
                    ArtifactTransferState::Failed,
                    authorization.lease.allowed_offset,
                    ClusterfluxPathKind::Unknown,
                    Some(code),
                    None,
                    None,
                )
                .await?;
                return Ok(());
            }
        };
        if let Err(error) = result {
            report_transfer_request_async(
                &self.args,
                session,
                &self.node_private_key,
                &authorization,
                ArtifactTransferState::Failed,
                authorization.lease.allowed_offset,
                ClusterfluxPathKind::Unknown,
                Some(error.stable_code()),
                None,
                None,
            )
            .await?;
            return Ok(());
        }
        acknowledge_assignment_async(
            &self.args,
            session,
            &self.node_private_key,
            &authorization,
            ArtifactAssignmentRole::Provider,
        )
        .await?;
        let response = report_transfer_request_async(
            &self.args,
            session,
            &self.node_private_key,
            &authorization,
            ArtifactTransferState::Connecting,
            authorization.lease.allowed_offset,
            ClusterfluxPathKind::Unknown,
            None,
            None,
            None,
        )
        .await?;
        if refresh_authorization_from_response(&mut authorization, &response)
            .map_err(|error| error.to_string())?
        {
            let source = self
                .provider_source(authorization.lease.artifact.clone())
                .await?
                .ok_or_else(|| {
                    ArtifactTransferErrorCode::ArtifactMissingAtSource
                        .as_str()
                        .to_owned()
                })?;
            self.provider_registry
                .register_verified_source(
                    authorization.lease.clone(),
                    authorization.transfer_secret,
                    source,
                    unix_timestamp_seconds(),
                )
                .await
                .map_err(|error| error.to_string())?;
        }
        Ok(())
    }
}
async fn report_node_heartbeat_async(
    args: &Args,
    session: &AsyncCoordinatorSession,
    node_private_key: &str,
) -> Result<(), String> {
    let request = CoordinatorRequest::NodeHeartbeat {
        tenant: args.tenant.clone(),
        project: args.project.clone(),
        node: args.node.clone(),
        node_signature: None,
    };
    let signature = sign_node_request(
        node_private_key,
        &NodeId::try_new(args.node.clone()).map_err(|error| error.to_string())?,
        "node_heartbeat",
        &signed_request_payload_digest(
            &serde_json::to_value(&request).map_err(|error| error.to_string())?,
        ),
        node_nonce("node-heartbeat-artifact-control"),
        unix_timestamp_seconds(),
    )
    .map_err(|error| format!("sign artifact-control node heartbeat: {error}"))?;
    let request = CoordinatorRequest::NodeHeartbeat {
        tenant: args.tenant.clone(),
        project: args.project.clone(),
        node: args.node.clone(),
        node_signature: Some(signature),
    };
    session.request(request).await?;
    Ok(())
}

fn acknowledge_assignment(
    args: &Args,
    session: &mut CoordinatorSession,
    node_private_key: &str,
    authorization: &ArtifactTransferAuthorization,
    role: ArtifactAssignmentRole,
) -> Result<Value, Box<dyn std::error::Error>> {
    let response = session.request_signed(|| {
        signed_node_request(
            args,
            node_private_key,
            "acknowledge_artifact_assignment",
            CoordinatorRequest::AcknowledgeArtifactAssignment {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
                transfer_id: authorization.lease.transfer_id.clone(),
                role,
            },
        )
    })?;
    match response {
        response @ CoordinatorResponse::ArtifactAssignmentAcknowledged { .. } => {
            serde_json::to_value(response).map_err(Into::into)
        }
        _ => Err("coordinator returned an unexpected assignment acknowledgement".into()),
    }
}

async fn acknowledge_assignment_async(
    args: &Args,
    session: &AsyncCoordinatorSession,
    node_private_key: &str,
    authorization: &ArtifactTransferAuthorization,
    role: ArtifactAssignmentRole,
) -> Result<CoordinatorResponse, String> {
    let response = session
        .request(
            signed_node_request(
                args,
                node_private_key,
                "acknowledge_artifact_assignment",
                CoordinatorRequest::AcknowledgeArtifactAssignment {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    node: args.node.clone(),
                    transfer_id: authorization.lease.transfer_id.clone(),
                    role,
                },
            )
            .map_err(|error| error.to_string())?,
        )
        .await?;
    if matches!(
        response,
        CoordinatorResponse::ArtifactAssignmentAcknowledged { .. }
    ) {
        Ok(response)
    } else {
        Err("coordinator returned an unexpected assignment acknowledgement".to_owned())
    }
}

fn report_endpoint_advertisement(
    args: &Args,
    session: &mut CoordinatorSession,
    node_private_key: &str,
    endpoint: &ClusterfluxEndpoint,
    policy: &ArtifactDataPlanePolicy,
) -> Result<(), Box<dyn std::error::Error>> {
    let now = unix_timestamp_seconds();
    let advertisement = endpoint.advertisement(
        policy.generation,
        now.saturating_add(policy.endpoint_advertisement_ttl_seconds),
    )?;
    let response = session.request_signed(|| {
        signed_node_request(
            args,
            node_private_key,
            "report_iroh_endpoint_advertisement",
            CoordinatorRequest::ReportIrohEndpointAdvertisement {
                tenant: args.tenant.clone(),
                project: args.project.clone(),
                node: args.node.clone(),
                advertisement: advertisement.clone(),
            },
        )
    })?;
    match response {
        CoordinatorResponse::IrohEndpointAdvertisementAccepted { .. } => Ok(()),
        _ => Err("coordinator returned an unexpected endpoint-advertisement response".into()),
    }
}

async fn report_endpoint_advertisement_async(
    args: &Args,
    session: &AsyncCoordinatorSession,
    node_private_key: &str,
    endpoint: &ClusterfluxEndpoint,
    policy: &ArtifactDataPlanePolicy,
) -> Result<(), String> {
    let now = unix_timestamp_seconds();
    let advertisement = endpoint
        .advertisement(
            policy.generation,
            now.saturating_add(policy.endpoint_advertisement_ttl_seconds),
        )
        .map_err(|error| error.to_string())?;
    let response = session
        .request(
            signed_node_request(
                args,
                node_private_key,
                "report_iroh_endpoint_advertisement",
                CoordinatorRequest::ReportIrohEndpointAdvertisement {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    node: args.node.clone(),
                    advertisement,
                },
            )
            .map_err(|error| error.to_string())?,
        )
        .await?;
    if matches!(
        response,
        CoordinatorResponse::IrohEndpointAdvertisementAccepted { .. }
    ) {
        Ok(())
    } else {
        Err("coordinator returned an unexpected endpoint-advertisement response".to_owned())
    }
}

#[allow(clippy::too_many_arguments)]
async fn report_transfer_request_async(
    args: &Args,
    session: &AsyncCoordinatorSession,
    node_private_key: &str,
    authorization: &ArtifactTransferAuthorization,
    state: ArtifactTransferState,
    bytes_completed: u64,
    path_kind: ClusterfluxPathKind,
    failure_code: Option<ArtifactTransferErrorCode>,
    verified_digest: Option<Digest>,
    verified_size: Option<u64>,
) -> Result<CoordinatorResponse, String> {
    session
        .request(
            signed_node_request(
                args,
                node_private_key,
                "report_artifact_interchange",
                CoordinatorRequest::ReportArtifactInterchange {
                    tenant: args.tenant.clone(),
                    project: args.project.clone(),
                    node: args.node.clone(),
                    transfer_id: authorization.lease.transfer_id.clone(),
                    state,
                    bytes_completed,
                    path_kind,
                    failure_code,
                    verified_digest,
                    verified_size,
                },
            )
            .map_err(|error| error.to_string())?,
        )
        .await
}

fn refresh_authorization_from_response(
    authorization: &mut ArtifactTransferAuthorization,
    response: &CoordinatorResponse,
) -> Result<bool, Box<dyn std::error::Error>> {
    let renewed = match response {
        CoordinatorResponse::ArtifactTransferAuthorization { authorization, .. }
        | CoordinatorResponse::ArtifactTransferProgressAccepted { authorization, .. } => {
            authorization.as_deref().cloned()
        }
        _ => None,
    };
    let Some(renewed) = renewed else {
        return Ok(false);
    };
    let current = &authorization.lease;
    let candidate = &renewed.lease;
    if candidate.transfer_id != current.transfer_id
        || candidate.tenant != current.tenant
        || candidate.project != current.project
        || candidate.process != current.process
        || candidate.artifact != current.artifact
        || candidate.digest != current.digest
        || candidate.size_bytes != current.size_bytes
        || candidate.source_node != current.source_node
        || candidate.destination_node != current.destination_node
        || candidate.allowed_offset != current.allowed_offset
        || renewed.transfer_secret != authorization.transfer_secret
    {
        return Err("coordinator renewed artifact authorization changed immutable scope".into());
    }
    *authorization = renewed;
    Ok(true)
}

fn transfer_from_response(response: &CoordinatorResponse) -> Option<ArtifactTransferRecord> {
    match response {
        CoordinatorResponse::ArtifactTransferAuthorization { transfer, .. } => transfer.clone(),
        CoordinatorResponse::ArtifactTransferProgressAccepted { transfer, .. } => {
            Some(transfer.clone())
        }
        _ => None,
    }
}

fn iroh_identity_path(project_root: &Path, node: &str) -> PathBuf {
    let node_digest = Digest::sha256(node);
    project_root
        .join("target/clusterflux")
        .join("nodes")
        .join(format!(
            "{}.iroh.json",
            node_digest.as_str().trim_start_matches("sha256:")
        ))
}

fn next_idle_poll_backoff(current: Duration) -> Duration {
    match current.as_millis() {
        0..=100 => Duration::from_millis(250),
        101..=250 => Duration::from_millis(500),
        251..=500 => Duration::from_secs(1),
        _ => Duration::from_secs(2),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn handle(id: &str, contents: &str) -> ArtifactHandle {
        ArtifactHandle {
            id: ArtifactId::from(id),
            digest: Digest::sha256(contents),
            size_bytes: contents.len() as u64,
        }
    }

    #[test]
    fn cancelling_one_shared_consumer_does_not_cancel_the_transfer() {
        let first_handle = handle("artifact-a", "same bytes");
        let second_handle = handle("artifact-b", "same bytes");
        let first = (
            ProcessId::from("process"),
            TaskInstanceId::from("task-a"),
            first_handle.id.clone(),
        );
        let second = (
            ProcessId::from("process"),
            TaskInstanceId::from("task-b"),
            second_handle.id.clone(),
        );
        let entry = ArtifactWarmupEntry {
            digest: first_handle.digest.clone(),
            size_bytes: first_handle.size_bytes,
            state: Mutex::new(ArtifactWarmupState::Transferring),
            changed: tokio::sync::Notify::new(),
            consumers: Mutex::new(BTreeMap::from([
                (first.clone(), first_handle),
                (second.clone(), second_handle),
            ])),
            demanded: Mutex::new(BTreeSet::from([first.clone(), second.clone()])),
            ready_handle: Mutex::new(None),
            cancel: Mutex::new(CancellationToken::new()),
        };

        assert!(!remove_consumer_from_entry(&entry, &first));
        assert!(!entry.cancellation().is_cancelled());
        assert!(entry.consumers.lock().unwrap().contains_key(&second));
        assert!(remove_consumer_from_entry(&entry, &second));
        assert!(entry.cancellation().is_cancelled());
    }

    #[test]
    fn demanded_retry_classification_distinguishes_temporary_and_permanent_failures() {
        assert_eq!(
            retry_class_from_message(ArtifactTransferErrorCode::ConnectionFailed.as_str()),
            clusterflux_core::ArtifactTransferRetryClass::RetrySameSource
        );
        assert_eq!(
            retry_class_from_message(ArtifactTransferErrorCode::DigestMismatch.as_str()),
            clusterflux_core::ArtifactTransferRetryClass::PermanentSourceInvalidation
        );
    }

    #[test]
    fn transient_speculative_failure_requeues_for_demanded_materialization() {
        let cancelled = CancellationToken::new();
        cancelled.cancel();
        let entry = ArtifactWarmupEntry {
            digest: Digest::sha256("retry bytes"),
            size_bytes: 11,
            state: Mutex::new(ArtifactWarmupState::Failed(
                ArtifactWarmupFailure::from_message(
                    ArtifactTransferErrorCode::ConnectionFailed
                        .as_str()
                        .to_owned(),
                ),
            )),
            changed: tokio::sync::Notify::new(),
            consumers: Mutex::new(BTreeMap::new()),
            demanded: Mutex::new(BTreeSet::new()),
            ready_handle: Mutex::new(None),
            cancel: Mutex::new(cancelled),
        };
        assert!(reset_retryable_failed_entry(&entry).unwrap());
        assert_eq!(*entry.state.lock().unwrap(), ArtifactWarmupState::Queued);
        assert!(!entry.cancellation().is_cancelled());

        *entry.state.lock().unwrap() =
            ArtifactWarmupState::Failed(ArtifactWarmupFailure::from_message(
                ArtifactTransferErrorCode::DigestMismatch
                    .as_str()
                    .to_owned(),
            ));
        assert!(!reset_retryable_failed_entry(&entry).unwrap());
        assert!(matches!(
            &*entry.state.lock().unwrap(),
            ArtifactWarmupState::Failed(failure)
                if failure.retry_class
                    == clusterflux_core::ArtifactTransferRetryClass::PermanentSourceInvalidation
        ));
    }
}
