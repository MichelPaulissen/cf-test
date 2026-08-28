use std::future::Future;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use clusterflux_core::{ArtifactRelayPolicy, ClusterfluxPathKind};
use futures_util::{FutureExt, StreamExt};
use iroh::endpoint::Connection;
use thiserror::Error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PathPolicy {
    pub relay_policy: ArtifactRelayPolicy,
    pub direct_path_deadline: Duration,
    pub direct_path_grace_period: Duration,
    pub direct_recovery_deadline: Duration,
}

impl PathPolicy {
    pub fn direct_required(deadline: Duration) -> Self {
        Self {
            relay_policy: ArtifactRelayPolicy::DirectRequired,
            direct_path_deadline: deadline,
            direct_path_grace_period: Duration::ZERO,
            direct_recovery_deadline: Duration::from_secs(5),
        }
    }

    pub fn relay_fallback_allowed(grace_period: Duration) -> Self {
        Self {
            relay_policy: ArtifactRelayPolicy::RelayFallbackAllowed,
            direct_path_deadline: grace_period,
            direct_path_grace_period: grace_period,
            direct_recovery_deadline: Duration::from_secs(5),
        }
    }

    pub async fn wait_for_permitted_path(
        &self,
        connection: &Connection,
        metrics: &PathPolicyMetrics,
    ) -> Result<ClusterfluxPathKind, PathPolicyError> {
        let deadline = match self.relay_policy {
            ArtifactRelayPolicy::DirectRequired => self.direct_path_deadline,
            ArtifactRelayPolicy::RelayFallbackAllowed => self.direct_path_grace_period,
        };
        let wait = async {
            let mut snapshots = connection.paths_stream();
            while let Some(snapshot) = snapshots.next().await {
                let kind = selected_path_kind(&snapshot);
                metrics.observe(kind);
                if kind == ClusterfluxPathKind::Direct {
                    return Ok(ClusterfluxPathKind::Direct);
                }
            }
            Err(PathPolicyError::ConnectionClosed)
        };
        match tokio::time::timeout(deadline, wait).await {
            Ok(result) => result,
            Err(_) if self.relay_policy == ArtifactRelayPolicy::RelayFallbackAllowed => {
                let selected = selected_connection_path_kind(connection);
                metrics.observe(selected);
                match selected {
                    ClusterfluxPathKind::Direct => Ok(ClusterfluxPathKind::Direct),
                    ClusterfluxPathKind::Relayed => Ok(ClusterfluxPathKind::Relayed),
                    ClusterfluxPathKind::Local | ClusterfluxPathKind::Unknown => {
                        Err(PathPolicyError::NoSelectedPath)
                    }
                }
            }
            Err(_) => {
                metrics.direct_timeouts.fetch_add(1, Ordering::Relaxed);
                Err(PathPolicyError::DirectPathTimeout)
            }
        }
    }

    pub async fn run_while_permitted<T, F>(
        &self,
        connection: &Connection,
        metrics: &PathPolicyMetrics,
        transfer: F,
    ) -> Result<T, PathPolicyError>
    where
        F: Future<Output = Result<T, PathPolicyError>>,
    {
        let mut initial = selected_connection_path_kind(connection);
        if self.relay_policy == ArtifactRelayPolicy::DirectRequired
            && initial != ClusterfluxPathKind::Direct
        {
            initial = self.wait_for_direct_recovery(connection, metrics).await?;
        }
        metrics.observe(initial);

        let mut snapshots = connection.paths_stream();
        tokio::pin!(transfer);
        loop {
            tokio::select! {
                result = &mut transfer => return result,
                snapshot = snapshots.next() => {
                    let Some(snapshot) = snapshot else {
                        // A local terminal condition (for example ENOSPC) can close the
                        // Iroh stream and its path stream in the same scheduler turn. Keep
                        // that concrete transfer error instead of racing it into the less
                        // useful generic connection-closed result.
                        if let Some(result) = transfer.as_mut().now_or_never() {
                            return result;
                        }
                        return Err(PathPolicyError::ConnectionClosed);
                    };
                    let selected = selected_path_kind(&snapshot);
                    metrics.observe(selected);
                    if self.relay_policy == ArtifactRelayPolicy::DirectRequired {
                        match selected {
                            ClusterfluxPathKind::Direct => {}
                            ClusterfluxPathKind::Relayed => {
                                metrics.forbidden_path_transitions.fetch_add(1, Ordering::Relaxed);
                                return Err(PathPolicyError::RelayPathForbidden);
                            }
                            ClusterfluxPathKind::Local | ClusterfluxPathKind::Unknown => {
                                if let Some(result) = transfer.as_mut().now_or_never() {
                                    return result;
                                }
                                let recovery = self.wait_for_direct_recovery(connection, metrics);
                                tokio::pin!(recovery);
                                let recovered = tokio::select! {
                                    biased;
                                    recovered = &mut recovery => recovered,
                                    result = &mut transfer => return result,
                                };
                                if let Err(error) = recovered {
                                    if error != PathPolicyError::RelayPathForbidden {
                                        if let Some(result) = transfer.as_mut().now_or_never() {
                                            return result;
                                        }
                                    }
                                    return Err(error);
                                }
                            }
                        }
                    }
                }
            }
        }
    }

    pub(crate) async fn wait_for_direct_recovery(
        &self,
        connection: &Connection,
        metrics: &PathPolicyMetrics,
    ) -> Result<ClusterfluxPathKind, PathPolicyError> {
        let selected = selected_connection_path_kind(connection);
        metrics.observe(selected);
        match selected {
            ClusterfluxPathKind::Direct => return Ok(selected),
            ClusterfluxPathKind::Relayed => {
                metrics
                    .forbidden_path_transitions
                    .fetch_add(1, Ordering::Relaxed);
                return Err(PathPolicyError::RelayPathForbidden);
            }
            ClusterfluxPathKind::Local | ClusterfluxPathKind::Unknown => {}
        }

        let recovery = async {
            let mut snapshots = connection.paths_stream();
            while let Some(snapshot) = snapshots.next().await {
                let selected = selected_path_kind(&snapshot);
                metrics.observe(selected);
                match selected {
                    ClusterfluxPathKind::Direct => return Ok(selected),
                    ClusterfluxPathKind::Relayed => {
                        metrics
                            .forbidden_path_transitions
                            .fetch_add(1, Ordering::Relaxed);
                        return Err(PathPolicyError::RelayPathForbidden);
                    }
                    ClusterfluxPathKind::Local | ClusterfluxPathKind::Unknown => {}
                }
            }
            Err(PathPolicyError::ConnectionClosed)
        };
        match tokio::time::timeout(self.direct_recovery_deadline, recovery).await {
            Ok(result) => result,
            Err(_) => {
                metrics.direct_timeouts.fetch_add(1, Ordering::Relaxed);
                Err(PathPolicyError::DirectPathTimeout)
            }
        }
    }
}

pub fn selected_connection_path_kind(connection: &Connection) -> ClusterfluxPathKind {
    selected_path_kind(&connection.paths())
}

fn selected_path_kind(paths: &iroh::endpoint::PathList<'_>) -> ClusterfluxPathKind {
    paths
        .iter()
        .find(|path| path.is_selected())
        .map(|path| {
            if path.is_ip() {
                ClusterfluxPathKind::Direct
            } else if path.is_relay() {
                ClusterfluxPathKind::Relayed
            } else {
                ClusterfluxPathKind::Unknown
            }
        })
        .unwrap_or(ClusterfluxPathKind::Unknown)
}

#[derive(Debug, Default)]
pub struct PathPolicyMetrics {
    selected_direct: AtomicU64,
    selected_relay: AtomicU64,
    selected_unknown: AtomicU64,
    direct_timeouts: AtomicU64,
    forbidden_path_transitions: AtomicU64,
}

impl PathPolicyMetrics {
    fn observe(&self, kind: ClusterfluxPathKind) {
        match kind {
            ClusterfluxPathKind::Direct => &self.selected_direct,
            ClusterfluxPathKind::Relayed => &self.selected_relay,
            ClusterfluxPathKind::Local | ClusterfluxPathKind::Unknown => &self.selected_unknown,
        }
        .fetch_add(1, Ordering::Relaxed);
    }

    pub fn selected_direct(&self) -> u64 {
        self.selected_direct.load(Ordering::Relaxed)
    }

    pub fn selected_relay(&self) -> u64 {
        self.selected_relay.load(Ordering::Relaxed)
    }

    pub fn direct_timeouts(&self) -> u64 {
        self.direct_timeouts.load(Ordering::Relaxed)
    }

    pub fn forbidden_path_transitions(&self) -> u64 {
        self.forbidden_path_transitions.load(Ordering::Relaxed)
    }
}

#[derive(Clone, Debug, Error, PartialEq, Eq)]
pub enum PathPolicyError {
    #[error("direct path did not form before the transfer deadline")]
    DirectPathTimeout,
    #[error("artifact relay path is forbidden by deployment policy")]
    RelayPathForbidden,
    #[error("Iroh connection has no selected transport path")]
    NoSelectedPath,
    #[error("Iroh connection closed while enforcing artifact path policy")]
    ConnectionClosed,
    #[error("artifact stream failed: {0}")]
    Transfer(String),
    #[error("artifact destination disk is full")]
    DestinationDiskFull,
}
