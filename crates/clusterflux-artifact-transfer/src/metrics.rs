use std::sync::atomic::{AtomicU64, Ordering};

use clusterflux_core::ClusterfluxPathKind;

#[derive(Debug, Default)]
pub struct ArtifactDataPlaneMetrics {
    direct_body_bytes: AtomicU64,
    relayed_body_bytes: AtomicU64,
    unknown_path_body_bytes: AtomicU64,
    completed_transfers: AtomicU64,
    resumed_transfers: AtomicU64,
    integrity_failures: AtomicU64,
}

impl ArtifactDataPlaneMetrics {
    pub(crate) fn record_body_bytes(&self, path: ClusterfluxPathKind, bytes: u64) {
        if path == ClusterfluxPathKind::Local {
            debug_assert_eq!(
                bytes, 0,
                "local artifact paths cannot carry network body bytes"
            );
            return;
        }
        match path {
            ClusterfluxPathKind::Direct => &self.direct_body_bytes,
            ClusterfluxPathKind::Relayed => &self.relayed_body_bytes,
            ClusterfluxPathKind::Unknown => &self.unknown_path_body_bytes,
            ClusterfluxPathKind::Local => unreachable!(),
        }
        .fetch_add(bytes, Ordering::Relaxed);
    }

    pub(crate) fn record_completed(&self, resumed: bool) {
        self.completed_transfers.fetch_add(1, Ordering::Relaxed);
        if resumed {
            self.resumed_transfers.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub(crate) fn record_integrity_failure(&self) {
        self.integrity_failures.fetch_add(1, Ordering::Relaxed);
    }

    pub fn snapshot(&self) -> ArtifactDataPlaneMetricsSnapshot {
        ArtifactDataPlaneMetricsSnapshot {
            direct_body_bytes: self.direct_body_bytes.load(Ordering::Relaxed),
            relayed_body_bytes: self.relayed_body_bytes.load(Ordering::Relaxed),
            unknown_path_body_bytes: self.unknown_path_body_bytes.load(Ordering::Relaxed),
            completed_transfers: self.completed_transfers.load(Ordering::Relaxed),
            resumed_transfers: self.resumed_transfers.load(Ordering::Relaxed),
            integrity_failures: self.integrity_failures.load(Ordering::Relaxed),
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ArtifactDataPlaneMetricsSnapshot {
    pub direct_body_bytes: u64,
    pub relayed_body_bytes: u64,
    pub unknown_path_body_bytes: u64,
    pub completed_transfers: u64,
    pub resumed_transfers: u64,
    pub integrity_failures: u64,
}
