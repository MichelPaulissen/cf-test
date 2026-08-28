use std::collections::BTreeMap;
use std::time::{Duration, Instant};

use clusterflux_core::{
    ArtifactRelayPolicy, AuthorizedPeerEndpoint, NodeId, ProjectId, TenantId,
    CLUSTERFLUX_ARTIFACT_ALPN,
};
use iroh::endpoint::Connection;
use tokio::sync::Mutex;

use crate::endpoint::{ClusterfluxEndpoint, EndpointError};

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct ConnectionPoolKey {
    tenant: TenantId,
    project: ProjectId,
    peer_node: NodeId,
    peer_endpoint_id: String,
    peer_endpoint_generation: u64,
    relay_policy: u8,
}

impl ConnectionPoolKey {
    pub(crate) fn new(
        tenant: TenantId,
        project: ProjectId,
        peer: &AuthorizedPeerEndpoint,
        relay_policy: ArtifactRelayPolicy,
    ) -> Self {
        Self {
            tenant,
            project,
            peer_node: peer.node.clone(),
            peer_endpoint_id: peer.endpoint_id.clone(),
            peer_endpoint_generation: peer.generation,
            relay_policy: match relay_policy {
                ArtifactRelayPolicy::DirectRequired => 0,
                ArtifactRelayPolicy::RelayFallbackAllowed => 1,
            },
        }
    }
}

#[derive(Debug)]
struct PooledConnection {
    connection: Connection,
    last_used: Instant,
}

#[derive(Debug)]
pub(crate) struct ConnectionPool {
    connections: Mutex<BTreeMap<ConnectionPoolKey, PooledConnection>>,
    maximum_connections: usize,
    idle_timeout: Duration,
}

impl ConnectionPool {
    pub(crate) fn new(maximum_connections: usize, idle_timeout: Duration) -> Self {
        Self {
            connections: Mutex::new(BTreeMap::new()),
            maximum_connections: maximum_connections.max(1),
            idle_timeout,
        }
    }

    pub(crate) async fn get_or_connect(
        &self,
        endpoint: &ClusterfluxEndpoint,
        key: ConnectionPoolKey,
        peer: &AuthorizedPeerEndpoint,
    ) -> Result<Connection, EndpointError> {
        let now = Instant::now();
        {
            let mut connections = self.connections.lock().await;
            connections.retain(|_, pooled| {
                now.duration_since(pooled.last_used) <= self.idle_timeout
                    && pooled.connection.close_reason().is_none()
            });
            if let Some(pooled) = connections.get_mut(&key) {
                pooled.last_used = now;
                return Ok(pooled.connection.clone());
            }
        }

        let address = endpoint.authorized_endpoint_addr(peer)?;
        let connection = endpoint
            .endpoint()
            .connect(address, CLUSTERFLUX_ARTIFACT_ALPN)
            .await
            .map_err(|error| EndpointError::Connect(error.to_string()))?;
        if connection.remote_id().to_string() != peer.endpoint_id {
            connection.close(1_u32.into(), b"peer identity mismatch");
            return Err(EndpointError::PeerIdentityMismatch);
        }

        let mut connections = self.connections.lock().await;
        // Another task may have connected to the same peer while this connect was in flight.
        // Reuse the winner and close this duplicate instead of replacing a live pooled
        // connection and leaving it detached from the bound.
        if let Some(pooled) = connections.get_mut(&key) {
            if pooled.connection.close_reason().is_none() {
                pooled.last_used = now;
                connection.close(0_u32.into(), b"duplicate pooled connection");
                return Ok(pooled.connection.clone());
            }
            connections.remove(&key);
        }
        if connections.len() >= self.maximum_connections {
            if let Some(oldest) = connections
                .iter()
                .min_by_key(|(_, pooled)| pooled.last_used)
                .map(|(key, _)| key.clone())
            {
                if let Some(evicted) = connections.remove(&oldest) {
                    evicted
                        .connection
                        .close(0_u32.into(), b"connection pool eviction");
                }
            }
        }
        connections.insert(
            key,
            PooledConnection {
                connection: connection.clone(),
                last_used: now,
            },
        );
        Ok(connection)
    }

    pub(crate) async fn invalidate(&self, key: &ConnectionPoolKey) {
        if let Some(pooled) = self.connections.lock().await.remove(key) {
            pooled
                .connection
                .close(0_u32.into(), b"endpoint generation or policy invalidated");
        }
    }

    pub(crate) async fn close_all(&self) {
        let mut connections = self.connections.lock().await;
        for (_, pooled) in std::mem::take(&mut *connections) {
            pooled.connection.close(0_u32.into(), b"node shutdown");
        }
    }
}
